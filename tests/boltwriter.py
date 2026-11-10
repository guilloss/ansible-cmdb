# -*- coding: utf-8 -*-
"""Écriture d'une petite base BoltDB pour les tests (le lecteur est tools/cmdb_bolt.py).

Arbre de compartiments en dict : {nom: valeur bytes | dict}. Un compartiment de plus de
LEAF_MAX clés est réparti sur plusieurs feuilles sous une page branche, pour éprouver la
recherche dans les branches. Les sous-compartiments ne sont jamais « en ligne », sauf
inline=True : alors les petits sont écrits en ligne, comme le fait bbolt."""
import struct

PAGE = 4096
LEAF_MAX = 8


def _b(x):
    return x if isinstance(x, bytes) else str(x).encode("utf-8")


class Writer(object):
    def __init__(self, inline=False):
        self.pages = {}       # pgid -> octets (multiple de PAGE)
        self.next = 3         # 0, 1 : méta ; 2 : liste libre
        self.inline = inline

    def _alloc(self, data):
        n = max(1, -(-len(data) // PAGE))
        pgid = self.next
        self.next += n
        # en-tête : le nombre de pages de débordement
        data = data[:12] + struct.pack("<I", n - 1) + data[16:]
        self.pages[pgid] = data + b"\0" * (n * PAGE - len(data))
        return pgid

    @staticmethod
    def _leaf_bytes(pgid, items):
        """items : [(clé, valeur, est_bucket)] triés."""
        n = len(items)
        head = struct.pack("<QHHI", pgid, 0x02, n, 0)
        elems, data = b"", b""
        base = 16 + 16 * n
        for i, (k, v, is_bucket) in enumerate(items):
            pos = base + len(data) - (16 + 16 * i)
            elems += struct.pack("<IIII", 1 if is_bucket else 0, pos, len(k), len(v))
            data += k + v
        return head + elems + data

    def bucket(self, tree):
        """Écrit un compartiment ; renvoie l'id de sa page racine."""
        items = []
        for k in sorted(tree, key=_b):
            v = tree[k]
            if isinstance(v, dict):
                if self.inline and len(v) <= 2 and all(not isinstance(x, dict) for x in v.values()):
                    sub = [(_b(a), _b(b), False) for a, b in sorted(v.items(), key=lambda kv: _b(kv[0]))]
                    items.append((_b(k), struct.pack("<QQ", 0, 0) + self._leaf_bytes(0, sub), True))
                else:
                    items.append((_b(k), struct.pack("<QQ", self.bucket(v), 0), True))
            else:
                items.append((_b(k), _b(v), False))
        if len(items) <= LEAF_MAX:
            pgid = self.next
            return self._alloc(self._leaf_bytes(pgid, items))
        children = []
        for i in range(0, len(items), LEAF_MAX):
            chunk = items[i:i + LEAF_MAX]
            pgid = self.next
            children.append((chunk[0][0], self._alloc(self._leaf_bytes(pgid, chunk))))
        n = len(children)
        head = struct.pack("<QHHI", self.next, 0x01, n, 0)
        elems, data = b"", b""
        base = 16 + 16 * n
        for i, (k, child) in enumerate(children):
            pos = base + len(data) - (16 + 16 * i)
            elems += struct.pack("<IIQ", pos, len(k), child)
            data += k
        return self._alloc(head + elems + data)

    def write(self, path, tree):
        root = self.bucket(tree)
        with open(path, "wb") as f:
            for i in (0, 1):
                meta = struct.pack("<QHHI", i, 0x04, 0, 0) + struct.pack("<IIIIQQQQQ", 0xED0CDAED, 2, PAGE, 0, root, 0, 2,
                                                                           self.next, i + 1)
                f.write(meta + b"\0" * (PAGE - len(meta)))
            f.write(struct.pack("<QHHI", 2, 0x10, 0, 0) + b"\0" * (PAGE - 16))
            for pgid in range(3, self.next):
                if pgid in self.pages:
                    f.write(self.pages[pgid])
