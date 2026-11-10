# -*- coding: utf-8 -*-
"""Lecture seule d'une base BoltDB (bbolt), en Python pur : de quoi lire la base de Trivy (trivy.db)
sans Go ni dépendance. Le fichier est projeté en mémoire (mmap) et jamais modifié.

Format (go.etcd.io/bbolt) : pages de taille fixe ; en-tête de page id u64, flags u16, count u16,
overflow u32. Pages : branche (0x01), feuille (0x02), méta (0x04). Un élément de feuille marqué
0x01 est un sous-compartiment (bucket) : racine u64 + séquence u64, puis, si la racine vaut 0,
une page « en ligne » qui contient directement ses éléments."""
import mmap
import struct

BRANCH, LEAF, META = 0x01, 0x02, 0x04
BUCKET_LEAF = 0x01
MAGIC = 0xED0CDAED
HDR = 16


class BoltError(Exception):
    pass


class Bolt(object):
    def __init__(self, path):
        self._f = open(path, "rb")
        self.mm = mmap.mmap(self._f.fileno(), 0, access=mmap.ACCESS_READ)
        metas = []
        for page_size_guess in (4096,):
            for i in (0, 1):
                m = self._meta(i * page_size_guess)
                if m:
                    metas.append(m)
        if not metas:
            self.close()
            raise BoltError("%s : pas une base BoltDB" % path)
        # La page méta valide la plus récente (txid le plus grand) fait foi
        meta = max(metas, key=lambda m: m["txid"])
        self.page_size = meta["page_size"]
        if self.page_size != 4096:   # relire les deux métas à la bonne taille
            metas = [m for m in (self._meta(0), self._meta(self.page_size)) if m]
            meta = max(metas, key=lambda m: m["txid"])
        self.root = meta["root"]

    def close(self):
        self.mm.close()
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _meta(self, off):
        if off + HDR + 64 > len(self.mm):
            return None
        _pid, flags, _c, _o = struct.unpack_from("<QHHI", self.mm, off)
        if flags != META:
            return None
        magic, version, page_size, _flags, root, _seq, _free, _pgid, txid = struct.unpack_from("<IIIIQQQQQ", self.mm, off + HDR)
        if magic != MAGIC or version != 2:
            return None
        return {"page_size": page_size, "root": root, "txid": txid}

    # -- parcours ---------------------------------------------------------------
    def _page(self, pgid):
        off = pgid * self.page_size
        _pid, flags, count, _overflow = struct.unpack_from("<QHHI", self.mm, off)
        return off, flags, count

    def _items(self, buf, off, flags, count):
        """Éléments (clé, valeur, est_bucket) d'une page feuille, ou enfants d'une branche, dans l'ordre."""
        if flags & LEAF:
            for i in range(count):
                e = off + HDR + i * 16
                eflags, pos, ksize, vsize = struct.unpack_from("<IIII", buf, e)
                k = e + pos
                yield bytes(buf[k:k + ksize]), (k + ksize, vsize), bool(eflags & BUCKET_LEAF)
        elif flags & BRANCH:
            for i in range(count):
                e = off + HDR + i * 16
                _pos, _ksize, child = struct.unpack_from("<IIQ", buf, e)
                coff, cflags, ccount = self._page(child)
                for item in self._items(self.mm, coff, cflags, ccount):
                    yield item
        else:
            raise BoltError("page inattendue (flags %#x)" % flags)

    def _seek(self, buf, off, flags, count, key):
        """Recherche dichotomique d'une clé ; renvoie (position valeur, est_bucket) ou None."""
        while flags & BRANCH:
            lo, hi, child = 0, count - 1, None
            # dernier élément dont la clé est <= key
            while lo <= hi:
                mid = (lo + hi) // 2
                e = off + HDR + mid * 16
                pos, ksize, pg = struct.unpack_from("<IIQ", buf, e)
                k = bytes(buf[e + pos:e + pos + ksize])
                if k <= key:
                    child, lo = pg, mid + 1
                else:
                    hi = mid - 1
            if child is None:
                e = off + HDR
                child = struct.unpack_from("<IIQ", buf, e)[2]
            buf = self.mm
            off, flags, count = self._page(child)
        lo, hi = 0, count - 1
        while lo <= hi:
            mid = (lo + hi) // 2
            e = off + HDR + mid * 16
            eflags, pos, ksize, vsize = struct.unpack_from("<IIII", buf, e)
            k = bytes(buf[e + pos:e + pos + ksize])
            if k == key:
                return buf, (e + pos + ksize, vsize), bool(eflags & BUCKET_LEAF)
            if k < key:
                lo = mid + 1
            else:
                hi = mid - 1
        return None


class Bucket(object):
    """Compartiment : itération (clé, valeur ou Bucket) et accès direct par clé."""

    def __init__(self, db, buf, off, flags, count):
        self.db, self.buf, self.off, self.flags, self.count = db, buf, off, flags, count

    @classmethod
    def root(cls, db):
        return cls._from_header(db, None, db.root, None)

    @classmethod
    def _from_header(cls, db, buf, root, inline_off):
        if root:
            off, flags, count = db._page(root)
            return cls(db, db.mm, off, flags, count)
        _pid, flags, count, _o = struct.unpack_from("<QHHI", buf, inline_off)
        return cls(db, buf, inline_off, flags, count)

    def _sub(self, buf, vpos):
        start, _size = vpos
        root, _seq = struct.unpack_from("<QQ", buf, start)
        return Bucket._from_header(self.db, buf, root, start + 16)

    def items(self):
        for k, vpos, is_bucket in self.db._items(self.buf, self.off, self.flags, self.count):
            buf = self.buf if not self.flags & BRANCH else self.db.mm
            if is_bucket:
                yield k, self._sub(buf, vpos)
            else:
                start, size = vpos
                yield k, bytes(buf[start:start + size])

    def keys(self):
        for k, _v in self.items():
            yield k

    def get(self, key):
        if isinstance(key, str):
            key = key.encode("utf-8")
        r = self.db._seek(self.buf, self.off, self.flags, self.count, key)
        if r is None:
            return None
        buf, vpos, is_bucket = r
        if is_bucket:
            return self._sub(buf, vpos)
        start, size = vpos
        return bytes(buf[start:start + size])
