#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Décode la sortie "flux" d'un collecteur en fichier .json.gz.

Usage : cmdb_unpack.py <fichier_stdout> <destination.json.gz>

Le texte entre les marqueurs CMDB-B64-BEGIN / CMDB-B64-END est décodé ;
tout ce qui précède ou suit (bannières, messages sudo...) est ignoré.
  * collecteurs Python (--output -) et PowerShell : JSON gzip, écrit tel quel ;
  * collecteur shell (cmdb_collector.sh) : archive tar.gz de sorties brutes,
    convertie au schéma JSON par cmdb_shell_parse.py.
"""
import base64
import gzip
import json
import os
import sys


def main():
    src, dst = sys.argv[1], sys.argv[2]
    lines = open(src, encoding="utf-8", errors="replace").read().splitlines()
    try:
        start = lines.index("CMDB-B64-BEGIN") + 1
        end = lines.index("CMDB-B64-END", start)
    except ValueError:
        sys.exit("Marqueurs CMDB-B64 absents de %s : la collecte a probablement échoué" % src)
    # uuencode -m ajoute une ligne d'en-tête "begin-base64 ..." et une ligne finale "===="
    payload = "".join(l.strip() for l in lines[start:end]
                      if l.strip() and not l.startswith("begin-base64") and l.strip() != "====")
    raw = base64.b64decode(payload)
    inner = gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw   # AIX sans gzip : tar non compressé
    if inner[257:262] == b"ustar":
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import cmdb_shell_parse
        doc = cmdb_shell_parse.convert(raw)
        raw = gzip.compress(json.dumps(doc).encode("utf-8"))
        kind = "collecteur shell, converti"
    else:
        meta = json.loads(inner.decode("utf-8")).get("meta") or {}  # contrôle d'intégrité
        kind = "collecteur PowerShell" if meta.get("collector") == "powershell" else "collecteur Python"
    with open(dst, "wb") as f:
        f.write(raw)
    print("%s : %d octets (%s)" % (dst, len(raw), kind))


if __name__ == "__main__":
    main()
