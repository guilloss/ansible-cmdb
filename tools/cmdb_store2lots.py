#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Convertit un magasin de collectes (store/) en lots transférables, un lot par passage.

    python3 tools/cmdb_store2lots.py store /depot/lots
    python3 tools/cmdb_store2lots.py store /depot/lots --run 20261112T090000Z-1a2b
    python3 tools/cmdb_store2lots.py --from-sqlite build/cmdb.sqlite store /depot/lots

--from-sqlite : les .json.gz ont disparu mais une consolidation a été faite. cmdb_build.py garde la
dernière collecte de chaque serveur dans cmdb.sqlite (table raw_documents, sauf --no-raw-documents) :
elle est réécrite telle quelle dans le lot, avec le manifeste du passage s'il est dans <store>/_runs.
Seule la dernière collecte de chaque serveur est récupérable (pas l'historique).

Chaque lot contient, chemins relatifs au magasin, comme ceux de collect.yml :
    _runs/<run_id>/...                         manifeste du passage (s'il existe)
    <app>/<pf>/<hôte>/<run_id>.json.gz         collectes du passage
    <app>/<pf>/<hôte>/<run_id>.ansible_facts.json
Nom : <app>__<pf>__<run_id>.tar.gz (plusieurs valeurs jointes par « + », au-delà de trois « multi »).

Un lot par passage et non un seul pour tout le magasin : la consolidation ignore un lot entier dès
qu'un de ses passages figure déjà dans le magasin qu'elle lit. Le magasin n'est jamais modifié."""
import argparse
import gzip
import io
import json
import os
import sqlite3
import sys
import tarfile
import time

SUFFIXES = (".ansible_facts.json", ".json.gz")


def part(values):
    values = sorted(values)
    return "multi" if len(values) > 3 else "+".join(values) or "NA"


def scan(store):
    """{run_id: [chemins relatifs des collectes]}, à toute profondeur ; latest.json.gz, traces d'échec,
    _runs et _lots exclus. La consolidation lit une collecte d'un lot quel que soit son chemin."""
    runs = {}
    for d, dirs, files in os.walk(store):
        rel = os.path.relpath(d, store)
        if rel == ".":
            dirs[:] = [x for x in dirs if x not in ("_runs", "_lots")]
        dirs.sort()
        parts = [] if rel == "." else rel.split(os.sep)
        for f in sorted(files):
            suffix = next((s for s in SUFFIXES if f.endswith(s)), None)
            if not suffix or f == "latest.json.gz":
                continue
            runs.setdefault(f[:-len(suffix)], []).append("/".join(parts + [f]))
    return runs


def app_platform(store, rel):
    """Application et plate-forme d'une collecte : chemin <app>/<pf>/<hôte>/, sinon étiquettes du document."""
    parts = rel.split("/")
    if len(parts) == 4:
        return parts[0], parts[1]
    try:
        with gzip.open(os.path.join(store, *parts), "rt", encoding="utf-8") as fh:
            tags = (json.load(fh).get("meta") or {}).get("tags") or {}
    except (OSError, ValueError, EOFError, AttributeError) as e:
        print("ATTENTION %s illisible (%s)" % (rel, e), file=sys.stderr)
        tags = {}
    return tags.get("app") or "NA", tags.get("platform") or "NA"


def from_sqlite(db, store, out, only):
    """Lots refaits depuis la table raw_documents d'une consolidation."""
    con = sqlite3.connect("file:%s?mode=ro" % os.path.abspath(db), uri=True)
    try:
        rows = con.execute("SELECT app, platform, host, document, ansible_facts FROM raw_documents").fetchall()
    except sqlite3.Error as e:
        print("ERREUR %s : %s" % (db, e), file=sys.stderr)
        return 2
    finally:
        con.close()
    runs = {}
    for app, pf, host, document, facts in rows:
        doc = json.loads(document)
        meta = doc.get("meta") or {}
        rid = meta.get("run_id") or "sans-passage"
        if not only or rid in only:
            runs.setdefault(rid, []).append((app or "NA", pf or "NA", meta.get("host_label") or host, document, facts))
    if not runs:
        print("Aucune collecte dans %s (consolidation faite avec --no-raw-documents ?)" % db)
        return 1
    os.makedirs(out, exist_ok=True)
    for rid in sorted(runs):
        docs = runs[rid]
        name = "%s__%s__%s.tar.gz" % (part({d[0] for d in docs}), part({d[1] for d in docs}), rid)
        path = os.path.join(out, name)
        manifest = os.path.join(store, "_runs", rid) if store else None
        with tarfile.open(path + ".part", "w:gz") as tf:
            if manifest and os.path.isdir(manifest):
                tf.add(manifest, "_runs/" + rid)
            for app, pf, host, document, facts in docs:
                base = "%s/%s/%s/%s" % (app, pf, host, rid)
                add_bytes(tf, base + ".json.gz", gzip.compress(document.encode("utf-8")))
                if facts:
                    add_bytes(tf, base + ".ansible_facts.json", facts.encode("utf-8"))
        os.replace(path + ".part", path)
        print("%s  (%d collecte(s)%s)" % (path, len(docs), "" if manifest and os.path.isdir(manifest) else ", sans manifeste"))
    return 0


def add_bytes(tf, name, data):
    info = tarfile.TarInfo(name)
    info.size, info.mode, info.mtime = len(data), 0o640, int(time.time())
    tf.addfile(info, io.BytesIO(data))


def explain(store):
    """Magasin sans collecte : ce que disent les manifestes des passages (statut et fichier de chaque hôte)."""
    runs_dir = os.path.join(store, "_runs")
    if not os.path.isdir(runs_dir):
        return
    for rid in sorted(os.listdir(runs_dir)):
        d = os.path.join(runs_dir, rid)
        if not os.path.isdir(d):
            continue
        print("Passage %s :" % rid)
        hosts = [f for f in sorted(os.listdir(d)) if f.endswith(".json") and f != "_run.json"]
        if not hosts:
            print("  aucun hôte dans le manifeste")
        for f in hosts:
            try:
                with open(os.path.join(d, f), encoding="utf-8") as fh:
                    m = json.load(fh)
            except (OSError, ValueError) as e:
                print("  %s : illisible (%s)" % (f, e))
                continue
            if m.get("file"):
                found = os.path.isfile(os.path.join(store, *m["file"].split("/")))
                note = " ; %s %s" % ("présent :" if found else "ABSENT de ce magasin :", m["file"])
            else:
                note = " ; %s" % m["detail"] if m.get("detail") else ""
            print("  %s/%s/%s : %s%s" % (m.get("app"), m.get("platform"), m.get("host"), m.get("status"), note))


def main(argv=None):
    ap = argparse.ArgumentParser(description="Magasin de collectes -> lots .tar.gz (un par passage)")
    ap.add_argument("store", help="magasin à convertir (store/)")
    ap.add_argument("out", help="répertoire où écrire les lots")
    ap.add_argument("--run", action="append", default=[], help="ne convertir que ce passage (répétable)")
    ap.add_argument("--from-sqlite", metavar="CMDB_SQLITE",
                    help="refaire les lots depuis build/cmdb.sqlite quand les .json.gz ont disparu")
    a = ap.parse_args(argv)
    if a.from_sqlite:
        if not os.path.isfile(a.from_sqlite):
            print("ERREUR base introuvable : %s" % a.from_sqlite, file=sys.stderr)
            return 2
        return from_sqlite(a.from_sqlite, a.store, a.out, set(a.run))
    if not os.path.isdir(a.store):
        print("ERREUR magasin introuvable : %s" % a.store, file=sys.stderr)
        return 2
    runs = scan(a.store)
    if a.run:
        missing = sorted(set(a.run) - set(runs))
        for rid in missing:
            print("ATTENTION passage sans collecte dans le magasin : %s" % rid, file=sys.stderr)
        runs = dict((rid, runs[rid]) for rid in a.run if rid in runs)
    if not runs:
        print("Aucune collecte à convertir dans %s" % a.store)
        explain(a.store)
        return 1
    os.makedirs(a.out, exist_ok=True)
    for rid in sorted(runs):
        files = sorted(runs[rid])
        docs = [f for f in files if f.endswith(".json.gz")]
        if not docs:
            continue
        ap = [app_platform(a.store, f) for f in docs]
        name = "%s__%s__%s.tar.gz" % (part({x[0] for x in ap}), part({x[1] for x in ap}), rid)
        path = os.path.join(a.out, name)
        tmp = path + ".part"
        with tarfile.open(tmp, "w:gz") as tf:
            manifest = os.path.join(a.store, "_runs", rid)
            if os.path.isdir(manifest):
                tf.add(manifest, "_runs/" + rid)
            for f in files:
                tf.add(os.path.join(a.store, *f.split("/")), f)
        os.replace(tmp, path)
        print("%s  (%d collecte(s)%s)" % (path, len(docs), "" if os.path.isdir(manifest) else ", sans manifeste"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
