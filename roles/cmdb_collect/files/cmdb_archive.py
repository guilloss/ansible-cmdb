#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Archive les collectes anciennes du magasin : par serveur, seules les N dernières restent en place.

    python3 roles/cmdb_collect/files/cmdb_archive.py store                 # garde les 2 dernières
    python3 roles/cmdb_collect/files/cmdb_archive.py store --keep 3 --archive /data/archive
    python3 roles/cmdb_collect/files/cmdb_archive.py store --dry-run       # affiche sans déplacer

Les fichiers d'un passage plus ancien (<run_id>.json.gz, .ansible_facts.json, .error.json) sont
déplacés, jamais supprimés, vers <archive>/<même chemin relatif> (par défaut <magasin>/_archive).
latest.json.gz, les manifestes (_runs) et les lots (_lots) ne bougent pas.

La consolidation lit la dernière collecte de chaque serveur et l'avant-dernière (évolutions) :
en garder deux ne change rien au résultat. Elle ignore le répertoire _archive."""
import argparse
import os
import re
import shutil
import sys
import time

SUFFIXES = (".json.gz", ".ansible_facts.json", ".error.json")
SKIP = ("_runs", "_lots", "_archive")
STD_RID = re.compile(r"^\d{8}T\d{6}Z-[0-9A-Za-z]+$")


def run_of(name):
    """(run_id, suffixe) d'un fichier de collecte horodaté, sinon None."""
    if name.startswith("latest."):
        return None
    for s in SUFFIXES:
        if name.endswith(s) and len(name) > len(s):
            return name[:-len(s)], s
    return None


def order(d, rid):
    """Clé chronologique : le run_id standard commence par la date UTC ; un run_id imposé
    (-e cmdb_run_id=...) est daté par la date de modification de sa collecte."""
    if STD_RID.match(rid):
        return rid
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(os.path.getmtime(os.path.join(d, rid + ".json.gz")))) + "~" + rid


def plan(store, keep, archive=None):
    """[(source, chemin relatif)] des fichiers à déplacer."""
    moves, arch = [], os.path.abspath(archive) if archive else None
    for d, dirs, files in os.walk(store):
        if os.path.abspath(d) == os.path.abspath(store):
            dirs[:] = [x for x in dirs if x not in SKIP]
        dirs[:] = [x for x in dirs if os.path.abspath(os.path.join(d, x)) != arch]
        dirs.sort()
        runs = {}
        for f in files:
            r = run_of(f)
            if r:
                runs.setdefault(r[0], []).append(f)
        done = sorted((order(d, rid), rid) for rid, fs in runs.items() if rid + ".json.gz" in fs)
        if len(done) <= keep:
            continue
        limit = done[-keep][0]
        for rid, fs in runs.items():
            # passages antérieurs au plus ancien gardé, y compris les traces d'échec sans collecte
            key = order(d, rid) if rid + ".json.gz" in fs else (rid if STD_RID.match(rid) else None)
            if key is not None and key < limit:
                rel = os.path.relpath(d, store)
                moves += [(os.path.join(d, f), os.path.join(rel, f)) for f in sorted(fs)]
    return sorted(moves)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Garder les N dernières collectes de chaque serveur, archiver les autres")
    ap.add_argument("store", help="magasin des collectes (store/)")
    ap.add_argument("--keep", type=int, default=2, help="collectes gardées par serveur (défaut : 2)")
    ap.add_argument("--archive", help="répertoire d'archive (défaut : <magasin>/_archive)")
    ap.add_argument("--dry-run", action="store_true", help="afficher sans déplacer")
    a = ap.parse_args(argv)
    if a.keep < 1:
        print("ERREUR --keep doit valoir au moins 1", file=sys.stderr)
        return 2
    if not os.path.isdir(a.store):
        print("ERREUR magasin introuvable : %s" % a.store, file=sys.stderr)
        return 2
    archive = a.archive or os.path.join(a.store, "_archive")
    moves = plan(a.store, a.keep, archive)
    for src, rel in moves:
        dst = os.path.join(archive, rel)
        if a.dry_run:
            print("à archiver : %s" % src)
            continue
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.move(src, dst)
    if moves:
        print("%d fichier(s) %s vers %s" % (len(moves), "à déplacer" if a.dry_run else "déplacé(s)", archive))
    else:
        print("Rien à archiver (au plus %d collecte(s) par serveur)" % a.keep)
    return 0


if __name__ == "__main__":
    sys.exit(main())
