#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Corrige les étiquettes (application, plate-forme, étiquettes libres) d'un lot de collecte mal étiqueté.

    python3 tools/cmdb_retag.py lots/APPDEMO__prod__20261112T090000Z-1a2b.tar.gz            # contenu du lot
    python3 tools/cmdb_retag.py lots/APPDEMO__prod__20261112T090000Z-1a2b.tar.gz --platform preprod
    python3 tools/cmdb_retag.py LOT --platform recette --host 'rec-*'            # une partie des serveurs
    python3 tools/cmdb_retag.py LOT --app APPDEMO --tag site=Paris --untag squad -n   # simulation
    python3 tools/cmdb_retag.py LOT --platform preprod -o /depot/corrige.tar.gz         # lot d'origine intact

Ce qui est réécrit, pour chaque collecte retenue par les filtres (--host, --only-app, --only-platform) :
  * meta.tags du document <app>/<pf>/<hôte>/<run_id>.json.gz, et son chemin dans le lot (faits Ansible
    du même répertoire compris) ; l'étiquetage d'origine est gardé dans meta.retag (historique) ;
  * le statut de l'hôte dans le manifeste _runs/<run_id>/<app>__<pf>__<hôte>.json (app, platform, tags,
    file), renommé lui aussi ; les hôtes injoignables, sans collecte, sont corrigés de la même façon.
Le reste du lot (en-tête _run.json, autres collectes) est recopié tel quel.

Sans -o, le lot corrigé prend le nom que la collecte lui aurait donné (<app>__<pf>__<run_id>.tar.gz) dans
le répertoire du lot, et l'original est renommé en <lot>.orig (--no-backup : supprimé). Il ne doit pas
rester à côté sous un nom en .tar.gz : la consolidation lirait les deux et compterait les serveurs deux fois.

Sans option de correction : liste le contenu du lot (hôtes, application, plate-forme, étiquettes)."""
import argparse
import datetime as dt
import fnmatch
import gzip
import io
import json
import os
import re
import sys
import tarfile

TAG_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")   # cmdb_tag_regex du rôle
RESERVED = ("app", "platform")
NA = "NA"


def part(values):
    """Comme finish.yml : valeurs jointes par « + », au-delà de trois « multi »."""
    values = sorted(set(v for v in values if v))
    return "multi" if len(values) > 3 else "+".join(values) or NA


def kv(text):
    if "=" not in text:
        raise argparse.ArgumentTypeError("CLE=VALEUR attendu : %s" % text)
    k, v = text.split("=", 1)
    for x in (k, v):
        if not TAG_RX.match(x):
            raise argparse.ArgumentTypeError("« %s » : lettres, chiffres, . _ - seulement (64 caractères au plus)" % x)
    if k in RESERVED:
        raise argparse.ArgumentTypeError("%s : utiliser --%s" % (k, k))
    return k, v


def label(text):
    if not TAG_RX.match(text):
        raise argparse.ArgumentTypeError("« %s » : lettres, chiffres, . _ - seulement (64 caractères au plus)" % text)
    return text


class Lot(object):
    """Contenu d'un lot : collectes (documents) et statuts d'hôtes des manifestes."""

    def __init__(self, path):
        self.path = path
        self.docs = {}       # nom du membre -> document
        self.manifests = {}  # nom du membre -> statut d'hôte
        with tarfile.open(path, "r:*") as tf:
            for m in tf:
                if not m.isfile():
                    continue
                if m.name.endswith(".json.gz") and os.path.basename(m.name) != "latest.json.gz":
                    try:
                        self.docs[m.name] = json.loads(gzip.decompress(tf.extractfile(m).read()).decode("utf-8"))
                    except (OSError, ValueError, EOFError) as e:
                        sys.exit("ERREUR %s:%s illisible (%s) : lot non modifié" % (path, m.name, e))
                elif self.is_manifest(m.name):
                    try:
                        st = json.loads(tf.extractfile(m).read().decode("utf-8"))
                    except ValueError as e:
                        sys.exit("ERREUR %s:%s illisible (%s) : lot non modifié" % (path, m.name, e))
                    if isinstance(st, dict) and st.get("host"):
                        self.manifests[m.name] = st

    @staticmethod
    def is_manifest(name):
        parts = name.split("/")
        return len(parts) >= 3 and parts[-3] == "_runs" and name.endswith(".json") and parts[-1] != "_run.json"


def doc_info(doc):
    meta = doc.get("meta") or {}
    tags = meta.get("tags") or {}
    return (tags.get("app") or NA, tags.get("platform") or NA, meta.get("host_label") or "",
            (doc.get("os") or {}).get("hostname") or "", meta.get("run_id") or "", tags)


def selected(a, app, pf, names):
    if a.only_app and not any(fnmatch.fnmatchcase(app, p) for p in a.only_app):
        return False
    if a.only_platform and not any(fnmatch.fnmatchcase(pf, p) for p in a.only_platform):
        return False
    if a.host:
        names = [n for n in names if n]
        names += [n.split(".")[0] for n in names]
        return any(fnmatch.fnmatchcase(n, p) for n in names for p in a.host)
    return True


def new_tags(a, tags):
    t = dict(tags)
    if a.app:
        t["app"] = a.app
    if a.platform:
        t["platform"] = a.platform
    for k in a.untag:
        t.pop(k, None)
    for k, v in a.tag:
        t[k] = v
    return t


def move_dir(path, old_app, old_pf, app, pf):
    """<…>/<app>/<pf>/<hôte>/fichier -> mêmes chemins avec les nouvelles valeurs ; autre forme : inchangé."""
    parts = path.split("/")
    if len(parts) >= 4 and parts[-4] == old_app and parts[-3] == old_pf:
        parts[-4], parts[-3] = app, pf
    return "/".join(parts)


def plan(a, lot):
    """Corrections à faire : {membre: (nouveau nom, nouveau contenu)}, répertoires déplacés, lignes à afficher."""
    changes, moved_dirs, lines = {}, {}, []
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    by_host = {}   # (run_id, host_label, app, pf) -> (hostname, nouvelles étiquettes, nouveau chemin du document)
    for name in sorted(lot.docs):
        doc = lot.docs[name]
        app, pf, alias, hostname, rid, tags = doc_info(doc)
        if not selected(a, app, pf, [alias, hostname, name.split("/")[-2] if "/" in name else ""]):
            lines.append(("=", alias or hostname, app, pf, tags, tags))
            continue
        t = new_tags(a, tags)
        if t == tags:
            lines.append(("=", alias or hostname, app, pf, tags, tags))
            continue
        meta = doc.setdefault("meta", {})
        meta["tags"] = t
        meta.setdefault("retag", []).append({"at": now, "tool": "cmdb_retag.py", "before": tags})
        dst = move_dir(name, app, pf, t.get("app") or NA, t.get("platform") or NA)
        changes[name] = (dst, gzip.compress(json.dumps(doc, ensure_ascii=False).encode("utf-8")))
        if os.path.dirname(dst) != os.path.dirname(name):
            moved_dirs[os.path.dirname(name)] = os.path.dirname(dst)
        by_host[(rid, alias, app, pf)] = (hostname, t, dst)
        lines.append(("*", alias or hostname, app, pf, tags, t))
    for name in sorted(lot.manifests):
        st = lot.manifests[name]
        app, pf, host = st.get("app") or NA, st.get("platform") or NA, st.get("host")
        known = by_host.get((st.get("run_id") or "", host, app, pf))
        if known:
            t, dst_doc = known[1], known[2]
        else:
            old = dict(st.get("tags") or {}, app=app, platform=pf)
            # Hôte sans collecte (injoignable) : mêmes filtres ; avec collecte non retenue : inchangé
            has_doc = any(doc_info(d)[2] == host and doc_info(d)[4] == (st.get("run_id") or "") for d in lot.docs.values())
            if has_doc or not selected(a, app, pf, [host]):
                continue
            t = new_tags(a, old)
            if t == old:
                continue
            dst_doc = None
            lines.append(("*", host + " (sans collecte : %s)" % (st.get("status") or "?"), app, pf, old, t))
        st = dict(st)
        st["app"], st["platform"] = t.get("app"), t.get("platform")
        st["tags"] = dict((k, v) for k, v in t.items() if k not in RESERVED)
        if dst_doc and st.get("file"):
            st["file"] = dst_doc
        dst = "%s/%s__%s__%s.json" % (os.path.dirname(name), t.get("app") or NA, t.get("platform") or NA, host)
        changes[name] = (dst, (json.dumps(st, ensure_ascii=False, indent=4) + "\n").encode("utf-8"))
    return changes, moved_dirs, lines


def show(lines):
    fmt = lambda tags: ", ".join("%s=%s" % kv for kv in sorted(tags.items()) if kv[0] not in RESERVED)
    for mark, host, app, pf, before, after in lines:
        extra = fmt(before)
        if mark == "*":
            dest = "%s/%s" % (after.get("app") or NA, after.get("platform") or NA)
            extra = "%s -> %s" % (extra or "-", fmt(after) or "-") if fmt(after) != extra else extra
            print("  * %-40s %s/%s -> %s%s" % (host, app, pf, dest, ("  [%s]" % extra) if extra else ""))
        else:
            print("    %-40s %s/%s%s" % (host, app, pf, ("  [%s]" % extra) if extra else ""))


def rewrite(src, dst, changes, moved_dirs):
    """Recopie le lot en appliquant les corrections ; écrit dans dst.part puis renomme."""
    tmp = dst + ".part"
    written = set()
    with tarfile.open(src, "r:*") as tin, tarfile.open(tmp, "w:gz") as tout:
        for m in tin:
            name = m.name
            if m.isdir():
                if name.rstrip("/") in moved_dirs:
                    continue   # recréé à l'extraction par les fichiers qu'il contient
                tout.addfile(m)
                continue
            if name in changes:
                new, data = changes[name]
            else:
                new = moved_dirs.get(os.path.dirname(name))
                new = new + "/" + os.path.basename(name) if new else name
                data = tin.extractfile(m).read() if m.isfile() else None
            if new in written:
                os.unlink(tmp)
                sys.exit("ERREUR : deux fichiers aboutiraient à %s (hôte déjà présent sous ces étiquettes ?) : lot non modifié" % new)
            written.add(new)
            info = tarfile.TarInfo(new) if m.isfile() else m
            if m.isfile():
                info.size, info.mode, info.mtime = len(data), m.mode, m.mtime
                info.uid, info.gid, info.uname, info.gname = m.uid, m.gid, m.uname, m.gname
                tout.addfile(info, io.BytesIO(data))
            else:
                info.name = new
                tout.addfile(info)
    os.replace(tmp, dst)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0], epilog=__doc__.split("\n", 1)[1],
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("lot", help="Lot de collecte (.tar.gz)")
    g = p.add_argument_group("corrections")
    g.add_argument("--app", type=label, help="Nouvelle application")
    g.add_argument("--platform", "--pf", type=label, help="Nouvelle plate-forme")
    g.add_argument("--tag", type=kv, action="append", default=[], help="Étiquette libre CLE=VALEUR à poser (répétable)")
    g.add_argument("--untag", action="append", default=[], metavar="CLE", help="Étiquette libre à retirer (répétable)")
    f = p.add_argument_group("collectes concernées (par défaut : toutes)")
    f.add_argument("--host", action="append", default=[], metavar="MOTIF",
                   help="Nom d'inventaire ou hostname, motif shell accepté ('web-pp*') ; répétable")
    f.add_argument("--only-app", action="append", default=[], metavar="MOTIF", help="Seulement les collectes de cette application")
    f.add_argument("--only-platform", action="append", default=[], metavar="MOTIF", help="Seulement les collectes de cette plate-forme")
    o = p.add_argument_group("sortie")
    o.add_argument("-o", "--output", help="Lot corrigé écrit ici ; le lot d'origine n'est pas touché")
    o.add_argument("--no-backup", action="store_true", help="Sans -o : supprimer le lot d'origine au lieu de le garder en .orig")
    o.add_argument("--force", action="store_true", help="Écraser un fichier de sortie existant")
    o.add_argument("-n", "--dry-run", action="store_true", help="Afficher les corrections sans rien écrire")
    a = p.parse_args(argv)
    for k in a.untag:
        if k in RESERVED:
            p.error("--untag %s : l'application et la plate-forme ne se retirent pas" % k)

    if not os.path.isfile(a.lot):
        print("Lot introuvable : %s" % a.lot, file=sys.stderr)
        return 2
    try:
        lot = Lot(a.lot)
    except (OSError, tarfile.TarError) as e:
        print("ERREUR %s : %s" % (a.lot, e), file=sys.stderr)
        return 2
    if not lot.docs and not lot.manifests:
        print("Aucune collecte dans %s" % a.lot, file=sys.stderr)
        return 1
    changes, moved_dirs, lines = plan(a, lot)
    editing = a.app or a.platform or a.tag or a.untag
    print("%s : %d collecte(s), %d statut(s) d'hôte" % (a.lot, len(lot.docs), len(lot.manifests)))
    show(lines)
    if not editing:
        return 0
    if not changes:
        print("Rien à corriger (filtres sans correspondance, ou étiquettes déjà bonnes).")
        return 1

    runs = set(doc_info(d)[4] for d in lot.docs.values()) | set(s.get("run_id") for s in lot.manifests.values())
    runs.discard(None)
    runs.discard("")
    final = {}
    for name, doc in lot.docs.items():
        if name in changes:
            doc = json.loads(gzip.decompress(changes[name][1]).decode("utf-8"))
        final[name] = doc_info(doc)
    if a.output:
        dst = a.output
    else:
        dst = os.path.join(os.path.dirname(a.lot), "%s__%s__%s.tar.gz" % (
            part(i[0] for i in final.values()), part(i[1] for i in final.values()), part(runs) if len(runs) != 1 else next(iter(runs))))
    same = os.path.abspath(dst) == os.path.abspath(a.lot)
    if same and a.output:
        p.error("-o : choisir un autre fichier que le lot d'origine (sans -o, l'original est gardé en .orig)")
    if os.path.exists(dst) and not same and not a.force:
        print("ERREUR %s existe déjà (--force pour l'écraser, ou -o)" % dst, file=sys.stderr)
        return 2
    backup = None if a.output or a.no_backup else a.lot + ".orig"
    if backup and os.path.exists(backup) and not a.force:
        print("ERREUR %s existe déjà (correction déjà faite ? --force pour l'écraser)" % backup, file=sys.stderr)
        return 2
    print("%d fichier(s) du lot corrigé(s)" % len(changes))
    if a.dry_run:
        print("Simulation : %s serait écrit%s" % (dst, ", original gardé en %s" % backup if backup else ""))
        return 0
    out = dst if not same else dst + ".new"
    rewrite(a.lot, out, changes, moved_dirs)
    if not a.output:
        if backup:
            os.replace(a.lot, backup)
        elif not same:
            os.unlink(a.lot)
        if same:
            os.replace(out, dst)
    print("Lot corrigé : %s%s" % (dst, "  (original : %s)" % backup if backup else ""))
    # Lot d'origine encore présent sous son nom de passage (lien dur ou copie faits par la collecte)
    for rid in runs:
        twin = os.path.join(os.path.dirname(a.lot), rid + ".tar.gz")
        if os.path.isfile(twin) and os.path.abspath(twin) not in (os.path.abspath(dst), os.path.abspath(a.lot)):
            print("ATTENTION %s est sans doute l'ancien lot sous son nom d'origine : le retirer, sinon la "
                  "consolidation lira les deux." % twin, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
