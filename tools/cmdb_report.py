#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cmdb_report.py - Rapport HTML consolidé, autonome et interrogeable.

Produit un fichier HTML unique (aucune ressource externe : utilisable sur un poste
sans accès Internet) à partir de la base cmdb.sqlite. Les données sont embarquées
compressées (gzip + base64) et décompressées par le navigateur
(DecompressionStream : Firefox >= 113, Chrome/Edge >= 80, Safari >= 16.4).

Usage autonome : cmdb_report.py <cmdb.sqlite> <rapport.html> [--exclude-categories go-module,os-package]
Appelé automatiquement par cmdb_build.py.
"""
import argparse
import base64
import csv
import datetime as dt
import gzip
import json
import os
import sqlite3
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATE = os.path.join(HERE, "cmdb_report_template.html")


# Réglages PHP repris dans le rapport ; tous les autres restent dans runtime_settings
PHP_KEYS = ("PHP Version", "Server API", "Loaded Configuration File", "expose_php", "display_errors", "allow_url_fopen", "allow_url_include",
            "disable_functions", "open_basedir", "memory_limit", "upload_max_filesize", "post_max_size", "max_execution_time",
            "session.cookie_secure", "session.cookie_httponly", "opcache.enable", "date.timezone")


def table(db, sql, params=()):
    cur = db.execute(sql, params)
    return {"cols": [c[0] for c in cur.description], "rows": [list(r) for r in cur]}


SW_COMP = ["category", "ecosystem", "family", "name", "version", "evidence", "managed", "owner_pkg", "purl", "cpe"]


def software_tables(db, exclude_categories=()):
    """Logiciels sous forme compacte, sans perte : c'est de loin la table la plus volumineuse.

    Un composant identique sur plusieurs serveurs n'est stocké qu'une fois, un chemin est
    découpé en répertoire et nom de fichier, et toutes les chaînes sont dédoublonnées.
    Listes à plat, décodées par le rapport (voir swVal) :
      rows  : app, platform, host, composant, emplacement (5 entiers par ligne)
      comps : les champs de SW_COMP (managed vaut 0 ou 1, les autres sont des index de strings)
      locs  : répertoire (-1 si le chemin n'a pas de « / »), nom de fichier"""
    strings, index = [], {}

    def si(v):
        v = "" if v is None else str(v)
        i = index.get(v)
        if i is None:
            i = index[v] = len(strings)
            strings.append(v)
        return i

    comps, comp_index, locs, loc_index, rows = [], {}, [], {}, []
    cols = ["app", "platform", "host", "location"] + SW_COMP
    where = ""
    if exclude_categories:
        where = " WHERE category NOT IN (%s)" % ",".join("?" * len(exclude_categories))
    for r in db.execute("SELECT %s FROM software%s" % (", ".join(cols), where), tuple(exclude_categories)):
        comp = tuple((1 if v else 0) if k == "managed" else si(v) for k, v in zip(SW_COMP, r[4:]))
        c = comp_index.get(comp)
        if c is None:
            c = comp_index[comp] = len(comp_index)
            comps.extend(comp)
        path = "" if r[3] is None else str(r[3])
        l = loc_index.get(path)
        if l is None:
            l = loc_index[path] = len(loc_index)
            head, sep, tail = path.rpartition("/")
            locs.extend((si(head) if sep else -1, si(tail)))
        rows.extend((si(r[0]), si(r[1]), si(r[2]), c, l))
    return {"cols": ["app", "platform", "host", "category", "ecosystem", "family", "name", "version", "location", "evidence",
                     "managed", "owner_pkg", "purl", "cpe"],
            "comp_cols": SW_COMP, "strings": strings, "comps": comps, "locs": locs, "rows": rows,
            "excluded": list(exclude_categories)}


def build_report(dbpath, outpath, matrix_csv=None, exclude_categories=(), build_version="", dossiers=None):
    db = sqlite3.connect(dbpath)
    K = "app, platform, host"   # clé de chaque serveur : un même hôte peut servir plusieurs applications
    data = {
        "generated": dt.datetime.now().strftime("%d/%m/%Y %H:%M"),
        "build_version": build_version,
        "dossiers": dossiers or {},
        "hosts": table(db, "SELECT * FROM hosts ORDER BY " + K),
        "interfaces": table(db, "SELECT * FROM interfaces ORDER BY %s, ifname" % K),
        "addresses": table(db, "SELECT %s, ifname, family, cidr, scope, label, mac FROM addresses ORDER BY %s, ifname" % (K, K)),
        "disks": table(db, "SELECT * FROM disks ORDER BY %s, name" % K),
        "filesystems": table(db, "SELECT %s, mountpoint, device, fstype, size_gb, used_gb, free_gb, used_pct, free_pct, "
                                 "inodes_used_pct, network FROM filesystems ORDER BY %s, mountpoint" % (K, K)),
        "pci": table(db, "SELECT %s, slot, class, vendor, device, driver FROM pci_devices ORDER BY %s, slot" % (K, K)),
        "fc": table(db, "SELECT * FROM fc_hosts ORDER BY %s, name" % K),
        "memory": table(db, "SELECT * FROM memory_modules ORDER BY %s, locator" % K),
        "listening": table(db, "SELECT %s, proto, address, port, process, user, exe, exe_managed FROM v_listening_detail "
                               "ORDER BY %s, port" % (K, K)),
        "services": table(db, "SELECT %s, unit, active, sub, unit_file_state, user, description FROM services "
                              "WHERE active = 'active' ORDER BY %s, unit" % (K, K)),
        "containers": table(db, "SELECT %s, engine, kind, name, image, digest, status FROM containers ORDER BY %s" % (K, K)),
        "cpu_vulns": table(db, "SELECT %s, name, status FROM cpu_vulnerabilities ORDER BY %s, name" % (K, K)),
        "java_risky": table(db, "SELECT %s, archive, marker FROM v_java_risky ORDER BY %s" % (K, K)),
        "restart": table(db, "SELECT %s, pid, user, comm, exe, deleted_files_count FROM v_restart_needed" % K),
        "deleted_running": table(db, "SELECT %s, family, version, location FROM software "
                                     "WHERE evidence LIKE 'strings:process_exe_deleted%%' AND category = 'runtime'" % K),
        "errors": table(db, "SELECT %s, section, error FROM collect_errors" % K),
        # Dernier passage de chaque serveur quand il n'a pas abouti (injoignable, échec) : la
        # collecte affichée pour ce serveur est alors plus ancienne, ou absente.
        "runs_failed": table(db, """
            SELECT r.app, r.platform, r.host, r.status, r.started_at, r.run_id, r.detail,
                   h.collected_at AS last_ok
            FROM runs r LEFT JOIN hosts h ON h.app = r.app AND h.platform = r.platform AND h.host = r.host
            WHERE r.status != 'ok' AND r.started_at = (SELECT MAX(started_at) FROM runs x
                  WHERE x.app = r.app AND x.platform = r.platform AND x.host = r.host)
            ORDER BY r.app, r.platform, r.host"""),
        "oracle_homes": table(db, "SELECT * FROM oracle_homes ORDER BY %s, home" % K),
        "oracle_patches": table(db, "SELECT * FROM oracle_patches ORDER BY %s, home, patch_date DESC" % K),
        "db_instances": table(db, "SELECT * FROM db_instances ORDER BY %s, engine, instance" % K),
        "oracle_licence": table(db, "SELECT * FROM oracle_licence ORDER BY %s" % K),
        "links": table(db, "SELECT * FROM db_links ORDER BY engine, server_host, client_host"),
        "modules": table(db, "SELECT * FROM service_modules ORDER BY %s, product, module" % K),
        "endpoints": table(db, "SELECT * FROM endpoints ORDER BY %s, product, kind, port" % K),
        "crypto_files": table(db, "SELECT * FROM crypto_files ORDER BY %s, path" % K),
        "crypto_certs": table(db, "SELECT * FROM crypto_certs ORDER BY days_left"),
        "runtime_services": table(db, "SELECT * FROM runtime_services ORDER BY %s, port" % K),
        "php_settings": table(db, "SELECT app, platform, host, runtime, binary, key, value FROM runtime_settings WHERE key IN (%s) "
                                  "ORDER BY %s, binary, key" % (",".join("'%s'" % k for k in PHP_KEYS), K)),
        "changes": table(db, "SELECT * FROM changes ORDER BY to_at DESC, %s, kind LIMIT 50000" % K),
        "eol": table(db, "SELECT * FROM eol_status ORDER BY days_left"),
        "cert_usage": table(db, "SELECT * FROM cert_usage ORDER BY days_left"),
        "certs_shared": table(db, "SELECT * FROM v_certs_shared"),
        "flows": table(db, "SELECT * FROM app_flows"),
        "drift": table(db, "SELECT * FROM drift ORDER BY app, scope, kind, item"),
        "hardening": table(db, "SELECT * FROM hardening_results ORDER BY %s, ref" % K),
        "hardening_scores": table(db, "SELECT * FROM hardening_scores ORDER BY %s" % K),
        "anssi": table(db, "SELECT * FROM anssi_recommendations"),
    }
    data["sw"] = software_tables(db, exclude_categories)
    if matrix_csv and os.path.exists(matrix_csv):
        with open(matrix_csv, encoding="utf-8") as f:
            m = list(csv.reader(f, delimiter=";"))
        data["matrix"] = {"cols": m[0] if m else [], "rows": m[1:]}
    else:
        data["matrix"] = {"cols": [], "rows": []}
    db.close()

    payload = base64.b64encode(gzip.compress(json.dumps(data, separators=(",", ":"), ensure_ascii=False)
                                             .encode("utf-8"), 9)).decode("ascii")
    with open(TEMPLATE, encoding="utf-8") as f:
        html = f.read()
    html = html.replace("__CMDB_DATA__", payload)
    with open(outpath, "w", encoding="utf-8") as f:
        f.write(html)
    return {"software_rows": len(data["sw"]["rows"]) // 5, "strings": len(data["sw"]["strings"]), "bytes": len(html)}


def main():
    ap = argparse.ArgumentParser(description="Rapport HTML consolidé CMDB")
    ap.add_argument("db")
    ap.add_argument("out")
    ap.add_argument("--matrix")
    ap.add_argument("--exclude-categories", default="")
    a = ap.parse_args()
    st = build_report(a.db, a.out, a.matrix, [c for c in a.exclude_categories.split(",") if c])
    print("%s : %d composants, %.1f Mo" % (a.out, st["software_rows"], st["bytes"] / 1e6))


if __name__ == "__main__":
    sys.exit(main())
