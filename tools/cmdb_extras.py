#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cmdb_extras.py - Consolidation : bases de données, services réseau, clés, évolutions.

Complète cmdb_build.py :
  * ExtrasMixin        par hôte : Oracle, instances, modules, points d'entrée, clés,
                       réglages des runtimes, runtimes exposés sur le réseau ;
  * build_db_links     après tous les hôtes : qui parle à quelle base ;
  * build_changes      évolutions entre les deux dernières collectes ;
  * build_eol          fins de support (référentiel cmdb_eol.csv).
"""
import csv
import datetime as dt
import json
import math
import os
import re
import sqlite3

import cmdb_hardening
from cmdb_shell_parse import C

HERE = os.path.dirname(os.path.abspath(__file__))
EOL_FILE = os.path.join(HERE, "cmdb_eol.csv")
EOL_SOON_DAYS = 180
ORACLE_PATCH_OLD_DAYS = 200       # un peu plus de deux trimestres de retard sur les correctifs Oracle

# Tables par hôte : "app, platform" sont ajoutées par cmdb_build.py
SCHEMA_HOST = """
CREATE TABLE oracle_homes (host TEXT, home TEXT, product TEXT, version TEXT, edition TEXT, patch_level TEXT, patch_date TEXT,
  patch_age_days INTEGER, opatch_version TEXT, visibility TEXT, patch_count INTEGER, sources TEXT, present INTEGER,
  in_use INTEGER, behind_fleet INTEGER);
CREATE TABLE oracle_patches (host TEXT, home TEXT, patch_id TEXT, kind TEXT, version TEXT, patch_date TEXT, description TEXT,
  installed_at TEXT);
CREATE TABLE db_instances (host TEXT, engine TEXT, instance TEXT, status TEXT, home TEXT, version TEXT, patch_level TEXT,
  ports TEXT, role TEXT, cluster TEXT, datadir TEXT, evidence TEXT);
CREATE TABLE oracle_licence (host TEXT, editions TEXT, instances INTEGER, arch TEXT, cores INTEGER, sockets INTEGER,
  threads INTEGER, virtualization TEXT, partitioning TEXT, entitled_capacity REAL, core_factor REAL,
  processor_licences_indicative INTEGER, remark TEXT);
CREATE TABLE db_refs (host TEXT, engine TEXT, target TEXT, port INTEGER, database TEXT, alias TEXT, kind TEXT, path TEXT,
  resolved TEXT);
CREATE TABLE service_modules (host TEXT, product TEXT, module TEXT, value TEXT, source TEXT, path TEXT);
CREATE TABLE endpoints (host TEXT, product TEXT, kind TEXT, address TEXT, port INTEGER, server_name TEXT, aliases TEXT,
  location TEXT, root TEXT, tls INTEGER, protocol TEXT, cert TEXT, backend TEXT, path TEXT, listening INTEGER);
CREATE TABLE crypto_files (host TEXT, path TEXT, kind TEXT, has_private_key INTEGER, encrypted INTEGER, key_type TEXT,
  empty_password INTEGER, mode TEXT, owner TEXT, size INTEGER, mtime TEXT, world_readable INTEGER, cert_count INTEGER,
  owner_pkg TEXT, note TEXT);
CREATE TABLE crypto_certs (host TEXT, path TEXT, alias TEXT, subject TEXT, cn TEXT, issuer TEXT, not_before TEXT, not_after TEXT,
  days_left INTEGER, serial TEXT, sans TEXT, sig_alg TEXT, key_alg TEXT, key_bits INTEGER, self_signed INTEGER, is_ca INTEGER,
  sha256 TEXT);
CREATE TABLE runtime_settings (host TEXT, runtime TEXT, binary TEXT, section TEXT, key TEXT, value TEXT);
CREATE TABLE runtime_services (host TEXT, proto TEXT, address TEXT, port INTEGER, exposed INTEGER, pid INTEGER, user TEXT,
  runtime TEXT, version TEXT, process TEXT, app_ref TEXT, options TEXT, exe TEXT);
CREATE TABLE changes (host TEXT, from_run TEXT, to_run TEXT, from_at TEXT, to_at TEXT, kind TEXT, change TEXT, item TEXT,
  before TEXT, after TEXT);
CREATE TABLE hardening_results (host TEXT, rule_id TEXT, ref TEXT, level TEXT, title TEXT, status TEXT, observed TEXT, expected TEXT,
  note TEXT);
CREATE TABLE hardening_scores (host TEXT, level TEXT, ok INTEGER, ko INTEGER, unknown INTEGER, score REAL);
CREATE TABLE cert_usage (host TEXT, product TEXT, kind TEXT, server_name TEXT, port INTEGER, cert_path TEXT, cn TEXT, not_after TEXT,
  days_left INTEGER, state TEXT, name_match INTEGER);
CREATE TABLE eol_status (host TEXT, product TEXT, cycle TEXT, version TEXT, location TEXT, managed INTEGER, eol TEXT,
  extended TEXT, days_left INTEGER, status TEXT);
"""

SCHEMA_GLOBAL = """
CREATE TABLE db_links (client_app TEXT, client_platform TEXT, client_host TEXT, client_addr TEXT, client_process TEXT,
  server_app TEXT, server_platform TEXT, server_host TEXT, server_addr TEXT, engine TEXT, port INTEGER, database TEXT,
  db_user TEXT, link_type TEXT, status TEXT, sources TEXT, evidence TEXT, connections INTEGER);
CREATE INDEX ix_links_client ON db_links(client_app, client_platform, client_host);
CREATE INDEX ix_links_server ON db_links(server_app, server_platform, server_host);
CREATE TABLE app_flows (src_app TEXT, src_platform TEXT, src_host TEXT, src_addr TEXT, dst_app TEXT, dst_platform TEXT, dst_host TEXT,
  dst_addr TEXT, port INTEGER, kind TEXT, detail TEXT, status TEXT);
CREATE TABLE drift (scope TEXT, app TEXT, left_platform TEXT, right_platform TEXT, left_host TEXT, right_host TEXT, kind TEXT, item TEXT,
  left_value TEXT, right_value TEXT);
CREATE TABLE anssi_recommendations (ref TEXT, level TEXT, title TEXT, coverage TEXT, note TEXT);
CREATE VIEW v_hardening_failures AS
  SELECT app, platform, host, ref, level, title, observed, expected FROM hardening_results WHERE status = 'non conforme'
  ORDER BY app, platform, host, ref;
CREATE VIEW v_hardening_by_rule AS
  SELECT rule_id, ref, level, title, SUM(status = 'conforme') AS conformes, SUM(status = 'non conforme') AS non_conformes,
         SUM(status = 'non vérifiable') AS non_verifiables FROM hardening_results GROUP BY rule_id ORDER BY non_conformes DESC;
CREATE VIEW v_oracle_homes_unused AS
  SELECT app, platform, host, home, product, version, patch_level FROM oracle_homes
  WHERE in_use = 0 AND product = 'database';
CREATE VIEW v_oracle_patch_late AS
  SELECT app, platform, host, home, product, version, patch_level, patch_date, patch_age_days, behind_fleet FROM oracle_homes
  WHERE present = 1 AND product IN ('database', 'grid') AND (patch_age_days >= %d OR behind_fleet = 1)
  ORDER BY patch_age_days DESC;
CREATE VIEW v_oracle_patch_unknown AS
  SELECT app, platform, host, home, visibility, sources FROM oracle_homes WHERE visibility != 'complet';
CREATE VIEW v_private_keys AS
  SELECT app, platform, host, path, kind, key_type, encrypted, empty_password, mode, owner, world_readable, cert_count, owner_pkg, note
  FROM crypto_files WHERE has_private_key = 1 OR kind IN ('gskit-kdb', 'gskit-stash', 'oracle-wallet', 'pkcs12', 'illisible');
CREATE VIEW v_private_keys_exposed AS
  SELECT app, platform, host, path, kind, key_type, encrypted, empty_password, mode, owner FROM crypto_files
  WHERE (has_private_key = 1 OR kind IN ('gskit-stash', 'oracle-wallet', 'pkcs12'))
    AND (world_readable = 1 OR empty_password = 1) ORDER BY app, platform, host, path;
CREATE VIEW v_certs_expiring AS
  SELECT app, platform, host, path, alias, cn, subject, issuer, not_after, days_left FROM crypto_certs
  WHERE days_left <= 90 AND COALESCE(is_ca, 0) = 0 ORDER BY days_left;
CREATE VIEW v_certs_shared AS
  SELECT sha256, cn, not_after, days_left, COUNT(DISTINCT host) AS hosts, GROUP_CONCAT(DISTINCT host) AS host_list FROM crypto_certs
  WHERE sha256 IS NOT NULL AND COALESCE(is_ca, 0) = 0 GROUP BY sha256 HAVING COUNT(DISTINCT host) > 1 ORDER BY hosts DESC;
CREATE VIEW v_db_servers AS
  SELECT server_app AS app, server_platform AS platform, server_host AS host, engine, port,
         COUNT(DISTINCT COALESCE(client_host, client_addr)) AS clients, GROUP_CONCAT(DISTINCT database) AS databases
  FROM db_links WHERE server_host IS NOT NULL AND link_type = 'application'
  GROUP BY server_app, server_platform, server_host, engine, port;
CREATE VIEW v_eol_expired AS
  SELECT app, platform, host, product, cycle, version, location, managed, eol, extended, days_left FROM eol_status
  WHERE status = 'expiré' ORDER BY days_left;
""" % ORACLE_PATCH_OLD_DAYS

# -- Oracle -----------------------------------------------------------------
PATCH_KINDS = (
    (r"ojvm|javavm|java vm", "ojvm"), (r"\bocw\b|clusterware", "ocw"), (r"acfs", "acfs"), (r"tomcat", "tomcat"), (r"\bjdk\b", "jdk"),
    (r"dbwlm", "dbwlm"), (r"release update revision", "rur"), (r"release update", "ru"), (r"patch set update", "psu"),
    (r"bundle patch", "bp"),
)
LEVEL_KINDS = ("ru", "rur", "psu", "bp")
ORACLE_VERSION_RX = re.compile(r"(\d+\.\d+\.\d+\.\d+\.\d{6})")
ORACLE_PROC_RX = re.compile(r"^(ora|asm|apx|mdb)_([a-z0-9]+)_(.+)$")


def classify_patch(description):
    """Description d'un correctif -> (nature, version, date ISO)"""
    d = (description or "").lower()
    kind = next((k for rx, k in PATCH_KINDS if re.search(rx, d)), "oneoff" if d else "inconnu")
    m = ORACLE_VERSION_RX.search(description or "")
    version = date = None
    if m:
        version = m.group(1)
        s = version.rsplit(".", 1)[1]
        date = "20%s-%s-%s" % (s[0:2], s[2:4], s[4:6])
    return kind, version, date


def version_key(v):
    return tuple(int(x) for x in re.findall(r"\d+", v or ""))


def edition(raw):
    r = (raw or "").upper().replace(" ", "")
    if r in ("EE", "ENTERPRISE", "ENTERPRISEEDITION") or "ENTERPRISE" in r:
        return "Enterprise"
    if r in ("SE", "SE2", "SEONE", "STANDARD", "STANDARDEDITION") or "STANDARD" in r:
        return "Standard"
    return None


def parse_oratab(text):
    rows = []
    for line in (text or "").splitlines():
        p = line.strip().split(":")
        if len(p) >= 2 and p[0] and not p[0].startswith("#"):
            rows.append((p[0], p[1].rstrip("/"), p[2] if len(p) > 2 else None))
    return rows


# -- Bases de données ---------------------------------------------------------
DB_PROCESSES = (
    (r"^(postgres|postmaster)$", "postgresql"), (r"^(tnslsnr|oracle)", "oracle"), (r"^(mysqld|mariadbd)", "mysql"),
    (r"^mongod$", "mongodb"), (r"^redis-server", "redis"), (r"^sqlservr", "sqlserver"), (r"^db2sysc", "db2"),
    (r"^pgbouncer$", "pgbouncer"), (r"^pgpool", "pgpool"),
)
DEFAULT_PORTS = {5432: "postgresql", 1521: "oracle", 1522: "oracle", 3306: "mysql", 27017: "mongodb", 6379: "redis", 1433: "sqlserver",
                 50000: "db2", 6432: "pgbouncer", 9999: "pgpool"}
PG_BACKEND_RX = re.compile(r"^postgres:\s+(?:[\w./-]+:\s+)?(\S+)\s+(\S+)\s+\[?([0-9A-Fa-f.:]+)\]?\((\d+)\)\s")
PG_WALSENDER_RX = re.compile(r"^postgres:\s+(?:[\w./-]+:\s+)?walsender\s+(\S+)\s+\[?([0-9A-Fa-f.:]+)\]?\((\d+)\)")
PG_VERSION_PATH_RX = re.compile(r"/(?:pgsql-|postgresql/|postgres/)(\d+(?:\.\d+)?)/")
LOOPBACK = ("127.0.0.1", "::1", "localhost")


def db_engine_of(process):
    return next((e for rx, e in DB_PROCESSES if re.match(rx, process or "")), None)


# -- Runtimes exposés ---------------------------------------------------------
RUNTIMES = (
    (r"^java$", "java"), (r"^python[\d.]*$", "python"), (r"^(gunicorn|uwsgi|uvicorn|daphne|celery)", "python"), (r"^node(js)?$", "node"),
    (r"^php(-fpm)?[\d.]*", "php"), (r"^ruby[\d.]*$", "ruby"), (r"^(puma|unicorn|passenger)", "ruby"), (r"^perl[\d.]*$", "perl"),
    (r"^dotnet$", "dotnet"),
)
JVM_OPTION_RX = re.compile(r"^-(Xm[xs]\S+|XX:\+?MaxRAMPercentage\S*|Dcatalina\.base=\S+|Dspring\.profiles\.active=\S+|"
                           r"Djboss\.server\.base\.dir=\S+|Dserver\.port=\S+|Dweblogic\.Name=\S+|javaagent:\S+)$")
PHP_SECTION_RX = re.compile(r"^[A-Za-z][\w .+-]*$")


def runtime_of(process, exe):
    for name in (os.path.basename(exe or ""), process or ""):
        for rx, runtime in RUNTIMES:
            if name and re.match(rx, name):
                return runtime
    return None


def jvm_details(cmdline):
    args = (cmdline or "").split()
    opts = [a for a in args if JVM_OPTION_RX.match(a)]
    ref = None
    for i, a in enumerate(args):
        if a == "-jar" and i + 1 < len(args):
            ref = args[i + 1]
            break
    if ref is None:
        skip = False
        for a in args[1:]:
            if skip:
                skip = False
            elif a in ("-cp", "-classpath", "--class-path", "-m", "--module-path"):
                skip = True
            elif not a.startswith("-"):
                ref = a
                break
    return ref, " ".join(opts) or None


def script_of(cmdline):
    for a in (cmdline or "").split()[1:]:
        if not a.startswith("-"):
            return a
    return None


def parse_phpinfo(text):
    """Sortie filtrée de php -i -> [(section, clé, valeur)]. Une section sans directive décrit une extension."""
    rows, section = [], "PHP"
    for line in (text or "").splitlines():
        s = line.strip()
        if not s:
            continue
        if "=>" not in s:
            if PHP_SECTION_RX.match(s) and s not in ("phpinfo()", "Directive", "Configuration", "PHP License"):
                section = s
            continue
        p = [x.strip() for x in s.split("=>")]
        if p[0] in ("Directive", "Variable"):
            continue
        rows.append((section, p[0], p[1] if len(p) > 1 else None))
    return rows


def parse_php_m(text):
    return sorted(set(l.strip().lower() for l in (text or "").splitlines() if l.strip() and not l.startswith("[")))


def parse_httpd_m(text):
    return [m.group(1) for m in (re.match(r"^\s*(\w+_module)\s+\((?:static|shared)\)", l) for l in (text or "").splitlines()) if m]


def parse_nginx_v(text):
    mods = re.findall(r"--with-([\w-]+_module)", text or "")
    mods += [os.path.basename(x.rstrip("/")) for x in re.findall(r"--add(?:-dynamic)?-module=(\S+)", text or "")]
    return sorted(set(mods))


def days_until(iso, today):
    try:
        return (dt.date(int(iso[0:4]), int(iso[5:7]), int(iso[8:10])) - today).days
    except (TypeError, ValueError):
        return None


class ExtrasMixin(object):
    """Méthodes ajoutées au Builder de cmdb_build.py. Lit doc, alimente self.add()/self.soft()."""

    today = None

    def extras(self, host, doc):
        self.today = self.today or dt.date.today()
        fs = doc.get("filesystem") or {}
        procs = (doc.get("processes") or {}).get("list") or []
        net = doc.get("network") or {}
        ports = {}
        for l in net.get("listening") or []:
            ports.setdefault(l.get("pid"), []).append(l.get("port"))
        listening = set(l.get("port") for l in net.get("listening") or [])
        homes = self.oracle_homes(host, doc, procs)
        self.db_instances(host, doc, procs, ports, net, homes)
        self.oracle_licence(host, doc, homes)
        self.db_references(host, doc, fs, procs)
        self.modules(host, doc, fs)
        self.endpoints(host, doc, fs, listening)
        self.crypto(host, fs)
        self.runtime_details(host, doc, procs, net)
        if cmdb_hardening.is_linux(doc):
            for r, status, seen in cmdb_hardening.evaluate(doc, self.hardening_rules()):
                self.add("hardening_results", (host, r["id"], r["ref"], r["level"], r["title"], status, seen, r["expected"], r["note"] or None))

    _rules = None

    @classmethod
    def hardening_rules(cls):
        if ExtrasMixin._rules is None:
            ExtrasMixin._rules = cmdb_hardening.load_rules()
        return ExtrasMixin._rules

    # -- Oracle -----------------------------------------------------------
    def oracle_homes(self, host, doc, procs):
        ora = doc.get("oracle") or {}
        oratab = parse_oratab(ora.get("oratab"))
        used = set(h for _s, h, _a in oratab)
        for p in procs:
            env = p.get("env") or {}
            if env.get("ORACLE_HOME"):
                used.add(env["ORACLE_HOME"].rstrip("/"))
            m = re.match(r"^(/.+)/bin/(?:tnslsnr|oracle)$", p.get("exe") or (p.get("cmdline") or "").split(" ")[0])
            if m:
                used.add(m.group(1))
        out = {}
        crs = set(h.get("loc") for h in ora.get("central_inventory_homes") or [] if h.get("crs"))
        crs.add((ora.get("olr_loc") or {}).get("crs_home"))
        for f in ora.get("homes") or []:
            home = f["home"]
            product = f.get("product") or ("grid" if home in crs else None)
            version = f.get("version")
            if not version:
                m = re.search(r"/(\d+(?:\.\d+)+)/", home + "/")
                version = m.group(1) if m else None
            best = None
            for p in f.get("patches") or []:
                kind, ver, date = classify_patch(p.get("description"))
                self.add("oracle_patches", (host, home, p.get("id"), kind, ver, date, p.get("description"), p.get("installed_at")))
                if kind in LEVEL_KINDS and ver and (best is None or version_key(ver) > version_key(best[0])):
                    best = (ver, date)
            level, date = best or (None, None)
            age = -days_until(date, self.today) if date else None
            self.add("oracle_homes", (host, home, product, version, edition(f.get("install_type")), level, date, age, f.get("opatch_version"),
                                      f.get("visibility"), len(f.get("patches") or []), ",".join(f.get("sources") or []),
                                      1 if f.get("exists", True) else 0, 1 if home in used else 0, 0))
            shown = level or version
            if product in ("database", "grid", "client") and shown:
                fam = {"database": "oracle-database", "grid": "oracle-grid", "client": "oracle-client"}[product]
                cpe = "cpe:2.3:a:oracle:database_server:%s:*:*:*:*:*:*:*" % shown if product == "database" else None
                self.soft(host, "runtime", "oracle", fam, fam, shown, home, "inventaire Oracle", managed=0, cpe=cpe,
                          extra={"visibility": f.get("visibility"), "base_version": version})
            out[home] = {"product": product, "version": version, "level": level, "edition": edition(f.get("install_type")), "facts": f}
        return out

    def db_instances(self, host, doc, procs, ports, net, homes):
        ora = doc.get("oracle") or {}
        oratab = parse_oratab(ora.get("oratab"))
        vis = (doc.get("meta") or {}).get("visibility") or {}
        blind = bool(vis.get("proc_hidepid")) or not procs
        running, roles, cluster = {}, {}, None
        for p in procs:
            name = (p.get("cmdline") or p.get("comm") or "").split(" ")[0]
            m = ORACLE_PROC_RX.match(name)
            if m:
                prefix, proc, sid = m.groups()
                if proc == "pmon":
                    env = p.get("env") or {}
                    home = (env.get("ORACLE_HOME") or "").rstrip("/") or None
                    if not home:
                        hm = re.match(r"^(/.+)/bin/oracle$", p.get("exe") or "")
                        home = hm.group(1) if hm else None
                    running[sid] = {"home": home, "kind": prefix}
                elif proc in ("mrp0", "pr00"):
                    roles[sid] = "standby"
                elif proc == "lms0":
                    cluster = "RAC"
                elif proc == "dmon":
                    roles.setdefault(sid, "broker Data Guard")
            elif re.match(r"^(ocssd|crsd|ohasd)", os.path.basename(name)):
                cluster = cluster or "Grid"
        listeners = {}
        for home, h in homes.items():
            for l in h["facts"].get("listeners") or []:
                if l.get("port"):
                    listeners.setdefault(home, set()).add(l["port"])
        declared = dict((s, (h, a)) for s, h, a in oratab)
        for sid in sorted(set(declared) | set(running)):
            d = declared.get(sid)
            r = running.get(sid)
            home = (r or {}).get("home") or (d[0] if d else None)
            status = "démarrée" if r else ("inconnu" if blind else "arrêtée")
            if r and not d:
                status = "démarrée, hors oratab"
            h = homes.get(home) or {}
            kind = "asm" if sid.startswith("+") or (r or {}).get("kind") == "asm" else "instance"
            self.add("db_instances", (host, "oracle", sid, status, home, h.get("version"), h.get("level"),
                                      " ".join(str(x) for x in sorted(listeners.get(home) or [])) or None,
                                      kind if kind == "asm" else roles.get(sid, "primaire" if r else None), cluster, None,
                                      "oratab" if d and not r else ("processus" if not d else "oratab+processus")))
        # PostgreSQL : un processus maître par instance ; ses fils portent leur rôle dans leur titre
        by_pid = dict((p.get("pid"), p) for p in procs)
        for p in procs:
            comm = os.path.basename((p.get("cmdline") or p.get("comm") or "").split(" ")[0])
            if comm not in ("postgres", "postmaster"):
                other = db_engine_of(p.get("comm") or comm)
                if other in ("mysql", "mongodb", "redis") and (by_pid.get(p.get("ppid")) or {}).get("comm") != p.get("comm"):
                    dm = re.search(r"--(?:datadir|dbpath)[= ](\S+)", p.get("cmdline") or "")
                    self.add("db_instances", (host, other, p.get("comm"), "démarrée", None, None, None,
                                              " ".join(str(x) for x in sorted(set(ports.get(p.get("pid")) or []))) or None, None, None,
                                              dm.group(1) if dm else None, "processus"))
                continue
            cmd = p.get("cmdline") or ""
            if cmd.startswith("postgres:"):
                continue
            dm = re.search(r"\s-D\s*(\S+)", cmd)
            kids = [c.get("cmdline") or "" for c in procs if c.get("ppid") == p.get("pid")]
            role = "standby" if any("walreceiver" in k or "startup recovering" in k for k in kids) else "primaire"
            vm = PG_VERSION_PATH_RX.search((p.get("exe") or cmd.split(" ")[0]) + "/") or PG_VERSION_PATH_RX.search(cmd)
            pm = re.search(r"\s-p\s*(\d+)", cmd)
            pp = sorted(set(ports.get(p.get("pid")) or [])) or ([int(pm.group(1))] if pm else [])
            self.add("db_instances", (host, "postgresql", dm.group(1) if dm else "postgres", "démarrée", None, vm.group(1) if vm else None, None,
                                      " ".join(str(x) for x in pp) or None, role, None, dm.group(1) if dm else None, "processus"))

    def oracle_licence(self, host, doc, homes):
        dbs = [h for h in homes.values() if h["product"] == "database"]
        if not dbs:
            return
        hw = doc.get("hardware") or {}
        lk = hw.get("lscpu_kv") or {}
        lpar = hw.get("lparstat") or ((doc.get("os") or {}).get("aix") or {}).get("lparstat") or {}
        arch = ((doc.get("os") or {}).get("uname") or {}).get("machine")
        ints = {}
        for k, name in (("sockets", "Socket(s)"), ("cps", "Core(s) per socket"), ("tpc", "Thread(s) per core")):
            try:
                ints[k] = int(lk.get(name))
            except (TypeError, ValueError):
                ints[k] = None
        cores = ints["sockets"] * ints["cps"] if ints["sockets"] and ints["cps"] else None
        threads = cores * ints["tpc"] if cores and ints["tpc"] else None
        virt = hw.get("virtualization") if hw.get("virtualization") not in (None, "none") else None
        entitled = None
        try:
            entitled = float(lpar.get("Entitled Capacity"))
        except (TypeError, ValueError):
            pass
        online = lpar.get("Online Virtual CPUs")
        if lpar:
            virt = virt or "powervm"
            mode = (lpar.get("Mode") or "").strip().lower()
            part = "LPAR %s" % (mode or "mode inconnu")
            cores = cores or (int(online) if str(online or "").isdigit() else None)
            remark = "POWER : partitionnement matériel reconnu sous conditions ; vérifier capped/uncapped et le pool partagé"
            base = entitled if mode == "capped" and entitled else cores
            factor = 1.0
        else:
            if not virt:
                part, remark = "physique", "Tous les cœurs du serveur comptent"
            else:
                part = "partitionnement logiciel"
                remark = "Virtualisation %s : Oracle peut exiger de licencier tout le cluster hôte, cœurs de la VM non représentatifs" % virt
            base = cores
            factor = 0.5 if (arch or "").startswith(("x86", "amd64")) else None
        lic = int(math.ceil(base * factor)) if base and factor else None
        eds = sorted(set(h["edition"] for h in dbs if h["edition"]))
        if "Standard" in eds and "Enterprise" not in eds:
            remark += ". Édition Standard : licence par socket"
        n = sum(1 for s, h, _a in parse_oratab((doc.get("oracle") or {}).get("oratab")) if not s.startswith("+"))
        self.add("oracle_licence", (host, ",".join(eds) or None, n, arch, cores, ints["sockets"], threads, virt, part, entitled, factor, lic, remark))

    # -- Références de bases ---------------------------------------------
    def db_references(self, host, doc, fs, procs):
        resolved = dict(fs.get("db_refs_resolved") or {})
        for line in ((doc.get("network") or {}).get("hosts_file") or "").splitlines():
            p = line.split("#")[0].split()
            for name in p[1:]:
                resolved.setdefault(name, [p[0]])
        seen = set()

        def add(r, path):
            target = r.get("host")
            k = (r.get("engine"), target, r.get("port"), r.get("database"), r.get("alias"), path)
            if k in seen:
                return
            seen.add(k)
            self.add("db_refs", (host, r.get("engine"), target, r.get("port"), r.get("database"), r.get("alias"), r.get("kind"), path,
                                 " ".join(resolved.get(target) or []) or None))
        for r in fs.get("db_refs") or []:
            add(r, r.get("path"))
        for f in (doc.get("oracle") or {}).get("homes") or []:
            for r in f.get("tns_refs") or []:
                add(r, f["home"] + "/network/admin/tnsnames.ora")
        for p in procs:
            cmd = p.get("cmdline") or ""
            if "://" in cmd or "jdbc:" in cmd:
                for r in C.extract_db_refs(cmd):
                    r["kind"] = "cmdline"
                    add(r, "processus " + (p.get("comm") or ""))

    # -- Modules ----------------------------------------------------------
    def modules(self, host, doc, fs):
        rows = {}
        for m in fs.get("service_modules") or []:
            prod, name = m.get("product"), m.get("module")
            rows[(prod, name.lower() if prod == "php" else name)] = (m.get("value"), "configuration", m.get("path"))
        for r in ((doc.get("runtimes") or {}).get("list") or []):
            probe = r.get("probe")
            for o in r.get("outputs") or []:
                args = o.get("args") or []
                if o.get("rc") != 0:
                    continue
                found = []
                if probe == "php" and "-m" in args:
                    found = [("php", x, "php -m") for x in parse_php_m(o.get("output"))]
                elif probe == "httpd" and "-M" in args:
                    found = [("apache", x, "httpd -M") for x in parse_httpd_m(o.get("output"))]
                elif probe == "nginx" and "-V" in args:
                    found = [("nginx", x, "nginx -V") for x in parse_nginx_v(o.get("output"))]
                for prod, name, src in found:
                    if (prod, name) in rows:
                        v = rows[(prod, name)]
                        rows[(prod, name)] = (v[0], "%s+%s" % (v[1], src) if src not in v[1] else v[1], v[2])
                    else:
                        rows[(prod, name)] = (None, src, r.get("realpath"))
        for (prod, name), (value, src, path) in sorted(rows.items()):
            self.add("service_modules", (host, prod, name, value, src, path))

    # -- Points d'entrée --------------------------------------------------
    def endpoints(self, host, doc, fs, listening):
        for e in fs.get("endpoints") or []:
            port = e.get("port")
            self.add("endpoints", (host, e.get("product"), e.get("kind"), e.get("address"), port, e.get("server_name"),
                                   " ".join(e.get("aliases") or []) or None, e.get("location"), e.get("root"),
                                   1 if e.get("tls") else 0, e.get("protocol"), e.get("cert"), e.get("backend"), e.get("path"),
                                   (1 if port in listening else 0) if port and listening else None))
        for a in fs.get("java_archives") or []:
            m = re.search(r"^(.*/webapps)/([^/]+)\.war$", a.get("path") or "")
            if m:
                ctx = "/" if m.group(2) == "ROOT" else "/" + m.group(2).replace("#", "/")
                self.add("endpoints", (host, "tomcat", "context", None, None, None, None, ctx, a.get("path"), 0, None, None, None, a.get("path"), None))

    # -- Clés et certificats ---------------------------------------------
    def crypto(self, host, fs):
        for f in fs.get("crypto_files") or []:
            mode = f.get("mode")
            world = None
            if mode:
                world = 1 if int(mode, 8) & 0o004 else 0

            def b(v):
                return None if v is None else (1 if v else 0)
            self.add("crypto_files", (host, f.get("path"), f.get("kind"), b(f.get("has_private_key")), b(f.get("encrypted")), f.get("key_type"),
                                      b(f.get("empty_password")), mode, f.get("owner"), f.get("size"), f.get("mtime"), world,
                                      f.get("cert_count"), f.get("owner_pkg"), f.get("note")))
            for c in f.get("certs") or []:
                self.add("crypto_certs", (host, f.get("path"), c.get("alias"), c.get("subject"), c.get("cn"), c.get("issuer"), c.get("not_before"),
                                          c.get("not_after"), days_until(c.get("not_after"), self.today), c.get("serial"),
                                          " ".join(c.get("sans") or []) or None, c.get("sig_alg"), c.get("key_alg"), c.get("key_bits"),
                                          b(c.get("self_signed")), b(c.get("is_ca")), c.get("sha256")))

    # -- Runtimes ---------------------------------------------------------
    def runtime_details(self, host, doc, procs, net):
        for r in ((doc.get("runtimes") or {}).get("list") or []):
            if r.get("probe") not in ("php", "php-fpm"):
                continue
            for o in r.get("outputs") or []:
                if "-i" in (o.get("args") or []) and o.get("output"):
                    for section, key, value in parse_phpinfo(o["output"]):
                        self.add("runtime_settings", (host, r["probe"], r.get("realpath"), section, key, value))
        versions = {}
        for row in self.rows.get("software") or []:
            if row[2] == host and row[0] == self.app and row[1] == self.platform:
                category, fam, version, location = row[3], row[5], row[7], row[8]
                if category == "runtime" and fam:
                    versions.setdefault(fam, {})[location] = version
        by_pid = dict((p.get("pid"), p) for p in procs)
        for l in net.get("listening") or []:
            p = by_pid.get(l.get("pid"))
            if not p:
                continue
            runtime = runtime_of(p.get("comm"), p.get("exe"))
            if not runtime:
                continue
            cmd = p.get("cmdline") or ""
            ref, opts = jvm_details(cmd) if runtime == "java" else (script_of(cmd), None)
            vs = versions.get(runtime) or {}
            version = vs.get(p.get("exe")) or (list(vs.values())[0] if len(set(vs.values())) == 1 else None)
            addr = l.get("address")
            self.add("runtime_services", (host, l.get("proto"), addr, l.get("port"), 0 if addr in LOOPBACK else 1, l.get("pid"), p.get("user"),
                                          runtime, version, p.get("comm"), ref, opts, p.get("exe")))


def oracle_fleet(db):
    """Un home est en retard sur le parc si une version plus récente de sa branche y existe."""
    best = {}
    rows = db.execute("SELECT rowid, product, version, patch_level FROM oracle_homes WHERE patch_level IS NOT NULL").fetchall()
    for _r, prod, version, level in rows:
        k = (prod, (version or "").split(".")[0])
        if k not in best or version_key(level) > version_key(best[k]):
            best[k] = level
    for rowid, prod, version, level in rows:
        if version_key(level) < version_key(best[(prod, (version or "").split(".")[0])]):
            db.execute("UPDATE oracle_homes SET behind_fleet = 1 WHERE rowid = ?", (rowid,))


def cert_matches(name, cn, sans):
    """Le nom présenté est-il couvert par le certificat ? Un joker ne couvre qu'un seul niveau."""
    n = (name or "").lower()
    for c in [cn] + (sans or "").split():
        c = (c or "").lower()
        if c == n or (c.startswith("*.") and n.split(".", 1)[-1] == c[2:] and n.count(".") == c.count(".")):
            return True
    return False


def build_cert_usage(db):
    """Relie les services à leur certificat : un fichier qui expire devient un service qui tombe."""
    certs, files = {}, {}
    q = "SELECT app, platform, host, path, cn, sans, not_after, days_left, is_ca FROM crypto_certs"
    for app, pf, host, path, cn, sans, not_after, days, is_ca in db.execute(q).fetchall():
        if not is_ca:
            certs.setdefault((app, pf, host, path), []).append((days if days is not None else 10 ** 6, cn, sans, not_after))
    for app, pf, host, path, kind in db.execute("SELECT app, platform, host, path, kind FROM crypto_files").fetchall():
        files[(app, pf, host, path)] = kind
    q = "SELECT app, platform, host, product, kind, server_name, port, cert FROM endpoints WHERE cert IS NOT NULL"
    for app, pf, host, product, kind, name, port, path in db.execute(q).fetchall():
        k = (app, pf, host, path)
        found = certs.get(k)
        if found:
            days, cn, sans, not_after = min(found, key=lambda x: x[0])
            days = None if days == 10 ** 6 else days
            state = "inconnu" if days is None else ("expiré" if days < 0 else ("à renouveler" if days <= 30 else "valide"))
            match = None if not name or kind != "vhost" else (1 if any(cert_matches(name, c[1], c[2]) for c in found) else 0)
        else:
            cn = not_after = days = match = None
            state = {"illisible": "illisible"}.get(files.get(k), "non lu" if k in files else "non inventorié")
        db.execute("INSERT INTO cert_usage VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (app, pf, host, product, kind, name, port, path, cn, not_after, days, state, match))


# ---------------------------------------------------------------------------
# Liens entre applications et bases
# ---------------------------------------------------------------------------
class Directory(object):
    """Retrouve un serveur de l'inventaire à partir d'une adresse ou d'un nom."""

    def __init__(self, db):
        self.by_ip, self.by_name = {}, {}
        for app, pf, host, cidr in db.execute("SELECT app, platform, host, cidr FROM addresses"):
            ip = (cidr or "").split("/")[0]
            if ip and ip not in LOOPBACK:
                self.by_ip.setdefault(ip, []).append((app, pf, host))
        for app, pf, host, hostname, fqdn in db.execute("SELECT app, platform, host, hostname, fqdn FROM hosts"):
            for n in (host, hostname, fqdn, (host or "").split(".")[0], (fqdn or "").split(".")[0]):
                if n:
                    lst = self.by_name.setdefault(n.lower(), [])
                    if (app, pf, host) not in lst:
                        lst.append((app, pf, host))

    @staticmethod
    def best(cands, near):
        """Une adresse privée peut exister sur deux plates-formes : on préfère la même plate-forme, puis la même application."""
        if not cands:
            return None
        if near:
            for test in (lambda c: c[:2] == near[:2], lambda c: c[1] == near[1], lambda c: c[0] == near[0]):
                hit = [c for c in cands if test(c)]
                if hit:
                    return hit[0]
        return cands[0]

    def find(self, target, near=None, resolved=()):
        t = (target or "").lower()
        if t in LOOPBACK and near:
            return near
        return self.best(self.by_ip.get(t) or self.by_name.get(t) or self.by_name.get(t.split(".")[0]) or
                         [c for ip in resolved for c in self.by_ip.get(ip, [])], near)


class Links(object):
    def __init__(self):
        self.items = {}

    def add(self, client, client_addr, process, server, server_addr, engine, port, database, user, link_type, source, evidence, count=None):
        k = (client or client_addr, server or server_addr, engine, port, database, link_type)
        e = self.items.setdefault(k, {"client": client, "client_addr": client_addr, "process": set(), "server": server, "server_addr": server_addr,
                                      "engine": engine, "port": port, "database": database, "users": set(), "type": link_type,
                                      "sources": set(), "evidence": set(), "count": 0})
        e["sources"].add(source)
        for field, value in (("process", process), ("users", user), ("evidence", evidence)):
            if value:
                e[field].add(value)
        e["count"] += count or 0

    def merged(self):
        """Une connexion observée sans nom de base rejoint le lien de configuration du même couple."""
        named = {}
        for k, e in self.items.items():
            if k[4] is not None:
                named.setdefault((k[0], k[1], k[2], k[3], k[5]), []).append(e)
        out = []
        for k, e in self.items.items():
            twins = named.get((k[0], k[1], k[2], k[3], k[5]))
            if k[4] is None and twins:
                t = twins[0]
                for f in ("process", "users", "sources", "evidence"):
                    t[f] |= e[f]
                t["count"] += e["count"]
            else:
                out.append(e)
        return out


def build_db_links(db):
    d = Directory(db)
    L = Links()
    servers = {}
    for app, pf, host, port, process in db.execute("SELECT app, platform, host, port, process FROM listening"):
        eng = db_engine_of(process)
        if eng:
            servers[((app, pf, host), port)] = eng
    for app, pf, host, engine, ports in db.execute("SELECT app, platform, host, engine, ports FROM db_instances WHERE ports IS NOT NULL"):
        for p in ports.split():
            servers.setdefault(((app, pf, host), int(p)), engine)

    def engine_for(server, port, default=None):
        return servers.get((server, port)) or default or DEFAULT_PORTS.get(port)

    # 1. Connexions sortantes vues du client
    q = "SELECT app, platform, host, remote_addr, remote_port, process, count FROM connections WHERE direction = 'out'"
    for app, pf, host, raddr, rport, process, count in db.execute(q).fetchall():
        client = (app, pf, host)
        server = d.find(raddr, client)
        eng = engine_for(server, rport)
        if eng:
            L.add(client, None, process, server, raddr, eng, rport, None, None, "application", "connexion", None, count)
    # 2. Connexions entrantes vues du serveur : clients hors inventaire compris
    q = "SELECT app, platform, host, local_port, remote_addr, process, count FROM connections WHERE direction = 'in'"
    for app, pf, host, lport, raddr, process, count in db.execute(q).fetchall():
        server = (app, pf, host)
        eng = servers.get((server, lport)) or (db_engine_of(process) if process else None)
        if eng and raddr not in LOOPBACK:
            client = d.find(raddr, server)
            L.add(client, raddr, None, server, None, eng, lport, None, None, "application", "connexion", None, count)
    # 3. Titres des processus PostgreSQL : base, compte et adresse du client, sans connexion à la base
    q = "SELECT app, platform, host, cmdline FROM processes WHERE cmdline LIKE 'postgres:%'"
    for app, pf, host, cmd in db.execute(q).fetchall():
        server = (app, pf, host)
        ports = [p for (s, p), e in servers.items() if s == server and e == "postgresql"]
        port = ports[0] if len(ports) == 1 else None
        m = PG_WALSENDER_RX.match(cmd)
        if m:
            L.add(d.find(m.group(2), server), m.group(2), None, server, None, "postgresql", port, None, m.group(1), "réplication", "processus", None, 1)
            continue
        m = PG_BACKEND_RX.match(cmd)
        if m and m.group(3) not in LOOPBACK:
            L.add(d.find(m.group(3), server), m.group(3), None, server, None, "postgresql", port or 5432, m.group(2), m.group(1), "application", "processus", None, 1)
    # 4. Configurations et lignes de commande. Un alias TNS se résout avec les tnsnames du même hôte
    rows = db.execute("SELECT app, platform, host, engine, target, port, database, alias, kind, path, resolved FROM db_refs").fetchall()
    tns = {}
    for app, pf, host, engine, target, port, database, alias, kind, path, resolved in rows:
        if alias and target:
            tns.setdefault(((app, pf, host), alias.upper()), []).append((target, port, database, resolved))
    for app, pf, host, engine, target, port, database, alias, kind, path, resolved in rows:
        client = (app, pf, host)
        if kind == "tnsnames":
            continue            # un alias déclaré n'est pas un usage : il ne compte que s'il est référencé
        targets = [(target, port, database, resolved)] if target else tns.get((client, (alias or "").upper())) or []
        for t, p, dbname, res in targets:
            server = d.find(t, client, (res or "").split())
            eng = engine or (engine_for(server, p) if p else None) or "inconnu"
            default = next((x for x, e in DEFAULT_PORTS.items() if e == eng), None)
            src = "ligne de commande" if kind == "cmdline" else "configuration"
            L.add(client, None, None, server, t, eng, p or default, dbname, None, "application", src, path)
    for e in L.merged():
        c, s = e["client"] or (None, None, None), e["server"] or (None, None, None)
        active = "connexion" in e["sources"] or "processus" in e["sources"]
        db.execute("INSERT INTO db_links VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   (c[0], c[1], c[2], e["client_addr"], ", ".join(sorted(e["process"])) or None, s[0], s[1], s[2], e["server_addr"], e["engine"],
                    e["port"], e["database"], ", ".join(sorted(e["users"])) or None, e["type"], "actif" if active else "configuré",
                    ", ".join(sorted(e["sources"])), "\n".join(sorted(e["evidence"])) or None, e["count"] or None))


# ---------------------------------------------------------------------------
# Évolutions entre les deux dernières collectes d'un hôte
# ---------------------------------------------------------------------------
TRACKED = (
    # (nature, table, colonnes de clé, colonnes de valeur, filtre)
    ("système", "hosts", ("host",), ("os_pretty", "kernel"), None),
    ("paquet", "packages", ("manager", "name", "arch"), ("version", "release"), None),
    ("composant", "software", ("category", "family", "name", "location"), ("version",), "category NOT IN ('os-package', 'go-module', 'npm-package')"),
    ("port", "listening", ("proto", "address", "port"), ("process",), None),
    ("compte", "accounts", ("name",), ("uid", "shell"), None),
    ("correctif Oracle", "oracle_patches", ("home", "patch_id"), ("description",), None),
    ("ORACLE_HOME", "oracle_homes", ("home",), ("patch_level",), None),
    ("instance", "db_instances", ("engine", "instance"), ("status", "role"), None),
    ("module", "service_modules", ("product", "module"), (), None),
    ("point d'entrée", "endpoints", ("product", "kind", "port", "server_name", "location"), ("root", "backend"), None),
    ("durcissement", "hardening_results", ("ref", "rule_id"), ("status",), "rule_id != '%s'" % cmdb_hardening.EOL_RULE),
    ("clé ou certificat", "crypto_files", ("path",), ("kind", "mode"), None),
    ("certificat", "crypto_certs", ("path", "alias", "sha256"), ("not_after",), None),
)


def snapshot(db, table, keys, values, where, app, pf, host):
    cols = ", ".join(keys + values)
    sql = "SELECT %s FROM %s WHERE app = ? AND platform = ? AND host = ?%s" % (cols, table, " AND " + where if where else "")
    out = {}
    for r in db.execute(sql, (app, pf, host)):
        out[tuple(r[:len(keys)])] = tuple(r[len(keys):])
    return out


def label(key):
    return " ".join(str(k) for k in key if k not in (None, ""))


def build_changes(db, builder_class, schema, previous, current_meta):
    """previous : {clé: (doc, source)} ; current_meta : {clé: meta de la collecte courante}."""
    n = 0
    for key, (doc, source) in sorted(previous.items()):
        mem = sqlite3.connect(":memory:")
        mem.executescript(schema)
        b = builder_class(mem)
        b.process_host(key, doc, None, source)
        b.rows.pop("raw_documents", None)
        b.flush()
        app, pf, host = key
        pm, cm = doc.get("meta") or {}, current_meta.get(key) or {}
        upgraded = pm.get("collector_version") != cm.get("collector_version")
        for kind, table, keys, values, where in TRACKED:
            old = snapshot(mem, table, keys, values, where, app, pf, host)
            new = snapshot(db, table, keys, values, where, app, pf, host)
            if upgraded and not old and new:
                continue            # table apparue avec le collecteur : ce n'est pas une évolution du serveur
            for k in sorted(set(old) | set(new), key=repr):
                a, c = old.get(k), new.get(k)
                if a == c:
                    continue
                change = "ajout" if a is None else ("retrait" if c is None else "modification")
                db.execute("INSERT INTO changes VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                           (app, pf, host, pm.get("run_id"), cm.get("run_id"), pm.get("started_at"), cm.get("started_at"), kind, change,
                            label(k) if table != "hosts" else "système", label(a or ()) or None, label(c or ()) or None))
                n += 1
        mem.close()
    return n


# ---------------------------------------------------------------------------
# Fins de support
# ---------------------------------------------------------------------------
def load_eol(path=EOL_FILE):
    ref = {}
    with open(path, encoding="utf-8") as f:
        lines = [l for l in f if not l.startswith("#")]
    for r in csv.DictReader(lines, delimiter=";"):
        ref.setdefault(r["product"], {})[r["cycle"]] = (r["eol"], r["extended"] or None)
    return ref


def cycle_of(cycles, version):
    """Le cycle le plus long dont la version est un préfixe pointé."""
    best = None
    for c in cycles:
        if (version == c or version.startswith(c + ".")) and (best is None or len(c) > len(best)):
            best = c
    return best


def aix_cycle(level):
    m = re.match(r"^(\d)(\d)00-(\d+)", level or "")
    return "%s.%s.%d" % (m.group(1), m.group(2), int(m.group(3))) if m else None


OS_PRODUCTS = {"rhel": "rhel", "redhat": "rhel", "centos": "centos", "ol": "ol", "debian": "debian", "ubuntu": "ubuntu", "sles": "sles",
               "sled": "sles", "rocky": "rocky", "almalinux": "almalinux"}
SOFT_PRODUCTS = {"oracle-database": "oracle-database", "postgresql": "postgresql", "mysql": "mysql", "mariadb": "mariadb", "php": "php",
                 "python": "python", "tomcat": "tomcat", "node": "node", "mongodb": "mongodb", "redis": "redis", "nginx": "nginx"}


def build_eol(db, today=None, path=EOL_FILE):
    ref = load_eol(path)
    today = today or dt.date.today()
    seen = set()

    def add(app, pf, host, product, cycle, version, location, managed):
        k = (app, pf, host, product, cycle, location)
        if k in seen:
            return
        seen.add(k)
        eol, extended = ref[product][cycle]
        left = days_until(eol, today)
        status = "expiré" if left < 0 else ("bientôt" if left <= EOL_SOON_DAYS else "supporté")
        db.execute("INSERT INTO eol_status VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                   (app, pf, host, product, cycle, version, location, managed, eol, extended, left, status))
    for app, pf, host, os_id, os_version in db.execute("SELECT app, platform, host, os_id, os_version FROM hosts").fetchall():
        product = OS_PRODUCTS.get(os_id or "")
        if product and os_version:
            cycle = cycle_of(ref[product], os_version)
            if not cycle and "." in os_version:
                cycle = cycle_of(ref[product], os_version.split(".")[0])
            if not cycle and product == "sles" and "." not in os_version:
                cycle = cycle_of(ref[product], os_version + ".0")
            if cycle:
                add(app, pf, host, product, cycle, os_version, "système", 1)
    q = "SELECT app, platform, host, version FROM software WHERE family = 'aix'"
    for app, pf, host, level in db.execute(q).fetchall():
        cycle = aix_cycle(level)
        if cycle in ref["aix"]:
            add(app, pf, host, "aix", cycle, level, "système", 1)
    fams = ",".join("'%s'" % f for f in SOFT_PRODUCTS)
    q = ("SELECT app, platform, host, family, version, location, managed, extra FROM software "
         "WHERE family IN (%s) AND category != 'os-package' OR (family IN (%s) AND category = 'os-package')" % (fams, fams))
    for app, pf, host, fam, version, location, managed, extra in db.execute(q).fetchall():
        v = version or ""
        if extra:
            try:
                v = json.loads(extra).get("upstream_version") or v
            except ValueError:
                pass
        m = re.match(r"^\d+(?:\.\d+)*", v)
        if not m:
            continue
        product = SOFT_PRODUCTS[fam]
        cycle = cycle_of(ref[product], m.group(0))
        if cycle:
            add(app, pf, host, product, cycle, v, location, managed)
