#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cmdb_maps.py - Carte des dépendances entre serveurs et écarts de configuration.

  * build_flows   : flux entre serveurs (table app_flows), à partir des liens vers les bases,
                    des proxys déclarés et des connexions observées ;
  * write_dot     : un graphe Graphviz par application et plate-forme ;
  * build_drift   : écarts entre plates-formes d'une application, et entre serveurs jumeaux.
"""
import collections
import fnmatch
import itertools
import json
import os
import re

from cmdb_extras import Directory, LOOPBACK

HERE = os.path.dirname(os.path.abspath(__file__))
DRIFT_IGNORE = os.path.join(HERE, "cmdb_drift_ignore.txt")
# Ports d'infrastructure : ils relient tout à tout et n'expliquent aucune dépendance applicative
NOISE_PORTS = set([22, 25, 53, 88, 111, 123, 137, 138, 139, 161, 162, 389, 445, 514, 636, 2049, 10050, 10051])
TWIN_IGNORED_PORTS = NOISE_PORTS
REPORT_PHP_KEYS = ("PHP Version", "expose_php", "display_errors", "allow_url_fopen", "allow_url_include", "disable_functions", "open_basedir",
                   "memory_limit", "upload_max_filesize", "post_max_size", "max_execution_time", "session.cookie_secure",
                   "session.cookie_httponly", "opcache.enable", "date.timezone")


def parse_backends(text):
    """Cible de proxy -> [(hôte, port)]. Une amorce balancer:// n'indique aucun serveur."""
    out = []
    t = text or ""
    inner = re.search(r"\(([^)]*)\)", t)
    if inner:
        t = inner.group(1)
    for part in re.split(r"[,\s]+", t):
        part = re.sub(r"(?i)^[a-z][a-z0-9+]*://", "", part).split("/")[0]
        if not part or (text or "").startswith("balancer://"):
            continue
        host, _, port = part.rpartition(":")
        if host and port.isdigit():
            out.append((host, int(port)))
        elif not host and port:
            out.append((port, None))
    return out


def parse_share(device):
    """Périphérique d'un montage réseau -> (serveur, partage, port)"""
    d = device or ""
    m = re.match(r"^//([^/]+)/(.*)$", d) or re.match(r"^\\\\([^\\]+)\\(.*)$", d)
    if m:
        return m.group(1), m.group(2), 445
    m = re.match(r"^([A-Za-z0-9_.\-]+):(/.*)?$", d)
    if m:
        return m.group(1), m.group(2) or "/", 2049
    return None


def build_flows(db):
    d = Directory(db)
    edges = collections.OrderedDict()

    def add(src, src_addr, dst, dst_addr, port, kind, detail, status):
        k = (src or src_addr, dst or dst_addr, port, kind)
        e = edges.setdefault(k, {"src": src, "src_addr": src_addr, "dst": dst, "dst_addr": dst_addr, "port": port, "kind": kind,
                                 "detail": set(), "status": status})
        if detail:
            e["detail"].add(detail)
        if status == "actif":
            e["status"] = "actif"
    q = """SELECT client_app, client_platform, client_host, client_addr, server_app, server_platform, server_host, server_addr,
                  engine, port, database, link_type, status FROM db_links"""
    for ca, cp, ch, caddr, sa, sp, sh, saddr, engine, port, database, ltype, status in db.execute(q).fetchall():
        src = (ca, cp, ch) if ch else None
        dst = (sa, sp, sh) if sh else None
        add(src, caddr, dst, saddr, port, "réplication" if ltype == "réplication" else "base", " ".join(x for x in (engine, database) if x), status)
    q = "SELECT app, platform, host, product, location, backend FROM endpoints WHERE kind = 'proxy' AND backend IS NOT NULL"
    for app, pf, host, product, location, backend in db.execute(q).fetchall():
        src = (app, pf, host)
        for target, port in parse_backends(backend):
            add(src, None, d.find(target, src), target, port, "proxy", " ".join(x for x in (product, location) if x), "configuré")
    q = "SELECT app, platform, host, mountpoint, device FROM filesystems WHERE network = 1"
    for app, pf, host, mountpoint, device in db.execute(q).fetchall():
        share = parse_share(device)
        if share:
            src = (app, pf, host)
            add(src, None, d.find(share[0], src), share[0], share[2], "stockage", "%s depuis %s" % (mountpoint, share[1]), "actif")
    # Un LUN vu par plusieurs serveurs : cluster ou bascule. Pas de sens de dépendance.
    luns = collections.defaultdict(set)
    for app, pf, host, wwn in db.execute("SELECT app, platform, host, wwn FROM disks WHERE wwn IS NOT NULL").fetchall():
        if len(wwn) >= 8:
            luns[wwn].add((app, pf, host))
    pairs = collections.Counter()
    for wwn, hosts in luns.items():
        if 2 <= len(set(h[2] for h in hosts)) <= 16:
            for a, b in itertools.combinations(sorted(hosts), 2):
                if a[2] != b[2]:
                    pairs[(a, b)] += 1
    for (a, b), n in sorted(pairs.items()):
        add(a, None, b, None, None, "disque partagé", "%d disque(s)" % n, "actif")
    known = set((e["src"], e["dst"], e["port"]) for e in edges.values())
    q = "SELECT app, platform, host, direction, local_port, remote_addr, remote_port, process FROM connections"
    for app, pf, host, direction, lport, raddr, rport, process in db.execute(q).fetchall():
        me = (app, pf, host)
        other = d.find(raddr, me) if raddr not in LOOPBACK else None
        if not other or other == me:
            continue
        src, dst, port = (me, other, rport) if direction == "out" else (other, me, lport)
        if port in NOISE_PORTS or (src, dst, port) in known:
            continue
        add(src, None, dst, None, port, "réseau", process, "actif")
    for e in edges.values():
        s, t = e["src"] or (None, None, None), e["dst"] or (None, None, None)
        db.execute("INSERT INTO app_flows VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                   (s[0], s[1], s[2], e["src_addr"], t[0], t[1], t[2], e["dst_addr"], e["port"], e["kind"], ", ".join(sorted(e["detail"])) or None, e["status"]))


def dot_quote(s):
    return '"%s"' % str(s).replace("\\", "\\\\").replace('"', '\\"')


def write_dot(db, outdir, safe_name):
    """Un fichier par (application, plate-forme) ; les serveurs voisins y figurent aussi."""
    os.makedirs(outdir, exist_ok=True)
    rows = db.execute("""SELECT src_app, src_platform, src_host, src_addr, dst_app, dst_platform, dst_host, dst_addr, port, kind, status
                         FROM app_flows""").fetchall()
    groups = collections.defaultdict(list)
    for r in rows:
        for pair in set(((r[0], r[1]), (r[4], r[5]))):
            if pair[0]:
                groups[pair].append(r)
    style = {"base": "", "proxy": ", color=steelblue", "réplication": ", style=dotted", "réseau": ", color=gray", "stockage": ", color=seagreen",
             "disque partagé": ", dir=none, style=dashed, color=seagreen"}
    for (app, pf), edges in sorted(groups.items()):
        lines = ["digraph %s {" % dot_quote("%s %s" % (app, pf)), "  rankdir=LR;", "  node [shape=box, fontname=sans];"]
        for r in edges:
            a, b = r[2] or r[3], r[6] or r[7]
            if a == b:
                continue
            for name, inv in ((a, r[2]), (b, r[6])):
                if not inv:
                    lines.append("  %s [style=dashed];" % dot_quote(name))
            lines.append("  %s -> %s [label=%s%s];" % (dot_quote(a), dot_quote(b), dot_quote("%s %s" % (r[9], r[8] or "")), style.get(r[9], "")))
        lines.append("}")
        with open(os.path.join(outdir, safe_name(app, pf) + ".dot"), "w", encoding="utf-8") as f:
            f.write("\n".join(lines[:3] + sorted(set(lines[3:-1])) + ["}"]) + "\n")
    return len(groups)


# ---------------------------------------------------------------------------
# Écarts
# ---------------------------------------------------------------------------
def load_ignore(path=DRIFT_IGNORE):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def host_profiles(db, app=None):
    """{serveur: {(nature, élément): valeur}} : ce qui devrait être identique entre deux serveurs comparables.
    app : limite aux serveurs d'une application (la mémoire dépend alors de la plus grosse application)."""
    prof = collections.defaultdict(dict)
    versions = collections.defaultdict(set)
    only, args = (" AND app = ?", (app,)) if app is not None else ("", ())

    def rows(sql, extra=()):
        return db.execute(sql.replace(" {APP}", only), tuple(extra) + args)
    q = "SELECT app, platform, host, family, version, extra FROM software WHERE family IS NOT NULL AND version IS NOT NULL AND category NOT IN ('go-module', 'npm-package') {APP}"
    for app_, pf, host, fam, version, extra in rows(q):
        v = version
        if extra:
            try:
                v = json.loads(extra).get("upstream_version") or v
            except ValueError:
                pass
        versions[((app_, pf, host), fam)].add(v)
    for (k, fam), vs in versions.items():
        prof[k][("composant", fam)] = " | ".join(sorted(vs))
    del versions
    for app_, pf, host, os_pretty in rows("SELECT app, platform, host, os_pretty FROM hosts WHERE 1 {APP}"):
        prof[(app_, pf, host)][("système", "version")] = os_pretty
    for app_, pf, host, product, version, level in rows("SELECT app, platform, host, product, version, patch_level FROM oracle_homes WHERE product IS NOT NULL {APP}"):
        if level:
            prof[(app_, pf, host)][("correctif Oracle", "%s %s" % (product, (version or "").split(".")[0]))] = level
    for app_, pf, host, product, module in rows("SELECT app, platform, host, product, module FROM service_modules WHERE 1 {APP}"):
        prof[(app_, pf, host)][("module", "%s %s" % (product, module))] = "présent"
    marks = ",".join("?" * len(REPORT_PHP_KEYS))
    for app_, pf, host, key, value in rows("SELECT app, platform, host, key, value FROM runtime_settings WHERE key IN (%s) {APP}" % marks, REPORT_PHP_KEYS):
        prof[(app_, pf, host)][("réglage PHP", key)] = value
    for app_, pf, host, ref, status in rows("SELECT app, platform, host, rule_id, status FROM hardening_results WHERE status != 'non vérifiable' {APP}"):
        prof[(app_, pf, host)][("durcissement", ref)] = status
    return prof


def twin_groups(db, prof, app=None):
    """Serveurs d'une même application et plate-forme qui font le même métier : mêmes composants, mêmes ports d'écoute."""
    only, args = (" AND app = ?", (app,)) if app is not None else ("", ())
    ports = collections.defaultdict(set)
    for app, pf, host, port in db.execute("SELECT app, platform, host, port FROM listening WHERE address NOT IN ('127.0.0.1', '::1')" + only, args):
        if port and port < 32768 and port not in TWIN_IGNORED_PORTS:
            ports[(app, pf, host)].add(port)
    runtime = collections.defaultdict(set)
    for app, pf, host, fam in db.execute("SELECT DISTINCT app, platform, host, family FROM software WHERE category = 'runtime' AND family IS NOT NULL" + only, args):
        if fam not in ("linux-kernel", "aix"):
            runtime[(app, pf, host)].add(fam)
    groups = collections.defaultdict(list)
    for k in prof:
        if ports[k] or runtime[k]:
            groups[(k[0], k[1], tuple(sorted(ports[k])), tuple(sorted(runtime[k])))].append(k)
    return [sorted(g) for g in groups.values() if len(g) > 1]


def build_drift(db, ignore=None):
    """Écarts entre plates-formes d'une application et entre serveurs jumeaux.
    Calculés application par application : seul le profil d'une application est en mémoire."""
    ignore = load_ignore() if ignore is None else ignore
    for (app,) in db.execute("SELECT DISTINCT app FROM hosts ORDER BY app").fetchall():
        _drift_app(db, host_profiles(db, app), ignore, app)


def _drift_app(db, prof, ignore, only_app):
    def skip(item):
        return any(fnmatch.fnmatchcase("%s:%s" % item, p) for p in ignore)

    def put(scope, app, lp, rp, lh, rh, item, lv, rv):
        db.execute("INSERT INTO drift VALUES (?,?,?,?,?,?,?,?,?,?)", (scope, app, lp, rp, lh, rh, item[0], item[1], lv, rv))
    # Plates-formes d'une application, deux à deux : on compare les valeurs présentes sur chaque plate-forme
    by_app = collections.defaultdict(lambda: collections.defaultdict(lambda: collections.defaultdict(set)))
    for (app, pf, _h), items in prof.items():
        for item, value in items.items():
            by_app[app][pf][item].add(value)
    for app, pfs in sorted(by_app.items()):
        for left, right in itertools.combinations(sorted(pfs), 2):
            for item in sorted(set(pfs[left]) | set(pfs[right])):
                a, b = pfs[left].get(item), pfs[right].get(item)
                if a != b and not skip(item):
                    put("plates-formes", app, left, right, None, None, item, " / ".join(sorted(a)) if a else None, " / ".join(sorted(b)) if b else None)
    # Serveurs jumeaux : le nœud différent se compare à la majorité du groupe
    for group in twin_groups(db, prof, only_app):
        app, pf = group[0][:2]
        for item in sorted(set(i for k in group for i in prof[k])):
            if skip(item):
                continue
            values = [prof[k].get(item) for k in group]
            if len(set(values)) == 1:
                continue
            if len(group) == 2:
                put("jumeaux", app, pf, pf, group[0][2], group[1][2], item, values[0], values[1])
                continue
            common, n = collections.Counter(values).most_common(1)[0]
            for k, v in zip(group, values):
                if v != common:
                    put("jumeaux", app, pf, pf, k[2], "majorité (%d/%d)" % (n, len(group)), item, v, common)
