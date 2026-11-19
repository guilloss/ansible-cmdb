#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cmdb_updates.py - Consolidation : paquets et mises à jour.

  * UpdatesMixin.host_updates  par hôte : programmes et KB Windows, mises à jour connues du cache local
                               (apt-get -s, dnf / yum -C, zypper --no-refresh, Windows Update hors ligne) ;
  * build_fleet_gaps           après tous les hôtes : version plus récente du même paquet ailleurs sur le parc
                               (même système, même version majeure) et retard de mise à jour cumulative Windows ;
  * build_cve_fixes            versions corrigées connues de la base de vulnérabilités (--trivy-db) ;
  * build_update_status        un état par serveur, avec ses alertes.

Le cache local d'un serveur n'est jamais rafraîchi (pas de réseau, pas de privilège) : sa date est relevée et
l'écart au parc et la base de vulnérabilités, à jour côté contrôleur, complètent ce qu'il ne sait pas.
"""
import datetime as dt
import re

import cmdb_cve

UPDATE_ALERT_DAYS = 60     # alerte : pas de mise à jour depuis plus longtemps, ou cache plus ancien
EOL_SOON_DAYS = 180

# Tables par hôte : "app, platform" sont ajoutées par cmdb_build.py
SCHEMA_HOST = """
CREATE TABLE updates (host TEXT, manager TEXT, name TEXT, arch TEXT, installed TEXT, available TEXT, kind TEXT, security INTEGER,
  severity TEXT, advisory TEXT, detail TEXT);
CREATE TABLE update_sources (host TEXT, manager TEXT, source TEXT, cache_date TEXT, last_change TEXT, status TEXT, detail TEXT);
CREATE TABLE hotfixes (host TEXT, kb TEXT, description TEXT, installed_on TEXT);
CREATE TABLE windows_os (host TEXT, caption TEXT, version TEXT, build TEXT, ubr TEXT, display_version TEXT, edition TEXT,
  last_search TEXT, last_install TEXT);
"""
SCHEMA_GLOBAL = """
CREATE TABLE update_status (app TEXT, platform TEXT, host TEXT, manager TEXT, cache_date TEXT, cache_age_days INTEGER,
  last_change TEXT, last_change_days INTEGER, pending INTEGER, pending_security INTEGER, fleet_gap INTEGER, cve_fixes INTEGER,
  os_product TEXT, os_cycle TEXT, os_eol TEXT, os_extended TEXT, os_eol_days INTEGER, alerts TEXT, state TEXT, alert_days INTEGER);
CREATE VIEW v_update_alerts AS
  SELECT app, platform, host, manager, last_change, last_change_days, cache_date, cache_age_days, pending_security, cve_fixes,
         os_eol, os_eol_days, alerts FROM update_status WHERE alerts IS NOT NULL ORDER BY app, platform, host;
"""

KIND_CACHE, KIND_WU, KIND_FLEET, KIND_CVE = "cache local", "Windows Update", "écart au parc", "base CVE"
# Catégories Windows Update (identifiants stables, les noms sont traduits)
WU_SECURITY = "0fa1201d-4330-4fa8-8ae9-b877473b6441"
WU_CRITICAL = "e6cf1350-c01b-414d-a61f-263d14d133b4"
WU_DEFINITIONS = "e0789628-ce08-4437-be74-2495b842f43b"

APT_INST_RX = re.compile(r"^Inst (\S+) \[([^\]]+)\] \((\S+) (.*?)(?: \[([^\]]+)\])?\)")
NEVRA_RX = re.compile(r"^(.+)-(?:(\d+):)?([^-:]+)-([^-]+)\.([^.]+)$")


# --- lecture des sorties ---------------------------------------------------------------------
def parse_apt_simulate(text):
    """apt-get -s dist-upgrade -> [(nom, arch, installée, disponible, origine, sécurité)]"""
    out = []
    for line in (text or "").splitlines():
        m = APT_INST_RX.match(line)
        if m:
            origin = m.group(4) or ""
            out.append((m.group(1).split(":")[0], m.group(5), m.group(2), m.group(3), origin,
                        1 if re.search(r"security", origin, re.I) else 0))
    return out


def parse_check_update(text):
    """dnf / yum check-update -> [(nom, arch, disponible, dépôt)]"""
    out, carry = [], None
    for line in (text or "").splitlines():
        if re.match(r"^(Obsoleting|Security:|Last metadata|Loaded plugins|Dernière)", line.strip()):
            if line.startswith("Obsoleting"):
                break
            continue
        p = line.split()
        if carry and p and line[:1].isspace():
            p = [carry] + p
            carry = None
        elif len(p) == 1 and not line[:1].isspace():
            carry = p[0]
            continue
        if len(p) < 3 or "." not in p[0]:
            continue
        name, _, arch = p[0].rpartition(".")
        out.append((name, arch, p[1], p[2]))
    return out


def parse_updateinfo(text):
    """dnf / yum updateinfo list security -> [(avis, sévérité, nom, arch, epoch:version-release)]"""
    out = []
    for line in (text or "").splitlines():
        p = line.split()
        if len(p) < 3 or not re.match(r"^[A-Z]+-\d{4}[:-]", p[0]):
            continue
        sev = p[1].split("/")[0] if "/" in p[1] else None
        m = NEVRA_RX.match(p[-1])
        if not m:
            continue
        ver = "%s%s-%s" % (m.group(2) + ":" if m.group(2) else "", m.group(3), m.group(4))
        out.append((p[0], sev, m.group(1), m.group(5), ver))
    return out


def parse_zypper_table(text):
    """Tableau de zypper (colonnes séparées par |) -> [dict] selon l'en-tête."""
    rows, head = [], None
    for line in (text or "").splitlines():
        if "|" not in line or re.match(r"^[-+]+$", line.strip()):
            continue
        cells = [c.strip() for c in line.split("|")]
        if head is None:
            head = [c.lower() for c in cells]
            continue
        rows.append(dict(zip(head, cells)))
    return rows


def parse_win_date(v):
    """Date d'installation d'un KB : ISO, MM/dd/yyyy (invariante), yyyymmdd ou FILETIME en hexadécimal."""
    v = (v or "").strip()
    if not v:
        return None
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", v)
    if m:
        return "%s-%s-%s" % m.groups()
    m = re.match(r"^(\d{1,2})/(\d{1,2})/(\d{4})", v)
    if m:
        return "%s-%02d-%02d" % (m.group(3), int(m.group(1)), int(m.group(2)))
    m = re.match(r"^(\d{4})(\d{2})(\d{2})$", v)
    if m:
        return "%s-%s-%s" % m.groups()
    if re.match(r"^[0-9a-fA-F]{15,16}$", v):
        try:
            d = dt.datetime(1601, 1, 1) + dt.timedelta(microseconds=int(v, 16) // 10)
            return d.strftime("%Y-%m-%d")
        except (OverflowError, ValueError):
            return None
    return None


def days_since(iso, today):
    if not iso:
        return None
    try:
        return (today - dt.date(*[int(x) for x in iso[:10].split("-")])).days
    except (ValueError, TypeError):
        return None


class UpdatesMixin(object):
    """Méthodes ajoutées au Builder de cmdb_build.py."""

    def host_updates(self, host, doc):
        win = doc.get("windows") or {}
        if win:
            self.windows_inventory(host, win)
        uc = doc.get("update_cache")
        if uc:
            self.cache_updates(host, uc, "cache local")
        elif doc.get("pending_updates"):
            self.pending_updates(host, doc["pending_updates"])

    def windows_inventory(self, host, win):
        for p in win.get("programs") or []:
            if not p.get("name") or p.get("system_component"):
                continue
            self.add("packages", (host, "windows", p["name"], None, p.get("version") or None, None, p.get("arch"),
                                  p.get("publisher") or None, None, None, p.get("install_date") or None, None, None))
            self.soft(host, "os-package", "windows", None, p["name"], p.get("version") or None, p.get("location") or "registre",
                      "programmes installés (registre)", owner_pkg=p["name"], managed=1)
        dates = []
        for k in win.get("hotfixes") or []:
            d = parse_win_date(k.get("installed_on"))
            if d:
                dates.append(d)
            self.add("hotfixes", (host, k.get("id"), k.get("description"), d))
        o, u = win.get("os") or {}, win.get("updates") or {}
        self.add("windows_os", (host, o.get("caption"), o.get("version"), o.get("build"), o.get("ubr"), o.get("display_version"),
                                o.get("edition"), u.get("last_search"), u.get("last_install")))
        last = max([x for x in dates + [(u.get("last_install") or "")[:10]] if x] or [None])
        if not u:
            self.add("update_sources", (host, "windows", None, None, last, "non collecté", "collecteur sans recherche Windows Update"))
            return
        status = "erreur" if u.get("error") else "ok"
        self.add("update_sources", (host, "windows", u.get("source"), u.get("last_search"), last, status, u.get("error")))
        for x in u.get("pending") or []:
            cats = x.get("categories") or []
            if WU_DEFINITIONS in cats:
                continue        # signatures antivirus : renouvelées plusieurs fois par jour
            sec = 1 if (WU_SECURITY in cats or WU_CRITICAL in cats or x.get("severity")) else 0
            self.add("updates", (host, "windows", x.get("title"), None, None, None, KIND_WU, sec, x.get("severity") or None,
                                 " ".join(x.get("kb") or []) or None, "publiée le %s" % x["published"][:10] if x.get("published") else None))

    def _installed(self, host):
        """{(nom, arch): version installée} des paquets rpm / dpkg déjà lus pour ce serveur"""
        got = {}
        for r in self.rows.get("packages") or []:
            if r[2] != host or r[0] != self.app or r[1] != self.platform:
                continue
            mgr, name, epoch, version, release, arch = r[3], r[4], r[5], r[6], r[7], r[8]
            v = "%s%s%s" % (epoch + ":" if epoch and epoch not in ("0", "(none)") else "", version or "", "-" + release if release else "")
            got[(name, arch)] = v
            got.setdefault((name, None), v)
        return got

    def _last_rpm_install(self, host):
        best = None
        for r in self.rows.get("packages") or []:
            if r[2] == host and r[0] == self.app and r[1] == self.platform and r[3] == "rpm" and r[12]:
                try:
                    t = int(r[12])
                except (TypeError, ValueError):
                    continue
                best = t if best is None or t > best else best
        return dt.datetime.fromtimestamp(best, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if best else None

    def cache_updates(self, host, uc, source):
        mgr = uc.get("manager")
        cmds = dict((c.get("name"), c) for c in uc.get("commands") or [])
        last = uc.get("last_change") or self._last_rpm_install(host)
        errs = []
        inst = self._installed(host)
        rows = {}
        if mgr == "apt":
            c = cmds.get("apt_simulate") or {}
            if c.get("rc") not in (0, None) or c.get("timeout"):
                errs.append("apt-get -s : code %s %s" % (c.get("rc"), (c.get("error") or "").strip()[-200:]))
            for name, arch, old, new, origin, sec in parse_apt_simulate(c.get("output")):
                rows[(name, arch)] = [name, arch, old, new, sec, None, None, origin]
        elif mgr in ("dnf", "yum"):
            c = cmds.get("check_update") or {}
            if c.get("rc") not in (0, 100, None) or c.get("timeout"):
                errs.append("%s -C check-update : code %s %s" % (mgr, c.get("rc"), (c.get("error") or "").strip()[-200:]))
            for name, arch, new, repo in parse_check_update(c.get("output")):
                rows[(name, arch)] = [name, arch, inst.get((name, arch)) or inst.get((name, None)), new, 0, None, None, repo]
            for adv, sev, name, arch, ver in parse_updateinfo((cmds.get("updateinfo_security") or {}).get("output")):
                e = rows.get((name, arch)) or rows.setdefault((name, arch), [name, arch, inst.get((name, arch)), ver, 0, None, None, None])
                e[4] = 1
                e[5] = e[5] or sev
                e[6] = " ".join(sorted(set((e[6] or "").split() + [adv])))
        elif mgr == "zypper":
            c = cmds.get("list_updates") or {}
            if c.get("rc") not in (0, None) or c.get("timeout"):
                errs.append("zypper list-updates : code %s %s" % (c.get("rc"), (c.get("error") or "").strip()[-200:]))
            for r in parse_zypper_table(c.get("output")):
                name, arch = r.get("name"), r.get("arch")
                if name:
                    rows[(name, arch)] = [name, arch, r.get("current version"), r.get("available version"), 0, None, None, r.get("repository")]
            for r in parse_zypper_table((cmds.get("list_patches_security") or {}).get("output")):
                if r.get("name") and (r.get("status") or "").lower() in ("needed", "nécessaire", "requis"):
                    rows[("patch:" + r["name"], None)] = [r["name"], None, None, None, 1, r.get("severity"), r["name"], r.get("summary")]
        for name, arch, old, new, sec, sev, adv, detail in rows.values():
            self.add("updates", (host, mgr, name, arch, old, new, KIND_CACHE, sec, sev, adv, detail))
        status = "erreur" if errs else ("cache absent" if not uc.get("cache_date") else "ok")
        self.add("update_sources", (host, mgr, source, uc.get("cache_date"), last, status, " ; ".join(errs) or None))

    def pending_updates(self, host, pu):
        """--pending-updates (dépôts interrogés) quand le collecteur ne lit pas le cache local."""
        if pu.get("apt_simulate"):
            uc = {"manager": "apt", "commands": [{"name": "apt_simulate", "rc": 0, "output": pu["apt_simulate"]}]}
        elif pu.get("dnf_updateinfo_security") or pu.get("yum_updateinfo_security"):
            mgr = "dnf" if pu.get("dnf_updateinfo_security") else "yum"
            uc = {"manager": mgr, "commands": [{"name": "updateinfo_security", "rc": 0, "output": pu.get(mgr + "_updateinfo_security")}]}
        else:
            return
        self.cache_updates(host, uc, "dépôts interrogés (--pending-updates)")


# --- après tous les hôtes ---------------------------------------------------------------------
def _major(v):
    return (v or "").split(".")[0]


def _cmp_for(manager):
    return {"rpm": cmdb_cve.rpm_cmp, "dpkg": cmdb_cve.deb_cmp}.get(manager, cmdb_cve.gen_cmp)


def _evr(epoch, version, release):
    return "%s%s%s" % (epoch + ":" if epoch and epoch not in ("0", "(none)") else "", version or "", "-" + release if release else "")


def build_fleet_gaps(db):
    """Écart au parc : pour un même système (identifiant et version majeure), un même gestionnaire, un même nom,
    une même architecture (et, en rpm, un même éditeur), la version la plus récente installée sur le parc sert de
    référence ; un serveur en dessous est « en retard sur le parc ». Indépendant des caches des serveurs."""
    hosts = dict(((a, p, h), (o or "", v or "")) for a, p, h, o, v in db.execute("SELECT app, platform, host, os_id, os_version FROM hosts"))
    best_host, groups = {}, {}
    q = ("SELECT app, platform, host, manager, name, epoch, version, release, arch, vendor FROM packages "
         "WHERE manager IN ('rpm', 'dpkg', 'apk', 'windows') AND name != 'gpg-pubkey'")
    for a, p, h, mgr, name, epoch, version, release, arch, vendor in db.execute(q):
        if not version or (a, p, h) not in hosts:
            continue
        os_id, os_v = hosts[(a, p, h)]
        v = _evr(epoch, version, release) if mgr != "windows" else version
        key = (os_id, _major(os_v) if mgr != "windows" else os_v, mgr, name, arch or "", vendor or "" if mgr in ("rpm", "windows") else "")
        cmp = _cmp_for(mgr)
        k2 = key + ((a, p, h),)
        cur = best_host.get(k2)
        if cur is None or cmp(v, cur) > 0:
            best_host[k2] = v
            groups.setdefault(key, set()).add((a, p, h))
    rows = []
    for key, members in groups.items():
        if len(members) < 2:
            continue
        cmp = _cmp_for(key[2])
        vers = [(best_host[key + (m,)], m) for m in members]
        ref = vers[0][0]
        for v, _m in vers[1:]:
            if cmp(v, ref) > 0:
                ref = v
        at_ref = sorted(m[2] for v, m in vers if cmp(v, ref) == 0)
        for v, m in vers:
            if cmp(v, ref) < 0:
                rows.append(m + (key[2], key[3], key[4] or None, v, ref, KIND_FLEET, 0, None, None,
                                 "%d serveur(s) en %s, dont %s" % (len(at_ref), ref, ", ".join(at_ref[:3]))))
    # Mise à jour cumulative Windows : même build, révision (UBR) la plus haute du parc
    ubr = {}
    for a, p, h, build, r in db.execute("SELECT app, platform, host, build, ubr FROM windows_os WHERE build IS NOT NULL AND ubr IS NOT NULL"):
        if str(r).isdigit():
            ubr.setdefault(build, []).append(((a, p, h), int(r)))
    for build, lst in ubr.items():
        top = max(r for _m, r in lst)
        at = sorted(m[2] for m, r in lst if r == top)
        for m, r in lst:
            if r < top:
                rows.append(m + ("windows", "Mise à jour cumulative (build %s)" % build, None, "%s.%d" % (build, r), "%s.%d" % (build, top),
                                 KIND_FLEET, 1, None, None, "%d serveur(s) en %s.%d, dont %s" % (len(at), build, top, ", ".join(at[:3]))))
    db.executemany("INSERT INTO updates VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    return len(rows)


SEV_ORDER = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def build_cve_fixes(db):
    """Base CVE : pour chaque composant d'un serveur qui a une CVE corrigeable, la version qui les corrige toutes."""
    g = {}
    for a, p, h, src, comp, inst, vid, sev, fixed, feed in db.execute(
            "SELECT app, platform, host, source, component, installed, vuln_id, severity, fixed_version, feed FROM vulnerabilities "
            "WHERE status = 'corrigeable' AND fixed_version IS NOT NULL AND fixed_version != ''"):
        e = g.setdefault((a, p, h, src, comp, inst), {"fix": None, "sev": "UNKNOWN", "ids": set(), "feed": feed or ""})
        kind = cmdb_cve._kind_of(e["feed"])
        cmp = {"rpm": cmdb_cve.rpm_cmp, "deb": cmdb_cve.deb_cmp}.get(kind, cmdb_cve.gen_cmp)
        for f in str(fixed).split(","):
            f = f.strip()
            if f and (e["fix"] is None or cmp(f, e["fix"]) > 0):
                e["fix"] = f
        if sev in SEV_ORDER and SEV_ORDER.index(sev) > SEV_ORDER.index(e["sev"]):
            e["sev"] = sev
        e["ids"].add(vid)
    rows = []
    for (a, p, h, src, comp, inst), e in g.items():
        ids = sorted(e["ids"])
        rows.append((a, p, h, src, comp, None, inst, e["fix"], KIND_CVE, 1, cmdb_cve.SEV_FR.get(e["sev"], e["sev"]),
                     " ".join(ids[:5]) + (" … (%d CVE)" % len(ids) if len(ids) > 5 else ""), e["feed"] or None))
    db.executemany("INSERT INTO updates VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    return len(rows)


def build_update_status(db, today=None, alert_days=UPDATE_ALERT_DAYS):
    """Un état par serveur : fraîcheur du cache, dernière mise à jour, correctifs de sécurité en attente,
    écart au parc, fin de support du système ; « alerts » liste ce qui demande une action."""
    today = today or dt.date.today()
    src = {}
    for a, p, h, mgr, cache, last, status, detail in db.execute(
            "SELECT app, platform, host, manager, cache_date, last_change, status, detail FROM update_sources"):
        src[(a, p, h)] = (mgr, cache, last, status, detail)
    cnt = {}
    for a, p, h, kind, sec, n in db.execute("SELECT app, platform, host, kind, security, COUNT(*) FROM updates GROUP BY 1, 2, 3, 4, 5"):
        c = cnt.setdefault((a, p, h), {"pending": 0, "sec": 0, "fleet": 0, "cve": 0})
        if kind in (KIND_CACHE, KIND_WU):
            c["pending"] += n
            c["sec"] += n if sec else 0
        elif kind == KIND_FLEET:
            c["fleet"] += n
        elif kind == KIND_CVE:
            c["cve"] += n
    eol = {}
    for a, p, h, product, cycle, e, x, left in db.execute(
            "SELECT app, platform, host, product, cycle, eol, extended, days_left FROM eol_status WHERE location = 'système'"):
        eol[(a, p, h)] = (product, cycle, e, x, left)
    rows = []
    for a, p, h, os_id in db.execute("SELECT app, platform, host, os_id FROM hosts ORDER BY app, platform, host").fetchall():
        k = (a, p, h)
        mgr, cache, last, status, detail = src.get(k, (None, None, None, None, None))
        c = cnt.get(k, {"pending": 0, "sec": 0, "fleet": 0, "cve": 0})
        product, cycle, e, x, left = eol.get(k, (None, None, None, None, None))
        cache_age, last_age = days_since(cache, today), days_since(last, today)
        alerts = []
        if last_age is not None and last_age > alert_days:
            alerts.append("aucune mise à jour depuis %d jours" % last_age)
        if c["sec"] or c["cve"]:
            alerts.append("correctifs de sécurité non appliqués (%s)" % ", ".join(
                x_ for x_ in ("%d selon le serveur" % c["sec"] if c["sec"] else "", "%d selon la base CVE" % c["cve"] if c["cve"] else "") if x_))
        if cache_age is not None and cache_age > alert_days:
            alerts.append("cache des mises à jour vieux de %d jours" % cache_age)
        if status == "erreur":
            alerts.append("lecture des mises à jour en erreur")
        if left is not None and left < 0:
            alerts.append("système hors support depuis le %s%s" % (e, " (support étendu jusqu'au %s)" % x if x and days_since(x, today) is not None and days_since(x, today) < 0 else ""))
        elif left is not None and left <= EOL_SOON_DAYS:
            alerts.append("fin de support du système le %s (dans %d jours)" % (e, left))
        if mgr is None and last is None:
            state = "inconnu"
        elif alerts:
            state = "à traiter"
        elif c["pending"] or c["fleet"]:
            state = "mises à jour disponibles"
        else:
            state = "à jour"
        rows.append((a, p, h, mgr, cache, cache_age, last, last_age, c["pending"], c["sec"], c["fleet"], c["cve"],
                     product, cycle, e, x, left, " ; ".join(alerts) or None, state, alert_days))
    db.executemany("INSERT INTO update_status VALUES (%s)" % ",".join("?" * 20), rows)
    return len(rows)
