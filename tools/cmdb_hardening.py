#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cmdb_hardening.py - Contrôles de durcissement selon le guide ANSSI-BP-028 v2.0 (Linux).

Les règles sont dans cmdb_anssi_rules.csv et s'appliquent aux collectes déjà faites :
rien n'est exécuté sur les serveurs. Une règle dont la donnée manque (droits insuffisants,
collecteur shell) est « non vérifiable » : elle ne compte ni pour ni contre le serveur.

Contrôle de configuration partiel : il ne remplace pas un audit. Le fichier
cmdb_anssi_recos.csv indique, pour les 80 recommandations, ce qui est réellement couvert.
"""
import csv
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
RULES_FILE = os.path.join(HERE, "cmdb_anssi_rules.csv")
RECOS_FILE = os.path.join(HERE, "cmdb_anssi_recos.csv")
LEVELS = ("minimal", "intermédiaire", "renforcé", "élevé")
OK, KO, UNKNOWN = "conforme", "non conforme", "non vérifiable"
EOL_RULE = "R61-os-supported"
REDHAT = ("rhel", "centos", "ol", "rocky", "almalinux", "fedora", "scientific")
APPARMOR = ("debian", "ubuntu", "sles", "sled", "opensuse-leap", "opensuse")


def read_csv(path):
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader([l for l in f if not l.startswith("#")], delimiter=";"))


def load_rules(path=RULES_FILE):
    return read_csv(path)


def load_recos(path=RECOS_FILE):
    return read_csv(path)


def parse_sysctl(text):
    out = {}
    for line in (text or "").splitlines():
        k, sep, v = line.partition("=")
        if sep:
            out[k.strip()] = " ".join(v.split())
    return out


def parse_sshd(sec):
    """-> (réglages, effectif ?). sshd -T donne la configuration effective, sshd_config seulement ce qui est écrit."""
    text = sec.get("sshd_effective_config")
    effective = bool(text)
    text = text or sec.get("sshd_config") or ""
    out = {}
    for line in text.splitlines():
        p = line.split(None, 1)
        if len(p) == 2 and not p[0].startswith("#"):
            out.setdefault(p[0].lower(), p[1].strip().lower())
    return out, effective


def sudo_lines(accounts):
    """Lignes utiles de sudoers, continuations jointes. None si aucun fichier n'a pu être lu."""
    files = accounts.get("sudoers")
    if not files:
        return None
    lines = []
    for text in files.values():
        for line in re.sub(r"\\\n", " ", text or "").splitlines():
            s = line.split("#")[0].strip()
            if s:
                lines.append(s)
    return lines


def sudo_specs(lines):
    """Règles utilisateur uniquement : ni Defaults, ni alias."""
    return [l for l in lines if "=" in l and not re.match(r"^(Defaults|User_Alias|Runas_Alias|Host_Alias|Cmnd_Alias)\b", l)]


def sudo_commands(spec):
    cmds = spec.split("=", 1)[1]
    cmds = re.sub(r"\([^)]*\)", "", cmds)
    cmds = re.sub(r"\b(NOPASSWD|PASSWD|NOEXEC|EXEC|SETENV|NOSETENV|LOG_INPUT|NOLOG_INPUT|LOG_OUTPUT|NOLOG_OUTPUT):", "", cmds)
    return [c.strip() for c in cmds.split(",") if c.strip()]


class Facts(object):
    def __init__(self, doc):
        self.doc = doc
        self.sec = doc.get("security") or {}
        self.acc = doc.get("accounts") or {}
        self.sysctl = parse_sysctl((doc.get("kernel") or {}).get("sysctl"))
        self.sshd, self.sshd_effective = parse_sshd(self.sec)
        self.sudo = sudo_lines(self.acc)
        self.mounts = dict((m.get("mountpoint"), m) for m in (doc.get("hardware") or {}).get("mounts") or [] if m.get("mountpoint"))
        s = doc.get("services") or {}
        self.units = dict((u.get("unit"), u.get("active")) for u in s.get("units") or [])
        mgrs = (doc.get("packages") or {}).get("managers") or {}
        self.packages = set(r.get("name") for m in ("rpm", "dpkg", "apk") for r in mgrs.get(m) or [])
        self.os_id = (((doc.get("os") or {}).get("os_release") or {}).get("ID") or "").lower()
        self.listening = (doc.get("network") or {}).get("listening")


def check_sysctl(f, r):
    v = f.sysctl.get(r["target"])
    if v is None:
        return UNKNOWN, None
    return (OK if v == r["expected"] else KO), v


def check_mount(f, r):
    if not f.mounts:
        return UNKNOWN, None
    m = f.mounts.get(r["target"])
    if not m:
        return KO, "pas de partition dédiée"
    opts = m.get("options")
    if opts is None:
        return UNKNOWN, "options inconnues"
    have = opts.split(",")
    missing = [o for o in r["expected"].split(",") if o not in have]
    return (KO, "manque " + ",".join(missing)) if missing else (OK, opts)


def check_sshd(f, r):
    v = f.sshd.get(r["target"])
    if v is None:
        return UNKNOWN, None           # valeur par défaut inconnue sans sshd -T
    return (OK if v == r["expected"] else KO), v


def check_sudo_default(f, r):
    if f.sudo is None:
        return UNKNOWN, "sudoers illisible"
    word = r["target"]
    for line in f.sudo:
        if line.startswith("Defaults") and re.search(r"(^|[\s,])%s($|[\s,])" % re.escape(word), line[len("Defaults"):]):
            return OK, line[:120]
    return KO, "absente"


def check_service(f, r):
    if not f.units:
        return UNKNOWN, None
    active = [u for u in r["target"].split("|") if f.units.get(u) == "active"]
    return (OK, ", ".join(active)) if active else (KO, "inactif")


def check_package_absent(f, r):
    if not f.packages:
        return UNKNOWN, None
    found = sorted(set(r["target"].split("|")) & f.packages)
    return (KO, ", ".join(found)) if found else (OK, None)


def b_proc_hidepid(f):
    vis = (f.doc.get("meta") or {}).get("visibility") or {}
    if "proc_hidepid" not in vis:
        return UNKNOWN, None           # non relevé par le collecteur shell
    return (OK, vis["proc_hidepid"]) if vis["proc_hidepid"] else (KO, "hidepid absent")


def b_sudo_rule(test):
    def check(f):
        if f.sudo is None:
            return UNKNOWN, "sudoers illisible"
        bad = [s for s in sudo_specs(f.sudo) if test(s)]
        return (KO, "%d règle(s), dont : %s" % (len(bad), bad[0][:100])) if bad else (OK, None)
    return check


def _explicit(cmd):
    c = cmd.lstrip("!")
    return not c.startswith("/") or " " in c


def b_selinux(f):
    if f.os_id not in REDHAT:
        return None
    text = f.sec.get("sestatus") or ""
    mode = re.search(r"Current mode:\s*(\S+)", text)
    pol = re.search(r"Loaded policy name:\s*(\S+)", text)
    if mode:
        got = (mode.group(1), pol.group(1) if pol else None)
    else:
        cfg = f.sec.get("selinux_config") or ""
        m, p = re.search(r"(?m)^SELINUX=(\S+)", cfg), re.search(r"(?m)^SELINUXTYPE=(\S+)", cfg)
        if not m:
            return UNKNOWN, None
        got = (m.group(1), p.group(1) if p else None)
    return (OK if got == ("enforcing", "targeted") else KO), " ".join(x for x in got if x)


def b_apparmor(f):
    if f.os_id not in APPARMOR:
        return None
    n = f.sec.get("apparmor_profiles_count")
    if n is None:
        return UNKNOWN, None           # /sys/kernel/security exige root
    return (OK if n else KO), "%d profil(s)" % n


def b_mta(f):
    if f.listening is None:
        return UNKNOWN, None
    exposed = [l.get("address") for l in f.listening if l.get("port") == 25 and l.get("address") not in ("127.0.0.1", "::1")]
    return (KO, "port 25 sur " + ", ".join(sorted(set(str(a) for a in exposed)))) if exposed else (OK, None)


BUILTIN = {
    "proc_hidepid": b_proc_hidepid,
    "sudo_no_root_target": b_sudo_rule(lambda s: re.search(r"=\s*\(\s*(ALL|root)\b", s) or re.search(r"=\s*(NOPASSWD:\s*)?ALL\s*$", s)),
    "sudo_no_negation": b_sudo_rule(lambda s: any(c.startswith("!") for c in sudo_commands(s))),
    "sudo_explicit_args": b_sudo_rule(lambda s: any(not _explicit(c) for c in sudo_commands(s))),
    "selinux": b_selinux,
    "apparmor": b_apparmor,
    "mta_local_only": b_mta,
}
CHECKS = {"sysctl": check_sysctl, "mount": check_mount, "sshd": check_sshd, "sudo_default": check_sudo_default,
          "service": check_service, "package_absent": check_package_absent}


def evaluate(doc, rules):
    """-> [(règle, état, valeur observée)]. Une règle sans objet sur ce système est omise."""
    f = Facts(doc)
    out = []
    for r in rules:
        if r["type"] == "check":
            if r["target"] == "os_supported":
                continue               # évaluée après les fins de support : voir apply_eol
            res = BUILTIN[r["target"]](f)
            if res is None:
                continue
        else:
            res = CHECKS[r["type"]](f, r)
        out.append((r, res[0], res[1]))
    return out


def is_linux(doc):
    return ((doc.get("os") or {}).get("os_release") or {}).get("ID", "").lower() != "aix"


def apply_eol(db, rules):
    r = next((x for x in rules if x["id"] == EOL_RULE), None)
    if not r:
        return
    q = """SELECT h.app, h.platform, h.host, e.status, e.product, e.cycle, e.eol FROM hosts h
           LEFT JOIN eol_status e ON e.app = h.app AND e.platform = h.platform AND e.host = h.host AND e.location = 'système'
           WHERE h.os_id != 'aix'"""
    for app, pf, host, status, product, cycle, eol in db.execute(q).fetchall():
        state = UNKNOWN if status is None else (KO if status == "expiré" else OK)
        seen = "%s %s, fin %s" % (product, cycle, eol) if status else None
        db.execute("INSERT INTO hardening_results VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                   (app, pf, host, r["id"], r["ref"], r["level"], r["title"], state, seen, r["expected"], r["note"] or None))


def build_scores(db):
    """Score par niveau : chaque niveau inclut les précédents, comme dans le guide. Le non vérifiable est exclu du calcul."""
    hosts = db.execute("SELECT DISTINCT app, platform, host FROM hardening_results").fetchall()
    for app, pf, host in hosts:
        rows = db.execute("SELECT level, status FROM hardening_results WHERE app = ? AND platform = ? AND host = ?", (app, pf, host)).fetchall()
        for i, level in enumerate(LEVELS):
            allowed = LEVELS[:i + 1]
            ok = sum(1 for l, s in rows if l in allowed and s == OK)
            ko = sum(1 for l, s in rows if l in allowed and s == KO)
            unknown = sum(1 for l, s in rows if l in allowed and s == UNKNOWN)
            score = round(100.0 * ok / (ok + ko), 1) if ok + ko else None
            db.execute("INSERT INTO hardening_scores VALUES (?,?,?,?,?,?,?,?)", (app, pf, host, level, ok, ko, unknown, score))
