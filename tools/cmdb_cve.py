# -*- coding: utf-8 -*-
"""Croisement de l'inventaire avec la base de vulnérabilités de Trivy (trivy.db), hors ligne.

Trois sources, chacune comparée à la base qui lui correspond :
  * paquets de la distribution (table packages) : avis de l'éditeur (Red Hat, Debian, Ubuntu,
    Rocky, Alma, Oracle Linux, SUSE, Amazon, Alpine), comparaison rpm ou dpkg. Les correctifs
    rétroportés sont donc bien pris en compte. Noyau : seul celui qui tourne est évalué ;
  * bibliothèques (table software, purl) : GitHub Security Advisory par écosystème (Maven, pip,
    npm, composer, RubyGems, Go, NuGet) ;
  * produits installés hors distribution (PostgreSQL, Tomcat, nginx, PHP, Redis…, y compris un
    paquet d'un dépôt tiers comme PGDG) : base Bitnami, par version amont.

Rien ne sort du contrôleur : la base est un fichier local, lu en lecture seule."""
import json
import re

import cmdb_bolt

SEVERITIES = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEV_FR = {"CRITICAL": "critique", "HIGH": "haute", "MEDIUM": "moyenne", "LOW": "faible", "UNKNOWN": "inconnue"}
# Statuts Red Hat sans correctif (trivy-db types.Status) : affecté, en cours d'analyse, ne sera pas corrigé, reporté, fin de vie
RH_UNFIXED = {2: "affecté", 4: "en cours d'analyse", 5: "ne sera pas corrigé", 6: "correctif reporté", 7: "fin de vie"}

SCHEMA = """
CREATE TABLE vulnerabilities (app TEXT, platform TEXT, host TEXT, source TEXT, component TEXT, installed TEXT,
  location TEXT, vuln_id TEXT, severity TEXT, cvss REAL, fixed_version TEXT, status TEXT, title TEXT, published TEXT, feed TEXT);
CREATE INDEX ix_vuln_host ON vulnerabilities (app, platform, host);
CREATE INDEX ix_vuln_id ON vulnerabilities (vuln_id);
CREATE TABLE vuln_meta (trivy_updated TEXT, unfixed TEXT, os_unsupported TEXT, hosts INTEGER);
CREATE TABLE vuln_by_app (app TEXT, platform TEXT, source TEXT, component TEXT, installed TEXT, feed TEXT, hosts INTEGER,
  host_list TEXT, critical INTEGER, high INTEGER, medium INTEGER, low INTEGER, total INTEGER, fixable INTEGER, max_cvss REAL,
  fix_to TEXT, worst TEXT, top TEXT);
CREATE TABLE vuln_components (source TEXT, component TEXT, installed TEXT, feed TEXT, hosts INTEGER, apps TEXT,
  critical INTEGER, high INTEGER, medium INTEGER, low INTEGER, total INTEGER, fixable INTEGER, max_cvss REAL,
  fix_to TEXT, worst TEXT);
"""

# Systèmes : ID de /etc/os-release -> (compartiment de la base, comparaison, version : majeure ou complète)
OS_FEEDS = {
    "rhel": ("Red Hat", "rpm", "major"), "centos": ("Red Hat", "rpm", "major"),
    "rocky": ("rocky", "rpm", "major"), "almalinux": ("alma", "rpm", "major"), "ol": ("Oracle Linux", "rpm", "major"),
    "debian": ("debian", "deb", "major"), "ubuntu": ("ubuntu", "deb", "full"),
    "sles": ("SUSE Linux Enterprise", "rpm", "full"), "sled": ("SUSE Linux Enterprise", "rpm", "full"),
    "opensuse-leap": ("openSUSE Leap", "rpm", "full"), "amzn": ("amazon linux", "rpm", "full"),
    "alpine": ("alpine", "apk", "minor"),
}
VENDOR_SOURCE = {"Oracle Linux": "oracle-oval", "SUSE Linux Enterprise": "suse-cvrf", "openSUSE Leap": "suse-cvrf",
                 "amazon linux": "amazon", "alma": "alma", "rocky": "rocky", "debian": "debian", "ubuntu": "ubuntu", "alpine": "alpine"}
LANG_FEEDS = {
    "maven": "maven::GitHub Security Advisory Maven", "pypi": "pip::GitHub Security Advisory pip",
    "npm": "npm::GitHub Security Advisory npm", "composer": "composer::GitHub Security Advisory Composer",
    "gem": "rubygems::GitHub Security Advisory RubyGems", "golang": "go::GitHub Security Advisory Go",
    "nuget": "nuget::GitHub Security Advisory NuGet",
}
BITNAMI = "bitnami::Bitnami Vulnerability Database"
# Famille de l'inventaire -> nom dans la base Bitnami (versions amont)
PRODUCTS = {
    "postgresql": "postgresql", "tomcat": "tomcat", "nginx": "nginx", "httpd": "apache", "php": "php", "php-fpm": "php",
    "redis": "redis", "mariadb": "mariadb", "mongodb": "mongodb", "memcached": "memcached", "haproxy": "haproxy",
    "varnish": "varnish", "node": "node", "python": "python", "ruby": "ruby", "go": "golang", "git": "git",
    "kafka": "kafka", "zookeeper": "zookeeper", "elasticsearch": "elasticsearch", "kibana": "kibana", "logstash": "logstash",
    "activemq": "activemq", "rabbitmq": "rabbitmq", "solr": "solr", "jenkins": "jenkins", "keycloak": "keycloak",
    "wildfly": "wildfly", "grafana": "grafana", "prometheus": "prometheus", "consul": "consul", "vault": "vault",
    "etcd": "etcd", "openldap": "openldap", "influxdb": "influxdb", "cassandra": "cassandra", "openresty": "openresty",
    "sqlite": "sqlite", "pgbouncer": "pgbouncer", "pgpool": "pgpool", "postgresql-jdbc": "postgresql-jdbc-driver",
}
DISTRO_VENDORS = re.compile(r"Red Hat|CentOS|Rocky|AlmaLinux|CloudLinux|Oracle America|SUSE|openSUSE|Amazon|Debian|Ubuntu|Canonical",
                            re.I)
# Révisions des dépôts tiers les plus courants (apt.postgresql.org, nginx.org, MariaDB, MySQL, Docker…)
THIRD_PARTY_DEB = re.compile(r"pgdg|~(bookworm|bullseye|buster|jammy|focal|noble)$|\+(maria|mysql)|ubuntu\.\d+\.\d+~", re.I)
KERNEL_PKG = re.compile(r"^(kernel(-core|-modules|-uek|-default|-rt)?|linux-image-.*)$")


# --- comparaison de versions ------------------------------------------------------------
def _segments(s):
    return re.findall(r"\d+|[A-Za-z]+|~|\^", s)


def rpmvercmp(a, b):
    """Algorithme de rpm (rpmvercmp) : segments numériques et alphabétiques, ~ avant tout, ^ après."""
    if a == b:
        return 0
    sa, sb = _segments(a), _segments(b)
    while sa or sb:
        x = sa.pop(0) if sa else None
        y = sb.pop(0) if sb else None
        if x == "~" or y == "~":
            if x != y:
                return -1 if x == "~" else 1
            continue
        if x == "^" or y == "^":
            if x is None:
                return -1
            if y is None:
                return 1
            if x != y:
                return 1 if x == "^" else -1
            continue
        if x is None:
            return -1
        if y is None:
            return 1
        if x.isdigit() and y.isdigit():
            xi, yi = int(x), int(y)
            if xi != yi:
                return -1 if xi < yi else 1
        elif x.isdigit() != y.isdigit():
            return 1 if x.isdigit() else -1
        elif x != y:
            return -1 if x < y else 1
    return 0


def split_evr(v):
    m = re.match(r"^(?:(\d+):)?([^-]*)(?:-(.*))?$", v or "")
    return (int(m.group(1) or 0), m.group(2) or "", m.group(3) or "") if m else (0, v or "", "")


def rpm_cmp(a, b):
    ea, va, ra = split_evr(a)
    eb, vb, rb = split_evr(b)
    if ea != eb:
        return -1 if ea < eb else 1
    c = rpmvercmp(va, vb)
    if c or not ra or not rb:
        return c
    return rpmvercmp(ra, rb)


def _deb_order(c):
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _deb_part(a, b):
    while a or b:
        na = re.match(r"^[^\d]*", a).group(0)
        nb = re.match(r"^[^\d]*", b).group(0)
        a, b = a[len(na):], b[len(nb):]
        for i in range(max(len(na), len(nb))):
            oa = _deb_order(na[i]) if i < len(na) else 0
            ob = _deb_order(nb[i]) if i < len(nb) else 0
            if oa != ob:
                return -1 if oa < ob else 1
        da = re.match(r"^\d*", a).group(0)
        db = re.match(r"^\d*", b).group(0)
        a, b = a[len(da):], b[len(db):]
        ia, ib = int(da or 0), int(db or 0)
        if ia != ib:
            return -1 if ia < ib else 1
    return 0


def deb_cmp(a, b):
    """Comparaison de versions Debian (epoch:amont-révision, ~ avant tout)."""
    def split(v):
        m = re.match(r"^(?:(\d+):)?(.*?)(?:-([^-]*))?$", v or "")
        return int(m.group(1) or 0), m.group(2), m.group(3) or ""
    ea, ua, ra = split(a)
    eb, ub, rb = split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _deb_part(ua, ub) or _deb_part(ra, rb)


PRE = {"alpha", "a", "beta", "b", "rc", "cr", "pre", "preview", "m", "milestone", "snapshot", "dev", "ea"}


def gen_key(v):
    """Version amont « générique » (bibliothèques, produits) : (numéros, suffixe).
    15.4 == 15.4.0 ; 2.0-rc1 < 2.0 < 2.0-sp1 ; 1.2.3.Final == 1.2.3."""
    v = re.sub(r"^[vV]", "", str(v or "").strip())
    v = re.sub(r"[.-](final|release|ga)$", "", v, flags=re.I)
    toks = re.findall(r"\d+|[A-Za-z]+", v)
    nums = []
    while toks and toks[0].isdigit():
        nums.append(int(toks.pop(0)))
    while nums and nums[-1] == 0:
        nums.pop()
    rest = tuple((0, int(t), "") if t.isdigit() else (1 if t.lower() not in PRE else -1, 0, t.lower()) for t in toks)
    return nums, rest


def gen_cmp(a, b):
    (na, ra), (nb, rb) = gen_key(a), gen_key(b)
    n = max(len(na), len(nb))
    na, nb = na + [0] * (n - len(na)), nb + [0] * (n - len(nb))
    if na != nb:
        return -1 if na < nb else 1
    # Même numéro : une préversion (rc, beta…) est avant la version finale, un suffixe (sp1, k…) après
    pa = ra[0][0] if ra else 0
    pb = rb[0][0] if rb else 0
    if (pa, ra) == (pb, rb):
        return 0
    if pa != pb:
        return -1 if pa < pb else 1
    return -1 if ra < rb else 1


CMP = {"rpm": rpm_cmp, "deb": deb_cmp, "apk": gen_cmp, "gen": gen_cmp}
CONSTRAINT = re.compile(r"(>=|<=|==|!=|>|<|=)?\s*([^\s,|<>=!]+)")


def in_ranges(version, ranges, cmp=gen_cmp):
    """Plages GHSA / Bitnami : liste de conjonctions (« >=2.0, <2.8.2 ») ; vrai si l'une contient la version."""
    for r in ranges or []:
        conds = CONSTRAINT.findall(r)
        if not conds:
            continue
        ok = True
        for op, ver in conds:
            c = cmp(version, ver)
            if not {">=": c >= 0, "<=": c <= 0, ">": c > 0, "<": c < 0, "!=": c != 0}.get(op or "=", c == 0):
                ok = False
                break
        if ok:
            return True
    return False


def first_patch(version, patched, cmp=gen_cmp):
    """Plus petite version corrigée supérieure à la version installée."""
    higher = [p for p in patched or [] if cmp(p, version) > 0]
    if not higher:
        return None
    best = higher[0]
    for p in higher[1:]:
        if cmp(p, best) < 0:
            best = p
    return best


# --- base Trivy ---------------------------------------------------------------------------
class TrivyDB(object):
    def __init__(self, path):
        self.bolt = cmdb_bolt.Bolt(path)
        self.root = cmdb_bolt.Bucket.root(self.bolt)
        self._buckets, self._pkgs, self._vulns, self._rhcpe, self._modules = {}, {}, {}, None, None
        meta = None
        try:
            with open(path[:-len("trivy.db")] + "metadata.json") as f:
                meta = json.load(f)
        except (OSError, ValueError):
            pass
        self.updated = (meta or {}).get("UpdatedAt")
        if self.root.get("vulnerability") is None:
            raise cmdb_bolt.BoltError("%s : pas une base de vulnérabilités Trivy (compartiment « vulnerability » absent)" % path)

    def close(self):
        self.bolt.close()

    def bucket(self, name):
        if name not in self._buckets:
            self._buckets[name] = self.root.get(name)
        return self._buckets[name]

    def advisories(self, feed, pkg):
        """[(identifiant, avis JSON)] d'un paquet dans un compartiment, mis en cache."""
        key = (feed, pkg)
        if key not in self._pkgs:
            b = self.bucket(feed)
            p = b.get(pkg) if b is not None else None
            self._pkgs[key] = [] if p is None or not isinstance(p, cmdb_bolt.Bucket) else \
                [(k.decode("utf-8", "replace"), json.loads(v.decode("utf-8"))) for k, v in p.items() if isinstance(v, bytes)]
        return self._pkgs[key]

    def known(self, feed, pkg):
        b = self.bucket(feed)
        return b is not None and b.get(pkg) is not None

    def vuln(self, vid):
        if vid not in self._vulns:
            raw = self.bucket("vulnerability").get(vid)
            v = json.loads(raw.decode("utf-8")) if raw else {}
            # Seuls les champs utiles restent en mémoire (pas la description ni les références)
            self._vulns[vid] = {"Title": v.get("Title") or (v.get("Description") or "")[:200] or None, "Severity": v.get("Severity"),
                                "VendorSeverity": v.get("VendorSeverity"), "CVSS": v.get("CVSS"),
                                "PublishedDate": v.get("PublishedDate")}
            if len(self._vulns) > 200000:
                self._vulns.clear()
        return self._vulns[vid]

    def rh_modules(self, name, version):
        """Clés « module:flux::paquet » de Red Hat pour un paquet en module (RHEL 8 et 9), flux déduit de la version
        installée (postgresql-server 10.23 -> postgresql:10::postgresql-server). La collecte ne relève pas l'étiquette
        de modularité : à version égale, plusieurs flux candidats sont tous évalués."""
        if self._modules is None:
            self._modules = {}
            for k in self.bucket("Red Hat").keys():
                if b"::" in k:
                    mod, pkg = k.decode("utf-8", "replace").split("::", 1)
                    self._modules.setdefault(pkg, []).append(mod)
        out = []
        for mod in self._modules.get(name, []):
            stream = mod.split(":", 1)[1] if ":" in mod else ""
            if stream and (version == stream or version.startswith(stream + ".")):
                out.append("%s::%s" % (mod, name))
        return out

    def rh_cpes(self, major):
        """Indices des CPE Red Hat d'une version majeure (dépôts par défaut : BaseOS, AppStream…)."""
        if self._rhcpe is None:
            self._rhcpe = {}
            cpe = self.bucket("Red Hat CPE")
            sub = cpe.get("cpe") if cpe is not None else None
            for k, v in (sub.items() if sub is not None else []):
                self._rhcpe[int(k)] = json.loads(v.decode("utf-8"))
        pat = re.compile(r"^cpe:/[ao]:redhat:enterprise_linux:%s(::|$)" % re.escape(major))
        return set(i for i, c in self._rhcpe.items() if pat.match(c))


def severity_of(tdb, vid, vendor_sev=None, sources=()):
    """Gravité : celle de l'éditeur si fournie (entier 0-4), sinon celle de la source, sinon la générale."""
    v = tdb.vuln(vid)
    if isinstance(vendor_sev, int) and 0 < vendor_sev < len(SEVERITIES):
        sev = SEVERITIES[vendor_sev]
    else:
        vs = v.get("VendorSeverity") or {}
        sev = next((SEVERITIES[vs[s]] for s in sources if isinstance(vs.get(s), int) and 0 < vs[s] < len(SEVERITIES)), None)
        sev = sev or v.get("Severity") or "UNKNOWN"
    cvss = None
    for src in ("nvd",) + tuple(sources) + ("ghsa", "redhat", "bitnami"):
        c = (v.get("CVSS") or {}).get(src) or {}
        if c.get("V3Score") or c.get("V40Score"):
            cvss = c.get("V3Score") or c.get("V40Score")
            break
    return sev, cvss, v.get("Title"), (v.get("PublishedDate") or "")[:10] or None


# --- croisement --------------------------------------------------------------------------
def _os_feed(os_id, version):
    f = OS_FEEDS.get((os_id or "").lower())
    if not f or not version:
        return None
    name, kind, level = f
    parts = version.split(".")
    ver = parts[0] if level == "major" else ".".join(parts[:2]) if level == "minor" else version
    return ("Red Hat" if name == "Red Hat" else "%s %s" % (name, ver)), kind, parts[0]


def _running_kernel(name, evr, kernel):
    """Faux pour un noyau installé qui n'est pas celui en cours (conservé pour un retour arrière)."""
    if not KERNEL_PKG.match(name or "") or not kernel:
        return True
    if name.startswith("linux-image-"):
        return name[len("linux-image-"):] == kernel
    _e, v, r = split_evr(evr)
    return kernel.startswith("%s-%s" % (v, r))


def _deb_source(name, source):
    src = (source or name or "").split(" ")[0]
    return "linux" if src.startswith("linux-signed") or src.startswith("linux-image") else src


class Matcher(object):
    def __init__(self, tdb, unfixed="high"):
        self.tdb = tdb
        self.unfixed = unfixed   # « all », « high » (hautes et critiques seulement) ou « none »

    def keep_unfixed(self, sev):
        return self.unfixed == "all" or (self.unfixed == "high" and sev in ("HIGH", "CRITICAL"))

    def os_package(self, feed, kind, major, name, source, evr, arch):
        """[(id, gravité, cvss, titre, publié, corrigé en, statut)] pour un paquet de distribution."""
        out = []
        cmp = CMP[kind]
        if feed == "Red Hat":
            cpes = self.tdb.rh_cpes(major)
            keys = [name]
            if ".module+el" in evr or ".module_el" in evr:
                keys = self.tdb.rh_modules(name, split_evr(evr)[1]) or keys
            advisories = [a for k in keys for a in self.tdb.advisories(feed, k)]
            for key, adv in advisories:
                for e in adv.get("Entries") or []:
                    if not cpes.intersection(e.get("Affected") or []):
                        continue
                    if e.get("Arches") and arch and arch not in e["Arches"] and arch != "noarch":
                        continue
                    fixed = e.get("FixedVersion")
                    if fixed and cmp(evr, fixed) >= 0:
                        continue
                    for c in e.get("Cves") or [{}]:
                        vid = c.get("ID") or key
                        sev, cvss, title, pub = severity_of(self.tdb, vid, c.get("Severity"), ("redhat",))
                        if fixed:
                            out.append((vid, sev, cvss, title, pub, fixed, "corrigeable"))
                        elif self.keep_unfixed(sev):
                            out.append((vid, sev, cvss, title, pub, None, RH_UNFIXED.get(e.get("Status"), "sans correctif")))
            return out
        pkg = _deb_source(name, source) if kind == "deb" else name
        # Gravité donnée par l'éditeur de la distribution, sinon la gravité générale (NVD), comme Trivy
        src_name = VENDOR_SOURCE.get(feed.rsplit(" ", 1)[0], feed.split(" ")[0].lower())
        for vid, adv in self.tdb.advisories(feed, pkg):
            fixed = adv.get("FixedVersion")
            if fixed and cmp(evr, fixed) >= 0:
                continue
            sev, cvss, title, pub = severity_of(self.tdb, vid, adv.get("Severity"), (src_name,))
            if fixed:
                out.append((vid, sev, cvss, title, pub, fixed, "corrigeable"))
            elif self.keep_unfixed(sev):
                out.append((vid, sev, cvss, title, pub, None, "sans correctif"))
        return out

    def ranges(self, feed, pkg, version, sources):
        out = []
        for vid, adv in self.tdb.advisories(feed, pkg):
            if not in_ranges(version, adv.get("VulnerableVersions")):
                continue
            fix = first_patch(version, adv.get("PatchedVersions"))
            sev, cvss, title, pub = severity_of(self.tdb, vid, None, sources)
            if fix or self.keep_unfixed(sev):
                out.append((vid, sev, cvss, title, pub, fix, "corrigeable" if fix else "sans correctif"))
        return out


def purl_key(p):
    """purl -> (écosystème, nom dans la base GHSA, version)."""
    m = re.match(r"^pkg:([^/]+)/(.+?)@([^?#]+)", p or "")
    if not m:
        return None
    from urllib.parse import unquote
    eco, path, ver = m.group(1), unquote(m.group(2)), unquote(m.group(3))
    if eco == "maven":
        path = path.replace("/", ":", 1)
    elif eco == "pypi":
        path = re.sub(r"[-_.]+", "-", path).lower()
    return eco, path, ver


def build_vulnerabilities(db, path, unfixed="high", log=None):
    """Remplit la table vulnerabilities (créée par le schéma de la consolidation). Renvoie un résumé."""
    tdb = TrivyDB(path)
    m = Matcher(tdb, unfixed)
    stats = {"rows": 0, "hosts": 0, "os_unsupported": set(), "updated": tdb.updated}
    rows = []

    def flush():
        db.executemany("INSERT INTO vulnerabilities VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        stats["rows"] += len(rows)
        del rows[:]

    hosts = db.execute("SELECT app, platform, host, os_id, os_version, kernel FROM hosts ORDER BY 1, 2, 3").fetchall()
    for app, pf, host, os_id, os_version, kernel in hosts:
        stats["hosts"] += 1
        f = _os_feed(os_id, os_version)
        os_pkgs = set()
        if f is None:
            if os_id:
                stats["os_unsupported"].add(os_id)
        else:
            feed, kind, major = f
            seen = set()
            for name, epoch, version, release, arch, source, vendor in db.execute(
                    "SELECT name, epoch, version, release, arch, source, vendor FROM packages WHERE app = ? AND platform = ? AND host = ?",
                    (app, pf, host)):
                if kind == "rpm":
                    evr = "%s%s%s" % ("%s:" % epoch if epoch not in (None, "", "0", "(none)") else "", version or "",
                                      "-" + release if release else "")
                else:
                    evr = version or ""
                if not _running_kernel(name, evr, kernel) or (name, evr) in seen:
                    continue
                seen.add((name, evr))
                lookup = name if kind != "deb" else _deb_source(name, source)
                # Paquet de la distribution : connu de ses avis, ou publié par son éditeur (rpm).
                # Les autres (PGDG, dépôt d'éditeur…) sont évalués comme produits, par version amont.
                if (kind == "rpm" and (tdb.known(feed, lookup) or DISTRO_VENDORS.search(vendor or ""))) \
                        or (kind != "rpm" and tdb.known(feed, lookup) and not THIRD_PARTY_DEB.search(version or "")):
                    os_pkgs.add(name)
                for vid, sev, cvss, title, pub, fix, status in m.os_package(feed, kind, major, name, source, evr, arch):
                    rows.append((app, pf, host, "paquet", name, evr, None, vid, sev, cvss, fix, status, title, pub, feed))
        seen = set()
        for category, family, name, version, location, owner, managed, purl in db.execute(
                "SELECT category, family, name, version, location, owner_pkg, managed, purl FROM software "
                "WHERE app = ? AND platform = ? AND host = ?", (app, pf, host)):
            # Bibliothèques hors distribution, par purl
            k = purl_key(purl) if not managed else None
            if k and k[0] in LANG_FEEDS and (k, location) not in seen:
                seen.add((k, location))
                for vid, sev, cvss, title, pub, fix, status in m.ranges(LANG_FEEDS[k[0]], k[1], k[2], ("ghsa",)):
                    rows.append((app, pf, host, "bibliothèque", k[1], k[2], location, vid, sev, cvss, fix, status, title, pub,
                                 LANG_FEEDS[k[0]].split("::")[1]))
                continue
            # Produits : hors distribution, ou paquet inconnu des avis de la distribution (dépôt tiers)
            prod = PRODUCTS.get(family or "")
            if not prod or not version or (managed and owner in os_pkgs) or (prod, version) in seen:
                continue
            seen.add((prod, version))
            ver = re.match(r"^[\d.]+", version)
            if not ver:
                continue
            for vid, sev, cvss, title, pub, fix, status in m.ranges(BITNAMI, prod, ver.group(0).rstrip("."), ("bitnami", "nvd")):
                rows.append((app, pf, host, "produit", family, version, location, vid, sev, cvss, fix, status, title, pub,
                             "Bitnami" + (" (paquet %s hors avis de la distribution)" % owner if managed else "")))
        if len(rows) > 20000:
            flush()
    flush()
    tdb.close()
    build_components(db)
    stats["os_unsupported"] = sorted(stats["os_unsupported"])
    db.execute("INSERT INTO vuln_meta VALUES (?,?,?,?)", (stats["updated"], unfixed, " ".join(stats["os_unsupported"]), stats["hosts"]))
    return stats


def _kind_of(feed):
    for name, kind, _level in OS_FEEDS.values():
        if feed == name or feed.startswith(name + " "):
            return kind
    return "gen"


def _summarize(groups):
    for key, g in groups.items():
        cmp = CMP[_kind_of(key[-1])]
        fix_to = None
        for f in g["fixes"]:
            if fix_to is None or cmp(f, fix_to) > 0:
                fix_to = f
        sevs = [v[0] for v in g["vulns"].values()]
        count = lambda s: sum(1 for x in sevs if x == s)
        rank = lambda s: SEVERITIES.index(s) if s in SEVERITIES else 0
        worst = max(sevs, key=rank) if sevs else None
        # Les CVE les plus graves d'abord, puis par score CVSS
        top = sorted(g["vulns"], key=lambda v: (-rank(g["vulns"][v][0]), -(g["vulns"][v][2] or 0), v))[:5]
        yield key, g, (count("CRITICAL"), count("HIGH"), count("MEDIUM"), count("LOW"), len(sevs),
                       sum(1 for v in g["vulns"].values() if v[1]), g.get("cvss"),
                       re.sub(r"^0:", "", fix_to) if fix_to else None, worst, " ".join(top))


def build_components(db):
    """Synthèses par composant et version installée : par application et plate-forme (vuln_by_app),
    et pour tout le parc (vuln_components). Version qui corrige tout : la plus haute des versions correctives."""
    by_app, fleet = {}, {}
    for source, comp, inst, feed, app, pf, host, vid, sev, cvss, fix, status in db.execute(
            "SELECT source, component, installed, feed, app, platform, host, vuln_id, severity, cvss, fixed_version, status "
            "FROM vulnerabilities"):
        for groups, key in ((by_app, (app, pf, source, comp, inst, feed)), (fleet, (source, comp, inst, feed))):
            g = groups.setdefault(key, {"hosts": set(), "apps": set(), "vulns": {}, "fixes": set()})
            g["hosts"].add((app, pf, host))
            g["apps"].add(app)
            g["vulns"][vid] = (sev, status == "corrigeable", cvss)
            if cvss:
                g["cvss"] = max(g.get("cvss") or 0, cvss)
            if fix:
                g["fixes"].add(fix)
    db.executemany("INSERT INTO vuln_by_app VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   [key + (len(g["hosts"]), " ".join(sorted(h for _a, _p, h in g["hosts"]))) + agg[:-1] + (agg[-1],)
                    for key, g, agg in _summarize(by_app)])
    db.executemany("INSERT INTO vuln_components VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                   [key + (len(g["hosts"]), ",".join(sorted(g["apps"]))) + agg[:-1] for key, g, agg in _summarize(fleet)])
