#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cmdb_build.py - Consolidation des collectes CMDB (côté contrôleur, Python >= 3.8, stdlib).

Lit un ou plusieurs magasins de collectes (store/<appli>/<plate-forme>/<hôte>/, ou
l'ancien output/raw/<hôte>/) et des lots transférés (.tar.gz produits par la collecte),
garde la dernière collecte de chaque triplet (application, plate-forme, hôte) et produit :
  * build/cmdb.sqlite         base interrogeable (tables normalisées + documents bruts),
                              chaque ligne étiquetée app / platform / host
  * build/csv/*.csv           export de chaque table et vue
  * build/runtimes_matrix.csv matrice hôte x composant (java, php, python, postgresql...)
  * build/sbom/<app>__<pf>__<hôte>.cdx.json  SBOM CycloneDX 1.5 par hôte (purl/CPE), à donner
                               à Trivy, Grype, OSV-Scanner ou Dependency-Track
  * build/flrtvc/<app>__<pf>__<hôte>.lslpp.txt  (AIX) entrée de l'outil IBM FLRTVC

Tout le parsing des versions est fait ICI (le collecteur conserve les sorties
brutes) : on peut améliorer les règles et relancer sans recollecter.
"""
import argparse
import csv
import datetime as dt
import fnmatch
import glob
import gzip
import hashlib
import json
import os
import re
import sqlite3
import sys
import tarfile
import uuid
import zlib
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cmdb_extras  # noqa: E402
import cmdb_hardening  # noqa: E402
import cmdb_dossier  # noqa: E402
import cmdb_maps  # noqa: E402
import cmdb_cve  # noqa: E402

BUILD_VERSION = "1.2.0"

# ---------------------------------------------------------------------------
# Règles de normalisation
# ---------------------------------------------------------------------------

# Sondes : regex d'extraction de version sur la sortie brute (première qui matche)
PROBE_VERSION_RX = {
    "python": [r"^version=(\S+)"],
    "php": [r"PHP (\d+\.\d+\.\d+\S*)"],
    "php-fpm": [r"PHP (\d+\.\d+\.\d+\S*)"],
    "node": [r"^v(\d+\.\d+\.\d+)"],
    "ruby": [r"ruby (\d+\.\d+\.\d+)"],
    "perl": [r"v(\d+\.\d+\.\d+)"],
    "go": [r"go version go(\S+)"],
    "postgresql": [r"\(PostgreSQL\) (\S+)"],
    "psql": [r"\(PostgreSQL\) (\S+)"],
    "mysqld": [r"Ver (\S+)"],
    "mysql-client": [r"Distrib (\S+?),", r"Ver (\d\S*)"],
    "mongod": [r"db version v(\S+)"],
    "redis": [r"v=(\S+)", r"(\d+\.\d+\.\d+)"],
    "memcached": [r"memcached (\S+)"],
    "nginx": [r"nginx/(\S+)"],
    "httpd": [r"Apache/(\S+)"],
    "haproxy": [r"HA-?Proxy version (\S+)"],
    "varnish": [r"varnish-(\S+)"],
    "squid": [r"Version (\S+)"],
    "bind": [r"BIND (\S+)"],
    "samba": [r"Version (\S+)"],
    "proftpd": [r"ProFTPD Version (\S+)"],
    "openssh-client": [r"OpenSSH_([^\s,]+)"],
    "openssh-server": [r"OpenSSH_([^\s,]+)"],
    "openssl": [r"(?:OpenSSL|LibreSSL) (\S+)"],
    "sudo": [r"Sudo version (\S+)"],
    "bash": [r"version (\d+\.\d+\.\d+)"],
    "curl": [r"curl (\S+)"],
    "wget": [r"Wget (\S+)"],
    "git": [r"git version (\S+)"],
    # ldd --version ("ldd (GNU libc) 2.17") ou exécution de libc.so.6 ("... release version 2.5, by ...")
    "glibc": [r"release version (\d+\.\d+(?:\.\d+)?)", r"^ldd .*?(\d+\.\d+)\s*$"],
    "systemd": [r"systemd (\d+)"],
    "xz": [r"XZ Utils\) (\S+)"],
    "polkit": [r"version (\S+)"],
    "docker": [r"version (\S+?),"],
    "containerd": [r"containerd \S+ v?(\d\S*)"],
    "runc": [r"runc version (\S+)"],
    "kubelet": [r"Kubernetes v(\S+)"],
    "kubectl": [r"Client Version: v?(\S+)", r'GitVersion:"v([^"]+)"'],
    "k3s": [r"k3s version v(\S+)"],
    "etcd": [r"etcd Version: (\S+)"],
    "helm": [r"v(\d+\.\d+\.\d+)"],
    "imagemagick": [r"ImageMagick (\S+)"],
    "ffmpeg": [r"ffmpeg version (\S+)"],
    "zabbix": [r"\(Zabbix\) (\S+)"],
    "db2": [r"^\S+\s+(\d+\.\d+\.\d+\.\d+)", r"DB2 v(\d+\.\d+\.\d+\.\d+)"],   # db2ls / db2level
    "ibm-mq": [r"^Version:\s+(\S+)"],                                                    # dspmqver
}
# Empreintes statiques (chaînes compilées dans les binaires)
FP_PRODUCT_OF_PROBE = {"httpd": "httpd", "nginx": "nginx", "php": "php", "php-fpm": "php", "openssl": "openssl", "curl": "curl"}
FP_RUNTIME_PRODUCTS = set(["httpd", "nginx", "lighttpd", "php"])
GENERIC_VERSION_RX = r"(\d+\.\d+(?:\.\d+)*(?:[-+._]?[A-Za-z0-9]+)*)"

# Paquets OS -> famille de composant (pour la matrice)
PKG_FAMILIES = [
    (r"^java-[\d.]+-openjdk(-headless)?$|^openjdk-\d+-(jre|jdk)(-headless)?$|^temurin-\d+-(jdk|jre)$|^jdk-?\d|^jre-?\d", "java"),
    (r"^(rh-)?php\d*(-php)?-(cli|fpm)$|^php\d+\.\d+-(cli|fpm)$|^php\d+$", "php"),
    (r"^python(\d(\.\d+)?)?(-minimal)?$|^python3\d+$|^rh-python\d+-python$|^platform-python$", "python"),
    (r"^postgresql\d*-server$|^postgresql-\d+$", "postgresql"),
    (r"^(mysql-server|mysql-community-server|mysql-server-core-[\d.]+|percona-server-server.*)$", "mysql"),
    (r"^(mariadb-server|MariaDB-server|mariadb-server-core(-[\d.]+)?)$", "mariadb"),
    (r"^mongodb-org-server$|^mongodb-server$", "mongodb"),
    (r"^redis\d*(-server)?$", "redis"),
    (r"^nginx(-core|-light|-full|-extras)?$", "nginx"),
    (r"^httpd$|^apache2(-bin)?$", "httpd"),
    (r"^tomcat\d*$", "tomcat"),
    (r"^haproxy\d*$", "haproxy"),
    (r"^openssl-libs$|^libssl\d[\w.]*$|^openssl$", "openssl"),
    (r"^openssh-server$", "openssh"),
    (r"^glibc$|^libc6$|^musl$", "glibc"),
    (r"^nodejs$", "node"),
    (r"^ruby(\d\.\d+)?$", "ruby"),
    (r"^perl(-base)?$", "perl"),
    (r"^sudo$", "sudo"),
    (r"^bash$", "bash"),
    (r"^systemd$", "systemd"),
    (r"^(docker-ce|docker-engine|docker\.io|moby-engine)$", "docker"),
    (r"^podman$", "podman"),
    (r"^containerd(\.io)?$", "containerd"),
    (r"^kubelet$", "kubelet"),
    (r"^(kernel|kernel-core|kernel-uek(-core)?|linux-image-[\d.]+-\d+-[\w-]+)$", "linux-kernel-installed"),
    (r"^curl$", "curl"),
    (r"^xz(-libs)?$|^xz-utils$", "xz"),
    (r"^polkit$|^policykit-1$|^pkexec$", "polkit"),
    (r"^bind\d*$|^bind9$", "bind"),
    (r"^postfix$", "postfix"),
    (r"^samba$", "samba"),
    (r"^git$", "git"),
    (r"^ImageMagick$|^imagemagick-6\.q16$", "imagemagick"),
]
PKG_FAMILIES = [(re.compile(rx), fam) for rx, fam in PKG_FAMILIES]

# AIX : filesets installp (lslpp) -> famille
AIX_FILESET_FAMILIES = [
    (r"^Java\d+(_64)?\.(jre|sdk)$", "java"),
    (r"^openssl\.base$", "openssl"),
    (r"^openssh\.base\.server$", "openssh"),
    (r"^(bos\.)?perl\.rte$", "perl"),
    (r"^python\d\.\d+\.base$", "python"),
    (r"^bos\.net\.tcp\.sendmail$", "sendmail"),
    (r"^bos\.net\.tcp\.(bind|bind_utils)$", "bind"),
    (r"^mqm\.base\.runtime$", "ibm-mq"),
    (r"^db2_\d+_\d+\.", "db2"),
    (r"^bos\.rte$", "aix-bos"),
]
AIX_FILESET_FAMILIES = [(re.compile(rx), fam) for rx, fam in AIX_FILESET_FAMILIES]
# Méta-paquets Debian/Ubuntu sans version amont significative (php-cli = "2:8.3+93ubuntu2")
PKG_FAMILY_EXCLUDE = re.compile(r"^(php|php-cli|php-fpm|default-jre.*|default-jdk.*|python3-minimal)$")

# Famille -> (vendor, product) CPE 2.3 — INDICATIF (le dictionnaire NVD évolue)
CPE_MAP = {
    "python": ("python", "python"), "php": ("php", "php"), "php-fpm": ("php", "php"),
    "node": ("nodejs", "node.js"), "ruby": ("ruby-lang", "ruby"), "perl": ("perl", "perl"),
    "go": ("golang", "go"), "postgresql": ("postgresql", "postgresql"), "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"), "mongodb": ("mongodb", "mongodb"), "redis": ("redis", "redis"),
    "nginx": ("f5", "nginx"), "httpd": ("apache", "http_server"), "tomcat": ("apache", "tomcat"),
    "haproxy": ("haproxy", "haproxy"), "openssl": ("openssl", "openssl"), "openssh": ("openbsd", "openssh"),
    "sudo": ("sudo_project", "sudo"), "bash": ("gnu", "bash"), "glibc": ("gnu", "glibc"),
    "curl": ("haxx", "curl"), "git": ("git-scm", "git"), "imagemagick": ("imagemagick", "imagemagick"),
    "ghostscript": ("artifex", "ghostscript"), "ffmpeg": ("ffmpeg", "ffmpeg"), "xz": ("tukaani", "xz"),
    "polkit": ("polkit_project", "polkit"), "squid": ("squid-cache", "squid"), "bind": ("isc", "bind"),
    "postfix": ("postfix", "postfix"), "dovecot": ("dovecot", "dovecot"), "samba": ("samba", "samba"),
    "proftpd": ("proftpd", "proftpd"), "memcached": ("memcached", "memcached"),
    "grafana": ("grafana", "grafana"), "vault": ("hashicorp", "vault"), "consul": ("hashicorp", "consul"),
    "zabbix": ("zabbix", "zabbix"), "keepalived": ("keepalived", "keepalived"), "kubelet": ("kubernetes", "kubernetes"),
    "wordpress": ("wordpress", "wordpress"), "drupal": ("drupal", "drupal"), "joomla": ("joomla", "joomla\\!"),
    "phpmyadmin": ("phpmyadmin", "phpmyadmin"), "moodle": ("moodle", "moodle"), "mediawiki": ("mediawiki", "mediawiki"),
    "glpi": ("glpi-project", "glpi"), "roundcube": ("roundcube", "webmail"), "matomo": ("matomo", "matomo"),
    "limesurvey": ("limesurvey", "limesurvey"), "spip": ("spip", "spip"), "nextcloud-owncloud": ("nextcloud", "nextcloud_server"),
    "gitlab": ("gitlab", "gitlab"), "jquery": ("jquery", "jquery"), "jquery-ui": ("jqueryui", "jquery_ui"),
    "bootstrap": ("getbootstrap", "bootstrap"), "angular": ("angularjs", "angular.js"), "angularjs": ("angularjs", "angular.js"),
    "moment": ("momentjs", "moment"), "lodash": ("lodash", "lodash"), "tinymce": ("tiny", "tinymce"),
    "ckeditor": ("ckeditor", "ckeditor"), "dompurify": ("cure53", "dompurify"), "handlebars": ("handlebarsjs", "handlebars"),
    "linux-kernel": ("linux", "linux_kernel"), "lighttpd": ("lighttpd", "lighttpd"), "zlib": ("zlib", "zlib"),
    "sendmail": ("sendmail", "sendmail"), "websphere": ("ibm", "websphere_application_server"),
    "websphere-nd": ("ibm", "websphere_application_server"), "websphere-base": ("ibm", "websphere_application_server"),
    "ihs": ("ibm", "http_server"), "db2": ("ibm", "db2"), "ibm-mq": ("ibm", "websphere_mq"),
}

PURL_RPM_NS = {"rhel": "redhat", "centos": "centos", "rocky": "rocky", "almalinux": "almalinux", "ol": "oracle",
               "fedora": "fedora", "amzn": "amazon", "sles": "suse", "sled": "suse", "opensuse-leap": "opensuse",
               "opensuse-tumbleweed": "opensuse", "opensuse": "opensuse"}

# ID de os-release -> famille d'OS de Trivy, quand ils diffèrent
TRIVY_OS = {"rhel": "redhat", "ol": "oracle", "almalinux": "alma", "amzn": "amazon", "sled": "sles"}

# Colonnes de la matrice (familles), dans l'ordre d'affichage
MATRIX_FAMILIES = [
    "aix", "linux-kernel", "glibc", "openssl", "openssh", "sudo", "systemd", "polkit", "xz",
    "java", "php", "php-fpm", "python", "node", "ruby", "perl", "go", "dotnet",
    "websphere", "websphere-nd", "ihs", "websphere-plugin", "db2", "ibm-mq", "sendmail",
    "oracle-database", "oracle-grid", "oracle-client", "postgresql", "postgresql-datadir", "mysql", "mariadb", "mysql-datadir", "mongodb", "redis", "memcached",
    "nginx", "httpd", "tomcat", "jboss-wildfly-keycloak", "haproxy", "varnish", "squid",
    "docker", "podman", "containerd", "runc", "kubelet",
    "log4j-core", "log4j", "spring-core", "spring-webmvc", "spring-boot", "struts2-core", "jackson-databind",
    "commons-text", "commons-collections", "snakeyaml", "xstream", "fastjson",
    "wordpress", "drupal", "joomla", "glpi", "moodle", "mediawiki", "nextcloud-owncloud", "phpmyadmin",
    "spip", "dolibarr", "roundcube", "limesurvey", "matomo", "gitlab", "codeigniter", "smarty", "phpmailer",
    "zend-framework-1", "jquery",
]

# Familles de produits (serveurs, environnements d'exécution, socle). Une bibliothèque ne doit jamais
# en prendre le nom : le pilote JDBC postgresql-42.7.1.jar ou le paquet Python redis ne sont pas le
# serveur PostgreSQL ou Redis (matrice, fins de support, écarts, dossiers d'application).
# (Pas les paquets conda : un environnement conda embarque de vrais python, openssl, postgresql.)
LIBRARY_CATEGORIES = frozenset(["java-archive", "python-package", "npm-package", "ruby-gem", "go-module",
                                "composer-package", "dotnet-package"])
PRODUCT_FAMILIES = frozenset(MATRIX_FAMILIES[:MATRIX_FAMILIES.index("log4j-core")]) \
    | frozenset(cmdb_extras.SOFT_PRODUCTS) | frozenset(cmdb_dossier.KEY_FAMILIES)


def library_family(family, ecosystem):
    """Famille d'une bibliothèque : suffixée par son écosystème si elle porte le nom d'un produit."""
    if family and family in PRODUCT_FAMILIES:
        return "%s-%s" % (family, (ecosystem or "lib").split("-")[0])
    return family


def jar_family(family, group=None, manifest=None, version=None):
    """Pilotes JDBC nommés comme leur base : famille propre (postgresql-42.7.1.jar -> postgresql-jdbc)."""
    if family == "postgresql":
        sym = ((manifest or {}).get("Bundle-SymbolicName") or "").split(";")[0]
        major = re.match(r"^(\d+)\.", version or "")
        if group == "org.postgresql" or sym.startswith("org.postgresql") or (not group and major and int(major.group(1)) >= 8):
            return "postgresql-jdbc"
    return family


# ---------------------------------------------------------------------------
# Utilitaires
# ---------------------------------------------------------------------------

# Types de châssis SMBIOS (/sys/class/dmi/id/chassis_type)
CHASSIS_TYPES = {"1": "autre", "3": "poste de travail", "4": "poste bas", "6": "mini-tour", "7": "tour",
                 "9": "portable", "10": "portable", "13": "tout-en-un", "17": "serveur", "23": "serveur rack",
                 "24": "boîtier sealed-case", "25": "châssis multi-système", "28": "lame", "29": "châssis de lames",
                 "30": "tablette", "31": "convertible", "35": "mini PC", "36": "stick PC"}


def strip_ids(v):
    """"Intel Corporation [8086]" -> "Intel Corporation"."""
    return re.sub(r"\s*\[[0-9a-fA-F]{4}\]$", "", v) if v else v


def parse_dmi_memory(text):
    """Barrettes mémoire depuis la sortie brute de dmidecode (collecte en root)."""
    mods = []
    for block in re.split(r"\n(?=Handle 0x)", text or ""):
        lines = block.splitlines()
        if len(lines) < 2 or lines[1].strip() != "Memory Device":
            continue
        kv = {}
        for line in lines[2:]:
            if line.startswith("\t") and ":" in line and not line.startswith("\t\t"):
                k, v = line.strip().split(":", 1)
                kv[k.strip()] = v.strip()
        if kv.get("Size") and "No Module" not in kv["Size"]:
            mods.append(kv)
    return mods

def first_match(rxs, text):
    for rx in rxs:
        m = re.search(rx, text or "", re.M)
        if m:
            return next((g for g in m.groups() if g), None)
    return None


def cpe_escape(v):
    return re.sub(r"([^A-Za-z0-9._\-])", r"\\\1", v)


def make_cpe(family, version, update="*"):
    if not version or family not in CPE_MAP:
        return None
    vendor, product = CPE_MAP[family]
    return "cpe:2.3:a:%s:%s:%s:%s:*:*:*:*:*:*" % (vendor, product, cpe_escape(version), update)


def java_cpe(version, vendor_text):
    if not version:
        return None
    product = "jdk" if vendor_text and "Oracle" in vendor_text and "OpenJDK" not in vendor_text else "openjdk"
    m = re.match(r"^1\.(\d+)\.(\d+)_(\d+)", version)
    if m:
        return "cpe:2.3:a:oracle:%s:1.%s.%s:update%s:*:*:*:*:*:*" % (product, m.group(1), m.group(2), m.group(3))
    return "cpe:2.3:a:oracle:%s:%s:*:*:*:*:*:*:*" % (product, cpe_escape(version.split("+")[0]))


def purl(ptype, name, version, namespace=None, qualifiers=None):
    if not name:
        return None
    parts = "pkg:%s/" % ptype
    if namespace:
        parts += "/".join(quote(seg, safe="") for seg in namespace.split("/")) + "/"
    parts += quote(name, safe="")
    if version:
        parts += "@" + quote(version, safe="+")
    if qualifiers:
        q = "&".join("%s=%s" % (k, quote(str(v), safe=":/")) for k, v in sorted(qualifiers.items()) if v not in (None, ""))
        if q:
            parts += "?" + q
    return parts


def short_version(v, eco="deb"):
    """Version "amont" lisible : retire l'epoch et la révision de distribution
    (Debian : tout ce qui suit le dernier tiret ; Alpine : le suffixe -rN)."""
    if not v:
        return v
    v = re.sub(r"^\d+:", "", v)
    if eco == "apk":
        return re.sub(r"-r\d+$", "", v)
    if "-" in v:
        v = v.rsplit("-", 1)[0]
    return v


# Formats de collecte lus par cette consolidation (voir docs/format-collecte.md). Un document
# sans « schema » vient d'une version antérieure au gel (collecteur PowerShell 0.1.0) : lu comme v1.
SUPPORTED_SCHEMAS = ("cmdb-collector/1",)


def schema_supported(doc):
    schema = doc.get("schema")
    return schema is None or schema in SUPPORTED_SCHEMAS


NA = "NA"   # application / plate-forme non renseignée (anciennes collectes non étiquetées)


def safe_name(*parts):
    return "__".join(re.sub(r"[^\w.\-]", "_", p or NA) for p in parts)


class Store(object):
    """Collectes lues dans des répertoires (récursivement) et des lots .tar.gz.

    Clé : (application, plate-forme, hôte), lue dans le document (meta.tags) et non
    dans le chemin : un fichier déplacé ou renommé reste correctement rattaché.
    Pour chaque clé on garde la collecte la plus récente (meta.started_at).

    Mémoire : seul l'en-tête (meta) des collectes retenues reste en mémoire, avec de quoi
    les relire : chemin du fichier, ou contenu encore compressé pour un lot. Les documents
    sont relus un à un au moment de remplir la base (current(), previous_docs())."""

    def __init__(self, default_app=NA, default_platform=NA, apps=None, platforms=None, hosts=None, history=True):
        self.docs = {}       # clé -> (meta, réf. document, réf. faits Ansible, source)
        self.previous = {}   # clé -> (meta, réf. document, source) : avant-dernière collecte
        self.history = history
        self.runs = {}       # run_id -> manifeste
        self.dir_runs = set()   # passages présents dans les magasins lus (pour ignorer leurs lots)
        self.default_app, self.default_platform = default_app, default_platform
        self.filters = (apps or [], platforms or [], hosts or [])
        self.read = self.skipped = 0
        self.unsupported = []   # (source, schema) : format plus récent que cette consolidation

    @staticmethod
    def _match(v, pats):
        return not pats or any(fnmatch.fnmatchcase(v, p) for p in pats)

    @staticmethod
    def _head(doc):
        """Ce qu'il faut garder d'un document pour le classer : meta et nom d'hôte de secours."""
        return {"schema": doc.get("schema"), "meta": doc.get("meta") or {}, "os": {"hostname": (doc.get("os") or {}).get("hostname")}}

    @staticmethod
    def load(ref):
        """Relit un document ou des faits : ("file", chemin), ("gz", octets) ou ("z", octets zlib)."""
        if ref is None:
            return None
        kind, data = ref
        if kind == "file":
            if data.endswith(".gz"):
                with gzip.open(data, "rb") as f:
                    return json.loads(f.read().decode("utf-8"))
            with open(data, encoding="utf-8") as f:
                return json.load(f)
        if kind == "gz":
            return json.loads(gzip.decompress(data).decode("utf-8"))
        return json.loads(zlib.decompress(data).decode("utf-8"))

    def offer(self, doc, ref, facts, source, fallback_host, counted=True):
        if not schema_supported(doc):
            # Jamais lu à moitié : un format inconnu est écarté et signalé (mettre à jour la consolidation)
            self.unsupported.append((source, doc.get("schema")))
            return
        meta = doc.get("meta") or {}
        tags = meta.get("tags") or {}
        key = (tags.get("app") or self.default_app, tags.get("platform") or self.default_platform,
               meta.get("host_label") or fallback_host or (doc.get("os") or {}).get("hostname") or "inconnu")
        if not all(self._match(v, f) for v, f in zip(key, self.filters)):
            self.skipped += 1
            return
        if counted:
            self.read += 1
        cur = self.docs.get(key)
        stamp = meta.get("started_at") or ""
        if cur is None or stamp >= (cur[0].get("started_at") or ""):
            if cur is not None and cur[0].get("run_id") != meta.get("run_id"):
                self._offer_previous(key, cur[0], cur[1], cur[3])
            self.docs[key] = (meta, ref, facts, source)
        elif cur[0].get("run_id") != meta.get("run_id"):
            self._offer_previous(key, meta, ref, source)

    def _offer_previous(self, key, meta, ref, source):
        if not self.history:
            return
        stamp = meta.get("started_at") or ""
        old = self.previous.get(key)
        if old is None or stamp >= (old[0].get("started_at") or ""):
            self.previous[key] = (meta, ref, source)

    def current(self):
        """(clé, document, faits, source) des collectes retenues, relues une à une."""
        for key in sorted(self.docs):
            meta, ref, fref, source = self.docs[key]
            try:
                doc = self.load(ref)
            except (OSError, ValueError, EOFError) as e:
                print("ERREUR relecture %s : %s" % (source, e), file=sys.stderr)
                continue
            try:
                facts = self.load(fref)
            except (OSError, ValueError, EOFError):
                facts = None
            yield key, doc, facts, source

    def previous_docs(self):
        """(clé, (document, source)) des avant-dernières collectes, relues une à une."""
        for key in sorted(self.previous):
            meta, ref, source = self.previous[key]
            try:
                yield key, (self.load(ref), source)
            except (OSError, ValueError, EOFError) as e:
                print("ERREUR relecture %s : %s" % (source, e), file=sys.stderr)

    def metas(self):
        return dict((k, v[0]) for k, v in self.docs.items())

    def add_manifest(self, m, source):
        """_runs/<run_id>/_run.json (en-tête) ou _runs/<run_id>/<app>__<pf>__<hôte>.json (statut d'un hôte)."""
        if not isinstance(m, dict) or not m.get("run_id"):
            return
        r = self.runs.setdefault(m["run_id"], {"run_id": m["run_id"], "hosts": {}})
        if m.get("host"):
            r["hosts"][(m.get("app") or NA, m.get("platform") or NA, m["host"])] = m
        else:
            r.update((k, v) for k, v in m.items() if k != "hosts")
            r["_source"] = source

    def add_dir(self, root):
        for d, dirs, files in os.walk(root):
            dirs.sort()
            if os.path.basename(d) == "_lots":
                dirs[:] = []
                continue
            rel = os.path.relpath(d, root).split(os.sep)
            if "_runs" in rel:
                if rel[-1] != "_runs":
                    self.dir_runs.add(rel[-1])
                for f in sorted(files):
                    if f.endswith(".json"):
                        try:
                            with open(os.path.join(d, f), encoding="utf-8") as fh:
                                m = json.load(fh)
                            self.add_manifest(m, os.path.join(d, f))
                            if isinstance(m, dict) and m.get("run_id"):
                                self.dir_runs.add(m["run_id"])
                        except (OSError, ValueError) as e:
                            print("ERREUR manifeste %s : %s" % (f, e), file=sys.stderr)
                continue
            cands = sorted(f for f in files if f.endswith(".json.gz"))
            if not cands:
                continue
            path = os.path.join(d, "latest.json.gz" if "latest.json.gz" in cands else cands[-1])
            try:
                head = self._head(self.load(("file", path)))
            except (OSError, ValueError, EOFError) as e:
                print("ERREUR lecture %s : %s" % (path, e), file=sys.stderr)
                continue
            fref = None
            rid = head["meta"].get("run_id")
            fcands = sorted(f for f in files if f.endswith(".ansible_facts.json"))
            fpath = rid and "%s.ansible_facts.json" % rid in fcands and "%s.ansible_facts.json" % rid or (fcands[-1] if fcands else None)
            if fpath:
                fref = ("file", os.path.join(d, fpath))
            self.offer(head, ("file", path), fref, path, os.path.basename(d))
            if self.history:
                # Collectes horodatées : la plus récente dont le passage diffère de celui de latest
                for f in reversed(cands):
                    if f == "latest.json.gz" or f == "%s.json.gz" % rid:
                        continue
                    p = os.path.join(d, f)
                    try:
                        self.offer(self._head(self.load(("file", p))), ("file", p), None, p, os.path.basename(d), counted=False)
                    except (OSError, ValueError, EOFError) as e:
                        print("ERREUR lecture %s : %s" % (f, e), file=sys.stderr)
                    break

    def add_lot(self, lot):
        """Lot transféré depuis une autre plate-forme : lu sans extraction sur disque.
        Les documents retenus restent compressés en mémoire jusqu'à leur relecture.
        Renvoie le passage déjà présent dans un magasin lu (lot ignoré), sinon None."""
        facts_by_dir, docs = {}, []
        with tarfile.open(lot, "r:*") as tf:
            for m in tf:
                name = m.name
                parts = ("/" + name).split("/")
                if "_runs" in parts and parts.index("_runs") + 1 < len(parts):
                    rid = parts[parts.index("_runs") + 1]
                    if rid in self.dir_runs:
                        return rid
                if not m.isfile():
                    continue
                try:
                    if name.endswith(".json.gz"):
                        raw = tf.extractfile(m).read()
                        docs.append((name, self._head(json.loads(gzip.decompress(raw).decode("utf-8"))), raw))
                    elif name.endswith(".ansible_facts.json"):
                        raw = tf.extractfile(m).read()
                        json.loads(raw.decode("utf-8"))
                        facts_by_dir[os.path.dirname(name)] = ("z", zlib.compress(raw, 1))
                    elif "/_runs/" in "/" + name and name.endswith(".json"):
                        self.add_manifest(json.loads(tf.extractfile(m).read().decode("utf-8")), "%s:%s" % (lot, name))
                except (OSError, ValueError, EOFError) as e:
                    print("ERREUR %s:%s : %s" % (lot, name, e), file=sys.stderr)
        for name, head, raw in docs:
            d = os.path.dirname(name)
            self.offer(head, ("gz", raw), facts_by_dir.get(d), "%s:%s" % (lot, name), os.path.basename(d))
        return None


# ---------------------------------------------------------------------------
# Schéma SQLite
# ---------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE hosts (host TEXT, hostname TEXT, fqdn TEXT, machine_id TEXT, os_id TEXT, os_version TEXT,
  os_pretty TEXT, kernel TEXT, arch TEXT, virtualization TEXT, sys_vendor TEXT, product_name TEXT, serial TEXT,
  cpu_model TEXT, cpu_count INTEGER, mem_total_mb INTEGER, boot_time TEXT, uptime_days REAL, selinux TEXT,
  reboot_required TEXT, ip_addresses TEXT, collected_at TEXT, collector_version TEXT, fs_scan_truncated INTEGER,
  collect_errors INTEGER, source_file TEXT, privileged INTEGER, collect_user TEXT, processes_visible INTEGER,
  processes_exe_readable INTEGER, fs_unreadable_dirs INTEGER, board TEXT, bios_version TEXT, bios_date TEXT,
  chassis TEXT, cpu_sockets INTEGER, cpu_cores INTEGER, cpu_threads INTEGER, hypervisor TEXT, mac_addresses TEXT,
  nic_count INTEGER, disk_total_gb REAL, run_id TEXT, tags TEXT, PRIMARY KEY (app, platform, host));
CREATE TABLE interfaces (host TEXT, ifname TEXT, kind TEXT, mac TEXT, permanent_mac TEXT, mtu INTEGER, state TEXT,
  speed_mbps INTEGER, duplex TEXT, driver TEXT, driver_version TEXT, firmware TEXT, pci_slot TEXT, model TEXT,
  vendor TEXT, master TEXT, parent TEXT, vlan_id INTEGER, members TEXT, ipv4 TEXT, ipv6 TEXT);
CREATE TABLE disks (host TEXT, name TEXT, transport TEXT, size_gb REAL, model TEXT, vendor TEXT, serial TEXT,
  wwn TEXT, rotational INTEGER, removable INTEGER, read_only INTEGER, dm_name TEXT, slaves TEXT, controller TEXT);
CREATE TABLE filesystems (host TEXT, mountpoint TEXT, device TEXT, fstype TEXT, size_gb REAL, used_gb REAL,
  free_gb REAL, used_pct REAL, free_pct REAL, inodes_used_pct REAL, network INTEGER, options TEXT);
CREATE TABLE pci_devices (host TEXT, slot TEXT, class TEXT, vendor TEXT, device TEXT, subsystem TEXT, driver TEXT, rev TEXT);
CREATE TABLE fc_hosts (host TEXT, name TEXT, wwpn TEXT, wwnn TEXT, state TEXT, speed TEXT, port_type TEXT, model TEXT);
CREATE TABLE memory_modules (host TEXT, locator TEXT, size TEXT, type TEXT, speed TEXT, manufacturer TEXT,
  part_number TEXT, serial TEXT);
CREATE TABLE packages (host TEXT, manager TEXT, name TEXT, epoch TEXT, version TEXT, release TEXT, arch TEXT,
  vendor TEXT, source TEXT, source_version TEXT, installtime TEXT, summary TEXT, purl TEXT);
CREATE TABLE software (host TEXT, category TEXT, ecosystem TEXT, family TEXT, name TEXT, version TEXT,
  location TEXT, evidence TEXT, owner_pkg TEXT, managed INTEGER, purl TEXT, cpe TEXT, extra TEXT);
CREATE TABLE java_markers (host TEXT, archive TEXT, marker TEXT, shaded INTEGER);
CREATE TABLE processes (host TEXT, pid INTEGER, ppid INTEGER, user TEXT, comm TEXT, exe TEXT, exe_owner_pkg TEXT,
  cmdline TEXT, start TEXT, rss_mb REAL, in_container INTEGER, container_id TEXT, systemd_unit TEXT,
  deleted_files_count INTEGER, deleted_files TEXT, open_archives TEXT);
CREATE TABLE listening (host TEXT, proto TEXT, address TEXT, port INTEGER, pid INTEGER, process TEXT, user TEXT);
CREATE TABLE connections (host TEXT, direction TEXT, local_port INTEGER, remote_addr TEXT, remote_port INTEGER,
  process TEXT, count INTEGER);
CREATE TABLE services (host TEXT, unit TEXT, load TEXT, active TEXT, sub TEXT, unit_file_state TEXT,
  main_pid INTEGER, exec_start TEXT, user TEXT, fragment_path TEXT, description TEXT);
CREATE TABLE container_images (host TEXT, engine TEXT, image TEXT, image_id TEXT, containers TEXT, os_id TEXT, os_version TEXT,
  os_pretty TEXT, packages INTEGER, components INTEGER, truncated INTEGER, seconds REAL, note TEXT);
CREATE TABLE container_packages (host TEXT, image_id TEXT, image TEXT, manager TEXT, name TEXT, epoch TEXT, version TEXT,
  release TEXT, arch TEXT, vendor TEXT, source TEXT, purl TEXT);
CREATE TABLE containers (host TEXT, engine TEXT, kind TEXT, id TEXT, name TEXT, image TEXT, digest TEXT,
  status TEXT, created TEXT);
CREATE TABLE cpu_vulnerabilities (host TEXT, name TEXT, status TEXT);
CREATE TABLE kernel_modules (host TEXT, name TEXT);
CREATE TABLE accounts (host TEXT, name TEXT, uid TEXT, gid TEXT, home TEXT, shell TEXT, gecos TEXT);
CREATE TABLE addresses (host TEXT, ifname TEXT, family TEXT, cidr TEXT, scope TEXT, label TEXT, secondary INTEGER,
  mac TEXT);
CREATE TABLE probe_outputs (host TEXT, probe TEXT, realpath TEXT, paths TEXT, owner_pkg TEXT, run_as_uid INTEGER,
  skipped TEXT, args TEXT, rc INTEGER, output TEXT);
CREATE TABLE collect_errors (host TEXT, section TEXT, error TEXT);
CREATE TABLE raw_documents (host TEXT, collected_at TEXT, document TEXT, ansible_facts TEXT,
  PRIMARY KEY (app, platform, host));

CREATE INDEX ix_soft_name ON software(name, version);
CREATE INDEX ix_soft_host ON software(app, platform, host);
CREATE INDEX ix_soft_family ON software(family, version);
CREATE INDEX ix_soft_purl ON software(purl);
CREATE INDEX ix_pkg_name ON packages(name, version);

CREATE VIEW v_unmanaged_software AS
  SELECT * FROM software WHERE managed = 0 AND category NOT IN ('os-package');
CREATE VIEW v_restart_needed AS
  SELECT app, platform, host, pid, user, comm, exe, deleted_files_count, deleted_files FROM processes
  WHERE deleted_files_count > 0 ORDER BY app, platform, host, deleted_files_count DESC;
CREATE VIEW v_listening_detail AS
  SELECT l.app, l.platform, l.host, l.proto, l.address, l.port, l.process, l.user, p.exe, p.exe_owner_pkg,
         CASE WHEN p.exe_owner_pkg IS NULL THEN 0 ELSE 1 END AS exe_managed, p.cmdline
  FROM listening l LEFT JOIN processes p
    ON p.app = l.app AND p.platform = l.platform AND p.host = l.host AND p.pid = l.pid;
CREATE VIEW v_java_risky AS
  SELECT app, platform, host, archive, marker FROM java_markers
  WHERE marker LIKE 'log4j2-core:JndiLookup%' OR marker LIKE 'log4j1:%'
     OR marker LIKE 'commons-collections%InvokerTransformer%' OR marker LIKE 'commons-text:ScriptStringLookup%';
CREATE VIEW v_runtimes AS
  SELECT app, platform, host, family, version, managed, location, evidence, owner_pkg FROM software
  WHERE category IN ('runtime', 'webapp', 'db-datadir', 'embedded') ORDER BY app, platform, host, family;
CREATE VIEW v_filesystems_full AS
  SELECT app, platform, host, mountpoint, fstype, size_gb, used_gb, free_gb, used_pct, free_pct, inodes_used_pct
  FROM filesystems WHERE (used_pct >= 90 OR inodes_used_pct >= 90) AND fstype NOT IN ('tmpfs', 'devtmpfs', 'overlay')
    AND size_gb > 0
  ORDER BY used_pct DESC;
CREATE VIEW v_applications AS
  SELECT app, platform, COUNT(*) AS hosts, MIN(collected_at) AS oldest_collect, MAX(collected_at) AS newest_collect,
         GROUP_CONCAT(DISTINCT os_pretty) AS os
  FROM hosts GROUP BY app, platform ORDER BY app, platform;
"""
SCHEMA += cmdb_extras.SCHEMA_HOST
# Toutes les tables de données portent l'application et la plate-forme en tête
SCHEMA = re.sub(r"CREATE TABLE (\w+) \(host TEXT", r"CREATE TABLE \1 (app TEXT, platform TEXT, host TEXT", SCHEMA)
SCHEMA += """
CREATE TABLE runs (run_id TEXT, app TEXT, platform TEXT, host TEXT, status TEXT, collector TEXT, started_at TEXT,
  file TEXT, detail TEXT, manifest TEXT);
"""
SCHEMA += cmdb_extras.SCHEMA_GLOBAL
SCHEMA += """
CREATE TABLE eol_reference (product TEXT, cycle TEXT, eol TEXT, extended TEXT);
"""
SCHEMA += cmdb_cve.SCHEMA


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

class JavaDb(object):
    """Base trivy-java.db, en lecture seule : SHA-1 d'une archive -> coordonnées Maven.

    Sert aux archives sans pom.properties. Tout se passe en local : aucune empreinte ne sort."""

    def __init__(self, path):
        self.path = path
        self.cache = {}
        self.without_pom = self.hashed = self.found = 0
        uri = "file:%s?mode=ro" % quote(os.path.abspath(path))
        try:
            self.db = sqlite3.connect(uri, uri=True)
            self.db.execute("SELECT a.group_id, a.artifact_id, i.version, i.sha1 FROM indices i "
                            "JOIN artifacts a ON a.id = i.artifact_id LIMIT 1").fetchall()
        except sqlite3.Error as e:
            raise ValueError("%s n'est pas une base trivy-java.db lisible : %s" % (path, e))

    def find(self, sha1):
        """(groupId, artifactId, version) de cette empreinte, ou None."""
        self.without_pom += 1
        if not sha1 or not re.match(r"^[0-9a-fA-F]{40}$", sha1):
            return None
        self.hashed += 1
        key = sha1.lower()
        if key not in self.cache:
            self.cache[key] = self.db.execute(
                "SELECT a.group_id, a.artifact_id, i.version FROM indices i JOIN artifacts a ON a.id = i.artifact_id "
                "WHERE i.sha1 = ?", (bytes.fromhex(key),)).fetchone()
        hit = self.cache[key]
        if hit and hit[0] and hit[1] and hit[2]:
            self.found += 1
            return hit
        return None


class Builder(cmdb_extras.ExtrasMixin):

    def __init__(self, db, java_db=None):
        self.db = db
        self.java_db = java_db
        self.rows = {}
        self.app = self.platform = NA
        self.flrtvc = []

    def add(self, table, row):
        self.rows.setdefault(table, []).append((self.app, self.platform) + tuple(row))

    def soft(self, host, category, ecosystem, family, name, version, location, evidence=None, owner_pkg=None,
             managed=None, purl_=None, cpe=None, extra=None):
        if managed is None:
            managed = 1 if owner_pkg else 0
        if category in LIBRARY_CATEGORIES:
            family = library_family(family, ecosystem)
        self.add("software", (host, category, ecosystem, family, name, version, location, evidence, owner_pkg,
                              managed, purl_, cpe, json.dumps(extra, ensure_ascii=False) if extra else None))

    def flush(self):
        for table, rows in self.rows.items():
            if not rows:
                continue
            ph = ",".join("?" * len(rows[0]))
            self.db.executemany("INSERT INTO %s VALUES (%s)" % (table, ph), rows)
        self.rows = {}

    # -- par hôte ---------------------------------------------------------
    def process_host(self, key, doc, facts, source):
        self.app, self.platform, host = key
        osd = doc.get("os") or {}
        osr = osd.get("os_release") or {}
        os_id = (osr.get("ID") or "").lower()
        os_ver = osr.get("VERSION_ID") or ""
        hw = doc.get("hardware") or {}
        dmi = hw.get("dmi") or {}
        cpu = hw.get("cpu") or {}
        fs = doc.get("filesystem") or {}
        meta = doc.get("meta") or {}
        net = doc.get("network") or {}
        # adresses globales avec leur interface : "eth0=10.1.2.3/24 bond0.100=10.9.0.4/24"
        ips = []
        for a in net.get("addresses") or []:
            if a.get("scope") in ("global", None):
                lbl = "%s=%s" % (a.get("label") or a.get("ifname"), a.get("cidr"))
                if lbl not in ips:
                    ips.append(lbl)
        nr = osd.get("needs_restarting_r") or {}
        reboot = "oui" if osd.get("reboot_required_file") or nr.get("rc") == 1 else ("non" if nr or "reboot_required_file" in osd else None)
        uname = osd.get("uname") or {}
        self.add("hosts", (
            host, osd.get("hostname"), osd.get("fqdn"), osd.get("machine_id"), os_id, os_ver, osr.get("PRETTY_NAME"),
            uname.get("release"), uname.get("machine"), hw.get("virtualization"), dmi.get("sys_vendor"),
            dmi.get("product_name"), dmi.get("product_serial"), cpu.get("model name"), cpu.get("count"),
            int((hw.get("meminfo_kb") or {}).get("MemTotal", 0) / 1024) or None, osd.get("boot_time"),
            round(osd["uptime_seconds"] / 86400, 1) if osd.get("uptime_seconds") else None,
            osd.get("selinux_getenforce"), reboot, " ".join(ips), meta.get("started_at"), meta.get("collector_version"),
            1 if (fs.get("stats") or {}).get("truncated") else 0, len(meta.get("errors") or []), source,
            1 if str(meta.get("uid")) == "0" else 0, meta.get("user") or str(meta.get("uid")),
            (meta.get("visibility") or {}).get("processes"), (meta.get("visibility") or {}).get("processes_exe_readable"),
            (meta.get("visibility") or {}).get("fs_unreadable_dirs")) + self.hardware(host, doc)
            + (meta.get("run_id"), json.dumps(meta.get("tags"), ensure_ascii=False, sort_keys=True) if meta.get("tags") else None))
        for e in meta.get("errors") or []:
            self.add("collect_errors", (host, e.get("section"), e.get("error")))
        self.add("raw_documents", (host, meta.get("started_at"), json.dumps(doc, ensure_ascii=False),
                                   json.dumps(facts, ensure_ascii=False) if facts else None))

        # Noyau en cours d'exécution (AIX : niveau oslevel -s)
        aix = osd.get("aix") or {}
        if os_id == "aix":
            self.soft(host, "runtime", "os", "aix", "aix", aix.get("oslevel_s") or os_ver, "/", "oslevel -s", managed=1,
                      cpe="cpe:2.3:o:ibm:aix:%s:*:*:*:*:*:*:*" % cpe_escape(os_ver) if os_ver else None)
            if aix.get("lslpp_Lcq_raw"):
                self.flrtvc.append((self.app, self.platform, host, aix.get("lslpp_Lcq_raw"),
                                    aix.get("emgr_raw") if aix.get("emgr_rc") == 0 else None))
        elif uname.get("release"):
            kv = uname["release"]
            self.soft(host, "runtime", "os", "linux-kernel", "linux-kernel", kv, "/boot", "uname -r", managed=1,
                      cpe=make_cpe("linux-kernel", re.split(r"[-+]", kv)[0]))

        self.fp_seen = set()
        self.packages(host, doc, os_id, os_ver)
        self.processes(host, doc)
        self.network(host, doc)
        self.services(host, doc)
        self.containers(host, doc)
        self.container_content(host, doc)
        self.misc(host, doc)
        self.runtimes(host, doc)
        self.filesystem(host, doc, fs)
        self.go_binaries(host, doc)
        self.process_artifacts(host, doc)
        self.extras(host, doc)

    def hardware(self, host, doc):
        """Tables matériel ; renvoie les colonnes matériel ajoutées à "hosts"."""
        hw = doc.get("hardware") or {}
        net = doc.get("network") or {}
        dmi = hw.get("dmi") or {}
        pci = hw.get("pci") or {}
        lk = hw.get("lscpu_kv") or {}
        hn = hw.get("hostnamectl_kv") or {}
        for slot, p in sorted(pci.items()):
            self.add("pci_devices", (host, slot, p.get("Class"), p.get("Vendor"), p.get("Device"),
                                     " ".join(x for x in (p.get("SVendor"), p.get("SDevice")) if x) or None,
                                     p.get("Driver"), p.get("Rev")))
        addrs = {}
        for a in net.get("addresses") or []:
            addrs.setdefault((a.get("ifname"), a.get("family")), []).append(a.get("cidr") + (" (%s)" % a["label"] if a.get("label") else ""))
        macs = []
        nphys = 0
        for i in net.get("interfaces") or []:
            et = i.get("ethtool") or {}
            p = pci.get(i.get("pci_slot") or "", {})
            try:
                speed = int(i.get("speed")) if i.get("speed") and int(i.get("speed")) > 0 else None
            except ValueError:
                speed = None
            members = i.get("bond_slaves") or i.get("bridge_ports") or []
            self.add("interfaces", (
                host, i.get("name"), i.get("kind"), i.get("address"), i.get("permanent_address"),
                int(i["mtu"]) if str(i.get("mtu") or "").isdigit() else None, i.get("operstate"), speed,
                i.get("duplex") if i.get("duplex") not in (None, "unknown") else None,
                et.get("driver") or i.get("driver"), et.get("version"), et.get("firmware-version"), i.get("pci_slot"),
                strip_ids(p.get("Device")), strip_ids(p.get("Vendor")), i.get("master"), i.get("parent"), i.get("vlan_id"),
                " ".join(members) or None, ", ".join(addrs.get((i.get("name"), "inet"), [])) or None,
                ", ".join(addrs.get((i.get("name"), "inet6"), [])) or None))
            if i.get("kind") not in ("loopback",) and i.get("address") and i.get("address") != "00:00:00:00:00:00":
                if i.get("kind") == "physical":
                    nphys += 1
                    macs.append("%s=%s" % (i["name"], i.get("permanent_address") or i["address"]))
        total = 0.0
        for dsk in hw.get("disks") or []:
            gb = round((dsk.get("size_bytes") or 0) / 1e9, 1)
            if dsk.get("transport") not in ("device-mapper", "md") and not dsk.get("slaves"):
                total += gb
            p = pci.get(dsk.get("pci_slot") or "", {})
            self.add("disks", (host, dsk.get("name"), dsk.get("transport"), gb, dsk.get("model"), dsk.get("vendor"),
                               dsk.get("serial"), dsk.get("wwn") or dsk.get("wwid"),
                               int(dsk["rotational"]) if str(dsk.get("rotational", "")).isdigit() else None,
                               int(dsk["removable"]) if str(dsk.get("removable", "")).isdigit() else None,
                               int(dsk["ro"]) if str(dsk.get("ro", "")).isdigit() else None,
                               dsk.get("dm_name"), " ".join(dsk.get("slaves") or []) or None, strip_ids(p.get("Device"))))
        # Systèmes de fichiers montés : total / utilisé / libre, en Go et en %.
        # Pourcentages calculés comme df : utilisé / (utilisé + disponible), la réserve root étant
        # exclue de « libre » (espace réellement disponible pour les applications).
        net_fs = ("nfs", "nfs3", "nfs4", "cifs", "smb3", "smbfs", "ceph", "glusterfs", "9p", "gpfs", "mmfs", "lustre",
                  "beegfs", "afs", "davfs", "ocfs2", "gfs2", "sshfs", "fuse.sshfs", "stnfs")
        seen = {}
        for m in hw.get("mounts") or []:
            if m.get("mountpoint"):
                seen[m["mountpoint"]] = m          # montages empilés : le dernier l'emporte, comme df
        for mp, m in sorted(seen.items()):
            size, used, avail = m.get("size_bytes"), m.get("used_bytes"), m.get("avail_bytes")
            gb = (lambda b: round(b / 1073741824.0, 2) if isinstance(b, (int, float)) else None)
            base = (used or 0) + (avail or 0)
            upct = round(100.0 * used / base, 1) if base and used is not None and avail is not None else None
            ipct = m.get("inodes_used_pct")
            if ipct is None and m.get("inodes") and m.get("inodes_free") is not None:
                ipct = round(100.0 * (m["inodes"] - m["inodes_free"]) / m["inodes"], 1)
            fst = m.get("fstype")
            self.add("filesystems", (host, mp, m.get("device"), fst, gb(size), gb(used), gb(avail), upct,
                                     round(100.0 - upct, 1) if upct is not None else None, ipct,
                                     1 if (fst in net_fs or (fst or "").startswith("nfs")
                                           or re.match(r"^[^/][^:]*:", m.get("device") or "")) else 0, m.get("options")))
        for f in hw.get("fc_hosts") or []:
            self.add("fc_hosts", (host, f.get("name"), f.get("port_name"), f.get("node_name"), f.get("port_state"),
                                  f.get("speed"), f.get("port_type"), f.get("symbolic_name")))
        for m in parse_dmi_memory(hw.get("dmidecode")):
            self.add("memory_modules", (host, m.get("Locator"), m.get("Size"), m.get("Type"),
                                        m.get("Configured Memory Speed") or m.get("Speed"), m.get("Manufacturer"),
                                        m.get("Part Number"), m.get("Serial Number")))

        def as_int(v):
            try:
                return int(v)
            except (TypeError, ValueError):
                return None
        sockets = as_int(lk.get("Socket(s)"))
        cores = as_int(lk.get("Core(s) per socket"))
        tpc = as_int(lk.get("Thread(s) per core"))
        chassis = hn.get("Chassis") or CHASSIS_TYPES.get(dmi.get("chassis_type"))
        board = " ".join(x for x in (dmi.get("board_vendor"), dmi.get("board_name")) if x) or None
        return (board, dmi.get("bios_version"), dmi.get("bios_date"), chassis, sockets,
                sockets * cores if sockets and cores else None,
                sockets * cores * tpc if sockets and cores and tpc else None,
                lk.get("Hypervisor vendor") or (hw.get("virtualization") if hw.get("virtualization") not in (None, "none") else None),
                " ".join(macs) or None, nphys, round(total, 1))

    def packages(self, host, doc, os_id, os_ver):
        mgrs = ((doc.get("packages") or {}).get("managers") or {})
        distro = "%s-%s" % (os_id, os_ver) if os_id else None
        for row in mgrs.get("rpm") or []:
            if row.get("name") == "gpg-pubkey":
                continue
            ns = PURL_RPM_NS.get(os_id, os_id or "rpm")
            p = purl("rpm", row["name"], "%s-%s" % (row.get("version"), row.get("release")), ns,
                     {"arch": row.get("arch"), "epoch": row.get("epoch"), "distro": distro, "upstream": row.get("sourcerpm")})
            self.add("packages", (host, "rpm", row["name"], row.get("epoch"), row.get("version"), row.get("release"),
                                  row.get("arch"), row.get("vendor"), row.get("sourcerpm"), None, row.get("installtime"),
                                  row.get("summary"), p))
            self._pkg_soft(host, "rpm", row["name"], "%s-%s" % (row.get("version"), row.get("release")),
                           row.get("version"), p)
        for row in mgrs.get("dpkg") or []:
            st = row.get("status") or ""
            if st and not (st.startswith("ii") or "installed" in st and "not-installed" not in st):
                continue
            ns = "ubuntu" if os_id == "ubuntu" else ("debian" if os_id in ("debian", "") else os_id)
            src = row.get("source") or None
            p = purl("deb", row["name"], row.get("version"), ns,
                     {"arch": row.get("arch"), "distro": distro,
                      "upstream": src if src and src != row["name"] else None})
            self.add("packages", (host, "dpkg", row["name"], None, row.get("version"), None, row.get("arch"),
                                  row.get("maintainer"), src, row.get("source_version"), None, row.get("summary"), p))
            self._pkg_soft(host, "deb", row["name"], row.get("version"), short_version(row.get("version")), p)
        for row in mgrs.get("apk") or []:
            p = purl("apk", row["name"], row.get("version"), "alpine", {"arch": row.get("arch"), "distro": distro,
                                                                         "upstream": row.get("origin")})
            self.add("packages", (host, "apk", row["name"], None, row.get("version"), None, row.get("arch"), None,
                                  row.get("origin"), None, None, row.get("summary"), p))
            self._pkg_soft(host, "apk", row["name"], row.get("version"), short_version(row.get("version"), "apk"), p)
        for row in mgrs.get("lslpp") or []:
            name, lvl = row.get("name"), row.get("version")
            p = purl("generic", name, lvl, "ibm", {"distro": distro})
            self.add("packages", (host, "lslpp", name, None, lvl, None, None, "IBM", row.get("package"), None, None,
                                  row.get("summary"), p))
            fam = next((f for rx, f in AIX_FILESET_FAMILIES if rx.match(name or "")), None)
            # Pas de CPE : le niveau d'un fileset IBM (openssl.base 1.0.2.2107) n'est pas la version
            # amont du logiciel. Le croisement CVE des filesets passe par FLRTVC (build/flrtvc/).
            self.soft(host, "os-package", "aix", fam, name, lvl, "lslpp", owner_pkg=name, managed=1, purl_=p,
                      extra={"upstream_version": lvl, "note": "niveau de fileset IBM"} if fam else None)
        for mgr in ("pacman", "snap", "flatpak"):
            for row in mgrs.get(mgr) or []:
                self.add("packages", (host, mgr, row.get("name"), None, row.get("version"), None, None,
                                      row.get("publisher") or row.get("origin"), None, None, None, None, None))
                self.soft(host, "os-package", mgr, None, row.get("name"), row.get("version"), mgr, managed=1)

    def _pkg_soft(self, host, eco, name, full_version, upstream_version, p):
        fam = None
        for rx, f in ([] if PKG_FAMILY_EXCLUDE.match(name) else PKG_FAMILIES):
            if rx.match(name):
                fam = f
                break
        self.soft(host, "os-package", eco, fam, name, full_version, eco, owner_pkg=name, managed=1, purl_=p,
                  extra={"upstream_version": upstream_version} if fam else None)

    def processes(self, host, doc):
        for p in ((doc.get("processes") or {}).get("list") or []):
            dl = p.get("deleted_mapped_files") or []
            self.add("processes", (
                host, p.get("pid"), p.get("ppid"), p.get("user"), p.get("comm"), p.get("exe"), p.get("exe_owner_pkg"),
                p.get("cmdline"), p.get("start"), round((p.get("rss_bytes") or 0) / 1048576.0, 1),
                1 if p.get("in_container_ns") else 0, p.get("container_id"), p.get("systemd_unit"),
                len(dl), "\n".join(dl) or None, "\n".join(p.get("open_archives") or []) or None))

    def network(self, host, doc):
        net = doc.get("network") or {}
        for l in net.get("listening") or []:
            self.add("listening", (host, l.get("proto"), l.get("address"), l.get("port"), l.get("pid"),
                                   l.get("process"), l.get("user")))
        for c in net.get("established") or []:
            self.add("connections", (host, c.get("direction"), c.get("local_port"), c.get("remote_addr"),
                                     c.get("remote_port"), c.get("process"), c.get("count")))
        macs = dict((i.get("name"), i.get("address")) for i in net.get("interfaces") or [])
        for a in net.get("addresses") or []:
            self.add("addresses", (host, a.get("ifname"), a.get("family"), a.get("cidr"), a.get("scope"), a.get("label"),
                                   1 if a.get("secondary") else 0, macs.get(a.get("ifname"))))

    def services(self, host, doc):
        s = doc.get("services") or {}
        files = dict((f["unit"], f.get("state")) for f in s.get("unit_files") or [])
        details = dict((d.get("Id"), d) for d in s.get("service_details") or [])
        for u in s.get("units") or []:
            if not u["unit"].endswith(".service"):
                continue
            d = details.get(u["unit"], {})
            mp = d.get("MainPID")
            self.add("services", (host, u["unit"], u.get("load"), u.get("active"), u.get("sub"),
                                  files.get(u["unit"]) or d.get("UnitFileState"), int(mp) if mp and mp.isdigit() else None,
                                  d.get("ExecStart"), d.get("User"), d.get("FragmentPath"), u.get("description")))

    def containers(self, host, doc):
        c = doc.get("containers") or {}
        for engine in ("docker", "podman"):
            e = c.get(engine) or {}
            for r in e.get("ps") or []:
                if isinstance(r, dict):
                    self.add("containers", (host, engine, "container", r.get("ID") or r.get("Id"),
                                            str(r.get("Names")), r.get("Image"), None, r.get("Status") or r.get("State"),
                                            str(r.get("CreatedAt") or r.get("Created") or "")))
            for r in e.get("images") or []:
                if not isinstance(r, dict):
                    continue
                repo = r.get("Repository")
                if not repo and isinstance(r.get("Names"), list) and r["Names"]:
                    repo = r["Names"][0]
                tag = r.get("Tag")
                digest = r.get("Digest")
                self.add("containers", (host, engine, "image", r.get("ID") or r.get("Id"), repo, "%s:%s" % (repo, tag),
                                        digest, None, str(r.get("CreatedAt") or r.get("Created") or "")))
                if repo and repo != "<none>":
                    name = repo.rsplit("/", 1)[-1]
                    p = purl("oci", name, digest if digest and digest.startswith("sha256:") else None, None,
                             {"repository_url": repo, "tag": tag})
                    self.soft(host, "container-image", "oci", name, repo, tag, engine, digest, managed=0, purl_=p)
        cr = c.get("crictl") or {}
        for img in ((cr.get("images") or {}).get("images") or []):
            tags = img.get("repoTags") or []
            digests = img.get("repoDigests") or []
            self.add("containers", (host, "cri", "image", img.get("id"), ",".join(tags), ",".join(tags),
                                    ",".join(digests), None, None))
        for ctr in ((cr.get("ps") or {}).get("containers") or []):
            self.add("containers", (host, "cri", "container", ctr.get("id"), (ctr.get("metadata") or {}).get("name"),
                                    (ctr.get("image") or {}).get("image"), ctr.get("imageRef"), ctr.get("state"),
                                    str(ctr.get("createdAt"))))

    def container_content(self, host, doc):
        """Contenu des conteneurs (docker / podman export) : une ligne par image lue, ses paquets à part
        (container_packages, la distribution de l'image n'est pas celle de l'hôte) et ses autres composants
        dans software, l'emplacement préfixé par « moteur:conteneur: »."""
        cc = doc.get("container_content") or {}
        for e in cc.get("images") or []:
            osr = e.get("os_release") or {}
            os_id, os_ver = (osr.get("ID") or "").lower(), osr.get("VERSION_ID") or ""
            names = [c.get("name") for c in e.get("containers") or [] if c.get("name")]
            label = (names[0] if names else (e.get("image_id") or "?")[:12]) + (" (+%d)" % (len(names) - 1) if len(names) > 1 else "")
            prefix = "%s:%s:" % (e.get("engine"), label)
            saved, self.rows = self.rows, {}
            self.packages(host, e, os_id, os_ver)
            self.filesystem(host, e, e.get("filesystem") or {})
            got, self.rows = self.rows, saved
            for r in got.get("packages") or []:
                # (app, pf, host, manager, name, epoch, version, release, arch, vendor, source, source_version, installtime, summary, purl)
                self.rows.setdefault("container_packages", []).append(
                    r[:3] + (e.get("image_id"), e.get("image"), r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[10], r[14]))
            ncomp = 0
            for r in got.get("software") or []:
                if r[3] == "os-package":
                    continue
                r = list(r)
                r[8] = prefix + (r[8] or "")
                extra = json.loads(r[14]) if r[14] else {}
                extra.update(container=label, image=e.get("image"))
                r[14] = json.dumps(extra, ensure_ascii=False)
                self.rows.setdefault("software", []).append(tuple(r))
                ncomp += 1
            for r in got.get("java_markers") or []:
                self.rows.setdefault("java_markers", []).append(r[:3] + (prefix + (r[3] or ""),) + r[4:])
            st = e.get("stats") or {}
            notes = [x for x in (e.get("error"), e.get("packages_note")) if x]
            self.add("container_images", (host, e.get("engine"), e.get("image"), e.get("image_id"), " ".join(names), os_id or None,
                                          os_ver or None, osr.get("PRETTY_NAME"), len(got.get("packages") or []), ncomp,
                                          1 if st.get("truncated") else 0, st.get("seconds"), " ; ".join(notes) or None))
        for engine, st in sorted((cc.get("engines") or {}).items()):
            if not st.get("readable"):
                self.add("container_images", (host, engine, None, None, None, None, None, None, None, None, None, None,
                                              "moteur non lisible par le compte de collecte : %s" % (st.get("error") or "")[:200]))

    def misc(self, host, doc):
        for k, v in ((doc.get("hardware") or {}).get("cpu_vulnerabilities") or {}).items():
            self.add("cpu_vulnerabilities", (host, k, v))
        for m in ((doc.get("kernel") or {}).get("modules") or []):
            self.add("kernel_modules", (host, m.get("name")))
        for a in ((doc.get("accounts") or {}).get("passwd") or []):
            self.add("accounts", (host, a.get("name"), str(a.get("uid")), str(a.get("gid")), a.get("home"),
                                  a.get("shell"), a.get("gecos")))

    # -- sondes de version ---------------------------------------------------
    def runtimes(self, host, doc):
        for r in ((doc.get("runtimes") or {}).get("list") or []):
            probe = r.get("probe")
            outs = r.get("outputs") or []
            for o in outs or [{}]:
                self.add("probe_outputs", (host, probe, r.get("realpath"), "\n".join(r.get("paths") or []),
                                           r.get("owner_pkg"), r.get("run_as_uid"), r.get("skipped"),
                                           json.dumps(o.get("args")) if o else None, o.get("rc") if o else None,
                                           o.get("output") if o else None))
            fp = r.get("fingerprint") or {}
            main = FP_PRODUCT_OF_PROBE.get(probe)
            if fp:
                # composants compilés dans le binaire (OpenSSL statique d'un httpd maison...)
                self.fingerprint_rows(host, r.get("realpath"), dict((k, v) for k, v in fp.items() if k != main),
                                      r.get("owner_pkg"), "strings:binaire")
            if not outs or not any(o.get("rc") == 0 for o in outs):
                # binaire non exécuté (non fiable, budget...) ou en échec : version lue dans le binaire
                if main and fp.get(main):
                    self.fingerprint_rows(host, r.get("realpath"), {main: fp[main]}, r.get("owner_pkg"),
                                          "strings:binaire (non exécuté : %s)" % (r.get("skipped") or "échec"), main=main)
                if not outs:
                    continue
            text = "\n".join(o.get("output") or "" for o in outs)
            first = outs[0].get("output") or ""
            fam, version, extra, cpe = probe, None, {}, None
            if probe == "java":
                props = dict(re.findall(r"^\s+([\w.]+) = (.*)$", first, re.M))
                version = props.get("java.version") or first_match([r'version "([^"]+)"'], text)
                extra = {"vendor": props.get("java.vendor"), "vm": props.get("java.vm.name"),
                         "runtime_version": props.get("java.runtime.version"),
                         "java.home": props.get("java.home"), "java.version": props.get("java.version")}
                cpe = java_cpe(props.get("java.version") or version, (props.get("java.vendor") or "") + " " + (props.get("java.vm.name") or ""))
            elif probe in ("mysqld",):
                v = first_match(PROBE_VERSION_RX["mysqld"], text)
                fam = "mariadb" if "MariaDB" in text else "mysql"
                version = re.sub(r"-MariaDB.*$", "", v or "") or None
            elif probe == "dotnet":
                for line in text.splitlines():
                    m = re.match(r"^(Microsoft\.\S+)\s+(\S+)\s+\[(.*)\]", line)
                    if m:
                        self.soft(host, "runtime", "generic", "dotnet", m.group(1), m.group(2), m.group(3),
                                  r.get("realpath"), r.get("owner_pkg"))
                    m = re.match(r"^(\d+\.\d+\.\d+)\s+\[(.*)\]", line)
                    if m:
                        self.soft(host, "runtime", "generic", "dotnet-sdk", "dotnet-sdk", m.group(1), m.group(2),
                                  r.get("realpath"), r.get("owner_pkg"))
                continue
            else:
                base = os.path.basename(r.get("realpath") or "")
                if probe in ("prometheus", "hashicorp", "salt", "zabbix", "grafana-server"):
                    fam = re.sub(r"^(salt|zabbix)[-_].*$", r"\1", base)
                if probe in ("openssh-client", "openssh-server"):
                    fam = "openssh"
                version = first_match(PROBE_VERSION_RX.get(probe, []), text) or first_match([GENERIC_VERSION_RX], text)
                if probe == "python":
                    extra = {"openssl": first_match([r"^openssl=(.*)$"], text), "prefix": first_match([r"^prefix=(.*)$"], text)}
                elif probe == "nginx":
                    extra = {"built_with_openssl": first_match([r"built with (\S+ \S+)"], text),
                             "configure": first_match([r"configure arguments: (.*)$"], text)}
                elif probe in ("php", "php-fpm"):
                    extra = {"openssl": first_match([r"OpenSSL Library Version => (.*)$"], text),
                             "loaded_ini": first_match([r"Loaded Configuration File => (.*)$"], text)}
                    if len(outs) > 1 and outs[1].get("output"):
                        extra["modules"] = [l.strip() for l in outs[1]["output"].splitlines() if l.strip() and not l.startswith("[")]
                elif probe == "node" and len(outs) > 1:
                    try:
                        extra = json.loads(outs[1].get("output") or "{}")
                    except ValueError:
                        pass
                cpe = make_cpe(fam, version)
            loc = r.get("realpath")
            self.soft(host, "runtime", "generic", fam, os.path.basename(loc or probe), version, loc,
                      "exec:" + " ".join((outs[0].get("args") or [])), r.get("owner_pkg"),
                      purl_=purl("generic", fam, version), cpe=cpe, extra=dict((k, v) for k, v in extra.items() if v))

    def fingerprint_rows(self, host, path, found, owner, evidence, main=None, extra=None):
        """Lignes "software" à partir de chaînes de version trouvées dans un binaire."""
        for product, versions in sorted((found or {}).items()):
            for v in versions[:3]:
                key = (path, product, v)
                if key in self.fp_seen:
                    continue
                self.fp_seen.add(key)
                cat = "runtime" if (product == main or product in FP_RUNTIME_PRODUCTS) else "embedded"
                self.soft(host, cat, "generic", product, product, v, path, evidence, owner,
                          purl_=purl("generic", product, v), cpe=make_cpe(product, v), extra=extra)

    def process_artifacts(self, host, doc):
        pa = doc.get("process_artifacts") or {}
        for h in pa.get("jvm_homes") or []:
            rel = h.get("release") or {}
            if h.get("already_in_filesystem_scan") or not rel:
                continue
            v = rel.get("JAVA_VERSION") or rel.get("JAVA_RUNTIME_VERSION")
            self.soft(host, "runtime", "generic", "java", "jvm (processus)", v, h.get("path"),
                      "processus:%s+release" % (h.get("via") or "libjvm.so"),
                      h.get("owner_pkg"), purl_=purl("generic", "java", v),
                      cpe=java_cpe(rel.get("JAVA_VERSION"), rel.get("IMPLEMENTOR")),
                      extra={"implementor": rel.get("IMPLEMENTOR"), "pids": h.get("pids"),
                             "container_id": h.get("container_id")})
        for a in pa.get("archives") or []:
            self._archive(host, a, a.get("owner_pkg"), top=a.get("path"), origin="processus")
        for f in pa.get("fingerprints") or []:
            loc = f.get("path")
            self.fingerprint_rows(host, loc, f.get("found"), f.get("owner_pkg"), "strings:" + (f.get("reason") or ""),
                                  extra={"pids": f.get("pids"), "container_id": f.get("container_id")})

    # -- système de fichiers --------------------------------------------------
    def filesystem(self, host, doc, fs):
        for j in fs.get("jdk_homes") or []:
            rel = j.get("release") or {}
            v = rel.get("JAVA_VERSION") or rel.get("JAVA_RUNTIME_VERSION")
            self.soft(host, "runtime", "generic", "java", "jdk-home", v, j.get("path"), "release",
                      j.get("owner_pkg"), purl_=purl("generic", "java", v),
                      cpe=java_cpe(rel.get("JAVA_VERSION"), rel.get("IMPLEMENTOR")),
                      extra={"implementor": rel.get("IMPLEMENTOR"), "java_version": rel.get("JAVA_VERSION"),
                             "runtime_version": rel.get("JAVA_RUNTIME_VERSION"), "image_type": rel.get("IMAGE_TYPE")})
        for a in fs.get("java_archives") or []:
            self._archive(host, a, a.get("owner_pkg"), top=a.get("path"),
                          origin="processus" if a.get("origin") == "process" else None)
        for m in fs.get("maven_exploded") or []:
            self._maven(host, m, m.get("path"), "pom.properties (exploded)", m.get("owner_pkg"))
        for p in fs.get("python_packages") or []:
            name = (p.get("name") or "")
            norm = re.sub(r"[-_.]+", "-", name).lower()
            self.soft(host, "python-package", "pypi", norm, name, p.get("version"), p.get("site"), p.get("meta"),
                      p.get("owner_pkg"), purl_=purl("pypi", norm, p.get("version")),
                      extra={"installer": p.get("installer")} if p.get("installer") else None)
        for v in fs.get("python_venvs") or []:
            cfg = v.get("cfg") or {}
            self.soft(host, "python-venv", "generic", "python", "venv", cfg.get("version") or cfg.get("version_info"),
                      v.get("path"), "pyvenv.cfg", extra={"home": cfg.get("home")})
        for c in fs.get("conda_packages") or []:
            self.soft(host, "conda-package", "conda", c.get("name"), c.get("name"), c.get("version"), c.get("prefix"),
                      "conda-meta", purl_=purl("conda", c.get("name"), c.get("version")))
        for n in fs.get("npm_packages") or []:
            name = n.get("name") or ""
            ns, nm = (name.split("/", 1) if name.startswith("@") and "/" in name else (None, name))
            self.soft(host, "npm-package", "npm", name, name, n.get("version"), n.get("path"), "package.json",
                      n.get("owner_pkg"), purl_=purl("npm", nm, n.get("version"), ns))
        for lk in fs.get("npm_lockfiles") or []:
            for name, ver in lk.get("packages") or []:
                ns, nm = (name.split("/", 1) if name.startswith("@") and "/" in name else (None, name))
                self.soft(host, "npm-package", "npm", name, name, ver, os.path.dirname(lk.get("path")),
                          "package-lock.json", purl_=purl("npm", nm, ver, ns), extra={"from": "lockfile"})
        for na in fs.get("node_apps") or []:
            self.soft(host, "node-app", "generic", na.get("name"), na.get("name"), na.get("version"), na.get("path"),
                      "package.json", na.get("owner_pkg"))
        for kind in ("composer_installed", "composer_locks"):
            for c in fs.get(kind) or []:
                for p in c.get("packages") or []:
                    name = p.get("name") or ""
                    ns, nm = (name.split("/", 1) if "/" in name else (None, name))
                    ver = re.sub(r"^v(?=\d)", "", p.get("version") or "")
                    self.soft(host, "composer-package", "composer", nm, name, ver,
                              re.sub(r"/vendor/composer/installed\.json$|/composer\.lock$", "", c.get("path")),
                              c.get("path"), c.get("owner_pkg"), purl_=purl("composer", nm, ver, ns))
        for g in fs.get("ruby_gems") or []:
            self.soft(host, "ruby-gem", "gem", g.get("name"), g.get("name"), g.get("version"), g.get("path"),
                      "gemspec", g.get("owner_pkg"), purl_=purl("gem", g.get("name"), g.get("version")))
        for d in fs.get("dotnet_deps") or []:
            for lib in d.get("libraries") or []:
                if lib.get("type") != "package":
                    continue
                self.soft(host, "dotnet-package", "nuget", lib["name"].lower(), lib["name"], lib["version"],
                          os.path.dirname(d.get("path")), d.get("path"), purl_=purl("nuget", lib["name"], lib["version"]))
        for w in fs.get("webapps") or []:
            prod = w.get("product")
            vals = w.get("values") or []
            version = vals[0] if vals else None
            name = prod
            if prod == "joomla" and len(vals) >= 3 and w.get("evidence", "").endswith("Version.php"):
                version = ".".join(vals[:3])
            elif prod == "joomla" and len(vals) >= 2:
                version = "%s.%s" % (vals[0], vals[1])
            elif prod == "nextcloud-owncloud" and len(vals) >= 2:
                name = vals[1]
            elif prod == "gitlab" and vals:
                name, _, version = vals[0].partition(" ")
            elif prod == "jboss-wildfly-keycloak" and vals:
                name = vals[0]
                version = first_match([r"(\d+\.\d+\.\d+(?:\.[\w-]+)?)"], vals[0])
            elif prod == "oracle-home" and vals:
                name, _, version = vals[0].partition(" ")
            fam = prod if prod not in ("nextcloud-owncloud",) else prod
            self.soft(host, "webapp", "generic", fam, name, version, w.get("root"), w.get("evidence"),
                      w.get("owner_pkg"), purl_=purl("generic", name, version), cpe=make_cpe(fam, version))
        for js in fs.get("js_libraries") or []:
            lib = js.get("library")
            fam = {"jquery.ui": "jquery-ui", "angularjs": "angular", "purify": "dompurify"}.get(lib, lib)
            ver = js.get("version_from_header") or js.get("version_from_filename")
            self.soft(host, "js-library", "generic", fam, os.path.basename(js.get("path")), ver, js.get("path"),
                      "header" if js.get("version_from_header") else "filename", js.get("owner_pkg"),
                      purl_=purl("npm", fam, ver) if ver else None, cpe=make_cpe(fam, ver))
        for nl in fs.get("native_libs") or []:
            name = nl.get("name") or ""
            fam = "openssl" if re.match(r"^lib(ssl|crypto)", name) else ("curl" if name.startswith("libcurl") else
                                                                         ("zlib" if name.startswith("libz.") else
                                                                          ("php" if name.startswith("libphp") else None)))
            ver = nl.get("embedded_version") or nl.get("version_from_filename")
            self.soft(host, "native-lib", "generic", fam, name, ver, nl.get("path"),
                      "strings" if nl.get("embedded_version") else "filename", nl.get("owner_pkg"),
                      cpe=make_cpe(fam, nl.get("embedded_version")) if fam else None)
        for d in fs.get("db_datadirs") or []:
            fam = "postgresql-datadir" if d.get("engine") == "postgresql" else "mysql-datadir"
            self.soft(host, "db-datadir", "generic", fam, d.get("engine"), d.get("version"), d.get("path"),
                      "PG_VERSION" if fam == "postgresql-datadir" else "mysql_upgrade_info", managed=1)

    def _maven(self, host, m, location, evidence, owner):
        g, a, v = m.get("groupId"), m.get("artifactId"), m.get("version")
        if not a:
            return
        self.soft(host, "java-archive", "maven", jar_family(a, g, None, v), "%s:%s" % (g, a), v, location, evidence, owner,
                  purl_=purl("maven", a, v, g))

    def _archive(self, host, a, owner, top, origin=None):
        path = a.get("path")
        man = a.get("manifest") or {}
        mavens = a.get("maven") or []
        suffix = " (%s)" % origin if origin else ""
        for m in mavens:
            self._maven(host, m, path, "pom.properties" + suffix, owner)
        if path.endswith("/lib/rt.jar") and man.get("Implementation-Title") == "Java Runtime Environment":
            v = man.get("Implementation-Version")
            self.soft(host, "runtime", "generic", "java", "jvm (rt.jar)", v, path[:-len("/lib/rt.jar")],
                      "rt.jar" + suffix, owner, purl_=purl("generic", "java", v),
                      cpe=java_cpe(v, man.get("Implementation-Vendor")))
        hit = self.java_db.find(a.get("sha1")) if self.java_db and not mavens else None
        if hit:
            self.soft(host, "java-archive", "maven", jar_family(hit[1], hit[0], None, hit[2]), "%s:%s" % (hit[0], hit[1]), hit[2], path,
                      "sha1 trivy-java-db" + suffix, owner, purl_=purl("maven", hit[1], hit[2], hit[0]),
                      extra={"sha1": a.get("sha1")})
        elif not mavens:
            fname = os.path.basename(path.split("!/")[-1])
            fm = re.match(r"^(.+?)-(\d[\w.\-]*?)\.(jar|war|ear|hpi|jpi|sar)$", fname, re.I)
            name = man.get("Bundle-SymbolicName", "").split(";")[0] or man.get("Implementation-Title") or \
                (fm.group(1) if fm else fname)
            ver = man.get("Implementation-Version") or man.get("Bundle-Version") or (fm.group(2) if fm else None)
            fam = jar_family(fm.group(1).lower(), None, man, ver) if fm else None
            self.soft(host, "java-archive", "maven-unidentified", fam, name, ver, path,
                      ("manifest" if man else "filename") + suffix, owner,
                      extra={"sha1": a.get("sha1"), "title": man.get("Implementation-Title")} if a.get("sha1") else None)
        for mk in a.get("markers") or []:
            self.add("java_markers", (host, path, mk, 1 if "(shaded:" in mk else 0))
        st = (a.get("special") or {}).get("tomcat_serverinfo")
        if st:
            v = st.get("server.number") or first_match([r"/(\S+)"], st.get("server.info", ""))
            v = re.sub(r"\.0$", "", v) if v and v.count(".") == 3 else v
            root = os.path.dirname(os.path.dirname(path.split("!/")[0]))
            self.soft(host, "runtime", "generic", "tomcat", "tomcat", v, root, path, owner,
                      purl_=purl("generic", "tomcat", v), cpe=make_cpe("tomcat", v))
        for n in a.get("nested") or []:
            self._archive(host, n, owner, top, origin)

    def go_binaries(self, host, doc):
        for g in ((doc.get("go_binaries") or {}).get("list") or []):
            gv = (g.get("go_version") or "")
            loc = g.get("realpath")
            own = g.get("owner_pkg")
            if gv:
                sv = gv[2:] if gv.startswith("go") else gv
                self.soft(host, "go-binary", "golang", "go-stdlib", "stdlib", sv, loc, "go.buildinfo", own,
                          purl_=purl("golang", "stdlib", sv), cpe=make_cpe("go", sv))
            mm = g.get("main_module")
            if mm and mm[1] not in ("(devel)", ""):
                self.soft(host, "go-binary", "golang", mm[0].rsplit("/", 1)[-1], mm[0], mm[1], loc, "go.buildinfo", own,
                          purl_=purl("golang", mm[0].rsplit("/", 1)[-1], mm[1], mm[0].rsplit("/", 1)[0] if "/" in mm[0] else None))
            for dep in g.get("deps") or []:
                mod, ver = dep[0], dep[1]
                self.soft(host, "go-module", "golang", mod.rsplit("/", 1)[-1], mod, ver, loc, "go.buildinfo", own,
                          purl_=purl("golang", mod.rsplit("/", 1)[-1], ver, mod.rsplit("/", 1)[0] if "/" in mod else None))


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------

def export_csv(db, outdir):
    os.makedirs(outdir, exist_ok=True)
    names = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type IN ('table','view') "
                                      "AND name NOT IN ('raw_documents') ORDER BY name")]
    for n in names:
        cur = db.execute("SELECT * FROM %s" % n)
        cols = [c[0] for c in cur.description]
        with open(os.path.join(outdir, n + ".csv"), "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f, delimiter=";")
            w.writerow(cols)
            for row in cur:
                w.writerow(row)
    return names


def build_matrix(db, path):
    hosts = [tuple(r) for r in db.execute("SELECT app, platform, host, os_pretty FROM hosts ORDER BY app, platform, host")]
    cells = {}
    wanted = set(MATRIX_FAMILIES)
    q = """SELECT app, platform, host, family, version, managed, category, extra FROM software
           WHERE family IS NOT NULL AND version IS NOT NULL AND version != ''
             AND category IN ('runtime','os-package','webapp','java-archive','db-datadir','js-library','embedded')"""
    for app, pf, host, fam, ver, managed, cat, extra in db.execute(q):
        host = (app, pf, host)
        if cat == "os-package":
            try:
                ver = (json.loads(extra) or {}).get("upstream_version") or ver
            except (TypeError, ValueError):
                pass
            if fam == "linux-kernel-installed":
                continue
        if fam == "php-fpm":
            fam = "php"
        if fam not in wanted:
            continue            # seules les familles de la matrice : la mémoire ne dépend pas du nombre de bibliothèques
        label = ver if managed else ver + "*"
        cells.setdefault((host, fam), set()).add(label)
    present = [f for f in MATRIX_FAMILIES if any((h[:3], f) in cells for h in hosts)]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, delimiter=";")
        w.writerow(["app", "platform", "host", "os"] + present)
        for app, pf, hn, os_pretty in hosts:
            h = (app, pf, hn)
            row = [app, pf, hn, os_pretty]
            for fam in present:
                vals = cells.get((h, fam), set())
                # une version sans * (paquet) et la même avec * : on garde les deux, c'est une information
                row.append(" | ".join(sorted(vals)))
            w.writerow(row)
    return present


def build_sboms(db, outdir, include_managed=False):
    os.makedirs(outdir, exist_ok=True)
    count = 0
    for app, pf, host, os_id, os_ver, os_pretty, kernel, collected in db.execute(
            "SELECT app, platform, host, os_id, os_version, os_pretty, kernel, collected_at FROM hosts").fetchall():
        comps = {}
        os_ref = "os:%s-%s" % (os_id, os_ver)
        q = """SELECT category, ecosystem, family, name, version, location, purl, cpe, managed, owner_pkg
               FROM software WHERE app = ? AND platform = ? AND host = ?"""
        for cat, eco, fam, name, ver, loc, p, cpe, managed, owner in db.execute(q, (app, pf, host)).fetchall():
            if cat in ("python-venv", "node-app", "db-datadir"):
                continue
            if cat != "os-package" and managed and not include_managed:
                continue  # déjà couvert par le paquet OS propriétaire (avis de la distribution)
            if not p and not cpe:
                continue
            if cat == "container-image":
                continue  # à scanner séparément (trivy image ...)
            key = p or cpe
            c = comps.get(key)
            if c is None:
                c = {"type": "library" if cat != "runtime" else "application",
                     "bom-ref": hashlib.sha1(key.encode("utf-8")).hexdigest()[:16],
                     "name": name.split(":")[-1] if eco == "maven" else name,
                     "version": ver or "",
                     "properties": [{"name": "cmdb:category", "value": cat}]}
                if eco == "maven" and ":" in name:
                    c["group"] = name.split(":")[0]
                if p:
                    c["purl"] = p
                if cpe:
                    c["cpe"] = cpe
                comps[key] = c
            if loc and len(c["properties"]) < 25:
                c["properties"].append({"name": "cmdb:location", "value": loc})
        # Trivy prend name pour sa famille d'OS (redhat, oracle…), sans message si elle est inconnue ;
        # Syft et Grype lisent d'abord swid.name et attendent l'ID de os-release (rhel, ol…).
        os_comp = {"type": "operating-system", "bom-ref": os_ref, "name": TRIVY_OS.get(os_id, os_id or "linux"),
                   "version": os_ver or "", "description": os_pretty or ""}
        if os_id:
            os_comp["swid"] = {"tagId": os_ref, "name": os_id, "version": os_ver or ""}
        bom = {
            "bomFormat": "CycloneDX", "specVersion": "1.5",
            "serialNumber": "urn:uuid:%s" % uuid.uuid4(), "version": 1,
            "metadata": {
                "timestamp": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                "tools": {"components": [{"type": "application", "name": "cmdb_build", "version": BUILD_VERSION}]},
                # pas "device" : valide en CycloneDX, mais erreur fatale pour Trivy sur le composant racine
                "component": {"type": "application", "bom-ref": "host:" + host, "name": host, "version": collected or "",
                              "properties": [{"name": "cmdb:kernel", "value": kernel or ""},
                                             {"name": "cmdb:app", "value": app}, {"name": "cmdb:platform", "value": pf}]},
            },
            "components": [os_comp] + list(comps.values()),
            "dependencies": [
                {"ref": "host:" + host, "dependsOn": [os_ref]},
                {"ref": os_ref, "dependsOn": [c["bom-ref"] for c in comps.values()
                                              if any(pr["value"] == "os-package" for pr in c["properties"])]},
            ],
        }
        with open(os.path.join(outdir, safe_name(app, pf, host) + ".cdx.json"), "w", encoding="utf-8") as f:
            json.dump(bom, f, ensure_ascii=False, indent=1)
        count += 1
    return count


def write_runs(db, store):
    """Table runs : manifestes d'exécution (statut par hôte, y compris échecs et injoignables)
    complétés par les collectes présentes sans manifeste."""
    seen = set()
    for rid, m in sorted(store.runs.items()):
        for (app, pf, host), h in sorted(m["hosts"].items()):
            if not store._match(app, store.filters[0]) or not store._match(pf, store.filters[1]) \
                    or not store._match(host, store.filters[2]):
                continue
            db.execute("INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?,?)", (
                rid, app, pf, host, h.get("status"), h.get("collector"),
                m.get("started_at") or rid, h.get("file"), h.get("detail"), m.get("_source")))
            seen.add((rid, app, pf, host))
    for (app, pf, host), (meta, _r, _f, src) in store.docs.items():
        if (meta.get("run_id"), app, pf, host) not in seen:
            db.execute("INSERT INTO runs VALUES (?,?,?,?,?,?,?,?,?,?)", (
                meta.get("run_id"), app, pf, host, "ok", meta.get("collector") or "python", meta.get("started_at"),
                src, None, None))


def write_flrtvc(rows, outdir):
    """AIX : fichiers d'entrée de FLRTVC (IBM Fix Level Recommendation Tool Vulnerability Checker).
    lslpp -Lcq est obligatoire ; emgr -lv3 n'est lisible qu'en root, donc souvent absent."""
    if not rows:
        return 0
    os.makedirs(outdir, exist_ok=True)
    for app, pf, host, lslpp, emgr in rows:
        base = os.path.join(outdir, safe_name(app, pf, host))
        with open(base + ".lslpp.txt", "w", encoding="utf-8") as f:
            f.write(lslpp if lslpp.endswith("\n") else lslpp + "\n")
        if emgr and emgr.strip():
            with open(base + ".emgr.txt", "w", encoding="utf-8") as f:
                f.write(emgr)
    return len(rows)


def main():
    ap = argparse.ArgumentParser(description="Consolidation CMDB : SQLite + CSV + SBOM CycloneDX + rapport HTML")
    ap.add_argument("--store", action="append", default=[],
                    help="Magasin de collectes (répétable) : store/<appli>/<pf>/<hôte>/ ou ancien output/raw")
    ap.add_argument("--raw", action="append", default=[], help=argparse.SUPPRESS)   # compatibilité
    ap.add_argument("--lot", action="append", default=[],
                    help="Lot de collecte transféré (.tar.gz, répétable ; accepte un motif glob)")
    ap.add_argument("--app", action="append", default=[], help="Ne garder que ces applications (motifs glob, répétable)")
    ap.add_argument("--platform", action="append", default=[], help="Ne garder que ces plates-formes (motifs glob)")
    ap.add_argument("--host", action="append", default=[], help="Ne garder que ces hôtes (motifs glob)")
    ap.add_argument("--default-app", default=NA, help="Application des collectes non étiquetées (défaut : NA)")
    ap.add_argument("--default-platform", default=NA, help="Plate-forme des collectes non étiquetées (défaut : NA)")
    ap.add_argument("--out", default="build", help="Répertoire de sortie")
    ap.add_argument("--sbom-include-managed", action="store_true",
                    help="Inclure aussi dans les SBOM les composants appartenant à un paquet OS (doublons, faux positifs)")
    ap.add_argument("--java-db", help="Base trivy-java.db locale : identifie par SHA-1 les archives Java sans pom.properties")
    ap.add_argument("--trivy-db", help="Base trivy.db locale : croise paquets, bibliothèques et produits avec les CVE (table vulnerabilities)")
    ap.add_argument("--cve-unfixed", choices=("all", "high", "none"), default="high",
                    help="CVE sans correctif à garder : toutes, hautes et critiques seulement (défaut), aucune")
    ap.add_argument("--no-raw-documents", action="store_true", help="Ne pas stocker les documents JSON bruts dans SQLite")
    ap.add_argument("--no-report", action="store_true", help="Ne pas générer le rapport HTML")
    ap.add_argument("--no-history", action="store_true", help="Ne pas comparer aux collectes précédentes")
    ap.add_argument("--no-dossiers", action="store_true", help="Ne pas produire les dossiers d'application")
    ap.add_argument("--dossier-mention", default=cmdb_dossier.DEFAULT_MENTION,
                    help="Mention de diffusion portée sur chaque page des dossiers d'application")
    ap.add_argument("--platform-order", default="",
                    help="Ordre de promotion des plates-formes, de l'amont vers la production (ex. dev,rec,preprod,prod). "
                         "Défaut : noms courants reconnus (dev, int, rec/qualif, preprod, prod et variantes)")
    ap.add_argument("--report-exclude-categories", default="",
                    help="Catégories à exclure du rapport HTML pour l'alléger (ex. go-module,npm-package)")
    a = ap.parse_args()
    if a.trivy_db and not os.path.isfile(a.trivy_db):
        print("ERREUR base Trivy introuvable : %s (fichier trivy.db attendu)" % a.trivy_db, file=sys.stderr)
        return 1

    store = Store(a.default_app, a.default_platform, a.app, a.platform, a.host, history=not a.no_history)
    dirs = a.store + a.raw
    lots = sorted(set(p for pat in a.lot for p in (glob.glob(pat) or [pat])))
    if not dirs and not lots:
        dirs = [d for d in ("store", os.path.join("output", "raw")) if os.path.isdir(d)]
    for d in dirs:
        if not os.path.isdir(d):
            print("Magasin introuvable : %s" % d, file=sys.stderr)
            return 2
        store.add_dir(d)
    seen_lots = {}
    for lot in lots:
        # Un lot et son nom d'origine (<run_id>.tar.gz, lien dur) sont le même fichier : lu une fois
        try:
            st = os.stat(lot)
            ident = (st.st_dev, st.st_ino)
        except OSError:
            ident = lot
        if ident in seen_lots:
            print("Lot ignoré       : %s (même fichier que %s)" % (lot, seen_lots[ident]))
            continue
        seen_lots[ident] = lot
        rid = store.add_lot(lot)
        if rid:
            print("Lot ignoré       : %s (passage %s déjà présent dans le magasin)" % (lot, rid))
    docs = store.docs
    if not docs:
        print("Aucune collecte trouvée (magasins : %s ; lots : %s)" % (", ".join(dirs) or "-", ", ".join(lots) or "-"))
        return 1
    os.makedirs(a.out, exist_ok=True)
    dbpath = os.path.join(a.out, "cmdb.sqlite")
    java_db = None
    if a.java_db:
        try:
            if not os.path.isfile(a.java_db):
                raise ValueError("base Java introuvable : %s" % a.java_db)
            java_db = JavaDb(a.java_db)
        except ValueError as e:
            print("ERREUR %s" % e, file=sys.stderr)
            return 1
    tmp = dbpath + ".tmp"
    if os.path.exists(tmp):
        os.remove(tmp)
    db = sqlite3.connect(tmp)
    db.executescript(SCHEMA)
    b = Builder(db, java_db)
    for key, doc, facts, src in store.current():
        b.process_host(key, doc, None if a.no_raw_documents else facts, src)
        del doc, facts
        if a.no_raw_documents:
            b.rows["raw_documents"] = []
        b.flush()
    write_runs(db, store)
    cmdb_extras.oracle_fleet(db)
    cmdb_extras.build_db_links(db)
    for product, cycles in sorted(cmdb_extras.load_eol().items()):
        db.executemany("INSERT INTO eol_reference VALUES (?,?,?,?)", [(product, c, e, x) for c, (e, x) in sorted(cycles.items())])
    cmdb_extras.build_eol(db)
    cmdb_hardening.apply_eol(db, Builder.hardening_rules())
    cmdb_hardening.build_scores(db)
    db.executemany("INSERT INTO anssi_recommendations VALUES (?,?,?,?,?)",
                   [(r["ref"], r["level"], r["title"], r["coverage"], r["note"] or None) for r in cmdb_hardening.load_recos()])
    cmdb_extras.build_cert_usage(db)
    cmdb_maps.build_flows(db)
    cmdb_maps.build_drift(db, order=[x for x in (a.platform_order or "").split(",") if x.strip()],
                          important=PRODUCT_FAMILIES | frozenset(MATRIX_FAMILIES))
    nchanges = cmdb_extras.build_changes(db, Builder, SCHEMA, store.previous_docs(), store.metas())
    vstats = cmdb_cve.build_vulnerabilities(db, a.trivy_db, a.cve_unfixed) if a.trivy_db else None
    db.commit()
    db.close()
    os.replace(tmp, dbpath)

    db = sqlite3.connect(dbpath)
    tables = export_csv(db, os.path.join(a.out, "csv"))
    fams = build_matrix(db, os.path.join(a.out, "runtimes_matrix.csv"))
    n = build_sboms(db, os.path.join(a.out, "sbom"), a.sbom_include_managed)
    stats = dict(db.execute("SELECT category, COUNT(*) FROM software GROUP BY category").fetchall())
    nflr = write_flrtvc(b.flrtvc, os.path.join(a.out, "flrtvc"))
    ngraphs = cmdb_maps.write_dot(db, os.path.join(a.out, "graphes"), safe_name)
    dossiers = {} if a.no_dossiers else cmdb_dossier.write_all(db, os.path.join(a.out, "dossiers"), safe_name, a.dossier_mention)
    apps = db.execute("SELECT app, platform, hosts FROM v_applications").fetchall()
    print("Hôtes consolidés : %d (%d collectes lues, %d écartées par les filtres)" % (len(docs), store.read, store.skipped))
    for src, schema in store.unsupported[:20]:
        print("ATTENTION : %s ignorée, format %s inconnu de cette consolidation (à mettre à jour)" % (src, schema), file=sys.stderr)
    if len(store.unsupported) > 20:
        print("ATTENTION : %d autres collectes au format inconnu ignorées" % (len(store.unsupported) - 20), file=sys.stderr)
    print("Applis / pf      : " + ", ".join("%s/%s=%d" % r for r in apps))
    print("Base SQLite      : %s" % dbpath)
    print("Exports CSV      : %d fichiers dans %s" % (len(tables), os.path.join(a.out, "csv")))
    print("Matrice          : %s (%d colonnes)" % (os.path.join(a.out, "runtimes_matrix.csv"), len(fams)))
    print("SBOM CycloneDX   : %d fichiers dans %s" % (n, os.path.join(a.out, "sbom")))
    if nflr:
        print("FLRTVC (AIX)     : %d hôte(s) dans %s" % (nflr, os.path.join(a.out, "flrtvc")))
    if java_db:
        print("Archives Java    : %d sans pom.properties, dont %d avec empreinte, %d identifiées par %s"
              % (java_db.without_pom, java_db.hashed, java_db.found, os.path.basename(a.java_db)))
    if vstats:
        crit = db.execute("SELECT severity, COUNT(DISTINCT vuln_id) FROM vulnerabilities WHERE status = 'corrigeable' GROUP BY 1").fetchall()
        print("Vulnérabilités   : %d constats sur %d hôtes (base Trivy du %s) ; CVE distinctes corrigeables : %s"
              % (vstats["rows"], vstats["hosts"], (vstats["updated"] or "?")[:10],
                 ", ".join("%s=%d" % (cmdb_cve.SEV_FR.get(s_, s_), n_) for s_, n_ in sorted(crit, key=lambda r: -cmdb_cve.SEVERITIES.index(r[0])))
                 or "aucune"))
        if vstats["os_unsupported"]:
            print("                   systèmes sans avis dans la base : " + ", ".join(vstats["os_unsupported"]))
    print("Composants       : " + ", ".join("%s=%d" % kv for kv in sorted(stats.items())))
    one = lambda sql: db.execute(sql).fetchone()[0]
    print("Oracle           : %d ORACLE_HOME, %d instances, %d en retard de correctifs"
          % (one("SELECT COUNT(*) FROM oracle_homes"), one("SELECT COUNT(*) FROM db_instances WHERE engine = 'oracle'"),
             one("SELECT COUNT(*) FROM v_oracle_patch_late")))
    print("Liens vers bases : %d | points d'entrée : %d | clés et certificats : %d fichiers"
          % (one("SELECT COUNT(*) FROM db_links"), one("SELECT COUNT(*) FROM endpoints"), one("SELECT COUNT(*) FROM crypto_files")))
    print("Carte            : %d flux, %d graphes dans %s | écarts : %d"
          % (one("SELECT COUNT(*) FROM app_flows"), ngraphs, os.path.join(a.out, "graphes"), one("SELECT COUNT(*) FROM drift")))
    print("Dossiers         : %d dans %s" % (len(dossiers), os.path.join(a.out, "dossiers")))
    print("Durcissement     : %d serveur(s) évalués, %d contrôles non conformes"
          % (one("SELECT COUNT(DISTINCT app || '|' || platform || '|' || host) FROM hardening_results"),
             one("SELECT COUNT(*) FROM v_hardening_failures")))
    print("Évolutions       : %d (%d hôte(s) comparé(s)) | fins de support dépassées : %d"
          % (nchanges, len(store.previous), one("SELECT COUNT(*) FROM v_eol_expired")))
    unmanaged = db.execute("SELECT COUNT(*) FROM v_unmanaged_software").fetchone()[0]
    risky = db.execute("SELECT COUNT(*) FROM v_java_risky").fetchone()[0]
    restart = db.execute("SELECT COUNT(DISTINCT app || '|' || platform || '|' || host || ':' || pid) "
                         "FROM v_restart_needed").fetchone()[0]
    print("Hors paquets OS  : %d composants | archives Java à risque : %d | processus à redémarrer : %d"
          % (unmanaged, risky, restart))
    db.close()
    if not a.no_report:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import cmdb_report
        rp = os.path.join(a.out, "cmdb_rapport.html")
        st = cmdb_report.build_report(dbpath, rp, os.path.join(a.out, "runtimes_matrix.csv"),
                                      [c for c in a.report_exclude_categories.split(",") if c], BUILD_VERSION, dossiers)
        print("Rapport HTML     : %s (%.1f Mo, %d composants)" % (rp, st["bytes"] / 1e6, st["software_rows"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
