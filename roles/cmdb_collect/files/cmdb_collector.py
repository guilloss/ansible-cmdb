#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
cmdb_collector.py - Collecteur d'inventaire "CMDB maison" pour serveurs Linux.

Philosophie : on entasse d'abord TOUT (sorties brutes conservées), on trie ensuite
côté contrôleur (tools/cmdb_build.py). Le collecteur ne fait que peu
d'interprétation : il rapporte des faits et des preuves (chemins, manifestes,
sorties de commandes), le parsing des versions se fait à la consolidation.

Contraintes de conception :
  * bibliothèque standard uniquement ; compatible Python 2.6, 2.7 et 3.6+ ;
  * lecture seule : aucun fichier n'est modifié hors du fichier de sortie ;
  * exécution de binaires (sondes de version) limitée aux ELF et à une liste
    blanche de scripts, avec dégradation de privilèges : un binaire qui n'est
    pas sous contrôle exclusif de root est exécuté sous l'identité de son
    propriétaire (ou de nobody), jamais en root ;
  * redaction des secrets évidents (mots de passe en ligne de commande,
    identifiants dans les URL) ;
  * budget de temps sur le parcours du système de fichiers, priorité basse
    (nice 19 / ionice idle).

Sortie : un document JSON compressé (gzip) + un résumé JSON sur stdout.
"""
from __future__ import print_function

import base64
import gzip
import hashlib
import io
import json
import mmap
import os
import re
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import traceback
import zipfile

try:
    import pwd
    import grp
except ImportError:  # pragma: no cover
    pwd = None
    grp = None

COLLECTOR_VERSION = "1.1.0"
SCHEMA = "cmdb-collector/1"
PY3 = sys.version_info[0] >= 3
text_type = type(u"")
binary_type = type(b"")

CLEAN_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "HOME": "/",
    "TERM": "dumb",
    "SYSTEMD_PAGER": "cat",
    "PAGER": "cat",
    "SYSTEMD_COLORS": "0",
}
SEARCH_PATH = CLEAN_ENV["PATH"].split(":")


# --------------------------------------------------------------------------
# Utilitaires génériques
# --------------------------------------------------------------------------

def u(x):
    """Convertit en texte unicode sûr pour JSON (remplace l'indécodable)."""
    if x is None:
        return None
    if isinstance(x, binary_type):
        return x.decode("utf-8", "replace")
    if PY3 and isinstance(x, str):
        try:
            x.encode("utf-8")
            return x
        except UnicodeEncodeError:
            return x.encode("utf-8", "surrogateescape").decode("utf-8", "replace")
    if isinstance(x, text_type):
        return x
    return u(str(x))


def sanitize(obj):
    """Parcours récursif : toutes les chaînes deviennent de l'unicode valide."""
    if isinstance(obj, dict):
        return dict((u(k) if isinstance(k, (text_type, binary_type)) else k, sanitize(v))
                    for k, v in obj.items())
    if isinstance(obj, (list, tuple, set)):
        return [sanitize(v) for v in obj]
    if isinstance(obj, (text_type, binary_type)):
        return u(obj)
    return obj


def now_iso(ts=None):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts if ts is not None else time.time()))


def read_bytes(path, limit=1 << 20):
    try:
        st = os.stat(path)
        if not stat.S_ISREG(st.st_mode):
            return None
        with open(path, "rb") as f:
            return f.read(limit)
    except (IOError, OSError):
        return None


def read_text(path, limit=1 << 20):
    b = read_bytes(path, limit)
    return None if b is None else u(b)


def readlink(path):
    try:
        return os.readlink(path)
    except (IOError, OSError):
        return None


def listdir(path):
    try:
        return sorted(os.listdir(path))
    except (IOError, OSError):
        return []


def is_regular(path):
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except (IOError, OSError):
        return False


def kv_text(text, sep="="):
    d = {}
    if not text:
        return d
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or sep not in line:
            continue
        k, v = line.split(sep, 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        d[k.strip()] = v
    return d


def which(name):
    for d in SEARCH_PATH:
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def sha1_file(path, limit):
    try:
        if os.path.getsize(path) > limit:
            return None
        h = hashlib.sha1()
        with open(path, "rb") as f:
            while True:
                b = f.read(1 << 20)
                if not b:
                    break
                h.update(b)
        return h.hexdigest()
    except (IOError, OSError):
        return None


_uid_cache = {}


def uid_name(uid):
    if uid in _uid_cache:
        return _uid_cache[uid]
    name = None
    if pwd is not None:
        try:
            name = pwd.getpwuid(int(uid)).pw_name
        except (KeyError, ValueError, TypeError):
            name = None
    _uid_cache[uid] = name
    return name


# Redaction des secrets évidents --------------------------------------------
_SECRET_WORDS = r"(?:passw(?:or)?d|passwd|pwd|secret|token|api[_-]?key|apikey|credentials?|private[_-]?key|authtok|access[_-]?key)"
REDACTIONS = [
    # -Dfoo.password=xxx  --password=xxx  DB_PASSWORD=xxx  password: xxx
    (re.compile(r"((?:^|[\s;&|,'\"(])-{0,2}[\w.\-]*" + _SECRET_WORDS + r"[\w.\-]*\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;'\"]+)", re.I), r"\1***"),
    # --password xxx
    (re.compile(r"((?:^|\s)--?[\w\-]*" + _SECRET_WORDS + r"[\w\-]*\s+)(?!-)(\S+)", re.I), r"\1***"),
    # scheme://user:pass@host
    (re.compile(r"(\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:)[^@\s/]+(@)", re.I), r"\1***\2"),
]


def redact(s):
    if not s:
        return s
    s = u(s)
    for rx, rep in REDACTIONS:
        s = rx.sub(rep, s)
    return s


# Exécution de commandes ----------------------------------------------------

def run(cmd, timeout=60, as_ids=None, max_out=64 << 20, env=None):
    """Exécute une commande (liste) avec timeout, environnement propre, sans shell.

    as_ids=(uid, gid) : exécute sous cette identité (si on est root).
    Retourne None si la commande n'existe pas.
    """
    exe = cmd[0]
    if not os.path.isabs(exe):
        found = which(exe)
        if not found:
            return None
        cmd = [found] + list(cmd[1:])
    elif not os.path.exists(exe):
        return None
    preexec = None
    if as_ids is not None and os.geteuid() == 0 and tuple(as_ids) != (0, 0):
        uid, gid = as_ids

        def _drop_privileges():
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
        preexec = _drop_privileges
    t0 = time.time()
    try:
        devnull = open(os.devnull, "rb")
    except (IOError, OSError):
        devnull = None
    try:
        p = subprocess.Popen(cmd, stdin=devnull, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=env or CLEAN_ENV, close_fds=True, preexec_fn=preexec, cwd="/")
    except (OSError, ValueError) as e:
        if devnull:
            devnull.close()
        return {"rc": None, "out": "", "err": u(str(e)), "timeout": False, "duration": 0}
    killed = []

    def _kill():
        killed.append(True)
        try:
            p.kill()
        except OSError:
            pass
    timer = threading.Timer(timeout, _kill)
    timer.start()
    try:
        out, err = p.communicate()
    finally:
        timer.cancel()
        if devnull:
            devnull.close()
    return {
        "rc": p.returncode,
        "out": u(out[:max_out]),
        "err": u(err[:65536]),
        "timeout": bool(killed),
        "duration": round(time.time() - t0, 3),
    }


def run_out(cmd, timeout=60, **kw):
    """Raccourci : stdout si la commande existe, sinon None."""
    r = run(cmd, timeout=timeout, **kw)
    if r is None:
        return None
    return r["out"]


def parse_mounts():
    mounts = []
    text = read_text("/proc/self/mounts") or read_text("/proc/mounts") or ""
    for line in text.splitlines():
        p = line.split()
        if len(p) < 4:
            continue

        def unesc(s):
            return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)
        mounts.append({"device": unesc(p[0]), "mountpoint": unesc(p[1]), "fstype": p[2], "options": p[3]})
    return mounts


PSEUDO_FS = set("""proc sysfs devtmpfs devpts cgroup cgroup2 securityfs pstore bpf debugfs tracefs
configfs fusectl mqueue hugetlbfs autofs rpc_pipefs nfsd binfmt_misc selinuxfs efivarfs nsfs ramfs
squashfs iso9660 udf overlay aufs""".split())
NETWORK_FS = set("""nfs nfs4 cifs smb3 smbfs ceph glusterfs 9p gpfs lustre beegfs afs davfs
ocfs2 gfs2 sshfs""".split())


# --------------------------------------------------------------------------
# Définition des sondes de version (exécution de binaires)
# --------------------------------------------------------------------------
# (nom, regex sur le nom du fichier, [(args, filtre_lignes_regex|None)], mode)
#   mode "all"   : toutes les variantes d'arguments sont exécutées
#   mode "first" : s'arrête à la première variante qui réussit (rc == 0)
PY_PROBE_CODE = (
    "import sys\n"
    "try:\n"
    "    import ssl\n"
    "    o = ssl.OPENSSL_VERSION\n"
    "except Exception:\n"
    "    o = '-'\n"
    "sys.stdout.write('version=%s\\nopenssl=%s\\nprefix=%s\\nimpl=%s\\n' % "
    "(sys.version.split()[0], o, sys.prefix, sys.version.replace('\\n', ' ')))\n"
)

PROBES = [
    ("java", r"^java$", [(["-XshowSettings:properties", "-version"], None), (["-version"], None)], "first"),
    ("python", r"^(python([23](\.\d+)?[mtd]?)?|platform-python)$", [(["-c", PY_PROBE_CODE], None)], "all"),
    ("php", r"^php(\d+(\.\d+)?)?$|^php-cgi(\d+(\.\d+)?)?$", [(["-v"], None), (["-m"], None), (["-i"], "PHPINFO")], "all"),
    ("php-fpm", r"^php-?fpm(\d+(\.\d+)?)?$", [(["-v"], None), (["-i"], "PHPINFO")], "all"),
    ("node", r"^(node|nodejs)$", [(["--version"], None), (["-p", "JSON.stringify(process.versions)"], None)], "all"),
    ("ruby", r"^ruby(\d+(\.\d+)*)?$", [(["--version"], None)], "all"),
    ("perl", r"^perl(5[\d.]*)?$", [(["-e", 'print "$^V\\n"'], None)], "all"),
    ("go", r"^go$", [(["version"], None)], "all"),
    ("dotnet", r"^dotnet$", [(["--list-runtimes"], None), (["--list-sdks"], None)], "all"),
    ("postgresql", r"^(postgres|postmaster)$", [(["--version"], None)], "all"),
    ("psql", r"^psql$", [(["--version"], None)], "all"),
    ("mysqld", r"^(mysqld|mariadbd)$", [(["--version"], None)], "all"),
    ("mysql-client", r"^(mysql|mariadb)$", [(["--version"], None)], "all"),
    ("mongod", r"^mongod$", [(["--version"], None)], "all"),
    ("redis", r"^redis-server$", [(["--version"], None)], "all"),
    ("memcached", r"^memcached$", [(["-V"], None)], "all"),
    ("nginx", r"^nginx$", [(["-V"], None)], "all"),
    ("httpd", r"^(httpd|apache2)$", [(["-v"], None), (["-M"], None)], "all"),
    ("haproxy", r"^haproxy$", [(["-vv"], None)], "all"),
    ("varnish", r"^varnishd$", [(["-V"], None)], "all"),
    ("squid", r"^squid$", [(["-v"], None)], "all"),
    ("bind", r"^named$", [(["-v"], None)], "all"),
    ("postfix", r"^postconf$", [(["-h", "mail_version"], None)], "all"),
    ("dovecot", r"^dovecot$", [(["--version"], None)], "all"),
    ("samba", r"^smbd$", [(["--version"], None)], "all"),
    ("proftpd", r"^proftpd$", [(["-v"], None)], "all"),
    ("openssh-client", r"^ssh$", [(["-V"], None)], "all"),
    ("openssh-server", r"^sshd$", [(["-V"], None)], "all"),
    ("openssl", r"^openssl$", [(["version", "-a"], None)], "all"),
    ("sudo", r"^sudo$", [(["-V"], None)], "all"),
    ("bash", r"^bash$", [(["--version"], None)], "all"),
    ("curl", r"^curl$", [(["--version"], None)], "all"),
    ("wget", r"^wget$", [(["--version"], r"^GNU Wget")], "all"),
    ("git", r"^git$", [(["--version"], None)], "all"),
    ("glibc", r"^ldd$", [(["--version"], None)], "all"),
    ("systemd", r"^systemctl$", [(["--version"], None)], "all"),
    ("xz", r"^xz$", [(["--version"], None)], "all"),
    ("polkit", r"^pkexec$", [(["--version"], None)], "all"),
    ("rsync", r"^rsync$", [(["--version"], r"version")], "all"),
    ("sqlite", r"^sqlite3$", [(["--version"], None)], "all"),
    ("docker", r"^(docker|dockerd)$", [(["--version"], None)], "all"),
    ("podman", r"^podman$", [(["--version"], None)], "all"),
    ("containerd", r"^containerd$", [(["--version"], None)], "all"),
    ("runc", r"^runc$", [(["--version"], None)], "all"),
    ("crictl", r"^crictl$", [(["--version"], None)], "all"),
    ("kubelet", r"^kubelet$", [(["--version"], None)], "all"),
    ("kubectl", r"^kubectl$", [(["version", "--client"], None)], "all"),
    ("k3s", r"^k3s$", [(["--version"], None)], "all"),
    ("etcd", r"^etcd$", [(["--version"], None)], "all"),
    ("helm", r"^helm$", [(["version"], None)], "all"),
    ("grafana", r"^grafana$", [(["--version"], None)], "all"),
    ("grafana-server", r"^grafana-server$", [(["-v"], None)], "all"),
    ("prometheus", r"^(prometheus|alertmanager|pushgateway|[\w-]+_exporter)$", [(["--version"], None)], "all"),
    ("hashicorp", r"^(consul|vault|nomad|terraform|packer)$", [(["version"], None)], "all"),
    ("ansible", r"^ansible$", [(["--version"], None)], "all"),
    ("salt", r"^salt-(minion|master|call)$", [(["--version"], None)], "all"),
    ("puppet", r"^puppet$", [(["--version"], None)], "all"),
    ("zabbix", r"^zabbix_(agentd|agent2|server|proxy)$", [(["-V"], None)], "all"),
    ("keepalived", r"^keepalived$", [(["--version"], None)], "all"),
    ("influxdb", r"^influxd$", [(["version"], None)], "all"),
    ("clickhouse", r"^clickhouse(-server)?$", [(["--version"], None)], "all"),
    ("traefik", r"^traefik$", [(["version"], None)], "all"),
    ("caddy", r"^caddy$", [(["version"], None)], "all"),
    ("envoy", r"^envoy$", [(["--version"], None)], "all"),
    ("uwsgi", r"^uwsgi$", [(["--version"], None)], "all"),
    ("imagemagick", r"^(convert|magick)(-im\d[\w.]*)?$", [(["-version"], None)], "all"),
    ("ghostscript", r"^gs$", [(["--version"], None)], "all"),
    ("ffmpeg", r"^ffmpeg$", [(["-version"], r"version|configuration")], "all"),
    ("exiftool", r"^exiftool$", [(["-ver"], None)], "all"),
    ("wkhtmltopdf", r"^wkhtmltopdf$", [(["--version"], None)], "all"),
    ("openldap", r"^slapd$", [(["-VV"], None)], "all"),
    ("sssd", r"^sssd$", [(["--version"], None)], "all"),
    ("openvpn", r"^openvpn$", [(["--version"], r"OpenVPN|library")], "all"),
    ("snmpd", r"^snmpd$", [(["-v"], None)], "all"),
    ("chrony", r"^chronyd$", [(["-v"], None)], "all"),
    ("ntpd", r"^ntpd$", [(["--version"], None)], "all"),
    ("rsyslog", r"^rsyslogd$", [(["-v"], r"rsyslogd")], "all"),
    ("syslog-ng", r"^syslog-ng$", [(["--version"], None)], "all"),
    ("gitlab-runner", r"^gitlab-runner$", [(["--version"], None)], "all"),
]
PROBE_RX = [(name, re.compile(rx), argsets, mode) for name, rx, argsets, mode in PROBES]
PROBE_ANY_RX = re.compile("|".join("(?:%s)" % p[1] for p in PROBES))
# Sondes autorisées sur des scripts (non ELF), uniquement si le script appartient à un paquet
SCRIPT_PROBES = set(["glibc", "ansible", "salt", "puppet", "exiftool", "gitlab-runner"])

# Répertoires où chercher des binaires même sans parcours complet du disque
EXTRA_BIN_GLOBS = [
    "/usr/libexec", "/usr/lib/jvm/*/bin", "/usr/lib/jvm/*/jre/bin", "/usr/java/*/bin",
    "/usr/pgsql-*/bin", "/usr/lib/postgresql/*/bin", "/opt/rh/*/root/usr/bin", "/opt/rh/*/root/usr/sbin",
    "/opt/remi/*/root/usr/bin", "/opt/remi/*/root/usr/sbin", "/opt/*/bin", "/opt/*/sbin", "/opt/*/*/bin",
    "/usr/local/*/bin", "/usr/local/*/sbin", "/usr/lib/apache2", "/usr/sbin",
]


# --------------------------------------------------------------------------
# Règles de détection sur le système de fichiers
# --------------------------------------------------------------------------
ARCHIVE_EXT = (".jar", ".war", ".ear", ".hpi", ".jpi", ".sar")
MANIFEST_DROP = set(["Class-Path", "Import-Package", "Export-Package", "Private-Package", "Include-Resource",
                     "Require-Capability", "Provide-Capability", "DynamicImport-Package", "Embedded-Artifacts",
                     "Embed-Dependency", "Ignore-Package", "Sealed", "Name", "Bnd-LastModified", "Tool"])
# Classes "sentinelles" : détectent des composants même ombragés (shaded) dans une archive
CLASS_MARKERS = {
    "org/apache/logging/log4j/core/lookup/JndiLookup.class": "log4j2-core:JndiLookup",
    "org/apache/logging/log4j/core/LoggerContext.class": "log4j2-core",
    "org/apache/log4j/net/JMSAppender.class": "log4j1:JMSAppender",
    "org/apache/log4j/net/SocketServer.class": "log4j1:SocketServer",
    "org/apache/log4j/Logger.class": "log4j1",
    "org/apache/commons/text/lookup/ScriptStringLookup.class": "commons-text:ScriptStringLookup",
    "org/springframework/core/SpringVersion.class": "spring-core",
    "org/springframework/boot/SpringApplication.class": "spring-boot",
    "org/apache/struts2/dispatcher/Dispatcher.class": "struts2",
    "org/yaml/snakeyaml/Yaml.class": "snakeyaml",
    "com/fasterxml/jackson/databind/ObjectMapper.class": "jackson-databind",
    "org/codehaus/jackson/map/ObjectMapper.class": "jackson1-mapper",
    "org/apache/commons/collections/functors/InvokerTransformer.class": "commons-collections3:InvokerTransformer",
    "org/apache/commons/collections4/functors/InvokerTransformer.class": "commons-collections4:InvokerTransformer",
    "com/thoughtworks/xstream/XStream.class": "xstream",
    "org/apache/shiro/SecurityUtils.class": "shiro",
    "com/alibaba/fastjson/JSON.class": "fastjson",
    "org/h2/Driver.class": "h2",
    "org/apache/catalina/startup/Catalina.class": "tomcat-catalina",
    "org/eclipse/jetty/server/Server.class": "jetty-server",
    "io/netty/handler/codec/http/HttpObjectDecoder.class": "netty-codec-http",
    "org/apache/xmlrpc/XmlRpcRequest.class": "xmlrpc",
    "org/apache/axis2/engine/AxisServer.class": "axis2",
    "org/apache/axis/client/Service.class": "axis1",
}
CLASS_MARKER_BASENAMES = {}
for _k, _v in CLASS_MARKERS.items():
    CLASS_MARKER_BASENAMES.setdefault(_k.rsplit("/", 1)[-1], []).append(_k)
SPECIAL_ARCHIVE_ENTRIES = {
    "org/apache/catalina/util/ServerInfo.properties": "tomcat_serverinfo",
    "META-INF/MANIFEST.MF": None,
}

# Applications web / frameworks PHP (fichier, suffixe du répertoire, produit, regex de version)
WEBAPP_RULES = [
    ("version.php", "/wp-includes", "wordpress", [r"\$wp_version\s*=\s*'([^']+)'"]),
    ("version.php", "", "nextcloud-owncloud", [r"\$OC_VersionString\s*=\s*'([^']+)'", r"\$vendor\s*=\s*'([^']+)'"]),
    ("version.php", "", "moodle", [r"(?m)^\$release\s*=\s*'([^']+)'"]),
    ("version.php", "/application/config", "limesurvey", [r"\$config\['versionnumber'\]\s*=\s*'([^']+)'"]),
    ("version.php", "/libraries/cms/version", "joomla", [r"\$RELEASE\s*=\s*'([^']+)'", r"\$DEV_LEVEL\s*=\s*'([^']+)'"]),
    ("Version.php", "/libraries/src", "joomla", [r"const\s+MAJOR_VERSION\s*=\s*(\d+)", r"const\s+MINOR_VERSION\s*=\s*(\d+)", r"const\s+PATCH_VERSION\s*=\s*(\d+)"]),
    ("Version.php", "/libraries/classes", "phpmyadmin", [r"VERSION\s*=\s*'([^']+)'"]),
    ("Config.php", "/libraries", "phpmyadmin", [r"'PMA_VERSION',\s*'([^']+)'"]),
    ("Version.php", "/core", "matomo", [r"const\s+VERSION\s*=\s*'([^']+)'"]),
    ("Version.php", "/library/Zend", "zend-framework-1", [r"const\s+VERSION\s*=\s*'([^']+)'"]),
    ("Drupal.php", "/core/lib", "drupal", [r"const\s+VERSION\s*=\s*'([^']+)'"]),
    ("bootstrap.inc", "/includes", "drupal", [r"define\('VERSION',\s*'([^']+)'\)"]),
    ("define.php", "/inc", "glpi", [r"define\(\s*['\"]GLPI_VERSION['\"]\s*,\s*['\"]([^'\"]+)"]),
    ("Defines.php", "/includes", "mediawiki", [r"define\(\s*'MW_VERSION'\s*,\s*'([^']+)'"]),
    ("DefaultSettings.php", "/includes", "mediawiki", [r"\$wgVersion\s*=\s*'([^']+)'"]),
    ("iniset.php", "/program/include", "roundcube", [r"define\(\s*'RCMAIL_VERSION'\s*,\s*'([^']+)'"]),
    ("filefunc.inc.php", "", "dolibarr", [r"define\(\s*'DOL_VERSION'\s*,\s*'([^']+)'"]),
    ("inc_version.php", "/ecrire", "spip", [r"\$spip_version_branche\s*=\s*['\"]([^'\"]+)"]),
    ("CodeIgniter.php", "/system/core", "codeigniter", [r"define\(\s*'CI_VERSION'\s*,\s*'([^']+)'", r"const\s+CI_VERSION\s*=\s*'([^']+)'"]),
    ("Smarty.class.php", "", "smarty", [r"SMARTY_VERSION\s*=\s*'([^']+)'", r"\$_version\s*=\s*'([^']+)'"]),
    ("class.phpmailer.php", "", "phpmailer", [r"\$Version\s*=\s*'([^']+)'"]),
    ("PHPMailer.php", "", "phpmailer", [r"const\s+VERSION\s*=\s*'([^']+)'"]),
    ("version-manifest.txt", "/gitlab", "gitlab", [r"^(gitlab-[ce]e)\s+(\S+)"]),
    ("version.txt", "", "jboss-wildfly-keycloak", [r"^(.+)$"]),
    ("comps.xml", "/inventory/ContentsXML", "oracle-home", [r"<COMP NAME=\"([^\"]+)\" VER=\"([^\"]+)\""]),
    # IBM WebSphere, IBM HTTP Server et greffons : <produit>/properties/version/*.product
    ("WAS.product", "/properties/version", "websphere", [r"<version>([^<]+)</version>"]),
    ("ND.product", "/properties/version", "websphere-nd", [r"<version>([^<]+)</version>"]),
    ("BASE.product", "/properties/version", "websphere-base", [r"<version>([^<]+)</version>"]),
    ("IHS.product", "/properties/version", "ihs", [r"<version>([^<]+)</version>"]),
    ("PLG.product", "/properties/version", "websphere-plugin", [r"<version>([^<]+)</version>"]),
    ("WCT.product", "/properties/version", "websphere-toolbox", [r"<version>([^<]+)</version>"]),
    ("WXS.product", "/properties/version", "websphere-extreme-scale", [r"<version>([^<]+)</version>"]),
    ("JDK.product", "/properties/version", "websphere-jdk", [r"<version>([^<]+)</version>"]),
]
WEBAPP_FILENAMES = set(r[0] for r in WEBAPP_RULES)

JSLIB_RX = re.compile(r"^(jquery(?:[.-]ui)?|jquery\.dataTables|angular(?:js)?|bootstrap|moment|lodash|underscore|vue|"
                      r"react(?:-dom)?|handlebars|dompurify|purify|knockout|backbone|ckeditor|tinymce|select2|"
                      r"swfobject|prototype|mootools|dojo|ember|d3|highcharts|leaflet|pdf|plupload|fancybox|"
                      r"summernote|froala|datatables|sweetalert2?|axios|socket\.io)([.-][\w.-]*)?\.js$", re.I)
JS_HEADER_VERSION_RX = re.compile(r"(?:\bv|[Vv]ersion[\s:=]*|@version\s+|\s)(\d+\.\d+(?:\.\d+)?(?:[-.][\w.]+)?)")
FILENAME_VERSION_RX = re.compile(r"(\d+\.\d+(?:\.\d+)*(?:[-_.]?(?:rc|beta|alpha|b|u|p|Final|GA|RELEASE)\d*)?)")

NATIVE_LIB_RX = re.compile(r"^lib[\w+-]+?\.so(\.\d+)*$|^lib[\w+-]+?-[\d.]+\.so$")
SYSTEM_LIB_PREFIXES = ("/lib/", "/lib64/", "/lib32/", "/usr/lib/", "/usr/lib64/", "/usr/lib32/", "/usr/libx32/")
# Empreintes statiques : chaînes de version compilées dans les binaires/bibliothèques.
# Lues sans rien exécuter (y compris un binaire supprimé du disque, via /proc/PID/exe).
FINGERPRINTS = [
    ("httpd", re.compile(br"Apache/(\d+\.\d+\.\d+)")),
    ("nginx", re.compile(br"nginx/(\d+\.\d+\.\d+)")),
    ("php", re.compile(br"X-Powered-By: PHP/(\d+\.\d+\.\d+[\w.-]*)")),
    ("lighttpd", re.compile(br"lighttpd/(\d+\.\d+\.\d+)")),
    ("openssl", re.compile(br"OpenSSL (\d+\.\d+\.\d+[a-z]{0,2})(?:-fips)?\s+\d{1,2} \w{3} \d{4}")),
    ("curl", re.compile(br"libcurl/(\d+\.\d+\.\d+)")),
    ("zlib", re.compile(br"(?:deflate|inflate) (\d+\.\d+\.\d+(?:\.\d+)?) Copyright")),
]
FINGERPRINT_LIB_RX = re.compile(r"^(lib|mod_)php[\d.]*\.so|^lib(ssl|crypto|curl)[\w.-]*\.so")
# Chemins absolus dans une ligne de commande (classpath, -Dxxx=/chemin, argv[0]...)
CMDLINE_PATH_RX = re.compile(r"(/[^\s:=,;'\"]+)")
CMDLINE_HOME_PROPS = re.compile(r"-D(catalina\.home|catalina\.base|jboss\.home\.dir|java\.home|es\.path\.home|kafka\.logs\.dir)=(/[^\s:,;'\"]+)")
JVM_HOME_RX = re.compile(r"/lib/(?:[^/]+/)?(?:server|client|j9vm|default|minimal)/libjvm\.so$")


def fingerprint(path, max_size=256 << 20):
    """Versions trouvées dans un fichier binaire : {produit: [versions]}."""
    found = {}
    try:
        f = open(path, "rb")
    except (IOError, OSError):
        return found
    try:
        try:
            size = os.fstat(f.fileno()).st_size
            if size == 0 or size > max_size:
                return found
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        except (IOError, OSError, ValueError):
            return found
        try:
            for product, rx in FINGERPRINTS:
                vals = []
                for m in rx.finditer(mm):
                    v = u(m.group(1))
                    if v not in vals:
                        vals.append(v)
                    if len(vals) >= 5:
                        break
                if vals:
                    found[product] = vals
        finally:
            mm.close()
    finally:
        f.close()
    return found


LIB_STRING_PATTERNS = [
    (re.compile(r"^lib(ssl|crypto)"), re.compile(br"OpenSSL (\d+\.\d+\.\d+[a-z]{0,2})(?:-fips)?\s+\d{1,2} \w{3} \d{4}")),
    (re.compile(r"^libcurl"), re.compile(br"libcurl/(\d+\.\d+\.\d+)")),
    (re.compile(r"^libz\."), re.compile(br"(?:deflate|inflate) (\d+\.\d+\.\d+(?:\.\d+)?) Copyright")),
    (re.compile(r"^libphp"), re.compile(br"X-Powered-By: PHP/(\d+\.\d+\.\d+[\w.-]*)")),   # mod_php d'un Apache
]

OWN_INDEX_RX = re.compile(r"(\.(jar|war|ear|so(\.[\d.]+)?|js|json|php|inc|gemspec|txt|xml|cfg)$|/(METADATA|PKG-INFO|release|PG_VERSION)$|/s?bin/|/libexec/|\.(dist|egg)-info)")

DEFAULT_EXCLUDES = [
    "/proc", "/sys", "/dev", "/run", "/var/run", "/var/lock",
    "/var/lib/docker", "/var/lib/containers", "/var/lib/containerd", "/var/lib/kubelet/pods",
    "/var/lib/lxc", "/var/lib/lxd", "/var/lib/libvirt/images", "/var/lib/snapd/snaps", "/snap",
    "/var/cache/yum", "/var/cache/dnf", "/var/cache/apt", "/var/cache/zypp",
    "/usr/share/doc", "/usr/share/man", "/usr/share/locale", "/usr/share/info", "/usr/share/i18n",
    "/usr/share/zoneinfo", "/usr/share/icons", "/usr/share/fonts", "/usr/share/help",
    "/usr/src", "/usr/include", "/var/lib/mlocate", "/var/lib/plocate", "/lost+found",
    "/var/log/journal", "/var/lib/rpm", "/var/lib/dpkg", "/var/lib/apt/lists",
]
CONTAINER_STORAGE = ["/var/lib/docker", "/var/lib/containers", "/var/lib/containerd", "/var/lib/kubelet/pods"]
PRUNE_DIRNAMES = set([".git", ".svn", ".hg", "__pycache__", ".snapshot", ".snapshots", ".cache", ".npm",
                      ".m2", ".gradle", ".ivy2", "lost+found"])
# Les caches de dépendances (.m2, .gradle, .npm) ne sont pas "déployés" : exclus par défaut.

ENV_WHITELIST = set(["JAVA_HOME", "JRE_HOME", "CATALINA_HOME", "CATALINA_BASE", "JBOSS_HOME", "WILDFLY_HOME",
                     "ORACLE_HOME", "ORACLE_SID", "PATH", "LD_LIBRARY_PATH", "LD_PRELOAD", "PYTHONPATH",
                     "VIRTUAL_ENV", "CONDA_PREFIX", "NODE_ENV", "NODE_PATH", "PHPRC", "PHP_INI_SCAN_DIR",
                     "GEM_HOME", "GOPATH", "KAFKA_HOME", "ES_HOME", "SOLR_HOME", "SPRING_PROFILES_ACTIVE",
                     "container", "KUBERNETES_SERVICE_HOST", "PGDATA", "MYSQL_HOME", "JAVA_OPTS", "CATALINA_OPTS"])


# --------------------------------------------------------------------------
# Parsing d'archives Java
# --------------------------------------------------------------------------

def parse_manifest(text):
    attrs = {}
    last = None
    for line in text.splitlines():
        if not line.strip():
            break  # fin de la section principale
        if line.startswith(" ") and last:
            attrs[last] += line[1:]
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            last = k.strip()
            attrs[last] = v.strip()
    out = {}
    for k, v in attrs.items():
        if k in MANIFEST_DROP:
            continue
        out[k] = v[:512]
    return out


def parse_properties(text):
    d = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#!":
            continue
        m = re.match(r"([^=:\s]+)\s*[=:]\s*(.*)$", line)
        if m:
            d[m.group(1)] = m.group(2)
    return d


def inspect_archive(fileobj, display_path, depth, opts):
    res = {"path": display_path}
    try:
        z = zipfile.ZipFile(fileobj)
    except Exception as e:  # zip corrompu, format inattendu...
        res["error"] = u(repr(e))[:300]
        return res
    try:
        infos = z.infolist()
        res["entries"] = len(infos)
        maven = []
        markers = set()
        nested = []
        special = {}
        for info in infos:
            name = info.filename
            if name.endswith("/"):
                continue
            if name == "META-INF/MANIFEST.MF":
                try:
                    res["manifest"] = parse_manifest(u(z.open(info).read(256 * 1024)))
                except Exception:
                    pass
                continue
            if name.startswith("META-INF/maven/") and name.endswith("/pom.properties"):
                try:
                    pp = parse_properties(u(z.open(info).read(64 * 1024)))
                    maven.append({"groupId": pp.get("groupId"), "artifactId": pp.get("artifactId"),
                                  "version": pp.get("version")})
                except Exception:
                    pass
                continue
            base = name.rsplit("/", 1)[-1]
            if base in CLASS_MARKER_BASENAMES:
                for key in CLASS_MARKER_BASENAMES[base]:
                    if name.endswith(key):
                        markers.add(CLASS_MARKERS[key] + ("" if name == key else " (shaded:%s)" % name[:-len(key)].rstrip("/")))
            if name in SPECIAL_ARCHIVE_ENTRIES and SPECIAL_ARCHIVE_ENTRIES[name]:
                try:
                    special[SPECIAL_ARCHIVE_ENTRIES[name]] = parse_properties(u(z.open(info).read(64 * 1024)))
                except Exception:
                    pass
            lname = name.lower()
            if lname.endswith(ARCHIVE_EXT) and depth < opts["max_depth"]:
                if len(nested) >= 3000:
                    res["nested_truncated"] = True
                    continue
                if info.file_size > opts["nested_max"]:
                    nested.append({"path": display_path + "!/" + name, "skipped": "too_large",
                                   "size": info.file_size})
                    continue
                try:
                    data = z.read(name)
                except Exception as e:
                    nested.append({"path": display_path + "!/" + name, "error": u(repr(e))[:200]})
                    continue
                sub = inspect_archive(io.BytesIO(data), display_path + "!/" + name, depth + 1, opts)
                sub["size"] = len(data)
                sub["sha1"] = hashlib.sha1(data).hexdigest()
                nested.append(sub)
        if maven:
            res["maven"] = maven
        if markers:
            res["markers"] = sorted(markers)
        if special:
            res["special"] = special
        if nested:
            res["nested"] = nested
    finally:
        z.close()
    return res


# --------------------------------------------------------------------------
# Binaires Go : lecture de la section .go.buildinfo (Go >= 1.18)
# --------------------------------------------------------------------------

def elf_section(path, wanted=b".go.buildinfo"):
    try:
        with open(path, "rb") as f:
            ident = f.read(16)
            if len(ident) < 16 or ident[:4] != b"\x7fELF":
                return None
            cls = ord(ident[4:5])
            end = "<" if ord(ident[5:6]) == 1 else ">"
            if cls == 2:
                f.seek(0x28)
                shoff = struct.unpack(end + "Q", f.read(8))[0]
                f.seek(0x3A)
            else:
                f.seek(0x20)
                shoff = struct.unpack(end + "I", f.read(4))[0]
                f.seek(0x2E)
            shentsize, shnum, shstrndx = struct.unpack(end + "HHH", f.read(6))
            if not shoff or shnum == 0 or shnum > 8192 or shstrndx >= shnum:
                return None
            f.seek(shoff)
            raw = f.read(shentsize * shnum)

            def sh(i):
                b = raw[i * shentsize:(i + 1) * shentsize]
                if cls == 2:
                    nm, _t, _fl, _a, off, size = struct.unpack(end + "IIQQQQ", b[:40])
                else:
                    nm, _t, _fl, _a, off, size = struct.unpack(end + "IIIIII", b[:24])
                return nm, off, size
            _n, stroff, strsize = sh(shstrndx)
            f.seek(stroff)
            strtab = f.read(min(strsize, 1 << 20))
            for i in range(shnum):
                nm, off, size = sh(i)
                e = strtab.find(b"\0", nm)
                if strtab[nm:e] == wanted:
                    f.seek(off)
                    return f.read(min(size, 4 << 20))
    except (IOError, OSError, struct.error, ValueError):
        return None
    return None


def parse_go_buildinfo(data):
    if not data or data[:14] != b"\xff Go buildinf:":
        return None
    flags = ord(data[15:16])
    if not flags & 2:
        return {"go_version": None, "note": "format buildinfo antérieur à Go 1.18 (non décodé)"}

    def uvarint(pos):
        n = 0
        shift = 0
        while pos < len(data):
            b = ord(data[pos:pos + 1])
            pos += 1
            n |= (b & 0x7F) << shift
            if b < 0x80:
                break
            shift += 7
        return n, pos
    pos = 32
    n, pos = uvarint(pos)
    ver = data[pos:pos + n]
    pos += n
    n, pos = uvarint(pos)
    mod = data[pos:pos + n]
    if len(mod) >= 33 and mod[-17:-16] == b"\n":
        mod = mod[16:-16]
    res = {"go_version": u(ver), "deps": [], "build": {}}
    for line in u(mod).splitlines():
        p = line.split("\t")
        if p[0] == "path" and len(p) > 1:
            res["main_path"] = p[1]
        elif p[0] == "mod" and len(p) > 2:
            res["main_module"] = [p[1], p[2]]
        elif p[0] == "dep" and len(p) > 2:
            res["deps"].append([p[1], p[2]])
        elif p[0] == "=>" and len(p) > 2 and res["deps"]:
            res["deps"][-1].append("=> %s %s" % (p[1], p[2]))
        elif p[0] == "build" and len(p) > 1 and "=" in p[1]:
            k, v = p[1].split("=", 1)
            res["build"][k] = v[:200]
    return res


# ---------------------------------------------------------------------------
# Matériel et réseau : fonctions d'analyse partagées avec cmdb_shell_parse.py
# ---------------------------------------------------------------------------

def parse_lspci_vmm(text):
    """lspci -D -vmm -nn -k -> {slot: {Class, Vendor, Device, SVendor, SDevice, Rev, Driver...}}"""
    devs = {}
    cur = {}
    for line in (text or "").splitlines() + [""]:
        if not line.strip():
            if cur.get("Slot"):
                devs[cur["Slot"]] = cur
            cur = {}
            continue
        if ":" in line:
            k, v = line.split(":", 1)
            cur[k.strip()] = v.strip()
    return devs


def parse_colon_kv(text):
    """Sorties "Clé: valeur" (lscpu, ethtool -i, hostnamectl)."""
    d = {}
    for line in (text or "").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            k = k.strip()
            if k and k not in d:
                d[k] = v.strip()
    return d


def parse_ip_o_addr(text):
    addrs = []
    for line in (text or "").splitlines():
        t = line.replace("\\", " ").split()
        if len(t) >= 4 and t[2] in ("inet", "inet6"):
            a = {"ifname": t[1].split("@")[0], "family": t[2], "cidr": t[3],
                 "scope": t[t.index("scope") + 1] if "scope" in t else None}
            if "scope" in t:
                rest = [x for x in t[t.index("scope") + 2:] if x not in ("secondary", "dynamic", "noprefixroute",
                                                                         "valid_lft", "preferred_lft", "forever",
                                                                         "tentative", "deprecated", "temporary",
                                                                         "mngtmpaddr", "nodad", "permanent")
                        and not x.endswith("sec")]
                if rest and rest[0] != a["ifname"]:
                    a["label"] = rest[0]          # alias "eth0:1"
            if "secondary" in t:
                a["secondary"] = True
            addrs.append(a)
    return addrs


def parse_ip_link_details(text):
    """ip -o -d link show -> {ifname: {parent, vlan_id, kind}}"""
    out = {}
    for line in (text or "").splitlines():
        m = re.match(r"^\d+:\s+([^:@\s]+)(?:@([^:\s]+))?:", line)
        if not m:
            continue
        e = {}
        if m.group(2) and m.group(2) != "NONE":
            e["parent"] = m.group(2)
        v = re.search(r"\bvlan protocol (\S+) id (\d+)", line)
        if v:
            e["kind"] = "vlan"
            e["vlan_id"] = int(v.group(2))
        else:
            for kind in ("bond_slave", "bridge_slave", "bond", "bridge", "vxlan", "veth", "tun", "macvlan",
                         "ipvlan", "team", "dummy", "geneve", "wireguard", "openvswitch"):
                if re.search(r"\\\s+%s\b|\s%s\s" % (kind, kind), line):
                    e.setdefault("kind", kind)
        out[m.group(1)] = e
    return out


def parse_bonding_perm(text):
    """/proc/net/bonding/<bond> -> {esclave: MAC permanente}"""
    out = {}
    slave = None
    for line in (text or "").splitlines():
        if line.startswith("Slave Interface:"):
            slave = line.split(":", 1)[1].strip()
        elif line.startswith("Permanent HW addr:") and slave:
            out[slave] = line.split(":", 1)[1].strip()
    return out


PCI_SLOT_RX = re.compile(r"([0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f])")


def pci_slot_of(syspath):
    """Dernière adresse PCI d'un chemin sysfs (le contrôleur parent d'un virtio, d'un disque...)."""
    found = PCI_SLOT_RX.findall(syspath or "")
    return found[-1] if found else None


NIC_DETAIL_KINDS = ("vlan", "vxlan", "veth", "tun", "macvlan", "ipvlan", "team", "dummy", "geneve", "wireguard",
                    "openvswitch")


def nic_kind(name, has_device, is_bond, is_bridge, devtype, detail_kind):
    if is_bond:
        return "bond"
    if is_bridge:
        return "bridge"
    if name == "lo":
        return "loopback"
    if detail_kind in NIC_DETAIL_KINDS:
        return detail_kind
    if devtype:
        return devtype
    return "physical" if has_device else "virtual"


def disk_transport(syspath):
    p = syspath or ""
    for key, val in (("/nvme", "nvme"), ("/usb", "usb"), ("/virtio", "virtio"), ("rport-", "fc"),
                     ("/session", "iscsi"), ("/ata", "sata"), ("/xen", "xen"), ("/vmbus", "hyperv"),
                     ("/host", "scsi"), ("/virtual/", "virtuel")):
        if key in p:
            return val
    return None


def find_strings(path, rx, max_size=64 << 20):
    try:
        size = os.path.getsize(path)
        if size == 0 or size > max_size:
            return None
        with open(path, "rb") as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                m = rx.search(mm)
                return u(m.group(1)) if m else None
            finally:
                mm.close()
    except (IOError, OSError, ValueError):
        return None


# --------------------------------------------------------------------------
# Le collecteur
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Références de bases de données dans les configurations applicatives
#
# Seuls le moteur, l'hôte, le port et le nom de base sortent de ces fonctions :
# identifiants, mots de passe et paramètres d'URL ne sont jamais conservés.
# Fonctions partagées avec tools/cmdb_shell_parse.py.
# --------------------------------------------------------------------------
DB_CONFIG_NAMES = set([
    "context.xml", "server.xml", "standalone.xml", "standalone-ha.xml", "standalone-full.xml", "standalone-full-ha.xml",
    "domain.xml", "hibernate.cfg.xml", "persistence.xml", "resources.xml", "tnsnames.ora", "pgbouncer.ini", "pgpool.conf",
    "pg_service.conf", ".pg_service.conf", "odbc.ini", ".odbc.ini", "my.cnf", ".my.cnf", "wp-config.php", "config.php",
    "configuration.php", "config.inc.php", "settings.php", "settings.py", "local_settings.py", "database.yml",
    "database.yaml", "database.php", "db.php", "parameters.yml", "parameters.yaml", ".env", "web.config"])
DB_CONFIG_RX = re.compile(r"(\.properties$)|(\.env$)|(^\.env\.)|(-jdbc\.xml$)|(^application[-.\w]*\.ya?ml$)"
                          r"|(^bootstrap[-.\w]*\.ya?ml$)|(datasources?[-.\w]*\.(xml|ya?ml|json)$)|(^appsettings[-.\w]*\.json$)", re.I)
DB_CONFIG_SKIP_RX = re.compile(r"/(samples?|examples?|demos?|docs?|tests?|testdata|fixtures|node_modules|site-packages|"
                               r"dist-packages|vendor|i18n|locales?)/|/usr/(share|lib|lib64)/|/product/\d", re.I)
DB_CONFIG_MAX_SIZE = 256 * 1024
DB_CONFIG_MAX_FILES = 20000
DB_REFS_MAX_PER_FILE = 50
_DB_BLOCK_FILES = set(["settings.py", "local_settings.py", "database.yml", "database.yaml", "odbc.ini", ".odbc.ini",
                       "pg_service.conf", ".pg_service.conf", "my.cnf", ".my.cnf"])
_DB_HOST_OK = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9_.\-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:.]+\])$")
_DB_NAME_OK = re.compile(r"^[\w.$#\-]{1,128}$")
_DB_HOST_FAKE = set(["host", "hostname", "server", "servername", "dbhost", "db_host", "yourhost", "your_host", "your-host",
                     "dbserver", "myhost", "mydbhost", "myserver", "none", "null", "true", "false", "example.com",
                     "example.org", "example.net", "db.example.com", "x", "xxx"])
_DB_URI_RX = re.compile(r"(?<![\w+.\-])(jdbc:)?([A-Za-z][A-Za-z0-9_-]*(?:[:+][A-Za-z0-9_-]+)*)://([^\s'\"<>`]*)")
_DB_ORA_JDBC_RX = re.compile(r"jdbc:oracle:[A-Za-z0-9]+\s*:([^'\"<>`\r\n]*)", re.I)
_DB_PDO_RX = re.compile(r"(?<![\w.])(pgsql|mysql|sqlsrv):((?:[A-Za-z_]+=[^;'\"\s]*;?)+)", re.I)
_DB_PDO_OCI_RX = re.compile(r"(?<![\w.])oci:dbname=/{0,2}([^'\"\s;(]+)", re.I)
_DB_KV_RX = re.compile(r"""^\s*(?:export\s+)?(?:define\s*\(\s*)?['"]?([A-Za-z][\w.\-]*?)[_.\-]?"""
                       r"""(HOSTNAME|HOST|SERVER|ADDRESS|ADDR|PORT|DATABASE|DBNAME|NAME|DB|SERVICE_NAME|SERVICE|SID)"""
                       r"""['"]?\s*(?:=>|[=:,])\s*['"]?([^'"\s;,)]+)""", re.I)
_DB_KV_PREFIX_RX = re.compile(r"(?:^|[_.\-])(DB|DATABASE|DATASOURCE|POSTGRES|POSTGRESQL|PG|PGSQL|MYSQL|MARIADB|ORACLE|ORA|"
                              r"MONGO|MONGODB|REDIS|JDBC)$", re.I)
_DB_KV_ENGINE_RX = re.compile(r"""^\s*(?:export\s+)?['"]?(?:\w*[_.\-])?(?:DB_)?(?:CONNECTION|DRIVER|ADAPTER|ENGINE|TYPE)['"]?\s*"""
                              r"""[=:]\s*['"]?([\w.\-]+)""", re.I)
_DB_TNS_TOKEN_RX = re.compile(r"\(\s*(HOST|PORT|SERVICE_NAME|SID)\s*=\s*([^)\s]+)\s*\)", re.I)
_DB_TNS_ENTRY_RX = re.compile(r"^[ \t]*([A-Za-z0-9_.\-]+(?:[ \t]*,[ \t]*[A-Za-z0-9_.\-]+)*)[ \t]*=[ \t]*(?=\(|$)", re.M)
_DB_TNS_KEYWORDS = set(["DESCRIPTION", "DESCRIPTION_LIST", "ADDRESS", "ADDRESS_LIST", "CONNECT_DATA", "SERVICE_NAME", "SID",
                        "HOST", "PORT", "PROTOCOL", "SERVER", "SOURCE_ROUTE", "LOAD_BALANCE", "FAILOVER", "RETRY_COUNT"])


def is_db_config(path, lname):
    """Ce fichier peut-il contenir une chaîne de connexion ? (lname : nom en minuscules)"""
    if lname == "tnsnames.ora":
        return "/samples/" not in path
    if not (lname in DB_CONFIG_NAMES or DB_CONFIG_RX.search(lname) or (lname.endswith(".xml") and "/conf/Catalina/" in path)):
        return False
    return not DB_CONFIG_SKIP_RX.search(path)


def db_engine_name(text):
    s = (text or "").lower()
    for rx, engine in (("postgres|pgsql|psql|npgsql|(^|[_.\\-])pg$", "postgresql"), ("oracle|\\boci", "oracle"), ("mysql|maria", "mysql"),
                       ("sqlserver|mssql|sqlsrv|sql server", "sqlserver"), ("db2", "db2"), ("mongo", "mongodb"),
                       ("redis", "redis"), ("informix", "informix")):
        if re.search(rx, s):
            return engine
    return None


def _db_add(refs, seen, engine, host, port, database, alias, kind):
    host = (host or "").strip().strip("[]") if host else None
    if host is not None:
        if not _DB_HOST_OK.match(host if ":" not in host else "[%s]" % host) or host.lower() in _DB_HOST_FAKE:
            return
    elif not alias:
        return
    if port is not None:
        port = str(port).strip()
        if not port.isdigit() or not 0 < int(port) < 65536:
            return
        port = int(port)
    if database is not None and not _DB_NAME_OK.match(database):
        database = None
    if alias is not None and not _DB_NAME_OK.match(alias):
        alias = None
    key = (engine, host, port, database, alias)
    if key in seen or len(refs) >= DB_REFS_MAX_PER_FILE:
        return
    seen.add(key)
    refs.append({"engine": engine, "host": host, "port": port, "database": database, "alias": alias, "kind": kind})


def _db_hostport(text):
    """h, h:p, [v6]:p -> (hôte, port)"""
    m = re.match(r"^\[([^\]]+)\](?::(\d+))?$", text)
    if m:
        return m.group(1), m.group(2)
    if text.count(":") == 1:
        h, p = text.split(":")
        return h, p
    return text, None


def _db_tns_descriptor(text, refs, seen, alias, kind):
    hosts, ports, service = [], [], None
    for key, val in _DB_TNS_TOKEN_RX.findall(text):
        key = key.upper()
        if key == "HOST":
            hosts.append(val)
        elif key == "PORT":
            ports.append(val)
        elif service is None:
            service = val
    for i, h in enumerate(hosts):
        _db_add(refs, seen, "oracle", h, ports[i] if i < len(ports) else None, service, alias, kind)


def tns_entries(text):
    """tnsnames.ora ou listener.ora -> [(alias, texte de l'entrée)]"""
    text = re.sub(r"(?m)#.*$", "", text or "")
    marks = [m for m in _DB_TNS_ENTRY_RX.finditer(text) if m.group(1).upper() not in _DB_TNS_KEYWORDS]
    out = []
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        out.append((m.group(1).split(",")[0].strip(), text[m.end():end]))
    return out


def _db_inline_descriptors(text, refs, seen):
    for m in re.finditer(r"\(\s*DESCRIPTION\b", text, re.I):
        depth, i = 0, m.start()
        while i < len(text) and i - m.start() < 4096:
            if text[i] == "(":
                depth += 1
            elif text[i] == ")":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        _db_tns_descriptor(text[m.start():i + 1], refs, seen, None, "tns")


def _db_block_refs(text, fname, refs, seen):
    """Fichiers à sections : odbc.ini, pg_service.conf, my.cnf, database.yml, settings.py."""
    default = {"pg_service.conf": "postgresql", ".pg_service.conf": "postgresql", "my.cnf": "mysql", ".my.cnf": "mysql"}.get(fname)
    cur = {}

    def flush():
        if cur.get("host"):
            _db_add(refs, seen, db_engine_name(cur.get("engine")) or default, cur["host"], cur.get("port"), cur.get("db"), None, "config")
        cur.clear()
    for line in text.splitlines():
        s = line.strip()
        if not s or s[0] in "#;" or len(s) > 2000:
            continue
        if (s[0] == "[" and s.endswith("]")) or (line[0] not in " \t" and s.endswith(":")) or re.match(r"""['"]\w+['"]\s*:\s*\{""", s):
            flush()
            continue
        m = re.match(r"""['"]?(\w+)['"]?\s*[:=]\s*['"]?([^'",\s#]+)""", s)
        if not m:
            continue
        k, v = m.group(1).lower(), m.group(2)
        if k in ("host", "hostname", "server", "servername", "address"):
            cur.setdefault("host", v)
        elif k == "port":
            cur.setdefault("port", v)
        elif k in ("database", "dbname", "db") or (k == "name" and fname.endswith(".py")):
            cur.setdefault("db", v)
        elif k in ("adapter", "engine", "driver", "type"):
            cur.setdefault("engine", v)
    flush()


def extract_db_refs(text, fname=""):
    """Texte d'un fichier de configuration -> [{engine, host, port, database, alias, kind}]"""
    refs, seen = [], set()
    if not text:
        return refs
    fname = (fname or "").lower()
    if fname == "tnsnames.ora":
        for alias, body in tns_entries(text):
            _db_tns_descriptor(body, refs, seen, alias, "tnsnames")
        return refs
    for m in _DB_URI_RX.finditer(text):
        engine = db_engine_name(re.split(r"[:+]", m.group(2))[0])
        if not engine:
            continue
        rest = re.split(r"[?#]", m.group(3))[0]
        if "@" in rest:
            rest = rest.rsplit("@", 1)[1]
        auth, _, path = rest.partition("/")
        auth, _, params = auth.partition(";")
        path = path.split("/")[0].split(";")[0]
        pm = re.search(r"(?:^|;)database(?:name)?=([^;]+)", params + ";" + rest.partition(";")[2], re.I)
        database = pm.group(1) if pm else (path or None)
        for one in auth.split(","):
            h, p = _db_hostport(one)
            if h:
                _db_add(refs, seen, engine, h, p, database, None, "jdbc" if m.group(1) else "uri")
    for m in _DB_ORA_JDBC_RX.finditer(text):
        rest = m.group(1).strip()
        if "@" not in rest:
            continue                       # sans @, ce qui suit peut être un identifiant : ignoré
        rest = rest.rsplit("@", 1)[1].strip()
        if rest.startswith("("):
            _db_tns_descriptor(rest, refs, seen, None, "jdbc")
            continue
        rest = rest.lstrip("/").split("?")[0].split()[0] if rest.strip("/") else ""
        hm = re.match(r"^([^:/]+):(\d+)[:/]([^:/]+)", rest) or re.match(r"^([^:/]+)()/([^:/]+)", rest)
        if hm:
            _db_add(refs, seen, "oracle", hm.group(1), hm.group(2) or None, hm.group(3), None, "jdbc")
        elif rest:
            _db_add(refs, seen, "oracle", None, None, None, rest, "jdbc")
    for m in _DB_PDO_RX.finditer(text):
        kv = dict((p.split("=", 1)[0].lower(), p.split("=", 1)[1]) for p in m.group(2).split(";") if "=" in p)
        h, p = _db_hostport(kv.get("host") or kv.get("server") or "")
        if h:
            _db_add(refs, seen, db_engine_name(m.group(1)), h, kv.get("port") or p, kv.get("dbname") or kv.get("database"), None, "pdo")
    for m in _DB_PDO_OCI_RX.finditer(text):
        hm = re.match(r"^([^:/]+)(?::(\d+))?/([^/]+)", m.group(1))
        if hm:
            _db_add(refs, seen, "oracle", hm.group(1), hm.group(2), hm.group(3), None, "pdo")
    if "description" in text.lower():
        _db_inline_descriptors(text, refs, seen)
    if fname in _DB_BLOCK_FILES:
        _db_block_refs(text, fname, refs, seen)
        return refs
    groups, hint = {}, None
    for line in text.splitlines():
        if len(line) > 2000:
            continue
        low = line.lower()
        if ("database" in low or "initial catalog" in low) and ";" in line and "=" in line:
            # chaîne de connexion ADO.NET : Server=h;Port=p;Database=d;User Id=...;Password=...
            kv = {}
            for part in re.split(r"[;\"']", line):
                k, sep, v = part.partition("=")
                if sep:
                    kv[k.strip().lower().rsplit(" ", 1)[-1] if k.strip().lower() not in ("data source", "initial catalog")
                       else k.strip().lower()] = v.strip()
            h = kv.get("server") or kv.get("host") or kv.get("data source")
            if h and "dbname" not in kv:
                h, _, p = h.replace("tcp:", "").partition(",")
                h, p2 = _db_hostport(h)
                _db_add(refs, seen, None, h, kv.get("port") or p or p2, kv.get("database") or kv.get("initial catalog"), None, "connstring")
                continue
        if "dbname" in low and "host" in low:
            # chaîne libpq : host=h port=p dbname=d user=u password=x
            hm = re.search(r"(?<![\w.])host\s*=\s*['\"]?([^\s'\";]+)", line, re.I)
            dm = re.search(r"(?<![\w.])dbname\s*=\s*['\"]?([^\s'\";]+)", line, re.I)
            pm = re.search(r"(?<![\w.])port\s*=\s*['\"]?(\d+)", line, re.I)
            if hm and dm and not re.search(r"(pgsql|mysql|sqlsrv):", line, re.I):
                _db_add(refs, seen, "postgresql", hm.group(1), pm and pm.group(1), dm.group(1), None, "libpq")
                continue
        em = _DB_KV_ENGINE_RX.match(line)
        if em and db_engine_name(em.group(1)):
            hint = db_engine_name(em.group(1))
        m = _DB_KV_RX.match(line)
        if m and _DB_KV_PREFIX_RX.search(m.group(1) or "DB"):
            g = groups.setdefault((m.group(1) or "DB").lower(), {})
            k = m.group(2).upper()
            k = {"HOSTNAME": "HOST", "SERVER": "HOST", "ADDRESS": "HOST", "ADDR": "HOST"}.get(k, k)
            k = "PORT" if k == "PORT" else ("HOST" if k == "HOST" else "DB")
            g.setdefault(k, m.group(3))
    for prefix, g in sorted(groups.items()):
        if g.get("HOST"):
            h, p = _db_hostport(g["HOST"])
            engine = db_engine_name(prefix) or hint or ("mysql" if fname == "wp-config.php" else None)
            _db_add(refs, seen, engine, h, g.get("PORT") or p, g.get("DB"), None, "config")
    return refs


# --------------------------------------------------------------------------
# Oracle : lecture seule des fichiers d'inventaire. opatch n'est jamais exécuté :
# il appartient au compte oracle et écrit dans cfgtoollogs.
# Fonctions partagées avec tools/cmdb_shell_parse.py.
# --------------------------------------------------------------------------
ORACLE_PRODUCTS = (("oracle.server", "database"), ("oracle.crs", "grid"), ("oracle.client", "client"))
ORACLE_ONEOFF_RX = re.compile(r"<ONEOFF\b([^>]*)>\s*<DESC>(.*?)</DESC>", re.S)


def xml_attrs(tag):
    return dict(re.findall(r'([A-Za-z_]+)="([^"]*)"', tag))


def parse_central_inventory(text):
    homes = []
    for m in re.finditer(r"<HOME\b[^>]*>", text or ""):
        a = xml_attrs(m.group(0))
        if a.get("LOC") and a.get("REMOVED") != "T":
            homes.append({"name": a.get("NAME"), "loc": a.get("LOC"), "crs": a.get("CRS") == "true"})
    return homes


def oracle_home_candidates(oratab, inventory_homes, olr_loc, processes):
    """Tous les ORACLE_HOME connus -> {home: [origines]}"""
    homes = {}

    def add(path, origin):
        path = (path or "").rstrip("/")
        if path.startswith("/") and origin not in homes.setdefault(path, []):
            homes[path].append(origin)
    for line in (oratab or "").splitlines():
        p = line.strip().split(":")
        if len(p) >= 2 and not line.strip().startswith("#"):
            add(p[1], "oratab")
    for h in inventory_homes or []:
        add(h.get("loc"), "inventory")
    add(kv_text(olr_loc or "").get("crs_home"), "olr.loc")
    for p in processes or []:
        env = p.get("env") or {}
        if env.get("ORACLE_HOME"):
            add(env["ORACLE_HOME"], "process")
        for cand in (p.get("exe"), (p.get("cmdline") or "").split(" ")[0]):
            m = re.match(r"^(/.+)/bin/(?:tnslsnr|oracle)$", cand or "")
            if m:
                add(m.group(1), "process")
    return homes


def oracle_home_facts(home, read, ls):
    """read(chemin relatif) -> texte ou None ; ls(chemin relatif) -> liste ou None."""
    f = {"home": home, "patches": [], "patch_sources": []}
    patches = {}

    def patch(pid, desc, installed, source):
        cur = patches.setdefault(pid, {"id": pid, "description": None, "installed_at": None})
        cur["description"] = cur["description"] or (desc or "").strip() or None
        cur["installed_at"] = cur["installed_at"] or installed
        if source not in f["patch_sources"]:
            f["patch_sources"].append(source)
    comps = read("inventory/ContentsXML/comps.xml")
    f["comps_readable"] = comps is not None
    if comps:
        for name, kind in ORACLE_PRODUCTS:
            m = re.search(r'<COMP NAME="%s" VER="([^"]+)"' % re.escape(name), comps)
            if m:
                f["product"], f["version"] = kind, m.group(1)
                break
        m = re.search(r'<INST_TYPE NAME="([^"]+)"', comps)
        if m:
            f["install_type"] = m.group(1)
        for m in ORACLE_ONEOFF_RX.finditer(comps):
            a = xml_attrs(m.group(1))
            if a.get("REF_ID"):
                patch(a["REF_ID"], m.group(2), a.get("INSTALL_TIME"), "comps.xml")
    gv = read("inventory/globalvariables/oracle.server/globalvariables.xml")
    if gv:
        m = re.search(r'NAME="oracle_install_db_Install(?:Type|Edition)"[^>]*?VALUE="([^"]*)"', gv)
        if m and m.group(1):
            f["install_type"] = m.group(1)
    for pid in ls("inventory/oneoffs") or []:
        if pid.isdigit():
            t = read("inventory/oneoffs/%s/etc/config/inventory.xml" % pid)
            m = re.search(r"<(?:patch_)?description>(.*?)</", t or "", re.S)
            patch(pid, m and m.group(1), None, "oneoffs")
    for name in ls(".patch_storage") or []:
        m = re.match(r"^(\d{6,})_", name)
        if m:
            patch(m.group(1), None, None, ".patch_storage")
    f["patches"] = sorted(patches.values(), key=lambda x: x["id"])
    f["visibility"] = "complet" if comps else ("partiel" if f["patches"] else "aucun")
    t = read("OPatch/version.txt")
    if t:
        m = re.search(r"OPATCH_VERSION:\s*(\S+)", t)
        f["opatch_version"] = m.group(1) if m else None
    sids = set()
    for name in ls("dbs") or []:
        m = re.match(r"^(?:init|spfile|orapw)([A-Za-z+\-][\w+\-]*?)(?:\.ora)?$", name)
        if m and m.group(1).lower() != "dbs":
            sids.add(m.group(1))
    f["configured_sids"] = sorted(sids)
    f["listeners"] = []
    for name, body in tns_entries(read("network/admin/listener.ora")):
        if name.upper().startswith(("SID_LIST_", "ADR_", "SSL_", "INBOUND_", "SECURE_", "VALID_NODE", "TRACE_", "LOG_")):
            continue
        toks = _DB_TNS_TOKEN_RX.findall(body)
        hosts = [v for k, v in toks if k.upper() == "HOST"]
        ports = [v for k, v in toks if k.upper() == "PORT"]
        for i, p in enumerate(ports):
            f["listeners"].append({"name": name, "host": hosts[i] if i < len(hosts) else None, "port": int(p) if p.isdigit() else None})
    f["tns_refs"] = extract_db_refs(read("network/admin/tnsnames.ora"), "tnsnames.ora")
    return f


# --------------------------------------------------------------------------
# Modules activés (Apache, IHS, nginx, PHP, PostgreSQL, Redis, MySQL)
# Seules les directives de chargement sont lues. Partagé avec cmdb_shell_parse.py.
# --------------------------------------------------------------------------
MODULE_FILES = set(["httpd.conf", "apache2.conf", "nginx.conf", "php.ini", "postgresql.conf", "postgresql.auto.conf",
                    "redis.conf", "my.cnf", "mysqld.cnf", "mariadb.cnf", "server.cnf"])
_MODULE_LINE_RX = re.compile(r"^[ \t]*(LoadModule|load_module|zend_extension|extension|shared_preload_libraries|loadmodule|"
                             r"plugin[-_]load(?:[-_]add)?)\b[ \t]*=?[ \t]*(.*?)[ \t]*;?[ \t]*$", re.I | re.M)


def is_module_config(path, lname):
    if re.search(r"/usr/share/|/samples?/|/docs?/|/examples?/", path):
        return False
    if lname in MODULE_FILES:
        return True
    if lname.endswith(".load"):
        return "/mods-enabled/" in path
    if lname.endswith(".conf"):
        return "/conf.modules.d/" in path or "/modules-enabled/" in path
    if lname.endswith(".ini"):
        return "/php.d/" in path or ("/conf.d/" in path and "/php" in path)
    return False


def parse_modules(text, path):
    """Directives actives d'un fichier -> [{product, module, value}]"""
    out = []
    apache = "ihs" if "/HTTPServer/" in path else "apache"
    for m in _MODULE_LINE_RX.finditer(text or ""):
        word, val = m.group(1).lower(), m.group(2).split("#")[0].strip().strip("\"'")
        if not val:
            continue
        if word == "loadmodule" and path.lower().endswith("redis.conf"):
            out.append({"product": "redis", "module": val.split()[0].rsplit("/", 1)[-1], "value": val})
        elif word == "loadmodule":
            p = val.split()
            if len(p) >= 2:
                out.append({"product": apache, "module": p[0], "value": p[1]})
        elif word == "load_module":
            name = val.rsplit("/", 1)[-1]
            out.append({"product": "nginx", "module": re.sub(r"\.so$", "", name), "value": val})
        elif word in ("extension", "zend_extension"):
            val = val.split(";")[0].strip().strip("\"'")
            name = val.rsplit("/", 1)[-1]
            out.append({"product": "php", "module": re.sub(r"\.(so|dll)$", "", name), "value": val})
        elif word == "shared_preload_libraries":
            for lib in re.split(r"[,\s]+", val):
                if lib.strip("'\""):
                    out.append({"product": "postgresql", "module": lib.strip("'\""), "value": None})
        else:
            for item in val.split(";"):
                name = item.split("=")[0].strip()
                if name:
                    out.append({"product": "mysql", "module": re.sub(r"\.so$", "", name), "value": item.strip()})
    return out


# --------------------------------------------------------------------------
# Clés et certificats : tout fichier repéré est mentionné. On en tire ce qui est
# public (sujet, émetteur, dates, empreinte du certificat), JAMAIS le contenu d'une
# clé. Aucun mot de passe n'est essayé, hormis le mot de passe vide pour PKCS#12.
# Partagé avec cmdb_shell_parse.py.
# --------------------------------------------------------------------------
CRYPTO_EXT = (".key", ".pem", ".crt", ".cer", ".der", ".p12", ".pfx", ".jks", ".keystore", ".jceks", ".bcfks", ".kdb",
              ".sth", ".p7b", ".p8", ".pk8", ".ppk", ".truststore", ".sso")
CRYPTO_NAMES = set(["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "keystore", "truststore", "secring.gpg"])
CRYPTO_TRUST_RX = re.compile(r"/etc/ssl/certs/|/etc/pki/ca-trust/|/etc/pki/tls/certs/ca-|/etc/ca-certificates/|"
                             r"/usr/share/ca-certificates/|/usr/share/pki/|/usr/share/doc/|/certifi/|/usr/lib/ssl/certs")
CRYPTO_MAX_READ = 2 << 20
CRYPTO_MAX_FILES = 20000
CRYPTO_MAX_CERTS = 20
CRYPTO_MAX_P12 = 200
_OID_NAMES = {"2.5.4.3": "CN", "2.5.4.5": "serialNumber", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O",
              "2.5.4.11": "OU", "1.2.840.113549.1.9.1": "emailAddress", "0.9.2342.19200300.100.1.25": "DC"}
_OID_SIG = {"1.2.840.113549.1.1.4": "md5WithRSA", "1.2.840.113549.1.1.5": "sha1WithRSA", "1.2.840.113549.1.1.11": "sha256WithRSA",
            "1.2.840.113549.1.1.12": "sha384WithRSA", "1.2.840.113549.1.1.13": "sha512WithRSA", "1.2.840.113549.1.1.10": "rsassaPss",
            "1.2.840.10045.4.1": "ecdsaWithSHA1", "1.2.840.10045.4.3.2": "ecdsaWithSHA256", "1.2.840.10045.4.3.3": "ecdsaWithSHA384",
            "1.2.840.10045.4.3.4": "ecdsaWithSHA512", "1.3.101.112": "ed25519", "1.2.840.10040.4.3": "dsaWithSHA1"}
_OID_CURVE = {"1.2.840.10045.3.1.7": "P-256", "1.3.132.0.34": "P-384", "1.3.132.0.35": "P-521"}


def _der_tlv(b, i):
    """-> (étiquette, début de la valeur, fin de la valeur)"""
    tag = b[i]
    i += 1
    n = b[i]
    i += 1
    if n & 0x80:
        k = n & 0x7f
        if not 0 < k <= 4:
            raise ValueError("longueur DER")
        n = 0
        for x in b[i:i + k]:
            n = (n << 8) | x
        i += k
    if i + n > len(b):
        raise ValueError("DER tronqué")
    return tag, i, i + n


def _der_children(b, start, end):
    out = []
    while start < end:
        t, s, e = _der_tlv(b, start)
        out.append((t, s, e))
        start = e
    return out


def _der_oid(b, s, e):
    first = b[s]
    parts = [min(first // 40, 2), first - 40 * min(first // 40, 2)]
    v = 0
    for x in b[s + 1:e]:
        v = (v << 7) | (x & 0x7f)
        if not x & 0x80:
            parts.append(v)
            v = 0
    return ".".join(str(p) for p in parts)


def _der_string(b, t, s, e):
    raw = bytes(b[s:e])
    try:
        if t == 0x1e:
            return raw.decode("utf-16-be")
        return raw.decode("utf-8")
    except UnicodeError:
        return raw.decode("latin-1")


def _der_name(b, s, e):
    parts = []
    for _t, rs, re_ in _der_children(b, s, e):
        for _t2, as_, ae in _der_children(b, rs, re_):
            kids = _der_children(b, as_, ae)
            oid = _der_oid(b, kids[0][1], kids[0][2])
            parts.append((_OID_NAMES.get(oid, oid), _der_string(b, *kids[1])))
    return parts


def _der_time(b, t, s, e):
    v = bytes(b[s:e]).decode("ascii")
    if t == 0x17:
        v = ("19" if int(v[:2]) >= 50 else "20") + v
    return "%s-%s-%sT%s:%s:%sZ" % (v[0:4], v[4:6], v[6:8], v[8:10], v[10:12], v[12:14])


def x509_facts(der):
    """Certificat DER -> champs publics, ou None s'il n'est pas lisible."""
    try:
        b = bytearray(der)
        _t, s, e = _der_tlv(b, 0)
        top = _der_children(b, s, e)
        tbs = _der_children(b, top[0][1], top[0][2])
        i = 1 if tbs[0][0] == 0xa0 else 0
        serial = "".join("%02x" % x for x in b[tbs[i][1]:tbs[i][2]])
        sig_kids = _der_children(b, top[1][1], top[1][2])
        sig = _der_oid(b, sig_kids[0][1], sig_kids[0][2])
        issuer = _der_name(b, tbs[i + 2][1], tbs[i + 2][2])
        val = _der_children(b, tbs[i + 3][1], tbs[i + 3][2])
        subject = _der_name(b, tbs[i + 4][1], tbs[i + 4][2])
        f = {"subject": ",".join("%s=%s" % x for x in subject), "issuer": ",".join("%s=%s" % x for x in issuer),
             "cn": ([v for k, v in subject if k == "CN"] or [None])[0], "not_before": _der_time(b, *val[0]),
             "not_after": _der_time(b, *val[1]), "serial": serial, "sig_alg": _OID_SIG.get(sig, sig), "sans": [], "is_ca": False,
             "self_signed": subject == issuer, "sha256": hashlib.sha256(bytes(b[0:e])).hexdigest()}
        spki = _der_children(b, tbs[i + 5][1], tbs[i + 5][2])
        alg = _der_children(b, spki[0][1], spki[0][2])
        oid = _der_oid(b, alg[0][1], alg[0][2])
        if oid == "1.2.840.113549.1.1.1":
            f["key_alg"] = "RSA"
            _t, ks, ke = _der_tlv(b, spki[1][1] + 1)
            mod = _der_children(b, ks, ke)[0]
            n = mod[2] - mod[1]
            f["key_bits"] = (n - 1 if b[mod[1]] == 0 else n) * 8
        elif oid == "1.2.840.10045.2.1":
            f["key_alg"] = "EC"
            curve = _der_oid(b, alg[1][1], alg[1][2])
            f["key_curve"] = _OID_CURVE.get(curve, curve)
        else:
            f["key_alg"] = {"1.3.101.112": "Ed25519", "1.2.840.10040.4.1": "DSA"}.get(oid, oid)
        for t, xs, xe in tbs[i + 6:]:
            if t != 0xa3:
                continue
            _t, es, ee = _der_tlv(b, xs)
            for _t2, ys, ye in _der_children(b, es, ee):
                kids = _der_children(b, ys, ye)
                ext = _der_oid(b, kids[0][1], kids[0][2])
                vt, vs, ve = kids[-1]
                if ext == "2.5.29.17":
                    _t3, ss, se = _der_tlv(b, vs)
                    for gt, gs, ge in _der_children(b, ss, se):
                        if gt == 0x82:
                            f["sans"].append(bytes(b[gs:ge]).decode("ascii", "replace"))
                        elif gt == 0x87 and ge - gs == 4:
                            f["sans"].append(".".join(str(x) for x in b[gs:ge]))
                elif ext == "2.5.29.19":
                    _t3, ss, se = _der_tlv(b, vs)
                    bc = _der_children(b, ss, se)
                    f["is_ca"] = bool(bc and bc[0][0] == 1 and b[bc[0][1]] != 0)
        return f
    except (IndexError, ValueError, UnicodeError, TypeError):
        return None


def certs_from_pem(text):
    out = []
    for m in re.finditer(r"-----BEGIN (?:TRUSTED |X509 )?CERTIFICATE-----(.*?)-----END", text or "", re.S):
        try:
            c = x509_facts(base64.b64decode(re.sub(r"\s", "", m.group(1)).encode("ascii")))
        except (ValueError, TypeError, UnicodeError):
            c = None
        if c:
            out.append(c)
    return out


def _java_store(data, f):
    """JKS / JCEKS : alias et certificats sont en clair, les clés restent chiffrées et ne sont pas lues."""
    magic, _ver, count = struct.unpack(">III", data[:12])
    i = 12

    def utf():
        n = struct.unpack(">H", data[i[0]:i[0] + 2])[0]
        v = data[i[0] + 2:i[0] + 2 + n].decode("utf-8", "replace")
        i[0] += 2 + n
        return v

    def u32():
        v = struct.unpack(">I", data[i[0]:i[0] + 4])[0]
        i[0] += 4
        return v

    def cert(alias):
        utf()
        n = u32()
        c = x509_facts(data[i[0]:i[0] + n])
        i[0] += n
        if c:
            c["alias"] = alias
            f["certs"].append(c)
    i = [i]
    f["entries"] = count
    f["has_private_key"] = False
    for _n in range(min(count, 500)):
        tag = u32()
        alias = utf()
        i[0] += 8
        if tag == 1:
            f["has_private_key"] = True
            f["encrypted"] = True
            n = u32()
            i[0] += n
            for _c in range(u32()):
                cert(alias)
        elif tag == 2:
            cert(alias)
        else:
            f["note"] = "entrées de clé secrète : lecture arrêtée"
            f["has_private_key"] = True
            f["encrypted"] = True
            break


def _crypto_openssh(text, f):
    m = re.search(r"-----BEGIN OPENSSH PRIVATE KEY-----(.*?)-----END", text, re.S)
    f["has_private_key"] = True
    if not m:
        return
    raw = base64.b64decode(re.sub(r"\s", "", m.group(1)).encode("ascii"))
    i = len(b"openssh-key-v1\0")

    def s(i):
        n = struct.unpack(">I", raw[i:i + 4])[0]
        return raw[i + 4:i + 4 + n], i + 4 + n
    cipher, i = s(i)
    _kdf, i = s(i)
    _opts, i = s(i)
    i += 4
    blob, i = s(i)
    f["encrypted"] = cipher != b"none"
    f["key_type"] = blob[4:4 + struct.unpack(">I", blob[:4])[0]].decode("ascii", "replace")


def crypto_facts(data, lname):
    """Contenu d'un fichier (bytes) -> description. Ne retient rien du contenu d'une clé."""
    f = {"kind": "inconnu", "has_private_key": None, "encrypted": None, "certs": []}
    try:
        if data[:4] in (b"\xfe\xed\xfe\xed", b"\xce\xce\xce\xce"):
            f["kind"] = "jks" if data[:1] == b"\xfe" else "jceks"
            _java_store(data, f)
        elif b"-----BEGIN " in data[:1 << 20]:
            text = data.decode("latin-1")
            f["kind"] = "pem"
            keys = re.findall(r"-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY)-----", text)
            if "OPENSSH PRIVATE KEY" in keys:
                f["key_type"] = "openssh"
                _crypto_openssh(text, f)
            elif keys:
                f["has_private_key"] = True
                f["key_type"] = keys[0].replace(" PRIVATE KEY", "").replace("PRIVATE KEY", "").strip() or "PKCS8"
                f["encrypted"] = "ENCRYPTED" in keys[0] or "Proc-Type: 4,ENCRYPTED" in text
            else:
                f["has_private_key"] = False
            f["certs"] = certs_from_pem(text)
        elif data[:21] == b"PuTTY-User-Key-File-2" or data[:21] == b"PuTTY-User-Key-File-3":
            m = re.search(br"Encryption: (\S+)", data)
            f.update({"kind": "ppk", "has_private_key": True, "encrypted": bool(m and m.group(1) != b"none")})
        elif lname.endswith((".p12", ".pfx")):
            f["kind"] = "pkcs12"
        elif lname.endswith(".kdb"):
            f["kind"] = "gskit-kdb"
        elif lname.endswith(".sth"):
            f.update({"kind": "gskit-stash", "note": "mot de passe de base de clés, récupérable par quiconque lit ce fichier"})
        elif lname == "cwallet.sso" or lname.endswith(".sso"):
            f.update({"kind": "oracle-wallet", "has_private_key": None, "note": "portefeuille à ouverture automatique, sans mot de passe"})
        elif data[:1] == b"\x30":
            c = x509_facts(data)
            if c:
                f.update({"kind": "der", "has_private_key": False, "certs": [c]})
            else:
                f["kind"] = "der-inconnu"
    except (struct.error, IndexError, ValueError, TypeError, UnicodeError) as e:
        f["note"] = "format non décodé : %s" % type(e).__name__
    f["cert_count"] = len(f["certs"])
    f["certs"] = f["certs"][:CRYPTO_MAX_CERTS]
    return f


def is_crypto_file(path, lname):
    if not (lname.endswith(CRYPTO_EXT) or lname in CRYPTO_NAMES or re.match(r"^ssh_host_\w+_key$", lname)):
        return False
    return not CRYPTO_TRUST_RX.search(path)


# --------------------------------------------------------------------------
# Points d'entrée : virtualhosts, connecteurs, proxys (Apache, IHS, nginx, Tomcat,
# JBoss/WildFly, HAProxy). Seules les directives utiles sont retenues.
# Partagé avec cmdb_shell_parse.py.
# --------------------------------------------------------------------------
WEB_FILES = set(["httpd.conf", "apache2.conf", "ports.conf", "ssl.conf", "httpd-vhosts.conf", "httpd-ssl.conf", "vhosts.conf",
                 "nginx.conf", "haproxy.cfg", "server.xml", "standalone.xml", "standalone-ha.xml", "standalone-full.xml",
                 "standalone-full-ha.xml", "domain.xml"])


def is_web_config(path, lname):
    if re.search(r"/usr/share/|/samples?/|/docs?/|/examples?/|/tests?/|/site-packages/|/node_modules/", path):
        return False
    if lname in WEB_FILES or "/sites-enabled/" in path:
        return True
    if lname.endswith(".conf"):
        return bool(re.search(r"/vhosts\.d/|/(httpd|apache2?|nginx|HTTPServer)/conf\.d/|/nginx/conf\.d/", path))
    return False


def _web_url(url):
    """Retire d'une URL de proxy tout identifiant éventuel."""
    m = re.match(r"^([a-z][a-z0-9+]*://)(?:[^/@]*@)?(.*)$", url, re.I)
    return m.group(1) + m.group(2) if m else url


def _listen_addr(text):
    """*:443, 10.0.0.1:80, [::]:80, 8080 -> (adresse, port)"""
    text = text.strip()
    m = re.match(r"^\[([^\]]*)\]:(\d+)$", text) or re.match(r"^([^:]*):(\d+)$", text)
    if m:
        return m.group(1) or None, int(m.group(2))
    return (None, int(text)) if text.isdigit() else (text or None, None)


def _ep_apache(text, product):
    out, cur = [], None

    def ep(**kw):
        d = {"product": product}
        d.update(kw)
        out.append(d)
    for line in text.splitlines():
        s = line.strip()
        if not s or s[0] == "#":
            continue
        low = s.lower()
        m = re.match(r"^<virtualhost\s+([^>]+)>", low)
        if m:
            cur = {"addrs": s[s.index(" "):].strip(" >\t").split(), "aliases": [], "name": None, "root": None, "tls": False,
                   "cert": None, "proxies": []}
            continue
        if low.startswith("</virtualhost"):
            if cur:
                for a in cur["addrs"]:
                    addr, port = _listen_addr(a)
                    ep(kind="vhost", address=addr, port=port, server_name=cur["name"], aliases=cur["aliases"], root=cur["root"],
                       tls=cur["tls"] or port == 443, cert=cur["cert"])
                for loc, url in cur["proxies"]:
                    ep(kind="proxy", server_name=cur["name"], location=loc, backend=url)
            cur = None
            continue
        p = s.split()
        k = p[0].lower()
        if k == "listen" and len(p) > 1 and cur is None:
            addr, port = _listen_addr(p[1])
            ep(kind="listen", address=addr, port=port, tls=len(p) > 2 and p[2].lower() == "https")
        elif k in ("proxypass", "proxypassmatch") and len(p) > 2 and p[2] != "!":
            if cur is not None:
                cur["proxies"].append((p[1], _web_url(p[2])))
            else:
                ep(kind="proxy", location=p[1], backend=_web_url(p[2]))
        elif cur is not None and len(p) > 1:
            if k == "servername":
                cur["name"] = re.sub(r"^https?://|:\d+$", "", p[1])
            elif k == "serveralias":
                cur["aliases"].extend(p[1:])
            elif k == "documentroot":
                cur["root"] = p[1].strip('"')
            elif k == "sslengine":
                cur["tls"] = p[1].lower() == "on"
            elif k == "sslcertificatefile":
                cur["cert"] = p[1].strip('"')
    return out


def _ep_nginx(text):
    out, cur, ups = [], None, {}

    def flush(c):
        if not c:
            return
        for addr, port, tls in c["listen"] or [(None, None, False)]:
            out.append({"product": "nginx", "kind": "vhost", "address": addr, "port": port, "server_name": (c["names"] or [None])[0],
                        "aliases": c["names"][1:], "root": c["root"], "tls": tls or bool(c["cert"]), "cert": c["cert"]})
        for loc, url in c["proxies"]:
            out.append({"product": "nginx", "kind": "proxy", "server_name": (c["names"] or [None])[0], "location": loc, "backend": url})
    upstream, loc = None, None
    for line in text.splitlines():
        s = line.split("#")[0].strip()
        if not s:
            continue
        m = re.match(r"^upstream\s+(\S+)\s*\{", s)
        if m:
            flush(cur)
            cur, upstream = None, m.group(1)
            ups[upstream] = []
            continue
        if re.match(r"^server\s*\{", s):
            flush(cur)
            upstream = None
            cur = {"listen": [], "names": [], "root": None, "cert": None, "proxies": []}
            continue
        v = s.rstrip(";").split()
        if upstream and v[0] == "server" and len(v) > 1:
            ups[upstream].append(v[1])
        if cur is None or len(v) < 2:
            continue
        if v[0] == "listen":
            addr, port = _listen_addr(v[1])
            cur["listen"].append((addr, port, "ssl" in v[2:]))
        elif v[0] == "server_name":
            cur["names"].extend(x for x in v[1:] if x != "_")
        elif v[0] == "root":
            cur["root"] = v[1]
        elif v[0] == "ssl_certificate":
            cur["cert"] = v[1]
        elif v[0] == "location":
            loc = v[-2] if v[-1] == "{" and len(v) > 2 else v[-1]
        elif v[0] == "proxy_pass":
            cur["proxies"].append((loc, _web_url(v[1])))
    flush(cur)
    for e in out:
        m = re.match(r"^https?://([^/:]+)", e.get("backend") or "")
        if m and m.group(1) in ups:
            e["backend"] = "%s (%s)" % (e["backend"], ", ".join(ups[m.group(1)]))
    return out


def _tomcat_path(store, path):
    """Un magasin relatif se résout depuis CATALINA_BASE, parent de conf/server.xml."""
    base = os.path.dirname(os.path.dirname(path))
    store = re.sub(r"^\$\{catalina\.(?:base|home)\}/?", "", store)
    return store if store.startswith("/") else os.path.join(base, store)


def _ep_tomcat(text, path):
    out = []
    text = re.compile(r"<!--.*?-->", re.S).sub("", text)
    for m in re.finditer(r"<(Connector|Certificate)\b([^>]*)>", text):
        a = xml_attrs(m.group(2))
        store = a.get("keystoreFile") or a.get("certificateKeystoreFile") or a.get("certificateFile")
        if m.group(1) == "Certificate":
            if out and store:
                out[-1]["cert"] = _tomcat_path(store, path)
            continue
        port = a.get("port")
        out.append({"product": "tomcat", "kind": "connector", "port": int(port) if (port or "").isdigit() else None, "address": a.get("address"),
                    "protocol": a.get("protocol"), "tls": a.get("SSLEnabled") == "true" or a.get("scheme") == "https",
                    "cert": _tomcat_path(store, path) if store else None})
    host = None
    for m in re.finditer(r"<(Host|Context|Alias)\b([^>]*)>(?:([^<]*)</Alias>)?", text):
        a = xml_attrs(m.group(2))
        if m.group(1) == "Host":
            host = a.get("name")
            out.append({"product": "tomcat", "kind": "vhost", "server_name": host, "root": a.get("appBase"), "aliases": []})
        elif m.group(1) == "Alias" and out and m.group(3):
            for e in reversed(out):
                if e["kind"] == "vhost":
                    e["aliases"].append(m.group(3).strip())
                    break
        elif m.group(1) == "Context":
            out.append({"product": "tomcat", "kind": "context", "server_name": host, "location": a.get("path"), "root": a.get("docBase")})
    return out


def _ep_jboss(text):
    out = []
    for m in re.finditer(r"<socket-binding\b([^>]*)>", text):
        a = dict(re.findall(r'([\w-]+)="([^"]*)"', m.group(1)))
        name = a.get("name") or ""
        pm = re.search(r"(\d+)\}?$", a.get("port") or "")
        if pm and re.match(r"^(http|https|ajp|management)", name):
            out.append({"product": "jboss", "kind": "connector", "port": int(pm.group(1)), "protocol": name, "tls": "https" in name})
    return out


def _ep_haproxy(text):
    out, sect, name = [], None, None
    for line in text.splitlines():
        s = line.split("#")[0].strip()
        p = s.split()
        if not p:
            continue
        if p[0] in ("frontend", "backend", "listen", "defaults", "global"):
            sect, name = p[0], (p[1] if len(p) > 1 else None)
        elif p[0] == "bind" and len(p) > 1 and sect in ("frontend", "listen"):
            for one in p[1].split(","):
                addr, port = _listen_addr(one)
                out.append({"product": "haproxy", "kind": "frontend", "server_name": name, "address": addr, "port": port,
                            "tls": "ssl" in p[2:], "cert": p[p.index("crt") + 1] if "crt" in p[:-1] else None})
        elif p[0] == "server" and len(p) > 2 and sect in ("backend", "listen"):
            out.append({"product": "haproxy", "kind": "proxy", "server_name": name, "location": p[1], "backend": p[2]})
    return out


def parse_endpoints(text, path):
    if not text:
        return []
    name = path.rsplit("/", 1)[-1].lower()
    if name == "haproxy.cfg":
        return _ep_haproxy(text)
    if name == "server.xml":
        return _ep_tomcat(text, path)
    if name.startswith("standalone") or name == "domain.xml":
        return _ep_jboss(text)
    if "nginx" in path:
        return _ep_nginx(text)
    return _ep_apache(text, "ihs" if "/HTTPServer/" in path else "apache")


def phpinfo_filter(text):
    """Sortie de php -i : l'environnement et les valeurs ressemblant à un secret sont retirés.
    Même règle que la fonction php_filter du collecteur shell."""
    out, skip = [], False
    for line in (text or "").splitlines():
        if line in ("Environment", "PHP Variables"):
            skip = True
            continue
        if skip:
            if re.match(r"^[A-Z][A-Za-z ]*$", line) and "=>" not in line:
                skip = False
            else:
                continue
        if line.startswith("$_"):
            continue
        if re.search(r"pass|secret|token|_key\b", line.split("=>")[0], re.I) and "=>" in line:
            line = line.split("=>")[0] + "=> ***"
        out.append(re.sub(r"(://)[^/@\s]*@", r"\1***@", line))
    return "\n".join(out)


class Collector(object):

    def __init__(self, args):
        self.args = args
        self.errors = []
        self.timings = {}
        self.owner_index = {}
        self.owner_index_kind = None
        self.probe_candidates = {}   # realpath -> {"probe":..., "paths": set()}
        self.go_candidates = set()
        self.jvm_homes = {}          # répertoire JVM (lu via libjvm.so chargée) -> infos
        self.fp_targets = {}         # (st_dev, st_ino) -> binaire/bibliothèque à empreinter
        self.proc_archives = {}      # archive Java ouverte par un processus -> infos
        self.inode_pid = {}
        self.proc_names = {}
        self.exec_count = 0
        self.exec_deadline = None

    # -- infrastructure --------------------------------------------------
    def section(self, name, fn):
        t0 = time.time()
        try:
            res = fn()
        except Exception as e:  # une section en échec n'arrête jamais la collecte
            self.errors.append({"section": name, "error": u(repr(e)),
                                "trace": u(traceback.format_exc())[-4000:]})
            res = {"_error": u(repr(e))}
        self.timings[name] = round(time.time() - t0, 2)
        return res

    def owner(self, path):
        if not self.owner_index or not path:
            return None
        cands = [path]
        try:
            rp = os.path.realpath(path)
            if rp != path:
                cands.append(rp)
        except (OSError, ValueError):
            pass
        for c in list(cands):
            if c.startswith("/usr/"):
                cands.append(c[4:])
            else:
                cands.append("/usr" + c)
        for c in cands:
            o = self.owner_index.get(c)
            if o:
                return o
        return None

    def add_probe_candidate(self, path, origin):
        base = os.path.basename(path)
        if not PROBE_ANY_RX.match(base) or path.startswith("/etc/"):
            return
        try:
            rp = os.path.realpath(path)
            st = os.stat(rp)
        except (OSError, ValueError):
            return
        # La cible réelle doit elle aussi ressembler à un binaire connu : évite
        # d'exécuter un programme quelconque atteint via un lien symbolique homonyme.
        if not PROBE_ANY_RX.match(os.path.basename(rp)) or rp.startswith("/etc/"):
            return
        if not stat.S_ISREG(st.st_mode) or not (st.st_mode & 0o111):
            return
        for name, rx, _a, _m in PROBE_RX:
            if rx.match(base):
                c = self.probe_candidates.setdefault(rp, {"probe": name, "paths": set(), "origins": set()})
                c["paths"].add(path)
                c["origins"].add(origin)
                break

    # -- OS -------------------------------------------------------------
    def collect_os(self):
        d = {}
        for f in ("/etc/os-release", "/usr/lib/os-release"):
            t = read_text(f)
            if t:
                d["os_release"] = kv_text(t)
                break
        rel = {}
        for f in ("/etc/redhat-release", "/etc/centos-release", "/etc/rocky-release", "/etc/almalinux-release",
                  "/etc/oracle-release", "/etc/system-release", "/etc/debian_version", "/etc/lsb-release",
                  "/etc/SuSE-release", "/etc/alpine-release", "/etc/issue"):
            t = read_text(f, 4096)
            if t:
                rel[f] = t.strip()
        d["release_files"] = rel
        un = os.uname()
        d["uname"] = {"sysname": un[0], "nodename": un[1], "release": un[2], "version": un[3], "machine": un[4]}
        d["hostname"] = socket.gethostname()
        try:
            d["fqdn"] = socket.getfqdn()
        except Exception:
            d["fqdn"] = None
        d["machine_id"] = (read_text("/etc/machine-id", 256) or "").strip() or None
        d["proc_version"] = (read_text("/proc/version") or "").strip()
        d["kernel_cmdline"] = (read_text("/proc/cmdline") or "").strip()
        up = read_text("/proc/uptime")
        if up:
            d["uptime_seconds"] = float(up.split()[0])
        for line in (read_text("/proc/stat") or "").splitlines():
            if line.startswith("btime "):
                d["boot_time"] = now_iso(int(line.split()[1]))
        d["timezone"] = readlink("/etc/localtime") or (read_text("/etc/timezone") or "").strip() or None
        d["locale"] = read_text("/etc/locale.conf", 4096) or read_text("/etc/default/locale", 4096)
        try:
            d["glibc"] = os.confstr("CS_GNU_LIBC_VERSION")
        except (ValueError, OSError, AttributeError):
            d["glibc"] = None
        d["selinux_getenforce"] = (run_out(["getenforce"], 10) or "").strip() or None
        sv = run_out(["systemctl", "--version"], 10)
        d["systemd_version"] = sv.splitlines()[0] if sv else None
        d["hostnamectl"] = run_out(["hostnamectl"], 15)
        d["loadavg"] = (read_text("/proc/loadavg") or "").strip()
        d["reboot_required_file"] = os.path.exists("/var/run/reboot-required")
        d["reboot_required_pkgs"] = read_text("/var/run/reboot-required.pkgs")
        nr = run(["needs-restarting", "-r"], 60)
        if nr is not None:
            d["needs_restarting_r"] = {"rc": nr["rc"], "out": nr["out"][-4000:]}
        env_files = {}
        for f in ["/etc/environment"] + [os.path.join("/etc/profile.d", n) for n in listdir("/etc/profile.d")]:
            t = read_text(f, 64 * 1024)
            if t is not None:
                env_files[f] = redact(t)
        d["env_files"] = env_files
        d["collector_python"] = {"version": sys.version, "executable": sys.executable}
        return d

    # -- matériel ---------------------------------------------------------
    def collect_hardware(self):
        d = {}
        dmi = {}
        for n in listdir("/sys/class/dmi/id"):
            p = os.path.join("/sys/class/dmi/id", n)
            if n in ("modalias", "uevent") or not os.path.isfile(p):
                continue
            t = read_text(p, 4096)
            if t is not None:
                dmi[n] = t.strip()
        d["dmi"] = dmi
        d["dmidecode"] = run_out(["dmidecode"], 60)
        cpu = {"count": 0}
        for line in (read_text("/proc/cpuinfo", 8 << 20) or "").splitlines():
            if ":" not in line:
                continue
            k, v = [x.strip() for x in line.split(":", 1)]
            if k == "processor":
                cpu["count"] += 1
            elif k in ("model name", "vendor_id", "cpu family", "model", "stepping", "microcode", "bugs",
                       "cpu cores", "siblings", "physical id", "flags") and k not in cpu:
                cpu[k] = v
        d["cpu"] = cpu
        d["lscpu"] = run_out(["lscpu"], 15)
        mem = {}
        for line in (read_text("/proc/meminfo") or "").splitlines():
            m = re.match(r"(\S+):\s+(\d+)", line)
            if m:
                mem[m.group(1)] = int(m.group(2))
        d["meminfo_kb"] = mem
        r = run(["lsblk", "-J", "-O", "-b"], 30)
        if r and r["rc"] == 0:
            try:
                d["lsblk"] = json.loads(r["out"])
            except ValueError:
                d["lsblk_raw"] = r["out"]
        else:
            d["lsblk_raw"] = run_out(["lsblk", "-P", "-b", "-o", "NAME,KNAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,MODEL,SERIAL,VENDOR,UUID"], 30)
        mounts = []
        for m in parse_mounts():
            if m["fstype"] in PSEUDO_FS and m["fstype"] not in ("overlay",):
                continue
            entry = dict(m)
            try:
                sv = os.statvfs(m["mountpoint"])
                entry["size_bytes"] = sv.f_blocks * sv.f_frsize
                entry["avail_bytes"] = sv.f_bavail * sv.f_frsize
                entry["used_bytes"] = (sv.f_blocks - sv.f_bfree) * sv.f_frsize
                entry["free_bytes"] = sv.f_bfree * sv.f_frsize      # y compris la réserve root
                entry["inodes"] = sv.f_files
                entry["inodes_free"] = sv.f_favail
            except (OSError, IOError):
                pass
            mounts.append(entry)
        d["mounts"] = mounts
        d["virtualization"] = (run_out(["systemd-detect-virt"], 10) or "").strip() or None
        d["container_markers"] = {
            "/.dockerenv": os.path.exists("/.dockerenv"),
            "/run/.containerenv": os.path.exists("/run/.containerenv"),
        }
        d["lspci"] = run_out(["lspci", "-mm"], 30)
        r = run(["lspci", "-D", "-vmm", "-nn", "-k"], 30)
        if not r or r["rc"] != 0:
            r = run(["lspci", "-vmm", "-nn"], 30)
        d["pci"] = parse_lspci_vmm(r["out"]) if r and r["rc"] == 0 else {}
        d["lscpu_kv"] = parse_colon_kv(d.get("lscpu"))
        d["hostnamectl_kv"] = parse_colon_kv(run_out(["hostnamectl"], 15))
        disks = []
        for n in listdir("/sys/block"):
            if n.startswith(("loop", "ram", "zram", "fd")):
                continue
            b = "/sys/block/" + n

            def rd(rel):
                return (read_text(os.path.join(b, rel), 4096) or "").strip() or None
            e = {"name": n}
            try:
                e["size_bytes"] = int(rd("size") or 0) * 512
            except ValueError:
                pass
            for k, rel in (("rotational", "queue/rotational"), ("removable", "removable"), ("ro", "ro"),
                           ("model", "device/model"), ("vendor", "device/vendor"), ("rev", "device/rev"),
                           ("serial", "device/serial"), ("wwid", "device/wwid"), ("dm_name", "dm/name"),
                           ("dm_uuid", "dm/uuid")):
                v = rd(rel)
                if v:
                    e[k] = v
            if not e.get("wwid") and rd("wwid"):
                e["wwid"] = rd("wwid")
            sp = readlink(b) or os.path.realpath(b + "/device")   # vieux noyaux : /sys/block/x n'est pas un lien
            e["sys_path"] = sp
            e["pci_slot"] = pci_slot_of(sp)
            e["transport"] = "device-mapper" if n.startswith("dm-") else ("md" if n.startswith("md") else disk_transport(sp))
            e["slaves"] = listdir(b + "/slaves")
            disks.append(e)
        # lsblk (base udev, lisible sans root) complète série, WWN et transport
        for bd in ((d.get("lsblk") or {}).get("blockdevices") or []):
            for e in disks:
                if e["name"] == bd.get("name") or e["name"] == bd.get("kname"):
                    for k_src, k_dst in (("serial", "serial"), ("wwn", "wwn"), ("model", "model"), ("tran", "transport"),
                                         ("vendor", "vendor")):
                        if bd.get(k_src) and not e.get(k_dst):
                            e[k_dst] = str(bd[k_src]).strip()
        d["disks"] = disks
        fc = []
        for n in listdir("/sys/class/fc_host"):
            b = "/sys/class/fc_host/" + n
            fc.append(dict([("name", n)] + [(k, (read_text(os.path.join(b, k), 4096) or "").strip() or None)
                                            for k in ("port_name", "node_name", "port_state", "speed",
                                                      "symbolic_name", "port_type")]))
        d["fc_hosts"] = fc
        vulns = {}
        for n in listdir("/sys/devices/system/cpu/vulnerabilities"):
            vulns[n] = (read_text(os.path.join("/sys/devices/system/cpu/vulnerabilities", n)) or "").strip()
        d["cpu_vulnerabilities"] = vulns
        return d

    # -- paquets ----------------------------------------------------------
    def collect_packages(self):
        d = {"managers": {}}
        if which("rpm"):
            qf = "\t".join(["%{NAME}", "%{EPOCH}", "%{VERSION}", "%{RELEASE}", "%{ARCH}", "%{VENDOR}",
                            "%{INSTALLTIME}", "%{BUILDTIME}", "%{SOURCERPM}", "%{PACKAGER}",
                            "%{RSAHEADER:pgpsig}", "%{SIGPGP:pgpsig}", "%{SUMMARY}"]) + "\n"
            r = run(["rpm", "-qa", "--qf", qf], 300)
            rows = []
            if r and r["rc"] == 0:
                keys = ["name", "epoch", "version", "release", "arch", "vendor", "installtime", "buildtime",
                        "sourcerpm", "packager", "sig_rsa", "sig_pgp", "summary"]
                for line in r["out"].splitlines():
                    p = line.split("\t")
                    if len(p) < 5:
                        continue
                    row = dict(zip(keys, p))
                    for k in list(row):
                        if row[k] == "(none)":
                            row[k] = None
                    rows.append(row)
            else:
                d["rpm_error"] = r
            d["managers"]["rpm"] = rows
        if which("dpkg-query"):
            fmt_new = "${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\t${source:Package}\t${source:Version}\t${Maintainer}\t${Installed-Size}\t${binary:Summary}\n"
            fmt_old = "${Package}\t${Version}\t${Architecture}\t${Status}\t${Source}\t\t${Maintainer}\t${Installed-Size}\t\n"
            r = run(["dpkg-query", "-W", "-f", fmt_new], 300)
            if not r or r["rc"] != 0:
                r = run(["dpkg-query", "-W", "-f", fmt_old], 300)
            rows = []
            keys = ["name", "version", "arch", "status", "source", "source_version", "maintainer", "installed_size", "summary"]
            if r:
                for line in r["out"].splitlines():
                    p = line.split("\t")
                    if len(p) < 4:
                        continue
                    row = dict(zip(keys, p))
                    rows.append(row)
            d["managers"]["dpkg"] = rows
        apkdb = read_text("/lib/apk/db/installed", 64 << 20)
        if apkdb:
            rows = []
            cur = {}
            for line in apkdb.splitlines() + [""]:
                if not line.strip():
                    if cur.get("P"):
                        rows.append({"name": cur.get("P"), "version": cur.get("V"), "arch": cur.get("A"),
                                     "origin": cur.get("o"), "maintainer": cur.get("m"), "summary": cur.get("T")})
                    cur = {}
                    continue
                if len(line) > 2 and line[1] == ":" and line[0] in "PVAomT":
                    cur[line[0]] = line[2:]
            d["managers"]["apk"] = rows
        out = run_out(["pacman", "-Q"], 120)
        if out:
            d["managers"]["pacman"] = [dict(zip(["name", "version"], l.split(None, 1))) for l in out.splitlines() if l.strip()]
        out = run_out(["snap", "list", "--unicode=never", "--color=never"], 60)
        if out:
            rows = []
            for l in out.splitlines()[1:]:
                p = l.split()
                if len(p) >= 3:
                    rows.append({"name": p[0], "version": p[1], "rev": p[2], "publisher": p[4] if len(p) > 4 else None})
            d["managers"]["snap"] = rows
        out = run_out(["flatpak", "list", "--columns=application,version,branch,origin,installation"], 60)
        if out:
            d["managers"]["flatpak"] = [dict(zip(["name", "version", "branch", "origin", "installation"], l.split("\t")))
                                        for l in out.splitlines() if l.strip()]
        repos = {}
        for dname in ("/etc/yum.repos.d", "/etc/apt/sources.list.d", "/etc/zypp/repos.d"):
            for n in listdir(dname):
                t = read_text(os.path.join(dname, n), 256 * 1024)
                if t is not None:
                    repos[os.path.join(dname, n)] = redact(t)
        for f in ("/etc/apt/sources.list", "/etc/yum.conf", "/etc/dnf/dnf.conf"):
            t = read_text(f, 256 * 1024)
            if t is not None:
                repos[f] = redact(t)
        d["repo_files"] = repos
        if which("dnf"):
            d["dnf_modules_enabled"] = run_out(["dnf", "-q", "-C", "module", "list", "--enabled"], 90)
        d["alternatives"] = run_out(["update-alternatives", "--get-selections"], 30) or \
            run_out(["alternatives", "--list"], 30)
        self.build_owner_index()
        d["owner_index"] = {"kind": self.owner_index_kind, "entries": len(self.owner_index)}
        return d

    def build_owner_index(self):
        """Index chemin -> paquet propriétaire (filtré sur les chemins utiles)."""
        if not self.args.file_owners:
            return
        idx = {}
        if which("rpm"):
            r = run(["rpm", "-qa", "--qf", "[%{FILENAMES}\t%{NAME}\n]"], 600, max_out=1 << 30)
            if r and r["rc"] == 0:
                for line in r["out"].splitlines():
                    if OWN_INDEX_RX.search(line):
                        p = line.rsplit("\t", 1)
                        if len(p) == 2:
                            idx[p[0]] = p[1]
                self.owner_index_kind = "rpm"
        if os.path.isdir("/var/lib/dpkg/info"):
            for n in listdir("/var/lib/dpkg/info"):
                if not n.endswith(".list"):
                    continue
                pkg = n[:-5].split(":", 1)[0]
                t = read_text(os.path.join("/var/lib/dpkg/info", n), 64 << 20) or ""
                for line in t.splitlines():
                    if OWN_INDEX_RX.search(line):
                        idx.setdefault(line, pkg)
            self.owner_index_kind = (self.owner_index_kind + "+dpkg") if self.owner_index_kind else "dpkg"
        apkdb = read_text("/lib/apk/db/installed", 64 << 20)
        if apkdb:
            pkg = None
            cur_dir = ""
            for line in apkdb.splitlines():
                if line.startswith("P:"):
                    pkg = line[2:]
                elif line.startswith("F:"):
                    cur_dir = "/" + line[2:]
                elif line.startswith("R:") and pkg:
                    pth = cur_dir.rstrip("/") + "/" + line[2:]
                    if OWN_INDEX_RX.search(pth):
                        idx.setdefault(pth, pkg)
            self.owner_index_kind = "apk"
        self.owner_index = idx

    # -- processus --------------------------------------------------------
    def collect_processes(self):
        procs = []
        try:
            clk = os.sysconf("SC_CLK_TCK")
            page = os.sysconf("SC_PAGE_SIZE")
        except (ValueError, OSError):
            clk, page = 100, 4096
        btime = 0
        for line in (read_text("/proc/stat") or "").splitlines():
            if line.startswith("btime "):
                btime = int(line.split()[1])
        host_mnt_ns = readlink("/proc/1/ns/mnt")
        my_pid = os.getpid()
        kthreads = 0
        for pid in listdir("/proc"):
            if not pid.isdigit():
                continue
            base = "/proc/" + pid
            st = read_text(base + "/stat", 8192)
            if not st:
                continue
            rpar = st.rfind(")")
            comm = st[st.find("(") + 1:rpar]
            fields = st[rpar + 2:].split()
            try:
                ppid = int(fields[1])
                start = btime + int(fields[19]) / float(clk)
            except (IndexError, ValueError):
                ppid, start = None, None
            if int(pid) == 2 or ppid == 2:
                kthreads += 1
                continue
            if int(pid) == my_pid:
                continue
            uid = None
            for line in (read_text(base + "/status", 16384) or "").splitlines():
                if line.startswith("Uid:"):
                    uid = int(line.split()[1])
                    break
            raw_cmd = read_bytes(base + "/cmdline", 128 * 1024) or b""
            argv = [u(a) for a in raw_cmd.split(b"\0") if a]
            exe = readlink(base + "/exe")
            p = {
                "pid": int(pid), "ppid": ppid, "comm": u(comm), "uid": uid, "user": uid_name(uid),
                "start": now_iso(start) if start else None,
                "exe": u(exe), "cmdline": redact(" ".join(argv))[:8192],
                "cwd": u(readlink(base + "/cwd")),
            }
            statm = read_text(base + "/statm", 256)
            if statm:
                try:
                    p["rss_bytes"] = int(statm.split()[1]) * page
                except (IndexError, ValueError):
                    pass
            mnt_ns = readlink(base + "/ns/mnt")
            p["in_container_ns"] = bool(host_mnt_ns and mnt_ns and mnt_ns != host_mnt_ns)
            cg = read_text(base + "/cgroup", 16384) or ""
            m = re.search(r"(?:docker|libpod|crio|cri-containerd|containerd)[-/]([0-9a-f]{64})|/([0-9a-f]{64})(?:\.scope)?\s*$", cg, re.M)
            if m:
                p["container_id"] = m.group(1) or m.group(2)
            m = re.search(r"pod([0-9a-f]{8}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{4}[-_][0-9a-f]{12})", cg)
            if m:
                p["k8s_pod_uid"] = m.group(1).replace("_", "-")
            sysd = re.search(r"/system\.slice/([^/\s]+\.service)", cg)
            if sysd:
                p["systemd_unit"] = sysd.group(1)
            envb = read_bytes(base + "/environ", 256 * 1024)
            if envb:
                env = {}
                for kv in envb.split(b"\0"):
                    if b"=" in kv:
                        k, v = kv.split(b"=", 1)
                        k = u(k)
                        if k in ENV_WHITELIST:
                            env[k] = redact(u(v))[:2048]
                if env:
                    p["env"] = env
            libs = set()
            deleted = set()
            for line in (read_text(base + "/maps", 16 << 20) or "").splitlines():
                parts = line.split(None, 5)
                if len(parts) < 6:
                    continue
                path = parts[5]
                if path.endswith(" (deleted)"):
                    if not path.startswith(("/dev/", "/memfd:", "/SYSV", "[")):
                        deleted.add(path[:-10])
                    continue
                if ".so" in os.path.basename(path) or path.endswith((".jar", ".node")):
                    libs.add(path)
            if libs:
                p["mapped_libs"] = sorted(libs)
            if deleted:
                p["deleted_mapped_files"] = sorted(deleted)
            jars = set()
            nfd = 0
            for fd in listdir(base + "/fd"):
                nfd += 1
                tgt = readlink(base + "/fd/" + fd)
                if not tgt:
                    continue
                if tgt.startswith("socket:["):
                    self.inode_pid[tgt[8:-1]] = int(pid)
                elif tgt.lower().endswith(ARCHIVE_EXT):
                    jars.add(tgt)
            p["open_fds"] = nfd
            if jars:
                p["open_archives"] = sorted(jars)
            procs.append(p)
            self._note_process_artifacts(int(pid), base, p, exe, libs, jars, argv)
            self.proc_names[int(pid)] = (p["comm"], p["user"])
            if exe and not p["in_container_ns"] and not exe.endswith(" (deleted)"):
                p["exe_owner_pkg"] = self.owner(exe)
                self.add_probe_candidate(exe, "process")
                self.go_candidates.add(exe)
            elif exe and exe.endswith(" (deleted)"):
                p["exe_deleted"] = True
        return {"kernel_threads": kthreads, "count": len(procs), "list": procs}

    def _note_process_artifacts(self, pid, base, p, exe, libs, jars, argv=None):
        """Mémorise ce que les processus révèlent d'installations hors des sentiers
        battus : JVM (via libjvm.so), archives Java ouvertes, binaires à empreinter.
        Pour un processus d'un autre espace de noms (conteneur), les fichiers sont
        lus via /proc/PID/root ; un exécutable supprimé reste lisible via /proc/PID/exe."""
        inc = p["in_container_ns"]
        root = base + "/root" if inc else ""
        ctx = {"pid": pid, "container_id": p.get("container_id"), "in_container": inc}

        def target(read_path, display, reason):
            try:
                st = os.stat(read_path)
            except (OSError, ValueError):
                return
            if not stat.S_ISREG(st.st_mode):
                return
            t = self.fp_targets.setdefault((st.st_dev, st.st_ino), {
                "path": display, "read": read_path, "reason": reason, "pids": [],
                "container_id": p.get("container_id")})
            if len(t["pids"]) < 20:
                t["pids"].append(pid)
        if exe:
            target(base + "/exe", exe, "process_exe_deleted" if exe.endswith(" (deleted)") else
                   ("process_exe_container" if inc else "process_exe"))
        for lib in libs:
            b = os.path.basename(lib)
            if b == "libjvm.so":
                home = JVM_HOME_RX.sub("", lib)
                if home != lib:
                    h = self.jvm_homes.setdefault((root, home), dict(ctx, home=home, pids=[]))
                    h["pids"].append(pid)
            elif FINGERPRINT_LIB_RX.match(b) and not (lib.startswith(SYSTEM_LIB_PREFIXES) and not inc):
                target(root + lib, lib, "mapped_lib")
        for j in jars:
            a = self.proc_archives.setdefault((root, j), dict(ctx, path=j, pids=[]))
            a["pids"].append(pid)
        # Ligne de commande : seule information lisible sur les processus des AUTRES
        # comptes quand on n'est pas root (exe, maps, fd et environ sont alors refusés).
        if argv and (not inc or os.geteuid() == 0):
            self._note_cmdline(pid, root, ctx, argv, target)

    def _note_cmdline(self, pid, root, ctx, argv, target):
        paths = []
        for a in argv:
            for m in CMDLINE_PATH_RX.finditer(a):
                if m.group(1) not in paths:
                    paths.append(m.group(1))
        if not paths:
            return

        def archive(path, why):
            if (root, path) in self.proc_archives or len(self.proc_archives) > 20000:
                if (root, path) in self.proc_archives:
                    self.proc_archives[(root, path)]["pids"].append(pid)
                return
            if is_regular(root + path):
                self.proc_archives[(root, path)] = dict(ctx, path=path, pids=[pid], via=why)
        # binaire lancé : premier chemin absolu (nginx réécrit argv : "nginx: master process /chemin/nginx")
        first = paths[0]
        if is_regular(root + first):
            target(root + first, first, "process_cmdline")
            if not ctx["in_container"]:
                self.add_probe_candidate(first, "process_cmdline")
            d = os.path.dirname(first)
            if os.path.basename(d) == "bin":   # .../bin/java, .../bin/monappli -> JVM éventuelle
                home = os.path.dirname(d)
                self.jvm_homes.setdefault((root, home), dict(ctx, home=home, pids=[], via="cmdline"))["pids"].append(pid)
        for path in paths:
            low = path.lower()
            if low.endswith(ARCHIVE_EXT):
                archive(path, "cmdline")
            elif path.endswith("/*"):          # classpath "lib/*"
                for n in listdir(root + path[:-2])[:2000]:
                    if n.lower().endswith(ARCHIVE_EXT):
                        archive(path[:-1] + n, "cmdline-wildcard")
        for m in CMDLINE_HOME_PROPS.finditer(" ".join(argv)):
            prop, d = m.group(1), m.group(2)
            if prop == "java.home":
                self.jvm_homes.setdefault((root, d), dict(ctx, home=d, pids=[], via="cmdline"))["pids"].append(pid)
            elif prop.startswith("catalina"):
                for j in ("lib/catalina.jar", "bin/bootstrap.jar"):
                    archive(d + "/" + j, "cmdline:-D" + prop)
            elif prop == "jboss.home.dir":
                archive(d + "/jboss-modules.jar", "cmdline:-D" + prop)

    def process_artifacts(self, doc):
        """Exploite les indices laissés par les processus en mémoire."""
        res = {"jvm_homes": [], "archives": [], "fingerprints": []}
        fs = doc.get("filesystem") or {}
        known_jdk = set(j.get("path") for j in fs.get("jdk_homes") or [])
        known_arch = set(x.get("path") for x in fs.get("java_archives") or [])
        t0 = time.time()
        # JVM dont la bibliothèque est chargée : fichier "release", sinon rt.jar (Java <= 8)
        for (root, home), h in sorted(self.jvm_homes.items()):
            entry = {"path": home, "pids": sorted(set(h["pids"]))[:20], "container_id": h.get("container_id"),
                     "in_container": h["in_container"], "already_in_filesystem_scan": home in known_jdk}
            rel = read_text(root + home + "/release", 64 * 1024)
            if rel is None and home.endswith("/jre"):
                rel = read_text(root + home[:-4] + "/release", 64 * 1024)
            if rel:
                entry["release"] = kv_text(rel)
            has_rt = is_regular(root + home + "/lib/rt.jar") or is_regular(root + home + "/jre/lib/rt.jar")
            if h.get("via") == "cmdline" and not has_rt and "JAVA_VERSION" not in (entry.get("release") or {}):
                continue   # simple répertoire .../bin d'un autre logiciel
            entry["via"] = h.get("via") or "libjvm.so"
            for rt in (home + "/lib/rt.jar", home + "/jre/lib/rt.jar"):
                if is_regular(root + rt) and (root, rt) not in self.proc_archives:
                    self.proc_archives[(root, rt)] = {"path": rt, "pids": entry["pids"], "container_id": h.get("container_id"),
                                                      "in_container": h["in_container"]}
            if not h["in_container"]:
                o = self.owner(home + "/release")
                if o:
                    entry["owner_pkg"] = o
            res["jvm_homes"].append(entry)
        # Archives ouvertes par des processus et non vues par le parcours disque
        # (montage réseau, répertoire exclu, budget dépassé, conteneur)
        archive_opts = {"max_depth": 3, "nested_max": 100 << 20}
        for (root, path), a in sorted(self.proc_archives.items()):
            if not root and path in known_arch:
                continue
            if time.time() - t0 > 600 or len(res["archives"]) >= 5000:
                res["truncated"] = True
                break
            rp = root + path
            if not is_regular(rp):
                continue
            try:
                st = os.stat(rp)
                fo = open(rp, "rb")
                try:
                    info = inspect_archive(fo, path, 0, archive_opts)
                finally:
                    fo.close()
            except (IOError, OSError) as e:
                info = {"path": path, "error": u(repr(e))[:200]}
            info["size"] = st.st_size
            info["mtime"] = now_iso(st.st_mtime)
            if self.args.hash_archives:
                info["sha1"] = sha1_file(rp, self.args.hash_max_mb << 20)
            info["origin"] = "process"
            if a.get("via"):
                info["via"] = a["via"]
            info["pids"] = sorted(set(a["pids"]))[:20]
            if a.get("container_id"):
                info["container_id"] = a["container_id"]
            if not root:
                o = self.owner(path)
                if o:
                    info["owner_pkg"] = o
            res["archives"].append(info)
        # Empreintes statiques des exécutables et bibliothèques chargés
        for _key, t in sorted(self.fp_targets.items(), key=lambda kv: kv[1]["path"]):
            if time.time() - t0 > 900:
                res["fingerprints_truncated"] = True
                break
            found = fingerprint(t["read"])
            if not found:
                continue
            e = {"path": t["path"], "reason": t["reason"], "pids": t["pids"], "found": found}
            if t.get("container_id"):
                e["container_id"] = t["container_id"]
            if t["reason"] in ("process_exe", "mapped_lib") and not t.get("container_id"):
                o = self.owner(t["path"])
                if o:
                    e["owner_pkg"] = o
            res["fingerprints"].append(e)
        return res

    # -- réseau -----------------------------------------------------------
    @staticmethod
    def _hex_ip(h):
        try:
            if len(h) == 8:
                return socket.inet_ntoa(struct.pack("<I", int(h, 16)))
            b = b"".join(struct.pack("<I", int(h[i:i + 8], 16)) for i in range(0, 32, 8))
            return socket.inet_ntop(socket.AF_INET6, b)
        except (ValueError, struct.error, socket.error):
            return h

    def collect_network(self):
        d = {}
        d["ip_link_details_raw"] = run_out(["ip", "-o", "-d", "link", "show"], 15)
        details = parse_ip_link_details(d["ip_link_details_raw"])
        bond_raw = {}
        perm = {}
        for n in listdir("/proc/net/bonding"):
            t = read_text("/proc/net/bonding/" + n, 256 * 1024)
            if t:
                bond_raw[n] = t
                perm.update(parse_bonding_perm(t))
        d["bonding"] = bond_raw
        ifaces = []
        for n in listdir("/sys/class/net"):
            b = os.path.join("/sys/class/net", n)

            def rd(rel):
                return (read_text(os.path.join(b, rel), 4096) or "").strip() or None
            i = {"name": n}
            for k in ("address", "mtu", "operstate", "carrier", "speed", "duplex", "type", "ifindex", "iflink",
                      "addr_assign_type"):
                i[k] = rd(k)
            dev = readlink(os.path.join(b, "device"))
            i["virtual"] = dev is None
            if dev:
                i["bus_info"] = os.path.basename(dev)
                i["pci_slot"] = pci_slot_of(os.path.realpath(os.path.join(b, "device")))
                i["pci_ids"] = ":".join(x for x in (rd("device/vendor"), rd("device/device")) if x) or None
                i["pci_subsys_ids"] = ":".join(x for x in (rd("device/subsystem_vendor"), rd("device/subsystem_device")) if x) or None
            drv = readlink(os.path.join(b, "device", "driver"))
            i["driver"] = os.path.basename(drv) if drv else None
            master = readlink(os.path.join(b, "master"))
            if master:
                i["master"] = os.path.basename(master)
            devtype = None
            for line in (rd("uevent") or "").splitlines():
                if line.startswith("DEVTYPE="):
                    devtype = line[8:]
            det = details.get(n, {})
            is_bond = os.path.isdir(os.path.join(b, "bonding"))
            is_bridge = os.path.isdir(os.path.join(b, "bridge"))
            if is_bond:
                i["bond_mode"] = rd("bonding/mode")
                i["bond_slaves"] = (rd("bonding/slaves") or "").split()
            if is_bridge:
                i["bridge_ports"] = listdir(os.path.join(b, "brif"))
            i["kind"] = nic_kind(n, dev is not None, is_bond, is_bridge, devtype, det.get("kind"))
            if det.get("vlan_id") is not None:
                i["vlan_id"] = det["vlan_id"]
            if det.get("parent"):
                i["parent"] = det["parent"]
            if n in perm:
                i["permanent_address"] = perm[n]
            if dev and which("ethtool"):
                ei = parse_colon_kv(run_out(["ethtool", "-i", n], 10))
                if ei:
                    i["ethtool"] = dict((k, ei.get(k)) for k in ("driver", "version", "firmware-version", "bus-info")
                                        if ei.get(k))
                if "permanent_address" not in i:
                    pm = re.search(r"Permanent address:\s*(\S+)", run_out(["ethtool", "-P", n], 10) or "")
                    if pm and pm.group(1) != "00:00:00:00:00:00":
                        i["permanent_address"] = pm.group(1)
            ifaces.append(i)
        d["interfaces"] = ifaces
        r = run(["ip", "-j", "addr", "show"], 15)
        if r and r["rc"] == 0:
            try:
                d["ip_addr"] = json.loads(r["out"])
            except ValueError:
                pass
        addrs = parse_ip_o_addr(run_out(["ip", "-o", "addr", "show"], 15))
        d["addresses"] = addrs
        d["routes_v4"] = run_out(["ip", "route", "show", "table", "all"], 15)
        d["routes_v6"] = run_out(["ip", "-6", "route", "show"], 15)
        d["resolv_conf"] = read_text("/etc/resolv.conf", 64 * 1024)
        d["hosts_file"] = read_text("/etc/hosts", 256 * 1024)
        d["nsswitch"] = read_text("/etc/nsswitch.conf", 64 * 1024)
        listening = []
        conns = {}
        listen_ports = set()
        raw = []
        for proto in ("tcp", "tcp6", "udp", "udp6"):
            text = read_text("/proc/net/" + proto, 64 << 20) or ""
            for line in text.splitlines()[1:]:
                p = line.split()
                if len(p) < 10:
                    continue
                raw.append((proto, p))
        for proto, p in raw:
            lip, lport = p[1].split(":")
            st = p[3]
            if (proto.startswith("tcp") and st == "0A") or (proto.startswith("udp") and st == "07" and p[2].endswith(":0000")):
                listen_ports.add(int(lport, 16))
        for proto, p in raw:
            lip, lport = p[1].split(":")
            rip, rport = p[2].split(":")
            st = p[3]
            inode = p[9]
            pid = self.inode_pid.get(inode)
            comm, user = self.proc_names.get(pid, (None, None))
            if (proto.startswith("tcp") and st == "0A") or (proto.startswith("udp") and st == "07" and rport == "0000"):
                listening.append({"proto": proto, "address": self._hex_ip(lip), "port": int(lport, 16),
                                  "pid": pid, "process": comm, "user": user or uid_name(int(p[7])), "uid": int(p[7])})
            elif proto.startswith("tcp") and st == "01":
                lp = int(lport, 16)
                if lp in listen_ports:
                    key = ("in", lp, self._hex_ip(rip), None, comm)
                else:
                    key = ("out", None, self._hex_ip(rip), int(rport, 16), comm)
                conns[key] = conns.get(key, 0) + 1
        d["listening"] = listening
        d["established"] = [{"direction": k[0], "local_port": k[1], "remote_addr": k[2], "remote_port": k[3],
                             "process": k[4], "count": v} for k, v in sorted(conns.items(), key=lambda kv: -kv[1])][:5000]
        return d

    # -- services ---------------------------------------------------------
    def collect_services(self):
        d = {}
        if which("systemctl"):
            units = []
            for line in (run_out(["systemctl", "list-units", "--all", "--no-legend", "--no-pager", "--plain", "--full"], 60) or "").splitlines():
                p = line.split(None, 4)
                if len(p) >= 4:
                    units.append({"unit": p[0], "load": p[1], "active": p[2], "sub": p[3], "description": p[4] if len(p) > 4 else ""})
            d["units"] = units
            files = []
            for line in (run_out(["systemctl", "list-unit-files", "--no-legend", "--no-pager", "--full"], 60) or "").splitlines():
                p = line.split()
                if len(p) >= 2:
                    files.append({"unit": p[0], "state": p[1], "preset": p[2] if len(p) > 2 else None})
            d["unit_files"] = files
            services = sorted(set([x["unit"] for x in units if x["unit"].endswith(".service")] +
                                  [x["unit"] for x in files if x["unit"].endswith(".service") and "@" not in x["unit"]]))
            shows = []
            props = "Id,MainPID,ExecStart,FragmentPath,User,Group,ActiveState,SubState,UnitFileState,Description,Environment,EnvironmentFiles,WorkingDirectory"
            for i in range(0, len(services), 100):
                out = run_out(["systemctl", "show", "--no-pager", "-p", props] + services[i:i + 100], 60) or ""
                for block in out.split("\n\n"):
                    kv = {}
                    for line in block.splitlines():
                        if "=" in line:
                            k, v = line.split("=", 1)
                            kv[k] = redact(v)[:4096]
                    if kv.get("Id"):
                        shows.append(kv)
            d["service_details"] = shows
            d["timers"] = run_out(["systemctl", "list-timers", "--all", "--no-legend", "--no-pager"], 30)
            d["failed"] = run_out(["systemctl", "--failed", "--no-legend", "--no-pager", "--plain"], 30)
        d["chkconfig"] = run_out(["chkconfig", "--list"], 30)
        d["initd_scripts"] = listdir("/etc/init.d")
        return d

    def collect_scheduled(self):
        d = {}
        files = {}
        for f in ["/etc/crontab", "/etc/anacrontab"]:
            t = read_text(f, 256 * 1024)
            if t is not None:
                files[f] = redact(t)
        for dn in ("/etc/cron.d", "/var/spool/cron", "/var/spool/cron/crontabs"):
            for n in listdir(dn):
                p = os.path.join(dn, n)
                if os.path.isfile(p):
                    t = read_text(p, 256 * 1024)
                    if t is not None:
                        files[p] = redact(t)
        d["cron_files"] = files
        d["cron_dirs"] = dict((dn, listdir(dn)) for dn in ("/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"))
        d["atq"] = run_out(["atq"], 10)
        return d

    # -- comptes ----------------------------------------------------------
    def collect_accounts(self):
        d = {}
        users = []
        for line in (read_text("/etc/passwd", 8 << 20) or "").splitlines():
            p = line.split(":")
            if len(p) >= 7:
                users.append({"name": p[0], "uid": int(p[2]) if p[2].isdigit() else p[2], "gid": p[3],
                              "gecos": p[4], "home": p[5], "shell": p[6]})
        d["passwd"] = users
        groups = []
        for line in (read_text("/etc/group", 8 << 20) or "").splitlines():
            p = line.split(":")
            if len(p) >= 4:
                groups.append({"name": p[0], "gid": p[2], "members": [m for m in p[3].split(",") if m]})
        d["groups"] = groups
        sud = {}
        for f in ["/etc/sudoers"] + [os.path.join("/etc/sudoers.d", n) for n in listdir("/etc/sudoers.d")]:
            t = read_text(f, 256 * 1024)
            if t is not None:
                sud[f] = redact(t)
        d["sudoers"] = sud
        d["who"] = run_out(["who"], 10)
        d["realm_list"] = run_out(["realm", "list"], 20)
        d["ipa_default_conf"] = read_text("/etc/ipa/default.conf", 64 * 1024)
        return d

    # -- sécurité ---------------------------------------------------------
    def collect_security(self):
        d = {}
        d["sestatus"] = run_out(["sestatus"], 15)
        d["selinux_config"] = read_text("/etc/selinux/config", 16384)
        aa = read_text("/sys/kernel/security/apparmor/profiles", 4 << 20)
        d["apparmor_profiles_count"] = len(aa.splitlines()) if aa else None
        d["fips_enabled"] = (read_text("/proc/sys/crypto/fips_enabled", 16) or "").strip() or None
        d["crypto_policy"] = (read_text("/etc/crypto-policies/config", 4096) or "").strip() or None
        r = run(["sshd", "-T"], 20)
        if r and r["rc"] == 0:
            d["sshd_effective_config"] = r["out"]
        else:
            d["sshd_config"] = redact(read_text("/etc/ssh/sshd_config", 256 * 1024))
        d["iptables_save"] = (run_out(["iptables-save"], 30) or "")[:1 << 20] or None
        d["ip6tables_save"] = (run_out(["ip6tables-save"], 30) or "")[:1 << 20] or None
        d["nft_ruleset"] = (run_out(["nft", "list", "ruleset"], 30) or "")[:1 << 20] or None
        d["firewalld_state"] = (run_out(["firewall-cmd", "--state"], 20) or "").strip() or None
        if d["firewalld_state"] == "running":
            d["firewalld_zones"] = run_out(["firewall-cmd", "--list-all-zones"], 60)
        d["auditctl_status"] = run_out(["auditctl", "-s"], 15)
        d["lockdown"] = (read_text("/sys/kernel/security/lockdown", 256) or "").strip() or None
        return d

    # -- noyau ------------------------------------------------------------
    def collect_kernel(self):
        d = {}
        mods = []
        for line in (read_text("/proc/modules", 4 << 20) or "").splitlines():
            p = line.split()
            if p:
                mods.append({"name": p[0], "size": p[1], "state": p[4] if len(p) > 4 else None})
        d["modules"] = mods
        d["tainted"] = (read_text("/proc/sys/kernel/tainted", 64) or "").strip()
        d["sysctl"] = run_out(["sysctl", "-a"], 60)
        d["boot_dir"] = listdir("/boot")
        d["default_kernel"] = (run_out(["grubby", "--default-kernel"], 15) or "").strip() or None
        d["livepatch_sysfs"] = listdir("/sys/kernel/livepatch")
        d["kpatch"] = run_out(["kpatch", "list"], 30)
        d["canonical_livepatch"] = run_out(["canonical-livepatch", "status"], 30)
        return d

    # -- conteneurs -------------------------------------------------------
    def collect_containers(self):
        d = {}
        for tool in ("docker", "podman"):
            if not which(tool):
                continue
            t = {}
            for key, cmd in (("info", [tool, "info", "--format", "{{json .}}"]),
                             ("ps", [tool, "ps", "-a", "--no-trunc", "--format", "{{json .}}"]),
                             ("images", [tool, "images", "--digests", "--no-trunc", "--format", "{{json .}}"])):
                r = run(cmd, 60)
                if not r:
                    continue
                if r["rc"] != 0:
                    t[key + "_error"] = (r["err"] or "")[:500]
                    continue
                rows = []
                for line in r["out"].splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        rows.append(line)
                if key == "info":
                    t[key] = rows[0] if len(rows) == 1 else rows
                else:
                    t[key] = rows
            d[tool] = t
        if which("crictl"):
            c = {}
            for key, cmd in (("ps", ["crictl", "ps", "-a", "-o", "json"]), ("images", ["crictl", "images", "-o", "json"])):
                r = run(cmd, 60)
                if r and r["rc"] == 0:
                    try:
                        c[key] = json.loads(r["out"])
                    except ValueError:
                        c[key + "_raw"] = r["out"][:1 << 20]
            d["crictl"] = c
        return d

    # -- Oracle et assimilés ----------------------------------------------
    def collect_oracle(self, doc=None):
        d = {}
        d["oratab"] = read_text("/etc/oratab", 64 * 1024)
        loc = kv_text(read_text("/etc/oraInst.loc", 4096) or "")
        d["oraInst_loc"] = loc
        inv = loc.get("inventory_loc")
        if inv:
            d["central_inventory_homes"] = parse_central_inventory(
                read_text(os.path.join(inv, "ContentsXML", "inventory.xml"), 1 << 20))
        olr = read_text("/etc/oracle/olr.loc", 4096)
        d["olr_loc"] = kv_text(olr or "")
        procs = ((doc or {}).get("processes") or {}).get("list") or []
        cands = oracle_home_candidates(d["oratab"], d.get("central_inventory_homes"), olr, procs)
        homes = []
        for home in sorted(cands)[:40]:
            def read(rel, home=home):
                return read_text(os.path.join(home, rel), 16 << 20)

            def ls(rel, home=home):
                return listdir(os.path.join(home, rel))
            f = oracle_home_facts(home, read, ls)
            f["sources"] = cands[home]
            f["exists"] = os.path.isdir(home)
            homes.append(f)
        d["homes"] = homes
        return d if any(d.values()) else {}

    # -- parcours du système de fichiers -----------------------------------
    def scan_filesystem(self):
        a = self.args
        res = dict((k, []) for k in (
            "java_archives", "maven_exploded", "jdk_homes", "python_packages", "python_venvs", "conda_packages",
            "npm_packages", "node_apps", "npm_lockfiles", "composer_installed", "composer_locks", "ruby_gems",
            "dotnet_deps", "webapps", "js_libraries", "native_libs", "db_datadirs", "db_refs", "service_modules", "crypto_files", "endpoints"))
        stats = {"files": 0, "dirs": 0, "walk_errors": 0, "truncated": False, "db_config_files": 0, "db_config_unreadable": 0,
                 "crypto_files": 0, "p12_attempts": 0}
        t0 = time.time()
        deadline = t0 + a.scan_max_seconds
        excludes = set(a.exclude or [])
        if a.include_container_storage:
            excludes -= set(CONTAINER_STORAGE)
        skipped_mounts = []
        for m in parse_mounts():
            fst = m["fstype"]
            skip = fst in PSEUDO_FS or ((fst in NETWORK_FS or fst.startswith("fuse")) and not a.include_network_fs)
            if skip and m["mountpoint"] != "/":
                excludes.add(m["mountpoint"])
                skipped_mounts.append(m["mountpoint"] + " (" + fst + ")")
        stats["skipped_mounts"] = skipped_mounts[:500]
        stats["excludes"] = sorted(excludes)
        roots = a.scan_root or ["/"]
        hash_limit = a.hash_max_mb << 20 if a.hash_archives else -1
        archive_opts = {"max_depth": 3, "nested_max": 100 << 20}
        counters = {"js": 0, "native": 0, "archives": 0}

        def onerror(e):
            stats["walk_errors"] += 1

        def add_owner(entry, path):
            o = self.owner(path)
            if o:
                entry["owner_pkg"] = o
            return entry

        for root0 in roots:
            if root0 in excludes:
                continue
            for root, dirs, files in os.walk(root0, onerror=onerror):
                stats["dirs"] += 1
                if stats["dirs"] % 200 == 0 and time.time() > deadline:
                    stats["truncated"] = True
                    break
                base = os.path.basename(root)
                parent = os.path.basename(os.path.dirname(root))
                dirs[:] = [x for x in dirs if x not in PRUNE_DIRNAMES and os.path.join(root, x) not in excludes]

                # --- node_modules : on ne lit que package.json de chaque paquet
                is_npm_pkg = parent == "node_modules" or (
                    parent.startswith("@") and os.path.basename(os.path.dirname(os.path.dirname(root))) == "node_modules")
                if is_npm_pkg:
                    if "package.json" in files:
                        pj = os.path.join(root, "package.json")
                        try:
                            meta = json.loads(read_text(pj, 2 << 20) or "{}")
                            if isinstance(meta, dict) and meta.get("name"):
                                res["npm_packages"].append(add_owner({
                                    "path": root, "name": meta.get("name"), "version": meta.get("version"),
                                    "license": meta.get("license") if isinstance(meta.get("license"), (text_type, binary_type)) else None}, pj))
                        except (ValueError, TypeError):
                            pass
                    dirs[:] = [x for x in dirs if x == "node_modules"]
                    stats["files"] += len(files)
                    continue

                # --- Python : *.dist-info / *.egg-info (répertoires)
                keep = []
                for x in dirs:
                    if x.endswith(".dist-info") or x.endswith(".egg-info"):
                        md = os.path.join(root, x, "METADATA" if x.endswith(".dist-info") else "PKG-INFO")
                        self._python_meta(md, root, res, add_owner, x)
                    else:
                        keep.append(x)
                dirs[:] = keep

                # --- conda
                if base == "conda-meta":
                    for f in files:
                        if f.endswith(".json"):
                            try:
                                cm = json.loads(read_text(os.path.join(root, f), 4 << 20) or "{}")
                                res["conda_packages"].append({"prefix": os.path.dirname(root), "name": cm.get("name"),
                                                              "version": cm.get("version"), "build": cm.get("build"),
                                                              "channel": cm.get("channel")})
                            except (ValueError, TypeError):
                                pass
                    stats["files"] += len(files)
                    continue

                # --- datadirs de bases de données (on ne descend pas dedans)
                if "PG_VERSION" in files and "global" in dirs:
                    res["db_datadirs"].append({"engine": "postgresql", "path": root,
                                               "version": (read_text(os.path.join(root, "PG_VERSION"), 64) or "").strip()})
                    dirs[:] = []
                if "mysql_upgrade_info" in files or ("ibdata1" in files and "mysql" in dirs):
                    res["db_datadirs"].append({"engine": "mysql/mariadb", "path": root,
                                               "version": (read_text(os.path.join(root, "mysql_upgrade_info"), 128) or "").strip() or None})
                    dirs[:] = []

                in_bin_dir = base in ("bin", "sbin", "libexec")
                for f in files:
                    stats["files"] += 1
                    path = os.path.join(root, f)
                    lf = f.lower()
                    if is_db_config(path, lf):
                        self._db_config(path, lf, res, stats, add_owner)
                    if is_module_config(path, lf) and os.path.isfile(path):
                        for mod in parse_modules(read_text(path, 1 << 20), path):
                            mod["path"] = path
                            res["service_modules"].append(mod)
                    if is_web_config(path, lf) and os.path.isfile(path):
                        for ep in parse_endpoints(read_text(path, 2 << 20), path):
                            ep["path"] = path
                            res["endpoints"].append(ep)
                    if is_crypto_file(path, lf):
                        self._crypto_file(path, lf, res, stats, add_owner)
                    if lf.endswith(ARCHIVE_EXT):
                        if not is_regular(path):
                            continue
                        counters["archives"] += 1
                        try:
                            st = os.stat(path)
                            with open(path, "rb") as fo:
                                info = inspect_archive(fo, path, 0, archive_opts)
                            info["size"] = st.st_size
                            info["mtime"] = now_iso(st.st_mtime)
                            if hash_limit > 0:
                                info["sha1"] = sha1_file(path, hash_limit)
                            res["java_archives"].append(add_owner(info, path))
                        except (IOError, OSError) as e:
                            res["java_archives"].append({"path": path, "error": u(repr(e))[:200]})
                        continue
                    if f == "pom.properties" and "/META-INF/maven/" in root:
                        pp = parse_properties(read_text(path, 64 * 1024) or "")
                        res["maven_exploded"].append(add_owner({"path": path, "groupId": pp.get("groupId"),
                                                                "artifactId": pp.get("artifactId"),
                                                                "version": pp.get("version")}, path))
                        continue
                    if f == "release" and os.path.exists(os.path.join(root, "bin", "java")):
                        res["jdk_homes"].append(add_owner({"path": root, "release": kv_text(read_text(path, 64 * 1024) or "")}, path))
                        continue
                    if f == "package.json" and "node_modules" not in root:
                        try:
                            meta = json.loads(read_text(path, 2 << 20) or "{}")
                            if isinstance(meta, dict):
                                res["node_apps"].append(add_owner({
                                    "path": root, "name": meta.get("name"), "version": meta.get("version"),
                                    "dependencies": meta.get("dependencies") if isinstance(meta.get("dependencies"), dict) else None,
                                    "has_node_modules": "node_modules" in dirs}, path))
                        except (ValueError, TypeError):
                            pass
                        continue
                    if f == "package-lock.json" and "node_modules" not in dirs and "node_modules" not in root:
                        self._npm_lock(path, res)
                        continue
                    if f == "installed.json" and base == "composer" and parent == "vendor":
                        self._composer(path, res, "installed", add_owner)
                        continue
                    if f == "composer.lock" and not os.path.exists(os.path.join(root, "vendor", "composer", "installed.json")):
                        self._composer(path, res, "lock", add_owner)
                        continue
                    if lf.endswith(".gemspec") and base == "specifications":
                        m = re.match(r"^(.+)-(\d[^-]*(?:-[a-z0-9_]+)?)\.gemspec$", f)
                        if m:
                            res["ruby_gems"].append(add_owner({"path": path, "name": m.group(1), "version": m.group(2)}, path))
                        continue
                    if lf.endswith(".deps.json"):
                        self._dotnet(path, res)
                        continue
                    if f.endswith(".egg-info") and is_regular(path):
                        self._python_meta(path, root, res, add_owner, f)
                        continue
                    if f == "pyvenv.cfg":
                        res["python_venvs"].append({"path": root, "cfg": kv_text(read_text(path, 16384) or "")})
                        continue
                    if f in WEBAPP_FILENAMES:
                        self._webapp(path, root, f, files, res, add_owner)
                        continue
                    if lf.endswith(".js") and JSLIB_RX.match(f) and counters["js"] < a.max_js_libs:
                        if not is_regular(path):
                            continue
                        counters["js"] += 1
                        head = read_text(path, 2048) or ""
                        hm = JS_HEADER_VERSION_RX.search(head[:1024])
                        fm = FILENAME_VERSION_RX.search(f)
                        res["js_libraries"].append(add_owner({
                            "path": path, "library": JSLIB_RX.match(f).group(1).lower(),
                            "version_from_filename": fm.group(1) if fm else None,
                            "version_from_header": hm.group(1) if hm else None,
                            "header": head[:200]}, path))
                        continue
                    if ".so" in f and NATIVE_LIB_RX.match(f) and not path.startswith(SYSTEM_LIB_PREFIXES) \
                            and "-packages/" not in path and counters["native"] < 50000:
                        if not is_regular(path):
                            continue
                        counters["native"] += 1
                        entry = {"path": path, "name": f}
                        fm = re.search(r"\.so\.([\d.]+)$", f) or re.search(r"-([\d.]+)\.so$", f)
                        entry["version_from_filename"] = fm.group(1) if fm else None
                        for name_rx, str_rx in LIB_STRING_PATTERNS:
                            if name_rx.match(f):
                                entry["embedded_version"] = find_strings(path, str_rx)
                                break
                        res["native_libs"].append(add_owner(entry, path))
                        continue
                    if PROBE_ANY_RX.match(f):
                        self.add_probe_candidate(path, "filesystem")
                    if in_bin_dir:
                        self.go_candidates.add(path)
            if stats["truncated"]:
                break
        stats["duration"] = round(time.time() - t0, 1)
        stats["archives"] = counters["archives"]
        res["db_refs_resolved"] = self.resolve_db_hosts(res["db_refs"])
        res["stats"] = stats
        return res

    def _python_meta(self, md, site, res, add_owner, dname):
        if os.path.isdir(md):
            md = os.path.join(md, "PKG-INFO")
        t = read_text(md, 256 * 1024)
        if t is None:
            m = re.match(r"^(.+?)-(\d[^-]*?)(?:-py\d.*)?\.(?:dist|egg)-info$", dname)
            if m:
                res["python_packages"].append(add_owner({"site": site, "name": m.group(1), "version": m.group(2),
                                                         "source": "dirname"}, md))
            return
        name = version = None
        for line in t.splitlines():
            if not line.strip():
                break
            if line.startswith("Name:"):
                name = line[5:].strip()
            elif line.startswith("Version:"):
                version = line[8:].strip()
        installer = (read_text(os.path.join(os.path.dirname(md), "INSTALLER"), 256) or "").strip() or None
        res["python_packages"].append(add_owner({"site": site, "name": name, "version": version,
                                                 "installer": installer, "meta": md}, md))

    def _npm_lock(self, path, res):
        try:
            lk = json.loads(read_text(path, 64 << 20) or "{}")
        except ValueError:
            return
        pkgs = []
        if isinstance(lk.get("packages"), dict):
            for k, v in lk["packages"].items():
                if k and isinstance(v, dict) and "node_modules/" in k:
                    pkgs.append([k.rsplit("node_modules/", 1)[-1], v.get("version")])
        elif isinstance(lk.get("dependencies"), dict):
            stack = [lk["dependencies"]]
            while stack:
                deps = stack.pop()
                for k, v in deps.items():
                    if isinstance(v, dict):
                        pkgs.append([k, v.get("version")])
                        if isinstance(v.get("dependencies"), dict):
                            stack.append(v["dependencies"])
        res["npm_lockfiles"].append({"path": path, "name": lk.get("name"), "version": lk.get("version"),
                                     "packages": pkgs})

    def _composer(self, path, res, kind, add_owner):
        try:
            data = json.loads(read_text(path, 64 << 20) or "{}")
        except ValueError:
            return
        if isinstance(data, list):
            pk = data
        elif kind == "installed":
            pk = data.get("packages", [])
        else:
            pk = (data.get("packages") or []) + (data.get("packages-dev") or [])
        rows = []
        for p in pk:
            if isinstance(p, dict):
                rows.append({"name": p.get("name"), "version": p.get("version"),
                             "version_normalized": p.get("version_normalized"), "type": p.get("type")})
        key = "composer_installed" if kind == "installed" else "composer_locks"
        res[key].append(add_owner({"path": path, "packages": rows}, path))

    def _dotnet(self, path, res):
        try:
            data = json.loads(read_text(path, 32 << 20) or "{}")
        except ValueError:
            return
        libs = []
        for k, v in (data.get("libraries") or {}).items():
            if "/" in k:
                n, ver = k.rsplit("/", 1)
                libs.append({"name": n, "version": ver, "type": (v or {}).get("type")})
        res["dotnet_deps"].append({"path": path, "runtimeTarget": data.get("runtimeTarget"), "libraries": libs})

    def _db_config(self, path, lname, res, stats, add_owner):
        """Fichier de configuration : seules les références de bases sont retenues, jamais le contenu."""
        if not is_regular(path) or stats["db_config_files"] >= DB_CONFIG_MAX_FILES:
            return
        stats["db_config_files"] += 1
        text = read_text(path, DB_CONFIG_MAX_SIZE)
        if text is None:
            stats["db_config_unreadable"] += 1
            return
        for r in extract_db_refs(text, lname):
            r["path"] = path
            res["db_refs"].append(add_owner(r, path))

    def _crypto_file(self, path, lname, res, stats, add_owner):
        """Fichier de clé ou de certificat : mentionné dans tous les cas, jamais copié."""
        if not is_regular(path) or stats["crypto_files"] >= CRYPTO_MAX_FILES:
            return
        stats["crypto_files"] += 1
        st = os.lstat(path)
        data = read_bytes(path, CRYPTO_MAX_READ)
        f = crypto_facts(data, lname) if data is not None else {
            "kind": "illisible", "has_private_key": None, "encrypted": None, "certs": [], "cert_count": 0,
            "note": "illisible pour le compte de collecte"}
        if f["kind"] == "pkcs12" and stats["p12_attempts"] < CRYPTO_MAX_P12:
            stats["p12_attempts"] += 1
            self._pkcs12(path, f)
        f.update({"path": path, "size": st.st_size, "mode": "%04o" % stat.S_IMODE(st.st_mode), "owner": uid_name(st.st_uid),
                  "gid": st.st_gid, "mtime": now_iso(st.st_mtime)})
        res["crypto_files"].append(add_owner(f, path))

    def _pkcs12(self, path, f):
        """Mot de passe vide uniquement : aucun autre n'est essayé. -nokeys : seuls les certificats sortent."""
        f["has_private_key"] = None
        if not which("openssl"):
            f["note"] = "openssl absent : contenu non lu"
            return
        for extra in ([], ["-legacy"]):
            out = run_out(["openssl", "pkcs12", "-in", path, "-nokeys", "-passin", "pass:"] + extra, 10)
            certs = certs_from_pem(out)
            if certs:
                f.update({"certs": certs[:CRYPTO_MAX_CERTS], "cert_count": len(certs), "empty_password": True})
                return
        f["encrypted"] = True
        f["note"] = "protégé par un mot de passe : contenu non lu"

    def resolve_db_hosts(self, refs):
        """Noms des serveurs de bases résolus depuis la cible (getent, budget limité)."""
        if not which("getent"):
            return {}
        out, deadline = {}, time.time() + 30
        names = sorted(set(r["host"] for r in refs if r.get("host") and not re.match(r"^[\d.:]+$", r["host"])
                           and r["host"] != "localhost"))
        for name in names[:40]:
            if time.time() > deadline:
                break
            ips = sorted(set(line.split()[0] for line in (run_out(["getent", "hosts", name], 3) or "").splitlines() if line.strip()))
            if ips:
                out[name] = ips
        return out

    def _webapp(self, path, root, fname, files, res, add_owner):
        if not is_regular(path):
            return
        text = None
        for rfile, suffix, product, rxs in WEBAPP_RULES:
            if rfile != fname or (suffix and not root.endswith(suffix)):
                continue
            if product == "jboss-wildfly-keycloak":
                if not (os.path.exists(os.path.join(root, "jboss-modules.jar")) or
                        os.path.exists(os.path.join(root, "bin", "kc.sh"))):
                    continue
            if product == "gitlab" and not root.startswith("/opt/gitlab"):
                continue
            if text is None:
                text = read_text(path, 512 * 1024) or ""
            found = []
            for rx in rxs:
                m = re.search(rx, text, re.M)
                if m:
                    found.append(" ".join(g for g in m.groups() if g))
            if found:
                app_root = root
                if suffix:
                    app_root = root[:-len(suffix)] or "/"
                res["webapps"].append(add_owner({"product": product, "root": app_root, "evidence": path,
                                                 "values": found}, path))
                return

    # -- sondes de version ------------------------------------------------
    def exec_identity(self, rp):
        """Décide sous quelle identité exécuter un binaire trouvé.

        root uniquement si le fichier ET tous ses répertoires parents appartiennent
        à root et ne sont pas modifiables par d'autres (sticky toléré) ; sinon le
        propriétaire du fichier (s'il contrôle la chaîne), sinon nobody.
        """
        try:
            st = os.stat(rp)
        except OSError:
            return None
        allowed = set([0, st.st_uid])

        def chain_ok(uids):
            if st.st_uid not in uids or st.st_mode & 0o022:
                return False
            d = os.path.dirname(rp)
            while True:
                try:
                    ds = os.stat(d)
                except OSError:
                    return False
                if ds.st_uid not in uids:
                    return False
                if ds.st_mode & 0o022 and not ds.st_mode & stat.S_ISVTX:
                    return False
                if d == "/":
                    return True
                d = os.path.dirname(d)
        me = os.geteuid()
        if me != 0:
            # Sans root, impossible de changer d'identité : on n'exécute que ce qui est sous
            # le contrôle de root (ou du compte de collecte lui-même). Un binaire d'un autre
            # compte exécuterait son code sous l'identité du compte de collecte.
            if (st.st_uid == 0 and chain_ok(set([0]))) or (st.st_uid == me and chain_ok(set([0, me]))):
                return (me, os.getegid())
            return None
        if st.st_uid == 0 and chain_ok(set([0])):
            return (0, 0)
        if st.st_uid != 0 and chain_ok(allowed):
            return (st.st_uid, st.st_gid)
        return (65534, 65534)

    def probe_runtimes(self):
        a = self.args
        # Candidats supplémentaires : PATH + répertoires usuels
        import glob
        dirs = list(SEARCH_PATH)
        for g in EXTRA_BIN_GLOBS:
            dirs.extend(glob.glob(g))
        for d in dirs:
            for n in listdir(d):
                p = os.path.join(d, n)
                self.add_probe_candidate(p, "path")
                if d.endswith(("bin", "sbin")):
                    self.go_candidates.add(p)
        results = []
        if not a.exec_probes:
            return {"disabled": True, "candidates": [{"probe": c["probe"], "realpath": rp, "paths": sorted(c["paths"])}
                                                     for rp, c in sorted(self.probe_candidates.items())]}
        per_probe = {}
        deadline = time.time() + a.exec_max_seconds
        for rp, c in sorted(self.probe_candidates.items()):
            name = c["probe"]
            entry = {"probe": name, "realpath": rp, "paths": sorted(c["paths"]), "origins": sorted(c["origins"])}
            own = self.owner(rp)
            if own:
                entry["owner_pkg"] = own
            per_probe[name] = per_probe.get(name, 0) + 1
            if per_probe[name] > a.max_per_probe:
                entry["skipped"] = "max_per_probe"
                results.append(entry)
                continue
            if time.time() > deadline or self.exec_count >= a.max_execs:
                entry["skipped"] = "exec_budget"
                results.append(entry)
                continue
            head = read_bytes(rp, 4) or b""
            is_elf = head == b"\x7fELF"
            if is_elf:
                fp = fingerprint(rp)
                if fp:
                    entry["fingerprint"] = fp
            if not is_elf and not (name in SCRIPT_PROBES and own):
                entry["skipped"] = "not_elf_or_untrusted_script"
                results.append(entry)
                continue
            ids = self.exec_identity(rp)
            if ids is None:
                entry["skipped"] = "untrusted_owner_or_perms"
                results.append(entry)
                continue
            entry["run_as_uid"] = ids[0]
            try:
                entry["file_uid"] = os.stat(rp).st_uid
            except OSError:
                pass
            spec = [p for p in PROBE_RX if p[0] == name][0]
            outs = []
            for args, flt in spec[2]:
                self.exec_count += 1
                r = run([rp] + args, timeout=a.exec_timeout, as_ids=ids, max_out=4 << 20)
                if r is None:
                    break
                text = ((r["out"] or "") + ("\n" if r["out"] and r["err"] else "") + (r["err"] or ""))
                if flt == "PHPINFO":
                    text = phpinfo_filter(text)
                elif flt:
                    frx = re.compile(flt)
                    text = "\n".join(l for l in text.splitlines() if frx.search(l))
                outs.append({"args": args if name != "python" else ["-c", "<probe>"], "rc": r["rc"],
                             "timeout": r["timeout"], "output": text[:524288 if flt == "PHPINFO" else 65536]})
                if spec[3] == "first" and r["rc"] == 0:
                    break
            entry["outputs"] = outs
            results.append(entry)
        return {"count": len(results), "execs": self.exec_count, "list": results}

    def scan_go_binaries(self):
        found = []
        checked = 0
        t0 = time.time()
        for p in sorted(self.go_candidates):
            if time.time() - t0 > 300:
                break
            try:
                rp = os.path.realpath(p)
                st = os.stat(rp)
            except (OSError, ValueError):
                continue
            if not stat.S_ISREG(st.st_mode) or st.st_size < 512 * 1024:
                continue
            checked += 1
            info = parse_go_buildinfo(elf_section(rp))
            if info:
                info["path"] = p
                info["realpath"] = rp
                o = self.owner(rp)
                if o:
                    info["owner_pkg"] = o
                found.append(info)
        # dédoublonnage par realpath
        seen = {}
        for f in found:
            seen.setdefault(f["realpath"], f)
        return {"checked": checked, "list": list(seen.values())}

    def software_dirs(self):
        out = {}
        for top in ("/opt", "/usr/local", "/srv", "/app", "/apps", "/applis", "/data", "/u01", "/u02", "/home",
                    "/var/www", "/var/lib/tomcat", "/var/lib/tomcats", "/usr/share/tomcat", "/usr/share/java"):
            if not os.path.isdir(top):
                continue
            lvl1 = listdir(top)
            entry = {}
            for n in lvl1[:500]:
                p = os.path.join(top, n)
                if os.path.isdir(p) and not os.path.islink(p):
                    entry[n] = listdir(p)[:200]
                else:
                    entry[n] = None
            out[top] = entry
        return out

    def pending_updates(self):
        d = {}
        if which("dnf"):
            d["dnf_updateinfo_cve"] = run_out(["dnf", "-q", "updateinfo", "list", "--with-cve"], 900)
            d["dnf_updateinfo_security"] = run_out(["dnf", "-q", "updateinfo", "list", "--security"], 900)
        elif which("yum"):
            d["yum_updateinfo_cve"] = run_out(["yum", "-q", "updateinfo", "list", "cves"], 900)
            d["yum_updateinfo_security"] = run_out(["yum", "-q", "updateinfo", "list", "security"], 900)
        if which("apt-get"):
            d["apt_simulate"] = run_out(["apt-get", "-s", "-o", "Debug::NoLocking=1", "dist-upgrade"], 600)
        if which("debsecan"):
            d["debsecan"] = run_out(["debsecan"], 600)
        if which("zypper"):
            d["zypper_patches"] = run_out(["zypper", "--non-interactive", "list-patches", "--category", "security"], 600)
        return d

    # -- orchestration ----------------------------------------------------
    def collect(self):
        a = self.args
        started = time.time()
        doc = {"schema": SCHEMA, "meta": {
            "collector_version": COLLECTOR_VERSION, "started_at": now_iso(started),
            "host_label": a.host_label, "run_id": a.run_id,
            "tags": dict(t.split("=", 1) for t in (a.tag or []) if "=" in t),
            "uid": os.geteuid(), "user": uid_name(os.geteuid()),
            "privileged": os.geteuid() == 0, "argv": sys.argv[1:],
        }}
        doc["os"] = self.section("os", self.collect_os)
        doc["hardware"] = self.section("hardware", self.collect_hardware)
        doc["packages"] = self.section("packages", self.collect_packages)
        doc["processes"] = self.section("processes", self.collect_processes)
        doc["network"] = self.section("network", self.collect_network)
        doc["services"] = self.section("services", self.collect_services)
        doc["scheduled"] = self.section("scheduled", self.collect_scheduled)
        doc["accounts"] = self.section("accounts", self.collect_accounts)
        doc["security"] = self.section("security", self.collect_security)
        doc["kernel"] = self.section("kernel", self.collect_kernel)
        doc["containers"] = self.section("containers", self.collect_containers)
        doc["oracle"] = self.section("oracle", lambda: self.collect_oracle(doc))
        doc["software_dirs"] = self.section("software_dirs", self.software_dirs)
        if a.scan_filesystem:
            doc["filesystem"] = self.section("filesystem", self.scan_filesystem)
        doc["process_artifacts"] = self.section("process_artifacts", lambda: self.process_artifacts(doc))
        doc["runtimes"] = self.section("runtimes", self.probe_runtimes)
        doc["go_binaries"] = self.section("go_binaries", self.scan_go_binaries)
        if a.pending_updates:
            doc["pending_updates"] = self.section("pending_updates", self.pending_updates)
        procs = (doc.get("processes") or {}).get("list") or []
        hide = [m["options"] for m in parse_mounts() if m["fstype"] == "proc" and "hidepid" in m["options"]]
        doc["meta"]["visibility"] = {
            "processes": len(procs),
            "processes_exe_readable": sum(1 for x in procs if x.get("exe")),
            "proc_hidepid": hide[0] if hide else None,
            "fs_unreadable_dirs": ((doc.get("filesystem") or {}).get("stats") or {}).get("walk_errors"),
        }
        doc["meta"]["finished_at"] = now_iso()
        doc["meta"]["duration_seconds"] = round(time.time() - started, 1)
        doc["meta"]["section_timings"] = self.timings
        doc["meta"]["errors"] = self.errors
        return doc


def lower_priority():
    try:
        os.nice(19)
    except OSError:
        pass
    # ionice idle (classe 3) via l'appel système ioprio_set si possible, sinon l'outil ionice
    run(["ionice", "-c", "3", "-p", str(os.getpid())], 5)


class _OptparseAdapter(object):
    """Expose l'API add_argument/parse_args d'argparse au-dessus d'optparse (Python 2.6)."""

    def __init__(self, description):
        import optparse
        self._p = optparse.OptionParser(description=description)
        self._required = []

    def add_argument(self, *flags, **kw):
        if kw.pop("required", False):
            self._required.append(kw.get("dest") or flags[0].lstrip("-").replace("-", "_"))
        t = kw.get("type")
        if t is int:
            kw["type"] = "int"
        self._p.add_option(*flags, **kw)

    def parse_args(self, argv=None):
        opts, _rest = self._p.parse_args(argv)
        for d in self._required:
            if getattr(opts, d, None) is None:
                self._p.error("option --%s obligatoire" % d.replace("_", "-"))
        return opts


def make_parser(description):
    try:
        import argparse  # novermin (repli optparse ci-dessous)
        return argparse.ArgumentParser(description=description)
    except ImportError:  # Python 2.6 : pas d'argparse dans la bibliothèque standard
        return _OptparseAdapter(description)


def parse_args(argv=None):
    p = make_parser("Collecteur d'inventaire CMDB (lecture seule).")
    p.add_argument("--output", "-o", required=True,
                   help="Fichier de sortie (.json.gz ou .json), ou '-' pour un flux base64 sur stdout")
    p.add_argument("--host-label", dest="host_label", default=None, help="Nom de l'hôte dans l'inventaire Ansible")
    p.add_argument("--tag", dest="tag", action="append", default=None,
                   help="Étiquette CLE=VALEUR enregistrée dans la collecte (ex. app=APPDEMO, platform=prod) ; répétable")
    p.add_argument("--run-id", dest="run_id", default=None, help="Identifiant de l'exécution (commun à tous les hôtes)")
    p.add_argument("--no-scan-filesystem", dest="scan_filesystem", action="store_false", default=True)
    p.add_argument("--scan-root", dest="scan_root", action="append", help="Racine(s) de parcours (défaut : /)")
    p.add_argument("--exclude", action="append", default=None,
                   help="Chemin à exclure (répétable) ; REMPLACE la liste d'exclusions par défaut")
    p.add_argument("--extra-exclude", dest="extra_exclude", action="append", default=[],
                   help="Chemin à exclure en plus des exclusions par défaut (répétable)")
    p.add_argument("--scan-max-seconds", type=int, default=900)
    p.add_argument("--include-network-fs", action="store_true", default=False)
    p.add_argument("--include-container-storage", action="store_true", default=False)
    p.add_argument("--no-hash-archives", dest="hash_archives", action="store_false", default=True)
    p.add_argument("--hash-max-mb", type=int, default=256)
    p.add_argument("--max-js-libs", type=int, default=30000)
    p.add_argument("--no-exec-probes", dest="exec_probes", action="store_false", default=True)
    p.add_argument("--exec-timeout", type=int, default=20)
    p.add_argument("--exec-max-seconds", type=int, default=600)
    p.add_argument("--max-execs", type=int, default=800)
    p.add_argument("--max-per-probe", type=int, default=64)
    p.add_argument("--no-file-owners", dest="file_owners", action="store_false", default=True)
    p.add_argument("--pending-updates", action="store_true", default=False,
                   help="Interroge le gestionnaire de paquets sur les mises à jour de sécurité (peut contacter les dépôts)")
    p.add_argument("--no-nice", dest="nice", action="store_false", default=True)
    p.add_argument("--pretty", action="store_true", default=False)
    a = p.parse_args(argv)
    if a.exclude is None:
        a.exclude = list(DEFAULT_EXCLUDES)
    a.exclude = [x.rstrip("/") or "/" for x in a.exclude + (a.extra_exclude or [])]
    return a


def main(argv=None):
    a = parse_args(argv)
    if a.nice:
        lower_priority()
    c = Collector(a)
    doc = sanitize(c.collect())
    data = json.dumps(doc, indent=1 if a.pretty else None, sort_keys=False, ensure_ascii=True)
    if not isinstance(data, binary_type):
        data = data.encode("utf-8")
    out = a.output
    fs = doc.get("filesystem") or {}
    summary = {
        "host": doc["os"].get("hostname") if isinstance(doc.get("os"), dict) else None,
        "output": out, "bytes_json": len(data),
        "duration_seconds": doc["meta"]["duration_seconds"], "errors": len(doc["meta"]["errors"]),
        "packages": dict((k, len(v)) for k, v in ((doc.get("packages") or {}).get("managers") or {}).items()),
        "runtimes_probed": (doc.get("runtimes") or {}).get("count"),
        "java_archives": len(fs.get("java_archives") or []),
        "python_packages": len(fs.get("python_packages") or []),
        "npm_packages": len(fs.get("npm_packages") or []),
        "fs_truncated": (fs.get("stats") or {}).get("truncated"),
    }
    if out == "-":
        # Mode "flux" (playbook collect_legacy.yml) : JSON gzip encodé en base64 sur stdout,
        # encadré de marqueurs pour ignorer d'éventuelles bannières ; résumé sur stderr.
        buf = io.BytesIO()
        gz = gzip.GzipFile(fileobj=buf, mode="wb")
        gz.write(data)
        gz.close()
        b64 = base64.b64encode(buf.getvalue())
        if not isinstance(b64, str):
            b64 = b64.decode("ascii")
        sys.stdout.write("CMDB-B64-BEGIN\n")
        for i in range(0, len(b64), 76):
            sys.stdout.write(b64[i:i + 76] + "\n")
        sys.stdout.write("CMDB-B64-END\n")
        sys.stdout.flush()
        sys.stderr.write(json.dumps(summary) + "\n")
        return 0
    tmp = out + ".tmp"
    if out.endswith(".gz"):
        f = gzip.open(tmp, "wb")  # pas de "with" : GzipFile n'est un gestionnaire de contexte qu'à partir de 2.7
        try:
            f.write(data)
        finally:
            f.close()
    else:
        with open(tmp, "wb") as f:
            f.write(data)
    os.chmod(tmp, 0o600)
    os.rename(tmp, out)
    summary["bytes_file"] = os.path.getsize(out)
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
