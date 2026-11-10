# -*- coding: utf-8 -*-
"""Contenu des conteneurs : collecte par « export » (faux moteur docker), consolidation, croisement CVE.

Le faux docker imite ps -q, inspect et export (archive tar d'une arborescence fabriquée) : aucun
moteur réel n'est nécessaire."""
import gzip
import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import zipfile

from tests.common import C, ROOT, TOOLS
from tests.boltwriter import Writer
from tests.test_cve import TREE, J
import cmdb_build as B
import cmdb_cve

SECRET = "S3cr3tCtr"
FAKE = r'''#!%(py)s
import json, os, sys, tarfile
root = %(root)r
CTRS = {"c1" * 32: ("sha256:img-app", "registry.exemple.test/app:1.0", "/web-1"),
        "c2" * 32: ("sha256:img-app", "registry.exemple.test/app:1.0", "/web-2"),
        "c3" * 32: ("sha256:img-alp", "alpine:3.19", "/outil")}
args = sys.argv[1:]
if os.path.exists(os.path.join(root, "refus")):
    sys.stderr.write("permission denied while trying to connect to the Docker daemon socket\n")
    sys.exit(1)
if args[:1] == ["ps"]:
    print("\n".join(sorted(CTRS)))
elif args[:1] == ["inspect"]:
    print(json.dumps([{"Id": i, "Name": CTRS[i][2], "Image": CTRS[i][0], "Config": {"Image": CTRS[i][1], "Env": ["DB_PASSWORD=%(secret)s"]},
                       "State": {"StartedAt": "2026-11-01T00:00:00Z"},
                       "Mounts": [{"Type": "bind", "Source": "/srv/data", "Destination": "/data"}]} for i in args[1:]]))
elif args[:1] == ["export"]:
    with open(os.path.join(root, "exports.log"), "a") as f:
        f.write(args[1] + "\n")
    out = getattr(sys.stdout, "buffer", sys.stdout)
    t = tarfile.open(fileobj=out, mode="w|")
    t.add(os.path.join(root, CTRS[args[1]][0].split(":")[1]), arcname=".")
    t.close()
'''


def jar(path, group, artifact, version):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
        z.writestr("META-INF/maven/%s/%s/pom.properties" % (group, artifact),
                   "groupId=%s\nartifactId=%s\nversion=%s\n" % (group, artifact, version))


def write(root, rel, text):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(text)


def make_engine(tmp):
    app, alp = os.path.join(tmp, "img-app"), os.path.join(tmp, "img-alp")
    write(app, "etc/os-release", 'ID=debian\nVERSION_ID="12"\nPRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n')
    write(app, "var/lib/dpkg/status",
          "Package: openssl\nStatus: install ok installed\nVersion: 3.0.14-1~deb12u2\nArchitecture: amd64\n"
          "Maintainer: Debian OpenSSL Team <x@exemple.test>\nDescription: Secure Sockets Layer toolkit\n second line\n\n"
          "Package: libssl3\nStatus: install ok installed\nSource: openssl\nVersion: 3.0.14-1~deb12u2\nArchitecture: amd64\n\n"
          "Package: oldpkg\nStatus: deinstall ok config-files\nVersion: 1.0\n")
    jar(os.path.join(app, "app/lib/log4j-core-2.14.1.jar"), "org.apache.logging.log4j", "log4j-core", "2.14.1")
    write(app, "usr/local/lib/python3.11/site-packages/requests-2.25.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: requests\nVersion: 2.25.0\n")
    write(app, "app/node_modules/lodash/package.json", json.dumps({"name": "lodash", "version": "4.17.20"}))
    write(app, "app/node_modules/@scope/x/package.json", json.dumps({"name": "@scope/x", "version": "1.0.0"}))
    write(app, "app/node_modules/lodash/test/package.json", json.dumps({"name": "faux", "version": "0"}))
    write(app, "opt/java/openjdk/release", 'JAVA_VERSION="17.0.9"\nIMPLEMENTOR="Eclipse Adoptium"\n')
    write(app, "app/config/application.properties", "spring.datasource.password=%s\n" % SECRET)
    write(alp, "etc/os-release", "ID=alpine\nVERSION_ID=3.19.1\nPRETTY_NAME=\"Alpine Linux v3.19\"\n")
    write(alp, "lib/apk/db/installed", "P:libssl3\nV:3.1.4-r0\nA:x86_64\no:openssl\n\nP:busybox\nV:1.36.1-r15\nA:x86_64\no:busybox\n\n")
    bindir = os.path.join(tmp, "bin")
    os.makedirs(bindir)
    with open(os.path.join(bindir, "docker"), "w") as f:
        f.write(FAKE % {"py": sys.executable, "root": tmp, "secret": SECRET})
    os.chmod(os.path.join(bindir, "docker"), 0o755)
    return bindir


def collect(tmp, *extra):
    old = C.SEARCH_PATH
    C.SEARCH_PATH = [os.path.join(tmp, "bin")]
    try:
        a = C.parse_args(["-o", os.path.join(tmp, "x.json.gz"), "--no-scan-filesystem"] + list(extra))
        return C.Collector(a).collect_container_content()
    finally:
        C.SEARCH_PATH = old


class Collecte(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="cmdbctr")
        make_engine(cls.tmp)
        cls.out = collect(cls.tmp)
        cls.images = dict((i["image_id"], i) for i in cls.out["images"])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_une_lecture_par_image(self):
        self.assertEqual(self.out["engines"]["docker"], {"readable": True, "running": 3})
        self.assertEqual(sorted(self.images), ["sha256:img-alp", "sha256:img-app"])
        with open(os.path.join(self.tmp, "exports.log")) as f:
            self.assertEqual(len(f.read().split()), 2)      # web-1 et web-2 partagent l'image : un seul export
        self.assertEqual([c["name"] for c in self.images["sha256:img-app"]["containers"]], ["web-1", "web-2"])

    def test_systeme_et_paquets(self):
        app = self.images["sha256:img-app"]
        self.assertEqual(app["os_release"]["ID"], "debian")
        dpkg = dict((p["name"], p) for p in app["packages"]["managers"]["dpkg"])
        self.assertEqual(dpkg["openssl"]["version"], "3.0.14-1~deb12u2")
        self.assertEqual(dpkg["libssl3"]["source"], "openssl")
        apk = self.images["sha256:img-alp"]["packages"]["managers"]["apk"]
        self.assertEqual([(p["name"], p["origin"]) for p in apk], [("libssl3", "openssl"), ("busybox", "busybox")])

    def test_composants(self):
        fs = self.images["sha256:img-app"]["filesystem"]
        self.assertEqual(fs["java_archives"][0]["maven"][0]["version"], "2.14.1")
        self.assertEqual(fs["java_archives"][0]["path"], "/app/lib/log4j-core-2.14.1.jar")
        self.assertEqual([(p["name"], p["version"]) for p in fs["python_packages"]], [("requests", "2.25.0")])
        self.assertEqual(sorted(p["name"] for p in fs["npm_packages"]), ["@scope/x", "lodash"])
        self.assertEqual(fs["jdk_homes"][0]["release"]["JAVA_VERSION"], "17.0.9")

    def test_rien_de_sensible(self):
        text = json.dumps(self.out)
        self.assertNotIn(SECRET, text)          # ni les variables d'environnement, ni les fichiers de configuration
        self.assertNotIn("DB_PASSWORD", text)

    def test_moteur_refuse(self):
        open(os.path.join(self.tmp, "refus"), "w").close()
        try:
            out = collect(self.tmp)
        finally:
            os.remove(os.path.join(self.tmp, "refus"))
        self.assertFalse(out["engines"]["docker"]["readable"])
        self.assertIn("permission denied", out["engines"]["docker"]["error"])
        self.assertEqual(out["images"], [])

    def test_duree_maximale(self):
        out = collect(self.tmp, "--container-max-seconds", "0")
        self.assertEqual(len(out["images"]), 2)        # conteneurs listés, contenu non lu
        self.assertTrue(all("durée maximale" in i["error"] for i in out["images"]))

    def test_desactivable(self):
        self.assertEqual(collect(self.tmp, "--no-container-content"), {"disabled": True})

    def test_python2_compatible(self):
        with open(os.path.join(ROOT, "roles", "cmdb_collect", "files", "cmdb_collector.py"), encoding="utf-8") as f:
            src = f.read()
        block = src[src.index("# --- Contenu des conteneurs"):src.index("\nclass _OptparseAdapter")]
        block += src[src.index("    def collect_container_content"):src.index("    # -- Oracle et assimilés")]
        import re
        self.assertIsNone(re.search(r"(?<![\w\\])f[\"']|\bnonlocal\b|yield from| := |exist_ok|\.format_map", block))


class Consolidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="cmdbctr")
        make_engine(cls.tmp)
        with open(os.path.join(ROOT, "tests", "fixtures", "format_v1", "python-1.1.0.json")) as f:
            doc = json.load(f)
        doc["container_content"] = collect(cls.tmp)
        store = os.path.join(cls.tmp, "store", "APPV1", "prod", "srv-py01")
        os.makedirs(store)
        with gzip.open(os.path.join(store, "r.json.gz"), "wt") as f:
            json.dump(doc, f)
        tree = dict(TREE)
        tree["alpine 3.19"] = {"openssl": {"CVE-2024-3001": J({"FixedVersion": "3.1.4-r5"})}}
        tree["vulnerability"] = dict(TREE["vulnerability"], **{"CVE-2024-3001": J({"Title": "openssl: alpine", "Severity": "HIGH"})})
        cls.trivy = os.path.join(cls.tmp, "trivy.db")
        Writer().write(cls.trivy, tree)
        out = os.path.join(cls.tmp, "build")
        cls.out = out
        proc = subprocess.run([sys.executable, os.path.join(TOOLS, "cmdb_build.py"), "--store", os.path.join(cls.tmp, "store"),
                               "--out", out, "--no-dossiers", "--trivy-db", cls.trivy],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        assert proc.returncode == 0, proc.stderr
        cls.db = sqlite3.connect(os.path.join(out, "cmdb.sqlite"))

    @classmethod
    def tearDownClass(cls):
        cls.db.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def q(self, sql, *a):
        return self.db.execute(sql, a).fetchall()

    def test_images(self):
        self.assertEqual(self.q("SELECT image, containers, os_id, os_version, packages FROM container_images ORDER BY image"),
                         [("alpine:3.19", "outil", "alpine", "3.19.1", 2),
                          ("registry.exemple.test/app:1.0", "web-1 web-2", "debian", "12", 2)])

    def test_paquets_a_part(self):
        self.assertEqual(self.q("SELECT COUNT(*) FROM packages WHERE name = 'libssl3'"), [(0,)])   # pas mêlés à ceux de l'hôte
        self.assertEqual(self.q("SELECT name, version, source FROM container_packages WHERE image = 'registry.exemple.test/app:1.0' "
                                "ORDER BY name"), [("libssl3", "3.0.14-1~deb12u2", "openssl"), ("openssl", "3.0.14-1~deb12u2", "openssl")])

    def test_composants_dans_software(self):
        got = self.q("SELECT name, version, location FROM software WHERE location LIKE 'docker:%' ORDER BY name")
        self.assertIn(("org.apache.logging.log4j:log4j-core", "2.14.1", "docker:web-1 (+1):/app/lib/log4j-core-2.14.1.jar"), got)
        self.assertIn("requests", [r[0] for r in got])
        self.assertIn("lodash", [r[0] for r in got])

    def test_cve_conteneurs(self):
        got = self.q("SELECT component, vuln_id, fixed_version, location FROM vulnerabilities WHERE source = 'conteneur' ORDER BY 1, 2")
        self.assertIn(("openssl", "CVE-2024-2004", "3.0.15-1~deb12u1", "image registry.exemple.test/app:1.0 (web-1 web-2)"), got)
        self.assertIn(("libssl3", "CVE-2024-2004", "3.0.15-1~deb12u1", "image registry.exemple.test/app:1.0 (web-1 web-2)"), got)
        self.assertIn(("libssl3", "CVE-2024-3001", "3.1.4-r5", "image alpine:3.19 (outil)"), got)
        log4j = self.q("SELECT DISTINCT vuln_id FROM vulnerabilities WHERE component LIKE '%log4j-core' AND location LIKE 'docker:%'")
        self.assertEqual(len(log4j), 7)   # 2.14.1 < 2.15 … 2.21 dans la petite base de test

    @unittest.skipUnless(shutil.which("node"), "node absent")
    def test_rapport(self):
        from urllib.parse import quote
        host = "serveur/" + quote("APPV1|prod|srv-py01", safe="")
        views = json.loads(subprocess.check_output(["node", os.path.join(ROOT, "tests", "report_harness.js"),
                                                    os.path.join(self.out, "cmdb_rapport.html"), host + "?onglet=exposition", "logiciels?q=docker%3A",
                                                    "vulnerabilites?onglet=conteneurs"]).decode())
        page = " ".join(views.values())
        self.assertIn("Contenu des conteneurs en marche", page)
        self.assertIn("registry.exemple.test/app:1.0", page)
        self.assertIn("Debian GNU/Linux 12", page)
        self.assertIn("log4j-core", views["logiciels?q=docker%3A"])    # lien « Autres composants » : recherche par emplacement


if __name__ == "__main__":
    unittest.main()
