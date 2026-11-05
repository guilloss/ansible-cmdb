# -*- coding: utf-8 -*-
"""Exécution réelle des deux collecteurs sur une arborescence fabriquée."""
import base64
import gzip
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

from tests.common import COLLECTOR, SHELL_COLLECTOR
import cmdb_shell_parse

SECRET = "S3cr3tPw"
COMPS = """<PRD_LIST><TL_LIST><COMP NAME="oracle.server" VER="19.0.0.0.0" BUILD_NUMBER="0"><INST_TYPE NAME="EE"/></COMP></TL_LIST>
<ONEOFF_LIST><ONEOFF REF_ID="36233263" UNIQ_ID="1" ROLLBACK="T" INSTALL_TIME="2024.Jun.10 12:00:00 CEST">
<DESC>Database Release Update : 19.23.0.0.240416 (36233263)</DESC></ONEOFF></ONEOFF_LIST></PRD_LIST>"""
CONFIGS = {
    "app/application.properties": "spring.datasource.url=jdbc:postgresql://pg01.exemple.test:5433/appdb?user=a&password=%s\n"
                                  "spring.datasource.password=%s\n" % (SECRET, SECRET),
    "app/.env": "DB_CONNECTION=pgsql\nDB_HOST=pg02.exemple.test\nDB_PORT=5432\nDB_DATABASE=envdb\nDB_PASSWORD=%s\n" % SECRET,
    "app/conf/context.xml": '<Resource name="jdbc/x" url="jdbc:oracle:thin:scott/%s@//ora1.exemple.test:1521/svc" password="%s"/>\n' % (SECRET, SECRET),
    "app/wp-config.php": "<?php\ndefine('DB_NAME', 'wp');\ndefine('DB_PASSWORD', '%s');\ndefine('DB_HOST', 'my1.exemple.test:3307');\n" % SECRET,
    "app/database.yml": "production:\n  adapter: postgresql\n  host: pg03.exemple.test\n  port: 5432\n  database: railsdb\n  password: %s\n" % SECRET,
    "app/odbc.ini": "[x]\nDriver=PostgreSQL\nServername=pg04.exemple.test\nPort=5432\nDatabase=odbcdb\nPassword=%s\n" % SECRET,
    "app/uri.properties": "broker=postgres://u:%s@pg05.exemple.test/uridb\n" % SECRET,
    "app/samples/application.properties": "url=jdbc:postgresql://piege.exemple.test/x\n",
}
EXPECTED = {("postgresql", "pg01.exemple.test", 5433, "appdb"), ("postgresql", "pg02.exemple.test", 5432, "envdb"),
            ("oracle", "ora1.exemple.test", 1521, "svc"), ("mysql", "my1.exemple.test", 3307, "wp"),
            ("postgresql", "pg03.exemple.test", 5432, "railsdb"), ("postgresql", "pg04.exemple.test", 5432, "odbcdb"),
            ("postgresql", "pg05.exemple.test", None, "uridb"), ("oracle", "ora2.exemple.test", 1521, "tnssvc")}


class Fixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp(prefix="cmdbt")
        cls.home = os.path.join(cls.root, "orahome")
        for rel, text in CONFIGS.items():
            p = os.path.join(cls.root, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write(text)
        files = {"inventory/ContentsXML/comps.xml": COMPS, "OPatch/version.txt": "OPATCH_VERSION:12.2.0.1.41\n",
                 "network/admin/listener.ora": "LISTENER = (DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=ora1)(PORT=1521)))\n",
                 "network/admin/tnsnames.ora": "T = (DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=ora2.exemple.test)(PORT=1521))"
                                               "(CONNECT_DATA=(SERVICE_NAME=tnssvc)))\n",
                 "inventory/oneoffs/36233263/etc/config/inventory.xml": "<x/>", "dbs/initPROD.ora": ""}
        for rel, text in files.items():
            p = os.path.join(cls.home, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w") as f:
                f.write(text)
        # Vrai processus dont la ligne de commande désigne l'ORACLE_HOME
        os.makedirs(os.path.join(cls.home, "bin"))
        fake = os.path.join(cls.home, "bin", "tnslsnr")
        shutil.copy(shutil.which("sleep"), fake)
        cls.proc = subprocess.Popen([fake, "300"])

    @classmethod
    def tearDownClass(cls):
        cls.proc.kill()
        cls.proc.wait()
        shutil.rmtree(cls.root, ignore_errors=True)

    def check(self, doc):
        refs = (doc.get("filesystem") or {}).get("db_refs") or []
        got = set((r["engine"], r["host"], r["port"], r["database"]) for r in refs)
        self.assertEqual(got, EXPECTED)
        for r in refs:
            self.assertNotIn("/fs/", r["path"])
        homes = dict((h["home"], h) for h in (doc.get("oracle") or {}).get("homes") or [])
        h = homes[self.home]
        self.assertEqual((h["product"], h["version"], h["visibility"]), ("database", "19.0.0.0.0", "complet"))
        self.assertEqual(h["patches"][0]["id"], "36233263")
        self.assertIn("19.23.0.0.240416", h["patches"][0]["description"])
        self.assertEqual(h["configured_sids"], ["PROD"])
        self.assertEqual(h["listeners"][0]["port"], 1521)
        self.assertEqual(h["tns_refs"][0]["host"], "ora2.exemple.test")
        self.assertNotIn(SECRET, json.dumps(doc))


class Python(Fixture):
    def test_collecte(self):
        out = os.path.join(self.root, "out.json.gz")
        subprocess.check_call([sys.executable, COLLECTOR, "--scan-root", self.root, "--no-exec-probes", "-o", out,
                               "--host-label", "t", "--run-id", "r"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with gzip.open(out) as f:
            doc = json.loads(f.read().decode("utf-8"))
        os.remove(out)
        self.check(doc)


class Shell(Fixture):
    def run_with(self, argv):
        env = dict(os.environ, CMDB_TEST_SCAN_ROOT=self.root)
        out = subprocess.check_output(argv + [SHELL_COLLECTOR, "--no-exec-probes", "--host-label", "t", "--run-id", "r"],
                                      env=env, stderr=subprocess.DEVNULL).decode()
        b64 = out.split("CMDB-B64-BEGIN")[1].split("CMDB-B64-END")[0]
        raw = base64.b64decode(b64)
        with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
            for m in tf:
                if m.isfile():
                    self.assertNotIn(SECRET.encode(), tf.extractfile(m).read(), m.name)
        self.check(cmdb_shell_parse.convert(raw))

    def test_dash(self):
        self.run_with(["dash"])

    def test_bash(self):
        self.run_with(["bash"])

    def test_bash_posix(self):
        self.run_with(["bash", "--posix"])

    @unittest.skipUnless(shutil.which("busybox"), "busybox absent")
    def test_busybox(self):
        self.run_with(["busybox", "sh"])


if __name__ == "__main__":
    unittest.main()
