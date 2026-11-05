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
        key, crt = os.path.join(cls.root, "tls", "srv.key"), os.path.join(cls.root, "tls", "srv.crt")
        os.makedirs(os.path.dirname(key))
        subprocess.check_call(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", crt, "-days", "9",
                               "-subj", "/CN=t.exemple.test"], stderr=subprocess.DEVNULL)
        os.chmod(key, 0o644)
        with open(key) as f:
            cls.keyline = f.read().splitlines()[2]
        for name, pw in (("vide.p12", ""), ("prot.p12", "motdepasse")):
            subprocess.check_call(["openssl", "pkcs12", "-export", "-inkey", key, "-in", crt, "-out", os.path.join(cls.root, "tls", name),
                                   "-passout", "pass:" + pw])
        ferme = os.path.join(cls.root, "tls", "ferme.key")
        shutil.copy(key, ferme)
        os.chmod(ferme, 0)
        for rel, text in (("web/httpd.conf", "# LoadModule off_module x.so\nLoadModule ssl_module modules/mod_ssl.so\nServerAdmin a@b\n"),
                          ("nginx/modules.conf/nginx.conf", "load_module modules/ngx_stream_module.so;\n"),
                          ("web/php.ini", ";extension=off\nextension=mbstring\n"),
                          ("web/postgresql.conf", "shared_preload_libraries = 'pg_stat_statements'\n"),
                          ("web/redis.conf", "requirepass %s\n" % SECRET)):
            p = os.path.join(cls.root, rel)
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
        os.chmod(os.path.join(cls.root, "tls", "ferme.key"), 0o600)
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
        crypto = dict((os.path.basename(c["path"]), c) for c in doc["filesystem"]["crypto_files"])
        self.assertEqual(crypto["srv.key"]["has_private_key"], True)
        self.assertFalse(crypto["srv.key"]["encrypted"])
        self.assertEqual(crypto["srv.key"]["mode"], "0644")
        self.assertEqual(crypto["srv.crt"]["certs"][0]["cn"], "t.exemple.test")
        self.assertEqual(crypto["vide.p12"]["certs"][0]["cn"], "t.exemple.test")
        self.assertTrue(crypto["vide.p12"]["empty_password"])
        self.assertEqual(crypto["prot.p12"]["certs"], [])
        self.assertIn("mot de passe", crypto["prot.p12"]["note"])
        self.assertEqual(crypto["ferme.key"]["kind"], "illisible")
        self.assertNotIn(self.keyline, json.dumps(doc))
        eps = doc["filesystem"]["endpoints"]
        vh = [e for e in eps if e["kind"] == "vhost" and e["product"] == "apache"][0]
        self.assertEqual((vh["server_name"], vh["port"], vh["tls"]), ("www.exemple.test", 443, True))
        self.assertIn(("tomcat", 8443, True), [(e["product"], e.get("port"), e.get("tls")) for e in eps if e["kind"] == "connector"])
        self.assertIn(("nginx", "app.exemple.test"), [(e["product"], e.get("server_name")) for e in eps])
        self.assertIn("10.0.0.2:8080", [e.get("backend") for e in eps])
        mods = set((m["product"], m["module"]) for m in doc["filesystem"]["service_modules"])
        self.assertEqual(mods, {("apache", "ssl_module"), ("nginx", "ngx_stream_module"), ("php", "mbstring"),
                                ("postgresql", "pg_stat_statements")})


class PhpFilter(unittest.TestCase):
    def test_parite_shell(self):
        from tests.test_endpoints import Phpinfo
        src = open(SHELL_COLLECTOR, encoding="utf-8").read()
        fn = src[src.index("php_filter() {"):src.index("section_probes() {")]
        for shell in ("dash", "bash"):
            out = subprocess.run([shell, "-c", fn + "\nphp_filter"], input=Phpinfo.T.encode(), stdout=subprocess.PIPE).stdout.decode()
            self.assertNotIn("S3cr3t", out)
            self.assertNotIn("mdp", out)
            self.assertIn("memory_limit => 128M", out)
            self.assertIn("mysql.default_password => ***", out)
            self.assertIn("PHP License", out)


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
                    data = tf.extractfile(m).read()
                    self.assertNotIn(SECRET.encode(), data, m.name)
                    self.assertNotIn(self.keyline.encode(), data, m.name)
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
