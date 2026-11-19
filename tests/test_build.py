# -*- coding: utf-8 -*-
"""Consolidation complète d'un parc fictif."""
import datetime as dt
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

from tests import fleet
from tests.common import TOOLS, C
import cmdb_extras as X


class Parc(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="cmdbb")
        store = os.path.join(cls.d, "store")
        old = fleet.oracle_host("r1", "2026-10-01T08:00:00Z", "19.21.0.0.231017", "35643107")
        old_app = fleet.app_host("r1", "2026-10-01T08:00:00Z")
        old_app["filesystem"]["crypto_files"] = []
        old_app["network"]["listening"] = []
        fleet.write_store(store, [old, old_app, fleet.oracle_host(), fleet.app_host(), fleet.pg_host(), fleet.pg_standby()])
        out = os.path.join(cls.d, "build")
        cls.log = subprocess.check_output([sys.executable, os.path.join(TOOLS, "cmdb_build.py"), "--store", store, "--out", out],
                                          stderr=subprocess.STDOUT).decode()
        cls.db = sqlite3.connect(os.path.join(out, "cmdb.sqlite"))
        cls.out = out

    @classmethod
    def tearDownClass(cls):
        cls.db.close()
        shutil.rmtree(cls.d, ignore_errors=True)

    def q(self, sql, *a):
        return self.db.execute(sql, a).fetchall()

    def test_homes_oracle(self):
        r = self.q("SELECT product, edition, patch_level, patch_date, opatch_version, in_use FROM oracle_homes WHERE home = ?", fleet.ORA_HOME)[0]
        self.assertEqual(r, ("database", "Enterprise", "19.23.0.0.240416", "2024-04-16", "12.2.0.1.41", 1))
        self.assertEqual(self.q("SELECT visibility, version FROM oracle_homes WHERE home = ?", fleet.ORA_OLD)[0], ("aucun", "12.2.0"))
        self.assertEqual(len(self.q("SELECT * FROM v_oracle_patch_unknown")), 1)
        self.assertEqual(len(self.q("SELECT * FROM v_oracle_patch_late")), 1)

    def test_patchs(self):
        kinds = dict(self.q("SELECT patch_id, kind FROM oracle_patches"))
        self.assertEqual(kinds, {"36233263": "ru", "36199232": "ojvm"})

    def test_matrice_et_recherche(self):
        r = self.q("SELECT version, cpe FROM software WHERE family = 'oracle-database'")
        self.assertEqual(r[0][0], "19.23.0.0.240416")
        self.assertIn("database_server", r[0][1])

    def test_instances(self):
        r = dict((x[0], x[1:]) for x in self.q("SELECT instance, status, home, ports, role FROM db_instances WHERE engine = 'oracle'"))
        self.assertEqual(r["PROD"], ("démarrée", fleet.ORA_HOME, "1521", "primaire"))
        self.assertEqual(r["ARCH"][0], "arrêtée")

    def test_instances_postgresql(self):
        r = dict((x[0], x[1:]) for x in self.q("SELECT host, version, ports, role, datadir FROM db_instances WHERE engine = 'postgresql'"))
        self.assertEqual(r["pg1.exemple.test"], ("14", "5432", "primaire", "/var/lib/pgsql/14/data"))
        self.assertEqual(r["pg2.exemple.test"][2], "standby")

    def test_licence(self):
        r = self.q("SELECT editions, cores, core_factor, processor_licences_indicative, partitioning FROM oracle_licence")[0]
        self.assertEqual(r, ("Enterprise", 8, 0.5, 4, "partitionnement logiciel"))

    def link(self, client, server):
        return self.q("SELECT engine, port, database, db_user, status, sources FROM db_links WHERE client_host = ? AND server_host = ?", client, server)

    def test_lien_postgresql_toutes_sources(self):
        r = self.link("app1.exemple.test", "pg1.exemple.test")
        full = [x for x in r if x[2] == "appdb"][0]
        self.assertEqual(full[:5], ("postgresql", 5432, "appdb", "appuser", "actif"))
        self.assertEqual(full[5], "configuration, connexion, processus")

    def test_lien_par_nom_resolu(self):
        self.assertIn("rep", [x[2] for x in self.link("app1.exemple.test", "pg1.exemple.test")])

    def test_lien_oracle_par_alias_tns(self):
        r = self.link("app1.exemple.test", "ora1.exemple.test")
        self.assertEqual([(x[0], x[1], x[2], x[4]) for x in r], [("oracle", 1521, "prod.svc", "actif")])

    def test_client_hors_inventaire(self):
        r = self.q("SELECT client_addr, server_host, engine FROM db_links WHERE client_host IS NULL")
        self.assertIn(("10.9.9.9", "ora1.exemple.test", "oracle"), r)

    def test_serveur_hors_inventaire(self):
        r = self.q("SELECT server_addr, engine, status FROM db_links WHERE server_host IS NULL AND client_host = 'app1.exemple.test'")
        self.assertEqual(r, [("my9.exemple.test", "mysql", "configuré")])

    def test_replication(self):
        r = self.q("SELECT client_host, server_host, db_user FROM db_links WHERE link_type = 'réplication'")
        self.assertEqual(r, [("pg2.exemple.test", "pg1.exemple.test", "repl")])

    def test_modules(self):
        r = self.q("SELECT product, module, source FROM service_modules ORDER BY 1, 2")
        self.assertIn(("apache", "ssl_module", "configuration"), r)
        self.assertIn(("php", "mbstring", "php -m"), r)

    def test_endpoints(self):
        r = self.q("SELECT product, kind, port, server_name, location FROM endpoints ORDER BY kind, location")
        self.assertIn(("apache", "vhost", 443, "www.exemple.test", None), r)
        self.assertIn(("tomcat", "context", None, None, "/gestion"), r)
        self.assertIn(("tomcat", "context", None, None, "/"), r)

    def test_cles(self):
        r = [x[0] for x in self.q("SELECT path FROM v_private_keys_exposed")]
        self.assertEqual(r, ["/etc/pki/tls/private/www.key"])
        self.assertEqual(len(self.q("SELECT * FROM v_private_keys")), 2)
        self.assertEqual(self.q("SELECT cn FROM v_certs_expiring")[0][0], "www.exemple.test")

    def test_runtime_services(self):
        r = self.q("SELECT port, runtime, app_ref, options, exposed FROM runtime_services")[0]
        self.assertEqual(r, (8080, "java", "org.apache.catalina.startup.Bootstrap", "-Xmx2g -Dcatalina.base=/opt/tomcat", 1))

    def test_phpinfo(self):
        self.assertEqual(self.q("SELECT value FROM runtime_settings WHERE key = 'expose_php'")[0][0], "On")
        self.assertEqual(self.q("SELECT section FROM runtime_settings WHERE key = 'Multibyte Support'")[0][0], "mbstring")

    def test_evolutions(self):
        r = self.q("SELECT host, kind, change, item, before, after FROM changes ORDER BY 1, 2, 3, 4")
        self.assertIn(("ora1.exemple.test", "correctif Oracle", "ajout", fleet.ORA_HOME + " 36233263", None,
                       "Database Release Update : 19.23.0.0.240416 (36233263)"), r)
        self.assertIn(("ora1.exemple.test", "ORACLE_HOME", "modification", fleet.ORA_HOME, "19.21.0.0.231017", "19.23.0.0.240416"), r)
        self.assertIn(("app1.exemple.test", "port", "ajout", "tcp 0.0.0.0 8080", None, "java"), r)
        self.assertIn("clé ou certificat", [x[1] for x in r])

    def test_pas_d_evolution_sans_historique(self):
        self.assertEqual(self.q("SELECT COUNT(*) FROM changes WHERE host LIKE 'pg%'")[0][0], 0)

    def test_fin_de_support(self):
        r = dict((x[0], x[1:]) for x in self.q("SELECT product, cycle, status FROM eol_status WHERE host = 'ora1.exemple.test'"))
        self.assertEqual(r["rhel"], ("8", "supporté"))
        self.assertEqual(r["oracle-database"][0], "19")
        self.assertEqual(self.q("SELECT COUNT(*) FROM eol_reference")[0][0] > 300, True)

    def test_csv_et_sortie(self):
        self.assertTrue(os.path.exists(os.path.join(self.out, "csv", "db_links.csv")))
        self.assertIn("Liens vers bases", self.log)


class Unitaires(unittest.TestCase):
    def test_noms_de_certificat(self):
        self.assertTrue(X.cert_matches("a.exemple.test", "*.exemple.test", None))
        self.assertFalse(X.cert_matches("a.b.exemple.test", "*.exemple.test", None))
        self.assertTrue(X.cert_matches("www.exemple.test", "autre", "x www.exemple.test"))
        self.assertFalse(X.cert_matches("www.exemple.test", "autre", ""))

    def test_correctifs(self):
        self.assertEqual(X.classify_patch("Database Release Update : 19.23.0.0.240416 (36233263)"), ("ru", "19.23.0.0.240416", "2024-04-16"))
        self.assertEqual(X.classify_patch("Database Patch Set Update : 12.1.0.2.190716 (29494060)")[0], "psu")
        self.assertEqual(X.classify_patch("GI Release Update Revision 19.5.1.0.200114")[0], "rur")
        self.assertEqual(X.classify_patch("OCW RELEASE UPDATE 19.23.0.0.0 (36240578)")[0], "ocw")
        self.assertEqual(X.classify_patch("JDK BUNDLE PATCH 19.0.0.0.240416")[0], "jdk")
        self.assertEqual(X.classify_patch("fix for bug 123")[0], "oneoff")
        self.assertEqual(X.classify_patch(None)[0], "inconnu")

    def test_cycles(self):
        self.assertEqual(X.cycle_of(["14", "15", "9.6"], "14.5"), "14")
        self.assertEqual(X.cycle_of(["9.6", "9"], "9.6.24"), "9.6")
        self.assertIsNone(X.cycle_of(["14"], "144"))
        self.assertEqual(X.aix_cycle("7300-02-03-2419"), "7.3.2")

    def test_eol_expiree(self):
        db = sqlite3.connect(":memory:")
        import cmdb_build
        db.executescript(cmdb_build.SCHEMA)
        db.execute("INSERT INTO hosts (app, platform, host, os_id, os_version) VALUES ('a', 'p', 'h', 'centos', '6.10')")
        db.execute("INSERT INTO software (app, platform, host, category, family, version, location, managed) VALUES ('a','p','h','runtime','aix','7300-02-03-2419','/',1)")
        X.build_eol(db, dt.date(2026, 11, 5))
        r = dict(db.execute("SELECT product, status FROM eol_status").fetchall())
        self.assertEqual(r["centos"], "expiré")
        self.assertEqual(r["aix"], "bientôt")


if __name__ == "__main__":
    unittest.main()


class DistributionJava(unittest.TestCase):
    """software.distribution : éditeur des Java, d'après le fichier release, la JVM, le paquet ou le chemin."""

    def test_classement(self):
        import cmdb_build as B
        d = lambda *a, **k: B.java_distribution(*a, **k)[0]
        self.assertEqual(d({"implementor": "Eclipse Adoptium", "implementor_version": "Temurin-21.0.2+13"}), "Eclipse Temurin")
        self.assertEqual(d({"implementor": "Azul Systems, Inc."}), "Azul Zulu")
        self.assertEqual(d({"implementor": "Amazon.com Inc."}), "Amazon Corretto")
        self.assertEqual(d({"vendor": "IBM Corporation", "vm": "IBM J9 VM"}), "IBM Semeru / J9")
        self.assertEqual(d({"vendor": "Red Hat, Inc.", "vm": "OpenJDK 64-Bit Server VM"}), "OpenJDK Red Hat")
        # Oracle JDK : seulement sur preuve du JDK commercial
        self.assertEqual(d({"implementor": "Oracle Corporation", "build_type": "commercial"}), "Oracle JDK")
        self.assertEqual(d({"vendor": "Oracle Corporation", "vm": "Java HotSpot(TM) 64-Bit Server VM"}), "Oracle JDK")
        self.assertEqual(d({"runtime_name": "Java(TM) SE Runtime Environment"}), "Oracle JDK")
        self.assertEqual(d({}, "jdk-17", "Oracle Corporation", "rhel"), "Oracle JDK")
        self.assertEqual(d({}, "jdk1.8", None, "rhel"), "Oracle JDK")
        # « Oracle Corporation » seul, ou build OpenJDK : pas Oracle JDK
        self.assertEqual(d({"implementor": "Oracle Corporation"}), "Oracle (JDK ou OpenJDK ?)")
        self.assertEqual(d({"implementor": "Oracle Corporation"}, "java-17-openjdk-headless", "Oracle America", "ol"), "OpenJDK Oracle Linux")
        self.assertEqual(d({"implementor": "Oracle Corporation"}, "java-1.8.0-openjdk-headless", None, "centos"), "OpenJDK CentOS")
        self.assertEqual(d({"vendor": "Oracle Corporation", "vm": "OpenJDK 64-Bit Server VM"}), "Oracle OpenJDK")
        self.assertEqual(d({"implementor": "Oracle Corporation", "build_type": "release"}), "Oracle OpenJDK")
        self.assertEqual(d({}, "java-17-openjdk-headless", None, "rocky"), "OpenJDK Rocky")
        self.assertEqual(d({}, "openjdk-17-jre-headless", None, "debian"), "OpenJDK Debian")
        self.assertEqual(d({}, "temurin-17-jdk"), "Eclipse Temurin")
        self.assertEqual(d({}, "Java8_64.sdk"), "IBM Semeru / J9")
        self.assertEqual(d({}, location="/opt/zulu17"), "Azul Zulu")
        self.assertEqual(d({"vendor": "Private Build", "vm": "OpenJDK 64-Bit Server VM"}), "OpenJDK (éditeur inconnu)")
        self.assertEqual(d({}, location="/opt/jdk1.8.0_401"), "Inconnue")
        # la preuve est gardée
        self.assertEqual(B.java_distribution({"implementor": "Oracle Corporation", "build_type": "commercial"})[1],
                         "release : IMPLEMENTOR=Oracle Corporation, BUILD_TYPE=commercial")
        self.assertEqual(B.java_distribution({}, "jdk-17", "Oracle Corporation")[1], "paquet jdk-17 (éditeur Oracle Corporation)")

    def test_licence(self):
        import cmdb_build as B
        L = B.oracle_jdk_licence
        self.assertEqual(L("1.8.0_202"), "gratuit (BCL)")
        self.assertEqual(L("1.8.0_211"), "payant en production (OTN)")
        self.assertEqual(L("2000:1.8.0_401-fcs"), "payant en production (OTN)")
        self.assertEqual(L("11.0.22"), "payant en production (OTN)")
        self.assertEqual(L("17.0.12"), "gratuit (NFTC)")
        self.assertEqual(L("17.0.13+10"), "payant en production (OTN)")
        self.assertEqual(L("21.0.12"), "gratuit (NFTC)")
        self.assertEqual(L("21.0.13"), "payant en production (OTN)")
        self.assertEqual(L("22.0.1"), "gratuit (NFTC)")
        self.assertEqual(L("1.7.0_80"), "gratuit (BCL)")
        self.assertEqual(L("1.7.0_351"), "support Oracle (mise à jour non publique)")
        self.assertEqual(L("x"), "à vérifier")

    def test_base(self):
        d = tempfile.mkdtemp(prefix="cmdbj")
        self.addCleanup(shutil.rmtree, d, True)
        a = fleet.app_host()
        a["packages"]["managers"]["rpm"] = [
            {"name": "java-17-openjdk-headless", "epoch": "1", "version": "17.0.9.0.9", "release": "2.el8", "arch": "x86_64"},
            {"name": "jdk-17", "version": "17.0.10", "release": "ga", "arch": "x86_64", "vendor": "Oracle Corporation"},
            {"name": "bash", "version": "4.4", "release": "1.el8", "arch": "x86_64"}]
        a["filesystem"]["jdk_homes"] = [{"path": "/opt/temurin-21", "release": {"JAVA_VERSION": "21.0.2", "IMPLEMENTOR": "Eclipse Adoptium"}},
                                        {"path": "/opt/jdk1.8.0_401", "release": {"JAVA_VERSION": "1.8.0_401", "IMPLEMENTOR": "Oracle Corporation", "BUILD_TYPE": "commercial"}}]
        o = fleet.oracle_host()
        o["filesystem"] = {"jdk_homes": [{"path": fleet.ORA_HOME + "/jdk", "release": {"JAVA_VERSION": "1.8.0_201", "IMPLEMENTOR": "Oracle Corporation", "BUILD_TYPE": "commercial"}}]}
        fleet.write_store(os.path.join(d, "store"), [a, o])
        subprocess.check_call([sys.executable, os.path.join(TOOLS, "cmdb_build.py"), "--store", os.path.join(d, "store"), "--out", os.path.join(d, "b")],
                              stdout=subprocess.DEVNULL)
        db = sqlite3.connect(os.path.join(d, "b", "cmdb.sqlite"))
        got = dict(db.execute("SELECT name, distribution FROM software WHERE name IN ('java-17-openjdk-headless', 'jdk-17', 'bash', 'php') "
                              "OR location = '/opt/temurin-21'"))
        proof = db.execute("SELECT distribution_evidence FROM software WHERE name = 'jdk-17'").fetchone()[0]
        lic = dict(db.execute("SELECT CASE WHEN category = 'os-package' THEN name ELSE location END, java_licence FROM software WHERE family = 'java'"))
        db.close()
        self.assertEqual(got, {"java-17-openjdk-headless": "OpenJDK Red Hat", "jdk-17": "Oracle JDK", "jdk-home": "Eclipse Temurin",
                               "bash": None, "php": None})
        self.assertEqual(proof, "paquet jdk-17 (éditeur Oracle Corporation)")
        self.assertEqual(lic["jdk-17"], "gratuit (NFTC)")                    # 17.0.10
        self.assertEqual(lic["/opt/jdk1.8.0_401"], "payant en production (OTN)")
        self.assertEqual(lic[fleet.ORA_HOME + "/jdk"], "embarqué : database (%s)" % fleet.ORA_HOME)
        self.assertIsNone(lic["/opt/temurin-21"])


class Processeurs(unittest.TestCase):
    """Table cpus : identifiants, niveau x86-64 et extensions notables."""
    V4 = ("fpu sse2 lm cx16 lahf_lm popcnt sse4_1 sse4_2 ssse3 avx avx2 bmi1 bmi2 f16c fma abm movbe xsave "
          "avx512f avx512bw avx512cd avx512dq avx512vl avx512_vnni aes hypervisor")

    def test_resume(self):
        import cmdb_build as B
        lvl, nb = B.cpu_summary(self.V4.split())
        self.assertEqual(lvl, "x86-64-v4")
        self.assertIn("avx512 (f bw cd dq vl vnni)", nb)
        self.assertEqual(B.cpu_summary("fpu sse2 lm sse4_2 avx avx2".split())[0], "x86-64")
        self.assertEqual(B.cpu_summary("fp asimd aes sha2 atomics".split()), (None, "aes, sha2, atomics"))

    def test_base(self):
        d = tempfile.mkdtemp(prefix="cmdbc")
        self.addCleanup(shutil.rmtree, d, True)
        a = fleet.app_host()
        a["hardware"]["cpu"] = {"count": 8, "model name": "Intel(R) Xeon(R) Gold 6248", "vendor_id": "GenuineIntel", "cpu family": "6",
                                "model": "85", "stepping": "7", "microcode": "0x5003604", "flags": self.V4}
        w = fleet.pg_host()
        w["hardware"]["cpu"] = {"count": 4, "model name": "Intel(R) Xeon(R) Silver", "vendor_id": "GenuineIntel", "cpu family": "6",
                                "model": "85", "stepping": "4", "flags": "sse3 ssse3 sse4_1 sse4_2 avx avx2 avx512f",
                                "flags_source": "IsProcessorFeaturePresent (partiel)"}
        fleet.write_store(os.path.join(d, "store"), [a, w, fleet.web_host()])
        subprocess.check_call([sys.executable, os.path.join(TOOLS, "cmdb_build.py"), "--store", os.path.join(d, "store"), "--out", os.path.join(d, "b")],
                              stdout=subprocess.DEVNULL)
        db = sqlite3.connect(os.path.join(d, "b", "cmdb.sqlite"))
        got = {r[0]: r[1:] for r in db.execute("SELECT host, family, model, stepping, microcode, isa_level, flags_source FROM cpus")}
        db.close()
        self.assertEqual(got["app1.exemple.test"], ("6", "85", "7", "0x5003604", "x86-64-v4", "/proc/cpuinfo"))
        self.assertIsNone(got["pg1.exemple.test"][4])   # liste partielle : pas de niveau
        self.assertNotIn("web1.exemple.test", got)       # rien de collecté sur le processeur


class ServicesSysteme(unittest.TestCase):
    """Services systemd, SysV, SRC et Windows ; lien service -> composant sans collecte privilégiée."""

    @classmethod
    def setUpClass(cls):
        import gzip as _gz
        import json as _json
        import sqlite3 as _sq
        import subprocess as _sp
        import tempfile as _tf
        from tests import fleet
        from tests.common import TOOLS
        cls.dir = _tf.mkdtemp(prefix="cmdbsvc")

        def probe(v, path):
            return {"probe": "postgresql", "realpath": path, "paths": [path],
                    "outputs": [{"args": [path, "--version"], "rc": 0, "output": "postgres (PostgreSQL) %s.1" % v}]}
        # collecte non privilégiée : exécutables des processus illisibles (exe vide)
        sysd = fleet.doc("sd1.exemple.test", "APP", "prod", "10.0.0.1", "r1", "2026-11-12T08:00:00Z",
                         runtimes={"list": [probe("13", "/usr/lib/postgresql/13/bin/postgres"), probe("15", "/usr/lib/postgresql/15/bin/postgres"),
                                            probe("16", "/opt/pg16/bin/postgres")]},
                         processes=[{"pid": 10, "ppid": 1, "comm": "postgres", "user": "postgres", "systemd_unit": "postgresql@15-main.service",
                                     "cmdline": "/usr/lib/postgresql/15/bin/postgres -D /var/lib/postgresql/15/main"},
                                    {"pid": 11, "ppid": 10, "comm": "postgres", "user": "postgres", "systemd_unit": "postgresql@15-main.service",
                                     "cmdline": "postgres: 15/main: checkpointer"},
                                    {"pid": 20, "ppid": 1, "comm": "postgres", "user": "pg16", "systemd_unit": "pg16.service",
                                     "cmdline": "postgres: main"}],
                         services={"units": [
                             {"unit": "postgresql@15-main.service", "load": "loaded", "active": "active", "sub": "running", "description": "PostgreSQL 15"},
                             {"unit": "pg16.service", "load": "loaded", "active": "active", "sub": "running", "description": "PG 16"},
                             {"unit": "casse.service", "load": "loaded", "active": "failed", "sub": "failed", "description": "En panne"},
                             {"unit": "arrete.service", "load": "loaded", "active": "inactive", "sub": "dead", "description": "Arrêté"},
                             {"unit": "ponctuel.service", "load": "loaded", "active": "inactive", "sub": "dead", "description": "Oneshot"},
                             {"unit": "inutile.service", "load": "loaded", "active": "inactive", "sub": "dead", "description": "Désactivé"}],
                             "unit_files": [{"unit": "arrete.service", "state": "enabled"}, {"unit": "ponctuel.service", "state": "enabled"},
                                            {"unit": "inutile.service", "state": "disabled"}],
                             "service_details": [
                                 {"Id": "postgresql@15-main.service", "MainPID": "10", "User": "postgres",
                                  "ExecStart": "{ path=/usr/bin/pg_ctlcluster ; argv[]=/usr/bin/pg_ctlcluster --skip-systemctl-redirect 15-main start ; }"},
                                 {"Id": "pg16.service", "MainPID": "20", "Type": "notify",
                                  "ExecStart": "{ path=/opt/pg16/bin/postgres ; argv[]=/opt/pg16/bin/postgres -D /data/pg16 ; }"},
                                 {"Id": "arrete.service", "MainPID": "0", "Type": "simple"},
                                 {"Id": "ponctuel.service", "MainPID": "0", "Type": "oneshot"}]})
        sysv = fleet.doc("sv1.exemple.test", "APP", "prod", "10.0.0.2", "r1", "2026-11-12T08:00:00Z",
                         processes=[{"pid": 30, "ppid": 1, "comm": "httpd", "user": "root", "cmdline": "/usr/sbin/httpd"},
                                    {"pid": 31, "ppid": 30, "comm": "httpd", "user": "apache", "cmdline": "/usr/sbin/httpd"},
                                    {"pid": 40, "ppid": 1, "comm": "sshd", "user": "root", "cmdline": "/usr/sbin/sshd"}],
                         services={"chkconfig": "httpd          0:off 1:off 2:on 3:on 4:on 5:on 6:off\n"
                                                "crond          0:off 1:off 2:on 3:on 4:on 5:on 6:off\n"
                                                "iptables       0:off 1:off 2:off 3:off 4:off 5:off 6:off\n",
                                   "rc_links": {"/etc/rc.d/rc3.d": ["S55sshd", "K10netconsole"]},
                                   "pid_files": {"/var/run/httpd/httpd.pid": 30, "/var/run/crond.pid": 999}})
        aix = fleet.doc("ax1.exemple.test", "APP", "prod", "10.0.0.3", "r1", "2026-11-12T08:00:00Z",
                        services={"lssrc": "Subsystem         Group            PID          Status\n"
                                           " syslogd          ras              3932356      active\n"
                                           " sendmail         mail                          inoperative\n"})
        win = fleet.doc("wn1.exemple.test", "APP", "prod", "10.0.0.4", "r1", "2026-11-12T08:00:00Z",
                        windows={"services": [
                            {"name": "Spooler", "display_name": "Spouleur", "state": "Running", "start_mode": "Auto", "pid": 500,
                             "path": "C:\\Windows\\System32\\spoolsv.exe", "account": "LocalSystem"},
                            {"name": "wuauserv", "display_name": "Windows Update", "state": "Stopped", "start_mode": "Manual", "pid": 0,
                             "path": "C:\\Windows\\system32\\svchost.exe -k netsvcs", "account": "LocalSystem"}]})
        for name, d in (("sd1", sysd), ("sv1", sysv), ("ax1", aix), ("wn1", win)):
            p = os.path.join(cls.dir, "store", "APP", "prod", name, "r1.json.gz")
            os.makedirs(os.path.dirname(p))
            with _gz.open(p, "wt") as f:
                _json.dump(d, f)
        out = os.path.join(cls.dir, "b")
        _sp.check_call([sys.executable, os.path.join(TOOLS, "cmdb_build.py"), "--store", os.path.join(cls.dir, "store"), "--out", out,
                        "--no-dossiers"], stdout=_sp.DEVNULL)
        cls.out = out
        cls.db = _sq.connect(os.path.join(out, "cmdb.sqlite"))

    @classmethod
    def tearDownClass(cls):
        import shutil as _sh
        cls.db.close()
        _sh.rmtree(cls.dir, True)

    def svc(self, host):
        return dict((r[0], r[1:]) for r in self.db.execute(
            "SELECT unit, kind, active, sub, unit_file_state, main_pid, software, software_location FROM services WHERE host = ?",
            (host + ".exemple.test",)))

    def test_systemd_composant(self):
        s = self.svc("sd1")
        self.assertIn("15.1", s["postgresql@15-main.service"][5])
        self.assertEqual(s["postgresql@15-main.service"][6], "/usr/lib/postgresql/15/bin/postgres")
        self.assertEqual(s["pg16.service"][6], "/opt/pg16/bin/postgres")
        self.assertEqual(s["arrete.service"][0], "systemd")
        self.assertIsNone(s["casse.service"][5])

    def test_service_marque_le_composant_en_cours(self):
        # pg16 : exécutable illisible et ligne de commande sans chemin ; seul ExecStart le désigne
        run = dict(self.db.execute("SELECT location, running FROM software WHERE host = 'sd1.exemple.test' AND category = 'runtime' "
                                   "AND location LIKE '%postgres'"))
        self.assertEqual(run["/opt/pg16/bin/postgres"], 1)
        self.assertEqual(run["/usr/lib/postgresql/15/bin/postgres"], 1)
        self.assertIsNone(run["/usr/lib/postgresql/13/bin/postgres"])

    def test_sysv(self):
        s = self.svc("sv1")
        self.assertEqual(s["httpd"][:5], ("sysv", "active", "running", "enabled", 30))
        self.assertEqual(s["crond"][1:3], ("inactive", "fichier PID périmé"))
        self.assertEqual(s["iptables"][1:4], (None, None, "disabled"))
        self.assertEqual(s["sshd"][1], "active")      # lien S55sshd, processus du même nom
        self.assertNotIn("netconsole", s)

    def test_aix_src(self):
        s = self.svc("ax1")
        self.assertEqual(s["syslogd"][:2], ("src", "active"))
        self.assertEqual(s["syslogd"][4], 3932356)
        self.assertEqual(s["sendmail"][1:3], ("inactive", "inoperative"))

    def test_windows(self):
        s = self.svc("wn1")
        self.assertEqual(s["Spooler"][:5], ("windows", "active", "running", "enabled", 500))
        self.assertEqual(s["wuauserv"][1:4], ("inactive", "stopped", "manual"))

    def test_rapport(self):
        import base64 as _b64
        import gzip as _gz
        import json as _json
        import re as _re
        with open(os.path.join(self.out, "cmdb_rapport.html"), encoding="utf-8") as f:
            html = f.read()
        m = _re.search(r'id="cmdb-data">([^<]+)<', html)
        data = _json.loads(_gz.decompress(_b64.b64decode(m.group(1))))
        cols = data["services"]["cols"]
        units = [r[cols.index("unit")] for r in data["services"]["rows"]]
        self.assertIn("software", cols)
        self.assertIn("casse.service", units)
        self.assertIn("arrete.service", units)
        self.assertNotIn("inutile.service", units)   # arrêté et non activé : pas exporté


class EnCoursDExecution(unittest.TestCase):
    """Plusieurs PostgreSQL installés, un seul lancé : software.running le distingue."""

    def test_postgresql_lance(self):
        import gzip as _gz
        import json as _json
        import sqlite3 as _sq
        import subprocess as _sp
        import shutil as _sh
        import tempfile as _tf
        from tests import fleet
        from tests.common import TOOLS
        d = _tf.mkdtemp(prefix="cmdbrun")
        self.addCleanup(_sh.rmtree, d, True)

        def probe(v, path, tool="postgres"):
            return {"probe": "postgresql", "realpath": path, "paths": [path], "owner_pkg": "postgresql-%s" % v,
                    "outputs": [{"args": [path, "--version"], "rc": 0, "output": "%s (PostgreSQL) %s.1" % (tool, v)}]}
        runtimes = {"list": [probe(v, "/usr/lib/postgresql/%s/bin/postgres" % v) for v in ("9.6", "12", "15")]}
        procs = [{"pid": 10, "ppid": 1, "comm": "postgres", "user": "postgres", "exe": "/usr/lib/postgresql/15/bin/postgres",
                  "exe_owner_pkg": "postgresql-15",
                  "cmdline": "/usr/lib/postgresql/15/bin/postgres -D /var/lib/postgresql/15/main"},
                 {"pid": 11, "ppid": 1, "comm": "sshd", "user": "root", "exe": "/usr/sbin/sshd", "cmdline": "sshd: /usr/sbin/sshd -D"}]
        doc = fleet.doc("db9.exemple.test", "APP", "prod", "10.0.0.9", "r1", "2026-11-12T08:00:00Z",
                        runtimes=runtimes, processes=procs,
                        packages={"managers": {"dpkg": [{"name": "postgresql-%s" % v, "version": "%s.1-1" % v, "arch": "amd64"}
                                                        for v in ("9.6", "12", "15")]}})
        p = os.path.join(d, "store", "APP", "prod", "db9", "r1.json.gz")
        os.makedirs(os.path.dirname(p))
        with _gz.open(p, "wt") as f:
            _json.dump(doc, f)
        out = os.path.join(d, "b")
        _sp.check_call([sys.executable, os.path.join(TOOLS, "cmdb_build.py"), "--store", os.path.join(d, "store"), "--out", out,
                        "--no-report", "--no-dossiers"], stdout=_sp.DEVNULL)
        db = _sq.connect(os.path.join(out, "cmdb.sqlite"))
        got = dict(db.execute("SELECT location, running FROM software WHERE category = 'runtime' AND family = 'postgresql'"))
        self.assertEqual(got, {"/usr/lib/postgresql/9.6/bin/postgres": 0, "/usr/lib/postgresql/12/bin/postgres": 0,
                               "/usr/lib/postgresql/15/bin/postgres": 1})
        pk = dict(db.execute("SELECT name, running FROM software WHERE category = 'os-package' AND name LIKE 'postgresql-%'"))
        self.assertEqual(pk.get("postgresql-15"), 1)
        self.assertIsNone(pk.get("postgresql-9.6"))
        db.close()

    def test_exe_illisible_reste_inconnu(self):
        from cmdb_build import Builder
        b = Builder(None)
        b.rows = {"processes": [("A", "p", "h", 1, 0, "pg", "postgres", None, None, "postgres: checkpointer", None, None, None, 0)],
                  "software": [("A", "p", "h", "runtime", "generic", "postgresql", "postgres", "12.1", "/usr/lib/postgresql/12/bin/postgres",
                                "exec:", None, 0, None, None, None)]}
        b.mark_running()
        self.assertIsNone(b.rows["software"][0][15])


class BaseAncienne(unittest.TestCase):
    """Nouveau rapport sur une base d'une version précédente : colonnes, tables et vues absentes lues comme vides."""

    def test_rapport_sur_base_ancienne(self):
        import hashlib
        import shutil as _sh
        import sqlite3 as _sq
        import subprocess as _sp
        import tempfile as _tf
        from tests import fleet
        from tests.common import TOOLS
        d = _tf.mkdtemp(prefix="cmdbold")
        self.addCleanup(_sh.rmtree, d, True)
        store, out = os.path.join(d, "store"), os.path.join(d, "b")
        fleet.write_store(store, [fleet.pg_host(), fleet.app_host()])
        _sp.check_call([sys.executable, os.path.join(TOOLS, "cmdb_build.py"), "--store", store, "--out", out,
                        "--no-report", "--no-dossiers"], stdout=_sp.DEVNULL)
        dbp = os.path.join(out, "cmdb.sqlite")
        db = _sq.connect(dbp)
        db.executescript("""
            DROP VIEW v_unmanaged_software;
            CREATE TABLE services_old AS SELECT app, platform, host, unit, load, active, sub, unit_file_state, main_pid,
              exec_start, user, fragment_path, description FROM services;
            DROP TABLE services; ALTER TABLE services_old RENAME TO services;
            DROP TABLE container_images;""")
        db.commit()
        db.close()
        with open(dbp, "rb") as f:
            before = hashlib.sha1(f.read()).hexdigest()
        r = _sp.run([sys.executable, os.path.join(TOOLS, "cmdb_report.py"), dbp, os.path.join(d, "r.html")],
                    stdout=_sp.PIPE, stderr=_sp.PIPE, universal_newlines=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("services.kind", r.stderr)
        self.assertIn("container_images", r.stderr)
        self.assertTrue(os.path.getsize(os.path.join(d, "r.html")) > 10000)
        with open(dbp, "rb") as f:
            self.assertEqual(hashlib.sha1(f.read()).hexdigest(), before)


class Reglages(unittest.TestCase):
    """config_settings : php -i effectif, php.ini des jeux sans binaire, pools PHP-FPM, directives Apache et nginx."""

    def test_parseur(self):
        P = C.parse_directives
        self.assertEqual(C.directive_product("/etc/php/8.2/apache2/conf.d/90-local.ini", "90-local.ini"), "php")
        self.assertEqual(C.directive_product("/etc/php/8.2/fpm/pool.d/www.conf", "www.conf"), "php-fpm")
        self.assertEqual(C.directive_product("/etc/apache2/conf-enabled/security.conf", "security.conf"), "apache")
        self.assertIsNone(C.directive_product("/etc/apache2/conf-available/security.conf", "security.conf"))
        php = P("[PHP]\nsession.upload_progress.enabled = Off ; x\n;expose_php = On\nmysqli.default_pw = s\nextension=gd\n", "x", "php")
        self.assertEqual([(d["key"], d["value"]) for d in php], [("session.upload_progress.enabled", "Off"), ("mysqli.default_pw", "***")])
        fpm = P("[www]\nphp_admin_value[session.upload_progress.enabled] = 0\npm.max_children = 5\n", "x", "php-fpm")
        self.assertEqual([(d["product"], d["key"], d["value"], d["scope"]) for d in fpm],
                         [("php", "session.upload_progress.enabled", "0", "pool www"), ("php-fpm", "pm.max_children", "5", "pool www")])
        ap = P("ServerTokens Prod\n<VirtualHost *:443>\nServerName www.exemple.test\n<Directory /srv>\nOptions Indexes\n</Directory>\n"
               "SetEnv DB_PASSWORD x\n</VirtualHost>\n", "x", "apache")
        self.assertEqual([(d["key"], d["value"], d["scope"]) for d in ap],
                         [("ServerTokens", "Prod", None), ("Options", "Indexes", "vhost www.exemple.test / Directory /srv")])
        ng = P("http { server_tokens off; server { server_name a.exemple.test; location / { autoindex on; } } }", "x", "nginx")
        self.assertEqual([(d["key"], d["value"], d["scope"]) for d in ng],
                         [("server_tokens", "off", None), ("autoindex", "on", "server a.exemple.test / location /")])

    def test_base(self):
        d = tempfile.mkdtemp(prefix="cmdbr")
        self.addCleanup(shutil.rmtree, d, True)
        a = fleet.app_host()
        a["runtimes"]["list"][0]["outputs"].append({"args": ["-i"], "rc": 0, "output": (
            "phpinfo()\nPHP Version => 8.2.7\nServer API => Command Line Interface\nLoaded Configuration File => /etc/php/8.2/cli/php.ini\n\n"
            "session\n\nDirective => Local Value => Master Value\nsession.upload_progress.enabled => On => On\n")})
        a["filesystem"]["config_directives"] = [
            {"product": "php", "key": "session.upload_progress.enabled", "value": "Off", "scope": None, "path": "/etc/php/8.2/cli/php.ini"},
            {"product": "php", "key": "session.upload_progress.enabled", "value": "1", "scope": None, "path": "/etc/php/8.2/apache2/php.ini"},
            {"product": "php", "key": "session.upload_progress.enabled", "value": "off", "scope": None, "path": "/etc/php/8.2/apache2/conf.d/99-local.ini"},
            {"product": "php", "key": "memory_limit", "value": "512M", "scope": None, "path": "/etc/php/8.2/cgi/php.ini"},
            {"product": "php", "key": "session.upload_progress.enabled", "value": "0", "scope": "pool www", "path": "/etc/php/8.2/fpm/pool.d/www.conf"},
            {"product": "apache", "key": "ServerTokens", "value": "Prod", "scope": None, "path": "/etc/apache2/conf-enabled/security.conf"}]
        fleet.write_store(os.path.join(d, "store"), [a])
        subprocess.check_call([sys.executable, os.path.join(TOOLS, "cmdb_build.py"), "--store", os.path.join(d, "store"), "--out", os.path.join(d, "b")],
                              stdout=subprocess.DEVNULL)
        db = sqlite3.connect(os.path.join(d, "b", "cmdb.sqlite"))
        got = sorted(db.execute("SELECT product, source, scope, key, value FROM config_settings WHERE key IN ('session.upload_progress.enabled', 'ServerTokens')"))
        mem = db.execute("SELECT source, value FROM config_settings WHERE key = 'memory_limit' AND scope = 'cgi 8.2'").fetchall()
        db.close()
        self.assertEqual(got, [("apache", "configuration", None, "ServerTokens", "Prod"),
                               ("php", "défaut PHP", "cgi 8.2", "session.upload_progress.enabled", "On"),
                               ("php", "php -i", "cli", "session.upload_progress.enabled", "On"),      # le php.ini de cli est lu par php -i
                               ("php", "php.ini", "apache2 8.2", "session.upload_progress.enabled", "Off"),  # conf.d l'emporte
                               ("php", "pool PHP-FPM", "pool www", "session.upload_progress.enabled", "Off")])
        self.assertEqual(mem, [("php.ini", "512M")])


class MisesAJour(unittest.TestCase):
    """Paquets et mises à jour : cache local, Windows Update, écart au parc, état et alertes par serveur."""

    def test_lecture(self):
        import cmdb_updates as U
        apt = U.parse_apt_simulate("Inst libssl3 [3.0.11-1~deb12u1] (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64])\n"
                                   "Inst tzdata [2024a-0+deb12u1] (2025b-0+deb12u1 Debian:12.11/stable [all])\nInst newdep (1.0 Debian:12/stable [amd64])\n")
        self.assertEqual(apt, [("libssl3", "amd64", "3.0.11-1~deb12u1", "3.0.15-1~deb12u1", "Debian-Security:12/stable-security", 1),
                               ("tzdata", "all", "2024a-0+deb12u1", "2025b-0+deb12u1", "Debian:12.11/stable", 0)])
        cu = U.parse_check_update("\nopenssl-libs.x86_64    1:3.0.7-27.el9    baseos\na-very-long-package-name-for-wrapping.noarch\n"
                                  "                       2.0-1.el9         appstream\nObsoleting Packages\nfoo.x86_64 1-1 baseos\n")
        self.assertEqual(cu, [("openssl-libs", "x86_64", "1:3.0.7-27.el9", "baseos"),
                              ("a-very-long-package-name-for-wrapping", "noarch", "2.0-1.el9", "appstream")])
        ui = U.parse_updateinfo("RHSA-2024:2447 Important/Sec. openssl-libs-1:3.0.7-27.el9.x86_64\nRLSA-2024:1 Moderate/Sec. curl-7.76.1-29.el9_4.x86_64\n")
        self.assertEqual(ui, [("RHSA-2024:2447", "Important", "openssl-libs", "x86_64", "1:3.0.7-27.el9"),
                              ("RLSA-2024:1", "Moderate", "curl", "x86_64", "7.76.1-29.el9_4")])
        z = U.parse_zypper_table("S | Repository | Name | Current Version | Available Version | Arch\n--+---\nv | SLES-Updates | curl | 8.0.1-1 | 8.0.1-2 | x86_64\n")
        self.assertEqual(z[0]["available version"], "8.0.1-2")
        self.assertEqual(U.parse_win_date("11/12/2024 00:00:00"), "2024-11-12")
        self.assertEqual(U.parse_win_date("20241112"), "2024-11-12")

    def test_base(self):
        d = tempfile.mkdtemp(prefix="cmdbu")
        self.addCleanup(shutil.rmtree, d, True)
        old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=200)).strftime("%Y-%m-%dT%H:%M:%SZ")
        recent = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        a = fleet.doc("a1.exemple.test", "APP", "prod", "10.0.0.1", "r1", "2026-11-02T08:00:00Z")
        b = fleet.doc("a2.exemple.test", "APP", "prod", "10.0.0.2", "r1", "2026-11-02T08:00:00Z")
        a["packages"]["managers"]["rpm"] = [{"name": "openssl-libs", "epoch": "1", "version": "3.0.7", "release": "24.el9", "arch": "x86_64",
                                             "vendor": "Red Hat, Inc.", "installtime": str(int(time.time()) - 200 * 86400)}]
        b["packages"]["managers"]["rpm"] = [{"name": "openssl-libs", "epoch": "1", "version": "3.0.7", "release": "27.el9", "arch": "x86_64",
                                             "vendor": "Red Hat, Inc.", "installtime": str(int(time.time()) - 3 * 86400)}]
        a["update_cache"] = {"manager": "dnf", "cache_date": old, "commands": [
            {"name": "check_update", "rc": 100, "output": "openssl-libs.x86_64  1:3.0.7-25.el9  baseos\n"},
            {"name": "updateinfo_security", "rc": 0, "output": "RHSA-2024:1 Important/Sec. openssl-libs-1:3.0.7-25.el9.x86_64\n"}]}
        b["update_cache"] = {"manager": "dnf", "cache_date": recent, "commands": [{"name": "check_update", "rc": 0, "output": ""}]}
        w = fleet.doc("w1.exemple.test", "APP", "prod", "10.0.0.3", "r1", "2026-11-02T08:00:00Z")
        w["os"]["os_release"] = {"ID": "windows", "VERSION_ID": "11", "PRETTY_NAME": "Windows 11"}
        w["windows"] = {"os": {"caption": "Microsoft Windows 11 Pro", "build": "26100", "ubr": "2033", "display_version": "24H2"},
                        "programs": [{"name": "7-Zip 24.08 (x64)", "version": "24.08", "publisher": "Igor Pavlov"},
                                     {"name": "Composant", "version": "1", "system_component": True}],
                        "hotfixes": [{"id": "KB5044284", "description": "Security Update", "installed_on": "10/20/2026"}],
                        "updates": {"source": "Windows Update (recherche hors ligne)", "last_search": recent, "last_install": recent,
                                    "pending": [{"title": "Mise à jour cumulative", "kb": ["KB5099999"], "severity": "Critical", "categories": []}]}}
        fleet.write_store(os.path.join(d, "store"), [a, b, w])
        subprocess.check_call([sys.executable, os.path.join(TOOLS, "cmdb_build.py"), "--store", os.path.join(d, "store"), "--out", os.path.join(d, "b")],
                              stdout=subprocess.DEVNULL)
        db = sqlite3.connect(os.path.join(d, "b", "cmdb.sqlite"))
        ups = sorted(db.execute("SELECT host, name, installed, available, kind, security, advisory FROM updates"))
        st = {r[0]: r[1:] for r in db.execute("SELECT host, state, last_change_days, pending_security, fleet_gap, os_cycle, alerts FROM update_status")}
        progs = db.execute("SELECT name FROM software WHERE ecosystem = 'windows'").fetchall()
        db.close()
        self.assertIn(("a1.exemple.test", "openssl-libs", "1:3.0.7-24.el9", "1:3.0.7-25.el9", "cache local", 1, "RHSA-2024:1"), ups)
        self.assertIn(("a1.exemple.test", "openssl-libs", "1:3.0.7-24.el9", "1:3.0.7-27.el9", "écart au parc", 0, None), ups)
        self.assertIn(("w1.exemple.test", "Mise à jour cumulative", None, None, "Windows Update", 1, "KB5099999"), ups)
        self.assertEqual(progs, [("7-Zip 24.08 (x64)",)])
        self.assertEqual(st["a1.exemple.test"][0], "à traiter")
        self.assertIn("aucune mise à jour depuis 200 jours", st["a1.exemple.test"][5])
        self.assertIn("correctifs de sécurité non appliqués", st["a1.exemple.test"][5])
        self.assertIn("cache des mises à jour vieux de 200 jours", st["a1.exemple.test"][5])
        self.assertEqual(st["a2.exemple.test"][:4], ("à jour", 3, 0, 0))
        self.assertEqual(st["w1.exemple.test"][4], "11-24h2")
