# -*- coding: utf-8 -*-
"""Consolidation complète d'un parc fictif."""
import datetime as dt
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from tests import fleet
from tests.common import TOOLS
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
