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
