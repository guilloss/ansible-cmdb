# -*- coding: utf-8 -*-
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from tests import fleet
from tests.common import TOOLS
import cmdb_maps as M


class Backends(unittest.TestCase):
    def test_formats(self):
        self.assertEqual(M.parse_backends("http://tomcat01:8080/app"), [("tomcat01", 8080)])
        self.assertEqual(M.parse_backends("10.0.0.2:8080"), [("10.0.0.2", 8080)])
        self.assertEqual(M.parse_backends("http://api/ (10.0.0.2:8080, 10.0.0.3:8080)"), [("10.0.0.2", 8080), ("10.0.0.3", 8080)])
        self.assertEqual(M.parse_backends("http://app"), [("app", None)])
        self.assertEqual(M.parse_backends("balancer://grappe/"), [])


class Parc(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="cmdbm")
        store = os.path.join(cls.d, "store")
        fleet.write_store(store, [fleet.oracle_host(), fleet.app_host(), fleet.pg_host(), fleet.pg_standby(), fleet.web_host(),
                                  fleet.twin("t1.exemple.test", "10.0.1.1"), fleet.twin("t2.exemple.test", "10.0.1.2"),
                                  fleet.twin("t3.exemple.test", "10.0.1.3", php="8.1.9"),
                                  fleet.twin("r1.exemple.test", "10.0.2.1", php="8.3.0", pf="recette")])
        cls.out = os.path.join(cls.d, "build")
        cls.log = subprocess.check_output([sys.executable, os.path.join(TOOLS, "cmdb_build.py"), "--store", store, "--out", cls.out]).decode()
        cls.db = sqlite3.connect(os.path.join(cls.out, "cmdb.sqlite"))

    @classmethod
    def tearDownClass(cls):
        cls.db.close()
        shutil.rmtree(cls.d, ignore_errors=True)

    def q(self, sql, *a):
        return self.db.execute(sql, a).fetchall()

    def test_chaine_complete(self):
        r = self.q("SELECT src_host, dst_host, port, kind FROM app_flows WHERE dst_host IS NOT NULL")
        self.assertIn(("web1.exemple.test", "app1.exemple.test", 8080, "proxy"), r)
        self.assertIn(("app1.exemple.test", "pg1.exemple.test", 5432, "base"), r)
        self.assertIn(("app1.exemple.test", "ora1.exemple.test", 1521, "base"), r)
        self.assertIn(("pg2.exemple.test", "pg1.exemple.test", 5432, "réplication"), r)

    def test_proxy_confirme_par_une_connexion_sans_doublon(self):
        r = self.q("SELECT kind FROM app_flows WHERE src_host = 'web1.exemple.test' AND dst_host = 'app1.exemple.test'")
        self.assertEqual(r, [("proxy",)])

    def test_ssh_n_est_pas_une_dependance(self):
        self.assertEqual(self.q("SELECT COUNT(*) FROM app_flows WHERE port = 22")[0][0], 0)

    def test_dot(self):
        p = os.path.join(self.out, "graphes", "APPDEMO__prod.dot")
        with open(p, encoding="utf-8") as f:
            t = f.read()
        self.assertIn('"web1.exemple.test" -> "app1.exemple.test"', t)
        self.assertIn('"my9.exemple.test" [style=dashed]', t)
        self.assertTrue(t.rstrip().endswith("}"))

    def test_ecart_entre_plates_formes(self):
        r = self.q("SELECT left_platform, right_platform, left_value, right_value FROM drift WHERE scope = 'plates-formes' AND item = 'php'")
        self.assertEqual(len(r), 1)
        self.assertEqual(r[0][:2], ("prod", "recette"))
        self.assertIn("8.3.0", r[0][3])

    def test_jumeau_divergent(self):
        r = self.q("SELECT left_host, right_host, left_value, right_value FROM drift WHERE scope = 'jumeaux' AND item = 'php'")
        self.assertEqual(r, [("t3.exemple.test", "majorité (2/3)", "8.1.9", "8.1.2")])

    def test_pas_de_faux_jumeaux(self):
        r = self.q("SELECT COUNT(*) FROM drift WHERE scope = 'jumeaux' AND left_host IN ('ora1.exemple.test', 'pg1.exemple.test')")
        self.assertEqual(r[0][0], 0)

    def test_durcissement_du_parc(self):
        self.assertIn("Durcissement", self.log)
        r = self.q("SELECT level, ok, ko, unknown, score FROM hardening_scores WHERE host = 'ora1.exemple.test' ORDER BY ok + ko + unknown")
        self.assertEqual([x[0] for x in r], ["minimal", "intermédiaire", "renforcé", "élevé"])
        self.assertEqual(self.q("SELECT status FROM hardening_results WHERE rule_id = 'R61-os-supported' AND host = 'ora1.exemple.test'"), [("conforme",)])
        self.assertEqual(self.q("SELECT COUNT(*) FROM anssi_recommendations")[0][0], 80)

    def test_ignore(self):
        db = sqlite3.connect(":memory:")
        import cmdb_build
        db.executescript(cmdb_build.SCHEMA)
        for pf, v in (("a", "1"), ("b", "2")):
            db.execute("INSERT INTO hosts (app, platform, host, os_pretty) VALUES ('x', ?, 'h', 'OS')", (pf,))
            db.execute("INSERT INTO software (app, platform, host, category, family, version) VALUES ('x', ?, 'h', 'runtime', 'php', ?)", (pf, v))
        M.build_drift(db, ["composant:ph*"])
        self.assertEqual(db.execute("SELECT COUNT(*) FROM drift").fetchone()[0], 0)
        M.build_drift(db, [])
        self.assertEqual(db.execute("SELECT COUNT(*) FROM drift").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
