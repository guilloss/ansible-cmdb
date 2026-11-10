# -*- coding: utf-8 -*-
"""Écarts entre plates-formes : une ligne par élément, constat selon l'ordre de promotion."""
import json
import sqlite3
import unittest

from tests.common import TOOLS  # noqa: F401  (chemin des outils)
import cmdb_build as B
import cmdb_maps as M

HOSTS = [("dev", "d1"), ("rec", "r1"), ("prod", "p1"), ("prod", "p2"), ("formation", "f1")]
SOFT = {   # famille -> {hôte: version}
    "openssl": {"d1": "3.0.7", "r1": "3.0.7", "p1": "1.1.1k", "p2": "1.1.1k", "f1": "1.1.1k"},
    "tomcat": {"d1": "9.0.85", "r1": "9.0.80", "p1": "9.0.80", "p2": "9.0.80", "f1": "9.0.80"},
    "java": {"d1": "17.0.9", "r1": "17.0.9", "p1": "21.0.2", "p2": "21.0.2", "f1": "17.0.9"},
    "php": {"d1": "8.1.9", "r1": "8.1.9", "p1": "8.1.2", "p2": "8.1.9", "f1": "8.1.9"},
    "glibc": {"d1": "2.28", "r1": "2.28", "p1": "2.28", "p2": "2.28", "f1": "2.28"},
    "commons-lang3": {"d1": "3.14.0", "r1": "3.12.0", "p1": "3.12.0", "p2": "3.12.0", "f1": "3.12.0"},
    "redis": {"d1": "7.2.4", "r1": "7.2.4"},
}


def fill(db):
    for pf, h in HOSTS:
        db.execute("INSERT INTO hosts (app, platform, host, os_pretty) VALUES ('APP', ?, ?, 'RHEL 8.9')", (pf, h))
        for fam, by in SOFT.items():
            if h in by:
                cat = "java-archive" if fam == "commons-lang3" else "runtime"
                db.execute("INSERT INTO software (app, platform, host, category, family, version) VALUES ('APP', ?, ?, ?, ?, ?)",
                           (pf, h, cat, fam, by[h]))
        st = "non conforme" if pf == "prod" else "conforme"
        db.execute("INSERT INTO hardening_results (app, platform, host, rule_id, status) VALUES ('APP', ?, ?, 'R1', ?)", (pf, h, st))


class Matrice(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = sqlite3.connect(":memory:")
        cls.db.executescript(B.SCHEMA)
        fill(cls.db)
        M.build_drift(cls.db, [], important=B.PRODUCT_FAMILIES | frozenset(B.MATRIX_FAMILIES))

    def row(self, item, db=None):
        r = (db or self.db).execute("SELECT importance, severity, finding, action, platforms, cells FROM drift_matrix WHERE item = ?",
                                    (item,)).fetchone()
        return r and (r[0], r[1], r[2], r[3], json.loads(r[4]), json.loads(r[5]))

    def test_ordre_des_colonnes(self):
        self.assertEqual(self.row("openssl")[4], ["dev", "rec", "prod", "formation"])

    def test_une_ligne_par_element(self):
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM drift_matrix WHERE item = 'openssl'").fetchone()[0], 1)

    def test_a_promouvoir(self):
        imp, sev, finding, action, _pfs, cells = self.row("openssl")
        self.assertEqual((imp, sev), (1, 2))
        self.assertIn("à promouvoir en prod", finding)
        self.assertIn("passer prod à 3.0.7", action)
        self.assertEqual(cells["prod"], "1.1.1k")
        self.assertIn("à promouvoir en rec", self.row("tomcat")[2])

    def test_en_avance_non_teste(self):
        _imp, sev, finding, action, _pfs, _cells = self.row("java")
        self.assertEqual(sev, 3)
        self.assertIn("prod en avance sur rec", finding)
        self.assertIn("21.0.2 non testé en rec", action)

    def test_heterogene(self):
        _imp, _sev, finding, action, _pfs, cells = self.row("php")
        self.assertIn("hétérogène en prod", finding)
        self.assertIn("aligner les 2 serveurs de prod (2 valeurs)", action)
        self.assertIn("(1/2)", cells["prod"])

    def test_identique_absent_de_la_liste(self):
        self.assertIsNone(self.row("glibc"))

    def test_absent(self):
        _imp, _sev, finding, _a, _pfs, cells = self.row("redis")
        self.assertIn("absent de prod, formation", finding)
        self.assertIsNone(cells["prod"])

    def test_importance(self):
        self.assertEqual(self.row("commons-lang3")[0], 3)
        self.assertEqual(self.row("R1")[0], 2)

    def test_durcissement(self):
        _imp, sev, finding, action, _pfs, _cells = self.row("R1")
        self.assertEqual(sev, 2)
        self.assertEqual(finding, "non conforme en prod")
        self.assertIn("appliquer la règle en prod", action)

    def test_plate_forme_sans_rang(self):
        # formation n'a pas de rang : elle est affichée mais n'entre pas dans les constats d'avance ou de retard
        self.assertNotIn("formation", self.row("openssl")[2])

    def test_ordre_personnalise(self):
        db = sqlite3.connect(":memory:")
        db.executescript(B.SCHEMA)
        fill(db)
        M.build_drift(db, [], order=["prod", "rec", "dev"])
        self.assertEqual(self.row("openssl", db)[4][:3], ["prod", "rec", "dev"])
        self.assertIn("rec en avance sur prod", self.row("openssl", db)[2])

    def test_rangs(self):
        r = M.platform_ranks()
        self.assertEqual([M.platform_rank(n, r) for n in ("PROD", "prod2", "PROD_DR", "rec-a", "Recette", "pre-prod", "formation")],
                         [50, 50, 50, 30, 30, 40, None])

    def test_versions(self):
        self.assertGreater(M.version_key("1.10"), M.version_key("1.9"))
        self.assertGreater(M.version_key("19.23.0.0.240416"), M.version_key("19.21.0.0.231017"))
        self.assertGreater(M.version_key("1.1.1w"), M.version_key("1.1.1k"))


if __name__ == "__main__":
    unittest.main()
