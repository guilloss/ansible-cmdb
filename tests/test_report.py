# -*- coding: utf-8 -*-
"""Le JavaScript du rapport, exécuté pour de vrai sur chaque page."""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from urllib.parse import quote

from tests import fleet
from tests.common import ROOT, TOOLS

ROUTES = ["accueil", "serveurs", "logiciels", "versions", "exposition", "materiel", "alertes", "bases", "bases?onglet=liens", "bases?onglet=homes",
          "bases?onglet=patches", "bases?onglet=licences", "services", "services?onglet=runtimes", "services?onglet=modules",
          "services?onglet=php", "cles", "cles?onglet=certs", "cles?onglet=tout", "support", "support?onglet=tout", "evolutions",
          "bases?onglet=liens&app=APPDEMO&pf=prod", "bases?onglet=liens&q=appdb", "carte", "carte?onglet=flux", "carte?reseau=1",
          "ecarts", "ecarts?onglet=jumeaux", "durcissement", "durcissement?onglet=regles", "durcissement?onglet=ecarts", "durcissement?onglet=couverture"]
FOCUS = "carte?serveur=" + quote("APPDEMO|prod|pg1.exemple.test", safe="")
ROUTES.append(FOCUS)
HOST = "serveur/" + quote("APPDEMO|prod|app1.exemple.test", safe="")
ROUTES += [HOST + "?onglet=" + t for t in ("synthese", "bases", "web", "cles", "dependances", "durcissement", "evolutions", "alertes")]


@unittest.skipUnless(shutil.which("node"), "node absent")
class Rapport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="cmdbr")
        store = os.path.join(cls.d, "store")
        old = fleet.oracle_host("r1", "2026-10-01T08:00:00Z", "19.21.0.0.231017", "35643107")
        fleet.write_store(store, [old, fleet.oracle_host(), fleet.app_host(), fleet.pg_host(), fleet.pg_standby(), fleet.web_host(),
                                  fleet.twin("t1.exemple.test", "10.0.1.1"), fleet.twin("t2.exemple.test", "10.0.1.2"),
                                  fleet.twin("t3.exemple.test", "10.0.1.3", php="8.1.9"), fleet.twin("r1.exemple.test", "10.0.2.1", php="8.3.0", pf="recette")])
        out = os.path.join(cls.d, "build")
        subprocess.check_call([sys.executable, os.path.join(TOOLS, "cmdb_build.py"), "--store", store, "--out", out], stdout=subprocess.DEVNULL)
        res = subprocess.check_output(["node", os.path.join(ROOT, "tests", "report_harness.js"), os.path.join(out, "cmdb_rapport.html")] + ROUTES)
        cls.pages = json.loads(res.decode("utf-8"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def test_aucune_erreur(self):
        for r in ROUTES:
            self.assertNotIn("Erreur d'affichage", self.pages[r], r)

    def test_liens(self):
        p = self.pages["bases?onglet=liens"]
        for x in ("app1.exemple.test", "pg1.exemple.test", "appdb", "appuser", "hors inventaire", "10.9.9.9", "my9.exemple.test", "réplication"):
            self.assertIn(x, p)

    def test_filtre(self):
        p = self.pages["bases?onglet=liens&q=appdb"]
        self.assertIn("appdb", p)
        self.assertNotIn("my9.exemple.test", p)

    def test_oracle(self):
        self.assertIn("19.23.0.0.240416", self.pages["bases?onglet=homes"])
        self.assertIn("non visible", self.pages["bases?onglet=homes"])
        self.assertIn("Database Release Update", self.pages["bases?onglet=patches"])
        self.assertIn("partitionnement logiciel", self.pages["bases?onglet=licences"])
        self.assertIn("standby", self.pages["bases"])

    def test_services(self):
        self.assertIn("www.exemple.test", self.pages["services"])
        self.assertIn("/gestion", self.pages["services"])
        self.assertIn("org.apache.catalina.startup.Bootstrap", self.pages["services?onglet=runtimes"])
        self.assertIn("ssl_module", self.pages["services?onglet=modules"])
        self.assertIn("expose_php", self.pages["services?onglet=php"])

    def test_cles(self):
        p = self.pages["cles"]
        self.assertIn("/etc/pki/tls/private/www.key", p)
        self.assertIn("en clair", p)
        self.assertIn("protégé par un mot de passe", p)
        self.assertIn("www.exemple.test", self.pages["cles?onglet=certs"])

    def test_accueil_a_traiter(self):
        self.assertIn("Clés privées exposées", self.pages["accueil"])
        self.assertIn("ORACLE_HOME en retard", self.pages["accueil"])

    def test_evolutions(self):
        self.assertIn("36233263", self.pages["evolutions"])

    def test_carte(self):
        p = self.pages["carte"]
        self.assertIn("<svg", p)
        self.assertIn("web1", p)
        self.assertIn("fl-proxy", p)

    def test_impact(self):
        p = self.pages[FOCUS]
        self.assertIn('class="fn up', p)                  # app1 et web1 touchés si pg1 s'arrête
        self.assertIn("Si ce serveur s'arrête", p)
        self.assertIn("web1.exemple.test", p)

    def test_impact_ignore_la_replication(self):
        self.assertIn('<g class="fn dim"><title>pg2.exemple.test</title>', self.pages[FOCUS])

    def test_adresse_entiere_sur_la_carte(self):
        self.assertIn(">10.9.9.9</text>", self.pages["carte"])

    def test_ecarts(self):
        self.assertIn("8.3.0", self.pages["ecarts"])
        self.assertIn("majorité (2/3)", self.pages["ecarts?onglet=jumeaux"])

    def test_durcissement(self):
        self.assertIn("recommandations sur 80", self.pages["durcissement"])
        self.assertIn("non conforme", self.pages["durcissement?onglet=ecarts"])
        self.assertIn("non contrôlée", self.pages["durcissement?onglet=couverture"])

    def test_fiche_serveur(self):
        self.assertIn("pg1.exemple.test", self.pages[HOST + "?onglet=bases"])
        self.assertIn("www.exemple.test", self.pages[HOST + "?onglet=web"])
        self.assertIn("www.key", self.pages[HOST + "?onglet=cles"])


if __name__ == "__main__":
    unittest.main()
