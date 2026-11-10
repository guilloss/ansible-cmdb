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
          "ecarts", "ecarts?onglet=jumeaux", "ecarts?onglet=paires", "durcissement", "durcissement?onglet=regles", "durcissement?onglet=ecarts", "durcissement?onglet=couverture"]
FOCUS = "carte?serveur=" + quote("APPDEMO|prod|pg1.exemple.test", safe="")
ROUTES.append(FOCUS)
TAG = "tag=" + quote("squad=S3", safe="")
ROUTES += ["serveurs?" + TAG, "bases?onglet=liens&" + TAG, "logiciels?" + TAG, "carte?" + TAG, "ecarts?" + TAG, "accueil?" + TAG,
           "serveurs?app=APPDEMO&pf=prod&" + TAG, "serveurs?tag=" + quote("squad=inconnue", safe=""), "serveurs?q=S4"]
ROUTES += ["logiciels?q=" + quote("webapps/gestion", safe=""), "logiciels?q=" + quote("chemin:webapps/gestion", safe=""), "logiciels?vue=versions",
           "logiciels?gestion=um", "logiciels?q=" + quote("serveur:app1", safe="")]
HOST = "serveur/" + quote("APPDEMO|prod|app1.exemple.test", safe="")
ROUTES += [HOST + "?onglet=" + t for t in ("synthese", "bases", "web", "cles", "dependances", "durcissement", "evolutions", "alertes")]


@unittest.skipUnless(shutil.which("node"), "node absent")
class Rapport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="cmdbr")
        store = os.path.join(cls.d, "store")
        old = fleet.oracle_host("r1", "2026-10-01T08:00:00Z", "19.21.0.0.231017", "35643107")
        app, pg = fleet.app_host(), fleet.pg_host()
        app["meta"]["tags"]["squad"] = "S3"
        pg["meta"]["tags"].update({"squad": "S4", "site": "Paris"})
        fleet.write_store(store, [old, fleet.oracle_host(), app, pg, fleet.pg_standby(), fleet.web_host(),
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

    def test_etiquettes_liste(self):
        p = self.pages["serveurs"]
        self.assertIn(">squad<", p.replace(" ▲", ""))
        self.assertIn(">site<", p.replace(" ▲", ""))
        self.assertIn("tag=squad%3DS3", p)

    def test_etiquettes_filtre(self):
        p = self.pages["serveurs?" + TAG]
        self.assertIn("app1.exemple.test", p)
        self.assertNotIn("pg1.exemple.test", p)
        self.assertIn("squad=S3", p)
        self.assertNotIn("t1.exemple.test", self.pages["logiciels?" + TAG])
        self.assertIn("Aucun serveur", self.pages["serveurs?tag=" + quote("squad=inconnue", safe="")])

    def test_etiquettes_lien_garde_les_deux_cotes(self):
        p = self.pages["bases?onglet=liens&" + TAG]
        self.assertIn("app1.exemple.test", p)
        self.assertIn("pg1.exemple.test", p)

    def test_etiquettes_recherche(self):
        p = self.pages["serveurs?q=S4"]
        self.assertIn("pg1.exemple.test", p)
        self.assertNotIn("app1.exemple.test", p)

    def test_etiquettes_selecteur(self):
        p = self.pages["__scope"]
        self.assertIn('id="s-tag"', p)
        self.assertIn("squad=S3 (1)", p)
        self.assertIn("site=Paris (1)", p)

    def test_logiciels_sans_perte(self):
        """Les tables compactes redonnent exactement la table software."""
        import base64, gzip, re, sqlite3
        out = os.path.join(self.d, "build")
        with open(os.path.join(out, "cmdb_rapport.html"), encoding="utf-8") as handle:
            data = json.loads(gzip.decompress(base64.b64decode(re.search(r'id="cmdb-data">([^<]*)<', handle.read()).group(1))))
        sw = data["sw"]
        strings, comps, locs, rows, cc = sw["strings"], sw["comps"], sw["locs"], sw["rows"], sw["comp_cols"]
        got = []
        for o in range(0, len(rows), 5):
            c = rows[o + 3] * len(cc)
            d, b = locs[rows[o + 4] * 2], strings[locs[rows[o + 4] * 2 + 1]]
            row = {"app": strings[rows[o]], "platform": strings[rows[o + 1]], "host": strings[rows[o + 2]],
                   "location": b if d < 0 else strings[d] + "/" + b}
            for i, k in enumerate(cc):
                row[k] = comps[c + i] if k == "managed" else strings[comps[c + i]]
            got.append(tuple(row[k] for k in sw["cols"]))
        db = sqlite3.connect(os.path.join(out, "cmdb.sqlite"))
        want = [tuple((1 if v else 0) if k == "managed" else ("" if v is None else str(v)) for k, v in zip(sw["cols"], r))
                for r in db.execute("SELECT %s FROM software" % ", ".join(sw["cols"]))]
        db.close()
        self.assertTrue(want)
        self.assertEqual(got, want)

    def test_recherche_dans_les_chemins(self):
        # le terme chevauche le répertoire et le nom de fichier, stockés séparément
        for q in ("webapps/gestion", "chemin:webapps/gestion"):
            self.assertIn("1 composants correspondent", self.pages["logiciels?q=" + quote(q, safe="")], q)

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
        # une ligne par élément, dans l'ordre de promotion, avec constat et action
        self.assertIn("recette → prod", self.pages["ecarts"])
        self.assertIn("à promouvoir en prod", self.pages["ecarts"])
        self.assertIn("passer prod à 8.3.0", self.pages["ecarts"])
        self.assertIn("8.3.0", self.pages["ecarts?onglet=paires"])
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
