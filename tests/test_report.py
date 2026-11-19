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
ROUTES += ["serveurs?pf=prod,recette", "serveurs?pf=prod", "serveurs?tag=" + quote("squad=S3,squad=S4", safe=""),
           "serveurs?tag=" + quote("squad=S4,site=Paris", safe=""), "serveurs?tag=" + quote("squad=S3,site=Paris", safe="")]
ROUTES += ["cles?onglet=certs&etat=expires", "cles?onglet=certs&du=" + fleet.in_days(6), "cles?onglet=certs&au=" + fleet.in_days(4),
           "cles?onglet=certs&etat=30x"]
ROUTES += ["systeme", "systeme?onglet=tout", "systeme?onglet=echec", "systeme?onglet=arretes", "systeme?onglet=tout&q=pg1",
           "serveur/" + quote("APPDEMO|prod|pg1.exemple.test", safe="") + "?onglet=exposition"]
HOST = "serveur/" + quote("APPDEMO|prod|app1.exemple.test", safe="")
ROUTES += ["logiciels?q=php&vue=versions", "logiciels?q=php", "logiciels?q=php&app=APPDEMO&pf=prod&vue=versions"]
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
        pg["runtimes"] = {"list": [{"probe": "postgresql", "realpath": "/usr/pgsql-14/bin/postgres", "paths": ["/usr/pgsql-14/bin/postgres"],
                                    "outputs": [{"args": ["/usr/pgsql-14/bin/postgres", "--version"], "rc": 0, "output": "postgres (PostgreSQL) 14.9"}]}]}
        pg["services"] = {"units": [{"unit": "postgresql-14.service", "load": "loaded", "active": "active", "sub": "running", "description": "PostgreSQL 14"},
                                    {"unit": "kdump.service", "load": "loaded", "active": "failed", "sub": "failed", "description": "Crash recovery kernel"},
                                    {"unit": "chronyd.service", "load": "loaded", "active": "inactive", "sub": "dead", "description": "NTP"}],
                          "unit_files": [{"unit": "chronyd.service", "state": "enabled"}, {"unit": "postgresql-14.service", "state": "enabled"}],
                          "service_details": [{"Id": "postgresql-14.service", "MainPID": "20", "User": "postgres", "Type": "notify"},
                                              {"Id": "chronyd.service", "MainPID": "0", "Type": "forking"}]}
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

    def test_services_systeme(self):
        p = self.pages["systeme"]
        self.assertIn("postgresql-14", p)
        self.assertIn("postgres 14.9", p)
        self.assertIn("kdump", self.pages["systeme?onglet=echec"])
        self.assertNotIn("postgresql-14", self.pages["systeme?onglet=echec"])
        self.assertIn("chronyd", self.pages["systeme?onglet=arretes"])
        h = self.pages["serveur/" + quote("APPDEMO|prod|pg1.exemple.test", safe="") + "?onglet=exposition"]
        self.assertIn("postgres 14.9", h)
        self.assertIn("en échec", h)
        self.assertIn("Services en échec", self.pages["accueil"])

    def test_logiciels_par_application(self):
        p = self.pages["logiciels?q=php&vue=versions"]
        self.assertIn("Applications et plates-formes concernées", p)
        self.assertIn("Applications / plates-formes", p)
        self.assertIn("APPDEMO / recette", p)
        self.assertIn("Applications et plates-formes concernées", self.pages["logiciels?q=php"])
        # une seule application et plate-forme : rien à répartir
        one = self.pages["logiciels?q=php&app=APPDEMO&pf=prod&vue=versions"]
        self.assertNotIn("Applications et plates-formes concernées", one)
        self.assertNotIn("Applications / plates-formes", one)

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
        self.assertIn('value="squad=S3"> squad=S3 <span class="cat">(1)</span>', p)
        self.assertIn('value="site=Paris"> site=Paris <span class="cat">(1)</span>', p)
        self.assertIn('data-all="1" checked', p)

    def test_perimetre_multiple(self):
        both = self.pages["serveurs?pf=prod,recette"]
        self.assertIn("r1.exemple.test", both)
        self.assertIn("t1.exemple.test", both)
        self.assertNotIn("r1.exemple.test", self.pages["serveurs?pf=prod"])
        # même nom d'étiquette : l'une ou l'autre
        ou = self.pages["serveurs?tag=" + quote("squad=S3,squad=S4", safe="")]
        self.assertIn("app1.exemple.test", ou)
        self.assertIn("pg1.exemple.test", ou)
        self.assertNotIn("t1.exemple.test", ou)
        # noms différents : toutes
        et = self.pages["serveurs?tag=" + quote("squad=S4,site=Paris", safe="")]
        self.assertIn("pg1.exemple.test", et)
        self.assertNotIn("app1.exemple.test", et)
        self.assertIn("Aucun serveur", self.pages["serveurs?tag=" + quote("squad=S3,site=Paris", safe="")])

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
            n = o // 5
            got.append(tuple(row[k] for k in sw["cols"]) + (1 if n in sw["running"] else (0 if n in sw["stopped"] else None),))
        db = sqlite3.connect(os.path.join(out, "cmdb.sqlite"))
        want = [tuple((1 if v else 0) if k == "managed" else ("" if v is None else str(v)) for k, v in zip(sw["cols"], r[:-1])) + (r[-1],)
                for r in db.execute("SELECT %s, running FROM software" % ", ".join(sw["cols"]))]
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

    def test_cles_filtres_certificats(self):
        p = self.pages
        self.assertNotIn("www.exemple.test</b>", p["cles?onglet=certs&etat=expires"])
        self.assertIn("Effacer les filtres", p["cles?onglet=certs&etat=expires"])
        self.assertIn("www.exemple.test</b>", p["cles?onglet=certs&du=" + fleet.in_days(6)])
        self.assertIn("Certificats (0)", p["cles?onglet=certs&au=" + fleet.in_days(4)])
        self.assertNotIn("www.exemple.test</b>", p["cles?onglet=certs&au=" + fleet.in_days(4)])
        self.assertIn("www.exemple.test</b>", p["cles?onglet=certs&etat=30x"])
        # les onglets gardent les filtres, la page sans filtre n'a pas de bouton d'effacement
        self.assertIn("etat=expires", p["cles?onglet=certs&etat=expires"].split('class="tabs"')[1].split("</div>")[0])
        self.assertNotIn("Effacer les filtres", p["cles?onglet=certs"])
        self.assertIn('id="c-etat"', p["cles?onglet=certs"])
        self.assertNotIn('id="c-etat"', p["cles"])

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


class RechercheVersion(unittest.TestCase):
    """Comparaisons de version de la recherche des logiciels : écriture libre, précision de la référence."""
    Q = {"java >17": ["21.0.1"], "java > 17": ["21.0.1"], "java>17": ["21.0.1"], "java >=17": ["17.0.9", "21.0.1"],
         "java =17": ["17.0.9"], "java <=17": ["1.8.0", "17.0.9"], "java <17": ["1.8.0"], "java >17.0.8": ["17.0.9", "21.0.1"]}

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="cmdbv")
        store, out = os.path.join(cls.d, "store"), os.path.join(cls.d, "build")
        a = fleet.app_host()
        a["packages"]["managers"]["rpm"] = [
            {"name": "java-%s-openjdk-headless" % n, "epoch": "1", "version": v, "release": "2.el8", "arch": "x86_64"}
            for n, v in (("17", "17.0.9.0.9"), ("21", "21.0.1.0.12"), ("1.8.0", "1.8.0.392.b08"))]
        fleet.write_store(store, [a])
        subprocess.check_call([sys.executable, os.path.join(TOOLS, "cmdb_build.py"), "--store", store, "--out", out], stdout=subprocess.DEVNULL)
        res = subprocess.check_output(["node", os.path.join(ROOT, "tests", "report_harness.js"), os.path.join(out, "cmdb_rapport.html")]
                                      + ["logiciels?q=" + quote(q, safe="") for q in cls.Q])
        cls.pages = json.loads(res.decode("utf-8"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def test_comparaisons(self):
        for q, want in self.Q.items():
            p = self.pages["logiciels?q=" + quote(q, safe="")]
            self.assertIn("%d composants correspondent" % len(want), p, q)
            for v in ("1.8.0", "17.0.9", "21.0.1"):
                (self.assertIn if v in want else self.assertNotIn)(v + ".", p.split("<table")[-1], q)


class DistributionJavaRapport(unittest.TestCase):
    """Distribution Java dans la page Logiciels, filtre distrib: et export CSV de la vue affichée."""
    R = ["logiciels", "logiciels?q=distrib:oracle-jdk", "logiciels?q=" + quote("java distrib:temurin", safe=""),
         "logiciels?q=java&vue=versions", "materiel?onglet=cpu", "materiel?onglet=cpu&q=avx512", "materiel?onglet=cpu&q=" + quote("!avx512f", safe=""),
         "serveur/" + quote("APPDEMO|prod|app1.exemple.test", safe=""), "socle", "socle?famille=java", "socle?famille=systemes"]

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="cmdbj")
        store, out = os.path.join(cls.d, "store"), os.path.join(cls.d, "build")
        a = fleet.app_host()
        a["packages"]["managers"]["rpm"] = [
            {"name": "java-17-openjdk-headless", "epoch": "1", "version": "17.0.9.0.9", "release": "2.el8", "arch": "x86_64"},
            {"name": "jdk-17", "version": "17.0.10", "release": "ga", "arch": "x86_64", "vendor": "Oracle Corporation"}]
        a["filesystem"]["jdk_homes"] = [{"path": "/opt/temurin-21", "release": {"JAVA_VERSION": "21.0.2", "IMPLEMENTOR": "Eclipse Adoptium"}}]
        a["hardware"]["cpu"] = {"count": 8, "model name": "Intel(R) Xeon(R) Gold 6248", "vendor_id": "GenuineIntel", "cpu family": "6",
                                "model": "85", "stepping": "7", "flags": "sse2 lm sse4_2 avx avx2 avx512f avx512bw"}
        a["hardware"]["cpu_vulnerabilities"] = {"gather_data_sampling": "Vulnerable: No microcode"}
        t = fleet.twin("t1.exemple.test", "10.0.1.1", pf="recette")
        t["packages"]["managers"]["rpm"] = [{"name": "java-17-openjdk-headless", "epoch": "1", "version": "17.0.9.0.9", "release": "2.el8", "arch": "x86_64"}]
        fleet.write_store(store, [a, t])
        subprocess.check_call([sys.executable, os.path.join(TOOLS, "cmdb_build.py"), "--store", store, "--out", out], stdout=subprocess.DEVNULL)
        res = subprocess.check_output(["node", os.path.join(ROOT, "tests", "report_harness.js"), os.path.join(out, "cmdb_rapport.html")] + cls.R)
        cls.pages = json.loads(res.decode("utf-8"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def test_page(self):
        self.assertNotIn("Par distribution", self.pages["logiciels"])
        p = self.pages["socle?famille=java"]
        self.assertIn("Par distribution", p)
        self.assertIn("Par version majeure", p)
        for lab in ("OpenJDK Red Hat", "Oracle JDK", "Eclipse Temurin", "paquet jdk-17 (éditeur Oracle Corporation)", "famille%3Ajava+%3D17"):
            self.assertIn(lab, p)
        self.assertIn("Par version majeure", self.pages["socle"])
        self.assertIn("RHEL 8.9", self.pages["socle?famille=systemes"])
        self.assertIn("Preuve : paquet jdk-17", self.pages["logiciels?q=distrib:oracle-jdk"])
        self.assertIn("Licence probable des JDK Oracle", p)
        self.assertIn("gratuit (NFTC)", p)
        self.assertIn("licence%3Agratuit", p)
        self.assertIn("gratuit (NFTC)", self.pages["logiciels?q=distrib:oracle-jdk"])
        self.assertIn("1 composants correspondent", self.pages[self.R[2]])
        self.assertIn("1 composants correspondent", self.pages[self.R[1]])

    def test_processeurs(self):
        p = self.pages["materiel?onglet=cpu"]
        self.assertIn("dont 1 avec AVX-512", p)
        self.assertIn("famille 6, modèle 85, stepping 7", p)
        self.assertIn("gather_data_sampling", p)
        self.assertIn("1 correspondent", self.pages["materiel?onglet=cpu&q=avx512"])
        self.assertNotIn("Xeon(R) Gold", self.pages["materiel?onglet=cpu&q=" + quote("!avx512f", safe="")].split("Par modèle")[1])
        self.assertIn("avx512 (f bw)", self.pages["serveur/" + quote("APPDEMO|prod|app1.exemple.test", safe="")])

    def test_export_vue(self):
        det = self.pages["__csv"][self.R[1]]
        self.assertEqual(det["name"], "cmdb_logiciels.csv")
        self.assertIn("distribution", det["header"])
        self.assertEqual([r[det["header"].index("name")] for r in det["rows"]], ["jdk-17"])
        grp = self.pages["__csv"]["logiciels?q=java&vue=versions"]
        self.assertEqual(grp["name"], "cmdb_logiciels_par_version.csv")
        self.assertEqual(grp["header"][:3], ["composant", "distribution", "version"])
        rh = [r for r in grp["rows"] if r[1] == "OpenJDK Red Hat"]
        self.assertEqual(len(rh), 1)
        self.assertEqual(rh[0][3], 2)
        self.assertIn("APPDEMO / recette (1)", rh[0][6])


if __name__ == "__main__":
    unittest.main()


class ReglagesRapport(unittest.TestCase):
    """Socle logiciel › Réglages et Modules ; export CSV de chaque tableau, conforme à la vue affichée."""
    K = "session.upload_progress.enabled"
    R = ["socle?famille=reglages", "socle?famille=reglages&produit=php&cle=" + K,
         "socle?famille=reglages&produit=php&cle=" + K + "&valeur=Off", "socle?famille=reglages&produit=apache&cle=ServerTokens",
         "socle?famille=modules", "socle?famille=java", "serveurs?q=t1", "versions?q=t1", "services?onglet=modules&q=mbstring"]

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="cmdbr")
        store, out = os.path.join(cls.d, "store"), os.path.join(cls.d, "build")
        a = fleet.app_host()
        a["filesystem"]["config_directives"] = [
            {"product": "php", "key": cls.K, "value": "0", "path": "/etc/php/8.1/apache2/php.ini"},
            {"product": "apache", "key": "ServerTokens", "value": "Prod", "path": "/etc/httpd/conf/httpd.conf"}]
        t = fleet.twin("t1.exemple.test", "10.0.1.1", pf="recette")
        t["filesystem"] = {"config_directives": [{"product": "php", "key": "memory_limit", "value": "256M", "path": "/etc/php/8.1/apache2/php.ini"},
                                                 {"product": "apache", "key": "TraceEnable", "value": "Off", "path": "/etc/httpd/conf/httpd.conf"}]}
        fleet.write_store(store, [a, t])
        subprocess.check_call([sys.executable, os.path.join(TOOLS, "cmdb_build.py"), "--store", store, "--out", out], stdout=subprocess.DEVNULL)
        res = subprocess.check_output(["node", os.path.join(ROOT, "tests", "report_harness.js"), os.path.join(out, "cmdb_rapport.html")] + cls.R)
        cls.pages = json.loads(res.decode("utf-8"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def csv(self, route, name):
        return next(t for t in self.pages["__tcsv"][route] if t["name"] == name)

    def test_reglages(self):
        p = self.pages[self.R[0]]
        self.assertIn("Réglages", p)
        self.assertIn(self.K, p)
        x = self.csv(self.R[0], "cmdb_socle_reglages_reglages.csv")
        self.assertEqual(x["header"], ["Réglage", "Serveurs", "Valeurs distinctes", "Répartition (serveurs)", "Sources"])
        row = next(r for r in x["rows"] if r[0] == self.K)
        self.assertEqual(row[1:4], [2, 2, "Off (1) ; On (1)"])   # mod_php : 0 -> Off ; t1 : défaut PHP On
        v = self.csv(self.R[1], "cmdb_socle_reglages_php_" + self.K + "_par_valeur.csv")
        self.assertEqual(sorted((r[0], r[1]) for r in v["rows"]), [("Off", 1), ("On", 1)])
        s = self.csv(self.R[2], "cmdb_socle_reglages_php_" + self.K + "_par_serveur.csv")
        self.assertEqual(s["header"][:4], ["Application", "Plate-forme", "Serveur", "Valeur"])
        self.assertEqual([r[2:4] for r in s["rows"]], [["app1.exemple.test", "Off"]])
        # Apache : t1 a des directives Apache, mais pas ServerTokens
        st = self.csv(self.R[3], "cmdb_socle_reglages_apache_ServerTokens_par_valeur.csv")
        self.assertEqual(sorted(r[0] for r in st["rows"]), ["(non relevé)", "Prod"])

    def test_modules(self):
        p = self.pages["socle?famille=modules"]
        self.assertIn("mbstring", p)
        x = self.csv("socle?famille=modules", "cmdb_socle_modules_modules.csv")
        self.assertIn("mbstring", [r[0] for r in x["rows"]])

    def test_exports(self):
        # Socle par version : export du tableau affiché
        names = [t["name"] for t in self.pages["__tcsv"]["socle?famille=java"]]
        self.assertIn("cmdb_socle_java_par_version.csv", names)
        # Serveurs et Versions : le bouton de la page suit le filtre
        self.assertEqual([r[2] for r in self.pages["__csv"]["serveurs?q=t1"]["rows"]], ["t1.exemple.test"])
        self.assertEqual([r[2] for r in self.pages["__csv"]["versions?q=t1"]["rows"]], ["t1.exemple.test"])
        # un tableau quelconque : filtre appliqué, texte sans balises, serveur précédé de l'application
        m = self.pages["__tcsv"]["services?onglet=modules&q=mbstring"][0]
        self.assertEqual(m["header"][:3], ["Application", "Plate-forme", "Serveur"])
        self.assertTrue(m["rows"] and all("mbstring" in " ".join(map(str, r)) for r in m["rows"]))
        self.assertFalse(any("<" in str(c) for r in m["rows"] for c in r))


class MisesAJourRapport(unittest.TestCase):
    """Page Mises à jour, onglet Paquets de la fiche serveur, alertes de mises à jour et de fin de support."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="cmdbu")
        store, out = os.path.join(cls.d, "store"), os.path.join(cls.d, "build")
        a = fleet.app_host()
        a["packages"]["managers"]["rpm"] = [{"name": "openssl-libs", "epoch": "1", "version": "3.0.7", "release": "24.el9", "arch": "x86_64", "vendor": "Red Hat, Inc."}]
        a["update_cache"] = {"manager": "dnf", "cache_date": "2026-01-01T00:00:00Z", "last_change": "2026-01-01T00:00:00Z", "commands": [
            {"name": "check_update", "rc": 100, "output": "openssl-libs.x86_64  1:3.0.7-25.el9  baseos\n"},
            {"name": "updateinfo_security", "rc": 0, "output": "RHSA-2024:1 Important/Sec. openssl-libs-1:3.0.7-25.el9.x86_64\n"}]}
        w = fleet.doc("w1.exemple.test", "APPDEMO", "prod", "10.0.0.3", "r2", "2026-11-02T08:00:00Z")
        w["os"]["os_release"] = {"ID": "windows-server", "VERSION_ID": "2012-r2", "PRETTY_NAME": "Windows Server 2012 R2"}
        w["windows"] = {"os": {"caption": "Microsoft Windows Server 2012 R2", "build": "9600", "ubr": "21000"},
                        "programs": [{"name": "7-Zip", "version": "24.08"}], "hotfixes": [{"id": "KB5044284", "installed_on": "10/20/2026"}]}
        fleet.write_store(store, [a, w])
        subprocess.check_call([sys.executable, os.path.join(TOOLS, "cmdb_build.py"), "--store", store, "--out", out], stdout=subprocess.DEVNULL)
        cls.R = ["misesajour", "misesajour?onglet=serveurs", "misesajour?onglet=paquets", "misesajour?onglet=windows", "alertes", "accueil",
                 "serveur/" + quote("APPDEMO|prod|app1.exemple.test", safe="") + "?onglet=paquets",
                 "serveur/" + quote("APPDEMO|prod|w1.exemple.test", safe="") + "?onglet=paquets",
                 "serveur/" + quote("APPDEMO|prod|w1.exemple.test", safe=""), "support?onglet=systemes"]
        res = subprocess.check_output(["node", os.path.join(ROOT, "tests", "report_harness.js"), os.path.join(out, "cmdb_rapport.html")] + cls.R)
        cls.pages = json.loads(res.decode("utf-8"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def test_pages(self):
        p = self.pages["misesajour"]
        self.assertIn("À traiter", p)
        self.assertIn("correctifs de sécurité non appliqués", p)
        self.assertIn("système hors support depuis le 2023-10-10<", self.pages["misesajour?onglet=serveurs"])
        self.assertIn("openssl-libs", self.pages["misesajour?onglet=paquets"])
        self.assertIn("9600.21000", self.pages["misesajour?onglet=windows"])
        self.assertIn("Mises à jour en retard", self.pages["alertes"])
        self.assertIn("Systèmes hors support", self.pages["alertes"])
        self.assertIn("Serveurs en retard de mises à jour", self.pages["accueil"])
        s = self.pages[self.R[6]]
        self.assertIn("1:3.0.7-25.el9", s)
        self.assertIn("RHSA-2024:1", s)
        self.assertIn("Paquets installés", s)
        wp = self.pages[self.R[7]]
        self.assertIn("Programmes installés", wp)
        self.assertIn("7-Zip", wp)
        self.assertIn("KB5044284", wp)
        self.assertIn("2026-10-20", wp)
        self.assertIn("Fin de support du système", self.pages[self.R[8]])
        self.assertIn("windows-server", self.pages["support?onglet=systemes"])
