# -*- coding: utf-8 -*-
import html.parser
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests import fleet
from tests.common import TOOLS


class Balises(html.parser.HTMLParser):
    VIDES = {"meta", "br", "rect", "path"}

    def __init__(self):
        super().__init__()
        self.pile, self.erreurs, self.scripts = [], [], 0

    def handle_starttag(self, tag, attrs):
        self.scripts += tag == "script"
        if tag not in self.VIDES:
            self.pile.append(tag)

    def handle_startendtag(self, tag, attrs):
        pass

    def handle_endtag(self, tag):
        if not self.pile or self.pile.pop() != tag:
            self.erreurs.append(tag)


class Dossier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="cmdbd")
        store = os.path.join(cls.d, "store")
        etrangere = fleet.doc("secret1.exemple.test", "AUTREAPP", "prod", "10.5.0.1", "r2", "2026-11-02T08:00:00Z",
                              filesystem={"endpoints": [{"product": "nginx", "kind": "vhost", "port": 443, "server_name": "confidentiel.exemple.test"}]})
        voisine = fleet.doc("voisin1.exemple.test", "VOISINE", "prod", "10.6.0.1", "r2", "2026-11-02T08:00:00Z",
                            established=[{"direction": "out", "remote_addr": "10.0.0.11", "remote_port": 5432, "process": "java", "count": 1}],
                            filesystem={"endpoints": [{"product": "nginx", "kind": "vhost", "port": 443, "server_name": "interne-voisine.exemple.test"}]})
        fleet.write_store(store, [fleet.oracle_host(), fleet.app_host(), fleet.pg_host(), fleet.pg_standby(), fleet.web_host(), fleet.nas_client(), fleet.lun_peer(),
                                  fleet.twin("r1.exemple.test", "10.0.2.1", php="8.3.0", pf="recette"), etrangere, voisine])
        out = os.path.join(cls.d, "build")
        subprocess.check_call([sys.executable, os.path.join(TOOLS, "cmdb_build.py"), "--store", store, "--out", out, "--dossier-mention", "Diffusion <restreinte>"],
                              stdout=subprocess.DEVNULL)
        cls.dir = os.path.join(out, "dossiers")
        with open(os.path.join(cls.dir, "APPDEMO__prod.html"), encoding="utf-8") as f:
            cls.t = f.read()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def test_un_fichier_par_perimetre(self):
        self.assertEqual(sorted(os.listdir(self.dir)), ["APPDEMO__prod.html", "APPDEMO__recette.html", "AUTREAPP__prod.html", "VOISINE__prod.html"])

    def test_cloisonnement(self):
        self.assertNotIn("secret1", self.t)
        self.assertNotIn("AUTREAPP", self.t)
        self.assertNotIn("confidentiel.exemple.test", self.t)

    def test_voisine_reduite_a_son_lien(self):
        self.assertIn("voisin1.exemple.test", self.t)
        self.assertNotIn("interne-voisine.exemple.test", self.t)

    def test_contenu(self):
        for x in ("ora1.exemple.test", "19.23.0.0.240416", "www.exemple.test", "appdb", "nas1.exemple.test", "<svg", "ANSSI-BP-028", "site.exemple.test", "Limites de ce document"):
            self.assertIn(x, self.t, x)

    def test_ecarts_entre_plates_formes(self):
        sec = self.t[self.t.index('id="ecarts"'):]
        self.assertIn("prod (ce dossier)", sec)
        self.assertIn("à promouvoir en prod", sec)
        self.assertIn("passer prod à 8.3.0", sec)

    def test_points_d_attention(self):
        self.assertIn("clé(s) privée(s) exposée(s)", self.t)
        self.assertIn("certificat à renouveler", self.t)
        self.assertIn("ORACLE_HOME dont le niveau", self.t)

    def test_html_bien_forme_et_sans_script(self):
        p = Balises()
        p.feed(self.t)
        self.assertEqual((p.erreurs, p.pile, p.scripts), ([], [], 0))

    def test_mention_echappee(self):
        self.assertIn("Diffusion &lt;restreinte&gt;", self.t)

    def test_perimetre_vide_sans_erreur(self):
        with open(os.path.join(self.dir, "AUTREAPP__prod.html"), encoding="utf-8") as f:
            t = f.read()
        self.assertIn("confidentiel.exemple.test", t)
        self.assertNotIn("ora1.exemple.test", t)


if __name__ == "__main__":
    unittest.main()
