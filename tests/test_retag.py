# -*- coding: utf-8 -*-
"""cmdb_retag.py : correction des étiquettes d'un lot mal étiqueté."""
import gzip
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest

from tests import fleet
from tests.common import TOOLS

RETAG = os.path.join(TOOLS, "cmdb_retag.py")
RID = "20261112T090000Z-1a2b"


def run(*args):
    p = subprocess.run([sys.executable, RETAG] + list(args), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.returncode, p.stdout.decode("utf-8")


def members(path):
    out = {}
    with tarfile.open(path) as tf:
        for m in tf:
            if m.isfile():
                raw = tf.extractfile(m).read()
                out[m.name] = json.loads(gzip.decompress(raw).decode("utf-8") if m.name.endswith(".gz") else raw.decode("utf-8"))
    return out


def make_lot(d):
    """Lot d'un passage couvrant prod et recette, tout étiqueté APPDEMO/prod (comme finish.yml)."""
    docs = [fleet.twin("app1.exemple.test", "10.0.0.20", run=RID), fleet.twin("rec-app1.exemple.test", "10.0.1.20", run=RID)]
    docs[1]["meta"]["tags"]["squad"] = "S3"
    path = os.path.join(d, "APPDEMO__prod__%s.tar.gz" % RID)
    with tarfile.open(path, "w:gz") as tf:
        def add(name, data):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, __import__("io").BytesIO(data))
        add("_runs/%s/_run.json" % RID, json.dumps({"run_id": RID, "started_at": "2026-11-12T09:00:00Z"}).encode())
        for doc in docs:
            h = doc["meta"]["host_label"]
            rel = "APPDEMO/prod/%s/%s.json.gz" % (h, RID)
            add(rel, gzip.compress(json.dumps(doc).encode()))
            add("APPDEMO/prod/%s/%s.ansible_facts.json" % (h, RID), b'{"ansible_hostname": "x"}')
            add("_runs/%s/APPDEMO__prod__%s.json" % (RID, h), json.dumps(
                {"run_id": RID, "host": h, "app": "APPDEMO", "platform": "prod", "status": "ok", "file": rel,
                 "tags": dict((k, v) for k, v in doc["meta"]["tags"].items() if k not in ("app", "platform"))}).encode())
        add("_runs/%s/APPDEMO__prod__rec-db1.json" % RID, json.dumps(
            {"run_id": RID, "host": "rec-db1", "app": "APPDEMO", "platform": "prod", "status": "unreachable", "file": None, "tags": {}}).encode())
    return path


class Retag(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="cmdbretag")
        self.lot = make_lot(self.d)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_liste_sans_correction(self):
        rc, out = run(self.lot)
        self.assertEqual(rc, 0, out)
        self.assertIn("rec-app1.exemple.test", out)
        self.assertIn("APPDEMO/prod  [squad=S3]", out)
        self.assertEqual(sorted(os.listdir(self.d)), [os.path.basename(self.lot)])

    def test_simulation(self):
        rc, out = run(self.lot, "--platform", "recette", "--host", "rec-*", "-n")
        self.assertEqual(rc, 0, out)
        self.assertIn("* rec-app1.exemple.test", out)
        self.assertIn("rec-db1 (sans collecte : unreachable)", out)
        self.assertEqual(sorted(os.listdir(self.d)), [os.path.basename(self.lot)])

    def test_partie_des_hotes(self):
        rc, out = run(self.lot, "--platform", "recette", "--host", "rec-*", "--tag", "site=Paris")
        self.assertEqual(rc, 0, out)
        new = os.path.join(self.d, "APPDEMO__prod+recette__%s.tar.gz" % RID)
        self.assertEqual(sorted(os.listdir(self.d)), sorted([os.path.basename(new), os.path.basename(self.lot) + ".orig"]))
        m = members(new)
        doc = m["APPDEMO/recette/rec-app1.exemple.test/%s.json.gz" % RID]
        self.assertEqual(doc["meta"]["tags"], {"app": "APPDEMO", "platform": "recette", "squad": "S3", "site": "Paris"})
        self.assertEqual(doc["meta"]["retag"][0]["before"], {"app": "APPDEMO", "platform": "prod", "squad": "S3"})
        self.assertIn("APPDEMO/recette/rec-app1.exemple.test/%s.ansible_facts.json" % RID, m)
        st = m["_runs/%s/APPDEMO__recette__rec-app1.exemple.test.json" % RID]
        self.assertEqual((st["platform"], st["file"], st["tags"]),
                         ("recette", "APPDEMO/recette/rec-app1.exemple.test/%s.json.gz" % RID, {"squad": "S3", "site": "Paris"}))
        self.assertEqual(m["_runs/%s/APPDEMO__recette__rec-db1.json" % RID]["platform"], "recette")
        # Hôte non retenu : intact
        self.assertEqual(m["APPDEMO/prod/app1.exemple.test/%s.json.gz" % RID]["meta"]["tags"], {"app": "APPDEMO", "platform": "prod"})
        self.assertIn("_runs/%s/APPDEMO__prod__app1.exemple.test.json" % RID, m)
        self.assertIn("_runs/%s/_run.json" % RID, m)
        # Consolidation : chaque serveur sur sa plate-forme
        out_dir = os.path.join(self.d, "build")
        subprocess.check_output([sys.executable, os.path.join(TOOLS, "cmdb_build.py"), "--out", out_dir, "--no-report",
                                 "--no-dossiers", "--lot", os.path.join(self.d, "*.tar.gz")], stderr=subprocess.STDOUT)
        db = sqlite3.connect(os.path.join(out_dir, "cmdb.sqlite"))
        rows = sorted(db.execute("SELECT app, platform, host FROM hosts").fetchall())
        db.close()
        self.assertEqual(rows, [("APPDEMO", "prod", "app1.exemple.test"), ("APPDEMO", "recette", "rec-app1.exemple.test")])

    def test_tout_le_lot_vers_un_autre_fichier(self):
        dst = os.path.join(self.d, "corrige.tar.gz")
        rc, out = run(self.lot, "--app", "APPAUTRE", "--platform", "preprod", "--untag", "squad", "-o", dst)
        self.assertEqual(rc, 0, out)
        self.assertTrue(os.path.isfile(self.lot))
        m = members(dst)
        self.assertEqual(sorted(k for k in m if k.endswith(".json.gz")),
                         ["APPAUTRE/preprod/%s/%s.json.gz" % (h, RID) for h in ("app1.exemple.test", "rec-app1.exemple.test")])
        self.assertEqual(m["APPAUTRE/preprod/rec-app1.exemple.test/%s.json.gz" % RID]["meta"]["tags"],
                         {"app": "APPAUTRE", "platform": "preprod"})

    def test_nom_inchange_original_garde(self):
        rc, out = run(self.lot, "--tag", "site=Lyon")
        self.assertEqual(rc, 0, out)
        self.assertTrue(os.path.isfile(self.lot + ".orig"))
        self.assertEqual(members(self.lot)["APPDEMO/prod/app1.exemple.test/%s.json.gz" % RID]["meta"]["tags"]["site"], "Lyon")
        rc, out = run(self.lot, "--tag", "site=Nice")
        self.assertEqual(rc, 2, out)   # .orig déjà là : pas d'écrasement silencieux

    def test_refus(self):
        self.assertEqual(run(self.lot, "--platform", "pré prod")[0], 2)
        self.assertEqual(run(self.lot, "--untag", "app")[0], 2)
        rc, out = run(self.lot, "--platform", "recette", "--host", "inconnu*")
        self.assertEqual(rc, 1, out)
        self.assertEqual(sorted(os.listdir(self.d)), [os.path.basename(self.lot)])


if __name__ == "__main__":
    unittest.main()
