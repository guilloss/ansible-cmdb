# -*- coding: utf-8 -*-
"""Lecture des magasins et des lots : résultats identiques, lots déjà présents ignorés,
seuls les en-têtes des collectes restent en mémoire."""
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
import cmdb_build as B

TABLES = ("hosts", "software", "changes", "drift", "listening", "oracle_homes", "crypto_files")


def make_fleet(root):
    """Magasin à deux passages (r1, r2) avec leurs manifestes et leurs lots, comme finish.yml."""
    store = os.path.join(root, "store")
    old = fleet.oracle_host("r1", "2026-10-01T08:00:00Z", "19.21.0.0.231017", "35643107")
    old_app = fleet.app_host("r1", "2026-10-01T08:00:00Z")
    old_app["filesystem"]["crypto_files"] = []
    docs = [old, old_app, fleet.oracle_host(), fleet.app_host(), fleet.pg_host(), fleet.web_host(),
            fleet.twin("app2.exemple.test", "10.0.0.21"), fleet.twin("app3.exemple.test", "10.0.0.22", php="8.1.27")]
    fleet.write_store(store, docs)
    lots = os.path.join(root, "lots")
    os.makedirs(lots)
    for rid in ("r1", "r2"):
        rd = os.path.join(store, "_runs", rid)
        os.makedirs(rd)
        with open(os.path.join(rd, "_run.json"), "w") as f:
            json.dump({"run_id": rid, "started_at": "2026-11-02T08:00:00Z"}, f)
        with tarfile.open(os.path.join(lots, rid + ".tar.gz"), "w:gz") as tf:
            tf.add(rd, "_runs/" + rid)
            for d in docs:
                m = d["meta"]
                if m["run_id"] == rid:
                    p = os.path.join(m["tags"]["app"], m["tags"]["platform"], m["host_label"], rid + ".json.gz")
                    tf.add(os.path.join(store, p), p)
    return store, lots


def build(root, name, *args):
    out = os.path.join(root, name)
    log = subprocess.check_output([sys.executable, os.path.join(TOOLS, "cmdb_build.py"), "--out", out,
                                   "--no-report", "--no-dossiers"] + list(args), stderr=subprocess.STDOUT).decode()
    db = sqlite3.connect(os.path.join(out, "cmdb.sqlite"))
    rows = {}
    for t in TABLES:
        cols = [c[1] for c in db.execute("PRAGMA table_info(%s)" % t) if c[1] not in ("source", "source_file")]
        rows[t] = sorted(db.execute("SELECT %s FROM %s" % (", ".join(cols), t)).fetchall(), key=repr)
    db.close()
    return log, rows


class Lots(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="cmdbs")
        cls.store, cls.lots = make_fleet(cls.d)
        cls.lot_glob = os.path.join(cls.lots, "*.tar.gz")
        cls.from_store = build(cls.d, "a", "--store", cls.store)
        cls.from_lots = build(cls.d, "b", "--lot", cls.lot_glob)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def test_jeu_non_vide(self):
        rows = self.from_store[1]
        self.assertEqual(len(rows["hosts"]), 6)
        self.assertTrue(rows["changes"])
        self.assertTrue(rows["drift"])

    def test_lots_equivalents_au_magasin(self):
        for t in TABLES:
            self.assertEqual(self.from_store[1][t], self.from_lots[1][t], t)

    def test_lot_deja_dans_le_magasin_ignore(self):
        log, rows = build(self.d, "c", "--store", self.store, "--lot", self.lot_glob)
        self.assertEqual(log.count("Lot ignoré"), 2)
        self.assertIn("passage r2 déjà présent dans le magasin", log)
        self.assertIn("6 collectes lues", log)
        for t in TABLES:
            self.assertEqual(rows[t], self.from_store[1][t], t)

    def test_lot_renomme_reconnu(self):
        """La détection lit le passage dans le lot (_runs/<run_id>/), pas dans le nom du fichier."""
        d = tempfile.mkdtemp(prefix="cmdbr")
        try:
            shutil.copy(os.path.join(self.lots, "r2.tar.gz"), os.path.join(d, "transfert.tar.gz"))
            s = B.Store()
            s.add_dir(self.store)
            self.assertEqual(s.add_lot(os.path.join(d, "transfert.tar.gz")), "r2")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_lot_d_une_autre_equipe_lu(self):
        s = B.Store()
        self.assertIsNone(s.add_lot(os.path.join(self.lots, "r2.tar.gz")))
        self.assertEqual(len(s.docs), 6)

    def test_seuls_les_en_tetes_restent_en_memoire(self):
        s = B.Store()
        s.add_dir(self.store)
        s.add_lot(os.path.join(self.lots, "r1.tar.gz"))
        s2 = B.Store()
        s2.add_lot(os.path.join(self.lots, "r2.tar.gz"))
        for st in (s, s2):
            for meta, ref, _facts, _src in st.docs.values():
                self.assertIn("run_id", meta)
                self.assertNotIn("filesystem", meta)
                self.assertIn(ref[0], ("file", "gz"))
                self.assertIsInstance(ref[1], (str, bytes))
        self.assertEqual(s2.docs[("APPDEMO", "prod", "app1.exemple.test")][1][0], "gz")
        self.assertEqual(len(s.previous), 2)
        docs = list(s.current())
        self.assertEqual([k for k, _d, _f, _s in docs], sorted(s.docs))
        self.assertIn("filesystem", docs[0][1])
        prev = dict(s.previous_docs())
        self.assertEqual(prev[("APPDEMO", "prod", "ora1.exemple.test")][0]["meta"]["run_id"], "r1")


if __name__ == "__main__":
    unittest.main()
