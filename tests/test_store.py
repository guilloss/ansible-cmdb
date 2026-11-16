# -*- coding: utf-8 -*-
"""Lecture des magasins et des lots : résultats identiques, lots déjà présents ignorés,
seuls les en-têtes des collectes restent en mémoire."""
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

    def test_magasin_converti_en_lots(self):
        d = tempfile.mkdtemp(prefix="cmdbc")
        self.addCleanup(shutil.rmtree, d, True)
        out = subprocess.check_output([sys.executable, os.path.join(TOOLS, "cmdb_store2lots.py"), self.store,
                                       os.path.join(d, "lots")]).decode()
        self.assertEqual(sorted(os.listdir(os.path.join(d, "lots"))), ["APPDEMO__prod__r1.tar.gz", "APPDEMO__prod__r2.tar.gz"], out)
        with tarfile.open(os.path.join(d, "lots", "APPDEMO__prod__r2.tar.gz")) as tf:
            names = tf.getnames()
        self.assertIn("_runs/r2/_run.json", names)
        self.assertFalse([n for n in names if n.endswith("latest.json.gz") or "r1" in n], names)
        log, rows = build(d, "o", "--lot", os.path.join(d, "lots", "*.tar.gz"))
        for t in TABLES:
            self.assertEqual(rows[t], self.from_store[1][t], t)
        # le magasin d'origine fait foi : les lots convertis y sont reconnus et ignorés
        log, rows = build(d, "o2", "--store", self.store, "--lot", os.path.join(d, "lots", "*.tar.gz"))
        self.assertEqual(log.count("Lot ignoré"), 2)

    def test_lots_refaits_depuis_la_base(self):
        # .json.gz purgés : les lots se refont depuis raw_documents de la consolidation
        d = tempfile.mkdtemp(prefix="cmdbq")
        self.addCleanup(shutil.rmtree, d, True)
        runs = os.path.join(d, "store")
        shutil.copytree(os.path.join(self.store, "_runs"), os.path.join(runs, "_runs"))
        out = subprocess.check_output([sys.executable, os.path.join(TOOLS, "cmdb_store2lots.py"), "--from-sqlite",
                                       os.path.join(self.d, "a", "cmdb.sqlite"), runs, os.path.join(d, "lots")]).decode()
        self.assertNotIn("sans manifeste", out)
        log, rows = build(d, "o", "--lot", os.path.join(d, "lots", "*.tar.gz"), "--no-history")
        ref = build(d, "ref", "--store", self.store, "--no-history")[1]
        for t in TABLES:
            self.assertEqual(rows[t], ref[t], t)

    def test_majuscules_a_la_demande(self):
        d = tempfile.mkdtemp(prefix="cmdbu")
        self.addCleanup(shutil.rmtree, d, True)
        for i, (app, pf, host, day) in enumerate((("appDemo", "prod", "w1", "10"), ("APPDEMO", "Prod", "w1", "11"),
                                                  ("AppDemo", "rec", "w2", "11"))):
            os.makedirs(os.path.join(d, "s", "x%d" % i))
            doc = {"schema": "cmdb-collector/1", "os": {"os_release": {"ID": "rhel", "VERSION_ID": "8.9"}},
                   "meta": {"host_label": host, "run_id": "r%d" % i, "started_at": "2026-11-%sT08:00:00Z" % day,
                            "tags": {"app": app, "platform": pf, "site": "Paris"}}}
            with gzip.open(os.path.join(d, "s", "x%d" % i, "r%d.json.gz" % i), "wt") as f:
                json.dump(doc, f)
        log, rows = build(d, "o", "--store", os.path.join(d, "s"), "--upper-labels", "--app", "appdemo", "--platform", "prod")
        self.assertIn("Hôtes consolidés : 1 ", log)
        db = sqlite3.connect(os.path.join(d, "o", "cmdb.sqlite"))
        self.assertEqual(db.execute("SELECT app, platform, host, tags FROM hosts").fetchall(),
                         [("APPDEMO", "PROD", "w1", '{"app": "APPDEMO", "platform": "PROD", "site": "PARIS"}')])
        # la collecte d'origine (raw_documents) reste telle que saisie
        self.assertIn('"Prod"', db.execute("SELECT document FROM raw_documents").fetchone()[0])
        db.close()
        log, rows = build(d, "p", "--store", os.path.join(d, "s"))
        self.assertIn("Hôtes consolidés : 3 ", log)

    def test_nom_reel_et_alias_ansible(self):
        d = tempfile.mkdtemp(prefix="cmdbh")
        self.addCleanup(shutil.rmtree, d, True)
        cases = (("web01", "srv-web-01", "r1"), ("db01.exemple.test", "db01", "r1"), ("app1", "APP1", "r1"), ("nu", None, "r1"),
                 ("web01", "srv-web-01", "r2"))
        for i, (alias, real, rid) in enumerate(cases):
            os.makedirs(os.path.join(d, "s", "x%d" % i))
            doc = {"schema": "cmdb-collector/1", "os": {"os_release": {"ID": "rhel", "VERSION_ID": "8.9"}, "hostname": real},
                   "meta": {"host_label": alias, "run_id": rid, "started_at": "2026-11-1%dT08:00:00Z" % i,
                            "tags": {"app": "A", "platform": "prod"}}}
            with gzip.open(os.path.join(d, "s", "x%d" % i, rid + ".json.gz"), "wt") as f:
                json.dump(doc, f)
        # manifeste du passage r2 : web01 collecté, ghost injoignable (noms d'inventaire)
        os.makedirs(os.path.join(d, "s", "_runs", "r2"))
        for host, st in (("web01", "ok"), ("ghost", "unreachable")):
            with open(os.path.join(d, "s", "_runs", "r2", "A__prod__%s.json" % host), "w") as f:
                json.dump({"run_id": "r2", "host": host, "app": "A", "platform": "prod", "status": st}, f)
        log, rows = build(d, "o", "--store", os.path.join(d, "s"), "--real-hostnames")
        db = sqlite3.connect(os.path.join(d, "o", "cmdb.sqlite"))
        self.assertEqual(db.execute("SELECT host, inventory_name FROM hosts ORDER BY host").fetchall(),
                         [("app1", "app1"), ("db01.exemple.test", "db01.exemple.test"), ("nu", "nu"),
                          ("srv-web-01 (web01)", "web01")])
        self.assertEqual(db.execute("SELECT host, status FROM runs WHERE run_id = 'r2' ORDER BY host").fetchall(),
                         [("ghost", "unreachable"), ("srv-web-01 (web01)", "ok")])
        # les deux collectes de web01 sont le même serveur (historique)
        self.assertEqual(db.execute("SELECT COUNT(*) FROM hosts WHERE inventory_name = 'web01'").fetchone()[0], 1)
        db.close()
        log, rows = build(d, "f", "--store", os.path.join(d, "s"), "--real-hostnames", "--host", "web01")
        self.assertIn("Hôtes consolidés : 1 ", log)
        log, rows = build(d, "i", "--store", os.path.join(d, "s"))
        self.assertIn(("web01",), [r[2:3] for r in rows["hosts"]])

    def test_lien_dur_lu_une_fois(self):
        d = tempfile.mkdtemp(prefix="cmdbl")
        self.addCleanup(shutil.rmtree, d, True)
        os.link(os.path.join(self.lots, "r2.tar.gz"), os.path.join(d, "APP__pf__r2.tar.gz"))
        os.link(os.path.join(self.lots, "r2.tar.gz"), os.path.join(d, "r2.tar.gz"))
        log, rows = build(d, "o", "--lot", os.path.join(d, "*.tar.gz"))
        self.assertIn("même fichier que", log)
        self.assertEqual(log.count("Lot ignoré"), 1)

    def test_copie_identique_lue_une_fois(self):
        """Partage sans liens durs : le nom d'origine du lot est une copie, lue une seule fois."""
        d = tempfile.mkdtemp(prefix="cmdbl")
        self.addCleanup(shutil.rmtree, d, True)
        shutil.copy(os.path.join(self.lots, "r2.tar.gz"), os.path.join(d, "APP__pf__r2.tar.gz"))
        shutil.copy(os.path.join(self.lots, "r2.tar.gz"), os.path.join(d, "r2.tar.gz"))
        shutil.copy(os.path.join(self.lots, "r1.tar.gz"), os.path.join(d, "r1.tar.gz"))
        log, rows = build(d, "o", "--lot", os.path.join(d, "*.tar.gz"))
        self.assertIn("copie identique de", log)
        self.assertEqual(log.count("Lot ignoré"), 1)
        ref_log, ref = build(d, "p", "--lot", os.path.join(d, "APP__pf__r2.tar.gz"), "--lot", os.path.join(d, "r1.tar.gz"))
        for t in TABLES:
            self.assertEqual(rows[t], ref[t], t)

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


class Archivage(unittest.TestCase):
    """cmdb_archive.py : les N dernières collectes de chaque serveur restent, les autres vont dans _archive."""

    def setUp(self):
        import importlib.util
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        spec = importlib.util.spec_from_file_location("cmdb_archive", os.path.join(here, "roles", "cmdb_collect", "files", "cmdb_archive.py"))
        self.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.mod)
        self.d = tempfile.mkdtemp(prefix="cmdbarch")
        self.addCleanup(shutil.rmtree, self.d, True)
        self.host = os.path.join(self.d, "APP", "prod", "srv1")
        os.makedirs(self.host)
        for rid in ("20261101T080000Z-aaaa", "20261102T080000Z-bbbb", "20261103T080000Z-cccc", "20261104T080000Z-dddd"):
            for suffix in (".json.gz", ".ansible_facts.json"):
                open(os.path.join(self.host, rid + suffix), "w").close()
        open(os.path.join(self.host, "20261101T090000Z-eeee.error.json"), "w").close()   # échec sans collecte, ancien
        open(os.path.join(self.host, "20261105T080000Z-ffff.error.json"), "w").close()   # échec récent : reste
        open(os.path.join(self.host, "latest.json.gz"), "w").close()
        os.makedirs(os.path.join(self.d, "_runs", "20261101T080000Z-aaaa"))
        other = os.path.join(self.d, "APP", "prod", "srv2")
        os.makedirs(other)
        open(os.path.join(other, "20261104T080000Z-dddd.json.gz"), "w").close()

    def test_garde_les_deux_dernieres(self):
        self.assertEqual(self.mod.main([self.d, "--keep", "2"]), 0)
        self.assertEqual(sorted(os.listdir(self.host)), [
            "20261103T080000Z-cccc.ansible_facts.json", "20261103T080000Z-cccc.json.gz",
            "20261104T080000Z-dddd.ansible_facts.json", "20261104T080000Z-dddd.json.gz",
            "20261105T080000Z-ffff.error.json", "latest.json.gz"])
        arch = os.path.join(self.d, "_archive", "APP", "prod", "srv1")
        self.assertEqual(sorted(os.listdir(arch)), [
            "20261101T080000Z-aaaa.ansible_facts.json", "20261101T080000Z-aaaa.json.gz", "20261101T090000Z-eeee.error.json",
            "20261102T080000Z-bbbb.ansible_facts.json", "20261102T080000Z-bbbb.json.gz"])
        self.assertTrue(os.path.isdir(os.path.join(self.d, "_runs", "20261101T080000Z-aaaa")))
        self.assertEqual(os.listdir(os.path.join(self.d, "APP", "prod", "srv2")), ["20261104T080000Z-dddd.json.gz"])
        # relancé : rien de plus, et l'archive n'est pas elle-même archivée
        self.assertEqual(self.mod.plan(self.d, 2, os.path.join(self.d, "_archive")), [])
        self.assertEqual(self.mod.plan(self.d, 1, os.path.join(self.d, "_archive"))[0][1],
                         os.path.join("APP", "prod", "srv1", "20261103T080000Z-cccc.ansible_facts.json"))

    def test_simulation_et_archive_externe(self):
        ext = os.path.join(self.d, "ailleurs")
        self.mod.main([self.d, "--keep", "3", "--dry-run", "--archive", ext])
        self.assertEqual(len(os.listdir(self.host)), 11)
        self.mod.main([self.d, "--keep", "3", "--archive", ext])
        self.assertEqual(sorted(os.listdir(os.path.join(ext, "APP", "prod", "srv1"))), [
            "20261101T080000Z-aaaa.ansible_facts.json", "20261101T080000Z-aaaa.json.gz", "20261101T090000Z-eeee.error.json"])

    def test_lots(self):
        import io as _io
        import tarfile as _tar
        lots = os.path.join(self.d, "_lots")
        os.makedirs(lots)
        r0, r1, r2, r3 = ("202611%02dT080000Z-000%d" % (i + 1, i) for i in range(4))
        # lot d'une version antérieure, sans application dans le nom : lue dans ses chemins
        with _tar.open(os.path.join(lots, r0 + ".tar.gz"), "w:gz") as tf:
            info = _tar.TarInfo("APP/prod/srv1/%s.json.gz" % r0)
            info.size = 1
            tf.addfile(info, _io.BytesIO(b"x"))
        for rid in (r1, r2, r3):
            for name in ("APP__prod__%s.tar.gz" % rid, rid + ".tar.gz"):
                open(os.path.join(lots, name), "w").close()
        open(os.path.join(lots, "APP__recette__%s.tar.gz" % r1), "w").close()
        open(os.path.join(lots, "equipe-a.tar.gz"), "w").close()       # nom imposé : ne bouge pas
        self.assertEqual(self.mod.main([self.d, "--keep", "0"]), 0)    # collectes intactes, lots archivés
        self.assertEqual(sorted(os.listdir(lots)), sorted(["APP__prod__%s.tar.gz" % r2, r2 + ".tar.gz", "APP__prod__%s.tar.gz" % r3,
                                                           r3 + ".tar.gz", "APP__recette__%s.tar.gz" % r1, "equipe-a.tar.gz"]))
        self.assertEqual(sorted(os.listdir(os.path.join(self.d, "_archive", "_lots"))),
                         sorted([r0 + ".tar.gz", "APP__prod__%s.tar.gz" % r1, r1 + ".tar.gz"]))
        self.assertEqual(len(os.listdir(self.host)), 11)
        # --keep-lots 0 : les lots ne bougent pas
        self.assertEqual(self.mod.plan_lots(lots, 0), [])
        self.assertEqual(len(self.mod.plan_lots(lots, 1)), 2)

    def test_consolidation_ignore_archive(self):
        d = tempfile.mkdtemp(prefix="cmdbarch")
        self.addCleanup(shutil.rmtree, d, True)
        from tests import fleet
        fleet.write_store(os.path.join(d, "s"), [fleet.pg_host()])
        old = fleet.app_host()
        fleet.write_store(os.path.join(d, "s", "_archive"), [old])
        log, rows = build(d, "o", "--store", os.path.join(d, "s"))
        self.assertEqual([r[2] for r in rows["hosts"]], ["pg1.exemple.test"])

