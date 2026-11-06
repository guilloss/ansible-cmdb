# -*- coding: utf-8 -*-
"""--java-db : identification par SHA-1 dans une base au schéma de trivy-java-db (pkg/db/db.go)."""
import glob
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from tests import fleet
from tests.common import TOOLS

KNOWN = "aa" * 20
UNKNOWN = "bb" * 20
PATH = "/opt/app/lib/"


def java_db(path):
    db = sqlite3.connect(path)
    db.executescript("""
        CREATE TABLE artifacts(id INTEGER PRIMARY KEY, group_id TEXT, artifact_id TEXT);
        CREATE TABLE indices(artifact_id INTEGER, version TEXT, sha1 BLOB, archive_type TEXT,
                             FOREIGN KEY (artifact_id) REFERENCES artifacts (id));
        CREATE UNIQUE INDEX indices_sha1_idx ON indices(sha1);
    """)
    db.execute("INSERT INTO artifacts VALUES (1, 'commons-codec', 'commons-codec')")
    db.execute("INSERT INTO indices VALUES (1, '1.3', ?, 'jar')", (bytes.fromhex(KNOWN),))
    db.commit()
    db.close()


class JavaDb(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="cmdbj")
        cls.store = os.path.join(cls.d, "store")
        host = fleet.app_host()
        host["filesystem"]["java_archives"] = [
            {"path": PATH + "codec.jar", "sha1": KNOWN.upper()},
            {"path": PATH + "editeur.jar", "sha1": UNKNOWN, "manifest": {"Implementation-Title": "Editeur"}},
            {"path": PATH + "sans-empreinte-1.0.jar"},
            {"path": PATH + "avec-pom.jar", "sha1": KNOWN, "maven": [{"groupId": "org.x", "artifactId": "y", "version": "2"}]},
            {"path": PATH + "conteneur.war", "nested": [{"path": PATH + "conteneur.war!/WEB-INF/lib/c.jar", "sha1": KNOWN}]},
        ]
        fleet.write_store(cls.store, [host])
        cls.base = os.path.join(cls.d, "java.db")
        java_db(cls.base)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def build(self, name, *extra):
        out = os.path.join(self.d, name)
        proc = subprocess.run([sys.executable, os.path.join(TOOLS, "cmdb_build.py"), "--store", self.store, "--out", out] + list(extra),
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
        return proc.returncode, proc.stdout, out

    def jars(self, out):
        db = sqlite3.connect(os.path.join(out, "cmdb.sqlite"))
        rows = db.execute("SELECT location, ecosystem, name, version, purl, evidence FROM software WHERE category = 'java-archive'").fetchall()
        db.close()
        return dict((r[0], r[1:]) for r in rows)

    def test_identification(self):
        code, log, out = self.build("avec", "--java-db", self.base)
        self.assertEqual(code, 0, log)
        jars = self.jars(out)
        self.assertEqual(jars[PATH + "codec.jar"], ("maven", "commons-codec:commons-codec", "1.3",
                                                    "pkg:maven/commons-codec/commons-codec@1.3", "sha1 trivy-java-db"))
        self.assertEqual(jars[PATH + "editeur.jar"][0], "maven-unidentified")
        self.assertEqual(jars[PATH + "sans-empreinte-1.0.jar"][0], "maven-unidentified")
        self.assertEqual(jars[PATH + "avec-pom.jar"][1], "org.x:y")
        self.assertEqual(jars[PATH + "conteneur.war!/WEB-INF/lib/c.jar"][0], "maven")
        self.assertIn("5 sans pom.properties, dont 3 avec empreinte, 2 identifiées", log)

    def test_arrive_dans_le_sbom(self):
        _code, _log, out = self.build("sbom", "--java-db", self.base)
        with open(glob.glob(os.path.join(out, "sbom", "*.cdx.json"))[0], encoding="utf-8") as handle:
            purls = [c.get("purl") for c in json.load(handle)["components"]]
        self.assertIn("pkg:maven/commons-codec/commons-codec@1.3", purls)

    def test_sans_option_rien_ne_change(self):
        code, log, out = self.build("sans")
        self.assertEqual(code, 0, log)
        self.assertEqual(self.jars(out)[PATH + "codec.jar"][0], "maven-unidentified")
        self.assertNotIn("Archives Java", log)

    def test_base_absente_ou_invalide(self):
        bad = os.path.join(self.d, "mauvaise.db")
        sqlite3.connect(bad).close()
        for path in (os.path.join(self.d, "absente.db"), bad):
            code, log, out = self.build("erreur", "--java-db", path)
            self.assertEqual(code, 1, log)
            self.assertIn("ERREUR", log)
            self.assertFalse(os.path.exists(os.path.join(out, "cmdb.sqlite")))
