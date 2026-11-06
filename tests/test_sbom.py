# -*- coding: utf-8 -*-
"""SBOM CycloneDX : ce que Trivy et Syft/Grype acceptent et comprennent.

Règles relevées dans leur code source : unmarshalType et decodeComponents (Trivy),
linuxReleaseFromOSComponent et IDMapping (Syft, Grype)."""
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests import fleet
from tests.common import TOOLS

TRIVY_TYPES = {"container", "application", "library", "framework", "operating-system", "platform", "file"}


class Sbom(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="cmdbs")
        store = os.path.join(cls.d, "store")
        ol = fleet.app_host()
        ol["os"]["os_release"]["ID"] = "ol"
        fleet.write_store(store, [fleet.pg_host(), ol])
        out = os.path.join(cls.d, "build")
        subprocess.check_call([sys.executable, os.path.join(TOOLS, "cmdb_build.py"), "--store", store, "--out", out],
                              stdout=subprocess.DEVNULL)
        cls.boms = {}
        for path in glob.glob(os.path.join(out, "sbom", "*.cdx.json")):
            with open(path, encoding="utf-8") as handle:
                bom = json.load(handle)
            cls.boms[bom["metadata"]["component"]["name"]] = bom

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def os_of(self, host):
        return [c for c in self.boms[host]["components"] if c["type"] == "operating-system"][0]

    def test_racine_acceptee_par_trivy(self):
        for bom in self.boms.values():
            self.assertIn(bom["metadata"]["component"]["type"], TRIVY_TYPES)

    def test_composants_acceptes_par_trivy(self):
        for bom in self.boms.values():
            for comp in bom["components"]:
                self.assertIn(comp["type"], TRIVY_TYPES)

    def test_un_seul_os(self):
        for bom in self.boms.values():
            self.assertEqual(len([c for c in bom["components"] if c["type"] == "operating-system"]), 1)

    def test_famille_trivy_et_id_grype(self):
        rhel = self.os_of("pg1.exemple.test")
        self.assertEqual(rhel["name"], "redhat")
        self.assertEqual(rhel["swid"]["name"], "rhel")
        self.assertEqual(rhel["version"], "8.9")
        oracle = self.os_of("app1.exemple.test")
        self.assertEqual(oracle["name"], "oracle")
        self.assertEqual(oracle["swid"]["name"], "ol")

    def test_swid_conforme(self):
        swid = self.os_of("pg1.exemple.test")["swid"]
        self.assertTrue(swid["tagId"])
        self.assertTrue(swid["name"])

    def test_references_de_dependances(self):
        for bom in self.boms.values():
            refs = {c["bom-ref"] for c in bom["components"]} | {bom["metadata"]["component"]["bom-ref"]}
            for dep in bom["dependencies"]:
                self.assertIn(dep["ref"], refs)
                self.assertTrue(set(dep.get("dependsOn", [])) <= refs)
