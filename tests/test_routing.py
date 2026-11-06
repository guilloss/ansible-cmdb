# -*- coding: utf-8 -*-
"""Bascule de collect.yml : aiguillage réel, collecte réelle sur la machine locale."""
import glob
import gzip
import json
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DECIDE = """- hosts: localhost
  gather_facts: false
  tasks:
    - ansible.builtin.import_tasks: %s/roles/cmdb_collect/tasks/route.yml
    - ansible.builtin.debug:
        msg: "ROUTE={{ cmdb_use_legacy }}"
"""


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class Routing(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.env = dict(os.environ, ANSIBLE_HOME=self.tmp, ANSIBLE_LOCAL_TEMP=self.tmp + "/t", ANSIBLE_REMOTE_TEMP=self.tmp + "/r",
                        ANSIBLE_ASYNC_DIR=self.tmp + "/a", ANSIBLE_ROLES_PATH=os.path.join(ROOT, "roles"),
                        ANSIBLE_CONFIG=os.path.join(ROOT, "ansible.cfg"), ANSIBLE_NOCOLOR="1", TMPDIR=self.tmp)

    def play(self, *args):
        proc = subprocess.run(["ansible-playbook"] + list(args), env=self.env, cwd=self.tmp, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, universal_newlines=True)
        return proc.returncode, proc.stdout

    def decide(self, facts):
        path = os.path.join(self.tmp, "d.yml")
        with open(path, "w") as handle:
            handle.write(DECIDE % ROOT)
        code, out = self.play("-i", "localhost,", "-c", "local", path, "-e", json.dumps({"cmdb_setup": {"ansible_facts": facts}}))
        self.assertEqual(code, 0, out)
        return "ROUTE=True" in out

    def test_decision(self):
        py = lambda a, b: {"version": {"major": a, "minor": b}}
        self.assertTrue(self.decide({"ansible_system": "AIX", "ansible_python": py(3, 9)}))
        self.assertTrue(self.decide({}))
        self.assertTrue(self.decide({"ansible_system": "Linux", "ansible_python": py(2, 6)}))
        self.assertTrue(self.decide({"ansible_system": "Linux", "ansible_python": py(3, 5)}))
        self.assertFalse(self.decide({"ansible_system": "Linux", "ansible_python": py(3, 9)}))
        self.assertFalse(self.decide({"ansible_system": "Linux", "ansible_python": py(2, 7)}))

    def collect(self, inventory, *extra, **kw):
        inv = os.path.join(self.tmp, "inv")
        with open(inv, "w") as handle:
            handle.write(inventory)
        code, out = self.play("-i", inv, os.path.join(ROOT, kw.get("playbook", "collect.yml")), "-e", "cmdb_app=TEST", "-e", "cmdb_platform=QUALIF",
                              "-e", "cmdb_store=" + self.tmp + "/store", "-e", "cmdb_scan_max_seconds=5", *extra)
        self.assertEqual(code, 0, out)
        found = glob.glob(self.tmp + "/store/TEST/QUALIF/*/latest.json.gz")
        self.assertEqual(len(found), 1, out)
        with gzip.open(found[0], "rt") as handle:
            doc = json.load(handle)
        with open(glob.glob(self.tmp + "/store/_runs/*/TEST__*.json")[0]) as handle:
            status = json.load(handle)
        return out, doc, status

    def test_bascule_si_faits_impossibles(self):
        out, doc, status = self.collect("vieux ansible_connection=local ansible_python_interpreter=/nexiste/pas\n")
        self.assertIn("Bascule vers la collecte sans module", out)
        self.assertEqual(status["status"], "ok")
        self.assertNotEqual(status["collector"], "python")
        self.assertEqual(doc["meta"]["tags"]["app"], "TEST")

    def test_groupe_aix_sans_tentative_de_faits(self):
        out, doc, status = self.collect("[aix]\nunix ansible_connection=local ansible_python_interpreter=/nexiste/pas\n")
        self.assertIn("Bascule vers la collecte sans module", out)
        self.assertEqual(status["status"], "ok")
        self.assertEqual(doc["meta"]["host_label"], "unix")

    def test_shell_impose(self):
        out, doc, status = self.collect("unix ansible_connection=local\n", "-e", "cmdb_force_shell=true")
        self.assertEqual(status["collector"], "shell")

    def test_reprise_si_collecte_moderne_echoue(self):
        out, doc, status = self.collect("recent ansible_connection=local ansible_python_interpreter=%s\n" % shutil.which("python3"),
                                        "-e", "cmdb_python=/nexiste/pas")
        self.assertIn("Bascule vers la collecte sans module après échec", out)
        self.assertEqual(status["status"], "ok")
        self.assertNotEqual(status["collector"], "python")
        self.assertEqual(len(glob.glob(self.tmp + "/store/TEST/QUALIF/recent/*.error.json")), 1)

    def test_collect_legacy_direct(self):
        out, doc, status = self.collect("[aix]\nunix ansible_connection=local\n", playbook="collect_legacy.yml")
        self.assertEqual(status["status"], "ok")
        self.assertEqual(doc["meta"]["host_label"], "unix")

    def test_moderne_inchange(self):
        out, doc, status = self.collect("recent ansible_connection=local ansible_python_interpreter=%s\n" % shutil.which("python3"))
        self.assertNotIn("Bascule vers la collecte sans module", out)
        self.assertEqual(status["collector"], "python")
