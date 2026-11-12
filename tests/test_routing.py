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

    def decide_windows(self, inventory, *extra):
        inv, path = os.path.join(self.tmp, "inv"), os.path.join(self.tmp, "d.yml")
        with open(inv, "w") as handle:
            handle.write(inventory)
        with open(path, "w") as handle:
            handle.write(DECIDE.replace("hosts: localhost", "hosts: all").replace(
                "ROUTE={{ cmdb_use_legacy }}", "ROUTE={{ cmdb_use_legacy }} WIN={{ cmdb_use_windows }}") % ROOT)
        code, out = self.play("-i", inv, path, *extra)
        self.assertEqual(code, 0, out)
        return "WIN=True" in out, "ROUTE=True" in out

    def test_windows_reconnu_sans_faits(self):
        # winrm ou shell powershell : voie Windows, aucune tentative de faits Ansible (injoignable ici sinon)
        self.assertEqual(self.decide_windows("w ansible_connection=local ansible_shell_type=powershell\n")[0], True)
        self.assertEqual(self.decide_windows("[windows]\nw ansible_connection=local\n"), (True, False))
        self.assertEqual(self.decide_windows("l ansible_connection=local\n"), (False, False))
        self.assertEqual(self.decide_windows("l ansible_connection=local\n", "-e", "cmdb_force_windows=true"), (True, False))

    def test_windows_ligne_de_commande(self):
        import yaml
        with open(os.path.join(ROOT, "roles/cmdb_collect/tasks/windows.yml")) as handle:
            tasks = yaml.safe_load(handle)[0]["block"]
        task = [t for t in tasks if t["name"].startswith("Construire")][0]
        play = [{"hosts": "localhost", "gather_facts": False, "vars_files": [os.path.join(ROOT, "roles/cmdb_collect/defaults/main.yml")],
                 "tasks": [task, {"ansible.builtin.copy": {"content": "{{ cmdb_win_args | trim }}", "dest": self.tmp + "/args"}}]}]
        # -e : les valeurs du test doivent l'emporter sur les défauts du rôle
        extra = {"cmdb_app": "APP", "cmdb_platform": "prod", "cmdb_run_id": "R1", "cmdb_tags_map": {"site": "Paris", "squad": "S3"},
                 "cmdb_win_tmp": "C:\\Temp\\cmdb-x", "cmdb_hash_archives": False, "cmdb_win_scan_paths": ["D:\\Apps", "E:\\l'appli"]}
        path = os.path.join(self.tmp, "w.yml")
        with open(path, "w") as handle:
            yaml.safe_dump(play, handle, allow_unicode=True)
        code, out = self.play("-i", "localhost,", "-c", "local", path, "-e", json.dumps(extra))
        self.assertEqual(code, 0, out)
        with open(self.tmp + "/args") as handle:
            args = " ".join(handle.read().split())
        self.assertIn("-App 'APP' -Platform 'prod' -HostLabel 'localhost' -RunId 'R1' -OutFile 'C:\\Temp\\cmdb-x\\cmdb.out'", args)
        self.assertIn("-Tag 'site=Paris,squad=S3'", args)
        self.assertIn("-NoHash", args)
        self.assertNotIn("-NoScan", args)
        self.assertIn("-ScanPath 'D:\\Apps','E:\\l''appli'", args)

    def test_windows_echec_trace(self):
        # Sans vraie cible Windows : la commande PowerShell échoue sous sh, l'échec doit être tracé
        # dans le manifeste, sans bascule vers les collecteurs Linux.
        inv = os.path.join(self.tmp, "inv")
        with open(inv, "w") as handle:
            handle.write("[windows]\nw ansible_connection=local\n")
        code, out = self.play("-i", inv, os.path.join(ROOT, "collect.yml"), "-e", "cmdb_app=TEST", "-e", "cmdb_platform=QUALIF",
                              "-e", "cmdb_store=" + self.tmp + "/store")
        self.assertNotEqual(code, 0, out)
        self.assertIn("Windows : collecte par cmdb_collector.ps1", out)
        self.assertNotIn("Bascule vers la collecte sans module", out)
        with open(glob.glob(self.tmp + "/store/_runs/*/TEST__QUALIF__w.json")[0]) as handle:
            self.assertEqual(json.load(handle)["status"], "failed")
        self.assertEqual(len(glob.glob(self.tmp + "/store/TEST/QUALIF/w/*.error.json")), 1)

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

    def test_lot_nomme_par_application_et_plateforme(self):
        py = shutil.which("python3")
        out, doc, status = self.collect("a ansible_connection=local ansible_python_interpreter=%s\n" % py,
                                        "-e", "cmdb_lot=true", "-e", "cmdb_scan_filesystem=false")
        rid = doc["meta"]["run_id"]
        lots = self.tmp + "/store/_lots/"
        self.assertEqual(sorted(os.listdir(lots)), sorted(["TEST__QUALIF__%s.tar.gz" % rid, "%s.tar.gz" % rid]), out)
        # même fichier sous les deux noms
        self.assertTrue(os.path.samefile(lots + "TEST__QUALIF__%s.tar.gz" % rid, lots + rid + ".tar.gz"))
        self.assertIn("Lot à transférer : %s/store/_lots/TEST__QUALIF__%s.tar.gz" % (self.tmp, rid), out)

    def test_lot_plusieurs_applications_nom_impose(self):
        py = shutil.which("python3")
        inv = os.path.join(self.tmp, "inv")
        with open(inv, "w") as handle:
            handle.write("a ansible_connection=local ansible_python_interpreter=%s cmdb_app=APPB cmdb_platform=prod\n"
                         "b ansible_connection=local ansible_python_interpreter=%s cmdb_app=APPA cmdb_platform=prod\n" % (py, py))
        code, out = self.play("-i", inv, os.path.join(ROOT, "collect.yml"), "-e", "cmdb_store=" + self.tmp + "/store",
                              "-e", "cmdb_scan_filesystem=false", "-e", "cmdb_lot=true", "-e", "cmdb_lot_keep_run_id_name=false")
        self.assertEqual(code, 0, out)
        names = os.listdir(self.tmp + "/store/_lots")
        self.assertEqual(len(names), 1, names)
        self.assertRegex(names[0], r"^APPA\+APPB__prod__[0-9TZ]+-[0-9a-f]+\.tar\.gz$")
        code, out = self.play("-i", inv, os.path.join(ROOT, "collect.yml"), "-e", "cmdb_store=" + self.tmp + "/store2",
                              "-e", "cmdb_scan_filesystem=false", "-e", "cmdb_lot=true", "-e", "cmdb_lot_name=../x")
        self.assertNotEqual(code, 0)
        self.assertIn("cmdb_lot_name invalide", out)
