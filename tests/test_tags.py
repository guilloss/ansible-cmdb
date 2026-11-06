# -*- coding: utf-8 -*-
"""Étiquettes libres passées par -e : exécute le vrai context.yml avec Ansible."""
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLAY = """- hosts: localhost
  gather_facts: false
  tasks:
    - ansible.builtin.include_role:
        name: cmdb_collect
        tasks_from: context
    - ansible.builtin.debug:
        msg: "ARGV={{ cmdb_tag_argv | join(' ') }}"
"""


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class TagForms(unittest.TestCase):
    def run_play(self, *extra):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, True)
        play = os.path.join(tmp, "p.yml")
        with open(play, "w") as handle:
            handle.write(PLAY)
        env = dict(os.environ, ANSIBLE_HOME=tmp, ANSIBLE_LOCAL_TEMP=tmp + "/t", ANSIBLE_REMOTE_TEMP=tmp + "/r",
                   ANSIBLE_ROLES_PATH=os.path.join(ROOT, "roles"), ANSIBLE_NOCOLOR="1")
        cmd = ["ansible-playbook", "-i", "localhost,", "-c", "local", play, "-e", "cmdb_app=TEST",
               "-e", "cmdb_platform=QUALIF", "-e", "cmdb_store=" + tmp + "/store"]
        for item in extra:
            cmd += ["-e", item]
        proc = subprocess.run(cmd, env=env, cwd=tmp, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              universal_newlines=True)
        return proc.returncode, proc.stdout

    def test_accepted(self):
        for form in ("cmdb_tags=squad=S3", 'cmdb_tags={"squad":"S3"}', "cmdb_tags={'squad':'S3'}",
                     '{"cmdb_tags": {"squad": "S3"}}'):
            code, out = self.run_play(form)
            self.assertEqual(code, 0, form + "\n" + out)
            self.assertIn("--tag=squad=S3", out, form)

    def test_several(self):
        code, out = self.run_play("cmdb_tags=squad=S3,site=Paris")
        self.assertEqual(code, 0, out)
        self.assertIn("--tag=squad=S3 --tag=site=Paris", out)

    def test_none(self):
        code, out = self.run_play()
        self.assertEqual(code, 0, out)
        self.assertNotIn("--tag=", out.replace("--tag app", ""))

    def test_refused(self):
        for form in ('cmdb_tags={"squad":', "cmdb_tags=S3", "cmdb_tags={squad:", "cmdb_tags=app=X",
                     '{"cmdb_tags": {"squad": "S 3"}}'):
            code, out = self.run_play(form)
            self.assertNotEqual(code, 0, form + "\n" + out)
            self.assertIn("Étiquettes libres", out, form)
