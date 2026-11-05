# -*- coding: utf-8 -*-
import unittest

from tests.common import TOOLS  # noqa: F401
import cmdb_hardening as H

SYSCTL = "kernel.dmesg_restrict = 1\nkernel.sysrq = 1\nnet.ipv4.ip_local_port_range = 32768\t65535\n"


def base(**kw):
    d = {"os": {"os_release": {"ID": "rhel"}}, "kernel": {"sysctl": SYSCTL}, "security": {}, "accounts": {},
         "hardware": {"mounts": []}, "services": {}, "packages": {"managers": {}}, "network": {"listening": []}, "meta": {}}
    d.update(kw)
    return d


def result(doc, rule_id):
    rules = H.load_rules()
    got = [x for x in H.evaluate(doc, rules) if x[0]["id"] == rule_id]
    return got[0][1:] if got else None


class Referentiel(unittest.TestCase):
    def test_les_80_recommandations(self):
        recos = H.load_recos()
        self.assertEqual(len(recos), 80)
        self.assertEqual({r["level"] for r in recos}, set(H.LEVELS))

    def test_regles_coherentes(self):
        refs = {r["ref"]: r for r in H.load_recos()}
        rules = H.load_rules()
        self.assertEqual(len({r["id"] for r in rules}), len(rules))
        for r in rules:
            self.assertEqual(r["level"], refs[r["ref"]]["level"], r["id"])
            self.assertNotEqual(refs[r["ref"]]["coverage"], "non", r["id"])
            if r["type"] == "check" and r["target"] != "os_supported":
                self.assertIn(r["target"], H.BUILTIN)
            elif r["type"] != "check":
                self.assertIn(r["type"], H.CHECKS)


class Sysctl(unittest.TestCase):
    def test_conforme(self):
        self.assertEqual(result(base(), "R9-kernel-dmesg-restrict"), (H.OK, "1"))

    def test_non_conforme(self):
        self.assertEqual(result(base(), "R9-kernel-sysrq"), (H.KO, "1"))

    def test_absent_est_non_verifiable(self):
        self.assertEqual(result(base(), "R9-kernel-kptr-restrict")[0], H.UNKNOWN)

    def test_tabulation_normalisee(self):
        self.assertEqual(result(base(), "R12-net-ipv4-ip-local-port-range")[0], H.OK)


class Montage(unittest.TestCase):
    def test_options(self):
        d = base(hardware={"mounts": [{"mountpoint": "/tmp", "options": "rw,nosuid,nodev,noexec"}, {"mountpoint": "/home", "options": "rw,nodev"}]})
        self.assertEqual(result(d, "R28-tmp")[0], H.OK)
        self.assertEqual(result(d, "R28-home"), (H.KO, "manque nosuid,noexec"))
        self.assertEqual(result(d, "R28-var"), (H.KO, "pas de partition dédiée"))

    def test_sans_donnee(self):
        self.assertEqual(result(base(), "R28-tmp")[0], H.UNKNOWN)

    def test_options_inconnues(self):
        self.assertEqual(result(base(hardware={"mounts": [{"mountpoint": "/tmp"}]}), "R28-tmp")[0], H.UNKNOWN)


class Sshd(unittest.TestCase):
    def test_effectif(self):
        d = base(security={"sshd_effective_config": "port 22\npermitrootlogin no\n"})
        self.assertEqual(result(d, "R33-permitrootlogin"), (H.OK, "no"))

    def test_fichier(self):
        d = base(security={"sshd_config": "# PermitRootLogin no\nPermitRootLogin yes\n"})
        self.assertEqual(result(d, "R33-permitrootlogin"), (H.KO, "yes"))

    def test_sans_directive_ni_sshd_t(self):
        self.assertEqual(result(base(security={"sshd_config": "Port 22\n"}), "R33-permitrootlogin")[0], H.UNKNOWN)


class Sudo(unittest.TestCase):
    T = """Defaults env_reset, use_pty
Defaults   noexec
# Defaults requiretty
Cmnd_Alias X = /bin/ls
%wheel ALL=(ALL) ALL
op ALL=(appuser) /usr/bin/systemctl restart app, /bin/ls ""
bad ALL=(appuser) /bin/*, !/bin/su
nu ALL=(appuser) NOPASSWD: /usr/bin/vi
"""

    def doc(self):
        return base(accounts={"sudoers": {"/etc/sudoers": self.T}})

    def test_defaults(self):
        self.assertEqual(result(self.doc(), "R39-noexec")[0], H.OK)
        self.assertEqual(result(self.doc(), "R39-use-pty")[0], H.OK)
        self.assertEqual(result(self.doc(), "R39-requiretty"), (H.KO, "absente"))

    def test_cible_root(self):
        s, seen = result(self.doc(), "R40-sudo-no-root-target")
        self.assertEqual(s, H.KO)
        self.assertIn("%wheel", seen)

    def test_negation(self):
        self.assertEqual(result(self.doc(), "R42-sudo-no-negation")[0], H.KO)

    def test_arguments(self):
        s, seen = result(self.doc(), "R43-sudo-explicit-args")
        self.assertEqual(s, H.KO)

    def test_illisible(self):
        self.assertEqual(result(base(), "R40-sudo-no-root-target")[0], H.UNKNOWN)


class Divers(unittest.TestCase):
    def test_selinux(self):
        d = base(security={"sestatus": "Current mode:   enforcing\nLoaded policy name:  targeted\n"})
        self.assertEqual(result(d, "R46-selinux")[0], H.OK)
        d = base(security={"selinux_config": "SELINUX=permissive\nSELINUXTYPE=targeted\n"})
        self.assertEqual(result(d, "R46-selinux"), (H.KO, "permissive targeted"))

    def test_selinux_sans_objet_sur_debian(self):
        d = base(os={"os_release": {"ID": "debian"}})
        self.assertIsNone(result(d, "R46-selinux"))
        self.assertEqual(result(d, "R45-apparmor")[0], H.UNKNOWN)

    def test_services(self):
        d = base(services={"units": [{"unit": "auditd.service", "active": "inactive"}, {"unit": "chronyd.service", "active": "active"}]})
        self.assertEqual(result(d, "R73-auditd-service")[0], H.KO)
        rid = [r["id"] for r in H.load_rules() if r["target"].startswith("chronyd")][0]
        self.assertEqual(result(d, rid)[0], H.OK)

    def test_paquets(self):
        rid = [r["id"] for r in H.load_rules() if r["ref"] == "R62"][0]
        d = base(packages={"managers": {"rpm": [{"name": "telnet"}, {"name": "bash"}]}})
        self.assertEqual(result(d, rid), (H.KO, "telnet"))

    def test_mta(self):
        ok = base(network={"listening": [{"port": 25, "address": "127.0.0.1"}]})
        ko = base(network={"listening": [{"port": 25, "address": "0.0.0.0"}]})
        self.assertEqual(result(ok, "R74-mta-local-only")[0], H.OK)
        self.assertEqual(result(ko, "R74-mta-local-only")[0], H.KO)

    def test_hidepid(self):
        self.assertEqual(result(base(meta={"visibility": {"proc_hidepid": "rw,hidepid=2"}}), "R28-proc-hidepid")[0], H.OK)
        self.assertEqual(result(base(meta={"visibility": {"proc_hidepid": None}}), "R28-proc-hidepid")[0], H.KO)
        self.assertEqual(result(base(), "R28-proc-hidepid")[0], H.UNKNOWN)


if __name__ == "__main__":
    unittest.main()
