# -*- coding: utf-8 -*-
"""Croisement avec la base Trivy : lecteur BoltDB, comparaisons de versions, sources d'avis.

La vraie base (trivy.db, 1,7 Go) ne peut pas être livrée : une petite base de même structure
est fabriquée par tests/boltwriter.py. Le lecteur a par ailleurs été confronté à la vraie base
(lecture complète et accès direct concordants sur 12 894 clés du compartiment Red Hat/kernel)."""
import gzip
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from tests.common import ROOT, TOOLS
from tests.boltwriter import Writer
import cmdb_bolt
import cmdb_build as B
import cmdb_cve as C

J = lambda o: json.dumps(o).encode()
SEV = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def vuln(sev, title, nvd=None, **vendor):
    return J({"Title": title, "Severity": sev, "VendorSeverity": dict((k, SEV[v]) for k, v in vendor.items()),
              "CVSS": {"nvd": {"V3Score": nvd}} if nvd else {}, "PublishedDate": "2024-01-01T00:00:00Z"})


TREE = {
    "Red Hat": {
        "kernel": {
            "RHSA-2024:0001": J({"Entries": [{"Affected": [1], "Arches": ["x86_64"], "FixedVersion": "0:4.18.0-553.el8_10",
                                              "Cves": [{"ID": "CVE-2024-1001", "Severity": 3}, {"ID": "CVE-2024-1002", "Severity": 2}]}]}),
            "RHSA-2024:0002": J({"Entries": [{"Affected": [9], "FixedVersion": "0:4.18.0-999.el8_10",     # RHEL 9 seulement
                                              "Cves": [{"ID": "CVE-2024-1003", "Severity": 4}]}]}),
            "CVE-2024-1004": J({"Entries": [{"Affected": [1], "Status": 5, "Cves": [{"Severity": 4}]}]}),  # sans correctif, critique
            "CVE-2024-1005": J({"Entries": [{"Affected": [1], "Status": 5, "Cves": [{"Severity": 1}]}]}),  # sans correctif, faible
        },
        "postgresql:10::postgresql-server": {
            "RHSA-2024:0956": J({"Entries": [{"Affected": [1], "FixedVersion": "0:10.23-4.module+el8.9.0+21317+d2c6bf8a",
                                              "Cves": [{"ID": "CVE-2024-0985", "Severity": 3}]}]}),
        },
        "openssl": {"RHSA-2023:0001": J({"Entries": [{"Affected": [1], "FixedVersion": "1:1.1.1k-9.el8_7",
                                                      "Cves": [{"ID": "CVE-2023-0286", "Severity": 3}]}]})},
    },
    "Red Hat CPE": {"cpe": {"1": J("cpe:/o:redhat:enterprise_linux:8::baseos"), "9": J("cpe:/o:redhat:enterprise_linux:9::baseos")}},
    "debian 12": {
        "linux": {"CVE-2024-2001": J({"FixedVersion": "6.1.119-1"}), "CVE-2024-2002": J({"FixedVersion": "6.1.100-1"}),
                  "CVE-2024-2003": J({"Severity": 1})},
        "openssl": {"CVE-2024-2004": J({"FixedVersion": "3.0.15-1~deb12u1"})},
    },
    "maven::GitHub Security Advisory Maven": {
        "org.apache.commons:commons-lang3": {"CVE-2025-48924": J({"PatchedVersions": ["3.18.0"], "VulnerableVersions": [">=3.0, <3.18.0"]})},
        "org.apache.logging.log4j:log4j-core": dict(("CVE-2021-%d" % i, J({"PatchedVersions": ["2.%d.0" % i],
                                                                            "VulnerableVersions": ["<2.%d.0" % i]})) for i in range(10, 22)),
    },
    "bitnami::Bitnami Vulnerability Database": {
        "postgresql": {"CVE-2024-7348": J({"PatchedVersions": ["12.20.0", "15.8.0"],
                                           "VulnerableVersions": [">=12.0.0, <12.20.0", ">=15.0.0, <15.8.0"]})},
        "tomcat": {"CVE-2024-50379": J({"PatchedVersions": ["9.0.98"], "VulnerableVersions": [">=9.0.0, <9.0.98"]})},
    },
    "vulnerability": {
        "CVE-2024-1001": vuln("HIGH", "kernel: un"), "CVE-2024-1002": vuln("MEDIUM", "kernel: deux"),
        "CVE-2024-1003": vuln("CRITICAL", "kernel: rhel9"), "CVE-2024-1004": vuln("CRITICAL", "kernel: sans correctif"),
        "CVE-2024-1005": vuln("LOW", "kernel: faible"), "CVE-2024-0985": vuln("HIGH", "postgresql: refresh"),
        "CVE-2023-0286": vuln("HIGH", "openssl: x400"),
        "CVE-2024-2001": vuln("HIGH", "linux: a", debian=SEV and "LOW", nvd=7.8),
        "CVE-2024-2002": vuln("HIGH", "linux: b"), "CVE-2024-2003": vuln("LOW", "linux: c"),
        "CVE-2024-2004": vuln("MEDIUM", "openssl: d"), "CVE-2025-48924": vuln("MEDIUM", "commons-lang3: récursion", ghsa="MEDIUM"),
        "CVE-2024-7348": vuln("HIGH", "postgresql: pg_dump", nvd=8.8), "CVE-2024-50379": vuln("CRITICAL", "tomcat: TOCTOU", nvd=9.8),
    },
}
TREE["vulnerability"].update(("CVE-2021-%d" % i, vuln("CRITICAL", "log4j %d" % i)) for i in range(10, 22))


class Versions(unittest.TestCase):
    def test_rpm(self):
        lt = lambda a, b: self.assertEqual(C.rpm_cmp(a, b), -1, (a, b))
        lt("4.18.0-513.24.1.el8_9", "0:4.18.0-553.el8_10")
        lt("1.0~rc1-1", "1.0-1")
        lt("2.0-1", "1:1.0-1")
        lt("1.1.1k-12.el8_9", "1:1.1.1k-18.el8_6")
        lt("10.23-1.module+el8.7.0", "10.23-4.module+el8.9.0+21317+d2c6bf8a")
        self.assertEqual(C.rpm_cmp("0:1.2-3", "1.2-3"), 0)

    def test_deb(self):
        lt = lambda a, b: self.assertEqual(C.deb_cmp(a, b), -1, (a, b))
        lt("3.0.14-1~deb12u2", "3.0.15-1~deb12u1")
        lt("1.0~rc1-1", "1.0-1")
        lt("2.0-1", "1:0.9-1")
        lt("6.1.112-1", "6.1.119-1")
        self.assertEqual(C.deb_cmp("6.1.119-1", "6.1.100-1"), 1)

    def test_amont(self):
        self.assertEqual(C.gen_cmp("15.4", "15.4.0"), 0)
        self.assertEqual(C.gen_cmp("2.0.0-rc1", "2.0.0"), -1)
        self.assertEqual(C.gen_cmp("1.2.3.Final", "1.2.3"), 0)
        self.assertTrue(C.in_ranges("3.12.0", [">=3.0, <3.18.0"]))
        self.assertFalse(C.in_ranges("3.18.0", [">=3.0, <3.18.0"]))
        self.assertTrue(C.in_ranges("15.4", [">=12.0.0, <12.20.0", ">=15.0.0, <15.8.0"]))
        self.assertEqual(C.first_patch("15.4", ["12.20.0", "15.8.0"]), "15.8.0")


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="cmdbcve")
        cls.path = os.path.join(cls.tmp, "trivy.db")
        Writer().write(cls.path, TREE)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)


class Bolt(Base):
    def test_lecture(self):
        with cmdb_bolt.Bolt(self.path) as db:
            root = cmdb_bolt.Bucket.root(db)
            self.assertEqual(sorted(k.decode() for k in root.keys()), sorted(TREE))
            log4j = root.get("maven::GitHub Security Advisory Maven").get("org.apache.logging.log4j:log4j-core")
            keys = list(log4j.keys())            # 12 clés : une branche et deux feuilles
            self.assertEqual(keys, sorted(keys))
            self.assertEqual(len(keys), 12)
            for k in keys:
                self.assertEqual(log4j.get(k), TREE["maven::GitHub Security Advisory Maven"]["org.apache.logging.log4j:log4j-core"][k.decode()])
            self.assertIsNone(log4j.get("CVE-0000-0000"))
            self.assertIsNone(root.get("absent"))

    def test_compartiments_en_ligne(self):
        path = os.path.join(self.tmp, "inline.db")
        Writer(inline=True).write(path, {"a": {"x": b"1", "y": b"2"}, "b": {"z": b"3"}})
        with cmdb_bolt.Bolt(path) as db:
            root = cmdb_bolt.Bucket.root(db)
            self.assertEqual(dict(root.get("a").items()), {b"x": b"1", b"y": b"2"})
            self.assertEqual(root.get("b").get("z"), b"3")

    def test_pas_une_base(self):
        path = os.path.join(self.tmp, "faux.db")
        with open(path, "wb") as f:
            f.write(b"\0" * 8192)
        with self.assertRaises(cmdb_bolt.BoltError):
            cmdb_bolt.Bolt(path)


def fleet(db):
    """Quatre hôtes : RHEL 8, Debian 12, Windows, AIX (sans avis)."""
    H = "INSERT INTO hosts (app, platform, host, os_id, os_version, kernel) VALUES ('APP', 'prod', ?, ?, ?, ?)"
    db.execute(H, ("rh1", "rhel", "8.9", "4.18.0-513.24.1.el8_9.x86_64"))
    db.execute(H, ("deb1", "debian", "12", "6.1.0-26-amd64"))
    db.execute(H, ("win1", "windows-server", "2019", None))
    db.execute(H, ("aix1", "aix", "7.3", None))
    P = ("INSERT INTO packages (app, platform, host, manager, name, epoch, version, release, arch, vendor, source) "
         "VALUES ('APP', 'prod', ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    for row in (("rh1", "rpm", "kernel", None, "4.18.0", "513.24.1.el8_9", "x86_64", "Red Hat, Inc.", None),
                ("rh1", "rpm", "kernel", None, "4.18.0", "477.10.1.el8_8", "x86_64", "Red Hat, Inc.", None),   # ancien noyau
                ("rh1", "rpm", "openssl", "1", "1.1.1k", "12.el8_9", "x86_64", "Red Hat, Inc.", None),          # à jour
                ("rh1", "rpm", "postgresql-server", None, "10.23", "1.module+el8.7.0", "x86_64", "Red Hat, Inc.", None),
                ("rh1", "rpm", "postgresql15-server", None, "15.4", "1PGDG.rhel8", "x86_64", "PostgreSQL Global Development Group", None),
                ("deb1", "dpkg", "linux-image-6.1.0-26-amd64", None, "6.1.112-1", None, "amd64", None, "linux-signed-amd64"),
                ("deb1", "dpkg", "linux-image-6.1.0-18-amd64", None, "6.1.76-1", None, "amd64", None, "linux-signed-amd64"),
                ("deb1", "dpkg", "openssl", None, "3.0.14-1~deb12u2", None, "amd64", None, "openssl")):
        db.execute(P, row)
    S = ("INSERT INTO software (app, platform, host, category, family, name, version, location, owner_pkg, managed, purl) "
         "VALUES ('APP', 'prod', ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    for row in (("rh1", "runtime", "postgresql", "postgresql", "15.4", "/usr/pgsql-15/bin/postgres", "postgresql15-server", 1, None),
                ("rh1", "runtime", "postgresql", "postgresql", "10.23", "/usr/bin/postgres", "postgresql-server", 1, None),
                ("deb1", "server", "tomcat", "tomcat", "9.0.85", "/opt/tomcat", None, 0, None),
                ("win1", "server", "tomcat", "tomcat", "9.0.98", "D:/Apps/tomcat", None, 0, None),   # corrigé
                ("win1", "java-archive", "commons-lang3", "org.apache.commons:commons-lang3", "3.12.0", "D:/Apps/lib/c.jar", None, 0,
                 "pkg:maven/org.apache.commons/commons-lang3@3.12.0"),
                ("deb1", "java-archive", "log4j-core", "org.apache.logging.log4j:log4j-core", "2.17.1", "/opt/app/log4j-core.jar", None, 0,
                 "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1")):
        db.execute(S, row)


class Croisement(Base):
    @classmethod
    def setUpClass(cls):
        super(Croisement, cls).setUpClass()
        cls.db = sqlite3.connect(":memory:")
        cls.db.executescript(B.SCHEMA)
        fleet(cls.db)
        cls.stats = C.build_vulnerabilities(cls.db, cls.path)

    def found(self, host, component=None):
        sql = "SELECT vuln_id, severity, fixed_version, status, source FROM vulnerabilities WHERE host = ?"
        args = [host]
        if component:
            sql += " AND component = ?"
            args.append(component)
        return dict((r[0], r[1:]) for r in self.db.execute(sql, args))

    def test_noyau_redhat(self):
        got = self.found("rh1", "kernel")
        self.assertEqual(got["CVE-2024-1001"], ("HIGH", "0:4.18.0-553.el8_10", "corrigeable", "paquet"))
        self.assertEqual(got["CVE-2024-1002"][0], "MEDIUM")
        self.assertNotIn("CVE-2024-1003", got)                      # avis RHEL 9 seulement
        self.assertEqual(got["CVE-2024-1004"][2], "ne sera pas corrigé")  # sans correctif mais critique : gardé
        self.assertNotIn("CVE-2024-1005", got)                      # sans correctif et faible : écarté par défaut
        installed = set(r[0] for r in self.db.execute("SELECT installed FROM vulnerabilities WHERE host = 'rh1' AND component = 'kernel'"))
        self.assertEqual(installed, {"4.18.0-513.24.1.el8_9"})     # l'ancien noyau installé n'est pas évalué

    def test_paquet_a_jour(self):
        self.assertEqual(self.found("rh1", "openssl"), {})

    def test_module_rhel(self):
        self.assertEqual(self.found("rh1", "postgresql-server")["CVE-2024-0985"][1], "0:10.23-4.module+el8.9.0+21317+d2c6bf8a")

    def test_noyau_et_paquets_debian(self):
        got = self.found("deb1", "linux-image-6.1.0-26-amd64")
        self.assertEqual(set(got), {"CVE-2024-2001"})               # 2002 corrigé en 6.1.100 ; 2003 sans correctif et faible
        self.assertEqual(got["CVE-2024-2001"][0], "LOW")             # gravité Debian, pas la générale
        self.assertEqual(self.found("deb1", "linux-image-6.1.0-18-amd64"), {})   # noyau non démarré
        self.assertEqual(self.found("deb1", "openssl")["CVE-2024-2004"][1], "3.0.15-1~deb12u1")

    def test_bibliotheques(self):
        self.assertEqual(self.found("win1", "org.apache.commons:commons-lang3")["CVE-2025-48924"][1:3], ("3.18.0", "corrigeable"))
        log4j = self.found("deb1", "org.apache.logging.log4j:log4j-core")
        self.assertEqual(sorted(log4j), ["CVE-2021-18", "CVE-2021-19", "CVE-2021-20", "CVE-2021-21"])

    def test_produits_hors_distribution(self):
        pg = self.found("rh1", "postgresql")
        self.assertEqual(pg["CVE-2024-7348"][1:], ("15.8.0", "corrigeable", "produit"))   # PGDG : version amont
        n = self.db.execute("SELECT COUNT(*) FROM vulnerabilities WHERE host = 'rh1' AND component = 'postgresql' AND installed = '10.23'")
        self.assertEqual(n.fetchone()[0], 0)                        # paquet Red Hat : évalué par les avis Red Hat seulement
        self.assertEqual(self.found("deb1", "tomcat")["CVE-2024-50379"][:2], ("CRITICAL", "9.0.98"))
        self.assertEqual(self.found("win1", "tomcat"), {})

    def test_systeme_sans_avis(self):
        self.assertEqual(self.stats["os_unsupported"], ["aix", "windows-server"])

    def test_synthese(self):
        rows = dict(((r[0], r[1]), r[2:]) for r in self.db.execute(
            "SELECT component, installed, hosts, critical, high, fixable, fix_to, worst FROM vuln_components"))
        self.assertEqual(rows[("kernel", "4.18.0-513.24.1.el8_9")], (1, 1, 1, 2, "4.18.0-553.el8_10", "CRITICAL"))
        self.assertEqual(rows[("tomcat", "9.0.85")][-2:], ("9.0.98", "CRITICAL"))


class Consolidation(Base):
    @classmethod
    def setUpClass(cls):
        super(Consolidation, cls).setUpClass()
        store = os.path.join(cls.tmp, "store", "APPV1", "prod", "srv-py01")
        os.makedirs(store)
        with open(os.path.join(ROOT, "tests", "fixtures", "format_v1", "python-1.1.0.json"), "rb") as src:
            with gzip.open(os.path.join(store, "r.json.gz"), "wb") as dst:
                dst.write(src.read())

    def test_option_trivy_db(self):
        out = os.path.join(self.tmp, "build")
        proc = subprocess.run([sys.executable, os.path.join(TOOLS, "cmdb_build.py"), "--store", os.path.join(self.tmp, "store"),
                               "--out", out, "--no-report", "--no-dossiers", "--trivy-db", self.path],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Vulnérabilités   :", proc.stdout)
        db = sqlite3.connect(os.path.join(out, "cmdb.sqlite"))
        got = set(r[0] for r in db.execute("SELECT vuln_id FROM vulnerabilities"))
        db.close()
        self.assertIn("CVE-2024-1001", got)        # noyau de la collecte figée
        self.assertIn("CVE-2025-48924", got)       # commons-lang3
        self.assertTrue(os.path.exists(os.path.join(out, "csv", "vulnerabilities.csv")))

    @unittest.skipUnless(shutil.which("node"), "node absent")
    def test_rapport(self):
        out = os.path.join(self.tmp, "build_r")
        subprocess.check_call([sys.executable, os.path.join(TOOLS, "cmdb_build.py"), "--store", os.path.join(self.tmp, "store"),
                               "--out", out, "--no-dossiers", "--trivy-db", self.path], stdout=subprocess.DEVNULL)
        html = subprocess.check_output(["node", os.path.join(ROOT, "tests", "report_harness.js"), os.path.join(out, "cmdb_rapport.html"),
                                        "vulnerabilites", "vulnerabilites?onglet=bibliotheques"]).decode()
        views = json.loads(html)
        self.assertIn("Base Trivy du", views["vulnerabilites"])
        self.assertIn("4.18.0-553.el8_10", views["vulnerabilites"])          # noyau : version qui corrige
        self.assertIn("commons-lang3", views["vulnerabilites?onglet=bibliotheques"])

    def test_base_absente(self):
        proc = subprocess.run([sys.executable, os.path.join(TOOLS, "cmdb_build.py"), "--store", self.tmp, "--out",
                               os.path.join(self.tmp, "b2"), "--trivy-db", os.path.join(self.tmp, "absente.db")],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("base Trivy introuvable", proc.stderr)


if __name__ == "__main__":
    unittest.main()
