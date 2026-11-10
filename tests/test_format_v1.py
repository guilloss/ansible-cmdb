# -*- coding: utf-8 -*-
"""Contrat du format de collecte v1 (docs/format-collecte.md).

Ces tests protègent les équipes qui collectent déjà :
  * interface figée : options des collecteurs, variables du rôle, options de la consolidation ;
  * documents figés : ce que produisent les collecteurs garde au moins ces clés ;
  * lecture garantie : des collectes produites par les versions gelées (tests/fixtures/format_v1/)
    restent consolidées à l'identique.

Ajouter est permis ; retirer ou renommer fait échouer ces tests. Ne JAMAIS modifier les listes
ni les fichiers de tests/fixtures/format_v1/ pour faire passer un changement : c'est le changement
qui est incompatible. Un format incompatible s'appellera cmdb-collector/2, et la consolidation
devra continuer à lire cmdb-collector/1."""
import gzip
import io
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile

from tests.common import ROOT, COLLECTOR, SHELL_COLLECTOR, TOOLS

PS_COLLECTOR = os.path.join(ROOT, "roles", "cmdb_collect", "files", "cmdb_collector.ps1")
FIXTURES = os.path.join(ROOT, "tests", "fixtures", "format_v1")
BUILD = os.path.join(TOOLS, "cmdb_build.py")
UNPACK = os.path.join(TOOLS, "cmdb_unpack.py")

# --- Interface figée -----------------------------------------------------------------
PY_OPTIONS = {"--output", "-o", "--host-label", "--tag", "--run-id", "--no-scan-filesystem", "--scan-root", "--exclude",
              "--extra-exclude", "--scan-max-seconds", "--include-network-fs", "--include-container-storage",
              "--no-hash-archives", "--hash-max-mb", "--max-js-libs", "--no-exec-probes", "--exec-timeout",
              "--exec-max-seconds", "--max-execs", "--max-per-probe", "--no-file-owners", "--pending-updates", "--no-nice", "--pretty"}
SH_OPTIONS = {"--host-label", "--scan-max-seconds", "--exec-max-seconds", "--exec-timeout", "--no-scan-filesystem",
              "--no-exec-probes", "--no-hash-archives", "--extra-exclude", "--tag", "--run-id"}
PS_PARAMS = {"App", "Platform", "HostLabel", "RunId", "Tag", "OutFile", "ScanMaxSeconds", "ArchiveMaxSeconds",
             "ScanPath", "ExcludePath", "NoScan", "NoHash"}
ROLE_VARS = {"cmdb_tags", "cmdb_tag_regex", "cmdb_store", "cmdb_lot", "cmdb_python", "cmdb_save_ansible_facts",
             "cmdb_scan_filesystem", "cmdb_scan_roots", "cmdb_scan_max_seconds", "cmdb_scan_extra_excludes",
             "cmdb_scan_replace_excludes", "cmdb_include_network_fs", "cmdb_include_container_storage", "cmdb_hash_archives",
             "cmdb_hash_max_mb", "cmdb_exec_probes", "cmdb_exec_timeout", "cmdb_exec_max_seconds", "cmdb_file_owners",
             "cmdb_pending_updates", "cmdb_nice", "cmdb_win_archive_max_seconds", "cmdb_win_scan_paths",
             "cmdb_win_exclude_paths", "cmdb_async_timeout", "cmdb_async_poll", "cmdb_keep_remote_tmp_on_failure"}
CONSOLIDATE_VARS = {"cmdb_build", "cmdb_build_dir", "cmdb_filter_apps", "cmdb_filter_platforms", "cmdb_java_db", "cmdb_lots",
                    "cmdb_platform_order", "cmdb_report_exclude", "cmdb_store_dirs"}
BUILD_OPTIONS = {"--store", "--raw", "--lot", "--app", "--platform", "--host", "--default-app", "--default-platform", "--out",
                 "--sbom-include-managed", "--java-db", "--no-raw-documents", "--no-report", "--no-history", "--no-dossiers",
                 "--dossier-mention", "--platform-order", "--report-exclude-categories"}
PLAYBOOKS = ("collect.yml", "collect_legacy.yml", "consolidate.yml")

# --- Documents figés -------------------------------------------------------------------
SCHEMA = "cmdb-collector/1"
TOP = {"schema", "meta", "os", "hardware", "packages", "processes", "network", "services", "scheduled", "accounts",
       "security", "kernel", "containers", "oracle", "software_dirs", "filesystem", "process_artifacts", "runtimes", "go_binaries"}
META = {"collector_version", "started_at", "finished_at", "duration_seconds", "host_label", "run_id", "tags", "uid", "user",
        "errors", "visibility"}
FS = {"java_archives", "maven_exploded", "jdk_homes", "python_packages", "python_venvs", "conda_packages", "npm_packages",
      "node_apps", "npm_lockfiles", "composer_installed", "composer_locks", "ruby_gems", "dotnet_deps", "webapps",
      "js_libraries", "native_libs", "db_datadirs", "db_refs", "db_refs_resolved", "service_modules", "crypto_files", "endpoints", "stats"}
ARCHIVE = {"path", "size", "sha1", "manifest", "maven"}


def read(path):
    with open(path, encoding="utf-8-sig") as f:
        return f.read()


class Interface(unittest.TestCase):
    def assertKept(self, frozen, current, what):
        self.assertEqual(sorted(frozen - set(current)), [], "%s retiré(s) ou renommé(s) : incompatible avec le format v1" % what)

    def test_options_collecteur_python(self):
        self.assertKept(PY_OPTIONS, re.findall(r'"(--?[a-z][a-z-]*)"', " ".join(re.findall(r"add_argument\(([^)]*)", read(COLLECTOR)))),
                        "options de cmdb_collector.py")

    def test_options_collecteur_shell(self):
        self.assertKept(SH_OPTIONS, re.findall(r"^\s*(--[a-z-]+)\)", read(SHELL_COLLECTOR), re.M), "options de cmdb_collector.sh")

    def test_parametres_collecteur_powershell(self):
        src = read(PS_COLLECTOR)
        block = src[src.index("param("):src.index("$ErrorActionPreference")]
        self.assertKept(PS_PARAMS, re.findall(r"\]\s*\$([A-Za-z]+)", block), "paramètres de cmdb_collector.ps1")

    def test_variables_du_role(self):
        names = re.findall(r"^([a-z_]+):", read(os.path.join(ROOT, "roles", "cmdb_collect", "defaults", "main.yml")), re.M)
        self.assertKept(ROLE_VARS, names, "variables du rôle cmdb_collect")

    def test_consolidation(self):
        self.assertKept(CONSOLIDATE_VARS, re.findall(r"cmdb_[a-z_]+", read(os.path.join(ROOT, "consolidate.yml"))),
                        "variables de consolidate.yml")
        self.assertKept(BUILD_OPTIONS, re.findall(r'add_argument\("(--[a-z-]+)"', read(BUILD)), "options de cmdb_build.py")

    def test_fichiers_et_marqueurs(self):
        for p in PLAYBOOKS:
            self.assertTrue(os.path.exists(os.path.join(ROOT, p)), p)
        for c in (COLLECTOR, SHELL_COLLECTOR, PS_COLLECTOR):
            self.assertIn("CMDB-B64-BEGIN", read(c), c)
            self.assertIn("CMDB-B64-END", read(c), c)
        self.assertIn("'%s'" % SCHEMA, read(PS_COLLECTOR))


class Documents(unittest.TestCase):
    """Ce que produisent aujourd'hui les collecteurs Python et shell contient toujours les clés gelées."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="cmdbfmt")
        lib = os.path.join(cls.tmp, "tree", "opt", "app", "lib")
        os.makedirs(lib)
        with zipfile.ZipFile(os.path.join(lib, "commons-lang3-3.12.0.jar"), "w") as z:
            z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nImplementation-Version: 3.12.0\n")
            z.writestr("META-INF/maven/org.apache.commons/commons-lang3/pom.properties",
                       "groupId=org.apache.commons\nartifactId=commons-lang3\nversion=3.12.0\n")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def check(self, doc, meta_extra=()):
        self.assertEqual(doc["schema"], SCHEMA)
        self.assertEqual(sorted(TOP - set(doc)), [])
        self.assertEqual(sorted((META | set(meta_extra)) - set(doc["meta"])), [])
        self.assertEqual(sorted(FS - set(doc["filesystem"])), [])
        self.assertEqual(doc["meta"]["tags"], {"app": "A", "platform": "p"})
        arch = doc["filesystem"]["java_archives"]
        self.assertEqual(len(arch), 1)
        self.assertEqual(sorted(ARCHIVE - set(arch[0])), [])
        self.assertEqual(arch[0]["maven"][0]["artifactId"], "commons-lang3")

    def test_python(self):
        out = os.path.join(self.tmp, "py.json.gz")
        subprocess.check_call([sys.executable, COLLECTOR, "-o", out, "--scan-root", os.path.join(self.tmp, "tree"), "--no-exec-probes",
                               "--no-file-owners", "--host-label", "h", "--run-id", "r", "--tag", "app=A", "--tag", "platform=p"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with gzip.open(out) as f:
            self.check(json.loads(f.read().decode("utf-8")), ("privileged", "argv"))

    @unittest.skipUnless(shutil.which("dash"), "dash absent")
    def test_shell(self):
        env = dict(os.environ, CMDB_TEST_SCAN_ROOT=os.path.join(self.tmp, "tree"))
        raw = subprocess.check_output(["dash", SHELL_COLLECTOR, "--no-exec-probes", "--host-label", "h", "--run-id", "r",
                                       "--tag", "app=A", "--tag", "platform=p"], env=env, stderr=subprocess.DEVNULL)
        src, dst = os.path.join(self.tmp, "sh.out"), os.path.join(self.tmp, "sh.json.gz")
        with open(src, "wb") as f:
            f.write(raw)
        subprocess.check_call([sys.executable, UNPACK, src, dst], stdout=subprocess.DEVNULL)
        with gzip.open(dst) as f:
            self.check(json.loads(f.read().decode("utf-8")), ("collector",))


class Lecture(unittest.TestCase):
    """Collectes gelées (une par collecteur) : la consolidation doit toujours les lire."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="cmdbfmt")
        store = os.path.join(cls.tmp, "store")

        def put(host, run, doc_bytes):
            d = os.path.join(store, "APPV1", "prod", host)
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, run + ".json.gz"), "wb") as f:
                f.write(doc_bytes)

        for name, host, run in (("python-1.1.0.json", "srv-py01", "20261101T080000Z-0001"),
                                ("powershell-0.1.0.json", "srv-win01", "20261101T080000Z-win")):
            with open(os.path.join(FIXTURES, name), "rb") as f:
                put(host, run, gzip.compress(f.read()))
        sh = os.path.join(cls.tmp, "sh.json.gz")
        subprocess.check_call([sys.executable, UNPACK, os.path.join(FIXTURES, "shell-1.2.0.stdout"), sh], stdout=subprocess.DEVNULL)
        with open(sh, "rb") as f:
            put("srv-sh01", "20261101T080000Z-0001", f.read())
        # Collecte d'un format futur : à ignorer, avec un avertissement, sans rien casser
        put("srv-futur", "20261101T090000Z-0002", gzip.compress(json.dumps(
            {"schema": "cmdb-collector/2", "meta": {"host_label": "srv-futur", "tags": {"app": "APPV1", "platform": "prod"}}}).encode()))
        # Lot transférable (format de finish.yml) contenant une seconde copie de la collecte Python, sous un autre hôte
        lot = os.path.join(cls.tmp, "lot.tar.gz")
        with open(os.path.join(FIXTURES, "python-1.1.0.json"), encoding="utf-8") as f:
            doc = json.load(f)
        doc["meta"].update(host_label="srv-lot01", run_id="20261102T080000Z-0003")
        with tarfile.open(lot, "w:gz") as t:
            for name, data in (("APPV1/prod/srv-lot01/20261102T080000Z-0003.json.gz", gzip.compress(json.dumps(doc).encode())),
                               ("_runs/20261102T080000Z-0003/_run.json", json.dumps({"run_id": "20261102T080000Z-0003"}).encode()),
                               ("_runs/20261102T080000Z-0003/APPV1__prod__srv-lot01.json", json.dumps(
                                   {"run_id": "20261102T080000Z-0003", "host": "srv-lot01", "app": "APPV1", "platform": "prod",
                                    "status": "ok", "collector": "python"}).encode())):
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                t.addfile(ti, io.BytesIO(data))
        out = os.path.join(cls.tmp, "build")
        proc = subprocess.run([sys.executable, BUILD, "--store", store, "--lot", lot, "--out", out, "--no-report", "--no-dossiers"],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        cls.rc, cls.stdout, cls.stderr = proc.returncode, proc.stdout, proc.stderr
        cls.db = sqlite3.connect(os.path.join(out, "cmdb.sqlite"))

    @classmethod
    def tearDownClass(cls):
        cls.db.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def q(self, sql, *args):
        return self.db.execute(sql, args).fetchall()

    def test_consolidation_reussie(self):
        self.assertEqual(self.rc, 0, self.stderr)

    def test_hotes(self):
        self.assertEqual(self.q("SELECT host, app, platform FROM hosts ORDER BY host"),
                         [("srv-lot01", "APPV1", "prod"), ("srv-py01", "APPV1", "prod"), ("srv-sh01", "APPV1", "prod"),
                          ("srv-win01", "APPV1", "prod")])
        os_ = dict(self.q("SELECT host, os_pretty FROM hosts"))
        self.assertIn("Red Hat Enterprise Linux 8.9", os_["srv-py01"])
        self.assertIn("Debian GNU/Linux 12", os_["srv-sh01"])
        self.assertIn("Windows Server 2019", os_["srv-win01"])

    def test_archives_java(self):
        got = self.q("SELECT host FROM software WHERE family = 'commons-lang3' AND version = '3.12.0' ORDER BY host")
        self.assertEqual([h for (h,) in got], ["srv-lot01", "srv-py01", "srv-sh01", "srv-win01"])

    def test_paquets(self):
        got = set(self.q("SELECT host, name FROM packages WHERE name IN ('openssl', 'kernel', 'linux-image-6.1.0-26-amd64')"))
        self.assertTrue({("srv-py01", "openssl"), ("srv-py01", "kernel"), ("srv-sh01", "openssl")} <= got, got)

    def test_pas_de_durcissement_linux_sur_windows(self):
        self.assertEqual(self.q("SELECT COUNT(*) FROM hardening_results WHERE host = 'srv-win01'"), [(0,)])

    def test_format_futur_ignore(self):
        self.assertEqual(self.q("SELECT COUNT(*) FROM hosts WHERE host = 'srv-futur'"), [(0,)])
        self.assertIn("cmdb-collector/2", self.stderr)


if __name__ == "__main__":
    unittest.main()
