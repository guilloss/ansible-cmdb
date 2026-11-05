# -*- coding: utf-8 -*-
"""Clés et certificats : vérifiés contre de vrais fichiers produits par openssl."""
import os
import shutil
import struct
import subprocess
import tempfile
import unittest

from tests.common import C
import cmdb_shell_parse


def sh(*a, **kw):
    subprocess.check_call(a, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kw)


@unittest.skipUnless(shutil.which("openssl"), "openssl absent")
class Vrais(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp(prefix="cmdbc")
        cls.key, cls.crt = os.path.join(cls.d, "a.key"), os.path.join(cls.d, "a.crt")
        sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", cls.key, "-out", cls.crt, "-days", "30",
           "-subj", "/C=FR/O=Exemple/CN=web.exemple.test", "-addext", "subjectAltName=DNS:web.exemple.test,DNS:alias.exemple.test,IP:10.0.0.5")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def path(self, n):
        return os.path.join(self.d, n)

    def read(self, p):
        with open(p, "rb") as f:
            return f.read()

    def test_certificat_pem(self):
        f = C.crypto_facts(self.read(self.crt), "a.crt")
        self.assertEqual((f["kind"], f["has_private_key"], f["cert_count"]), ("pem", False, 1))
        c = f["certs"][0]
        self.assertEqual(c["subject"], "C=FR,O=Exemple,CN=web.exemple.test")
        self.assertEqual(c["cn"], "web.exemple.test")
        self.assertTrue(c["self_signed"])
        self.assertEqual((c["key_alg"], c["key_bits"], c["sig_alg"]), ("RSA", 2048, "sha256WithRSA"))
        self.assertEqual(c["sans"], ["web.exemple.test", "alias.exemple.test", "10.0.0.5"])
        ref = subprocess.check_output(["openssl", "x509", "-in", self.crt, "-noout", "-enddate", "-serial", "-fingerprint", "-sha256"]).decode()
        self.assertIn(c["serial"].upper().lstrip("0"), ref.replace("serial=", "").lstrip("0"))
        self.assertIn(c["sha256"].upper(), ref.replace(":", ""))
        self.assertTrue(c["not_after"].endswith("Z"))

    def test_certificat_der(self):
        p = self.path("a.der")
        sh("openssl", "x509", "-in", self.crt, "-outform", "DER", "-out", p)
        f = C.crypto_facts(self.read(p), "a.der")
        self.assertEqual((f["kind"], f["certs"][0]["cn"]), ("der", "web.exemple.test"))

    def test_cle_en_clair(self):
        f = C.crypto_facts(self.read(self.key), "a.key")
        self.assertEqual((f["has_private_key"], f["encrypted"], f["key_type"]), (True, False, "PKCS8"))

    def test_cle_chiffree(self):
        p = self.path("e.key")
        sh("openssl", "pkey", "-in", self.key, "-aes256", "-passout", "pass:x", "-out", p)
        f = C.crypto_facts(self.read(p), "e.key")
        self.assertEqual((f["has_private_key"], f["encrypted"]), (True, True))

    def test_certificat_ec(self):
        k, c = self.path("ec.key"), self.path("ec.crt")
        sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", k, "-out", c,
           "-days", "1", "-subj", "/CN=ec")
        f = C.crypto_facts(self.read(c), "ec.crt")
        self.assertEqual((f["certs"][0]["key_alg"], f["certs"][0]["key_curve"]), ("EC", "P-256"))

    def test_rien_de_la_cle_ne_sort(self):
        lines = [l for l in self.read(self.key).decode().splitlines() if not l.startswith("-----")]
        out = repr(C.crypto_facts(self.read(self.key), "a.key"))
        for l in lines:
            self.assertNotIn(l, out)

    def _p12(self, pw, name):
        p = self.path(name)
        sh("openssl", "pkcs12", "-export", "-inkey", self.key, "-in", self.crt, "-out", p, "-passout", "pass:" + pw)
        return p

    def _collect_p12(self, p):
        col = C.Collector.__new__(C.Collector)
        f = C.crypto_facts(self.read(p), os.path.basename(p))
        col._pkcs12(p, f)
        return f

    def test_pkcs12_mot_de_passe_vide(self):
        f = self._collect_p12(self._p12("", "vide.p12"))
        self.assertTrue(f["empty_password"])
        self.assertEqual(f["certs"][0]["cn"], "web.exemple.test")

    def test_pkcs12_protege(self):
        f = self._collect_p12(self._p12("secret", "prot.p12"))
        self.assertEqual((f["encrypted"], f["certs"]), (True, []))
        self.assertNotIn("empty_password", f)

    def test_jks_fabrique(self):
        der = subprocess.check_output(["openssl", "x509", "-in", self.crt, "-outform", "DER"])

        def utf(s):
            return struct.pack(">H", len(s)) + s.encode()
        cert = utf("X.509") + struct.pack(">I", len(der)) + der
        trusted = struct.pack(">I", 2) + utf("ca") + b"\0" * 8 + cert
        key = struct.pack(">I", 1) + utf("srv") + b"\0" * 8 + struct.pack(">I", 3) + b"KEY" + struct.pack(">I", 1) + cert
        data = b"\xfe\xed\xfe\xed" + struct.pack(">II", 2, 2) + trusted + key + b"\0" * 20
        f = C.crypto_facts(data, "x.jks")
        self.assertEqual((f["kind"], f["has_private_key"], f["encrypted"], f["entries"]), ("jks", True, True, 2))
        self.assertEqual([c["alias"] for c in f["certs"]], ["ca", "srv"])
        self.assertEqual(f["certs"][1]["cn"], "web.exemple.test")


class Divers(unittest.TestCase):
    def test_openssh(self):
        d = tempfile.mkdtemp(prefix="cmdbs")
        try:
            p = os.path.join(d, "id_ed25519")
            if not shutil.which("ssh-keygen"):
                self.skipTest("ssh-keygen absent")
            sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", p)
            with open(p, "rb") as fh:
                f = C.crypto_facts(fh.read(), "id_ed25519")
            self.assertEqual((f["has_private_key"], f["encrypted"], f["key_type"]), (True, False, "ssh-ed25519"))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_fichier_quelconque_mentionne(self):
        f = C.crypto_facts(b"licence 1234", "licence.key")
        self.assertEqual((f["kind"], f["has_private_key"]), ("inconnu", None))

    def test_stash(self):
        self.assertEqual(C.crypto_facts(b"\x01\x02", "key.sth")["kind"], "gskit-stash")

    def test_selection(self):
        for p in ("/etc/ssl/private/a.key", "/opt/x/ks.jks", "/home/a/.ssh/id_rsa", "/etc/ssh/ssh_host_rsa_key", "/u01/wallet/cwallet.sso"):
            self.assertTrue(C.is_crypto_file(p, p.rsplit("/", 1)[1].lower()), p)
        for p in ("/etc/ssl/certs/ca.pem", "/usr/lib/python3/certifi/cacert.pem", "/opt/x/readme.txt", "/etc/pki/ca-trust/x.pem"):
            self.assertFalse(C.is_crypto_file(p, p.rsplit("/", 1)[1].lower()), p)

    def test_keytool(self):
        t = """Alias name: srv
Entry type: PrivateKeyEntry
Owner: CN=web.exemple.test, O=Exemple
Issuer: CN=ca
Serial number: 1a2b
Valid from: Mon Jan 01 10:00:00 UTC 2024 until: Wed Jan 01 10:00:00 UTC 2025
"""
        c = cmdb_shell_parse.parse_keytool(t)[0]
        self.assertEqual((c["alias"], c["cn"], c["not_after"]), ("srv", "web.exemple.test", "2025-01-01T10:00:00Z"))

    def test_mode_ls(self):
        self.assertEqual(cmdb_shell_parse.ls_mode("-rw-r-----"), "0640")
        self.assertEqual(cmdb_shell_parse.ls_mode("-rwxr-xr-x"), "0755")


class Modules(unittest.TestCase):
    def test_apache(self):
        t = "# LoadModule off_module modules/off.so\nLoadModule ssl_module modules/mod_ssl.so\n  LoadModule rewrite_module modules/mod_rewrite.so\n"
        m = C.parse_modules(t, "/etc/httpd/conf.modules.d/00.conf")
        self.assertEqual([(x["product"], x["module"]) for x in m], [("apache", "ssl_module"), ("apache", "rewrite_module")])

    def test_ihs(self):
        self.assertEqual(C.parse_modules("LoadModule ibm_ssl_module modules/mod_ibm_ssl.so\n", "/opt/IBM/HTTPServer/conf/httpd.conf")[0]["product"], "ihs")

    def test_nginx(self):
        m = C.parse_modules('load_module modules/ngx_http_geoip_module.so;\n', "/etc/nginx/nginx.conf")
        self.assertEqual((m[0]["product"], m[0]["module"]), ("nginx", "ngx_http_geoip_module"))

    def test_php(self):
        m = C.parse_modules("; extension=off\nextension=mbstring\nextension = /x/opcache.so ; c\nzend_extension=xdebug.so\n", "/etc/php.ini")
        self.assertEqual([x["module"] for x in m], ["mbstring", "opcache", "xdebug"])

    def test_postgresql(self):
        m = C.parse_modules("shared_preload_libraries = 'pg_stat_statements,auto_explain'  # c\n", "/etc/postgresql/14/main/postgresql.conf")
        self.assertEqual([x["module"] for x in m], ["pg_stat_statements", "auto_explain"])

    def test_redis_mysql(self):
        self.assertEqual(C.parse_modules("loadmodule /usr/lib/redis/rejson.so\n", "/etc/redis.conf")[0]["product"], "redis")
        m = C.parse_modules("plugin-load-add=auth_pam.so\n", "/etc/my.cnf")
        self.assertEqual((m[0]["product"], m[0]["module"]), ("mysql", "auth_pam"))

    def test_selection(self):
        ok = ["/etc/apache2/mods-enabled/ssl.load", "/etc/httpd/conf.modules.d/00-ssl.conf", "/etc/nginx/modules-enabled/50-x.conf",
              "/etc/php/8.2/fpm/conf.d/20-curl.ini", "/etc/php.d/20-curl.ini", "/opt/IBM/HTTPServer/conf/httpd.conf"]
        ko = ["/etc/apache2/mods-available/ssl.load", "/etc/app/conf.d/x.ini", "/usr/share/doc/php/php.ini"]
        for p in ok:
            self.assertTrue(C.is_module_config(p, p.rsplit("/", 1)[1]), p)
        for p in ko:
            self.assertFalse(C.is_module_config(p, p.rsplit("/", 1)[1]), p)


if __name__ == "__main__":
    unittest.main()
