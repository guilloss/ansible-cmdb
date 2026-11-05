# -*- coding: utf-8 -*-
import unittest

from tests.common import C


def pick(eps, kind):
    return [e for e in eps if e["kind"] == kind]


class Apache(unittest.TestCase):
    T = """Listen 80
Listen 10.0.0.1:8443 https
# <VirtualHost *:81>
<VirtualHost *:443>
    ServerName www.exemple.test:443
    ServerAlias a.exemple.test b.exemple.test
    DocumentRoot "/var/www/html"
    SSLEngine on
    SSLCertificateFile /etc/pki/tls/certs/www.crt
    SSLCertificateKeyFile /etc/pki/tls/private/www.key
    ProxyPass /app http://u:mdp@tomcat01:8080/app
    ProxyPass /statique !
</VirtualHost>
"""

    def test_vhost(self):
        e = C.parse_endpoints(self.T, "/etc/httpd/conf.d/ssl.conf")
        v = pick(e, "vhost")[0]
        self.assertEqual((v["product"], v["address"], v["port"], v["server_name"], v["root"], v["tls"]),
                         ("apache", "*", 443, "www.exemple.test", "/var/www/html", True))
        self.assertEqual(v["aliases"], ["a.exemple.test", "b.exemple.test"])
        self.assertEqual(v["cert"], "/etc/pki/tls/certs/www.crt")

    def test_listen_et_proxy(self):
        e = C.parse_endpoints(self.T, "/etc/httpd/conf/httpd.conf")
        self.assertEqual([(x["address"], x["port"]) for x in pick(e, "listen")], [(None, 80), ("10.0.0.1", 8443)])
        p = pick(e, "proxy")
        self.assertEqual(len(p), 1)
        self.assertEqual((p[0]["location"], p[0]["backend"]), ("/app", "http://tomcat01:8080/app"))

    def test_ihs(self):
        self.assertEqual(C.parse_endpoints("Listen 80\n", "/opt/IBM/HTTPServer/conf/httpd.conf")[0]["product"], "ihs")


class Nginx(unittest.TestCase):
    T = """upstream api { server 10.0.0.2:8080; server 10.0.0.3:8080; }
upstream api2 {
    server 10.0.0.2:8080;
    server 10.0.0.3:8080;
}
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name www.exemple.test alias.exemple.test;
    root /srv/www;
    ssl_certificate /etc/nginx/www.crt;
    location /api/ {
        proxy_pass http://api2/;
    }
}
server {
    listen 80 default_server;
    server_name _;
}
"""

    def test_nginx(self):
        e = C.parse_endpoints(self.T, "/etc/nginx/nginx.conf")
        v = pick(e, "vhost")
        self.assertEqual([(x["address"], x["port"], x["server_name"], x["tls"]) for x in v],
                         [(None, 443, "www.exemple.test", True), ("::", 443, "www.exemple.test", True), (None, 80, None, False)])
        self.assertEqual(v[0]["aliases"], ["alias.exemple.test"])
        p = pick(e, "proxy")[0]
        self.assertEqual(p["location"], "/api/")
        self.assertIn("10.0.0.3:8080", p["backend"])


class Tomcat(unittest.TestCase):
    T = """<Server port="8005" shutdown="SHUTDOWN">
<!-- <Connector port="9999" /> -->
<Service name="Catalina">
  <Connector port="8080" protocol="HTTP/1.1" connectionTimeout="20000" />
  <Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol" SSLEnabled="true"
             scheme="https" keystoreFile="conf/ks.jks" keystorePass="S3cr3t"/>
  <Engine name="Catalina" defaultHost="localhost">
    <Host name="app.exemple.test" appBase="webapps">
      <Alias>www.app.exemple.test</Alias>
      <Context path="/gestion" docBase="/opt/app/gestion"/>
    </Host>
  </Engine>
</Service></Server>"""

    def test_tomcat(self):
        e = C.parse_endpoints(self.T, "/opt/tomcat/conf/server.xml")
        self.assertEqual([(x["port"], x["tls"]) for x in pick(e, "connector")], [(8080, False), (8443, True)])
        h = pick(e, "vhost")[0]
        self.assertEqual((h["server_name"], h["root"], h["aliases"]), ("app.exemple.test", "webapps", ["www.app.exemple.test"]))
        c = pick(e, "context")[0]
        self.assertEqual((c["location"], c["root"], c["server_name"]), ("/gestion", "/opt/app/gestion", "app.exemple.test"))
        self.assertNotIn("S3cr3t", repr(e))


class Autres(unittest.TestCase):
    def test_haproxy(self):
        t = "frontend web\n  bind *:443 ssl crt /x.pem\n  default_backend b\nbackend b\n  server s1 10.0.0.2:8080 check\n"
        e = C.parse_endpoints(t, "/etc/haproxy/haproxy.cfg")
        self.assertEqual((e[0]["kind"], e[0]["port"], e[0]["tls"]), ("frontend", 443, True))
        self.assertEqual((e[1]["kind"], e[1]["backend"]), ("proxy", "10.0.0.2:8080"))

    def test_jboss(self):
        t = '<socket-binding name="http" port="${jboss.http.port:8080}"/><socket-binding name="txn" port="4712"/>'
        e = C.parse_endpoints(t, "/opt/wildfly/standalone/configuration/standalone.xml")
        self.assertEqual([(x["protocol"], x["port"]) for x in e], [("http", 8080)])

    def test_selection(self):
        for p in ("/etc/apache2/sites-enabled/000-default", "/etc/httpd/conf.d/app.conf", "/etc/nginx/conf.d/a.conf", "/opt/tomcat/conf/server.xml"):
            self.assertTrue(C.is_web_config(p, p.rsplit("/", 1)[1].lower()), p)
        for p in ("/etc/apache2/sites-available/x.conf", "/usr/share/nginx/nginx.conf", "/etc/app/conf.d/x.conf"):
            self.assertFalse(C.is_web_config(p, p.rsplit("/", 1)[1].lower()), p)


class Phpinfo(unittest.TestCase):
    T = """phpinfo()
PHP Version => 8.2.1

Configuration

Core

memory_limit => 128M => 128M
mysql.default_password => x => x
session.save_path => tcp://u:mdp@r:6379 => tcp://u:mdp@r:6379

Environment

Variable => Value
DB_PASSWORD => S3cr3t
PATH => /bin

PHP Variables

$_SERVER['DB_PASSWORD'] => S3cr3t
$_ENV['X'] => S3cr3t
$_SERVER['argv'] => Array
(
    [0] => S3cr3t
)

PHP License
"""

    def test_filtre(self):
        o = C.phpinfo_filter(self.T)
        self.assertNotIn("S3cr3t", o)
        self.assertNotIn("mdp", o)
        self.assertIn("memory_limit => 128M", o)
        self.assertIn("mysql.default_password => ***", o)
        self.assertIn("PHP License", o)


if __name__ == "__main__":
    unittest.main()
