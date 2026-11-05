# -*- coding: utf-8 -*-
import unittest

from tests.common import C

SECRET = "S3cr3tPw"


def one(text, fname=""):
    refs = C.extract_db_refs(text, fname)
    assert len(refs) == 1, refs
    r = refs[0]
    return r["engine"], r["host"], r["port"], r["database"]


class Formats(unittest.TestCase):
    def test_jdbc_postgresql(self):
        self.assertEqual(one("spring.datasource.url=jdbc:postgresql://pg01.exemple.test:5433/appdb?sslmode=require"),
                         ("postgresql", "pg01.exemple.test", 5433, "appdb"))

    def test_jdbc_postgresql_multi_hotes(self):
        refs = C.extract_db_refs("url=jdbc:postgresql://pg1:5432,pg2:5433/appdb?targetServerType=primary")
        self.assertEqual([(r["host"], r["port"]) for r in refs], [("pg1", 5432), ("pg2", 5433)])

    def test_jdbc_mysql_et_mariadb(self):
        self.assertEqual(one('url="jdbc:mariadb://db1/app"')[:2], ("mysql", "db1"))

    def test_jdbc_sqlserver(self):
        self.assertEqual(one("jdbc:sqlserver://sql1:1433;databaseName=compta;encrypt=true"), ("sqlserver", "sql1", 1433, "compta"))

    def test_jdbc_oracle_sid(self):
        self.assertEqual(one("jdbc:oracle:thin:@ora1:1521:PROD"), ("oracle", "ora1", 1521, "PROD"))

    def test_jdbc_oracle_service(self):
        self.assertEqual(one("jdbc:oracle:thin:@//ora1.exemple.test:1522/svc.exemple"), ("oracle", "ora1.exemple.test", 1522, "svc.exemple"))

    def test_jdbc_oracle_descripteur(self):
        t = "url=jdbc:oracle:thin:@(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=scan1)(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=svc)))"
        self.assertEqual(one(t), ("oracle", "scan1", 1521, "svc"))

    def test_jdbc_oracle_alias_tns(self):
        r = C.extract_db_refs("jdbc:oracle:thin:@PRODTNS")[0]
        self.assertEqual((r["host"], r["alias"]), (None, "PRODTNS"))

    def test_uri_sqlalchemy(self):
        self.assertEqual(one("DATABASE_URL=postgresql+psycopg2://u:%s@pg1:5432/app" % SECRET), ("postgresql", "pg1", 5432, "app"))

    def test_mongodb(self):
        self.assertEqual(one("mongodb://m1:27017/app")[:3], ("mongodb", "m1", 27017))

    def test_http_ignore(self):
        self.assertEqual(C.extract_db_refs("url=https://exemple.test:8443/api"), [])

    def test_pdo(self):
        self.assertEqual(one('$dsn = "pgsql:host=pg1;port=5432;dbname=app";'), ("postgresql", "pg1", 5432, "app"))

    def test_libpq(self):
        self.assertEqual(one("host=pg1 port=5433 dbname=app user=a password=%s" % SECRET), ("postgresql", "pg1", 5433, "app"))

    def test_pgbouncer(self):
        self.assertEqual(one("[databases]\napp = host=pg1 port=5432 dbname=app\n", "pgbouncer.ini"), ("postgresql", "pg1", 5432, "app"))

    def test_env(self):
        t = "DB_CONNECTION=pgsql\nDB_HOST=pg1.exemple.test\nDB_PORT=5432\nDB_DATABASE=app\nDB_PASSWORD=%s\n" % SECRET
        self.assertEqual(one(t, ".env"), ("postgresql", "pg1.exemple.test", 5432, "app"))

    def test_pghost(self):
        self.assertEqual(one("export PGHOST=pg1\nexport PGPORT=5433\nexport PGDATABASE=app\n", ".env"), ("postgresql", "pg1", 5433, "app"))

    def test_wordpress(self):
        t = "define('DB_NAME', 'wp');\ndefine('DB_PASSWORD', '%s');\ndefine('DB_HOST', 'my1:3307');\n" % SECRET
        self.assertEqual(one(t, "wp-config.php"), ("mysql", "my1", 3307, "wp"))

    def test_rails(self):
        t = "production:\n  adapter: postgresql\n  host: pg1\n  port: 5432\n  database: app\n  password: %s\n" % SECRET
        self.assertEqual(one(t, "database.yml"), ("postgresql", "pg1", 5432, "app"))

    def test_django(self):
        t = "DATABASES = {\n 'default': {\n  'ENGINE': 'django.db.backends.postgresql',\n  'NAME': 'app',\n  'HOST': 'pg1',\n  'PORT': '5432',\n }\n}\n"
        self.assertEqual(one(t, "settings.py"), ("postgresql", "pg1", 5432, "app"))

    def test_odbc(self):
        t = "[app]\nDriver=PostgreSQL Unicode\nServername=pg1\nPort=5432\nDatabase=app\n"
        self.assertEqual(one(t, "odbc.ini"), ("postgresql", "pg1", 5432, "app"))

    def test_ado(self):
        t = '"Default": "Server=sql1,1433;Database=app;User Id=u;Password=%s;"' % SECRET
        self.assertEqual(one(t, "appsettings.json")[1:], ("sql1", 1433, "app"))

    def test_tnsnames(self):
        t = """# commentaire
PROD, PROD.EXEMPLE =
  (DESCRIPTION =
    (ADDRESS_LIST =
      (ADDRESS = (PROTOCOL = TCP)(HOST = ora1)(PORT = 1521))
      (ADDRESS = (PROTOCOL = TCP)(HOST = ora2)(PORT = 1522)))
    (CONNECT_DATA = (SERVICE_NAME = prod.exemple)))

RECETTE = (DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=ora3)(PORT=1521))(CONNECT_DATA=(SID=REC)))
"""
        refs = C.extract_db_refs(t, "tnsnames.ora")
        self.assertEqual([(r["alias"], r["host"], r["port"], r["database"]) for r in refs],
                         [("PROD", "ora1", 1521, "prod.exemple"), ("PROD", "ora2", 1522, "prod.exemple"), ("RECETTE", "ora3", 1521, "REC")])


class Secrets(unittest.TestCase):
    CASES = [
        ("jdbc:postgresql://pg1/app?user=a&password=%s", ""),
        ("jdbc:mysql://admin:%s@my1:3306/app", ""),
        ("jdbc:oracle:thin:scott/%s@//ora1:1521/svc", ""),
        ("jdbc:oracle:thin:scott/%s@ora1:1521:SID", ""),
        ("jdbc:oracle:thin:scott/%s", ""),
        ("postgres://u:%s@pg1/app", ""),
        ("mongodb://u:%s@m1,m2/app?replicaSet=r", ""),
        ("pgsql:host=pg1;dbname=app;user=u;password=%s", ""),
        ("Server=s1;Database=d;User Id=u;Password=%s;", ""),
        ("host=pg1 dbname=app password=%s", ""),
        ("DB_HOST=pg1\nDB_PASSWORD=%s\n", ".env"),
        ("[client]\nhost=my1\npassword=%s\n", "my.cnf"),
        ("production:\n  host: pg1\n  password: %s\n", "database.yml"),
    ]

    def test_aucun_secret_ne_sort(self):
        for tpl, fname in self.CASES:
            self.assertNotIn(SECRET, repr(C.extract_db_refs(tpl % SECRET, fname)), tpl)


class Filtrage(unittest.TestCase):
    def test_gabarits_ignores(self):
        for t in ("jdbc:postgresql://${DB_HOST}:5432/app", "DB_HOST={{ db_host }}\n", "DB_HOST=%(host)s\n",
                  "jdbc:mysql://example.com/test", "jdbc:postgresql://host:5432/db"):
            self.assertEqual([r for r in C.extract_db_refs(t, ".env") if r.get("host")], [], t)

    def test_port_invalide(self):
        self.assertEqual(C.extract_db_refs("jdbc:postgresql://pg1:99999/app"), [])

    def test_selection_des_fichiers(self):
        ok = ["/opt/app/conf/application.properties", "/srv/app/.env", "/var/www/html/wp-config.php", "/etc/odbc.ini",
              "/opt/tomcat/conf/context.xml", "/opt/tomcat/conf/Catalina/localhost/app.xml", "/opt/wl/config/jdbc/ds-jdbc.xml",
              "/u01/app/oracle/product/19/db/network/admin/tnsnames.ora"]
        ko = ["/opt/app/samples/application.properties", "/usr/share/app/app.properties", "/opt/app/test/.env",
              "/u01/app/oracle/product/19/db/network/admin/samples/tnsnames.ora", "/opt/app/readme.txt",
              "/u01/app/oracle/product/19/db/x/y.properties", "/opt/app/node_modules/a/.env"]
        for p in ok:
            self.assertTrue(C.is_db_config(p, p.rsplit("/", 1)[1].lower()), p)
        for p in ko:
            self.assertFalse(C.is_db_config(p, p.rsplit("/", 1)[1].lower()), p)


if __name__ == "__main__":
    unittest.main()
