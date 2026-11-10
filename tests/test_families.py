# -*- coding: utf-8 -*-
"""Une bibliothèque ne prend jamais la famille d'un produit (pilote JDBC postgresql != serveur PostgreSQL)."""
import sqlite3
import unittest

from tests import fleet
from tests.common import TOOLS  # noqa: F401  (chemin des outils)
import cmdb_build as B


def software(doc):
    db = sqlite3.connect(":memory:")
    db.executescript(B.SCHEMA)
    b = B.Builder(db)
    b.process_host(("APPDEMO", "prod", doc["meta"]["host_label"]), doc, None, "test")
    b.flush()
    return db.execute("SELECT category, family, name, version FROM software ORDER BY 1, 2, 3").fetchall()


class Familles(unittest.TestCase):
    def test_pilote_jdbc(self):
        self.assertEqual(B.jar_family("postgresql", "org.postgresql", None, "42.7.1"), "postgresql-jdbc")
        self.assertEqual(B.jar_family("postgresql", None, {"Bundle-SymbolicName": "org.postgresql.jdbc"}, "42.7.1"), "postgresql-jdbc")
        self.assertEqual(B.jar_family("postgresql", None, {}, "9.4.1212"), "postgresql-jdbc")

    def test_homonyme_suffixe(self):
        self.assertEqual(B.library_family(B.jar_family("postgresql", "org.testcontainers", None, "1.19.4"), "maven"), "postgresql-maven")
        self.assertEqual(B.library_family("postgresql", "maven-unidentified"), "postgresql-maven")
        self.assertEqual(B.library_family("redis", "pypi"), "redis-pypi")
        self.assertEqual(B.library_family("mysql", "golang"), "mysql-golang")

    def test_bibliotheques_ordinaires_inchangees(self):
        for f in ("log4j-core", "spring-core", "jackson-databind", "requests", None):
            self.assertEqual(B.library_family(f, "maven"), f)

    def test_consolidation(self):
        d = fleet.app_host("r2", "2026-11-02T08:00:00Z")
        d["filesystem"]["java_archives"] = [
            {"path": "/opt/app/lib/postgresql-42.7.1.jar", "sha1": "a" * 40,
             "manifest": {"Bundle-SymbolicName": "org.postgresql.jdbc", "Implementation-Version": "42.7.1"}},
            {"path": "/opt/app/lib/postgresql-1.19.4.jar", "sha1": "b" * 40, "manifest": {}},
            {"path": "/opt/app/lib/x.jar", "maven": [{"groupId": "org.postgresql", "artifactId": "postgresql", "version": "42.6.0"}]},
        ]
        d["filesystem"]["python_packages"] = [{"name": "redis", "version": "5.0.1", "site": "/usr/lib/python3/site-packages"}]
        rows = software(d)
        fams = dict(((r[2], r[3]), r[1]) for r in rows if r[0] in ("java-archive", "python-package"))
        self.assertEqual(fams[("org.postgresql.jdbc", "42.7.1")], "postgresql-jdbc")
        self.assertEqual(fams[("postgresql", "1.19.4")], "postgresql-maven")
        self.assertEqual(fams[("org.postgresql:postgresql", "42.6.0")], "postgresql-jdbc")
        self.assertEqual(fams[("redis", "5.0.1")], "redis-pypi")
        self.assertFalse([r for r in rows if r[0] in B.LIBRARY_CATEGORIES and r[1] in B.PRODUCT_FAMILIES])


if __name__ == "__main__":
    unittest.main()
