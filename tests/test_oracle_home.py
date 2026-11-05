# -*- coding: utf-8 -*-
import unittest

from tests.common import C

COMPS = """<?xml version="1.0"?>
<PRD_LIST><TL_LIST>
<COMP NAME="oracle.server" VER="19.0.0.0.0" BUILD_NUMBER="0" REP_VER="0.0.0.0.0" RELEASE="Production">
<EXT_NAME>Oracle Database 19c</EXT_NAME><INST_TYPE NAME="EE" NAME_ID="EE"/></COMP>
</TL_LIST>
<ONEOFF_LIST>
<ONEOFF REF_ID="36233263" UNIQ_ID="25580889" ROLLBACK="T" XML_INV_LOC="oneoffs/36233263/" ACT_INST_VER="12.2.0.7.0" INSTALL_TIME="2024.Jun.10 12:00:00 CEST">
   <DESC>Database Release Update : 19.23.0.0.240416 (36233263)</DESC>
   <REF_LIST><REF NAME="oracle.rdbms" VER="19.0.0.0.0" HOME_IDX="1"/></REF_LIST>
</ONEOFF>
<ONEOFF REF_ID="36199232" UNIQ_ID="1" ROLLBACK="T" INSTALL_TIME="2024.Jun.10 13:00:00 CEST"><DESC>OJVM RELEASE UPDATE: 19.23.0.0.240416 (36199232)</DESC></ONEOFF>
</ONEOFF_LIST></PRD_LIST>"""
LISTENER = """LISTENER =
  (DESCRIPTION_LIST =
    (DESCRIPTION =
      (ADDRESS = (PROTOCOL = TCP)(HOST = ora1)(PORT = 1521))))
SID_LIST_LISTENER = (SID_LIST = (SID_DESC = (SID_NAME = PROD)))
ADR_BASE_LISTENER = /u01/app/oracle
"""


def fake(files, dirs):
    return (lambda rel: files.get(rel)), (lambda rel: dirs.get(rel))


class Home(unittest.TestCase):
    def test_home_lisible(self):
        read, ls = fake({"inventory/ContentsXML/comps.xml": COMPS, "OPatch/version.txt": "OPATCH_VERSION:12.2.0.1.41\n",
                         "network/admin/listener.ora": LISTENER}, {"dbs": ["initPROD.ora", "spfilePROD.ora", "orapwPROD", "init.ora", "hc_PROD.dat"]})
        f = C.oracle_home_facts("/u01/db", read, ls)
        self.assertEqual((f["product"], f["version"], f["install_type"]), ("database", "19.0.0.0.0", "EE"))
        self.assertEqual(f["visibility"], "complet")
        self.assertEqual(f["opatch_version"], "12.2.0.1.41")
        self.assertEqual([p["id"] for p in f["patches"]], ["36199232", "36233263"])
        self.assertIn("19.23.0.0.240416", f["patches"][1]["description"])
        self.assertEqual(f["patches"][1]["installed_at"], "2024.Jun.10 12:00:00 CEST")
        self.assertEqual(f["configured_sids"], ["PROD"])
        self.assertEqual(f["listeners"], [{"name": "LISTENER", "host": "ora1", "port": 1521}])

    def test_home_partiellement_lisible(self):
        read, ls = fake({}, {".patch_storage": ["36233263_Apr_14_2024_07_30_00", "NApply", "interim_inventory.txt"]})
        f = C.oracle_home_facts("/u01/db", read, ls)
        self.assertEqual(f["visibility"], "partiel")
        self.assertEqual(f["patches"], [{"id": "36233263", "description": None, "installed_at": None}])

    def test_home_illisible(self):
        read, ls = fake({}, {})
        f = C.oracle_home_facts("/u01/db", read, ls)
        self.assertEqual((f["visibility"], f["patches"]), ("aucun", []))


class Candidats(unittest.TestCase):
    def test_toutes_les_sources(self):
        oratab = "# commentaire\nPROD:/u01/db:Y\n+ASM:/u01/grid:N\n"
        inv = C.parse_central_inventory('<HOME NAME="a" LOC="/u01/db" TYPE="O" IDX="1"/>'
                                        '<HOME NAME="b" LOC="/u01/old" TYPE="O" IDX="2" REMOVED="T"/>'
                                        '<HOME NAME="c" LOC="/u01/grid" TYPE="O" IDX="3" CRS="true"/>')
        self.assertEqual([h["loc"] for h in inv], ["/u01/db", "/u01/grid"])
        self.assertTrue(inv[1]["crs"])
        procs = [{"cmdline": "/u01/client/bin/tnslsnr LISTENER -inherit"}, {"exe": "/u01/x/bin/oracle"},
                 {"env": {"ORACLE_HOME": "/u01/y/"}}, {"cmdline": "/bin/bash"}]
        h = C.oracle_home_candidates(oratab, inv, "crs_home=/u01/crs\n", procs)
        self.assertEqual(sorted(h), ["/u01/client", "/u01/crs", "/u01/db", "/u01/grid", "/u01/x", "/u01/y"])
        self.assertEqual(h["/u01/db"], ["oratab", "inventory"])


if __name__ == "__main__":
    unittest.main()
