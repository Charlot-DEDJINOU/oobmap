import unittest

from oobmap.payloads import PROFILES as OLD_PROFILES
from oobmap._payloads_new import mssql as new_mssql
from oobmap._payloads_new import mysql as new_mysql


class MssqlEngineEquivalenceTests(unittest.TestCase):
    NAMES = ("mssql", "mssql-cmdshell")

    def test_substring_matches(self):
        for name in self.NAMES:
            self.assertEqual(
                new_mssql.substring(name, "SELECT x", 3),
                OLD_PROFILES[name].substring("SELECT x", 3),
            )

    def test_payload_matches(self):
        for name in self.NAMES:
            self.assertEqual(
                new_mssql.payload(name, "trk", "1=1", "tok.oast.test"),
                OLD_PROFILES[name].payload("trk", "1=1", "tok.oast.test"),
            )

    def test_payloads_full_matches(self):
        for name in self.NAMES:
            self.assertEqual(
                new_mssql.payloads_full(name, "trk", "1=1", "tok.oast.test"),
                OLD_PROFILES[name]._payloads_full("trk", "1=1", "tok.oast.test"),
            )

    def test_direct_payload_matches(self):
        for name in self.NAMES:
            self.assertEqual(
                new_mssql.direct_payload(name, "trk", "SELECT password FROM users", "run-d", "oast.test"),
                OLD_PROFILES[name].direct_payload("trk", "SELECT password FROM users", "run-d", "oast.test"),
            )

    def test_direct_payloads_full_matches(self):
        for name in self.NAMES:
            base_payload = OLD_PROFILES[name].direct_payload(
                "trk", "SELECT password FROM users", "run-d", "oast.test"
            )
            self.assertEqual(
                new_mssql.direct_payloads_full(
                    name, "trk", "SELECT password FROM users", "run-d", "oast.test", base_payload
                ),
                OLD_PROFILES[name]._direct_payloads_full(
                    "trk", "SELECT password FROM users", "run-d", "oast.test"
                ),
            )


class MysqlEngineEquivalenceTests(unittest.TestCase):
    NAMES = ("mysql", "mysql-stacked")

    def test_substring_matches(self):
        for name in self.NAMES:
            self.assertEqual(
                new_mysql.substring(name, "SELECT x", 3),
                OLD_PROFILES[name].substring("SELECT x", 3),
            )

    def test_payload_matches(self):
        for name in self.NAMES:
            self.assertEqual(
                new_mysql.payload(name, "trk", "1=1", "tok.oast.test"),
                OLD_PROFILES[name].payload("trk", "1=1", "tok.oast.test"),
            )

    def test_payloads_full_matches(self):
        for name in self.NAMES:
            self.assertEqual(
                new_mysql.payloads_full(name, "trk", "1=1", "tok.oast.test"),
                OLD_PROFILES[name]._payloads_full("trk", "1=1", "tok.oast.test"),
            )

    def test_direct_payload_matches(self):
        for name in self.NAMES:
            self.assertEqual(
                new_mysql.direct_payload(name, "trk", "SELECT password FROM users", "run-d", "oast.test"),
                OLD_PROFILES[name].direct_payload("trk", "SELECT password FROM users", "run-d", "oast.test"),
            )

    def test_direct_payloads_full_matches(self):
        for name in self.NAMES:
            base_payload = OLD_PROFILES[name].direct_payload(
                "trk", "SELECT password FROM users", "run-d", "oast.test"
            )
            self.assertEqual(
                new_mysql.direct_payloads_full(
                    name, "trk", "SELECT password FROM users", "run-d", "oast.test", base_payload
                ),
                OLD_PROFILES[name]._direct_payloads_full(
                    "trk", "SELECT password FROM users", "run-d", "oast.test"
                ),
            )
