import unittest

from oobmap.payloads import PROFILES as OLD_PROFILES
from oobmap._payloads_new import mssql as new_mssql
from oobmap._payloads_new import mysql as new_mysql
from oobmap._payloads_new import postgres as new_postgres
from oobmap._payloads_new import oracle as new_oracle
from oobmap._payloads_new import sqlite as new_sqlite


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


class PostgresEngineEquivalenceTests(unittest.TestCase):
    NAMES = ("postgres-program", "postgres-dblink")

    def test_substring_matches(self):
        for name in self.NAMES:
            self.assertEqual(
                new_postgres.substring(name, "SELECT x", 3),
                OLD_PROFILES[name].substring("SELECT x", 3),
            )

    def test_payload_matches(self):
        for name in self.NAMES:
            self.assertEqual(
                new_postgres.payload(name, "trk", "1=1", "tok.oast.test"),
                OLD_PROFILES[name].payload("trk", "1=1", "tok.oast.test"),
            )

    def test_payloads_full_matches(self):
        for name in self.NAMES:
            self.assertEqual(
                new_postgres.payloads_full(name, "trk", "1=1", "tok.oast.test"),
                OLD_PROFILES[name]._payloads_full("trk", "1=1", "tok.oast.test"),
            )

    def test_direct_payload_matches(self):
        for name in self.NAMES:
            self.assertEqual(
                new_postgres.direct_payload(name, "trk", "SELECT password FROM users", "run-d", "oast.test"),
                OLD_PROFILES[name].direct_payload("trk", "SELECT password FROM users", "run-d", "oast.test"),
            )

    def test_direct_payloads_full_matches(self):
        for name in self.NAMES:
            base_payload = OLD_PROFILES[name].direct_payload(
                "trk", "SELECT password FROM users", "run-d", "oast.test"
            )
            self.assertEqual(
                new_postgres.direct_payloads_full(
                    name, "trk", "SELECT password FROM users", "run-d", "oast.test", base_payload
                ),
                OLD_PROFILES[name]._direct_payloads_full(
                    "trk", "SELECT password FROM users", "run-d", "oast.test"
                ),
            )


class OracleEngineEquivalenceTests(unittest.TestCase):
    NAMES = ("oracle-http", "oracle-dns")

    def test_substring_matches(self):
        for name in self.NAMES:
            self.assertEqual(
                new_oracle.substring(name, "SELECT x", 3),
                OLD_PROFILES[name].substring("SELECT x", 3),
            )

    def test_payload_matches(self):
        for name in self.NAMES:
            self.assertEqual(
                new_oracle.payload(name, "trk", "1=1", "tok.oast.test"),
                OLD_PROFILES[name].payload("trk", "1=1", "tok.oast.test"),
            )

    def test_payloads_full_matches(self):
        for name in self.NAMES:
            self.assertEqual(
                new_oracle.payloads_full(name, "trk", "1=1", "tok.oast.test"),
                OLD_PROFILES[name]._payloads_full("trk", "1=1", "tok.oast.test"),
            )

    def test_direct_payload_matches(self):
        for name in self.NAMES:
            self.assertEqual(
                new_oracle.direct_payload(name, "trk", "SELECT password FROM users", "run-d", "oast.test"),
                OLD_PROFILES[name].direct_payload("trk", "SELECT password FROM users", "run-d", "oast.test"),
            )

    def test_direct_payloads_full_matches(self):
        for name in self.NAMES:
            base_payload = OLD_PROFILES[name].direct_payload(
                "trk", "SELECT password FROM users", "run-d", "oast.test"
            )
            self.assertEqual(
                new_oracle.direct_payloads_full(
                    name, "trk", "SELECT password FROM users", "run-d", "oast.test", base_payload
                ),
                OLD_PROFILES[name]._direct_payloads_full(
                    "trk", "SELECT password FROM users", "run-d", "oast.test"
                ),
            )


class SqliteEngineEquivalenceTests(unittest.TestCase):
    NAMES = ("sqlite-http",)

    def test_substring_matches(self):
        for name in self.NAMES:
            self.assertEqual(
                new_sqlite.substring(name, "SELECT x", 3),
                OLD_PROFILES[name].substring("SELECT x", 3),
            )

    def test_payload_matches(self):
        for name in self.NAMES:
            self.assertEqual(
                new_sqlite.payload(name, "trk", "1=1", "tok.oast.test"),
                OLD_PROFILES[name].payload("trk", "1=1", "tok.oast.test"),
            )

    def test_payloads_full_matches(self):
        for name in self.NAMES:
            self.assertEqual(
                new_sqlite.payloads_full(name, "trk", "1=1", "tok.oast.test"),
                OLD_PROFILES[name]._payloads_full("trk", "1=1", "tok.oast.test"),
            )

    def test_direct_payload_matches(self):
        for name in self.NAMES:
            self.assertEqual(
                new_sqlite.direct_payload(name, "trk", "SELECT password FROM users", "run-d", "oast.test"),
                OLD_PROFILES[name].direct_payload("trk", "SELECT password FROM users", "run-d", "oast.test"),
            )

    def test_direct_payloads_full_matches(self):
        for name in self.NAMES:
            base_payload = OLD_PROFILES[name].direct_payload(
                "trk", "SELECT password FROM users", "run-d", "oast.test"
            )
            self.assertEqual(
                new_sqlite.direct_payloads_full(
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
