import unittest

from oobmap.dbms import DBMS as OLD_DBMS
from oobmap.dbms import METADATA as OLD_METADATA
from oobmap._dbms_new import mssql as new_mssql
from oobmap._dbms_new import mysql as new_mysql
from oobmap._dbms_new import postgres as new_postgres
from oobmap._dbms_new import oracle as new_oracle
from oobmap._dbms_new import sqlite as new_sqlite


class MssqlEquivalenceTests(unittest.TestCase):
    def test_table_expression(self):
        for database in (None, "appdb"):
            for index in (0, 3):
                self.assertEqual(
                    new_mssql.table_expression(index, database),
                    OLD_DBMS["mssql"].table_expression(index, database),
                )

    def test_column_expression(self):
        for database in (None, "appdb"):
            for index in (0, 2):
                self.assertEqual(
                    new_mssql.column_expression("users", index, database),
                    OLD_DBMS["mssql"].column_expression("users", index, database),
                )

    def test_dump_expression(self):
        for database in (None, "appdb"):
            for where in (None, "enabled=1"):
                self.assertEqual(
                    new_mssql.dump_expression("users", ["username", "password"], 0, where, database),
                    OLD_DBMS["mssql"].dump_expression("users", ["username", "password"], 0, where, database),
                )

    def test_dbs_expression(self):
        self.assertEqual(new_mssql.dbs_expression(0), OLD_DBMS["mssql"].dbs_expression(0))
        self.assertEqual(new_mssql.dbs_expression(3), OLD_DBMS["mssql"].dbs_expression(3))

    def test_concat_columns(self):
        self.assertEqual(new_mssql.concat_columns(["username"]), OLD_DBMS["mssql"].concat_columns(["username"]))
        self.assertEqual(
            new_mssql.concat_columns(["username", "password"]),
            OLD_DBMS["mssql"].concat_columns(["username", "password"]),
        )

    def test_cast_text(self):
        self.assertEqual(new_mssql.cast_text("username"), OLD_DBMS["mssql"].cast_text("username"))

    def test_qualified_table(self):
        self.assertEqual(new_mssql.qualified_table("users"), OLD_DBMS["mssql"].qualified_table("users"))
        self.assertEqual(
            new_mssql.qualified_table("users", "appdb"),
            OLD_DBMS["mssql"].qualified_table("users", "appdb"),
        )

    def test_metadata_matches(self):
        for key in ("banner", "current_user", "current_db"):
            self.assertEqual(new_mssql.METADATA[key], OLD_METADATA["mssql"][key])


class MysqlEquivalenceTests(unittest.TestCase):
    def test_table_expression(self):
        for database in (None, "appdb"):
            for index in (0, 3):
                self.assertEqual(
                    new_mysql.table_expression(index, database),
                    OLD_DBMS["mysql"].table_expression(index, database),
                )

    def test_column_expression(self):
        for database in (None, "appdb"):
            for index in (0, 2):
                self.assertEqual(
                    new_mysql.column_expression("users", index, database),
                    OLD_DBMS["mysql"].column_expression("users", index, database),
                )

    def test_dump_expression(self):
        for database in (None, "appdb"):
            for where in (None, "enabled=1"):
                self.assertEqual(
                    new_mysql.dump_expression("users", ["username", "password"], 0, where, database),
                    OLD_DBMS["mysql"].dump_expression("users", ["username", "password"], 0, where, database),
                )

    def test_dbs_expression(self):
        self.assertEqual(new_mysql.dbs_expression(0), OLD_DBMS["mysql"].dbs_expression(0))
        self.assertEqual(new_mysql.dbs_expression(3), OLD_DBMS["mysql"].dbs_expression(3))

    def test_concat_columns(self):
        self.assertEqual(new_mysql.concat_columns(["username"]), OLD_DBMS["mysql"].concat_columns(["username"]))
        self.assertEqual(
            new_mysql.concat_columns(["username", "password"]),
            OLD_DBMS["mysql"].concat_columns(["username", "password"]),
        )

    def test_cast_text(self):
        self.assertEqual(new_mysql.cast_text("username"), OLD_DBMS["mysql"].cast_text("username"))

    def test_qualified_table(self):
        self.assertEqual(new_mysql.qualified_table("users"), OLD_DBMS["mysql"].qualified_table("users"))
        self.assertEqual(
            new_mysql.qualified_table("users", "appdb"),
            OLD_DBMS["mysql"].qualified_table("users", "appdb"),
        )

    def test_metadata_matches(self):
        for key in ("banner", "current_user", "current_db"):
            self.assertEqual(new_mysql.METADATA[key], OLD_METADATA["mysql"][key])


class PostgresEquivalenceTests(unittest.TestCase):
    def test_table_expression(self):
        for database in (None, "app"):
            for index in (0, 3):
                self.assertEqual(
                    new_postgres.table_expression(index, database),
                    OLD_DBMS["postgres-program"].table_expression(index, database),
                )

    def test_column_expression(self):
        for database in (None, "app"):
            for index in (0, 2):
                self.assertEqual(
                    new_postgres.column_expression("users", index, database),
                    OLD_DBMS["postgres-program"].column_expression("users", index, database),
                )

    def test_dump_expression(self):
        for database in (None, "app"):
            for where in (None, "enabled=1"):
                self.assertEqual(
                    new_postgres.dump_expression("users", ["username", "password"], 0, where, database),
                    OLD_DBMS["postgres-program"].dump_expression("users", ["username", "password"], 0, where, database),
                )

    def test_dbs_expression(self):
        self.assertEqual(new_postgres.dbs_expression(0), OLD_DBMS["postgres-program"].dbs_expression(0))
        self.assertEqual(new_postgres.dbs_expression(3), OLD_DBMS["postgres-program"].dbs_expression(3))

    def test_concat_columns(self):
        self.assertEqual(
            new_postgres.concat_columns(["username"]),
            OLD_DBMS["postgres-program"].concat_columns(["username"]),
        )
        self.assertEqual(
            new_postgres.concat_columns(["username", "password"]),
            OLD_DBMS["postgres-program"].concat_columns(["username", "password"]),
        )

    def test_cast_text(self):
        self.assertEqual(new_postgres.cast_text("username"), OLD_DBMS["postgres-program"].cast_text("username"))

    def test_qualified_table(self):
        self.assertEqual(new_postgres.qualified_table("users"), OLD_DBMS["postgres-program"].qualified_table("users"))
        self.assertEqual(
            new_postgres.qualified_table("users", "app"),
            OLD_DBMS["postgres-program"].qualified_table("users", "app"),
        )

    def test_metadata_matches(self):
        for key in ("banner", "current_user", "current_db"):
            self.assertEqual(new_postgres.METADATA[key], OLD_METADATA["postgres-program"][key])


class OracleEquivalenceTests(unittest.TestCase):
    def test_table_expression(self):
        for database in (None, "hr"):
            for index in (0, 3):
                self.assertEqual(
                    new_oracle.table_expression(index, database),
                    OLD_DBMS["oracle-http"].table_expression(index, database),
                )

    def test_column_expression(self):
        for database in (None, "hr"):
            for index in (0, 2):
                self.assertEqual(
                    new_oracle.column_expression("users", index, database),
                    OLD_DBMS["oracle-http"].column_expression("users", index, database),
                )

    def test_dump_expression(self):
        for database in (None, "hr"):
            for where in (None, "enabled=1"):
                self.assertEqual(
                    new_oracle.dump_expression("users", ["username", "password"], 1, where, database),
                    OLD_DBMS["oracle-http"].dump_expression("users", ["username", "password"], 1, where, database),
                )

    def test_dbs_expression(self):
        self.assertEqual(new_oracle.dbs_expression(0), OLD_DBMS["oracle-http"].dbs_expression(0))
        self.assertEqual(new_oracle.dbs_expression(3), OLD_DBMS["oracle-http"].dbs_expression(3))

    def test_concat_columns(self):
        self.assertEqual(new_oracle.concat_columns(["username"]), OLD_DBMS["oracle-http"].concat_columns(["username"]))
        self.assertEqual(
            new_oracle.concat_columns(["username", "password"]),
            OLD_DBMS["oracle-http"].concat_columns(["username", "password"]),
        )

    def test_cast_text(self):
        self.assertEqual(new_oracle.cast_text("username"), OLD_DBMS["oracle-http"].cast_text("username"))

    def test_qualified_table(self):
        self.assertEqual(new_oracle.qualified_table("users"), OLD_DBMS["oracle-http"].qualified_table("users"))
        self.assertEqual(
            new_oracle.qualified_table("users", "hr"),
            OLD_DBMS["oracle-http"].qualified_table("users", "hr"),
        )

    def test_metadata_matches(self):
        for key in ("banner", "current_user", "current_db"):
            self.assertEqual(new_oracle.METADATA[key], OLD_METADATA["oracle-http"][key])


class SqliteEquivalenceTests(unittest.TestCase):
    def test_table_expression(self):
        self.assertEqual(new_sqlite.table_expression(0), OLD_DBMS["sqlite-http"].table_expression(0))
        self.assertEqual(new_sqlite.table_expression(3), OLD_DBMS["sqlite-http"].table_expression(3))

    def test_column_expression(self):
        self.assertEqual(
            new_sqlite.column_expression("users", 0),
            OLD_DBMS["sqlite-http"].column_expression("users", 0),
        )

    def test_dump_expression(self):
        for where in (None, "enabled=1"):
            self.assertEqual(
                new_sqlite.dump_expression("users", ["username", "password"], 0, where),
                OLD_DBMS["sqlite-http"].dump_expression("users", ["username", "password"], 0, where),
            )

    def test_dbs_expression_raises(self):
        with self.assertRaises(ValueError):
            new_sqlite.dbs_expression(0)
        with self.assertRaises(ValueError):
            OLD_DBMS["sqlite-http"].dbs_expression(0)

    def test_concat_columns(self):
        self.assertEqual(new_sqlite.concat_columns(["username"]), OLD_DBMS["sqlite-http"].concat_columns(["username"]))
        self.assertEqual(
            new_sqlite.concat_columns(["username", "password"]),
            OLD_DBMS["sqlite-http"].concat_columns(["username", "password"]),
        )

    def test_cast_text(self):
        self.assertEqual(new_sqlite.cast_text("username"), OLD_DBMS["sqlite-http"].cast_text("username"))

    def test_qualified_table(self):
        self.assertEqual(new_sqlite.qualified_table("users"), OLD_DBMS["sqlite-http"].qualified_table("users"))
        self.assertEqual(
            new_sqlite.qualified_table("users", "ignored"),
            OLD_DBMS["sqlite-http"].qualified_table("users", "ignored"),
        )

    def test_metadata_matches(self):
        for key in ("banner", "current_user", "current_db"):
            self.assertEqual(new_sqlite.METADATA[key], OLD_METADATA["sqlite-http"][key])
