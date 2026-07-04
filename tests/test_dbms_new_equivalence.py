import unittest

from oobmap.dbms import DBMS as OLD_DBMS
from oobmap.dbms import METADATA as OLD_METADATA
from oobmap._dbms_new import mssql as new_mssql
from oobmap._dbms_new import mysql as new_mysql


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
