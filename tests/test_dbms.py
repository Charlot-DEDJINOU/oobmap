import unittest

from oobmap.dbms import DBMS, METADATA, sql_string
from oobmap.payloads import PROFILES


class DbmsExpressionTests(unittest.TestCase):
    def test_sql_string_escapes_quotes(self):
        self.assertEqual(sql_string("user's"), "'user''s'")

    def test_mssql_table_and_column_expressions(self):
        dbms = DBMS["mssql"]
        self.assertIn("INFORMATION_SCHEMA.TABLES", dbms.table_expression(0))
        self.assertIn("rn=1", dbms.table_expression(0))
        expr = dbms.column_expression("users", 2)
        self.assertIn("INFORMATION_SCHEMA.COLUMNS", expr)
        self.assertIn("TABLE_NAME='users'", expr)
        self.assertIn("rn=3", expr)
        dump = dbms.dump_expression("users", ["username", "password"], 0, "enabled=1")
        self.assertIn("CAST(username AS NVARCHAR(MAX)) + '|'", dump)
        self.assertIn("FROM users WHERE enabled=1", dump)
        self.assertIn("rn=1", dump)
        self.assertIn("TABLE_CATALOG='appdb'", dbms.table_expression(0, "appdb"))
        self.assertIn("FROM appdb..users", dbms.dump_expression("users", ["username"], 0, database="appdb"))

    def test_mysql_table_and_column_expressions(self):
        dbms = DBMS["mysql"]
        self.assertIn("information_schema.tables", dbms.table_expression(1))
        self.assertIn("LIMIT 1 OFFSET 1", dbms.table_expression(1))
        self.assertIn("table_name='users'", dbms.column_expression("users", 0))
        dump = dbms.dump_expression("users", ["username", "password"], 2)
        self.assertIn("CONCAT(CAST(username AS CHAR),'|',CAST(password AS CHAR))", dump)
        self.assertIn("LIMIT 1 OFFSET 2", dump)
        self.assertIn("table_schema='appdb'", dbms.table_expression(0, "appdb"))
        self.assertIn("FROM appdb.users", dbms.dump_expression("users", ["username"], 0, database="appdb"))

    def test_postgres_table_and_column_expressions(self):
        dbms = DBMS["postgres-program"]
        self.assertIn("table_schema='public'", dbms.table_expression(0))
        self.assertIn("information_schema.columns", dbms.column_expression("users", 0))
        dump = dbms.dump_expression("users", ["username", "password"], 0)
        self.assertIn("CAST(username AS TEXT) || '|'", dump)
        self.assertIn("table_schema='app'", dbms.table_expression(0, "app"))
        self.assertIn("FROM app.users", dbms.dump_expression("users", ["username"], 0, database="app"))

    def test_oracle_table_and_column_expressions(self):
        dbms = DBMS["oracle-http"]
        self.assertIn("all_tables", dbms.table_expression(0))
        self.assertIn("table_name='USERS'", dbms.column_expression("users", 0))
        dump = dbms.dump_expression("users", ["username", "password"], 1)
        self.assertIn("TO_CHAR(username) || '|'", dump)
        self.assertIn("rn=2", dump)
        self.assertIn("owner='HR'", dbms.table_expression(0, "hr"))
        self.assertIn("FROM hr.users", dbms.dump_expression("users", ["username"], 0, database="hr"))


class NewProfileTests(unittest.TestCase):
    def test_all_new_profiles_exist(self):
        for name in ("postgres-dblink", "mssql-cmdshell", "mysql-stacked", "sqlite-http"):
            self.assertIn(name, PROFILES)

    def test_postgres_dblink_payload_contains_dblink_connect(self):
        p = PROFILES["postgres-dblink"]
        payload = p.payload("base", "1=1", "tok.oast.site")
        self.assertIn("dblink_connect", payload)
        self.assertIn("tok.oast.site", payload)

    def test_mssql_cmdshell_payload_contains_xp_cmdshell(self):
        p = PROFILES["mssql-cmdshell"]
        payload = p.payload("base", "1=1", "tok.oast.site")
        self.assertIn("xp_cmdshell", payload)
        self.assertIn("tok.oast.site", payload)

    def test_mysql_stacked_payload_contains_load_file(self):
        p = PROFILES["mysql-stacked"]
        payload = p.payload("base", "1=1", "tok.oast.site")
        self.assertIn("LOAD_FILE", payload)

    def test_sqlite_http_payload_contains_http_get(self):
        p = PROFILES["sqlite-http"]
        payload = p.payload("base", "1=1", "tok.oast.site")
        self.assertIn("http_get", payload)

    def test_new_profiles_in_dbms_and_metadata(self):
        for name in ("postgres-dblink", "mssql-cmdshell", "mysql-stacked", "sqlite-http"):
            self.assertIn(name, DBMS, f"DBMS missing {name}")
            self.assertIn(name, METADATA, f"METADATA missing {name}")

    def test_postgres_dblink_table_expr_matches_parent(self):
        self.assertEqual(
            DBMS["postgres-dblink"].table_expression(0),
            DBMS["postgres-program"].table_expression(0),
        )

    def test_mssql_cmdshell_table_expr_matches_parent(self):
        self.assertEqual(
            DBMS["mssql-cmdshell"].table_expression(0),
            DBMS["mssql"].table_expression(0),
        )


if __name__ == "__main__":
    unittest.main()
