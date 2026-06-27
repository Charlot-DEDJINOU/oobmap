import unittest

from oobmap.dbms import DBMS, sql_string


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

    def test_mysql_table_and_column_expressions(self):
        dbms = DBMS["mysql"]
        self.assertIn("information_schema.tables", dbms.table_expression(1))
        self.assertIn("LIMIT 1 OFFSET 1", dbms.table_expression(1))
        self.assertIn("table_name='users'", dbms.column_expression("users", 0))

    def test_postgres_table_and_column_expressions(self):
        dbms = DBMS["postgres-program"]
        self.assertIn("table_schema='public'", dbms.table_expression(0))
        self.assertIn("information_schema.columns", dbms.column_expression("users", 0))

    def test_oracle_table_and_column_expressions(self):
        dbms = DBMS["oracle-http"]
        self.assertIn("all_tables", dbms.table_expression(0))
        self.assertIn("table_name='USERS'", dbms.column_expression("users", 0))


if __name__ == "__main__":
    unittest.main()
