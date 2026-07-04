from dataclasses import dataclass

from . import mssql, mysql, oracle, postgres, sqlite
from ._sql import sql_string

_FAMILY_MODULES = {
    "mssql": mssql,
    "mysql": mysql,
    "postgres-program": postgres,
    "oracle-http": oracle,
    "sqlite-http": sqlite,
}

# Variant aliases: which family module a variant profile name delegates to.
_FAMILY_OF = {
    "mssql-cmdshell": "mssql",
    "mysql-stacked": "mysql",
    "postgres-dblink": "postgres-program",
    "oracle-dns": "oracle-http",
}


@dataclass(frozen=True)
class DbmsProfile:
    name: str

    @property
    def _module(self):
        return _FAMILY_MODULES[_FAMILY_OF.get(self.name, self.name)]

    def metadata_expression(self, key: str) -> str | None:
        return METADATA.get(self.name, {}).get(key)

    def table_expression(self, index: int, database: str | None = None) -> str:
        return self._module.table_expression(index, database)

    def column_expression(self, table: str, index: int, database: str | None = None) -> str:
        return self._module.column_expression(table, index, database)

    def dump_expression(
        self,
        table: str,
        columns: list[str],
        index: int,
        where: str | None = None,
        database: str | None = None,
    ) -> str:
        return self._module.dump_expression(table, columns, index, where, database)

    def dbs_expression(self, index: int) -> str:
        return self._module.dbs_expression(index)

    def concat_columns(self, columns: list[str]) -> str:
        return self._module.concat_columns(columns)

    def cast_text(self, expression: str) -> str:
        return self._module.cast_text(expression)

    def qualified_table(self, table: str, database: str | None = None) -> str:
        return self._module.qualified_table(table, database)


METADATA = {name: dict(module.METADATA) for name, module in _FAMILY_MODULES.items()}

METADATA["postgres-dblink"] = METADATA["postgres-program"]
METADATA["mssql-cmdshell"] = METADATA["mssql"]
METADATA["mysql-stacked"] = METADATA["mysql"]
METADATA["oracle-dns"] = METADATA["oracle-http"]

DBMS = {name: DbmsProfile(name) for name in METADATA}
