import tempfile
import unittest
from pathlib import Path

from oobmap.oob import InteractshLog
from oobmap.cli import split_dump_row
from oobmap.requester import current_value, inject, injection_points, parse_raw_request
from oobmap.session import SessionStore


class RequesterTests(unittest.TestCase):
    def write_request(self, text):
        tmp = tempfile.NamedTemporaryFile("w", delete=False)
        tmp.write(text)
        tmp.close()
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        return tmp.name

    def test_cookie_value_and_injection(self):
        path = self.write_request(
            "GET / HTTP/1.1\n"
            "Host: example.test\n"
            "Cookie: TrackingId=guest; session=demo\n"
            "\n"
        )
        req = parse_raw_request(path)
        self.assertEqual(current_value(req, "TrackingId"), "guest")
        updated = inject(req, "TrackingId", "guest' AND 1=1--")
        cookie = updated.header_value("Cookie")
        self.assertIn("TrackingId=guest%27+AND+1%3D1--", cookie)
        self.assertIn("session=demo", cookie)

    def test_query_injection(self):
        path = self.write_request(
            "GET /search?q=test HTTP/1.1\n"
            "Host: example.test\n"
            "\n"
        )
        req = parse_raw_request(path)
        self.assertEqual(current_value(req, "q"), "test")
        updated = inject(req, "q", "abc'--", "query")
        self.assertIn("q=abc%27--", updated.target)

    def test_level_based_injection_points(self):
        path = self.write_request(
            "POST /search?q=test HTTP/1.1\n"
            "Host: example.test\n"
            "Cookie: TrackingId=guest; session=demo\n"
            "User-Agent: unit-test\n"
            "Content-Type: application/x-www-form-urlencoded\n"
            "\n"
            "name=alice"
        )
        req = parse_raw_request(path)

        level1 = injection_points(req, 1)
        self.assertEqual({(p.place, p.name) for p in level1}, {("query", "q"), ("body", "name")})

        level2 = injection_points(req, 2)
        self.assertIn(("cookie", "TrackingId"), {(p.place, p.name) for p in level2})

        level3 = injection_points(req, 3)
        self.assertIn(("header", "User-Agent"), {(p.place, p.name) for p in level3})


class InteractshLogTests(unittest.TestCase):
    def test_find_token_in_jsonl(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
            tmp.write('{"protocol":"dns","full-id":"run-p01-c73.example"}\n')
            name = tmp.name
        self.addCleanup(lambda: Path(name).unlink(missing_ok=True))

        log = InteractshLog(name)
        log.offset = 0
        token = log.find_any({"run-p01-c73": "s", "run-p01-c61": "a"})
        self.assertEqual(token, "run-p01-c73")


class SessionTests(unittest.TestCase):
    def test_extraction_resume_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            req_path = Path(tmpdir) / "req.txt"
            req_path.write_text(
                "GET / HTTP/1.1\n"
                "Host: example.test\n"
                "Cookie: TrackingId=guest\n"
                "\n"
            )
            req = parse_raw_request(str(req_path))
            session = SessionStore(tmpdir, req, False)
            extraction_id = session.extraction_id("mssql", "cookie", "TrackingId", "SELECT password", "abc")
            session.save_extraction(
                extraction_id,
                "mssql",
                "cookie",
                "TrackingId",
                "SELECT password",
                "abc",
                "secr",
                False,
            )
            saved = session.get_extraction(extraction_id)
            self.assertEqual(saved["value"], "secr")
            self.assertEqual(saved["completed"], 0)
            self.assertTrue(session.path.exists())
            session.close()

    def test_flush_session_removes_previous_state(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            req_path = Path(tmpdir) / "req.txt"
            req_path.write_text("GET / HTTP/1.1\nHost: example.test\n\n")
            req = parse_raw_request(str(req_path))
            first = SessionStore(tmpdir, req, False)
            first.set_kv("test", "key", {"value": 1})
            first.close()

            second = SessionStore(tmpdir, req, False, flush=True)
            self.assertIsNone(second.get_kv("test", "key"))
            second.close()


class DumpFormattingTests(unittest.TestCase):
    def test_split_dump_row_preserves_separator_in_last_column(self):
        self.assertEqual(
            split_dump_row("admin|sec|ret", 2),
            ["admin", "sec|ret"],
        )

    def test_split_dump_row_pads_missing_columns(self):
        self.assertEqual(split_dump_row("admin", 2), ["admin", ""])


class JsonBodyTests(unittest.TestCase):
    def _make_json_req(self, body_dict):
        import json as _json, tempfile
        body = _json.dumps(body_dict).encode()
        raw = (
            b"POST /api/search HTTP/1.1\r\n"
            b"Host: target.test\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n" + body
        )
        tmp = tempfile.NamedTemporaryFile("wb", delete=False, suffix=".txt")
        tmp.write(raw)
        tmp.close()
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        return tmp.name

    def test_json_current_value_top_level(self):
        path = self._make_json_req({"query": "test"})
        req = parse_raw_request(path)
        self.assertEqual(current_value(req, "query", "json"), "test")

    def test_json_current_value_nested(self):
        path = self._make_json_req({"user": {"name": "alice"}})
        req = parse_raw_request(path)
        self.assertEqual(current_value(req, "user.name", "json"), "alice")

    def test_json_current_value_array(self):
        path = self._make_json_req({"items": [{"id": "abc"}]})
        req = parse_raw_request(path)
        self.assertEqual(current_value(req, "items[0].id", "json"), "abc")

    def test_json_inject_top_level(self):
        path = self._make_json_req({"query": "test"})
        req = parse_raw_request(path)
        updated = inject(req, "query", "x' AND 1=1--", "json")
        import json as _json
        body = _json.loads(updated.body.decode())
        self.assertEqual(body["query"], "x' AND 1=1--")

    def test_json_inject_preserves_sibling_keys(self):
        path = self._make_json_req({"query": "test", "limit": 10})
        req = parse_raw_request(path)
        updated = inject(req, "query", "x", "json")
        import json as _json
        self.assertEqual(_json.loads(updated.body.decode())["limit"], 10)

    def test_json_inject_updates_content_length(self):
        path = self._make_json_req({"q": "x"})
        req = parse_raw_request(path)
        updated = inject(req, "q", "much longer payload value here", "json")
        self.assertEqual(int(updated.header_value("Content-Length")), len(updated.body))

    def test_json_injection_points_level1(self):
        path = self._make_json_req({"query": "test", "filter": "all"})
        req = parse_raw_request(path)
        points = injection_points(req, level=1)
        names = {(p.place, p.name) for p in points}
        self.assertIn(("json", "query"), names)
        self.assertIn(("json", "filter"), names)

    def test_json_place_not_found_raises(self):
        path = self._make_json_req({"query": "test"})
        req = parse_raw_request(path)
        with self.assertRaises(ValueError):
            inject(req, "nonexistent", "x", "json")


from oobmap.cli import format_json, format_csv


class OutputFormatTests(unittest.TestCase):
    def setUp(self):
        self.columns = ["username", "password"]
        self.rows = [["admin", "s3cr3t"], ["alice", "p4ss"]]

    def test_format_json_structure(self):
        import json
        data = json.loads(format_json(self.columns, self.rows))
        self.assertEqual(len(data), 2)
        self.assertEqual(data[0]["username"], "admin")
        self.assertEqual(data[0]["password"], "s3cr3t")

    def test_format_json_all_rows(self):
        import json
        data = json.loads(format_json(self.columns, self.rows))
        self.assertEqual(data[1]["username"], "alice")
        self.assertEqual(data[1]["password"], "p4ss")

    def test_format_csv_header(self):
        lines = format_csv(self.columns, self.rows).strip().splitlines()
        self.assertEqual(lines[0], "username,password")

    def test_format_csv_row_count(self):
        lines = format_csv(self.columns, self.rows).strip().splitlines()
        self.assertEqual(len(lines), 3)

    def test_format_csv_pipe_in_value_preserved(self):
        rows = [["admin", "pass|word"]]
        self.assertIn("pass|word", format_csv(["username", "password"], rows))


from oobmap.payloads import PROFILES


class BinaryStrategyTests(unittest.TestCase):
    def test_condition_gte_mssql(self):
        cond = PROFILES["mssql"].condition_gte("SELECT password FROM users", 1, "m")
        self.assertIn(">=", cond)
        self.assertIn("'m'", cond)
        self.assertIn("SUBSTRING", cond)

    def test_condition_gte_mysql(self):
        cond = PROFILES["mysql"].condition_gte("SELECT USER()", 1, "a")
        self.assertIn(">=", cond)
        self.assertIn("substr", cond.lower())

    def test_condition_gte_all_profiles(self):
        for name, profile in PROFILES.items():
            cond = profile.condition_gte("SELECT 1", 1, "x")
            self.assertIn(">=", cond, f"profile {name} missing >= in condition_gte")


if __name__ == "__main__":
    unittest.main()
