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


if __name__ == "__main__":
    unittest.main()
