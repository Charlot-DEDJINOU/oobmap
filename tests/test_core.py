import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from oobmap.oob import InteractshLog
from oobmap.core.actions import run_check, check
from oobmap.core.dispatch import expand_payloads, strip_payload_terminator
from oobmap.core.formatting import split_dump_row
from oobmap.cli.parser import make_parser
from oobmap.cli.app import _validate_action_flags
from oobmap.transport import RawRequest, current_value, inject, injection_points, parse_raw_request
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

    def test_inject_header_repeated_targets_first_occurrence_only(self):
        req = RawRequest(
            method="GET",
            target="/",
            version="HTTP/1.1",
            headers=[
                ("Host", "example.com"),
                ("X-Forwarded-For", "1.1.1.1"),
                ("X-Forwarded-For", "2.2.2.2"),
            ],
            body=b"",
        )
        injected = inject(req, "X-Forwarded-For", "PAYLOAD", "header")
        xff_values = [v for n, v in injected.headers if n.lower() == "x-forwarded-for"]
        self.assertEqual(xff_values, ["PAYLOAD", "2.2.2.2"])


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


from oobmap.core.formatting import format_json, format_csv


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

    def test_mssql_has_multiple_oob_variants(self):
        payloads = PROFILES["mssql"].payloads("trk", "1=1", "abc.oast.test")
        joined = "\n".join(payloads)
        self.assertGreaterEqual(len(payloads), 6)
        self.assertIn("xp_dirtree", joined)
        self.assertIn("xp_fileexist", joined)
        self.assertIn("xp_subdirs", joined)

    def test_mssql_default_variants_do_not_assume_business_columns(self):
        payloads = PROFILES["mssql"].payloads("trk", "1=1", "abc.oast.test")
        self.assertNotIn("is_admin", "\n".join(payloads))

    def test_strip_payload_terminator(self):
        self.assertEqual(strip_payload_terminator("abc-- -"), "abc")
        self.assertEqual(strip_payload_terminator("abc/*"), "abc")

    def test_custom_payload_suffix_is_explicit(self):
        class Args:
            payload_suffix = ["; SELECT 1 WHERE 'x'='x"]

        expanded = expand_payloads(Args(), ["abc-- -"])
        self.assertIn("abc; SELECT 1 WHERE 'x'='x", expanded)

    def test_direct_payloads_default_to_list(self):
        payloads = PROFILES["sqlite-http"].direct_payloads(
            "guest", "SELECT password FROM users", "run-d", "oast.test"
        )
        self.assertIsInstance(payloads, list)
        self.assertTrue(payloads)


import inspect
from oobmap.transport import send


class ProxySupportTests(unittest.TestCase):
    def test_send_has_proxy_param(self):
        self.assertIn("proxy", inspect.signature(send).parameters)

    def test_send_proxy_default_is_none(self):
        self.assertIsNone(inspect.signature(send).parameters["proxy"].default)

    def test_send_has_verify_ssl_param(self):
        self.assertIn("verify_ssl", inspect.signature(send).parameters)

    def test_send_verify_ssl_default_is_true(self):
        self.assertTrue(inspect.signature(send).parameters["verify_ssl"].default)


from oobmap.oob import InteractshLog, MultiInteractshLog


class MultiLogTests(unittest.TestCase):
    def _write_jsonl(self, content):
        import tempfile
        tmp = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False)
        tmp.write(content)
        tmp.close()
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        return tmp.name

    def test_find_token_in_first_log(self):
        p1 = self._write_jsonl('{"full-id":"tok-aaa.example"}\n')
        p2 = self._write_jsonl("")
        log = MultiInteractshLog([p1, p2])
        log._logs[0].offset = 0
        self.assertEqual(log.find_any({"tok-aaa": "a"}), "tok-aaa")

    def test_find_token_in_second_log(self):
        p1 = self._write_jsonl("")
        p2 = self._write_jsonl('{"full-id":"tok-bbb.example"}\n')
        log = MultiInteractshLog([p1, p2])
        log._logs[1].offset = 0
        self.assertEqual(log.find_any({"tok-bbb": "b"}), "tok-bbb")

    def test_find_returns_none_when_no_match(self):
        log = MultiInteractshLog([self._write_jsonl(""), self._write_jsonl("")])
        self.assertIsNone(log.find_any({"missing": "x"}))

    def test_single_log_path_works(self):
        p = self._write_jsonl('{"full-id":"solo-tok.example"}\n')
        log = MultiInteractshLog([p])
        log._logs[0].offset = 0
        self.assertEqual(log.find_any({"solo-tok": "s"}), "solo-tok")


import threading


class ThreadSafeLogTests(unittest.TestCase):
    def _empty_log(self):
        import tempfile
        tmp = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False)
        tmp.close()
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        return tmp.name

    def test_interactsh_log_has_lock(self):
        log = InteractshLog(self._empty_log())
        self.assertTrue(hasattr(log, "_lock"))
        self.assertIsInstance(log._lock, type(threading.Lock()))

    def test_concurrent_find_any_does_not_crash(self):
        import tempfile
        tmp = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False)
        tmp.write('{"full-id":"tok-con.example"}\n' * 200)
        tmp.close()
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        log = InteractshLog(tmp.name)
        log.offset = 0
        errors = []
        def task():
            try:
                log.find_any({"tok-con": "x"})
            except Exception as exc:
                errors.append(exc)
        threads = [threading.Thread(target=task) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])


class CheckFlagTests(unittest.TestCase):
    class Args:
        def __init__(self, check=False, expr=None):
            self.check = check
            self.expr = expr

    def test_check_flag_defaults_false(self):
        args = make_parser().parse_args([])
        self.assertFalse(args.check)

    def test_check_flag_parses_true(self):
        args = make_parser().parse_args(["--check"])
        self.assertTrue(args.check)

    def test_check_alone_does_not_raise(self):
        _validate_action_flags(self.Args(check=True), is_enum=False)

    def test_no_check_does_not_raise(self):
        _validate_action_flags(self.Args(check=False), is_enum=False)

    def test_check_with_expr_raises(self):
        with self.assertRaises(SystemExit):
            _validate_action_flags(self.Args(check=True, expr="SELECT 1"), is_enum=False)

    def test_check_with_enum_flag_raises(self):
        with self.assertRaises(SystemExit):
            _validate_action_flags(self.Args(check=True), is_enum=True)


class RiskLevelTests(unittest.TestCase):
    RISK_PROFILES = ("mssql", "mysql", "postgres-program")

    def test_risk_1_returns_single_variant(self):
        for name in self.RISK_PROFILES:
            payloads = PROFILES[name].payloads("trk", "1=1", "abc.oast.test", risk=1)
            self.assertEqual(len(payloads), 1, f"profile {name} risk=1 should return one variant")
            self.assertEqual(payloads[0], PROFILES[name].payload("trk", "1=1", "abc.oast.test"))

    def test_risk_2_matches_default_and_todays_output(self):
        for name in self.RISK_PROFILES:
            profile = PROFILES[name]
            default = profile.payloads("trk", "1=1", "abc.oast.test")
            explicit = profile.payloads("trk", "1=1", "abc.oast.test", risk=2)
            self.assertEqual(default, explicit)

    def test_risk_3_is_strict_superset(self):
        for name in self.RISK_PROFILES:
            profile = PROFILES[name]
            base = profile.payloads("trk", "1=1", "abc.oast.test", risk=2)
            aggressive = profile.payloads("trk", "1=1", "abc.oast.test", risk=3)
            self.assertTrue(set(base).issubset(set(aggressive)), f"profile {name} lost variants at risk=3")
            self.assertGreater(len(aggressive), len(base), f"profile {name} risk=3 did not add variants")

    def test_direct_payloads_risk_1_returns_single_variant(self):
        profile = PROFILES["mssql"]
        expr = "SELECT password FROM users"
        base = profile.direct_payloads("trk", expr, "run-d", "oast.test")
        minimal = profile.direct_payloads("trk", expr, "run-d", "oast.test", risk=1)
        self.assertEqual(len(minimal), 1)
        self.assertEqual(minimal[0], base[0])

    def test_direct_payloads_risk_3_is_strict_superset(self):
        profile = PROFILES["mssql"]
        expr = "SELECT password FROM users"
        base = profile.direct_payloads("trk", expr, "run-d", "oast.test")
        aggressive = profile.direct_payloads("trk", expr, "run-d", "oast.test", risk=3)
        self.assertTrue(set(base).issubset(set(aggressive)))
        self.assertGreater(len(aggressive), len(base))

    def test_risk_3_never_changes_profile_semantics(self):
        # Guard against risk creeping into cross-profile/stacked-query behavior.
        for name in self.RISK_PROFILES:
            aggressive = PROFILES[name].payloads("trk", "1=1", "abc.oast.test", risk=3)
            joined = "\n".join(aggressive)
            self.assertNotIn("xp_cmdshell", joined)
            self.assertNotIn("dblink_connect", joined)


class PackagingSmokeTest(unittest.TestCase):
    def test_cli_help_runs_via_module_entrypoint(self):
        result = subprocess.run(
            [sys.executable, "-m", "oobmap.cli", "--help"],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("--check", result.stdout)
        self.assertIn("--risk", result.stdout)

    def test_cli_entry_point_main_is_importable(self):
        from oobmap.cli import main
        self.assertTrue(callable(main))


class ActionableDiagnosticsTests(unittest.TestCase):
    class Args:
        def __init__(self, **kw):
            self.base = kw.get("base", "guest")
            self.true_condition = kw.get("true_condition", "1=1")
            self.false_condition = kw.get("false_condition", "1=2")
            self.timeout = kw.get("timeout", 0.05)
            self.param = kw.get("param", "TrackingId")
            self.place = kw.get("place", "cookie")
            self.log = kw.get("log", [])
            self.domain = kw.get("domain", "oast.test")
            self.dbms = kw.get("dbms", "sqlite-http")
            self.verbose = False
            self.force_ssl = False
            self.http_timeout = 1.0
            self.tamper = ""
            self.payload_suffix = None

    def _write_jsonl(self, content):
        tmp = tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False)
        tmp.write(content)
        tmp.close()
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        return tmp.name

    def _write_request(self, text):
        tmp = tempfile.NamedTemporaryFile("w", delete=False)
        tmp.write(text)
        tmp.close()
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        return tmp.name

    def test_run_check_no_signal_suggests_next_steps(self):
        log_path = self._write_jsonl("")
        log = InteractshLog(log_path)
        req_path = self._write_request(
            "GET / HTTP/1.1\nHost: example.test\nCookie: TrackingId=guest\n\n"
        )
        request = parse_raw_request(req_path)
        args = self.Args(log=[log_path])
        profile = PROFILES["sqlite-http"]

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run_check(args, profile, request, "oast.test", log, "testrun1")

        self.assertEqual(rc, 1)
        output = buf.getvalue()
        self.assertIn("No reliable conditional OOB behavior detected", output)
        self.assertIn("Try a different --place/-p injection point", output)

    def test_run_check_both_probes_suggests_next_steps(self):
        log_path = self._write_jsonl(
            '{"full-id":"testrun2-true.oast.test"}\n'
            '{"full-id":"testrun2-false.oast.test"}\n'
        )
        log = InteractshLog(log_path)
        log.offset = 0
        req_path = self._write_request(
            "GET / HTTP/1.1\nHost: example.test\nCookie: TrackingId=guest\n\n"
        )
        request = parse_raw_request(req_path)
        args = self.Args(log=[log_path])
        profile = PROFILES["sqlite-http"]

        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = run_check(args, profile, request, "oast.test", log, "testrun2")

        self.assertEqual(rc, 2)
        output = buf.getvalue()
        self.assertIn("Both probes triggered", output)
        self.assertIn("Try adjusting --true-condition/--false-condition", output)

    def test_check_scan_mode_no_points_suggests_higher_level(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            req_path = Path(tmpdir) / "req.txt"
            req_path.write_text("GET / HTTP/1.1\nHost: example.test\n\n")
            log_path = self._write_jsonl("")
            args = self.Args(log=[log_path], param=None)
            args.request = str(req_path)
            args.output_dir = tmpdir
            args.flush_session = False
            args.level = 1

            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = check(args)

            self.assertEqual(rc, 1)
            output = buf.getvalue()
            self.assertIn("No injection points found at this level", output)
            self.assertIn("Try a higher --level", output)


if __name__ == "__main__":
    unittest.main()
