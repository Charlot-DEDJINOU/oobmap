import tempfile
import unittest

from oobmap.session import SessionStore, fingerprint, target_id
from oobmap.transport import RawRequest


def _request(host="example.test", target="/path", method="GET"):
    return RawRequest(
        method=method,
        target=target,
        version="HTTP/1.1",
        headers=[("Host", host)],
        body=b"",
    )


class TargetIdTests(unittest.TestCase):
    def test_same_request_same_id(self):
        req = _request()
        self.assertEqual(target_id(req, False), target_id(req, False))

    def test_different_host_different_id(self):
        a = target_id(_request(host="a.test"), False)
        b = target_id(_request(host="b.test"), False)
        self.assertNotEqual(a, b)

    def test_force_ssl_changes_id(self):
        req = _request()
        self.assertNotEqual(target_id(req, False), target_id(req, True))

    def test_absolute_target_uses_url_host(self):
        absolute = _request(target="http://other.test/path")
        origin_form = _request(host="other.test", target="/path")
        self.assertEqual(target_id(absolute, False), target_id(origin_form, False))


class FingerprintTests(unittest.TestCase):
    def test_deterministic(self):
        self.assertEqual(fingerprint("a", "b"), fingerprint("a", "b"))

    def test_different_inputs_differ(self):
        self.assertNotEqual(fingerprint("a", "b"), fingerprint("a", "c"))


class SessionStoreTests(unittest.TestCase):
    def _store(self, tmpdir, flush=False):
        return SessionStore(tmpdir, _request(), False, flush=flush)

    def test_extraction_round_trip_incomplete(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = self._store(tmpdir)
            eid = session.extraction_id("mysql", "cookie", "id", "expr", "0123456789")
            session.save_extraction(eid, "mysql", "cookie", "id", "expr", "0123456789", "12", False)
            cached = session.get_extraction(eid)
            session.close()
        self.assertEqual(cached["value"], "12")
        self.assertEqual(cached["completed"], 0)

    def test_extraction_round_trip_completed(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = self._store(tmpdir)
            eid = session.extraction_id("mysql", "cookie", "id", "expr", "0123456789")
            session.save_extraction(eid, "mysql", "cookie", "id", "expr", "0123456789", "123", True)
            cached = session.get_extraction(eid)
            session.close()
        self.assertEqual(cached["value"], "123")
        self.assertEqual(cached["completed"], 1)

    def test_get_extraction_missing_returns_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = self._store(tmpdir)
            result = session.get_extraction("does-not-exist")
            session.close()
        self.assertIsNone(result)

    def test_check_round_trip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = self._store(tmpdir)
            cid = session.check_id("mysql", "cookie", "id")
            session.save_check(cid, "mysql", "cookie", "id", "confirmed")
            cached = session.get_check(cid)
            session.close()
        self.assertEqual(cached["status"], "confirmed")

    def test_get_check_missing_returns_none(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = self._store(tmpdir)
            result = session.get_check("does-not-exist")
            session.close()
        self.assertIsNone(result)

    def test_catalog_round_trip_without_table(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = self._store(tmpdir)
            session.save_catalog("mysql", "mydb", "tables", ["users", "orders"])
            cached = session.get_catalog("mysql", "mydb", "tables")
            session.close()
        self.assertEqual(cached, ["users", "orders"])

    def test_catalog_round_trip_with_table(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = self._store(tmpdir)
            session.save_catalog("mysql", "mydb", "columns", ["id", "name"], table="users")
            cached_users = session.get_catalog("mysql", "mydb", "columns", table="users")
            cached_other = session.get_catalog("mysql", "mydb", "columns", table="orders")
            session.close()
        self.assertEqual(cached_users, ["id", "name"])
        self.assertIsNone(cached_other)

    def test_flush_removes_existing_session(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            session = self._store(tmpdir)
            eid = session.extraction_id("mysql", "cookie", "id", "expr", "0123456789")
            session.save_extraction(eid, "mysql", "cookie", "id", "expr", "0123456789", "12", False)
            session.close()

            flushed = self._store(tmpdir, flush=True)
            result = flushed.get_extraction(eid)
            flushed.close()
        self.assertIsNone(result)
