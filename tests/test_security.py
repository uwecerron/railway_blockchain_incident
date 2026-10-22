"""The key must never escape: not in repr, URLs, errors, cache files or outputs."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import requests

from railway_trace.client import ApiError, GoldRushClient, ResponseCache
from railway_trace.config import ENV_VAR, MissingKeyError, Secret, load_api_key
from railway_trace.secrets_scan import scan

FAKE = "cqt_" + "Z9" * 12  # built at runtime so this file never contains a key-shaped literal


class FakeResp:
    def __init__(self, status, body=None, text="", headers=None):
        self.status_code, self._body, self.text, self.headers = status, body, text, headers or {}

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class FakeSession:
    def __init__(self, responses):
        self.responses, self.calls = list(responses), []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append({"url": url, "params": params, "headers": headers})
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


class SecretTests(unittest.TestCase):
    def test_masked_everywhere(self):
        s = Secret(FAKE)
        for rendered in (str(s), repr(s), f"{s}", "%s" % s, str([s]), str({"k": s})):
            self.assertNotIn(FAKE, rendered)
        self.assertEqual(s.reveal(), FAKE)

    def test_immutable_and_unpicklable(self):
        import pickle
        s = Secret(FAKE)
        with self.assertRaises(AttributeError):
            s._value = "x"
        with self.assertRaises(TypeError):
            pickle.dumps(s)

    def test_redact(self):
        self.assertEqual(Secret(FAKE).redact(f"bad key {FAKE}!"), "bad key ****!")

    def test_load_from_dotenv_and_env(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {}, clear=True):
            Path(d, ".env").write_text(f'# comment\nexport {ENV_VAR}="{FAKE}"\n')
            self.assertEqual(load_api_key([Path(d)]).reveal(), FAKE)
        with mock.patch.dict(os.environ, {ENV_VAR: FAKE}):
            self.assertEqual(load_api_key([Path("/nonexistent")]).reveal(), FAKE)

    def test_missing_key_message_has_no_value(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(MissingKeyError):
                load_api_key([Path(d)])


class ClientTests(unittest.TestCase):
    def make(self, responses, cache=None):
        sess = FakeSession(responses)
        return GoldRushClient(Secret(FAKE), cache=cache, session=sess, sleep=lambda s: None), sess

    def test_key_only_in_auth_header(self):
        c, sess = self.make([FakeResp(200, {"data": {"items": []}})])
        c.get("/v1/x/", {"a": 1})
        call = sess.calls[0]
        self.assertNotIn(FAKE, call["url"])
        self.assertNotIn(FAKE, str(call["params"]))
        self.assertEqual(call["headers"]["Authorization"], f"Bearer {FAKE}")
        self.assertNotIn(FAKE, repr(c))

    def test_rejects_plain_string_key(self):
        with self.assertRaises(TypeError):
            GoldRushClient(FAKE)

    def test_retries_then_succeeds(self):
        c, sess = self.make([FakeResp(429, text="slow down"), FakeResp(504, text="<!DOCTYPE html>"),
                             FakeResp(200, {"data": {"ok": True}})])
        self.assertEqual(c.get("/v1/x/"), {"ok": True})
        self.assertEqual(len(sess.calls), 3)

    def test_error_bodies_are_redacted(self):
        c, _ = self.make([FakeResp(401, text=f"invalid key {FAKE}")])
        with self.assertRaises(ApiError) as ctx:
            c.get("/v1/x/")
        self.assertNotIn(FAKE, str(ctx.exception))
        self.assertIn("****", str(ctx.exception))

    def test_network_exception_redacted(self):
        boom = requests.ConnectionError(f"failed with header Bearer {FAKE}")
        c, _ = self.make([boom] * 6)
        with self.assertRaises(ApiError) as ctx:
            c.get("/v1/x/")
        self.assertNotIn(FAKE, str(ctx.exception))

    def test_envelope_error(self):
        c, _ = self.make([FakeResp(200, {"error": True, "error_message": "Chain not supported", "error_code": 501})])
        with self.assertRaises(ApiError) as ctx:
            c.get("/v1/x/")
        self.assertEqual(ctx.exception.status, 501)

    def test_cache_never_stores_key(self):
        with tempfile.TemporaryDirectory() as d:
            cache = ResponseCache(Path(d))
            c, sess = self.make([FakeResp(200, {"data": {"v": 1}})], cache=cache)
            self.assertEqual(c.get("/v1/x/"), {"v": 1})
            self.assertEqual(c.get("/v1/x/"), {"v": 1})  # served from cache
            self.assertEqual(len(sess.calls), 1)
            self.assertEqual(scan(Path(d), FAKE), [])


class ScanTests(unittest.TestCase):
    def test_scan_finds_leaks_but_ignores_dotenv(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d, ".env").write_text(f"{ENV_VAR}={FAKE}")
            self.assertEqual(scan(Path(d)), [])
            Path(d, "notes.md").write_text(f"oops {FAKE}")
            self.assertEqual(scan(Path(d)), ["notes.md"])

    def test_repository_is_clean(self):
        root = Path(__file__).resolve().parent.parent
        self.assertEqual(scan(root), [], "a key-shaped string is committed somewhere")


if __name__ == "__main__":
    unittest.main()
