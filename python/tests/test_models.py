import base64
import unittest

from nucleisdk.models import EngineConfig, ScanOptions, TargetRequest, TemplateBytesEntry


class TestModels(unittest.TestCase):
    def test_template_bytes_entry_to_dict(self):
        entry = TemplateBytesEntry(name="t1", data=b"abc")
        d = entry.to_dict()
        self.assertEqual(d["name"], "t1")
        self.assertEqual(base64.b64decode(d["data"]), b"abc")

    def test_engine_config_to_dict_omits_defaults(self):
        cfg = EngineConfig(
            template_dirs=["/tmp/templates"],
            rate_limit=100,
            silent=True,
        )
        d = cfg.to_dict()
        self.assertEqual(d["template_dirs"], ["/tmp/templates"])
        self.assertEqual(d["rate_limit"], 100)
        self.assertTrue(d["silent"])
        self.assertNotIn("timeout", d)
        self.assertNotIn("retries", d)

    def test_scan_options_to_dict(self):
        opts = ScanOptions(
            targets=["https://example.com"],
            tags=["cve"],
            template_bytes=[TemplateBytesEntry(name="t1", data=b"id: test")],
        )
        d = opts.to_dict()
        self.assertEqual(d["targets"], ["https://example.com"])
        self.assertEqual(d["tags"], ["cve"])
        self.assertIn("template_bytes", d)
        self.assertEqual(d["template_bytes"][0]["name"], "t1")


    def test_target_request_to_dict(self):
        tr = TargetRequest(
            url="https://example.com/api/users",
            method="POST",
            headers={"Content-Type": "application/json"},
            body='{"name":"test"}',
        )
        d = tr.to_dict()
        self.assertEqual(d["url"], "https://example.com/api/users")
        self.assertEqual(d["method"], "POST")
        self.assertEqual(d["headers"]["Content-Type"], "application/json")
        self.assertEqual(d["body"], '{"name":"test"}')

    def test_target_request_to_dict_minimal(self):
        tr = TargetRequest(url="https://example.com/health", method="GET")
        d = tr.to_dict()
        self.assertEqual(d["url"], "https://example.com/health")
        self.assertEqual(d["method"], "GET")
        self.assertNotIn("headers", d)
        self.assertNotIn("body", d)

    def test_scan_options_with_request_response_targets(self):
        opts = ScanOptions(
            targets=["https://example.com"],
            request_response_targets=[
                TargetRequest(
                    url="https://example.com/api/users",
                    method="POST",
                    headers={"Content-Type": "application/json"},
                    body='{"name":"test"}',
                ),
            ],
        )
        d = opts.to_dict()
        self.assertIn("request_response_targets", d)
        self.assertEqual(len(d["request_response_targets"]), 1)
        rrt = d["request_response_targets"][0]
        self.assertEqual(rrt["method"], "POST")
        self.assertEqual(rrt["url"], "https://example.com/api/users")

    def test_scan_options_omits_empty_request_response_targets(self):
        opts = ScanOptions(targets=["https://example.com"])
        d = opts.to_dict()
        self.assertNotIn("request_response_targets", d)


if __name__ == "__main__":
    unittest.main()
