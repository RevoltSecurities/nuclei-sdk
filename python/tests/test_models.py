import base64
import unittest

from nucleisdk.models import EngineConfig, ScanOptions, TemplateBytesEntry


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


if __name__ == "__main__":
    unittest.main()
