import unittest

from nucleisdk._installer import _parse_version, check_version_compatible


class TestInstallerVersioning(unittest.TestCase):
    def test_parse_version(self):
        self.assertEqual(_parse_version("1.2.3"), (1, 2, 3))
        self.assertEqual(_parse_version("v2.0.1"), (2, 0, 1))
        self.assertEqual(_parse_version("invalid"), (0, 0, 0))

    def test_check_version_compatible(self):
        self.assertTrue(check_version_compatible("dev"))
        self.assertFalse(check_version_compatible("0.0.0"))
        self.assertFalse(check_version_compatible("0.9.0"))
        self.assertTrue(check_version_compatible("1.0.0"))


if __name__ == "__main__":
    unittest.main()
