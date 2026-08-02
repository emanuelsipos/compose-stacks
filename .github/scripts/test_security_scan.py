#!/usr/bin/env python3

import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("security_scan.py")
SPEC = importlib.util.spec_from_file_location("security_scan", SCRIPT)
security_scan = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(security_scan)


class SecurityScanTests(unittest.TestCase):
    def test_image_matrix_is_stable_and_deduplicated(self):
        matrix = security_scan.image_matrix(["example/a:1", "example/a:1", "example/b:2"])
        images = " ".join(item["images"] for item in matrix["include"]).split()
        self.assertEqual(sorted(images), ["example/a:1", "example/b:2"])
        self.assertTrue(all(len(item["id"]) == 2 for item in matrix["include"]))

    def test_combine_sarif_preserves_every_run(self):
        combined = security_scan.combine_sarif(
            [
                {"$schema": "schema", "runs": [{"id": "first"}]},
                {"$schema": "schema", "runs": [{"id": "second"}]},
            ]
        )
        self.assertEqual(combined["$schema"], "schema")
        self.assertEqual(combined["runs"], [{"id": "first"}, {"id": "second"}])

    def test_combine_sarif_rejects_empty_input(self):
        with self.assertRaises(ValueError):
            security_scan.combine_sarif([])


if __name__ == "__main__":
    unittest.main()
