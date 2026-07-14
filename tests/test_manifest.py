from __future__ import annotations

import re
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG = (PROJECT_ROOT / "adguard_dns_observer" / "config.yaml").read_text(encoding="utf-8")
CHANGELOG = (PROJECT_ROOT / "adguard_dns_observer" / "CHANGELOG.md").read_text(encoding="utf-8")


class ManifestTests(unittest.TestCase):
    def test_manager_role_is_declared_for_cross_app_reads(self) -> None:
        self.assertRegex(CONFIG, r"(?m)^hassio_role:\s+manager$")

    def test_manifest_version_has_matching_changelog_entry(self) -> None:
        match = re.search(r'(?m)^version:\s+"([0-9]+\.[0-9]+\.[0-9]+)"$', CONFIG)
        self.assertIsNotNone(match)
        self.assertIn(f"## {match.group(1)}", CHANGELOG)


if __name__ == "__main__":
    unittest.main()
