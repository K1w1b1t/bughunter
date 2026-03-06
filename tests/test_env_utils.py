from __future__ import annotations

from unittest import TestCase
from unittest.mock import patch

from hunterops.env_utils import evaluate_runtime_dependencies, filter_enabled_plugins


class EnvUtilsTests(TestCase):
    def test_dependency_eval_disables_missing_command_plugins(self) -> None:
        cfg = {
            "modules": {
                "scan": {"commands": ["nuclei -u https://example.com"]},
                "report_builder": {},
            }
        }

        def fake_which(tool: str) -> str | None:
            if tool == "nuclei":
                return None
            if tool in {"interactsh-client", "subfinder", "naabu"}:
                return f"/usr/bin/{tool}"
            return f"/usr/bin/{tool}"

        with patch("hunterops.env_utils.shutil.which", side_effect=fake_which):
            report = evaluate_runtime_dependencies(cfg, ["scan", "report_builder"])

        self.assertIn("scan", report["disabled_plugins"])
        self.assertNotIn("report_builder", report["disabled_plugins"])
        self.assertIn("nuclei", report["required_missing"])

        enabled = filter_enabled_plugins(["scan", "report_builder"], report["disabled_plugins"])
        self.assertEqual(enabled, ["report_builder"])
