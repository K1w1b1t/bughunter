from __future__ import annotations

import unittest
from unittest.mock import patch

from hunterops.plugins.auth_compare import PluginImpl as AuthComparePlugin
from hunterops.plugins.fuzz_smart import PluginImpl as FuzzSmartPlugin
from hunterops.plugins.idor_auto import PluginImpl as IDORPlugin
from hunterops.plugins.role_access import PluginImpl as RoleAccessPlugin
from hunterops.types import Task


class PluginIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_fuzz_smart_parses_ffuf_json_object(self) -> None:
        plugin = FuzzSmartPlugin()
        ctx = {
            "config": {"modules": {"fuzz_smart": {"commands": ["ffuf ..."]}}},
            "runtime": {"timeout_seconds": 5, "stealth_mode": False, "proxies": [], "wordlists": {"default": "wordlists/common.txt"}},
        }
        ffuf_json = '{"results":[{"status":200,"length":500,"words":40,"lines":12},{"status":403,"length":520,"words":45,"lines":15}]}'
        with patch("hunterops.plugins.fuzz_smart.run_command", return_value={"rc": 0, "stdout": ffuf_json, "stderr": ""}):
            findings = await plugin.run(Task(plugin="fuzz_smart", target="api.example.com"), ctx)
        self.assertGreaterEqual(len(findings), 1)

    async def test_auth_compare_detects_diff(self) -> None:
        plugin = AuthComparePlugin()
        ctx = {
            "config": {"modules": {"auth_compare": {"sessions_file": "data/sessions.yaml", "paths": ["/api/me"], "evidence_dir": "data/evidence/engine"}}},
            "runtime": {"timeout_seconds": 5},
        }
        fake_sessions = {"user": {"token": "x"}}
        with patch("hunterops.plugins.auth_compare.load_sessions", return_value=fake_sessions), patch(
            "hunterops.plugins.auth_compare.auth_header", return_value={"Authorization": "Bearer x"}
        ), patch(
            "hunterops.plugins.auth_compare.request_http_async",
            side_effect=[
                {"status": 401, "length": 100, "text": '{"error":"unauth"}'},
                {"status": 200, "length": 260, "text": '{"id":1,"email":"a@b.com"}'},
            ],
        ):
            findings = await plugin.run(Task(plugin="auth_compare", target="api.example.com"), ctx)
        self.assertGreaterEqual(len(findings), 1)

    async def test_idor_auto_detects_variant_change(self) -> None:
        plugin = IDORPlugin()
        ctx = {
            "config": {
                "modules": {
                    "idor_auto": {
                        "sessions_file": "data/sessions.yaml",
                        "evidence_dir": "data/evidence/engine",
                        "candidate_urls": ["https://{target}/api/profile?id=1"],
                    }
                }
            },
            "runtime": {"timeout_seconds": 5},
        }
        with patch("hunterops.plugins.idor_auto.load_sessions", return_value={"user": {"token": "x"}}), patch(
            "hunterops.plugins.idor_auto.auth_header", return_value={"Authorization": "Bearer x"}
        ), patch(
            "hunterops.plugins.idor_auto.request_http_async",
            side_effect=[
                {"status": 200, "text": '{"id":1,"name":"a"}', "length": 20},
                {"status": 200, "text": '{"id":2,"name":"b"}', "length": 20},
                {"status": 200, "text": '{"id":0,"name":"c"}', "length": 20},
            ],
        ):
            findings = await plugin.run(Task(plugin="idor_auto", target="api.example.com"), ctx)
        self.assertGreaterEqual(len(findings), 1)

    async def test_role_access_detects_equal_response(self) -> None:
        plugin = RoleAccessPlugin()
        ctx = {
            "config": {"modules": {"role_access": {"sessions_file": "data/sessions.yaml", "evidence_dir": "data/evidence/engine", "paths": ["/admin"]}}},
            "runtime": {"timeout_seconds": 5},
        }
        with patch("hunterops.plugins.role_access.load_sessions", return_value={"user": {"token": "u"}, "admin": {"token": "a"}}), patch(
            "hunterops.plugins.role_access.auth_header", side_effect=[{"Authorization": "Bearer u"}, {"Authorization": "Bearer a"}]
        ), patch(
            "hunterops.plugins.role_access.request_http_async",
            side_effect=[
                {"status": 200, "text": '{"ok":true}', "length": 11},
                {"status": 200, "text": '{"ok":true}', "length": 11},
            ],
        ):
            findings = await plugin.run(Task(plugin="role_access", target="api.example.com"), ctx)
        self.assertGreaterEqual(len(findings), 1)


if __name__ == "__main__":
    unittest.main()
