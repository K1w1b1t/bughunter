from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from hunterops.session_profiles import auth_header, load_sessions


class SessionTests(unittest.TestCase):
    def test_load_and_env_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "sessions.yaml"
            p.write_text(
                "sessions:\n"
                "  - name: user\n"
                "    token_type: Bearer\n"
                "    token_env: TEST_USER_TOKEN\n",
                encoding="utf-8",
            )
            os.environ["TEST_USER_TOKEN"] = "abc123"
            sessions = load_sessions(p)
            self.assertIn("user", sessions)
            hdr = auth_header(sessions["user"])
            self.assertIn("Authorization", hdr)


if __name__ == "__main__":
    unittest.main()

