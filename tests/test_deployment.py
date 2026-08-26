"""Checked-in deployment contracts for the public Render portfolio service."""

from __future__ import annotations

from pathlib import Path
import re
import unittest


_PROJECT_ROOT = Path(__file__).resolve().parents[1]


class DeploymentManifestTests(unittest.TestCase):
    def test_python_version_targets_python_312(self) -> None:
        version = (_PROJECT_ROOT / ".python-version").read_text(
            encoding="utf-8"
        )

        self.assertEqual(version.strip(), "3.12")

    def test_render_blueprint_is_public_offline_safe_and_health_checked(self) -> None:
        blueprint = (_PROJECT_ROOT / "render.yaml").read_text(
            encoding="utf-8"
        )

        required_lines = (
            r"(?m)^\s*- type: web\s*$",
            r"(?m)^\s*runtime: python\s*$",
            r"(?m)^\s*plan: free\s*$",
            r"(?m)^\s*buildCommand: pip install \.\s*$",
            (
                r"(?m)^\s*startCommand: uvicorn autosoc\.web\.app:app "
                r"--host 0\.0\.0\.0 --port \$PORT(?:\s|$)"
            ),
            r"(?m)^\s*healthCheckPath: /healthz\s*$",
            r"(?m)^\s*autoDeployTrigger: commit\s*$",
            r"(?m)^\s*- key: AUTOSOC_ENABLE_LIVE_PROVIDERS\s*$",
            r'(?m)^\s*value: "false"\s*$',
            r"(?m)^\s*- key: AUTOSOC_RATE_LIMIT_PER_MINUTE\s*$",
        )
        for pattern in required_lines:
            with self.subTest(pattern=pattern):
                self.assertRegex(blueprint, re.compile(pattern))

        self.assertNotIn("ABUSEIPDB_API_KEY", blueprint)
        self.assertNotIn("OPENAI_API_KEY", blueprint)
        self.assertNotIn("AUTOSOC_WEB_PASSWORD", blueprint)
        self.assertNotRegex(blueprint, r"(?i)\bsk-[a-z0-9_-]+")


if __name__ == "__main__":
    unittest.main()
