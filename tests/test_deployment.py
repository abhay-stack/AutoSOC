"""Checked-in contracts for hosted and containerized deployments."""

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
        self.assertNotIn("maxShutdownDelaySeconds", blueprint)
        self.assertNotRegex(blueprint, r"(?i)\bsk-[a-z0-9_-]+")


class ContainerDeploymentTests(unittest.TestCase):
    def test_dockerfile_uses_non_root_python_312_runtime(self) -> None:
        dockerfile = (_PROJECT_ROOT / "Dockerfile").read_text(
            encoding="utf-8"
        )

        required_patterns = (
            r"(?m)^FROM python:3\.12-slim AS builder$",
            r"(?m)^FROM python:3\.12-slim AS runtime$",
            r"(?m)^USER autosoc$",
            r"(?m)^EXPOSE 8000$",
            r"(?m)^HEALTHCHECK ",
            (
                r'(?m)^CMD \["uvicorn", "autosoc\.web\.app:app", '
                r'"--host", "0\.0\.0\.0", "--port", "8000", '
                r'"--no-server-header"\]$'
            ),
        )
        for pattern in required_patterns:
            with self.subTest(pattern=pattern):
                self.assertRegex(dockerfile, re.compile(pattern))

        self.assertNotIn("COPY .", dockerfile)
        self.assertNotIn("ABUSEIPDB_API_KEY=", dockerfile)
        self.assertNotIn("GREYNOISE_API_KEY=", dockerfile)
        self.assertNotIn("OPENAI_API_KEY=", dockerfile)
        self.assertNotRegex(dockerfile, r"(?i)\bsk-[a-z0-9_-]+")
        self.assertIn('[ "${APP_UID}" -gt 0 ]', dockerfile)
        self.assertIn('[ "${APP_GID}" -gt 0 ]', dockerfile)
        self.assertIn('getent group "${APP_GID}"', dockerfile)

    def test_compose_mounts_only_data_as_writable_persistent_storage(
        self,
    ) -> None:
        compose = (_PROJECT_ROOT / "docker-compose.yml").read_text(
            encoding="utf-8"
        )

        required_patterns = (
            r'(?m)^\s+user: "\$\{AUTOSOC_UID:-1000\}:\$\{AUTOSOC_GID:-1000\}"$',
            r'(?m)^\s+- "\$\{AUTOSOC_PORT:-8000\}:8000"$',
            r"(?m)^\s+AUTOSOC_DATA_DIR: /app/data$",
            r"(?m)^\s+source: \./data$",
            r"(?m)^\s+target: /app/data$",
            r"(?m)^\s+read_only: true$",
            r"(?m)^\s+cap_drop:$",
            r"(?m)^\s+- ALL$",
            r"(?m)^\s+- no-new-privileges:true$",
            r"(?m)^\s+pids_limit: 256$",
            r"(?m)^\s+healthcheck:$",
        )
        for pattern in required_patterns:
            with self.subTest(pattern=pattern):
                self.assertRegex(compose, re.compile(pattern))

        self.assertNotIn("privileged: true", compose)
        self.assertNotIn("/var/run/docker.sock", compose)
        self.assertNotRegex(compose, r"(?i)\bsk-[a-z0-9_-]+")

    def test_docker_context_excludes_secrets_and_local_artifacts(self) -> None:
        dockerignore = (_PROJECT_ROOT / ".dockerignore").read_text(
            encoding="utf-8"
        )
        entries = {
            line.strip()
            for line in dockerignore.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }

        for expected in {".git", ".env", ".env.*", ".venv", "data", "tests"}:
            with self.subTest(entry=expected):
                self.assertIn(expected, entries)


if __name__ == "__main__":
    unittest.main()
