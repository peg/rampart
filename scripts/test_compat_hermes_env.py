#!/usr/bin/env python3
"""Regression tests for the Hermes compatibility harness environment."""

from __future__ import annotations

import importlib.util
import io
import json
import os
import unittest
from unittest import mock
from pathlib import Path


SCRIPT = Path(__file__).with_name("compat-hermes-latest.py")
SPEC = importlib.util.spec_from_file_location("compat_hermes_latest", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CompatEnvironmentTests(unittest.TestCase):
    def test_ambient_credentials_and_runtime_injection_are_not_forwarded(self) -> None:
        env = MODULE.build_compat_env(
            {
                "PATH": "/usr/bin",
                "HTTPS_PROXY": "https://proxy.example:8443",
                "HTTP_PROXY": "http://user:password@proxy.example:8080",
                "ALL_PROXY": "https://proxy.example:8443?token=secret-proxy-token",
                "PIP_INDEX_URL": "https://mirror.example/simple#secret-fragment",
                "SSL_CERT_FILE": "/etc/company-ca.pem",
                "OPENAI_API_KEY": "secret-openai-key",
                "GITHUB_TOKEN": "secret-github-token",
                "AWS_SECRET_ACCESS_KEY": "secret-aws-key",
                "RAMPART_TOKEN": "real-rampart-token",
                "PYTHONPATH": "/credential-reader",
                "PIP_TRUSTED_HOST": "unverified-package-mirror.example",
            },
            Path("/tmp/isolated-home"),
            Path("/tmp/isolated-tmp"),
        )

        self.assertEqual(env["PATH"], "/usr/bin")
        self.assertEqual(env["HTTPS_PROXY"], "https://proxy.example:8443")
        self.assertEqual(env["SSL_CERT_FILE"], "/etc/company-ca.pem")
        self.assertEqual(env["HOME"], "/tmp/isolated-home")
        self.assertEqual(env["TMPDIR"], "/tmp/isolated-tmp")
        self.assertEqual(env["NO_PROXY"], "127.0.0.1,localhost,::1")
        self.assertEqual(env["no_proxy"], env["NO_PROXY"])
        self.assertEqual(env["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
        for key in (
            "HTTP_PROXY",
            "ALL_PROXY",
            "PIP_INDEX_URL",
            "OPENAI_API_KEY",
            "GITHUB_TOKEN",
            "AWS_SECRET_ACCESS_KEY",
            "RAMPART_TOKEN",
            "PYTHONPATH",
            "PIP_TRUSTED_HOST",
        ):
            self.assertNotIn(key, env)

    def test_failed_child_diagnostics_preserve_category_without_values(self) -> None:
        secret = "synthetic-private-value"
        for stderr, expected in (
            ("ask did not request Hermes native approval: " + secret, "ask did not request Hermes native approval"),
            ("ModuleNotFoundError: " + secret, "ModuleNotFoundError"),
            ("unrecognized failure " + secret, "child diagnostic unavailable"),
        ):
            result = MODULE.child_failure_diagnostic(stderr)
            self.assertIn(expected, result)
            self.assertNotIn(secret, result)
            self.assertIn("redacted", result)
        failed = MODULE.subprocess.CompletedProcess(["python", "-c", secret], 1, "", "RuntimeError: " + secret)
        with mock.patch.object(MODULE.subprocess, "run", return_value=failed):
            with self.assertRaisesRegex(RuntimeError, "python exited 1: RuntimeError") as error:
                MODULE.run(["python", "-c", secret], env={})
        self.assertNotIn(secret, str(error.exception))

    def test_missing_module_name_is_exposed_only_as_a_plain_identifier(self) -> None:
        exposed = MODULE.child_failure_diagnostic(
            "Traceback (most recent call last):\nModuleNotFoundError: No module named 'yaml.nodes'"
        )
        self.assertIn("'yaml.nodes'", exposed)
        self.assertIn("redacted", exposed)
        for stderr in (
            "ModuleNotFoundError: No module named 'synthetic-private-value'",
            "ModuleNotFoundError: No module named 'a' injected synthetic-private-value",
            "ModuleNotFoundError: No module named '" + "a" * 101 + "'",
        ):
            with self.subTest(stderr=stderr):
                result = MODULE.child_failure_diagnostic(stderr)
                self.assertNotIn("synthetic-private-value", result)
                self.assertNotIn("No module named", result)
                self.assertIn("ModuleNotFoundError", result)

    def test_child_timeout_does_not_render_command_or_output(self) -> None:
        secret = "synthetic-private-value"
        error = MODULE.subprocess.TimeoutExpired(["python", "-c", secret], 1, output=secret, stderr=secret)
        with mock.patch.object(MODULE.subprocess, "run", side_effect=error):
            with self.assertRaisesRegex(RuntimeError, "timed out after 1s") as caught:
                MODULE.run(["python", "-c", secret], env={}, timeout=1)
        self.assertNotIn(secret, str(caught.exception))

    def test_official_release_resolves_validated_github_checkout(self) -> None:
        payload = {
            "tag_name": "v2026.8.3",
            "name": "Hermes Agent v0.20.0 (2026.8.3)",
            "draft": False,
            "prerelease": False,
        }
        response = mock.MagicMock()
        response.__enter__.return_value = io.BytesIO(json.dumps(payload).encode())
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(MODULE, "url_opener", return_value=opener):
            tag, version, source = MODULE.github_latest_release({})

        self.assertEqual(tag, "v2026.8.3")
        self.assertEqual(version, "0.20.0")
        self.assertEqual(
            source,
            "git+https://github.com/NousResearch/hermes-agent.git@v2026.8.3#egg=hermes-agent",
        )

    def test_official_release_accepts_semver_tag_matching_release_name(self) -> None:
        payload = {
            "tag_name": "v0.21.7",
            "name": "Hermes Agent v0.21.7",
            "draft": False,
            "prerelease": False,
        }
        response = mock.MagicMock()
        response.__enter__.return_value = io.BytesIO(json.dumps(payload).encode())
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(MODULE, "url_opener", return_value=opener):
            tag, version, source = MODULE.github_latest_release({})

        self.assertEqual(tag, "v0.21.7")
        self.assertEqual(version, "0.21.7")
        self.assertEqual(
            source,
            "git+https://github.com/NousResearch/hermes-agent.git@v0.21.7#egg=hermes-agent",
        )

    def test_release_identity_accepts_stamped_version(self) -> None:
        def unexpected() -> list[str]:
            raise AssertionError("checkout must not be consulted for a stamped version")

        MODULE.verify_release_identity("0.21.5", "0.21.5", "v2026.9.24", unexpected)

    def test_release_identity_accepts_placeholder_only_at_release_tag(self) -> None:
        MODULE.verify_release_identity("0.0.0", "0.21.7", "v0.21.7", lambda: ["v0.21.7"])
        for tags in ([], ["v0.21.6"], ["v2026.9.24"]):
            with self.subTest(tags=tags):
                with self.assertRaisesRegex(RuntimeError, "expected 0.21.7"):
                    MODULE.verify_release_identity("0.0.0", "0.21.7", "v0.21.7", lambda tags=tags: tags)

    def test_release_identity_rejects_other_versions_without_consulting_checkout(self) -> None:
        def unexpected() -> list[str]:
            raise AssertionError("checkout must not rescue a mismatched stamped version")

        with self.assertRaisesRegex(RuntimeError, "installed distribution 0.21.4, expected 0.21.5"):
            MODULE.verify_release_identity("0.21.4", "0.21.5", "v2026.9.24", unexpected)

    def test_official_release_rejects_untrusted_metadata(self) -> None:
        for payload in (
            {"tag_name": "../../main", "name": "Hermes Agent v0.20.0", "draft": False, "prerelease": False},
            {"tag_name": "v2026.8.3", "name": "Hermes 0.20.0", "draft": False, "prerelease": False},
            {"tag_name": "v2026.8.3", "name": "Hermes Agent v0.20.0", "draft": False, "prerelease": True},
            # A SemVer tag must be exactly the version the release announces.
            {"tag_name": "v0.21.7", "name": "Hermes Agent v0.21.6", "draft": False, "prerelease": False},
            {"tag_name": "v0.21.7.1", "name": "Hermes Agent v0.21.7", "draft": False, "prerelease": False},
            {"tag_name": "v0.21.7-rc1", "name": "Hermes Agent v0.21.7", "draft": False, "prerelease": False},
            {"tag_name": "0.21.7", "name": "Hermes Agent v0.21.7", "draft": False, "prerelease": False},
            {"tag_name": "v0.21.7/../main", "name": "Hermes Agent v0.21.7", "draft": False, "prerelease": False},
        ):
            with self.subTest(payload=payload):
                response = mock.MagicMock()
                response.__enter__.return_value = io.BytesIO(json.dumps(payload).encode())
                opener = mock.Mock()
                opener.open.return_value = response
                with mock.patch.object(MODULE, "url_opener", return_value=opener):
                    with self.assertRaises(RuntimeError):
                        MODULE.github_latest_release({})


if __name__ == "__main__":
    unittest.main()
