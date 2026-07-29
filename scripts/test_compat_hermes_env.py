#!/usr/bin/env python3
"""Regression tests for the Hermes compatibility harness environment."""

from __future__ import annotations

import importlib.util
import unittest
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


if __name__ == "__main__":
    unittest.main()
