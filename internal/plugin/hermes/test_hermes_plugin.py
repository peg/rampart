# Copyright 2026 The Rampart Authors
# Licensed under the Apache License, Version 2.0

from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

PLUGIN_PATH = Path(__file__).with_name("__init__.py")
spec = importlib.util.spec_from_file_location("rampart_hermes_plugin_under_test", PLUGIN_PATH)
assert spec is not None
assert spec.loader is not None
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)


class HermesPluginTests(unittest.TestCase):
    def setUp(self) -> None:
        self.env_patch = mock.patch.dict(
            os.environ,
            {
                key: value
                for key, value in os.environ.items()
                if not key.startswith("RAMPART_")
            },
            clear=True,
        )
        self.env_patch.start()

    def tearDown(self) -> None:
        self.env_patch.stop()

    def test_terminal_maps_to_exec_with_command_metadata(self) -> None:
        rampart_tool, params = plugin.normalize_tool_call(
            "terminal",
            {"command": "sudo true", "workdir": "/tmp", "background": True},
        )

        self.assertEqual(rampart_tool, "exec")
        self.assertEqual(params["command"], "sudo true")
        self.assertEqual(params["workdir"], "/tmp")
        self.assertTrue(params["background"])
        self.assertEqual(params["hermes_tool"], "terminal")
        self.assertEqual(params["rampart_tool"], "exec")

    def test_write_file_does_not_send_content(self) -> None:
        rampart_tool, params = plugin.normalize_tool_call(
            "write_file",
            {"path": "/tmp/secret.txt", "content": "API_TOKEN=super-secret\n"},
        )

        self.assertEqual(rampart_tool, "write")
        self.assertEqual(params["path"], "/tmp/secret.txt")
        self.assertEqual(params["content_lines"], 1)
        self.assertNotIn("content", params)
        self.assertNotIn("super-secret", json.dumps(params))

    def test_patch_mode_reports_size_and_touched_paths_only(self) -> None:
        rampart_tool, params = plugin.normalize_tool_call(
            "patch",
            {
                "mode": "patch",
                "patch": "*** Begin Patch\n*** Update File: a.txt\n-secret\n+replacement\n*** End Patch",
            },
        )

        self.assertEqual(rampart_tool, "edit")
        self.assertEqual(params["mode"], "patch")
        self.assertGreater(params["patch_bytes"], 0)
        self.assertEqual(params["touched_paths"], ["a.txt"])
        self.assertNotIn("replacement", json.dumps(params))

    def test_patch_checks_every_path_and_deny_wins(self) -> None:
        paths_seen = []

        def requester(config, rampart_tool, payload):
            self.assertEqual(rampart_tool, "edit")
            path = payload["params"]["path"]
            paths_seen.append(path)
            if path == "secrets/.env":
                return {
                    "decision": "deny",
                    "allowed": False,
                    "message": "protected environment file",
                }
            return {"decision": "allow", "allowed": True}

        result = plugin.evaluate_pre_tool_call(
            "patch",
            {
                "mode": "patch",
                "patch": (
                    "*** Begin Patch\n"
                    "*** Add File: safe.txt\n"
                    "+safe\n"
                    "*** Update File: secrets/.env\n"
                    "@@\n-old\n+new\n"
                    "*** Move to: archive/.env\n"
                    "*** End Patch"
                ),
            },
            requester=requester,
        )

        self.assertEqual(paths_seen, ["safe.txt", "secrets/.env"])
        self.assertEqual(result["action"], "block")
        self.assertIn("protected environment file", result["message"])

    def test_oversized_patch_fails_closed_without_policy_requests(self) -> None:
        patch = "\n".join(
            f"*** Add File: generated/file-{index}.txt"
            for index in range(plugin.MAX_PATCH_PATHS + 1)
        )
        requester = mock.Mock(return_value={"decision": "allow"})

        result = plugin.evaluate_pre_tool_call(
            "patch",
            {"mode": "patch", "patch": patch},
            requester=requester,
        )

        requester.assert_not_called()
        self.assertEqual(result["action"], "block")
        self.assertIn("split into smaller calls", result["message"])

    def test_preflight_endpoint_is_default(self) -> None:
        config = plugin.load_config({"serve_url": "http://example.invalid/base/", "timeout_ms": 250})
        self.assertEqual(config.endpoint_mode, "preflight")
        self.assertEqual(plugin._endpoint_url(config, "exec"), "http://example.invalid/base/v1/preflight/exec")

    def test_policy_token_is_never_sent_to_non_loopback_service(self) -> None:
        config = plugin.load_config({"serve_url": "https://policy.example.invalid"})
        with mock.patch.object(plugin._NO_REDIRECT_OPENER, "open") as opener:
            with self.assertRaises(plugin.RampartInvalidResponse):
                plugin.post_to_rampart(config, "exec", {"params": {"command": "pwd"}})
        opener.assert_not_called()

        self.assertTrue(plugin._is_trusted_serve_url("http://127.0.0.1:9090"))
        self.assertTrue(plugin._is_trusted_serve_url("http://[::1]:9090"))
        self.assertFalse(plugin._is_trusted_serve_url("http://127.0.0.1@example.invalid:9090"))
        self.assertFalse(plugin._is_trusted_serve_url("http://localhost:9090?redirect=1"))

    def test_policy_requests_refuse_redirects(self) -> None:
        config = plugin.PluginConfig(serve_url="http://127.0.0.1:9090")
        redirect = plugin.urllib.error.HTTPError(
            config.serve_url,
            307,
            "Temporary Redirect",
            {"Location": "https://example.invalid/collect"},
            None,
        )
        with mock.patch.object(plugin, "_load_token", return_value="secret"):
            with mock.patch.object(
                plugin._NO_REDIRECT_OPENER, "open", side_effect=redirect
            ) as opener:
                with self.assertRaises(plugin.RampartInvalidResponse):
                    plugin.post_to_rampart(
                        config, "exec", {"params": {"command": "pwd"}}
                    )
        opener.assert_called_once()

    def test_policy_requests_ignore_ambient_proxy_configuration(self) -> None:
        # Passing ProxyHandler({}) suppresses urllib's default environment-backed
        # proxy handler. An empty handler installs no proxy_open methods, so it is
        # intentionally absent from the finalized opener.
        self.assertFalse(
            any(
                isinstance(handler, plugin.urllib.request.ProxyHandler)
                for handler in plugin._NO_REDIRECT_OPENER.handlers
            )
        )

    def test_auth_error_response_body_is_closed(self) -> None:
        config = plugin.PluginConfig(serve_url="http://127.0.0.1:9090")
        body = io.BytesIO(b'{"error":"invalid token"}')
        auth_error = plugin.urllib.error.HTTPError(
            config.serve_url,
            401,
            "Unauthorized",
            {},
            body,
        )
        with mock.patch.object(
            plugin._NO_REDIRECT_OPENER, "open", side_effect=auth_error
        ):
            result = plugin.post_to_rampart(config, "exec", {"params": {}})

        self.assertFalse(result["allowed"])
        self.assertTrue(body.closed)

    def test_generic_metadata_does_not_serialize_nested_secrets(self) -> None:
        _, params = plugin.normalize_tool_call(
            "vision_analyze",
            {"headers": {"Authorization": "Bearer plaintext-secret"}, "items": ["plaintext-secret"]},
        )
        encoded = json.dumps(params)
        self.assertNotIn("plaintext-secret", encoded)
        self.assertEqual(params["headers"], "<mapping keys=1>")
        self.assertEqual(params["items"], "<sequence items=1>")

    def test_deny_decision_blocks(self) -> None:
        captured = {}

        def requester(config, rampart_tool, payload):
            captured["config"] = config
            captured["tool"] = rampart_tool
            captured["payload"] = payload
            return {
                "decision": "deny",
                "allowed": False,
                "message": "blocked",
                "policy": "danger",
                "audit_id": "audit-deny-1",
            }

        result = plugin.evaluate_pre_tool_call(
            "terminal",
            {"command": "rm -rf /tmp/example"},
            task_id="task-1",
            session_id="sess-1",
            tool_call_id="call-1",
            config_overrides={"serve_url": "http://127.0.0.1:9090"},
            requester=requester,
        )

        self.assertEqual(captured["tool"], "exec")
        self.assertEqual(captured["payload"]["agent"], "hermes")
        self.assertEqual(captured["payload"]["session"], "sess-1")
        self.assertEqual(captured["payload"]["run_id"], "task-1")
        self.assertEqual(captured["payload"]["tool_call_id"], "call-1")
        self.assertNotIn("hermes_tool_call_id", captured["payload"]["params"])
        self.assertEqual(result["action"], "block")
        self.assertIn("blocked", result["message"])
        self.assertIn("danger", result["message"])
        self.assertIn("audit-deny-1", result["message"])

    def test_ask_decision_blocks_without_hidden_approval(self) -> None:
        def requester(config, rampart_tool, payload):
            self.assertEqual(config.endpoint_mode, "preflight")
            self.assertIs(payload["enforce"], True)
            self.assertNotIn("openclaw_hosted", payload)
            self.assertNotIn("skip_pending_approval", payload)
            self.assertEqual(payload["tool_call_id"], "call-ask-1")
            return {
                "decision": "ask",
                "allowed": False,
                "message": "needs human review",
                "matched_policies": ["prod-change"],
                "audit_id": "audit-ask-1",
            }

        result = plugin.evaluate_pre_tool_call(
            "terminal",
            {"command": "kubectl apply -f prod.yaml"},
            tool_call_id="call-ask-1",
            requester=requester,
        )

        self.assertEqual(result["action"], "block")
        self.assertIn("approval required", result["message"])
        self.assertIn("does not yet resume", result["message"])
        self.assertIn("prod-change", result["message"])
        self.assertIn("audit-ask-1", result["message"])

    def test_unavailable_blocks_mutating_tool(self) -> None:
        def requester(config, rampart_tool, payload):
            raise plugin.RampartUnavailable("connection refused")

        result = plugin.evaluate_pre_tool_call(
            "write_file",
            {"path": "/tmp/a", "content": "x"},
            requester=requester,
        )

        self.assertEqual(result["action"], "block")
        self.assertIn("unavailable", result["message"])

    def test_auth_error_response_blocks_mutating_tool(self) -> None:
        def requester(config, rampart_tool, payload):
            return {"error": "invalid authorization token", "message": "invalid authorization token"}

        result = plugin.evaluate_pre_tool_call(
            "terminal",
            {"command": "printf safe"},
            requester=requester,
        )

        self.assertEqual(result["action"], "block")
        self.assertIn("invalid authorization token", result["message"])

    def test_unknown_tool_fails_closed_without_policy_request(self) -> None:
        requester = mock.Mock(return_value={"decision": "allow"})

        result = plugin.evaluate_pre_tool_call(
            "future_mutating_tool",
            {"target": "/tmp/unsafe"},
            requester=requester,
        )

        requester.assert_not_called()
        self.assertEqual(result["action"], "block")
        self.assertIn("unsupported Hermes tool future_mutating_tool", result["message"])

    def test_malformed_policy_responses_fail_closed(self) -> None:
        for response in (
            {},
            {"decision": "future-decision"},
            {"decision": "allow"},
            {"decision": "allow", "allowed": False},
            {"decision": "deny", "allowed": True},
            ["allow"],
        ):
            with self.subTest(response=response):
                result = plugin.evaluate_pre_tool_call(
                    "terminal",
                    {"command": "printf safe"},
                    requester=mock.Mock(return_value=response),
                )

                self.assertEqual(result["action"], "block")

    def test_registered_hook_converts_adapter_exception_to_block(self) -> None:
        class Ctx:
            def __init__(self):
                self.hooks = {}

            def register_hook(self, name, callback):
                self.hooks[name] = callback

        ctx = Ctx()
        plugin.register(ctx)

        with mock.patch.object(plugin, "evaluate_pre_tool_call", side_effect=ValueError("bad input")):
            result = ctx.hooks["pre_tool_call"]("terminal", {"command": "printf safe"})

        self.assertEqual(result["action"], "block")
        self.assertIn("policy adapter error", result["message"])

    def test_unavailable_blocks_read_by_default(self) -> None:
        def requester(config, rampart_tool, payload):
            raise plugin.RampartUnavailable("connection refused")

        result = plugin.evaluate_pre_tool_call(
            "read_file",
            {"path": "/tmp/a"},
            requester=requester,
        )

        self.assertEqual(result["action"], "block")
        self.assertIn("unavailable", result["message"])

    def test_unavailable_allows_explicitly_configured_read_only_tool(self) -> None:
        def requester(config, rampart_tool, payload):
            raise plugin.RampartUnavailable("connection refused")

        result = plugin.evaluate_pre_tool_call(
            "read_file",
            {"path": "/tmp/a"},
            config_overrides={"fail_open_tools": ["read_file"]},
            requester=requester,
        )

        self.assertIsNone(result)

    def test_invalid_response_blocks_even_for_configured_fail_open_tool(self) -> None:
        def requester(config, rampart_tool, payload):
            raise plugin.RampartInvalidResponse("unexpected redirect")

        result = plugin.evaluate_pre_tool_call(
            "read_file",
            {"path": "/tmp/a"},
            config_overrides={"fail_open_tools": ["read_file"]},
            requester=requester,
        )

        self.assertEqual(result["action"], "block")
        self.assertIn("invalid policy response", result["message"])

    def test_relative_file_path_uses_hermes_task_working_directory(self) -> None:
        captured = {}

        def requester(config, rampart_tool, payload):
            captured["path"] = payload["params"]["path"]
            return {"decision": "deny", "allowed": False, "message": "fixture"}

        with mock.patch.dict(os.environ, {"TERMINAL_CWD": "/tmp/hermes-workspace"}):
            plugin.evaluate_pre_tool_call(
                "read_file",
                {"path": "../protected/credential.txt"},
                task_id="task-cwd",
                requester=requester,
            )

        self.assertEqual(captured["path"], str(Path("/tmp/protected/credential.txt").resolve()))

    def test_register_installs_pre_tool_call_hook(self) -> None:
        class Ctx:
            def __init__(self):
                self.hooks = {}

            def register_hook(self, name, callback):
                self.hooks[name] = callback

        ctx = Ctx()
        plugin.register(ctx)

        self.assertIn("pre_tool_call", ctx.hooks)


if __name__ == "__main__":
    unittest.main()
