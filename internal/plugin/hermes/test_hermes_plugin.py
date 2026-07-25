# Copyright 2026 The Rampart Authors
# Licensed under the Apache License, Version 2.0

from __future__ import annotations

import importlib.util
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
                return {"decision": "deny", "message": "protected environment file"}
            return {"decision": "allow"}

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

    def test_deny_decision_blocks(self) -> None:
        captured = {}

        def requester(config, rampart_tool, payload):
            captured["config"] = config
            captured["tool"] = rampart_tool
            captured["payload"] = payload
            return {"decision": "deny", "message": "blocked", "policy": "danger", "audit_id": "audit-deny-1"}

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
            self.assertNotIn("openclaw_hosted", payload)
            self.assertNotIn("skip_pending_approval", payload)
            self.assertEqual(payload["tool_call_id"], "call-ask-1")
            return {
                "decision": "ask",
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

    def test_unavailable_allows_configured_read_only_tool(self) -> None:
        def requester(config, rampart_tool, payload):
            raise plugin.RampartUnavailable("connection refused")

        result = plugin.evaluate_pre_tool_call(
            "read_file",
            {"path": "/tmp/a"},
            requester=requester,
        )

        self.assertIsNone(result)

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
