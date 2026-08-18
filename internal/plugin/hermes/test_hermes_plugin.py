# Copyright 2026 The Rampart Authors
# Licensed under the Apache License, Version 2.0

from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import types
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

    def test_native_approval_requires_exact_rule_key_contract(self) -> None:
        hermes_package = types.ModuleType("hermes_cli")
        hermes_package.__path__ = []
        hermes_plugins = types.ModuleType("hermes_cli.plugins")
        hermes_plugins.get_pre_tool_call_directive = lambda *_: None

        def details_getter(*_):
            return None

        def resolve_pre_tool_block(*_):
            return None

        def resolve_block_from_details(*_):
            return None

        hermes_plugins._get_pre_tool_call_directive_details = details_getter
        hermes_plugins.resolve_pre_tool_block = resolve_pre_tool_block
        hermes_plugins._resolve_block_from_details = resolve_block_from_details
        directive_type = type(
            "_PreToolCallDirective",
            (),
            {"__dataclass_fields__": {"rule_key": object()}},
        )
        hermes_plugins._PreToolCallDirective = directive_type
        hermes_package.plugins = hermes_plugins
        modules = {
            "hermes_cli": hermes_package,
            "hermes_cli.plugins": hermes_plugins,
        }
        sources = {
            details_getter: """
                def _get_pre_tool_call_directive_details():
                    rule_key = result.get("rule_key") if action == "approve" else None
                    return _PreToolCallDirective(action=action, rule_key=rule_key)
            """,
            resolve_pre_tool_block: """
                def resolve_pre_tool_block(tool_name, args):
                    details = _get_pre_tool_call_directive_details(tool_name, args)
                    return request_tool_approval(
                        tool_name, details.message or "",
                        rule_key=details.rule_key or tool_name,
                    )
            """,
            resolve_block_from_details: """
                def _resolve_block_from_details(details, tool_name):
                    return request_tool_approval(
                        tool_name, details.message or "",
                        rule_key=details.rule_key or tool_name,
                    )
            """,
        }

        with (
            mock.patch.dict(sys.modules, modules),
            mock.patch.object(
                plugin.inspect,
                "getsource",
                side_effect=lambda function: sources[function],
            ),
        ):
            self.assertTrue(plugin._hermes_supports_native_approval())
            sources[resolve_pre_tool_block] = """
                def resolve_pre_tool_block(tool_name, args):
                    details = _get_pre_tool_call_directive_details(tool_name, args)
                    return request_tool_approval(tool_name, details.message, rule_key=tool_name)
            """
            self.assertFalse(plugin._hermes_supports_native_approval())

            sources[resolve_pre_tool_block] = """
                def resolve_pre_tool_block(tool_name, args):
                    details = _get_pre_tool_call_directive_details(tool_name, args)
                    return _resolve_block_from_details(details, tool_name)
            """
            self.assertTrue(plugin._hermes_supports_native_approval())

            sources[resolve_block_from_details] = """
                def _resolve_block_from_details(details, tool_name):
                    return request_tool_approval(
                        tool_name, details.message or "", rule_key=tool_name
                    )
            """
            self.assertFalse(plugin._hermes_supports_native_approval())

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

    def test_ask_decision_uses_native_approval_with_exact_call_key(self) -> None:
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

        args = {"command": "kubectl apply -f prod.yaml", "workdir": "/workspace"}
        with (
            mock.patch.object(plugin, "_hermes_supports_native_approval", return_value=True),
            mock.patch.object(plugin, "_load_token", return_value="unit-test-token"),
        ):
            result = plugin.evaluate_pre_tool_call(
                "terminal",
                args,
                tool_call_id="call-ask-1",
                requester=requester,
            )

        self.assertEqual(result["action"], "approve")
        self.assertIn("approval required", result["message"])
        self.assertIn("prod-change", result["message"])
        self.assertIn("audit-ask-1", result["message"])
        self.assertIn("kubectl apply -f prod.yaml", result["message"])
        config = plugin.load_config()
        params = plugin.normalize_tool_call("terminal", args)[1]
        with mock.patch.object(plugin, "_load_token", return_value="unit-test-token"):
            expected = plugin._approval_rule_key(config, "terminal", args, params, "")
            different = plugin._approval_rule_key(
                config,
                "terminal",
                {"command": "kubectl apply -f other.yaml", "workdir": "/workspace"},
                plugin.normalize_tool_call(
                    "terminal",
                    {"command": "kubectl apply -f other.yaml", "workdir": "/workspace"},
                )[1],
                "",
            )
        self.assertEqual(result["rule_key"], expected)
        self.assertNotEqual(result["rule_key"], different)

    def test_browser_approval_shows_redacted_target(self) -> None:
        target = "https://user:browser-password@example.com/batches/current?token=query-secret#private"
        with (
            mock.patch.object(plugin, "_hermes_supports_native_approval", return_value=True),
            mock.patch.object(plugin, "_load_token", return_value="unit-test-token"),
        ):
            result = plugin.evaluate_pre_tool_call(
                "browser_navigate",
                {"url": target},
                task_id="task-browser",
                requester=lambda *_: {
                    "decision": "ask",
                    "allowed": False,
                    "message": "unclassified navigation",
                },
            )

        self.assertEqual(result["action"], "approve")
        self.assertEqual(plugin._safe_url_display(target), "https://example.com")
        self.assertIn(
            "browser navigate: https://example.com.",
            result["message"],
        )
        self.assertNotIn("browser-password", result["message"])
        self.assertNotIn("query-secret", result["message"])
        self.assertNotIn("private", result["message"])

    def test_approval_display_redacts_credentials_urls_and_format_controls(self) -> None:
        summary = plugin._redact_approval_text(
            "AWS_SECRET_ACCESS_KEY=aws-secret OPENAI_API_KEY=openai-secret "
            "GITHUB_TOKEN=github-secret curl -ualice:curl-secret "
            "-H 'Authorization: Bearer header-secret' "
            "https://user:url-secret@example.com/private/object?token=query-secret#fragment "
            "ssh://alice:ssh-secret@internal.example/private-key "
            'json={"api_key":"json-secret","password":"json-password",'
            '"Authorization":"Bearer json-auth-secret"} '
            "access_token: yaml-secret ssh alice:ssh-cli-secret@internal.example "
            "mailto:person+mail-secret@example.com "
            "\x1b[31mshown\u202e",
            600,
        )

        self.assertIsNotNone(summary)
        assert summary is not None
        for secret in (
            "aws-secret",
            "openai-secret",
            "github-secret",
            "curl-secret",
            "header-secret",
            "url-secret",
            "query-secret",
            "fragment",
            "ssh-secret",
            "ssh-cli-secret",
            "private-key",
            "mail-secret",
            "json-secret",
            "json-password",
            "json-auth-secret",
            "yaml-secret",
        ):
            self.assertNotIn(secret, summary)
        self.assertIn("AWS_SECRET_ACCESS_KEY=[REDACTED]", summary)
        self.assertIn("OPENAI_API_KEY=[REDACTED]", summary)
        self.assertIn("GITHUB_TOKEN=[REDACTED]", summary)
        self.assertIn("curl -u [REDACTED]", summary)
        self.assertIn("Authorization: Bearer [REDACTED]", summary)
        self.assertIn("https://example.com", summary)
        self.assertIn("<non-HTTP URL (ssh) redacted>", summary)
        self.assertIn("<non-HTTP URL (mailto) redacted>", summary)
        self.assertIn('"api_key":[REDACTED]', summary)
        self.assertIn('"password":[REDACTED]', summary)
        self.assertIn('"Authorization":[REDACTED]', summary)
        self.assertIn("access_token: [REDACTED]", summary)
        self.assertIn("ssh [REDACTED]@internal.example", summary)
        self.assertNotIn("\x1b", summary)
        self.assertNotIn("[31m", summary)
        self.assertNotIn("\u202e", summary)

    def test_approval_key_binds_resolved_path_and_does_not_expose_arguments(self) -> None:
        config = plugin.load_config()
        args = {"path": "notes.txt", "content": "API_TOKEN=super-secret"}
        with mock.patch.object(plugin, "_load_token", return_value="unit-test-token"):
            safe_key = plugin._approval_rule_key(
                config, "write_file", args, {"path": "/safe/notes.txt"}, "task-safe"
            )
            protected_key = plugin._approval_rule_key(
                config, "write_file", args, {"path": "/protected/notes.txt"}, "task-safe"
            )
            other_task_key = plugin._approval_rule_key(
                config, "write_file", args, {"path": "/safe/notes.txt"}, "task-other"
            )

        self.assertIsNotNone(safe_key)
        self.assertNotEqual(safe_key, protected_key)
        self.assertNotEqual(safe_key, other_task_key)
        self.assertNotIn("super-secret", safe_key)

    def test_terminal_approval_key_binds_effective_cwd_and_refuses_ambiguity(self) -> None:
        config = plugin.load_config()
        args = {"command": "printf safe"}
        params = plugin.normalize_tool_call("terminal", args)[1]
        with (
            mock.patch.object(plugin, "_load_token", return_value="unit-test-token"),
            mock.patch.object(plugin, "_effective_terminal_cwd", return_value="/safe"),
        ):
            safe_key = plugin._approval_rule_key(config, "terminal", args, params, "task")
        with (
            mock.patch.object(plugin, "_load_token", return_value="unit-test-token"),
            mock.patch.object(plugin, "_effective_terminal_cwd", return_value="/other"),
        ):
            other_key = plugin._approval_rule_key(config, "terminal", args, params, "task")
        with (
            mock.patch.object(plugin, "_load_token", return_value="unit-test-token"),
            mock.patch.object(plugin, "_effective_terminal_cwd", return_value=None),
        ):
            ambiguous_key = plugin._approval_rule_key(
                config, "terminal", args, params, "task"
            )

        self.assertIsNotNone(safe_key)
        self.assertNotEqual(safe_key, other_key)
        self.assertIsNone(ambiguous_key)

    def test_terminal_approval_key_requires_absolute_explicit_workdir(self) -> None:
        config = plugin.load_config()

        def key_for(workdir):
            args = {"command": "printf safe", "workdir": workdir}
            params = plugin.normalize_tool_call("terminal", args)[1]
            return plugin._approval_rule_key(
                config, "terminal", args, params, "task"
            )

        with mock.patch.object(plugin, "_load_token", return_value="unit-test-token"):
            absolute_key = key_for(os.path.abspath("workspace"))
            dot_key = key_for(".")
            named_key = key_for("project")
            windows_key = key_for(r"C:\workspace")

        self.assertIsNotNone(absolute_key)
        self.assertIsNone(dot_key)
        self.assertIsNone(named_key)
        if os.name == "nt":
            self.assertIsNotNone(windows_key)
        else:
            self.assertIsNone(windows_key)

    def test_approval_key_refuses_unbounded_or_non_json_identity(self) -> None:
        config = plugin.load_config()
        recursive = {}
        recursive["self"] = recursive
        with mock.patch.object(plugin, "_load_token", return_value="unit-test-token"):
            oversized = plugin._approval_rule_key(
                config,
                "write_file",
                {"path": "/tmp/notes.txt", "content": "x" * plugin.MAX_APPROVAL_IDENTITY_BYTES},
                {"path": "/tmp/notes.txt"},
                "task",
            )
            non_json = plugin._approval_rule_key(
                config,
                "terminal",
                {"command": object(), "workdir": "/tmp"},
                {"command": "safe"},
                "task",
            )
            recursive["workdir"] = "/tmp"
            recursive_key = plugin._approval_rule_key(
                config,
                "terminal",
                recursive,
                {"command": "safe"},
                "task",
            )
            huge_integer_key = plugin._approval_rule_key(
                config,
                "terminal",
                {
                    "timeout": 1 << (plugin.MAX_APPROVAL_IDENTITY_BYTES * 8),
                    "workdir": "/tmp",
                },
                {"command": "safe"},
                "task",
            )

        self.assertIsNone(oversized)
        self.assertIsNone(non_json)
        self.assertIsNone(recursive_key)
        self.assertIsNone(huge_integer_key)

    def test_ask_blocks_without_a_token_for_opaque_approval_identity(self) -> None:
        with (
            mock.patch.object(plugin, "_hermes_supports_native_approval", return_value=True),
            mock.patch.object(plugin, "_load_token", return_value=None),
        ):
            result = plugin.evaluate_pre_tool_call(
                "browser_navigate",
                {"url": "https://example.com"},
                requester=lambda *_: {
                    "decision": "ask",
                    "allowed": False,
                    "message": "navigation requires approval",
                },
            )

        self.assertEqual(result["action"], "block")
        self.assertIn("non-secret approval key", result["message"])

    def test_ask_decision_blocks_on_older_hermes(self) -> None:
        with mock.patch.object(plugin, "_hermes_supports_native_approval", return_value=False):
            result = plugin.evaluate_pre_tool_call(
                "browser_navigate",
                {"url": "https://example.com"},
                requester=lambda *_: {
                    "decision": "ask",
                    "allowed": False,
                    "message": "navigation requires approval",
                },
            )

        self.assertEqual(result["action"], "block")
        self.assertIn("does not support plugin-owned approval/resume", result["message"])

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
