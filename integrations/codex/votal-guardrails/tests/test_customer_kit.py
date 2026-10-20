import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

KIT = Path(__file__).resolve().parents[1]
PLUGIN = KIT / "plugins/votal-ai-guardrails"
sys.path.insert(0, str(PLUGIN / "hooks"))
import check_prompt as gate

spec = importlib.util.spec_from_file_location("launcher", PLUGIN / "scripts/start_guarded.py")
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)
EVENT = {"hook_event_name": "UserPromptSubmit", "prompt": "Synthetic test content"}


class GateTests(unittest.TestCase):
    def response(self, verdict=None, raw=None):
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value.read.return_value = raw if raw is not None else json.dumps(verdict).encode()
        with patch.object(gate, "load_settings", return_value=("https://example.invalid/guardrails/input", "synthetic-fixture")), patch.object(gate, "build_opener", return_value=opener):
            result = gate.evaluate(EVENT)
        req = opener.open.call_args.args[0]
        self.assertEqual(json.loads(req.data), {"message": EVENT["prompt"]})
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 15)
        self.assertNotIn(EVENT["prompt"], json.dumps(result))
        self.assertNotIn("synthetic-fixture", json.dumps(result))
        return result

    def test_explicit_allow(self):
        self.assertEqual(self.response({"safe": True, "action": "pass"}), {})

    def test_conflicting_and_block_decisions(self):
        for verdict in ({"safe": False, "action": "block"}, {"safe": True, "action": "block"}, {"safe": False, "action": "pass"}):
            with self.subTest(verdict=verdict):
                self.assertEqual(self.response(verdict)["decision"], "block")

    def test_redaction_never_passes_original(self):
        self.assertEqual(self.response({"safe": True, "action": "redact"})["decision"], "block")

    def test_unknown_or_malformed_decisions(self):
        for verdict in ({}, [], None, {"safe": True}, {"safe": "true", "action": "pass"}, {"safe": True, "action": "unknown"}):
            with self.subTest(verdict=verdict):
                self.assertEqual(self.response(verdict)["decision"], "block")

    def test_invalid_json_body(self):
        self.assertEqual(self.response(raw=b"not-json")["decision"], "block")

    def test_oversized_response(self):
        self.assertEqual(self.response(raw=b"a" * (gate.LIMIT + 1))["decision"], "block")

    def test_missing_credential(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(gate.evaluate(EVENT)["decision"], "block")

    def test_network_timeout(self):
        with patch.object(gate, "load_settings", return_value=("https://example.invalid/guardrails/input", "synthetic-fixture")), patch.object(gate, "build_opener", side_effect=TimeoutError):
            self.assertEqual(gate.evaluate(EVENT)["decision"], "block")

    def test_https_url_validation(self):
        for url in ("http://example.invalid", "https://user:password@example.invalid", "https://example.invalid?key=value", "https://example.invalid#fragment"):
            with self.subTest(url=url), patch.dict(os.environ, {"VOTAL_API_KEY": "synthetic-fixture", "VOTAL_SHIELD_URL": url}, clear=True):
                with self.assertRaises(ValueError):
                    gate.load_settings()

    def test_environment_config(self):
        with patch.dict(os.environ, {"VOTAL_API_KEY": "synthetic-fixture", "VOTAL_SHIELD_URL": "https://example.invalid/tenant/"}, clear=True):
            self.assertEqual(gate.load_settings()[0], "https://example.invalid/tenant/guardrails/input")

    def test_rejects_redirect(self):
        self.assertIsNone(gate.NoRedirect().redirect_request(None, None, 302, "", {}, "https://example.invalid"))

    def test_invalid_event(self):
        for event in ({}, None, {"hook_event_name": "PreToolUse", "prompt": "text"}, {"hook_event_name": "UserPromptSubmit", "prompt": []}):
            self.assertEqual(gate.evaluate(event)["decision"], "block")

    def test_main_invalid_json(self):
        output = io.StringIO()
        with patch("sys.stdin", io.StringIO("malformed")), contextlib.redirect_stdout(output):
            self.assertEqual(gate.main(), 0)
        self.assertEqual(json.loads(output.getvalue())["decision"], "block")


class DistributionTests(unittest.TestCase):
    def test_relocated_hook_with_spaces(self):
        with tempfile.TemporaryDirectory(prefix="votal customer path ") as directory:
            target = Path(directory) / "relocated plugin"
            shutil.copytree(PLUGIN, target, ignore=shutil.ignore_patterns("__pycache__"))
            config = json.loads((target / "hooks/hooks.json").read_text())
            command = config["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"]
            env = os.environ.copy()
            env.pop("VOTAL_API_KEY", None)
            env["PLUGIN_ROOT"] = str(target)
            result = subprocess.run(command, shell=True, input=json.dumps(EVENT), capture_output=True, text=True, env=env, cwd=directory, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            decision = json.loads(result.stdout)
            self.assertEqual(decision["decision"], "block")
            self.assertIn("not configured", decision["reason"])

    def test_catalog_and_manifest(self):
        catalog = json.loads((KIT / ".agents/plugins/marketplace.json").read_text())
        self.assertEqual((KIT / catalog["plugins"][0]["source"]["path"]).resolve(), PLUGIN.resolve())
        manifest = json.loads((PLUGIN / "plugin.json").read_text())
        legacy = json.loads((PLUGIN / ".codex-plugin/plugin.json").read_text())
        self.assertEqual(manifest["version"], "0.2.0")
        self.assertEqual(legacy["version"], manifest["version"])
        self.assertTrue(manifest["extensions"]["com.openai"]["requires_local_executor"])
        self.assertEqual(manifest["extensions"]["com.openai"]["hooks"], "./hooks/hooks.json")


class LauncherTests(unittest.TestCase):
    def invoke(self, verdict, args):
        out = io.StringIO()
        with patch.dict(os.environ, {"VOTAL_API_KEY": "synthetic-fixture"}, clear=True), patch.object(sys, "argv", ["start_guarded.py"] + args), patch.object(launcher, "resolve_command", return_value=["fake-codex"]), patch.object(gate, "evaluate", return_value=verdict), patch.object(launcher.subprocess, "call", return_value=0) as child, contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = launcher.main()
            if child.called:
                self.assertEqual(child.call_args.kwargs["env"]["VOTAL_API_KEY"], "synthetic-fixture")
                self.assertFalse(child.call_args.kwargs["shell"])
        self.assertNotIn("synthetic-fixture", out.getvalue())
        return code, child.called

    def test_preflight_block_does_not_launch(self):
        self.assertEqual(self.invoke({"decision": "block", "reason": "Synthetic block"}, ["--cli"]), (1, False))

    def test_preflight_allow_launches(self):
        self.assertEqual(self.invoke({}, ["--cli"]), (0, True))

    def test_check_does_not_launch(self):
        self.assertEqual(self.invoke({}, ["--check"]), (0, False))


if __name__ == "__main__":
    unittest.main()
