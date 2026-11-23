"""確認工作流程只使用已鎖定的工具，以及管理設定在缺少沙箱時停止執行。"""
import json
from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]


class EnvironmentControls(unittest.TestCase):
    def test_locked_tool_installation(self):
        directory = ROOT / "config/promptfoo/tooling"
        manifest = json.loads((directory / "package.json").read_text())
        packages = json.loads((directory / "package-lock.json").read_text())["packages"]
        self.assertEqual(packages[""]["dependencies"], manifest["dependencies"])
        self.assertEqual(packages["node_modules/promptfoo"]["version"], manifest["dependencies"]["promptfoo"])
        for name, entry in packages.items():
            if name:
                with self.subTest(package=name):
                    self.assertTrue(entry["resolved"].startswith("https://registry.npmjs.org/"))
                    self.assertRegex(entry["integrity"], r"^sha512-[A-Za-z0-9+/]{86}==$")

        workflow = yaml.safe_load((ROOT / ".github/workflows/staging-blackbox.yml").read_text())
        steps = {s["id"]: s for j in workflow["jobs"].values() for s in j["steps"] if "id" in s}
        install = steps["promptfoo_install"]
        self.assertEqual(install["working-directory"], "_trusted/config/promptfoo/tooling")
        self.assertIn("npm ci --ignore-scripts", install["run"])
        self.assertNotIn("env", install)
        for name in ("pfeval", "pfred"):
            self.assertIn("steps.promptfoo_install.outcome == 'success'", steps[name]["if"])
            self.assertNotIn("npx ", steps[name]["run"])
            self.assertIn("_trusted/config/promptfoo/tooling/node_modules/.bin/promptfoo", steps[name]["run"])

    def test_managed_sandbox(self):
        settings = json.loads((ROOT / "config/claude/managed-settings.json").read_text())
        sandbox = settings["sandbox"]
        self.assertIs(sandbox["enabled"], True)
        self.assertIs(sandbox["failIfUnavailable"], True)
        self.assertIs(sandbox["allowUnsandboxedCommands"], False)
        self.assertEqual(sandbox["network"]["allowedDomains"], [])
        self.assertIs(sandbox["network"]["strictAllowlist"], True)
        self.assertIs(sandbox["network"]["allowManagedDomainsOnly"], True)
        self.assertIs(settings["allowManagedMcpServersOnly"], True)
        self.assertEqual(settings["allowedMcpServers"], [])
        self.assertEqual(settings["permissions"]["disableBypassPermissionsMode"], "disable")
        self.assertTrue({"WebFetch", "WebSearch"}.issubset(settings["permissions"]["deny"]))
