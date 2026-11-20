#!/usr/bin/env python3
"""G1 供應鏈快篩（本機 pre-commit 版）— 四層防禦的輕量實作。

與 .github/workflows/pr-gates.yml 的內嵌 G1 檢查對齊。純 stdlib。
四層：(1) registry 存在性 + 週下載量；(2) 名稱相似度 vs popular 清單 + blacklist；
      (3) 安裝階段 hook（npm postinstall/preinstall/install）；(4) 新套件冷卻期。

原則（AGENTS.md #2）：網路失敗、registry 無法查詢、鎖定檔尚無解析器 → 標記 incomplete，絕不視為通過。
退出碼：0 無阻擋；1 有 blocking 發現；2 無法完成檢查（incomplete）。
用法：python3 scripts/g1_slopcheck.py [--target <dir>] [--staged] [--manifest <path> ...] [--rules-file <path> ...]
      [--changed-files <list>] [--base <ref>] [--sarif <out>] [--gate <out>] | selftest | --help

--target <dir>：被掃描的專案根目錄（預設本 repo）。設定、清單與阻擋政策一律取自本 repo；
  相對路徑、--staged、--changed-files、--base 都以目標專案為準。只給 --target、沒指定要掃哪些檔時，
  全量掃描目標專案追蹤中的所有 manifest 與 agent 規則檔（scope: full）。
  blocking-policy 的 exceptions 只核准給本 repo 的路徑，掃其他專案時不套用（fail closed）。
"""
from __future__ import annotations
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent      # VibeSec 本身：設定、清單、政策
sys.path.insert(0, str(Path(__file__).resolve().parent))
import gate_result  # noqa: E402
from g1_git import SubprocessGit, head_commit  # noqa: E402
from g1_screen import (  # noqa: E402
    CONTROL_OF,       # 相容匯出：供 scripts/run_evals.py 使用，#267（S6）遷移後移除
    Outcome,
    Request,
    TOOL_NAME,
    TOOL_VERSION,
    build_env,
    cfg,              # 相容匯出：供 scripts/run_evals.py G1FixtureRunner 使用，#267（S6）遷移後移除
    cooldown_finding,  # 相容匯出：供 scripts/run_evals.py G1FixtureRunner 使用，#267（S6）遷移後移除
    default_env,      # 相容匯出：供 scripts/run_evals.py G1FixtureRunner 使用，#267（S6）遷移後移除
    dumps_json,
    install_hook_finding,  # 相容匯出：供 scripts/run_evals.py G1FixtureRunner 使用，#267（S6）遷移後移除
    screen,
)

__all__ = [
    "CONTROL_OF",
    "ROOT",
    "cfg",
    "cooldown_finding",
    "default_env",
    "install_hook_finding",
    "main",
    "selftest",
]


def _opt(args, name):
    """收集重複出現的 `--name value` 參數。"""
    return [args[i + 1] for i, a in enumerate(args[:-1]) if a == name]


def _write_json(path, doc):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(dumps_json(doc), encoding="utf-8")


def main(argv, policy_root=ROOT, *, env=None, registry=None):
    """唯一有副作用的薄入口：解析命令列旗標、載入政策、呼叫 screen（或 Outcome.unreadable）、
    印標準輸出與標準錯誤結果行、寫 SARIF（無 SARIF 檢視時刪除舊檔）與閘門結果、回傳退出碼。"""
    args = argv[1:]
    if "--help" in args or "-h" in args:
        print(__doc__.strip())
        return 0
    if args[:1] == ["selftest"]:
        fails = selftest()
        for f in fails:
            print(f"FAIL {f}")
        print("selftest " + ("通過" if not fails else f"失敗 {len(fails)} 項"))
        return 1 if fails else 0
    started = gate_result.now()
    target = (_opt(args, "--target") or [None])[-1]
    root = ROOT
    if target:
        root = Path(target).expanduser().resolve()
        if not root.is_dir():
            print(f"⚠️ G1 無法完成檢查：--target 不是目錄（{target}）→ incomplete。", file=sys.stderr)
            return 2
    request = Request(target=root if target else None, manifests=tuple(_opt(args, "--manifest")),
                      rule_files=tuple(_opt(args, "--rules-file")), changed_lists=tuple(_opt(args, "--changed-files")),
                      staged="--staged" in args, base=(_opt(args, "--base") or [None])[-1])
    sarif_out = (_opt(args, "--sarif") or [None])[-1]
    gate_out = (_opt(args, "--gate") or [None])[-1]
    commit = head_commit(root) if gate_out else None
    if env is not None:
        problem = None
    else:
        env, problem = default_env(root, policy_root, registry=registry)
    outcome = Outcome.unreadable(problem, request, config_root=policy_root) if problem else screen(request, env)
    stdout_doc = outcome.to_stdout()
    if stdout_doc is not None:
        print(dumps_json(stdout_doc))
    if sarif_out:
        sarif_doc = outcome.to_sarif()
        if sarif_doc is None:
            gate_result.remove_stale(sarif_out)
        else:
            _write_json(sarif_out, sarif_doc)
    if gate_out:
        _write_json(gate_out, outcome.to_gate_result(started, commit, sarif_ref=sarif_out))
    print(outcome.result_line(), file=sys.stderr)
    return outcome.exit_code


def selftest():
    """命令列入口契約與整合案例自我測試（直接呼叫內部函式的單元案例已搬至 tests/test_g1_screen.py；
    其餘命令列驅動案例將於 #268 S7 對照總表收斂）。"""
    import contextlib
    import dataclasses
    from datetime import datetime, timezone
    import io
    import re
    import shutil
    import subprocess
    import tempfile
    from jsonschema import Draft202012Validator
    import yaml
    from g1_registry import Facts, Found
    from vibesec_policy import POLICY_UNREADABLE, Policy, broken_policy_root, set_mode_line, temp_policy_root

    fails = []
    schema = Draft202012Validator(json.loads((ROOT / "schemas/gate-result.schema.json").read_text(encoding="utf-8")))
    calls = []
    requires_of = {}
    boom = set()

    class StubRegistry:
        def facts(self, eco, name, ver):
            calls.append((name, ver))
            if name in boom:
                raise RuntimeError("selftest 意外")
            npm = eco == "npm"
            return Found(Facts(eco, name, ver or "0.0.1", datetime.now(timezone.utc).isoformat(), {} if npm else None, 10 ** 6 if npm else None))

        def requires(self, name, ver):
            return set(requires_of.get(name.lower(), ()))

    class CleanRegistry:
        def __init__(self):
            self.queried = []

        def facts(self, eco, name, ver):
            self.queried.append(name)
            npm = eco == "npm"
            return Found(Facts(eco, name, ver or "1.0.0", "2020-01-01T00:00:00Z", {} if npm else None, 10 ** 6 if npm else None))

        def requires(self, name, ver):
            return set()

    CR = Path(tempfile.mkdtemp())
    shutil.copytree(ROOT / "config" / "slopsquat", CR / "config" / "slopsquat")
    shutil.copy(ROOT / "vibesec.yaml", CR / "vibesec.yaml")

    def set_allow(entries):
        (CR / "config/slopsquat/allowlist.yaml").write_text(yaml.safe_dump({"version": 1, "entries": entries}), encoding="utf-8")
    set_allow([])

    PR = Path(tempfile.mkdtemp())
    (PR / "config/policy").mkdir(parents=True)
    pol = yaml.safe_load((ROOT / "config/policy/blocking-policy.yaml").read_text(encoding="utf-8"))
    pol["exceptions"] = [
        {"rule_id": "vibesec.g1.cooldown-violation", "path_glob": "examples/vulnapp/**",
         "reason": "selftest", "approved_by": "selftest", "expires": "2099-12-31"},
        {"rule_id": "vibesec.g1.cooldown-violation", "path_glob": "nowhere/**",
         "reason": "selftest", "approved_by": "selftest", "expires": "2020-01-01"},
        {"rule_id": "vibesec.g2.hardcoded-secret", "path_glob": "nowhere/**",
         "reason": "selftest", "approved_by": "selftest", "expires": "2020-01-01"},
    ]
    (PR / "config/policy/blocking-policy.yaml").write_text(yaml.safe_dump(pol, allow_unicode=True), encoding="utf-8")
    shutil.copy(ROOT / "vibesec.yaml", PR / "vibesec.yaml")
    (PR / "examples/vulnapp").mkdir(parents=True)
    shutil.copy(ROOT / "examples/vulnapp/pyproject.toml", PR / "examples/vulnapp/pyproject.toml")
    env = build_env(Policy(PR, project_root=None), git=None, registry=StubRegistry(), config_root=CR)

    def run(*argv):
        out, err = io.StringIO(), io.StringIO()
        target_arg = (_opt(list(argv), "--target") or [None])[-1]
        scan_root = Path(target_arg).expanduser().resolve() if target_arg else ROOT
        run_env = dataclasses.replace(env, git=SubprocessGit(scan_root))
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["g1_slopcheck.py", *argv], env=run_env)
        return code, (json.loads(out.getvalue()) if out.getvalue().strip() else {})

    def git(d, *a):
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *a], cwd=d, capture_output=True, check=True)

    try:
        with tempfile.TemporaryDirectory() as d:
            D = Path(d)
            (D / "examples/vulnapp").mkdir(parents=True)
            (D / "examples/vulnapp/requirements.txt").write_text("requests==2.0.0\n")
            (D / "deploy").mkdir()
            (D / "deploy/python-requirements.txt").write_text("fastapi==0.1.0 \\\n    --hash=sha256:00\n")
            (D / "frontend").mkdir()
            (D / "frontend/yarn.lock").write_text("# yarn lockfile v1\n")
            (D / "README.md").write_text("沒有安裝指令。\n")
            (D / "node_modules/x").mkdir(parents=True)
            (D / "node_modules/x/package.json").write_text('{"dependencies": {"evil": "1.0.0"}}')
            git(D, "init", "-q")
            git(D, "add", "examples", "deploy", "frontend", "README.md")
            git(D, "commit", "-qm", "t")
            gate = D.parent / f"{D.name}-gate.json"
            code, out = run("--target", str(D), "--gate", str(gate))
            pkgs = {f["package"]: f for f in out.get("findings", [])}
            if set(pkgs) != {"requests", "fastapi"}:
                fails.append(f"只給 --target → 全量掃描 requirements（含 python-requirements.txt），不掃 node_modules（得到 {sorted(pkgs)}）")
            if pkgs.get("requests", {}).get("policy_tier") != "blocking" or "exception" in pkgs.get("requests", {}):
                fails.append("外部目標：本 repo 的 examples/vulnapp/** 例外不得套用（仍為 blocking）")
            if pkgs.get("fastapi", {}).get("manifest") != "deploy/python-requirements.txt":
                fails.append("manifest 路徑相對目標專案根目錄")
            if code != 1 or out.get("status") != "fail" or "frontend/yarn.lock" not in out.get("status_reason", "") \
                    or not any("frontend/yarn.lock" in x for x in out.get("incomplete_checks", [])):
                fails.append(f"尚無解析器的鎖定檔 → 列入未完成原因（blocking 優先記 fail）（exit {code}，{out.get('status')}：{out.get('status_reason')}）")
            g = json.loads(gate.read_text(encoding="utf-8"))
            gate.unlink()
            errs = list(schema.iter_errors(g))
            if errs:
                fails.append(f"gate JSON 不符 schema：{errs[0].message}")
            if [c["control_id"] for c in g["coverage"] if c["state"] == "pending"] != ["VS-G1-SBOM", "ASVS5-V15.2"]:
                fails.append(f"gate JSON 應預留 SBOM 與 KEV 的 pending（沒併入時最終判定視同未實測）：{g['coverage']}")
            head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=D).stdout.strip()
            if g.get("commit") != head or g.get("scope") != "full" or "exceptions" not in (g.get("status_reason") or ""):
                fails.append("gate JSON 的 commit 取目標專案 HEAD、scope full、status_reason 註明例外未套用")

            reg = lambda n, v: f"https://registry.npmjs.org/{n}/-/{n.split('/')[-1]}-{v}.tgz"
            lock = {"lockfileVersion": 3, "packages": {
                "": {"dependencies": {"playwrigth": "1.0.0", "strip-cjs": "npm:strip-ansi@6.0.1"}},
                "node_modules/playwrigth": {"version": "1.0.0", "resolved": reg("playwrigth", "1.0.0")},
                "node_modules/playwright-core": {"version": "1.63.0", "resolved": reg("playwright-core", "1.63.0")},
                "node_modules/loadsh": {"version": "0.0.4", "resolved": reg("loadsh", "0.0.4")},
                "node_modules/strip-cjs": {"name": "strip-ansi", "version": "6.0.1", "resolved": reg("strip-ansi", "6.0.1")},
                "node_modules/a/node_modules/strip-ansi": {"version": "6.0.1", "resolved": reg("strip-ansi", "6.0.1")},
                "node_modules/gitdep": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/x/gitdep.git#abc"},
                "node_modules/ws-local": {"resolved": "packages/ws-local", "link": True},
                "packages/ws-local": {"version": "0.1.0"},
            }}
            (D / "web").mkdir()
            (D / "web/package-lock.json").write_text(json.dumps(lock))
            calls.clear()
            code, out = run("--target", str(D), "--manifest", "web/package-lock.json")
            hall = {f["package"] for f in out.get("findings", []) if f["rule_id"] == "vibesec.g1.hallucinated-package"}
            if hall != {"playwrigth", "loadsh"}:
                fails.append(f"直接相依做名稱相似度、間接相依只查黑名單（hallucinated 得到 {sorted(hall)}）")
            if sorted(calls) != [("loadsh", "0.0.4"), ("playwright-core", "1.63.0"), ("playwrigth", "1.0.0"), ("strip-ansi", "6.0.1")]:
                fails.append(f"registry 每個 (名稱, 版本) 只查一次、間接相依也要查（得到 {sorted(calls)}）")
            if out.get("status") != "fail" or "node_modules/gitdep" not in out.get("status_reason", ""):
                fails.append("非 npm registry 來源的條目 → 列入未完成原因（替身有 blocking，記 fail）")

            (D / "boom").mkdir()
            (D / "boom/package.json").write_text(json.dumps({"dependencies": {"fine-pkg": "1.0.0", "boom-pkg": "1.0.0", "other-pkg": "2.0.0"}}))
            boom.add("boom-pkg")
            try:
                calls.clear()
                code, out = run("--target", str(D), "--manifest", "boom/package.json")
            finally:
                boom.clear()
            if sorted(calls) != [("boom-pkg", "1.0.0"), ("fine-pkg", "1.0.0"), ("other-pkg", "2.0.0")]:
                fails.append(f"單一套件的檢查丟出意外錯誤時，其他套件仍要查（查詢 {sorted(calls)}）")
            if {f["package"] for f in out.get("findings", [])} != {"fine-pkg", "other-pkg"}:
                fails.append(f"單一套件失敗不得影響其他套件的發現（得到 {[f['package'] for f in out.get('findings', [])]}）")
            if not any("boom-pkg" in x and "未預期" in x and "RuntimeError" in x for x in out.get("incomplete_checks") or []):
                fails.append(f"失敗的那一個套件要記成未完成原因，不是崩潰也不是通過（得到 {out.get('incomplete_checks')}）")
            if code not in (1, 2):
                fails.append(f"單一套件失敗時整批仍要正常結束（exit 1 或 2，不是崩潰；得到 {code}）")

            set_allow([{"package": "fastapi", "ecosystem": "pypi", "version": "0.1.0", "bypass": ["cooldown"],
                        "approved_by": "a@x", "expires": "2099-12-31", "ticket": "SEC-9", "reason": "selftest"}])
            calls.clear()
            code, out = run("--target", str(D), "--manifest", "deploy/python-requirements.txt")
            set_allow([])
            fa = [f for f in out.get("findings", []) if f["package"] == "fastapi"]
            if calls != [("fastapi", "0.1.0")] or [f["policy_tier"] for f in fa] != ["advisory"] or code != 2:
                fails.append(f"allowlist 內的套件仍要查 registry，放行的發現降為 advisory（查詢 {calls}，發現 {fa}，exit {code}）")
            elif out.get("status") != "incomplete" or "VS-G1-INSTALL-HOOK" not in (out.get("status_reason") or ""):
                fails.append(f"PyPI 安裝腳本未檢查 → stdout 應為 incomplete 並列出 VS-G1-INSTALL-HOOK（得到 {out.get('status')}：{out.get('status_reason')}）")

            set_allow([{"package": "fastapi", "ecosystem": "pypi", "version": "0.1.0", "bypass": ["cooldown"],
                        "approved_by": "a@x", "expires": "2099-12-31", "ticket": "SEC-9", "reason": "selftest"}])
            gate = D.parent / f"{D.name}-hook-gate.json"
            code, _ = run("--target", str(D), "--manifest", "deploy/python-requirements.txt", "--gate", str(gate))
            set_allow([])
            g = json.loads(gate.read_text(encoding="utf-8"))
            gate.unlink()
            hook = next((c for c in g.get("coverage", []) if c["control_id"] == "VS-G1-INSTALL-HOOK"), {})
            if code != 2 or g.get("status") != "incomplete" or hook.get("state") != "untested" \
                    or "VS-G1-INSTALL-HOOK" not in (g.get("status_reason") or ""):
                fails.append(f"coverage 有 untested → gate 應為 incomplete 並說明（exit {code}，{g.get('status')}，{g.get('status_reason')}）")
            elif list(schema.iter_errors(g)):
                fails.append(f"untested 的 gate JSON 不符 schema：{list(schema.iter_errors(g))[0].message}")

            (D / "py").mkdir()
            (D / "py/requirements.lock.txt").write_text("openai==2.0.0 \\\n    --hash=sha256:00\nhttpx2==2.13.1\n"
                                                        "reqursts==1.0.0\nlanggraph==1.0.0\nlanggraph-sdk==0.4.5\n")
            requires_of.update({"openai": {"httpx2", "openai"}, "langgraph": {"langgraph-sdk"}, "reqursts": {"reqursts"}})
            code, out = run("--target", str(D), "--manifest", "py/requirements.lock.txt")
            hall = {f["package"] for f in out.get("findings", []) if f["rule_id"] == "vibesec.g1.hallucinated-package"}
            if hall != {"reqursts"}:
                fails.append(f"requirements 鎖定檔：間接相依（httpx2、langgraph-sdk）只查黑名單，自己需要自己不算（得到 {sorted(hall)}）")
            requires_of.clear()
            code, out = run("--target", str(D), "--manifest", "py/requirements.lock.txt")
            hall = {f["package"] for f in out.get("findings", []) if f["rule_id"] == "vibesec.g1.hallucinated-package"}
            if "httpx2" not in hall:
                fails.append(f"查不到 requires_dist 時照直接相依比對（得到 {sorted(hall)}）")
            code, out = run("--target", str(D), "--manifest", "examples/vulnapp/requirements.txt")
            if [f["package"] for f in out.get("findings", [])] != ["requests"] or code != 1:
                fails.append("--target 搭配 --manifest：相對路徑以目標專案為準，只掃指定的檔")

        gate, sarif_p = PR / "gate.json", PR / "g1.sarif"
        code, out = run("--target", str(PR), "--manifest", "examples/vulnapp/pyproject.toml", "--gate", str(gate), "--sarif", str(sarif_p))
        want_ex = {"path_glob": "examples/vulnapp/**", "reason": "selftest", "approved_by": "selftest", "expires": "2099-12-31",
                   "agent_id": None}
        if not out.get("findings") or any(f["policy_tier"] != "advisory" or f.get("exception") != want_ex for f in out["findings"]):
            fails.append(f"目標是本 repo 時照常套用 blocking-policy 例外（降為 advisory、附固定 5 欄核准資訊）：{out.get('findings')}")
        props = [r["properties"].get("exception") for run_ in json.loads(sarif_p.read_text(encoding="utf-8"))["runs"] for r in run_["results"]]
        if not props or any(x != want_ex for x in props):
            fails.append(f"SARIF properties.exception 與 finding 相同（固定 5 欄）：{props}")
        if out.get("ignored_exceptions") != ["vibesec.g1.cooldown-violation @ nowhere/**：已於 2020-01-01 過期",
                                             "vibesec.g2.hardcoded-secret @ nowhere/**：已於 2020-01-01 過期"]:
            fails.append(f"stdout 的 ignored_exceptions 列出全部忽略的例外：{out.get('ignored_exceptions')}")
        why = json.loads(gate.read_text(encoding="utf-8")).get("status_reason") or ""
        if "忽略的例外：vibesec.g1.cooldown-violation @ nowhere/**：已於 2020-01-01 過期" not in why or "hardcoded-secret" in why:
            fails.append(f"G1 的 status_reason 列出本閘門忽略的例外、不列其他閘門的：{why}")

        W = Path(tempfile.mkdtemp())
        (W / "examples/vulnapp").mkdir(parents=True)
        shutil.copy(ROOT / "examples/vulnapp/pyproject.toml", W / "examples/vulnapp/pyproject.toml")
        env_saved = env
        try:
            for proj, label in ((W, "project_root＝受驗樹"), (None, "沒有 project_root")):
                env = dataclasses.replace(env_saved, policy=Policy(PR, project_root=proj))
                gate = W / "gate.json"
                code, out = run("--target", str(W), "--manifest", "examples/vulnapp/pyproject.toml", "--gate", str(gate))
                why = json.loads(gate.read_text(encoding="utf-8")).get("status_reason") or ""
                n = len(out.get("findings") or [])
                if proj is not None:
                    if not n or any(f.get("exception") != want_ex for f in out["findings"]) or "target" in out \
                            or f"{n} 筆命中 blocking-policy 例外（blocking 降為 advisory，發現保留）" not in why or "未套用" in why:
                        fails.append(f"CI 形狀，{label} → 本 repo：例外套用並註明命中筆數（{why}；{out.get('findings')}）")
                elif any(f.get("exception") for f in out.get("findings") or []) or "未套用" not in why:
                    fails.append(f"CI 形狀，{label} → 外部專案，例外未套用（{why}）")
        finally:
            env = env_saved
            shutil.rmtree(W, ignore_errors=True)

        code, _ = run("--target", str(ROOT / "no-such-dir"))
        if code != 2:
            fails.append("--target 不是目錄 → exit 2（incomplete）")

        with tempfile.TemporaryDirectory() as d:
            D = Path(d)
            gate = D.parent / f"{D.name}-gate.json"
            code, out = run("--target", str(D), "--staged", "--gate", str(gate))
            g = json.loads(gate.read_text(encoding="utf-8")) if gate.exists() else {}
            if code != 2 or g.get("status") != "incomplete" or g.get("scope") != "diff":
                fails.append(f"非 git 目錄 --staged → incomplete（exit 2、scope diff），不是「沒有變更」（exit {code}，{g.get('status')}）")
            code, out = run("--target", str(D), "--manifest", "no-such/requirements.txt", "--gate", str(gate))
            g = json.loads(gate.read_text(encoding="utf-8"))
            if code != 2 or g.get("status") != "incomplete" or "no-such/requirements.txt" not in (g.get("status_reason") or ""):
                fails.append(f"--manifest 指定的檔不存在 → incomplete 並列出（exit {code}，{g.get('status_reason')}）")
            (D / "AGENTS.md").write_text("沒有安裝指令。\n")
            (D / "requirements.txt").write_text("requests==2.0.0\n")
            git(D, "init", "-q")
            git(D, "add", ".")
            git(D, "commit", "-qm", "a")
            first = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=D).stdout.strip()
            git(D, "rm", "-q", "requirements.txt")
            git(D, "commit", "-qm", "b")
            lst = D / "changed.txt"
            lst.write_text("requirements.txt\nAGENTS.md\n")
            code, out = run("--target", str(D), "--changed-files", str(lst), "--base", first, "--gate", str(gate))
            g = json.loads(gate.read_text(encoding="utf-8"))
            if code != 0 or g.get("status") != "pass" or "requirements.txt" not in (g.get("status_reason") or ""):
                fails.append(f"--changed-files：diff 刪掉的 manifest 正常略過並註記（exit {code}，{g.get('status')}，{g.get('status_reason')}）")
            lst.write_text("ghost/requirements.txt\n")
            code, out = run("--target", str(D), "--changed-files", str(lst), "--base", first, "--gate", str(gate))
            g = json.loads(gate.read_text(encoding="utf-8"))
            if code != 2 or "ghost/requirements.txt" not in (g.get("status_reason") or ""):
                fails.append(f"--changed-files 列的檔在 HEAD 與 base 都不存在 → incomplete（exit {code}，{g.get('status_reason')}）")
            lst.write_text("AGENTS.md\n")
            code, out = run("--target", str(D), "--changed-files", str(lst), "--gate", str(gate))
            g = json.loads(gate.read_text(encoding="utf-8"))
            if g.get("scope") != "diff":
                fails.append(f"--changed-files 沒給 --base 也是 scope diff（得到 {g.get('scope')}）")
            gate.unlink()

        with tempfile.TemporaryDirectory() as d:
            D, C = Path(d) / "proj", Path(d) / "cfg"
            D.mkdir()
            (D / "package.json").write_text(json.dumps({"dependencies": {"express": "4.21.2"}}))
            git(D, "init", "-q")
            git(D, "add", "package.json")
            git(D, "commit", "-qm", "t")
            cases = [
                ("完整設定（對照組）", None, None),
                ("cooldown.yaml 缺席", "cooldown.yaml", None),
                ("cooldown.yaml 語法錯誤", "cooldown.yaml", "thresholds: [\n"),
                ("cooldown.yaml 不是 mapping", "cooldown.yaml", "- a\n"),
                ("blacklist.yaml 缺席", "blacklist.yaml", None),
                ("blacklist.yaml 語法錯誤", "blacklist.yaml", "packages: {\n"),
                ("blacklist.yaml 不是 mapping 或清單", "blacklist.yaml", "just-a-string\n"),
                ("popular-npm.txt 缺席", "popular-npm.txt", None),
                ("popular-pypi.txt 缺席", "popular-pypi.txt", None),
                ("vibesec.yaml 缺席", "vibesec.yaml", None),
                ("vibesec.yaml 語法錯誤", "vibesec.yaml", "gates: [\n"),
            ]
            for label, broken, content in cases:
                shutil.rmtree(C, ignore_errors=True)
                shutil.copytree(ROOT / "config" / "slopsquat", C / "config" / "slopsquat")
                shutil.copy(ROOT / "vibesec.yaml", C / "vibesec.yaml")
                if broken:
                    broken_path = C / "vibesec.yaml" if broken == "vibesec.yaml" else C / "config" / "slopsquat" / broken
                    broken_path.unlink()
                    if content is not None:
                        broken_path.write_text(content)
                env_saved = env
                env = build_env(env_saved.policy, git=None, registry=CleanRegistry(), config_root=C)
                try:
                    code, out = run("--target", str(D))
                except Exception as e:
                    code, out = f"例外 {type(e).__name__}", {}
                finally:
                    env = env_saved
                if broken is None:
                    if code != 0 or out.get("status"):
                        fails.append(f"設定檔：{label} → pass（exit {code}，{out.get('status')}：{out.get('status_reason')}）")
                elif code != 2 or out.get("status") != "incomplete" \
                        or not any(broken in x for x in out.get("incomplete_checks") or []):
                    fails.append(f"設定檔：{label} → incomplete 並在 incomplete_checks 列出 {broken}"
                                 f"（exit {code}，{out.get('status')}，{out.get('incomplete_checks')}）")
    finally:
        shutil.rmtree(PR, ignore_errors=True)

    # --help／-h：印用法、exit 0，不執行掃描
    for flag in ("--help", "-h"):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = main(["g1_slopcheck.py", flag])
        if code != 0 or "用法" not in out.getvalue() or '"findings"' in out.getvalue():
            fails.append(f"{flag} 應印用法並 exit 0（exit {code}）")

    # 政策檔讀不到 → 進入點就停：G1 gate incomplete、沒有發現、刪舊 SARIF、退出碼 2（不查 registry）
    with broken_policy_root() as pr, tempfile.TemporaryDirectory() as d, \
            contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        gp, sp = Path(d, "G1.json"), Path(d, "G1.sarif")
        sp.write_text('{"stale": true}', encoding="utf-8")
        code = main(["g1_slopcheck.py", "--manifest", str(ROOT / "requirements-ci.in"), "--gate", str(gp),
                     "--sarif", str(sp)], policy_root=pr)
        g = json.loads(gp.read_text(encoding="utf-8")) if gp.is_file() else {}
        stale = sp.exists()
    cov = [(c["control_id"], c["state"], (c["reason"] or "").startswith(POLICY_UNREADABLE)) for c in g.get("coverage") or []]
    iso = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00$")
    if code != 2 or g.get("status") != "incomplete" or POLICY_UNREADABLE not in (g.get("status_reason") or "") \
            or g.get("findings_count") != {"blocking": 0, "advisory": 0} \
            or g.get("tools") != [gate_result.tool(TOOL_NAME, "error", version=TOOL_VERSION)] \
            or cov != [("VS-G1-SLOPSQUAT", "untested", True), ("VS-G1-COOLDOWN", "untested", True),
                       ("VS-G1-INSTALL-HOOK", "untested", True), ("VS-G1-SBOM", "pending", False), ("ASVS5-V15.2", "pending", False)] \
            or stale or list(schema.iter_errors(g)) \
            or not (iso.match(g.get("started_at") or "") and iso.match(g.get("finished_at") or "")):
        fails.append(f"政策檔讀不到 → 退出碼 2、G1 incomplete 並寫明原因、沒有發現、tool 只有一列 error、三個控制 untested"
                     f"（原因＝政策讀不到）、SBOM／KEV pending、舊 SARIF 刪掉、時間戳 +00:00（得到 {code}、舊 SARIF 存在={stale}、{g}）")

    # risk_tier 打錯 → 省略 risk_tier 欄位，不拋例外
    with temp_policy_root() as pr, tempfile.TemporaryDirectory() as d, \
            contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        vbp = pr / "vibesec.yaml"
        text, n = re.subn(r"(?m)^risk_tier:.*$", "risk_tier: l3", vbp.read_text(encoding="utf-8"), count=1)
        if n != 1:
            fails.append("selftest 前置：vibesec.yaml 找不到最上層的 risk_tier，無法製造打錯的情境")
        vbp.write_text(text, encoding="utf-8")
        gp = Path(d, "G1.json")
        try:
            code = main(["g1_slopcheck.py", "--manifest", str(ROOT / "requirements-ci.in"), "--gate", str(gp)], policy_root=pr)
            g = json.loads(gp.read_text(encoding="utf-8")) if gp.is_file() else {}
            if code != 2 or g.get("status") != "incomplete" or "risk_tier" in g:
                fails.append(f"risk_tier 打錯 → 退出碼 2、incomplete、沒有 risk_tier 欄位（得到 {code}、{g.get('status')}、{g.get('risk_tier')!r}）")
        except Exception as e:
            fails.append(f"risk_tier 打錯 → 不得拋例外（得到 {type(e).__name__}：{e}）")

    # mode 缺席或不合法 → 政策讀不到、mode 記 enforce、不查 registry、刪舊 SARIF、退出碼 2
    rec = CleanRegistry()
    queried = rec.queried
    with tempfile.TemporaryDirectory() as d, temp_policy_root() as pr:
        D = Path(d) / "proj"
        D.mkdir()
        (D / "package.json").write_text(json.dumps({"dependencies": {"express": "4.21.2"}}))
        git(D, "init", "-q")
        git(D, "add", "package.json")
        git(D, "commit", "-qm", "t")
        vbp = pr / "vibesec.yaml"
        real_text = vbp.read_text(encoding="utf-8")
        for label, line in [("缺席", ""), ("x", "mode: x"), ("Enforce", "mode: Enforce"), ("空字串", 'mode: ""'),
                            ("shadow", "mode: shadow"), ("enforce", "mode: enforce"), ("整個檔缺席", None),
                            ("整個檔語法錯誤", ("gates: [\n",)), ("整個檔不是 mapping", ("- a\n",))]:
            gp, sp = Path(d, "G1.json"), Path(d, "G1.sarif")
            if line is None:
                vbp.unlink(missing_ok=True)
            elif isinstance(line, tuple):
                vbp.write_text(line[0], encoding="utf-8")
            else:
                vbp.write_text(real_text, encoding="utf-8")
                set_mode_line(vbp, line)
            gp.unlink(missing_ok=True)
            sp.write_text('{"stale": true}', encoding="utf-8")
            queried.clear()
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    code = main(["g1_slopcheck.py", "--target", str(D), "--gate", str(gp), "--sarif", str(sp)],
                                policy_root=pr, registry=rec)
            except Exception as e:
                fails.append(f"mode {label} → 不得拋例外（得到 {type(e).__name__}：{e}）")
                continue
            g = json.loads(gp.read_text(encoding="utf-8")) if gp.is_file() else {}
            if label in ("shadow", "enforce"):
                if code != 0 or g.get("status") != "pass" or g.get("mode") != label or queried != ["express"]:
                    fails.append(f"mode {label} → 照常執行、閘門結果的 mode 取自政策（得到 exit {code}、{g.get('status')}、"
                                 f"mode={g.get('mode')}、查詢 {queried}）")
                continue
            why = g.get("status_reason") or ""
            about_mode = isinstance(line, str)
            cov = [(c["control_id"], c["state"], (c["reason"] or "").startswith(POLICY_UNREADABLE)) for c in g.get("coverage") or []]
            if code != 2 or g.get("status") != "incomplete" or not why.startswith(POLICY_UNREADABLE + "（") \
                    or (about_mode and "mode" not in why) \
                    or g.get("mode") != "enforce" or g.get("findings_count") != {"blocking": 0, "advisory": 0} \
                    or g.get("tools") != [gate_result.tool(TOOL_NAME, "error", version=TOOL_VERSION)] \
                    or cov != [("VS-G1-SLOPSQUAT", "untested", True), ("VS-G1-COOLDOWN", "untested", True),
                               ("VS-G1-INSTALL-HOOK", "untested", True), ("VS-G1-SBOM", "pending", False),
                               ("ASVS5-V15.2", "pending", False)] \
                    or queried or sp.exists() or list(schema.iter_errors(g)):
                fails.append(f"mode {label} → 退出碼 2、incomplete（政策讀不到）、mode 記 enforce、三個控制 untested、"
                             f"SBOM／KEV pending、tool 列只有一列 error、不查 registry、舊 SARIF 刪掉（得到 exit {code}、"
                             f"查詢 {queried}、舊 SARIF 存在={sp.exists()}、{g}）")

    shutil.rmtree(CR, ignore_errors=True)
    return fails


if __name__ == "__main__":
    sys.exit(main(sys.argv))
