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
from g1_git import head_commit  # noqa: E402
from g1_screen import (  # noqa: E402
    Outcome,
    Request,
    TOOL_NAME,
    TOOL_VERSION,
    default_env,
    dumps_json,
    screen,
)

__all__ = [
    "ROOT",
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
    印標準輸出與標準錯誤結果行、寫 SARIF（無 SARIF 檢視時刪除舊檔）與閘門結果、回傳 Outcome.exit_code。"""
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
    root = Path(target).expanduser().resolve() if target else ROOT
    request = Request(target=root if target else None, manifests=tuple(_opt(args, "--manifest")),
                      rule_files=tuple(_opt(args, "--rules-file")), changed_lists=tuple(_opt(args, "--changed-files")),
                      staged="--staged" in args, base=(_opt(args, "--base") or [None])[-1])
    sarif_out = (_opt(args, "--sarif") or [None])[-1]
    gate_out = (_opt(args, "--gate") or [None])[-1]
    commit = head_commit(root) if (gate_out and root.is_dir()) else None
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
        _write_json(gate_out, outcome.to_gate_run(started, commit, sarif_ref=sarif_out))
    print(outcome.result_line(), file=sys.stderr)
    return outcome.exit_code


def selftest():
    """命令列契約自我測試：旗標、退出碼、--gate／--sarif 寫出與未完成時刪除舊 SARIF、標準輸出形狀、結果行、政策讀不到。
    其餘領域案例已依對照表搬至 tests/test_g1_*.py。"""
    import contextlib
    import io
    import re
    import subprocess
    import tempfile
    from jsonschema import Draft202012Validator
    from g1_registry import Facts, Found, NotFound
    from vibesec_policy import POLICY_UNREADABLE, broken_policy_root, set_mode_line, temp_policy_root

    fails = []
    schema = Draft202012Validator(json.loads((ROOT / "schemas/gate-result.schema.json").read_text(encoding="utf-8")))

    class CleanRegistry:
        def __init__(self):
            self.queried = []

        def facts(self, eco, name, ver):
            self.queried.append(name)
            if name == "evil-pkg":
                return NotFound()
            npm = eco == "npm"
            return Found(Facts(eco, name, ver or "1.0.0", "2020-01-01T00:00:00Z", {} if npm else None, 10 ** 6 if npm else None))

        def requires(self, name, ver):
            return set()

    def git(d, *a):
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *a], cwd=d, capture_output=True, check=True)

    # 1. --help／-h：印用法、exit 0，不執行掃描
    for flag in ("--help", "-h"):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = main(["g1_slopcheck.py", flag])
        if code != 0 or "用法" not in out.getvalue() or '"findings"' in out.getvalue():
            fails.append(f"{flag} 應印用法並 exit 0（exit {code}）")

    # 2. --target 不是目錄 → exit 2、寫出未完成閘門結果、刪除舊 SARIF、不印 stdout
    with temp_policy_root() as pr, tempfile.TemporaryDirectory() as d:
        set_mode_line(pr / "vibesec.yaml", "mode: shadow")
        gp, sp = Path(d, "G1.json"), Path(d, "G1.sarif")
        sp.write_text('{"stale": true}', encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["g1_slopcheck.py", "--target", str(Path(d, "no-such-dir")),
                         "--gate", str(gp), "--sarif", str(sp)], policy_root=pr)
        g = json.loads(gp.read_text(encoding="utf-8")) if gp.is_file() else {}
        if code != 2 or out.getvalue() or sp.exists() or g.get("status") != "incomplete" or "不是目錄" not in err.getvalue():
            fails.append(f"--target 不是目錄 → exit 2、刪舊 SARIF、寫未完成 gate、無 stdout（得到 exit {code}、stale={sp.exists()}、{g}）")

    # 3. 命令列 --staged 空範圍與有掃描兩種標準輸出形狀、結果行、--gate（含 HEAD commit）與 --sarif 寫出
    with temp_policy_root() as pr, tempfile.TemporaryDirectory() as d:
        set_mode_line(pr / "vibesec.yaml", "mode: shadow")
        D = Path(d, "proj")
        D.mkdir()
        (D / "package.json").write_text(json.dumps({"dependencies": {"express": "4.21.2"}}), encoding="utf-8")
        git(D, "init", "-q")
        git(D, "add", "package.json")
        git(D, "commit", "-qm", "init")
        head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=D, check=True).stdout.strip()
        gp, sp = Path(d, "G1.json"), Path(d, "G1.sarif")
        rec = CleanRegistry()

        # 空暫存區 → 形狀 1、略過結果行、exit 0
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["g1_slopcheck.py", "--target", str(D), "--staged", "--gate", str(gp), "--sarif", str(sp)],
                        policy_root=pr, registry=rec)
        if code != 0 or json.loads(out.getvalue()).get("findings") != [] \
                or err.getvalue().strip() != "G1 slopcheck：無相依清單或規則檔變更，略過。":
            fails.append(f"--staged 空暫存區契約不符（exit {code}，err={err.getvalue()!r}）")

        # 全量掃描 → 形狀 2、通過結果行、commit 取目標專案 HEAD、SBOM／KEV 預留 pending
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["g1_slopcheck.py", "--target", str(D), "--gate", str(gp), "--sarif", str(sp)],
                        policy_root=pr, registry=rec)
        g = json.loads(gp.read_text(encoding="utf-8"))
        if code != 0 or g.get("commit") != head or g.get("scope") != "full" \
                or [c["control_id"] for c in g["coverage"] if c["state"] == "pending"] != ["VS-G1-SBOM", "ASVS5-V15.2"] \
                or not sp.is_file() or err.getvalue() != "\n✅ G1 快篩通過。\n" or list(schema.iter_errors(g)):
            fails.append(f"全量掃描命令列契約不符（exit {code}，err={err.getvalue()!r}，{g}）")

        # blocking 發現 → exit 1、阻擋結果行
        (D / "package.json").write_text(json.dumps({"dependencies": {"evil-pkg": "1.0.0"}}), encoding="utf-8")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(["g1_slopcheck.py", "--target", str(D), "--manifest", "package.json"],
                        policy_root=pr, registry=rec)
        if code != 1 or err.getvalue() != "\n⛔ G1 阻擋：1 筆 blocking 供應鏈發現。\n":
            fails.append(f"blocking 發現命令列契約不符（exit {code}，err={err.getvalue()!r}）")

    # 4. 政策檔讀不到 → 進入點就停：G1 gate incomplete、沒有發現、刪舊 SARIF、退出碼 2（不查 registry）
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

    # 5. risk_tier 打錯 → 省略 risk_tier 欄位，不拋例外
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

    # 6. mode 缺席或不合法 → 政策讀不到、mode 記 enforce、不查 registry、刪舊 SARIF、退出碼 2；合法 shadow／enforce 照常執行
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

    return fails


if __name__ == "__main__":
    sys.exit(main(sys.argv))
