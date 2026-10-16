#!/usr/bin/env python3
"""CI 設定的不變式（由 scripts/validate.py 呼叫）：防止已修過的 CI 弱點被改回去。

  workflow_write_permissions(text)        workflow 層級的 permissions 不得有 write（寫入權限按 job 宣告）
  unpaginated_list_comments(text)         issues.listComments 必須經 github.paginate（否則只拿到第一頁 30 則）
  precommit_semgrep_drift(pc, rules)      pre-commit 的 semgrep --config 與 vibesec.yaml g3 semgrep_rules 一致
  untrusted_script_runs(text)             workflow 不得執行本分支的 scripts/（判定程式只採用 _trusted/）
  sed_target_substitution(text)           不得以 sed 把受測目標 URL 代入設定（URL 含 # 或 & 會壞）
  sarif_jobs_without_permission(wf)       有 upload-sarif 的 job，有效權限須含 security-events: write
  self_sarif_uploads_without_hashfiles(wf)  上傳自產 SARIF 的步驟須以 hashFiles(<該檔>) 為條件（閘門沒有判定任何發現時不寫 SARIF）
  trusted_action_mode_reader(action)      受信任設定 action 以受信任樹的 vibesec_mode 讀 mode，不內嵌自己的 regex（ADR 0002）
  gate_mode_channels(wf)                  workflow 不得以 --mode／VIBESEC_MODE 把 mode 傳給閘門腳本（mode 只取自受信任政策，ADR 0002）

  python3 scripts/ci_invariants.py selftest
"""
from __future__ import annotations
import re, sys

_WRITE = re.compile(r"^\s+[a-z-]+:\s*write\b")


def workflow_write_permissions(text: str) -> list[str]:
    """workflow 層級 permissions 區塊中的 write 權限（'scope: write'）。"""
    out, inside = [], False
    for ln in text.splitlines():
        if re.match(r"^permissions:\s*(?:#.*)?$", ln):
            inside = True; continue
        if re.match(r"^permissions:\s*write-all\b", ln):
            out.append("write-all"); continue
        if inside:
            if ln and not ln[0].isspace() and not ln.lstrip().startswith("#"):
                inside = False; continue
            if _WRITE.match(ln):
                out.append(ln.strip().split("#", 1)[0].strip())
    return out


def unpaginated_list_comments(text: str) -> list[int]:
    """呼叫 rest.issues.listComments(…) 但不是傳給 github.paginate 的行號（1 起算）。"""
    return [i for i, ln in enumerate(text.splitlines(), 1)
            if re.search(r"issues\.listComments\s*\(", ln) and not ln.lstrip().startswith("//")]


def precommit_semgrep_drift(precommit: str, rules: list[str]) -> tuple[list[str], list[str]]:
    """(pre-commit 少了的規則集, pre-commit 多出的規則集)。只比對 semgrep hook 的 --config。"""
    have = set(re.findall(r"--config=(\S+?)\"?\s*(?:#|$)", precommit, re.M))
    want = set(rules or [])
    return sorted(want - have), sorted(have - want)


def untrusted_script_runs(text: str) -> list[int]:
    """執行或指向本分支 scripts/（不經 _trusted/）的行號：python3／bash／node scripts/…、S=scripts/…。註解行略過。"""
    pat = re.compile(r"(?:\b(?:python3?|bash|sh|node)(?:\s+-\S+)*\s+|=\s*[\"']?)(?:\./)?scripts/")
    return [i for i, ln in enumerate(text.splitlines(), 1)
            if not ln.lstrip().startswith("#") and pat.search(ln.split(" #", 1)[0])]


def sed_target_substitution(text: str) -> list[int]:
    """以 sed 代入受測目標 URL（VIBESEC_TARGET_URL）的行號。"""
    return [i for i, ln in enumerate(text.splitlines(), 1)
            if not ln.lstrip().startswith("#") and re.search(r"\bsed\b", ln) and "VIBESEC_TARGET_URL" in ln]


def sarif_jobs_without_permission(wf: dict) -> list[str]:
    """有 upload-sarif 步驟、但有效權限（job 層級，未宣告則取 workflow 層級）沒有 security-events: write 的 job。
    寫入權限從 workflow 層級移到 job 層級後，新增上傳 SARIF 的 job 忘了宣告就會上傳失敗——而這些步驟多半
    continue-on-error，失敗不會被注意到。"""
    top = wf.get("permissions")
    out = []
    for name, job in (wf.get("jobs") or {}).items():
        steps = (job or {}).get("steps") or []
        if not any("github/codeql-action/upload-sarif" in str(st.get("uses", "")) for st in steps):
            continue
        eff = job.get("permissions", top)
        if eff != "write-all" and not (isinstance(eff, dict) and eff.get("security-events") == "write"):
            out.append(name)
    return out


# 本 repo 閘門程式自產的 SARIF（gate_result.sarif）：沒有判定任何發現時會刪掉舊檔、不寫新檔（#179、#182、#184），
# 上傳步驟必須在檔案缺席時略過；第三方工具（grype、trivy、semgrep、checkov）的 SARIF 不在此列
SELF_SARIF = ("g1-slopcheck.sarif", "g1-sbom.sarif", "g1-kev.sarif", "g1-maintenance.sarif", "g1-provenance.sarif",
              "g4-static.sarif", "g5-api-probes.sarif", "g6.sarif")


def self_sarif_uploads_without_hashfiles(wf: dict) -> list[str]:
    """上傳自產 SARIF、但 if 條件沒有 hashFiles('<sarif_file>') 的步驟（「job：步驟名稱」）。
    沒有這個條件時，檔案缺席只會讓上傳步驟失敗（多半 continue-on-error），job 紀錄出現假的錯誤。"""
    out = []
    for name, job in (wf.get("jobs") or {}).items():
        for st in (job or {}).get("steps") or []:
            if "github/codeql-action/upload-sarif" not in str(st.get("uses", "")):
                continue
            sf = str((st.get("with") or {}).get("sarif_file") or "")
            if sf.rsplit("/", 1)[-1] in SELF_SARIF and f"hashFiles('{sf}')" not in str(st.get("if", "")):
                out.append(f"{name}：{st.get('name') or sf}")
    return out


def _step_runs(wf: dict, job: str, step_id: str | None = None, name: str | None = None) -> str | None:
    for st in (((wf.get("jobs") or {}).get(job) or {}).get("steps") or []):
        if (step_id and st.get("id") == step_id) or (name and st.get("name") == name):
            return str(st.get("run") or "")
    return None


def verdict_wiring(pr_gates: dict, staging: dict) -> list[str]:
    """閘門判定必須交給受信任樹的 scripts/gate_verdict.py（docs/08 §8）：以前 summary、staging 各自 inline 一份規則，
    順序不一致（#120、#121）。改回 inline 判定，或 staging 沒把 blackbox_problems 交給 notify → 回報。"""
    out = []
    run = _step_runs(pr_gates, "summary", name="彙整 gate-status 矩陣")
    if run is None or "_trusted/scripts/gate_verdict.py enforce" not in run:
        out.append("pr-gates.yml summary 的「彙整 gate-status 矩陣」沒有以 _trusted/scripts/gate_verdict.py enforce 判定")
    run = _step_runs(staging, "blackbox", step_id="verdict")
    for cmd in ("blackbox", "enforce"):
        if run is None or f"_trusted/scripts/gate_verdict.py {cmd}" not in run:
            out.append(f"staging-blackbox.yml 的 verdict 步驟沒有以 _trusted/scripts/gate_verdict.py {cmd} 判定")
    outputs = (((staging.get("jobs") or {}).get("blackbox") or {}).get("outputs") or {})
    if "steps.verdict.outputs.blackbox_problems" not in str(outputs.get("blackbox_problems", "")):
        out.append("staging-blackbox.yml 的 blackbox job outputs 沒有 blackbox_problems（notify 會改走舊判定）")
    return out


G4_STATIC_STEP = "G4 靜態檢查"
G4_STATIC_CALL = "python3 -I _trusted/scripts/g4_static.py"


def g4_static_wiring(pr_gates: dict) -> list[str]:
    """G4 靜態檢查必須以隔離模式執行受信任樹的 scripts/g4_static.py（#151／#152）：以前是 workflow 內約 270 行的
    inline heredoc，run_evals 與 g4_access 從 workflow 文字取出同一段來跑。改回 inline、改呼叫 PR head 的
    scripts/、或拿掉 -I（PYTHON* 環境變數與使用者 site-packages 可改寫判定程式 import 的模組）→ 回報。"""
    steps = [st for job in (pr_gates.get("jobs") or {}).values() for st in (job or {}).get("steps") or []
             if str(st.get("name", "")).startswith(G4_STATIC_STEP)]
    if len(steps) != 1:
        return [f"pr-gates.yml 應恰有一個「{G4_STATIC_STEP}」步驟（得到 {len(steps)} 個）"]
    run, out = str(steps[0].get("run") or ""), []
    if G4_STATIC_CALL not in run:
        out.append(f"「{G4_STATIC_STEP}」步驟沒有以 `{G4_STATIC_CALL}` 執行")
    if "<<" in run or re.search(r"\bpython3?\s+(-\S+\s+)*-\s*(<|$)", run, re.M):
        out.append(f"「{G4_STATIC_STEP}」步驟含 inline 程式碼（heredoc／stdin），判定程式必須在受信任的腳本內")
    return out


TRUSTED_CFG_STEP = "讀取受信任的 mode"
GATE_SCRIPTS = ("g4_static.py", "g4_review.py", "g5_api_probes.py", "g6_gate.py")   # 不含 gate_verdict.py（阻擋判定可以升級）


def trusted_action_mode_reader(action: dict) -> list[str]:
    """受信任設定 action 讀 mode 的步驟（#203）：以 python3 -I import 受信任樹的 vibesec_mode（read_mode、top_scalar），
    不得內嵌 regex 或合法值清單。以前 action 自己寫一份 regex，與閘門讀 mode 的規則可能漂移（ADR 0002）。"""
    steps = [st for st in ((action.get("runs") or {}).get("steps") or [])
             if str(st.get("name", "")).startswith(TRUSTED_CFG_STEP)]
    if len(steps) != 1:
        return [f"受信任設定 action 應恰有一個「{TRUSTED_CFG_STEP}」步驟（得到 {len(steps)} 個）"]
    run, out = str(steps[0].get("run") or ""), []
    if not re.search(r"^\s*from vibesec_mode import .*\bread_mode\b", run, re.M):
        out.append(f"「{TRUSTED_CFG_STEP}」步驟沒有 import vibesec_mode 的 read_mode")
    if re.search(r"^\s*import .*\bre\b|\bre\.(search|match|sub|compile)\(", run, re.M):
        out.append(f"「{TRUSTED_CFG_STEP}」步驟內嵌了自己的 regex（mode 的規則只能在 vibesec_mode）")
    if re.search(r"""[\(\[]\s*["']shadow["']\s*,\s*["']enforce["']""", run):
        out.append(f"「{TRUSTED_CFG_STEP}」步驟寫死了合法值清單（只能用 vibesec_mode 的 MODES）")
    if "python3 -I" not in run:
        out.append(f"「{TRUSTED_CFG_STEP}」步驟沒有以 python3 -I 執行（工作目錄是 PR head，可蓋掉標準函式庫）")
    return out


def gate_mode_channels(wf: dict) -> list[str]:
    """呼叫閘門腳本的步驟不得以 --mode 或 VIBESEC_MODE 傳 mode（#203、ADR 0002：mode 只取自受信任政策）。
    阻擋判定（gate_verdict）的 --mode 可以升級，不檢查；不呼叫閘門腳本的步驟（例如 G2 的 .env 檢查）不檢查。
    job 與 workflow 層級的 env 也會傳進步驟：有呼叫閘門腳本的 job，這兩層也不得有 VIBESEC_MODE。"""
    out = []
    for jname, job in (wf.get("jobs") or {}).items():
        inherited = "VIBESEC_MODE" in (wf.get("env") or {}) or "VIBESEC_MODE" in ((job or {}).get("env") or {})
        for st in (job or {}).get("steps") or []:
            run = str(st.get("run") or "")
            if not any(f"scripts/{g}" in run for g in GATE_SCRIPTS):
                continue
            if inherited or re.search(r"--mode\b", run) or "VIBESEC_MODE" in run or "VIBESEC_MODE" in (st.get("env") or {}):
                out.append(f"{jname}：{st.get('name') or st.get('id') or '（無名步驟）'}")
    return out


def selftest() -> list[str]:
    fails: list[str] = []
    wf_ok = "on: push\npermissions:\n  contents: read\n\njobs:\n  a:\n    permissions:\n      security-events: write\n"
    wf_bad = "on: push\npermissions:\n  contents: read\n  # 說明\n  security-events: write\n  actions: read\njobs: {}\n"
    for label, got, want in [
        ("workflow 層級只有 read", workflow_write_permissions(wf_ok), []),
        ("workflow 層級有 write", workflow_write_permissions(wf_bad), ["security-events: write"]),
        ("write-all", workflow_write_permissions("permissions: write-all\njobs: {}\n"), ["write-all"]),
        ("listComments 未分頁", unpaginated_list_comments(
            "const c = await github.rest.issues.listComments({owner, repo, issue_number});\n"), [1]),
        ("listComments 經 paginate", unpaginated_list_comments(
            "const c = await github.paginate(github.rest.issues.listComments, {owner, repo});\n// issues.listComments( 註解\n"), []),
        ("執行本分支 scripts", untrusted_script_runs(
            "  python3 scripts/g5_api_probes.py\n  S=scripts/g5_api_probes.py\n  python3 -I ./scripts/x.py\n"), [1, 2, 3]),
        ("只用 _trusted", untrusted_script_runs(
            '  python3 _trusted/scripts/g5_api_probes.py\n  S="${X:-_trusted/scripts/g5.py}"\n  # python3 scripts/x.py\n'
            "  sparse-checkout: .github/scripts\n"), []),
        ("sed 代入目標 URL", sed_target_substitution('  sed "s#a#${VIBESEC_TARGET_URL}/chat#" f > g\n'), [1]),
        ("沒有 sed 代入", sed_target_substitution("  python3 x.py --target \"$VIBESEC_TARGET_URL\"\n  sed -n 1p f\n"), []),
    ]:
        if got != want:
            fails.append(f"{label}：預期 {want}，得到 {got}")
    up = {"uses": "github/codeql-action/upload-sarif@abc"}
    for label, wf, want in [
        ("job 層級有權限", {"permissions": {"contents": "read"},
                           "jobs": {"a": {"permissions": {"security-events": "write"}, "steps": [up]}}}, []),
        ("job 沒宣告、workflow 層級唯讀", {"permissions": {"contents": "read"}, "jobs": {"a": {"steps": [up]}}}, ["a"]),
        ("job 宣告了但沒有 security-events", {"jobs": {"a": {"permissions": {"contents": "read"}, "steps": [up]}}}, ["a"]),
        ("沒有上傳 SARIF 的 job 不檢查", {"permissions": {"contents": "read"}, "jobs": {"a": {"steps": [{"run": "x"}]}}}, []),
    ]:
        if sarif_jobs_without_permission(wf) != want:
            fails.append(f"sarif_jobs_without_permission「{label}」：預期 {want}，得到 {sarif_jobs_without_permission(wf)}")
    # 自產 SARIF 的上傳步驟要以 hashFiles(<該檔>) 為條件；第三方 SARIF 不檢查
    sup = lambda f, cond=None: {"name": f, "uses": "github/codeql-action/upload-sarif@abc", "with": {"sarif_file": f},
                                **({"if": cond} if cond else {})}
    for label, steps, want in [
        ("自產、有 hashFiles", [sup("reports/g6.sarif", "always() && hashFiles('reports/g6.sarif') != ''")], []),
        ("自產、只有 always()", [sup("reports/g6.sarif", "always()")], ["a：reports/g6.sarif"]),
        ("自產、hashFiles 指向別的檔", [sup("reports/g6.sarif", "always() && hashFiles('reports/x.sarif') != ''")], ["a：reports/g6.sarif"]),
        ("第三方不檢查", [sup("reports/grype.sarif", "always()")], []),
    ]:
        got = self_sarif_uploads_without_hashfiles({"jobs": {"a": {"steps": steps}}})
        if got != want:
            fails.append(f"self_sarif_uploads_without_hashfiles（{label}）：預期 {want}，得到 {got}")
    pr_ok = {"jobs": {"summary": {"steps": [{"name": "彙整 gate-status 矩陣",
                                             "run": "python3 _trusted/scripts/gate_verdict.py enforce --trusted-root _trusted"}]}}}
    st_ok = {"jobs": {"blackbox": {"outputs": {"blackbox_problems": "${{ steps.verdict.outputs.blackbox_problems }}"},
                                   "steps": [{"id": "verdict", "run": "python3 _trusted/scripts/gate_verdict.py blackbox\n"
                                                                     "python3 _trusted/scripts/gate_verdict.py enforce"}]}}}
    if verdict_wiring(pr_ok, st_ok):
        fails.append(f"verdict_wiring：都接上時不應回報（得到 {verdict_wiring(pr_ok, st_ok)}）")
    inline = {"jobs": {"summary": {"steps": [{"name": "彙整 gate-status 矩陣", "run": "python3 -I - <<'EOF'"}]}}}
    st_bad = {"jobs": {"blackbox": {"steps": [{"id": "verdict", "run": "python3 _trusted/scripts/gate_verdict.py enforce"}]}}}
    if len(verdict_wiring(inline, st_bad)) != 3:
        fails.append(f"verdict_wiring：inline summary、staging 缺 blackbox 與 outputs 應各回報一項（得到 {verdict_wiring(inline, st_bad)}）")
    if len(verdict_wiring({}, {})) != 4:
        fails.append("verdict_wiring：找不到步驟也要回報")
    st = lambda run: {"jobs": {"g4": {"steps": [{"name": "G4 靜態檢查（Unicode / RLS）", "run": run}]}}}
    ok_run = "python3 -I _trusted/scripts/g4_static.py --target . --out reports --commit \"$COMMIT_SHA\"\n"
    for label, wf, want in [
        ("以受信任腳本執行", st(ok_run), 0),
        ("inline heredoc（舊版）", st("python3 -I - <<'EOF'\nimport json\nEOF\n"), 2),
        ("執行 PR head 的 scripts/", st("python3 -I scripts/g4_static.py --target . --out reports\n"), 1),
        ("拿掉 -I", st("python3 _trusted/scripts/g4_static.py --target . --out reports\n"), 1),
        ("步驟缺席", {"jobs": {"g4": {"steps": [{"name": "別的步驟", "run": ok_run}]}}}, 1),
        ("步驟重複", {"jobs": {"a": st(ok_run)["jobs"]["g4"], "b": st(ok_run)["jobs"]["g4"]}}, 1),
    ]:
        if len(g4_static_wiring(wf)) != want:
            fails.append(f"g4_static_wiring「{label}」應回報 {want} 項（得到 {g4_static_wiring(wf)}）")
    pc = ('        args:\n          - "--config=config/semgrep/vibesec-rules.yaml"\n'
          '          - "--config=p/owasp-top-ten"\n          - "--config=p/security-audit"   # 與 CI 一致\n          - "--error"\n')
    rules = ["config/semgrep/vibesec-rules.yaml", "p/owasp-top-ten", "p/security-audit"]
    if precommit_semgrep_drift(pc, rules) != ([], []):
        fails.append(f"pre-commit 與 CI 一致時不應回報差異（得到 {precommit_semgrep_drift(pc, rules)}）")
    if precommit_semgrep_drift(pc.replace('          - "--config=p/security-audit"   # 與 CI 一致\n', ""), rules) != (["p/security-audit"], []):
        fails.append("pre-commit 少了 p/security-audit 應回報")
    # 受信任設定 action 讀 mode：只能 import 受信任樹的 vibesec_mode（不依賴 PyYAML），不得內嵌 regex 或合法值清單
    good_cfg = ("python3 -I - <<'PY' >> \"$GITHUB_OUTPUT\"\nimport sys, pathlib\n"
                "sys.path.insert(0, str(pathlib.Path('_trusted/scripts').resolve()))\n"
                "from vibesec_mode import read_mode, top_scalar\nPY\n")
    act = lambda run, sid="cfg": {"runs": {"steps": [{"name": "讀取受信任的 mode / risk_tier", "id": sid, "run": run}]}}
    for label, a, want in [
        ("以 vibesec_mode 讀", act(good_cfg), 0),
        ("內嵌 regex（舊版）", act("python3 -I - <<'PY'\nimport sys, re, pathlib\nm = re.search(r'^mode', t)\n"
                                  "if mode not in (\"shadow\", \"enforce\"): sys.exit(2)\nPY\n"), 3),
        ("拿掉 -I", act(good_cfg.replace("python3 -I -", "python3 -")), 1),
        ("步驟缺席", {"runs": {"steps": []}}, 1),
    ]:
        try:
            got = trusted_action_mode_reader(a)
        except Exception as e:
            got = None, f"例外 {type(e).__name__}：{e}"
        if isinstance(got, tuple) or len(got) != want:
            fails.append(f"trusted_action_mode_reader「{label}」應回報 {want} 項（得到 {got}）")
    # 閘門腳本不得經 --mode／VIBESEC_MODE 收到 mode；阻擋判定（gate_verdict）的 --mode 與不呼叫閘門腳本的步驟不檢查
    step = lambda run, env=None: {"name": "s", "run": run, **({"env": env} if env else {})}
    for label, steps, want in [
        ("沒有 mode 管道", [step("python3 -I _trusted/scripts/g4_static.py --target . --out reports --commit x")], 0),
        ("g4_static 帶 --mode", [step('python3 -I _trusted/scripts/g4_static.py --target . --mode "$M"')], 1),
        ("g6_gate 帶 --mode", [step("python3 _trusted/scripts/g6_gate.py --gate g.json --mode shadow")], 1),
        ("g5 有 VIBESEC_MODE 環境變數", [step("python3 _trusted/scripts/g5_api_probes.py", {"VIBESEC_MODE": "${{ x }}"})], 1),
        ("g4_review gate 帶 --mode", [step("python3 _trusted/scripts/g4_review.py gate --static s --mode \"$VIBESEC_MODE\"")], 1),
        ("阻擋判定的 --mode 不檢查", [step("python3 _trusted/scripts/gate_verdict.py enforce --mode enforce")], 0),
        ("不呼叫閘門腳本的步驟不檢查", [step('if [ "$VIBESEC_MODE" = enforce ]; then exit 1; fi', {"VIBESEC_MODE": "x"})], 0),
    ]:
        try:
            got = gate_mode_channels({"jobs": {"a": {"steps": steps}}})
        except Exception as e:
            got = None, f"例外 {type(e).__name__}：{e}"
        if isinstance(got, tuple) or len(got) != want:
            fails.append(f"gate_mode_channels「{label}」應回報 {want} 項（得到 {got}）")
    # job 或 workflow 層級的 env 也會傳進步驟：有呼叫閘門腳本的 job，這兩層都不得有 VIBESEC_MODE
    g5 = step("python3 _trusted/scripts/g5_api_probes.py")
    for label, wf, want in [
        ("job 層級 env", {"jobs": {"a": {"env": {"VIBESEC_MODE": "x"}, "steps": [g5]}}}, 1),
        ("workflow 層級 env", {"env": {"VIBESEC_MODE": "x"}, "jobs": {"a": {"steps": [g5]}}}, 1),
        ("job 層級 env、但沒有閘門腳本", {"jobs": {"a": {"env": {"VIBESEC_MODE": "x"}, "steps": [step("echo")]}}}, 0),
    ]:
        try:
            got = gate_mode_channels(wf)
        except Exception as e:
            got = None, f"例外 {type(e).__name__}：{e}"
        if isinstance(got, tuple) or len(got) != want:
            fails.append(f"gate_mode_channels「{label}」應回報 {want} 項（得到 {got}）")
    return fails


if __name__ == "__main__":
    if sys.argv[1:2] == ["selftest"]:
        _fails = selftest()
        for f in _fails:
            print(f"FAIL {f}")
        print("selftest 通過" if not _fails else f"selftest 失敗 {len(_fails)} 項")
        sys.exit(1 if _fails else 0)
    print(__doc__.strip()); sys.exit(4)
