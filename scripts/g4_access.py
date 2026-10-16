#!/usr/bin/env python3
"""G4 架構與存取控制（本機／harness 版）— 靜態檢查 + LLM 審查紀錄；可用 --target 掃其他專案。

靜態檢查（隱形 Unicode、Supabase RLS、Agent 工具 allow-list、高影響工具 HITL、單層 middleware、MCP resource indicator）執行
scripts/g4_static.py（scripts/run_evals.py 的 G4 評測也執行同一支），不另寫一份；tier 由該腳本以本 repo 的
blocking-policy 計算（腳本以自己所在的樹為 ROOT）。腳本會走訪 --target，所以在目標「追蹤中檔案」的暫存副本上執行
（同 G3：不跟隨 symlink），輸出寫在副本以外的暫存目錄，不寫進被測專案。結果檔損毀或缺欄位 → incomplete。
mcp_resource_indicator（VS-G4-MCP-RESOURCE-INDICATOR，docs/05 §7）也在 g4_static.py 內（判定在 scripts/g4_mcp.py），
本機版與 CI 的 gate JSON 都含此控制：沒有 MCP 程式碼／設定 → not_applicable；MCP OAuth 缺 resource／audience 綁定 → fail（advisory 發現）。

VS-G4-LLM-REVIEW（LLM 審查紀錄）：
- 目標是本 repo：與 CI 相同，以 scripts/g4_review.py 從 reviews/g4/ 找對 HEAD 有效的紀錄並推導狀態
  （本機沒有 PR，紀錄不檢查 approve；CI 會另外檢查）。本機掃的是工作目錄，所以另外套用外部專案的兩條規則：
  reviews/g4/、rulings/ 以外有未提交的修改 → 紀錄過期、不採用；紀錄本身未提交或有未提交的修改 → 最高 pending。
- 目標是外部專案：紀錄放在本 repo 的 reviews/g4/external/<commit>.yaml（2026-10-06 人工決定），格式與規則同
  reviews/g4/<commit>.yaml，人工裁決同樣放本 repo 的 rulings/。不讀目標的 reviews/g4/ 與 rulings/——那是被測專案
  自己寫的，等於自證。紀錄只在以下條件下採用：
    · <commit> 恰好是目標目前的 HEAD（外部紀錄不另外提交到目標，任何新 commit 都是新的程式碼）；
    · 目標追蹤中的檔案沒有未提交的修改（掃描的就是紀錄審查的內容）；
    · 紀錄通過 g4_review 的規則檢查。
  紀錄尚未提交到本 repo（未經 PR 與 CODEOWNERS）或 recorded_by.handle 空白 → 最高 pending。
  沒有可用紀錄 → VS-G4-LLM-REVIEW 維持 pending，G4 最多 incomplete（有靜態 blocking 則 fail）。
原則（CLAUDE.md #2）：靜態檢查腳本找不到或執行失敗、目標不是 git repo 根目錄 → incomplete，絕不視為通過。

用法：python3 scripts/g4_access.py [--target <dir>] [--out-dir reports/raw/G4] [--gate reports/gates/G4.json]
      python3 scripts/g4_access.py selftest
退出碼：0 無 blocking；1 有 blocking 發現；2 incomplete／pending（LLM 審查未完成時一律如此）。
"""
from __future__ import annotations
import argparse, json, os, pathlib, re, subprocess, sys, tempfile, time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import g4_review  # noqa: E402  審查紀錄的驗證與狀態推導（缺 PyYAML／jsonschema 時以 exit 2 結束）
from g3_sast import copy_tracked, _git  # noqa: E402  同一份「追蹤中檔案、不跟隨 symlink」的副本
import gate_result  # noqa: E402  閘門結果的外層欄位與 tool 列（#183）
import g4_static  # noqa: E402  只取控制清單與 tool 名稱（靜態檢查本身以子行程執行 STATIC_SCRIPT）

STATIC_SCRIPT = ROOT / "scripts/g4_static.py"   # G4 靜態檢查（與 run_evals.py 的 G4 評測同一支）
STEP = "G4 靜態檢查"                             # 失敗理由中的名稱
EXTERNAL_REVIEWS = "reviews/g4/external"


# mcp_resource_indicator（docs/05 §7）已併入 scripts/g4_static.py（判定在 scripts/g4_mcp.py）；這裡只重新匯出名稱
from g4_mcp import MCP_CONTROL, MCP_RULE, mcp_resource_check  # noqa: E402,F401


def run_static(target: pathlib.Path, out_dir: pathlib.Path, script: pathlib.Path, commit: str | None, mode: str,
               timeout: int) -> tuple[dict | None, str | None, list[str]]:
    """在目標追蹤中檔案的副本上執行靜態檢查腳本。回傳 (靜態 gate JSON, 失敗原因, 附註)。"""
    if not pathlib.Path(script).is_file():
        return None, f"{STEP}腳本不存在：{script}", []
    notes = []
    with tempfile.TemporaryDirectory(prefix="vibesec-g4-") as tmp:
        copy = pathlib.Path(tmp) / "vibesec-target"
        copy.mkdir()
        skipped = copy_tracked(target, copy)
        if skipped:
            notes.append(f"靜態檢查略過 {skipped} 個 symlink（不跟隨到目標以外的檔案）")
        reports = pathlib.Path(tmp) / "reports"   # 副本以外：不讓輸出成為下一次掃描的內容
        t0 = time.monotonic()
        try:
            p = subprocess.run([sys.executable, "-I", str(script), "--target", str(copy), "--out", str(reports),
                                "--mode", mode, "--commit", commit or ""], capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return None, f"G4 靜態檢查逾時（{timeout}s）", notes
        except OSError as e:
            return None, f"G4 靜態檢查無法執行（{type(e).__name__}）", notes
        gate_p, sarif_p = reports / "g4-gate.json", reports / "g4-static.sarif"
        # 靜態檢查自己回報沒有執行（例如政策檔讀不到：tool error、不留 SARIF）→ 採用它寫明的未完成原因
        if p.returncode == 0 and gate_p.is_file() and not sarif_p.is_file():
            try:
                reported = json.loads(gate_p.read_text(encoding="utf-8"))
                tool = next(t for t in reported["tools"] if t.get("name") == "vibesec-g4-static")
            except (ValueError, KeyError, TypeError, StopIteration):
                reported, tool = None, {}
            if tool.get("state") == "error" and reported.get("status_reason"):
                return None, f"G4 靜態檢查未執行：{reported['status_reason']}", notes
        # enforce 且有 blocking 時腳本以 exit 1 結束（CI 用來擋 merge），結果仍有效；其餘非零、或沒寫出結果 → 失敗
        if p.returncode not in (0, 1) or not gate_p.is_file() or not sarif_p.is_file():
            return None, f"G4 靜態檢查 exit {p.returncode}：{(p.stderr or p.stdout).strip()[-200:]}", notes
        try:   # 結果檔損毀或缺欄位：靜態檢查沒有可用結果 → incomplete，不是 traceback
            static = json.loads(gate_p.read_text(encoding="utf-8"))
            static_blocking = int(static["findings_count"]["blocking"])
            sarif = json.loads(sarif_p.read_text(encoding="utf-8"))
            sarif["runs"][0]["results"]
        except (ValueError, KeyError, IndexError, TypeError) as e:
            return None, f"G4 靜態檢查的結果無法解析（{type(e).__name__}：{str(e)[:120]}）", notes
        if p.returncode == 1 and not static_blocking:
            return None, f"G4 靜態檢查 exit 1 但沒有 blocking 發現：{(p.stderr or p.stdout).strip()[-200:]}", notes
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "g4-static.sarif").write_text(json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8")
    for t in static.get("tools") or []:
        if t.get("name") == "vibesec-g4-static":
            t.update(output_ref=str(out_dir / "g4-static.sarif"), exit_code=p.returncode,
                     duration_seconds=round(time.monotonic() - t0, 1))
    return static, None, notes


def _committed(root: pathlib.Path, rel: str) -> bool:
    """rel 已提交到 root 的 HEAD，且工作目錄內容與 HEAD 相同。未提交的紀錄沒有經過 PR 與 CODEOWNERS 審核。"""
    if _git(root, "ls-files", "--error-unmatch", "--", rel) is None:
        return False
    try:
        return subprocess.run(["git", "diff", "--quiet", "HEAD", "--", rel], cwd=root, capture_output=True).returncode == 0
    except OSError:
        return False


def find_external_record(target: pathlib.Path, commit: str, cfg: dict, controls: set[str], root: pathlib.Path = ROOT):
    """外部專案的審查紀錄 root/reviews/g4/external/<commit>.yaml。
    回傳 (record, evaluation, record_ref, 沒有可用紀錄的理由, 信任上限的理由)。"""
    rel = f"{EXTERNAL_REVIEWS}/{commit}.yaml"
    path = root / rel
    if not path.is_file():
        return None, None, None, (f"沒有 {rel}：外部專案的 G4 LLM 審查紀錄放在本 repo 的 {EXTERNAL_REVIEWS}/<commit>.yaml"
                                  "（見 reviews/README.md）；目標自己的 reviews/g4、rulings 不採信（不得自證）"), None
    dirty = _git(target, "status", "--porcelain", "--untracked-files=no")
    if dirty is None or dirty:
        return None, None, None, f"目標的追蹤中檔案有未提交的修改，掃描的內容不是 {rel} 審查的 commit", None
    try:
        rec = g4_review._yaml(path)
    except Exception as e:   # YAML 錯誤：紀錄不可用，不是通過
        return None, None, None, f"{rel} 無法解析（{type(e).__name__}）", None
    ev = g4_review.evaluate(rec, cfg, controls, path)
    if ev["errors"]:
        return None, None, None, f"{rel} 違規：{ev['errors'][0]}", None
    cap = None if _committed(root, rel) else f"{rel} 尚未提交到本 repo（未經 PR 與 CODEOWNERS 審核）"
    return rec, ev, rel, None, cap


def _dirty_tracked(root: pathlib.Path) -> list[str] | None:
    """root 追蹤中檔案有未提交修改（含已暫存）的路徑；git 失敗回傳 None。"""
    try:
        p = subprocess.run(["git", "status", "--porcelain", "-z", "--untracked-files=no", "--no-renames"], cwd=root,
                           capture_output=True, text=True)
    except OSError:
        return None
    return [e[3:] for e in p.stdout.split("\0") if e[3:]] if p.returncode == 0 else None


def find_self_record(target: pathlib.Path, commit: str, cfg: dict, controls: set[str]):
    """目標是本 repo：與 CI 相同以 g4_review.find_record 找紀錄（freshness 只比 commit..HEAD），再補上工作目錄的檢查——
    本機掃的是工作目錄的內容，不是已提交的 commit（規則同外部專案）：
      · reviews/g4/ 與 rulings/ 以外的追蹤中檔案有未提交的修改 → 掃描內容不是紀錄審查的程式碼，紀錄過期、不採用；
      · 採用的紀錄未提交或有未提交的修改 → 沒有經過 PR 與 CODEOWNERS，最高 pending。
    回傳 (record, evaluation, record_ref, 沒有可用紀錄的理由, 信任上限的理由)。"""
    record, ev, ref, reason = g4_review.find_record(commit, cfg, controls)
    if record is None:
        return record, ev, ref, reason, None
    dirty = _dirty_tracked(target)
    if dirty is None:
        return None, None, None, f"無法取得工作目錄狀態（git status 失敗），不採用審查紀錄 {ref}", None
    changed = [f for f in dirty if not f.startswith(g4_review.FRESH_PREFIXES)]
    if changed:
        shown = "、".join(changed[:5]) + ("…" if len(changed) > 5 else "")
        return None, None, None, (f"工作目錄有未提交的程式變更（{len(changed)} 檔：{shown}），"
                                  f"掃描的內容不是 {ref} 審查的程式碼，紀錄已過期"), None
    cap = None if _committed(target, ref) else f"{ref} 尚未提交或有未提交的修改（未經 PR 與 CODEOWNERS 審核）"
    return record, ev, ref, None, cap


def scan(target: pathlib.Path, out_dir: pathlib.Path, script: pathlib.Path = STATIC_SCRIPT, timeout: int = 900,
         review_root: pathlib.Path = ROOT) -> dict:
    """掃描目標專案並回傳 G4 gate JSON（schemas/gate-result.schema.json）。
    review_root：外部專案審查紀錄所在的 repo（本 repo；selftest 以暫存 repo 代替）。"""
    started = gate_result.now()
    target, out_dir = target.resolve(), out_dir.resolve()
    external = target != g4_review.PROJECT   # 本 repo（或 VIBESEC_PROJECT_ROOT）= g4_review 讀 reviews/g4 的同一個 repo
    (out_dir / "g4-static.sarif").unlink(missing_ok=True)   # 不讓上一次的輸出被當成這次的結果
    mode = (g4_review._yaml(ROOT / "vibesec.yaml") or {}).get("mode", "shadow")
    top = _git(target, "rev-parse", "--show-toplevel")
    problem = (f"目標不是 git repo（{target}）" if top is None else
               None if pathlib.Path(top).resolve() == target else f"--target 必須是 git repo 根目錄（{top}）")
    commit = _git(target, "rev-parse", "HEAD") if not problem else None
    static, why, notes = (None, problem, []) if problem else run_static(target, out_dir, script, commit, mode, timeout)
    if static is None:
        # 靜態檢查沒有產出結果（腳本不存在或失敗、目標不是 repo 根目錄）：經過閘門判定（GateRun，#183），不再手刻
        # incomplete。coverage 是完整的宣告清單：靜態控制沒有回報 → untested（未執行），LLM 審查控制 pending 並寫明原因。
        # mode 不合法時 g4_static 的 argparse 會擋下，一定走到這裡：記為 enforce（讀不到 → 更嚴）、寫明原因，
        # 不拋例外（#183 決定 1：g4_access 的 exit 1 代表「有 blocking」，崩潰會誤導）
        problems = [why]
        if mode not in gate_result.MODES:
            problems.append(f"vibesec.yaml 的 mode 不合法（{mode!r}；須為 {'／'.join(gate_result.MODES)}），閘門結果記為 enforce")
            mode = "enforce"
        run = gate_result.GateRun("G4", controls=[c for c in g4_static.CONTROLS if c != g4_static.LLM_CONTROL],
                                  deferred=[g4_static.LLM_CONTROL], mode=mode, scope="full", commit=commit, started_at=started)
        run.tool(g4_static.TOOL_NAME, "error")
        run.cover(g4_static.LLM_CONTROL, "pending", why)
        for p in problems:
            run.problem(p)
        return run.result()
    cfg, controls = g4_review.load_cfg(), g4_review.known_controls()
    if external:
        record, ev, ref, reason, cap = find_external_record(target, commit, cfg, controls, review_root)
    else:
        record, ev, ref, reason, cap = find_self_record(target, commit, cfg, controls)
    gate = g4_review.derive_gate(static, record, ev, reason, ref)
    if record is not None:
        caps = [cap, g4_review.trust_cap(False, record["recorded_by"].get("handle", ""), None, [])]
        if any(caps):
            g4_review.apply_cap(gate, "；".join(c for c in caps if c))
    gate.pop("_llm_findings", None)
    if notes:
        gate["status_reason"] = "；".join(x for x in (gate.get("status_reason"), *notes) if x)
    gate.update(scope="full", diff_base=None, commit=commit, started_at=started)
    return gate


# ------------------------------------------------------------------ selftest
def selftest() -> list[str]:
    from jsonschema import Draft202012Validator
    import yaml
    fails: list[str] = []
    schema = Draft202012Validator(json.loads((ROOT / "schemas/gate-result.schema.json").read_text(encoding="utf-8")))
    script = STATIC_SCRIPT
    if not script.is_file():
        return [f"找不到 {script}"]
    _wrap_dir = tempfile.TemporaryDirectory(prefix="vibesec-g4-wrap-")

    def wrapped(name: str, tail: str) -> pathlib.Path:
        """先以相同參數執行 g4_static.py，再執行 tail（可用 rc 與輸出目錄 out）：模擬腳本執行後失敗、輸出損毀。"""
        w = pathlib.Path(_wrap_dir.name) / f"{name}.py"
        w.write_text("import pathlib, subprocess, sys\n"
                     f"rc = subprocess.run([sys.executable, '-I', {str(script)!r}, *sys.argv[1:]]).returncode\n"
                     "out = pathlib.Path(sys.argv[sys.argv.index('--out') + 1])\n" + tail + "\n", encoding="utf-8")
        return w
    git = lambda d, *a: subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *a], cwd=d,
                                       capture_output=True, check=True, text=True)
    zw = "​"   # 零寬空白：Rules File Backdoor 的典型手法

    def check(g, why):
        errs = list(schema.iter_errors(g))
        if errs:
            fails.append(f"{why}：gate JSON 不符 schema（{errs[0].message}）")
        return g

    # agent-tool-overexposure：只認「註冊給 Agent 的工具名稱」。以前檔案出現 tool 字樣且任一處提到高危名稱就報，
    # scripts/llm_observations.py 判定高影響工具的正則（HIGH_IMPACT）因此被判 blocking（L3）。
    # 高危名稱在執行期組出：本檔原文若含「tools=[…, 高危名稱]」會讓本 repo 命中自己的檢查。
    bad = "execute" + "_sql"
    def overexposed(files: dict[str, str]) -> list[str]:
        with tempfile.TemporaryDirectory() as d:
            for rel, body in files.items():
                (pathlib.Path(d) / rel).parent.mkdir(parents=True, exist_ok=True)
                (pathlib.Path(d) / rel).write_text(body, encoding="utf-8")
            subprocess.run([sys.executable, "-I", str(script), "--target", d, "--out", f"{d}/reports", "--mode", "shadow"],
                           capture_output=True, text=True, timeout=120, check=True)
            sarif = json.loads((pathlib.Path(d) / "reports/g4-static.sarif").read_text(encoding="utf-8"))
        return [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in sarif["runs"][0]["results"]
                if r["ruleId"] == "vibesec.g4.agent-tool-overexposure"]
    tool_cases = [
        ("@tool 註冊", {"agent.py": "from agent_sdk import Agent, tool\n\n@" + "tool\ndef " + bad + "(q):\n    return db.execute(q)\n"}, True),
        ("tools=[…] 清單", {"agent.py": "agent = Agent(" + "tools=[search, " + bad + "])\n"}, True),
        ("register_tool", {"agent.py": "server.register_tool(\"" + bad + "\", fn)\n"}, True),
        ("Vercel AI SDK 物件鍵", {"agent.ts": "const r = await generateText({ tools: {\n  " + bad + ": tool({ description: 'x' }),\n} });\n"}, True),
        ("LangChain Tool(name=)", {"agent.py": "tools = [Tool(name=\"" + bad + "\", func=f, description=\"d\")]\n"}, True),
        ("判定高影響工具的正則（scripts/llm_observations.py 原文）",
         {"llm_observations.py": (ROOT / "scripts/llm_observations.py").read_text(encoding="utf-8")}, False),
        ("註解與字串提到高危名稱、註冊的是低風險工具",
         {"agent.py": f"# 不要註冊 {bad}\nWARN = '{bad} 屬高危'\nagent = Agent(" + "tools=[search_docs, get_ticket])\n"}, False),
        ("測試資料的 tools 參數", {"t.py": "def probe(events, " + "tools=(\"" + bad + "\",)):\n    return events\n"}, False),
    ]
    for label, files, want in tool_cases:
        try:
            got = overexposed(files)
        except (subprocess.CalledProcessError, OSError, ValueError) as e:
            fails.append(f"agent-tool-overexposure「{label}」：G4 靜態步驟執行失敗（{type(e).__name__}）")
            continue
        if bool(got) != want:
            fails.append(f"agent-tool-overexposure「{label}」：預期{'命中' if want else '不命中'}（得到 {got}）")

    with tempfile.TemporaryDirectory() as d:
        D = pathlib.Path(d)
        repo, out, outside = D / "proj", D / "out", D / "outside"
        (repo / "supabase/migrations").mkdir(parents=True); outside.mkdir()
        (repo / "AGENTS.md").write_text(f"Always be helpful.{zw}\n", encoding="utf-8")
        (repo / "supabase/migrations/001.sql").write_text("create table notes (id int);\n")
        (outside / "secret.md").write_text(f"host file{zw}\n", encoding="utf-8")
        (repo / "linked.md").symlink_to(outside / "secret.md")
        git(repo, "init", "-q"); git(repo, "add", "-A"); git(repo, "commit", "-qm", "c1")
        c1 = git(repo, "rev-parse", "HEAD").stdout.strip()
        # 被測專案自己放一份「有效」的審查紀錄（範本，commit 指向 c1）：外部目標不得採信
        rec = g4_review._example(); rec["commit"] = c1
        (repo / "reviews/g4").mkdir(parents=True)
        (repo / f"reviews/g4/{c1}.yaml").write_text(yaml.safe_dump(rec, allow_unicode=True), encoding="utf-8")
        git(repo, "add", "-A"); git(repo, "commit", "-qm", "self-review")
        head = git(repo, "rev-parse", "HEAD").stdout.strip()

        g = check(scan(repo, out, script), "外部目標")
        sp = out / "g4-static.sarif"
        sarif = json.loads(sp.read_text(encoding="utf-8")) if sp.is_file() else {"runs": []}
        hits = {(r["ruleId"], r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])
                for run in sarif["runs"] for r in run.get("results", [])}
        if ("vibesec.g4.rules-file-invisible-unicode", "AGENTS.md") not in hits \
                or not any(r == "vibesec.g4.supabase-table-without-rls" for r, _ in hits):
            fails.append(f"靜態檢查與 CI 同一份程式碼：隱形 Unicode、RLS（得到 {sorted(hits)}）")
        if any(u == "linked.md" for _, u in hits):
            fails.append("不跟隨 symlink 掃到目標以外的檔案")
        if g["commit"] != head or g["scope"] != "full":
            fails.append("gate JSON 的 commit 取目標 HEAD、scope full")
        llm = next((c for c in g["coverage"] if c["control_id"] == g4_review.LLM_CONTROL), {})
        if g["status"] != "incomplete" or llm.get("state") != "pending" or "不得自證" not in (g["status_reason"] or "") \
                or "審查紀錄 reviews/g4" in (g["status_reason"] or ""):
            fails.append(f"外部目標不採信目標自己的 reviews/g4 → LLM 審查 pending、G4 incomplete（得到 {g['status']}：{g['status_reason']}）")
        # 高危工具名在執行期組出：字面值會讓本 repo 自己的 G4 靜態檢查命中這支測試（同 run_evals.py PLACEHOLDERS 的做法）
        dangerous = "execute" + "_sql"
        (repo / "agent.py").write_text(f"@tool\ndef {dangerous}(q):\n    return db.run(q)\n")
        git(repo, "add", "-A"); git(repo, "commit", "-qm", "tool")
        g = check(scan(repo, out, script), "靜態 blocking")
        if g["status"] != "fail" or not g["findings_count"]["blocking"]:
            fails.append("Agent 高危工具（blocking）→ G4 fail")
        g = check(scan(repo, out, pathlib.Path(_wrap_dir.name) / "none.py"), "找不到腳本")
        if g["status"] != "incomplete" or STEP not in (g["status_reason"] or ""):
            fails.append("找不到靜態檢查腳本 → incomplete")
        # 接線（#183）：靜態檢查失敗的閘門結果經過閘門判定（GateRun），coverage 是完整的宣告清單：
        # 靜態控制 untested（未執行）、LLM 審查控制 pending 並寫明原因；tool 列只有 vibesec-g4-static 一列 error
        cov = [(c["control_id"], c["state"]) for c in g["coverage"]]
        want = [(c, "untested") for c in g4_static.CONTROLS if c != g4_static.LLM_CONTROL] + [(g4_static.LLM_CONTROL, "pending")]
        llm = next((c for c in g["coverage"] if c["control_id"] == g4_static.LLM_CONTROL), {})
        if cov != want or STEP not in (llm.get("reason") or "") or g["tools"] != [gate_result.tool(g4_static.TOOL_NAME, "error")] \
                or g["findings_count"] != {"blocking": 0, "advisory": 0}:
            fails.append(f"靜態檢查失敗 → coverage 為完整的宣告清單（靜態控制 untested、LLM pending 寫明原因）、tool 列 error（得到 {g['coverage']}、{g['tools']}）")
        # vibesec.yaml 的 mode 不合法：g4_static 的 argparse 擋下 → 靜態失敗路徑。閘門結果記 enforce、寫明原因、
        # 照樣產出 incomplete，不拋例外（#183 決定 1；g4_access 的 exit 1 代表「有 blocking」，崩潰會誤導）
        _yaml0 = g4_review._yaml
        g4_review._yaml = lambda path: ({**(_yaml0(path) or {}), "mode": "x"} if pathlib.Path(path).name == "vibesec.yaml" else _yaml0(path))
        try:
            g = check(scan(repo, out, script), "mode 不合法")
            if g["status"] != "incomplete" or g["mode"] != "enforce" or "mode 不合法" not in (g["status_reason"] or ""):
                fails.append(f"vibesec.yaml 的 mode 不合法 → incomplete、mode 記 enforce、寫明原因（得到 {g['status']}、{g['mode']}：{g['status_reason']}）")
        except Exception as e:
            fails.append(f"vibesec.yaml 的 mode 不合法 → 不得拋例外（得到 {type(e).__name__}：{e}）")
        finally:
            g4_review._yaml = _yaml0
        g = check(scan(repo, out, wrapped("boom", "print('boom', file=sys.stderr); sys.exit(3)")), "腳本失敗")   # 結果已寫出，但以非零結束
        if g["status"] != "incomplete" or "exit 3" not in (g["status_reason"] or "") or (out / "g4-static.sarif").exists():
            fails.append("靜態檢查失敗 → incomplete，且不留下舊的 SARIF")
        # 靜態檢查回報政策檔讀不到（g4_static：gate JSON 寫明未完成原因、tool error、不留 SARIF）→ 採用它的原因
        # （以前落到「exit 0：stdout 最後 200 字」，只是剛好被當成 incomplete）
        unreadable = ("import json\n"
                      "g = json.loads((out / 'g4-gate.json').read_text(encoding='utf-8'))\n"
                      "g.update(status='incomplete', status_reason='blocking-policy 無法讀取（ParserError），無法決定發現的 tier')\n"
                      "g['tools'][0].update(state='error', exit_code=None, output_ref=None)\n"
                      "(out / 'g4-gate.json').write_text(json.dumps(g), encoding='utf-8')\n"
                      "(out / 'g4-static.sarif').unlink()\n"
                      "sys.exit(rc)")
        g = check(scan(repo, out, wrapped("unreadable", unreadable)), "政策讀不到")
        why = g["status_reason"] or ""
        if g["status"] != "incomplete" or "blocking-policy 無法讀取" not in why or "exit 0" in why:
            fails.append(f"靜態檢查回報政策讀不到 → incomplete 並採用它的未完成原因（得到 {g['status']}：{why}）")
        g = check(scan(repo / "supabase", out, script), "子目錄")
        if g["status"] != "incomplete" or "根目錄" not in (g["status_reason"] or ""):
            fails.append("--target 不是 repo 根目錄 → incomplete")
        if git(repo, "status", "--porcelain").stdout.strip():
            fails.append("掃描不得改動被測專案的工作目錄")
    # 外部專案的紀錄放在本 repo 的 reviews/g4/external/<commit>.yaml（2026-10-06 人工決定）；以暫存 repo 代替本 repo
    with tempfile.TemporaryDirectory() as d:
        D = pathlib.Path(d)
        repo, out, home = D / "proj", D / "out", D / "vibesec"
        repo.mkdir(); home.mkdir()
        (repo / "app.py").write_text("print('ok')\n")
        git(repo, "init", "-q"); git(repo, "add", "-A"); git(repo, "commit", "-qm", "c1")
        c1 = git(repo, "rev-parse", "HEAD").stdout.strip()
        (home / "README.md").write_text("vibesec\n")
        git(home, "init", "-q"); git(home, "add", "-A"); git(home, "commit", "-qm", "base")
        rel = f"{EXTERNAL_REVIEWS}/{c1}.yaml"
        # 沒有待裁決發現、coverage 全部 pass 的紀錄：條件都滿足時 G4 會是 pass，才看得出信任上限有沒有生效
        rec = g4_review._example(); rec.update(commit=c1, findings=[])
        for c in rec["coverage"]:
            c.update(state="pass", reason=None)

        def put(record, name=c1):
            p = home / EXTERNAL_REVIEWS / f"{name}.yaml"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(yaml.safe_dump(record, allow_unicode=True), encoding="utf-8")

        def ext(why):
            g = check(scan(repo, out, script, review_root=home), why)
            return g, g["status_reason"] or "", next((c for c in g["coverage"] if c["control_id"] == g4_review.LLM_CONTROL), {})

        g, why, llm = ext("外部紀錄缺席")
        none_gate = g   # 沒有紀錄時就是靜態結果加上 LLM pending，用來推導有紀錄時的預期狀態
        if f"沒有 {rel}" not in why or llm.get("state") != "pending" or g["status"] != "incomplete":
            fails.append(f"沒有 reviews/g4/external/<HEAD>.yaml → LLM 審查 pending、G4 incomplete（得到 {g['status']}：{why}）")
        put(rec)   # 只放在工作目錄、尚未提交
        g, why, _ = ext("外部紀錄未提交")
        if f"審查紀錄 {rel}" not in why or "尚未提交到本 repo" not in why or g["status"] != "pending":
            fails.append(f"未提交到本 repo 的外部紀錄會被讀取但最高 pending（得到 {g['status']}：{why}）")
        git(home, "add", "-A"); git(home, "commit", "-qm", "record")
        committed, why, llm = ext("外部紀錄已提交")
        if f"審查紀錄 {rel}" not in why or "尚未提交" in why or committed["status"] != "pass" or llm.get("state") != "pass":
            fails.append(f"已提交、條件都滿足的外部紀錄 → G4 pass（得到 {committed['status']}：{why}）")
        put(dict(rec, recorded_by={**rec["recorded_by"], "note": "本機改過、未提交"}))   # 已追蹤，但工作目錄的內容不是提交的版本
        g, why, _ = ext("外部紀錄有未提交的修改")
        if g["status"] != "pending" or "尚未提交到本 repo" not in why:
            fails.append(f"外部紀錄在本 repo 有未提交的修改 → 最高 pending（得到 {g['status']}：{why}）")
        git(home, "checkout", "--", rel)
        rec_unsigned = dict(rec, recorded_by={"handle": ""})
        put(rec_unsigned); git(home, "commit", "-qam", "unsigned")
        g, why, _ = ext("外部紀錄未經人確認")
        if g["status"] == "pass" or "recorded_by.handle" not in why:
            fails.append(f"recorded_by.handle 空白的外部紀錄不能讓 G4 pass（得到 {g['status']}：{why}）")
        put(rec); git(home, "commit", "-qam", "signed")
        rec_human = g4_review._example(); rec_human["commit"] = c1   # 有待人工裁決的發現：照 g4_review 的規則推導
        put(rec_human); git(home, "commit", "-qam", "needs ruling")
        g, why, _ = ext("外部紀錄待裁決")
        ev = g4_review.evaluate(rec_human, g4_review.load_cfg(), g4_review.known_controls())
        expected = g4_review.derive_gate(none_gate, rec_human, ev, None, rel)["status"]
        if g["status"] != expected or "待人工裁決" not in why:
            fails.append(f"外部紀錄的狀態照 g4_review 的規則推導（預期 {expected}，得到 {g['status']}：{why}）")
        put(rec); git(home, "commit", "-qam", "signed again")
        (repo / "app.py").write_text("print('changed')\n")   # 目標有未提交的修改：掃描內容不是紀錄審查的 commit
        g, why, _ = ext("目標有未提交修改")
        if "未提交的修改" not in why or f"審查紀錄 {rel}" in why:
            fails.append(f"目標追蹤中檔案有未提交修改 → 不採用紀錄（得到 {g['status']}：{why}）")
        git(repo, "commit", "-qam", "c2")
        c2 = git(repo, "rev-parse", "HEAD").stdout.strip()
        g, why, _ = ext("目標前進")
        if f"沒有 {EXTERNAL_REVIEWS}/{c2}.yaml" not in why or f"審查紀錄 {rel}" in why:
            fails.append(f"目標 HEAD 前進後，舊 commit 的紀錄不再適用（得到 {g['status']}：{why}）")
        put(rec, c2)   # 檔名是 c2，內容審的是 c1
        g, why, _ = ext("檔名與 commit 不符")
        if "違規" not in why or "不一致" not in why or g["status"] == "pass":
            fails.append(f"檔名與紀錄 commit 不一致 → 紀錄違規、不採用（得到 {g['status']}：{why}）")
        if git(repo, "status", "--porcelain").stdout.strip():
            fails.append("掃描不得改動被測專案的工作目錄")
    # 目標是本 repo 的本機執行：工作目錄的紀錄與程式變更也要檢查（以暫存 repo 代替本 repo：改 g4_review 的 PROJECT）
    with tempfile.TemporaryDirectory() as d:
        D = pathlib.Path(d)
        repo, out = D / "self", D / "out"
        repo.mkdir()
        (repo / "app.py").write_text("print('ok')\n")
        git(repo, "init", "-q"); git(repo, "add", "-A"); git(repo, "commit", "-qm", "c1")
        c1 = git(repo, "rev-parse", "HEAD").stdout.strip()
        rel = f"reviews/g4/{c1}.yaml"
        rec = g4_review._example(); rec.update(commit=c1, findings=[])
        for c in rec["coverage"]:
            c.update(state="pass", reason=None)
        (repo / "reviews/g4").mkdir(parents=True)
        saved = g4_review.PROJECT, g4_review.REVIEWS_DIR
        g4_review.PROJECT, g4_review.REVIEWS_DIR = repo.resolve(), repo.resolve() / "reviews/g4"
        try:
            def own(why):
                g = check(scan(repo, out, script), why)
                return g, g["status_reason"] or "", next((c for c in g["coverage"] if c["control_id"] == g4_review.LLM_CONTROL), {})
            (repo / rel).write_text(yaml.safe_dump(rec, allow_unicode=True), encoding="utf-8")   # 只在工作目錄、尚未提交
            g, why, _ = own("本 repo 紀錄未提交")
            if "不得自證" in why or f"審查紀錄 {rel}" not in why or "尚未提交" not in why or g["status"] != "pending":
                fails.append(f"本 repo 未提交的 reviews/g4/<HEAD>.yaml 會被讀取但最高 pending（得到 {g['status']}：{why}）")
            git(repo, "add", "-A"); git(repo, "commit", "-qm", "record")
            g, why, llm = own("本 repo 紀錄已提交")
            if f"審查紀錄 {rel}" not in why or "尚未提交" in why or g["status"] != "pass" or llm.get("state") != "pass":
                fails.append(f"本 repo 已提交、條件都滿足的紀錄 → G4 pass（得到 {g['status']}：{why}）")
            (repo / rel).write_text(yaml.safe_dump(dict(rec, recorded_by={**rec["recorded_by"], "note": "本機改過"}),
                                                   allow_unicode=True), encoding="utf-8")
            g, why, _ = own("本 repo 紀錄有未提交的修改")
            if g["status"] != "pending" or "尚未提交" not in why:
                fails.append(f"本 repo 紀錄有未提交的修改 → 最高 pending（得到 {g['status']}：{why}）")
            git(repo, "checkout", "--", rel)
            (repo / "rulings").mkdir(); (repo / "rulings/r.yaml").write_text("a: 1\n")
            git(repo, "add", "rulings/r.yaml")   # 已暫存但未提交的 rulings/：不讓紀錄過期（同 freshness 的 FRESH_PREFIXES）
            g, why, _ = own("本 repo 只有 rulings 未提交")
            if "未提交的程式變更" in why or f"審查紀錄 {rel}" not in why:
                fails.append(f"只有 rulings/ 未提交 → 紀錄仍採用（得到 {g['status']}：{why}）")
            git(repo, "rm", "-q", "--cached", "rulings/r.yaml")
            (repo / "app.py").write_text("print('changed')\n")   # freshness 只比 commit..HEAD，看不到這個
            g, why, llm = own("本 repo 有未提交的程式變更")
            if g["status"] != "incomplete" or "未提交的程式變更" not in why or "app.py" not in why \
                    or f"審查紀錄 {rel}" in why or llm.get("state") != "pending":
                fails.append(f"本 repo 工作目錄有未提交的程式變更 → 紀錄過期、G4 incomplete（得到 {g['status']}：{why}）")
            git(repo, "checkout", "--", "app.py")
            for bad, label in (("{", "損毀"), ("{}", "缺欄位")):   # 靜態結果檔無法使用 → incomplete，不是 traceback
                g = check(scan(repo, out, wrapped(f"bad{len(bad)}", f"(out / 'g4-gate.json').write_text({bad!r}); sys.exit(rc)")),
                          f"g4-gate.json {label}")
                if g["status"] != "incomplete" or "無法解析" not in (g["status_reason"] or ""):
                    fails.append(f"g4-gate.json {label} → incomplete 並寫明理由（得到 {g['status']}：{g['status_reason']}）")
        finally:
            g4_review.PROJECT, g4_review.REVIEWS_DIR = saved
    # mcp_resource_indicator：判定案例在 scripts/g4_mcp.py selftest；這裡驗證經 CI 同一段靜態步驟併進 gate JSON 與 SARIF
    imp, srv = "from " + "mcp.server.fastmcp import FastMCP\n", "mcp = Fast" + "MCP('notes')\n"
    with tempfile.TemporaryDirectory() as d:   # 經 scan：發現進 SARIF 與 findings_count，coverage 有 VS-G4-MCP-RESOURCE-INDICATOR
        repo, out = pathlib.Path(d) / "proj", pathlib.Path(d) / "out"
        repo.mkdir()
        (repo / "server.py").write_text(imp + srv + "claims = jwt.decode(tok, key)\n", encoding="utf-8")
        git(repo, "init", "-q"); git(repo, "add", "-A"); git(repo, "commit", "-qm", "c1")
        g = check(scan(repo, out, script), "MCP 經 scan")
        sarif = json.loads((out / "g4-static.sarif").read_text(encoding="utf-8"))
        hits = [r for run in sarif["runs"] for r in run["results"] if r["ruleId"] == MCP_RULE]
        cov = next((c for c in g["coverage"] if c["control_id"] == MCP_CONTROL), {})
        if len(hits) != 1 or hits[0]["properties"]["policy_tier"] != "advisory" or cov.get("state") != "fail" \
                or g["findings_count"]["advisory"] < 1 or g["status"] == "pass":
            fails.append(f"MCP 缺綁定經 scan → SARIF 一筆 advisory、coverage fail（得到 {len(hits)} 筆、{cov}、{g['findings_count']}）")
    # 靜態檢查腳本本身（不經 g4_access 的後處理）：gate JSON 一定含 VS-G4-MCP-RESOURCE-INDICATOR；
    # 腳本所在的受信任樹（CI 的 _trusted/）沒有 scripts/g4_mcp.py → 該控制 untested 並寫進 status_reason，不崩潰、不記 pass
    def run_step(cwd: pathlib.Path, step_script: pathlib.Path):
        p = subprocess.run([sys.executable, "-I", str(step_script), "--target", str(cwd), "--out", str(cwd / "reports"),
                            "--mode", "shadow"], capture_output=True, text=True, timeout=120)
        gp = cwd / "reports/g4-gate.json"
        return p.returncode, (json.loads(gp.read_text(encoding="utf-8")) if gp.is_file() else None)
    with tempfile.TemporaryDirectory() as d:
        D = pathlib.Path(d)
        proj, trusted = D / "proj", D / "trusted"
        proj.mkdir(); (trusted / "scripts").mkdir(parents=True); (trusted / "config/policy").mkdir(parents=True)
        (proj / "app.py").write_text("print('no mcp here')\n", encoding="utf-8")
        rc, g = run_step(proj, script)
        cov = next((c for c in (g or {}).get("coverage", []) if c["control_id"] == MCP_CONTROL), None)
        if rc != 0 or not g or not cov or cov["state"] != "not_applicable" or not cov.get("reason"):
            fails.append(f"靜態檢查腳本：沒有 MCP → coverage 應含 {MCP_CONTROL} not_applicable 並附理由（exit {rc}，{cov}）")
        elif g:
            check(g, "靜態檢查腳本（無 MCP）")
        for rel in ("vibesec.yaml", "config/policy/blocking-policy.yaml", "scripts/vibesec_policy.py", "scripts/gate_verdict.py",
                    "scripts/vibesec_mode.py", "scripts/gate_result.py", "scripts/g4_static.py"):
            (trusted / rel).write_text((ROOT / rel).read_text(encoding="utf-8"), encoding="utf-8")
        (proj / "reports/g4-gate.json").unlink(missing_ok=True)   # 不讓上一次的閘門結果被當成這一次的（腳本崩潰時會讀到舊檔）
        rc, g = run_step(proj, trusted / "scripts/g4_static.py")   # 受信任樹缺 g4_mcp.py（例如 default branch 尚未合併本模組）
        cov = next((c for c in (g or {}).get("coverage", []) if c["control_id"] == MCP_CONTROL), None)
        if rc != 0 or not g or not cov or cov["state"] != "untested" or "g4_mcp" not in (g.get("status_reason") or ""):
            fails.append(f"靜態檢查腳本：缺 scripts/g4_mcp.py → {MCP_CONTROL} untested 並寫進 status_reason（exit {rc}，{cov}）")
        elif g["status"] == "pass":
            fails.append("靜態檢查腳本：MCP 檢查無法執行時 G4 不得記 pass")
        else:
            check(g, "靜態檢查腳本（缺 g4_mcp）")
    # 目標是本 repo：與 CI 相同，從 reviews/g4 找紀錄（本 repo 目前沒有 → 標準的 pending 理由）
    with tempfile.TemporaryDirectory() as d:
        g = check(scan(ROOT, pathlib.Path(d), script), "本 repo")
        if "不得自證" in (g["status_reason"] or "") or g["status"] not in ("incomplete", "pending", "pass", "fail"):
            fails.append("目標是本 repo 時照 CI 的方式讀 reviews/g4，不套用外部專案的規則")
    _wrap_dir.cleanup()
    return fails


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["selftest"]:
        fails = selftest()
        for f in fails:
            print(f"FAIL {f}")
        print("selftest " + ("通過" if not fails else f"失敗 {len(fails)} 項"))
        return 1 if fails else 0
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--target", default=str(ROOT), help="被掃描的 git repo 根目錄（預設本 repo）")
    ap.add_argument("--out-dir", default="reports/raw/G4", help="靜態檢查 SARIF 的輸出目錄")
    ap.add_argument("--gate", default="reports/gates/G4.json", help="G4 gate JSON 輸出路徑")
    a = ap.parse_args(argv)
    target = pathlib.Path(a.target).expanduser()
    g4 = ((g4_review._yaml(ROOT / "vibesec.yaml").get("gates") or {}).get("g4_access_control_review") or {})
    g = scan(target, pathlib.Path(a.out_dir), STATIC_SCRIPT, int(g4.get("timeout_seconds") or 900))
    pathlib.Path(a.gate).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(a.gate).write_text(json.dumps(g, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"G4 {g['status']}（{target.resolve()}）：blocking={g['findings_count']['blocking']} "
          f"advisory={g['findings_count']['advisory']}" + (f"；{g['status_reason']}" if g["status_reason"] else ""))
    if g["findings_count"]["blocking"]:
        return 1
    return 0 if g["status"] == "pass" else 2


if __name__ == "__main__":
    sys.exit(main())
