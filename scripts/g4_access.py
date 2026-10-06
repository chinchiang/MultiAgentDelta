#!/usr/bin/env python3
"""G4 架構與存取控制（本機／harness 版）— 靜態檢查 + LLM 審查紀錄；可用 --target 掃其他專案。

靜態檢查（隱形 Unicode、Supabase RLS、Agent 工具 allow-list、單層 middleware）直接執行
.github/workflows/pr-gates.yml「G4 靜態檢查」步驟的同一段程式碼（scripts/run_evals.py 的 G4 評測也這樣做），
不另寫一份；tier 由該程式碼以本 repo 的 blocking-policy 計算（VIBESEC_CONFIG 指向本 repo）。
該程式碼會走訪工作目錄並寫出 reports/，所以在目標「追蹤中檔案」的暫存副本上執行（同 G3：不跟隨 symlink），
不寫進被測專案。

VS-G4-LLM-REVIEW（LLM 審查紀錄）：
- 目標是本 repo：與 CI 相同，以 scripts/g4_review.py 從 reviews/g4/ 找對 HEAD 有效的紀錄並推導狀態
  （本機沒有 PR，紀錄不檢查 approve；CI 會另外檢查）。
- 目標是外部專案：不讀目標的 reviews/g4/ 與 rulings/——那是被測專案自己寫的，等於自證；本 repo 的紀錄也只審本 repo。
  VS-G4-LLM-REVIEW 維持 pending，G4 最多 incomplete（有靜態 blocking 則 fail）。外部專案審查紀錄的存放與核准流程
  需人工決定（CLAUDE.md 規則 1）。
原則（CLAUDE.md #2）：靜態檢查程式碼找不到或執行失敗、目標不是 git repo 根目錄 → incomplete，絕不視為通過。

用法：python3 scripts/g4_access.py [--target <dir>] [--out-dir reports/raw/G4] [--gate reports/gates/G4.json]
      python3 scripts/g4_access.py selftest
退出碼：0 無 blocking；1 有 blocking 發現；2 incomplete／pending（LLM 審查未完成時一律如此）。
"""
from __future__ import annotations
import argparse, datetime, json, os, pathlib, shutil, subprocess, sys, tempfile, time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import g4_review  # noqa: E402  審查紀錄的驗證與狀態推導（缺 PyYAML／jsonschema 時以 exit 2 結束）
from g3_sast import copy_tracked, _git  # noqa: E402  同一份「追蹤中檔案、不跟隨 symlink」的副本

WORKFLOW = ROOT / ".github/workflows/pr-gates.yml"
STEP = "G4 靜態檢查"
EXTERNAL_LLM = ("外部專案的 G4 LLM 審查紀錄不採信：目標的 reviews/g4、rulings 是被測專案自己寫的（不得自證），"
                "本 repo 的紀錄只審本 repo；外部專案審查紀錄的存放與核准流程需人工決定")


def static_step_code(workflow: pathlib.Path = WORKFLOW) -> str | None:
    """pr-gates.yml 中「G4 靜態檢查」步驟的 run 內容（與 CI、run_evals.py 同一份）。"""
    import yaml
    wf = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    for job in (wf.get("jobs") or {}).values():
        for st in job.get("steps") or []:
            if str(st.get("name", "")).startswith(STEP):
                return st.get("run")
    return None


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def run_static(target: pathlib.Path, out_dir: pathlib.Path, code: str | None, commit: str | None, mode: str,
               timeout: int) -> tuple[dict | None, str | None, list[str]]:
    """在目標追蹤中檔案的副本上執行靜態檢查。回傳 (靜態 gate JSON, 失敗原因, 附註)。"""
    if not code:
        return None, f"{WORKFLOW.name} 找不到「{STEP}」步驟", []
    notes = []
    with tempfile.TemporaryDirectory(prefix="vibesec-g4-") as tmp:
        copy = pathlib.Path(tmp) / "vibesec-target"
        copy.mkdir()
        skipped = copy_tracked(target, copy)
        if skipped:
            notes.append(f"靜態檢查略過 {skipped} 個 symlink（不跟隨到目標以外的檔案）")
        env = {**os.environ, "VIBESEC_MODE": mode, "COMMIT_SHA": commit or "",
               "VIBESEC_CONFIG": str(ROOT / "vibesec.yaml")}
        t0 = time.monotonic()
        try:
            p = subprocess.run(["bash", "-e", "-c", code], env=env, cwd=copy, capture_output=True, text=True,
                               timeout=timeout)
        except subprocess.TimeoutExpired:
            return None, f"G4 靜態檢查逾時（{timeout}s）", notes
        except OSError as e:
            return None, f"G4 靜態檢查無法執行（{type(e).__name__}）", notes
        reports = copy / "reports"
        gate_p, sarif_p = reports / "g4-gate.json", reports / "g4-static.sarif"
        # enforce 且有 blocking 時該步驟以 exit 1 結束（CI 用來擋 merge），結果仍有效；其餘非零、或沒寫出結果 → 失敗
        if p.returncode not in (0, 1) or not gate_p.is_file() or not sarif_p.is_file():
            return None, f"G4 靜態檢查 exit {p.returncode}：{(p.stderr or p.stdout).strip()[-200:]}", notes
        static = json.loads(gate_p.read_text(encoding="utf-8"))
        if p.returncode == 1 and not static["findings_count"]["blocking"]:
            return None, f"G4 靜態檢查 exit 1 但沒有 blocking 發現：{(p.stderr or p.stdout).strip()[-200:]}", notes
        out_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(sarif_p, out_dir / "g4-static.sarif")
    for t in static.get("tools") or []:
        if t.get("name") == "vibesec-g4-static":
            t.update(output_ref=str(out_dir / "g4-static.sarif"), exit_code=p.returncode,
                     duration_seconds=round(time.monotonic() - t0, 1))
    return static, None, notes


def scan(target: pathlib.Path, out_dir: pathlib.Path, code: str | None = None, timeout: int = 900) -> dict:
    """掃描目標專案並回傳 G4 gate JSON（schemas/gate-result.schema.json）。"""
    started = _now()
    target, out_dir = target.resolve(), out_dir.resolve()
    external = target != ROOT.resolve()
    (out_dir / "g4-static.sarif").unlink(missing_ok=True)   # 不讓上一次的輸出被當成這次的結果
    mode = (g4_review._yaml(ROOT / "vibesec.yaml") or {}).get("mode", "shadow")
    top = _git(target, "rev-parse", "--show-toplevel")
    problem = (f"目標不是 git repo（{target}）" if top is None else
               None if pathlib.Path(top).resolve() == target else f"--target 必須是 git repo 根目錄（{top}）")
    commit = _git(target, "rev-parse", "HEAD") if not problem else None
    static, why, notes = (None, problem, []) if problem else run_static(target, out_dir, code, commit, mode, timeout)
    if static is None:
        return {"gate": "G4", "status": "incomplete", "status_reason": why, "mode": mode, "scope": "full",
                "diff_base": None, "commit": commit, "started_at": started, "finished_at": _now(),
                "tools": [{"name": "vibesec-g4-static", "version": None, "state": "error", "exit_code": None,
                           "output_ref": None, "duration_seconds": None}],
                "findings_count": {"blocking": 0, "advisory": 0},
                "coverage": [{"control_id": g4_review.LLM_CONTROL, "state": "pending", "reason": why}]}
    if external:
        gate = g4_review.derive_gate(static, None, None, EXTERNAL_LLM, None)
    else:
        cfg, controls = g4_review.load_cfg(), g4_review.known_controls()
        record, ev, ref, reason = g4_review.find_record(commit, cfg, controls)
        gate = g4_review.derive_gate(static, record, ev, reason, ref)
        if record is not None:
            cap = g4_review.trust_cap(False, record["recorded_by"].get("handle", ""), None, [])
            if cap:
                g4_review.apply_cap(gate, cap)
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
    code = static_step_code()
    if not code:
        return [f"{WORKFLOW.name} 找不到「{STEP}」步驟"]
    git = lambda d, *a: subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *a], cwd=d,
                                       capture_output=True, check=True, text=True)
    zw = "​"   # 零寬空白：Rules File Backdoor 的典型手法

    def check(g, why):
        errs = list(schema.iter_errors(g))
        if errs:
            fails.append(f"{why}：gate JSON 不符 schema（{errs[0].message}）")
        return g

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

        g = check(scan(repo, out, code), "外部目標")
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
        (repo / "agent.py").write_text("@tool\ndef execute_sql(q):\n    return db.run(q)\n")
        git(repo, "add", "-A"); git(repo, "commit", "-qm", "tool")
        g = check(scan(repo, out, code), "靜態 blocking")
        if g["status"] != "fail" or not g["findings_count"]["blocking"]:
            fails.append("Agent 高危工具（blocking）→ G4 fail")
        g = check(scan(repo, out, None), "找不到步驟")
        if g["status"] != "incomplete" or STEP not in (g["status_reason"] or ""):
            fails.append("找不到 CI 的靜態檢查步驟 → incomplete")
        g = check(scan(repo, out, code + "\necho boom >&2; exit 3\n"), "步驟失敗")   # 結果已寫出，但步驟以非零結束
        if g["status"] != "incomplete" or "exit 3" not in (g["status_reason"] or "") or (out / "g4-static.sarif").exists():
            fails.append("靜態檢查失敗 → incomplete，且不留下舊的 SARIF")
        g = check(scan(repo / "supabase", out, code), "子目錄")
        if g["status"] != "incomplete" or "根目錄" not in (g["status_reason"] or ""):
            fails.append("--target 不是 repo 根目錄 → incomplete")
        if git(repo, "status", "--porcelain").stdout.strip():
            fails.append("掃描不得改動被測專案的工作目錄")
    # 目標是本 repo：與 CI 相同，從 reviews/g4 找紀錄（本 repo 目前沒有 → 標準的 pending 理由）
    with tempfile.TemporaryDirectory() as d:
        g = check(scan(ROOT, pathlib.Path(d), code), "本 repo")
        if "不得自證" in (g["status_reason"] or "") or g["status"] not in ("incomplete", "pending", "pass", "fail"):
            fails.append("目標是本 repo 時照 CI 的方式讀 reviews/g4，不套用外部專案的規則")
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
    g = scan(target, pathlib.Path(a.out_dir), static_step_code(), int(g4.get("timeout_seconds") or 900))
    pathlib.Path(a.gate).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(a.gate).write_text(json.dumps(g, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"G4 {g['status']}（{target.resolve()}）：blocking={g['findings_count']['blocking']} "
          f"advisory={g['findings_count']['advisory']}" + (f"；{g['status_reason']}" if g["status_reason"] else ""))
    if g["findings_count"]["blocking"]:
        return 1
    return 0 if g["status"] == "pass" else 2


if __name__ == "__main__":
    sys.exit(main())
