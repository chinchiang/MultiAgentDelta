#!/usr/bin/env python3
"""G2 機密掃描（本機／harness 版）— gitleaks 全 Git 歷史 + .env 防護；可用 --target 掃其他專案。

與 .github/workflows/pr-gates.yml 的 G2 job 對齊：gitleaks 用本 repo 的 config/gitleaks.toml；.env 檢查同
scripts/env_guard.py；gate JSON 由 scripts/sarif_gate.py 的 derive() 推導（同一份規則對應、tier 與 coverage）。

--target <dir>：被掃描的 git repo 根目錄（預設本 repo）。設定與阻擋政策一律取自本 repo，輸出寫在本 repo
  （不寫進被測專案）。blocking-policy 的 exceptions 只核准給本 repo 的路徑，掃其他專案時不套用；
  目標專案自己的 `gitleaks:allow` 註解也不採信（--ignore-gitleaks-allow），例外只能經 blocking-policy 核准。
原則（CLAUDE.md #2）：gitleaks 缺席／逾時／失敗、目標不是 git repo 根目錄、shallow clone（不是全歷史）
  → incomplete，絕不視為通過。報告只留遮罩（gitleaks --redact），不印出原始祕密（CLAUDE.md #7）。

用法：python3 scripts/g2_secrets.py [--target <dir>] [--out-dir reports/raw/G2] [--gate reports/gates/G2.json]
      python3 scripts/g2_secrets.py selftest
gitleaks 路徑：$VIBESEC_GITLEAKS，否則 PATH 上的 gitleaks（需 v8.19+ 的 `gitleaks git` 子命令）。
退出碼：0 無 blocking 且完成；1 有 blocking 發現；2 無法完成（incomplete）。
"""
from __future__ import annotations
import argparse, datetime, json, os, pathlib, shutil, subprocess, sys, time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import sarif_gate  # noqa: E402  缺 PyYAML 時以 exit 2 結束（無法判定，不視為通過）
from env_guard import record as env_record  # noqa: E402


def _git(target: pathlib.Path, *args: str) -> str | None:
    try:
        r = subprocess.run(["git", *args], capture_output=True, text=True, cwd=target)
    except OSError:
        return None
    return r.stdout.strip() if r.returncode == 0 else None


def repo_problem(target: pathlib.Path) -> str | None:
    """全歷史掃描的前提：目標是 git repo 的根目錄，而且不是 shallow clone。"""
    top = _git(target, "rev-parse", "--show-toplevel")
    if top is None:
        return f"目標不是 git repo（{target}），無法掃全 Git 歷史"
    if pathlib.Path(top).resolve() != target.resolve():
        return f"--target 必須是 git repo 根目錄（{top}），否則 .gitignore 與歷史範圍不一致"
    if _git(target, "rev-parse", "--is-shallow-repository") == "true":
        return "目標是 shallow clone，不是全 Git 歷史（先 git fetch --unshallow）"
    return None


def run_gitleaks(binary: str | None, target: pathlib.Path, sarif: pathlib.Path, external: bool,
                 timeout: int) -> dict:
    """執行 gitleaks；回傳 tools[] 一列（state: ran / missing / timeout / error）與失敗原因。"""
    row = {"name": "gitleaks", "version": None, "state": "missing", "exit_code": None,
           "output_ref": str(sarif), "duration_seconds": None, "reason": None}
    sarif.unlink(missing_ok=True)            # 不讓上一次的輸出被當成這次的結果
    if not binary:
        row["reason"] = "gitleaks binary not found in PATH"
        return row
    try:
        row["version"] = subprocess.run([binary, "version"], capture_output=True, text=True,
                                        timeout=30).stdout.strip().lstrip("v") or None
    except (OSError, subprocess.TimeoutExpired):
        pass
    cmd = [binary, "git", str(target), "--config", str(ROOT / "config/gitleaks.toml"),
           "--report-format", "sarif", "--report-path", str(sarif),
           "--redact", "--no-banner", "--log-level", "warn", "--exit-code", "0"]
    if external:
        cmd.append("--ignore-gitleaks-allow")
    t0 = time.monotonic()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        row.update(state="timeout", duration_seconds=round(time.monotonic() - t0, 1),
                   reason=f"gitleaks 逾時（{timeout}s）")
        sarif.unlink(missing_ok=True)
        return row
    except OSError as e:
        row.update(state="error", reason=f"gitleaks 無法執行（{type(e).__name__}）")
        return row
    row.update(exit_code=p.returncode, duration_seconds=round(time.monotonic() - t0, 1))
    if p.returncode != 0 or not sarif.is_file():
        row.update(state="error", reason=f"gitleaks exit {p.returncode}：{p.stderr.strip()[-200:]}")
        sarif.unlink(missing_ok=True)
        return row
    row["state"] = "ran"
    return row


def scan(target: pathlib.Path, out_dir: pathlib.Path, binary: str | None, timeout: int,
         pol: dict | None = None, policy_root: pathlib.Path = ROOT) -> dict:
    """掃描目標專案並回傳 G2 gate JSON（schemas/gate-result.schema.json）。
    pol：sarif_gate.load_context 的結果（selftest 注入）；沒給 → 以 policy_root 的政策建立，讀不到 → 不掃描、incomplete。"""
    started = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    target = target.resolve()
    if pol is None:   # 只建立一次；政策讀不到 → 不跑 gitleaks，直接回傳 incomplete
        pol, unreadable = sarif_gate.context_or_unreadable("G2", policy_root, started)
        if unreadable:
            return unreadable
    pol = dict(pol)
    external = not pol["policy"].is_this_repo(target)   # 與例外是否套用同一份判斷（Policy；含 VIBESEC_PROJECT_ROOT）
    project = pol["policy"].for_project(target)          # 受驗樹的政策例外：外部專案 → 沒有任何例外，note 說明
    notes = []
    if external:
        notes.append(f"{project.note}；目標專案的 gitleaks:allow 註解不採信")
        if (target / ".gitleaksignore").exists():
            notes.append("目標專案有 .gitleaksignore，gitleaks 會略過其中的指紋（未經 blocking-policy 核准，需人工確認）")
    out_dir.mkdir(parents=True, exist_ok=True)
    sarif, envcheck = out_dir / "gitleaks.sarif", out_dir / "g2-envcheck.json"
    problem = repo_problem(target)
    if problem:
        sarif.unlink(missing_ok=True); envcheck.unlink(missing_ok=True)
        row = {"name": "gitleaks", "version": None, "state": "error", "exit_code": None,
               "output_ref": str(sarif), "duration_seconds": None, "reason": problem}
    else:
        row = run_gitleaks(binary, target, sarif, external, timeout)
        # .gitignore 少規則、已提交的 .env、git 失敗分開記（env_guard.record）；以前三種壓成 env_gitignore_fail 一個旗標，
        # 已提交的 .env 只記成 advisory 的 env-not-ignored（位置 .gitignore），G2 照樣 pass
        envcheck.write_text(json.dumps(env_record(target), ensure_ascii=False), encoding="utf-8")
    gate = sarif_gate.derive("G2", {"gitleaks": sarif}, envcheck, pol, project, started)
    reason = row.pop("reason")
    gate["tools"] = [dict(t, **row) if t["name"] == "gitleaks" else t for t in gate["tools"]]
    if reason:
        notes.insert(0, reason)
    if notes:
        gate["status_reason"] = "；".join(([gate["status_reason"]] if gate["status_reason"] else []) + notes)
    gate.update(scope="full", diff_base=None, commit=_git(target, "rev-parse", "HEAD") if not problem else None)
    return gate


def configured_timeout(path: pathlib.Path = ROOT / "vibesec.yaml", default: int = 300) -> int:
    """vibesec.yaml gates.g2_secrets.timeout_seconds；讀不到、YAMLError 或結構不符 → 預設值（只影響逾時，不影響結論）。"""
    import yaml
    try:
        return int((((yaml.safe_load(path.read_text(encoding="utf-8")) or {})
                     .get("gates") or {}).get("g2_secrets") or {}).get("timeout_seconds") or default)
    except (OSError, ValueError, TypeError, AttributeError, yaml.YAMLError):
        return default


# ------------------------------------------------------------------ selftest
def selftest() -> list[str]:
    import tempfile
    from jsonschema import Draft202012Validator
    fails: list[str] = []
    schema = Draft202012Validator(json.loads((ROOT / "schemas/gate-result.schema.json").read_text(encoding="utf-8")))
    from vibesec_policy import Policy, temp_policy_root
    # 合成例外（不依賴政策檔現有例外與其到期日）：暫存 root 放本 repo 政策的副本，只換掉 exceptions；外部目標必須忽略它
    with temp_policy_root([{"rule_id": r, "path_glob": "examples/vulnapp/app/main.py", "reason": "selftest",
                           "approved_by": "selftest", "expires": "2099-12-31"}
                          for r in ("vibesec.g2.hardcoded-secret", "vibesec.g2.hardcoded-llm-key")]) as PR:
        pol = sarif_gate.load_context(Policy(PR, project_root=None))   # 建構時讀完政策檔；不受 VIBESEC_PROJECT_ROOT 影響
    git = lambda d, *a: subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *a], cwd=d,
                                       capture_output=True, check=True)
    with tempfile.TemporaryDirectory() as d:
        D = pathlib.Path(d)
        repo, out = D / "proj", D / "out"
        repo.mkdir()
        (repo / ".gitignore").write_text(".env*\n")
        git(repo, "init", "-q"); git(repo, "add", "."); git(repo, "commit", "-qm", "t")
        # 假 gitleaks：依環境變數寫出 SARIF（含一筆會對到 hardcoded-secret 的結果）或失敗
        fake = D / "gitleaks"
        fake.write_text("#!/bin/sh\n[ \"$1\" = version ] && { echo 8.28.0; exit 0; }\n"
                        "[ -n \"$FAKE_FAIL\" ] && { echo boom >&2; exit 3; }\n"
                        "while [ $# -gt 0 ]; do [ \"$1\" = --report-path ] && R=$2; shift; done\n"
                        "printf '%s' \"$FAKE_SARIF\" > \"$R\"\n")
        fake.chmod(0o755)
        sarif = lambda *res: json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "gitleaks"}},
                                                                        "results": list(res)}]})
        hit = lambda uri: {"ruleId": "vibesec-openai-api-key",
                           "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}]}

        def run(target, binary=str(fake), env=None):
            os.environ.update(env or {})
            try:
                g = scan(target, out, binary, 60, pol)
            finally:
                for k in env or {}:
                    os.environ.pop(k, None)
            errs = list(schema.iter_errors(g))
            if errs:
                fails.append(f"gate JSON 不符 schema：{errs[0].message}")
            return g

        g = run(repo, env={"FAKE_SARIF": sarif()})
        head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=repo).stdout.strip()
        if g["status"] != "pass" or g["commit"] != head or g["scope"] != "full":
            fails.append(f"外部目標無發現、.env 已忽略 → pass，commit 取目標 HEAD（得到 {g['status']}）")
        if "exceptions" not in (g["status_reason"] or ""):
            fails.append("外部目標 → status_reason 註明 blocking-policy 例外未套用")
        g = run(repo, env={"FAKE_SARIF": sarif(hit("examples/vulnapp/app/main.py"))})
        if g["status"] != "fail" or not g["findings_count"]["blocking"]:
            fails.append("外部目標：本 repo 對 examples/vulnapp/app/main.py 的例外不得套用（仍為 blocking → fail）")
        g = run(repo, binary=None)
        if g["status"] != "incomplete" or "not found" not in (g["status_reason"] or "") or g["tools"][0]["state"] != "missing":
            fails.append("gitleaks 缺席 → incomplete（state missing），不是 pass")
        g = run(repo, env={"FAKE_FAIL": "1"})
        if g["status"] != "incomplete" or g["tools"][0]["state"] != "error" or g["tools"][0]["exit_code"] != 3:
            fails.append("gitleaks 非零結束 → incomplete（state error、記 exit_code）")
        (repo / ".gitignore").write_text("node_modules/\n")
        g = run(repo, env={"FAKE_SARIF": sarif()})
        if g["status"] != "pass" or g["findings_count"]["advisory"] + g["findings_count"]["blocking"] != 1:
            fails.append(".gitignore 未含 .env → env-not-ignored 發現（依政策 tier）")
        # 已提交的 .env（.gitignore 有規則，但 git add -f 強制追蹤）：以前記成「.gitignore 少規則」（env-not-ignored）
        (repo / ".gitignore").write_text(".env*\n")
        (repo / ".env").write_text("DB_PASSWORD=hunter2\n")
        git(repo, "add", "-f", ".gitignore", ".env"); git(repo, "commit", "-qm", "oops")
        g = run(repo, env={"FAKE_SARIF": sarif()})
        rec = json.loads((out / "g2-envcheck.json").read_text(encoding="utf-8"))
        if rec.get("committed") != [".env"] or rec.get("env_gitignore_fail") or rec.get("error"):
            fails.append(f"已提交的 .env 應記在 committed（vibesec.g2.env-committed），不是 .gitignore 少規則（得到 {rec}）")
        if g["findings_count"]["advisory"] + g["findings_count"]["blocking"] != 1:
            fails.append(f"已提交的 .env → 一筆發現（得到 {g['findings_count']}）")
        # tier 依 blocking-policy：政策把 env-committed 列為 blocking 時，同一個目標必須 fail
        class _Blocking:
            def __init__(self, inner): self.inner = inner
            def tier(self, rid): return "blocking" if rid == "vibesec.g2.env-committed" else self.inner.tier(rid)
            def __getattr__(self, name): return getattr(self.inner, name)   # 其餘（for_project 等）照實際政策
        pol_saved = dict(pol); pol["policy"] = _Blocking(pol["policy"])
        try:
            g = run(repo, env={"FAKE_SARIF": sarif()})
        finally:
            pol.clear(); pol.update(pol_saved)
        if g["status"] != "fail" or g["findings_count"]["blocking"] != 1:
            fails.append(f"env-committed 為 blocking 時，已提交的 .env → fail（得到 {g['status']}）")
        git(repo, "rm", "-q", "--cached", ".env"); git(repo, "commit", "-qm", "fix")
        sub = repo / "sub"; sub.mkdir()
        g = run(sub, env={"FAKE_SARIF": sarif()})
        if g["status"] != "incomplete" or "根目錄" not in (g["status_reason"] or ""):
            fails.append("--target 不是 repo 根目錄 → incomplete")
        g = run(D / "out", env={"FAKE_SARIF": sarif()})
        if g["status"] != "incomplete" or "不是 git repo" not in (g["status_reason"] or ""):
            fails.append("目標不是 git repo → incomplete")
        if any(p.is_relative_to(repo) for p in out.iterdir()):
            fails.append("輸出不得寫進被測專案")
        # vibesec.yaml 壞掉（YAMLError、結構不符）→ 用預設逾時，不得讓 main 以例外結束
        vb = D / "vibesec.yaml"
        for label, body, want in [("壞 YAML", "gates: [\n", 300), ("gates 是清單", "gates: [1]\n", 300),
                                  ("有設定", "gates:\n  g2_secrets:\n    timeout_seconds: 42\n", 42)]:
            vb.write_text(body)
            try:
                got = configured_timeout(vb)
            except Exception as e:
                got = f"例外 {type(e).__name__}"
            if got != want:
                fails.append(f"vibesec.yaml {label} → 逾時 {want}（得到 {got}）")
    # 政策檔讀不到 → scan 一開始就停：不跑 gitleaks、G2 incomplete、控制 untested 並寫明未完成原因、沒有任何發現
    from vibesec_policy import POLICY_UNREADABLE, broken_policy_root
    with broken_policy_root() as pr, tempfile.TemporaryDirectory() as d:
        g = scan(pathlib.Path(d), pathlib.Path(d, "out"), None, 60, policy_root=pr)
        why = g["status_reason"] or ""
        if g["status"] != "incomplete" or POLICY_UNREADABLE + "（" not in why or "not found" in why \
                or {c["state"] for c in g["coverage"]} != {"untested"} or g["findings_count"] != {"blocking": 0, "advisory": 0} \
                or list(schema.iter_errors(g)):
            fails.append(f"政策檔讀不到 → 不跑 gitleaks、G2 incomplete、控制 untested、寫明原因（得到 {g}）")
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
    ap.add_argument("--out-dir", default="reports/raw/G2", help="gitleaks SARIF 與 envcheck 的輸出目錄")
    ap.add_argument("--gate", default="reports/gates/G2.json", help="G2 gate JSON 輸出路徑")
    a = ap.parse_args(argv)
    target = pathlib.Path(a.target).expanduser()
    timeout = configured_timeout()
    binary = os.environ.get("VIBESEC_GITLEAKS") or shutil.which("gitleaks")
    g = scan(target, pathlib.Path(a.out_dir), binary, timeout)
    pathlib.Path(a.gate).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(a.gate).write_text(json.dumps(g, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"G2 {g['status']}（{target.resolve()}）：blocking={g['findings_count']['blocking']} "
          f"advisory={g['findings_count']['advisory']}" + (f"；{g['status_reason']}" if g["status_reason"] else ""))
    if g["findings_count"]["blocking"]:
        return 1
    return 2 if g["status"] == "incomplete" else 0


if __name__ == "__main__":
    sys.exit(main())
