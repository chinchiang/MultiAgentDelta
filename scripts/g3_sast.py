#!/usr/bin/env python3
"""G3 SAST／IaC（本機／harness 版）— semgrep + checkov + trivy config；可用 --target 掃其他專案。

與 .github/workflows/pr-gates.yml 的 G3 jobs 對齊：semgrep 用 vibesec.yaml gates.g3_sast_iac.semgrep_rules
（本 repo 規則 + p/owasp-top-ten + p/security-audit）；checkov 用 config/checkov/.checkov.yaml（check allow-list 與
custom 檢查）；trivy config；gate JSON 由 scripts/sarif_gate.py 的 derive() 推導（同一份規則對應、tier 與 coverage）。

--target <dir>：被掃描的 git repo 根目錄（預設本 repo）。設定與阻擋政策一律取自本 repo，輸出寫在本 repo
  （不寫進被測專案）。被測專案自己的抑制設定不採信：
  - semgrep：--disable-nosem（`# nosemgrep` 不採信）。目標的 .semgrepignore semgrep 一定會讀（沒有公開選項可關），
    有的話在 status_reason 註明、需人工確認。
  - checkov：會自動載入被掃目錄的 .checkov.yaml（可停用檢查，或以 external-checks-dir 執行目標的 Python 程式碼），
    所以掃的是目標「追蹤中檔案」的暫存副本（去掉 .checkov.yaml／.checkov.yml 與 symlink），工作目錄為空的暫存目錄。
  - trivy：只從工作目錄讀 .trivyignore／trivy.yaml，以空的暫存目錄執行。
  - 本 repo blocking-policy 的 exceptions 只核准給本 repo 路徑，不套用。
  - 目標裡的 `checkov:skip=`、`trivy:ignore` 行內註解工具一定會採信 → status_reason 列出檔案，需人工確認。
--base <ref>：semgrep diff-aware（--baseline-commit，只報相對 base 新增的發現；scope: diff）；checkov／trivy 仍全量。
原則（CLAUDE.md #2）：任一工具缺席／逾時／失敗、目標不是 git repo 根目錄 → incomplete，絕不視為通過。

用法：python3 scripts/g3_sast.py [--target <dir>] [--base <ref>] [--out-dir reports/raw/G3] [--gate reports/gates/G3.json]
      python3 scripts/g3_sast.py selftest
工具路徑：$VIBESEC_SEMGREP／$VIBESEC_CHECKOV／$VIBESEC_TRIVY，否則 PATH 上的 semgrep／checkov／trivy。
退出碼：0 無 blocking 且完成；1 有 blocking 發現；2 無法完成（incomplete）。
"""
from __future__ import annotations
import argparse, datetime, json, os, pathlib, re, shutil, subprocess, sys, tempfile, time

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import sarif_gate  # noqa: E402  缺 PyYAML 時以 exit 2 結束（無法判定，不視為通過）

TOOLS = ("semgrep", "checkov", "trivy")
CHECKOV_CONFIGS = (".checkov.yaml", ".checkov.yml")
INLINE_SUPPRESSIONS = r"checkov:skip=|trivy:ignore"


def _git(target: pathlib.Path, *args: str) -> str | None:
    try:
        r = subprocess.run(["git", *args], capture_output=True, text=True, cwd=target)
    except OSError:
        return None
    return r.stdout.strip() if r.returncode == 0 else None


def g3_config() -> dict:
    return ((sarif_gate._yaml(ROOT / "vibesec.yaml").get("gates") or {}).get("g3_sast_iac") or {})


def semgrep_configs(cfg: dict) -> list[str]:
    """vibesec.yaml 的 semgrep_rules：registry 規則集（p/…、r/…）原樣，其餘視為本 repo 內的路徑。"""
    rules = cfg.get("semgrep_rules") or ["config/semgrep/vibesec-rules.yaml", "p/owasp-top-ten", "p/security-audit"]
    return [r if re.match(r"^[pr]/", r) else str(ROOT / r) for r in rules]


def copy_tracked(target: pathlib.Path, dst: pathlib.Path) -> int:
    """把目標追蹤中的檔案複製到 dst 供 checkov 掃描：去掉 checkov 設定檔（checkov 會自動載入被掃目錄的設定）
    與 symlink（可能指向主機上的檔案）。回傳略過的 symlink 數。"""
    skipped = 0
    for f in (_git(target, "ls-files", "-z") or "").split("\0"):
        if not f or pathlib.PurePosixPath(f).name in CHECKOV_CONFIGS:
            continue
        src = target / f
        if src.is_symlink():
            skipped += 1
            continue
        if src.is_file():
            (dst / f).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst / f)
    return skipped


def _relativize_sarif(path: pathlib.Path, copy: pathlib.Path) -> None:
    """checkov 掃副本時回報的路徑帶副本目錄前綴；改成相對目標根目錄，與 semgrep／trivy 一致。"""
    data = json.loads(path.read_text(encoding="utf-8"))
    for run in data.get("runs") or []:
        for r in run.get("results") or []:
            for loc in r.get("locations") or []:
                art = (loc.get("physicalLocation") or {}).get("artifactLocation") or {}
                uri = re.sub(r"^file://", "", art.get("uri") or "")
                for pre in (str(copy) + "/", copy.name + "/", "/"):
                    if uri.startswith(pre):
                        uri = uri[len(pre):]
                        break
                if "uri" in art:
                    art["uri"] = uri
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")


def _version(binary: str, tool: str) -> str | None:
    try:
        out = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=60).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"(\d+\.\d+\.\d+)", out)
    return m.group(1) if m else None


def _run(tool: str, binary: str | None, cmd: list[str], cwd: pathlib.Path, sarif: pathlib.Path, deadline: float) -> dict:
    """執行工具；回傳 tools[] 一列（state: ran / missing / timeout / error）與失敗原因。"""
    row = {"name": tool, "version": None, "state": "missing", "exit_code": None,
           "output_ref": str(sarif), "duration_seconds": None, "reason": None}
    if not binary:
        row["reason"] = f"{tool} binary not found in PATH"
        return row
    row["version"] = _version(binary, tool)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        row.update(state="timeout", reason=f"{tool} 未執行：G3 時間預算已用完")
        return row
    t0 = time.monotonic()
    try:
        p = subprocess.run([binary, *cmd], capture_output=True, text=True, timeout=remaining, cwd=cwd)
    except subprocess.TimeoutExpired:
        row.update(state="timeout", duration_seconds=round(time.monotonic() - t0, 1), reason=f"{tool} 逾時")
        return row
    except OSError as e:
        row.update(state="error", reason=f"{tool} 無法執行（{type(e).__name__}）")
        return row
    row.update(exit_code=p.returncode, duration_seconds=round(time.monotonic() - t0, 1))
    if p.returncode != 0 or not sarif.is_file():
        row.update(state="error", reason=f"{tool} exit {p.returncode}：{(p.stderr or p.stdout).strip()[-200:]}")
        return row
    row["state"] = "ran"
    return row


def scan(target: pathlib.Path, out_dir: pathlib.Path, bins: dict, base: str | None = None,
         timeout: int = 900, pol: dict | None = None) -> dict:
    """掃描目標專案並回傳 G3 gate JSON（schemas/gate-result.schema.json）。"""
    started = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    target = target.resolve()
    out_dir = out_dir.resolve()                # semgrep 在目標目錄執行：相對路徑會寫進被測專案
    external = target != ROOT.resolve()
    pol = dict(pol or sarif_gate.load_policy())
    out_dir.mkdir(parents=True, exist_ok=True)
    sarifs = {t: out_dir / f"{t}.sarif" for t in TOOLS}
    for p in sarifs.values():
        p.unlink(missing_ok=True)              # 不讓上一次的輸出被當成這次的結果
    notes, reasons = [], {}
    top = _git(target, "rev-parse", "--show-toplevel")
    problem = (f"目標不是 git repo（{target}）" if top is None else
               None if pathlib.Path(top).resolve() == target else f"--target 必須是 git repo 根目錄（{top}）")
    rows = {}
    if problem:
        rows = {t: {"name": t, "version": None, "state": "error", "exit_code": None, "output_ref": str(sarifs[t]),
                    "duration_seconds": None} for t in TOOLS}
        notes.append(problem)
    else:
        if external:
            pol.update(exceptions=[], ignored_exceptions=[])
            notes.append(f"目標專案 {target.name}：blocking-policy exceptions 只核准給本 repo 路徑，未套用；"
                         "# nosemgrep 不採信；checkov 掃描已去除目標的 .checkov.yaml")
            if (target / ".semgrepignore").exists():
                notes.append("目標專案有 .semgrepignore，semgrep 會略過其中的路徑（未經 blocking-policy 核准，需人工確認）")
            inline = [f for f in (_git(target, "grep", "-l", "-E", INLINE_SUPPRESSIONS) or "").splitlines() if f]
            if inline:
                notes.append(f"目標專案有 {len(inline)} 個檔案含 checkov:skip／trivy:ignore 行內註解，工具會採信（需人工確認）："
                             + "、".join(inline[:5]) + (" …" if len(inline) > 5 else ""))
        deadline = time.monotonic() + timeout
        cmd = ["scan"] + [x for c in semgrep_configs(g3_config()) for x in ("--config", c)]
        cmd += ["--sarif", "--output", str(sarifs["semgrep"]), "--metrics=off", "--disable-version-check", "--quiet"]
        if base:
            cmd += ["--baseline-commit", base]
        if external:
            cmd.append("--disable-nosem")
        rows["semgrep"] = _run("semgrep", bins.get("semgrep"), cmd + ["."], target, sarifs["semgrep"], deadline)
        with tempfile.TemporaryDirectory(prefix="vibesec-g3-") as tmp:
            tmp = pathlib.Path(tmp)
            copy, cwd, ck_out = tmp / "vibesec-target", tmp / "cwd", tmp / "checkov-out"
            copy.mkdir(); cwd.mkdir()
            skipped = copy_tracked(target, copy)
            if skipped:
                notes.append(f"checkov 略過 {skipped} 個 symlink（不跟隨到目標以外的檔案）")
            rows["checkov"] = _run("checkov", bins.get("checkov"),
                                   ["-d", str(copy), "--config-file", str(ROOT / "config/checkov/.checkov.yaml"),
                                    "--external-checks-dir", str(ROOT / "config/checkov/custom"),
                                    "-o", "sarif", "--output-file-path", str(ck_out), "--soft-fail", "--quiet"],
                                   cwd, ck_out / "results_sarif.sarif", deadline)
            if rows["checkov"]["state"] == "ran":
                shutil.copy2(ck_out / "results_sarif.sarif", sarifs["checkov"])
                _relativize_sarif(sarifs["checkov"], copy)
            rows["checkov"]["output_ref"] = str(sarifs["checkov"])
            rows["trivy"] = _run("trivy", bins.get("trivy"),
                                 ["config", "--format", "sarif", "--output", str(sarifs["trivy"]), "--quiet", str(target)],
                                 cwd, sarifs["trivy"], deadline)
        for t in TOOLS:
            if rows[t]["state"] != "ran":
                sarifs[t].unlink(missing_ok=True)
            reasons[t] = rows[t].pop("reason")
    gate = sarif_gate.derive("G3", sarifs, None, pol, started)
    gate["tools"] = [dict(t, **rows[t["name"]]) if t["name"] in rows else t for t in gate["tools"]]
    notes = [r for r in reasons.values() if r] + notes
    if notes:
        gate["status_reason"] = "；".join(([gate["status_reason"]] if gate["status_reason"] else []) + notes)
    gate.update(scope="diff" if base else "full", diff_base=base,
                commit=_git(target, "rev-parse", "HEAD") if not problem else None)
    return gate


# ------------------------------------------------------------------ selftest
FAKE_TOOL = r'''#!/usr/bin/env python3
# selftest 用假工具：記錄 argv、工作目錄與掃描目錄內容，依環境變數寫出 SARIF 或失敗
import json, os, pathlib, sys
tool, argv = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
if argv[:1] in (["--version"], ["version"]):
    print("9.9.9"); sys.exit(0)
log = {"tool": tool, "argv": argv, "cwd": os.getcwd(), "cwd_files": sorted(os.listdir("."))}
if os.environ.get(f"FAKE_{tool.upper()}_EXIT"):
    print("boom", file=sys.stderr); sys.exit(int(os.environ[f"FAKE_{tool.upper()}_EXIT"]))
if tool == "checkov":
    d = pathlib.Path(argv[argv.index("-d") + 1])
    log["scanned"] = sorted(str(p.relative_to(d)) for p in d.rglob("*"))
    log["scanned_symlinks"] = [str(p.relative_to(d)) for p in d.rglob("*") if p.is_symlink()]
    out = pathlib.Path(argv[argv.index("--output-file-path") + 1]) / "results_sarif.sarif"
    uri = d.name + "/infra/main.tf"
else:
    out = pathlib.Path(argv[argv.index("--output") + 1])
    uri = "app/x.py"
res = [{"ruleId": r, "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}]}
       for r in json.loads(os.environ.get(f"FAKE_{tool.upper()}_RULES") or "[]")]
out.parent.mkdir(parents=True, exist_ok=True)
out.write_text(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": tool}}, "results": res}]}))
with open(os.environ["FAKE_LOG"], "a") as f:
    f.write(json.dumps(log) + "\n")
'''


def selftest() -> list[str]:
    from jsonschema import Draft202012Validator
    fails: list[str] = []
    schema = Draft202012Validator(json.loads((ROOT / "schemas/gate-result.schema.json").read_text(encoding="utf-8")))
    # 合成例外（不依賴政策檔現有例外與其到期日）：外部目標必須忽略它
    pol = dict(sarif_gate.load_policy(), exceptions=[
        {"rule_id": "vibesec.g3.command-injection", "path_glob": "app/**", "reason": "selftest",
         "approved_by": "selftest", "expires": "2099-12-31"}])
    git = lambda d, *a: subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *a], cwd=d,
                                       capture_output=True, check=True)
    with tempfile.TemporaryDirectory() as d:
        D = pathlib.Path(d)
        repo, out, bindir, log = D / "proj", D / "out", D / "bin", D / "log.jsonl"
        (repo / "infra").mkdir(parents=True); (repo / "app").mkdir(); bindir.mkdir()
        (repo / "infra/main.tf").write_text('resource "aws_instance" "x" {}\n')
        (repo / "app/x.py").write_text("x = 1\n")
        (repo / ".checkov.yaml").write_text("skip-check: [CKV_AWS_79]\n")
        (repo / "link.tf").symlink_to("/etc/hostname")
        git(repo, "init", "-q"); git(repo, "add", "-A"); git(repo, "commit", "-qm", "t")
        for t in TOOLS:
            (bindir / t).write_text(FAKE_TOOL); (bindir / t).chmod(0o755)
        bins = {t: str(bindir / t) for t in TOOLS}

        def run(target, env=None, **kw):
            env = {"FAKE_LOG": str(log), **(env or {})}
            log.unlink(missing_ok=True)
            os.environ.update(env)
            try:
                g = scan(target, out, kw.pop("bins", bins), pol=pol, **kw)
            finally:
                for k in env:
                    os.environ.pop(k, None)
            errs = list(schema.iter_errors(g))
            if errs:
                fails.append(f"gate JSON 不符 schema：{errs[0].message}")
            calls = {}
            if log.exists():
                for line in log.read_text().splitlines():
                    c = json.loads(line); calls[c["tool"]] = c
            return g, calls

        g, calls = run(repo)
        head = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=repo).stdout.strip()
        if g["status"] != "pass" or g["commit"] != head or g["scope"] != "full" or set(calls) != set(TOOLS):
            fails.append(f"外部目標、三個工具都跑完且無發現 → pass，commit 取目標 HEAD（得到 {g['status']}，{sorted(calls)}）")
        if "exceptions" not in (g["status_reason"] or ""):
            fails.append("外部目標 → status_reason 註明例外未套用")
        sg, ck, tv = calls.get("semgrep", {}), calls.get("checkov", {}), calls.get("trivy", {})
        if sg.get("cwd") != str(repo.resolve()) or "--disable-nosem" not in sg.get("argv", []) or sg.get("argv", [""])[-1] != ".":
            fails.append("semgrep 在目標根目錄掃 .，外部目標加 --disable-nosem")
        if not any(a.startswith(str(ROOT)) and a.endswith("vibesec-rules.yaml") for a in sg.get("argv", [])):
            fails.append("semgrep 規則取自本 repo（vibesec.yaml semgrep_rules）")
        if ({".checkov.yaml", "link.tf"} & set(ck.get("scanned", []))) or ck.get("scanned_symlinks") \
                or "infra/main.tf" not in ck.get("scanned", []):
            fails.append(f"checkov 掃目標追蹤中檔案的副本，去掉 .checkov.yaml 與 symlink（得到 {ck.get('scanned')}）")
        for name, c in (("checkov", ck), ("trivy", tv)):
            if c.get("cwd_files") != [] or c.get("cwd") in (str(repo.resolve()), str(repo)):
                fails.append(f"{name} 以空的暫存目錄為工作目錄（不讀目標的設定檔）")
        g, calls = run(repo, env={"FAKE_CHECKOV_RULES": json.dumps(["CKV2_VIBESEC_1"])})
        loc = json.loads((out / "checkov.sarif").read_text())["runs"][0]["results"][0]["locations"][0]
        if loc["physicalLocation"]["artifactLocation"]["uri"] != "infra/main.tf" or g["status"] != "fail":
            fails.append("checkov 的路徑改成相對目標根目錄；對到 blocking 規則 → fail")
        g, _ = run(repo, env={"FAKE_SEMGREP_RULES": json.dumps(["vibesec.g3.command-injection"])})
        if g["status"] != "fail":
            fails.append("外部目標：本 repo 對 app/** 的例外不得套用（仍為 blocking → fail）")
        g, calls = run(repo, base="HEAD")
        if g["scope"] != "diff" or g["diff_base"] != "HEAD" or "--baseline-commit" not in calls.get("semgrep", {}).get("argv", []):
            fails.append("--base → semgrep --baseline-commit、scope diff")
        g, _ = run(repo, bins=dict(bins, trivy=None))
        trow = next(t for t in g["tools"] if t["name"] == "trivy")
        if g["status"] != "incomplete" or trow["state"] != "missing" or "not found" not in (g["status_reason"] or ""):
            fails.append("trivy 缺席 → incomplete（state missing），不是 pass")
        g, _ = run(repo, env={"FAKE_CHECKOV_EXIT": "2"})
        crow = next(t for t in g["tools"] if t["name"] == "checkov")
        if g["status"] != "incomplete" or crow["state"] != "error" or crow["exit_code"] != 2:
            fails.append("checkov 非零結束 → incomplete（state error、記 exit_code）")
        (repo / ".semgrepignore").write_text("app/\n")
        (repo / "infra/skip.tf").write_text("# checkov:skip=CKV_AWS_79: target says ok\n")
        git(repo, "add", "-A"); git(repo, "commit", "-qm", "suppress")
        g, _ = run(repo)
        if ".semgrepignore" not in (g["status_reason"] or "") or "infra/skip.tf" not in (g["status_reason"] or ""):
            fails.append("目標的 .semgrepignore 與 checkov:skip 行內註解要寫進 status_reason")
        old_cwd = os.getcwd()
        os.chdir(D)
        try:
            log.unlink(missing_ok=True)
            os.environ["FAKE_LOG"] = str(log)
            g = scan(repo, pathlib.Path("rel-out"), bins, pol=pol)
        finally:
            os.environ.pop("FAKE_LOG", None)
            os.chdir(old_cwd)
        if g["status"] != "pass" or not all((D / "rel-out" / f"{t}.sarif").is_file() for t in TOOLS):
            fails.append(f"相對路徑的 --out-dir 以呼叫端目錄為準（得到 {g['status']}：{g['status_reason']}）")
        g, _ = run(repo / "app")
        if g["status"] != "incomplete" or "根目錄" not in (g["status_reason"] or ""):
            fails.append("--target 不是 repo 根目錄 → incomplete")
        if any(p.is_relative_to(repo) for p in out.iterdir()):
            fails.append("輸出不得寫進被測專案")
        if subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True, cwd=repo).stdout.strip():
            fails.append("掃描不得改動被測專案的工作目錄")
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
    ap.add_argument("--base", help="semgrep diff-aware 的比較基準（--baseline-commit）")
    ap.add_argument("--out-dir", default="reports/raw/G3", help="各工具 SARIF 的輸出目錄")
    ap.add_argument("--gate", default="reports/gates/G3.json", help="G3 gate JSON 輸出路徑")
    a = ap.parse_args(argv)
    target = pathlib.Path(a.target).expanduser()
    try:
        timeout = int(g3_config().get("timeout_seconds") or 900)
    except (OSError, ValueError):
        timeout = 900
    bins = {t: os.environ.get(f"VIBESEC_{t.upper()}") or shutil.which(t) for t in TOOLS}
    g = scan(target, pathlib.Path(a.out_dir), bins, a.base, timeout)
    pathlib.Path(a.gate).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(a.gate).write_text(json.dumps(g, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"G3 {g['status']}（{target.resolve()}）：blocking={g['findings_count']['blocking']} "
          f"advisory={g['findings_count']['advisory']}" + (f"；{g['status_reason']}" if g["status_reason"] else ""))
    if g["findings_count"]["blocking"]:
        return 1
    return 2 if g["status"] == "incomplete" else 0


if __name__ == "__main__":
    sys.exit(main())
