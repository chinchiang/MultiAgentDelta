#!/usr/bin/env python3
"""G3 SAST／IaC（本機／harness 版）— semgrep + checkov + trivy config；可用 --target 掃其他專案。

與 .github/workflows/pr-gates.yml 的 G3 jobs 對齊：semgrep 用 vibesec.yaml gates.g3_sast_iac.semgrep_rules
（本 repo 規則 + p/owasp-top-ten + p/security-audit）；checkov 用 config/checkov/.checkov.yaml（check allow-list 與
custom 檢查）；trivy config；gate JSON 由 scripts/sarif_gate.py 的 derive() 推導（同一份規則對應、tier 與 coverage）。

--target <dir>：被掃描的 git repo 根目錄（預設本 repo）。設定與阻擋政策一律取自本 repo，輸出寫在本 repo
  （不寫進被測專案）。被測專案自己的抑制設定不採信：
  - semgrep：--disable-nosem（`# nosemgrep` 不採信）。semgrep 沒有選項可關掉 .semgrepignore，所以掃的是副本（#317，
    semgrep_tree）：副本中任何深度的 .semgrepignore 都刪除、根目錄放一份空的（一併停用 tests/、vendor/ 等預設忽略）；
    diff 模式以 git clone 建副本、刪除後 commit，--baseline-commit 傳在受驗樹解析出的 SHA。副本建不出來 → semgrep error。
  - checkov：會自動載入被掃目錄的 .checkov.yaml（可停用檢查，或以 external-checks-dir 執行目標的 Python 程式碼），
    所以掃的是目標「追蹤中檔案」的暫存副本（去掉 .checkov.yaml／.checkov.yml 與 symlink），工作目錄為空的暫存目錄。
  - trivy：只從工作目錄讀 .trivyignore／trivy.yaml，以空的暫存目錄執行。
  - 本 repo blocking-policy 的 exceptions 只核准給本 repo 路徑，不套用。
  - 目標裡的 `checkov:skip=`、`trivy:ignore` 行內註解工具一定會採信 → status_reason 列出檔案，需人工確認。
--base <ref>：semgrep diff-aware（--baseline-commit，只報相對 base 新增的發現；scope: diff）；checkov／trivy 仍全量。
原則（AGENTS.md #2）：任一工具缺席／逾時／失敗、目標不是 git repo 根目錄 → incomplete，絕不視為通過。

用法：python3 scripts/g3_sast.py [--target <dir>] [--base <ref>] [--out-dir reports/raw/G3] [--gate reports/gates/G3.json]
      python3 scripts/g3_sast.py selftest
工具路徑：$VIBESEC_SEMGREP／$VIBESEC_CHECKOV／$VIBESEC_TRIVY，否則 PATH 上的 semgrep／checkov／trivy。
退出碼：0 無 blocking 且完成；1 有 blocking 發現；2 無法完成（incomplete）。
"""
from __future__ import annotations
import argparse, datetime, errno, json, os, pathlib, re, shutil, stat, subprocess, sys, tempfile, time, urllib.parse

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import sarif_gate  # noqa: E402  缺 PyYAML 時以 exit 2 結束（無法判定，不視為通過）

TOOLS = ("semgrep", "checkov", "trivy")
CHECKOV_CONFIGS = (".checkov.yaml", ".checkov.yml")
INLINE_SUPPRESSIONS = r"checkov:skip=|trivy:ignore"


def printable(obj):
    """輸出邊界：把含代理字元（surrogateescape 保留的原始位元組）的字串轉成可輸出 UTF-8 文字，合法 UTF-8 原樣不動。"""
    if isinstance(obj, str):
        try:
            obj.encode("utf-8")
            return obj
        except UnicodeEncodeError:
            return "".join(f"\\x{ord(c) - 0xDC00:02x}" if 0xDC80 <= ord(c) <= 0xDCFF
                           else f"\\u{ord(c):04x}" if 0xD800 <= ord(c) <= 0xDFFF else c for c in obj)
    if isinstance(obj, dict):
        return {printable(k): printable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [printable(v) for v in obj]
    return obj


def _git(target: pathlib.Path, *args: str) -> str | None:
    try:
        r = subprocess.run(["git", "-c", "core.quotepath=false", *args],
                           capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", cwd=target)
    except OSError:
        return None
    return r.stdout.strip() if r.returncode == 0 else None


def _git_z(target: pathlib.Path, *args: str) -> list[str] | None:
    """執行帶 -z（NUL 分隔）的 git 命令；保留前導／尾隨空白與非 UTF-8 位元組（surrogateescape），失敗回傳 None。"""
    try:
        r = subprocess.run(["git", "-c", "core.quotepath=false", *args],
                           capture_output=True, text=True, encoding="utf-8", errors="surrogateescape", cwd=target)
    except OSError:
        return None
    return [f for f in r.stdout.split("\0") if f] if r.returncode == 0 else None


def g3_config() -> dict:
    return ((sarif_gate._yaml(ROOT / "vibesec.yaml").get("gates") or {}).get("g3_sast_iac") or {})


def semgrep_configs(cfg: dict) -> list[str]:
    """vibesec.yaml 的 semgrep_rules：registry 規則集（p/…、r/…）原樣，其餘視為本 repo 內的路徑。"""
    rules = cfg.get("semgrep_rules") or ["config/semgrep/vibesec-rules.yaml", "p/owasp-top-ten", "p/security-audit"]
    return [r if re.match(r"^[pr]/", r) else str(ROOT / r) for r in rules]


def sarif_uri(uri: str) -> str:
    """SARIF artifactLocation.uri：合法 UTF-8 原樣不動，含非 UTF-8 代理字元的路徑改用百分比編碼。"""
    try:
        uri.encode("utf-8")
        return uri
    except UnicodeEncodeError:
        pass
    try:
        return urllib.parse.quote(uri.encode("utf-8", "surrogateescape"), safe="/")
    except UnicodeEncodeError:
        return printable(uri)


def copy_tracked(target: pathlib.Path, dst: pathlib.Path) -> tuple[int, str | None]:
    """把受驗樹追蹤中的檔案複製到 dst 供掃描：去掉 checkov 設定檔（checkov 會自動載入被掃目錄的設定）
    與 symlink（可能指向主機上的檔案）。回傳 (略過的 symlink 數, 未完成原因或 None)（#310）。"""
    files = _git_z(target, "ls-files", "-z")
    if files is None:
        return 0, f"無法列出已追蹤檔案（git ls-files 失敗：{printable(str(target))}）"
    skipped = 0
    for f in files:
        if pathlib.PurePosixPath(f).name in CHECKOV_CONFIGS:
            continue
        src = target / f
        try:
            st = src.lstat()
        except OSError as e:
            if e.errno == errno.ENOENT:
                continue   # 工作樹已刪除、尚未 git add 的一般檔
            return skipped, f"無法複製追蹤檔 {printable(f)}（{type(e).__name__}）"
        if stat.S_ISLNK(st.st_mode):
            skipped += 1
            continue
        if not stat.S_ISREG(st.st_mode):
            return skipped, f"無法複製追蹤檔 {printable(f)}（不是一般檔案）"
        try:
            (dst / f).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst / f)
        except OSError as e:
            return skipped, f"無法複製追蹤檔 {printable(f)}（{type(e).__name__}）"
    return skipped, None


def _stderr_tail(r) -> str:
    return printable(r.stderr.decode("utf-8", "replace").strip()[-120:])


def semgrep_tree(target: pathlib.Path, dst: pathlib.Path, base: str | None, deadline: float) -> tuple[list[str], str | None, str | None]:
    """外部受驗樹給 semgrep 掃的副本（#317）：semgrep 沒有選項可關掉 .semgrepignore，在受驗樹裡執行就會採信任何深度的
    .semgrepignore；沒有 .semgrepignore 時又套用內建預設忽略（tests/、vendor/…）。所以在副本裡刪除任何深度的 .semgrepignore，
    根目錄放一份空的（也一併停用預設忽略）。
      full：copy_tracked（追蹤檔，去掉 symlink）。
      diff（base）：--baseline-commit 需要 git 且不得有未暫存變更 → git clone --local --no-hardlinks，刪除後在副本裡 commit；
                    base 先在受驗樹解析成 SHA（clone 沒有受驗樹的 remote-tracking ref）。
    git 呼叫共用 G3 的時間預算（deadline）；git 不在 PATH、逾時、失敗 → 未完成原因（fail-closed，不拋例外）。
    回傳 (移除的 .semgrepignore 相對路徑, 給 --baseline-commit 的 SHA 或 None, 未完成原因或 None)。"""
    def git(*cmd):
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError
        return subprocess.run(["git", *cmd], capture_output=True, timeout=left)
    removed, sha = [], None
    try:
        if base:
            sha = (_git(target, "rev-parse", "--verify", "--quiet", f"{base}^{{commit}}") or "").strip() or None
            if not sha:
                return [], None, f"semgrep 副本：base {printable(base)} 在受驗樹找不到"
            r = git("clone", "-q", "--local", "--no-hardlinks", str(target), str(dst))
            if r.returncode != 0:
                return [], None, f"semgrep 副本：git clone 失敗（{_stderr_tail(r)}）"
        else:
            if deadline - time.monotonic() <= 0:
                raise TimeoutError
            dst.mkdir(parents=True, exist_ok=True)
            _, problem = copy_tracked(target, dst)
            if problem:
                return [], None, f"semgrep 副本：{problem}"
        removed = sorted(p.relative_to(dst).as_posix() for p in dst.rglob(".semgrepignore") if ".git" not in p.relative_to(dst).parts)
        for rel in removed:
            (dst / rel).unlink()
        (dst / ".semgrepignore").write_text("", encoding="utf-8")
        if base:
            ident = ["-C", str(dst), "-c", "user.name=vibesec", "-c", "user.email=vibesec@invalid", "-c", "commit.gpgsign=false"]
            for step in (["add", "-A", "--", "."], ["commit", "-q", "--allow-empty", "-m", "vibesec：移除受測方的 .semgrepignore（#317）"]):
                r = git(*ident, *step)
                if r.returncode != 0:
                    return removed, None, f"semgrep 副本：git {step[0]} 失敗（{_stderr_tail(r)}）"
    except (TimeoutError, subprocess.TimeoutExpired):
        return removed, None, "semgrep 副本：G3 時間預算已用完"
    except OSError as e:
        return removed, None, f"semgrep 副本：無法建立（{type(e).__name__}）"
    return removed, sha, None


def _relativize_sarif(path: pathlib.Path, copy: pathlib.Path) -> None:
    """checkov 掃副本時回報的路徑帶副本目錄前綴；改成相對受驗樹根目錄，與 semgrep／trivy 一致。"""
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
                    art["uri"] = sarif_uri(uri)
    path.write_text(json.dumps(printable(data), ensure_ascii=False), encoding="utf-8")


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
        p = subprocess.run([binary, *cmd], capture_output=True, text=True,
                           encoding="utf-8", errors="surrogateescape", timeout=remaining, cwd=cwd)
    except subprocess.TimeoutExpired:
        row.update(state="timeout", duration_seconds=round(time.monotonic() - t0, 1), reason=f"{tool} 逾時")
        return row
    except OSError as e:
        row.update(state="error", reason=f"{tool} 無法執行（{type(e).__name__}）")
        return row
    row.update(exit_code=p.returncode, duration_seconds=round(time.monotonic() - t0, 1))
    if p.returncode != 0 or not sarif.is_file():
        row.update(state="error", reason=f"{tool} exit {p.returncode}：{printable((p.stderr or p.stdout).strip())[-200:]}")
        return row
    row["state"] = "ran"
    return row


def scan(target: pathlib.Path, out_dir: pathlib.Path, bins: dict, base: str | None = None,
         timeout: int = 900, pol: dict | None = None, policy_root: pathlib.Path = ROOT) -> dict:
    """掃描目標專案並回傳 G3 gate JSON（schemas/gate-result.schema.json）。
    pol：sarif_gate.load_context 的結果（selftest 注入）；沒給 → 以 policy_root 的政策建立，讀不到 → 不掃描、incomplete。"""
    started = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    target = target.resolve()
    out_dir = out_dir.resolve()                # semgrep 在目標目錄執行：相對路徑會寫進被測專案
    if pol is None:   # 只建立一次；政策讀不到 → 不跑工具，直接回傳 incomplete
        pol, unreadable = sarif_gate.context_or_unreadable("G3", policy_root, started, diff_base=base)
        if unreadable:
            return unreadable
    pol = dict(pol)
    external = not pol["policy"].is_this_repo(target)   # 與例外是否套用同一份判斷（Policy；含 VIBESEC_PROJECT_ROOT）
    project = pol["policy"].for_project(target)          # 受驗樹的政策例外：外部專案 → 沒有任何例外，note 說明
    out_dir.mkdir(parents=True, exist_ok=True)
    sarifs = {t: out_dir / f"{t}.sarif" for t in TOOLS}
    for p in sarifs.values():
        p.unlink(missing_ok=True)              # 不讓上一次的輸出被當成這次的結果
    notes, reasons = [], {}
    top = _git(target, "rev-parse", "--show-toplevel")
    problem = (f"目標不是 git repo（{printable(str(target))}）" if top is None else
               None if pathlib.Path(top).resolve() == target else f"--target 必須是 git repo 根目錄（{printable(top)}）")
    rows = {}
    if problem:
        rows = {t: {"name": t, "version": None, "state": "error", "exit_code": None, "output_ref": str(sarifs[t]),
                    "duration_seconds": None} for t in TOOLS}
        notes.append(problem)
    else:
        if external:
            notes.append(f"{project.note}；# nosemgrep 不採信；checkov 掃描已去除目標的 .checkov.yaml")
            inline = [printable(f) for f in (_git_z(target, "grep", "-l", "-z", "-E", INLINE_SUPPRESSIONS) or [])]
            if inline:
                notes.append(f"目標專案有 {len(inline)} 個檔案含 checkov:skip／trivy:ignore 行內註解，工具會採信（需人工確認）："
                             + "、".join(inline[:5]) + (" …" if len(inline) > 5 else ""))
        deadline = time.monotonic() + timeout
        cmd = ["scan"] + [x for c in semgrep_configs(g3_config()) for x in ("--config", c)]
        # --max-target-bytes=0：semgrep 預設靜默跳過 >1 MB 的檔案；改成照掃，逾時由 sarif_gate 記 incomplete
        cmd += ["--sarif", "--output", str(sarifs["semgrep"]), "--metrics=off", "--disable-version-check", "--quiet",
                "--max-target-bytes=0"]
        if external:
            cmd.append("--disable-nosem")
        with tempfile.TemporaryDirectory(prefix="vibesec-g3-") as tmp:
            tmp = pathlib.Path(tmp)
            if not external:   # 本 repo：在受驗樹裡執行，採信本 repo 自己的 .semgrepignore（CODEOWNERS 保護）
                if base:
                    cmd += ["--baseline-commit", base]
                rows["semgrep"] = _run("semgrep", bins.get("semgrep"), cmd + ["."], target, sarifs["semgrep"], deadline)
            else:              # 外部受驗樹（#317）：掃移除了所有 .semgrepignore 的副本
                sg_dir = tmp / "semgrep-target"
                removed, sha, sg_problem = semgrep_tree(target, sg_dir, base, deadline)
                if sg_problem:
                    pass   # 副本建不出來：不宣稱已移除或已停用任何東西（原因由 semgrep 那一列帶出）
                elif removed:
                    shown = "、".join(printable(r) for r in removed[:5]) + (" …" if len(removed) > 5 else "")
                    notes.append(f"已移除目標專案的 {len(removed)} 個 .semgrepignore（{shown}）；semgrep 的預設忽略已停用")
                else:
                    notes.append("semgrep 的預設忽略已停用")
                if sg_problem:   # 不對殘缺的副本執行，也不退回直接掃受驗樹（那樣又會採信目標的 .semgrepignore）
                    rows["semgrep"] = {"name": "semgrep", "version": None, "state": "error", "exit_code": None,
                                       "output_ref": str(sarifs["semgrep"]), "duration_seconds": None, "reason": sg_problem}
                else:
                    if sha:
                        cmd += ["--baseline-commit", sha]
                    rows["semgrep"] = _run("semgrep", bins.get("semgrep"), cmd + ["."], sg_dir, sarifs["semgrep"], deadline)
                    if rows["semgrep"]["state"] == "ran":
                        _relativize_sarif(sarifs["semgrep"], sg_dir)
            copy, cwd, ck_out = tmp / "vibesec-target", tmp / "cwd", tmp / "checkov-out"
            copy.mkdir(); cwd.mkdir()
            skipped, copy_problem = copy_tracked(target, copy)
            if skipped:
                notes.append(f"checkov 略過 {skipped} 個 symlink（不跟隨到目標以外的檔案）")
            if copy_problem:
                rows["checkov"] = {"name": "checkov", "version": None, "state": "error", "exit_code": None,
                                   "output_ref": str(sarifs["checkov"]), "duration_seconds": None, "reason": copy_problem}
            else:
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
    gate = sarif_gate.derive("G3", sarifs, None, pol, project, started)
    gate["tools"] = [dict(t, **rows[t["name"]]) if t["name"] in rows else t for t in gate["tools"]]
    notes = [r for r in reasons.values() if r] + notes
    if notes:
        gate["status_reason"] = "；".join(([gate["status_reason"]] if gate["status_reason"] else []) + notes)
    gate.update(scope="diff" if base else "full", diff_base=base,
                commit=_git(target, "rev-parse", "HEAD") if not problem else None)
    return printable(gate)


# ------------------------------------------------------------------ selftest
FAKE_TOOL = r'''#!/usr/bin/env python3
# selftest 用假工具：記錄 argv、工作目錄與掃描目錄內容，依環境變數寫出 SARIF 或失敗
import json, os, pathlib, sys
tool, argv = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
if argv[:1] in (["--version"], ["version"]):
    print("9.9.9"); sys.exit(0)
log = {"tool": tool, "argv": argv, "cwd": os.getcwd(), "cwd_files": sorted(os.listdir("."))}
if tool == "semgrep":   # #317：semgrep 看得到的 .semgrepignore（任何深度）、根目錄那份的內容、副本的 git 狀態
    import subprocess
    log["semgrepignores"] = sorted(str(p) for p in pathlib.Path(".").rglob(".semgrepignore") if ".git" not in p.parts)
    log["root_ignore"] = pathlib.Path(".semgrepignore").read_text() if pathlib.Path(".semgrepignore").is_file() else None
    log["head_parent"] = subprocess.run(["git", "rev-parse", "HEAD^"], capture_output=True, text=True).stdout.strip() \
        if pathlib.Path(".git").exists() else None
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
    from vibesec_policy import Policy, temp_policy_root
    # 合成例外（不依賴政策檔現有例外與其到期日）：暫存 root 放本 repo 政策的副本，只換掉 exceptions；外部目標必須忽略它
    synthetic = [{"rule_id": "vibesec.g3.command-injection", "path_glob": "app/**", "reason": "selftest",
                  "approved_by": "selftest", "expires": "2099-12-31"}]
    with temp_policy_root(synthetic) as PR:
        pol = sarif_gate.load_context(Policy(PR, project_root=None))   # 建構時讀完政策檔；不受 VIBESEC_PROJECT_ROOT 影響
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
        # #317：外部受驗樹的 semgrep 改掃副本（不在受驗樹裡執行），根目錄只有一份空的 .semgrepignore（預設忽略停用）
        if sg.get("cwd") in (str(repo.resolve()), str(repo)) or "--disable-nosem" not in sg.get("argv", []) \
                or sg.get("argv", [""])[-1] != "." or sg.get("semgrepignores") != [".semgrepignore"] or sg.get("root_ignore") != "":
            fails.append(f"外部目標：semgrep 在副本根目錄掃 .、只有空的根目錄 .semgrepignore、加 --disable-nosem（得到 {sg}）")
        if "semgrep 的預設忽略已停用" not in (g["status_reason"] or "") or "已移除目標專案" in (g["status_reason"] or ""):
            fails.append(f"外部目標沒有 .semgrepignore → status_reason 只寫預設忽略已停用（得到 {g['status_reason']}）")
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
        # 接線：目標是本 repo（project_root 指向它）→ scan 以受驗樹綁定的例外照常套用：命中的發現降為 advisory、
        # status_reason 註明命中筆數（gate JSON 只有計數；逐筆的 exception 紀錄由 sarif_gate 的 selftest 檢查）
        with temp_policy_root(synthetic) as PR2:
            pol_ext, pol = pol, sarif_gate.load_context(Policy(PR2, project_root=repo))
        try:
            g, calls = run(repo, env={"FAKE_SEMGREP_RULES": json.dumps(["vibesec.g3.command-injection"])})
            _, calls_diff = run(repo, base="HEAD")
        finally:
            pol = pol_ext
        # #317：本 repo 不受影響：semgrep 照舊在受驗樹裡執行、不加 --disable-nosem、--baseline-commit 原樣傳 base
        for label, c, want_tail in (("full", calls.get("semgrep", {}), ["."]),
                                    ("diff", calls_diff.get("semgrep", {}), ["--baseline-commit", "HEAD", "."])):
            if c.get("cwd") != str(repo.resolve()) or "--disable-nosem" in c.get("argv", []) or c.get("argv", [])[-len(want_tail):] != want_tail:
                fails.append(f"本 repo（{label}）：semgrep 在受驗樹執行、參數與以前相同（得到 {c}）")
        if g["status"] == "fail" or g["findings_count"]["blocking"] or g["findings_count"]["advisory"] < 1 \
                or "筆命中 blocking-policy 例外" not in (g["status_reason"] or ""):
            fails.append(f"本 repo：命中例外 → advisory、status_reason 註明命中筆數（得到 {g['status']}：{g['findings_count']}、{g['status_reason']}）")
        # #317：diff 副本的 git 不在 PATH（OSError）或逾時 → semgrep error、不崩潰、不在受驗樹上執行
        old_path = os.environ["PATH"]
        os.environ["PATH"] = str(bindir)   # 只有假工具，沒有 git
        try:
            removed, sha, problem = semgrep_tree(repo, D / "sg-nogit", "HEAD", time.monotonic() + 30)
            if not problem or "semgrep 副本" not in problem:
                fails.append(f"semgrep_tree：沒有 git → 回報未完成原因，不拋例外（得到 {problem!r}）")
        except Exception as e:
            fails.append(f"semgrep_tree：沒有 git 不得拋例外（{type(e).__name__}: {e}）")
        finally:
            os.environ["PATH"] = old_path
        for label, b in (("diff", "HEAD"), ("full", None)):
            removed, sha, problem = semgrep_tree(repo, D / f"sg-late-{label}", b, time.monotonic() - 1)
            if not problem or "時間預算" not in problem:
                fails.append(f"semgrep_tree（{label}）：時間預算用完 → 回報未完成原因（得到 {problem!r}）")
        (D / "sg-file").write_text("x")   # 副本目的地已是一般檔案 → OSError，不得拋例外
        try:
            _, _, problem = semgrep_tree(repo, D / "sg-file", None, time.monotonic() + 30)
            if not problem or "semgrep 副本" not in problem:
                fails.append(f"semgrep_tree：建立副本時 OSError → 回報未完成原因（得到 {problem!r}）")
        except Exception as e:
            fails.append(f"semgrep_tree：建立副本時 OSError 不得拋例外（{type(e).__name__}: {e}）")
        g, calls = run(repo, base="HEAD")
        sg = calls.get("semgrep", {})
        argv = sg.get("argv", [])
        if g["scope"] != "diff" or g["diff_base"] != "HEAD" or "--baseline-commit" not in argv:
            fails.append("--base → semgrep --baseline-commit、scope diff")
        # #317：diff 模式的副本是 clone：HEAD 是「移除 .semgrepignore」的 commit，上一層是受驗樹的 HEAD；base 先在受驗樹解析成 SHA
        elif argv[argv.index("--baseline-commit") + 1] != head or sg.get("head_parent") != head \
                or sg.get("cwd") in (str(repo.resolve()), str(repo)) or sg.get("semgrepignores") != [".semgrepignore"]:
            fails.append(f"外部 diff：semgrep 在 clone 的副本執行、--baseline-commit 是受驗樹 HEAD 的 SHA、刪除已 commit（得到 {sg}）")
        if subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, cwd=repo).stdout.strip() != head:
            fails.append("外部 diff：副本裡的 commit 不得改到受驗樹的 HEAD")
        g, _ = run(repo, bins=dict(bins, trivy=None))
        trow = next(t for t in g["tools"] if t["name"] == "trivy")
        if g["status"] != "incomplete" or trow["state"] != "missing" or "not found" not in (g["status_reason"] or ""):
            fails.append("trivy 缺席 → incomplete（state missing），不是 pass")
        g, _ = run(repo, env={"FAKE_CHECKOV_EXIT": "2"})
        crow = next(t for t in g["tools"] if t["name"] == "checkov")
        if g["status"] != "incomplete" or crow["state"] != "error" or crow["exit_code"] != 2:
            fails.append("checkov 非零結束 → incomplete（state error、記 exit_code）")
        (repo / ".semgrepignore").write_text("app/\n")
        (repo / "app/.semgrepignore").write_text("*\n")
        (repo / "infra/skip.tf").write_text("# checkov:skip=CKV_AWS_79: target says ok\n")
        git(repo, "add", "-A"); git(repo, "commit", "-qm", "suppress")
        g, calls = run(repo)
        why, sg = g["status_reason"] or "", calls.get("semgrep", {})
        if "已移除目標專案的 2 個 .semgrepignore（.semgrepignore、app/.semgrepignore）；semgrep 的預設忽略已停用" not in why \
                or "需人工確認" in why.split("checkov:skip")[0] or "infra/skip.tf" not in why:
            fails.append(f"目標的 .semgrepignore（含子目錄）寫明已移除、checkov:skip 行內註解照舊列出（得到 {why}）")
        if sg.get("semgrepignores") != [".semgrepignore"] or sg.get("root_ignore") != "" \
                or not (repo / "app/.semgrepignore").is_file() or (repo / ".semgrepignore").read_text() != "app/\n":
            fails.append(f"副本裡任何深度的 .semgrepignore 都移除、根目錄換成空的；受驗樹本身不動（得到 {sg}）")
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
        # #310：copy_tracked 遇追蹤檔無法複製時 checkov 列 error、G3 incomplete，且保留前導空白／非 UTF-8 檔名
        (repo / "app/x.py").unlink(); (repo / "app/x.py").mkdir()
        try:
            g, _ = run(repo)
            crow = next(t for t in g["tools"] if t["name"] == "checkov")
            if g["status"] != "incomplete" or crow["state"] != "error" or "app/x.py" not in (g["status_reason"] or ""):
                fails.append(f"追蹤檔無法複製 → checkov error、G3 incomplete（得到 {g['status']}、{crow}）")
            # #317：semgrep 的副本也建不出來 → semgrep error，不得退回直接掃受驗樹；status_reason 不得宣稱已停用預設忽略
            g, calls = run(repo)
            srow = next(t for t in g["tools"] if t["name"] == "semgrep")
            if srow["state"] != "error" or "semgrep 副本" not in (g["status_reason"] or "") or "semgrep" in calls \
                    or "預設忽略已停用" in (g["status_reason"] or ""):
                fails.append(f"semgrep 副本建不出來 → semgrep error、不在受驗樹上執行、不寫預設忽略已停用（得到 {srow}、{sorted(calls)}）")
        except Exception as e:
            fails.append(f"追蹤檔無法複製不得拋例外（{type(e).__name__}: {e}）")
        finally:
            (repo / "app/x.py").rmdir(); (repo / "app/x.py").write_text("x = 1\n")
        try:
            raw_f = os.fsencode(repo) + b"/ infra-\xff.tf"
            with open(raw_f, "wb") as fh:
                fh.write(b"# checkov:skip=CKV_AWS_79: t\n")
            git(repo, "add", "-A"); git(repo, "commit", "-qm", "raw")
            g, calls = run(repo)
            json.dumps(g, ensure_ascii=False).encode("utf-8")
            if g["status"] != "pass" or r"infra-\xff.tf" not in (g["status_reason"] or "") \
                    or not any(s.startswith(" infra-") for s in calls.get("checkov", {}).get("scanned", [])):
                fails.append(f"非 UTF-8／前導空白追蹤檔應正常掃描並轉義輸出（得到 {g['status']}：{g['status_reason']}，{calls.get('checkov', {}).get('scanned')}）")
            ck_sur = D / "ck-sur.sarif"
            ck_sur.write_text(json.dumps({"version": "2.1.0", "runs": [{"results": [{"message": {"text": "x-\udcff"},
                              "locations": [{"physicalLocation": {"artifactLocation": {"uri": "c/a-\udcff.tf"}}}]}]}]}), encoding="utf-8")
            _relativize_sarif(ck_sur, D / "c")
            if json.loads(ck_sur.read_text(encoding="utf-8"))["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] != "a-%FF.tf":
                fails.append("_relativize_sarif 應把非 UTF-8 URI 轉成百分比編碼")
            if os.geteuid() != 0:
                (repo / "locked").mkdir(); (repo / "locked/z.tf").write_text("x=1\n")
                git(repo, "add", "-A"); git(repo, "commit", "-qm", "lk")
                (repo / "locked").chmod(0o000)
                try:
                    if copy_tracked(repo, D / "cp-lk")[1] is None:
                        fails.append("上層目錄無權限時 copy_tracked 不得當成已刪除而略過")
                finally:
                    (repo / "locked").chmod(0o755)
        except OSError:
            pass
        except Exception as e:
            fails.append(f"非 UTF-8／前導空白追蹤檔不得拋例外（{type(e).__name__}: {e}）")
    # 政策檔讀不到 → scan 一開始就停：不跑工具、G3 incomplete、控制 untested 並寫明未完成原因、沒有任何發現
    # 政策 root 的 vibesec.yaml 缺 mode 也是政策讀不到（#200）；兩種情況 mode 都記 enforce（mode 不明）
    from vibesec_policy import POLICY_UNREADABLE, broken_policy_root, modeless_policy_root
    import gate_result
    for make_root in (broken_policy_root, modeless_policy_root):
        with make_root() as pr, tempfile.TemporaryDirectory() as d:
            g = scan(pathlib.Path(d), pathlib.Path(d, "out"), {}, policy_root=pr)
            why = g["status_reason"] or ""
            if g["status"] != "incomplete" or POLICY_UNREADABLE + "（" not in why or "不是 git repo" in why or g["mode"] != "enforce" \
                    or (make_root is modeless_policy_root and "mode" not in why) \
                    or {c["state"] for c in g["coverage"]} != {"untested"} or g["findings_count"] != {"blocking": 0, "advisory": 0} \
                    or [c["control_id"] for c in g["coverage"]] != list(sarif_gate.GATE_CONTROLS["G3"]) \
                    or g["tools"] != [gate_result.tool(sarif_gate.SELF_TOOL, "error")] \
                    or list(schema.iter_errors(g)):
                fails.append(f"政策讀不到（{make_root.__name__}；只有 vibesec-sarif-gate 一列 error）→ 不跑工具、G3 incomplete、"
                             f"控制 untested、寫明原因、mode 記 enforce（得到 {g}）")
            # 經 main()：退出碼 2（同政策讀不到）、semgrep／checkov／trivy 都沒有執行（替身被呼叫會留下記號檔）
            rc, ran = sarif_gate.main_with_policy(sys.modules[__name__], pr, pathlib.Path(d), *(f"VIBESEC_{t.upper()}" for t in TOOLS))
            if rc != 2 or ran:
                fails.append(f"政策讀不到（{make_root.__name__}）→ main 退出碼 2、不執行任何工具（得到 {rc}、執行了 {ran}）")
    from vibesec_policy import temp_policy_root
    envs = [f"VIBESEC_{t.upper()}" for t in TOOLS]
    with temp_policy_root() as pr, tempfile.TemporaryDirectory() as d:   # 對照組：政策讀得到時替身確實會被執行
        ran = sarif_gate.main_with_policy(sys.modules[__name__], pr, pathlib.Path(d), *envs)[1]
        if not ran:
            fails.append(f"對照組：政策讀得到時工具替身應被執行（否則上面的「不執行」檢查沒有意義；得到 {ran}）")
    # mode 取自政策（#201）：閘門結果記受信任政策的 mode，不讀 ROOT 的 vibesec.yaml（ROOT 是 shadow：enforce 那一輪才分得出來源）
    from vibesec_policy import mode_policy_root
    for m in ("enforce", "shadow"):
        with mode_policy_root(f"mode: {m}") as pr, tempfile.TemporaryDirectory() as d:
            g = scan(pathlib.Path(d), pathlib.Path(d, "out"), {}, policy_root=pr)
            if g["mode"] != m or POLICY_UNREADABLE in (g["status_reason"] or ""):
                fails.append(f"G3：閘門結果的 mode 取自政策（{m}）（得到 {g['mode']}：{g['status_reason']}）")
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
    print(f"G3 {g['status']}（{printable(str(target.resolve()))}）：blocking={g['findings_count']['blocking']} "
          f"advisory={g['findings_count']['advisory']}" + (f"；{g['status_reason']}" if g["status_reason"] else ""))
    if g["findings_count"]["blocking"]:
        return 1
    return 2 if g["status"] == "incomplete" else 0


if __name__ == "__main__":
    sys.exit(main())
