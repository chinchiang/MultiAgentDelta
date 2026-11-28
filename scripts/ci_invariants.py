#!/usr/bin/env python3
"""CI 設定的不變式（由 scripts/validate.py 呼叫）：防止已修過的 CI 弱點被改回去。

  workflow_write_permissions(text)        workflow 層級的 permissions 不得有 write（寫入權限按 job 宣告）
  unpaginated_list_comments(text)         issues.listComments 必須經 github.paginate（否則只拿到第一頁 30 則）
  precommit_semgrep_drift(pc, rules)      pre-commit 的 semgrep --config 與 vibesec.yaml g3 semgrep_rules 一致
  untrusted_script_runs(text)             workflow 不得執行本分支的 scripts/（判定程式只採用 _trusted/）
  sed_target_substitution(text)           不得以 sed 把受測目標 URL 代入設定（URL 含 # 或 & 會壞）
  sarif_jobs_without_permission(wf)       有 upload-sarif 的 job，有效權限須含 security-events: write
  self_sarif_uploads_without_hashfiles(wf)  上傳自產 SARIF 的步驟須以 hashFiles(<該檔>) 為條件（閘門沒有判定任何發現時不寫 SARIF）
  action_mode_reader_problems(action)      受信任設定 action 以受信任樹的 vibesec_mode 讀 mode，不內嵌自己的 regex（ADR 0002）；不輸出 mode（#220）
  gate_mode_channels(wf)                  workflow 不得以 --mode／VIBESEC_MODE 把 mode 傳給閘門腳本（mode 只取自受信任政策，ADR 0002）
  step_mode_decisions(wf)                 workflow 步驟不得讀 mode 自己判定；判定只在 gate_verdict（#209、GLOSSARY「阻擋判定」）
  g5_probes_wiring(staging)               staging-blackbox.yml 的 G5 api-probes 步驟固定執行 _trusted/scripts/g5_api_probes.py、無路徑覆寫變數與 inline 判定（#292）
  local_gitleaks_flag_drift(pr, md)       workflow.md 第 7 步（中英）的本機 gitleaks 帶 PR CI G2 的掃描旗標（--config 等，#366）
  base_change_wiring(pr, base_changed)    pr-gates 不監聽 edited；目標分支改變由 pr-base-changed.yml 以 fail 的 check 提醒（#368）
  semgrep_registry_wiring(wf, jobs)       semgrep 不以 --config p/ 自己下載；經 semgrep_registry.py fetch／annotate，帶 -j（#374）
  g6_redteam_wiring(staging)              G6 promptfoo redteam 的評分 provider 由 _trusted/scripts/g6_redteam_provider.py 依資料分級挑選，不 inline、不寫死（#356）

  python3 scripts/ci_invariants.py selftest
"""
from __future__ import annotations
import copy, re, sys

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
G5_PROBES_STEP = "G5 api-probes"
G5_PROBES_SCRIPT = "_trusted/scripts/g5_api_probes.py"
G5_ALLOWED_STEP_ENV = frozenset({"VIBESEC_TARGET_URL", "HAS_A", "HAS_B", "VIBESEC_TOKEN_DIR", "VIBESEC_CONFIG"})
_G5_GUARD_LINE = re.compile(
    rf"^(?:if \[ ! -f {re.escape(G5_PROBES_SCRIPT)} \]; then|echo \"::error::[^\n`$]*\"|exit 1|fi)$"
)


def _matching_steps(wf: dict, prefix: str) -> list[tuple[dict, dict]]:
    return [
        (job or {}, st)
        for job in (wf.get("jobs") or {}).values()
        for st in ((job or {}).get("steps") or [])
        if str(st.get("name", "")).startswith(prefix)
    ]


def _has_inline_python(code: str) -> bool:
    return bool(
        "<<" in code
        or re.search(r"\bpython3?\b[^\n]*(?:\s-c\b|\s-\s*(?:<|$))", code, re.M)
        or re.search(r"\|\s*python3?(?:\s|$)", code)
    )


def g4_static_wiring(pr_gates: dict) -> list[str]:
    """G4 靜態檢查必須以隔離模式執行受信任樹的 scripts/g4_static.py（#151／#152）：以前是 workflow 內約 270 行的
    inline heredoc，run_evals 與 g4_access 從 workflow 文字取出同一段來跑。改回 inline、改呼叫 PR head 的
    scripts/、或拿掉 -I（PYTHON* 環境變數與使用者 site-packages 可改寫判定程式 import 的模組）→ 回報。"""
    matches = _matching_steps(pr_gates, G4_STATIC_STEP)
    if len(matches) != 1:
        return [f"pr-gates.yml 應恰有一個「{G4_STATIC_STEP}」步驟（得到 {len(matches)} 個）"]
    run, out = str(matches[0][1].get("run") or ""), []
    if G4_STATIC_CALL not in run:
        out.append(f"「{G4_STATIC_STEP}」步驟沒有以 `{G4_STATIC_CALL}` 執行")
    if _has_inline_python(run):
        out.append(f"「{G4_STATIC_STEP}」步驟含 inline 程式碼（heredoc／stdin），判定程式必須在受信任的腳本內")
    return out


def g5_probes_wiring(staging: dict) -> list[str]:
    """staging-blackbox.yml 的 G5 api-probes 步驟持有雙帳號 token（#292）：固定只執行受信任樹的
    _trusted/scripts/g5_api_probes.py（搭配缺檔 fail-closed 檢查），不得含腳本路徑覆寫變數、退回分支或 inline 程式碼。"""
    matches = _matching_steps(staging, G5_PROBES_STEP)
    if len(matches) != 1:
        return [f"staging-blackbox.yml 應恰有一個「{G5_PROBES_STEP}」步驟（得到 {len(matches)} 個）"]
    job, st = matches[0]
    raw_run = str(st.get("run") or "")
    lines = [ln.strip() for ln in raw_run.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    code = "\n".join(lines)
    out: list[str] = []
    exact_line = re.compile(rf"^python3(?:\s+-I)?\s+{re.escape(G5_PROBES_SCRIPT)}$")
    call_lines = [ln for ln in lines if exact_line.match(ln)]
    if len(call_lines) != 1:
        out.append(f"「{G5_PROBES_STEP}」步驟必須恰有一行獨立的 `python3 {G5_PROBES_SCRIPT}` 呼叫")
    step_env = st.get("env") or {}
    extra_step_env = sorted(set(step_env) - G5_ALLOWED_STEP_ENV)
    has_override = (
        "VIBESEC_G5_PROBES" in (staging.get("env") or {})
        or "VIBESEC_G5_PROBES" in (job.get("env") or {})
        or "VIBESEC_G5_PROBES" in step_env
        or "VIBESEC_G5_PROBES" in code
        or bool(extra_step_env)
        or bool(re.search(r"\$\{[^}]*:-", code))
    )
    if has_override:
        out.append(f"「{G5_PROBES_STEP}」步驟含腳本路徑覆寫或非預期環境變數設定")
    if _has_inline_python(code):
        out.append(f"「{G5_PROBES_STEP}」步驟含 inline 程式碼（heredoc／stdin／-c／pipe），判定程式必須在受信任的腳本內")
    other_lines = [ln for ln in lines if not exact_line.match(ln)]
    if any(not _G5_GUARD_LINE.match(ln) for ln in other_lines):
        out.append(f"「{G5_PROBES_STEP}」步驟含允許守衛以外的額外指令或退回分支")
    return out


G6_REDTEAM_STEP = "G6 promptfoo redteam"
G6_REDTEAM_CALL = "python3 -I _trusted/scripts/g6_redteam_provider.py"
_G6_HARDCODED_PROVIDER = re.compile(r"\banthropic:messages:|\bopenai:chat:")


def g6_redteam_wiring(staging: dict) -> list[str]:
    """redteam 會把目標回應送給 provider 評分（#356、規則 7）：評分 provider 只能由受信任樹的 g6_redteam_provider.py
    依資料分級挑選。改回 inline 選 provider、寫死 provider ID、直接讀 providers.yaml、改呼叫本分支腳本或拿掉 -I → 回報。
    註解不算（只看指令行）。"""
    matches = _matching_steps(staging, G6_REDTEAM_STEP)
    if len(matches) != 1:
        return [f"staging-blackbox.yml 應恰有一個「{G6_REDTEAM_STEP}」步驟（得到 {len(matches)} 個）"]
    lines = [ln for ln in str(matches[0][1].get("run") or "").splitlines() if not ln.lstrip().startswith("#")]
    code, out = "\n".join(lines), []
    if G6_REDTEAM_CALL not in code:
        out.append(f"「{G6_REDTEAM_STEP}」步驟沒有以 `{G6_REDTEAM_CALL}` 挑選評分 provider")
    if _has_inline_python(code):
        out.append(f"「{G6_REDTEAM_STEP}」步驟含 inline 程式碼（heredoc／stdin／-c／pipe），provider 必須由受信任的腳本挑選")
    if _G6_HARDCODED_PROVIDER.search(code):
        out.append(f"「{G6_REDTEAM_STEP}」步驟寫死 provider ID（anthropic:messages:／openai:chat:）")
    if "providers.yaml" in code:
        out.append(f"「{G6_REDTEAM_STEP}」步驟直接讀 providers.yaml（資料分級判斷只在 g6_redteam_provider.py）")
    # fail-closed：只有「exit 0 且輸出 provider=」才往下執行 redteam；退出碼被忽略時，腳本出錯也會照樣送出
    if not re.search(r'case "\$rc:\$DECISION" in', code) or not re.search(r"^\s*0:provider=\*\)", code, re.M):
        out.append(f"「{G6_REDTEAM_STEP}」步驟沒有以 case \"$rc:$DECISION\" 判斷退出碼（只有 0:provider=* 可以往下執行 redteam）")
    return out


GITLEAKS_SCAN_FLAGS = ("--config", "--gitleaks-ignore-path", "--ignore-gitleaks-allow")
LOCAL_GITLEAKS_STEPS = ("**本機 gitleaks**", "**Local gitleaks**")   # workflow.md 中英兩段該步驟的標題（不綁步驟編號）
_NUMBERED_ITEM = re.compile(r"^\d+\.\s")


def _has_flag(text: str, flag: str) -> bool:
    return bool(re.search(rf"(?<![\w-]){re.escape(flag)}(?=[\s=]|$)", text))


def local_gitleaks_flag_drift(pr_gates: dict, workflow_md: str) -> list[str]:
    """workflow.md「本機 gitleaks」步驟（中英兩段）的指令與 PR CI 的 G2（pr-gates.yml 的 id: gitleaks）都必須帶三個掃描旗標
    （--config、--gitleaks-ignore-path、--ignore-gitleaks-allow）。以前本機步驟沒帶 config/gitleaks.toml，本機 no leaks found、
    CI 的 G2 卻 fail（#366，PR #360）。只比旗標、不比路徑：CI 的設定是 _trusted/config/gitleaks.toml，.gitleaksignore 由受信任
    action 換成 default branch 的版本；本機兩者都取自 /tmp/wt-main。
    CI 少帶其中任何一個也回報（等於放寬 G2）。本機步驟只比對該項內的 ```bash 程式碼區塊（說明文字提到旗標不算）；
    範圍是從該項到下一個編號項目為止。找不到 CI step、該步驟或程式碼區塊 → 回報（無法比對，不是通過）。"""
    runs = [str(st.get("run") or "") for job in (pr_gates.get("jobs") or {}).values()
            for st in ((job or {}).get("steps") or []) if st.get("id") == "gitleaks"]
    if len(runs) != 1:
        return [f"pr-gates.yml 應恰有一個 id: gitleaks 的步驟（得到 {len(runs)} 個），無法比對本機 gitleaks 的旗標"]
    out = [f"pr-gates.yml 的 gitleaks 步驟少了掃描旗標 {f}（G2 不得少於這三個旗標）"
           for f in GITLEAKS_SCAN_FLAGS if not _has_flag(runs[0], f)]
    lines = workflow_md.splitlines()
    for head in LOCAL_GITLEAKS_STEPS:
        starts = [i for i, ln in enumerate(lines) if _NUMBERED_ITEM.match(ln) and head in ln]
        if len(starts) != 1:
            out.append(f"docs/agents/workflow.md 應恰有一個「{head}」步驟（得到 {len(starts)} 個）")
            continue
        end = next((j for j in range(starts[0] + 1, len(lines)) if _NUMBERED_ITEM.match(lines[j])), len(lines))
        code, inside = [], False
        for ln in lines[starts[0] + 1:end]:
            if ln.strip().startswith("```"):
                inside = not inside
                continue
            if inside:
                code.append(ln)
        command = "\n".join(code)
        if not command.strip():
            out.append(f"docs/agents/workflow.md「{head}」步驟沒有 ```bash 程式碼區塊，無法比對旗標")
            continue
        missing = [f for f in GITLEAKS_SCAN_FLAGS if not _has_flag(command, f)]
        if missing:
            out.append(f"docs/agents/workflow.md「{head}」的指令少了 PR CI G2 用到的旗標：{'、'.join(missing)}")
    return out


BASE_CHANGED_EVENTS = ("opened", "synchronize", "reopened", "edited")


def _on(wf: dict) -> dict:
    """workflow 的 on：PyYAML 把裸的 on 讀成 True。"""
    on = wf.get("on", wf.get(True))
    return on if isinstance(on, dict) else {}


def base_change_wiring(pr_gates: dict, base_changed: dict | None) -> list[str]:
    """改 PR 內文不得觸發 pr-gates；目標分支改變由 pr-base-changed.yml 以 fail 的 check 提醒（#368）。
    pr-gates 監聽 edited → 改標題或內文就整套重跑；而在 job 層略過又會產生同名的 skipped check，蓋掉真正的結果。
    pr-base-changed.yml：必須存在、監聽 opened／synchronize／reopened／edited、以 changes.base 判斷，
    不 checkout、權限只有 contents: read（它不需要讀程式碼）。"""
    out = []
    types = (_on(pr_gates).get("pull_request") or {}).get("types")
    if not isinstance(types, list):
        out.append("pr-gates.yml 的 pull_request 沒有明確列出 types（預設事件無法確認不含 edited）")
    elif "edited" in types:
        out.append("pr-gates.yml 的 pull_request.types 含 edited：改 PR 內文就整套重跑（目標分支改變改由 pr-base-changed.yml 處理）")
    if base_changed is None:
        return out + ["pr-base-changed.yml 不存在：目標分支改變後沒有任何提醒，pr-gates 的結果會停在舊的 base"]
    btypes = (_on(base_changed).get("pull_request") or {}).get("types") or []
    missing = [t for t in BASE_CHANGED_EVENTS if t not in btypes]
    if missing:
        out.append(f"pr-base-changed.yml 的 pull_request.types 少了 {'、'.join(missing)}")
    jobs = base_changed.get("jobs") or {}
    steps = [st for job in jobs.values() for st in ((job or {}).get("steps") or [])]
    # 只看 step（if／env／run）：job 名稱的運算式也含 changes.base，但它只決定名稱，不決定 fail
    if not any("changes.base" in repr({k: st.get(k) for k in ("if", "env", "run")}) for st in steps):
        out.append("pr-base-changed.yml 沒有在 step 以 github.event.changes.base 判斷目標分支是否改變（fail 的條件）")
    if any(str(st.get("uses") or "").startswith("actions/checkout") for st in steps):
        out.append("pr-base-changed.yml 含 actions/checkout（它不需要讀程式碼）")
    # 權限不得超過 contents: read（更小的 {}、contents: none 可以）；workflow 層必須明確宣告，否則是 repo 的預設權限
    within = lambda perms: isinstance(perms, dict) and all(v == "none" or (k == "contents" and v == "read")
                                                           for k, v in perms.items())
    if not within(base_changed.get("permissions")):
        out.append(f"pr-base-changed.yml 的 workflow 權限必須明確宣告且不超過 contents: read（得到 {base_changed.get('permissions')!r}）")
    for jid, job in jobs.items():
        perms = (job or {}).get("permissions")
        if perms is not None and not within(perms):
            out.append(f"pr-base-changed.yml 的 job {jid} 權限超過 contents: read（得到 {perms!r}）")
    return out


# semgrep 的呼叫：行首（可有 VAR=值 前綴）的 semgrep，後面接 ci／scan 子命令或直接接旗標（舊寫法 `semgrep --config …`）
_SEMGREP_RUN = re.compile(r"^\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*semgrep\s+(?:ci\b|scan\b|-)", re.M)
# registry 規則集：--config／-c 接 p/、r/，或 auto（也會從 registry 下載）
_REGISTRY_CONFIG = re.compile(r"(?:--config|(?<![\w-])-c)[\s=]+['\"]?(?:[pr]/|auto\b)")


def semgrep_registry_wiring(wf: dict, max_jobs: int) -> list[str]:
    """workflow 的 semgrep 不得以 --config p/<名稱> 讓 semgrep 自己下載 registry 規則集（#374）：那樣沒有任何紀錄能說明
    這次用的是哪一版規則集。要經 semgrep_registry.py fetch（下載一次、記 SHA-256、輸出檔案路徑）與 annotate（紀錄寫進 SARIF），
    semgrep 也要帶 -j <max_jobs>（scripts/g3_sast.py 的 SEMGREP_MAX_JOBS，#344）。沒有執行 semgrep 的 workflow 不檢查；註解行略過。"""
    out = []
    for job in (wf.get("jobs") or {}).values():
        for st in ((job or {}).get("steps") or []):
            code = "\n".join(ln for ln in str(st.get("run") or "").splitlines() if not ln.lstrip().startswith("#"))
            # 一個指令可能跨好幾行（行尾 \）：接成一行再比對（`--config \` 換行後才接 p/ 也抓得到）
            calls = [ln for ln in re.sub(r"\\\n\s*", " ", code).splitlines() if _SEMGREP_RUN.match(ln)]
            if not calls:
                continue
            where = f"「{st.get('name') or st.get('id') or '（未命名 step）'}」"
            if any(_REGISTRY_CONFIG.search(ln) for ln in calls):
                out.append(f"{where} 的 semgrep 以 --config p/<名稱>（或 -c p/、r/、auto）讓 semgrep 自己下載 registry 規則集；"
                           "要經 semgrep_registry.py fetch 取得檔案")
            for sub in ("fetch", "annotate"):   # 同一個 step 裡（不是整份 workflow 任一處）
                if f"semgrep_registry.py {sub}" not in code:
                    out.append(f"{where} 沒有以 semgrep_registry.py {sub} 處理 registry 規則集")
            for ln in calls:
                m = re.search(r"(?:^|\s)(?:-j|--jobs)[\s=]+(\d+)", ln)
                if not m or int(m.group(1)) != max_jobs:
                    out.append(f"{where} 的 semgrep 沒有帶 -j {max_jobs}（SEMGREP_MAX_JOBS，#344）：{ln.strip()[:80]}")
    return out


CFG_STEP_NAME = "讀取受信任的 mode"
GATE_SCRIPTS = ("g4_static.py", "g4_review.py", "g5_api_probes.py", "g6_gate.py")   # 不含 gate_verdict.py（阻擋判定可以升級）


def action_mode_reader_problems(action: dict) -> list[str]:
    """受信任設定 action 讀 mode 的步驟（#203）：以 python3 -I import 受信任樹的 vibesec_mode（read_mode、top_scalar），
    不得內嵌 regex 或合法值清單。以前 action 自己寫一份 regex，與閘門讀 mode 的規則可能漂移（ADR 0002）。
    mode 只用來算 shadow，不得經 action 的輸出（不論鍵名）或步驟輸出（不論寫法）交給 workflow（#220）。"""
    steps = [st for st in ((action.get("runs") or {}).get("steps") or [])
             if str(st.get("name", "")).startswith(CFG_STEP_NAME)]
    if len(steps) != 1:
        return [f"受信任設定 action 應恰有一個「{CFG_STEP_NAME}」步驟（得到 {len(steps)} 個）"]
    run, out = str(steps[0].get("run") or ""), []
    if not re.search(r"^\s*from vibesec_mode import .*\bread_mode\b", run, re.M):
        out.append(f"「{CFG_STEP_NAME}」步驟沒有 import vibesec_mode 的 read_mode")
    if re.search(r"^\s*import .*\bre\b|\bre\.(search|match|sub|compile)\(", run, re.M):
        out.append(f"「{CFG_STEP_NAME}」步驟內嵌了自己的 regex（mode 的規則只能在 vibesec_mode）")
    if re.search(r"""[\(\[]\s*["']shadow["']\s*,\s*["']enforce["']""", run):
        out.append(f"「{CFG_STEP_NAME}」步驟寫死了合法值清單（只能用 vibesec_mode 的 MODES）")
    if "python3 -I" not in run:
        out.append(f"「{CFG_STEP_NAME}」步驟沒有以 python3 -I 執行（工作目錄是 PR head，可蓋掉標準函式庫）")
    # mode 只用來算 shadow；阻擋判定自己讀受信任樹，workflow 不得讀 mode（step_mode_decisions），所以也不輸出（#220）
    outputs = action.get("outputs") or {}
    if "mode" in outputs or _MODE_READ.search(repr(outputs)):
        out.append("受信任設定 action 不得輸出 mode（只輸出 shadow；判定由 gate_verdict 讀受信任樹）")
    if re.search(r"(?:(?<![\w.])|(?<=\\n))mode=(?!=)", run):   # print(f"mode=…")、echo "mode=…"、"…\nmode=…" 都算；mode == 比較不算
        out.append(f"「{CFG_STEP_NAME}」步驟把 mode 寫進步驟輸出（只輸出 shadow）")
    return out


def gate_mode_channels(wf: dict) -> list[str]:
    """呼叫閘門腳本的步驟不得以 --mode 或 VIBESEC_MODE 傳 mode（#203、ADR 0002：mode 只取自受信任政策）。
    阻擋判定（gate_verdict）的 --mode 可以升級，不檢查；所有步驟讀 mode 與否另由 step_mode_decisions 檢查（兩者重疊時會各報一次）。
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


_MODE_READ = re.compile(r"VIBESEC_MODE|\boutputs\s*(\.\s*mode\b|\[\s*['\"]mode['\"]\s*\])")


def _mode_read_in(fields: dict) -> bool:
    """fields（步驟、job 或 workflow 的設定）是否讀 mode。run 裡只有註解的行不算（說明文字不是判定），name 不檢查。"""
    fields = dict(fields)
    fields.pop("name", None)
    if isinstance(fields.get("run"), str):
        fields["run"] = "\n".join(ln for ln in fields["run"].splitlines() if not ln.lstrip().startswith("#"))
    return bool(_MODE_READ.search(repr(fields)))


def step_mode_decisions(wf: dict) -> list[str]:
    """阻擋判定一律由 gate_verdict.py 執行（GLOSSARY「阻擋判定」、docs/10 §9.1）：workflow 的步驟（run、env、if 等欄位）不得讀 mode
    （VIBESEC_MODE、steps.<id>.outputs.mode）。以前 G2 的 .env 檢查在 bash 裡依 VIBESEC_MODE 自己擋，是第二份判定（#209）。
    gate_verdict 自己讀受信任樹的 mode，步驟不必傳給它，所以呼叫 gate_verdict 的步驟也不豁免；--mode enforce 這類寫死的升級不算讀 mode。
    job 與 workflow 層級的設定（env、if）會作用到每個步驟，一併檢查。"""
    out = []
    if _mode_read_in({k: v for k, v in wf.items() if k == "env"}):
        out.append("workflow 層級 env")
    for jname, job in (wf.get("jobs") or {}).items():
        if _mode_read_in({k: v for k, v in (job or {}).items() if k != "steps"}):
            out.append(f"{jname}：job 層級設定")
        for st in (job or {}).get("steps") or []:
            if _mode_read_in(st):
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
                "from vibesec_mode import read_mode, top_scalar\nprint(f\"shadow={'true' if mode == 'shadow' else 'false'}\")\nPY\n")
    act = lambda run, sid="cfg": {"runs": {"steps": [{"name": "讀取受信任的 mode / risk_tier", "id": sid, "run": run}]}}
    for label, a, want in [
        ("以 vibesec_mode 讀", act(good_cfg), 0),
        ("內嵌 regex（舊版）", act("python3 -I - <<'PY'\nimport sys, re, pathlib\nm = re.search(r'^mode', t)\n"
                                  "if mode not in (\"shadow\", \"enforce\"): sys.exit(2)\nPY\n"), 3),
        ("拿掉 -I", act(good_cfg.replace("python3 -I -", "python3 -")), 1),
        ("步驟缺席", {"runs": {"steps": []}}, 1),
        ("輸出 mode（#220 以前）", {**act(good_cfg + 'print(f"mode={mode}")\n'),
                                  "outputs": {"mode": {"value": "${{ steps.cfg.outputs.mode }}"}}}, 2),
        ("換鍵名輸出 mode", {**act(good_cfg), "outputs": {"gate_mode": {"value": "${{ steps.cfg.outputs.mode }}"}}}, 1),
        ("其他寫法輸出 mode", act(good_cfg + 'sys.stdout.write("shadow=x\\nmode=" + mode)\n'), 1),
        ("bash echo 輸出 mode", act(good_cfg + 'echo "mode=$M" >> "$GITHUB_OUTPUT"\n'), 1),
        ("只輸出 shadow", {**act(good_cfg), "outputs": {"shadow": {"value": "${{ steps.cfg.outputs.shadow }}"}}}, 0),
    ]:
        try:
            got = action_mode_reader_problems(a)
        except Exception as e:
            got = None, f"例外 {type(e).__name__}：{e}"
        if isinstance(got, tuple) or len(got) != want:
            fails.append(f"action_mode_reader_problems「{label}」應回報 {want} 項（得到 {got}）")
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
    # 步驟不得讀 mode（#209）：G2 .env 檢查以前的寫法、if 條件、job 層級、gate_verdict 步驟裡另寫的判定；
    # 寫死的 --mode enforce、註解、action 的 shadow 輸出不算
    for label, wf, want in [
        ("G2 .env 步驟以前的寫法", {"jobs": {"g2": {"steps": [step(
            'python3 -I "$ROOT/scripts/env_guard.py" --json > r.json\nif [ "${VIBESEC_MODE}" = "enforce" ]; then exit 1; fi',
            {"VIBESEC_MODE": "${{ steps.trusted.outputs.mode }}"})]}}}, 1),
        ("步驟 if 讀 outputs.mode", {"jobs": {"a": {"steps": [{"name": "s", "if": "steps.trusted.outputs.mode == 'enforce'",
                                                            "run": "exit 1"}]}}}, 1),
        ("job 層級 env", {"jobs": {"a": {"env": {"M": "${{ needs.x.outputs.mode }}"}, "steps": [step("echo")]}}}, 1),
        ("workflow 層級 env", {"env": {"VIBESEC_MODE": "x"}, "jobs": {"a": {"steps": [step("echo")]}}}, 1),
        ("gate_verdict 步驟另寫判定", {"jobs": {"a": {"steps": [step(
            'python3 _trusted/scripts/gate_verdict.py enforce --trusted-root _trusted\n'
            'if [ "$VIBESEC_MODE" = enforce ]; then exit 1; fi')]}}}, 1),
        ("outputs['mode'] 寫法", {"jobs": {"a": {"steps": [{"name": "s", "if": "steps.trusted.outputs['mode'] == 'enforce'",
                                                          "run": "exit 1"}]}}}, 1),
        ("寫死升級的 gate_verdict", {"jobs": {"a": {"steps": [step(
            "python3 _trusted/scripts/gate_verdict.py enforce --trusted-root _trusted --mode enforce")]}}}, 0),
        ("只有註解提到", {"jobs": {"a": {"steps": [{"name": "說明 VIBESEC_MODE", "run":
            "# 以前這裡讀 VIBESEC_MODE 自己擋\n  # steps.trusted.outputs.mode\npython3 -I x.py"}]}}}, 0),
        ("shadow 輸出不算", {"jobs": {"a": {"steps": [{"name": "s", "continue-on-error": "${{ steps.trusted.outputs.shadow == 'true' }}",
                                                      "run": "python3 -I _trusted/scripts/env_guard.py --json"}]}}}, 0),
    ]:
        try:
            got = step_mode_decisions(wf)
        except Exception as e:
            got = None, f"例外 {type(e).__name__}：{e}"
        if isinstance(got, tuple) or len(got) != want:
            fails.append(f"step_mode_decisions「{label}」應回報 {want} 項（得到 {got}）")
    # staging 的 G5 api-probes 步驟持有雙帳號 token（#292）：固定執行 _trusted/scripts/g5_api_probes.py，
    # 不得有 VIBESEC_G5_PROBES 覆寫分支、間接變數執行或 inline 程式碼
    g5_ok_run = ("# 探針程式取自 default branch\n"
                 "if [ ! -f _trusted/scripts/g5_api_probes.py ]; then\n"
                 "  exit 1\n"
                 "fi\n"
                 "python3 _trusted/scripts/g5_api_probes.py\n")
    g5_wf = lambda run, env=None, job_env=None, wf_env=None: {
        **({"env": wf_env} if wf_env else {}),
        "jobs": {"blackbox": {
            **({"env": job_env} if job_env else {}),
            "steps": [{"name": "G5 api-probes（雙帳號 BOLA / JWT / SSRF / 設定外溢 / rate-limit）",
                       "run": run, **({"env": env} if env else {})}],
        }},
    }
    for label, wf, want_bad in [
        ("固定執行受信任腳本", g5_wf(g5_ok_run), False),
        ("支援 python3 -I 呼叫", g5_wf("python3 -I _trusted/scripts/g5_api_probes.py\n"), False),
        ("允許標準步驟 env", g5_wf(g5_ok_run, env={"VIBESEC_TARGET_URL": "x", "VIBESEC_CONFIG": "_trusted/vibesec.yaml"}), False),
        ("舊版 VIBESEC_G5_PROBES 覆寫分支", g5_wf(
            'S="${VIBESEC_G5_PROBES:-_trusted/scripts/g5_api_probes.py}"\npython3 "$S"\n'), True),
        ("改名變數覆寫分支", g5_wf(
            'S="${ALT_G5_SCRIPT:-_trusted/scripts/g5_api_probes.py}"\nbash "$S"\n'), True),
        ("步驟 env 含 VIBESEC_G5_PROBES", g5_wf(g5_ok_run, env={"VIBESEC_G5_PROBES": "x"}), True),
        ("步驟 env 含未授權變數", g5_wf(g5_ok_run, env={"ALT_PROBES": "x"}), True),
        ("job env 含 VIBESEC_G5_PROBES", g5_wf(g5_ok_run, job_env={"VIBESEC_G5_PROBES": "x"}), True),
        ("workflow env 含 VIBESEC_G5_PROBES", g5_wf(g5_ok_run, wf_env={"VIBESEC_G5_PROBES": "x"}), True),
        ("改跑 PR head 的 scripts/", g5_wf("python3 scripts/g5_api_probes.py\n"), True),
        ("else 退回本分支腳本", g5_wf(
            "if [ -f _trusted/scripts/g5_api_probes.py ]; then\n"
            "  python3 _trusted/scripts/g5_api_probes.py\n"
            "else\n"
            "  python3 scripts/g5_api_probes.py\n"
            "fi\n"), True),
        ("同行 || 退回本分支腳本", g5_wf("python3 _trusted/scripts/g5_api_probes.py || python3 scripts/g5_api_probes.py\n"), True),
        ("間接變數執行 python3 \"$S\"", g5_wf('S=_trusted/scripts/g5_api_probes.py\npython3 "$S"\n'), True),
        ("直接呼叫外夾帶額外指令", g5_wf(g5_ok_run + 'bash "$EXTRA"\n'), "額外指令"),
        ("只有缺檔守衛、漏掉執行腳本", g5_wf("if [ ! -f _trusted/scripts/g5_api_probes.py ]; then\n  exit 1\nfi\n"), "恰有一行"),
        ("重複呼叫探針腳本兩次", g5_wf(g5_ok_run + "python3 _trusted/scripts/g5_api_probes.py\n"), "恰有一行"),
        ("只有註解提到呼叫、實際未執行", g5_wf("# python3 _trusted/scripts/g5_api_probes.py\necho noop\n"), "恰有一行"),
        ("inline heredoc 判定", g5_wf(g5_ok_run + "python3 -I - <<'EOF'\nprint(1)\nEOF\n"), "inline"),
        ("inline python -c 判定", g5_wf(g5_ok_run + "python3 -c 'print(1)'\n"), "inline"),
        ("pipe 送進 python 判定", g5_wf(g5_ok_run + "echo 'print(1)' | python3\n"), "inline"),
        ("步驟缺席", {"jobs": {"blackbox": {"steps": [{"name": "其他步驟", "run": g5_ok_run}]}}}, "恰有一個"),
        ("步驟重複", {"jobs": {"a": g5_wf(g5_ok_run)["jobs"]["blackbox"],
                              "b": g5_wf(g5_ok_run)["jobs"]["blackbox"]}}, "恰有一個"),
    ]:
        try:
            got = g5_probes_wiring(wf)
        except Exception as e:
            got = None, f"例外 {type(e).__name__}：{e}"
        if isinstance(got, tuple):
            fails.append(f"g5_probes_wiring「{label}」拋出例外：{got}")
        elif want_bad is False and got:
            fails.append(f"g5_probes_wiring「{label}」應通過（得到 {got}）")
        elif want_bad and not got:
            fails.append(f"g5_probes_wiring「{label}」應回報問題（得到 {got}）")
        elif isinstance(want_bad, str) and not any(want_bad in m for m in got):
            fails.append(f"g5_probes_wiring「{label}」應回報含「{want_bad}」的問題（得到 {got}）")

    # #356：redteam 的評分 provider 只能由受信任樹的 g6_redteam_provider.py 依資料分級挑選（規則 7）
    g6_ok_run = ('set +e\nDECISION=$(python3 -I _trusted/scripts/g6_redteam_provider.py --target-kind "$TARGET_KIND" '
                 '--out "$RUNNER_TEMP/promptfoo-redteam.yaml"); rc=$?\nset -e\ncase "$rc:$DECISION" in\n'
                 '  0:provider=*) echo ok ;;\n  *) exit 0 ;;\nesac\n'
                 'timeout 1800 npx --yes "promptfoo@${PROMPTFOO_VERSION}" redteam run -c "$RUNNER_TEMP/promptfoo-redteam.yaml"\n')
    g6_wf = lambda run: {"jobs": {"blackbox": {"steps": [{"name": "G6 promptfoo redteam（選用）", "run": run}]}}}
    old_inline = ("python3 -I - <<'PY'\nprov = yaml.safe_load(open(\"_trusted/config/providers.yaml\"))[\"providers\"]\n"
                  "pid = f\"anthropic:messages:{prov['anthropic-cloud']['model']}\"\nPY\n")
    wiring = globals().get("g6_redteam_wiring")
    for label, wf, want_bad in [
        ("呼叫受信任腳本", g6_wf(g6_ok_run), False),
        ("註解提到 providers.yaml 不算", g6_wf("# 依 config/providers.yaml 的分級挑選\n" + g6_ok_run), False),
        ("改回 inline 選 provider（#356 以前）", g6_wf(old_inline), "inline"),
        ("寫死 anthropic provider ID", g6_wf(g6_ok_run + "PID=anthropic:messages:claude\n"), "寫死"),
        ("寫死 openai provider ID", g6_wf(g6_ok_run + "PID=openai:chat:gpt\n"), "寫死"),
        ("直接讀 providers.yaml", g6_wf(g6_ok_run + "yq .providers _trusted/config/providers.yaml\n"), "providers.yaml"),
        ("呼叫本分支的腳本", g6_wf(g6_ok_run.replace("_trusted/scripts/", "scripts/")), "g6_redteam_provider"),
        ("拿掉 -I", g6_wf(g6_ok_run.replace("python3 -I ", "python3 ")), "g6_redteam_provider"),
        ("步驟缺席", {"jobs": {"blackbox": {"steps": [{"name": "其他", "run": g6_ok_run}]}}}, "恰有一個"),
        ("忽略退出碼直接執行", g6_wf("python3 -I _trusted/scripts/g6_redteam_provider.py --target-kind lab --out x || true\n"
                                 "npx promptfoo redteam run -c x\n"), "退出碼"),
    ]:
        try:
            got = wiring(wf) if wiring else None
        except Exception as e:
            got = f"例外 {type(e).__name__}：{e}"
        if not isinstance(got, list):
            fails.append(f"g6_redteam_wiring「{label}」無法執行（得到 {got!r}）")
        elif want_bad is False and got:
            fails.append(f"g6_redteam_wiring「{label}」應通過（得到 {got}）")
        elif want_bad and not any(want_bad in m for m in got):
            fails.append(f"g6_redteam_wiring「{label}」應回報含「{want_bad}」的問題（得到 {got}）")

    # #366：workflow.md 第 7 步（中英兩段）的本機 gitleaks 必須帶 PR CI G2 用到的掃描旗標
    ci_run = ('"$RUNNER_TEMP/gitleaks" git . --config _trusted/config/gitleaks.toml --gitleaks-ignore-path .gitleaksignore \\\n'
              '  --ignore-gitleaks-allow --log-opts="--text ${RANGE}" --redact --no-banner --exit-code 0\n')
    pr_wf = lambda run: {"jobs": {"g2": {"steps": [{"id": "gitleaks", "name": "Gitleaks", "run": run}]}}}
    local = ('"$(python3 -I scripts/fetch_gitleaks.py)" git --config /tmp/wt-main/config/gitleaks.toml \\\n'
             '     --gitleaks-ignore-path /tmp/wt-main/.gitleaksignore --ignore-gitleaks-allow \\\n'
             '     --log-opts="--text origin/main..HEAD" --no-banner --redact .')
    md = lambda zh, en: (f"6. **code review**：…\n7. **本機 gitleaks**：\n   ```bash\n   {zh}\n   ```\n   必須沒有發現。\n8. **開 PR**：…\n"
                         f"\n6. **Code review**: …\n7. **Local gitleaks**:\n   ```bash\n   {en}\n   ```\n   must find nothing.\n8. **Open the PR**: …\n")
    drift = globals().get("local_gitleaks_flag_drift")
    for label, wf, text, want_bad in [
        ("中英兩段都帶三個旗標", pr_wf(ci_run), md(local, local), False),
        ("中文段少 --config", pr_wf(ci_run), md(local.replace("--config /tmp/wt-main/config/gitleaks.toml ", ""), local), "本機 gitleaks"),
        ("英文段少 --ignore-gitleaks-allow", pr_wf(ci_run), md(local, local.replace("--ignore-gitleaks-allow ", "")), "Local gitleaks"),
        ("第 8 步的旗標不算第 7 步的", pr_wf(ci_run),
         md(local.replace(" --ignore-gitleaks-allow", ""), local).replace("8. **開 PR**：…", "8. **開 PR**：--ignore-gitleaks-allow"), "--ignore-gitleaks-allow"),
        ("只有名稱相近的 --config-dir 不算 --config", pr_wf(ci_run),
         md(local.replace("--config /tmp/wt-main/config/gitleaks.toml", "--config-dir /tmp/wt-main/config"), local), "--config"),
        ("舊的第 7 步（#366 以前）", pr_wf(ci_run), md('gitleaks git --log-opts="--text origin/main..HEAD" --no-banner --redact .', local), "--config"),
        ("CI 少帶 --ignore-gitleaks-allow 也回報", pr_wf(ci_run.replace("--ignore-gitleaks-allow ", "")), md(local, local), "pr-gates.yml"),
        ("說明文字提到旗標不算", pr_wf(ci_run),
         md(local.replace(" --ignore-gitleaks-allow", ""), local).replace("   必須沒有發現。", "   必須沒有發現。以前沒帶 --ignore-gitleaks-allow 等旗標。"),
         "--ignore-gitleaks-allow"),
        ("步驟沒有程式碼區塊", pr_wf(ci_run), md(local, local).replace("   ```bash\n   " + local + "\n   ```\n   必須沒有發現。", "   必須沒有發現。", 1),
         "程式碼區塊"),
        ("步驟重新編號（第 6 步）仍找得到", pr_wf(ci_run), md(local, local).replace("7. **本機 gitleaks**", "6. **本機 gitleaks**"), False),
        ("找不到該步驟", pr_wf(ci_run), "6. **code review**：…\n", "步驟"),
        ("pr-gates 找不到 gitleaks step", {"jobs": {"g2": {"steps": [{"id": "other", "run": ci_run}]}}}, md(local, local), "無法比對"),
    ]:
        try:
            got = drift(wf, text) if drift else None
        except Exception as e:
            got = f"例外 {type(e).__name__}：{e}"
        if not isinstance(got, list):
            fails.append(f"local_gitleaks_flag_drift「{label}」無法執行（得到 {got!r}）")
        elif want_bad is False and got:
            fails.append(f"local_gitleaks_flag_drift「{label}」應通過（得到 {got}）")
        elif want_bad and not any(want_bad in m for m in got):
            fails.append(f"local_gitleaks_flag_drift「{label}」應回報含「{want_bad}」的問題（得到 {got}）")

    # #368：pr-gates 不監聽 edited；目標分支改變由 pr-base-changed.yml 以 fail 的 check 提醒
    pr_ok = {"on": {"pull_request": {"types": ["opened", "synchronize", "reopened"]}, "workflow_dispatch": None}}
    bc_ok = {"on": {"pull_request": {"types": ["opened", "synchronize", "reopened", "edited"]}},
             "permissions": {"contents": "read"},
             "jobs": {"base": {"name": "${{ github.event.action == 'edited' && !github.event.changes.base && '目標分支一致性（內文變更，不需重跑）' || '目標分支一致性' }}",
                               "runs-on": "ubuntu-latest", "permissions": {"contents": "read"},
                               "steps": [{"name": "判斷", "env": {"BASE_CHANGED": "${{ github.event.action == 'edited' && github.event.changes.base != null }}"},
                                          "run": 'if [ "$BASE_CHANGED" = "true" ]; then echo "::error::目標分支已變更"; exit 1; fi\n'}]}}}
    def mut(d, f):
        d = copy.deepcopy(d); f(d); return d
    # PyYAML 把 on: 讀成 True：兩種鍵都要認得
    yaml_on = lambda d: {(True if k == "on" else k): v for k, v in d.items()}
    wiring = globals().get("base_change_wiring")
    for label, pr, bc, want_bad in [
        ("正確設定", pr_ok, bc_ok, False),
        ("PyYAML 讀成 True 的 on 鍵", yaml_on(pr_ok), yaml_on(bc_ok), False),
        ("pr-gates 又監聽 edited", mut(pr_ok, lambda d: d["on"]["pull_request"]["types"].append("edited")), bc_ok, "edited"),
        ("pr-gates 沒有列 types（預設含 edited 以外的事件，但無法確認）", mut(pr_ok, lambda d: d["on"]["pull_request"].pop("types")), bc_ok, "types"),
        ("pr-base-changed.yml 缺席", pr_ok, None, "不存在"),
        ("少監聽 reopened", pr_ok, mut(bc_ok, lambda d: d["on"]["pull_request"]["types"].remove("reopened")), "reopened"),
        ("少監聽 edited", pr_ok, mut(bc_ok, lambda d: d["on"]["pull_request"]["types"].remove("edited")), "edited"),
        ("fail 條件沒有 changes.base", pr_ok, mut(bc_ok, lambda d: d["jobs"]["base"]["steps"][0]["env"].update(
            BASE_CHANGED="${{ github.event.action == 'edited' }}")), "changes.base"),
        ("含 actions/checkout", pr_ok, mut(bc_ok, lambda d: d["jobs"]["base"]["steps"].insert(0, {"uses": "actions/checkout@abc"})), "checkout"),
        ("workflow 權限過大", pr_ok, mut(bc_ok, lambda d: d["permissions"].update({"pull-requests": "write"})), "權限"),
        ("多給 pull-requests: read 也算超過", pr_ok, mut(bc_ok, lambda d: d["permissions"].update({"pull-requests": "read"})), "權限"),
        ("job 權限過大", pr_ok, mut(bc_ok, lambda d: d["jobs"]["base"]["permissions"].update({"contents": "write"})), "權限"),
        ("沒有宣告 workflow 權限（預設權限）", pr_ok, mut(bc_ok, lambda d: d.pop("permissions")), "權限"),
        ("權限更小（{} 與 contents: none）", pr_ok, mut(bc_ok, lambda d: (d.update(permissions={}),
                                                                   d["jobs"]["base"].update(permissions={"contents": "none"}))), False),
    ]:
        try:
            got = wiring(pr, bc) if wiring else None
        except Exception as e:
            got = f"例外 {type(e).__name__}：{e}"
        if not isinstance(got, list):
            fails.append(f"base_change_wiring「{label}」無法執行（得到 {got!r}）")
        elif want_bad is False and got:
            fails.append(f"base_change_wiring「{label}」應通過（得到 {got}）")
        elif want_bad and not any(want_bad in m for m in got):
            fails.append(f"base_change_wiring「{label}」應回報含「{want_bad}」的問題（得到 {got}）")

    # #374：workflow 的 semgrep 不得以 --config p/<名稱> 讓 semgrep 自己下載；經 semgrep_registry.py fetch／annotate，帶 -j
    sg_ok = ('CONFIGS=$(python3 -I _trusted/scripts/semgrep_registry.py fetch --out "$RUNNER_TEMP/r" --record reports/semgrep-rulesets.json \\\n'
             '  _trusted/config/semgrep/vibesec-rules.yaml p/owasp-top-ten p/security-audit); rc=$?\n'
             'semgrep ci --disable-nosem -j 4 "${args[@]}" --sarif --output reports/semgrep.sarif || true\n'
             'python3 -I _trusted/scripts/semgrep_registry.py annotate --sarif reports/semgrep.sarif --record reports/semgrep-rulesets.json\n')
    sg_wf = lambda run: {"jobs": {"g3": {"steps": [{"name": "Semgrep", "run": run}]}}}
    wiring = globals().get("semgrep_registry_wiring")
    for label, wf, jobs, want_bad in [
        ("經 fetch／annotate、帶 -j 4", sg_wf(sg_ok), 4, False),
        ("註解提到 --config p/ 不算", sg_wf("# 以前用 --config p/security-audit\n" + sg_ok), 4, False),
        ("又用 --config p/（#374 以前）", sg_wf(sg_ok + "semgrep scan --config p/security-audit -j 4 .\n"), 4, "--config p/"),
        ("--config=r/ 的寫法", sg_wf(sg_ok.replace("semgrep ci --disable-nosem", "semgrep ci --config=r/python.x --disable-nosem")), 4, "--config"),
        ("沒有經 fetch", sg_wf(sg_ok.replace("semgrep_registry.py fetch", "other.py fetch")), 4, "fetch"),
        ("沒有 annotate", sg_wf(sg_ok.replace("semgrep_registry.py annotate", "other.py annotate")), 4, "annotate"),
        ("semgrep 沒有帶 -j", sg_wf(sg_ok.replace(" -j 4", "")), 4, "-j"),
        ("-j 與 SEMGREP_MAX_JOBS 不一致", sg_wf(sg_ok.replace(" -j 4", " -j 8")), 4, "-j"),
        ("沒有 semgrep 的 workflow 不檢查", {"jobs": {"x": {"steps": [{"run": "echo hi\n"}]}}}, 4, False),
        ("註解提到 semgrep_registry.py fetch 不算", sg_wf("# 用 semgrep_registry.py fetch 取得\n" + sg_ok.replace("semgrep_registry.py fetch", "other.py fetch")), 4, "fetch"),
        ("semgrep login 不是掃描（不要求 -j）", {"jobs": {"x": {"steps": [{"run": "semgrep login\n"}]}}}, 4, False),
        ("只是提到 semgrep 的 echo 不算呼叫", {"jobs": {"x": {"steps": [{"run": 'echo "semgrep exit=$code"\n'}]}}}, 4, False),
        ("短旗標 -c p/", sg_wf(sg_ok + "semgrep scan -c p/security-audit -j 4 .\n"), 4, "-c p/"),
        ("--config auto", sg_wf(sg_ok + "semgrep scan --config auto -j 4 .\n"), 4, "auto"),
        ("--config 換行後才接 p/", sg_wf(sg_ok + "semgrep scan -j 4 --config \\\n  p/security-audit .\n"), 4, "--config"),
        ("沒有子命令的舊寫法", sg_wf("semgrep --config p/security-audit -j 4 .\n"), 4, "--config"),
        ("fetch 在別的 step 不算", {"jobs": {"g3": {"steps": [{"name": "取得", "run": "python3 -I _trusted/scripts/semgrep_registry.py fetch --out x --record y a\n"},
                                                         {"name": "Semgrep", "run": sg_ok.replace("semgrep_registry.py fetch", "other.py fetch")}]}}}, 4, "fetch"),
    ]:
        try:
            got = wiring(wf, jobs) if wiring else None
        except Exception as e:
            got = f"例外 {type(e).__name__}：{e}"
        if not isinstance(got, list):
            fails.append(f"semgrep_registry_wiring「{label}」無法執行（得到 {got!r}）")
        elif want_bad is False and got:
            fails.append(f"semgrep_registry_wiring「{label}」應通過（得到 {got}）")
        elif want_bad and not any(want_bad in m for m in got):
            fails.append(f"semgrep_registry_wiring「{label}」應回報含「{want_bad}」的問題（得到 {got}）")
    return fails


if __name__ == "__main__":
    if sys.argv[1:2] == ["selftest"]:
        _fails = selftest()
        for f in _fails:
            print(f"FAIL {f}")
        print("selftest 通過" if not _fails else f"selftest 失敗 {len(_fails)} 項")
        sys.exit(1 if _fails else 0)
    print(__doc__.strip()); sys.exit(4)
