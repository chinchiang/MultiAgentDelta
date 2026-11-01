#!/usr/bin/env python3
"""VibeSec：PR 的 CI 和基準 PR 逐項比對（#240）。只讀 GitHub API（gh），不碰任何判定邏輯。

workflow 文件「判準」的 CI 一節：check 數量與閘門表格要和最近一個合併的 PR 相同；G1 的已知漏洞筆數和當天 main 的 nightly 比。
以前每次都要臨時拼湊指令，本腳本一次輸出：
  1. check：兩邊各狀態的數量、名稱與結果的差異、不是 workflow（github-actions）產生的 check 及其來源（app）
  2. 閘門表格：pr-gates 的 VibeSec Summary job 裡 `| G… |` 那幾行，逐列比對
  3. G1：已知漏洞（非 KEV）筆數、KEV 命中數、slopcheck 是否略過；PR 的已知漏洞筆數再和當天（UTC）main 的 nightly 比
  4. validate：repo-validate 三次執行（PR 版、受信任樹版、enforce 副本）各自的錯誤數、警告數與警告內容
  5. 結論：差異分成「預期內」與「需要說明」
預期內只有這幾種，其餘都算需要說明：
  - Dependabot 的 `.github/dependabot.yml` 設定驗證 check 只出現在一邊（GitHub 在 PR 改到該檔時才建立）
  - G1 已知漏洞筆數和當天 nightly 相同（漏洞資料庫每天更新，不和基準 PR 比）
  - G1 說明欄的「忽略的 allowlist 條目」句只出現在一邊，而且那一邊的 slopcheck 有掃描（改到相依清單或規則檔，含 *.md；#210）

用法：
  python3 -I scripts/compare_ci.py <PR> --baseline <PR>
  python3 scripts/compare_ci.py selftest
退出碼：0 只有預期內差異；1 有需要說明的差異；
       2 無法比對（CI 未完成、找不到 run 或 job、log 缺少需要的行、gh／API 失敗；incomplete ≠ pass）；4 用法錯誤。
CI 未完成：PR 的 check 或 workflow run 還沒結束，或 github-actions 的 check 數少於這些 run 的 job 數。這時不比對。
不輪詢、不寫入 GitHub（不留言、不合併）。
"""
from __future__ import annotations
import collections, json, re, subprocess, sys
from typing import NamedTuple


class InputError(Exception):
    """無法比對（CI 未完成、找不到 run、log 缺行、API 失敗）：exit 2，不得當成沒有差異。"""


# ---------------------------------------------------------------- 純函式：解析 log
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_STAMP = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z ?")


def log_lines(text: str) -> list[str]:
    """job log → 去掉 ANSI 色碼與行首時間戳的行。"""
    return [_STAMP.sub("", _ANSI.sub("", ln)) for ln in text.replace("\r\n", "\n").split("\n")]


def parse_gate_table(text: str) -> dict[str, list[str]]:
    """VibeSec Summary job log → {閘門: [狀態, blocking, advisory, 說明]}。同一列重複出現只算一次；
    同一閘門有兩種不同的列、或一列都沒有 → InputError。"""
    rows: dict[str, list[str]] = {}
    for ln in log_lines(text):
        m = re.match(r"^\|\s*(G\d)\s*\|(.*)\|\s*$", ln)
        if not m:
            continue
        cells = [c.strip() for c in m[2].split("|")]
        if m[1] in rows and rows[m[1]] != cells:
            raise InputError(f"閘門表格的 {m[1]} 有兩種不同的列：{rows[m[1]]}、{cells}")
        rows[m[1]] = cells
    if not rows:
        raise InputError("VibeSec Summary 的 log 裡沒有閘門表格（`| G… |` 行）")
    return dict(sorted(rows.items()))


class ValidateRun(NamedTuple):
    passed: int
    warnings: int
    errors: int
    warn_lines: tuple
    err_lines: tuple


VALIDATE_LABELS = ("PR 版", "受信任樹版", "enforce 副本")
_VALIDATE_SUMMARY = re.compile(r"通過 (\d+) 項；警告 (\d+)；錯誤 (\d+)")


def parse_validate(text: str) -> list[ValidateRun]:
    """repo-validate job log → 三次執行（依序：PR 版、受信任樹版、enforce 副本）。摘要行不是剛好三行 → InputError。
    摘要行之後緊接著的 WARN／ERR 行屬於那一次；中間隔了別的行就不再收。"""
    runs: list[ValidateRun] = []
    collecting = False
    for ln in log_lines(text):
        if m := _VALIDATE_SUMMARY.fullmatch(ln.strip()):
            runs.append(ValidateRun(int(m[1]), int(m[2]), int(m[3]), (), ()))
            collecting = True
        elif collecting and (m := re.match(r"^\s+(WARN|ERR) ", ln)):
            field = "warn_lines" if m[1] == "WARN" else "err_lines"
            runs[-1] = runs[-1]._replace(**{field: getattr(runs[-1], field) + (ln.strip(),)})
        else:
            collecting = False
    if len(runs) != len(VALIDATE_LABELS):
        raise InputError(f"repo-validate 的 log 應有 {len(VALIDATE_LABELS)} 行 validate 摘要（找到 {len(runs)} 行）")
    return runs


class G1Info(NamedTuple):
    known: int          # 已知漏洞（非 KEV）筆數
    kev_hits: int       # KEV 命中數
    slop_skipped: bool  # slopcheck 因為沒有相依清單或規則檔變更而略過


# g1_slopcheck.py 印在 stderr 的結果行：略過一種、有掃描四種（通過、阻擋、無法完成、未實測）。
# 「有掃描」要找到正面證據；兩種都找不到（例如措辭改了）→ 無法比對，不推定為有掃描。
SLOP_SKIPPED = "G1 slopcheck：無相依清單或規則檔變更，略過。"
SLOP_SCANNED = ("✅ G1 快篩通過。", "⛔ G1 阻擋：", "⚠️ G1 無法完成檢查（網路/registry", "⚠️ G1 有控制未實測")


def parse_g1(text: str) -> G1Info:
    """PR 的 G1 job log → G1Info。已知漏洞、KEV、slopcheck 結果行都要剛好一行，否則 InputError。"""
    lines = log_lines(text)
    kev = _one(lines, r"KEV：檢查 \d+ 筆 grype 結果，命中 (\d+) 筆", "G1 job 的 KEV 命中")
    skipped = [ln for ln in lines if SLOP_SKIPPED in ln]
    scanned = [ln for ln in lines if any(ln.lstrip().startswith(x) for x in SLOP_SCANNED)]
    if len(skipped) + len(scanned) != 1:
        raise InputError(f"G1 job 的 slopcheck 結果行應剛好一行（略過 {len(skipped)} 行、有掃描 {len(scanned)} 行）")
    return G1Info(parse_known_vulns(text, "G1 job"), kev, bool(skipped))


def _one(lines: list[str], pattern: str, what: str) -> int:
    hit = [int(m[1]) for ln in lines if (m := re.search(pattern, ln))]
    if len(hit) != 1:
        raise InputError(f"{what}那行應剛好一行（找到 {len(hit)} 行）")
    return hit[0]


def parse_known_vulns(text: str, where: str = "nightly 的 G1 job") -> int:
    """G1 job log（PR 或 nightly）→ 已知漏洞（非 KEV）筆數；不是剛好一行 → InputError。"""
    return _one(log_lines(text), r"已知漏洞（非 KEV[^）]*）：(\d+) 筆", f"{where}的已知漏洞（非 KEV）")


# ---------------------------------------------------------------- 純函式：完成判斷與比對
def bucket(state: str) -> str:
    """check 的狀態或結論 → gh pr checks 的分類：pass／skipping／fail／cancel／pending。不認得的結論算 fail。"""
    s = state.lower()
    if s == "success":
        return "pass"
    if s in ("neutral", "skipped"):
        return "skipping"
    if s == "cancelled":
        return "cancel"
    if s in ("queued", "in_progress", "pending", "waiting", "requested", "expected"):
        return "pending"
    return "fail"


def incomplete_reason(side: dict) -> str | None:
    """side 的 CI 還沒結束 → 原因；結束了 → None。
    side["checks"]：[{name, source, state}]；side["runs"]：[{name, status, jobs}]（jobs 是該 run 的 job 數）。"""
    pending = sorted(c["name"] for c in side["checks"] if bucket(c["state"]) == "pending")
    if pending:
        return f"{len(pending)} 個 check 還沒結束（{'、'.join(pending)}）"
    running = sorted(r["name"] for r in side["runs"] if r["status"] != "completed")
    if running:
        return f"workflow run 還沒結束（{'、'.join(running)}）"
    jobs = sum(r["jobs"] for r in side["runs"])
    got = sum(c["source"] == ACTIONS for c in side["checks"])
    if not side["checks"] or got < jobs:
        return f"github-actions 的 check 只回報 {got} 個，少於 workflow run 的 {jobs} 個 job"
    return None


ACTIONS = "github-actions"
DEPENDABOT_CHECK = ("dependabot", ".github/dependabot.yml")
SOURCE_NOTE = {"github-advanced-security": "code scanning：各 job 上傳的 SARIF", "dependabot": "Dependabot 設定驗證",
               "commit status": "commit status API"}
BUCKETS = ("pass", "skipping", "fail", "cancel", "pending")


class Report(NamedTuple):
    lines: list       # 各節的輸出
    expected: list    # 預期內的差異
    unexplained: list # 需要說明的差異


class _Acc(NamedTuple):
    """各節共用的輸出累積器。"""
    out: list
    expected: list
    unexplained: list


def compare(pr: dict, base: dict, nightly: dict) -> Report:
    """pr、base：{"number", "checks", "logs": {"summary", "validate", "g1"}}；nightly：{"date", "same_day", "run_id", "g1_log"}。
    log 解析失敗 → InputError。"""
    acc = _Acc([], [], [])
    P, B = f"#{pr['number']}", f"#{base['number']}"
    _compare_checks(acc, P, pr["checks"], B, base["checks"])
    pg, bg = parse_g1(pr["logs"]["g1"]), parse_g1(base["logs"]["g1"])
    nightly_known = parse_known_vulns(nightly["g1_log"])
    _compare_gate_tables(acc, P, parse_gate_table(pr["logs"]["summary"]), pg,
                         B, parse_gate_table(base["logs"]["summary"]), bg, nightly, nightly_known)
    _compare_g1(acc, P, pg, B, bg, nightly, nightly_known)
    _compare_validate(acc, P, parse_validate(pr["logs"]["validate"]), B, parse_validate(base["logs"]["validate"]))
    acc.out.append("## 結論")
    acc.out.append("- 預期內：" + ("無" if not acc.expected else ""))
    acc.out.extend(f"  - {x}" for x in acc.expected)
    acc.out.append("- 需要說明：" + ("無" if not acc.unexplained else ""))
    acc.out.extend(f"  - {x}" for x in acc.unexplained)
    return Report(*acc)


def _compare_checks(acc: _Acc, P: str, pr_checks: list, B: str, base_checks: list) -> None:
    """各狀態數量、不是 workflow 產生的 check；以（來源, 名稱）為單位比對結果的多重集合，同名的 check 也逐個算。"""
    acc.out.append(f"## check（{P} 對 基準 {B}）")
    groups = {}
    for who, checks in ((P, pr_checks), (B, base_checks)):
        n = collections.Counter(bucket(c["state"]) for c in checks)
        acc.out.append(f"- {who}：" + "、".join(f"{k} {n[k]}" for k in BUCKETS if k in n))
        others = collections.defaultdict(list)
        for c in checks:
            if c["source"] != ACTIONS:
                others[c["source"]].append(c["name"])
        acc.out.append(f"  不是 workflow 產生的：" + ("無" if not others else "；".join(
            f"{src}（{SOURCE_NOTE.get(src, '來源不明')}）{len(v)} 個：{'、'.join(sorted(v))}" for src, v in sorted(others.items()))))
        g = collections.defaultdict(collections.Counter)
        for c in checks:
            g[(c["source"], c["name"])][bucket(c["state"])] += 1
        groups[who] = g
    for ident in sorted(set(groups[P]) | set(groups[B])):
        a, b = groups[P].get(ident, collections.Counter()), groups[B].get(ident, collections.Counter())
        if a == b:
            continue
        name = f"{ident[1]}（{ident[0]}）"
        if not a or not b:
            msg = f"check {name} 只在 {P if a else B}"
            if ident == DEPENDABOT_CHECK:
                acc.expected.append(msg + "（GitHub 在 PR 改到 .github/dependabot.yml 時才建立）")
            else:
                acc.unexplained.append(msg)
        else:
            show = lambda c: "、".join(f"{k} {c[k]}" for k in BUCKETS if c[k])
            acc.unexplained.append(f"check {name} 結果或個數不同：{B} {show(b)} → {P} {show(a)}")
    for c in pr_checks:
        if bucket(c["state"]) in ("fail", "cancel"):
            acc.unexplained.append(f"{P} 的 check {c['name']}（{c['source']}）是 {c['state']}")


def _compare_gate_tables(acc: _Acc, P: str, pt: dict, pg: G1Info, B: str, bt: dict, bg: G1Info,
                         nightly: dict, nightly_known: int) -> None:
    acc.out.append("## 閘門表格（| 閘門 | 狀態 | blocking | advisory | 說明 |）")
    for who, t in ((P, pt), (B, bt)):
        acc.out.append(f"- {who}：")
        acc.out.extend(f"  | {g} | " + " | ".join(cells) + " |" for g, cells in t.items())
    for g in sorted(set(pt) | set(bt)):
        a, b = pt.get(g), bt.get(g)
        if a is None or b is None:
            acc.unexplained.append(f"閘門 {g} 只在 {P if a else B} 的表格裡")
        elif a != b and (g != "G1" or len(a) != 4 or len(b) != 4):
            acc.unexplained.append(f"閘門 {g} 的列不同：{B} {b} → {P} {a}")
        elif a != b:
            _compare_g1_row(acc, (P, a, pg), (B, b, bg), nightly, nightly_known)


def _compare_g1_row(acc: _Acc, pr_row: tuple, base_row: tuple, nightly: dict, nightly_known: int) -> None:
    """G1 列：advisory 的變化要和已知漏洞的變化一致、且 PR 的已知漏洞和 nightly 相同；allowlist 句只能出現在有掃描的那邊。"""
    (P, a, pg), (B, b, bg) = pr_row, base_row
    if a[:2] != b[:2]:
        acc.unexplained.append(f"G1 的狀態或 blocking 不同：{B} {b[:2]} → {P} {a[:2]}")
    if a[2] != b[2]:
        same_delta = a[2].isdigit() and b[2].isdigit() and int(a[2]) - int(b[2]) == pg.known - bg.known
        if pg.known == nightly_known and same_delta:
            acc.expected.append(f"G1 advisory {b[2]} → {a[2]}：已知漏洞筆數和 {nightly['date']} 的 nightly 相同（{nightly_known}）")
        else:
            acc.unexplained.append(f"G1 advisory {b[2]} → {a[2]}：和已知漏洞的變化（{bg.known} → {pg.known}）"
                                   f"或 nightly（{nightly_known}）對不上")
    (allow_a, rest_a), (allow_b, rest_b) = _note_parts(a[3]), _note_parts(b[3])
    if rest_a != rest_b:
        acc.unexplained.append(f"G1 說明不同（allowlist 句以外）：{B}「{b[3]}」→ {P}「{a[3]}」")
    elif allow_a != allow_b and allow_a and allow_b:
        acc.unexplained.append(f"G1 的 allowlist 句兩邊不同：{B}「{'；'.join(allow_b)}」→ {P}「{'；'.join(allow_a)}」")
    elif allow_a != allow_b:
        who, info = (P, pg) if allow_a else (B, bg)
        if not info.slop_skipped:
            acc.expected.append(f"G1 的 allowlist 句只在 {who}：那一邊的 slopcheck 有掃描（改到相依清單或規則檔，含 *.md；#210）")
        else:
            acc.unexplained.append(f"G1 的 allowlist 句只在 {who}，但那一邊的 slopcheck 略過了")


def _compare_g1(acc: _Acc, P: str, pg: G1Info, B: str, bg: G1Info, nightly: dict, nightly_known: int) -> None:
    acc.out.append("## G1")
    for who, x in ((P, pg), (B, bg)):
        acc.out.append(f"- {who}：已知漏洞（非 KEV）{x.known} 筆；KEV 命中 {x.kev_hits} 筆；slopcheck "
                       + ("略過（無相依清單或規則檔變更）" if x.slop_skipped else "有掃描"))
    day = nightly["date"] + ("" if nightly["same_day"] else "（PR 當天沒有已結束的 nightly，取之前最近的一次）")
    acc.out.append(f"- main nightly（{day}，run {nightly['run_id']}）：已知漏洞（非 KEV）{nightly_known} 筆")
    if pg.known != nightly_known:
        acc.unexplained.append(f"{P} 的 G1 已知漏洞 {pg.known} 筆，和 {nightly['date']} 的 nightly（{nightly_known} 筆）不同")
    if pg.kev_hits != bg.kev_hits:
        acc.unexplained.append(f"KEV 命中數不同：{B} {bg.kev_hits} → {P} {pg.kev_hits}")


def _compare_validate(acc: _Acc, P: str, pv: list, B: str, bv: list) -> None:
    acc.out.append("## validate（repo-validate 的三次執行）")
    for label, a, b in zip(VALIDATE_LABELS, pv, bv):
        acc.out.append(f"- {label}：{P} 通過 {a.passed}、警告 {a.warnings}、錯誤 {a.errors}；"
                       f"{B} 通過 {b.passed}、警告 {b.warnings}、錯誤 {b.errors}")
        acc.out.extend(f"  {P} {ln}" for ln in a.warn_lines + a.err_lines)
        if a.errors:
            acc.unexplained.append(f"validate {label}：{P} 有 {a.errors} 個錯誤")
        if a.warn_lines != b.warn_lines or a.warnings != b.warnings:
            acc.unexplained.append(f"validate {label} 的警告不同：{B} {list(b.warn_lines)} → {P} {list(a.warn_lines)}")


ALLOW_PREFIX = "忽略的 allowlist 條目"


def _note_parts(note: str) -> tuple[tuple, tuple]:
    """G1 說明欄 →（allowlist 句, 其他句）；句子以「；」分隔。"""
    parts = [p.strip() for p in note.split("；") if p.strip()]
    return tuple(p for p in parts if p.startswith(ALLOW_PREFIX)), tuple(p for p in parts if not p.startswith(ALLOW_PREFIX))


# ---------------------------------------------------------------- 取資料（gh）
def gh_runner(args: list[str]) -> str:
    try:
        r = subprocess.run(["gh", *args], capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise InputError(f"無法執行 gh：{type(e).__name__}: {e}") from e
    if r.returncode != 0:
        raise InputError(f"gh {' '.join(args[:3])} 失敗（exit {r.returncode}）：{(r.stderr or r.stdout).strip()[:300]}")
    return r.stdout


REPO = "repos/{owner}/{repo}"   # gh api 會代入目前 repo


def _jsonl(gh, path: str, jq: str) -> list[dict]:
    out = gh(["api", "--paginate", path, "--jq", jq])
    try:
        return [json.loads(ln) for ln in out.splitlines() if ln.strip()]
    except ValueError as e:
        raise InputError(f"{path}：回應無法解析") from e


def _job_log(gh, job_id) -> str:
    return gh(["api", "--allow-escape-sequences", f"{REPO}/actions/jobs/{job_id}/logs"])


def _pick_job(jobs: list[dict], prefix: str, where: str) -> dict:
    hit = [j for j in jobs if j["name"].startswith(prefix)]
    if len(hit) != 1:
        raise InputError(f"{where}：名稱以「{prefix}」開頭的 job 應剛好一個（找到 {len(hit)} 個）")
    return hit[0]


PR_GATES = ".github/workflows/pr-gates.yml"
JOB_SUMMARY, JOB_VALIDATE, JOB_G1 = "VibeSec Summary", "倉庫驗證", "G1 供應鏈"
NIGHTLY, JOB_NIGHTLY_G1 = "nightly-full.yml", "G1 全量供應鏈"


def _jobs(gh, run_id) -> list[dict]:
    return _jsonl(gh, f"{REPO}/actions/runs/{run_id}/jobs?per_page=100", ".jobs[] | {id, name, status}")


def fetch_side(gh, number: int) -> dict:
    """一個 PR 的 head、check、workflow run（含 job 清單與 job 數）。log 另由 fetch_logs 取。"""
    head = gh(["api", f"{REPO}/pulls/{number}", "--jq", ".head.sha"]).strip()
    if not re.fullmatch(r"[0-9a-f]{40}", head):
        raise InputError(f"#{number}：取不到 head SHA")
    checks = [{"name": c["name"], "source": c["app"] or "?",
               "state": (c["conclusion"] if c["status"] == "completed" else c["status"]) or "?"}
              for c in _jsonl(gh, f"{REPO}/commits/{head}/check-runs?per_page=100",
                              ".check_runs[] | {name, status, conclusion, app: .app.slug}")]
    checks += [{"name": s["context"], "source": "commit status", "state": s["state"]}
               for s in _jsonl(gh, f"{REPO}/commits/{head}/status?per_page=100", ".statuses[] | {context, state}")]
    runs = _jsonl(gh, f"{REPO}/actions/runs?head_sha={head}&per_page=100",
                  ".workflow_runs[] | {id, name, path, event, status, created_at}")
    if not runs:
        raise InputError(f"#{number}：head {head[:7]} 找不到任何 workflow run")
    for r in runs:
        r["job_list"] = _jobs(gh, r["id"])
        r["jobs"] = len(r["job_list"])
    return {"number": number, "head": head, "checks": checks, "runs": runs}


def fetch_logs(gh, side: dict) -> dict:
    """side 加上最近一次 pr-gates（pull_request）run 的建立時間，以及 Summary、repo-validate、G1 三個 job 的 log。"""
    number, head = side["number"], side["head"]
    gates = sorted((r for r in side["runs"] if r["path"].startswith(PR_GATES) and r["event"] == "pull_request"),
                   key=lambda r: r["created_at"])
    if not gates:
        raise InputError(f"#{number}：head {head[:7]} 找不到 pr-gates 的 pull_request run")
    g = gates[-1]
    where = f"#{number} pr-gates run {g['id']}"
    side["gates_created"] = g["created_at"]
    side["logs"] = {key: _job_log(gh, _pick_job(g["job_list"], prefix, where)["id"])
                    for key, prefix in (("summary", JOB_SUMMARY), ("validate", JOB_VALIDATE), ("g1", JOB_G1))}
    return side


def fetch_nightly(gh, when: str) -> dict:
    """PR 的 pr-gates run 建立時間（ISO）→ 同一天（UTC）main 最近一次 nightly；那天沒有 → 那之前最近的一次。"""
    day = when[:10]
    runs = _jsonl(gh, f"{REPO}/actions/workflows/{NIGHTLY}/runs?branch=main&per_page=30",
                  ".workflow_runs[] | {id, created_at, status}")
    done = [r for r in runs if r["status"] == "completed"]
    same = [r for r in done if r["created_at"][:10] == day]
    before = [r for r in done if r["created_at"][:10] < day]
    pick = max(same, key=lambda r: r["created_at"]) if same else max(before, key=lambda r: r["created_at"], default=None)
    if pick is None:
        raise InputError(f"找不到 {day} 或之前已結束的 main nightly")
    job = _pick_job(_jobs(gh, pick["id"]), JOB_NIGHTLY_G1, f"nightly run {pick['id']}")
    return {"date": pick["created_at"][:10], "same_day": bool(same), "run_id": pick["id"], "g1_log": _job_log(gh, job["id"])}


def main(argv: list[str], *, gh=gh_runner) -> int:
    """gh 只給 selftest 注入。"""
    if len(argv) != 3 or argv[1] != "--baseline" or not all(a.isdigit() for a in (argv[0], argv[2])):
        print(__doc__.strip(), file=sys.stderr)
        return 4
    pr_n, base_n = int(argv[0]), int(argv[2])
    try:
        sides = []
        for label, n in (("", pr_n), ("基準 PR ", base_n)):   # 先判斷 PR 完成了沒：未完成就不取基準與 log
            side = fetch_side(gh, n)
            if why := incomplete_reason(side):
                print(f"{label}#{n} 的 CI 未完成：{why}；不比對。")
                return 2
            sides.append(fetch_logs(gh, side))
        pr, base = sides
        rep = compare(pr, base, fetch_nightly(gh, pr["gates_created"]))
    except InputError as e:
        print(f"無法比對：{e}")
        return 2
    print("\n".join(rep.lines))
    return 1 if rep.unexplained else 0


# ---------------------------------------------------------------- selftest（不連網）
def _fx_log(*lines: str) -> str:
    """fixture：每行加上 Actions 的時間戳，部分行加 ANSI 色碼（和 gh api --allow-escape-sequences 拿到的一樣）。"""
    return "\n".join(f"2026-11-01T08:18:{i % 60:02d}.1234567Z {ln}" for i, ln in enumerate(lines))


ALLOW = "忽略的 allowlist 條目：requests：已於 2026-10-16 過期"
G4_NOTE = "G4 LLM 審查未在 CI 執行"


def _fx_summary(g1_adv=92, g1_note=ALLOW, g2="`pass` | 0 | 0 |  ", dup=True) -> str:
    rows = [f"| G1 | `pass` | 0 | {g1_adv} | {g1_note} |", f"| G2 | {g2} |", "| G3 | `pass` | 0 | 0 |  |",
            f"| G4 | `incomplete` | 0 | 0 | {G4_NOTE} |"]
    return _fx_log("# VibeSec 閘門狀態", "", "| 閘門 | 狀態 | blocking | advisory | 說明 |", "|---|---|---|---|---|",
                   *rows, "", "**判定：不阻擋**（shadow 只報告）", *(rows if dup else []))


WARN_TRIFECTA = "  WARN docs/threat-model.yaml：vibesec.g0.lethal-trifecta-open（advisory，例外）"
WARN_G4 = "  WARN vibesec.yaml（mode: enforce）：enforce 下 G4 未完成不擋 merge"


def _fx_validate(runs=((1, 0), (1, 0), (2, 0)), extra_warn=None) -> str:
    out = ["##[group]Run python3 scripts/validate.py", "\x1b[36;1mpython3 scripts/validate.py\x1b[0m", "##[endgroup]"]
    for i, (w, e) in enumerate(runs):
        out.append(f"通過 378 項；警告 {w}；錯誤 {e}")
        warns = ([WARN_G4] if i == 2 else []) + [WARN_TRIFECTA]
        if extra_warn and i == 0:
            warns = [extra_warn] + warns[1:]
        out += warns[:w] + [f"  ERR scripts/x.py：錯誤 {k}" for k in range(e)]
        out.append(f"##[group]Run 下一步 {i}")
    return _fx_log(*out)


def _fx_g1(known=92, kev=0, skipped=False) -> str:
    return _fx_log("##[group]Run # 與 pre-commit 共用同一支腳本", "##[endgroup]",
                   "G1 slopcheck：無相依清單或規則檔變更，略過。" if skipped else "✅ G1 快篩通過。",
                   "KEV feed：cisa（dateReleased 2026-10-30T17:02:45Z，1766 筆）",
                   f"\x1b[0m已知漏洞（非 KEV，advisory）：{known} 筆", f"KEV：檢查 102 筆 grype 結果，命中 {kev} 筆")


def _fx_checks(extra=(), drop=(), change=None) -> list[dict]:
    names = [("VibeSec Summary", "github-actions", "success"), ("G1 供應鏈與 Slopsquatting", "github-actions", "success"),
             ("倉庫驗證（validate.py）", "github-actions", "success"), ("Analyze (python)", "github-actions", "success"),
             ("grype", "github-advanced-security", "neutral"), ("CodeQL", "github-advanced-security", "success")]
    out = [{"name": n, "source": s, "state": (change or {}).get(n, st)} for n, s, st in names if n not in drop]
    return out + [{"name": n, "source": s, "state": st} for n, s, st in extra]


DEPENDABOT = (".github/dependabot.yml", "dependabot", "success")


def _fx_side(number=250, checks=None, **logs) -> dict:
    return {"number": number, "checks": _fx_checks() if checks is None else checks,
            "logs": {"summary": logs.get("summary", _fx_summary()), "validate": logs.get("validate", _fx_validate()),
                     "g1": logs.get("g1", _fx_g1())}}


def _fx_nightly(known=92) -> dict:
    return {"date": "2026-11-01", "same_day": True, "run_id": 1,
            "g1_log": _fx_log("##[group]Run grype", f"已知漏洞（非 KEV，advisory）：{known} 筆")}


def selftest() -> list[str]:
    fails: list[str] = []

    def check(label, fn):
        try:
            msg = fn()
        except Exception as e:   # 紅燈要是 FAIL，不是崩潰
            msg = f"拋出例外 {type(e).__name__}：{e}"
        if msg:
            fails.append(f"{label}：{msg}")

    # ---- log 解析
    def t_strip():
        got = log_lines("2026-11-01T08:18:16.9640920Z \x1b[36;1mpython3 x\x1b[0m\r\n2026-11-01T08:18:17Z 通過")
        return None if got == ["python3 x", "通過"] else f"得到 {got}"
    check("log_lines 去掉時間戳與 ANSI 色碼", t_strip)

    def t_table():
        got = parse_gate_table(_fx_summary())
        want = {"G1": ["`pass`", "0", "92", ALLOW], "G2": ["`pass`", "0", "0", ""], "G3": ["`pass`", "0", "0", ""],
                "G4": ["`incomplete`", "0", "0", G4_NOTE]}
        return None if got == want else f"得到 {got}"
    check("閘門表格：逐列解析、重複列只算一次、表頭不算", t_table)

    def t_table_bad():
        bad = []
        for label, text in (("沒有表格", _fx_log("# VibeSec 閘門狀態")),
                            ("同一閘門兩種列", _fx_summary() + "\n" + _fx_log("| G2 | `fail` | 1 | 0 |  |"))):
            try:
                parse_gate_table(text)
                bad.append(label)
            except InputError:
                pass
        return f"應 InputError：{bad}" if bad else None
    check("閘門表格：沒有表格、同一閘門兩種列 → 無法比對", t_table_bad)

    def t_validate():
        got = parse_validate(_fx_validate(runs=((1, 0), (1, 0), (2, 1))))
        if [(r.warnings, r.errors) for r in got] != [(1, 0), (1, 0), (2, 1)]:
            return f"三次的警告、錯誤數不對：{got}"
        if got[2].warn_lines != (WARN_G4.strip(), WARN_TRIFECTA.strip()) or got[0].warn_lines != (WARN_TRIFECTA.strip(),):
            return f"警告內容要分到各自那一次：{[r.warn_lines for r in got]}"
        if got[2].err_lines != ("ERR scripts/x.py：錯誤 0",):
            return f"錯誤內容：{got[2].err_lines}"
        return None
    check("validate：三次執行各自的錯誤數、警告數與內容", t_validate)

    def t_validate_bad():
        two = _fx_log("通過 378 項；警告 1；錯誤 0", "通過 378 項；警告 1；錯誤 0")
        try:
            parse_validate(two)
            return "只有兩行摘要應 InputError"
        except InputError:
            return None
    check("validate：摘要行不是三行 → 無法比對", t_validate_bad)

    def t_g1():
        a, b = parse_g1(_fx_g1()), parse_g1(_fx_g1(known=7, kev=1, skipped=True))
        if a != G1Info(92, 0, False) or b != G1Info(7, 1, True):
            return f"得到 {a}、{b}"
        try:
            parse_g1(_fx_log("✅ G1 快篩通過。"))
            return "缺已知漏洞行應 InputError"
        except InputError:
            pass
        if parse_known_vulns(_fx_nightly(91)["g1_log"]) != 91:
            return "nightly 筆數"
        try:
            parse_known_vulns(_fx_log("沒有"))
            return "nightly 缺行應 InputError"
        except InputError:
            return None
    check("G1：已知漏洞、KEV 命中、slopcheck 略過；nightly 筆數", t_g1)

    def t_slop_evidence():   # 有掃描要有正面證據：措辭改了、兩種行都找不到 → 無法比對，不推定為有掃描（fail-closed）
        base = _fx_g1().replace("✅ G1 快篩通過。", "{}")
        bad = []
        for label, line in (("兩種都沒有", "G1 快篩：完成"), ("兩種都有", "✅ G1 快篩通過。\n" + SLOP_SKIPPED)):
            try:
                parse_g1(base.replace("{}", line))
                bad.append(label)
            except InputError:
                pass
        for line in ("⛔ G1 阻擋：1 筆 blocking 供應鏈發現。", "⚠️ G1 有控制未實測 → incomplete，絕不視為通過：x"):
            if parse_g1(base.replace("{}", line)).slop_skipped is not False:
                bad.append(f"{line[:8]} 應算有掃描")
        return f"{bad}" if bad else None
    check("G1：slopcheck 是否掃描要有正面證據", t_slop_evidence)

    # ---- 完成判斷
    def t_incomplete():
        done = {"checks": _fx_checks(), "runs": [{"name": "VibeSec PR Gates", "status": "completed", "jobs": 3},
                                                 {"name": "CodeQL", "status": "completed", "jobs": 1}]}
        if incomplete_reason(done) is not None:
            return f"全部結束應 None（得到 {incomplete_reason(done)}）"
        cases = {
            "check 還在跑": {**done, "checks": _fx_checks(change={"CodeQL": "in_progress"})},
            "commit status pending": {**done, "checks": _fx_checks(extra=[("ci/x", "commit status", "pending")])},
            "run 還沒結束": {**done, "runs": done["runs"][:1] + [{"name": "CodeQL", "status": "queued", "jobs": 0}]},
            "github-actions check 少於 job 數": {**done, "checks": _fx_checks(drop=("VibeSec Summary",))},
            "沒有任何 check": {**done, "checks": []},
        }
        bad = [k for k, v in cases.items() if not incomplete_reason(v)]
        return f"應判為未完成：{bad}" if bad else None
    check("CI 未完成：check／status／run 未結束、check 數少於 job 數", t_incomplete)

    def t_bucket():
        want = {"success": "pass", "neutral": "skipping", "skipped": "skipping", "failure": "fail", "timed_out": "fail",
                "action_required": "fail", "error": "fail", "cancelled": "cancel", "in_progress": "pending",
                "queued": "pending", "pending": "pending"}
        bad = {k: bucket(k) for k, v in want.items() if bucket(k) != v}
        return f"{bad}" if bad else None
    check("check 狀態分類同 gh pr checks", t_bucket)

    # ---- 比對與分類
    def cls(pr, base, nightly=None):
        rep = compare(pr, base, nightly or _fx_nightly())
        return rep, len(rep.expected), len(rep.unexplained)

    def t_same():
        rep, e, u = cls(_fx_side(), _fx_side(249))
        text = "\n".join(rep.lines)
        miss = [w for w in ("pass 5", "skipping 1", "github-advanced-security", "| G1 |", "已知漏洞（非 KEV）", "nightly",
                            "PR 版", "受信任樹版", "enforce 副本", WARN_G4.strip()) if w not in text]
        if (e, u) != (0, 0):
            return f"完全相同應沒有差異（預期內 {rep.expected}、需要說明 {rep.unexplained}）"
        return f"輸出缺少：{miss}" if miss else None
    check("完全相同：0 項差異；輸出含各節", t_same)

    def t_others_both_sides():
        rep, _, _ = cls(_fx_side(), _fx_side(249, checks=_fx_checks(extra=[DEPENDABOT])))
        text = "\n".join(rep.lines)
        return None if text.count("不是 workflow 產生的") == 2 and "dependabot（Dependabot 設定驗證）" in text \
            else f"兩邊都要列出不是 workflow 產生的 check 與來源（得到 {text[:400]!r}）"
    check("check：兩邊都列出不是 workflow 產生的 check", t_others_both_sides)

    def t_same_name():
        dup = _fx_checks(extra=[("CodeQL", "github-advanced-security", "success")])
        _, e, u = cls(_fx_side(checks=dup), _fx_side(249))
        return None if u >= 1 else "同名同來源的 check 多一個 → 需要說明（不能合併成一項）"
    check("check：同名 check 的個數不同 → 需要說明", t_same_name)

    def t_nightly_fallback():   # 維護者決定（#240 留言）：當天沒有 nightly → 取之前最近一次，相同算預期內，輸出註明
        old = {**_fx_nightly(), "same_day": False, "date": "2026-10-31"}
        rep, e, u = cls(_fx_side(), _fx_side(249), old)
        if (e, u) != (0, 0) or "取之前最近的一次" not in "\n".join(rep.lines):
            return f"相同 → 沒有差異、輸出註明不是當天（得到 {e}、{u}）"
        _, e, u = cls(_fx_side(), _fx_side(249), {**old, "g1_log": _fx_nightly(91)["g1_log"]})
        return None if u >= 1 else "不是當天、筆數不同 → 需要說明"
    check("G1：當天沒有 nightly → 取之前最近一次並註明", t_nightly_fallback)

    def t_dependabot():
        _, e, u = cls(_fx_side(checks=_fx_checks(extra=[DEPENDABOT])), _fx_side(249))
        if (e, u) != (1, 0):
            return f"PR 多 Dependabot check 應預期內 1、需要說明 0（得到 {e}、{u}）"
        _, e, u = cls(_fx_side(), _fx_side(249, checks=_fx_checks(extra=[DEPENDABOT])))
        return None if (e, u) == (1, 0) else f"基準多 Dependabot check 也是預期內（得到 {e}、{u}）"
    check("分類：Dependabot 設定驗證 check → 預期內", t_dependabot)

    def t_checks_unexplained():
        bad = []
        for label, pr in (("多一個 workflow check", _fx_checks(extra=[("新 job", "github-actions", "success")])),
                          ("少一個 check", _fx_checks(drop=("CodeQL",))),
                          ("結果不同", _fx_checks(change={"grype": "success"})),
                          ("別的 app 的 check", _fx_checks(extra=[("x", "some-app", "success")]))):
            _, e, u = cls(_fx_side(checks=pr), _fx_side(249))
            if u < 1:
                bad.append(label)
        _, e, u = cls(_fx_side(checks=_fx_checks(change={"grype": "failure"})),
                      _fx_side(249, checks=_fx_checks(change={"grype": "failure"})))
        if u < 1:
            bad.append("兩邊同樣失敗也要說明")
        return f"應需要說明：{bad}" if bad else None
    check("分類：其他 check 差異 → 需要說明", t_checks_unexplained)

    def t_g1_nightly():
        pr = _fx_side(summary=_fx_summary(g1_adv=92), g1=_fx_g1(known=92))
        base = _fx_side(237, summary=_fx_summary(g1_adv=7), g1=_fx_g1(known=7))
        _, e, u = cls(pr, base)
        if (e, u) != (1, 0):
            return f"G1 7→92、和 nightly 相同 → 預期內 1、需要說明 0（得到 {e}、{u}）"
        _, e, u = cls(pr, base, _fx_nightly(91))
        if u < 1:
            return "G1 和 nightly 不同 → 需要說明"
        _, e, u = cls(_fx_side(), _fx_side(249), _fx_nightly(91))
        if u < 1:
            return "PR 和基準相同、但和 nightly 不同 → 仍需要說明（以 nightly 為準）"
        _, e, u = cls(_fx_side(summary=_fx_summary(g1_adv=93), g1=_fx_g1(known=92)), base)
        return None if u >= 1 else "表格 advisory 的變化和已知漏洞的變化不一致 → 需要說明"
    check("分類：G1 筆數和當天 nightly 相同 → 預期內", t_g1_nightly)

    def t_allowlist():
        plain = _fx_summary(g1_note="")
        _, e, u = cls(_fx_side(), _fx_side(249, summary=plain, g1=_fx_g1(skipped=True)))
        if (e, u) != (1, 0):
            return f"PR 有掃描、多 allowlist 句 → 預期內 1、需要說明 0（得到 {e}、{u}）"
        _, e, u = cls(_fx_side(summary=plain, g1=_fx_g1(skipped=True)), _fx_side(249))
        if (e, u) != (1, 0):
            return f"基準有掃描、多 allowlist 句 → 預期內（得到 {e}、{u}）"
        _, e, u = cls(_fx_side(g1=_fx_g1(skipped=True)), _fx_side(249, summary=plain, g1=_fx_g1(skipped=True)))
        if u < 1:
            return "slopcheck 略過卻出現 allowlist 句 → 需要說明"
        _, e, u = cls(_fx_side(summary=_fx_summary(g1_note=ALLOW + "；另一句")), _fx_side(249))
        return None if u >= 1 else "allowlist 句以外的說明不同 → 需要說明"
    check("分類：有掃描的那邊多 allowlist 句 → 預期內", t_allowlist)

    def t_gate_unexplained():
        _, e, u = cls(_fx_side(summary=_fx_summary(g2="`fail` | 1 | 0 | x")), _fx_side(249))
        return None if u >= 1 else "G2 列不同 → 需要說明"
    check("分類：其他閘門列不同 → 需要說明", t_gate_unexplained)

    def t_validate_cls():
        bad = []
        _, e, u = cls(_fx_side(validate=_fx_validate(runs=((1, 0), (1, 1), (2, 0)))), _fx_side(249))
        if u < 1:
            bad.append("PR 有錯誤")
        _, e, u = cls(_fx_side(validate=_fx_validate(extra_warn="  WARN 新警告")), _fx_side(249))
        if u < 1:
            bad.append("警告內容不同")
        _, e, u = cls(_fx_side(validate=_fx_validate(runs=((2, 0), (1, 0), (2, 0)))), _fx_side(249))
        if u < 1:
            bad.append("警告數不同")
        return f"應需要說明：{bad}" if bad else None
    check("分類：validate 有錯誤或警告不同 → 需要說明", t_validate_cls)

    def t_kev():
        _, e, u = cls(_fx_side(g1=_fx_g1(kev=1)), _fx_side(249))
        return None if u >= 1 else "KEV 命中數不同 → 需要說明"
    check("分類：KEV 命中數不同 → 需要說明", t_kev)

    # ---- main：退出碼；gh 注入，不連網
    def fake_gh(pr_checks=None, base_checks=None, pr_g1=None, runs_status="completed", fail_path=None):
        heads = {"250": "a" * 40, "249": "b" * 40}
        side_checks = {"a" * 40: pr_checks or _fx_checks(), "b" * 40: base_checks or _fx_checks()}
        logs = {"1": _fx_summary(), "2": _fx_validate(), "3": pr_g1 or _fx_g1(), "4": _fx_summary(), "5": _fx_validate(),
                "6": _fx_g1(), "9": _fx_nightly()["g1_log"]}

        def gh(args):
            path = next(a for a in args if a.startswith(REPO))
            if fail_path and fail_path in path:
                raise InputError(f"gh api {path} 失敗")
            if m := re.search(r"/pulls/(\d+)$", path):
                return heads[m[1]] + "\n"
            if m := re.search(r"/commits/(\w+)/check-runs", path):
                return "\n".join(json.dumps({"name": c["name"], "app": c["source"],
                                             "status": "completed" if bucket(c["state"]) != "pending" else c["state"],
                                             "conclusion": c["state"] if bucket(c["state"]) != "pending" else None})
                                 for c in side_checks[m[1]])
            if "/status?" in path:
                return ""
            if m := re.search(r"head_sha=(\w)", path):
                k = "1" if m[1] == "a" else "2"
                return json.dumps({"id": int(k), "name": "VibeSec PR Gates", "path": PR_GATES, "event": "pull_request",
                                   "status": runs_status, "created_at": "2026-11-01T09:18:08Z"})
            if m := re.search(r"/runs/(\d+)/jobs", path):
                ids = {"1": (1, 2, 3), "2": (4, 5, 6), "9": (9,)}[m[1]]
                names = {1: JOB_SUMMARY, 2: "倉庫驗證（validate.py）", 3: "G1 供應鏈與 Slopsquatting", 9: "G1 全量供應鏈 x"}
                return "\n".join(json.dumps({"id": i, "name": names[(i - 1) % 3 + 1 if i != 9 else 9], "status": "completed"})
                                 for i in ids)
            if NIGHTLY in path:
                return json.dumps({"id": 9, "created_at": "2026-11-01T18:01:10Z", "status": "completed"})
            if m := re.search(r"/jobs/(\d+)/logs", path):
                return logs[m[1]]
            raise AssertionError(f"未預期的 gh 呼叫：{args}")
        return gh

    def run(argv, gh):
        import contextlib, io
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = main(argv, gh=gh)
        return rc, out.getvalue()

    def t_main():
        bad = []
        for label, gh, want in (
            ("相同", fake_gh(), 0),
            ("只有 Dependabot", fake_gh(pr_checks=_fx_checks(extra=[DEPENDABOT])), 0),
            ("KEV 不同", fake_gh(pr_g1=_fx_g1(kev=1)), 1),
            ("API 失敗", fake_gh(fail_path="/jobs/2/logs"), 2),
            ("找不到 nightly", fake_gh(fail_path=NIGHTLY), 2),
        ):
            rc, out = run(["250", "--baseline", "249"], gh)
            if rc != want:
                bad.append(f"{label} 應 exit {want}（得到 {rc}：{out[-200:]!r}）")
        rc, out = run(["250", "--baseline", "249"], fake_gh(pr_checks=_fx_checks(change={"CodeQL": "in_progress"})))
        if rc != 2 or "CI 未完成" not in out or "| G1 |" in out:
            bad.append(f"CI 未完成 → exit 2、不比對（得到 {rc}：{out!r}）")
        rc, out = run(["250", "--baseline", "249"], fake_gh(runs_status="in_progress"))
        if rc != 2 or "CI 未完成" not in out:
            bad.append(f"run 未結束 → exit 2（得到 {rc}）")
        for argv in (["250"], ["250", "249"], ["x", "--baseline", "249"]):
            if run(argv, fake_gh())[0] != 4:
                bad.append(f"{argv} 應 exit 4")
        return "；".join(bad) or None
    check("main：退出碼 0／1／2／4，CI 未完成時不比對", t_main)
    return fails


if __name__ == "__main__":
    if sys.argv[1:2] == ["selftest"]:
        _fails = selftest()
        for f in _fails:
            print(f"FAIL {f}")
        print("compare_ci selftest ok" if not _fails else f"selftest 失敗 {len(_fails)} 項")
        sys.exit(1 if _fails else 0)
    sys.exit(main(sys.argv[1:]))
