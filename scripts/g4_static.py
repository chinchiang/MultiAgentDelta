#!/usr/bin/env python3
"""VibeSec G4 靜態檢查：隱形 Unicode（Rules File Backdoor）、Supabase RLS、Agent 工具 allow-list、HITL、
單層 middleware 授權、MCP resource indicator。

  python3 -I scripts/g4_static.py --target <受測專案> --out <輸出目錄> --mode shadow|enforce [--commit <sha>]
  python3 scripts/g4_static.py selftest

輸出：<out>/g4-static.sarif、<out>/g4-gate.json（VS-G4-LLM-REVIEW 為 pending，由 scripts/g4_review.py 接續判定）。
退出碼：enforce 且有 blocking 發現 → 1；其餘 0；參數不合法 → 2（argparse）。
"""
from __future__ import annotations
import argparse, json, os, pathlib, subprocess, sys, tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent


TOOL_NAME, TOOL_VERSION = "vibesec-g4-static", "1.0.0"
# LLM 審查控制：由 g4_review.py 依審查紀錄判定（GateRun 的 deferred）。本檔不依賴 PyYAML，是這個 ID 的唯一來源，
# g4_review、g4_access 都從這裡取用
LLM_CONTROL = "VS-G4-LLM-REVIEW"
# G4 gate JSON 的控制（順序同 coverage）；政策檔讀不到時靜態控制記 untested、LLM_CONTROL 維持 pending
CONTROLS = ("VS-G4-RULES-FILE-UNICODE", "ASVS5-V8.2", "ASVS5-V8.3", "VS-G4-AGENT-TOOL-ALLOWLIST", "ASVS5-V2.3",
            "VS-G4-MCP-RESOURCE-INDICATOR", LLM_CONTROL)


def scan(MODE: str, COMMIT: str | None, REPORTS: pathlib.Path, policy_root: pathlib.Path = ROOT) -> None:
    """在目前目錄（受測專案根目錄）執行靜態檢查，結果寫到 REPORTS。主體逐行沿用原 pr-gates.yml 的 inline（純搬遷）。
    policy_root：阻擋政策所在的 repo（selftest 指向壞政策檔；不開命令列參數）。"""
    # G4 靜態檢查：隱形 Unicode（Rules File Backdoor）、Supabase RLS、Agent 工具 allow-list、單層 middleware 授權
    import json, re, pathlib, os, datetime, glob, sys
    NOW = datetime.datetime.now(datetime.timezone.utc)
    def iso(dt): return dt.replace(microsecond=0).isoformat()
    # tier 只來自 blocking-policy（含 risk_tier 的 tier_overrides）；ROOT 為本腳本所在的樹（CI 中為 _trusted/）
    sys.path.insert(0, str(ROOT / "scripts"))
    from vibesec_policy import load_policy
    import gate_result   # 必須在上面的 sys.path.insert 之後：CI 以 python3 -I 執行，腳本目錄不在 sys.path（#183）
    REPORTS.mkdir(parents=True, exist_ok=True)

    # 閘門結果由 GateRun 產出（#183）：LLM 審查控制由 g4_review.py 接續判定 → 宣告為 deferred
    run = gate_result.GateRun("G4", controls=[c for c in CONTROLS if c != LLM_CONTROL], deferred=[LLM_CONTROL],
                              mode=MODE, scope="full", commit=COMMIT, started_at=iso(NOW))

    def write_gate(gate):
        (REPORTS / "g4-gate.json").write_text(json.dumps(gate, ensure_ascii=False, indent=2), encoding="utf-8")

    POLICY, problem = load_policy(policy_root)   # 只建立一次；讀不到 → incomplete，不分類任何發現
    if problem:
        gate_result.remove_stale(REPORTS / "g4-static.sarif")   # 不讓上一次的結果被當成這次的
        # 靜態控制 untested（原因＝problem）、LLM 審查控制維持 pending、tool 列只有一列 error。mode 取自政策：
        # 政策讀不到（含 mode 缺席或不合法，#200）＝ mode 不明 → unreadable() 記 enforce，不採用 --mode 傳進來的值
        run.mode = None
        write_gate(run.unreadable(problem, tool_name=TOOL_NAME, version=TOOL_VERSION))
        print(f"G4 static: incomplete（{problem}）")
        return
    # _trusted/ 是 default branch 的判定程式副本，不是被掃描的專案內容
    def _skip(p): return str(p).startswith(("_trusted/", "./_trusted/", ".git/")) or "/node_modules/" in str(p)
    # 列檔一律用 os.walk：glob 的 ** 會跳過 .agents/、.cursor/ 等隱藏目錄，PR 把高危工具放進隱藏目錄就看不到
    def _files(*exts):
        out = []
        for root, dirs, files in os.walk("."):
            dirs[:] = [x for x in dirs if x not in (".git", "node_modules", "_trusted")]
            for fn in files:
                if fn.endswith(exts):
                    out.append(os.path.normpath(os.path.relpath(os.path.join(root, fn), ".")).replace(os.sep, "/"))
        return sorted(out)
    # 讀檔失敗（目錄名為 x.sql、指向目錄的 symlink、權限）不得讓整步崩潰而丟掉其他發現；
    # 對應控制記 untested（沒看到內容不等於沒有問題），已有 blocking 發現照樣 fail
    READ_ERR = {}
    def _read(p, ctl):
        try:
            return pathlib.Path(p).read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            READ_ERR.setdefault(ctl, []).append(f"{p}（{type(e).__name__}）")
            return None

    results = []; rules = {}
    def add(rule_id, level, msg, uri, line=1):
        tier = POLICY.tier(rule_id)
        rules.setdefault(rule_id, {"id": rule_id, "name": rule_id,
                                   "shortDescription": {"text": rule_id},
                                   "defaultConfiguration": {"level": level},
                                   "properties": {"policy_tier": tier}})
        results.append({"ruleId": rule_id, "level": level, "message": {"text": msg},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                                       "region": {"startLine": line}}}],
                        "properties": {"policy_tier": tier}})

    # 1) 隱形 Unicode 掃描
    INVISIBLE = ["\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad"]  # 零寬、WJ、BOM、soft hyphen
    INVISIBLE += [chr(c) for c in range(0x202A, 0x202F)]  # U+202A-U+202E bidi
    INVISIBLE += [chr(c) for c in range(0x2066, 0x206A)]  # U+2066-U+2069 isolates
    INVISIBLE += [chr(c) for c in range(0x2061, 0x2065)]  # U+2061-U+2064 invisible operators
    INVISIBLE += [chr(c) for c in range(0xE0000, 0xE0080)]  # Unicode Tag 字元（可藏 ASCII 指令）
    # 範圍依 docs/05 §6：所有 Markdown（含 .github/copilot-instructions.md、CLAUDE.md、AGENTS.md、SKILL.md）
    # 加上無副檔名的 AI 助理規則檔（Cursor / Windsurf / Cline）
    # 用 os.walk 而非 glob：glob 的 ** 會跳過 .github/、.cursor/ 等隱藏目錄
    RULE_NAMES = {".cursorrules", ".windsurfrules", ".clinerules"}
    rule_files = []
    for root, dirs, files in os.walk("."):
        dirs[:] = [x for x in dirs if x not in (".git", "node_modules", "_trusted")]
        rel_root = os.path.relpath(root, ".")
        in_rules_dir = rel_root.startswith((".cursor/rules", ".clinerules"))
        for fn in files:
            if fn.endswith((".md", ".mdc")) or fn in RULE_NAMES or in_rules_dir:
                rule_files.append(os.path.normpath(os.path.join(rel_root, fn)))
    for p in sorted(set(rule_files)):
        fp = pathlib.Path(p)
        if not fp.exists(): continue
        try: lines = fp.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception: continue
        for i, ln in enumerate(lines, 1):
            hits = [hex(ord(ch)) for ch in ln if ch in INVISIBLE]
            if hits:
                add("vibesec.g4.rules-file-invisible-unicode", "error",
                    f"Rules File Backdoor：{p} 第 {i} 行含隱形 Unicode {hits}", p, i)

    # 2) Supabase migrations RLS
    # 兩個 glob 會重疊（supabase/migrations 也符合 **/migrations）→ 去重，避免同一檔案重複回報
    SQL_MIGRATIONS = 0   # 沒有任何 migration → ASVS5-V8.2 not_applicable（沒有可查的表，不是「已啟用 RLS」）
    for p in [f for f in _files(".sql") if f.startswith("supabase/migrations/") or "/migrations/" in f or f.startswith("migrations/")]:
        if _skip(p): continue
        SQL_MIGRATIONS += 1
        body = _read(p, "ASVS5-V8.2")
        if body is None: continue
        if re.search(r'disable\s+row\s+level\s+security', body, re.I):
            add("vibesec.g4.supabase-rls-disabled", "error", f"{p} 明確停用 RLS（全表暴露風險）", p, 1)
        for m in re.finditer(r'create\s+table\s+(?:if\s+not\s+exists\s+)?["`]?([A-Za-z0-9_.]+)', body, re.I):
            tbl = m.group(1)
            if not re.search(rf'alter\s+table\s+["`]?{re.escape(tbl)}["`]?\s+enable\s+row\s+level\s+security', body, re.I):
                add("vibesec.g4.supabase-table-without-rls", "warning",
                    f"{p}：資料表 {tbl} 未見 enable row level security", p, 1)

    # Agent 工具註冊脈絡與工具名稱（3) allow-list lint 與 3b) HITL 共用）
    TOOL_CTX = re.compile(r'@(?:\w+\.)?tool\b|register_tool|\btools\s*[=:]|\.tool\(|\btool\(\s*\{', re.I)
    def _tool_names(body):
        """(名稱, 行號)：@tool／@mcp.tool 下一個 def、tools=[…]／tools: […] 清單、YAML tools: 區塊條目、
        register_tool("x")／server.tool("x")、tool({name: "x"})、tools: { x: tool({…}) }（Vercel AI SDK）、
        Tool(name="x")／StructuredTool.from_function(name="x")（LangChain）。"""
        out = []
        lines = body.splitlines()
        for i, ln in enumerate(lines, 1):
            if re.search(r'@(?:\w+\.)?tool\b', ln):
                for j in range(i, min(i + 4, len(lines))):
                    m = re.match(r'\s*(?:async\s+)?def\s+(\w+)', lines[j])
                    if m: out.append((m.group(1), j + 1)); break
            for m in re.finditer(r'\btools\s*[=:]\s*\[([^\]]*)\]', ln):
                out += [(n, i) for n in re.findall(r'[A-Za-z_][\w-]*', m.group(1))]
            for m in re.finditer(r'(?:register_tool|\.tool)\(\s*["\']([\w-]+)', ln):
                out.append((m.group(1), i))
            for m in re.finditer(r'\bname\s*:\s*["\']([\w-]+)["\']', ln):
                out.append((m.group(1), i))
            for m in re.finditer(r'\b([A-Za-z_]\w*)\s*:\s*tool\(', ln):
                out.append((m.group(1), i))
            for m in re.finditer(r'(?:\bTool|from_function)\([^)]*?\bname\s*=\s*["\']([\w-]+)', ln):
                out.append((m.group(1), i))
            if re.match(r'\s*tools\s*:\s*$', ln):          # YAML 區塊清單：tools:\n  - refund_payment
                for j in range(i, len(lines)):
                    m = re.match(r'\s*-\s*(?:name\s*:\s*)?["\']?([A-Za-z_][\w-]*)', lines[j])
                    if not m: break
                    out.append((m.group(1), j + 1))
        return out
    # 3) Agent 工具 allow-list lint（高危工具暴露）：只看「註冊給 Agent 的工具名稱」（_tool_names）。
    #    以前只要檔案出現 tool 字樣、且任一處提到 delete_user／execute_sql／drop_table 就報：分類工具名稱的正則、
    #    文件字串、測試資料都會誤報（例如 scripts/llm_observations.py 第 23 行判定高影響工具用的 HIGH_IMPACT，L3 下為 blocking）。
    DANGEROUS = re.compile(r'(delete_user|execute_sql|drop_table)', re.I)
    for p in _files(".py", ".ts", ".js"):
        if _skip(p): continue
        body = _read(p, "VS-G4-AGENT-TOOL-ALLOWLIST")
        if body is None or not TOOL_CTX.search(body): continue
        risky = [(n, i) for n, i in _tool_names(body) if DANGEROUS.search(n)]
        if risky:
            n, i = risky[0]
            add("vibesec.g4.agent-tool-overexposure", "warning",
                f"{p} 第 {i} 行向 Agent 註冊高危工具 {n}（delete_user/execute_sql/drop_table）；應限制 allow-list + HITL", p, i)

    # 3b) 高影響工具缺 Human-in-the-Loop（vibesec.g4.missing-hitl，advisory）— 啟發式，只看單一檔案：
    #     檔案有 Agent 工具註冊脈絡、註冊的工具名稱有高影響動作（金流、刪除、部署、對外送信、改權限），
    #     且同檔案看不到任何人工核准訊號（confirm／approval／HITL／interrupt…）→ 回報。
    #     核准若做在其他檔案（框架設定、gateway）會誤報，所以是 advisory；跨檔確認交 LLM 審查（VS-G4-LLM-REVIEW）。
    HI_TOOL = re.compile(r'(refund|transfer|payout|payment|charge|withdraw|wire|delete|drop|truncate|wipe|purge|destroy|'
                         r'deploy|release|publish|send_(?:email|mail|sms|message)|grant|revoke|set_role)', re.I)
    HITL_SIGNAL = re.compile(r'confirm|approv|human[_ -]?in[_ -]?the[_ -]?loop|\bhitl\b|interrupt\(|ask_user|'
                             r'require_?(?:human|review)|needs_?review|permission_mode|人工(?:確認|核准)', re.I)
    HITL_FILES = (_files(".py", ".ts", ".js")
                  + [f for f in _files(".yml", ".yaml", ".json")
                     if not f.startswith(".github/")])   # workflow 的 deploy／release job 不是 Agent 工具
    HITL_FILES = [f for f in HITL_FILES if not f.startswith("evals/cases/")]   # 評測 fixture（同 .semgrepignore 的 evals/）
    for p in HITL_FILES:
        if _skip(p): continue
        body = _read(p, "ASVS5-V2.3")
        if body is None: continue
        if not TOOL_CTX.search(body) or HITL_SIGNAL.search(body):
            continue
        risky = [(n, i) for n, i in _tool_names(body) if HI_TOOL.search(n)]
        if risky:
            n, i = risky[0]
            add("vibesec.g4.missing-hitl", "warning",
                f"{p} 第 {i} 行：Agent 工具 {n} 屬高影響動作，同檔案未見人工核准（confirm／approval／HITL）；"
                f"請確認執行前有人工確認與稽核（若核准做在其他檔案，於 LLM 審查說明）", p, i)

    # 4) 單層 middleware 授權（CVE-2025-29927 類）— advisory
    for p in [f for f in _files("middleware.ts") if f.rsplit("/", 1)[-1] == "middleware.ts"]:
        if _skip(p): continue
        add("vibesec.g4.single-middleware-authz", "note",
            f"偵測到 Next.js {p}：請確認授權不只靠單層 middleware（CVE-2025-29927），資料層需獨立 authz", p, 1)

    # 4b) FastAPI／Starlette：授權只做在 app middleware，路由與 router 都沒有授權依賴 → 同一規則（advisory）。
    #     「middleware 做授權」= @app.middleware("http") 函式或 BaseHTTPMiddleware 子類別內有授權訊號；
    #     「路由層授權」= 任何 Security()，或依賴名稱像授權的 Depends()（Depends(get_db) 這類不算）。
    #     只要有路由層授權就不報：那已是兩層，是否涵蓋每條路由交給 LLM 審查（VS-G4-LLM-REVIEW）。
    import ast
    AUTH_SIGNAL = re.compile(r'authori[sz]ation|bearer|token|session|api[_-]?key|unauthori[sz]ed|forbidden|\b40[13]\b|HTTP_40[13]', re.I)
    AUTH_DEP = re.compile(r'auth|user|token|session|principal|permission|scope|login|verify|require|current|guard|role', re.I)
    def _name(n):
        return n.attr if isinstance(n, ast.Attribute) else n.id if isinstance(n, ast.Name) else ""
    mw_hits, route_auth = [], False
    for p in _files(".py"):
        if _skip(p) or "site-packages/" in p or p.startswith(("venv/", ".venv/")): continue
        src = _read(p, "ASVS5-V8.3")
        if src is None: continue
        if not re.search(r'^\s*(from|import)\s+(fastapi|starlette)\b', src, re.M): continue
        try: tree = ast.parse(src)
        except (SyntaxError, ValueError): continue
        funcs = {n.name: n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
        def _does_auth(node):
            # middleware 常把判斷交給同檔的 helper（例如 response = await guard(request)）：往下看一層
            called = {_name(c.func) for c in ast.walk(node) if isinstance(c, ast.Call)}
            return any(AUTH_SIGNAL.search(ast.get_source_segment(src, n) or "")
                       for n in [node, *(funcs[c] for c in called if c in funcs and funcs[c] is not node)])
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if any(isinstance(d, ast.Call) and _name(d.func) == "middleware" and d.args
                       and isinstance(d.args[0], ast.Constant) and d.args[0].value == "http" for d in node.decorator_list) \
                        and _does_auth(node):
                    mw_hits.append((p, node.lineno))
            elif isinstance(node, ast.ClassDef):
                if any(_name(b) == "BaseHTTPMiddleware" for b in node.bases) and _does_auth(node):
                    mw_hits.append((p, node.lineno))
            elif isinstance(node, ast.Call):
                fn = _name(node.func)
                if fn == "Security" or (fn == "Depends" and node.args and AUTH_DEP.search(_name(node.args[0]))):
                    route_auth = True
    if not route_auth:
        for p, line in mw_hits:
            add("vibesec.g4.single-middleware-authz", "note",
                f"FastAPI {p} 第 {line} 行的 middleware 含授權判斷，但沒有任何路由或 router 以 Depends／Security 檢查授權："
                "middleware 被繞過或路由掛到其他 app 時沒有第二道檢查；路由或服務層需獨立 authz，資料層再加 owner filter", p, line)

    # 5) MCP OAuth 的 RFC 8707 resource indicator（vibesec.yaml static_checks 的 mcp_resource_indicator；docs/05 §7）— advisory。
    #    判定在受信任的 scripts/g4_mcp.py（與本機版 g4_access.py、run_evals.py 共用，只用標準函式庫）。
    #    無法載入或執行（例如 default branch 還沒有這支模組）→ 控制記 untested 並寫進 status_reason，不讓整步崩潰。
    try:
        from g4_mcp import mcp_resource_check, MCP_RULE
        mcp_hits, MCP_COV = mcp_resource_check(pathlib.Path("."))
    except Exception as e:
        mcp_hits, MCP_COV = [], {"control_id": "VS-G4-MCP-RESOURCE-INDICATOR", "state": "untested",
                                 "reason": f"MCP resource indicator 檢查無法執行（scripts/g4_mcp.py：{type(e).__name__}）"}
    for uri, line, msg in mcp_hits:
        add(MCP_RULE, "warning", msg, uri, line)

    sarif = gate_result.sarif({"name": TOOL_NAME, "version": TOOL_VERSION}, list(rules.values()), results)
    (REPORTS / "g4-static.sarif").write_text(json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8")

    blocking = sum(1 for r in results if r["properties"]["policy_tier"] == "blocking")
    advisory = len(results) - blocking
    # 狀態反映發現本身；shadow 只決定是否擋下 merge（見下方 exit 與 job 的 continue-on-error），不把 fail 改寫成 pass。
    # CI 只跑靜態部分；VS-G4-LLM-REVIEW（跨檔授權推理、BOLA/IDOR、HITL）在此仍 pending → G4 最多是 incomplete，
    # 不報 pass（incomplete ≠ pass，CLAUDE.md #2；docs/05「reviewer 缺席 → incomplete 或 pending；不得 pass」）。
    # G4 不在 blocking-policy 的 incomplete_gate_is_blocking_in_enforce，所以 incomplete 不擋 merge；要擋須人類另開 PR 改政策。
    LLM_PENDING = "G4 LLM 審查（VS-G4-LLM-REVIEW）未在 CI 執行，需由 /vibesec-harness 或人工完成"
    def _state(*ids, ctl=None):
        if any(r["ruleId"] in ids for r in results): return "fail"
        return "untested" if ctl in READ_ERR else "pass"
    def _why(ctl):
        return ("無法讀取：" + "、".join(READ_ERR[ctl][:5])) if ctl in READ_ERR else None
    entries = [
        {"control_id": "VS-G4-RULES-FILE-UNICODE", "state": _state("vibesec.g4.rules-file-invisible-unicode"), "reason": None},
        ({"control_id": "ASVS5-V8.2", "state": _state("vibesec.g4.supabase-rls-disabled", "vibesec.g4.supabase-table-without-rls", ctl="ASVS5-V8.2"), "reason": _why("ASVS5-V8.2")}
         if SQL_MIGRATIONS else
         {"control_id": "ASVS5-V8.2", "state": "not_applicable", "reason": "沒有 supabase／migrations 的 .sql 檔，RLS 靜態檢查無對象"}),
        {"control_id": "ASVS5-V8.3", "state": _state("vibesec.g4.single-middleware-authz", ctl="ASVS5-V8.3"), "reason": _why("ASVS5-V8.3")},
        {"control_id": "VS-G4-AGENT-TOOL-ALLOWLIST", "state": _state("vibesec.g4.agent-tool-overexposure", ctl="VS-G4-AGENT-TOOL-ALLOWLIST"), "reason": _why("VS-G4-AGENT-TOOL-ALLOWLIST")},
        {"control_id": "ASVS5-V2.3", "state": _state("vibesec.g4.missing-hitl", ctl="ASVS5-V2.3"), "reason": _why("ASVS5-V2.3")},
        MCP_COV,
        {"control_id": LLM_CONTROL, "state": "pending", "reason": "LLM 審查需由 /vibesec-harness 或人工執行"},
    ]
    # 依 CONTROLS 排列（政策檔讀不到時用同一份清單）：多一個、少一個控制都直接失敗，不靠兩份清單手動同步
    by_id = {e["control_id"]: e for e in entries}
    if sorted(by_id) != sorted(CONTROLS) or len(by_id) != len(entries):
        raise SystemExit(f"G4 coverage 與 CONTROLS 不一致：{sorted(by_id)} vs {sorted(CONTROLS)}")
    coverage = [by_id[c] for c in CONTROLS]
    # 狀態由受信任的 gate_verdict.verdict 判定（GateRun.result）：blocking → fail；否則 LLM 審查未完成 → incomplete（無法讀取的檔案、
    # MCP 檢查無法執行等 untested 控制一併寫進 status_reason）。下一步 g4_review.py 依審查紀錄重新判定。
    run.tool(TOOL_NAME, "ran", version=TOOL_VERSION, exit_code=0, output_ref="reports/g4-static.sarif")
    for c in coverage:
        run.cover(c["control_id"], c["state"], c["reason"])
    run.count(blocking=blocking, advisory=advisory)
    run.problem(LLM_PENDING)
    write_gate(run.result())
    print(f"G4 static: blocking={blocking} advisory={advisory}")
    if MODE == "enforce" and blocking:
        raise SystemExit(1)


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["selftest"]:
        fails = selftest()
        for f in fails:
            print(f"FAIL {f}")
        print("selftest 通過" if not fails else f"selftest 失敗 {len(fails)} 項")
        return 1 if fails else 0
    sys.path.insert(0, str(ROOT / "scripts"))   # CI 以 python3 -I 執行：import 必須在 sys.path.insert 之後
    from vibesec_mode import MODES                # mode 的合法值只有一份（#200）
    ap = argparse.ArgumentParser(description="VibeSec G4 靜態檢查")
    ap.add_argument("--target", required=True, type=pathlib.Path, help="受測專案根目錄")
    ap.add_argument("--out", required=True, type=pathlib.Path, help="輸出目錄（g4-static.sarif、g4-gate.json）")
    ap.add_argument("--mode", required=True, choices=MODES, help="沒有預設值：預設 shadow 等於靜默放行")
    ap.add_argument("--commit", default=None, help="受測 commit（寫入 gate JSON；沒給記 null）")
    a = ap.parse_args(argv)
    out = a.out.resolve()                 # 先以呼叫端 cwd 解析，再切換到受測專案
    os.chdir(a.target)
    scan(a.mode, (a.commit or "")[:40] or None, out)
    return 0


# ------------------------------------------------------------------ selftest：CLI 合約（規則邏輯由 G4 評測與 g4_access selftest 涵蓋）
def selftest() -> list[str]:
    from jsonschema import Draft202012Validator
    fails: list[str] = []
    schema = Draft202012Validator(json.loads((ROOT / "schemas/gate-result.schema.json").read_text(encoding="utf-8")))
    me = pathlib.Path(__file__).resolve()
    rls = "alter table notes disable row level security;\n"     # vibesec.g4.supabase-rls-disabled（blocking）

    def run(*args, cwd):
        p = subprocess.run([sys.executable, "-I", str(me), *map(str, args)], cwd=cwd, capture_output=True, text=True, timeout=300)
        return p.returncode

    def outputs(out: pathlib.Path):
        try:
            sarif = json.loads((out / "g4-static.sarif").read_text(encoding="utf-8"))
            gate = json.loads((out / "g4-gate.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None, None
        return {r.get("ruleId") for run_ in sarif.get("runs", []) for r in run_.get("results", [])}, gate

    with tempfile.TemporaryDirectory() as d:
        D = pathlib.Path(d)
        clean, risky, hidden = D / "clean", D / "risky", D / "hidden"
        for t in (clean, risky, hidden):
            t.mkdir()
            (t / "README.md").write_text("沒有任何發現。\n", encoding="utf-8")
        (risky / "supabase/migrations").mkdir(parents=True)
        (risky / "supabase/migrations/001.sql").write_text(rls, encoding="utf-8")
        # 受信任副本、.git、node_modules 不是受測內容：放在那裡的發現不得回報
        for sub in ("_trusted", ".git", "node_modules/pkg"):
            (hidden / sub / "supabase/migrations").mkdir(parents=True)
            (hidden / sub / "supabase/migrations/001.sql").write_text(rls, encoding="utf-8")

        # 參數：--target／--out／--mode 必填，--mode 只收 shadow／enforce（沒有預設 shadow：預設等於靜默放行）
        for label, args in [("沒有參數", []), ("缺 --mode", ["--target", clean, "--out", D / "o0"]),
                            ("--mode 不合法", ["--target", clean, "--out", D / "o0", "--mode", "audit"]),
                            ("缺 --target", ["--out", D / "o0", "--mode", "shadow"]),
                            ("缺 --out", ["--target", clean, "--mode", "shadow"])]:
            rc = run(*args, cwd=D)
            if rc != 2:
                fails.append(f"參數：{label} → exit 2（得到 {rc}）")

        # 沒有發現：exit 0、寫出 SARIF 與符合 schema 的 gate JSON；--commit 寫入 commit，沒給則為 null
        rc = run("--target", clean, "--out", D / "o1", "--mode", "enforce", "--commit", "a" * 40, cwd=D)
        hits, gate = outputs(D / "o1")
        if rc != 0 or gate is None or hits:
            fails.append(f"沒有發現 → exit 0 並寫出空的 SARIF 與 gate JSON（exit {rc}，發現 {hits}）")
        else:
            errs = list(schema.iter_errors(gate))
            if errs:
                fails.append(f"gate JSON 不符 schema：{errs[0].message[:120]}")
            if gate.get("gate") != "G4" or gate.get("mode") != "enforce" or gate.get("commit") != "a" * 40:
                fails.append(f"gate JSON 應記 gate G4、mode、commit（得到 {gate.get('gate')}、{gate.get('mode')}、{gate.get('commit')}）")
        run("--target", clean, "--out", D / "o2", "--mode", "shadow", cwd=D)
        if (outputs(D / "o2")[1] or {}).get("commit", "缺") is not None:
            fails.append("沒給 --commit → gate JSON 的 commit 為 null")

        # 有 blocking 發現：shadow 只報告（exit 0）、enforce exit 1；兩者都要寫出結果
        for mode, want in (("shadow", 0), ("enforce", 1)):
            out = D / f"o-{mode}"
            rc = run("--target", risky, "--out", out, "--mode", mode, cwd=D)
            hits, gate = outputs(out)
            if rc != want or "vibesec.g4.supabase-rls-disabled" not in (hits or set()) \
                    or (gate or {}).get("findings_count", {}).get("blocking") != 1:
                fails.append(f"blocking 發現、{mode} → exit {want} 並回報（exit {rc}，發現 {hits}）")

        # 排除：只出現在 _trusted／.git／node_modules 的發現不回報
        rc = run("--target", hidden, "--out", D / "o3", "--mode", "enforce", cwd=D)
        hits, _ = outputs(D / "o3")
        if rc != 0 or hits is None or hits:
            fails.append(f"_trusted／.git／node_modules 不得掃描（exit {rc}，發現 {hits}）")

        # 相對路徑的 --out 以呼叫端的 cwd 為準（腳本會切換到 --target，但輸出不得寫進受測專案）
        rc = run("--target", "clean", "--out", "rel-out", "--mode", "shadow", cwd=D)
        if rc != 0 or outputs(D / "rel-out")[1] is None or (clean / "rel-out").exists() or (clean / "reports").exists():
            fails.append(f"相對 --out 應寫到呼叫端 cwd 下，不寫進受測專案（exit {rc}）")
    # CONTROLS 與正常路徑的 coverage 是同一組（政策檔讀不到時全部記 untested）
    with tempfile.TemporaryDirectory() as d:
        out = pathlib.Path(d, "out")
        run("--target", d, "--out", out, "--mode", "shadow", cwd=d)
        got = [c["control_id"] for c in (outputs(out)[1] or {}).get("coverage", [])]
        if got != list(CONTROLS):
            fails.append(f"CONTROLS 應與 coverage 的控制相同（得到 {got}）")
    # 政策檔讀不到 → scan 一開始就停：G4 gate incomplete 並寫明未完成原因、沒有任何發現、控制 untested、
    # 不留 SARIF（以前 Policy(ROOT) 拋出例外、整支結束，gate JSON 沒有寫出）。在同一個行程呼叫：不為測試開命令列參數
    import contextlib, io
    sys.path.insert(0, str(ROOT / "scripts"))
    # 政策 root 的 vibesec.yaml 缺 mode 也是政策讀不到（#200）；兩種情況 mode 都記 enforce（不採用 --mode 傳進來的 shadow）
    from vibesec_policy import POLICY_UNREADABLE, broken_policy_root, modeless_policy_root
    cwd = os.getcwd()
    for make_root in (broken_policy_root, modeless_policy_root):
        with make_root() as pr, tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d, "out"); out.mkdir()
            (out / "g4-static.sarif").write_text("上一次的結果", encoding="utf-8")
            try:
                os.chdir(d)
                with contextlib.redirect_stdout(io.StringIO()):
                    scan("shadow", None, out, policy_root=pr)
            finally:
                os.chdir(cwd)
            g = json.loads((out / "g4-gate.json").read_text(encoding="utf-8"))
            # 接線（#183）：閘門結果由 GateRun.unreadable 產出 → 靜態控制依序 untested（原因＝政策讀不到）、
            # LLM 審查控制（deferred）維持 pending、tool 列只有一列 error
            import gate_result
            cov = [(c["control_id"], c["state"], (c["reason"] or "").startswith(POLICY_UNREADABLE)) for c in g["coverage"]]
            want = [(c, "untested", True) for c in CONTROLS if c != LLM_CONTROL] + [(LLM_CONTROL, "pending", False)]
            if g["status"] != "incomplete" or not (g["status_reason"] or "").startswith(POLICY_UNREADABLE + "（") \
                    or g["mode"] != "enforce" or (make_root is modeless_policy_root and "mode" not in (g["status_reason"] or "")) \
                    or g["findings_count"] != {"blocking": 0, "advisory": 0} or cov != want \
                    or g["tools"] != [gate_result.tool(TOOL_NAME, "error", version=TOOL_VERSION)] \
                    or (out / "g4-static.sarif").exists() or list(schema.iter_errors(g)):
                fails.append(f"政策讀不到（{make_root.__name__}）→ G4 incomplete、寫明原因、mode 記 enforce、靜態控制 untested、"
                             f"LLM 審查 pending、tool error、不留 SARIF（得到 {g}）")
    return fails


if __name__ == "__main__":
    sys.exit(main())
