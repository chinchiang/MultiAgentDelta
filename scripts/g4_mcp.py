#!/usr/bin/env python3
"""G4 mcp_resource_indicator（VS-G4-MCP-RESOURCE-INDICATOR，docs/05 §7）的單檔啟發式靜態檢查。

由 .github/workflows/pr-gates.yml 的「G4 靜態檢查」步驟、scripts/g4_access.py（本機／harness 版，執行同一段步驟）
與 scripts/run_evals.py（G4 評測，同樣執行該步驟）共用。只用標準函式庫：CI 的靜態步驟在安裝 PyYAML／jsonschema 之前執行，
不能 import g4_access（它載入 g4_review，缺套件時直接結束）。

用法：python3 scripts/g4_mcp.py selftest
"""
from __future__ import annotations
import pathlib, re, sys, tempfile

# mcp_resource_indicator（docs/05 §7）：MCP client 要 Token 時帶 resource=<MCP server URI>（RFC 8707），server 驗 aud 等於自己。
# 啟發式、只看單一檔案：檔案是 MCP 程式碼或設定（mcp SDK import、mcpServers），同檔案有 OAuth／Token 驗證脈絡，
# 但看不到 resource／audience 綁定，或明確關掉 aud 驗證 → vibesec.g4.mcp-missing-resource-indicator（tier 取自 blocking-policy）。
# 綁定做在其他檔案（共用 auth 模組、gateway）時會誤報；同檔案有 resource 字樣也不代表 server 真的驗 aud、沒有 token passthrough——
# 這兩者交 LLM 審查（VS-G4-LLM-REVIEW）。樣式刻意只認 import 行與設定鍵這類結構：本檔的 regex 原文不會讓本 repo 命中自己。
MCP_RULE, MCP_CONTROL = "vibesec.g4.mcp-missing-resource-indicator", "VS-G4-MCP-RESOURCE-INDICATOR"
MCP_EXTS = (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".json", ".yaml", ".yml", ".toml")
MCP_SKIP = (".git/", "node_modules/", ".github/", "evals/cases/", "_trusted/", "reports/")
MCP_CTX = re.compile(r'^\s*(?:from|import)\s+(?:fast)?mcp\b|["\']@modelcontextprotocol/|["\']mcpServers["\']\s*:|^\s*mcpServers\s*:', re.M)
OAUTH_CTX = re.compile(r'oauth|authorization_endpoint|token_endpoint|grant_type|client_credentials|authorization_code|'
                       r'\bTokenVerifier\b|\bAuthSettings\b|\bverify_token\b|jwt\.(?:decode|verify)\b|\bjwtVerify\b|access_token|\bBearer\b', re.I)
AUD_BIND = re.compile(r'\bresource\s*=\s*["\'\w]|["\']resource["\']\s*:|\bresource\s*:\s*(?![\s{\[])|\bresource_(?:server_)?url\b|'
                      r'\bresource(?:Server)?Url\b|\baudience\s*[=:]|["\']aud(?:ience)?["\']|\.aud\b|\bexpected_aud\w*')
AUD_OFF = re.compile(r'["\']?verify_aud["\']?\s*[:=]\s*(?:False|false|0)\b|\bignoreAudience\s*:\s*true')


def mcp_resource_check(root: pathlib.Path) -> tuple[list[tuple[str, int, str]], dict]:
    """掃 root 下的 MCP 程式碼／設定。回傳 ([(路徑, 行號, 訊息)], VS-G4-MCP-RESOURCE-INDICATOR 的 coverage)。"""
    hits, mcp_files, oauth_files = [], 0, 0
    for f in sorted(root.rglob("*")):
        rel = f.relative_to(root).as_posix()
        if f.is_symlink() or not f.is_file() or not rel.endswith(MCP_EXTS) or rel.startswith(MCP_SKIP) or "/node_modules/" in rel:
            continue
        try:
            body = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not MCP_CTX.search(body):
            continue
        mcp_files += 1
        m = OAUTH_CTX.search(body)
        if not m:
            continue
        oauth_files += 1
        off = AUD_OFF.search(body)
        if off:
            hits.append((rel, body.count("\n", 0, off.start()) + 1,
                         f"{rel}：MCP 的 Token 驗證明確關閉 aud 檢查，會接受為其他資源簽發的 Token（confused deputy／token passthrough）"))
        elif not AUD_BIND.search(body):
            hits.append((rel, body.count("\n", 0, m.start()) + 1,
                         f"{rel}：MCP 程式碼有 OAuth／Token 流程，同檔案未見 RFC 8707 resource 參數或 aud／audience 驗證；"
                         "client 要 Token 時須帶 resource=<MCP server URI>，server 須驗 aud 等於自己（若綁定做在其他檔案，於 LLM 審查說明）"))
    if hits:
        cov = {"control_id": MCP_CONTROL, "state": "fail", "reason": f"{len(hits)} 個 MCP 檔案缺 resource／audience 綁定"}
    elif not mcp_files:
        cov = {"control_id": MCP_CONTROL, "state": "not_applicable", "reason": "未發現 MCP 程式碼或設定（mcp SDK import、mcpServers）"}
    elif not oauth_files:
        cov = {"control_id": MCP_CONTROL, "state": "not_applicable",
               "reason": f"{mcp_files} 個 MCP 檔案未見 OAuth／Token 流程（stdio 或未授權的 server 不適用 RFC 8707；是否該有授權交 LLM 審查）"}
    else:
        cov = {"control_id": MCP_CONTROL, "state": "pass",
               "reason": f"啟發式：{oauth_files} 個 MCP OAuth 檔案皆見 resource／audience 綁定；token passthrough 與驗證順序交 LLM 審查"}
    return hits, cov


def selftest() -> list[str]:
    fails: list[str] = []
    # mcp_resource_indicator（docs/05 §7）：只看 MCP 程式碼／設定；樣式在執行期組出，避免本檔原文命中自己的檢查
    imp, srv = "from " + "mcp.server.fastmcp import FastMCP\n", "mcp = Fast" + "MCP('notes')\n"
    mcp_cases = {
        "無 MCP": ({"app.py": "import requests\ntoken = requests.post(url, data={'grant_type': 'client_credentials'})\n"},
                   "not_applicable", 0),
        "MCP 無 OAuth": ({"server.py": imp + srv}, "not_applicable", 0),
        "MCP OAuth 缺綁定": ({"server.py": imp + srv + "claims = jwt.decode(tok, key, algorithms=['RS256'])\n"}, "fail", 1),
        "MCP OAuth 關掉 aud": ({"server.py": imp + srv + "claims = jwt.decode(tok, key, audience=URI, options={'verify_aud': False})\n"},
                               "fail", 1),
        "MCP OAuth 驗 aud": ({"server.py": imp + srv + "claims = jwt.decode(tok, key, algorithms=['RS256'], audience=SERVER_URI)\n"},
                             "pass", 0),
        "TS client 帶 resource": ({"client.ts": "import { Client } from \"@" + "modelcontextprotocol/sdk/client/index.js\";\n"
                                                "const body = new URLSearchParams({ grant_type: 'authorization_code', code, "
                                                "resource: 'https://mcp.example.com' });\n"}, "pass", 0),
        "MCP fixture 在 evals/cases": ({"evals/cases/g4/x.py": imp + "jwt.decode(t, k)\n"}, "not_applicable", 0),
    }
    for label, (files, state, n) in mcp_cases.items():
        with tempfile.TemporaryDirectory() as d:
            for rel, body in files.items():
                (pathlib.Path(d) / rel).parent.mkdir(parents=True, exist_ok=True)
                (pathlib.Path(d) / rel).write_text(body, encoding="utf-8")
            hits, cov = mcp_resource_check(pathlib.Path(d))
            if cov["state"] != state or len(hits) != n or (state == "not_applicable" and not cov["reason"]):
                fails.append(f"mcp_resource_indicator「{label}」→ {state}、{n} 筆（得到 {cov['state']}、{len(hits)} 筆：{cov['reason']}）")
    return fails


if __name__ == "__main__":
    if sys.argv[1:2] == ["selftest"]:
        _fails = selftest()
        for f in _fails:
            print(f"FAIL {f}")
        print("selftest 通過" if not _fails else f"selftest 失敗 {len(_fails)} 項")
        sys.exit(1 if _fails else 0)
    print(__doc__.strip()); sys.exit(4)
