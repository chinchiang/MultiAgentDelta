#!/usr/bin/env python3
"""agent 訊號（agent signal）的偵測樣式：受驗樹中顯示系統含有 agent 或 LLM 的證據。

G4 靜態檢查（scripts/g4_static.py 的 allow-list lint 與 HITL 檢查）、MCP resource indicator 檢查（scripts/g4_mcp.py）
共用這裡的樣式；G0 的交叉核對（#380）也會用到。本模組只放樣式與純函式，不讀檔、不列檔：
掃描範圍與讀檔失敗的處理由各呼叫端負責。

只用標準函式庫：CI 的 G4 靜態步驟在安裝 PyYAML／jsonschema 之前執行（見 g4_mcp.py 檔頭）。

用法：python3 scripts/agent_signals.py selftest
"""
from __future__ import annotations
import pathlib, re, sys

# Agent 工具註冊脈絡（自 g4_static.scan() 原樣搬出，#379）：@tool／@mcp.tool、register_tool、tools=[…]／tools: …、.tool(、tool({
TOOL_CTX = re.compile(r'@(?:\w+\.)?tool\b|register_tool|\btools\s*[=:]|\.tool\(|\btool\(\s*\{', re.I)

# MCP 程式碼或設定的判定範圍與樣式（自 g4_mcp.py 原樣搬出，#379）：mcp SDK 的 import 行、@modelcontextprotocol/ 套件、
# mcpServers 設定鍵。樣式刻意只認 import 行與設定鍵這類結構：本檔的 regex 原文不會讓本 repo 命中自己。
MCP_EXTS = (".py", ".ts", ".tsx", ".js", ".mjs", ".cjs", ".json", ".yaml", ".yml", ".toml")
MCP_SKIP = (".git/", "node_modules/", ".github/", "evals/cases/", "_trusted/", "reports/")
MCP_CTX = re.compile(r'^\s*(?:from|import)\s+(?:fast)?mcp\b|["\']@modelcontextprotocol/|["\']mcpServers["\']\s*:|^\s*mcpServers\s*:', re.M)


def tool_names(body: str) -> list[tuple[str, int]]:
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


def selftest() -> list[str]:
    # fixture 刻意不用高危或高影響的工具名稱（g4_static 的 DANGEROUS／HI_TOOL），mcpServers 鍵與 MCP 套件前綴也在執行時才組出來：
    # G4 會掃本 repo，本檔的原文不得讓本 repo 命中自己（同 g4_mcp.py 的做法）
    fails, servers, sdk = [], "mcp" + "Servers", "@" + "modelcontextprotocol/"
    cases = [
        ("@tool 下一個 def", "from x import tool\n@tool\ndef search_docs(query):\n    pass\n", [("search_docs", 3)]),
        ("@mcp.tool() 與 async def", "@mcp.tool()\nasync def get_weather(city):\n    ...\n", [("get_weather", 2)]),
        ("tools=[…] 清單", "agent = Agent(tools=[search, summarize])\n", [("search", 1), ("summarize", 1)]),
        ("YAML tools: 區塊", "tools:\n  - list_files\n  - name: read_note\nother: 1\n",
         [("list_files", 2), ("read_note", 3)]),
        ("register_tool 與 server.tool", 'register_tool("geo-lookup")\nserver.tool("lookup", fn)\n',
         [("geo-lookup", 1), ("lookup", 2)]),
        ("tool({name: …})（Vercel AI SDK）", 'const t = tool({ name: "fetch_page" })\n', [("fetch_page", 1)]),
        ("tools: { x: tool({…}) }", "const tools = { translate: tool({ execute }) }\n", [("translate", 1)]),
        ("LangChain Tool(name=…)", 'Tool(name="calc", func=f)\nStructuredTool.from_function(name="echo")\n',
         [("calc", 1), ("echo", 2)]),
        ("沒有工具註冊", "def helper():\n    return 'tools are nice'\n", []),
    ]
    for label, body, want in cases:
        got = tool_names(body)
        if got != want:
            fails.append(f"tool_names「{label}」應得 {want}，得到 {got}")
    for label, body, want in [
            ("@tool", "@tool\ndef f(): pass\n", True), ("@mcp.tool", "@mcp.tool()\ndef f(): pass\n", True),
            ("register_tool", "register_tool('x')\n", True), ("tools=", "Agent(tools=[a])\n", True),
            ("tools:", "tools:\n  - a\n", True), (".tool(", "server.tool('x', f)\n", True),
            ("tool({", "tool({ name: 'x' })\n", True),
            ("散文裡的 tools", "We use many tools in this project.\n", False),
            ("toolbox 不是工具註冊", "toolbox = load()\n", False)]:
        if bool(TOOL_CTX.search(body)) != want:
            fails.append(f"TOOL_CTX「{label}」應為 {want}")
    for label, body, want in [
            ("from mcp import", "from mcp.server.fastmcp import FastMCP\n", True),
            ("import fastmcp", "import fastmcp\n", True),
            ("modelcontextprotocol 的 npm 套件", 'import { Server } from "' + sdk + 'sdk/server";\n', True),
            ("JSON 的 mcpServers", '{"' + servers + '": {"x": {}}}\n', True),
            ("YAML 的 mcpServers", servers + ":\n  x: {}\n", True),
            ("散文提到 mcp", "This project talks about mcp servers.\n", False),
            ("mcp 開頭的其他模組", "import mcpkit\n", False)]:
        if bool(MCP_CTX.search(body)) != want:
            fails.append(f"MCP_CTX「{label}」應為 {want}")
    # G4 會掃本 repo：本檔的原文不得被當成 MCP 檔案，也不得抽出 g4_static 的高危工具名稱（L3 下為 blocking）
    own = pathlib.Path(__file__).read_text(encoding="utf-8")
    if MCP_CTX.search(own):
        fails.append("本檔原文不得命中 MCP_CTX（fixture 的 mcpServers 鍵、MCP 套件前綴要在執行時組出來）")
    danger = [n for n, _ in tool_names(own) if n.lower() in ("delete" + "_user", "execute" + "_sql", "drop" + "_table")]
    if danger:
        fails.append(f"本檔原文不得抽出高危工具名稱（得到 {danger}）")
    if ".json" not in MCP_EXTS or ".py" not in MCP_EXTS or "evals/cases/" not in MCP_SKIP or "_trusted/" not in MCP_SKIP:
        fails.append(f"MCP_EXTS／MCP_SKIP 應涵蓋 .py、.json 與 evals/cases/、_trusted/（得到 {MCP_EXTS}、{MCP_SKIP}）")
    return fails


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["selftest"]:
        fails = selftest()
        for f in fails:
            print(f"FAIL {f}")
        print("selftest 通過" if not fails else f"selftest 失敗 {len(fails)} 項")
        return 1 if fails else 0
    print(__doc__)
    return 4


if __name__ == "__main__":
    sys.exit(main())
