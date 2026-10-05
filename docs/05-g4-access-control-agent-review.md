# 05 G4 架構與存取控制審查（白箱；人工 + AI）

| 項目 | 值 |
|---|---|
| 閘門 ID | `G4` |
| 性質 | 白箱；靜態規則 + LLM 輔助分流 + 人工裁決；重大變更、AI 生成模組上線前 |
| 設定 | `vibesec.yaml` → `gates.g4_access_control_review`（`static_checks: [owner_binding, supabase_rls, single_middleware_authz, agent_tool_allowlist, rules_file_unicode, mcp_resource_indicator]`、`llm_review: true`、`roles: [architecture, identity-authz]`、`high_impact_actions_require_hitl: true`、`diff_aware: true`、`timeout_seconds: 900`） |
| 規則 | `config/semgrep/vibesec-rules.yaml`（`vibesec.g4.*`）、`config/catalogs/`；審查流程見 `docs/09-multi-model-review.md` |
| 負責 | AppSec / 治理（主持）、架構師、identity-authz reviewer |

## 對抗成因

**前端防禦假象**：AI 為了「畫面能動」把授權做在 UI（隱藏按鈕、前端路由守衛），後端 API 既不驗 Session 也不檢查資源歸屬。Base44 案例用 `app_id` 當校驗依據，任何人只要知道 ID 就能註冊進私有應用。這類缺陷無法用語法規則完全抓到，需要「這個端點應該屬於誰」的架構知識，所以 G4 是白箱閘門中唯一人工 + AI 的一道。

**單層授權**：CVE-2025-29927（Next.js，CVSS 9.1）——攻擊者送 `x-middleware-subrequest` 標頭即可讓 middleware 被跳過；所有只靠 middleware 判斷的授權全數失效。教訓：授權必須在資料層再做一次。

**Agent 過度代理**：通用 Agent 被掛上 `delete_user`、`execute_sql`；Replit 事件中 Agent 無視凍結指令刪除正式資料庫。工具清單就是 Agent 的權限邊界。

**Rules File Backdoor**：`.cursorrules` / `AGENTS.md` 內嵌零寬或 bidi 字元，人眼看不到、AI 看得到，使助手悄悄加入外送程式碼或改用惡意套件（MAESTRO-L7）。

## 觸發時機與性質

- 每次 PR 跑靜態部分（`diff_aware: true`；秒–分級）。
- **重大變更**（新端點、新資料表、新 Agent / 工具、新 MCP 伺服器）與 **AI 生成模組上線前**跑完整審查（靜態 + LLM 分流 + 人工）。
- 性質：靜態高確定性項目（RLS 停用、工具清單含 `execute_sql`、隱形 Unicode）為 blocking；架構判斷為 advisory 並進 `risk_register.json`。LLM 審查結果**永遠**只是 E0/E1 線索（VulDetectBench：定位根因 < 30%），升級需人工。

## 核心任務

### 1. owner binding：每筆查詢綁定當前已驗證主體（`owner_binding`）

規則：資源查詢 / 更新 / 刪除必須同時含 `id = :id` **且** `owner_id = :current_user`（或等價 tenant 條件），主體來自已驗證 Token，不來自請求參數。

```python
# ✘ BAD（Python + SQLAlchemy）：只用 id；任何登入者改 URL 就能讀別人的
@router.get("/todos/{todo_id}")
def get_todo(todo_id: int, db: Session = Depends(get_db), user=Depends(current_user)):
    return db.query(Todo).filter(Todo.id == todo_id).first()

# ✔ GOOD：綁定 owner；查不到就 404（不洩漏存在性）
@router.get("/todos/{todo_id}")
def get_todo(todo_id: int, db: Session = Depends(get_db), user=Depends(current_user)):
    todo = db.query(Todo).filter(Todo.id == todo_id, Todo.owner_id == user.id).first()
    if todo is None:
        raise HTTPException(status_code=404)
    return todo
# 等價 SQL：SELECT * FROM todos WHERE id = :id AND owner_id = :current_user
```

```ts
// ✘ BAD（Supabase JS；若該表未啟用 RLS，anon key 即可讀全表）
const { data } = await supabase.from('todos').select('*').eq('id', id)

// ✔ GOOD：RLS 啟用（資料層）+ 查詢仍明確綁定 user（縱深）
const { data: { user } } = await supabase.auth.getUser()
const { data } = await supabase.from('todos').select('*').eq('id', id).eq('user_id', user.id)
```

靜態規則 `vibesec.g4.missing-owner-filter`（py）/ `-supabase-js`（advisory，CWE-639）；黑箱證實由 G5 `vibesec.g5.bola-cross-account`。

### 2. Supabase Row Level Security（`supabase_rls`）

Supabase 前端直連資料庫，RLS 是唯一的資料層授權；新建表**預設不啟用**。

```sql
-- 每張含使用者資料的表都要
alter table public.todos enable row level security;

create policy "todos_select_own" on public.todos
  for select using (auth.uid() = owner_id);
create policy "todos_insert_own" on public.todos
  for insert with check (auth.uid() = owner_id);
create policy "todos_update_own" on public.todos
  for update using (auth.uid() = owner_id) with check (auth.uid() = owner_id);
create policy "todos_delete_own" on public.todos
  for delete using (auth.uid() = owner_id);

-- 多租戶：改比 tenant_id = (auth.jwt() ->> 'tenant_id')::uuid
```

規則：`vibesec.g4.supabase-rls-disabled`（`disable row level security`，blocking，CWE-284）、`vibesec.g4.supabase-table-without-rls`（同一 migration 建表但無 enable，advisory）。`service_role` key 只能在伺服器端使用（G2 有專用規則）。

### 3. 單一 middleware 授權 → 資料層縱深防禦（`single_middleware_authz`）

檢查項（LLM 輔助 + 人工）：

- 授權邏輯是否只存在於 `middleware.ts` / 全域 `before_request` / API Gateway authorizer？
- 服務層函式被直接呼叫（背景工作、內部 RPC、另一條路由）時是否仍檢查？
- 資料層是否有 RLS / owner filter 作為最後一道？

修法：三層都做——路由層（middleware，快速拒絕）、服務層（`assert_owner(user, resource)`）、資料層（RLS / `WHERE owner_id`）。規則 `vibesec.g4.single-middleware-authz`（advisory，CWE-287 / CWE-863）。

### 4. Agent 工具 allow-list（`agent_tool_allowlist`）

原則：**通用 Agent 永遠不得暴露 `delete_user`、`execute_sql`、`drop_table`、`rm -rf`、任意 HTTP**。工具要細粒度（`get_my_todos`、`create_todo`），且以當前使用者身分執行（工具內部仍走 owner binding）。

OPA / Rego 白名單範例（由工具執行器在每次呼叫前查詢）：

```rego
package vibesec.agent_tools

default allow := false

# 通用助理：只允許讀取與低影響寫入
allowed_tools := {
  "general_assistant": {"get_my_todos", "create_todo", "update_my_todo", "search_docs"},
  "ops_agent":         {"get_service_status", "restart_service"},
}

high_impact := {"delete_todo", "delete_user", "execute_sql", "drop_table", "transfer_funds", "restart_service", "send_email"}

allow if {
  input.tool in allowed_tools[input.agent]
  not input.tool in high_impact
}

# 高影響工具：需有效的人工核准票（HITL）
allow if {
  input.tool in allowed_tools[input.agent]
  input.tool in high_impact
  input.approval.approved_by != ""
  time.now_ns() < input.approval.expires_ns
}
```

靜態規則 `vibesec.g4.agent-tool-overexposure`（py / js，blocking，CWE-250）掃 `@tool`、`@mcp.tool()`、`tools=[…]`、`server.tool("…")`、`tool({name: …})` 中的高影響名稱。

### 5. Human-in-the-Loop（`high_impact_actions_require_hitl: true`）

高影響動作定義：刪除 / 不可逆變更、金流、對外送信 / 發布、部署、改權限、對正式 DB 寫入。要求：Agent 先產出「擬執行內容」→ 人工核准（含 diff 或 SQL 預覽）→ 才執行；核准票有時效；全部寫稽核日誌（`ASVS5-V16.1`、MAESTRO-L5）。缺 HITL → `vibesec.g4.missing-hitl`（advisory，CWE-250）。對應 threat-model 的 `agents[].high_impact_tools` 與 `mitigations: [human_in_the_loop]`。

### 6. Rules File Backdoor：隱形 Unicode 掃描（`rules_file_unicode`）

掃描 `.cursorrules`、`AGENTS.md`、`SKILL.md`、`CLAUDE.md`、`.cursor/rules/**/*.mdc`、`**/*.md`，禁止下列字元：

| 類別 | 碼位 |
|---|---|
| 零寬 | U+200B（ZWSP）、U+200C（ZWNJ）、U+200D（ZWJ）、U+2060（WJ）、U+FEFF（BOM / ZWNBSP，非檔首） |
| Bidi 控制 | U+202A–U+202E（LRE、RLE、PDF、LRO、RLO）、U+2066–U+2069（LRI、RLI、FSI、PDI） |
| 其他 | U+00AD（soft hyphen）、U+2061–U+2064、Unicode Tag 區 U+E0000–U+E007F |

```bash
# 偵測（任何輸出即 fail）
grep -rnP '[\x{200B}-\x{200D}\x{2060}\x{FEFF}\x{202A}-\x{202E}\x{2066}-\x{2069}\x{00AD}\x{2061}-\x{2064}\x{E0000}-\x{E007F}]' \
  --include='.cursorrules' --include='AGENTS.md' --include='SKILL.md' --include='CLAUDE.md' --include='*.mdc' --include='*.md' .
# 顯示實際碼位
python3 - <<'EOF'
import pathlib, unicodedata
bad = set(range(0x200B,0x200E))|{0x2060,0xFEFF,0x00AD}|set(range(0x202A,0x202F))|set(range(0x2066,0x206A))|set(range(0x2061,0x2065))|set(range(0xE0000,0xE0080))
for p in pathlib.Path('.').rglob('*'):
    if p.suffix in {'.md','.mdc'} or p.name in {'.cursorrules','AGENTS.md','SKILL.md','CLAUDE.md'}:
        for i, ch in enumerate(p.read_text(errors='ignore')):
            if ord(ch) in bad and not (i == 0 and ord(ch) == 0xFEFF):
                print(f"{p}: offset {i} U+{ord(ch):04X} {unicodedata.name(ch, '?')}")
EOF
```

規則 `vibesec.g4.rules-file-invisible-unicode`（blocking，CWE-94：隱形字元本質是對程式碼產生器的指令注入）。G1 掃規則檔時順帶執行。

### 7. MCP 伺服器 OAuth：RFC 8707 Resource Indicators（`mcp_resource_indicator`）

MCP client 向授權伺服器要 Token 時必須帶 `resource=<MCP server canonical URI>`；MCP server 驗證 `aud` 等於自己，拒絕為其他資源簽發的 Token（防 token passthrough / confused deputy）。檢查：授權請求與 token 請求含 `resource` 參數；server 端驗 `aud`；不把上游 Token 原樣轉給下游 API。缺失 → `vibesec.g4.mcp-missing-resource-indicator`（advisory，CWE-863，`ASVS5-V10.1`）。

## 自動化作法

1. **靜態**：`semgrep --config config/semgrep/vibesec-rules.yaml --baseline-commit $BASE --sarif -o reports/semgrep-g4.sarif .`（結果中 `metadata.gate == G4` 的歸 G4）+ 上述 Unicode 腳本 + `grep -rn 'disable row level security'`。
2. **LLM 輔助分流（handoff 到 reviewer）**：harness 把 diff、路由表、threat-model 的 `trust_boundaries` 與 `agents[]`、靜態結果打包，交給 `docs/09-multi-model-review.md` 定義的四角色中與 G4 相關的兩個（`roles: [architecture, identity-authz]`；`appsec` 與 `supplychain-cicd` 視變更範圍加入）。每個 reviewer 回答固定問題：
   - identity-authz：每個新 / 改端點的「主體 → 資源 → 操作」矩陣；哪裡只靠 middleware；哪裡缺 owner filter；跨租戶路徑。
   - architecture：Agent 工具清單 vs threat-model `agents[].tools`；高影響工具是否有 HITL；資料流是否新增跨邊界路徑；Lethal Trifecta 是否被重新打開。
3. **規則**：高風險控制 ≥ 2 個不同 `family`；第一輪不交換結論；最多兩輪交叉；保留少數意見；不多數決；分歧 `requires_human: true`（CLAUDE.md 規則 6）。模型意見記在 `finding.review.opinions[]`，`evidence_grade` 最高 E1，人工核對程式後才升 E2 / E3。
4. **資料分級**：未分類程式碼只能送 `config/providers.yaml` 允許的 provider（規則 7）。

## 工具與設定檔

| 用途 | 檔案 / 工具 |
|---|---|
| 靜態規則 | `config/semgrep/vibesec-rules.yaml`（`vibesec.g4.*`） |
| Unicode 掃描 | 上述 grep / python 腳本（harness 內建） |
| 工具白名單 | OPA（Rego 政策，建議放 `config/policy/agent-tools.rego`，由 AppSec 維護） |
| 審查角色提示 | `config/harness/`、`.claude/agents/`（architecture、identity） |
| 控制對照 | `config/catalogs/cwe-map.yaml`、`asvs-5.0-controls.yaml`、`llm-top10-2025.yaml`、`maestro-layers.yaml` |

## 阻擋政策

| 規則 | 層級 | CWE |
|---|---|---|
| `vibesec.g4.supabase-rls-disabled` | advisory（L3 升 blocking） | CWE-284 |
| `vibesec.g4.agent-tool-overexposure` | advisory（L3 升 blocking） | CWE-250 |
| `vibesec.g4.rules-file-invisible-unicode` | advisory | CWE-94 |
| `vibesec.g4.missing-owner-filter` | advisory（G5 證實後升 blocking） | CWE-639 |
| `vibesec.g4.single-middleware-authz` | advisory | CWE-287 / CWE-863 |
| `vibesec.g4.missing-hitl` | advisory | CWE-250 |
| `vibesec.g4.mcp-missing-resource-indicator` | advisory | CWE-863 |
| reviewer 缺席 / provider 失敗 / 分歧未裁決 | `incomplete` 或 `pending`；不得 pass | — |

CI（`pr-gates.yml` 的 G4 job）只跑靜態部分；LLM 審查由 `/vibesec-harness` 執行，結果寫成 `reports/g4-review.yaml`（`schemas/g4-review.schema.json`，範例 `docs/templates/g4-review.example.yaml`），由人複製為 `reviews/g4/<commit>.yaml` 提交（`reviews/` 受 CODEOWNERS 審核；harness 不得自行寫入）。G4 job 以 `scripts/g4_review.py gate` 讀取對 PR head **有效**的紀錄——紀錄的 `commit` 是 head 的祖先，且其後只動過 `reviews/g4/`、`rulings/`——並推導狀態：

| 情況 | G4 狀態 |
|---|---|
| 靜態 blocking，或 LLM 發現屬 blocking 且經人工裁決（`rulings/`）confirm | `fail` |
| 任一發現 `requires_human` 且無有效裁決 | `pending` |
| 無紀錄、紀錄過期、實際執行的 family < `min_families_for_high_risk`、必要角色缺席、coverage 有 pending／untested | `incomplete` |
| 其餘 | `pass` |

紀錄本身受規則約束（`g4_review.py check`，違規即 CI 失敗）：provider 名稱與 family 必須與 `config/providers.yaml` 一致；意見只能來自實際執行（`state: ran`）的 provider；分歧、少數意見、高風險發現 family 不足 → `requires_human` 必須為 true；沒有 `ruling_ref` 時 `validation_status` 只能是 `pending`、`evidence_grade` 最高 E2。也就是說，紀錄只能「誠實陳述審查發生了什麼」，不能自行宣告結論；結論只來自裁決。

**信任上限（職責分離）**：紀錄由本 PR 新增或修改時不能自證。只有在「非 PR 作者在目前 head SHA 上 approve（之後再 push 需重新 approve）」且「`recorded_by.handle` 不是 PR 作者」時，紀錄才能把 G4 推到 `pass`；否則 `pass` 降為 `pending`（`fail` 不受影響）。`recorded_by.handle` 空白（harness 產出時的預設）一律不採信。已在 base 分支上的紀錄經過另一個 PR 審查合併，照常採用。approve 由 G4 job 以 GitHub API 取得，查詢失敗視為沒有 approve（fail closed）。G4 不在 `config/policy/blocking-policy.yaml` 的 `incomplete_gate_is_blocking_in_enforce`，所以 enforce 模式下 G4 `incomplete` 不擋 merge；若要改為阻擋，須由人類在獨立 PR 修改該政策（CLAUDE.md 規則 1）。

## 對應控制（ASVS、CWE、LLM Top 10、MAESTRO）

| 類型 | ID |
|---|---|
| ASVS 5.0（節層級，自編；V7–V10、V16 為 vibesec-extension） | `ASVS5-V7.1` Session、`ASVS5-V8.1` 授權文件化、`ASVS5-V8.2` 物件層級授權、`ASVS5-V8.3` 操作層級 / 縱深、`ASVS5-V2.3` 多人審批（HITL）、`ASVS5-V10.1` OAuth 受眾、`ASVS5-V16.1` 稽核日誌 |
| vibesec | `VS-G4-AGENT-TOOL-ALLOWLIST`、`VS-G4-RULES-FILE-UNICODE`、`VS-G4-MCP-RESOURCE-INDICATOR`、`VS-G0-LETHAL-TRIFECTA` |
| CWE | `CWE-639`、`CWE-284`、`CWE-287`、`CWE-863`、`CWE-250`、`CWE-94` |
| LLM Top 10 2025 | `LLM06:2025` Excessive Agency、`LLM01:2025` Prompt Injection（Rules File）、`LLM08:2025` Vector / Embedding（向量庫租戶隔離） |
| MAESTRO | `MAESTRO-L2`（RLS）、`MAESTRO-L3`（工具、MCP）、`MAESTRO-L6`（前端假象、單層授權）、`MAESTRO-L7`（Rules File） |

## 驗證方式

1. **靜態 fixture**：`db.query(Todo).filter(Todo.id == id)` 在路由內 → advisory；加 `Todo.owner_id == user.id` → 無。`alter table … disable row level security` → blocking。`@tool def execute_sql` → blocking。`.cursorrules` 含 U+200B → blocking。
2. **審查流程**：抽樣 PR 檢查 `finding.review.opinions[]`：≥ 2 家族、round 1 無互引、分歧有 `requires_human: true`，裁決後有 `human_decision` 與 `review.ruling_ref`（指向 `rulings/<id>.yaml`，每則少數意見都有回應；格式見 docs/09 §12）。
3. **白箱 → 黑箱**：每個 G4 advisory 的 BOLA 候選都在 G5 `two-account-context.yaml` 有對應 resource；G5 結果回填 `validation_status`。
4. **OPA 單元測試**：`opa test config/policy/` 含「general_assistant 呼叫 execute_sql → deny」「ops_agent restart_service 無 approval → deny、有 approval → allow」。
5. **MCP**：以缺 `resource` 參數的授權請求測試 MCP server → 必須拒絕（401 / invalid_target）。
6. **人工簽核**：AI 生成模組上線前，identity-authz 與 architecture 各一位人員在 g4 報告簽名；少數意見保留於 `risk_register.json`。
