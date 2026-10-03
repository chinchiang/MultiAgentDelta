# 01 G0 威脅建模（設計期前置）

| 項目 | 值 |
|---|---|
| 閘門 ID | `G0` |
| 性質 | 設計期、人工為主、文件化產出；不是自動掃描 |
| 設定 | `vibesec.yaml` → `gates.g0_threat_model`（`trigger`、`methodologies`、`lethal_trifecta_check: required`）、`project.threat_model`、`risk_tier` |
| 輸入模板 | `docs/templates/threat-model.yaml`（符合 `schemas/threat-model.schema.json`） |
| 輸出模板 | `docs/templates/g0-report.md` |
| 負責 | AppSec / 治理（主持）、架構師（填寫）、Red Team（挑戰） |

## 對抗成因

G0 對抗的是 Vibe Coding 的兩個結構性問題：

1. **上下文破碎**：AI 每次只看得到一個檔案、一個函式、一個 prompt，看不到資料從哪裡來、流經哪些元件、最後存到哪裡。信任邊界對模型是隱形的，所以它會把「使用者輸入」「LLM 輸出」「外部網頁」一律當成可信字串處理。
2. **Agent 過度代理**：為了讓功能「能動」，AI 傾向要最大權限：直連正式資料庫、拿 service_role key、掛上 `execute_sql` 工具。Replit AI Agent 刪除正式資料庫並生成 4000 筆假資料（OWASP LLM06 Excessive Agency）就是沒有在設計期劃定 Agent 能力邊界的結果。

G0 的角色是在寫第一行程式碼前，把這兩件事變成**明文**：資料流圖、信任邊界、Agent 能力盤點、風險分級。沒有這份明文，後面六道閘門不知道該掃多深、哪些控制 `not_applicable`。

## 觸發時機與性質

`gates.g0_threat_model.trigger: [design, major_change, agent_introduction]`：

| 觸發 | 說明 | 產出要求 |
|---|---|---|
| `design` | 新系統 / 新服務設計 | 完整 threat-model.yaml + g0-report.md |
| `major_change` | 重大架構變更：新增對外介面、新增資料儲存、改變驗證方式、新增第三方整合 | 更新受影響的 flows / trust_boundaries / threats，重算 risk_tier |
| `agent_introduction` | 導入 LLM Agent、MCP 伺服器、新工具，或既有 Agent 新增能力 | 更新 `agents[]`，重跑 Lethal Trifecta 檢驗 |

性質：**阻擋性文件閘門**。`project.threat_model` 指向的檔案不存在或不符 schema → G0 狀態 `incomplete`（`status_reason: "threat model missing"`），harness 不得把 `risk_tier` 當成已決定；在 `enforce` 模式下 G0 incomplete 使 exit code 為 2。

## 核心任務

### 1. 回答四個問題（OWASP Threat Modeling / Threat Modeling Manifesto）

| 問題 | 在 threat-model.yaml 的落點 |
|---|---|
| 我們在做什麼？（What are we working on?） | `system`、`assets[]`、`components[]`、`flows[]`、`trust_boundaries[]` |
| 會出什麼錯？（What can go wrong?） | `threats[]`（category 為 STRIDE / LINDDUN 類別或 `MAESTRO-Lx`） |
| 如何處理？（What are we going to do about it?） | `threats[].mitigation`、`threats[].gate`（由哪道執行閘門驗證）、`agents[].mitigations` |
| 做得夠好嗎？（Did we do a good enough job?） | `risk_tier` + `risk_tier_rationale`、`decisions[]`；之後由 G1–G6 的 coverage 回答 |

### 2. 選方法論（`methodologies`）

| 方法論 | 適用 | 類別 |
|---|---|---|
| **STRIDE** | 一般 Web / API 應用（預設） | Spoofing、Tampering、Repudiation、Information disclosure、Denial of service、Elevation of privilege |
| **LINDDUN** | 處理個資（`data_sensitivity: pii` 或 `sensitive_pii_or_secrets`）時加入 | Linking、Identifying、Non-repudiation、Detecting、Data disclosure、Unawareness、Non-compliance |
| **MAESTRO** | 含 LLM / Agent（`components[].kind` 有 `llm`、`agent`、`tool`、`mcp_server`、`vector_store`）時必選 | 七層，見第 6 節 |

### 3. 畫 DFD 與信任邊界

每條 `flows[]` 寫清楚 `from / to / data / protocol / authenticated / crosses_boundary`。對 Vibe Coding 應用特別要畫出的四條流：

```
[瀏覽器] ──HTTP(JWT)──► [API] ──SQL──► [DB]
                          │
                          ├──prompt──► [LLM] ──completion──► [API]   ← LLM 輸出是「不可信輸入」，跨邊界
                          │
                          └──tool call──► [Agent tools] ──► [外部 API / DB 寫入 / shell]   ← 對外通訊能力
[外部文件 / 網頁 / Email] ──RAG──► [vector_store] ──context──► [LLM]   ← 不受信任內容進入 prompt
```

信任邊界至少三條：`internet ↔ app`、`app ↔ data`、`app ↔ llm/agent`。LLM 與 Agent 自成一個區域（zone），因為模型輸出可被間接注入操控。

### 4. 風險分級決策樹（暴露面 × 資料敏感度 × Agent 能力）

對應 schema 欄位：`system.exposure`（`internal | partner | public`）、`system.data_sensitivity`（`none | business | pii | sensitive_pii_or_secrets`）、`agents[]`（能力與 mitigations）。

```
START
 ├─ system.exposure == internal
 │    └─ data_sensitivity ∈ {none, business} 且 agents == [] 且 contains_llm == false ──► L1
 │    └─ 否則 ──► 往下
 ├─ data_sensitivity ∈ {pii, sensitive_pii_or_secrets}
 │    └─ exposure ∈ {partner, public} 且 任一 agent 的 can_communicate_externally == true
 │         且 high_impact_tools 非空 ──► L3
 │    └─ 否則 ──► L2（建議 L3 若 sensitive_pii_or_secrets）
 └─ 其餘（對外或處理業務資料的一般企業應用）──► L2
```

決定後寫入 `threat-model.yaml.risk_tier` 與 `vibesec.yaml.risk_tier`，並填 `risk_tier_rationale`。兩處不一致 → G0 `fail`。

### 5. 致命三要素（Lethal Trifecta）硬規則

Simon Willison 定義的三要素，對應 `agents[]` 三個布林欄位：

| 要素 | 欄位 | 例子 |
|---|---|---|
| 存取私有資料 | `accesses_private_data` | 讀使用者待辦、客戶資料、內部文件、環境變數 |
| 暴露於不受信任外部內容 | `exposed_to_untrusted_content` | 網頁、Email、PDF、外部 JSON、使用者上傳、RAG 來源 |
| 對外通訊或執行能力 | `can_communicate_externally` | 發 HTTP、寫 DB、呼叫外部 API、執行指令、送 Email |

**硬規則**（`lethal_trifecta_check: required`）：三者皆 `true` 且 `mitigations` 為空 → G0 `fail`，設計不得放行；必須在設計期**切斷至少一隻腳**並記錄 `trifecta_leg_cut`：

| 切哪隻腳 | `mitigations` 值 | 做法 |
|---|---|---|
| 對外通訊 | `sandbox` | Agent 在無網路 / 唯讀檔案系統的沙箱執行 |
| 對外通訊 | `egress_allowlist` | 出向只允許列舉的網域與方法（例如只能呼叫公司內部 API） |
| 對外通訊 | `tool_allowlist` | 工具 allow-list，移除寫入 / 刪除 / shell / 任意 HTTP（見 docs/05） |
| 私有資料 | `read_only_data` | 只給唯讀、去識別化或範圍限定（當前使用者）的資料 |
| 不受信任內容 | `no_untrusted_input` | 不讓外部文件 / 網頁進入同一個上下文；或先經結構化擷取 |
| （補償） | `human_in_the_loop` | 高影響動作需人工確認；**不算切腳**，只能與上列之一並用 |

控制 ID：`VS-G0-LETHAL-TRIFECTA`；由 G4（靜態確認 allow-list / HITL）與 G6（間接注入是否真的觸發外連）驗證。

### 6. 文件化安全決策

`decisions[]` 記錄每個被接受的風險與理由（例如「staging 開啟 Swagger UI，正式關閉」）。這同時滿足 ASVS 5.0 的文件化安全決策（`ASVS5-V15.1`、各章 x.1 文件化節如 `ASVS5-V2.1`、`ASVS5-V13.1`）與 ISO 27001:2022 的風險處置紀錄；NIST AI RMF 1.0 的 **Map** 功能（盤點情境、能力、影響、風險容忍度）由 `system`、`agents[]`、`risk_tier_rationale` 共同覆蓋。

## 自動化作法

G0 本身是人工活動，但 harness 做四件確定性檢查：

1. `project.threat_model` 存在且通過 `schemas/threat-model.schema.json` 驗證（`python3 scripts/validate.py`）。
2. Lethal Trifecta：對每個 `agents[]` 計算三布林；全 true 且 `mitigations == []` → finding `rule_id: vibesec.g0.lethal-trifecta-open`（`control_id: VS-G0-LETHAL-TRIFECTA`，policy blocking）。
3. `risk_tier` 一致性：threat-model 與 `vibesec.yaml` 相同；且決策樹推導值不低於宣告值（宣告 L1 但有 `public` 暴露 → fail，附推導路徑）。
4. 覆蓋對照：每條 `threats[].gate` 指向的閘門必須 `enabled: true`；`contains_llm: true` 但 methodologies 無 MAESTRO → advisory。

LLM 輔助（非裁決）：harness 可請 `architecture` reviewer 依 DFD 提出遺漏的威脅候選，標 `evidence_grade: E0/E1`，由人決定是否收進 `threats[]`。

## 工具與設定檔

| 用途 | 檔案 / 工具 |
|---|---|
| 威脅模型輸入 | `docs/templates/threat-model.yaml`、`schemas/threat-model.schema.json` |
| 報告 | `docs/templates/g0-report.md` |
| 分級參數 | `vibesec.yaml` → `risk_tier`、`gates.g0_threat_model` |
| MAESTRO 對照 | `config/catalogs/maestro-layers.yaml` |
| 畫圖（可選） | OWASP Threat Dragon、pytm（程式化 DFD）、draw.io；圖檔放 `docs/threat-models/` |

## 阻擋政策

| 條件 | 結果 |
|---|---|
| threat-model 缺失 / 不符 schema | `incomplete`（enforce 時 exit 2） |
| Lethal Trifecta 全 true 且無 mitigation | `fail`（blocking） |
| `risk_tier` 兩處不一致或低於推導值 | `fail`（blocking） |
| `contains_llm: true` 但未用 MAESTRO | advisory |
| `threats[]` 為空但 exposure 為 public | advisory（要求至少列 STRIDE 六類各一） |

## 風險分級 → 閘門深度

| `risk_tier` | 啟用閘門 | 深度要求 | 工具組合（docs/11） |
|---|---|---|---|
| **L1** 純內部、不含 LLM、不處理個資 | G1、G2；G3–G6 記 `not_applicable` 並附理由（例如「internal, no LLM」） | G1 冷卻期 + 黑名單；G2 全歷史 | 全開源：Semgrep CE + Trivy + Gitleaks |
| **L2** 對外或處理業務資料 | G1–G6 全開 | G3 需跨檔污點（Semgrep Pro 或夜間 CodeQL）；G5 需雙帳號 BOLA；G6 五項檢查 | Semgrep Pro / CodeQL + Socket / DevSentinel + Trivy + Burp Suite Pro + PyRIT / promptfoo |
| **L3** 對外 + 個資 / 商業機密 + 高權限 Agent | G1–G6 全開且深度加倍 | 正式威脅建模（ASVS 5.0 L3 明列）；委外滲透；商用 AI 紅隊平台；沙箱隔離 + HITL 為必要；`review.min_families_for_high_risk` 建議提高到 3 | Checkmarx / Snyk + SonarQube AI Code Assurance + 商用 DAST + 委外滲透；對齊 EU CRA / ISO 27001 |

## MAESTRO 七層對照表（CSA，2025 年 2 月）

| 層 | 名稱 | 威脅 | Vibe Coding 失守案例 | 閘門 |
|---|---|---|---|---|
| `MAESTRO-L1` | Foundation Models | 越獄、幻覺、輸出被當成可信 | 直接安裝模型推薦的不存在套件（Slopsquatting）；聊天機器人被越獄 | G6、G1 |
| `MAESTRO-L2` | Data Operations | RAG 來源植入指令、資料層無存取控制、向量庫投毒 | Supabase 未啟用 RLS 全表暴露；RAG 匯入的 PDF 含「ignore previous instructions」 | G4、G6 |
| `MAESTRO-L3` | Agent Frameworks | 工具缺 allow-list、System Prompt 寫死金鑰、MCP 工具描述投毒 | 通用 Agent 掛 `execute_sql`；金鑰寫在 prompt 模板；MCP 未用 RFC 8707 | G4、G2 |
| `MAESTRO-L4` | Deployment & Infrastructure | Agent 對正式 DB 破壞性權限、IaC 未強制 IMDSv2、容器 root | Replit 刪庫；AI 生成 Terraform 省略 `metadata_options` | G3、G4 |
| `MAESTRO-L5` | Evaluation & Observability | 缺稽核日誌、未設用量限制（Denial of Wallet） | 聊天端點無 Token 配額；工具呼叫未記錄 | G6、治理監控 |
| `MAESTRO-L6` | Security & Compliance | 前端防禦假象、單層授權繞過、合規證據缺失 | Base44 以 app_id 當校驗；CVE-2025-29927 middleware 繞過 | G4、G5 |
| `MAESTRO-L7` | Agent Ecosystem | 過度信任 AI、Rules File Backdoor、供應鏈蠕蟲濫用本機 AI CLI | Nx s1ngularity / Shai-Hulud；`.cursorrules` 零寬字元；Perry et al. 的 automation bias | G0、G1 |

機讀版：`config/catalogs/maestro-layers.yaml`。每個 `components[]` 可填 `maestro_layer`（1–7），harness 用它把 G4 / G6 發現對到層。

## 對應控制（ASVS、CWE、LLM Top 10、MAESTRO）

| 類型 | ID | 說明 |
|---|---|---|
| ASVS 5.0（節層級，自編） | `ASVS5-V15.1` | 安全編碼與架構文件：威脅建模、文件化決策 |
| ASVS 5.0 | `ASVS5-V2.1`、`ASVS5-V5.1`、`ASVS5-V8.1`、`ASVS5-V13.1` | 各章文件化節：輸入驗證規則、檔案規範、授權矩陣、環境組態差異 |
| vibesec | `VS-G0-LETHAL-TRIFECTA`、`VS-G0-RISK-TIER` | 三要素切腳、分級已決定 |
| CWE | `CWE-250`（過度權限）、`CWE-1427`（LLM prompt 輸入未中和） | G0 威脅條目常對到的根因 CWE，正式 CWE 由執行閘門填 |
| LLM Top 10 2025 | `LLM06:2025` Excessive Agency、`LLM01:2025` Prompt Injection、`LLM03:2025` Supply Chain | Agent 能力盤點直接對應 |
| MAESTRO | `MAESTRO-L1`–`MAESTRO-L7` | 見上表 |
| 合規 | NIST AI RMF 1.0 Map；ASVS 5.0.0 L3 正式威脅建模；ISO 27001:2022 風險評鑑與處置紀錄 | 以 `decisions[]` 與 g0-report 為證據 |

ASVS ID 為 vibesec 自編到節，非官方需求編號（見 `config/catalogs/asvs-5.0-controls.yaml` 免責）。

## 驗證方式

1. **Schema 驗證**：`python3 scripts/validate.py` 對 `project.threat_model` 跑 `threat-model.schema.json`。
2. **Trifecta 單元測試**：`evals/` 內含正例（三 true 無 mitigation → fail）與反例（三 true + `tool_allowlist` → pass）。
3. **分級一致性**：以 `system.exposure × data_sensitivity × agents` 重算，與宣告值比對。
4. **人工審查**：AppSec 與 Red Team 各一人簽核 g0-report.md；分歧記錄為少數意見，不多數決（CLAUDE.md 規則 6）。
5. **下游回饋**：G1–G6 的 `coverage[]` 中每個 `control_id` 應能回溯到 `threats[].gate`；G6 若證實間接注入可外連，而 G0 宣稱已切斷 `external_comms` → 回頭把 G0 標 `fail` 並重審。

## 常見錯誤

- 把「有 HITL」當成已切斷三要素：HITL 是補償，不是切腳。
- 把 LLM 輸出畫在信任邊界內：模型輸出必須視為不可信輸入（這也是 G3 污點來源包含 LLM 輸出的理由）。
- `risk_tier` 只寫在 vibesec.yaml、threat-model 沒更新：G0 會 fail。
- 用模型自評信心當證據等級：模型提出的威脅一律 E0/E1，人工確認後才升級（CLAUDE.md 規則 5）。
