# G0 威脅建模報告 — <系統名稱>

> 由 G0 閘門在設計期或重大架構變更前產出。回答 Threat Modeling Manifesto 四問，輸出威脅清單、風險分級與致命三要素裁決。對應 `docs/01-g0-threat-modeling.md`。

- 日期：<YYYY-MM-DD>
- 參與者：<架構、AppSec、開發>
- 固定版本／commit：<commit hash>
- 威脅模型輸入：`threat-model.yaml`（符合 `schemas/threat-model.schema.json`）

## 1. 我們在做什麼？（資料流圖與信任邊界）

<貼上 DFD 或連結；標明資料來源、流經元件、儲存位置、信任邊界。元件與資料流以 threat-model.yaml 的 components/flows/trust_boundaries 為準。>

## 2. 會出什麼錯？（威脅清單）

以 STRIDE（一般應用）、LINDDUN（隱私）、MAESTRO（Agent，見 `config/catalogs/maestro-layers.yaml`）盤點。

| 威脅 ID | 類別 | 目標元件 | 說明 | 由哪道閘門驗證 |
|---|---|---|---|---|
| T-01 | Tampering / MAESTRO-L2 | c-db | 未啟用 RLS 導致跨租戶讀取 | G4、G5 |
| T-02 | MAESTRO-L1 | c-llm | 間接 Prompt Injection 經外部網頁觸發外連 | G6 |
| T-03 | Information Disclosure | c-api | Stack Trace / Swagger 外溢 | G5 |

## 3. 我們要怎麼處理？（緩解控制）

| 威脅 ID | 緩解措施 | 狀態 |
|---|---|---|
| T-01 | 啟用 Supabase RLS、後端 owner 綁定 | open / mitigated / accepted / transferred |

## 4. 致命三要素裁決（Lethal Trifecta）

| Agent | 存取私有資料 | 不受信任內容 | 對外通訊 | 三要素成立？ | 切斷的腳 | 緩解 |
|---|---|---|---|---|---|---|
| c-agent | ✅ | ✅ | ✅ | 是 | untrusted_content | 出向 allow-list + 擷取內容淨化 |

> 三要素同時成立且無法切斷任一隻腳者，**設計期不得放行**；必須透過沙箱、出向 Allow-list、工具權限限制或 Human-in-the-Loop 至少切斷一隻腳。

## 5. 風險分級與閘門深度

- `risk_tier`: **L2**（寫入 `vibesec.yaml`）
- 理由：<暴露面 × 資料敏感度 × Agent 能力>
- 啟用閘門：L1 → G1、G2；L2 → G1–G6；L3 → G1–G6 深度加倍 + 正式威脅建模 + 委外滲透。

## 6. 我們做得夠好嗎？（驗證）

- [ ] 所有 open 威脅都有對應緩解或已接受風險（具簽核）。
- [ ] 致命三要素已切斷至少一隻腳。
- [ ] risk_tier 已寫回 vibesec.yaml，對應閘門已啟用。
- [ ] 文件化安全決策已記錄（ASVS 5.0、ISO 27001:2022）。
