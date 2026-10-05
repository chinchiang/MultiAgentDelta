# 03 G2 機密與金鑰（白箱；pre-commit、每次 push）

| 項目 | 值 |
|---|---|
| 閘門 ID | `G2` |
| 性質 | 白箱、確定性；本機 pre-commit + CI push protection + 全 Git 歷史 |
| 設定 | `vibesec.yaml` → `gates.g2_secrets`（`diff_aware: false`、`tools: [gitleaks]`、`config: config/gitleaks.toml`、`require_env_in_gitignore: true`、`timeout_seconds: 300`） |
| 規則 | `config/gitleaks.toml`（延伸 gitleaks 預設 + LLM 供應商金鑰）、`config/semgrep/vibesec-rules.yaml` 的 `vibesec.g2.hardcoded-llm-key`（PR diff 第二道） |
| 負責 | DevOps / 平台建置；全體開發者遵守；AppSec 處理事故 |

## 對抗成因

啟用 AI 助手的儲存庫金鑰外洩率比未啟用者高 40%，約 6.4% 的此類儲存庫含外洩金鑰。原因很具體：

- AI 從範例程式碼學到 `openai.api_key = "sk-..."` 的寫法，直接把使用者貼在對話裡的真金鑰寫進原始碼。
- AI 很樂意幫你生成 `.env`，但很少順手把它加進 `.gitignore`；第一次 `git add .` 就提交了。
- AI 生成的 System Prompt 模板常把 API key、資料庫連線字串當成「設定」寫在字串裡（MAESTRO-L3），之後 G6 一提取 System Prompt 就一起外洩。
- 金鑰一旦進入 Git 歷史，`git rm` 無法移除；fork、CI 快取、IDE 索引都可能已複製。

## 觸發時機與性質

| 時機 | 指令 | 範圍 | 失敗行為 |
|---|---|---|---|
| 本機 pre-commit | `gitleaks protect --staged --config config/gitleaks.toml --redact` | 暫存區 | 阻止 commit（開發者可修正後重試；**不可** `--no-verify` 繞過，CI 會再擋一次） |
| CI 每次 push / PR | `gitleaks detect --source . --config config/gitleaks.toml --log-opts="$BASE_SHA..$HEAD_SHA" --redact --report-format sarif --report-path reports/gitleaks.sarif` | 新增 commit 的歷史 | blocking（push protection） |
| CI 全歷史（`diff_aware: false`） | `gitleaks detect --source . --config config/gitleaks.toml --redact --report-format sarif --report-path reports/gitleaks-full.sarif` | 全部 Git 歷史 + 工作樹 | blocking；首次導入時既有命中進事故 SOP |
| 夜間 | 同全歷史 + 規則更新 | — | — |

性質：確定性、低誤報（熵值 + 關鍵字 + allowlist），因此屬 **blocking**。工具缺席或逾時 → `incomplete`。

## 核心任務

1. **全 Git 歷史掃描 + Shannon 熵值**：gitleaks 對每個 commit 的 diff 套用正則，再以 `entropy` 門檻過濾低熵的假值（`vibesec-generic-high-entropy` 門檻 4.0；供應商規則 3.0–3.5）。
2. **本機 pre-commit**：`gitleaks protect --staged`，在祕密離開開發機前攔截。
3. **CI push protection**：PR 檢查失敗，並在 enforce 模式下拒絕合併。
4. **`.env` 檢查**（`require_env_in_gitignore: true`）：
   - 工作樹存在 `.env*`（不含 `.env.example`）但 `.gitignore` 無對應規則 → `vibesec.g2.env-not-ignored`（CWE-538，blocking）。
   - `git ls-files | grep -E '^\.env($|\.)'` 有結果（`.env` 已被追蹤）→ 同一規則 + 事故 SOP。
5. **LLM 供應商金鑰專用規則**（gitleaks 預設沒有或較舊）：見下表。
6. **報告只保留遮罩與指紋**（CLAUDE.md 規則 7）：`--redact`；finding 記 `sha256(secret)[:12]` 作為指紋以便去重與輪替追蹤，不記原值。

### 金鑰樣式（`config/gitleaks.toml`）

| 規則 ID（`gitleaks:` 前綴） | 樣式 | 備註 |
|---|---|---|
| `vibesec-openai-api-key` | `sk-[A-Za-z0-9_-]{20,}`、`sk-proj-…`、`sk-svcacct-…`、`sk-admin-…` | 熵 ≥ 3.5 |
| `vibesec-anthropic-api-key` | `sk-ant-api03-[A-Za-z0-9_-]{80,}` | 版本碼 `api\d{2}` 容許未來變化 |
| `vibesec-deepseek-api-key` | `deepseek…(key|token)… = "sk-…"` | DeepSeek 亦用 `sk-` 前綴，靠關鍵字上下文區分 |
| `vibesec-glm-zhipu-api-key` | `[0-9a-f]{32}\.[A-Za-z0-9]{16}` | GLM / 智譜 `id.secret` 格式；排除 `sha256:` / `digest:` 上下文 |
| `vibesec-google-ai-studio-key` | `AIza[0-9A-Za-z_-]{35}` 搭配 gemini / genai 關鍵字 | — |
| `vibesec-huggingface-token` | `hf_[A-Za-z0-9]{30,}` | — |
| `vibesec-supabase-service-role-jwt` | `eyJ….eyJ…cm9sZSI6InNlcnZpY2Vfcm9sZSI…` | payload 含 `"role":"service_role"` 的 base64url 片段；service_role 可**繞過 RLS**，外洩等於整庫暴露（連動 G4） |
| `vibesec-supabase-service-role-keyword` | `service_role… = "eyJ…"` | 關鍵字輔助 |
| `vibesec-jwt-secret-assignment` | `JWT_SECRET|SECRET_KEY|SIGNING_KEY = "…16+"` | 排除 `changeme` / `${VAR}` / `os.environ` |
| `vibesec-generic-high-entropy` | `api_key|access_token|client_secret|password|private_key = "…24+"` | 熵 ≥ 4.0 |
| 預設規則（`useDefault = true`） | AWS、GCP、Azure、GitHub、GitLab、Slack、Stripe、Twilio、私鑰 PEM… | gitleaks 內建 |

允許清單：`examples/vulnapp/README.md`、`evals/**fixtures**`、`docs/**/*.md`、lockfile、以及 `VIBESEC-…CANARY/FAKE/EXAMPLE` 標記。靶場內的「假金鑰」必須使用這些標記，否則會被擋。

## 自動化作法

```bash
# 1) 安裝（固定版本）
GITLEAKS_VERSION=8.24.3
curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" | tar -xz gitleaks

# 2) pre-commit（.pre-commit-config.yaml 已掛；手動裝 hook）
pre-commit install --hook-type pre-commit
# hook 內容等同：
gitleaks protect --staged --config config/gitleaks.toml --redact --verbose

# 3) CI：新 commit 範圍（PR）
gitleaks detect --source . --config config/gitleaks.toml \
  --log-opts="${BASE_SHA}..${HEAD_SHA}" --redact \
  --report-format sarif --report-path reports/gitleaks.sarif

# 4) CI：全歷史（diff_aware: false）
gitleaks detect --source . --config config/gitleaks.toml --redact \
  --report-format sarif --report-path reports/gitleaks-full.sarif

# 5) .env 檢查
test -z "$(git ls-files | grep -E '^(.*/)?\.env($|\.(local|dev|prod|staging)$)')" || echo "FAIL: .env tracked"
for f in $(find . -name '.env*' -not -name '.env.example' -not -path './node_modules/*'); do
  git check-ignore -q "$f" || echo "FAIL: $f not ignored"
done

# 6) PR diff 第二道（Semgrep；涵蓋 gitleaks 未啟動的情境）
semgrep --config config/semgrep/vibesec-rules.yaml --include '*.py' --include '*.js' --include '*.ts' \
  --include '*.json' --include '*.yaml' --include '*.env*' --baseline-commit "${BASE_SHA}" \
  --sarif -o reports/semgrep-g2.sarif .
```

GitHub 原生 Secret Scanning + Push Protection 若可用，開啟後與 gitleaks 並行（互補：GitHub 有合作夥伴驗證金鑰是否有效）。

## 工具與設定檔

| 工具 | 用途 | 設定 |
|---|---|---|
| gitleaks（github.com/gitleaks/gitleaks） | 歷史 / 暫存區 / 範圍掃描；SARIF | `config/gitleaks.toml` |
| pre-commit | 本機 hook | `.pre-commit-config.yaml` |
| Semgrep | PR diff 第二道 | `vibesec.g2.hardcoded-llm-key` |
| trivy `--scanners secret`（可選） | 容器層 / 建置產物中的祕密 | 由 G1 job 一起跑 |
| git filter-repo / BFG Repo-Cleaner | 事故後清歷史 | 見 SOP |

## 阻擋政策

CI 的閘門狀態由 `pr-gates.yml` summary job 以 `scripts/sarif_gate.py` 從gitleaks SARIF 與 `.env` 檢查結果推導（gate JSON，`schemas/gate-result.schema.json`）：外部工具規則經 `config/catalogs/cwe-map.yaml` 的 `implemented_by` 對回 vibesec 規則，tier 依 `config/policy/blocking-policy.yaml`（含 `tier_overrides` 與未過期的 `exceptions`）；有 blocking → `fail`；任一工具輸出缺席或無法解析 → `incomplete`；其餘 → `pass`。enforce 模式下 incomplete 是否擋 merge 依政策的 `incomplete_gate_is_blocking_in_enforce`。

| 規則 | 層級 | CWE | 備註 |
|---|---|---|---|
| `gitleaks:*`（任何命中）→ `vibesec.g2.hardcoded-secret` | blocking | CWE-798 | 誤報只能透過 `config/gitleaks.toml` allowlist 或 `.gitleaksignore`（需附指紋與理由）處理 |
| `vibesec.g2.hardcoded-llm-key` | blocking | CWE-798 | — |
| `vibesec.g2.env-not-ignored` | blocking | CWE-538 | — |
| 命中且為正式環境有效高權限祕密 | **P0** | — | 立即事故處理（`scoring.priority_sla_days.P0: 0`） |
| gitleaks 缺席 / 逾時 | `incomplete` | — | 不得 pass |

## 事故 SOP（命中時）

順序不可顛倒：**先撤銷，再清歷史**。清歷史不會讓已被複製的金鑰失效。

1. **撤銷（Revoke）**：到服務商後台立即撤銷該金鑰（OpenAI / Anthropic / Supabase / AWS IAM…）。確認相關服務改用新金鑰前，寧可短暫中斷。
2. **輪替（Rotate）**：產生新金鑰，放入祕密管理（GitHub Environments secrets、Vault、雲端 Secret Manager），程式改以環境變數讀取；確認 CI 與正式環境皆更新。
3. **稽核**：查服務商用量 / 稽核日誌，確認撤銷前是否被濫用；Supabase service_role 外洩時另查資料庫存取日誌（可能的 RLS 繞過）。
4. **清歷史**：
   ```bash
   # 方式 A：git filter-repo（建議）
   pip install git-filter-repo
   git filter-repo --invert-paths --path .env                     # 移除檔案
   printf 'sk-ant-api03-REDACTED==>***REMOVED***\n' > /tmp/replacements.txt
   git filter-repo --replace-text /tmp/replacements.txt           # 置換字串
   # 方式 B：BFG
   bfg --replace-text /tmp/replacements.txt --no-blob-protection .
   git reflog expire --expire=now --all && git gc --prune=now --aggressive
   git push --force --all && git push --force --tags
   ```
   通知所有協作者重新 clone；處理 fork、CI 快取、artifact、IDE / 搜尋索引。
5. **驗證**：重跑全歷史 `gitleaks detect`，確認指紋不再出現；finding `retest_result: fixed`，`validation_status: confirmed`，記錄撤銷時間與新金鑰指紋（遮罩）。
6. **根因**：若來源是 AI 生成的 prompt 模板或範例檔，補 G4 審查項與 `.gitignore` 範本；若是 `.env`，確認 `require_env_in_gitignore` 為何沒擋到（通常是 hook 未安裝）。

## 對應控制（ASVS、CWE、LLM Top 10、MAESTRO）

| 類型 | ID |
|---|---|
| ASVS 5.0（節層級，自編；V13 為 vibesec-extension，對應舊版 V13.3 祕密管理語意，正文可寫「組態／祕密管理章節」） | `ASVS5-V13.3` |
| CWE | `CWE-798`、`CWE-538` |
| LLM Top 10 2025 | `LLM02:2025` Sensitive Information Disclosure、`LLM07:2025` System Prompt Leakage（金鑰寫在 prompt） |
| MAESTRO | `MAESTRO-L3` Agent Frameworks（System Prompt 寫死金鑰） |

## 驗證方式

1. **正例**：fixture 含 `sk-ant-api03-` + 95 字元隨機 → gitleaks 與 Semgrep 皆命中；含 `[0-9a-f]{32}.[A-Za-z0-9]{16}` → GLM 規則命中。
2. **反例**：`sk-ant-api03-EXAMPLE…`、`${OPENAI_API_KEY}`、`{{ env.OPENAI_API_KEY }}`、`sha256:<64hex>` → 不命中。
3. **`.env` 檢查**：fixture repo 追蹤 `.env` → `vibesec.g2.env-not-ignored`；`.env` 在 `.gitignore` 且未追蹤 → pass。
4. **歷史穿透**：在 fixture 中提交金鑰後再提交刪除，工作樹乾淨 → 全歷史掃描仍命中（證明 `diff_aware: false` 有效）。
5. **遮罩**：SARIF 與 findings.json 中不得出現完整金鑰（grep 檢查 `sk-[A-Za-z0-9]{32,}` 無結果）。
6. **hook 存在**：`git config core.hooksPath` 或 `.git/hooks/pre-commit` 含 gitleaks；CI 另驗，開發者繞過本機 hook 仍會被 CI 擋。
7. **SOP 演練**：每季一次假金鑰演練，量測從命中到撤銷的時間（目標 < 1 小時）。
