# 12. 試點與評測

本框架在全面導入前，先以**影子運行（shadow）**試點，量化多模型審查相對單模型的增益，並校準誤報。

## 一、試點設計

- **期程**：4 週。
- **範圍**：3 種代表性專案（例如 Web + API、純後端腳本、含 LLM/Agent 應用）。
- **啟動方式**：人工提交固定版本（commit / digest）啟動，`mode: shadow`，**不自動阻擋合併或部署**。
- **GitHub Actions**：納入測試內容；未使用 GitHub 的專案記為 `not_applicable` 並檢查實際 CI 平台。
- **資料隔離**：未分類資料留地端 provider；測試在隔離環境執行；無未核准外傳或越權操作。

## 二、評測案例集（`evals/`）

- 至少 **60 個**漏洞／控制測試案例，涵蓋 14 個審查領域與六道閘門；每個適用領域**至少一正例與一反例**（反例用於量測誤報）。
- 至少 **1/3** 不參與提示（prompt）調整（`held_out: true`），領域與風險層級分布記錄於 `evals/split.yaml`。
- 案例格式見 `evals/README.md`。案例置於 `evals/cases/g0..g6/`，目前數量以 `evals/README.md` 為準（`validate.py` 核對）；試點期持續補齊尚無案例的規則。

## 三、三組比較

固定案例、資料與預算上限，比較：

1. **工具 + 單模型**
2. **工具 + 同模型多代理**（同一 family 多角色）
3. **工具 + 不同模型多代理**（≥2 不同 family，本框架預設）

量測：召回率、精確率、共同漏報（common false negatives）、每個模型的新增有效發現、人工確認時間、成本。

> **狀態：尚未執行。** 下列工具只準備盲測輸入與評分；截至目前沒有任何真實模型的三組結果，本專案不宣稱多模型優於單模型。工具的 selftest 用的是合成資料，不是實驗結果。

### 執行步驟

```bash
# 1. 準備（不呼叫模型）：盲測審查包、三組計畫、執行腳本與答案檔
python3 scripts/prepare_comparison.py prepare --out reports/comparison/run-01
#    預設：--split held_out --data-class internal
#          A=anthropic-bedrock:auto  B=anthropic-bedrock:auto,anthropic-cloud:auto  C=anthropic-bedrock:auto,gemini-cloud:auto
#    覆寫範例（全在內網，可用 confidential）：
#    --data-class confidential --arm A=iec-glm --arm B=iec-glm,iec-glm:architecture --arm C=iec-glm,iec-deepseek

# 2. 執行（會花費 API 額度、需要金鑰與網路；由人決定何時跑）
reports/comparison/run-01/run.sh

# 3. 評分：需要 answer-key.json；分歧可另附人工裁決 {"<組>/<packet_id>": "flag"|"clear"}
python3 scripts/compare_reviews.py --dir reports/comparison/run-01 [--rulings rulings.json]
```

`prepare_comparison.py` 的設計：

- **只用 held-out**：`evals/split.yaml` 的 held_in 用於調整 prompt，量測只用 held_out，避免調整與量測用同一批案例。另排除 `gate_status` 狀態驗證案例、需要執行中靶場的 `target_app` 案例（去標籤後 vulnapp 與 vulnapp-patched 的輸入相同，靜態審查無從區分），以及去標籤後仍含案例 ID／rule_id、或輸入相同但答案不同的案例。目前 45 個 held-out 案例中 32 個可盲測（正例 18、反例 14）。
- **盲測**：審查包只含案例 `input`（遞迴去除 `title`、`notes`、`expected`、`target_app` 等欄位），`packet_id` 以 HMAC-SHA256（salt、案例 ID）產生，同一 salt 可重現；salt 與對照只寫在 `answer-key.json`，不得送給模型。審查包宣告 `data_class`，`review_provider.py` 取審查包與 `--data-class` 中較嚴格者。
- **計畫驗證**（規則 6、7）：provider 須 `enabled`、`allowed_data_classes` 含審查包分級，confidential／pii 只能用 `sensitive_data_providers`；A 恰 1 個 agent，B ≥2 個 agent 且只有 1 個 family，C ≥2 個 agent 且 ≥2 個 family。不符就不產生任何檔案。
- **角色**：`auto` 依案例 domain 取 docs/09 §8 的主責角色，三組同一規則；角色本身會透露領域，但每個領域都有正反例，不透露答案。預設 B 與 C 都是「同一角色、兩個獨立 agent」，兩組只差在 family，呼叫數相同（預算一致）；A1、B1、C1 是同一 provider:role 的獨立呼叫。

`compare_reviews.py` 的設計：

- 每次 call 的 state 照實計數（ran／missing／timeout／error／refused）；輸出檔不存在 = missing，與計畫的 provider／role／data_class 不符 = error。任一 agent 沒有 ran → 該組該案例 `incomplete`，**不算對、也不算 clear**。
- `confirm` = flag、`refute` = clear、`uncertain` = 未判定。多代理組只有全部一致才有結論；分歧保留全部意見與少數意見、標 `requires_human`，**不多數決**，人工裁決後才計分（來源標 `human`）。
- 各組分開列出 TP／FP／FN／TN、召回率與精確率（附分母與 Wilson 95% 區間）、coverage、一致率、每個 agent 的個別結果、共同漏報、相對 A 組的新增有效發現。**不做綜合分數，不讀模型自評信心**（規則 4）。任一 call 不是 ran → `incomplete`；有未裁決分歧 → `pending_human`；兩者都不是 complete（離開碼 2）。

注意事項：

- **成本**：預設 32 個審查包 × (1 + 2 + 2) = **160 次 call**；`rotation.budget.max_calls_per_run`（400）以一次 harness 執行為單位，此實驗應另行核准預算。費用與人工確認時間不在模型輸出中，需人工另行記錄，不得補造。
- **資料分級**：評測案例是本 repo 的合成 fixture，預設 `internal`；境外雲端 `glm-cloud`、`deepseek-cloud` 只收 public，放進 internal 計畫會被拒絕。改用 confidential／pii 時三組都只能用地端／內網 provider（iec-glm、iec-deepseek、lmstudio-local、onprem_vllm）。
- **可比較性**：`anthropic-bedrock` 不接受 temperature，同一 prompt 的輸出可能不同；內網端點連不到會是 error。只有三組都 complete 且分母相同時才比較召回率；32 案的區間很寬，不能當作普遍結論。

## 四、驗收門檻

- 保留集（held-out）**高風險召回率不低於最佳單模型**；整體召回率目標 **+10 個百分點**；最終發現**精確率 ≥ 80%**。附樣本數與不確定性，不宣稱小樣本能證明全面安全。
- 每件正式發現都有可追溯證據；有 CVSS 的案件都有完整向量且計算可重現（CVSS 計算器尚未實作，見 docs/10）。
- **XSS 與 CSP 分別測試**；授權包含跨角色與跨租戶；供應鏈包含套件、建置與發布三層。
- API 失敗、工具逾時、缺帳號／文件、環境無法啟動時標示 `incomplete`，**不產生「通過」**。
- 修復驗證使用新版本，重跑原失敗案例與相關安全對照，確認漏洞關閉且控制未退化（`retest_result`）。

## 五、交付物

完整控制矩陣、審查角色與提示、證據與評分規範、JSON/SARIF 格式、測試案例集、試點比較報告，以及修復與例外處理手冊。精確模型版本於啟動時盤點（見 `config/providers.yaml`）。
