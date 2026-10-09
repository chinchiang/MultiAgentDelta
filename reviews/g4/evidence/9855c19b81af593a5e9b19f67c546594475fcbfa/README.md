[正體中文（臺灣）](#zh-tw) | [English](#english)

<a id="zh-tw"></a>

# G4 實際模型審查證據

審查目標為 `9855c19b81af593a5e9b19f67c546594475fcbfa`。Anthropic（AWS Bedrock Claude Sonnet 4）與 Google（Gemini 3.8 Flash）已完成必要的架構、身分與授權角色之獨立首輪及交叉核對，另完成應用程式安全審查。審查範圍以封存的輸入檔案為準，不代表逐行審查整個儲存庫。

請從[證據索引](evidence-index.json)查看模型、執行結果、來源版本及 SHA-256；`packet-*.json.gz` 為可用 gzip 解壓縮的原始輸入，其餘 JSON 保留原始回應、失敗及重試紀錄。輸入資料分級為 internal，未包含提供的憑證值；輸入已通過機密掃描。

實際執行重現了模型傳輸回應含 `choices: null` 時發生未攔截例外的問題，已於目標提交修正並加入回歸測試。兩家模型已覆核修正後的相關來源。

尚未完成的部分：

- 架構審查對執行工具的憑證與對外網路權限仍有防禦深度疑慮，且對現行 G0 規則的解讀有分歧；實際 G0 檢查未產生發現，不以模型票數取代人工判定。
- 部分首輪疑慮已在交叉核對時被否定；原始模型提出的識別碼及意見尚未逐項採納為正式發現。
- 附加供應鏈範圍的 Gemini 回應遭內容過濾，已停止該範圍重試；Claude 的節流失敗與成功重試均保留。必要的兩個角色已完成，不將附加範圍標成通過。
- [審查草稿](g4-review.draft.json)的人工確認欄位留白、覆蓋狀態為 pending；`findings: []` 不表示所有原始疑慮皆已排除。[驗證結果](draft-validation.json)確認格式有效、兩個家族成立，但仍為 incomplete。
- 本目錄不是自動採納的正式審查紀錄。新增的 Bedrock provider 設定仍需進入受信任的基底版本，正式紀錄也需要符合政策的獨立人工審查與核准；不能由自動化冒填確認者。

35 項 Python 測試與 94 案固定評測已通過。固定評測不是實際模型效益的三組對照實驗，也不能證明未涵蓋的程式沒有問題。

<a id="english"></a>

# G4 live model review evidence

The reviewed target is `9855c19b81af593a5e9b19f67c546594475fcbfa`. Anthropic (AWS Bedrock Claude Sonnet 4) and Google (Gemini 3.8 Flash) completed independent first rounds and cross-examination for the required architecture and identity/authorization roles, plus application security. Coverage is limited to the archived input files; this is not a line-by-line review of the entire repository.

The [evidence index](evidence-index.json) records models, execution results, source revisions, and SHA-256 hashes. `packet-*.json.gz` files contain gzip-compressed original inputs; other JSON files preserve original responses, failures, and retries. Inputs were classified internal, excluded the supplied credential values, and passed secret scanning.

Execution reproduced an uncaught exception for a transport response containing `choices: null`. The target commit fixes it and adds regression tests. Both families reviewed the relevant repaired source.

Outstanding items:

- Architecture reviews retain defense-in-depth concerns about tool credentials and outbound network access, and disagree on the current G0 policy interpretation. The actual G0 check emitted no findings; model voting does not replace human adjudication.
- Cross-examination rejected some first-round concerns. Raw proposed identifiers and opinions have not been individually adopted as formal findings.
- Gemini's optional supply-chain response encountered content filtering, and retries for that scope stopped. Claude throttling failures and successful retries remain archived. Both required roles completed; the optional scope is not marked passed.
- The [review draft](g4-review.draft.json) leaves human confirmation blank and coverage pending. `findings: []` does not mean every raw concern was dismissed. [Validation](draft-validation.json) confirms a valid format and two families, while retaining incomplete status.
- This directory is not an automatically adopted review record. The new Bedrock provider configuration must enter the trusted base, and a formal record requires policy-eligible independent human review and approval. Automation cannot impersonate that reviewer.

The 35 Python tests and 94 fixed evaluation cases passed. These evaluations are not a live three-arm model-effectiveness experiment and do not establish that unreviewed code is defect-free.
