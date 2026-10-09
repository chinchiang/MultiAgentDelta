[正體中文（臺灣）](#zh-tw) | [English](#english)

<a id="zh-tw"></a>

# G4 後續修正與人工判定清單

本文件整理可重現的程式判斷與待核准事項，不是人工裁決，也不取代正式 G4 紀錄。原始意見見[前次審查證據](../reviews/g4/evidence/9855c19b81af593a5e9b19f67c546594475fcbfa/README.md)。後續程式修改使該次紀錄不再涵蓋目前版本。

| 疑慮 | 程式與驗證依據 | 處理與待確認事項 |
|---|---|---|
| 第三方工具可取得憑證並自由連外 | `staging-blackbox.yml` 原本在主機執行 promptfoo／garak | 改用無網路容器與容器外受限轉接器；仍需人工確認剩餘的供應鏈、容器核心及模型費用風險 |
| HITL 是否代表 G0 規則違反 | `g0_trifecta.py` 會檢查補償控制；實際檢查沒有發現 | 保留兩模型分歧；沒有把殘留風險改寫成已違反現行規則，也沒有修改政策 |
| 偽造 recorded_by 可自行通過 | `g4_review.py` 的 `trusted_approvers`、`trust_cap` 及內建反例 | 必須是目前 head 上有資格的非作者核准者；單填別人的名字不成立。正式採納仍需人工 |
| 跨來源或降級重新導向 | `safe_http.py` 比較協定、主機及連接埠 | 來源檢查拒絕越界；新轉接器更直接拒絕所有重新導向 |
| 工具名稱比對可涵蓋所有危險操作 | `agent_tool_lint.py` 僅為靜態啟發式檢查 | 不宣稱完整語意授權；實際權限應由外部系統強制限制 |
| 模型異常傳輸回應 | `test_bedrock_provider.py` 包含 `choices: null` 等反例 | 前次已修正為 error；不得當成模型已審查 |
| 工具沒有完成卻採用舊報告或空報告 | `isolated_redteam.py` 與 `test_evaluation.py` | 清除同類舊輸出，異常退出只保留 partial 證據，空報告與錯誤退出維持 incomplete |

## 第三方工具隔離

`config/runtime/Dockerfile` 在沒有模型金鑰的建置階段安裝固定版本工具，基底映像釘定 digest；`.dockerignore` 只允許必要建置檔。轉接器啟動後不再安裝套件。工具容器使用非 root、唯讀檔案系統、移除 Linux capabilities、禁止新增權限、限制程序數／記憶體／CPU，並設定 `--network none`。

容器僅掛載生成的工具設定、本機轉接程式、專用輸出目錄與 Unix socket。真正的模型金鑰留在容器外，不掛載工作區、主機家目錄或 Docker socket。容器只能經轉接器 POST 到指定目標的 `/chat`，或指定供應商及模型的固定 API。轉接器不轉送客戶端驗證標頭、不接受重新導向、限制單次資料大小、輸出 token 與總請求數。garak 上限為 50,000 次目標請求，其他模式為 1,000 次；用量耗盡即保持 incomplete。缺少映像、金鑰或隔離能力時保持 incomplete，不回退到主機執行。

限制：供應商與授權目標仍可接收測試內容；這不是禁止所有資料外傳的證明。模型請求可能產生費用，請求次數限制不等於精準金額預算。建置階段的遞移相依套件尚未全部雜湊鎖定。容器不防禦主機管理員或核心漏洞。garak 若需要執行期下載資料集或模型，會失敗並保持 incomplete；應另行審查並在建置階段提供資產，不能臨時開放容器外網。

## 可重現驗證

```bash
docker build -f config/runtime/Dockerfile -t vibesec-redteam:local .
VIBESEC_DOCKER_TEST_IMAGE=python:3.11-slim-bookworm python3 -m unittest discover -s tests -p test_runtime_isolation.py -v
VIBESEC_TARGET_URL=http://127.0.0.1:8000 python3 scripts/isolated_redteam.py eval --image vibesec-redteam:local
python3 scripts/prepare_comparison.py --out reports/comparison-prepared
```

最後一個指令只準備盲測輸入。只將 `packets/` 送給模型，`grader-only.json` 留給評分者；每案 A1、A2、B1 獨立呼叫，單模型組用 A1、同家族組用 A1+A2、跨家族組用 A1+B1。保留原始回應、模型版本、用量、實際費用與人工時間，分歧交人工，不以多數決補結果。案例輸入本身可能含有明顯安全線索，因此移除標準答案不等於完全排除資料集偏差。未實際執行與裁決前不得宣稱效益提升。

## 仍需要外部條件的事項

GitHub 管理與 Code Scanning API 重新檢查仍回傳 403，現有整合無法完成設定。獨立審查者須判定分歧、核准 provider 設定及目前提交的正式紀錄；不得代填姓名。政策切換仍需獨立 PR，維持 shadow。這些事項不會因本機測試通過而自動完成。

[本次執行證據](../reviews/g4/follow-up/2026-10-09/index.json)保留模型失敗、GitHub 權限檢查與盲測準備對照。

本次新增程式的模型覆核未完成：AWS 回傳 `ExpiredTokenException`，Gemini 回應缺漏或不符 JSON 契約；這些失敗不算第二家族或有效審查。需要更新 AWS 暫時性憑證後，重新檢查最終版本。模型介面已增加停止原因辨識：內容過濾、截斷與其他未完成原因不進行格式重試；一般 JSON 錯誤保留遮蔽機密後的原文。31 案三組盲測已準備輸入，但未執行完整跨家族比較或人工計時，不宣稱模型增益。

<a id="english"></a>

# G4 follow-up repairs and human decision list

This document records reproducible code assessments and pending approvals. It is not human adjudication or a formal G4 record. See the [previous evidence](../reviews/g4/evidence/9855c19b81af593a5e9b19f67c546594475fcbfa/README.md). Subsequent code changes mean that review no longer covers the current revision.

| Concern | Code and verification | Action and remaining decision |
|---|---|---|
| Third-party tools can access credentials and unrestricted egress | `staging-blackbox.yml` previously ran promptfoo/garak on the host | Use networkless containers and an external restricted broker; humans must assess residual supply-chain, kernel, and cost risks |
| Whether HITL implies a G0 violation | `g0_trifecta.py` checks compensating controls; the actual check returned no findings | Retain model dissent; do not relabel residual risk as a demonstrated current-rule violation or change policy |
| Forged recorded_by can self-approve | `trusted_approvers`, `trust_cap`, and counterexamples in `g4_review.py` | Requires an eligible non-author approval on the current head; another person's name alone is insufficient; formal adoption still needs a human |
| Cross-origin or downgrade redirects | `safe_http.py` compares scheme, host, and port | Origin checks reject escapes; the new broker rejects every redirect |
| Tool-name matching covers all dangerous operations | `agent_tool_lint.py` is a static heuristic | Do not claim complete semantic authorization; external controls must enforce actual privileges |
| Malformed model transport responses | `test_bedrock_provider.py` includes `choices: null` and other counterexamples | Previously fixed to record error, never a completed review |
| Old or empty reports conceal incomplete execution | `isolated_redteam.py` and `test_evaluation.py` | Remove stale outputs; abnormal exits retain only partial evidence; empty reports and execution errors remain incomplete |

## Third-party tool isolation

`config/runtime/Dockerfile` installs pinned tools without model keys during build, with digest-pinned base images. `.dockerignore` exposes only required build files. No packages are installed after the broker starts. Tool containers are non-root, read-only, capability-free, prohibit privilege escalation, limit processes/memory/CPU, and use `--network none`.

Containers mount only generated configuration, the loopback bridge, a dedicated output directory, and a Unix socket. Real model keys remain outside; the workspace, host home, and Docker socket are not mounted. The broker allows only POST to the selected target's `/chat` or a fixed provider API using the selected model. It does not forward caller authentication headers, rejects redirects, and bounds request size, output tokens, and request count. garak permits at most 50,000 target calls; other modes allow 1,000. Exhausting the budget remains incomplete. Missing images, keys, or isolation capabilities remain incomplete without host-execution fallback.

Limits: the provider and authorized target still receive test content; this is not proof against all disclosure. Requests may incur charges, and a request limit is not an exact monetary budget. Transitive build dependencies are not all hash-locked. Containers do not protect against host administrators or kernel exploits. garak requiring runtime datasets/models will fail and remain incomplete; review and provision those assets during build instead of enabling external networking.

## Reproducible verification

Use the shared commands above to build the image, run actual Docker isolation tests, evaluate the authorized local lab, and prepare blinded comparison inputs. Only `packets/` goes to models; `grader-only.json` stays with the evaluator. For each case, call A1, A2, and B1 independently: single uses A1, same-family uses A1+A2, cross-family uses A1+B1. Retain raw responses, model versions, usage, actual cost, and human time. Humans adjudicate dissent without majority voting. Inputs may themselves contain obvious security cues, so removing answers does not eliminate dataset bias. Preparation alone establishes no model-effectiveness gain.

## Remaining external requirements

Fresh GitHub administration and Code Scanning API checks still return 403; the current integration cannot finish setup. An independent reviewer must adjudicate dissent and approve provider configuration and the current revision's formal record; automation cannot impersonate that reviewer. Enforcement still requires a separate policy PR; shadow remains enabled. Passing local tests does not complete these requirements.

[Current execution evidence](../reviews/g4/follow-up/2026-10-09/index.json) retains model failures, GitHub permission checks, and the prepared experiment mapping.

Model review of the new code did not complete: AWS returned `ExpiredTokenException`, and Gemini responses were missing or violated the JSON contract. These failures do not establish another family or valid review. Refresh AWS temporary credentials and review the final revision. The provider interface now recognizes termination reasons: filtering, truncation, and other incomplete terminations do not trigger format retries; ordinary JSON errors retain credential-redacted raw text. Inputs for a 31-case three-arm study are prepared, but a complete cross-family comparison and human timing have not run; no model-gain claim is made.
