
[正體中文（臺灣）](#zh-tw) | [English](#english)

<a id="zh-tw"></a>

# 操作、部署與驗證界線

## GitHub 必要設定

`.github/CODEOWNERS` 只有在分支保護要求審查時才會強制。`main` 至少需要下列必要檢查，並限制直接推送、強制推送及刪除：

- `VibeSec Summary`
- `倉庫驗證（validate.py）`
- `外部 G4 紀錄不得自證`

執行 `python3 scripts/configure_github.py --json reports/github-readiness.json` 會分別查核分支保護與 Code Scanning，並列出必要設定。退出碼 `0` 表示這兩項設定查核通過，`1` 表示查到設定缺口，`2` 表示權限不足、API 失敗或缺少分析資料；不代表所有安全閘門通過。具 Administration 權限的管理者可用 `--apply` 建立尚未設定的保護。只有分支明確未受保護且保護 API 回傳 404，程式才會新增；403、未知狀態或既有保護都不整組覆寫。新增後會重新讀取確認。CODEOWNERS 審查至少要有另一位具權限的維護者，PR 作者不能自行核准。

PR 的最終判定讀取基底提交的模式與政策，PR 本身不能把 enforce 改為 shadow 取得放行。執行器與 workflow 的變更仍是信任邊界，必須受到審查與分支保護；僅在程式內讀取可信 YAML 並不能阻止惡意改寫判定程式。

CodeQL 的掃描與上傳已分開：原始 SARIF 先保存為 artifact，再上傳 Code Scanning。儲存庫必須啟用 Code Scanning；私有儲存庫可能需要適用方案。未啟用時上傳步驟會明確失敗，不會掩飾為成功。程式不會自行購買或啟用付費服務。

本次修正期間，管理 API 實際回傳 `403 Resource not accessible by integration`，Code Scanning API 回報尚未啟用。因此不能把「已加入管理腳本」等同於「遠端保護已啟用」。管理者完成後須重跑驗證並確認介面設定。

## 部署相依關係

`staging-blackbox.yml` 支援 `workflow_call`。同一專案的正式部署工作流程可將黑箱測試設為必要前置工作：

```yaml
jobs:
  security:
    uses: ./.github/workflows/staging-blackbox.yml
    secrets: inherit
  deploy:
    needs: security
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy-production.sh
```

此片段放入目標專案既有的部署工作流程。先設定授權測試環境 `vars.VIBESEC_TARGET_URL`、雙帳號 secret、模型金鑰與目標專案的 API 情境，再經獨立政策變更將 `vibesec.yaml` 設為 enforce。未設定 URL 時只跑內建漏洞靶場，成功表示偵測器抓到預期漏洞，**不代表任何正式系統通過安全驗證**。本專案沒有正式環境部署指令，因此不加入虛構部署工作。

shadow 只報告；enforce 依 blocking 與必要閘門未完成狀態決定退出碼。ZAP、API 探針、promptfoo、garak、模型生成層與用量遙測分別保留完成狀態。缺模型金鑰仍會記為未完成，即使決定性靶場測試正常。靶場驗收只容許模型生成層缺金鑰，其餘必要工具與控制必須完成；抓到 blocking 不能掩蓋 garak 等工具缺席。garak 使用官方 CPU 版 torch 及 constraint，避免安裝 CUDA 套件耗盡 runner 磁碟。

## 可重現驗證

```bash
python3 -m pip install --require-hashes -r requirements-ci.txt
python3 scripts/validate.py
python3 -m unittest discover -s tests -v
node --test .github/scripts/*.test.js
python3 scripts/run_evals.py --baseline evals/baseline.yaml --json reports/evals.json --md reports/evals.md
```

評測工具版本依 `nightly-full.yml`：Semgrep 1.179.0、Checkov 3.3.22、Gitleaks 8.28.0（下載後核對 SHA-256），另需 uv 啟動本機靶場。主要 Python 驗證相依含遞移相依皆鎖定版本與雜湊；掃描器的遞移相依及線上規則集仍受上游影響，不能宣稱整條管線位元組級可重現。

更新基礎相依時，使用 `requirements-ci.in` 並以 `uv pip compile requirements-ci.in --python-version 3.11 --generate-hashes --exclude-newer <冷卻期截止日> -o requirements-ci.txt` 重新鎖定，經供應鏈檢查後提交。

KEV 先查 CISA 官網，失敗時改查 CISA 維護的 `cisagov/kev-data` 官方鏡像；兩者失敗都不能判 pass。nightly 不把無法查詢的 KEV 誤記為 `false`，而是 `null`；失效快取也不交給阻擋判定。

94 個案例中，90 個驗證偵測結果、4 個驗證失敗狀態。靶場、合成 Grype 輸入與故障注入各自的證據範圍見 [評測說明](../evals/README.md)。真實模型三組比較需另行收集完整證據，見 [試點與評測](12-pilot-and-evaluation.md)。


## 雙語文件維護

`python3 scripts/check_documents.py` 檢查所有 Git 追蹤中的 Markdown：兩種語言的導覽、非空正文、本機連結與章節錨點。`scripts/validate.py` 已納入此檢查，PR 另以 `--base <基底提交>` 比對兩種語言是否同步更新，以及 `config/harness/` 的提示內容變更時 `prompt_version` 是否遞增。找不到基底提交時明確失敗，不略過版本檢查。

兩種語言共用程式碼範例，因此只改共用範例不要求重複修改正文；提示檔的任何內容變更仍須遞增版本。新增雙語文件須加入 Git 追蹤後再檢查。檢查器不會驗證外部網站是否可用，也不能判定翻譯語意正確；審查者仍須核對政策、例外與限制是否一致。

## 正式阻擋模式啟用條件

以下是驗收條件，並非已完成的宣告；目前維持 `mode: shadow`。切換應放在獨立政策 PR，不能把本機測試通過當成正式環境驗收。

| 項目 | 必要證據 | 未完成時的處理 |
|---|---|---|
| 合併保護 | 預設分支禁止強制推送與刪除、管理者也受約束、必要檢查及 CODEOWNERS 審查生效；另有可核准的非作者審查者 | 管理者補設定與人員資格，不由作者代填核准 |
| PR 與掃描 | 目前提交的必要檢查成功、CodeQL 分析與 SARIF 上傳成功，報告對應受測提交 | 修復失敗；API 可用或舊分析存在並不足夠 |
| G4 審查 | 高風險控制由兩個不同模型家族獨立審查，保存版本、範圍及原始證據；分歧由人員裁決 | 缺金鑰、意見或核准仍為 `incomplete`／`pending` |
| 授權測試環境 | 明確的測試目標、雙帳號與實際 API 情境；G5/G6 所需工具、模型生成層及遙測完成 | 靶場預期漏洞被偵測到，不代表正式目標通過 |
| 修復與試點 | 重播失敗案例及安全反例；試點符合 [評測驗收標準](12-pilot-and-evaluation.md)，三組比較使用同一保留集並保留真實成本與人工時間 | 缺實測資料不宣稱模型增益；不得拿合成資料補足 |
| 政策切換 | 獨立 PR 記錄適用範圍、責任人與證據；確認部署工作確實依賴必要閘門 | 未達條件就保留 shadow；不降級 blocking 或放寬未完成判定 |

管理者可先以唯讀命令產生設定報告，再以適當憑證補齊缺口。模型金鑰應透過環境或 GitHub Actions 的機密設定提供，不貼在對話、文件或提交中。設定存在仍不代表模型呼叫成功；必須重新執行並保存真實結果。

---

<a id="english"></a>

# Operation, Deployment, and Verification Boundaries

## Required GitHub settings

`.github/CODEOWNERS` is enforced only when branch protection requires review. Protect `main` against direct pushes, force pushes, and deletion, and require at least these checks (their literal names are configuration identifiers):

- `VibeSec Summary`
- `倉庫驗證（validate.py）` — repository validation
- `外部 G4 紀錄不得自證` — external G4 records must not self-attest

Run `python3 scripts/configure_github.py --json reports/github-readiness.json` to audit branch protection and Code Scanning independently and list required settings. Exit `0` means these configuration checks passed, `1` indicates confirmed gaps, and `2` indicates denied access, API failure, or absent analysis data; this is not an all-gates pass. An administrator with Administration permission can use `--apply` to create missing protection. Creation requires explicitly unprotected branch metadata and a protection API 404. A 403, unknown state, or existing protection never triggers wholesale replacement. New protection is read back and verified. CODEOWNERS approval requires another eligible maintainer; a PR author cannot approve their own PR.

The PR verdict reads mode and policy from the base commit. A PR cannot switch enforce to shadow to obtain approval. Runners and workflows remain trust boundaries requiring review and branch protection; loading trusted YAML alone cannot prevent malicious changes to the verdict code.

CodeQL analysis and upload are separate: raw SARIF is saved as an artifact before upload to Code Scanning. Enable Code Scanning; private repositories may require an eligible plan. Upload fails explicitly if the service is unavailable. The program does not purchase or enable paid services.

During this repair, administration APIs returned `403 Resource not accessible by integration`, and Code Scanning reported that it was disabled. Adding the setup script does not mean remote protection is enabled. An administrator must finish setup, rerun verification, and inspect the settings.

## Deployment dependencies

`staging-blackbox.yml` supports `workflow_call`. An existing production workflow can require black-box testing first:

```yaml
jobs:
  security:
    uses: ./.github/workflows/staging-blackbox.yml
    secrets: inherit
  deploy:
    needs: security
    runs-on: ubuntu-latest
    steps:
      - run: ./deploy-production.sh
```

Add this to the target project's actual deployment workflow. Configure the authorized test environment (`vars.VIBESEC_TARGET_URL`), two account secrets, model keys, and project-specific API scenarios. Switch `vibesec.yaml` to enforce through a separate policy change. Without a URL, only the bundled vulnerable lab runs: success means detectors found expected flaws, **not that any production system passed security verification**. This repository has no production deployment command, so it does not invent a deployment job.

Shadow reports only; enforce returns exit codes based on blocking findings and incomplete required gates. ZAP, API probes, promptfoo, garak, model-generated attacks, and usage telemetry retain separate completion states. Missing model keys remain incomplete even if deterministic lab checks work. Lab acceptance permits only the optional generation layer to lack keys; all other required tools/controls must finish. A blocking finding cannot conceal absent garak or other tools. garak uses official CPU-only torch and a constraint to prevent CUDA packages from exhausting runner storage.

## Reproducible verification

```bash
python3 -m pip install --require-hashes -r requirements-ci.txt
python3 scripts/validate.py
python3 -m unittest discover -s tests -v
node --test .github/scripts/*.test.js
python3 scripts/run_evals.py --baseline evals/baseline.yaml --json reports/evals.json --md reports/evals.md
```

Versions in `nightly-full.yml`: Semgrep 1.179.0, Checkov 3.3.22, Gitleaks 8.28.0 (verify SHA-256 after downloading), plus uv for the local lab. Core Python verification dependencies and transitives are version/hash locked. Scanner transitives and online rule sets still depend on upstream; the entire pipeline is not claimed to be byte-for-byte reproducible.

Update core dependencies from `requirements-ci.in` using `uv pip compile requirements-ci.in --python-version 3.11 --generate-hashes --exclude-newer <cooldown-cutoff-date> -o requirements-ci.txt`, then pass supply-chain checks before committing.

KEV queries CISA first, then CISA's official `cisagov/kev-data` mirror. Failure of both cannot yield pass. Nightly records unavailable KEV as `null`, not `false`, and does not use stale cache for blocking decisions.

Of 94 cases, 90 verify detection and four verify failure states. See [evaluation documentation](../evals/README.md#english) for the limits of lab, synthetic Grype, and fault-injection evidence, and [pilot/evaluation](12-pilot-and-evaluation.md#english) for the separate real-model three-arm comparison.

## Bilingual documentation maintenance

`python3 scripts/check_documents.py` checks Git-tracked Markdown for navigation, nonempty language sections, local links, and anchors. `scripts/validate.py` includes this check. PRs additionally use `--base <base-commit>` to detect one-sided translation changes and require increasing `prompt_version` when `config/harness/` prompt content changes. An unavailable base commit fails explicitly rather than skipping version checks.

Both languages share code examples, so changing only shared code does not require duplicate prose edits; any prompt-file change still requires a version increase. Add new bilingual documents to Git before checking. The checker does not test external website availability or translation accuracy; reviewers must verify equivalent policies, exceptions, and limitations.

## Conditions for enabling enforcement

These are acceptance criteria, not claims of completion; `mode: shadow` remains in place. Change modes in a separate policy PR. Local tests alone do not establish production acceptance.

| Area | Required evidence | When incomplete |
|---|---|---|
| Merge protection | Default branch prohibits force pushes/deletion, includes administrators, enforces required checks and CODEOWNERS, and has an eligible non-author reviewer | An administrator supplies settings and reviewer eligibility; authors cannot approve for someone else |
| PR and scanning | Required checks pass for the current commit; CodeQL analysis and SARIF upload succeed, with reports tied to the tested revision | Fix failures; API availability or historical analyses alone are insufficient |
| G4 review | Two model families independently review high-risk controls, retaining versions, scope, and raw evidence; humans adjudicate dissent | Missing keys, opinions, or approval remain incomplete/pending |
| Authorized test environment | Explicit target, two accounts, actual API scenarios, required G5/G6 tools, model generation, and telemetry complete | Detecting expected lab vulnerabilities does not clear a production target |
| Remediation and pilot | Replay failures and safe controls; satisfy [pilot acceptance](12-pilot-and-evaluation.md#english), using the same held-out cases across three arms with actual costs and human time | Missing observations cannot support model-gain claims or be replaced with synthetic evidence |
| Policy transition | A separate PR records scope, responsible owners, evidence, and deployment dependencies on required gates | Remain in shadow until ready; never demote blocking rules or relax incomplete semantics |

Administrators can first generate a read-only configuration report, then address gaps with appropriate credentials. Supply model keys through environment or GitHub Actions secrets, never conversation text, documentation, or commits. A configured key does not establish a successful model call: rerun and preserve actual results.
