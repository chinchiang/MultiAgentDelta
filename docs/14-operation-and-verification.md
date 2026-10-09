# 操作、部署與驗證界線

## GitHub 必要設定

`.github/CODEOWNERS` 只有在分支保護要求審查時才會強制。`main` 至少需要下列必要檢查，並限制直接推送、強制推送及刪除：

- `VibeSec Summary`
- `倉庫驗證（validate.py）`
- `外部 G4 紀錄不得自證`

執行 `python3 scripts/configure_github.py` 可列出建議設定；具 Administration 權限的管理者可用 `--apply` 建立尚未設定的保護。已有保護時程式不整組覆寫，以免降低既有要求。CODEOWNERS 審查至少要有另一位具權限的維護者，PR 作者不能自行核准。

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
