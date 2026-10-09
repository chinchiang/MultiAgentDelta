[正體中文（臺灣）](#zh-tw) | [English](#english)

<a id="zh-tw"></a>

# 離線突變測試

突變測試刻意修改正式程式，再確認迴歸測試是否能抓到錯誤。本專案使用標準函式庫實作定向測試執行器，無須新增突變測試套件；測試仍需要 `requirements-ci.txt` 內既有的相依套件。套件安裝完成後，執行不需要外部服務、模型金鑰或 Docker。

```bash
python3 scripts/run_mutations.py --profile core
python3 scripts/run_mutations.py --profile full --out reports/mutations-full.json
```

## 範圍與執行方式

[固定清單](../config/mutations.json) 定義 19 個安全邏輯突變：核心範圍 16 個，完整範圍另加多份生成、回應大小上限與模型家族限制。涵蓋閘門退出碼、靶場工具完成狀態、空白報告、工具失敗、同來源限制、模型與資料分級限制、請求額度、遮罩、過期輸出，以及目前版本的獨立可信審查。

執行器先在暫存副本確認各組原始測試通過，再逐一修改單一位置並啟動新的 Python 程序；不修改工作目錄中的正式程式。修改位置必須唯一，程式重構造成位置不符時會失敗，不能靜默略過。子程序不繼承模型金鑰、代理設定或 Docker 測試開關，測試中的 Python socket 連線僅允許回送位址。這是測試防呆，並非用來執行不可信程式的安全沙箱。

PR 執行核心範圍；每日排程與手動觸發執行完整範圍，並保存 JSON 產物。GitHub Actions 的簽出、套件安裝與產物上傳仍需要網路；離線的是測試執行本身。新工作流程須合併至預設分支後，排程才會生效。

## 結果判讀

- `killed`：原始測試通過，修改後出現斷言失敗，且測試數與略過數不變。
- `survived`：修改後測試仍通過，需檢查測試盲點或等價突變。
- `invalid`：程式無法編譯、位置不符、測試出現例外，或測試數／略過數改變；不計為成功偵測。
- `timeout`：超過每組測試的時間限制，預設 30 秒；不計為成功偵測。

原始測試失敗或執行器出錯時，整體為 `incomplete`。只有全部選定突變皆被偵測，退出碼才為零。分數以被偵測數除以全部選定突變數，逾時與無效案例不會被排除以提高分數。報告包含原始測試結果、修改前後內容、來源與清單 SHA-256，以及失敗測試名稱。

第一輪 19 個案例有 4 個存活：空白評測、多份生成、回應大小上限與資料分級。補強後應以當次 JSON 報告確認結果。資料分級案例原本因缺少其他必要設定而誤通過；現已提供完整設定，直接驗證分級限制。

新增案例時，先確認原始行為的正反例，再加入可編譯、行為確實不同的修改。若突變等價，應在程式碼審查中說明並修正清單，不得用忽略逾時或例外來美化分數。這是人工選定的安全範圍，並非全專案所有可能突變；通過不表示沒有漏洞，也不能代替真實模型評測、完整三組實驗或 G4 人工審查。

<a id="english"></a>

# Offline mutation testing

Mutation testing deliberately changes production code and checks whether regression tests detect the error. This repository uses a targeted runner implemented with the standard library, without adding a mutation framework. Tests still require the existing dependencies in `requirements-ci.txt`. Once installed, execution needs no external services, model credentials, or Docker.

```bash
python3 scripts/run_mutations.py --profile core
python3 scripts/run_mutations.py --profile full --out reports/mutations-full.json
```

## Scope and execution

The [fixed manifest](../config/mutations.json) defines 19 security mutations: 16 core cases plus multiple generations, response size, and model-family requirements in the full profile. It covers gate exit codes, completed lab tools, empty reports, tool failures, same-origin restrictions, model and data classification restrictions, request budgets, redaction, stale outputs, and independent trusted review of the current revision.

The runner first verifies baseline test groups in a temporary copy, then changes one location at a time and starts a fresh Python process. Production files in the working tree are never changed. Each replacement must match exactly once; refactoring cannot silently skip a case. Workers do not inherit model credentials, proxy settings, or the Docker test switch. Python socket connections in the worker are limited to loopback. This is an accidental-network-use guard, not a sandbox for untrusted code.

Pull requests run the core profile; daily and manual runs use the full profile and save JSON artifacts. GitHub Actions checkout, dependency installation, and artifact upload still need network access; test execution itself is offline. Scheduled execution begins only after the workflow reaches the default branch.

## Interpreting results

- `killed`: the baseline passed and the mutation caused an assertion failure, with unchanged test and skip counts.
- `survived`: tests still passed; investigate a coverage gap or equivalent mutation.
- `invalid`: compilation failure, unmatched location, test exception, or changed test/skip counts; never counted as detection.
- `timeout`: the test group exceeded its limit, 30 seconds by default; never counted as detection.

Baseline failure or runner errors make the overall result `incomplete`. Exit status is zero only when every selected mutant is killed. The score divides killed mutants by all selected mutants, retaining invalid and timed-out cases in the denominator. Reports include baseline results, before/after changes, source and manifest SHA-256 hashes, and failing test names.

The initial 19-case run had four survivors: empty evaluations, multiple generations, response size, and data classification. Consult the current JSON report for results after strengthening tests. The classification test previously passed because unrelated required configuration was missing; it now supplies complete configuration to test the intended restriction.

When adding cases, establish positive and negative behavior first, then add a compilable change with different behavior. Explain equivalent mutations during code review and revise the manifest; never improve the score by ignoring exceptions or timeouts. This is a curated security scope, not exhaustive repository-wide mutation coverage. Passing neither proves absence of vulnerabilities nor replaces real model evaluations, the full three-arm experiment, or G4 human review.
