[正體中文（臺灣）](#zh-tw) | [English](#english)

<a id="zh-tw"></a>

# ADR 0003：G1 快篩只在三處立接縫、否決外掛註冊表與設定檔接縫，標準輸出形狀與結果行為對外契約

- 狀態：已採納（2026-11-19）
- 相關：#260（父規格）、#262（`scripts/g1_manifests.py`）、#263（`scripts/https_only.py`）、#264（`scripts/g1_registry.py`）、#265（`scripts/g1_git.py`）、#266（`scripts/g1_screen.py`）

## 背景

#260 之前，`scripts/g1_slopcheck.py` 是一支超過兩千行的單檔腳本，把套件登錄庫查詢、HTTPS 重試、Git 呼叫、清單與鎖定檔解析、四層判定、SARIF 與閘門結果輸出全部混在一起，並靠模組層全域變數傳遞目標路徑與政策。測試與評測為了離線執行，必須在執行期覆寫模組全域變數，或以 `importlib` 繞過命令列邊界直接抓取內部判定函式。

深化為深模組 `scripts/g1_screen.py`（`screen(Request, Env) -> Outcome`）時，架構檢視曾評估多種邊界切法：是否在每個子概念都立抽象接縫、是否引入外掛註冊表（`Ecosystem`、`Check`、`ManifestParser`）以便擴充、是否替設定檔讀取建立儲存接縫，以及是否順便整理標準輸出 JSON 與標準錯誤訊息格式。

## 決定

1. **外部依賴接縫只立在三處：套件登錄庫、HTTPS 傳輸層、Git。** 只有具備兩個真實轉接器（生產轉接器與測試／評測替身）的外部 I/O 邊界才立接縫：
   - **套件登錄庫**（`scripts/g1_registry.py`）：`facts(eco, name, ver)` 回傳三態值（存在、不存在、無法查詢）與 `requires(name, ver)`，生產轉接器為 `HttpRegistry`，替身為 `FakeRegistry`。不存在是正常發現，無法查詢與欄位未知是未完成原因（AGENTS.md 規則 2）。
   - **HTTPS 傳輸層**（`scripts/https_only.py`）：`get_json(url, timeout, retries)`，生產轉接器只註冊 HTTPS handler，替身可腳本化暫時性錯誤與回應截斷。
   - **Git**（`scripts/g1_git.py`）：`staged()`、`tracked_files()`、`show(ref, path)`，生產轉接器為 `SubprocessGit`（由真 git 契約測試把關旗標與只取追蹤檔行為），替身為記憶體內的 `FakeGit`。

   清單與鎖定檔解析（`scripts/g1_manifests.py`）是純計算的行程內模組，由快篩與 `scripts/g1_sbom.py` 直接匯入共用，不立接縫。

2. **否決外掛註冊表與設定檔接縫。**
   - **不設 `Ecosystem`、`Check`、`ManifestParser` 外掛註冊表**：本 repo 目前只涵蓋 npm 與 PyPI 兩個生態系與四層固定檢查。在第三個生態系實際出現之前，引入動態註冊表只會把「哪些檢查實際執行、缺資料如何轉成未完成原因、控制覆蓋如何推導（例如 PyPI 尚無安裝腳本檢查時 `VS-G1-INSTALL-HOOK` 必須記未實測）」拆散到多個間接層，降低局部性並增加靜默放行的風險。
   - **不設設定檔讀取接縫**：快篩透過 `Env.config_root` 指向檔案系統上的設定目錄；測試只需建立暫存目錄即可完整驗證設定缺席、YAML 語法錯誤與型別不符的 fail-closed 路徑，無須額外抽象出虛擬設定儲存介面。政策與執行模式仍只經 `load_policy` 取得（ADR 0001、ADR 0002 不動）。

3. **標準輸出形狀與標準錯誤結果行是對外契約。**
   - 標準輸出的兩種 JSON 形狀（無相依清單或規則檔變更時的精簡形狀，以及實際掃描時含 `findings`、`incomplete_checks`、`untested_controls` 等欄位的形狀）由 `scripts/run_evals.py` 與既有自動化腳本直接解析。
   - 標準錯誤的單行結果訊息（略過 1 種、有掃描 4 種，以及範圍失敗或政策讀不到的未完成訊息）由 `scripts/compare_ci.py` 用來核對 CI 執行紀錄，且必須剛好輸出一行。
   - 受信任樹 `_trusted/scripts/g1_slopcheck.py` 的命令列路徑、旗標與退出碼（`0` 無阻擋、`1` 有 blocking 發現、`2` 未完成）由 CI workflow 與 pre-commit 直接呼叫。
   - `Outcome` 以四個純函式檢視（`to_stdout`、`to_sarif`、`to_gate_run`／`to_gate_result`、`result_line`）鎖住上述契約，內部重構不得改變逐字輸出；`scripts/g1_slopcheck.py` 的 `main` 只負責印輸出、寫檔、無 SARIF 檢視時刪除舊檔與回傳退出碼。

## 後果

- 未來做架構檢視時，除非 repo 實際新增第三個套件生態系，否則不再提議替快篩引入 `Ecosystem`、`Check` 或 `ManifestParser` 外掛註冊表，也不再提議替 YAML／文字設定檔建立讀取接縫。
- 修改 `scripts/g1_screen.py` 或 `scripts/g1_slopcheck.py` 時，標準輸出鍵名與形狀、標準錯誤結果行文字（含前導換行）以及退出碼推導皆視為公開契約；若因政策變嚴而需調整可觀察輸出，必須在獨立的行為變更 PR 中明確列出並更新對應消費端（如 `scripts/compare_ci.py`、`scripts/run_evals.py`）。
- 拆出的模組皆放在 `scripts/` 同層目錄，並維持 `sys.path.insert(0, 腳本目錄)` 在匯入之前，確保 CI 執行受信任樹腳本時不會載入受驗樹的同名檔案。

---

<a id="english"></a>

# ADR 0003: G1 screening places seams only at three boundaries, rejects plugin registries and a config seam, and treats stdout shapes and stderr result lines as external contracts

- Status: accepted (2026-11-19)
- Related: #260 (parent spec), #262 (`scripts/g1_manifests.py`), #263 (`scripts/https_only.py`), #264 (`scripts/g1_registry.py`), #265 (`scripts/g1_git.py`), #266 (`scripts/g1_screen.py`)

If the two language sections disagree, the Traditional Chinese section prevails.

## Context

Before #260, `scripts/g1_slopcheck.py` was a single file of more than two thousand lines mixing package-registry lookups, HTTPS retries, Git subprocess calls, manifest and lockfile parsing, four-layer judgements, and SARIF and gate-result formatting, passing the scanned directory and policy through module-level globals. Offline tests and evals had to monkey-patch module globals at runtime or load internal helper functions via `importlib` across the command-line boundary.

While deepening screening into `scripts/g1_screen.py` (`screen(Request, Env) -> Outcome`), architecture review evaluated where seams belong: whether every sub-concept should get an abstract port, whether plugin registries (`Ecosystem`, `Check`, `ManifestParser`) should be introduced for extensibility, whether configuration loading should sit behind a storage seam, and whether stdout JSON and stderr summary lines could be reshaped along the way.

## Decision

1. **External-dependency seams exist at only three boundaries: package registry, HTTPS transport, and Git.** A seam is introduced only at an external I/O boundary backed by two real adapters (a production adapter and a test/eval double):
   - **Package registry** (`scripts/g1_registry.py`): `facts(eco, name, ver)` returning a tri-state lookup result (found, not found, unavailable) plus `requires(name, ver)`, implemented by `HttpRegistry` in production and `FakeRegistry` in tests and evals. Not found is a normal finding; unavailable lookups and unknown fields become problems (AGENTS.md rule 2).
   - **HTTPS transport** (`scripts/https_only.py`): `get_json(url, timeout, retries)`, backed by an HTTPS-only opener in production and scripted doubles for transient errors and truncated responses in tests.
   - **Git** (`scripts/g1_git.py`): `staged()`, `tracked_files()`, and `show(ref, path)`, backed by `SubprocessGit` in production (guarded by real-git contract tests for flags and tracked-files-only semantics) and in-memory `FakeGit` in tests.

   Manifest and lockfile parsing (`scripts/g1_manifests.py`) is pure in-process computation shared directly by screening and `scripts/g1_sbom.py`, without an abstract seam.

2. **Plugin registries and a configuration-file seam are rejected.**
   - **No `Ecosystem`, `Check`, or `ManifestParser` plugin registries**: this repo checks only two ecosystems (npm and PyPI) across four fixed layers. Until a third ecosystem actually arrives, dynamic registries would scatter which checks ran, how missing data becomes a problem, and how coverage is derived (for example, marking `VS-G1-INSTALL-HOOK` untested whenever PyPI packages are checked) across indirection layers, hurting locality and risking silent fail-open gaps.
   - **No configuration-file storage seam**: screening reads configuration from `Env.config_root` on the filesystem. Temporary directories in tests exercise missing files, broken YAML syntax, and wrong top-level types directly on the real fail-closed code path without a virtual config store. Policy and mode still come exclusively through `load_policy` (ADR 0001 and ADR 0002 remain unchanged).

3. **Stdout shapes and stderr result lines are external contracts.**
   - Both JSON shapes on stdout (the compact shape when no manifests or rule files changed, and the full shape carrying `findings`, `incomplete_checks`, `untested_controls`, and waiver metadata when files are scanned) are consumed directly by `scripts/run_evals.py` and automation.
   - The single-line summary printed to stderr (one skip string, four scanned strings, plus the early incomplete line on scope failure or unreadable policy) is parsed by `scripts/compare_ci.py` to verify CI logs and must appear exactly once per run.
   - The command-line path `_trusted/scripts/g1_slopcheck.py`, its flags, and its exit codes (`0` non-blocking, `1` blocking findings, `2` incomplete) are invoked directly by CI workflows and pre-commit.
   - `Outcome` exposes four pure view methods (`to_stdout`, `to_sarif`, `to_gate_run`/`to_gate_result`, and `result_line`) locking byte-for-byte compatibility, while `main` in `scripts/g1_slopcheck.py` performs only side effects (printing, writing files, removing stale SARIF when no SARIF view exists, and returning the exit code).

## Consequences

- Future architecture reviews should not propose `Ecosystem`, `Check`, or `ManifestParser` plugin registries unless a third package ecosystem is genuinely added, nor propose a virtual seam over YAML/text configuration files.
- Changes to `scripts/g1_screen.py` or `scripts/g1_slopcheck.py` must treat stdout keys/shapes, stderr result-line strings (including leading newlines), and exit-code derivation as public contracts; any intentional tightening that alters observable output belongs in its own dedicated PR alongside updates to consumers (`scripts/compare_ci.py`, `scripts/run_evals.py`).
- Extracted modules stay flat under `scripts/` with `sys.path.insert(0, script_dir)` before imports so trusted-tree runs in CI never import same-named files from the project tree.
