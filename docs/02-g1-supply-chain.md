
[正體中文（臺灣）](#zh-tw) | [English](#english)

<a id="zh-tw"></a>

# 02 G1 相依性與供應鏈（白箱；管線最前端）

| 項目 | 值 |
|---|---|
| 閘門 ID | `G1` |
| 性質 | 白箱、確定性、每次 commit / PR 與相依變動；`order: first` |
| 設定 | `vibesec.yaml` → `gates.g1_supply_chain`（`cooldown_days: 14`、`min_weekly_downloads: 1000`、`popular_lists`、`blacklist`、`allowlist`、`scan_agent_rule_files`、`sbom_format: cyclonedx-json`、`tools: [syft, grype, trivy]`、`enrich: [epss, kev]`） |
| 細部參數 | `config/slopsquat/cooldown.yaml`、`config/slopsquat/popular-npm.txt`、`config/slopsquat/popular-pypi.txt`、`config/slopsquat/blacklist.yaml`、`config/slopsquat/allowlist.yaml` |
| 負責 | DevOps / 平台 |

## 對抗成因

**幻覺套件（Slopsquatting）**：研究量測 LLM 在產生程式碼時推薦的套件約 19.7%–20% 不存在，而且 58% 的幻覺名稱在重複詢問時會再次出現。可預測 = 可搶註：攻擊者只要把常見幻覺名稱註冊到 npm / PyPI 並放入惡意 `postinstall`，等開發者「全部接受」AI 的 `npm install` 建議即可。

**供應鏈蠕蟲**：Nx s1ngularity 與 Shai-Hulud 兩起 npm 事件的共同手法是 `postinstall` 在安裝瞬間執行，呼叫受害者本機已登入的 Claude / Gemini CLI 去搜尋並搜刮 `~/.aws`、`~/.npmrc`、`.env`、GitHub token，再用這些 token 自我傳播。Flooding Dropper 類蠕蟲則多藏在剛發布的新版本裡。

**原則：絕不自動安裝 LLM / Agent 直接輸出的未知套件。**

## 觸發時機與性質

- **每次 commit / PR**，且 `diff_aware: true`：只對 lockfile / manifest / 規則檔 diff 中「新增或變更版本」的套件做 Registry 查詢；SBOM 與漏洞比對則對整個 lockfile 跑。
- **`order: first`**：G1 必須在任何 `npm ci` / `pip install` 之前執行，因為惡意 postinstall 會在安裝瞬間執行；CI job 在 G1 通過前只允許解析 lockfile，不允許安裝。
- 夜間（`nightly-full.yml`）全量重跑：冷卻期是時間函數，昨天被擋的版本今天可能已滿 14 天；反之昨天安全的套件今天可能進了 KEV。
- `timeout_seconds: 600`；Registry API 失敗 → `incomplete`，不得記 pass。

## 核心任務

四層防禦，任一層命中 blocking 即停止安裝：

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ 第 1 層  官方 Registry 存在性與健康度快篩                                        │
│   npm: registry.npmjs.org/<pkg>  + api.npmjs.org/downloads/point/last-week     │
│   pypi: pypi.org/pypi/<pkg>/json + pypistats                                   │
│   不存在 → block   週下載 < 1000 → high risk   首次發布 < 30 天 → block           │
│   只有 1 個版本 / 維護者 30 天內變更 → high risk                                  │
├──────────────────────────────────────────────────────────────────────────────┤
│ 第 2 層  名稱相似度與幻覺黑名單                                                  │
│   對 popular-npm.txt / popular-pypi.txt：編輯距離 ≤ 2（≤ 5 字元的名稱 ≤ 1）     │
│   或 difflib ratio ≥ 0.85                                                       │
│   且名稱不相等 → 疑似 typosquat（axois vs axios）                                │
│   blacklist.yaml 命中 → block / warn                                            │
│   掃描範圍：package.json、requirements.txt、lockfile，以及 .cursorrules、         │
│   AGENTS.md、SKILL.md、**/*.md 內的 pip install / npm i 指令                      │
├──────────────────────────────────────────────────────────────────────────────┤
│ 第 3 層  安裝階段 Hook 靜態與動態檢查                                            │
│   npm: scripts.preinstall / install / postinstall / prepare                     │
│   python: setup.py / setup.cfg / pyproject build hooks                          │
│   啟發式：網路外連 + 環境變數讀取 + 憑證路徑（~/.aws ~/.npmrc ~/.claude …）         │
│          + 呼叫本機 AI CLI（claude -p / gemini -y）+ base64 解碼後 eval            │
│   動態（可選）：在無網路沙箱安裝並以 strace / 代理觀察外連                           │
├──────────────────────────────────────────────────────────────────────────────┤
│ 第 4 層  新套件 / 新版本 7–14 天冷卻期                                           │
│   發布時間距今 < cooldown_days（預設 14）→ CI 拒絕建置或要求安全團隊人工審查          │
│   例外只能走 allowlist.yaml（需 approved_by + expires）                           │
└──────────────────────────────────────────────────────────────────────────────┘
          │ 全數通過
          ▼
  syft 產 CycloneDX SBOM → grype / trivy 比對 NVD / OSV → EPSS + CISA KEV 加值 → 優先修補真實可達的漏洞
```

### 第 1 層：Registry 健康度

| 檢查 | 門檻（`config/slopsquat/cooldown.yaml`） | 判定 |
|---|---|---|
| 存在性 | `GET https://registry.npmjs.org/<pkg>` / `GET https://pypi.org/pypi/<pkg>/json` 回 404 | **block**：`vibesec.g1.hallucinated-package` |
| 週下載 | `GET https://api.npmjs.org/downloads/point/last-week/<pkg>` → `downloads`；PyPI 用 `https://pypistats.org/api/packages/<pkg>/recent` → `data.last_week` | `< min_weekly_downloads (1000)` → advisory `vibesec.g1.low-download-package`；若同時命中第 2 層 → 升 blocking |
| 首次發布 | npm `time.created`；PyPI 最早 `upload_time_iso_8601` | `< min_age_days (30)` → block（全新套件需人工審查） |
| 版本數 / 維護者 | `versions` 長度、`maintainers` 變更 | `< min_versions (2)` 或 30 天內維護者變更 → high risk 標記 |

可選工具：SlopCheck、DevSentinel、Socket（行為分析與幻覺套件偵測）；它們的結果以 `rule_id` 前綴保留原名。

### 第 2 層：相似度與黑名單

正規化：小寫；PyPI 把 `_`、`.` 視同 `-`（PEP 503）；npm 去 scope 另比；同形字（`I`/`l`、`0`/`o`）正規化。對 `popular_lists` 每個名稱計算：

```python
import difflib
def suspicious(name, popular):
    for p in popular:
        if name == p or len(name) < 4: continue
        # 編輯距離用 optimal string alignment：相鄰字母易位算 1（axois → axios）
        limit = 1 if len(name) <= 5 else 2   # 短名改兩個字母已是另一個字（zipp／pip、hpack／black）
        if 0 < osa_distance(name, p) <= limit or difflib.SequenceMatcher(None, name, p).ratio() >= 0.85:
            return p   # 疑似 typosquat of p
```

- 命中 → `vibesec.g1.hallucinated-package`（blocking），finding.notes 記 `looks_like`。
- `blacklist.yaml` 的 `status` 分三類：`confirmed_malicious`（曾被下架 / CERT 證實，例如 `crossenv`、`colourama`、`jeIlyfish`、`torchtriton`）、`hallucination_prone`（`axois`、`reqeusts`、`python-dotenv-env`、`yaml`、`beautifulsoup`；`huggingface-cli` 也是 LLM 常捏造的名稱，PyPI 上並不存在，真正提供該指令的套件是 `huggingface-hub`）、`confusable_legit`（真實存在但易混淆，例如 `sklearn` 應為 `scikit-learn`、`pytorch` 應為 `torch`）。
- **規則檔也要掃**（`scan_agent_rule_files: [".cursorrules", "AGENTS.md", "SKILL.md", "**/*.md"]`）：AI 助手會「照做」規則檔裡的 `pip install foo`；在這些檔案發現未知 / 黑名單套件 → `vibesec.g1.rules-file-unknown-package`。帶值旗標後面的是檔案、路徑或 URL，不是套件名（`pip install -r requirements.txt`、`-e git+https://…`、`--index-url …`、`npm install --registry …`；清單見 `scripts/g1_slopcheck.py` 的 `VALUE_FLAGS`）；同一個檔重複提及同一個套件只記一次。同時這一步順便執行 G4 的隱形 Unicode 掃描（`VS-G4-RULES-FILE-UNICODE`）。

### 第 3 層：安裝鉤子

對 diff 新增套件，下載 tarball（不安裝）後檢查：

| 訊號 | 正則（摘自 `cooldown.yaml.install_hooks.suspicious_patterns`） | 判定 |
|---|---|---|
| 網路 | `curl|wget|fetch(|http.request|axios|urllib.request|requests.(get|post)|socket.connect` | 與下列任一併存 → block |
| 環境變數 | `process.env|os.environ|os.getenv|$...TOKEN/SECRET/KEY/PASSWORD` | 網路 + 環境變數 → **block** `vibesec.g1.postinstall-egress`（CWE-506） |
| 憑證路徑 | `~/.aws`、`~/.npmrc`、`~/.pypirc`、`~/.ssh`、`~/.claude`、`~/.config/gcloud`、`~/.docker/config.json`、`~/.gitconfig`、`~/.netrc`、`~/.kube/config`、`.env` | **block** |
| 濫用本機 AI CLI | `claude|gemini|codex|aider` 搭配 `-p|--print|-y|--yes|--dangerously-skip-permissions` | **block**（Nx s1ngularity / Shai-Hulud 手法） |
| 動態執行 | `child_process|execSync|subprocess|os.system|eval(|new Function(`、`base64 … decode`、管線交給 shell（`| sh`） | 與網路併存（例如 `curl … \| sh`）→ **block**；單獨出現 → advisory |

實作：`scripts/g1_slopcheck.py` 的 `install_hook_finding()` 依上表分類 npm `preinstall`／`install`／`postinstall`。只有網路（例如單純 `wget` 下載）→ advisory；不含任何可疑樣式的 hook（例如 `node-gyp rebuild`）不判 `postinstall-egress`。

```bash
# npm：不執行 scripts 取得 tarball 並檢查
npm pack <pkg>@<ver> --ignore-scripts --pack-destination /tmp/g1 && tar -xzf /tmp/g1/*.tgz -C /tmp/g1
jq '.scripts | {preinstall, install, postinstall, prepare}' /tmp/g1/package/package.json
# Python：注意 pip download 仍可能執行來源套件的中繼資料建置程式；僅在隔離環境使用。
# Python: pip download may execute source-package metadata builds; use an isolated environment.
pip download <pkg>==<ver> --no-deps --no-binary :all: -d /tmp/g1 && tar -xzf /tmp/g1/*.tar.gz -C /tmp/g1
grep -nE 'urllib|requests|socket|os\.environ|\.aws|\.npmrc|\.claude' /tmp/g1/*/setup.py
```

動態（L2 以上建議）：在無網路 egress 的容器內 `npm ci --ignore-scripts=false` 並用 `strace -f -e trace=network` 或 mitmproxy 記錄；任何外連即 block。

### 第 4 層：冷卻期

```
publish_time = npm: time[<version>] | pypi: releases[<version>][0].upload_time_iso_8601
if now - publish_time < cooldown_days(14):  → vibesec.g1.cooldown-violation (blocking)
```

- 允許範圍 7–14 天，預設取上限 14（`vibesec.yaml` 的 `cooldown_days: 14`）。
- 緊急安全修補走 `allowlist.yaml`（`bypass: [cooldown]`、`expires` ≤ 14 天、`approved_by` 為 AppSec）。
- 冷卻期對「既有套件的新版本」同樣適用；lockfile 鎖版本是前提（沒有 lockfile → G1 `fail`）。

### 通過後：SBOM 與漏洞加值

SBOM 由 `scripts/g1_sbom.py` 產生並驗證（控制 `VS-G1-SBOM`），三件事都做到才算 pass：

1. **乾淨的樹、可重現**：以 `git archive` 匯出受測 commit（不讀工作目錄，本機裝過的 `node_modules`、`.venv` 不會混入），syft 產生兩次，`components[]` 集合必須相同（忽略 serialNumber、timestamp、bom-ref）。
2. **格式**：`bomFormat: CycloneDX`、`specVersion` 1.4 以上、`components` 為清單。
3. **完整**：每個鎖定檔（`package-lock.json`、`uv.lock`、`poetry.lock`、檔名含 requirements 的 `.txt` 中以 `==` 釘選者）釘選的套件版本都要以 purl 出現在 SBOM。漏列的套件不會被 grype 與 KEV 比對，所以缺漏 → `vibesec.g1.sbom-incomplete`（一個鎖定檔一筆，tier 依 blocking-policy），`VS-G1-SBOM` 記 fail。
   - syft 預設不收 npm devDependencies；建置工具在建置時會執行，屬供應鏈範圍，所以固定開啟 `SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES`。對 chinchiang/MultiAgentBeta 實測，沒開時 `frontend/package-lock.json` 的 119 個套件漏列 111 個。

缺 syft、syft 失敗、格式不符、兩次產出不同，或受測樹含尚無解析器的 `pnpm-lock.yaml`／`yarn.lock` → `incomplete`（exit 2），`VS-G1-SBOM` 記 untested。

```bash
python3 scripts/g1_sbom.py --target . --sbom reports/sbom.cdx.json \
  --sarif reports/g1-sbom.sarif --json reports/g1-sbom.json --merge-gate reports/g1-gate.json
grype sbom:reports/sbom.cdx.json -o sarif --file reports/grype.sarif
trivy sbom reports/sbom.cdx.json --format sarif --output reports/trivy.sarif --scanners vuln
trivy fs . --scanners vuln,secret,misconfig --format sarif --output reports/trivy-fs.sarif
# 加值（記錄查詢日；不做乘法）
curl -s "https://api.first.org/data/v1/epss?cve=CVE-2025-XXXXX"      # → epss, percentile, date
curl -s https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | jq '.vulnerabilities[] | select(.cveID=="CVE-2025-XXXXX")'
```

每個 CVE 的 finding 分欄記 `cvss_vector / cvss_score / epss / epss_date / kev / kev_date`（CLAUDE.md 規則 4）。KEV 命中 → 升 blocking 且 priority P1；EPSS 只用來排序修補順序，不改嚴重度。實作：PR（pr-gates G1，結果併入 `g1-gate.json`，依 mode 決定是否阻擋）與 nightly 都以 `scripts/g1_kev.py` 比對 grype 結果與 CISA KEV feed，命中即發出 `vibesec.g1.kev-hit`（SARIF，Code Scanning 分類 `vibesec-nightly-kev`）並以退出碼 1 讓 nightly 轉紅、notify 開 issue；缺 grype 結果或 KEV feed 無法取得時退出碼 2、nightly 轉紅並由 notify 開 issue（incomplete ≠ pass）。摘要記錄所用 KEV feed 的發布時間，看得出是否用了舊快取。SBOM 保存於 artifact（EU CRA 要求可提供 SBOM 與無已知漏洞證明）。

## 自動化作法

`.github/workflows/pr-gates.yml` 的 G1 job（摘要）：

1. `actions/checkout` → **不安裝**。
2. 計算 diff：`git diff --name-only $BASE...HEAD -- package.json package-lock.json pnpm-lock.yaml requirements*.txt pyproject.toml uv.lock .cursorrules AGENTS.md SKILL.md '**/*.md'`。
3. 解析新增 / 變更套件 → 四層檢查（Registry 查詢快取 24h；失敗 → `incomplete`）。
4. 全通過 → `npm ci --ignore-scripts` / `uv sync`，再對白名單內需要 build 的套件單獨允許 scripts。
5. `scripts/g1_sbom.py`（syft，驗證後併入 `g1-gate.json`）→ grype / trivy → EPSS / KEV → 合併 SARIF（`rule_id` 前綴 `grype:` / `trivy:`）。
6. 寫 `reports/g1.gate-result.json`（`coverage`: `ASVS5-V15.2`、`VS-G1-SLOPSQUAT`、`VS-G1-COOLDOWN`、`VS-G1-INSTALL-HOOK`、`VS-G1-SBOM`）。

本機開發者：`.pre-commit-config.yaml` 掛同一支檢查腳本（只跑第 1、2、4 層，秒級）。

掃其他專案（被測專案在本機另一個目錄）：

```bash
python3 scripts/g1_slopcheck.py --target ../MultiAgentBeta \
  --sarif reports/raw/G1/slopcheck.sarif --gate reports/raw/G1/slopcheck-gate.json > reports/raw/G1/slopcheck.json
```

只給 `--target` → 全量掃描目標專案追蹤中的所有 manifest 與 agent 規則檔（`scope: full`）；`--changed-files`、`--staged`、`--base`、相對路徑都以目標專案為準。設定、清單與阻擋政策取自本 repo；`blocking-policy.yaml` 的 `exceptions` 只核准給本 repo 路徑，對外部專案不套用。`pnpm-lock.yaml`、`yarn.lock` 尚無解析器 → `incomplete` 並列出檔名。

`package-lock.json`（lockfileVersion 1–3）逐筆解析（別名取實名、略過 workspace 連結）：每個條目都做 registry 存在性、冷卻期、安裝 hook、週下載與黑名單；名稱相似度只做**直接相依**（根目錄與 workspace 宣告的相依；v1 取同目錄 `package.json`），間接相依的名稱由上游決定、不是開發者或 AI 打出來的。`requirements*.txt` 鎖定檔（pip-compile、uv export）沒有直接／間接的標記，改以 PyPI 該版本的 `requires_dist` 推得：同檔其他套件宣告為相依者視為間接相依（自己需要自己不算）；查不到 `requires_dist` 就照直接相依比對，不會少查。`resolved` 不在 npm registry（git、file、tarball URL、私有 registry）或版本不是 semver 的條目無法以 registry 驗證 → `incomplete` 並列出。同一個（名稱, 版本）只查一次，registry 以 8 個並行查詢；連線中斷、傳輸截斷、逾時、429、5xx 重試 2 次（404 不重試），仍失敗 → `incomplete`。

## 工具與設定檔

| 工具 | 用途 | 設定 |
|---|---|---|
| 自製檢查（harness G1 步驟） | 四層防禦 | `config/slopsquat/*.yaml`、`*.txt` |
| syft | SBOM（CycloneDX JSON；可改 SPDX） | `sbom_format: cyclonedx-json` |
| grype | SBOM 比對 NVD / GHSA | `grype sbom:…` |
| trivy | 漏洞 + 祕密 + IaC + K8s；2026 預設首選（Apache-2.0） | `trivy sbom` / `trivy fs` |
| Socket / DevSentinel（可選） | 行為分析、幻覺套件 | API token 放 repo secret |
| SlopCheck / SlopScan（可選） | Markdown、.cursorrules、AGENTS.md 掃描 | — |
| FIRST EPSS、CISA KEV | 加值 | `cooldown.yaml.sbom.enrich` |

## 阻擋政策

| 規則 | 層級 | CWE |
|---|---|---|
| `vibesec.g1.hallucinated-package`（不存在 / 相似度 / 黑名單 block） | blocking | CWE-1357 |
| `vibesec.g1.cooldown-violation` | blocking | CWE-1357 |
| `vibesec.g1.postinstall-egress` | blocking | CWE-506 |
| `vibesec.g1.rules-file-unknown-package` | blocking | CWE-1357 |
| `vibesec.g1.low-download-package` | advisory（與相似度併發升 blocking） | CWE-1357 |
| `vibesec.g1.vulnerable-dependency`（`scripts/g1_kev.py` 由 grype 結果產生；KEV 以外的已知漏洞，CVSS 原樣分欄、EPSS 另記） | advisory；KEV 命中改發 `vibesec.g1.kev-hit`（blocking） | CWE-1395 |
| `vibesec.g1.unmaintained-dependency`（nightly `scripts/g1_maintenance.py`：SBOM 套件查 deps.dev，所用版本 deprecated 或最新版發布超過 `unmaintained_days`（預設 730）天；查詢失敗或查無 → incomplete；本 repo 自身專案與 GitHub Actions 列 not_applicable） | advisory | CWE-1104 |
| `vibesec.g1.sbom-missing-provenance`（nightly 以 `actions/attest-build-provenance` 為 SBOM 簽發 SLSA provenance，`scripts/g1_provenance.py` 以 `gh attestation verify --signer-workflow` 驗證存在、簽章有效且由本 repo 的 nightly-full 簽發；缺 SBOM／gh、權限或網路錯誤 → incomplete） | advisory | CWE-1357 |
| `vibesec.g1.sbom-incomplete`（`scripts/g1_sbom.py`：鎖定檔釘選的套件不在 CycloneDX SBOM；一個鎖定檔一筆） | advisory | 無（MITRE CWE 沒有對應類別，見 cwe-map 的 notes） |
| 無 lockfile / Registry API 失敗 | `fail` / `incomplete` | — |

正式判定以 `config/policy/blocking-policy.yaml` 為準。

### 套件例外：`config/slopsquat/allowlist.yaml`

`scripts/g1_slopcheck.py` 的 `load_allowlist()` 讀 `entries`，只採用合規且未過期的條目；其餘忽略並列在輸出的 `ignored_allowlist` 與 gate `status_reason`（fail closed）。

| 欄位 | 規則 |
|---|---|
| `package`、`approved_by`、`expires`、`reason`、`bypass` | 必填；`expires` 為 `YYYY-MM-DD`，過期即失效 |
| `ecosystem` | `npm` / `pypi`；省略＝所有生態系。名稱比對同第 2 層（PyPI 依 PEP 503） |
| `version` | 省略／`null`＝所有版本；精確版本（`2.32.5`、`==2.32.5`）；或全部須成立的比較式（`>=2.0.0 <3.0.0`、`>=2,<3`）。`^`、`~`、`x`、`\|\|` 不接受（條目忽略）；預發布版本不落在範圍內 |
| `bypass` | 只能是 `registry_health`（registry 查無）、`low_download`、`cooldown`、`blacklist`、`similarity`（名稱相似度）。**安裝 hook（`postinstall-egress`）與 KEV 不可放行**，寫了整筆忽略 |

套用方式：allowlist 內的套件仍做全部檢查（安裝 hook 照查）；某筆發現的檢查在條目的 `bypass` 內且版本相符 → blocking 降為 advisory，發現保留並附 `allowlist`（核准人、到期日、ticket、理由），同 blocking-policy 的 `exceptions`。allowlist 以套件為單位、不綁路徑，`--target` 掃其他專案時同樣適用。

## 對應控制（ASVS、CWE、LLM Top 10、MAESTRO）

| 類型 | ID |
|---|---|
| ASVS 5.0（節層級，自編；V15 為 vibesec-extension） | `ASVS5-V15.2` 安全架構與相依性 |
| vibesec | `VS-G1-SLOPSQUAT`、`VS-G1-COOLDOWN`、`VS-G1-INSTALL-HOOK`、`VS-G1-SBOM`、`VS-G4-RULES-FILE-UNICODE`（規則檔掃描順帶） |
| CWE | `CWE-1357`、`CWE-829`、`CWE-506`、`CWE-1395`、`CWE-1104` |
| LLM Top 10 2025 | `LLM03:2025` Supply Chain、`LLM09:2025` Misinformation（幻覺） |
| MAESTRO | `MAESTRO-L1`（幻覺）、`MAESTRO-L7`（生態系蠕蟲、Rules File） |

## 驗證方式

1. **正例 / 反例（`evals/`）**：lockfile 含 `axois` → block；含 `axios` 最新版但發布 3 天 → cooldown block；含 allowlist 內緊急版本 → pass 並附 ticket；`.cursorrules` 指示以 pip 安裝幻覺套件 `huggingface-cli` → block（案例描述刻意不寫成可執行指令，避免文件本身被規則檔掃描命中或被 AI 助手照做）。
2. **安裝鉤子 fixture**：假 tarball 的 postinstall 含 `curl … $NPM_TOKEN` → `vibesec.g1.postinstall-egress`。
3. **Registry 失敗模擬**：封鎖 `registry.npmjs.org` → G1 `incomplete`，summary 顯示紅字而非綠勾。
4. **SBOM 可重現且完整**：同一 commit 兩次產出的 CycloneDX `components[]` 集合相同（忽略 timestamp / serialNumber），且鎖定檔釘選的套件都在 SBOM。`scripts/g1_sbom.py` 每次執行都檢查；`python3 scripts/g1_sbom.py selftest` 涵蓋可重現、格式、缺漏、只讀 commit 與無解析器鎖定檔等案例。
5. **分欄不混算**：抽查 finding：`cvss_score` 與 `epss` 各自存在，`priority` 由政策表決定而非乘積。
6. **時效**：PR 階段 G1 wall-clock < 3 分鐘（快取命中時 < 60 秒）。


---

<a id="english"></a>

# 02 G1 Dependencies and Supply Chain (White-Box; First in the Pipeline)

G1 is deterministic and runs on commits/PRs and dependency changes with `order: first`. DevOps/platform owns it. `vibesec.yaml → gates.g1_supply_chain` configures a 14-day cooldown, 1,000 weekly downloads, popular/black/allowlists, agent-rule scanning, CycloneDX JSON, Syft/Grype/Trivy, and EPSS/KEV enrichment. Detailed settings live in `config/slopsquat/`.

## Causes addressed

Studies report roughly 19.7–20% hallucinated package recommendations and 58% recurring hallucinated names. Attackers can preregister predictable names and wait for developers to accept generated installation commands. Nx s1ngularity/Shai-Hulud used install hooks and authenticated local Claude/Gemini CLIs to steal credentials from AWS/npm/environment files and propagate. Flooding Dropper-style malware also hides in newly released versions.

**Never automatically install unknown packages emitted by an LLM or agent.**

## Triggers and nature

- Each commit/PR: query registries for packages added or version-changed in manifests, lockfiles, or rule-file diffs. SBOM/vulnerability checks cover the full lockfile.
- Run before target `npm ci` or dependency installation: install hooks execute immediately. Until G1 passes, parse files without installing target packages.
- Rerun fully each night: package age and KEV membership change over time.
- Timeout: 600 seconds. Registry failure is `incomplete`, never pass.

## Core tasks: four defensive layers

Any blocking result stops installation. After all layers pass, generate an SBOM, compare CVEs, and enrich with EPSS/KEV.

### 1. Official-registry existence and health

| Check | Source / threshold | Result |
|---|---|---|
| Existence | npm `registry.npmjs.org/<pkg>`; PyPI `pypi.org/pypi/<pkg>/json`; HTTP 404 | Blocking `vibesec.g1.hallucinated-package` |
| Weekly downloads | npm `api.npmjs.org/downloads/point/last-week/<pkg>`; PyPI `pypistats.org/api/packages/<pkg>/recent` | Below 1,000: advisory `low-download-package`; with suspicious similarity: blocking |
| Initial publication | npm `time.created`; earliest PyPI `upload_time_iso_8601` | Under 30 days: block pending review |
| Versions / maintainers | Fewer than two versions or maintainer change within 30 days | High-risk flag |

Optional SlopCheck/DevSentinel/Socket results retain their native prefixed rule IDs.

### 2. Similarity and blacklist

Normalize case, PyPI `_`/`.`/`-` per PEP 503, npm scopes separately, and confusables such as I/l and 0/o. Compare against popular-package lists. Ignore exact matches and names shorter than four characters. Use optimal-string-alignment edit distance (adjacent swaps count as one): threshold one for names ≤5 characters, two otherwise, or `difflib` ratio ≥0.85. This avoids treating every short unrelated name as a typo. Matches create blocking `hallucinated-package` with `looks_like` notes.

Blacklist categories:

- `confirmed_malicious`: removed/CERT-confirmed packages such as `crossenv`, `colourama`, `jeIlyfish`, `torchtriton`.
- `hallucination_prone`: `axois`, `reqeusts`, `python-dotenv-env`, `yaml`, `beautifulsoup`, and `huggingface-cli` (the actual CLI is supplied by `huggingface-hub`).
- `confusable_legit`: real but misleading names, such as `sklearn` versus `scikit-learn`, or `pytorch` versus `torch`.

Scan `.cursorrules`, `AGENTS.md`, `SKILL.md`, and `**/*.md`, because assistants may execute their installation instructions. Unknown/blacklisted packages yield `rules-file-unknown-package`. Arguments to value-taking flags are paths/URLs, not package names (`-r`, `-e`, `--index-url`, `--registry`; see `VALUE_FLAGS`). Deduplicate each package within a file. G4's invisible-Unicode rule-file check runs alongside this work.

### 3. Installation hooks

Inspect npm `preinstall`, `install`, `postinstall`, `prepare`, and Python setup/build hooks without executing untrusted build code.

| Signal | Examples | Decision |
|---|---|---|
| Network | curl/wget/fetch/HTTP/axios/urllib/requests/socket | Network alone: advisory; combine with sensitive access/execution: block |
| Environment | `process.env`, `os.environ`, `os.getenv`, token/secret/key/password variables | Network + environment: blocking `postinstall-egress` (CWE-506) |
| Credential paths | `.aws`, `.npmrc`, `.pypirc`, `.ssh`, `.claude`, gcloud, Docker config, `.gitconfig`, `.netrc`, kubeconfig, `.env` | Blocking |
| Local AI CLI abuse | claude/gemini/codex/aider with unattended or permission-bypass flags | Blocking |
| Dynamic execution | child_process/execSync/subprocess/os.system/eval/new Function, base64 decoding, piping to shell | With network: blocking; alone: advisory |

`scripts/g1_slopcheck.py → install_hook_finding()` classifies npm hooks. Benign hooks such as `node-gyp rebuild` do not automatically count as egress. Downloading a tarball for inspection is different from installing it; Python download/build tooling may execute metadata hooks, so handle untrusted source archives in isolation.

For L2+, optional dynamic testing runs installation in a network-isolated container, observing `strace -f -e trace=network` or a proxy; any attempted external connection blocks.

### 4. Release cooldown

Use npm `time[version]` or PyPI release timestamps. Age below configured `cooldown_days` yields blocking `vibesec.g1.cooldown-violation`. Supported policy range is 7–14 days; default 14. It applies to new versions of old packages too. Missing lockfiles fail G1. Emergency security updates require AppSec-approved `allowlist.yaml`, `bypass: [cooldown]`, and expiry no longer than 14 days.

### SBOM and vulnerability enrichment

`scripts/g1_sbom.py` verifies `VS-G1-SBOM`:

1. Export the tested commit with `git archive`, excluding working-tree `node_modules`/`.venv`. Generate twice; component sets must match, ignoring serial number, timestamp, and bom-ref.
2. Require CycloneDX, spec ≥1.4, and a component list.
3. Every pinned version in package-lock, uv.lock, poetry.lock, or pinned requirements text must appear by purl. Missing components yield one `sbom-incomplete` finding per lockfile and fail coverage. Enable `SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES`: build tools are supply-chain inputs. In one MultiAgentBeta test, disabling it omitted 111 of 119 frontend packages.

Missing/failing Syft, invalid format, nondeterminism, or unsupported pnpm/yarn locks yield incomplete (exit 2), with the control untested.

```bash
python3 scripts/g1_sbom.py --target . --sbom reports/sbom.cdx.json \
  --sarif reports/g1-sbom.sarif --json reports/g1-sbom.json --merge-gate reports/g1-gate.json
grype sbom:reports/sbom.cdx.json -o sarif --file reports/grype.sarif
trivy sbom reports/sbom.cdx.json --format sarif --output reports/trivy.sarif --scanners vuln
trivy fs . --scanners vuln,secret,misconfig --format sarif --output reports/trivy-fs.sarif
```

Query FIRST EPSS and CISA KEV for each actual CVE. Keep `cvss_vector`, `cvss_score`, `epss`, `epss_date`, `kev`, and `kev_date` separate. KEV yields blocking/P1; EPSS sorts remediation without changing severity. `scripts/g1_kev.py` merges PR results according to mode; nightly emits `vibesec.g1.kev-hit`, exits 1, and triggers issue notification. Missing Grype/KEV input exits 2 and reports incomplete. Preserve feed publication time and SBOM artifacts for audit/compliance evidence.

## Automation

PR sequence: checkout without installing target dependencies → compute relevant manifest/lock/rule-file diffs → four-layer checks (24-hour registry cache; failure incomplete) → install with scripts disabled, enabling only explicitly allowed build scripts → validated Syft SBOM → Grype/Trivy and EPSS/KEV → SARIF/gate coverage for `ASVS5-V15.2`, slopsquatting, cooldown, hooks, and SBOM. Pre-commit performs fast layers 1/2/4.

```bash
python3 scripts/g1_slopcheck.py --target ../MultiAgentBeta \
  --sarif reports/raw/G1/slopcheck.sarif --gate reports/raw/G1/slopcheck-gate.json > reports/raw/G1/slopcheck.json
```

With only `--target`, scan all tracked manifests/rule files (`scope: full`). Changed files, staged/base options, and relative paths refer to the target. Configuration/lists/policy remain from this repository; repository-path policy exceptions do not apply externally. Unsupported pnpm/yarn locks are explicitly incomplete.

Parse package-lock v1–3 entries, resolving aliases and skipping workspace links. Check existence, cooldown, hooks, downloads, and blacklist for all packages, but name similarity only for direct dependencies (root/workspace declarations; v1 uses adjacent package.json). For requirements locks, infer transitives from other packages' `requires_dist`; self-dependencies do not count. Missing metadata defaults to direct checking, not omission. Nonregistry resolved sources (git/file/tarball/private registry) or non-semver versions are incomplete. Deduplicate name/version queries, use eight concurrent registry requests, retry transport failures/timeouts/429/5xx twice, and do not retry 404.

## Tools and configuration

Custom checks use `config/slopsquat/*.yaml`/`*.txt`; Syft emits CycloneDX (SPDX optional); Grype compares SBOMs with NVD/GHSA; Trivy covers vulnerabilities/secrets/IaC/K8s (Apache-2.0). Optional Socket/DevSentinel tokens belong in repository secrets; SlopCheck/SlopScan inspect agent-rule documentation. EPSS/KEV settings are in `cooldown.yaml.sbom.enrich`.

## Blocking policy

| Rule (prefix `vibesec.g1.`) | Tier | CWE |
|---|---|---|
| hallucinated-package, cooldown-violation, rules-file-unknown-package | Blocking | 1357 |
| postinstall-egress | Blocking | 506 |
| low-download-package | Advisory; similarity can escalate | 1357 |
| vulnerable-dependency | Advisory; KEV emits separate blocking kev-hit | 1395 |
| unmaintained-dependency | Advisory | 1104 |
| sbom-missing-provenance | Advisory | 1357 |
| sbom-incomplete | Advisory | No matching CWE; see catalog notes |

Nightly maintenance checks deps.dev for deprecated versions or a latest release older than `unmaintained_days` (730 by default). Unknown/failed queries are incomplete; this repository itself and GitHub Actions entries are not applicable. Nightly provenance uses `actions/attest-build-provenance`; `g1_provenance.py` verifies the signature and this repository's nightly signer with `gh attestation verify --signer-workflow`. Missing SBOM/gh, permission/network errors are incomplete. The actual policy file governs final tiers.

### Package exceptions

`load_allowlist()` accepts only valid, unexpired entries; rejected entries appear in `ignored_allowlist` and gate reasons.

- Required: `package`, `approved_by`, `expires` (YYYY-MM-DD), `reason`, `bypass`.
- `ecosystem`: npm/pypi; omitted means either. Normalize names as above.
- `version`: omitted/null means all; accept exact versions (optionally `==`) or conjunctive comparisons such as `>=2,<3`. Reject caret, tilde, wildcard, and OR ranges; prereleases do not match ranges.
- `bypass`: only `registry_health`, `low_download`, `cooldown`, `blacklist`, `similarity`. Hook and KEV bypasses invalidate the entire entry.

Always execute all checks. A matching authorized exception demotes only its designated finding to advisory while retaining approver, expiry, ticket, and reason. Package exceptions are not path-bound and also apply with external targets.

## Mapped controls

`ASVS5-V15.2` (local section-level VibeSec extension); `VS-G1-SLOPSQUAT`, `VS-G1-COOLDOWN`, `VS-G1-INSTALL-HOOK`, `VS-G1-SBOM`, plus rule-file Unicode control. CWE 1357/829/506/1395/1104; OWASP `LLM03:2025`/`LLM09:2025`; MAESTRO L1/L7.

## Verification

Test typo packages, a legitimate package released three days ago, approved emergency versions with tickets, and hallucinated names in agent rules. Use non-executable prose for malicious-package examples. Test fake hooks accessing network/tokens, registry outages yielding incomplete, reproducible/complete SBOMs (`python3 scripts/g1_sbom.py selftest`), separate CVSS/EPSS fields, and policy-derived priorities. Target PR wall time under three minutes, under 60 seconds with a warm cache.
