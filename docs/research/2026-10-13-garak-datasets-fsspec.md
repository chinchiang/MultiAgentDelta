[正體中文（臺灣）](#zh-tw) | [English](#english)

<a id="zh-tw"></a>

# garak 0.17.0 是否走得到 datasets folder-based builder 與 fsspec `ReferenceFileSystem`（issue #128 待確認第 3 項）

研究日期：2026-10-13。性質：唯讀原始碼查核，沒有執行、import 或安裝任何下載的套件。

## 問題

`requirements-garak.txt` 鎖定 `garak==0.17.0`、`datasets==3.6.0`、`fsspec==2025.3.0`。issue #128 列出兩個無法升級的漏洞：

- GHSA-379c-qx7v-6h59（datasets，Medium）：folder-based builder 的 `file_name` 路徑穿越。
- GHSA-27vj-qcqg-25rc（fsspec，High）：`ReferenceFileSystem` 的 Jinja2 SSTI。

要回答的是：staging 的 G6 garak 執行是否走得到這兩條觸發路徑？garak 0.17.0 整體有沒有程式碼呼叫這兩條路徑？

## 方法

### 版本與取得方式

每個套件各放一個全新的空目錄，以 `pip download --no-deps --only-binary :all:` 下載 wheel，用 `unzip` 解壓，只用 `grep`／`sed` 閱讀。

| 套件 | 檔案 | SHA-256 | 與 `requirements-garak.txt` 比對 | METADATA |
|---|---|---|---|---|
| garak | `garak-0.17.0-py3-none-any.whl` | `9a67e629…db145` | 相符 | `Name: garak`、`Version: 0.17.0`；`Requires-Dist: datasets>=3.0.0,<4.0` |
| datasets | `datasets-3.6.0-py3-none-any.whl` | `25000c4a…cd1b` | 相符 | `Version: 3.6.0`；`Requires-Dist: fsspec[http]<=2025.3.0,>=2023.1.0` |
| fsspec | `fsspec-2025.3.0-py3-none-any.whl` | `efb87af3…b1b3` | 相符 | `Version: 2025.3.0` |
| huggingface_hub（輔助） | `huggingface_hub-1.33.0-py3-none-any.whl` | `04e434b0…b5c07eb899` | 相符 | `Version: 1.33.0` |

advisory 原文以 `gh api /advisories/<GHSA>` 取得。

### 我們實際的執行方式（repo 內）

- `.github/workflows/staging-blackbox.yml:309-355`「G6 garak」步驟：以 `_trusted/scripts/garak_config.py` 從 `_trusted/config/garak/vibesec.probes.yaml` 產生設定（`:342`），再執行 `garak --config "$RUNNER_TEMP/garak.yaml" --report_prefix g6-garak`（`:350`）。沒有 `--spec`、`--detectors`、`--buffs` 等覆寫參數。
- `scripts/garak_config.py`：只把佔位 `uri` 換成 `$VIBESEC_TARGET_URL/chat`，其餘設定不變。
- `config/garak/vibesec.probes.yaml`：`run.spec.include` = `probes.promptinject`、`probes.dan`、`probes.encoding`、`probes.leakreplay`、`probes.web_injection`（`:30-36`）；`target_type: rest`（`:39`）；`detector_spec: auto`、`extended_detectors: false`、`buff_spec: null`（`:48-50`）；`probes.encoding.payloads: ["default", "xss"]`（`:76`）。

### 搜尋的關鍵字與範圍

| 範圍 | 關鍵字 | 結果 |
|---|---|---|
| garak 0.17.0 全部檔案（`garak/`，含非 `.py`） | `fsspec`、`ReferenceFileSystem`、`reference://`、`kerchunk`、`filesystem(` | **0 筆** |
| 同上 | `jinja2` | **0 筆** |
| 同上 | `load_dataset`、`from datasets`、`import datasets`、`"datasets"`／`'datasets'` | 4 個呼叫點（見下） |
| 同上 | `imagefolder`、`audiofolder`、`videofolder`、`pdffolder`、`FolderBased`、`folder_based`、`data_dir` | 只有 garak 自己的 `_config.transient.data_dir`、`visual_jailbreak.py` 的本機目錄變數，**沒有** folder-based builder 的使用 |
| 同上 | `hf_hub_download`、`snapshot_download`、`HfFileSystem`、`huggingface_hub`、`hf://` | 只有 `probes/fileformats.py:17-18,98,118`（下載模型 repo 檔案，不經 datasets） |
| 同上 | `save_to_disk`、`push_to_hub` | **0 筆** |
| datasets 3.6.0（`datasets/`） | `ReferenceFileSystem`、`"reference"`、`reference://`、`kerchunk` | **0 筆** |
| huggingface_hub 1.33.0 | `ReferenceFileSystem`、`"reference"`、`reference://` | **0 筆** |
| fsspec 2025.3.0（排除 `implementations/reference.py` 本身） | `"reference"`、`ReferenceFileSystem` | 只有 `fsspec/registry.py:183` 的協定註冊 |

## 發現

### 1. advisory 原文的觸發條件

對應的 CVE 與 CWE 編號見 advisory 原文；本 repo 的 `config/catalogs/` 沒有收錄，依 AGENTS.md 規則 3 這裡只以 GHSA ID 引用。

- **GHSA-379c-qx7v-6h59**：`vulnerable_version_range: < 5.0.1`、`first_patched_version: 5.0.1`、`vulnerable_functions: []`。描述：folder-based builder 未驗證 metadata 的 `file_name` 欄位就與資料集目錄相接；攻擊者提供含 `../` 的 `file_name` 可讀任意本機檔案，**在呼叫 `save_to_disk` 或 `push_to_hub` 時**被嵌入輸出。也就是需要：(a) 載入的資料集由 folder-based builder（`imagefolder`／`audiofolder`／`videofolder`／`pdffolder`）處理，(b) 攻擊者控制該資料集的 metadata 檔。
- **GHSA-27vj-qcqg-25rc**：`vulnerable_version_range: >= 0.9.0, < 2026.6.0`、`first_patched_version: 2026.6.0`、`vulnerable_functions: []`。描述：`fsspec.implementations.reference.ReferenceFileSystem` 以未沙箱化的 `jinja2.Template(...).render(...)` 渲染 references JSON（Kerchunk 格式）的欄位；觸發方式是受害者以 `fsspec.filesystem("reference", fo=URL)` 或 `reference://` 開啟攻擊者控制的 references JSON。
- 在 fsspec 2025.3.0 中三個 sink 都在：`fsspec/implementations/reference.py:1006-1007`（`_render_jinja`）、`:1038-1040`（`_process_templates`）、`:1062-1071`（`_process_gen`）；類別定義 `:596`、`protocol = "reference"` `:611`；協定註冊 `fsspec/registry.py:183`。

### 2. garak 0.17.0 中所有 datasets 呼叫點

全部都是**函式內延遲 import**（模組載入、plugin cache 建立時不會執行）：

| 呼叫點（garak 0.17.0） | 資料集來源 | 預設 active | 是否在我們的 spec 內 |
|---|---|---|---|
| `garak/probes/sysprompt_extraction.py:64,66`：`load_dataset(dataset_name, split="train", trust_remote_code=False)` | `DEFAULT_PARAMS.system_prompt_sources`（`:45-48`）：`garak-llm/drh-System-Prompt-processed`、`garak-llm/tm-system_prompt` | `active = True`（`:41`） | 否 |
| `garak/probes/audio.py:69,81`：`load_dataset("garak-llm/audio_achilles_heel")`，再逐筆讀 `item["audio"]` 寫檔 | 寫死的 Hub 名稱 | `active = False`（`:43`） | 否 |
| `garak/probes/goat.py:278,280`：`load_dataset(self.attack_hf_dataset, **self.attack_hf_dataset_load_kwargs)` | `DEFAULT_PARAMS`（`:135-137`）：`JailbreakBench/JBB-Behaviors`；可由設定覆寫 | `active = False`（`:107`） | 否 |
| `garak/detectors/packagehallucination.py:56,61`：`datasets.load_dataset(self.dataset_name, split="train")`，在 `detect()` 第一次呼叫時載入（`:105,108`） | `garak-llm/pypi-20241031` 等（`:145,188,209,238,270,294,313`） | 只由 `packagehallucination` 探針使用 | 否 |

四處都傳入 Hub 名稱（`org/name` 形式），沒有任何一處傳入本機目錄、`data_dir`、`data_files`，也沒有明確指定 `"imagefolder"`／`"audiofolder"` 等 builder 名稱。

### 3. datasets 3.6.0 何時會選到 folder-based builder

- `datasets/load.py:1490-1516`（`dataset_module_factory`）：`path` 是 packaged module 名稱（如 `"imagefolder"`）→ `PackagedDatasetModuleFactory`；`path` 是本機目錄 → `LocalDatasetModuleFactoryWithoutScript`。
- `datasets/load.py:1521` 起：`path` 是 Hub 名稱且 repo **沒有** dataset script → `HubDatasetModuleFactoryWithoutScript`（`:1621-1629`），其 `get_module` 呼叫 `infer_module_for_data_files`（`:1025`）。
- `datasets/load.py:503-537`（`infer_module_for_data_files_list`）依最常見副檔名查 `_EXTENSION_TO_MODULE`；`datasets/packaged_modules/__init__.py:80-87` 把圖片、音訊、影片、PDF 副檔名對應到 `imagefolder`／`audiofolder`／`videofolder`／`pdffolder`。
- 因此**從 Hub 下載、沒有 script、以音訊或圖片檔為主的資料集，會經由 folder-based builder 處理**。
- 漏洞處：`datasets/packaged_modules/folder_based_builder/folder_based_builder.py:368-374`，metadata 的 `file_name` 被取出後以 `os.path.normpath` 正規化、再 `os.path.join(downloaded_metadata_dir, file_relpath)`；`normpath` 不會移除開頭的 `..`。

### 4. datasets 3.6.0 與 fsspec 的介面

datasets 3.6.0 本身沒有寫死使用 `reference` 協定（關鍵字 0 筆），但多處以 `url_to_fs(...)`／`fsspec.open(...)` 依 URL 字串決定檔案系統，例如 `datasets/data_files.py:350,483`、`datasets/utils/file_utils.py:304,326,561,647,747,949`、`datasets/load.py:2138`。協定是由傳進來的路徑決定的。

## 對 #128 的結論

### GHSA-379c-qx7v-6h59（datasets folder-based builder 路徑穿越）

- **我們的 staging G6 garak：確認不可達。** 我們選的 5 個探針模組（`promptinject`、`dan`、`encoding`、`leakreplay`、`web_injection`）及其 detector（`promptinject`、`dan`、`mitigation`、`encoding`、`base`、`leakreplay`、`web_injection`），都不在 garak 中 4 個 datasets 呼叫點之列（第 2 節，全 garak 搜尋只有這 4 處）。`rest` generator 也不使用 datasets。workflow 沒有傳入其他 spec 或 detector 覆寫。這次執行根本不會呼叫 `datasets.load_dataset`。另外，garak 全部原始碼都沒有呼叫 `save_to_disk`／`push_to_hub`，而這是 advisory 描述中把讀到的檔案嵌進輸出的步驟。
- **garak 整體（我們沒用到的部分）：可達，但需要攻擊者控制 Hub 上的資料集 repo。** `probes.audio.AudioAchillesHeel` 載入 `garak-llm/audio_achilles_heel`；如果這個 repo 沒有 script、而且以音訊檔為主，依第 3 節的推導會走 `audiofolder`。這個 repo 的實際結構不在本次讀取的原始碼範圍內，**無法判定**。`goat` 的 `attack_hf_dataset` 可由設定指向任何資料集，所以能控制 garak 設定的人可以選到 folder-based 資料集。即使走到 folder-based builder，advisory 描述的外洩步驟（`save_to_disk`／`push_to_hub`）在 garak 中也不存在；`audio.py:82-86` 會解碼 `item["audio"]` 並寫入本機，這樣算不算 advisory 定義的外洩，本次無法判定。

### GHSA-27vj-qcqg-25rc（fsspec `ReferenceFileSystem` SSTI）

- **我們的 staging G6 garak：確認不可達。** garak 0.17.0 全部檔案沒有 `fsspec`、`ReferenceFileSystem`、`reference://`、`jinja2`（0 筆）；我們的探針完全不呼叫 datasets，所以 datasets 的 fsspec 介面也不會被用到。
- **garak 整體：在已讀到的程式碼中沒有直接使用；只有在攻擊者能控制交給 datasets 的路徑或 storage options 時，理論上才可能。** garak 自己從不使用 `reference` 協定；datasets 3.6.0 與 huggingface_hub 1.33.0 也沒有寫死使用（0 筆）。剩下的唯一途徑，是 datasets 依傳入的 URL 協定建立檔案系統（第 4 節），而 garak 傳入的都是 Hub 名稱。Hub 資料集的 README `configs.data_files` 能不能寫入 `reference://` 或 `reference::` 鏈式 URL 並帶 `fo`，本次**沒有追完**，列為無法判定。

## 限制與未涵蓋處

- 只讀 wheel 內容，沒有執行 garak，所以 spec 解析（例如 `probes.dan` 會選到哪些 class）是依原始碼判讀，沒有執行期驗證。不過結論不依賴這一點：我們的 5 個模組都沒有 datasets 呼叫。
- 沒有檢查 Hugging Face Hub 上 `garak-llm/*`、`JailbreakBench/JBB-Behaviors` 等 repo 的實際檔案結構，也不知道它們會走 script、Parquet export 還是 folder-based builder。
- 沒有閱讀 torch（`requirements-garak.txt` 註明 fsspec 也是 torch 的相依）、transformers 等其他遞移相依是否使用 `ReferenceFileSystem`。我們用的 detector 都是 `StringDetector` 或 `Detector` 子類，沒有用 `HFDetector`，但 torch 是否在 import 時碰到 fsspec reference 未查證。
- 沒有追 datasets 內 `url_to_fs` 在 Hub 資料集 `data_files` 解析時是否接受任意協定（第 4 節）。
- 「不可達」的前提是 staging 繼續以 `_trusted/` 的設定、不加 `--spec` 覆寫執行。如果日後把 `probes.sysprompt_extraction`（預設 active）、`packagehallucination`、`audio`、`goat` 加入 spec，或使用 `--spec all`，第 2 節的呼叫點就會被執行，需要重新評估。

---

<a id="english"></a>

# Does garak 0.17.0 reach the datasets folder-based builder or the fsspec `ReferenceFileSystem`? (issue #128, open item 3)

Research date: 2026-10-13. Nature: read-only source review; none of the downloaded packages was executed, imported, or installed.

## Question

`requirements-garak.txt` pins `garak==0.17.0`, `datasets==3.6.0`, and `fsspec==2025.3.0`. Issue #128 lists two vulnerabilities that cannot be upgraded away:

- GHSA-379c-qx7v-6h59 (datasets, Medium): path traversal through `file_name` in the folder-based builders.
- GHSA-27vj-qcqg-25rc (fsspec, High): Jinja2 SSTI in `ReferenceFileSystem`.

The questions are whether the staging G6 garak run reaches either trigger path, and whether any code in garak 0.17.0 as a whole calls either path.

## Method

### Versions and acquisition

Each package went into its own fresh, empty directory. Wheels were fetched with `pip download --no-deps --only-binary :all:`, extracted with `unzip`, and read only with `grep`/`sed`.

| Package | File | SHA-256 | Against `requirements-garak.txt` | METADATA |
|---|---|---|---|---|
| garak | `garak-0.17.0-py3-none-any.whl` | `9a67e629…db145` | matches | `Name: garak`, `Version: 0.17.0`; `Requires-Dist: datasets>=3.0.0,<4.0` |
| datasets | `datasets-3.6.0-py3-none-any.whl` | `25000c4a…cd1b` | matches | `Version: 3.6.0`; `Requires-Dist: fsspec[http]<=2025.3.0,>=2023.1.0` |
| fsspec | `fsspec-2025.3.0-py3-none-any.whl` | `efb87af3…b1b3` | matches | `Version: 2025.3.0` |
| huggingface_hub (auxiliary) | `huggingface_hub-1.33.0-py3-none-any.whl` | `04e434b0…b5c07eb899` | matches | `Version: 1.33.0` |

Advisory text was fetched with `gh api /advisories/<GHSA>`.

### How we actually run garak (in this repo)

- `.github/workflows/staging-blackbox.yml:309-355`, the "G6 garak" step: `_trusted/scripts/garak_config.py` renders the config from `_trusted/config/garak/vibesec.probes.yaml` (`:342`), then the step runs `garak --config "$RUNNER_TEMP/garak.yaml" --report_prefix g6-garak` (`:350`). There is no `--spec`, `--detectors`, or `--buffs` override.
- `scripts/garak_config.py` replaces only the placeholder `uri` with `$VIBESEC_TARGET_URL/chat` and leaves everything else unchanged.
- `config/garak/vibesec.probes.yaml`: `run.spec.include` = `probes.promptinject`, `probes.dan`, `probes.encoding`, `probes.leakreplay`, `probes.web_injection` (`:30-36`); `target_type: rest` (`:39`); `detector_spec: auto`, `extended_detectors: false`, `buff_spec: null` (`:48-50`); `probes.encoding.payloads: ["default", "xss"]` (`:76`).

### Search keywords and scope

| Scope | Keywords | Result |
|---|---|---|
| All of garak 0.17.0 (`garak/`, including non-`.py` files) | `fsspec`, `ReferenceFileSystem`, `reference://`, `kerchunk`, `filesystem(` | **0 hits** |
| Same | `jinja2` | **0 hits** |
| Same | `load_dataset`, `from datasets`, `import datasets`, `"datasets"`/`'datasets'` | 4 call sites (below) |
| Same | `imagefolder`, `audiofolder`, `videofolder`, `pdffolder`, `FolderBased`, `folder_based`, `data_dir` | Only garak's own `_config.transient.data_dir` and a local directory variable in `visual_jailbreak.py`; **no** use of a folder-based builder |
| Same | `hf_hub_download`, `snapshot_download`, `HfFileSystem`, `huggingface_hub`, `hf://` | Only `probes/fileformats.py:17-18,98,118` (downloads model repo files without going through datasets) |
| Same | `save_to_disk`, `push_to_hub` | **0 hits** |
| datasets 3.6.0 (`datasets/`) | `ReferenceFileSystem`, `"reference"`, `reference://`, `kerchunk` | **0 hits** |
| huggingface_hub 1.33.0 | `ReferenceFileSystem`, `"reference"`, `reference://` | **0 hits** |
| fsspec 2025.3.0 (excluding `implementations/reference.py` itself) | `"reference"`, `ReferenceFileSystem` | Only the protocol registration at `fsspec/registry.py:183` |

## Findings

### 1. Trigger conditions in the advisory text

The corresponding CVE and CWE IDs are in the advisory text. They are not in this repo's `config/catalogs/`, so per AGENTS.md rule 3 this note cites only the GHSA IDs.

- **GHSA-379c-qx7v-6h59**: `vulnerable_version_range: < 5.0.1`, `first_patched_version: 5.0.1`, `vulnerable_functions: []`. Description: the folder-based builders join the metadata `file_name` field to the dataset directory without validating it. An attacker who supplies a `file_name` containing `../` can read arbitrary local files, which are embedded into the output **when `save_to_disk` or `push_to_hub` is called**. Two conditions are needed: (a) the dataset is processed by a folder-based builder (`imagefolder`/`audiofolder`/`videofolder`/`pdffolder`), and (b) the attacker controls that dataset's metadata file.
- **GHSA-27vj-qcqg-25rc**: `vulnerable_version_range: >= 0.9.0, < 2026.6.0`, `first_patched_version: 2026.6.0`, `vulnerable_functions: []`. Description: `fsspec.implementations.reference.ReferenceFileSystem` renders fields of a references JSON (Kerchunk format) with un-sandboxed `jinja2.Template(...).render(...)`. It is triggered when the victim opens an attacker-controlled references JSON with `fsspec.filesystem("reference", fo=URL)` or `reference://`.
- All three sinks are present in fsspec 2025.3.0: `fsspec/implementations/reference.py:1006-1007` (`_render_jinja`), `:1038-1040` (`_process_templates`), and `:1062-1071` (`_process_gen`). The class is defined at `:596`, `protocol = "reference"` is at `:611`, and the protocol is registered at `fsspec/registry.py:183`.

### 2. Every datasets call site in garak 0.17.0

All of them are **lazy imports inside functions**, so they do not run when a module is imported or the plugin cache is built.

| Call site (garak 0.17.0) | Dataset source | Default active | In our spec |
|---|---|---|---|
| `garak/probes/sysprompt_extraction.py:64,66`: `load_dataset(dataset_name, split="train", trust_remote_code=False)` | `DEFAULT_PARAMS.system_prompt_sources` (`:45-48`): `garak-llm/drh-System-Prompt-processed`, `garak-llm/tm-system_prompt` | `active = True` (`:41`) | No |
| `garak/probes/audio.py:69,81`: `load_dataset("garak-llm/audio_achilles_heel")`, then reads `item["audio"]` row by row and writes files | Hard-coded Hub name | `active = False` (`:43`) | No |
| `garak/probes/goat.py:278,280`: `load_dataset(self.attack_hf_dataset, **self.attack_hf_dataset_load_kwargs)` | `DEFAULT_PARAMS` (`:135-137`): `JailbreakBench/JBB-Behaviors`; can be overridden in config | `active = False` (`:107`) | No |
| `garak/detectors/packagehallucination.py:56,61`: `datasets.load_dataset(self.dataset_name, split="train")`, loaded on the first `detect()` call (`:105,108`) | `garak-llm/pypi-20241031` and others (`:145,188,209,238,270,294,313`) | Used only by the `packagehallucination` probes | No |

All four pass a Hub name (`org/name`). None passes a local directory, `data_dir`, or `data_files`, and none names a builder such as `"imagefolder"` or `"audiofolder"` explicitly.

### 3. When datasets 3.6.0 selects a folder-based builder

- `datasets/load.py:1490-1516` (`dataset_module_factory`): if `path` is a packaged module name (such as `"imagefolder"`), it uses `PackagedDatasetModuleFactory`; if `path` is a local directory, it uses `LocalDatasetModuleFactoryWithoutScript`.
- `datasets/load.py:1521` onward: if `path` is a Hub name and the repo has **no** dataset script, it uses `HubDatasetModuleFactoryWithoutScript` (`:1621-1629`), whose `get_module` calls `infer_module_for_data_files` (`:1025`).
- `datasets/load.py:503-537` (`infer_module_for_data_files_list`) looks up the most common file extension in `_EXTENSION_TO_MODULE`. `datasets/packaged_modules/__init__.py:80-87` maps image, audio, video, and PDF extensions to `imagefolder`/`audiofolder`/`videofolder`/`pdffolder`.
- So **a Hub dataset that has no script and consists mostly of audio or image files is processed by a folder-based builder**.
- The vulnerable code is `datasets/packaged_modules/folder_based_builder/folder_based_builder.py:368-374`. The metadata `file_name` is taken out, normalized with `os.path.normpath`, and then passed to `os.path.join(downloaded_metadata_dir, file_relpath)`. `normpath` does not remove leading `..` components.

### 4. How datasets 3.6.0 uses fsspec

datasets 3.6.0 never uses the `reference` protocol directly (0 keyword hits). In many places, though, it picks the filesystem from the URL string through `url_to_fs(...)`/`fsspec.open(...)`, for example `datasets/data_files.py:350,483`, `datasets/utils/file_utils.py:304,326,561,647,747,949`, and `datasets/load.py:2138`. The protocol is decided by the path that is passed in.

## Conclusions for #128

### GHSA-379c-qx7v-6h59 (datasets folder-based builder path traversal)

- **Our staging G6 garak run: confirmed unreachable.** Our five probe modules (`promptinject`, `dan`, `encoding`, `leakreplay`, `web_injection`) and their detectors (`promptinject`, `dan`, `mitigation`, `encoding`, `base`, `leakreplay`, `web_injection`) are not among garak's four datasets call sites (Section 2; a search of all of garak found only those four). The `rest` generator does not use datasets either, and the workflow passes no other spec or detector override. This run never calls `datasets.load_dataset`. In addition, no garak code calls `save_to_disk`/`push_to_hub`, which is the step the advisory names for embedding the files it reads into the output.
- **garak as a whole (parts we do not use): reachable, but only if an attacker controls a dataset repo on the Hub.** `probes.audio.AudioAchillesHeel` loads `garak-llm/audio_achilles_heel`. Following Section 3, if that repo has no script and consists mostly of audio files, it goes through `audiofolder`. The repo's actual layout is outside the source code read here, so this is **undetermined**. The `attack_hf_dataset` option of `goat` can point to any dataset, so anyone who controls the garak config could pick a folder-based dataset. Even if a folder-based builder runs, the exfiltration step the advisory describes (`save_to_disk`/`push_to_hub`) does not exist in garak. `audio.py:82-86` decodes `item["audio"]` and writes it to local disk; whether that counts as disclosure in the advisory's sense is undetermined.

### GHSA-27vj-qcqg-25rc (fsspec `ReferenceFileSystem` SSTI)

- **Our staging G6 garak run: confirmed unreachable.** No file in garak 0.17.0 contains `fsspec`, `ReferenceFileSystem`, `reference://`, or `jinja2` (0 hits). Our probes never call datasets, so datasets' fsspec entry points are never used either.
- **garak as a whole: no direct use in the code read; theoretically possible only if an attacker controls the path or storage options handed to datasets.** garak itself never uses the `reference` protocol, and neither datasets 3.6.0 nor huggingface_hub 1.33.0 uses it directly (0 hits). The only remaining route is datasets building a filesystem from the protocol of the URL it receives (Section 4), and garak only ever passes Hub names. This review **did not trace** whether a Hub dataset's README `configs.data_files` can contain a `reference://` or chained `reference::` URL together with `fo`, so that remains undetermined.

## Limitations and gaps

- Only the wheel contents were read and garak was never run, so spec resolution (for example, which classes `probes.dan` selects) is based on reading the source, without runtime confirmation. The conclusion does not depend on this, because none of our five modules contains a datasets call.
- The actual file layout of Hub repos such as `garak-llm/*` and `JailbreakBench/JBB-Behaviors` was not checked, so it is unknown whether they load via a script, the Parquet export, or a folder-based builder.
- Other transitive dependencies such as torch (`requirements-garak.txt` notes that fsspec is also a torch dependency) and transformers were not read for `ReferenceFileSystem` use. All of our detectors are `StringDetector` or `Detector` subclasses and none is an `HFDetector`, but whether torch touches fsspec reference at import time was not verified.
- This review did not trace whether datasets' `url_to_fs` accepts arbitrary protocols when resolving `data_files` for Hub datasets (Section 4).
- The "unreachable" verdict assumes staging keeps running with the `_trusted/` config and no `--spec` override. If `probes.sysprompt_extraction` (active by default), `packagehallucination`, `audio`, or `goat` is later added to the spec, or `--spec all` is used, the Section 2 call sites will run and the assessment must be redone.
