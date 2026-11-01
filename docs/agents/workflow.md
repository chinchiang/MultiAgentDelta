[正體中文（臺灣）](#zh-tw) | [English](#english)

<a id="zh-tw"></a>

# Agent 工作流程：實作 ticket、開 PR、合併

實作任何 ticket（`/mattpocock-skills:implement`）時依本檔執行。規則以 `AGENTS.md` 為準，本檔只寫流程、判準與容易踩的坑。

## 每張 ticket 的步驟

0. **準備 main 的 worktree**：`git fetch -q origin && git worktree add /tmp/wt-main origin/main`。第 3、4、7 步都用這份 `origin/main`；第 9 步合併後移除（`git worktree remove /tmp/wt-main`）。
1. **TDD**：先寫測試，確認是**紅燈**。紅燈要是回報 FAIL，不是崩潰。測試注入見下方「容易踩的坑」。
2. **突變測試**：對每條新檢查各做一個突變，確認突變真的套用了（diff 非空），而且 selftest 回報 FAIL，不是崩潰。突變和 mode 切換都在 `/tmp/wt-main`、另一個 worktree 或受信任樹副本（`vibesec_policy.tree_copy`）裡做，追蹤中的檔案（例如 `vibesec.yaml`）保持原樣。
3. **worktree 比對**：用同一組情境分別跑 `/tmp/wt-main` 和分支，逐項比對輸出與退出碼。比對前要正規化時間戳、SHA、暫存路徑、duration。完成條件是兩邊一致，或每項差異都在 PR 列為預期的變更；兩邊同時拋例外，或同時沒有產出，不算一致。
4. **評測逐案比對**：在同一台機器、用同一組參數，分別在 `/tmp/wt-main` 和分支各跑一次 `run_evals`，再用 `compare_evals.py` 比對，必須 exit 0（見「判準」）。動到 G5、G6 或 workflow 時，接 vulnapp 的版本也要再比對一次（拿掉 `--no-target`）。
5. **validate**：`python3 scripts/validate.py` 必須 0 個錯誤。它會自動執行所有 `scripts/*.py` 的 selftest，不必另外跑迴圈。
6. **code review**：`/mattpocock-skills:code-review`。Standards、Spec 兩個 sub-agent 平行執行，結果分兩軸彙整，每軸各寫一句最嚴重的問題。完成條件是兩軸的每項意見都已修正，或在 PR 寫明不改的理由。修正之後，重跑第 2、5 步。
7. **本機 gitleaks**：`gitleaks git --log-opts="--text origin/main..HEAD" --no-banner --redact .`，必須沒有發現。
8. **開 PR、等 CI**：讀閘門表格，對照「判準」。
9. **維護者說了才合併**：`gh pr merge <n> --squash --delete-branch --match-head-commit <sha>`。

其他規則：
- spec 沒涵蓋、而且會影響不變欄位（status、status_reason、findings_count、coverage、退出碼）的地方，先問維護者，附上推薦答案，並把決定寫回 issue 留言。
- PR 要逐項列出「變嚴」的變動（放寬見 AGENTS.md 規則 1）。
- 對外的動作要先問，例如觸發 staging-blackbox、改 issue 標籤。PR 合併、issue 關閉之後，如果 issue 仍掛著 `needs-triage`，先問要不要拿掉。
- commit、PR、issue 都用正體中文；結尾的 attribution 依 harness 的指示。
- 新一輪 architecture review 的流程：`improve-codebase-architecture` → `grilling`（一輪問完當下所有能問的題目，每題附推薦答案）→ `to-spec`（父 issue，標 `ready-for-agent`）→ `to-tickets`（GitHub 原生 sub-issue，加上阻擋關係）→ 依序對每張 ticket 執行 `implement`。

## 判準

### 評測：逐案和 main 相同

```bash
(cd /tmp/wt-main && python3 scripts/run_evals.py --no-network --no-target --baseline evals/baseline.yaml --json /tmp/ev-main.json --md /dev/null)
python3 scripts/run_evals.py --no-network --no-target --baseline evals/baseline.yaml --json /tmp/ev-branch.json --md /dev/null
python3 scripts/compare_evals.py /tmp/ev-main.json /tmp/ev-branch.json   # 0 逐案相同、1 有差異、2 無法比對、4 用法錯誤
```

- 判準是 `compare_evals.py` exit 0，不是絕對數字。
- `evals/baseline.yaml` 是 nightly 完整環境的契約。本機缺工具時，`run_evals --baseline` 一定會報退步、exit 1，這是正常的。
- 兩邊全部都是 untested 時，比對結果也會是逐案相同，但這只代表環境沒有跑到那些案例。被比對的閘門要有實際執行的案例（summary 的 `executed` 大於 0）。
- run_evals 會讀這些工具：`VIBESEC_GITLEAKS` 或 PATH 上的 `gitleaks`、`VIBESEC_CHECKOV` 或 PATH 上的 `checkov`，以及 PATH 上的 `semgrep`、`docker`、`uv`、`git`。缺的工具會讓對應的案例變成 untested。
- **gitleaks**：版本和 SHA-256 要與 `.github/workflows/nightly-full.yml` 的 `GITLEAKS_VERSION`、`GITLEAKS_SHA256` 相同。下載 tarball 之後先 `sha256sum -c`，解壓縮，再把 `VIBESEC_GITLEAKS` 指向解出來的 binary。

參考值（2026-10-17；本機有 gitleaks 8.28.0（`VIBESEC_GITLEAKS`）、`uv`、`docker`，沒有 semgrep、syft、grype、checkov；沒設 `VIBESEC_GITLEAKS` 時，G2 的 7 個案例會變成 untested）：

| 參數 | TP | TN | STATUS_OK | untested |
| --- | --- | --- | --- | --- |
| `--no-network --no-target` | 28 | 25 | 6 | 86 |
| `--no-network`（接 vulnapp） | 47 | 44 | 6 | 48 |

數字對不上時，先比對工具組合，再懷疑程式。

### CI：和最近一個合併的 PR 相同

```bash
read -r n br < <(gh pr list --state merged --limit 1 --json number,headRefName --jq '.[0] | "\(.number) \(.headRefName)"')
gh pr checks "$n"                                                    # pass／skipping 的數量
id=$(gh run list --workflow pr-gates.yml --branch "$br" --limit 1 --json databaseId --jq '.[0].databaseId')
gh run view "$id" --log | grep '| G' | sed 's/.*Z //' | sort -u     # 閘門表格
```

- 本 PR 的 check 數量和閘門表格，要和最近一個合併的 PR 相同；有差異時，逐項說明是哪個改動造成的。
- shadow 下 blocking 發現也是綠燈，所以一定要讀表格，不能只看 check 的顏色。

參考值（2026-10-17）：15 pass／5 skipping。各列由誰決定：

| 閘門 | 狀態 | blocking／advisory | 由誰決定 |
| --- | --- | --- | --- |
| G1 | `pass` | 0／當天 nightly 的筆數 | advisory 是 grype 的已知漏洞（非 KEV），其中包含 #128（遞移相依被上游卡住）；漏洞資料庫每天更新，筆數跟著變，所以以當天 main 的 nightly 為準（指令見表格下方），不和最近合併的 PR 比。PR 改到相依清單或規則檔（含 `*.md`）時，G1 才會掃描，這時會多出一句「忽略的 allowlist 條目：requests…已過期」，見 #210 |
| G2 | `pass` | 0／0 | |
| G3 | `pass` | 0／0 | |
| G4 | `incomplete` | 0／0 | CI 不跑 LLM 審查；enforce 下也不擋，見 #215 |

當天 nightly 的 G1 advisory 筆數：

```bash
nid=$(gh run list --workflow nightly-full.yml --branch main --limit 1 --json databaseId --jq '.[0].databaseId')
jid=$(gh run view "$nid" --json jobs --jq '.jobs[] | select(.name | startswith("G1 全量供應鏈")) | .databaseId')
gh api --allow-escape-sequences "repos/chinchiang/MultiAgentDelta/actions/jobs/$jid/logs" | grep '已知漏洞（非 KEV'
```

## 容易踩的坑

- **版本錯開**：PR CI 用的是 PR head 的 workflow 和 action，呼叫的卻是 `_trusted/`（main）的腳本。action 或 workflow 會用到的新 module 或函式，要先用 prefactor PR 合進 main（#207）。
- **CodeQL 名稱規則**：CodeQL 會把名稱含 `trusted`、`secret`、`key` 的函式回傳值當成敏感資料（#208）。遇到時，把函式改名。
- **gitleaks 誤判成串的識別碼**：程式裡成串以引號括起的識別碼或檔名，會被 gitleaks 的 `generic-api-key` 判成祕密，G2 變成 `fail`。實例有工具別名表（`"api-…": "較長的識別碼字串"`）和舊版 `validate.py` 的 selftest 檔名清單。寫法有兩種：比照 `scripts/gate_verdict.py` 的 `TOOL_ALIASES`，把前綴另存成變數再串接；或者不寫死清單，改由程式推導，例如 `validate.py` 現在自動偵測有 selftest 的腳本。這種誤報一旦進了 main，就會永遠留在 git 歷史裡，nightly 的全歷史掃描每晚都會失敗，只能由 owner 在 `.gitleaksignore` 加指紋（#139；2026-10-12、10-13 各發生一次，見 `.gitleaksignore` 的說明）。推送前見第 7 步。
- **Checkov 卡住**：Checkov 的 check run 偶爾會卡在 `in_progress`，但 SARIF 其實已經收到。重跑 G3 IaC 那個 job 就會恢復。
- **mode**：規則見 ADR 0002。workflow 步驟讀 mode 會被 `ci_invariants.step_mode_decisions` 擋下（#209）；action 輸出 mode 會被 `ci_invariants.action_mode_reader_problems` 擋下（#220）。
- **verdict 的 pending**：verdict 只把 `untested` 當成未完成；`pending` 是「待併入」，要到 `finalize` 才會被視同未實測（#213）。
- **測試注入**：用 `vibesec_policy` 的 `temp_policy_root`、`broken_policy_root`、`modeless_policy_root`、`mode_policy_root(line)`、`tree_copy(line)`、`set_mode_line`、`write_policy_key`，或 `sarif_gate.main_with_policy`。閘門的命令列參數維持不變。
- **`python3 -I`**：g4_static 和 action 都以 `-I` 執行，import 一定要放在 `sys.path.insert` 之後。
- **ID 掃描**：`validate.py` 會掃 scripts 裡的 `vibesec.gN.*`、`VS-G*-*`，測試資料也一樣，所以要用目錄裡存在的 ID。
- **不變式會掃到註解**：`step_mode_decisions` 會略過 bash 的註解行，其他不變式不一定。註解裡改寫說法，避開被禁止的字樣。
- **雙語**：只有雙語集合（見 AGENTS.md「文件語言」）要中英兩段一起改；改 `AGENTS.md` 時要同步改英文譯本 `docs/agents/rules.en.md`；其他文件只寫正體中文。`validate.py` 會檢查集合內的錨點、切換連結與標題結構，以及譯本與 `AGENTS.md` 的標題結構（`scripts/bilingual.py`），句子是否逐一對應要靠 review。
- **selftest 的 mode**：selftest 用 `tree_copy("mode: …")` 固定 mode，不依賴 repo 目前的 `vibesec.yaml`。CI 的 repo-validate 會在 mode 改為 enforce 的副本裡再跑一次 validate，依賴 repo mode 的 selftest 在 PR 階段就會失敗（#223）。
- **staging-blackbox**：repo 沒有設定 `vars.VIBESEC_TARGET_URL`，所以 staging-blackbox 只會打 job 內啟動的 vulnapp。
- **合併條件**：`main` 沒有 required status checks。要確認某個 check 是不是合併條件，用 `gh api repos/chinchiang/MultiAgentDelta/rulesets` 查（#209）。

---

<a id="english"></a>

# Agent workflow: implementing a ticket, opening a PR, merging

Follow this file whenever you implement a ticket (`/mattpocock-skills:implement`). `AGENTS.md` holds the rules; this file covers only the process, the pass criteria, and the gotchas.

## Steps for every ticket

0. **Prepare a main worktree**: `git fetch -q origin && git worktree add /tmp/wt-main origin/main`. Steps 3, 4, and 7 all use this `origin/main`; remove it after the merge in step 9 (`git worktree remove /tmp/wt-main`).
1. **TDD**: write the test first and confirm it is **red**. Red means it reports FAIL rather than crashing. For test injection, see "Gotchas" below.
2. **Mutation testing**: make one mutation per new check, confirm the mutation was actually applied (non-empty diff), and confirm the selftest reports FAIL rather than crashing. Do mutations and mode switches inside `/tmp/wt-main`, another worktree, or a trusted-tree copy (`vibesec_policy.tree_copy`), and leave tracked files (such as `vibesec.yaml`) untouched.
3. **Worktree comparison**: run the same scenarios on `/tmp/wt-main` and on the branch, and compare outputs and exit codes item by item. Normalize timestamps, SHAs, temporary paths, and durations first. The step is done when the two sides match, or when every difference is listed in the PR as an intended change; both sides raising, or both producing nothing, does not count as a match.
4. **Case-by-case eval comparison**: on the same machine with the same flags, run `run_evals` once in `/tmp/wt-main` and once on the branch, then compare with `compare_evals.py`, which must exit 0 (see "Pass criteria"). When G5, G6, or a workflow changes, also compare the vulnapp run (drop `--no-target`).
5. **validate**: `python3 scripts/validate.py` must report 0 errors. It runs every `scripts/*.py` selftest automatically; no separate loop is needed.
6. **Code review**: `/mattpocock-skills:code-review`. Standards and Spec sub-agents run in parallel; report the two axes separately, with one line for the worst issue in each. The step is done when every finding on both axes is fixed or the PR states why it was left as is. After fixing, rerun steps 2 and 5.
7. **Local gitleaks**: `gitleaks git --log-opts="--text origin/main..HEAD" --no-banner --redact .` must find nothing.
8. **Open the PR and wait for CI**: read the gate table and check it against "Pass criteria".
9. **Merge only when the maintainer says so**: `gh pr merge <n> --squash --delete-branch --match-head-commit <sha>`.

Other rules:
- Where the spec is silent and the change affects invariant fields (status, status_reason, findings_count, coverage, exit codes), ask the maintainer with a recommended answer, and record the decision as an issue comment.
- The PR lists every change that makes checks stricter (for relaxing, see AGENTS.md rule 1).
- Ask before outward-facing actions, such as triggering staging-blackbox or changing issue labels. After a PR is merged and its issue closes, if the issue still has `needs-triage`, ask whether to remove it.
- Commits, PRs, and issues are written in Traditional Chinese; the closing attribution follows the harness instructions.
- A new architecture review round: `improve-codebase-architecture` → `grilling` (each round asks every question that can be asked now, each with a recommended answer) → `to-spec` (a parent issue labelled `ready-for-agent`) → `to-tickets` (native GitHub sub-issues with blocking relationships) → `implement` for each ticket in order.

## Pass criteria

### Evals: case-by-case identical to main

```bash
(cd /tmp/wt-main && python3 scripts/run_evals.py --no-network --no-target --baseline evals/baseline.yaml --json /tmp/ev-main.json --md /dev/null)
python3 scripts/run_evals.py --no-network --no-target --baseline evals/baseline.yaml --json /tmp/ev-branch.json --md /dev/null
python3 scripts/compare_evals.py /tmp/ev-main.json /tmp/ev-branch.json   # 0 identical, 1 differences, 2 cannot compare, 4 usage error
```

- The criterion is `compare_evals.py` exiting 0, not the absolute numbers.
- `evals/baseline.yaml` is the contract for nightly's full environment. When local tools are missing, `run_evals --baseline` always reports regressions and exits 1; that is expected.
- Two runs where every case is untested also compare as identical, but that only means the environment ran none of those cases. The gates under comparison must have executed cases (`executed` greater than 0 in the summary).
- run_evals uses these tools: `VIBESEC_GITLEAKS` or `gitleaks` on PATH, `VIBESEC_CHECKOV` or `checkov` on PATH, and `semgrep`, `docker`, `uv`, and `git` on PATH. A missing tool turns its cases into untested.
- **gitleaks**: the version and SHA-256 must match `GITLEAKS_VERSION` and `GITLEAKS_SHA256` in `.github/workflows/nightly-full.yml`. Download the tarball, run `sha256sum -c`, extract it, and point `VIBESEC_GITLEAKS` at the extracted binary.

Reference values (2026-10-17; this machine has gitleaks 8.28.0 (`VIBESEC_GITLEAKS`), `uv`, and `docker`, but not semgrep, syft, grype, or checkov; without `VIBESEC_GITLEAKS`, 7 G2 cases become untested):

| Flags | TP | TN | STATUS_OK | untested |
| --- | --- | --- | --- | --- |
| `--no-network --no-target` | 28 | 25 | 6 | 86 |
| `--no-network` (with vulnapp) | 47 | 44 | 6 | 48 |

When the numbers disagree, compare the tool sets before suspecting the code.

### CI: identical to the most recently merged PR

```bash
read -r n br < <(gh pr list --state merged --limit 1 --json number,headRefName --jq '.[0] | "\(.number) \(.headRefName)"')
gh pr checks "$n"                                                    # pass/skipping counts
id=$(gh run list --workflow pr-gates.yml --branch "$br" --limit 1 --json databaseId --jq '.[0].databaseId')
gh run view "$id" --log | grep '| G' | sed 's/.*Z //' | sort -u     # gate table
```

- This PR's check counts and gate table must match the most recently merged PR; explain every difference by the change that caused it.
- In shadow mode a blocking finding still shows green, so always read the table rather than the check colours.

Reference values (2026-10-17): 15 pass / 5 skipping. What decides each row:

| Gate | Status | blocking/advisory | Decided by |
| --- | --- | --- | --- |
| G1 | `pass` | 0/the count in that day's nightly | The advisory findings are grype known vulnerabilities (not in KEV), including #128 (a transitive dependency blocked upstream). The vulnerability database updates daily and the count moves with it, so compare against that day's nightly on main (command below the table), not against the last merged PR. G1 scans only when the PR touches dependency manifests or rule files (including `*.md`), and then adds the line "忽略的 allowlist 條目：requests…已過期"; see #210 |
| G2 | `pass` | 0/0 | |
| G3 | `pass` | 0/0 | |
| G4 | `incomplete` | 0/0 | CI does not run the LLM review; it does not block in enforce either, see #215 |

G1 advisory count in that day's nightly:

```bash
nid=$(gh run list --workflow nightly-full.yml --branch main --limit 1 --json databaseId --jq '.[0].databaseId')
jid=$(gh run view "$nid" --json jobs --jq '.jobs[] | select(.name | startswith("G1 全量供應鏈")) | .databaseId')
gh api --allow-escape-sequences "repos/chinchiang/MultiAgentDelta/actions/jobs/$jid/logs" | grep '已知漏洞（非 KEV'
```

## Gotchas

- **Version skew**: PR CI runs the PR head's workflows and actions but calls the scripts in `_trusted/` (main). A new module or function that an action or workflow needs must land in main first through a prefactor PR (#207).
- **CodeQL naming**: CodeQL treats return values of functions whose names contain `trusted`, `secret`, or `key` as sensitive data (#208). When this happens, rename the function.
- **gitleaks false positives on runs of identifiers**: runs of quoted identifiers or file names in code are flagged as secrets by gitleaks' `generic-api-key` rule, turning G2 into `fail`. Real cases were a tool-alias table (`"api-…": "a long identifier string"`) and the old selftest file-name list in `validate.py`. Two ways to write them: follow `TOOL_ALIASES` in `scripts/gate_verdict.py` and keep the prefix in a variable that you concatenate, or derive the list in code instead of hard-coding it, as `validate.py` now detects scripts that have a selftest. Once such a false positive reaches main it stays in git history for good, so nightly's full-history scan fails every night until the owner adds a fingerprint to `.gitleaksignore` (#139; it happened on 2026-10-12 and again on 10-13, see the notes in `.gitleaksignore`). Before pushing, see step 7.
- **Stuck Checkov**: the Checkov check run sometimes stays `in_progress` even though the SARIF has been received. Rerunning the G3 IaC job clears it.
- **mode**: the rules are in ADR 0002. A workflow step that reads mode is caught by `ci_invariants.step_mode_decisions` (#209); an action that outputs mode is caught by `ci_invariants.action_mode_reader_problems` (#220).
- **pending in the verdict**: the verdict treats only `untested` as unfinished; `pending` means "awaiting merge" and counts as untested only at `finalize` (#213).
- **Test injection**: use `vibesec_policy`'s `temp_policy_root`, `broken_policy_root`, `modeless_policy_root`, `mode_policy_root(line)`, `tree_copy(line)`, `set_mode_line`, and `write_policy_key`, or `sarif_gate.main_with_policy`. Gate command-line parameters stay unchanged.
- **`python3 -I`**: g4_static and the action run with `-I`, so imports must come after `sys.path.insert`.
- **ID scan**: `validate.py` scans scripts for `vibesec.gN.*` and `VS-G*-*`, test data included, so use IDs that exist in the catalogs.
- **Invariants scan comments**: `step_mode_decisions` skips bash comment lines; other invariants may not. Reword comments to avoid the forbidden strings.
- **Bilingual docs**: only the bilingual set (see "文件語言" in AGENTS.md) needs both language sections updated together; a change to `AGENTS.md` also updates its English translation `docs/agents/rules.en.md`; all other documents are Traditional Chinese only. `validate.py` checks the anchors, language links, and heading structure inside the set, and that the translation has the same heading structure as `AGENTS.md` (`scripts/bilingual.py`); sentence-by-sentence correspondence is left to review.
- **Selftest mode**: selftests pin the mode with `tree_copy("mode: …")` instead of relying on the repo's current `vibesec.yaml`. CI's repo-validate runs validate again in a copy whose mode is enforce, so a selftest that depends on the repo's mode fails at the PR stage (#223).
- **staging-blackbox**: the repo has no `vars.VIBESEC_TARGET_URL`, so staging-blackbox only hits the vulnapp started inside the job.
- **Merge requirements**: `main` has no required status checks. To check whether a given check gates merging, query `gh api repos/chinchiang/MultiAgentDelta/rulesets` (#209).
