
[正體中文（臺灣）](#zh-tw) | [English](#english)

<a id="zh-tw"></a>

# reviews/ — G4 LLM 審查紀錄

`/vibesec-harness` 執行 G4 LLM 審查後寫出 `reports/g4-review.yaml`（`reports/` 不入版控）。人確認內容後複製為 `reviews/g4/<commit>.yaml` 提交（格式：`schemas/g4-review.schema.json`，範例：`docs/templates/g4-review.example.yaml`，`<commit>` = 紀錄的 `commit`，40 碼）。

- harness、模型與 bot 不得寫入此目錄；`recorded_by.handle` 填複製提交的人（harness 產出時留空；空白的紀錄不會被採信）。
- **不能自證**：紀錄由某個 PR 新增或修改時，需要非 PR 作者在該 PR 目前的 head 上 approve，且 `recorded_by` 不是 PR 作者，G4 才可能是 `pass`；否則最高 `pending`。
- CI 的 G4 job（`scripts/g4_review.py gate`）只採用對 PR head **有效**的紀錄：紀錄的 `commit` 是 head 的祖先，且其後只動過 `reviews/g4/`、`rulings/`。再改程式碼就要重跑審查。
- 紀錄只陳述審查發生了什麼：意見全部保留、不多數決、分歧 → `requires_human: true`（結論只來自 `rulings/` 的人工裁決）。違規的紀錄讓 `validate.py` 失敗。
- 提交前先跑：`python3 scripts/g4_review.py check reviews/g4/<commit>.yaml`
- 狀態推導規則見 `docs/05-g4-access-control-agent-review.md`「阻擋政策」。

## 外部專案：`reviews/g4/external/<commit>.yaml`

`--target` 掃其他專案時（`scripts/g4_access.py --target <dir>`），G4 LLM 審查紀錄放在**本 repo** 的 `reviews/g4/external/<commit>.yaml`（2026-10-06 人工決定）；被測專案自己的 `reviews/g4/`、`rulings/` 一律不採信（不得自證）。

- 格式、規則、提交方式與上面相同：`<commit>` = 被測專案審查時的 HEAD（40 碼），`recorded_by.handle` 填複製提交的人，經 PR 由 CODEOWNERS 審核；同樣不能自證（`recorded_by` 不是 PR 作者，且須在 PR head 上 approve）。CI 的「外部 G4 紀錄不得自證」check（`.github/workflows/review-record-trust.yml`）會自動檢查這條規則：本 PR 新增或修改的外部紀錄，`recorded_by` 必須是在目前 head 上 approve、且不是 PR 作者的協作者。有人 approve、request changes 或 dismiss 時會重新判定；approve 之後再 push 就要重新 approve。這個 check 要在 branch protection 設為 required 才會擋 merge。建議在 `recorded_by.note` 寫明被測專案（例如 `chinchiang/MultiAgentBeta`）。
- 外部發現的人工裁決同樣放本 repo 的 `rulings/`。
- 紀錄只在以下條件下採用，否則 `VS-G4-LLM-REVIEW` 維持 `pending`：
  - `<commit>` 恰好是被測專案目前的 HEAD：紀錄不會提交到被測專案，所以它的任何新 commit 都是新的程式碼，要重新審查。
  - 被測專案追蹤中的檔案沒有未提交的修改：掃描的就是紀錄審查的內容。
  - 紀錄通過 `scripts/g4_review.py check`。
- 紀錄尚未提交到本 repo（未經 PR 與 CODEOWNERS），或 `recorded_by.handle` 空白 → G4 最高 `pending`。
- `validate.py` 會檢查這裡每一份紀錄的規則與檔名。


---

<a id="english"></a>

# reviews/ — G4 LLM Review Records

After a G4 LLM review, `/vibesec-harness` writes `reports/g4-review.yaml`; `reports/` is not versioned. A human verifies it and copies it to `reviews/g4/<commit>.yaml`. Schema: `schemas/g4-review.schema.json`; example: `docs/templates/g4-review.example.yaml`. `<commit>` is the record's full 40-character commit.

- Harnesses, models, and bots must not write review records here. `recorded_by.handle` identifies the human copying/submitting the record. The harness leaves it empty; empty records are not trusted.
- **No self-attestation:** for a record added/changed by a PR, a non-author must approve the PR's current head, and `recorded_by` must not be the author, before G4 can pass. Otherwise its review status remains at most `pending`.
- The G4 CI job (`scripts/g4_review.py gate`) accepts a record only if its commit is an ancestor of the PR head and later changes affect only `reviews/g4/` or `rulings/`. Any subsequent code change requires a new review.
- Records describe what happened: retain every opinion, never majority-vote, and mark disagreements `requires_human: true`. Only human rulings in `rulings/` settle them. Invalid records fail `validate.py`.
- Before submitting: `python3 scripts/g4_review.py check reviews/g4/<commit>.yaml`.
- See the blocking-policy section of `docs/05-g4-access-control-agent-review.md` for status derivation.

## External projects: `reviews/g4/external/<commit>.yaml`

For `scripts/g4_access.py --target <dir>`, place G4 records in **this repository's** `reviews/g4/external/<commit>.yaml` (human decision dated 2026-10-06). Never trust the target's own `reviews/g4/` or `rulings/` as self-attestation.

- Apply the same format, human submission, and CODEOWNERS review rules. `<commit>` is the target's reviewed HEAD. The recorder must be a non-author collaborator who approved the current PR head. `.github/workflows/review-record-trust.yml` checks this under the literal check name `外部 G4 紀錄不得自證`. Approval, change requests, and dismissed reviews trigger reevaluation; pushing after approval requires reapproval. Make the check required in branch protection for it to block merging. Identify the target in `recorded_by.note`, for example `chinchiang/MultiAgentBeta`.
- External findings' human rulings also belong in this repository's `rulings/`.
- A record is usable only when its commit exactly matches the target's current HEAD, the target has no uncommitted tracked changes, and `scripts/g4_review.py check` passes. Records are not committed to the target; every new target commit requires another review. Otherwise `VS-G4-LLM-REVIEW` remains `pending`.
- A record not yet committed here through PR/CODEOWNERS review, or an empty `recorded_by.handle`, cannot advance G4 beyond `pending`.
- `validate.py` checks all records and filenames here.
