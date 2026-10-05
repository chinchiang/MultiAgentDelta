# reviews/ — G4 LLM 審查紀錄

`/vibesec-harness` 執行 G4 LLM 審查後寫出 `reports/g4-review.yaml`（`reports/` 不入版控）。人確認內容後複製為 `reviews/g4/<commit>.yaml` 提交（格式：`schemas/g4-review.schema.json`，範例：`docs/templates/g4-review.example.yaml`，`<commit>` = 紀錄的 `commit`，40 碼）。

- harness、模型與 bot 不得寫入此目錄；`recorded_by.handle` 填複製提交的人。
- CI 的 G4 job（`scripts/g4_review.py gate`）只採用對 PR head **有效**的紀錄：紀錄的 `commit` 是 head 的祖先，且其後只動過 `reviews/g4/`、`rulings/`。再改程式碼就要重跑審查。
- 紀錄只陳述審查發生了什麼：意見全部保留、不多數決、分歧 → `requires_human: true`（結論只來自 `rulings/` 的人工裁決）。違規的紀錄讓 `validate.py` 失敗。
- 提交前先跑：`python3 scripts/g4_review.py check reviews/g4/<commit>.yaml`
- 狀態推導規則見 `docs/05-g4-access-control-agent-review.md`「阻擋政策」。
