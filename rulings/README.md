# rulings/ — 人工裁決紀錄

每個 `requires_human: true` 的發現，經人工裁決後存成 `rulings/<finding_id>.yaml`（格式：`schemas/human-ruling.schema.json`，範例：`docs/templates/human-ruling.example.yaml`）。

- 這裡只放**人**寫的裁決。harness、模型與 bot 不得新增或修改此目錄的檔案。
- 每份裁決經 PR 合併，由另一位人員審查；PR 紀錄就是稽核軌跡。
- 提交前先跑：`python3 scripts/ruling.py check rulings/<finding_id>.yaml --findings reports/findings.json`
- 流程與規則見 `docs/09-multi-model-review.md` §12。
