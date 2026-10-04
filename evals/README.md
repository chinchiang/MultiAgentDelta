# 評測案例集（evals/）

量化多模型審查相對單模型的增益，並校準誤報。對應 `docs/12-pilot-and-evaluation.md`。

## 案例格式

每個 YAML 檔一個案例，置於 `evals/cases/g<N>/`：

```yaml
id: g5-bola-pos-01              # g<gate>-<domain>-<pos|neg>-<序號>
gate: G5
domain: authorization          # 對應 14 審查領域之一
title: 跨帳號讀取他人資源
input:                         # 餵給閘門/工具的輸入（程式片段、HTTP 請求或 prompt）
  kind: http                   # code | http | prompt | manifest | iac | config
  target: /users/{id}/notes
  steps:
    - login as bob
    - GET /users/1/notes with bob token   # alice=1, bob=2
expected:
  should_flag: true            # true=正例（應命中）, false=反例（不應命中，用於量測誤報）
  control_id: ASVS5-V8.1
  rule_id: vibesec.g5.bola-cross-account
  policy_tier: blocking
  gate_status: incomplete      # 選填：工具缺席／逾時／缺金鑰等情境的預期閘門狀態（pass|fail|incomplete|not_applicable）
held_out: false                # true 者不參與 prompt 調整（至少 1/3）；須與 split.yaml 一致
notes: 靶場 examples/vulnapp 可重現。
```

## 規則

- 每個適用領域**至少一正例與一反例**。
- 至少 **1/3** 案例 `held_out: true`；清單集中於 `evals/split.yaml`。
- 總數目標 **≥ 60**（目前 66）。
- `domain` 使用 14 審查領域的固定代碼：`application_architecture`、`general_vulnerabilities`、`xss`、`csp`、`authentication`、`authorization`、`dependency`、`build_supply_chain`、`github_actions`、`secret_exposure`、`input_validation`、`error_handling`、`data_integrity`、`ai_agent_security`。
- `gate_status: incomplete` 案例驗證「incomplete ≠ pass」：工具或環境無法完成時，評測期望閘門回報 incomplete，而非 pass。
- 含隱形字元或假金鑰的 fixture 以 YAML 跳脫或佔位值表示，避免觸發本 repo 自身的 G2／G4 掃描。
- `scripts/validate.py` 檢查：id 與檔名一致、gate 與目錄一致、split 與 `held_out` 欄位一致、held_out ≥ 1/3、每領域正反例、ID 存在於 catalogs。
- `expected.control_id` / `rule_id` 必須存在於 `config/catalogs/` 與規則集，否則評測視為設定錯誤。

## 三組比較

以 `evals/split.yaml` 的 held-in 子集調整 prompt，held-out 子集量測：召回率、精確率、共同漏報、每模型新增有效發現、人工確認時間、成本。三組為：工具+單模型、工具+同模型多代理、工具+不同模型多代理。
