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
held_out: false                # true 者不參與 prompt 調整（至少 1/3）
notes: 靶場 examples/vulnapp 可重現。
```

## 規則

- 每個適用領域**至少一正例與一反例**。
- 至少 **1/3** 案例 `held_out: true`；清單集中於 `evals/split.yaml`。
- 總數目標 **≥ 60**；種子案例已就緒，其餘於試點期補齊。
- `expected.control_id` / `rule_id` 必須存在於 `config/catalogs/` 與規則集，否則評測視為設定錯誤。

## 三組比較

以 `evals/split.yaml` 的 held-in 子集調整 prompt，held-out 子集量測：召回率、精確率、共同漏報、每模型新增有效發現、人工確認時間、成本。三組為：工具+單模型、工具+同模型多代理、工具+不同模型多代理。
