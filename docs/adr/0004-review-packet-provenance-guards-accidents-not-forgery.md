[正體中文（臺灣）](#zh-tw) | [English](#english)

<a id="zh-tw"></a>

# ADR 0004：審查包的來源標記防意外、不防偽造；評測審查包刻意不遮罩；送出端不重掃祕密

- 狀態：已採納（2026-11-26）
- 相關：#329（缺口與 grilling 決定）、#230（審查包的遮罩與 HMAC 指紋）、`scripts/vibesec_provenance.py`、`scripts/review_packet.py`、`scripts/prepare_comparison.py`、`scripts/review_provider.py`

## 背景

`review_provider` 會把審查包送給非 Claude Code 的 provider。送出前有兩道拒送：provider 的 `allowed_data_classes` 必須包含該資料分級，而 confidential／pii 只能送給 `sensitive_data_providers`。但這兩道防線都只看「分級」，分級又來自呼叫端：`--data-class` 參數，或審查包自己宣告的 `data_class`。`review_provider` 不知道審查包是不是經過 `review_packet` 的遮罩。手組一份未遮罩的審查包、把分級報低，就能送給雲端 provider（#329 已用本機假 provider 重現）。

會送審查包的正當來源只有兩個：G4 審查用的審查包由 `review_packet` 產生，並遮罩祕密；評測比較（docs/12）的盲測審查包由 `prepare_comparison` 從 `evals/cases` 產生，內容是合成 fixture，其中 G2 案例的假祕密正是要讓模型找的東西。

## 決定

1. **用來源標記綁定審查包與產生工具。** 產生工具用指紋金鑰，對整份審查包（標記欄位除外，以固定格式序列化）計算 HMAC-SHA256，寫進 `provenance = {kind, key_id, hmac}`。`review_provider` 在判斷分級之前先驗證標記：缺少、`kind` 不認得、另一把金鑰、內容在標記後被改過、拿不到金鑰，都回 `refused`（離開碼 3），並在 `note` 寫明原因，不送出任何內容。驗證通過後，送出前會拿掉標記。分級規則不變：審查包內的分級與 `--data-class` 取較嚴格者。
2. **防的是意外與被誘導，不防偽造。** 指紋金鑰在本機（`VIBESEC_FINGERPRINT_KEY` 或 `~/.config/vibesec/fingerprint-key`），讀得到它的人或 agent 都能自己算出標記。這道防線擋得住的是：agent 手組審查包、填錯分級、跳過遮罩，或被 prompt injection 誘導直接呼叫 `review_provider`。擋不住的是：刻意偽造的本機操作者。要防偽造，就得把金鑰隔離到另一個行程或使用者，讓產生工具成為唯一能簽章的一方，範圍與維運成本都大很多。
3. **評測審查包刻意不遮罩，改用另一種標記（`kind: eval-fixture`）。** 評測若走 `review_packet` 遮罩，G2 案例的假祕密會被遮掉，評測就失真；給 `review_provider` 加一個放行旗標（例如 `--eval`）又會回到呼叫端自報。`eval-fixture` 標記只由 `prepare_comparison` 從 `evals/cases` 產生。
4. **送出端不重掃祕密。** 遮罩是 `review_packet` 的責任，它有不套 allowlist 的 gitleaks，以及序列化前的殘留檢查，由它自己的 selftest 把關。`review_provider` 再掃一次，會多一個依賴（gitleaks 缺席就送不出去），還要另外替 `eval-fixture` 開例外，擋的卻是 `review_packet` 本身有 bug 的情況。
5. **不另設狀態、不提供過渡期。** 驗證不過沿用 `refused`，G4 與評測對 `refused` 的既有處理不變（G4 記為 `missing` tool、閘門 `incomplete`；評測記 `incomplete`）。沒有標記的舊審查包一律 `refused`；審查包本來就是每次執行時重新產生的暫存產物。

## 後果

- 讀取金鑰與計算、驗證標記的程式只有一份（`scripts/vibesec_provenance.py`）。只有 `review_packet` 會在沒有金鑰檔時建立金鑰；`prepare_comparison` 與 `review_provider` 拿不到金鑰就停止，不會自己建立。
- 不得把來源標記當成防偽造的機制，也不得據此放寬 `allowed_data_classes` 或 `sensitive_data_providers`。這兩道防線照舊，由人在獨立 PR 決定（AGENTS.md 規則 1、7）。
- 產生審查包之後的任何修改（包括人工編輯）都會讓標記失效，審查包必須重新產生。修改前準備的評測 run 要重新 prepare。
- 如果日後要防偽造，應另開 ADR 討論金鑰隔離，而不是在送出端加更多啟發式檢查。

---

<a id="english"></a>

# ADR 0004: The review packet provenance mark guards against accidents, not forgery; eval review packets are deliberately unmasked; the sending side does not rescan for secrets

- Status: accepted (2026-11-26)
- Related: #329 (the gap and the grilling decisions), #230 (review packet masking and HMAC fingerprints), `scripts/vibesec_provenance.py`, `scripts/review_packet.py`, `scripts/prepare_comparison.py`, `scripts/review_provider.py`

## Context

`review_provider` sends review packets to providers other than Claude Code. Two refusals stand before sending: the provider's `allowed_data_classes` must include the data class, and confidential/pii may only go to `sensitive_data_providers`. Both guards look only at the data class, and the data class comes from the caller: the `--data-class` argument, or the `data_class` the packet declares about itself. `review_provider` cannot tell whether the packet went through `review_packet`'s masking. A hand-built, unmasked packet with an understated data class could be sent to a cloud provider (#329 reproduced this against a local fake provider).

Only two legitimate sources send review packets: G4 review packets are produced by `review_packet`, which masks secrets; the blinded packets for the eval comparison (docs/12) are produced by `prepare_comparison` from `evals/cases`. Those hold synthetic fixtures, and the fake secrets in the G2 cases are exactly what the model is meant to find.

## Decision

1. **A provenance mark binds a review packet to its producing tool.** The producing tool uses the fingerprint key to compute an HMAC-SHA256 over the whole packet (excluding the mark field, serialized in a fixed form) and writes it as `provenance = {kind, key_id, hmac}`. `review_provider` verifies the mark before any data class check. A missing mark, an unrecognized `kind`, a different key, content changed after marking, or an unavailable key all return `refused` (exit code 3), with the reason in `note`, and nothing is sent. After a successful check the mark is removed before sending. The data class rule is unchanged: the stricter of the packet's own class and `--data-class` applies.
2. **It guards against accidents and manipulation, not forgery.** The fingerprint key is local (`VIBESEC_FINGERPRINT_KEY` or `~/.config/vibesec/fingerprint-key`), so anyone or any agent that can read it can compute a mark. What this guard stops: an agent hand-building a packet, declaring the wrong data class, skipping masking, or being led by prompt injection to call `review_provider` directly. What it does not stop: a local operator forging marks on purpose. Stopping forgery would mean isolating the key in another process or user so the producing tool is the only signer, a much larger scope with higher operating cost.
3. **Eval review packets are deliberately unmasked and carry a different mark (`kind: eval-fixture`).** Running evals through `review_packet` masking would mask the fake secrets in the G2 cases and distort the evaluation; adding a pass-through flag to `review_provider` (such as `--eval`) would bring back caller self-reporting. Only `prepare_comparison` produces `eval-fixture` marks, from `evals/cases`.
4. **The sending side does not rescan for secrets.** Masking is `review_packet`'s job. It has gitleaks without any allowlist and a residual check before serialization, and its own selftest guards them. Rescanning in `review_provider` would add a dependency (no gitleaks, no sending) and require a separate exception for `eval-fixture`, all to catch bugs in `review_packet` itself.
5. **No new state and no transition period.** A failed check reuses `refused`, and the existing handling of `refused` in G4 and the evals is unchanged (G4 records it as a `missing` tool and the gate is `incomplete`; the evals record `incomplete`). Old packets without a mark are always `refused`; review packets are short-lived artifacts regenerated on every run anyway.

## Consequences

- There is exactly one implementation of key loading and of computing and verifying the mark (`scripts/vibesec_provenance.py`). Only `review_packet` creates the key file when it is missing; `prepare_comparison` and `review_provider` stop when no key is available and never create one.
- The provenance mark must not be treated as an anti-forgery mechanism, nor used as a reason to loosen `allowed_data_classes` or `sensitive_data_providers`. Those two guards stay, and changing them is a human decision in a separate PR (AGENTS.md rules 1 and 7).
- Any change to a packet after it is produced (including manual edits) invalidates the mark, and the packet must be regenerated. Eval runs prepared before this change must be prepared again.
- If forgery ever needs to be stopped, a new ADR should cover key isolation instead of adding more heuristic checks on the sending side.
