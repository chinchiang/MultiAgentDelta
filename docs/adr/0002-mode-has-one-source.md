[正體中文（臺灣）](#zh-tw) | [English](#english)

<a id="zh-tw"></a>

# ADR 0002：mode 只有一個來源；閘門層級不接受 mode 管道，閘門結果的 mode 只是紀錄

- 狀態：已採納（2026-10-16）
- 相關：#199（spec）、#200（解析器）、#186（G5 `VIBESEC_MODE`）、#161（G6 `--mode`）、#190（G0／G1 的 mode 檢查）

## 背景

#199 之前，執行模式（mode：shadow／enforce）在 repo 裡有十幾處各讀一份：

- G2／G3／G4 在 mode 缺席時預設 shadow。
- G0／G1 各自檢查一次。
- G5 從環境變數 `VIBESEC_MODE` 讀，G4 靜態檢查和 G6 從必填的 `--mode` 讀。
- 阻擋判定自己用 YAML 讀 mode，並實作「只能升級」的規則。
- CI 的受信任設定 action 為了在沒有 PyYAML 的 semgrep 容器裡執行，另外用 regex 讀一次。

在 CI 裡，閘門層級的 `--mode` 和 `VIBESEC_MODE` 傳的都是 action 讀出的同一個受信任值，只是換了一條管道。同一個概念散在多處，預設值和錯誤處理也都不同（預設 shadow、拋例外、不寫閘門結果），很容易漂移。

## 決定

1. **唯一的來源是受信任樹 `vibesec.yaml` 最上層的 `mode`，沒有預設值。** 合法值清單、解析規則（`read_mode`）和覆寫規則（`apply_override`）只有一份，放在只用標準函式庫的 mode module。之所以不放在政策 module，有兩個原因：
   - 政策 module 在缺 PyYAML 時 import 就會 exit 2（這是刻意的行為），受信任設定 action 無法依賴它。
   - 政策檔壞掉時，阻擋判定仍要能讀出 mode（shadow 下只報告），不能因為政策讀不到就連 mode 也不明。
2. **閘門透過 `load_policy` 取得 mode。** mode 缺席或不合法是「政策讀不到」的一種，走同一個前綴、同一條 incomplete 路徑，閘門不另寫檢查。
3. **閘門層級不接受 mode 管道。** 閘門結果的 `mode` 一律記設定值，只是紀錄；阻擋判定另讀受信任樹，不採信 gate JSON 的 `mode`。閘門層級的 `--mode` 和 `VIBESEC_MODE` 依 #199 分兩階段移除。
4. **只有阻擋判定可以把 shadow 升為 enforce。** 理由是：阻擋判定是唯一決定是否阻擋的地方，閘門結果只是它的輸入；在閘門層級升級不會讓任何東西更嚴，只會多一個可能跟設定不一致的來源。覆寫規則：覆寫成 enforce 會生效；試圖降級時忽略並附註；覆寫值不合法視為錯誤（mode 視同 enforce），不會默默改以設定值執行。

## 落地過程

依 #199 分階段落地，已全部完成：
- #200：mode module、`load_policy` 回報 mode 錯誤、阻擋判定共用覆寫規則。
- #201、#202：G2–G6 改取 `policy.mode`，閘門層級的 `--mode`、`VIBESEC_MODE` 先改成接受但忽略（PR CI 以 PR head 的 workflow 呼叫受信任樹的腳本，兩邊版本錯開時不能讓 CI 失敗）。
- #203：workflow 不再傳 mode、移除這些參數；受信任設定 action 改用 `vibesec_mode`。`ci_invariants` 有兩條不變式把關：action 不得內嵌自己的 mode 規則；workflow 不得把 mode 傳給閘門腳本。action 要用的 `top_scalar` 先以 prefactor PR 進 main（action 從 PR head 執行，卻 import main 的受信任樹）。
- #203 合併之後，在那之前開的 PR 要 rebase：它們的 workflow 仍會傳 `--mode`，而受信任樹的閘門腳本已經沒有這個參數（argparse exit 2）。這是第二階段刻意接受的結果。

- #209：G2 的 `.env` 檢查步驟原本是唯一的例外，它在 workflow 的 bash 裡依 `VIBESEC_MODE` 自己做阻擋判定（#199 Out of Scope）。現在已移除：這個步驟只產生 `g2-envcheck.json`，阻擋與否交給 `gate_verdict`。`ci_invariants` 新增第三條不變式：除了阻擋判定之外，workflow 的步驟、job、workflow 層級都不得讀 mode（`VIBESEC_MODE`、`outputs.mode`）。

## 後果

- 以後做 architecture review 時，不要建議「替閘門加回 `--mode`」或「讓閘門讀環境變數決定 mode」。harness 要求更嚴格的判定時，`--mode enforce` 只交給阻擋判定；閘門結果照樣記錄設定值，summary 會註明升級。
- 政策讀不到時 mode 不明，閘門結果的 `mode` 記 enforce（較嚴的一側）。阻擋判定不讀這個欄位，所以不影響是否阻擋。
- 受信任設定 action 以 `python3 -I` import 受信任樹的 mode module。mode module 必須維持只用標準函式庫。

---

<a id="english"></a>

# ADR 0002: mode has one source; gates accept no mode channel, and the mode in a gate result is only a record

- Status: accepted (2026-10-16)
- Related: #199 (spec), #200 (resolver), #186 (G5 `VIBESEC_MODE`), #161 (G6 `--mode`), #190 (G0/G1 mode check)

If the two language sections disagree, the Traditional Chinese section prevails.

## Context

Before #199, the execution mode (shadow/enforce) was read separately in more than ten places:

- G2/G3/G4 defaulted to shadow when mode was missing.
- G0/G1 each checked it on their own.
- G5 read the `VIBESEC_MODE` environment variable; the G4 static check and G6 read a required `--mode`.
- The blocking decision read mode with YAML itself and implemented the "upgrade only" rule.
- The trusted-configuration action in CI read it again with a regex so it could run in the semgrep container, which has no PyYAML.

In CI, the gate-level `--mode` and `VIBESEC_MODE` all carry the same trusted value the action read, just through another channel. One concept was spread across many places with different defaults and error handling (default to shadow, raise, skip writing the gate result), which invites drift.

## Decision

1. **The only source is the top-level `mode` in the trusted tree's `vibesec.yaml`, with no default.** The list of valid values, the parsing rule (`read_mode`), and the override rule (`apply_override`) exist once, in a standard-library-only mode module. They are not in the policy module for two reasons:
   - The policy module exits 2 at import time when PyYAML is missing (on purpose), so the trusted-configuration action cannot depend on it.
   - When the policy file is broken, the blocking decision must still read mode (report only under shadow); an unreadable policy must not also make mode unknown.
2. **Gates get mode through `load_policy`.** A missing or invalid mode is one kind of "policy unreadable": same prefix, same incomplete path, and no separate check in each gate.
3. **Gates accept no mode channel.** The `mode` in a gate result always records the configured value and is only a record; the blocking decision reads the trusted tree on its own and does not trust the `mode` in gate JSON. The gate-level `--mode` and `VIBESEC_MODE` are removed in two phases, as #199 describes.
4. **Only the blocking decision can raise shadow to enforce.** The reason: the blocking decision is the only place that decides whether to block, and gate results are just its input; raising mode at the gate level makes nothing stricter and only adds another source that can disagree with the configuration. The override rule: an enforce override takes effect; a downgrade attempt is ignored with a note; an invalid override is an error (mode is treated as enforce) and never silently falls back to the configured value.

## Rollout

This landed in phases, as #199 describes, and is complete:
- #200: the mode module, `load_policy` reporting mode errors, and one override rule shared with the blocking decision.
- #201, #202: G2–G6 take `policy.mode`; the gate-level `--mode` and `VIBESEC_MODE` were first made accepted-but-ignored (PR CI runs the trusted tree's scripts from the PR head's workflow, so a version skew between the two must not break CI).
- #203: the workflows stop passing mode and these parameters are removed; the trusted-configuration action uses `vibesec_mode`. Two `ci_invariants` checks guard this: the action must not embed its own mode rule, and workflows must not pass mode to gate scripts. The `top_scalar` the action needs went into main first in a prefactor PR (the action runs from the PR head but imports main's trusted tree).
- After #203 is merged, PRs opened before it must be rebased: their workflows still pass `--mode`, while the trusted tree's gate scripts no longer accept it (argparse exits 2). This is an accepted consequence of the second phase.

- #209: G2's `.env` check step used to be the only exception: it made its own blocking decision in workflow bash based on `VIBESEC_MODE` (#199 Out of Scope). That is now removed: the step only produces `g2-envcheck.json`, and `gate_verdict` decides whether to block. A third `ci_invariants` check was added: apart from the blocking decision, no workflow step, job, or workflow-level setting may read mode (`VIBESEC_MODE`, `outputs.mode`).

## Consequences

- Future architecture reviews should not suggest adding `--mode` back to gates or letting gates decide mode from an environment variable. When the harness wants a stricter decision, `--mode enforce` goes only to the blocking decision; gate results still record the configured value, and the summary notes the upgrade.
- When the policy is unreadable, mode is unknown and the gate result records `mode` as enforce (the stricter side). The blocking decision does not read this field, so blocking is unaffected.
- The trusted-configuration action imports the trusted tree's mode module with `python3 -I`. The mode module must stay standard-library-only.
