[正體中文（臺灣）](#zh-tw) | [English](#english)

<a id="zh-tw"></a>

# VibeSec 領域用語

VibeSec 以六道資安閘門（G0–G6）檢查 Vibe Coding 產出的程式與設定；本檔定義各閘門、判定與政策共用的詞彙。判定規則的完整真值表見 `docs/10-evidence-scoring-and-findings.md`。

## 閘門與結果

**閘門（gate）**：
G0–G6 其中一道檢查；每次執行產出一份閘門結果。
_避免_：關卡、stage、check（check 專指閘門內的單項檢查）

**閘門結果（gate result）**：
一道閘門單次執行的紀錄：閘門狀態、狀態理由、發現計數與控制覆蓋。由閘門結果 module（`gate_result`）產出。
_避免_：報告、gate report

**閘門執行（gate run）**：
閘門單次執行的累積過程：先宣告本閘門的控制，再逐步記下 tool、控制覆蓋、發現計數與未完成原因，最後產出閘門結果。宣告了卻沒有回報的控制視同未實測；宣告為由後續步驟併入的控制則記為待併入。
_避免_：job、step（那是 workflow 的單位）

**發現（finding）**：
一筆具體的問題紀錄，帶有規則 ID 與政策 tier。
_避免_：告警、issue、漏洞（漏洞是發現的一種，不是同義詞）

**發現 ID（finding ID）**：
由規則、位置與 commit 決定的發現識別碼 `VS-YYYYMMDD-<8 hex>`：日期取發現建立時間的 UTC 日期，hex 取 `sha256(rule_id ␀ path ␀ start_line ␀ commit)` 前 8 碼（`␀` 是 NUL、`null` 編成空字串）。同一個 commit、同一天重跑得到同一個 ID；由 `gate_result.py finding` 產生。
_避免_：由模型產生或手拼的 ID

**控制覆蓋（coverage）**：
閘門對每個控制的實測狀態：通過、失敗、未實測、待併入或不適用。
_避免_：檢查清單、checklist

**未實測（untested）**：
某個控制這次沒有得到證據（工具缺席、逾時、無法讀取）。只用於控制覆蓋，不是閘門狀態。
_避免_：略過、skipped

**待併入（coverage pending）**：
控制的結果要由後續步驟補上，尚未補上；到最終判定時仍待併入，視同未實測。
_避免_：與「待人工裁決」混用

**未完成原因（problem）**：
讓閘門無法完整判定的工具或環境問題，例如工具缺席、registry 逾時、缺帳號 token。
_避免_：錯誤、error（error 專指程式本身的錯誤）

**待人工裁決（awaiting human）**：
模型意見分歧或證據不足以下結論、須由人工裁決的發現。
_避免_：待審、pending review

**待裁決的 blocking 發現（pending-ruling blocking finding）**：
policy tier 為 blocking、未被 refute、尚無人工裁決的 LLM 審查發現。計入閘門結果的 `findings_count.blocking`，enforce 下由阻擋判定依計數阻擋；但模型意見不能自行確認（docs/09 §5），所以不讓閘門狀態變成 fail，閘門維持 pending，理由列為待人工裁決。人工裁決後解除：confirm → 閘門 fail；refute → 不再計入。summary 標成「`pending`（blocking N，待裁決）」。
_避免_：未確認的 blocking、假 blocking

## 判定

**閘門判定（gate verdict）**：
由發現、控制覆蓋、未完成原因與待人工裁決推出閘門狀態與狀態理由的規則；全 repo 只有一份。
_避免_：評分、score、合併分數

**閘門狀態（gate status）**：
閘門判定的結論，五種之一：
- **fail**：有 blocking 發現；
- **incomplete**：沒有 blocking 發現，但有未完成原因或未實測的控制；
- **pending**：證據完整，但有待人工裁決的發現；
- **pass**：以上皆無；
- **not_applicable**：閘門由設計判定不適用，必須附理由。

incomplete 不等於 pass。
_避免_：用 untested 當閘門狀態；用「通過」描述 incomplete

**子結果（sub-result）**：
同一道閘門分段產出的部分結果（例如 G1 的 SBOM 與 KEV 檢查），併入閘門結果後才是完整的判定。
_避免_：子閘門、sub-gate

**最終判定（finalization）**：
消費閘門結果前，把仍待併入的控制視同未實測、重新確認閘門狀態的步驟。
_避免_：重算、recompute

**乾淨（clean）**：
經最終判定後閘門狀態為 pass 或 not_applicable；夜間監測以此決定是否開追蹤 issue。
_避免_：綠燈、green

**阻擋判定（enforcement decision）**：
依各閘門結果、執行模式與阻擋政策，決定是否擋下合併或部署。
_避免_：gating、blocking decision（blocking 專指政策 tier）

**黑箱健康（blackbox health）**：
staging 黑箱閘門（G5、G6）是否需要通知：靶場看靶場驗收，外部目標看是否乾淨。
_避免_：staging 狀態

**靶場驗收（lab acceptance）**：
對刻意有漏洞的靶場，G5、G6 必須判定 fail、有 blocking 發現，且必要工具都實際執行；否則代表偵測能力退步。
_避免_：靶場測試、lab test

## 政策與信任

**政策 tier（policy tier）**：
規則的阻擋等級：blocking 或 advisory，唯一來源是阻擋政策與風險層級。
_避免_：嚴重度、severity（嚴重度是 CVSS 的範疇）

**執行模式（mode）**：
shadow（只報告、不阻擋）或 enforce（依阻擋政策阻擋）。唯一的來源是受信任樹 `vibesec.yaml` 最上層的 `mode`，沒有預設值：缺席或不合法視為政策讀不到，閘門記 incomplete。只有阻擋判定可以把 shadow 升為 enforce，不能降級；閘門結果的 `mode` 只是紀錄（ADR 0002）。
_避免_：dry-run

**受信任樹（trusted tree）**：
default branch 的判定程式、政策與設定（CI 中的 `_trusted/`）；受測的 PR 內容不得改變判定。
_避免_：base、main（main 是分支名，不是信任概念）

**受驗樹（project tree）**：
被檢查的專案內容，在 CI 中是 PR head；只當資料讀取。
_避免_：目標、target（target 專指 G5／G6 的受測服務）

**政策例外（exception）**：
阻擋政策中經人類核准、附到期日的一筆豁免：指定規則在指定路徑上的發現由 blocking 降為 advisory，發現本身保留；只對本 repo 的受驗樹生效。
_避免_：allowlist（專指 G1 的套件允許清單）、抑制註解、suppression（受驗方自己寫的抑制註解不採信）

**外部專案（external project）**：
不是本 repo 的受驗樹，例如以 harness 掃描的其他專案；本 repo 的政策例外對它不套用。
_避免_：外部目標、external target（target 專指 G5／G6 的受測服務）

---

<a id="english"></a>

# VibeSec Domain Language

VibeSec checks the code and configuration produced by Vibe Coding through six security gates (G0–G6). This file defines the vocabulary shared by gates, verdicts, and policy. The full truth table for the verdict rules is in `docs/10-evidence-scoring-and-findings.md`. If the two language sections disagree, the Traditional Chinese section prevails.

## Gates and results

**Gate**:
One of the checks G0–G6; each run produces one gate result.
_Avoid_: stage, check (a check is a single item inside a gate)

**Gate result**:
The record of one gate run: gate status, status reason, finding counts, and coverage. Produced by the gate result module (`gate_result`).
_Avoid_: report, gate report

**Gate run**:
The accumulation for one execution of a gate: the gate first declares its controls, then records tools, coverage, finding counts, and problems, and finally produces the gate result. A declared control that is never reported counts as untested; a control declared as merged by a later step is recorded as pending merge.
_Avoid_: job, step (those are workflow units)

**Finding**:
A concrete problem record carrying a rule ID and a policy tier.
_Avoid_: alert, issue, vulnerability (a vulnerability is one kind of finding, not a synonym)

**Finding ID**:
The finding identifier `VS-YYYYMMDD-<8 hex>`, determined by the rule, location, and commit: the date is the UTC date of the finding's creation time, and the hex is the first 8 characters of `sha256(rule_id ␀ path ␀ start_line ␀ commit)` (`␀` is NUL; `null` is encoded as an empty string). Rerunning on the same commit on the same day yields the same ID. Produced by `gate_result.py finding`.
_Avoid_: IDs generated or assembled by a model

**Coverage**:
The tested state of each control in a gate: pass, fail, untested, pending merge, or not applicable.
_Avoid_: checklist

**Untested**:
A control that got no evidence this run (tool missing, timeout, unreadable). Used only for coverage, never as a gate status.
_Avoid_: skipped

**Coverage pending**:
A control whose result is to be supplied by a later step and has not been yet; still pending at finalization, it counts as untested.
_Avoid_: confusing it with "awaiting human"

**Problem**:
A tool or environment issue that prevents a complete verdict, such as a missing tool, a registry timeout, or a missing account token.
_Avoid_: error (error means a bug in the program itself)

**Awaiting human**:
A finding on which model opinions disagree or the evidence does not support a conclusion, so a human must rule.
_Avoid_: pending review

**Pending-ruling blocking finding**:
An LLM review finding whose policy tier is blocking, that has not been refuted, and that has no human ruling yet. It counts toward the gate result's `findings_count.blocking`, so under enforce the enforcement decision blocks on the count; but model opinions cannot confirm a finding on their own (docs/09 §5), so it does not turn the gate status into fail: the gate stays pending and the reason lists it as awaiting human. A human ruling resolves it: confirm → the gate fails; refute → it no longer counts. The summary shows it as `pending`（blocking N，待裁決）.
_Avoid_: unconfirmed blocking, fake blocking

## Verdicts

**Gate verdict**:
The rule that derives the gate status and status reason from findings, coverage, problems, and findings awaiting human rulings; there is exactly one in the repository.
_Avoid_: score, combined score

**Gate status**:
The conclusion of the gate verdict, one of five:
- **fail**: there is a blocking finding;
- **incomplete**: no blocking finding, but there are problems or untested controls;
- **pending**: the evidence is complete, but some findings await a human ruling;
- **pass**: none of the above;
- **not_applicable**: the gate does not apply by design; a reason is required.

Incomplete does not equal pass.
_Avoid_: using untested as a gate status; describing incomplete as "passed"

**Sub-result**:
A partial result produced in stages by the same gate (for example G1's SBOM and KEV checks); the verdict is complete only after it is merged into the gate result.
_Avoid_: sub-gate

**Finalization**:
The step before a gate result is consumed that treats still-pending controls as untested and reconfirms the gate status.
_Avoid_: recompute

**Clean**:
A gate whose status after finalization is pass or not_applicable; nightly monitoring uses it to decide whether to open a tracking issue.
_Avoid_: green

**Enforcement decision**:
The decision, from all gate results, the mode, and the blocking policy, whether to block a merge or deployment.
_Avoid_: gating, blocking decision (blocking refers only to the policy tier)

**Blackbox health**:
Whether the staging blackbox gates (G5, G6) need a notification: the lab is judged by lab acceptance, an external target by whether it is clean.
_Avoid_: staging status

**Lab acceptance**:
For the deliberately vulnerable lab, G5 and G6 must be judged fail with blocking findings, and every required tool must actually have run; otherwise detection has regressed.
_Avoid_: lab test

## Policy and trust

**Policy tier**:
A rule's blocking level, blocking or advisory, whose only sources are the blocking policy and the risk tier.
_Avoid_: severity (severity belongs to CVSS)

**Mode**:
shadow (report only, never block) or enforce (block according to the blocking policy). Its only source is the top-level `mode` in the trusted tree's `vibesec.yaml`, with no default: a missing or invalid value counts as an unreadable policy and the gate records incomplete. Only the blocking decision can raise shadow to enforce, never lower it; the `mode` in a gate result is only a record (ADR 0002).
_Avoid_: dry-run

**Trusted tree**:
The default branch's verdict code, policy, and configuration (`_trusted/` in CI); the PR content under test must not change a verdict.
_Avoid_: base, main (main is a branch name, not a trust concept)

**Project tree**:
The content being checked, the PR head in CI; it is read only as data.
_Avoid_: target (target means the service under test in G5/G6)

**Exception**:
A human-approved, expiring waiver in the blocking policy: findings of a given rule on a given path are lowered from blocking to advisory and the findings themselves are kept; it applies only to this repo's project tree.
_Avoid_: allowlist (that means G1's package allowlist), suppression comment (suppression comments written by the project under test are not trusted)

**External project**:
A project tree that is not this repo, such as another project scanned by the harness; this repo's exceptions do not apply to it.
_Avoid_: external target (target means the service under test in G5/G6)
