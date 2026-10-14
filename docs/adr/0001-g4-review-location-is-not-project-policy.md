[正體中文（臺灣）](#zh-tw) | [English](#english)

<a id="zh-tw"></a>

# ADR 0001：G4 的審查紀錄位置不併入政策例外的「本 repo」判斷；G0 暫不認 `VIBESEC_PROJECT_ROOT`

- 狀態：已採納（2026-10-14）
- 相關：#167（spec）、#168（`ProjectPolicy`）、#157（`VIBESEC_PROJECT_ROOT`）

## 背景

#168 把「受驗樹是不是本 repo」收進政策 module：`Policy.for_project(受驗樹)` 依 `Policy.is_this_repo` 判斷，外部專案拿到沒有任何政策例外的 `ProjectPolicy`。G1、G2、G3 早已改用 `is_this_repo`（#157），G0 的 trifecta 也在 #168 改由呼叫端傳入 `ProjectPolicy`。

另外有兩處各自判斷「本 repo」，沒有改用 `is_this_repo`：

- **G4**：`g4_access` 以「受驗樹不等於 `g4_review.PROJECT`」判斷外部專案。`PROJECT` 是 `VIBESEC_PROJECT_ROOT`，沒設定時是 `ROOT`。這個判斷決定**審查紀錄從哪裡讀**：本 repo 讀受驗樹的 `reviews/g4/<commit>.yaml`，外部專案讀本 repo 的 `reviews/g4/external/<commit>.yaml`。G4 不套用政策例外。
- **G0 威脅模型閘門**：以 `target != ROOT` 判斷外部專案，不認 `VIBESEC_PROJECT_ROOT`。這個判斷除了決定是否比對政策例外，也決定：
  - 是否檢查 MAESTRO methodologies；
  - 找不到 `project.threat_model` 時，是否改找預設的威脅模型位置；
  - `contains_llm` 取自本 repo 的 `vibesec.yaml`，還是從受驗樹的威脅模型推論。

## 決定

1. **G4 不併入 `ProjectPolicy`。** 「本 repo」在這個 repo 有兩種意思：一種決定政策例外要不要套用（`ProjectPolicy`），一種決定審查資料放在哪個 repo（G4）。兩者的輸入不同：審查紀錄跟著受驗樹的 commit；政策例外只核准給本 repo 的路徑。

   如果 G4 直接改用 `is_this_repo`，那麼設了 `VIBESEC_PROJECT_ROOT`、而受驗樹指向受信任樹本身時，`is_this_repo` 會判成本 repo，但 `find_self_record` 仍然從 `PROJECT`（也就是另一棵樹）讀紀錄，兩邊會對不上。
2. **G0 暫不認 `VIBESEC_PROJECT_ROOT`。** G0 不在任何 CI workflow 中執行。本機以 harness 執行時，`--target` 就是 `ROOT`；CI 只透過 `validate.py` 呼叫 trifecta，而那裡由呼叫端以受驗樹綁定 `ProjectPolicy`。

   G0 的 `target != ROOT` 和 `is_this_repo` 只有在「判定程式與受驗樹分開」時才會不同，而目前沒有這種執行路徑。#168 讓 G0 威脅模型閘門明確建立 `Policy(ROOT, project_root=None).for_project(target)`，完整保留現行行為。原本規劃的 PR2（G0 改認 `VIBESEC_PROJECT_ROOT`）取消。

## 後果

- 以後做 architecture review，不要再建議「G4 也改用 `is_this_repo`」。如果要統一，必須先把審查紀錄的位置做成獨立的概念。
- G0 進 CI、判定程式與受驗樹分開時，要改認 `VIBESEC_PROJECT_ROOT`，並逐項重新判斷上述三個附帶影響。程式碼在 G0 威脅模型閘門判斷 `external` 的地方留有註解，指向本 ADR。

---

<a id="english"></a>

# ADR 0001: G4's review-record location stays out of the policy exception "this repo" decision; G0 does not yet honour `VIBESEC_PROJECT_ROOT`

- Status: accepted (2026-10-14)
- Related: #167 (spec), #168 (`ProjectPolicy`), #157 (`VIBESEC_PROJECT_ROOT`)

If the two language sections disagree, the Traditional Chinese section prevails.

## Context

#168 moves "is the project tree this repo" into the policy module: `Policy.for_project(project tree)` decides with `Policy.is_this_repo`, and an external project gets a `ProjectPolicy` with no policy exceptions. G1, G2, and G3 already use `is_this_repo` (#157), and in #168 the G0 trifecta check receives its `ProjectPolicy` from the caller.

Two other places decide "this repo" on their own and do not use `is_this_repo`:

- **G4**: `g4_access` treats the project tree as external when it differs from `g4_review.PROJECT`. `PROJECT` is `VIBESEC_PROJECT_ROOT`, or `ROOT` when that is unset. This decision picks **where the review record is read from**: this repo reads `reviews/g4/<commit>.yaml` in the project tree; an external project reads `reviews/g4/external/<commit>.yaml` in this repo. G4 does not apply policy exceptions.
- **The G0 threat-model gate**: it treats `target != ROOT` as external and ignores `VIBESEC_PROJECT_ROOT`. Besides deciding whether policy exceptions are matched, this decision also controls:
  - whether the MAESTRO methodologies are checked;
  - whether the default threat-model location is tried when `project.threat_model` is not found;
  - whether `contains_llm` comes from this repo's `vibesec.yaml` or is inferred from the project tree's threat model.

## Decision

1. **G4 is not folded into `ProjectPolicy`.** "This repo" has two meanings here: one decides whether policy exceptions apply (`ProjectPolicy`); the other decides which repo holds the review data (G4). Their inputs differ: review records follow the project tree's commit, while policy exceptions are approved only for this repo's paths.

   If G4 switched to `is_this_repo`, then with `VIBESEC_PROJECT_ROOT` set and the project tree pointing at the trusted tree itself, `is_this_repo` would say "this repo" while `find_self_record` still read records from `PROJECT` (the other tree), and the two would disagree.
2. **G0 does not honour `VIBESEC_PROJECT_ROOT` yet.** G0 runs in no CI workflow. When the harness runs it locally, `--target` is `ROOT`; CI calls the trifecta check only through `validate.py`, where the caller binds the `ProjectPolicy` to the project tree.

   G0's `target != ROOT` and `is_this_repo` differ only when the verdict code and the project tree are split, and no execution path does that today. #168 has the G0 threat-model gate build `Policy(ROOT, project_root=None).for_project(target)` explicitly, keeping the current behaviour exactly. The planned PR2 (G0 honouring `VIBESEC_PROJECT_ROOT`) is cancelled.

## Consequences

- Future architecture reviews should not suggest "G4 should also use `is_this_repo`". Unifying them first requires making the review-record location a concept of its own.
- When G0 enters CI with the verdict code and the project tree split, it must honour `VIBESEC_PROJECT_ROOT`, and each of the three side effects above must be re-decided. The code where the G0 threat-model gate decides `external` carries a comment pointing to this ADR.
