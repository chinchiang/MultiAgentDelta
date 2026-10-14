[正體中文（臺灣）](#zh-tw) | [English](#english)

<a id="zh-tw"></a>

# Issue tracker：GitHub

本 repo 的 issue 與 spec 放在 GitHub Issues（`chinchiang/MultiAgentDelta`），所有操作用 `gh` CLI。

## 慣例

- **建立 issue**：`gh issue create --title "..." --body "..."`；多行內文用 heredoc 或 `--body-file`。
- **讀 issue**：`gh issue view <number> --comments`，並取得 labels。
- **列出 issue**：`gh issue list --state open --json number,title,body,labels,comments`，視需要加 `--label`、`--state`。
- **留言**：`gh issue comment <number> --body "..."`
- **加／移除 label**：`gh issue edit <number> --add-label "..."`／`--remove-label "..."`
- **關閉**：`gh issue close <number> --comment "..."`
- **語言**：issue 標題與內文用正體中文（臺灣慣用語）；技術名詞、程式識別碼、指令與 ID 保留原文。issue 不需要雙語。
- **用語**：依 `GLOSSARY.md`（例如「受驗樹」不寫成 target，「政策例外」不寫成 allowlist）。

repo 由 `git remote -v` 推得；在 clone 內執行 `gh` 會自動帶入。

## Pull request 作為 triage 來源

**PR 是否作為需求來源：否。**（若本 repo 把外部 PR 當成功能需求，改成「是」；`/triage` 讀這個旗標。）

## 技能說「發佈到 issue tracker」時

建立一個 GitHub issue。

## 技能說「取得相關 ticket」時

執行 `gh issue view <number> --comments`。

## 父子與阻擋關係

- **子 ticket**：以 GitHub sub-issue 掛在父 issue 下（`gh api` 的 sub-issues endpoint）；無法使用時，在父 issue 內文列 task list，並在子 issue 內文開頭寫 `Part of #<父>`。
- **阻擋**：用 GitHub 原生的 issue dependencies：`gh api --method POST repos/chinchiang/MultiAgentDelta/issues/<子>/dependencies/blocked_by -F issue_id=<阻擋者的 database id>`。database id 由 `gh api repos/chinchiang/MultiAgentDelta/issues/<n> --jq .id` 取得（不是 `#number`，也不是 `node_id`）。無法使用時，在子 issue 內文開頭寫 `Blocked by: #<n>`。所有阻擋者關閉後，ticket 才算解除阻擋。

---

<a id="english"></a>

# Issue tracker: GitHub

Issues and specs for this repo live in GitHub Issues (`chinchiang/MultiAgentDelta`). Use the `gh` CLI for all operations. If the two language sections disagree, the Traditional Chinese section prevails.

## Conventions

- **Create an issue**: `gh issue create --title "..." --body "..."`; use a heredoc or `--body-file` for multi-line bodies.
- **Read an issue**: `gh issue view <number> --comments`, also fetching labels.
- **List issues**: `gh issue list --state open --json number,title,body,labels,comments`, with `--label` and `--state` filters as needed.
- **Comment**: `gh issue comment <number> --body "..."`
- **Apply / remove labels**: `gh issue edit <number> --add-label "..."` / `--remove-label "..."`
- **Close**: `gh issue close <number> --comment "..."`
- **Language**: issue titles and bodies are written in Traditional Chinese (Taiwan usage); technical terms, code identifiers, commands, and IDs stay in their original form. Issues do not need to be bilingual.
- **Vocabulary**: follow `GLOSSARY.md` (for example, "project tree", not "target"; "policy exception", not "allowlist").

The repo is inferred from `git remote -v`; `gh` does this automatically inside a clone.

## Pull requests as a triage surface

**PRs as a request surface: no.** (Set to "yes" if this repo treats external PRs as feature requests; `/triage` reads this flag.)

## When a skill says "publish to the issue tracker"

Create a GitHub issue.

## When a skill says "fetch the relevant ticket"

Run `gh issue view <number> --comments`.

## Parent, child, and blocking relationships

- **Child ticket**: attach it to the parent issue as a GitHub sub-issue (the sub-issues endpoint via `gh api`). If unavailable, list it in a task list in the parent body and put `Part of #<parent>` at the top of the child body.
- **Blocking**: use GitHub's native issue dependencies: `gh api --method POST repos/chinchiang/MultiAgentDelta/issues/<child>/dependencies/blocked_by -F issue_id=<blocker database id>`. Get the database id with `gh api repos/chinchiang/MultiAgentDelta/issues/<n> --jq .id` (not the `#number` or `node_id`). If unavailable, put `Blocked by: #<n>` at the top of the child body. A ticket is unblocked when every blocker is closed.
