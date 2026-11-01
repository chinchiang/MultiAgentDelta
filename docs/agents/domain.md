[正體中文（臺灣）](#zh-tw) | [English](#english)

<a id="zh-tw"></a>

# 領域文件

技能在探索程式碼時，如何讀取本 repo 的領域文件。本 repo 是 single-context：一份領域用語檔加一個 ADR 目錄。

## 探索前先讀

- **`GLOSSARY.md`**（repo 根目錄）：本 repo 的領域用語。技能文件裡提到的 `CONTEXT.md` 在本 repo 一律指 `GLOSSARY.md`（#154 改名）。
- **`docs/adr/`**：與即將動到的範圍相關的 ADR。

任一檔案不存在時**直接繼續**，不要提醒缺少、也不要主動建議建立；`/domain-modeling` 會在用語或決策真正定案時才建立。

## 檔案結構

```
/
├── GLOSSARY.md
├── docs/adr/
│   └── 0001-<slug>.md
└── scripts/
```

新增的 ADR 與 `GLOSSARY.md` 一樣遵守 AGENTS.md 的雙語規範：先正體中文、再英文，以 `<a id="zh-tw"></a>`、`<a id="english"></a>` 分段，兩者有出入時以正體中文版為準。

## 使用用語檔的詞彙

輸出中提到領域概念時（issue 標題、重構提案、假設、測試名稱），使用 `GLOSSARY.md` 定義的詞，不要改用它列在「避免」的同義詞。

用語檔裡找不到需要的概念時，代表兩種可能：自己在發明專案沒有的說法（請重新考慮），或用語檔確實有缺口（記下來交給 `/domain-modeling`）。

## 標出與 ADR 的衝突

輸出與既有 ADR 矛盾時，要明確標出，不要默默推翻：

> _與 ADR-0001 矛盾，但值得重新討論，因為……_

---

<a id="english"></a>

# Domain docs

How the skills read this repo's domain documentation while exploring the code. This repo is single-context: one glossary file plus one ADR directory. If the two language sections disagree, the Traditional Chinese section prevails.

## Before exploring, read these

- **`GLOSSARY.md`** at the repo root: the domain vocabulary. Wherever the skills mention `CONTEXT.md`, in this repo it means `GLOSSARY.md` (renamed in #154).
- **`docs/adr/`**: ADRs that touch the area you are about to work in.

If either is missing, **proceed silently**: don't flag its absence or suggest creating it upfront. `/domain-modeling` creates them when a term or decision is actually resolved.

## File structure

```
/
├── GLOSSARY.md
├── docs/adr/
│   └── 0001-<slug>.md
└── scripts/
```

New ADRs follow the same bilingual rule as `GLOSSARY.md` and AGENTS.md: Traditional Chinese first, then English, separated by `<a id="zh-tw"></a>` and `<a id="english"></a>`; if they disagree, the Traditional Chinese version prevails.

## Use the glossary's vocabulary

When your output names a domain concept (an issue title, a refactor proposal, a hypothesis, a test name), use the term defined in `GLOSSARY.md`. Don't drift to the synonyms it lists under "Avoid".

If the concept you need isn't in the glossary, either you are inventing language the project doesn't use (reconsider), or there is a real gap (note it for `/domain-modeling`).

## Flag ADR conflicts

If your output contradicts an existing ADR, say so explicitly instead of silently overriding it:

> _Contradicts ADR-0001, but worth reopening because…_
