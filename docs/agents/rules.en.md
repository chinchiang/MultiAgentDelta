English translation of `AGENTS.md`, for readers who do not read Chinese. Agents do not load this file; `AGENTS.md` is the source, and **the Traditional Chinese version prevails** if the two disagree. Update this file in the same PR as any change to `AGENTS.md`; `scripts/bilingual.py` checks that both files have the same heading structure.

# AGENTS.md — VibeSec Repository Rules (for the harness agent and all AI contributors)

This repository holds the documentation, configuration, and lab for the "Vibe Coding six security gates (G0–G6)" framework. The main configuration is `vibesec.yaml`; before running or changing the gate process, read `docs/08-harness-agent.md`.

`AGENTS.md` is the single source of the repository rules; `CLAUDE.md` holds only the line `@AGENTS.md` so that Claude Code loads it. Edit the rules there only; how this English translation is kept in sync is under "Documentation language".

## Mandatory rules

Rule numbers are cited by code and documentation ("AGENTS.md 規則 N", "#N", "第 N 條"): append new rules at the end and keep existing numbers unchanged.

1. **Gates cannot be bypassed.** Do not disable, skip, or relax any gate with `enabled: true` in `vibesec.yaml`, and do not edit `config/policy/blocking-policy.yaml` to demote blocking to advisory so a check passes. Policy changes must be decided by a human in a separate PR.
2. **incomplete ≠ pass.** Missing tools, timeouts, API failures, missing accounts or documents, or an environment that cannot start → the gate status is `incomplete` with a `status_reason`. Never report a pass. Cases not on this list are fail-closed too: no evidence means `incomplete`.
3. **IDs come only from the catalogs.** CWE, CVE, ASVS control IDs, and OWASP LLM Top 10 IDs must come from `config/catalogs/`; never guess. If an ID cannot be found, use `null` and explain in `notes`.
4. **Do not combine scores.** Record the CVSS v4.0 vector and score, EPSS with its query date, and KEV with its date in separate fields. No custom `CVSS × EPSS × model confidence` multiplication. Model self-reported confidence is never turned into an evidence grade.
5. **Evidence grade and validation status are separate.** `evidence_grade` (E0–E3) describes how trustworthy the evidence is; `validation_status` (pending/confirmed/refuted) describes the current conclusion. Neither equals severity.
6. **Multi-model review rules.** High-risk controls need independent checks by models from at least two different `family` values; round 1 does not exchange conclusions; at most two cross-examination rounds follow; minority opinions are kept; no majority vote; disagreement goes to human adjudication (`requires_human: true`).
7. **No exfiltration.** Unclassified data stays with on-premises providers; only providers whose `allowed_data_classes` in `config/providers.yaml` include the data class may receive that content. Secrets in reports keep only a mask and a fingerprint.
8. **Attack only the lab.** `examples/vulnapp` is a deliberately vulnerable test target. G5/G6 offensive probes may run only against the authorized test environment that `VIBESEC_TARGET_URL` points to.

## Naming and format conventions

- Gate IDs: `G0`–`G6`. Rule IDs: `vibesec.g<N>.<kebab-name>`; external tool rules keep their original names with a prefix: `gitleaks:`, `semgrep:`, `trivy:`, `grype:`, `checkov:`, `zap:`, `promptfoo:`, `garak:`.
- Control IDs: ASVS uses `ASVS5-V<chapter>.<section>` (self-assigned down to the section, not official requirement numbers; see the disclaimer in `config/catalogs/asvs-5.0-controls.yaml`); OWASP LLM Top 10 uses `LLM01:2025`…`LLM10:2025`; MAESTRO uses `MAESTRO-L1`…`MAESTRO-L7`; vibesec's own controls use `VS-G<N>-<NAME>`.
- Finding ID: `VS-YYYYMMDD-<8 hex>`.
- All output must conform to `schemas/finding.schema.json` and `schemas/gate-result.schema.json`. SARIF 2.1.0 is for code-location findings; architecture findings go into `risk_register.json`.
- Every gate document has fixed sections: adversarial causes / triggers and nature / core tasks / automation / tools and configuration files / blocking policy / mapped controls (ASVS, CWE, LLM Top 10, MAESTRO) / verification.

### Documentation language

- Documentation is written in Traditional Chinese (Taiwan usage). Technical terms, code identifiers, commands, and IDs stay in their original form; code comments and tool output stay in Traditional Chinese.
- The **bilingual set** (`GLOSSARY.md`, `docs/agents/`, `docs/adr/`, `docs/research/`, including new files in those directories) also carries English: each Markdown file has the Traditional Chinese section first, then the English section, separated by `<a id="zh-tw"></a>` and `<a id="english"></a>`, with language links at the top.
- **Translation**: `AGENTS.md` is Traditional Chinese only; its English translation is `docs/agents/rules.en.md`. The translation is not part of the bilingual set and must have the same heading structure as `AGENTS.md`.
- When either language section of a bilingual-set file changes, or when `AGENTS.md` changes, update the other language in the same PR; if they disagree, **the Traditional Chinese version prevails**.
- All other documents are Traditional Chinese only (#178).
- `scripts/bilingual.py` checks the anchors, language links, and heading structure (including the translation); sentence-by-sentence correspondence is left to review.

## Verification commands

```bash
python3 scripts/validate.py          # YAML syntax, JSON schema, examples, catalog ID consistency
uv run --project examples/vulnapp uvicorn app.main:app --port 8000   # start the lab
```

## Agent skills

### Issue tracker

Before opening an issue, reading a spec, or commenting, see `docs/agents/issue-tracker.md` (GitHub Issues `chinchiang/MultiAgentDelta`, operated with `gh`).

### Triage labels

Before adding or changing issue labels, see `docs/agents/triage-labels.md`.

### Domain docs

Before naming a concept, using domain vocabulary, writing an ADR, or running an architecture review, read `GLOSSARY.md` and `docs/adr/` (single-context; see `docs/agents/domain.md`).

### Workflow

Before implementing a ticket, opening a PR, or merging: steps, pass criteria (case-by-case eval comparison, CI gate table), and gotchas are in `docs/agents/workflow.md`.
