
[正體中文（臺灣）](#zh-tw) | [English](#english)

<a id="zh-tw"></a>

# 11. 工具選型矩陣（SAST / SCA / Secrets / DAST / AI 紅隊）

Vibe Coding 產生的程式碼有兩個傳統工具難以覆蓋的面向：AI 把資料來源（Source）與危險匯點（Sink）拆散於多檔，以及自然語言介面上的 Prompt Injection 與 Agent 工具調用邏輯。因此工具鏈必須同時具備**跨檔跨函式污點分析**與**幻覺套件（Slopsquatting）防衛**，並在傳統 SAST/DAST 之外加上專屬 AI 紅隊層。

本框架不要求所有專案採用相同成本的工具；依 `vibesec.yaml` 的 `risk_tier`（ASVS 5.0 的 L1/L2/L3）分級投入。

## 一、SAST（靜態程式碼分析）

| 工具 | 檢測機制 | 速度 | 跨檔跨函式污點分析 | 定位 |
|---|---|---|---|---|
| **Semgrep** | Pattern / AST / Taint | 極快 | ⚠️ CE 版單檔單函式；Pro 版支援 | PR 階段首選，CI 整合佳（見 `config/semgrep/vibesec-rules.yaml`） |
| **CodeQL** | 語意化資料流查詢 | 較慢 | 強（深度追蹤） | 夜間全量（`nightly-full.yml`），GitHub 原生整合 |
| **SonarQube** | 規則 + AI Code Assurance | 中等 | 中等 | 品質閘門控管，專為 AI 程式碼設計的閘門 |
| **Snyk Code** | ML + 符號分析 | 快 | 支援 | 開發者體驗佳、IDE 整合、自動修補建議（商用） |

選型：PR 階段 Semgrep <5 分鐘快速攔截；夜間 CodeQL 全量深度掃描。

## 二、SCA（軟體成分與幻覺套件）

| 工具 | SBOM | 掃描範圍 | 授權 | 定位 |
|---|---|---|---|---|
| **Trivy** | CycloneDX / SPDX | 漏洞 + 祕密 + IaC + K8s | Apache-2.0 | 覆蓋最廣的預設首選 |
| **Grype / Syft** | 原生 SBOM-first | 漏洞（Syft 生成 SBOM） | Apache-2.0 | SBOM 合規與 air-gapped 環境 |
| **Socket / DevSentinel** | — | 行為分析 / 惡意套件 / Slopsquatting | 商業 / 免費層 | 安裝前驗證存在性、下載量、冷卻期 |
| **SlopCheck / SlopScan** | — | Markdown、`.cursorrules`、`AGENTS.md` | 開源 / API | Agent 規則檔中捏造套件名 |

G1 的四層快篩（存在性、相似度、安裝 Hook、冷卻期）以純 stdlib Python 內嵌於 `pr-gates.yml`，再接 Syft + Grype/Trivy 做 SBOM 與 CVE。詳見 `docs/02-g1-supply-chain.md`。

## 三、Secrets

**Gitleaks**（開源標準）：正則 + Shannon 熵值，掃全 Git 歷史，支援 `gitleaks protect --staged` pre-commit 與 CI Push Protection。設定見 `config/gitleaks.toml`。

## 四、DAST / API 模糊測試

| 工具 | 方法 | 優勢 | 邊界 |
|---|---|---|---|
| **OWASP ZAP** | Spider / Active / API Scan | 免費、CI Docker Action、URL 覆蓋高 | 不涵蓋 Prompt Injection 與 Agent 邏輯 |
| **Burp Suite Pro** | 互動式 Proxy | 業界標準，Autorize / AuthMatrix 精準實測 BOLA/IDOR | 需結合手動與 Token 替換 |
| **Nuclei** | YAML 範本 | 極快，比對已知 CVE 與除錯資訊暴露 | 無法測複雜業務邏輯與 LLM 鏈路 |
| **API Harvester / Schemathesis** | OpenAPI 屬性測試 | 依 schema 自動推演 BOLA、Rate Limit、參數 fuzzing | 依賴完整正確的 API 規格 |

## 五、AI / Agent 紅隊

| 工具 | 開發者 / 授權 | 功能 | 場景 |
|---|---|---|---|
| **garak** | NVIDIA / Apache-2.0 | 「LLM 界的 Nmap」：幻覺、資料洩漏、Direct Injection、Jailbreak 批次探測 | 上線前自動化掃描 |
| **PyRIT** | Microsoft / MIT | 編排式紅隊，自動生成多輪攻擊與對抗 Payload | 複雜 Multi-Agent 與企業紅隊 |
| **promptfoo** | Open Source / MIT | 宣告式評測、CI 整合、對照 OWASP LLM Top 10 | 嵌入 CI 的常態紅隊（見 `config/promptfoo/`） |
| **NeMo Guardrails / Llama Guard** | NVIDIA / Meta | 執行期語意防火牆、輸入/輸出攔截、PII 遮罩 | 執行期防護（非測試工具，無數學保證） |

## 六、依 ASVS 風險分級的工具鏈組合

```
                    [ 系統風險分級審查 (G0) ]
     ┌───────────────────────┼───────────────────────┐
【低風險 L1】            【中風險 L2】            【高風險 L3】
純內部 / 無個資 / 無 LLM   對外 / 一般業務 / 含 LLM   對外＋個資＋高權限 Agent
 • Semgrep CE            • Semgrep Pro / CodeQL   • Checkmarx / Snyk Code
 • Trivy + Gitleaks      • Socket / DevSentinel   • SonarQube AI Code Assurance
 • OWASP ZAP (+Nuclei)   • Trivy + Burp Suite Pro • 商用 DAST + 委外滲透測試
 • garak / promptfoo     • PyRIT + promptfoo      • 商用 AI 紅隊平台 + 沙箱隔離 + HITL
 （重點 G1、G2）          （六閘門全開）           （六閘門深度加倍、對齊 EU CRA / ISO 27001）
```

- **L1**：全開源、零授權費；跨檔污點較弱、需自行整合 SARIF。
- **L2**：補齊跨檔污點與幻覺套件攔截，具標準 CI 阻擋。
- **L3**：完整法規合規（EU CRA / ISO 27001）、企業面板；Agent 架構必須硬性沙箱與 Human-in-the-Loop。

> 資源配置原則：昂貴的商業授權與資深審查人力，應精準投放於涉及隱私與具對外連能力的高風險（ASVS L3）應用。


---

<a id="english"></a>

# 11. Tool Selection Matrix (SAST / SCA / Secrets / DAST / AI Red Team)

Traditional tools struggle with two features of AI-generated code: sources and dangerous sinks split across files, and natural-language prompt injection/agent tool-call logic. The toolchain therefore needs **cross-file, interprocedural taint analysis**, **slopsquatting defenses**, and a dedicated AI red-team layer alongside SAST/DAST.

Spend according to the ASVS L1/L2/L3 `risk_tier` in `vibesec.yaml`; not every project needs the same tool budget.

## 1. SAST

| Tool | Mechanism | Speed | Cross-file/interprocedural taint | Role |
|---|---|---|---|---|
| Semgrep | Patterns / AST / taint | Very fast | CE: single file/function; Pro: supported | PR default; strong CI integration (`config/semgrep/vibesec-rules.yaml`) |
| CodeQL | Semantic data-flow queries | Slower | Strong, deep tracing | Nightly full scans (`nightly-full.yml`); native GitHub integration |
| SonarQube | Rules + AI Code Assurance | Moderate | Moderate | Quality gates tailored to AI-generated code |
| Snyk Code | ML + symbolic analysis | Fast | Supported | Developer/IDE experience and remediation suggestions; commercial |

Use Semgrep for PR feedback under five minutes and CodeQL for deep nightly scans.

## 2. SCA and hallucinated packages

| Tool | SBOM | Coverage | License | Role |
|---|---|---|---|---|
| Trivy | CycloneDX / SPDX | Vulnerabilities, secrets, IaC, K8s | Apache-2.0 | Broad default coverage |
| Grype / Syft | Native SBOM-first | Vulnerabilities; Syft generates SBOMs | Apache-2.0 | SBOM compliance and air-gapped environments |
| Socket / DevSentinel | — | Behavior, malicious packages, slopsquatting | Commercial / free tier | Pre-install existence, download, and cooldown checks |
| SlopCheck / SlopScan | — | Markdown, `.cursorrules`, `AGENTS.md` | Open source / API | Fabricated package names in agent rule files |

G1's stdlib Python checks in `pr-gates.yml` cover existence, similarity, install hooks, and cooldown. Syft plus Grype/Trivy then provide SBOM/CVE checks. See `docs/02-g1-supply-chain.md`.

## 3. Secrets

**Gitleaks** combines regular expressions and Shannon entropy, scans full Git history, and supports staged pre-commit protection and CI integration. Configure it in `config/gitleaks.toml`; use Push Protection as an additional layer.

## 4. DAST / API fuzzing

| Tool | Method | Strength | Boundary |
|---|---|---|---|
| OWASP ZAP | Spider / active / API scan | Free, CI Docker actions, URL coverage | Does not cover prompt injection or agent logic |
| Burp Suite Pro | Interactive proxy | Autorize/AuthMatrix for precise BOLA/IDOR tests | Requires manual work and token substitution |
| Nuclei | YAML templates | Fast known-CVE/debug-exposure checks | Not complex business logic or LLM chains |
| API Harvester / Schemathesis | OpenAPI property testing | Schema-driven BOLA, rate-limit, parameter fuzzing | Depends on complete, accurate API specifications |

## 5. AI / agent red team

| Tool | Developer / license | Capability | Use |
|---|---|---|---|
| garak | NVIDIA / Apache-2.0 | Batch hallucination, leakage, direct-injection, jailbreak probes | Automated pre-release scans |
| PyRIT | Microsoft / MIT | Orchestrated multi-turn attacks and adversarial payloads | Complex multi-agent and enterprise red teams |
| promptfoo | Open source / MIT | Declarative evaluations, CI, OWASP LLM mapping | Continuous CI red teaming (`config/promptfoo/`) |
| NeMo Guardrails / Llama Guard | NVIDIA / Meta | Runtime semantic filtering, input/output interception, PII masking | Runtime defenses, not test tools or mathematical guarantees |

## 6. Toolchains by risk tier

| Tier / target | Suggested combination | Trade-offs |
|---|---|---|
| L1: internal, no personal data, no LLM | Semgrep CE; Trivy + Gitleaks; ZAP (+Nuclei); garak/promptfoo where applicable | Open source, no license fees; weaker cross-file taint; integrate SARIF yourself; emphasize G1/G2 |
| L2: public-facing, ordinary business, LLM use | Semgrep Pro / CodeQL; Socket / DevSentinel; Trivy + Burp Suite Pro; PyRIT + promptfoo | All six gates; cross-file taint, slopsquatting defense, standard CI blocking |
| L3: public-facing + personal data + privileged agents | Checkmarx / Snyk Code; SonarQube AI Code Assurance; commercial DAST + external penetration tests; commercial AI red team + sandbox + HITL | Deeper coverage across all gates, enterprise dashboards, EU CRA / ISO 27001 alignment; mandatory agent sandboxing and human oversight |

Allocate expensive licenses and senior reviewers to privacy-sensitive, externally connected high-risk L3 applications.
