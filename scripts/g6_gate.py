#!/usr/bin/env python3
"""G6 AI 紅隊結果彙整：promptfoo eval（決定性）＋ promptfoo redteam（選用，需金鑰）＋ garak → 一份 gate json + SARIF。

原則（CLAUDE.md #2）：
  - 測試失敗 → fail（不得因 promptfoo 非零退出碼而改寫成 incomplete）。
  - 工具缺席、輸出無法解析、單一測試執行錯誤、未設定金鑰 → 該層 / 該 check 記 untested，閘門 incomplete。
  - 未提供某一層的結果（缺 --redteam／--redteam-skipped、缺 --garak-glob、缺 --cost、缺 --observations）或結果為空 → 該層 untested。
  - vibesec.yaml gates.g6_ai_red_team.checks 宣告的每個 check 都必須有實測結果（pass／fail），否則記 untested。
  - promptfoo eval 退出碼非零但結果中沒有斷言失敗、或退出碼不是 0／100（工具錯誤，結果可能不完整）→ untested；
    退出碼 100 且有斷言失敗 → 照實記 fail。promptfoo redteam 同樣看退出碼（--redteam-exit-code）。
  - promptfoo redteam：設定（--redteam-config）列出的 plugin 在結果中沒有任何測試 → 該 plugin untested。
  - garak：報告缺 completion 紀錄（執行中途結束）、log 有 Traceback／❌（中止）、有送出攻擊但沒有評估結果的 probe、
    設定中指名但沒有結果的 probe 或 probe 家族 → untested（以前只要有任何 eval 紀錄，其餘就默認為完成）。
  - 只有所有層都實際執行且無失敗才是 pass。
規則 ID 只查 config/catalogs/cwe-map.yaml（CLAUDE.md #3）；查不到者 policy_tier 視為 advisory 並在 message 註明。

用法：
  python3 scripts/g6_gate.py --eval reports/g6-promptfoo.json \
      [--redteam reports/g6-promptfoo-redteam.json [--redteam-exit-code N] [--redteam-config config/promptfoo/promptfooconfig.yaml]
       | --redteam-skipped "未設定 ANTHROPIC_API_KEY / OPENAI_API_KEY secret"] \
      [--garak-glob 'reports/g6-garak*.report.jsonl'] \
      --cost reports/g6-cost.json --observations reports/g6-observations.json \
      --gate reports/g6-gate.json --sarif reports/g6.sarif
  python3 scripts/g6_gate.py --target-denied "<原因>" --gate … --sarif …   # 目標未通過 scripts/target_guard.py
  （mode 取自受信任政策，ADR 0002；--mode 已不使用、傳了也忽略，將在 #199 的第二階段移除）
  python3 scripts/g6_gate.py selftest
成本面（LLM10 denial_of_wallet_cost）由 scripts/g6_cost_probe.py 實測後以 --cost 帶入；未提供或無法解析 → untested。
工具事件（LLM06 excessive_agency_telemetry）由 scripts/g6_observe.py 實測後以 --observations 帶入：高影響工具未經人工核准
即執行 → fail（vibesec.g6.excessive-agency）；未提供、無法解析或目標沒有 tool_events → untested。
usage 只在觀測檔分欄記錄，不併入任何分數（CLAUDE.md 規則 4）。
退出碼：0 已寫出結果（不論 pass/fail/incomplete；是否阻擋由 workflow 的彙整步驟依 mode 與政策決定）。
"""
from __future__ import annotations
import argparse, glob, json, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SARIF_URI = ".github/workflows/staging-blackbox.yml"

# promptfoo failureReason：1 = 斷言失敗，2 = 執行錯誤
PF_ASSERT, PF_ERROR = 1, 2
PF_FAILED_EXIT = 100   # promptfoo 有測試失敗時的退出碼（PROMPTFOO_FAILED_TEST_EXIT_CODE 預設值）

# garak probe 前綴 → vibesec 規則
GARAK_RULES = {
    "promptinject": "vibesec.g6.direct-prompt-injection",
    "dan": "vibesec.g6.direct-prompt-injection",
    "encoding": "vibesec.g6.direct-prompt-injection",
    "latentinjection": "vibesec.g6.indirect-prompt-injection",
    "leakreplay": "vibesec.g6.system-prompt-extraction",
    "xss": "vibesec.g6.stored-xss-via-ai-output",            # garak < 0.17
    "web_injection": "vibesec.g6.stored-xss-via-ai-output",  # garak ≥ 0.17（TaskXSS、MarkdownXSS…）
}


def now() -> str:
    return gate_result.now()


def load_catalog() -> tuple[dict, dict]:
    try:
        import yaml
        d = yaml.safe_load((ROOT / "config/catalogs/cwe-map.yaml").read_text(encoding="utf-8")) or {}
        return d.get("rules", {}), d.get("external_prefixes", {})
    except Exception:
        return {}, {}


sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vibesec_policy import effective_mode, load_policy  # noqa: E402  tier 與 mode 的唯一來源
import gate_result  # noqa: E402  tool 列、自產 SARIF 骨架與時間戳只有一份寫法（#184）；coverage 與判定仍在 build()

# G6 自己的 tool 名稱與版本：SARIF driver，以及政策讀不到時閘門結果唯一的一列 tool
TOOL_NAME, TOOL_VERSION = "vibesec-g6", "1.0.0"


class Collector:
    def __init__(self, catalog: dict, prefixes: dict | None = None, policy=None):
        """policy：本 repo 的 Policy（進入點建立一次）；None ＝ 政策讀不到，不得呼叫 finding()。"""
        self.cat = catalog
        self.policy = policy
        self.prefixes = prefixes or {}
        self.results: list[dict] = []
        self.rules: dict[str, dict] = {}
        self.coverage: dict[str, dict] = {}   # key -> {control_id, state, reason}
        self.tools: list[dict] = []
        self.reasons: list[str] = []
        self.tested: set[str] = set()         # 有 pass／fail 實測結果的 check（對照 vibesec.yaml 宣告的 checks）

    def tier(self, rule_id: str) -> str:
        # tier 只來自 blocking-policy（vibesec_policy.Policy）；cwe-map 的 policy_tier 只是預設建議
        return self.policy.tier(rule_id)

    def control(self, rule_id: str, fallback: str) -> str:
        ids = (self.cat.get(rule_id) or {}).get("control_ids") or []
        llm = [c for c in ids if c.startswith("LLM")]
        return (llm or ids or [fallback])[0]

    def finding(self, rule_id: str, msg: str, source: str):
        known = rule_id in self.cat
        tier = self.tier(rule_id) if known else "advisory"
        level = "error" if tier == "blocking" else "warning"
        if not known:
            prefix = next((p for p in self.prefixes if rule_id.startswith(p)), None)
            msg += (f"（外部規則 {prefix}，cwe-map 未定 policy_tier，預設 advisory，待人工裁定）" if prefix
                    else f"（rule_id {rule_id} 不在 cwe-map，暫列 advisory）")
        self.rules.setdefault(rule_id, {"id": rule_id, "name": rule_id,
                                        "shortDescription": {"text": (self.cat.get(rule_id) or {}).get("title", rule_id)},
                                        "properties": {"policy_tier": tier}})
        self.results.append({"ruleId": rule_id, "level": level, "message": {"text": msg},
                             "locations": [{"physicalLocation": {"artifactLocation": {"uri": SARIF_URI}}}],
                             "properties": {"policy_tier": tier, "source": source}})

    def cover(self, key: str, control_id: str, state: str, reason: str | None = None, check: str | None = None):
        if check and state in ("pass", "fail"):
            self.tested.add(check)
        prev = self.coverage.get(key)
        rank = {"fail": 3, "untested": 2, "pass": 1}
        if prev is None or rank[state] > rank[prev["state"]]:
            self.coverage[key] = {"control_id": control_id, "state": state, "reason": reason}


def ingest_promptfoo_eval(c: Collector, path: str | None, exit_code: int | None):
    tool = gate_result.tool("promptfoo-eval", "ran", exit_code=exit_code, output_ref=path)
    try:
        data = json.loads(pathlib.Path(path).read_text(encoding="utf-8")) if path else None
        rows = data["results"]["results"]
        if not isinstance(rows, list):
            raise TypeError("results.results")
    except Exception as e:
        tool["state"] = "missing" if not path or not pathlib.Path(path).exists() else "error"
        c.tools.append(tool)
        c.reasons.append(f"promptfoo eval 無可解析輸出（{type(e).__name__}）")
        c.cover("promptfoo-eval", "LLM01:2025", "untested", "promptfoo eval 未產生可解析結果")
        return
    c.tools.append(tool)
    rows = [r for r in rows if isinstance(r, dict)]
    if not rows:
        why = "promptfoo eval 結果沒有任何測試（空結果不算通過）"
        c.cover("promptfoo-eval", "LLM01:2025", "untested", why)
        c.reasons.append(why)
        return
    asserted = 0
    for r in rows:
        md = ((r.get("testCase") or {}).get("metadata")) or r.get("metadata") or {}
        rule = md.get("vibesec_rule_id") or "promptfoo:unmapped"
        check = md.get("vibesec_check") or rule
        desc = (r.get("testCase") or {}).get("description") or check
        ctrl = c.control(rule, "LLM01:2025")
        if r.get("success"):
            c.cover(check, ctrl, "pass", check=check)
        elif r.get("failureReason") == PF_ERROR:
            c.cover(check, ctrl, "untested", f"執行錯誤：{(r.get('error') or '')[:160]}")
            c.reasons.append(f"promptfoo 測試「{desc}」執行錯誤")
        else:
            asserted += 1
            c.cover(check, ctrl, "fail", check=check)
            c.finding(rule, f"promptfoo：{desc} — {(r.get('error') or '斷言失敗')[:200]}", "promptfoo-eval")
    # 退出碼 100 = 有測試失敗（正常結果）；其他非零 = 工具錯誤，結果可能不完整；非零卻沒有斷言失敗 = 結果與退出碼矛盾
    if exit_code not in (None, 0) and (exit_code != PF_FAILED_EXIT or not asserted):
        why = (f"promptfoo eval 退出碼 {exit_code}" +
               ("，結果中沒有斷言失敗（工具錯誤或結果不完整）" if not asserted else "（非測試失敗的退出碼，結果可能不完整）"))
        c.cover("promptfoo-eval", "LLM01:2025", "untested", why)
        c.reasons.append(why)


def redteam_expected_plugins(config_path: str | None) -> list[str] | None:
    """promptfoo 設定 redteam.plugins 的 id 清單；未提供設定 → None（不比對），讀不到或格式不符 → []（呼叫端記 untested）。"""
    if not config_path:
        return None
    try:
        import yaml
        plugins = ((yaml.safe_load(pathlib.Path(config_path).read_text(encoding="utf-8")) or {}).get("redteam") or {}).get("plugins")
        ids = [p if isinstance(p, str) else (p or {}).get("id") for p in plugins or []]
        return [str(i) for i in ids if i]
    except Exception:
        return []


def ingest_promptfoo_redteam(c: Collector, path: str | None, skipped: str | None,
                             exit_code: int | None = None, config_path: str | None = None):
    if skipped:
        c.tools.append(gate_result.tool("promptfoo-redteam", "missing"))
        c.cover("promptfoo-redteam", "LLM01:2025", "untested", skipped)
        c.reasons.append(f"redteam 生成層未執行：{skipped}")
        return
    if not path:
        why = "redteam 生成層沒有結果（未提供 --redteam 或 --redteam-skipped）"
        c.tools.append(gate_result.tool("promptfoo-redteam", "missing"))
        c.cover("promptfoo-redteam", "LLM01:2025", "untested", why)
        c.reasons.append(why)
        return
    try:
        rows = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))["results"]["results"]
        if not isinstance(rows, list):
            raise TypeError("results.results")
    except Exception as e:
        c.tools.append(gate_result.tool("promptfoo-redteam", "error", output_ref=path))
        c.cover("promptfoo-redteam", "LLM01:2025", "untested", f"redteam 輸出無法解析（{type(e).__name__}）")
        c.reasons.append("promptfoo redteam 輸出無法解析")
        return
    c.tools.append(gate_result.tool("promptfoo-redteam", "ran", output_ref=path))
    rows = [r for r in rows if isinstance(r, dict)]
    if not rows:
        c.cover("promptfoo-redteam", "LLM01:2025", "untested", "redteam 結果沒有任何測試（空結果不算通過）")
        c.reasons.append("promptfoo redteam 結果沒有任何測試")
        return
    failed = errored = 0
    seen: set[str] = set()
    for r in rows:
        md = ((r.get("testCase") or {}).get("metadata")) or r.get("metadata") or {}
        plugin = md.get("pluginId") or md.get("plugin") or "unknown"
        seen.add(str(plugin))
        if r.get("success"):
            continue
        if r.get("failureReason") == PF_ERROR:
            errored += 1
            continue
        failed += 1
        c.finding(f"promptfoo:{plugin}", f"promptfoo redteam：plugin {plugin} 未通過 — {(r.get('error') or '')[:200]}",
                  "promptfoo-redteam")
    if failed:
        c.cover("promptfoo-redteam", "LLM01:2025", "fail")
    elif errored:
        c.cover("promptfoo-redteam", "LLM01:2025", "untested", f"{errored} 個 redteam 測試執行錯誤")
        c.reasons.append(f"promptfoo redteam 有 {errored} 個測試執行錯誤")
    else:
        c.cover("promptfoo-redteam", "LLM01:2025", "pass")
    c.tools[-1]["exit_code"] = exit_code
    # 退出碼：與 eval 相同（100 = 有測試失敗；其他非零 = 工具錯誤或逾時，結果可能不完整）
    if exit_code not in (None, 0) and (exit_code != PF_FAILED_EXIT or not failed):
        why = f"promptfoo redteam 退出碼 {exit_code}" + ("，結果中沒有測試失敗（工具錯誤或結果不完整）" if not failed
                                                         else "（非測試失敗的退出碼，結果可能不完整）")
        c.cover("promptfoo-redteam", "LLM01:2025", "untested", why)
        c.reasons.append(why)
    # 設定要求的 plugin 必須都有結果：集合型 plugin（pii、harmful）展開成 pii:direct 等子 plugin，以前綴比對。
    # 以前只看「有沒有失敗」：生成階段漏掉某些 plugin（逾時、模型拒答、遠端生成被停用）時照樣 pass。
    expected = redteam_expected_plugins(config_path)
    if expected == []:
        why = f"無法讀取 redteam 設定的 plugin 清單（{config_path}），無法確認每個 plugin 都有測試"
        c.cover("promptfoo-redteam", "LLM01:2025", "untested", why)
        c.reasons.append(why)
    for plug in expected or []:
        if not any(s == plug or s.startswith(plug + ":") for s in seen):
            c.cover(f"promptfoo-redteam:{plug}", "LLM01:2025", "untested", f"redteam plugin {plug} 沒有任何測試結果")
    _miss = [p for p in expected or [] if f"promptfoo-redteam:{p}" in c.coverage]
    if _miss:
        c.reasons.append(f"redteam plugin 沒有測試結果：{', '.join(_miss)}")


COST_RULE, COST_CHECK = "vibesec.g6.denial-of-wallet", "denial_of_wallet"


def ingest_cost(c: Collector, path: str | None):
    """scripts/g6_cost_probe.py 的輸出 → denial_of_wallet_cost 覆蓋與 finding。缺席或無法解析 → untested。"""
    tool = gate_result.tool("vibesec-g6-cost-probe", "ran", output_ref=path)
    try:
        d = json.loads(pathlib.Path(path).read_text(encoding="utf-8")) if path else None
        state = d["state"]
        if state not in ("pass", "fail", "untested"):
            raise ValueError(state)
    except Exception as e:
        tool["state"] = "missing" if not path or not pathlib.Path(path).exists() else "error"
        c.tools.append(tool)
        why = f"成本探針沒有可解析的結果（{type(e).__name__}）"
        c.cover("denial_of_wallet_cost", "LLM10:2025", "untested", why)
        c.reasons.append(why)
        return
    c.tools.append(tool)
    reason = d.get("reason") or ""
    ctrl = c.control(COST_RULE, "LLM10:2025")
    if state == "fail":
        c.cover("denial_of_wallet_cost", ctrl, "fail", check=COST_CHECK)
        c.finding(COST_RULE, f"成本探針：{reason}"[:300], "g6-cost-probe")
    elif state == "untested":
        c.cover("denial_of_wallet_cost", ctrl, "untested", reason or "成本探針未能實測")
        c.reasons.append(f"成本探針未能實測：{reason}")
    else:
        c.cover("denial_of_wallet_cost", ctrl, "pass", check=COST_CHECK)


OBS_KEY = "excessive_agency_telemetry"


def ingest_observations(c: Collector, path: str | None):
    """scripts/g6_observe.py 的觀測檔 → excessive_agency_telemetry 覆蓋與 finding。
    以 scripts/llm_observations.py 從逐探針紀錄重新判定（不信任檔內已寫好的結論）；缺席或無法解析 → untested。"""
    import llm_observations as lo
    tool = gate_result.tool("vibesec-g6-observe", "ran", output_ref=path)
    ctrl = c.control(lo.RULE, lo.CONTROL)
    try:
        d = json.loads(pathlib.Path(path).read_text(encoding="utf-8")) if path else None
        if not isinstance(d, dict) or d.get("schema") != "vibesec-g6-observations/v1":
            raise ValueError("schema")
        res = lo.evaluate(d.get("probes"))
        if d.get("denied"):
            res = {**res, "state": "untested", "reason": str(d["denied"])[:200]}
    except Exception as e:
        tool["state"] = "missing" if not path or not pathlib.Path(path).exists() else "error"
        c.tools.append(tool)
        why = f"工具事件遙測沒有可解析的觀測檔（{type(e).__name__}）"
        c.cover(OBS_KEY, ctrl, "untested", why)
        c.reasons.append(why)
        return
    c.tools.append(tool)
    if res["state"] == "fail":
        c.cover(OBS_KEY, ctrl, "fail", check=lo.CHECK)
        c.finding(lo.RULE, f"工具事件遙測：{res['reason']}"[:300], "g6-observe")
    elif res["state"] == "pass":
        c.cover(OBS_KEY, ctrl, "pass", check=lo.CHECK)
    else:
        why = f"工具事件遙測未能實測：{res['reason']}"
        c.cover(OBS_KEY, ctrl, "untested", why)
        c.reasons.append(why)


def garak_abort_reason(log_path: str | None) -> str | None:
    """從 garak log 擷取中止原因：優先取最後一行例外（如 AssertionError: …），其次 ❌ 行；不回傳 Traceback 標頭。"""
    import re
    try:
        lines = pathlib.Path(log_path).read_text(encoding="utf-8", errors="replace").splitlines() if log_path else []
    except OSError:
        return None
    exc = [ln.strip() for ln in lines if re.match(r"^\s*[\w.]+(Error|Exception)\b", ln) and "Traceback" not in ln]
    if exc:
        return exc[-1][:200]
    for line in lines:
        if "❌" in line:
            return line.replace("❌", "").strip()[:200]
    return None


def garak_aborted(log_path: str | None) -> str | None:
    """已有報告時判斷 garak 是否中途中止：log 有 Traceback 或 ❌ 才算（重試中的連線錯誤等單行警告不算），回傳原因。"""
    try:
        text = pathlib.Path(log_path).read_text(encoding="utf-8", errors="replace") if log_path else ""
    except OSError:
        return None
    if "Traceback (most recent call last)" in text or "❌" in text:
        return garak_abort_reason(log_path) or "garak log 有未處理的例外"
    return None


def garak_expected_specs(config_path: str | None) -> list[str]:
    """讀 garak 設定的 run.spec.include：probes.dan → dan（家族）、probes.dan.Dan_11_0 → dan.Dan_11_0（指定 probe）。"""
    try:
        import yaml
        spec = ((yaml.safe_load(pathlib.Path(config_path).read_text(encoding="utf-8")) or {}).get("run") or {}).get("spec") or {}
    except Exception:
        return []
    inc = spec.get("include") or [] if isinstance(spec, dict) else []
    return [s.removeprefix("probes.") for s in inc if isinstance(s, str) and s.startswith("probes.") and len(s.split(".")) > 1]


def ingest_garak(c: Collector, pattern: str | None, log_path: str | None = None, config_path: str | None = None):
    if not pattern:
        why = "garak 沒有結果（未提供 --garak-glob）"
        c.tools.append(gate_result.tool("garak", "missing"))
        c.cover("garak", "LLM01:2025", "untested", why)
        c.reasons.append(why)
        return
    files = sorted(glob.glob(pattern))
    if not files:
        why = garak_abort_reason(log_path)
        c.tools.append(gate_result.tool("garak", "error" if why else "missing", output_ref=log_path if why else None))
        detail = f"garak 中止：{why}" if why else "garak 未產生報告（未安裝、無法連線靶場或執行失敗）"
        c.cover("garak", "LLM01:2025", "untested", detail)
        c.reasons.append(detail)
        return
    c.tools.append(gate_result.tool("garak", "ran", output_ref=files[0]))
    evals = 0
    seen_families: set[str] = set()
    seen_probes: set[str] = set()       # 有 eval 紀錄的 probe（dan.Dan_11_0）
    attempted: set[str] = set()         # 有 attempt 紀錄的 probe
    unfinished: list[str] = []          # 缺 completion 紀錄的報告
    for f in files:
        try:
            text = pathlib.Path(f).read_text(encoding="utf-8", errors="replace")
        except OSError as ex:
            why = f"garak 報告 {pathlib.Path(f).name} 無法讀取（{type(ex).__name__}）"
            c.cover(f"garak-report:{pathlib.Path(f).name}", "LLM01:2025", "untested", why)
            c.reasons.append(why)
            continue
        completed = False
        for line in text.splitlines():
            try:
                e = json.loads(line)
            except Exception:
                continue
            if not isinstance(e, dict):
                continue
            if e.get("entry_type") == "completion":
                completed = True
            elif e.get("entry_type") == "attempt" and e.get("probe_classname"):
                attempted.add(str(e["probe_classname"]).removeprefix("probes."))
            if e.get("entry_type") != "eval":
                continue
            evals += 1
            probe, det = str(e.get("probe") or "?"), str(e.get("detector") or "?")
            seen_families.add(probe.split(".")[0])
            seen_probes.add(probe)
            rule = GARAK_RULES.get(probe.split(".")[0], f"garak:{probe}.{det}")
            ctrl = c.control(rule, "LLM01:2025")
            check = rule.removeprefix("vibesec.g6.").replace("-", "_") if rule.startswith("vibesec.g6.") else None
            # garak ≥ 0.17：total_evaluated / fails；舊版：total（fails = total - passed）
            try:
                total = int(e.get("total_evaluated", e.get("total")) or 0)
                passed = int(e.get("passed") or 0)
                fails = int(e["fails"]) if e.get("fails") is not None else max(total - passed, 0)
            except (TypeError, ValueError):
                c.cover(f"garak:{probe}", ctrl, "untested", f"{probe} / {det} 的計數欄位不是數字，無法判定")
                c.reasons.append(f"garak {probe} 計數欄位無法解析")
                continue
            if not total:
                c.cover(f"garak:{probe}", ctrl, "untested", f"{probe} / {det} 沒有可評估的輸出")
            elif fails:
                c.cover(f"garak:{probe}", ctrl, "fail", check=check)
                c.finding(rule, f"garak：{probe} / {det} 命中 {fails}/{total}", "garak")
            else:
                c.cover(f"garak:{probe}", ctrl, "pass", check=check)
        if not completed:
            unfinished.append(pathlib.Path(f).name)
    why = garak_aborted(log_path)
    suffix = f"（中止：{why}）" if why else ""
    # 執行完整性（garak 0.17：每次執行結束寫一筆 completion；中途崩潰或逾時就沒有）→ 整層 untested
    if unfinished or why:
        detail = (f"garak 報告缺 completion 紀錄（執行未正常結束）：{', '.join(unfinished)}" if unfinished
                  else "garak log 顯示執行中止") + suffix
        c.cover("garak", "LLM01:2025", "untested", detail)
        c.reasons.append(detail)
    # probe 層級：送出攻擊卻沒有評估結果（detector 失敗、中途結束）→ 該 probe untested
    for probe in sorted(attempted - seen_probes):
        rule = GARAK_RULES.get(probe.split(".")[0], f"garak:{probe}")
        c.cover(f"garak:{probe}", c.control(rule, "LLM01:2025"), "untested", f"garak {probe} 有送出攻擊但沒有評估結果{suffix}")
    if attempted - seen_probes:
        c.reasons.append(f"garak probe 沒有評估結果：{', '.join(sorted(attempted - seen_probes))}")
    if not evals:
        c.cover("garak", "LLM01:2025", "untested", f"garak 報告中沒有 eval 紀錄{suffix}")
        c.reasons.append(f"garak 報告中沒有 eval 紀錄{suffix}")
        return
    # 設定中要求、但報告裡沒有任何 eval 的 probe 家族（逾時或中途崩潰）→ untested，不得默認為 pass
    missing = [sp for sp in garak_expected_specs(config_path)
               if not any(p == sp or p.startswith(sp + ".") for p in seen_probes)]
    for fam in missing:
        rule = GARAK_RULES.get(fam.split(".")[0], f"garak:{fam}")
        c.cover(f"garak:{fam}", c.control(rule, "LLM01:2025"), "untested", f"garak 未完成 {fam}{suffix}")
    if missing:
        c.reasons.append(f"garak 未完成：{', '.join(missing)}{suffix}")


def check_rule(check: str) -> str:
    """vibesec.yaml 的 check 名稱 → 規則 ID（vibesec.g6.<kebab>）。"""
    return "vibesec.g6." + check.replace("_", "-")


def declared_checks() -> list[str] | None:
    """vibesec.yaml gates.g6_ai_red_team.checks；讀不到 → None（呼叫端記 untested）。"""
    try:
        import yaml
        g6 = ((yaml.safe_load((ROOT / "vibesec.yaml").read_text(encoding="utf-8")) or {}).get("gates") or {}).get("g6_ai_red_team") or {}
        checks = g6.get("checks")
        return [str(x) for x in checks] if isinstance(checks, list) else None
    except Exception:
        return None


def require_checks(c: Collector, checks: list[str] | None):
    """宣告的 check 沒有任何 pass／fail 實測結果 → untested（不得因為沒測到就算通過）。"""
    if checks is None:
        why = "無法讀取 vibesec.yaml gates.g6_ai_red_team.checks，無法確認宣告的檢查都已實測"
        c.cover("declared_checks", "LLM01:2025", "untested", why)
        c.reasons.append(why)
        return
    missing = [ck for ck in checks if ck not in c.tested]
    for ck in missing:
        rule = check_rule(ck)
        prev = c.coverage.get(ck)
        why = (prev or {}).get("reason") or "vibesec.yaml 宣告的 check 沒有任何實測結果"
        c.cover(ck, (prev or {}).get("control_id") or c.control(rule, "LLM01:2025"), "untested", why)
    if missing:
        c.reasons.append(f"宣告的 check 未實測：{', '.join(missing)}")


def build(c: Collector, mode: str, started: str) -> tuple[dict, dict]:
    blocking = sum(1 for r in c.results if r["properties"]["policy_tier"] == "blocking")
    advisory = len(c.results) - blocking
    cov = list(c.coverage.values())
    # 狀態由 gate_verdict.verdict 判定：fail 只代表有 blocking 發現（以前只有 advisory 的 coverage fail 也記 fail，
    # 與其他閘門不一致，staging 判定也不擋）；untested 的控制或沒有任何結果 → incomplete。
    # c.reasons 中已寫在 coverage reason 的不重複列入
    from gate_verdict import verdict
    in_cov = {x.get("reason") for x in cov}
    problems = [r for r in dict.fromkeys(c.reasons) if r not in in_cov] + ([] if cov else ["沒有可用的 G6 結果"])
    status, reason = verdict(blocking=blocking, coverage=cov, problems=problems)
    gate = {"gate": "G6", "status": status, "status_reason": reason, "mode": mode, "scope": "full",
            "diff_base": None, "commit": None, "started_at": started, "finished_at": now(),
            "tools": c.tools, "findings_count": {"blocking": blocking, "advisory": advisory},
            "coverage": cov}
    sarif = gate_result.sarif({"name": TOOL_NAME, "version": TOOL_VERSION}, list(c.rules.values()), c.results)
    return gate, sarif


def selftest() -> list[str]:
    import contextlib, io, tempfile
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as d:
        dp = pathlib.Path(d)
        row = lambda ck, ok=True: {"success": ok, "failureReason": 0 if ok else PF_ASSERT, "testCase": {"description": ck,
            "metadata": {"vibesec_check": ck, "vibesec_rule_id": check_rule(ck)}}}
        all_checks = declared_checks() or []
        ok_rows = [row(ck) for ck in all_checks]
        (dp / "eval.json").write_text(json.dumps({"results": {"results": ok_rows}}), encoding="utf-8")
        (dp / "red.json").write_text(json.dumps({"results": {"results": [{"success": True}]}}), encoding="utf-8")
        garak_lines = lambda *extra, done=True: "".join(json.dumps(x) + "\n" for x in (
            {"entry_type": "attempt", "probe_classname": "dan.Dan_11_0", "status": 2},
            {"entry_type": "eval", "probe": "dan.Dan_11_0", "detector": "dan.DAN", "total_evaluated": 5, "fails": 0},
            *extra, *([{"entry_type": "completion", "run": "r"}] if done else [])))
        (dp / "g6-garak.report.jsonl").write_text(garak_lines(), encoding="utf-8")

        obs_probe = lambda events, status=200: {"schema": "vibesec-g6-observations/v1", "denied": None, "probes": [
            {"id": "agency", "tools_offered": ["delete_customers"], "http_status": status, "tool_events": events,
             "usage": {"input_tokens": 4, "output_tokens": 6, "total_tokens": 10}}]}
        obs_ok = obs_probe([{"tool": "delete_customers", "executed": False, "human_approved": False}])

        def run(cost: dict | None, extra: list[str] | None = None, base: list[str] | None = None,
                obs: dict | str | None = obs_ok) -> dict:
            args = (["--eval", str(dp / "eval.json"), "--redteam", str(dp / "red.json"),
                     "--garak-glob", str(dp / "g6-garak*.report.jsonl")] if base is None else base) + ["--gate", str(dp / "gate.json"), "--mode", "shadow"]
            if cost is not None:
                (dp / "cost.json").write_text(json.dumps(cost), encoding="utf-8")
                args += ["--cost", str(dp / "cost.json")]
            if obs is not None:
                (dp / "obs.json").write_text(obs if isinstance(obs, str) else json.dumps(obs), encoding="utf-8")
                args += ["--observations", str(dp / "obs.json")]
            import contextlib, io
            with contextlib.redirect_stdout(io.StringIO()):
                main(args + (extra or []))
            return json.loads((dp / "gate.json").read_text(encoding="utf-8"))

        g = run({"state": "pass", "reason": "HTTP 413"})
        if g["status"] != "pass":
            fails.append(f"各層皆通過且成本探針 pass → G6 應為 pass，實際 {g['status']}（{g['status_reason']}）")
        # 自產 SARIF：gate_result 的骨架（$schema 排第一、driver 帶 version，#184）
        import contextlib as _cl, io as _io
        with _cl.redirect_stdout(_io.StringIO()):
            main(["--eval", str(dp / "eval.json"), "--redteam", str(dp / "red.json"), "--garak-glob", str(dp / "g6-garak*.report.jsonl"),
                  "--gate", str(dp / "gate-s.json"), "--sarif", str(dp / "g6.sarif"), "--mode", "shadow"])
        doc = json.loads((dp / "g6.sarif").read_text(encoding="utf-8"))
        drv = doc["runs"][0]["tool"]["driver"]
        if list(doc)[:2] != ["$schema", "version"] or drv.get("name") != TOOL_NAME or drv.get("version") != TOOL_VERSION:
            fails.append(f"G6 SARIF 應為 gate_result 的骨架：$schema 第一、driver 有 name／version（得到 {list(doc)}、{drv.get('name')}、{drv.get('version')}）")
        g = run({"state": "fail", "reason": "接受超長輸入"})
        cov = [x for x in g["coverage"] if x["control_id"] == "LLM10:2025"]
        # denial-of-wallet 為 advisory：控制 fail、計入 advisory；閘門狀態依 gate_verdict 只在有 blocking 時 fail
        want = "fail" if g["findings_count"]["blocking"] else "pass"
        if g["status"] != want or not any(x["state"] == "fail" for x in cov) or not (g["findings_count"]["advisory"] + g["findings_count"]["blocking"]):
            fails.append(f"成本探針 fail → 覆蓋 fail、發現照實計入、閘門 {want}；實際 {g['status']} {cov} {g['findings_count']}")
        if g["findings_count"]["advisory"] + g["findings_count"]["blocking"] != 1:
            fails.append(f"成本探針 fail 應產生 1 個 finding：{g['findings_count']}")
        g = run(None)
        if g["status"] != "incomplete" or "成本探針" not in (g["status_reason"] or ""):
            fails.append(f"未提供 --cost → incomplete；實際 {g['status']}（{g['status_reason']}）")
        # 工具事件遙測：未核准的高影響工具 → fail；缺席／格式錯誤／目標無 tool_events → untested
        cost_pass = {"state": "pass", "reason": "HTTP 413"}
        g = run(cost_pass, obs=obs_probe([{"tool": "delete_customers", "executed": True, "human_approved": False}]))
        cov = [x for x in g["coverage"] if x["control_id"] == "LLM06:2025" and x["state"] == "fail"]
        want = "fail" if g["findings_count"]["blocking"] else "pass"   # excessive-agency 的 tier 由政策決定
        if g["status"] != want or not cov or g["findings_count"]["advisory"] + g["findings_count"]["blocking"] != 1:
            fails.append(f"高影響工具未核准即執行 → 控制 fail、1 個 finding、閘門 {want}；實際 {g['status']} {g['findings_count']}")
        for name, obs in (("未提供 --observations", None), ("觀測檔不是 JSON", "{oops"),
                          ("目標沒有 tool_events", obs_probe(None)), ("探針 HTTP 500", obs_probe([], status=500)),
                          ("目標被拒", {**obs_ok, "denied": "目標未通過授權檢查"}), ("schema 不符", {"probes": []})):
            g = run(cost_pass, obs=obs)
            if g["status"] != "incomplete" or "工具事件遙測" not in (g["status_reason"] or ""):
                fails.append(f"{name} → incomplete 並寫明工具事件遙測；實際 {g['status']}（{g['status_reason']}）")
        g = run({"state": "untested", "reason": "HTTP 500"})
        if g["status"] != "incomplete":
            fails.append(f"成本探針 untested → incomplete；實際 {g['status']}")
        g = run({"oops": 1})
        if g["status"] != "incomplete":
            fails.append(f"成本結果格式錯誤 → incomplete；實際 {g['status']}")
        if len(all_checks) != 5:
            fails.append(f"vibesec.yaml gates.g6_ai_red_team.checks 應可讀出 5 個 check：{all_checks}")
        cost_ok = {"state": "pass", "reason": "HTTP 413"}
        ev, red, gk = (["--eval", str(dp / "eval.json")], ["--redteam", str(dp / "red.json")],
                       ["--garak-glob", str(dp / "g6-garak*.report.jsonl")])
        # 空的 promptfoo 結果不算覆蓋
        (dp / "empty.json").write_text(json.dumps({"results": {"results": []}}), encoding="utf-8")
        g = run(cost_ok, base=["--eval", str(dp / "empty.json")] + red + gk)
        if g["status"] != "incomplete" or "空結果" not in (g["status_reason"] or ""):
            fails.append(f"promptfoo 空結果 → incomplete；實際 {g['status']}（{g['status_reason']}）")
        # 缺 --redteam／--redteam-skipped、缺 --garak-glob → 該層 untested，不得默默略過
        g = run(cost_ok, base=ev + gk)
        if g["status"] != "incomplete" or "redteam" not in (g["status_reason"] or ""):
            fails.append(f"未提供 redteam 結果 → incomplete；實際 {g['status']}（{g['status_reason']}）")
        g = run(cost_ok, base=ev + red)
        if g["status"] != "incomplete" or "garak" not in (g["status_reason"] or ""):
            fails.append(f"未提供 --garak-glob → incomplete；實際 {g['status']}（{g['status_reason']}）")
        (dp / "red-empty.json").write_text(json.dumps({"results": {"results": []}}), encoding="utf-8")
        g = run(cost_ok, base=ev + ["--redteam", str(dp / "red-empty.json")] + gk)
        if g["status"] != "incomplete":
            fails.append(f"redteam 空結果 → incomplete；實際 {g['status']}")
        # 宣告的 check 沒有實測結果 → untested
        (dp / "partial.json").write_text(json.dumps({"results": {"results": ok_rows[:1]}}), encoding="utf-8")
        g = run(cost_ok, base=["--eval", str(dp / "partial.json")] + red + gk)
        miss = [x for x in g["coverage"] if x["state"] == "untested" and "宣告" in (x["reason"] or "")]
        if g["status"] != "incomplete" or not miss:
            fails.append(f"宣告的 check 未實測 → untested、閘門 incomplete；實際 {g['status']} {miss}")
        # 退出碼：非零且沒有斷言失敗 → incomplete；100 且有斷言失敗 → fail（不得改寫成 incomplete）
        g = run(cost_ok, ["--eval-exit-code", "1"])
        if g["status"] != "incomplete" or "退出碼 1" not in (g["status_reason"] or ""):
            fails.append(f"promptfoo 退出碼 1、全部通過 → incomplete；實際 {g['status']}（{g['status_reason']}）")
        g = run(cost_ok, ["--eval-exit-code", "100"])
        if g["status"] != "incomplete":
            fails.append(f"promptfoo 退出碼 100 但沒有斷言失敗 → incomplete；實際 {g['status']}")
        g = run(cost_ok, ["--eval-exit-code", "0"])
        if g["status"] != "pass":
            fails.append(f"promptfoo 退出碼 0、全部通過 → pass；實際 {g['status']}（{g['status_reason']}）")
        (dp / "evfail.json").write_text(json.dumps({"results": {"results": ok_rows[:-1] + [row("stored_xss_via_ai_output", False)]}}),
                                        encoding="utf-8")
        g = run(cost_ok, ["--eval-exit-code", "100"], base=["--eval", str(dp / "evfail.json")] + red + gk)
        if g["status"] != "fail":
            fails.append(f"promptfoo 退出碼 100 且有斷言失敗 → fail；實際 {g['status']}（{g['status_reason']}）")
        # garak：計數非數字、報告無法讀取 → untested，不得 traceback
        (dp / "g6-garak-bad.report.jsonl").write_text(json.dumps({"entry_type": "eval", "probe": "dan.Dan_11_0",
            "detector": "dan.DAN", "total_evaluated": "n/a", "fails": 0}) + "\n", encoding="utf-8")
        try:
            g = run(cost_ok, base=ev + red + ["--garak-glob", str(dp / "g6-garak-bad.report.jsonl")])
            if g["status"] != "incomplete" or "計數" not in (g["status_reason"] or ""):
                fails.append(f"garak 計數非數字 → incomplete；實際 {g['status']}（{g['status_reason']}）")
        except Exception as e:
            fails.append(f"garak 計數非數字不得丟出例外：{type(e).__name__}")
        (dp / "g6-garak-dir.report.jsonl").mkdir()
        try:
            g = run(cost_ok, base=ev + red + ["--garak-glob", str(dp / "g6-garak-dir.report.jsonl")])
            if g["status"] != "incomplete" or "無法讀取" not in (g["status_reason"] or ""):
                fails.append(f"garak 報告無法讀取 → incomplete；實際 {g['status']}（{g['status_reason']}）")
        except Exception as e:
            fails.append(f"garak 報告 OSError 不得丟出例外：{type(e).__name__}")
        # garak 完整性：缺 completion（中途結束）、有 attempt 沒有 eval 的 probe、log 有 Traceback → incomplete
        for name, text, log in (("缺 completion", garak_lines(done=False), None),
                                ("probe 只有 attempt", garak_lines({"entry_type": "attempt", "probe_classname": "encoding.InjectBase64"}), None),
                                ("log 有 Traceback", garak_lines(), "Traceback (most recent call last):\nAssertionError: boom\n")):
            (dp / "gk").mkdir(exist_ok=True)
            (dp / "gk/g6-garak.report.jsonl").write_text(text, encoding="utf-8")
            extra = []
            if log:
                (dp / "gk.log").write_text(log, encoding="utf-8"); extra = ["--garak-log", str(dp / "gk.log")]
            g = run(cost_ok, extra, base=ev + red + ["--garak-glob", str(dp / "gk/g6-garak*.report.jsonl")])
            if g["status"] != "incomplete" or "garak" not in (g["status_reason"] or ""):
                fails.append(f"garak {name} → incomplete；實際 {g['status']}（{g['status_reason']}）")
        # 以下用乾淨的目錄（前面的案例在 dp 放了壞掉的 garak 報告，會被預設 glob 收進來）
        (dp / "ok").mkdir(exist_ok=True)
        (dp / "ok/g6-garak.report.jsonl").write_text(garak_lines(), encoding="utf-8")
        gk = ["--garak-glob", str(dp / "ok/g6-garak*.report.jsonl")]
        # 設定指名的 probe（probes.dan.Dan_11_0 有結果、probes.encoding 家族沒有）→ 缺的那個 untested
        (dp / "garak.yaml").write_text("run:\n  spec:\n    include: [probes.dan.Dan_11_0, probes.encoding]\n", encoding="utf-8")
        g = run(cost_ok, ["--garak-config", str(dp / "garak.yaml")], base=ev + red + gk)
        if g["status"] != "incomplete" or "encoding" not in (g["status_reason"] or "") or "Dan_11_0" in (g["status_reason"] or ""):
            fails.append(f"garak 設定指名但無結果的 probe → incomplete（只列缺的）；實際 {g['status']}（{g['status_reason']}）")
        # promptfoo redteam：設定要求的 plugin 沒有結果、退出碼異常 → incomplete；集合型 plugin 以前綴比對
        (dp / "pf.yaml").write_text("redteam:\n  plugins:\n    - pii\n    - id: bola\n", encoding="utf-8")
        prow = lambda plug, ok=True: {"success": ok, "failureReason": 0 if ok else PF_ASSERT, "testCase": {"metadata": {"pluginId": plug}}}
        (dp / "red2.json").write_text(json.dumps({"results": {"results": [prow("pii:direct"), prow("bola")]}}), encoding="utf-8")
        red2 = ["--redteam", str(dp / "red2.json"), "--redteam-config", str(dp / "pf.yaml")]
        g = run(cost_ok, base=ev + red2 + gk)
        if g["status"] != "pass":
            fails.append(f"redteam 每個 plugin 都有結果（pii 以 pii:direct 涵蓋）→ pass；實際 {g['status']}（{g['status_reason']}）")
        (dp / "red3.json").write_text(json.dumps({"results": {"results": [prow("pii:direct")]}}), encoding="utf-8")
        g = run(cost_ok, base=ev + ["--redteam", str(dp / "red3.json"), "--redteam-config", str(dp / "pf.yaml")] + gk)
        if g["status"] != "incomplete" or "bola" not in (g["status_reason"] or ""):
            fails.append(f"redteam plugin bola 沒有結果 → incomplete；實際 {g['status']}（{g['status_reason']}）")
        for code, want in (("1", "incomplete"), ("124", "incomplete"), ("100", "incomplete"), ("0", "pass")):
            g = run(cost_ok, ["--redteam-exit-code", code], base=ev + red2 + gk)
            if g["status"] != want:
                fails.append(f"redteam 退出碼 {code}（全部通過）→ {want}；實際 {g['status']}（{g['status_reason']}）")
        g = run({"state": "pass"}, ["--target-denied", "example.com 不在允許清單"])
        if g["status"] != "incomplete" or "授權" not in (g["status_reason"] or "") or g["tools"]:
            fails.append(f"--target-denied → incomplete 且不讀任何結果；實際 {g['status']} tools={g['tools']}")
        # mode 取自受信任政策（#202，ADR 0002）：--mode 已不使用、傳了也忽略（以前必填，#161；#199 第二階段移除）。
        # 一般路徑與 --target-denied 都一樣：沒帶、帶 shadow、帶不合法的值，閘門結果都記政策的 mode（enforce）
        from vibesec_policy import POLICY_UNREADABLE, mode_policy_root, modeless_policy_root

        def run_with(pr, extra):
            (dp / "gate.json").unlink(missing_ok=True)
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    rc = main(ev + red2 + gk + ["--gate", str(dp / "gate.json")] + extra, policy_root=pr)
                return rc, json.loads((dp / "gate.json").read_text(encoding="utf-8"))
            except SystemExit as e:
                return f"SystemExit {e.code}", {}
        with mode_policy_root("mode: enforce") as pr:
            for path_extra in ([], ["--target-denied", "x"]):
                for cli in ([], ["--mode", "shadow"], ["--mode", "x"]):
                    rc, g = run_with(pr, path_extra + cli)
                    if rc != 0 or g.get("mode") != "enforce":
                        fails.append(f"--mode {cli[1:] or '未帶'}{'（--target-denied）' if path_extra else ''} → 忽略、照常寫出結果、"
                                     f"mode 取自政策（enforce）（得到 {rc}、mode={g.get('mode')}）")
        # 反方向：政策 shadow、--mode enforce → 記 shadow（寫死成 enforce 會被抓到）
        with mode_policy_root("mode: shadow") as pr:
            for path_extra in ([], ["--target-denied", "x"]):
                rc, g = run_with(pr, path_extra + ["--mode", "enforce"])
                if rc != 0 or g.get("mode") != "shadow":
                    fails.append(f"政策 shadow、--mode enforce{'（--target-denied）' if path_extra else ''} → mode 記 shadow"
                                 f"（得到 {rc}、mode={g.get('mode')}）")
        # 受信任政策缺 mode → 政策讀不到：incomplete、mode 記 enforce（mode 不明）、寫明原因；--target-denied 也一樣
        with modeless_policy_root() as pr:
            for path_extra in ([], ["--target-denied", "x"]):
                rc, g = run_with(pr, path_extra + ["--mode", "shadow"])
                why = g.get("status_reason") or ""
                if rc != 0 or g.get("status") != "incomplete" or g.get("mode") != "enforce" \
                        or POLICY_UNREADABLE + "（" not in why or "mode" not in why:
                    fails.append(f"受信任政策缺 mode{'（--target-denied）' if path_extra else ''} → incomplete、mode 記 enforce、"
                                 f"寫明原因（得到 {rc}、{g.get('status')}、mode={g.get('mode')}：{why}）")
    schema = __import__("jsonschema").Draft202012Validator(
        json.loads((ROOT / "schemas/gate-result.schema.json").read_text(encoding="utf-8")))
    # 政策檔讀不到 → 進入點就停：不讀任何結果、G6 incomplete 並寫明未完成原因、沒有任何發現
    # （以前在 import 時就建立 Policy：讀不到時整支無法執行，連 selftest 都跑不起來）
    from vibesec_policy import POLICY_UNREADABLE, broken_policy_root
    import gate_result
    with broken_policy_root() as pr, tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
        gp, sp = pathlib.Path(d, "G6.json"), pathlib.Path(d, "G6.sarif")
        sp.write_text('{"stale": true}', encoding="utf-8")   # 上一次留下的 SARIF
        rc = main(["--gate", str(gp), "--sarif", str(sp), "--mode", "shadow"], policy_root=pr)
        g = json.loads(gp.read_text(encoding="utf-8"))
        stale = sp.exists()
    # 接線（#184 決定 2）：coverage 是 vibesec.yaml 宣告的 5 個 check（untested、原因＝政策讀不到；control_id 取自 catalog）、
    # tool 列只有 G6 自己的一列 error、舊 SARIF 刪掉（以前寫空檔）
    declared = declared_checks() or []
    ids = [(c["control_id"], c["state"], (c["reason"] or "").startswith(POLICY_UNREADABLE)) for c in g["coverage"]]
    want = [(Collector(*load_catalog()).control(check_rule(ck), "LLM01:2025"), "untested", True) for ck in declared]
    if rc != 0 or g["status"] != "incomplete" or POLICY_UNREADABLE + "（" not in (g["status_reason"] or "") \
            or g["findings_count"] != {"blocking": 0, "advisory": 0} or not declared or ids != want \
            or g["tools"] != [gate_result.tool(TOOL_NAME, "error", version=TOOL_VERSION)] or stale \
            or list(schema.iter_errors(g)):
        fails.append(f"政策檔讀不到 → G6 incomplete、寫明原因、沒有發現、宣告的 check 全部 untested、tool 列只有一列 error、"
                     f"舊 SARIF 刪掉（得到 {rc}、SARIF 存在：{stale}、{g}）")
    # --target-denied：沒有讀任何結果 → 舊 SARIF 刪掉、不寫新檔（#184 決定 3；tools 維持 []）
    with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
        gp, sp = pathlib.Path(d, "G6.json"), pathlib.Path(d, "G6.sarif")
        sp.write_text('{"stale": true}', encoding="utf-8")
        main(["--target-denied", "example.com 不在允許清單", "--gate", str(gp), "--sarif", str(sp), "--mode", "shadow"])
        g = json.loads(gp.read_text(encoding="utf-8"))
        if g["status"] != "incomplete" or g["tools"] or sp.exists():
            fails.append(f"--target-denied → incomplete、tools 為 []、舊 SARIF 刪掉（得到 {g['status']}、{g['tools']}、SARIF 存在：{sp.exists()}）")
    return fails


def main(argv=None, policy_root: pathlib.Path = ROOT) -> int:
    """policy_root：阻擋政策所在的 repo（selftest 指向壞政策檔）。"""
    if argv is None:
        argv = sys.argv[1:]
    if argv[:1] == ["selftest"]:
        fails = selftest()
        for f in fails: print(f"FAIL {f}")
        print("selftest " + ("通過" if not fails else f"失敗 {len(fails)} 項"))
        return 1 if fails else 0
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--eval", dest="eval_path")
    ap.add_argument("--eval-exit-code", type=int)
    ap.add_argument("--redteam")
    ap.add_argument("--redteam-skipped")
    ap.add_argument("--redteam-exit-code", type=int)
    ap.add_argument("--redteam-config", help="promptfoo redteam 設定檔；比對 redteam.plugins 中要求但沒有結果的 plugin")
    ap.add_argument("--garak-glob")
    ap.add_argument("--garak-log", help="garak stdout/stderr；無報告時擷取中止原因")
    ap.add_argument("--garak-config", help="garak 設定檔；比對 run.spec 中要求但未完成的 probe 家族")
    ap.add_argument("--gate", required=True)
    ap.add_argument("--sarif")
    ap.add_argument("--cost", help="scripts/g6_cost_probe.py 的輸出（denial_of_wallet_cost）")
    ap.add_argument("--observations", help="scripts/g6_observe.py 的觀測檔（excessive_agency_telemetry）")
    ap.add_argument("--target-denied", help="目標未通過 scripts/target_guard.py 的原因：不讀任何結果，閘門 incomplete")
    ap.add_argument("--mode", help="已不使用、傳了也忽略：mode 取自受信任政策（ADR 0002），將在 #199 的第二階段移除")
    a = ap.parse_args(argv)
    started = now()
    policy, problem = load_policy(policy_root)   # 只建立一次；讀不到 → 不讀任何結果、閘門 incomplete
    c = Collector(*load_catalog(), policy=policy)
    if problem:
        # 政策讀不到（#184 決定 2）：vibesec.yaml 宣告的 check 全部 untested（原因＝problem，control_id 取自 catalog）、
        # tool 列只有 G6 自己的一列 error；宣告讀不到時與 require_checks 相同，記一列 declared_checks
        declared = declared_checks()
        if declared is None:
            c.cover("declared_checks", "LLM01:2025", "untested", problem)
        for ck in declared or []:
            c.cover(ck, c.control(check_rule(ck), "LLM01:2025"), "untested", problem)
        c.tools.append(gate_result.tool(TOOL_NAME, "error", version=TOOL_VERSION))
        c.reasons.append(problem)
    elif a.target_denied:
        why = f"目標未通過授權檢查：{a.target_denied}"
        c.cover("target_authorization", "LLM01:2025", "untested", why)
        c.reasons.append(why)
    else:
        ingest_promptfoo_eval(c, a.eval_path, a.eval_exit_code)
        ingest_promptfoo_redteam(c, a.redteam, a.redteam_skipped, a.redteam_exit_code, a.redteam_config)
        ingest_garak(c, a.garak_glob, a.garak_log, a.garak_config)
        ingest_cost(c, a.cost)
        ingest_observations(c, a.observations)
        require_checks(c, declared_checks())
    # mode 取自受信任政策（#202；以前取必填的 --mode，#161）。政策讀不到（含 mode 缺席或不合法）→ mode 不明，記 enforce
    gate, sarif = build(c, effective_mode(policy), started)
    pathlib.Path(a.gate).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(a.gate).write_text(json.dumps(gate, ensure_ascii=False, indent=2), encoding="utf-8")
    if a.sarif:
        if problem or a.target_denied:
            # 沒有讀任何結果：刪掉上一次的 SARIF、不寫新檔（以前寫空檔，看起來像「測過、沒有發現」；上傳步驟以 hashFiles 略過，#184）
            gate_result.remove_stale(a.sarif)
        else:
            pathlib.Path(a.sarif).write_text(json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"G6: status={gate['status']} blocking={gate['findings_count']['blocking']} "
          f"advisory={gate['findings_count']['advisory']}" + (f" reason={gate['status_reason']}" if gate["status_reason"] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
