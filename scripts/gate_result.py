#!/usr/bin/env python3
"""VibeSec 閘門結果（gate result）module：閘門結果、檢查執行、tool 列、自產 SARIF 骨架與時間戳的唯一一份寫法
（GLOSSARY.md「閘門執行」「檢查執行」）。

以前每道閘門各自手刻 gate JSON 的外層欄位、tool 列與 SARIF 骨架，「政策讀不到」也有約 10 種輸出形狀（#179）。
現在閘門先宣告自己的控制清單，再逐步累積 tool 列、控制覆蓋、發現計數與未完成原因，最後由本 module 產出閘門結果；
閘門狀態一律由 gate_verdict.verdict 決定（本 module 不判定狀態）。

公開入口（interface）：
  GateRun(gate, *, controls, deferred=(), mode, scope, commit=None, diff_base=None, risk_tier=None, started_at=None)
      一次閘門執行。建立時記下 started_at（或沿用呼叫端給的值）。
      .tool(name, state, …)          累積一列 tool（同 tool()）
      .cover(control_id, state, reason=None)
      .count(blocking=0, advisory=0)  累加發現計數
      .problem(text) / .note(text) / .awaiting_human(text) / .not_applicable(reason)   原樣轉給 verdict
      .fail_condition()               不是發現、卻讓閘門 fail（verdict 的 blocking +1，不計入 findings_count；G0 用）
      .awaiting_blocking(ids)         待裁決的 blocking 發現（GLOSSARY.md）：計入 findings_count.blocking、依呼叫順序加進待人工裁決，
                                      不計入 verdict 的 blocking（模型意見不能自行確認，docs/09 §5；G4 用）。與 fail_condition 相反
      .result() -> dict               記下 finished_at、套用控制覆蓋不變式、呼叫 verdict，回傳閘門結果
      .unreadable(problem, *, tool_name, version=None) -> dict
                                      政策讀不到：controls 全部 untested（原因＝problem）、deferred 維持 pending、
                                      只有閘門自己的一列 tool（error）；不使用已累積的內容
  CheckRun(*, label, tool_name, version, check, findings, to_sarif, gate=None, control=None,
           unreadable=None, report=None, notes=None)
      一次檢查執行（GLOSSARY.md「檢查執行」）；producer 提供的函式見 class docstring。
      .execute(*, policy_root, sarif_path, json_path, merge_gate=None) -> int
                                      讀政策（讀不到 → incomplete）、寫摘要 JSON、SARIF 寫出或刪掉舊檔（incomplete）、
                                      選用的併入（控制須列在 gate_verdict.REQUIRED_CONTROLS，否則 ValueError）、
                                      回傳退出碼：incomplete 2、有 blocking 發現 1、其他 0
  tool(name, state, *, version=None, exit_code=None, output_ref=None, duration_seconds=None) -> dict
  sarif(driver, rules, results) -> dict      自產 SARIF 2.1.0 文件骨架；rules、results 照原樣放入
  remove_stale(path) -> bool                 刪掉過期的自產 SARIF（incomplete 一律用：政策讀不到、G1 sbom／kev／
                                             maintenance／provenance 的 incomplete；部分發現只留在摘要 JSON，#243）；檔案不存在不出錯
  now() -> str                               UTC、精度到秒、+00:00
  finding(*, gate, rule_id, title, evidence_grade, policy_tier, sources, location=None, commit=None, created_at=None, …)
                                             完整的發現（schemas/finding.schema.json）與決定性的發現 ID（GLOSSARY.md「發現 ID」）：
                                             VS-<created_at 的 UTC 日期>-<sha256(rule_id ␀ path ␀ start_line ␀ commit)[:8]>，
                                             ␀ 是 NUL、null 編成空字串；control_id／cwe／cve 不在 config/catalogs/ → ValueError
  known_controls() / known_cwes() / known_cves() -> set[str]   config/catalogs/ 內的控制 ID、CWE、CVE

控制覆蓋不變式：宣告在 controls、卻沒有 cover 的控制，result() 時補成 untested（原因：未執行）；宣告在 deferred、
卻沒有 cover 的控制補成 pending。漏回報只會讓閘門變嚴，不可能變成 pass。cover 未宣告的控制 → ValueError。

mode：result() 只接受 shadow／enforce，不合法 → ValueError；unreadable() 遇到不合法的 mode 記為 enforce、不拋例外
（使用者 2026-10-14 決定，#180：拋例外會讓閘門結果缺席，與「讀不到 → 更嚴」的既有語意不同）。
risk_tier 同理：result() 不合法 → ValueError；unreadable() 遇到不合法的值省略該欄位（#181；risk_tier 打錯時
load_policy 本來就回報政策讀不到）。

只回傳 dict，不寫閘門 JSON，也不在執行時跑 jsonschema（finding CLI 例外）（jsonschema 在部分環境可能缺席）；輸入不合法 → ValueError，
那是閘門程式的 bug。schema 符合性由本檔的 selftest 以 jsonschema 驗證。

  python3 scripts/gate_result.py selftest
  python3 scripts/gate_result.py finding < 部分欄位.json > 發現.json
      harness 組裝發現用（不參與阻擋判定）：輸出以 jsonschema 驗證；輸入不合法或缺 jsonschema → exit 2、stderr 寫明原因
"""
from __future__ import annotations
import datetime, hashlib, pathlib, re, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from gate_verdict import COVERAGE_STATES, verdict  # noqa: E402  狀態判定與覆蓋 state 的唯一來源
from vibesec_mode import MODES  # noqa: E402  mode 的合法值只有一份（#200）

GATES = ("G0", "G1", "G2", "G3", "G4", "G5", "G6")
SCOPES = ("diff", "full")
RISK_TIERS = ("L1", "L2", "L3")
TOOL_STATES = ("ran", "missing", "timeout", "error")
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
NOT_RUN = "未執行"
# 待裁決的 blocking 發現在待人工裁決裡的開頭（GateRun.awaiting_blocking；措辭沿用 G4 組裝，#213 改由這裡產出）
AWAITING_BLOCKING_PREFIX = "blocking 發現尚未裁決（模型意見不能自行確認，docs/09 §5）："


INFORMATION_URI = "https://github.com/chinchiang/MultiAgentDelta"


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def _text(name, v) -> str:
    if not isinstance(v, str) or not v.strip():
        raise ValueError(f"{name} 必須是非空字串（得到 {v!r}）")
    return v


def _count(name, v) -> int:
    if not isinstance(v, int) or isinstance(v, bool) or v < 0:
        raise ValueError(f"{name} 必須是非負整數（得到 {v!r}）")
    return v


def _choice(name, v, allowed):
    if v not in allowed:
        raise ValueError(f"{name} 不合法：{v!r}（須為 {'／'.join(allowed)}）")
    return v


def tool(name, state, *, version=None, exit_code=None, output_ref=None, duration_seconds=None) -> dict:
    """gate JSON 的一列 tool（schemas/gate-result.schema.json tools[]）；欄位順序固定。"""
    _text("tool name", name)
    _choice("tool state", state, TOOL_STATES)
    if exit_code is not None and (not isinstance(exit_code, int) or isinstance(exit_code, bool)):
        raise ValueError(f"exit_code 必須是整數或 None（得到 {exit_code!r}）")
    if duration_seconds is not None and (not isinstance(duration_seconds, (int, float)) or isinstance(duration_seconds, bool)):
        raise ValueError(f"duration_seconds 必須是數字或 None（得到 {duration_seconds!r}）")
    return {"name": name, "version": version, "state": state, "exit_code": exit_code, "output_ref": output_ref,
            "duration_seconds": duration_seconds}


def sarif(driver, rules, results) -> dict:
    """自產 SARIF 2.1.0 文件骨架：$schema 排第一；driver 必須有 name、version，informationUri 預設本 repo。
    rules、results 照原樣放入（level、defaultConfiguration、properties 由閘門決定，本 module 不正規化）。"""
    if not isinstance(driver, dict):
        raise ValueError(f"driver 必須是物件（得到 {driver!r}）")
    _text("driver name", driver.get("name"))
    _text("driver version", driver.get("version"))
    if not isinstance(rules, list) or not isinstance(results, list):
        raise ValueError("rules、results 必須是清單")
    drv = {"name": driver["name"], "version": driver["version"],
           "informationUri": driver.get("informationUri") or INFORMATION_URI,
           **{k: v for k, v in driver.items() if k not in ("name", "version", "informationUri")}, "rules": rules}
    return {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [{"tool": {"driver": drv}, "results": results}]}


def remove_stale(path) -> bool:
    """刪掉上一次留下的自產 SARIF（不讓上一次的發現被當成這一次的結果）；回傳是否刪了檔案。
    incomplete 一律用它（政策讀不到、G1 sbom／kev／maintenance／provenance 的 incomplete），不寫新的 SARIF；
    部分發現只留在摘要 JSON。不完整的 SARIF 上傳後會被 Code Scanning 當成完整結果，關掉這次無法判定之處的既有 alert
    （#243，推翻 #182 的「還有部分發現時照常寫出」）。"""
    p = pathlib.Path(path)
    if p.is_file():
        p.unlink()
        return True
    return False


class GateRun:
    """一次閘門執行（GLOSSARY.md「閘門執行」）：宣告控制 → 累積 → result()／unreadable() 產出閘門結果。"""

    def __init__(self, gate, *, controls, deferred=(), mode, scope, commit=None, diff_base=None, risk_tier=None,
                 started_at=None):
        self.gate = _choice("gate", gate, GATES)
        self.controls = [_text("control_id", c) for c in controls]
        self.deferred = [_text("control_id", c) for c in deferred]
        declared = self.controls + self.deferred
        if len(set(declared)) != len(declared):
            raise ValueError(f"控制重複宣告：{declared}")
        # mode 在這裡不驗證：result() 遇到不合法的 mode 拋 ValueError，unreadable() 則記為 enforce（#180 的決定），
        # 建立時就驗證的話，政策讀不到的路徑會在產出結果之前拋例外
        self.mode = mode
        self.scope = _choice("scope", scope, SCOPES)
        self.risk_tier = risk_tier     # 同 mode：result() 才驗證；unreadable() 遇到不合法的值省略該欄位（#181 決定）
        self.commit, self.diff_base = commit, diff_base
        self.started_at = started_at or now()
        self._tools, self._cover = [], {}
        self._problems, self._notes, self._awaiting = [], [], []
        self._blocking = self._advisory = self._fail_conditions = self._awaiting_blocking_count = 0
        self._na = None

    # ---- 累積
    def tool(self, name, state, **kw) -> dict:
        row = tool(name, state, **kw)
        self._tools.append(row)
        return row

    def cover(self, control_id, state, reason=None) -> None:
        if control_id not in self.controls and control_id not in self.deferred:
            raise ValueError(f"{self.gate} 沒有宣告控制 {control_id!r}")
        if control_id in self._cover:
            raise ValueError(f"控制 {control_id} 重複回報")
        _choice(f"coverage {control_id} 的 state", state, COVERAGE_STATES)
        self._cover[control_id] = {"control_id": control_id, "state": state, "reason": reason}

    def count(self, blocking=0, advisory=0) -> None:
        self._blocking += _count("blocking", blocking)
        self._advisory += _count("advisory", advisory)

    def fail_condition(self) -> None:
        """不是發現、卻要讓閘門 fail 的條件：閘門判定的 blocking +1，不計入 findings_count；理由由呼叫端以 note() 加入。
        目前只有 G0 的 risk_tier 不一致使用（維持既有行為；改成正式規則須另開政策 PR，AGENTS.md 規則 1）。"""
        self._fail_conditions += 1

    def awaiting_blocking(self, ids) -> None:
        """待裁決的 blocking 發現（#211、#212）：blocking tier、未被 refute、尚無人工裁決的 LLM 審查發現。計入 findings_count.blocking
        （enforce 下阻擋判定依計數擋，不因沒人裁決就放過），並以一筆待人工裁決列出 ids；不計入 verdict 的 blocking，所以沒有其他
        blocking 時是 pending（模型意見不能自行確認，docs/09 §5；多模型審查與人工裁決的規則見 AGENTS.md 規則 6）。
        空清單 → 不做任何事。"""
        if not isinstance(ids, (list, tuple)):
            raise ValueError(f"ids 必須是清單（得到 {ids!r}）")
        ids = [_text("finding id", i) for i in ids]
        if ids:
            self._awaiting_blocking_count += len(ids)
            self._awaiting.append(AWAITING_BLOCKING_PREFIX + "、".join(ids))

    def problem(self, text) -> None:
        self._problems.append(_text("problem", text))

    def note(self, text) -> None:
        self._notes.append(_text("note", text))

    def awaiting_human(self, text) -> None:
        self._awaiting.append(_text("awaiting_human", text))

    def not_applicable(self, reason) -> None:
        self._na = _text("not_applicable", reason)

    # ---- 產出
    def _coverage(self, covered, untested_reason) -> list[dict]:
        """依宣告順序列出控制：covered 裡有的照回報值；沒有的 controls → untested（untested_reason）、deferred → pending。"""
        out = [covered.get(c) or {"control_id": c, "state": "untested", "reason": untested_reason} for c in self.controls]
        out += [covered.get(c) or {"control_id": c, "state": "pending", "reason": None} for c in self.deferred]
        return out

    def _gate(self, mode, risk_tier, status, status_reason, tools, blocking, advisory, coverage) -> dict:
        g = {"gate": self.gate, "status": status, "status_reason": status_reason, "mode": mode}
        if risk_tier is not None:
            g["risk_tier"] = risk_tier
        g.update({"scope": self.scope, "diff_base": self.diff_base, "commit": self.commit,
                  "started_at": self.started_at, "finished_at": now(), "tools": tools,
                  "findings_count": {"blocking": blocking, "advisory": advisory}, "coverage": coverage})
        return g

    def result(self) -> dict:
        mode = _choice("mode", self.mode, MODES)
        tier = None if self.risk_tier is None else _choice("risk_tier", self.risk_tier, RISK_TIERS)
        coverage = self._coverage(self._cover, NOT_RUN)   # 控制覆蓋不變式：漏回報 → untested
        status, status_reason = verdict(blocking=self._blocking + self._fail_conditions, coverage=coverage, problems=self._problems,
                                        awaiting_human=self._awaiting, not_applicable=self._na, notes=self._notes)
        return self._gate(mode, tier, status, status_reason, list(self._tools), self._blocking + self._awaiting_blocking_count,
                          self._advisory, coverage)

    def unreadable(self, problem, *, tool_name, version=None) -> dict:
        """政策讀不到：不使用已累積的內容；controls 全部 untested（原因＝problem）、deferred 維持 pending、
        只有閘門自己的一列 tool（error）。mode 不合法 → enforce（與 gate_verdict 相同；阻擋判定另讀受信任樹的 mode）。"""
        _text("problem", problem)
        row = tool(tool_name, "error", version=version)
        mode = self.mode if self.mode in MODES else "enforce"
        tier = self.risk_tier if self.risk_tier in RISK_TIERS else None   # 不合法 → 省略（政策讀不到的成因之一）
        coverage = self._coverage({}, problem)            # 不使用已累積的回報
        status, status_reason = verdict(blocking=0, coverage=coverage, problems=[problem])
        return self._gate(mode, tier, status, status_reason, [row], 0, 0, coverage)


# ------------------------------------------------------------------ 發現與發現 ID（#185）
CONTROL_RE = re.compile(r"(ASVS5-V\d+\.\d+(\.\d+)?|LLM\d{2}:2025|MAESTRO-L[1-7]|VS-G[0-6]-[A-Z0-9-]+)")
CWE_KEY_RE = re.compile(r"^\s+(CWE-\d+):", re.M)    # cwe-map.yaml 的 cwes 名稱表（每個 CWE 一個 key）
EVIDENCE_GRADES = ("E0", "E1", "E2", "E3")
VALIDATION_STATES = ("pending", "confirmed", "refuted")
POLICY_TIERS = ("blocking", "advisory")
SEVERITIES = ("critical", "high", "medium", "low", "info")
CVSS_VERSIONS = ("4.0", "3.1")
PRIORITIES = ("P0", "P1", "P2", "P3")
RETEST_RESULTS = ("fixed", "still_present", "regressed", "not_retested")


class CheckRun:
    """一次檢查執行（GLOSSARY.md「檢查執行」）：閘門內一項檢查的單次執行，產出摘要 JSON 與 SARIF；
    併入閘門結果時就是子結果。生命週期只有這一份寫法（#242）。

    producer 提供：
      check(policy) -> 摘要                     執行檢查；摘要至少有 status（pass／fail／incomplete）與 status_reason
      findings(摘要, policy) -> [發現]          每筆帶 policy_tier；不得修改摘要（摘要原樣寫出）
      to_sarif(摘要, 發現, policy) -> dict       自產 SARIF（用 sarif() 骨架）
      label、tool_name、version                訊息、未完成原因與 tool 列用
      gate、control                           要併入時：control 必須列在 gate_verdict.REQUIRED_CONTROLS[gate]
      unreadable(未完成原因) -> 摘要             選用：政策讀不到時的摘要（也可在這裡清掉過期的輸出）
      report(摘要, 發現, policy)               選用：判定完成時印出的說明（stdout）
      notes(摘要, 發現) -> [str]               選用：併入時額外的 note
    """

    def __init__(self, *, label, tool_name, version, check, findings, to_sarif, gate=None, control=None,
                 unreadable=None, report=None, notes=None):
        self.label, self.tool_name, self.version = _text("label", label), _text("tool_name", tool_name), version
        self._check, self._findings, self._to_sarif = check, findings, to_sarif
        self.gate, self.control = gate, control
        self._unreadable = unreadable or (lambda problem: {"status": "incomplete", "status_reason": problem})
        self._report, self._notes = report, notes

    def execute(self, *, policy_root, sarif_path, json_path, merge_gate=None) -> int:
        """執行一次：寫出摘要 JSON、寫出 SARIF 或刪掉舊檔、選用的併入，回傳退出碼（incomplete 2、有 blocking 發現 1、其他 0）。"""
        import json
        from vibesec_policy import load_policy   # 需要 PyYAML：只在執行時 import，本 module 其餘部分不依賴它
        policy, problem = load_policy(policy_root)   # 讀不到 → incomplete，不執行檢查、不分類發現（無法決定 tier）
        summary = self._unreadable(problem) if problem else self._check(policy)
        incomplete = summary["status"] == "incomplete"
        found = [] if incomplete else self._findings(summary, policy)
        blocking = sum(f["policy_tier"] == "blocking" for f in found)
        sarif_ref = None if incomplete else str(sarif_path)   # tool 列記呼叫端給的原字串（例如 reports/g1-kev.sarif）
        sarif_path, json_path = pathlib.Path(sarif_path), pathlib.Path(json_path)
        for out in (sarif_path, json_path):
            out.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
        if incomplete:   # 不完整的 SARIF 會被當成完整結果；部分發現只留在摘要 JSON（#243）
            remove_stale(sarif_path)
        else:
            sarif_path.write_text(json.dumps(self._to_sarif(summary, found, policy), ensure_ascii=False, indent=2), encoding="utf-8")
        if merge_gate:
            gp = pathlib.Path(merge_gate)
            if gp.is_file():
                merged = self._merge(json.loads(gp.read_text(encoding="utf-8")), summary, found, blocking,
                                     sarif_ref, policy_unreadable=bool(problem))
                gp.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
            else:
                print(f"::warning::{gp} 不存在，{self.label} 結果未併入 {self.gate} gate（summary 會顯示 {self.gate} untested）")
        if incomplete:
            print(f"::error::{self.label} 檢查未完成（incomplete ≠ pass）：{summary['status_reason']}")
            return 2
        if self._report:
            self._report(summary, found, policy)
        return 1 if blocking else 0

    def _merge(self, gate, summary, found, blocking, sarif_ref, *, policy_unreadable) -> dict:
        """併入閘門結果（子結果）：控制狀態 pass／fail／incomplete → pass／fail／untested，狀態由 gate_verdict.merge 決定。"""
        from gate_verdict import REQUIRED_CONTROLS, merge
        if self.control not in REQUIRED_CONTROLS.get(self.gate, ()):
            raise ValueError(f"{self.label}：控制 {self.control!r} 不在 {self.gate} 的必要控制（gate_verdict.REQUIRED_CONTROLS）")
        st, reason = summary["status"], summary.get("status_reason")
        return merge(gate, blocking=blocking, advisory=len(found) - blocking,
                     coverage=[{"control_id": self.control, "state": {"pass": "pass", "fail": "fail", "incomplete": "untested"}[st],
                                "reason": reason}],
                     problems=[f"{self.label}：{reason}"] if st == "incomplete" and reason else [],
                     notes=([f"{self.label}：{reason}"] if st != "incomplete" and reason else [])
                           + (list(self._notes(summary, found)) if self._notes else []),
                     tools=[tool(self.tool_name, "error", version=self.version) if policy_unreadable else
                            tool(self.tool_name, "ran", version=self.version,
                                 exit_code=2 if st == "incomplete" else (1 if blocking else 0), output_ref=sarif_ref)])


def _catalog_text(name) -> str:
    p = ROOT / "config/catalogs" / name
    return p.read_text(encoding="utf-8") if p.exists() else ""


def known_controls() -> set[str]:
    """config/catalogs/ 內出現的控制 ID（與 validate.py 同一個正則）。原在 g4_review（#185 搬到這裡，g4_review 沿用）。"""
    out: set[str] = set()
    for cat in ("cwe-map.yaml", "asvs-5.0-controls.yaml", "llm-top10-2025.yaml", "maestro-layers.yaml"):
        out |= {m.group(0) for m in CONTROL_RE.finditer(_catalog_text(cat))}
    return out


def known_cwes() -> set[str]:
    """config/catalogs/cwe-map.yaml 的 cwes 名稱表裡的 CWE。"""
    return set(CWE_KEY_RE.findall(_catalog_text("cwe-map.yaml")))


def known_cves() -> set[str]:
    """config/catalogs/cve-references.yaml 的 cves（cve_catalog 負責核對目錄本身）；需要 PyYAML，只在發現帶 CVE 時讀。"""
    import yaml
    from cve_catalog import CATALOG
    p = ROOT / CATALOG
    return set(((yaml.safe_load(p.read_text(encoding="utf-8")) or {}).get("cves") or {}) if p.exists() else ())


def _optional_choice(name, v, allowed):
    return None if v is None else _choice(name, v, allowed)


def _in_catalog(name, v, known) -> str | None:
    """AGENTS.md 規則 3：ID 只能查目錄；null 允許，查不到 → ValueError。"""
    if v is None:
        return None
    if not isinstance(v, str) or v not in known():
        raise ValueError(f"{name} {v!r} 不在 config/catalogs/（AGENTS.md 規則 3：ID 只能查目錄，查不到請填 null 並在 notes 說明）")
    return v


def _utc_date(created_at) -> str:
    _text("created_at", created_at)
    try:
        t = datetime.datetime.fromisoformat(created_at)
    except ValueError:
        raise ValueError(f"created_at 不是 ISO 8601 時間：{created_at!r}") from None
    if t.tzinfo is None:
        raise ValueError(f"created_at 必須帶時區：{created_at!r}")
    return t.astimezone(datetime.timezone.utc).strftime("%Y%m%d")


def _finding_id(rule_id, path, start_line, commit, created_at) -> str:
    """VS-<created_at 的 UTC 日期>-<sha256(rule_id ␀ path ␀ start_line ␀ commit) 前 8 hex>；null 編成空字串。"""
    key = "\0".join("" if v is None else str(v) for v in (rule_id, path, start_line, commit))
    return f"VS-{_utc_date(created_at)}-{hashlib.sha256(key.encode('utf-8')).hexdigest()[:8]}"


def finding(*, gate, rule_id, title, evidence_grade, policy_tier, sources, location=None, commit=None, created_at=None,
            description=None, control_id=None, cwe=None, cve=None, severity=None, cvss_version=None, cvss_vector=None,
            cvss_score=None, epss=None, epss_date=None, kev=None, kev_date=None, validation_status="pending",
            priority=None, owner=None, due_date=None, evidence_refs=None, review=None, retest_result=None, notes=None,
            exception=None) -> dict:
    """組出完整的發現（schemas/finding.schema.json），ID 由程式決定（GLOSSARY.md「發現 ID」）。
    evidence_grade、policy_tier 必填、沒有預設（規則 4、5；tier 由閘門或 ApplyPolicy 決定）；validation_status 預設 pending；
    其他沒給的欄位為 null 或 []，description、exception 省略。ID 的 commit 只取 commit 參數，location 照原樣放入（#185 決定）。
    這裡只做手動檢查，不跑 jsonschema；CLI 另以 jsonschema 驗證輸出。"""
    _choice("gate", gate, GATES)
    _text("rule_id", rule_id)
    _text("title", title)
    _choice("evidence_grade", evidence_grade, EVIDENCE_GRADES)
    _choice("validation_status", validation_status, VALIDATION_STATES)
    _choice("policy_tier", policy_tier, POLICY_TIERS)
    for name, v, allowed in (("severity", severity, SEVERITIES), ("cvss_version", cvss_version, CVSS_VERSIONS),
                             ("priority", priority, PRIORITIES), ("retest_result", retest_result, RETEST_RESULTS)):
        _optional_choice(name, v, allowed)
    _in_catalog("control_id", control_id, known_controls)
    _in_catalog("cwe", cwe, known_cwes)
    _in_catalog("cve", cve, known_cves)
    if not isinstance(sources, dict) or "tool_version" not in sources:
        raise ValueError(f"sources 必須是含 tool、tool_version 的物件（得到 {sources!r}）")
    _text("sources.tool", sources.get("tool"))
    if location is not None and not isinstance(location, dict):
        raise ValueError(f"location 必須是物件或 null（得到 {location!r}）")
    path, line = (location or {}).get("path"), (location or {}).get("start_line")
    if path is not None and not isinstance(path, str):
        raise ValueError(f"location.path 必須是字串或 null（得到 {path!r}）")
    if line is not None and (not isinstance(line, int) or isinstance(line, bool) or line < 1):
        raise ValueError(f"location.start_line 必須是正整數或 null（得到 {line!r}）")
    if commit is not None:
        _text("commit", commit)
    if evidence_refs is not None and not isinstance(evidence_refs, list):
        raise ValueError(f"evidence_refs 必須是清單（得到 {evidence_refs!r}）")
    created_at = now() if created_at is None else created_at   # 空字串不當成「沒給」，交給 _utc_date 拒絕
    f = {"id": _finding_id(rule_id, path, line, commit, created_at), "gate": gate, "rule_id": rule_id, "title": title}
    if description is not None:
        f["description"] = description
    f.update({"control_id": control_id, "cwe": cwe, "cve": cve, "severity": severity, "cvss_version": cvss_version,
              "cvss_vector": cvss_vector, "cvss_score": cvss_score, "epss": epss, "epss_date": epss_date, "kev": kev,
              "kev_date": kev_date, "evidence_grade": evidence_grade, "validation_status": validation_status,
              "policy_tier": policy_tier, "priority": priority, "owner": owner, "due_date": due_date,
              "location": location, "evidence_refs": list(evidence_refs or []), "review": review,
              "retest_result": retest_result, "sources": sources, "created_at": created_at, "notes": notes})
    if exception is not None:
        f["exception"] = exception
    return f


def _finding_validator():
    """finding schema 的 jsonschema 驗證器（CLI 與 selftest 共用；呼叫端負責 jsonschema 缺席的處理）。"""
    import json
    from jsonschema import Draft202012Validator
    return Draft202012Validator(json.loads((ROOT / "schemas/finding.schema.json").read_text(encoding="utf-8")),
                                format_checker=Draft202012Validator.FORMAT_CHECKER)


def finding_cli(stdin, stdout, stderr) -> int:
    """`finding` 子指令：stdin 讀部分欄位的 JSON 物件，stdout 輸出完整發現；不合法 → exit 2、stderr 寫明原因。
    只組裝發現，不參與阻擋判定。輸出先以 jsonschema 驗證；jsonschema 缺席 → exit 2，不輸出沒驗證過的發現（#185 決定）。"""
    import json
    try:
        schema = _finding_validator()
    except ImportError:
        print("finding：缺 jsonschema，無法驗證發現，未輸出（pip install jsonschema）", file=stderr)
        return 2
    try:
        data = json.loads(stdin.read())
    except ValueError as e:
        print(f"finding：stdin 不是合法的 JSON：{e}", file=stderr)
        return 2
    if not isinstance(data, dict):
        print(f"finding：stdin 必須是 JSON 物件（得到 {type(data).__name__}）", file=stderr)
        return 2
    try:
        f = finding(**data)
    except TypeError as e:            # 缺必填欄位、未知欄位（含自帶 id）
        print(f"finding：欄位不合法：{e}", file=stderr)
        return 2
    except ValueError as e:
        print(f"finding：{e}", file=stderr)
        return 2
    errors = sorted(schema.iter_errors(f), key=str)
    if errors:
        e = errors[0]
        print(f"finding：不符 finding schema（{'/'.join(map(str, e.absolute_path)) or '(root)'}）：{e.message}", file=stderr)
        return 2
    print(json.dumps(f, ensure_ascii=False, indent=2), file=stdout)
    return 0


# ------------------------------------------------------------------ selftest
def selftest() -> list[str]:
    import json, re, tempfile
    from jsonschema import Draft202012Validator
    fails: list[str] = []
    schema = Draft202012Validator(json.loads((ROOT / "schemas/gate-result.schema.json").read_text(encoding="utf-8")),
                                  format_checker=Draft202012Validator.FORMAT_CHECKER)

    def check(name, fn):
        """fn 回傳 None 表示通過；回傳字串或拋例外表示失敗。"""
        try:
            why = fn()
        except Exception as e:   # stub 階段的 NotImplementedError 也記成失敗（紅燈）
            why = f"{type(e).__name__}：{e}"
        if why:
            fails.append(f"{name}：{why}")

    def raises(fn) -> bool:
        try:
            fn()
        except ValueError:
            return True
        return False

    def errs(g):
        e = sorted(schema.iter_errors(g), key=str)
        return e[0].message if e else None

    ISO = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00$")
    run = lambda **kw: GateRun("G3", **{"controls": ["C1", "C2"], "mode": "shadow", "scope": "full", **kw})

    # ---- 時間戳
    check("now() 為 UTC、精度到秒、+00:00", lambda: None if ISO.match(now()) else f"得到 {now()!r}")

    # ---- tool 列
    def t_tool():
        row = tool("semgrep", "ran", version="1.0", exit_code=0, output_ref="r.sarif", duration_seconds=1.5)
        want = {"name": "semgrep", "version": "1.0", "state": "ran", "exit_code": 0, "output_ref": "r.sarif",
                "duration_seconds": 1.5}
        if row != want or list(row) != list(want):
            return f"欄位與順序應固定（得到 {row}）"
        if tool("x", "missing") != {"name": "x", "version": None, "state": "missing", "exit_code": None,
                                    "output_ref": None, "duration_seconds": None}:
            return "沒給的欄位應為 None"
        for bad in (lambda: tool("x", "refused"), lambda: tool("", "ran"), lambda: tool("x", "ran", exit_code="0"),
                    lambda: tool("x", "ran", exit_code=True), lambda: tool("x", "ran", duration_seconds="1")):
            if not raises(bad):
                return "不合法的 state／name／exit_code／duration_seconds 應拋 ValueError"
    check("tool()", t_tool)

    # ---- 閘門結果：正常路徑
    def t_pass():
        r = run(commit="abc1234", diff_base="main", risk_tier="L3")
        r.tool("semgrep", "ran"); r.cover("C1", "pass"); r.cover("C2", "pass")
        g = r.result()
        if errs(g):
            return f"不符 gate result schema：{errs(g)}"
        if (g["gate"], g["status"], g["status_reason"], g["mode"], g["scope"], g["commit"], g["diff_base"],
                g["risk_tier"]) != ("G3", "pass", None, "shadow", "full", "abc1234", "main", "L3"):
            return f"外層欄位不對：{g}"
        if list(g) != ["gate", "status", "status_reason", "mode", "risk_tier", "scope", "diff_base", "commit",
                       "started_at", "finished_at", "tools", "findings_count", "coverage"]:
            return f"欄位順序應與既有 gate JSON 相同（得到 {list(g)}）"
        if not (ISO.match(g["started_at"]) and ISO.match(g["finished_at"]) and g["started_at"] <= g["finished_at"]):
            return f"時間戳格式或先後不對：{g['started_at']}、{g['finished_at']}"
        if g["tools"] != [tool("semgrep", "ran")] or g["findings_count"] != {"blocking": 0, "advisory": 0}:
            return f"tools／findings_count 不對：{g}"
    check("全部控制 pass → pass，外層欄位齊全、符合 schema", t_pass)

    def t_no_tier():
        g = run().result()
        return "沒給 risk_tier 時不應出現 risk_tier 欄位" if "risk_tier" in g else errs(g)
    check("risk_tier 選填", t_no_tier)

    def t_started():
        g = run(started_at="2026-01-02T03:04:05+00:00").result()
        return None if g["started_at"] == "2026-01-02T03:04:05+00:00" else f"應沿用呼叫端的 started_at（得到 {g['started_at']}）"
    check("started_at 可由呼叫端提供", t_started)

    def t_blocking():
        r = run(); r.cover("C1", "fail"); r.cover("C2", "pass"); r.count(blocking=2, advisory=1); r.count(advisory=2)
        g = r.result()
        if g["status"] != "fail" or g["findings_count"] != {"blocking": 2, "advisory": 3}:
            return f"blocking > 0 → fail，計數累加（得到 {g['status']}、{g['findings_count']}）"
    check("狀態來自閘門判定：blocking → fail", t_blocking)

    def t_problem():
        r = run(); r.cover("C1", "pass"); r.cover("C2", "pass"); r.problem("checkov：結果檔缺席"); r.note("附註")
        g = r.result()
        if g["status"] != "incomplete" or g["status_reason"] != "checkov：結果檔缺席；附註":
            return f"未完成原因 → incomplete，附註接在理由末尾（得到 {g['status']}：{g['status_reason']}）"
    check("狀態來自閘門判定：未完成原因 → incomplete", t_problem)

    def t_same_as_verdict():
        from gate_verdict import verdict
        cov = [{"control_id": "C1", "state": "untested", "reason": "負責工具未完成：semgrep"},
               {"control_id": "C2", "state": "fail", "reason": None}]
        r = run()
        for c in cov:
            r.cover(c["control_id"], c["state"], c["reason"])
        r.count(blocking=1); r.problem("p1"); r.problem("p1"); r.note("n1")
        g = r.result()
        want = verdict(blocking=1, coverage=cov, problems=["p1", "p1"], notes=["n1"])
        if (g["status"], g["status_reason"]) != want or g["coverage"] != cov:
            return f"狀態與理由應逐字等於 gate_verdict.verdict（得到 {(g['status'], g['status_reason'])}，應為 {want}）"
    check("狀態與理由逐字等於 verdict", t_same_as_verdict)

    def t_awaiting():
        r = run(); r.cover("C1", "pass"); r.cover("C2", "pass"); r.awaiting_human("VS-1 分歧")
        g = r.result()
        return None if g["status"] == "pending" and "待人工裁決：VS-1 分歧" in (g["status_reason"] or "") else f"得到 {g['status']}"
    check("待人工裁決 → pending", t_awaiting)

    def t_na():
        r = run(); r.not_applicable("沒有 IaC 檔")
        g = r.result()
        if g["status"] != "not_applicable" or g["status_reason"] != "沒有 IaC 檔" or errs(g):
            return f"得到 {g['status']}：{g['status_reason']}（{errs(g)}）"
        if not raises(lambda: GateRun("G3", controls=[], mode="shadow", scope="full").not_applicable("  ")):
            return "not_applicable 沒附理由應拋 ValueError"
    check("not_applicable 附理由", t_na)

    def t_fail_condition():
        from gate_verdict import verdict
        r = run(); r.cover("C1", "fail", "宣告 L1 低於推導值 L3"); r.cover("C2", "pass"); r.count(advisory=1)
        r.note("risk_tier：宣告 L1 低於推導值 L3"); r.fail_condition()
        g = r.result()
        want = verdict(blocking=1, coverage=g["coverage"], notes=["risk_tier：宣告 L1 低於推導值 L3"])
        if (g["status"], g["status_reason"]) != want or g["findings_count"] != {"blocking": 0, "advisory": 1}:
            return f"fail_condition → verdict 的 blocking +1、findings_count 不計入（得到 {g['status']}、{g['findings_count']}）"
        r = run(); r.cover("C1", "pass"); r.cover("C2", "pass"); r.count(blocking=2); r.fail_condition()
        g = r.result()
        if g["status"] != "fail" or g["findings_count"]["blocking"] != 2:
            return f"有發現又有 fail_condition → fail、findings_count 只算發現（得到 {g['findings_count']}）"
    check("fail_condition()：不是發現、卻讓閘門 fail（G0 tier_fail 的暫行作法）", t_fail_condition)

    def t_awaiting_blocking():
        """待裁決的 blocking 發現（#211、#212）：計入 findings_count、加進待人工裁決，不計入 verdict 的 blocking。"""
        from gate_verdict import verdict
        why = "blocking 發現尚未裁決（模型意見不能自行確認，docs/09 §5）：VS-1、VS-2"
        r = run(); r.cover("C1", "pass"); r.cover("C2", "pass"); r.count(advisory=1); r.awaiting_blocking(["VS-1", "VS-2"])
        g = r.result()
        want = verdict(blocking=0, coverage=g["coverage"], awaiting_human=[why])
        if (g["status"], g["status_reason"]) != want or g["status"] != "pending" \
                or g["findings_count"] != {"blocking": 2, "advisory": 1} or errs(g):
            return f"沒有其他 blocking → pending、理由逐字、findings_count 計入（得到 {g['status']}：{g['status_reason']}、{g['findings_count']}）"
        r = run(); r.cover("C1", "fail"); r.cover("C2", "pass"); r.count(blocking=1); r.awaiting_blocking(["VS-1"])
        g = r.result()
        if g["status"] != "fail" or g["findings_count"]["blocking"] != 2 or "待人工裁決：blocking 發現尚未裁決" not in (g["status_reason"] or ""):
            return f"有其他 blocking → fail、計數相加、理由仍列出待裁決（得到 {g['status']}、{g['findings_count']}：{g['status_reason']}）"
        r = run(); r.cover("C1", "pass"); r.cover("C2", "pass"); r.awaiting_human("rulings/：VS-9"); r.awaiting_blocking(["VS-1"]); r.awaiting_blocking(["VS-2"])
        g = r.result()
        want = verdict(blocking=0, coverage=g["coverage"], awaiting_human=["rulings/：VS-9",
                       "blocking 發現尚未裁決（模型意見不能自行確認，docs/09 §5）：VS-1",
                       "blocking 發現尚未裁決（模型意見不能自行確認，docs/09 §5）：VS-2"])
        if (g["status"], g["status_reason"]) != want or g["findings_count"]["blocking"] != 2:
            return f"可多次呼叫、依呼叫順序排在其他待人工裁決之後、計數累加（得到 {g['status_reason']}、{g['findings_count']}）"
        r = run(); r.awaiting_blocking([])
        if r.result()["findings_count"]["blocking"] != 0:
            return "空清單 → 不計入、不加理由"
        for bad in (["", "VS-1"], [" "], [3], "VS-1", None):
            if not raises(lambda: run().awaiting_blocking(bad)):
                return f"不合法的 ids（{bad!r}）應拋 ValueError"
        r = GateRun("G4", controls=["A"], mode="shadow", scope="full"); r.awaiting_blocking(["VS-1"])
        g = r.unreadable("p", tool_name="vibesec-g4-static")
        if g["findings_count"] != {"blocking": 0, "advisory": 0}:
            return "unreadable() 不使用已累積的待裁決 blocking"
    check("awaiting_blocking()：待裁決的 blocking 發現（計入計數、不讓 status 變 fail）", t_awaiting_blocking)

    # ---- 控制覆蓋不變式
    def t_invariant():
        r = GateRun("G1", controls=["A", "B"], deferred=["S", "K"], mode="shadow", scope="full")
        r.cover("A", "pass"); r.cover("K", "pass")
        g = r.result()
        got = [(c["control_id"], c["state"], c["reason"]) for c in g["coverage"]]
        want = [("A", "pass", None), ("B", "untested", NOT_RUN), ("S", "pending", None), ("K", "pass", None)]
        if got != want:
            return f"沒有 cover 的 controls 補 untested、deferred 補 pending，依宣告順序（得到 {got}）"
        if g["status"] != "incomplete" or f"B 未實測（{NOT_RUN}）" not in (g["status_reason"] or ""):
            return f"漏回報的控制 → incomplete（得到 {g['status']}：{g['status_reason']}）"
    check("控制覆蓋不變式", t_invariant)

    def t_cover_bad():
        r = run()
        for bad in (lambda: r.cover("C9", "pass"), lambda: r.cover("C1", "skipped")):
            if not raises(bad):
                return "cover 未宣告的控制或不合法的 state 應拋 ValueError"
        r.cover("C1", "pass")
        if not raises(lambda: r.cover("C1", "fail")):
            return "同一個控制 cover 兩次應拋 ValueError"
        if not raises(lambda: GateRun("G3", controls=["A", "A"], mode="shadow", scope="full")) \
                or not raises(lambda: GateRun("G3", controls=["A"], deferred=["A"], mode="shadow", scope="full")):
            return "控制重複宣告應拋 ValueError"
    check("cover 的輸入檢查", t_cover_bad)

    # ---- 不合法輸入
    def t_bad_inputs():
        ok = dict(controls=["C1"], mode="shadow", scope="full")
        cases = {
            "gate": lambda: GateRun("G9", **ok),
            "scope": lambda: GateRun("G3", **dict(ok, scope="partial")),
            "risk_tier": lambda: GateRun("G3", **dict(ok, risk_tier="l3")).result(),
            "mode": lambda: GateRun("G3", **dict(ok, mode="Enforce")).result(),
            "mode None": lambda: GateRun("G3", **dict(ok, mode=None)).result(),
            "count 負數": lambda: GateRun("G3", **ok).count(blocking=-1),
            "count 非整數": lambda: GateRun("G3", **ok).count(advisory=1.5),
            "problem 空字串": lambda: GateRun("G3", **ok).problem(" "),
        }
        bad = [k for k, fn in cases.items() if not raises(fn)]
        return f"應拋 ValueError：{bad}" if bad else None
    check("不合法輸入拋 ValueError", t_bad_inputs)

    # ---- 政策讀不到
    PROBLEM = "blocking-policy 無法讀取（FileNotFoundError），無法決定發現的 tier"

    def t_unreadable():
        from gate_verdict import verdict
        r = GateRun("G4", controls=["A", "B"], deferred=["LLM"], mode="shadow", scope="full", commit="abc1234")
        r.tool("semgrep", "ran"); r.cover("A", "fail"); r.count(blocking=3); r.problem("不該出現")   # 已累積的內容不使用
        g = r.unreadable(PROBLEM, tool_name="vibesec-g4-static", version="1.0.0")
        if errs(g):
            return f"不符 schema：{errs(g)}"
        cov = [{"control_id": "A", "state": "untested", "reason": PROBLEM},
               {"control_id": "B", "state": "untested", "reason": PROBLEM},
               {"control_id": "LLM", "state": "pending", "reason": None}]
        if g["coverage"] != cov:
            return f"controls 全部 untested（原因＝problem）、deferred 維持 pending（得到 {g['coverage']}）"
        if g["tools"] != [tool("vibesec-g4-static", "error", version="1.0.0")]:
            return f"只有閘門自己的一列 tool：state error、exit_code／output_ref 為 null（得到 {g['tools']}）"
        want = verdict(blocking=0, coverage=cov, problems=[PROBLEM])
        if (g["status"], g["status_reason"]) != want or g["findings_count"] != {"blocking": 0, "advisory": 0}:
            return f"狀態與理由應等於 verdict(problems=[problem])、沒有發現（得到 {g['status']}：{g['status_reason']}）"
        if g["commit"] != "abc1234" or g["mode"] != "shadow":
            return "外層欄位（commit、mode）照建立時的值"
    check("unreadable()：每個宣告的控制 untested、自己的 tool 列 error", t_unreadable)

    def t_unreadable_mode():
        for m in ("Enforce", None, "", '"enforce"'):
            g = GateRun("G2", controls=["C"], mode=m, scope="diff").unreadable(PROBLEM, tool_name="vibesec-sarif-gate")
            if g["mode"] != "enforce" or errs(g):
                return f"mode={m!r} → 應記為 enforce、不拋例外（得到 {g['mode']}）"
        g = GateRun("G2", controls=["C"], mode="shadow", scope="diff").unreadable(PROBLEM, tool_name="vibesec-sarif-gate")
        return None if g["mode"] == "shadow" else "合法的 mode 照原值"
    check("unreadable()：不合法 mode → enforce、不拋例外（#180 決定）", t_unreadable_mode)

    def t_unreadable_tier():
        for t in ("l3", "L4", 3):
            g = GateRun("G1", controls=["C"], mode="shadow", scope="full", risk_tier=t).unreadable(PROBLEM, tool_name="vibesec-slopcheck")
            if "risk_tier" in g or errs(g):
                return f"risk_tier={t!r} → 省略 risk_tier 欄位、不拋例外（得到 {g.get('risk_tier')!r}、{errs(g)}）"
        g = GateRun("G1", controls=["C"], mode="shadow", scope="full", risk_tier="L3").unreadable(PROBLEM, tool_name="vibesec-slopcheck")
        return None if g.get("risk_tier") == "L3" else "合法的 risk_tier 照原值"
    check("unreadable()：不合法 risk_tier → 省略欄位、不拋例外（#181 決定）", t_unreadable_tier)

    def t_unreadable_bad():
        r = run()
        if not raises(lambda: r.unreadable(" ", tool_name="x")) or not raises(lambda: r.unreadable(PROBLEM, tool_name="")):
            return "problem 或 tool_name 為空應拋 ValueError"
    check("unreadable() 的輸入檢查", t_unreadable_bad)

    # ---- 自產 SARIF 骨架
    def t_sarif():
        rules = [{"id": "vibesec.g4.supabase-rls-disabled", "defaultConfiguration": {"level": "error"}}]
        results = [{"ruleId": "vibesec.g4.supabase-rls-disabled", "level": "error", "message": {"text": "m"}}]
        doc = sarif({"name": "vibesec-g4-static", "version": "1.0.0"}, rules, results)
        if list(doc)[:2] != ["$schema", "version"] or doc["$schema"] != SARIF_SCHEMA or doc["version"] != "2.1.0":
            return f"$schema 排第一、version 2.1.0（得到 {list(doc)}）"
        drv = doc["runs"][0]["tool"]["driver"]
        if (drv["name"], drv["version"], drv["informationUri"]) != ("vibesec-g4-static", "1.0.0",
                                                                     "https://github.com/chinchiang/MultiAgentDelta"):
            return f"driver 的 name、version、informationUri（預設本 repo）不對：{drv}"
        if drv["rules"] != rules or doc["runs"][0]["results"] != results:
            return "rules、results 應照原樣放入"
        if sarif({"name": "n", "version": "1", "informationUri": "https://example.test"}, [], [])["runs"][0]["tool"]["driver"]["informationUri"] != "https://example.test":
            return "driver 給的 informationUri 應保留"
        if len(doc["runs"]) != 1 or "invocations" in doc["runs"][0]:
            return "只有一個 run、不寫 invocations"
        for bad in (lambda: sarif({"name": "n"}, [], []), lambda: sarif({"version": "1"}, [], []),
                    lambda: sarif({"name": "n", "version": "1"}, None, []), lambda: sarif({"name": "n", "version": "1"}, [], "x")):
            if not raises(bad):
                return "driver 缺 name／version、rules／results 不是清單應拋 ValueError"
    check("sarif() 骨架", t_sarif)

    def t_remove():
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "old.sarif"
            p.write_text("{}")
            if remove_stale(p) is not True or p.exists():
                return "檔案存在 → 刪掉並回傳 True"
            if remove_stale(p) is not False:
                return "檔案不存在 → 不出錯、回傳 False"
    check("remove_stale()", t_remove)

    # ---- 發現與發現 ID（#185）
    import subprocess
    fschema = _finding_validator()

    def ferrs(f):
        e = sorted(fschema.iter_errors(f), key=str)
        return e[0].message if e else None

    SRC = {"tool": "vibesec-g5", "tool_version": "1.0.0"}
    AT = "2026-10-16T01:02:03+00:00"
    LOC = {"kind": "code", "path": "app/main.py", "start_line": 42}
    base = dict(gate="G5", rule_id="vibesec.g5.bola-cross-account", title="B 帳號可讀取 A 帳號訂單",
                evidence_grade="E3", policy_tier="blocking", sources=SRC, location=LOC, commit="a1b2c3d", created_at=AT)
    fid = lambda **kw: finding(**{**base, **kw})["id"]

    def t_finding_min():
        f = finding(**base)
        if ferrs(f):
            return f"不符 finding schema：{ferrs(f)}"
        if list(f) != ["id", "gate", "rule_id", "title", "control_id", "cwe", "cve", "severity", "cvss_version",
                       "cvss_vector", "cvss_score", "epss", "epss_date", "kev", "kev_date", "evidence_grade",
                       "validation_status", "policy_tier", "priority", "owner", "due_date", "location", "evidence_refs",
                       "review", "retest_result", "sources", "created_at", "notes"]:
            return f"欄位順序應同 docs/templates/finding.example.json，沒給的 description、exception 省略（得到 {list(f)}）"
        if f["validation_status"] != "pending" or f["evidence_refs"] != [] or f["control_id"] is not None \
                or f["review"] is not None or f["notes"] is not None:
            return f"validation_status 預設 pending、其他沒給的欄位為 null 或 []（得到 {f}）"
        if (f["location"], f["sources"], f["created_at"]) != (LOC, SRC, AT):
            return "location、sources、created_at 應照原樣放入"
    check("finding()：只給必填欄位 → 完整、符合 schema", t_finding_min)

    def t_finding_full():
        f = finding(**base, description="d", control_id="ASVS5-V8.2", cwe="CWE-639", severity="high",
                    cvss_version="4.0", cvss_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
                    cvss_score=7.1, validation_status="confirmed", priority="P1", owner="team-orders",
                    due_date="2026-10-23", evidence_refs=[{"kind": "http_exchange", "ref": "r.json"}],
                    retest_result="not_retested", notes="n",
                    exception={"path_glob": "app/**", "reason": "r", "approved_by": "a", "expires": "2026-12-31",
                               "agent_id": None})
        if ferrs(f):
            return f"不符 finding schema：{ferrs(f)}"
        if (f["description"], f["control_id"], f["cwe"], f["validation_status"], f["exception"]["path_glob"]) != \
                ("d", "ASVS5-V8.2", "CWE-639", "confirmed", "app/**"):
            return f"給了的欄位應照原樣放入（得到 {f}）"
        if list(f)[4] != "description" or list(f)[-1] != "exception":
            return f"description 接在 title 後、exception 排最後（得到 {list(f)}）"
        if finding(**base, cve="CVE-2021-44228")["cve"] != "CVE-2021-44228":
            return "目錄內的 CVE 應接受"
    check("finding()：選填欄位照原樣放入", t_finding_full)

    def t_finding_now():
        f = finding(**{**base, "created_at": None})
        if not ISO.match(f["created_at"]) or f["id"][3:11] != f["created_at"][:10].replace("-", ""):
            return f"沒給 created_at → 現在時間（+00:00、到秒），ID 日期跟著它（得到 {f['created_at']}、{f['id']}）"
    check("finding()：created_at 預設現在時間", t_finding_now)

    def t_id_formula():
        want = "VS-20261016-" + hashlib.sha256("vibesec.g5.bola-cross-account\0app/main.py\x0042\0a1b2c3d".encode()).hexdigest()[:8]
        if fid() != want:
            return f"ID 應為 VS-<UTC 日期>-sha256(rule_id␀path␀start_line␀commit)[:8]（得到 {fid()}，應為 {want}）"
        if fid() != fid():
            return "同樣的輸入應得到同樣的 ID"
        arch = "VS-20261016-" + hashlib.sha256("vibesec.g5.bola-cross-account\0\0\0".encode()).hexdigest()[:8]
        if fid(location=None, commit=None) != arch:
            return f"null 編成空字串：location、commit 都是 null 也能產生 ID（得到 {fid(location=None, commit=None)}）"
        if fid(location={"kind": "architecture"}, commit=None) != arch:
            return "location 沒有 path／start_line 時視同 null"
    check("發現 ID 公式", t_id_formula)

    def t_id_changes():
        ids = {fid(), fid(rule_id="vibesec.g5.missing-session-check"), fid(location={**LOC, "path": "app/x.py"}),
               fid(location={**LOC, "start_line": 43}), fid(commit="a1b2c3e"), fid(created_at="2026-10-17T01:02:03+00:00")}
        if len(ids) != 6:
            return f"rule_id、path、start_line、commit、日期任一改變，ID 就應改變（得到 {len(ids)} 個不同 ID）"
        if fid(title="另一個標題", evidence_grade="E1") != fid() or fid(created_at="2026-10-16T23:59:59+00:00") != fid():
            return "ID 只由 rule_id、path、start_line、commit 與 UTC 日期決定"
    check("發現 ID：任一組成欄位改變，ID 就改變", t_id_changes)

    def t_id_separator():
        a = fid(location={"kind": "code", "path": "a", "start_line": None}, commit="bc")
        b = fid(location={"kind": "code", "path": "ab", "start_line": None}, commit="c")
        return "a+bc 與 ab+c 不應撞在一起（分隔字元應為 NUL）" if a == b else None
    check("發現 ID：a+bc 與 ab+c 不撞", t_id_separator)

    def t_id_utc_date():
        if fid(created_at="2026-10-17T07:00:00+08:00") != fid():
            return "+08:00 的 10/17 07:00 是 UTC 10/16，ID 日期應取 UTC 日期"
        if not fid(created_at="2026-10-16T20:00:00-05:00").startswith("VS-20261017-"):
            return "-05:00 的 10/16 20:00 是 UTC 10/17"
    check("發現 ID：日期取 created_at 的 UTC 日期", t_id_utc_date)

    def t_finding_bad():
        bad_asvs, bad_cwe, bad_cve = "ASVS5-V99.99", "CWE-99999", "CVE-2099-0001"   # 刻意不在目錄（validate.py 不掃這三種）
        cases = {
            "evidence_grade 不合法": lambda: finding(**{**base, "evidence_grade": "E4"}),
            "policy_tier 不合法": lambda: finding(**{**base, "policy_tier": None}),
            "validation_status 不合法": lambda: finding(**base, validation_status="open"),
            "gate 不合法": lambda: finding(**{**base, "gate": "G9"}),
            "rule_id 空字串": lambda: finding(**{**base, "rule_id": " "}),
            "title 空字串": lambda: finding(**{**base, "title": ""}),
            "control_id 不在目錄": lambda: finding(**base, control_id=bad_asvs),
            "cwe 不在目錄": lambda: finding(**base, cwe=bad_cwe),
            "cve 不在目錄": lambda: finding(**base, cve=bad_cve),
            "sources 缺 tool": lambda: finding(**{**base, "sources": {"tool_version": None}}),
            "sources 缺 tool_version": lambda: finding(**{**base, "sources": {"tool": "x"}}),
            "start_line 非整數": lambda: finding(**{**base, "location": {**LOC, "start_line": "42"}}),
            "start_line 為 0": lambda: finding(**{**base, "location": {**LOC, "start_line": 0}}),
            "location 不是物件": lambda: finding(**{**base, "location": "app/main.py"}),
            "commit 非字串": lambda: finding(**{**base, "commit": 123}),
            "created_at 沒有時區": lambda: finding(**{**base, "created_at": "2026-10-16T01:02:03"}),
            "created_at 不是時間": lambda: finding(**{**base, "created_at": "yesterday"}),
            "created_at 空字串": lambda: finding(**{**base, "created_at": ""}),
            "severity 不合法": lambda: finding(**base, severity="severe"),
        }
        bad = [k for k, fn in cases.items() if not raises(fn)]
        for k in ("evidence_grade", "policy_tier"):     # 必填、沒有預設：簽名本身拒絕（TypeError）
            try:
                finding(**{n: v for n, v in base.items() if n != k})
                bad.append(f"缺 {k}")
            except TypeError:
                pass
        return f"應拋例外：{bad}" if bad else None
    check("finding()：不合法輸入拋例外（缺必填 → TypeError，其餘 → ValueError）", t_finding_bad)

    def t_known_controls():
        got = known_controls()
        missing = [c for c in ("ASVS5-V8.2", "LLM01:2025", "MAESTRO-L1") if c not in got]
        return f"known_controls() 應含 config/catalogs 的控制（缺 {missing}）" if missing else None
    check("known_controls()", t_known_controls)

    def cli(payload):
        p = subprocess.run([sys.executable, str(pathlib.Path(__file__).resolve()), "finding"], input=payload,
                           capture_output=True, text=True, timeout=60)
        return p.returncode, p.stdout, p.stderr

    def t_cli_ok():
        code, out, err = cli(json.dumps({**base, "control_id": "ASVS5-V8.2"}, ensure_ascii=False))
        if code != 0:
            return f"合法輸入應 exit 0（得到 {code}：{err.strip()}）"
        f = json.loads(out)
        if ferrs(f) or f != finding(**base, control_id="ASVS5-V8.2"):
            return f"stdout 應是與 finding() 相同的完整發現（{ferrs(f)}）"
    check("finding CLI：合法輸入", t_cli_ok)

    def t_cli_bad():
        cases = {"不是 JSON": "{", "不是物件": "[]", "缺 evidence_grade": json.dumps({k: v for k, v in base.items() if k != "evidence_grade"}),
                 "未知欄位": json.dumps({**base, "foo": 1}), "自帶 id": json.dumps({**base, "id": "VS-20261016-00000000"}),
                 "control_id 不在目錄": json.dumps({**base, "control_id": "ASVS5-V99.99"}),
                 "通過手動檢查但不符 schema": json.dumps({**base, "cvss_score": 11})}
        for name, payload in cases.items():
            code, out, err = cli(payload)
            if code == 0 or out.strip() or not err.strip():
                return f"{name}：應以非零退出碼結束、stdout 為空、stderr 寫明原因（得到 {code}、{out!r}、{err!r}）"
    check("finding CLI：不合法輸入", t_cli_bad)

    def t_cli_no_jsonschema():
        import io
        saved = sys.modules.get("jsonschema")
        sys.modules["jsonschema"] = None          # import jsonschema → ImportError
        try:
            out, err = io.StringIO(), io.StringIO()
            code = finding_cli(io.StringIO(json.dumps(base, ensure_ascii=False)), out, err)
        finally:
            sys.modules["jsonschema"] = saved
        if code != 2 or out.getvalue() or "jsonschema" not in err.getvalue():
            return f"缺 jsonschema → exit 2、不輸出沒驗證過的發現、stderr 寫明原因（得到 {code}、{out.getvalue()!r}）"
    check("finding CLI：缺 jsonschema → exit 2、不輸出", t_cli_no_jsonschema)

    # ---- 檢查執行（CheckRun，#245）：假的 producer 只回傳固定的摘要與發現，生命週期全部經由 CheckRun
    import contextlib, io
    from vibesec_policy import POLICY_UNREADABLE, broken_policy_root, temp_policy_root
    STALE = "上一次的結果"

    def check_run(summary=None, found=(), **kw):
        doc = sarif({"name": "fake", "version": "1"}, [], [{"ruleId": f.get("rule_id")} for f in found])
        return CheckRun(**{"label": "假檢查", "tool_name": "fake-check", "version": "1.0.0",
                           "check": lambda policy: dict(summary), "findings": lambda s, policy: [dict(f) for f in found],
                           "to_sarif": lambda s, fs, policy: doc, "gate": "G1", "control": "VS-G1-SBOM", **kw})

    def g1_gate(**kw):   # slopcheck 先寫出的 G1 閘門結果：VS-G1-SBOM 待併入
        return {"gate": "G1", "status": "pass", "status_reason": None, "mode": "shadow", "risk_tier": "L3", "scope": "full",
                "diff_base": None, "commit": None, "started_at": "2026-01-01T00:00:00+00:00",
                "finished_at": "2026-01-01T00:00:00+00:00", "tools": [], "findings_count": {"blocking": 0, "advisory": 0},
                "coverage": [{"control_id": "VS-G1-SBOM", "state": "pending", "reason": None}], **kw}

    def execute(cr, *, policy="ok", gate=None):
        """在暫存目錄執行 cr：先放一份舊 SARIF；回傳 (退出碼, 摘要, SARIF 是否為「缺席／舊檔／寫出」, 併入後的閘門結果, stdout)。"""
        out = io.StringIO()
        with (broken_policy_root() if policy == "broken" else temp_policy_root()) as pr, \
                tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(out):
            js, sf, gp = pathlib.Path(d, "out.json"), pathlib.Path(d, "out.sarif"), pathlib.Path(d, "G1.json")
            sf.write_text(STALE, encoding="utf-8")
            if gate is not None:
                gp.write_text(json.dumps(gate), encoding="utf-8")
            rc = cr.execute(policy_root=pr, sarif_path=sf, json_path=js, merge_gate=gp if gate is not None else None)
            raw = sf.read_text(encoding="utf-8") if sf.exists() else None
            seen = "缺席" if raw is None else "舊檔" if raw == STALE else "寫出"
            merged = json.loads(gp.read_text(encoding="utf-8")) if gate is not None else None
            return rc, json.loads(js.read_text(encoding="utf-8")), seen, merged, out.getvalue()

    def cov(g, cid="VS-G1-SBOM"):
        return [(c["state"], c["reason"]) for c in g["coverage"] if c["control_id"] == cid]

    def t_cr_unreadable():
        rc, s, seen, g, out = execute(check_run({"status": "pass", "status_reason": None}), policy="broken", gate=g1_gate())
        reason = s.get("status_reason") or ""
        if rc != 2 or s.get("status") != "incomplete" or not reason.startswith(POLICY_UNREADABLE + "（") or seen != "缺席":
            return f"政策讀不到 → 退出碼 2、摘要 incomplete 並寫明原因、刪掉舊 SARIF（得到 {rc}、{s}、SARIF {seen}）"
        if g["status"] != "incomplete" or cov(g) != [("untested", reason)] or g["findings_count"] != {"blocking": 0, "advisory": 0} \
                or g["tools"] != [tool("fake-check", "error", version="1.0.0")] or f"假檢查：{reason}" not in (g["status_reason"] or ""):
            return f"政策讀不到 → 併入後 G1 incomplete、控制 untested、tool 列 error、未完成原因帶 label（得到 {g}）"
        if f"::error::假檢查 檢查未完成（incomplete ≠ pass）：{reason}" not in out:
            return f"政策讀不到 → ::error:: 說明未完成（得到 {out!r}）"
    check("CheckRun：政策讀不到", t_cr_unreadable)

    BLK = {"rule_id": "vibesec.g1.sbom-incomplete", "policy_tier": "blocking"}
    ADV = {"rule_id": "vibesec.g1.sbom-incomplete", "policy_tier": "advisory"}
    for label, summary, found, want in [
        # (退出碼, SARIF, 併入後 G1 狀態, 控制狀態, findings_count, tool 列 exit_code, 有 output_ref)
        ("一般 incomplete", {"status": "incomplete", "status_reason": "缺 syft"}, [], (2, "缺席", "incomplete", "untested", (0, 0), 2, False)),
        ("pass", {"status": "pass", "status_reason": None}, [], (0, "寫出", "pass", "pass", (0, 0), 0, True)),
        ("有 blocking 發現", {"status": "fail", "status_reason": "缺"}, [BLK], (1, "寫出", "fail", "fail", (1, 0), 1, True)),
        # advisory 只計數：閘門不因此 fail，但控制本身沒有達成，仍記 fail
        ("只有 advisory 發現", {"status": "fail", "status_reason": "缺"}, [ADV], (0, "寫出", "pass", "fail", (0, 1), 0, True)),
    ]:
        def t_cr_case(summary=summary, found=found, want=want):
            rc, s, seen, g, out = execute(check_run(summary, found), gate=g1_gate())
            fc, tl = g["findings_count"], g["tools"]
            got = (rc, seen, g["status"], cov(g)[0][0] if cov(g) else None, (fc["blocking"], fc["advisory"]),
                   tl[0]["exit_code"] if len(tl) == 1 else tl, bool(tl[0]["output_ref"]) if len(tl) == 1 else None)
            if got != want or s != summary or len(cov(g)) != 1 or tl[0]["state"] != "ran" or errs(g):
                return f"應為 {want}，摘要原樣寫出、控制只留一筆、tool 列 ran、符合 schema（得到 {got}、{s}、{cov(g)}、{errs(g)}）"
        check(f"CheckRun：{label}", t_cr_case)

    def t_cr_no_gate_file():
        rc, s, seen, g, out = execute(check_run({"status": "pass", "status_reason": None}))
        if rc != 0 or seen != "寫出":
            return f"沒有 --merge-gate → 照常執行（得到 {rc}、SARIF {seen}）"
        cr = check_run({"status": "pass", "status_reason": None})
        with temp_policy_root() as pr, tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()) as o:
            gp = pathlib.Path(d, "none.json")
            rc = cr.execute(policy_root=pr, sarif_path=pathlib.Path(d, "o.sarif"), json_path=pathlib.Path(d, "o.json"), merge_gate=gp)
            if rc != 0 or gp.exists() or f"::warning::{gp} 不存在，假檢查 結果未併入 G1 gate" not in o.getvalue():
                return f"--merge-gate 檔案不存在 → 略過併入、不建立檔案、警告（得到 {rc}、{gp.exists()}、{o.getvalue()!r}）"
    check("CheckRun：--merge-gate 檔案不存在時略過", t_cr_no_gate_file)

    def t_cr_undeclared_control():
        if not raises(lambda: execute(check_run({"status": "pass", "status_reason": None}, control="VS-G1-COOLDOWN"), gate=g1_gate())):
            return "宣告的 control 不在 REQUIRED_CONTROLS[G1] → ValueError"
        if not raises(lambda: execute(check_run({"status": "pass", "status_reason": None}, gate="G3"), gate=g1_gate())):
            return "閘門沒有必要控制（G3）→ ValueError"
    check("CheckRun：併入時核對必要控制", t_cr_undeclared_control)

    def t_cr_upgrade_only():   # 預期值沿用 #245 之前 g1_sbom／g1_kev 的 merge_gate 測試
        ok_s, inc_s = {"status": "pass", "status_reason": None}, {"status": "incomplete", "status_reason": "x"}
        g = execute(check_run(ok_s), gate=g1_gate(status="fail", status_reason="slop"))[3]
        if g["status"] != "fail" or cov(g) != [("pass", None)]:
            return f"pass 不得降低既有的 fail（得到 {g['status']}、{cov(g)}）"
        g = execute(check_run(inc_s), gate=g1_gate(status="fail", status_reason="slop"))[3]
        if g["status"] != "fail":
            return f"G1 已 fail 時 incomplete 不得降為 incomplete（得到 {g['status']}）"
        g = execute(check_run(ok_s), gate=g1_gate(status="incomplete", status_reason="slop"))[3]
        if g["status"] != "incomplete" or g["status_reason"] != "slop":
            return f"pass 不得把 incomplete 的 G1 洗成 pass（得到 {g['status']}、{g['status_reason']}）"
    check("CheckRun：併入只升不降", t_cr_upgrade_only)

    def t_cr_pending_replaced():
        from gate_verdict import is_clean
        held = g1_gate(coverage=[{"control_id": "VS-G1-SBOM", "state": "pending", "reason": None},
                                 {"control_id": "ASVS5-V15.2", "state": "pass", "reason": None}])
        g = execute(check_run({"status": "pass", "status_reason": None}), gate=held)[3]
        if is_clean(held) or not is_clean(g) or cov(g) != [("pass", None)] or cov(g, "ASVS5-V15.2") != [("pass", None)]:
            return f"待併入的控制應被取代（只留一筆），未併入則不乾淨（得到 {g['coverage']}）"
    check("CheckRun：取代待併入的控制", t_cr_pending_replaced)

    def t_cr_hooks():
        calls = []
        cr = check_run({"status": "fail", "status_reason": None}, [ADV],
                       report=lambda s, fs, policy: calls.append(("report", len(fs))) or print("說明"),
                       notes=lambda s, fs: [f"命中 {len(fs)} 筆"])
        rc, s, seen, g, out = execute(cr, gate=g1_gate())
        if calls != [("report", 1)] or "說明" not in out or "命中 1 筆" not in (g["status_reason"] or ""):
            return f"判定完成 → report 收到發現、notes 進閘門結果（得到 {calls}、{out!r}、{g['status_reason']}）"
        calls.clear()
        execute(check_run({"status": "incomplete", "status_reason": "x"},
                          report=lambda s, fs, policy: calls.append("report"),
                          findings=lambda s, policy: calls.append("findings") or []), gate=g1_gate())
        if calls:
            return f"incomplete → 不分類發現、不印 report（得到 {calls}）"
        rc, s, seen, g, out = execute(check_run(None, unreadable=lambda problem: {"status": "incomplete", "status_reason": problem,
                                                                                    "extra": 1}), policy="broken")
        if rc != 2 or s.get("extra") != 1:
            return f"政策讀不到 → 摘要用 unreadable() 的結果（得到 {rc}、{s}）"
    check("CheckRun：report／notes／unreadable", t_cr_hooks)
    return fails


if __name__ == "__main__":
    if sys.argv[1:] == ["selftest"]:
        _fails = selftest()
        for _f in _fails:
            print(f"FAIL {_f}")
        print("selftest " + ("通過" if not _fails else f"失敗 {len(_fails)} 項"))
        sys.exit(1 if _fails else 0)
    if sys.argv[1:] == ["finding"]:
        sys.exit(finding_cli(sys.stdin, sys.stdout, sys.stderr))
    print(__doc__)
    sys.exit(2)
