#!/usr/bin/env python3
"""VibeSec 閘門結果（gate result）module：閘門結果、tool 列、自產 SARIF 骨架與時間戳的唯一一份寫法（GLOSSARY.md「閘門執行」）。

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
      .result() -> dict               記下 finished_at、套用控制覆蓋不變式、呼叫 verdict，回傳閘門結果
      .unreadable(problem, *, tool_name, version=None) -> dict
                                      政策讀不到：controls 全部 untested（原因＝problem）、deferred 維持 pending、
                                      只有閘門自己的一列 tool（error）；不使用已累積的內容
  tool(name, state, *, version=None, exit_code=None, output_ref=None, duration_seconds=None) -> dict
  sarif(driver, rules, results) -> dict      自產 SARIF 2.1.0 文件骨架；rules、results 照原樣放入
  remove_stale(path) -> bool                 刪掉過期的自產 SARIF（這一次沒有判定任何發現時用：政策讀不到、
                                             G1 sbom／kev 的 incomplete）；檔案不存在不出錯
  now() -> str                               UTC、精度到秒、+00:00

控制覆蓋不變式：宣告在 controls、卻沒有 cover 的控制，result() 時補成 untested（原因：未執行）；宣告在 deferred、
卻沒有 cover 的控制補成 pending。漏回報只會讓閘門變嚴，不可能變成 pass。cover 未宣告的控制 → ValueError。

mode：result() 只接受 shadow／enforce，不合法 → ValueError；unreadable() 遇到不合法的 mode 記為 enforce、不拋例外
（使用者 2026-10-14 決定，#180：拋例外會讓閘門結果缺席，與「讀不到 → 更嚴」的既有語意不同）。
risk_tier 同理：result() 不合法 → ValueError；unreadable() 遇到不合法的值省略該欄位（#181；risk_tier 打錯時
load_policy 本來就回報政策讀不到）。

只回傳 dict，不寫閘門 JSON，也不在執行時跑 jsonschema（jsonschema 在部分環境可能缺席）；輸入不合法 → ValueError，
那是閘門程式的 bug。schema 符合性由本檔的 selftest 以 jsonschema 驗證。

  python3 scripts/gate_result.py selftest
"""
from __future__ import annotations
import datetime, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from gate_verdict import COVERAGE_STATES, verdict  # noqa: E402  狀態判定與覆蓋 state 的唯一來源

GATES = ("G0", "G1", "G2", "G3", "G4", "G5", "G6")
MODES = ("shadow", "enforce")
SCOPES = ("diff", "full")
RISK_TIERS = ("L1", "L2", "L3")
TOOL_STATES = ("ran", "missing", "timeout", "error")
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
NOT_RUN = "未執行"


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
    這一次沒有判定任何發現時才用（政策讀不到、G1 sbom／kev 的 incomplete）；還有部分發現時應照常寫出 SARIF。"""
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
        self._blocking = self._advisory = self._fail_conditions = 0
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
        目前只有 G0 的 risk_tier 不一致使用（維持既有行為；改成正式規則須另開政策 PR，CLAUDE.md 規則 1）。"""
        self._fail_conditions += 1

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
        return self._gate(mode, tier, status, status_reason, list(self._tools), self._blocking, self._advisory, coverage)

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
    return fails


if __name__ == "__main__":
    if sys.argv[1:] == ["selftest"]:
        _fails = selftest()
        for _f in _fails:
            print(f"FAIL {_f}")
        print("selftest " + ("通過" if not _fails else f"失敗 {len(_fails)} 項"))
        sys.exit(1 if _fails else 0)
    print(__doc__)
    sys.exit(2)
