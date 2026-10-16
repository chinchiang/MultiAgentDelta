#!/usr/bin/env python3
"""VibeSec 阻擋政策查詢：規則 tier 的唯一來源。

來源：config/policy/blocking-policy.yaml（blocking 清單、default_tier、tier_overrides）＋ vibesec.yaml 的 risk_tier。
config/catalogs/cwe-map.yaml 的 policy_tier 只是預設建議（該檔第 7 行），validate.py 檢查它必須等於這裡的
base_tier；所有發出 finding 的元件（workflow 內嵌探針、scripts/*.py）都必須用這裡算 tier，不得自行寫死。

  from vibesec_policy import Policy
  p = Policy(root)
  p.tier(rule_id)        # 有效 tier：含 risk_tier 的 tier_overrides（CI 阻擋用）
  p.base_tier(rule_id)   # 基礎 tier：不含 tier_overrides（cwe-map／docs／evals 對齊用）
  p.cap(rule_id, req)    # 呼叫端只能把個別發現降為 advisory，不能升級到政策以上
  p, problem = load_policy(root)   # 閘門進入點：讀不到 → (None, 未完成原因)，閘門記 incomplete
  p.mode, p.mode_note    # 執行模式：受信任 vibesec.yaml 的 mode，沒有預設值（缺席或不合法 → 讀不到）；
                         # load_policy(root, mode_override=…) 只能把 shadow 升為 enforce（只有阻擋判定會傳），忽略降級時附註
  pp = p.for_project(project, today=None)       # 綁定受驗樹的政策例外（G0–G3 唯一的讀取與比對）；project 必填
  pp.classify(rule_id, path, agent_id=None, requested=None)
                         # {"policy_tier", "exception"}：tier 依 cap；命中例外 → advisory、發現保留，exception 為固定五欄
  pp.report(findings, gate, paths=())           # status_reason 的例外說明：命中筆數、本閘門忽略與缺 agent_id 而未套用的例外
  pp.note / pp.ignored                          # 外部專案的說明（本 repo → None）／全部被忽略的例外說明

exceptions：欄位（rule_id、path_glob、reason、approved_by、expires）缺一、expires 格式無效、已過期（expires < today；
到期當日仍有效）→ 不套用並列入 ignored；path_glob 以 fnmatch.fnmatchcase 比對（單一 * 也會跨越 /）。
p.is_this_repo(project)：None、root，或 project_root（存在的目錄）→ 本 repo；其他 → 外部專案，例外全部不套用
（例外只核准給本 repo 路徑）。project_root 是「判定程式與受驗樹分開」時的受驗樹（CI：_trusted/ 與 workspace），
預設取環境變數 VIBESEC_PROJECT_ROOT（由受信任的 workflow 設定）；明確傳 None ＝ 沒有（selftest 用）。

  python3 scripts/vibesec_policy.py <rule_id>...    # 每行印出「<rule_id> <有效 tier>」（給 shell 步驟用）
  python3 scripts/vibesec_policy.py selftest

政策檔缺席或無法解析、risk_tier／tier_overrides／applies_only_to_gates／incomplete_gate_is_blocking_in_enforce
不合法 → 例外（incomplete ≠ pass，CLAUDE.md #2）；要改政策必須由人類在獨立 PR 決定（規則 1）。
"""
from __future__ import annotations
import contextlib, fnmatch, os, pathlib, sys
from datetime import date

try:
    import yaml
except ImportError:
    print("工具缺席：PyYAML；無法讀取阻擋政策", file=sys.stderr)
    sys.exit(2)

DEFAULT_ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vibesec_mode import apply_override, read_mode  # noqa: E402  mode 的合法值與解析只有一份（#200）；只用標準函式庫
# Policy(project_root=…) 的預設：取環境變數 VIBESEC_PROJECT_ROOT；明確傳 None ＝ 沒有 project_root（selftest 用，不受環境影響）
FROM_ENV = object()
TIERS = ("blocking", "advisory")
GATES = ("G0", "G1", "G2", "G3", "G4", "G5", "G6")
EXCEPTION_FIELDS = ("rule_id", "path_glob", "reason", "approved_by", "expires")   # exceptions 必填（缺一 → 不套用）
RISK_TIERS = ("L1", "L2", "L3")             # vibesec.yaml risk_tier（docs/01 決策樹）
# 外部工具規則前綴 → 閘門（applies_only_to_gates 用）。trivy 同時用於 G1（漏洞）與 G3（IaC 設定），
# 從規則 ID 分不出閘門 → 不列，不因 applies_only_to_gates 降級（fail closed）。
# load_policy 讀不到政策時，未完成原因的開頭（各閘門相同的文字）
POLICY_UNREADABLE = "blocking-policy 無法讀取"
# 例外必須寫明 agent_id 才命中的規則：G0 的致命三要素例外只寫 path_glob，會連同同一份威脅模型之後新增的 agent 一起放行
AGENT_SCOPED_RULES = frozenset({"vibesec.g0.lethal-trifecta-open"})
TOOL_GATE = {"gitleaks": "G2", "semgrep": "G3", "checkov": "G3", "zap": "G5", "promptfoo": "G6", "garak": "G6", "grype": "G1"}


def rule_gate(rule_id: str) -> str | None:
    """規則所屬閘門：vibesec.g<N>.* → G<N>；外部工具依 TOOL_GATE；分不出 → None。"""
    rid = str(rule_id)
    if rid.startswith("vibesec.g") and rid[9:10].isdigit() and rid[10:11] == ".":
        return f"G{rid[9]}"
    return TOOL_GATE.get(rid.split(":", 1)[0]) if ":" in rid else None


class ModeError(ValueError):
    """vibesec.yaml 的 mode 缺席或不合法，或 mode_override 不合法；訊息即未完成原因（load_policy 原樣放進 problem）。"""


class Policy:
    def __init__(self, root: pathlib.Path | str | None = None, risk_tier: str | None = None,
                 project_root: pathlib.Path | str | None | object = FROM_ENV, mode_override: str | None = None):
        self.root = pathlib.Path(root) if root else DEFAULT_ROOT
        if project_root is FROM_ENV:
            project_root = os.environ.get("VIBESEC_PROJECT_ROOT")
        self.project_root = pathlib.Path(project_root) if project_root else None
        pol = yaml.safe_load((self.root / "config/policy/blocking-policy.yaml").read_text(encoding="utf-8")) or {}
        vb_text = (self.root / "vibesec.yaml").read_text(encoding="utf-8")
        if risk_tier is None:
            vb = yaml.safe_load(vb_text) or {}
            risk_tier = vb.get("risk_tier", "L2")
        overrides = pol.get("tier_overrides") or {}
        # risk_tier 必須是 vibesec.yaml 定義的層級（L1／L2／L3）：以前 l3、L4 這類打錯的值靜默取不到任何 override，
        # L3 的升級規則就消失了（例如 missing-owner-filter 變回 advisory）。打錯 → 例外（fail closed）
        if risk_tier not in RISK_TIERS:
            raise ValueError(f"risk_tier 不合法：{risk_tier!r}（須為 {'／'.join(RISK_TIERS)}）")
        if not set(overrides) <= set(RISK_TIERS):
            raise ValueError(f"blocking-policy tier_overrides 有未知層級：{sorted(set(overrides) - set(RISK_TIERS))}")
        self.risk_tier = risk_tier
        # mode 沒有預設值（#199）：缺席或不合法 → ModeError（load_policy 回報為政策讀不到）；以前各閘門各自預設 shadow
        mode, problem = read_mode(vb_text)
        if problem:
            raise ModeError(problem)
        try:
            self.mode, self.mode_note = apply_override(mode, mode_override)
        except ValueError as e:
            raise ModeError(str(e)) from None
        self.default_tier = pol.get("default_tier", "advisory")
        if self.default_tier not in TIERS:
            raise ValueError(f"blocking-policy default_tier 不合法：{self.default_tier!r}")
        self.blocking_base = {r["rule_id"] for r in pol.get("blocking") or [] if isinstance(r, dict) and r.get("rule_id")}
        self.advisory_listed = {r["rule_id"] for r in pol.get("advisory") or [] if isinstance(r, dict) and r.get("rule_id")}
        ov = overrides.get(risk_tier) or {}
        self.promoted = set(ov.get("promote_to_blocking") or [])
        self.demoted = set(ov.get("demote_to_advisory") or [])
        # applies_only_to_gates（例如 L1 只跑 G1、G2）：清單外閘門的規則不套用 → 有效 tier 為 advisory（發現保留、不阻擋）。
        # 以前宣告了卻沒有實作，L1 下 vibesec.g3.sql-string-concat 仍是 blocking。未宣告 → None（所有閘門都套用）
        only = ov.get("applies_only_to_gates")
        if only is not None:
            bad = [g for g in only if g not in GATES] if isinstance(only, list) else [only]
            if bad:
                raise ValueError(f"tier_overrides.{risk_tier}.applies_only_to_gates 不合法：{bad!r}（須為 {'／'.join(GATES)}）")
        self.applies_only_to_gates = set(only) if only is not None else None
        # incomplete_gate_is_blocking_in_enforce：打錯的閘門名稱以前靜默忽略（字串 "G1" 還會被拆成 G、1），
        # 該閘門 incomplete 就不阻擋了。打錯 → 例外（fail closed）
        gates = pol.get("incomplete_gate_is_blocking_in_enforce") or []
        bad = [g for g in gates if g not in GATES] if isinstance(gates, list) else [gates]
        if bad:
            raise ValueError(f"blocking-policy incomplete_gate_is_blocking_in_enforce 不合法：{bad!r}（須為 {'／'.join(GATES)}）")
        self.incomplete_blocking_gates = list(gates)
        self._exceptions = pol.get("exceptions") or []   # 政策檔只讀一次；for_project 再篩選

    def base_tier(self, rule_id: str) -> str:
        if rule_id in self.blocking_base:
            return "blocking"
        if rule_id in self.advisory_listed or str(rule_id).startswith("vibesec."):
            return "advisory"
        return self.default_tier

    def gate_applies(self, gate: str | None) -> bool:
        """本 risk_tier 下該閘門的規則是否套用；閘門分不出（None）→ 套用（不因此降級）。"""
        return self.applies_only_to_gates is None or gate is None or gate in self.applies_only_to_gates

    def tier(self, rule_id: str) -> str:
        if rule_id in self.demoted:
            return "advisory"
        if not self.gate_applies(rule_gate(rule_id)):
            return "advisory"
        if rule_id in self.promoted:
            return "blocking"
        return self.base_tier(rule_id)

    def cap(self, rule_id: str, requested: str | None) -> str:
        """requested 為 advisory → advisory（個別發現可降級，例如只有線索）；其餘 → 政策的有效 tier。"""
        return "advisory" if requested == "advisory" else self.tier(rule_id)

    def effective_blocking(self) -> set[str]:
        return {r for r in (self.blocking_base | self.promoted) - self.demoted if self.gate_applies(rule_gate(r))}

    def is_this_repo(self, target) -> bool:
        """target 是本 repo：None、root，或 project_root（判定程式與受驗樹分開的本 repo，例如 CI 的 _trusted/ 與 workspace）。"""
        if target is None:
            return True
        t = pathlib.Path(target).resolve()
        if t == self.root.resolve():
            return True
        # project_root 必須是存在的目錄：打錯或未取出時不因此認定本 repo（fail closed）
        return self.project_root is not None and self.project_root.is_dir() and t == self.project_root.resolve()

    def for_project(self, project, today=None) -> "ProjectPolicy":
        """綁定受驗樹的政策例外。project 必填：None 不再代表本 repo（以前 exceptions_for(None) 是預設值，
        外部專案忘了替換就套用本 repo 的例外）。today 只供測試注入日期。"""
        if project is None:
            raise ValueError("for_project 需要受驗樹；None 不代表本 repo")
        # 外部專案（受驗樹不是本 repo）：例外只核准給本 repo 路徑 → 全部不套用（fail closed）
        if not self.is_this_repo(project):
            return ProjectPolicy(self, [], [], note=f"目標專案 {pathlib.Path(project).name}：blocking-policy exceptions 只核准給本 repo 路徑，未套用")
        today = today or date.today()
        valid, ignored = [], []                   # ignored：(rule_id 或 None, 說明)；report 依 rule_id 分閘門
        for ex in self._exceptions:
            if not isinstance(ex, dict):
                continue
            missing = [k for k in EXCEPTION_FIELDS if not ex.get(k)]
            if missing:
                ignored.append((ex.get("rule_id"), f"{ex.get('rule_id', '?')}：缺少欄位 {', '.join(missing)}"))
                continue
            exp = ex["expires"]
            try:
                exp = exp if isinstance(exp, date) else date.fromisoformat(str(exp))
            except ValueError:
                ignored.append((ex["rule_id"], f"{ex['rule_id']}：expires 格式無效（{ex['expires']}）"))
                continue
            if exp < today:
                ignored.append((ex["rule_id"], f"{ex['rule_id']} @ {ex['path_glob']}：已於 {exp} 過期"))
                continue
            valid.append(dict(ex, expires=str(exp)))
        return ProjectPolicy(self, valid, ignored)


class ProjectPolicy:
    """Policy.for_project 的結果：綁定受驗樹的政策例外。外部專案沒有任何有效例外，note 說明為何未套用。"""
    def __init__(self, policy: Policy, valid: list[dict], ignored: list[tuple], note: str | None = None):
        self._policy, self._valid, self._ignored = policy, valid, ignored
        self.ignored = [text for _, text in ignored]     # 全部（G1 stdout 的 ignored_exceptions）
        self.note = note

    def classify(self, rule_id: str, path: str | None, agent_id: str | None = None,
                 requested: str | None = None) -> dict:
        """發現的政策 tier 與例外紀錄：{"policy_tier", "exception"}。tier 為 Policy.cap(rule_id, requested)
        （呼叫端只能先降級）；rule_id 相等且 fnmatchcase(path, path_glob) 的例外命中 → advisory，發現保留，
        exception 為 finding.schema.json 的固定五欄；沒有命中 → None。AGENT_SCOPED_RULES 的例外另須 agent_id 相同。"""
        tier = self._policy.cap(rule_id, requested)
        scoped = rule_id in AGENT_SCOPED_RULES
        ex = None if path is None else next(
            (e for e in self._valid if e["rule_id"] == rule_id and fnmatch.fnmatchcase(path, e["path_glob"])
             and (not scoped or (agent_id is not None and e.get("agent_id") == agent_id))), None)
        if ex is None:
            return {"policy_tier": tier, "exception": None}
        return {"policy_tier": "advisory", "exception": _record(ex)}

    def report(self, findings: list[dict], gate: str, paths=()) -> list[str]:
        """閘門 status_reason 的例外說明（各閘門相同的文字）：命中筆數、本閘門忽略的例外，以及缺 agent_id 而未套用的例外。
        paths：閘門比對例外用的路徑（G0：威脅模型）。AGENT_SCOPED_RULES 的例外只寫 path_glob 不放行任何 agent，
        path_glob 符合其中任一路徑時列為「缺 agent_id，未套用」；不列入 ignored。"""
        notes = []
        hits = sum(1 for f in findings if f.get("exception"))
        if hits:
            notes.append(f"{hits} 筆命中 blocking-policy 例外（blocking 降為 advisory，發現保留）")
        # 只列本閘門的規則；分不出閘門（缺 rule_id、trivy: 同時用於 G1／G3）→ 每個閘門都列，寧可重複不可漏看
        unapplied = [(ex["rule_id"], f"{ex['rule_id']} @ {ex['path_glob']}：{rule_gate(ex['rule_id'])} 例外缺 agent_id，未套用")
                     for ex in self._valid if ex["rule_id"] in AGENT_SCOPED_RULES and not ex.get("agent_id")
                     and any(fnmatch.fnmatchcase(p, ex["path_glob"]) for p in paths)]
        mine = [text for rid, text in self._ignored + unapplied if rid is None or rule_gate(rid) in (None, gate)]
        if mine:
            notes.append("忽略的例外：" + "；".join(mine))
        return notes


def _record(ex: dict) -> dict:
    """命中的例外寫進 finding 的固定形狀（各閘門相同，finding.schema.json 的 exception）；沒有 agent_id → None。"""
    return {"path_glob": ex["path_glob"], "reason": ex["reason"], "approved_by": ex["approved_by"],
            "expires": ex["expires"], "agent_id": ex.get("agent_id")}


def load_policy(root: pathlib.Path | str | None = None, **kw) -> tuple[Policy | None, str | None]:
    """閘門開始時建立一次 Policy：(Policy, None)。政策檔缺席、無法解析或不合法 → (None, 未完成原因)；
    閘門記一筆未完成原因、狀態 incomplete，不分類任何發現（incomplete ≠ pass，CLAUDE.md #2）。kw 原樣交給 Policy。"""
    try:
        return Policy(root, **kw), None
    except ModeError as e:   # mode 錯誤也是政策讀不到的一種：同一個前綴、同一條閘門路徑（#200）
        return None, f"{POLICY_UNREADABLE}（{e}）"
    except Exception as e:   # yaml.YAMLError 不是 ValueError 的子類別；任何讀取失敗都不得退回預設 tier 照樣判定
        return None, f"{POLICY_UNREADABLE}（{type(e).__name__}），無法決定發現的 tier"


@contextlib.contextmanager
def temp_policy_root(exceptions=(), root: pathlib.Path | None = None):
    """selftest 用：暫存 root 放 root（預設本 repo）政策的副本（blocking-policy.yaml、vibesec.yaml），只換掉 exceptions，
    不依賴政策檔現有例外與其到期日。yield 暫存 root；離開時刪除。要換例外時呼叫 write_exceptions。"""
    import shutil, tempfile
    root = pathlib.Path(root) if root else DEFAULT_ROOT
    with tempfile.TemporaryDirectory(prefix="vibesec-policy-") as d:
        tmp = pathlib.Path(d)
        (tmp / "config/policy").mkdir(parents=True)
        shutil.copy(root / "vibesec.yaml", tmp / "vibesec.yaml")
        shutil.copy(root / "config/policy/blocking-policy.yaml", tmp / "config/policy/blocking-policy.yaml")
        write_exceptions(tmp, exceptions)
        yield tmp


@contextlib.contextmanager
def broken_policy_root():
    """selftest 用：blocking-policy.yaml 是壞 YAML 的暫存 root（其餘照本 repo）；load_policy 會回傳 (None, 未完成原因)。"""
    with temp_policy_root() as tmp:
        (tmp / "config/policy/blocking-policy.yaml").write_text("blocking: [\n", encoding="utf-8")
        yield tmp


def set_mode_line(vibesec_yaml: pathlib.Path, mode_line: str) -> None:
    """selftest 用：把 vibesec.yaml 唯一的最上層 `mode:` 行換成 mode_line（空字串 → 拿掉這一行）；找不到或不唯一 → RuntimeError。"""
    import re
    text, n = re.subn(r"(?m)^mode:.*(\n|$)", (mode_line + "\n") if mode_line else "", vibesec_yaml.read_text(encoding="utf-8"))
    if n != 1:
        raise RuntimeError(f"{vibesec_yaml}：找不到唯一的最上層 mode")
    vibesec_yaml.write_text(text, encoding="utf-8")


@contextlib.contextmanager
def mode_policy_root(mode_line: str):
    """selftest 用：vibesec.yaml 的最上層 mode 行換成 mode_line 的暫存 root（例如 "mode: enforce"、"mode: x"；空字串 → 拿掉），
    其餘照本 repo（同 temp_policy_root：沒有政策例外）。給可以注入 policy_root= 的閘門進入點用。"""
    with temp_policy_root() as tmp:
        set_mode_line(tmp / "vibesec.yaml", mode_line)
        yield tmp


def modeless_policy_root():
    """selftest 用：vibesec.yaml 沒有最上層 mode 的暫存 root；load_policy 會回報 mode 缺席（政策讀不到）。"""
    return mode_policy_root("")


@contextlib.contextmanager
def trusted_tree(mode_line: str):
    """selftest 用：受信任樹副本（scripts、config、schemas、vibesec.yaml），vibesec.yaml 的 mode 行換成 mode_line（空字串 → 拿掉）。
    給只能經命令列執行、無法注入 policy_root 的測試（例如 CI 以 python3 -I 執行的 g4_static）。yield 暫存 root。"""
    import shutil, tempfile
    with tempfile.TemporaryDirectory(prefix="vibesec-tree-") as d:
        tree = pathlib.Path(d)
        for sub in ("scripts", "config", "schemas"):
            shutil.copytree(DEFAULT_ROOT / sub, tree / sub, ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copy(DEFAULT_ROOT / "vibesec.yaml", tree / "vibesec.yaml")
        set_mode_line(tree / "vibesec.yaml", mode_line)
        yield tree


def write_exceptions(root: pathlib.Path, exceptions) -> None:
    """selftest 用：把 root 的 blocking-policy.yaml 的 exceptions 換成 exceptions，其餘照舊。"""
    path = pathlib.Path(root) / "config/policy/blocking-policy.yaml"
    pol = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    path.write_text(yaml.safe_dump(dict(pol, exceptions=list(exceptions)), allow_unicode=True), encoding="utf-8")


def selftest() -> list[str]:
    import tempfile
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as d:
        root = pathlib.Path(d); (root / "config/policy").mkdir(parents=True)
        (root / "config/policy/blocking-policy.yaml").write_text(yaml.safe_dump({
            "default_tier": "advisory",
            "blocking": [{"rule_id": "vibesec.g9.a", "why": "x"}],
            "advisory": [{"rule_id": "vibesec.g9.b", "why": "x"}],
            "tier_overrides": {"L3": {"promote_to_blocking": ["vibesec.g9.b"], "demote_to_advisory": ["vibesec.g9.a"]}}}))
        (root / "vibesec.yaml").write_text("mode: shadow\nrisk_tier: L3\n")
        p = Policy(root)
        checks = [
            (p.base_tier("vibesec.g9.a"), "blocking", "blocking 清單 → base blocking"),
            (p.tier("vibesec.g9.a"), "advisory", "L3 demote → 有效 advisory"),
            (p.base_tier("vibesec.g9.b"), "advisory", "advisory 清單 → base advisory"),
            (p.tier("vibesec.g9.b"), "blocking", "L3 promote → 有效 blocking"),
            (p.tier("vibesec.g9.unlisted"), "advisory", "未列的 vibesec 規則 → advisory"),
            (p.tier("semgrep:foo"), "advisory", "外部規則 → default_tier"),
            (p.cap("vibesec.g9.b", "advisory"), "advisory", "cap：呼叫端可降級"),
            (p.cap("vibesec.g9.a", "blocking"), "advisory", "cap：呼叫端不能升到政策以上"),
            (Policy(root, risk_tier="L2").tier("vibesec.g9.b"), "advisory", "L2 無 override"),
            (sorted(p.effective_blocking()), ["vibesec.g9.b"], "effective_blocking"),
        ]
        for got, want, label in checks:
            if got != want:
                fails.append(f"{label}：得到 {got!r}，預期 {want!r}")
        # risk_tier 打錯（小寫、不存在的層級、非字串）→ 例外，不得靜默取不到 override（以前 l3 讓 L3 升級規則消失）
        for bad in ("l3", "L4", "", None, 3):
            (root / "vibesec.yaml").write_text(yaml.safe_dump({"mode": "shadow", "risk_tier": bad}))
            try:
                Policy(root); fails.append(f"risk_tier={bad!r} 應拋出例外")
            except ValueError:
                pass
        (root / "vibesec.yaml").write_text("mode: shadow\nproject: {name: x}\n")
        if Policy(root).risk_tier != "L2":
            fails.append("vibesec.yaml 未設定 risk_tier → 預設 L2")
        # applies_only_to_gates：清單外閘門的規則有效 tier 為 advisory（發現保留、不阻擋）；分不出閘門的規則不降級。
        # 假規則 ID 在執行期組出：validate.py 會掃 scripts/ 原文中的 vibesec.g<0-6>.* 是否都在 cwe-map
        g1a, g3a, g3b, g4p = ("vibesec." + x for x in ("g1.a", "g3.a", "g3.b", "g4.p"))
        pol = {"default_tier": "advisory",
               "blocking": [{"rule_id": r, "why": "x"} for r in (g1a, g3a, "gitleaks:aws", "semgrep:x",
                                                                 "trivy:AVD-1", "zap:40018", "custom-rule")],
               "tier_overrides": {"L1": {"applies_only_to_gates": ["G1", "G2"], "promote_to_blocking": [g4p]},
                                  "L3": {"promote_to_blocking": [g3b]}}}
        (root / "config/policy/blocking-policy.yaml").write_text(yaml.safe_dump(pol))
        l1, l3 = Policy(root, risk_tier="L1"), Policy(root, risk_tier="L3")
        for rid, want in [(g1a, "blocking"), ("gitleaks:aws", "blocking"), (g3a, "advisory"),
                          ("semgrep:x", "advisory"), ("zap:40018", "advisory"),
                          (g4p, "advisory"),             # promote 也不能讓清單外閘門的規則阻擋
                          ("trivy:AVD-1", "blocking"),              # trivy 同時用於 G1／G3，分不出 → 不降級
                          ("custom-rule", "blocking")]:             # 無閘門資訊 → 不降級（fail closed）
            if l1.tier(rid) != want:
                fails.append(f"L1 applies_only_to_gates：{rid} 應為 {want}（得到 {l1.tier(rid)}）")
        if sorted(l1.effective_blocking()) != ["custom-rule", "gitleaks:aws", "trivy:AVD-1", g1a]:
            fails.append(f"L1 effective_blocking 應排除清單外閘門（得到 {sorted(l1.effective_blocking())}）")
        if l3.tier(g3a) != "blocking" or l3.applies_only_to_gates is not None:
            fails.append("沒有 applies_only_to_gates 的層級：所有閘門都套用")
        for bad_only in (["G7"], ["g1"], "G1"):
            (root / "config/policy/blocking-policy.yaml").write_text(yaml.safe_dump(
                {"tier_overrides": {"L1": {"applies_only_to_gates": bad_only}}}))
            try:
                Policy(root, risk_tier="L1"); fails.append(f"applies_only_to_gates={bad_only!r} 應拋出例外")
            except ValueError:
                pass
        (root / "config/policy/blocking-policy.yaml").write_text(yaml.safe_dump({"tier_overrides": {"L9": {}}}))
        try:
            Policy(root, risk_tier="L2"); fails.append("tier_overrides 有未知層級 L9 應拋出例外")
        except ValueError:
            pass
        # for_project → ProjectPolicy.classify：rule_id 相等且 fnmatchcase(path, path_glob) → 命中，tier 降為 advisory、發現保留
        ok_ex = {"rule_id": "vibesec.g9.a", "path_glob": "lab/**", "reason": "靶場", "approved_by": "@o", "expires": "2099-01-01"}
        want = {"path_glob": "lab/**", "reason": "靶場", "approved_by": "@o", "expires": "2099-01-01", "agent_id": None}
        (root / "config/policy/blocking-policy.yaml").write_text(yaml.safe_dump({"blocking": [{"rule_id": "vibesec.g9.a", "why": "x"}]}))
        base_policy = Policy(root, risk_tier="L2", project_root=None)

        def pps(entries, project=root, today=date(2026, 10, 13), project_root=None):
            (root / "config/policy/blocking-policy.yaml").write_text(yaml.safe_dump(
                {"blocking": [{"rule_id": "vibesec.g9.a", "why": "x"}], "exceptions": entries}))
            return Policy(root, risk_tier="L2", project_root=project_root).for_project(project, today=today)

        pp = pps([ok_ex])
        got = pp.classify("vibesec.g9.a", "lab/app/main.py")
        if got != {"policy_tier": "advisory", "exception": want}:
            fails.append(f"rule_id 與 path_glob 都符合 → advisory 並帶固定 5 欄的例外紀錄；得到 {got!r}")
        for rid, path in (("vibesec.g9.b", "lab/app/main.py"), ("vibesec.g9.a", "src/main.py"), ("vibesec.g9.a", None)):
            got = pp.classify(rid, path)
            if got != {"policy_tier": base_policy.tier(rid), "exception": None}:
                fails.append(f"rule_id 或 path 不符（{rid} @ {path}）→ 政策 tier、沒有例外紀錄；得到 {got!r}")
        # requested：呼叫端可先把個別發現降為 advisory（G1 的 cap），例外不命中時保留，不得回到政策 tier
        if pp.classify("vibesec.g9.a", "src/x", requested="advisory")["policy_tier"] != "advisory" \
                or pp.classify("vibesec.g9.a", "src/x", requested="blocking")["policy_tier"] != "blocking":
            fails.append("classify 的 requested 依 Policy.cap：只能降級、不能升到政策以上")
        # 缺欄位、expires 格式無效、非 dict → 不套用（fail closed）；ignored 文字與舊 g1_slopcheck.load_exceptions 逐字相同
        no_owner = {k: v for k, v in ok_ex.items() if k not in ("approved_by", "reason")}
        pp = pps(["不是 dict", no_owner, dict(ok_ex, expires="明年")])
        if pp.classify("vibesec.g9.a", "lab/app/main.py")["exception"]:
            fails.append("缺欄位或 expires 無效的例外不得命中")
        if pp.ignored != ["vibesec.g9.a：缺少欄位 reason, approved_by", "vibesec.g9.a：expires 格式無效（明年）"]:
            fails.append(f"ignored 文字不符：{pp.ignored!r}")
        if pps([{"path_glob": "lab/**"}]).ignored != ["?：缺少欄位 rule_id, reason, approved_by, expires"]:
            fails.append("缺 rule_id → ignored 以 ? 代替")
        # 過期：expires < today 才算過期（到期當日仍有效）；YAML 的日期值與字串同樣處理；today 在建立 context 時注入
        due = dict(ok_ex, expires="2026-10-13")
        if not pps([due]).classify("vibesec.g9.a", "lab/x")["exception"] \
                or not pps([dict(due, expires=date(2026, 10, 13))]).classify("vibesec.g9.a", "lab/x")["exception"]:
            fails.append("到期當日的例外仍有效")
        pp = pps([due], today=date(2026, 10, 14))
        if pp.classify("vibesec.g9.a", "lab/x")["exception"] or pp.ignored != ["vibesec.g9.a @ lab/**：已於 2026-10-13 過期"]:
            fails.append(f"過期的例外不得命中且記入 ignored；得到 {pp.ignored!r}")
        # agent_id 規則（AGENT_SCOPED_RULES，目前只有 G0 的致命三要素）：例外必須寫明相同的 agent_id 才命中；
        # 只寫 path_glob 的例外不放行任何 agent，並由 report 列為未套用。其他規則不看 agent_id
        g0r, x1, x2 = ("vibesec." + x for x in ("g0.lethal-trifecta-open", "g1.x", "g2.x"))   # 執行期組出：validate 會掃原文
        g0ex = dict(ok_ex, rule_id=g0r, path_glob="docs/tm.yaml")
        pp = pps([dict(g0ex, agent_id="a")])
        if pp.classify(g0r, "docs/tm.yaml", agent_id="a")["exception"] != dict(want, path_glob="docs/tm.yaml", agent_id="a") \
                or pp.classify(g0r, "docs/tm.yaml", agent_id="b")["exception"] \
                or pp.classify(g0r, "docs/tm.yaml")["exception"]:
            fails.append("agent_id 規則：agent_id 相同才命中（沒傳 agent_id 也不命中）")
        pp = pps([g0ex])
        if pp.classify(g0r, "docs/tm.yaml", agent_id="a")["exception"]:
            fails.append("agent_id 規則：未寫 agent_id 的例外不得命中")
        if pp.report([], "G0", paths=["docs/tm.yaml"]) != [f"忽略的例外：{g0r} @ docs/tm.yaml：G0 例外缺 agent_id，未套用"] \
                or pp.report([], "G1", paths=["docs/tm.yaml"]) != [] or pp.ignored != []:
            fails.append(f"agent_id 規則：缺 agent_id 的例外只列在本閘門的 report（不列入 ignored）；得到 {pp.report([], 'G0', paths=['docs/tm.yaml'])!r}")
        # 只列 path_glob 符合閘門比對路徑的（與有沒有發現無關）；沒給路徑或路徑不符 → 不列
        if pp.report([], "G0", paths=["other/tm.yaml"]) != [] or pp.report([], "G0") != []:
            fails.append("agent_id 規則：缺 agent_id 的例外只列 path_glob 符合比對路徑的")
        if not pps([dict(ok_ex, agent_id="a")]).classify("vibesec.g9.a", "lab/x")["exception"]:
            fails.append("其他規則不看例外的 agent_id")
        # report：閘門 status_reason 的例外說明（各閘門相同的文字）
        hit = {"exception": want}
        got = pps([ok_ex]).report([hit, {}, hit], "G9")
        if got != ["2 筆命中 blocking-policy 例外（blocking 降為 advisory，發現保留）"]:
            fails.append(f"report：命中筆數說明；得到 {got!r}")
        if pps([ok_ex]).report([{}], "G9") != []:
            fails.append("report：沒有命中、沒有忽略的例外 → 不加說明")
        # 忽略的例外只列本閘門的規則（rule_gate）；分不出閘門的（缺 rule_id、trivy:）每個閘門都列，寧可重複不可漏看
        old = dict(ok_ex, expires="2026-01-01")
        pp = pps([dict(old, rule_id=x1), dict(old, rule_id=x2), {"path_glob": "lab/**"}, dict(old, rule_id="trivy:AVD-1"),
                  dict(ok_ex, rule_id=g0r, path_glob="docs/tm.yaml")])
        common = "?：缺少欄位 rule_id, reason, approved_by, expires；trivy:AVD-1 @ lab/**：已於 2026-01-01 過期"
        for gate, mine in (("G2", x2), ("G1", x1)):
            got = pp.report([], gate)
            if got != [f"忽略的例外：{mine} @ lab/**：已於 2026-01-01 過期；{common}"]:
                fails.append(f"report {gate}：只列本閘門與分不出閘門的忽略例外；得到 {got!r}")
        # 缺 agent_id 而未套用的例外與忽略的例外同列，接在後面、同一個前綴
        got = pp.report([], "G0", paths=["docs/tm.yaml"])
        if got != [f"忽略的例外：{common}；{g0r} @ docs/tm.yaml：G0 例外缺 agent_id，未套用"]:
            fails.append(f"report G0：缺 agent_id 的例外接在忽略的例外之後；得到 {got!r}")
        if len(pp.ignored) != 4:
            fails.append(f"ignored 仍列出全部忽略的例外（G1 stdout 用）；得到 {pp.ignored!r}")
        # 外部專案：例外只核准給本 repo 路徑 → 不套用、不列 ignored，附說明；受驗樹是本 repo → 套用
        (root / "other").mkdir()
        pp = pps([ok_ex, no_owner, g0ex], project=root / "other")
        if pp.classify("vibesec.g9.a", "lab/x") != {"policy_tier": "blocking", "exception": None} or pp.ignored \
                or pp.report([], "G0", paths=["docs/tm.yaml"]) != [] or pp.note != "目標專案 other：blocking-policy exceptions 只核准給本 repo 路徑，未套用":
            fails.append(f"外部專案 → 不套用例外並附說明；得到 note={pp.note!r} ignored={pp.ignored!r}")
        for same in (root, root / "other" / ".."):
            pp = pps([ok_ex], project=same)
            if pp.note is not None or not pp.classify("vibesec.g9.a", "lab/x")["exception"]:
                fails.append(f"受驗樹 {same} 是本 repo → 套用例外")
        # 受驗樹必填：None 不再代表「本 repo」（以前 exceptions_for(None) 是預設值，外部專案忘了換就套用本 repo 的例外）
        try:
            base_policy.for_project(None); fails.append("for_project(None) 應拋出例外")
        except (TypeError, ValueError):
            pass
        # project_root（CI：判定程式在 _trusted/、受驗樹在 workspace，兩者都是本 repo）：等於它的受驗樹也算本 repo
        (root / "proj").mkdir()
        pp_ = Policy(root, risk_tier="L2", project_root=root / "proj")
        got = [pp_.is_this_repo(t) for t in (None, root, root / "proj", root / "other" / ".." / "proj", root / "other")]
        if got != [True, True, True, True, False]:
            fails.append(f"is_this_repo（None、root、project_root、project_root 別名、其他目錄）應為 T T T T F；得到 {got}")
        pp = pps([ok_ex], project=root / "proj", project_root=root / "proj")
        if pp.note is not None or not pp.classify("vibesec.g9.a", "lab/x")["exception"]:
            fails.append("受驗樹等於 project_root → 本 repo，套用例外")
        # project_root 不是存在的目錄（打錯、未取出）→ 不因此認定本 repo（fail closed：例外不套用）
        for bad in (root / "nope", root / "vibesec.yaml"):
            if Policy(root, risk_tier="L2", project_root=bad).is_this_repo(bad):
                fails.append(f"project_root={bad.name} 不是存在的目錄 → 不算本 repo")
        if pps([ok_ex], project=root / "nope", project_root=root / "nope").note is None:
            fails.append("project_root 不是存在的目錄 → 受驗樹視為外部專案，例外不套用")
        # 沒傳 project_root → 取環境變數 VIBESEC_PROJECT_ROOT（CI 由受信任的 workflow 設定）；明確傳 None → 不讀（selftest 用）
        saved = os.environ.pop("VIBESEC_PROJECT_ROOT", None)
        try:
            if Policy(root, risk_tier="L2").is_this_repo(root / "proj"):
                fails.append("未設定 VIBESEC_PROJECT_ROOT → 只有 root 是本 repo")
            os.environ["VIBESEC_PROJECT_ROOT"] = str(root / "proj")
            if not Policy(root, risk_tier="L2").is_this_repo(root / "proj"):
                fails.append("沒傳 project_root → 取 VIBESEC_PROJECT_ROOT")
            if Policy(root, risk_tier="L2", project_root=None).is_this_repo(root / "proj"):
                fails.append("明確傳 project_root=None → 不讀 VIBESEC_PROJECT_ROOT")
        finally:
            os.environ.pop("VIBESEC_PROJECT_ROOT", None)
            if saved is not None:
                os.environ["VIBESEC_PROJECT_ROOT"] = saved
        # incomplete_gate_is_blocking_in_enforce 打錯（G7、小寫、非清單）→ 例外：以前靜默忽略，該閘門 incomplete 就不阻擋了
        for bad_gates in (["G1", "G7"], ["g1"], "G1"):
            (root / "config/policy/blocking-policy.yaml").write_text(yaml.safe_dump({"incomplete_gate_is_blocking_in_enforce": bad_gates}))
            try:
                Policy(root, risk_tier="L2"); fails.append(f"incomplete_gate_is_blocking_in_enforce={bad_gates!r} 應拋出例外")
            except ValueError:
                pass
        (root / "config/policy/blocking-policy.yaml").write_text(yaml.safe_dump({"incomplete_gate_is_blocking_in_enforce": ["G1", "G2"]}))
        if Policy(root, risk_tier="L2").incomplete_blocking_gates != ["G1", "G2"]:
            fails.append("合法的 incomplete_gate_is_blocking_in_enforce 照常讀入")
    # load_policy：閘門開始時建立一次 Policy；政策檔缺席、壞 YAML、不合法 → (None, 未完成原因)，不拋出例外
    with temp_policy_root() as tmp:
        got, problem = load_policy(tmp, project_root=None)
        if not isinstance(got, Policy) or problem is not None:
            fails.append(f"load_policy：政策可讀 → (Policy, None)；得到 {got!r}、{problem!r}")
        pf = tmp / "config/policy/blocking-policy.yaml"
        for label, body in (("壞 YAML", "blocking: [\n  - {rule_id: x\n"), ("risk_tier 不合法", None), ("缺檔", "")):
            if label == "risk_tier 不合法":
                (tmp / "vibesec.yaml").write_text("risk_tier: l3\n", encoding="utf-8")
            elif label == "缺檔":
                (tmp / "vibesec.yaml").write_text("risk_tier: L2\n", encoding="utf-8"); pf.unlink()
            else:
                pf.write_text(body, encoding="utf-8")
            got, problem = load_policy(tmp, project_root=None)
            if got is not None or not (problem or "").startswith(POLICY_UNREADABLE + "（"):
                fails.append(f"load_policy：{label} → (None, 「blocking-policy 無法讀取（…）」)；得到 {got!r}、{problem!r}")
            if label == "壞 YAML":
                pf.write_text("{}\n", encoding="utf-8")
    # temp_policy_root：本 repo 政策的副本只換掉 exceptions（tier 與本 repo 相同）；離開時刪除
    ex = {"rule_id": "vibesec.g2.hardcoded-secret", "path_glob": "x/**", "reason": "r", "approved_by": "@o", "expires": "2099-01-01"}
    with temp_policy_root([ex]) as tmp:
        tp = Policy(tmp, project_root=None)
        if tp._exceptions != [ex] or tp.tier("vibesec.g2.hardcoded-secret") != Policy(project_root=None).tier("vibesec.g2.hardcoded-secret"):
            fails.append("temp_policy_root：只換掉 exceptions，tier 與本 repo 政策相同")
        write_exceptions(tmp, [])
        if Policy(tmp, project_root=None)._exceptions:
            fails.append("write_exceptions：換掉 exceptions")
    with broken_policy_root() as tmp:
        if load_policy(tmp, project_root=None)[0] is not None:
            fails.append("broken_policy_root：load_policy 應讀不到")
    with modeless_policy_root() as tmp:
        if load_policy(tmp, project_root=None)[1] != f"{POLICY_UNREADABLE}（vibesec.yaml 缺 mode；須為 shadow／enforce）":
            fails.append("modeless_policy_root：load_policy 應回報 mode 缺席")
    with mode_policy_root("mode: enforce") as tmp:
        if getattr(load_policy(tmp, project_root=None)[0], "mode", None) != "enforce":
            fails.append("mode_policy_root：mode 行換成 enforce")
    with trusted_tree("mode: enforce") as tree:
        if not (tree / "scripts/vibesec_mode.py").is_file() or getattr(load_policy(tree, project_root=None)[0], "mode", None) != "enforce":
            fails.append("trusted_tree：含 scripts、政策與換過 mode 的 vibesec.yaml")
    if tmp.exists():
        fails.append("temp_policy_root：離開時刪除暫存 root")
    # 契約：record() 的形狀就是 finding.schema.json 的 exception（harness 原樣搬進 findings.json）；缺欄、多欄、型別不符 → 不通過
    import json
    from jsonschema import Draft202012Validator as V
    schema = json.loads((DEFAULT_ROOT / "schemas/finding.schema.json").read_text(encoding="utf-8"))
    finding = json.loads((DEFAULT_ROOT / "docs/templates/finding.example.json").read_text(encoding="utf-8"))
    rec = _record({"rule_id": "r", "path_glob": "lab/**", "reason": "靶場", "approved_by": "@o", "expires": "2099-01-01"})
    ok = lambda exc: not list(V(schema, format_checker=V.FORMAT_CHECKER).iter_errors(dict(finding, exception=exc)))
    if not ok(rec) or not ok(dict(rec, agent_id="a")):
        fails.append("finding.schema.json 接受 record() 的 exception（agent_id 為 null 或字串）")
    for label, bad in (("缺 reason", {k: v for k, v in rec.items() if k != "reason"}), ("多 rule_id", dict(rec, rule_id="r")),
                       ("agent_id 非字串", dict(rec, agent_id=3)), ("expires 不是日期", dict(rec, expires="明年")),
                       ("approved_by 空字串", dict(rec, approved_by=""))):
        if ok(bad):
            fails.append(f"finding.schema.json 的 exception 應拒絕：{label}")
    # mode（#200）：Policy 讀 vibesec.yaml 時以 vibesec_mode.read_mode 取得，沒有預設值；缺席或不合法 → load_policy 回報
    # 「政策讀不到」的一種（前綴 POLICY_UNREADABLE），閘門既有的讀不到路徑直接涵蓋。mode_override 只能把 shadow 升為 enforce
    with temp_policy_root() as tmp:
        vbp = tmp / "vibesec.yaml"
        base_text = vbp.read_text(encoding="utf-8")
        def with_mode(line):   # 每一輪都從原本的內容改起
            vbp.write_text(base_text, encoding="utf-8")
            set_mode_line(vbp, line)
        for label, line, want in [
                ("缺席", "", f"{POLICY_UNREADABLE}（vibesec.yaml 缺 mode；須為 shadow／enforce）"),
                ("不合法", "mode: x", f"{POLICY_UNREADABLE}（vibesec.yaml 的 mode 不合法：'x'；須為 shadow／enforce）"),
                ("大小寫", "mode: Enforce", f"{POLICY_UNREADABLE}（vibesec.yaml 的 mode 不合法：'Enforce'；須為 shadow／enforce）")]:
            with_mode(line)
            got = load_policy(tmp, project_root=None)
            if got != (None, want):
                fails.append(f"load_policy：mode {label} → (None, {want!r})（得到 {got[0] is not None and 'Policy' or None}, {got[1]!r}）")
            try:
                Policy(tmp, project_root=None); fails.append(f"Policy()：mode {label} 應拋出 ValueError")
            except ValueError:
                pass
        for cfg, override, want_mode, want_note in [
                ("shadow", None, "shadow", False), ("enforce", None, "enforce", False),
                ("shadow", "", "shadow", False), ("shadow", "enforce", "enforce", False),
                ("enforce", "enforce", "enforce", False), ("shadow", "shadow", "shadow", False),
                ("enforce", "shadow", "enforce", True)]:
            with_mode(f"mode: {cfg}")
            p, problem = load_policy(tmp, project_root=None, mode_override=override)
            got = (p.mode, bool(p.mode_note)) if p else problem
            if got != (want_mode, want_note):
                fails.append(f"mode_override：設定 {cfg}、覆寫 {override!r} → {want_mode}、附註={want_note}（得到 {got}）")
        with_mode("mode: enforce")
        p, _ = load_policy(tmp, project_root=None, mode_override="shadow")
        if not p or "shadow" not in (p.mode_note or "") or "enforce" not in (p.mode_note or ""):
            fails.append(f"忽略降級的附註應寫明覆寫值與設定值（得到 {p and p.mode_note!r}）")
        for bad in ("x", "Enforce", 3):
            got = load_policy(tmp, project_root=None, mode_override=bad)
            if got[0] is not None or not (got[1] or "").startswith(POLICY_UNREADABLE + "（") or repr(bad) not in (got[1] or ""):
                fails.append(f"mode_override 不合法（{bad!r}）→ 政策讀不到並附上讀到的值，不得忽略（得到 {got[1]!r}）")
    # 本 repo 的實際政策：L1 下 G3 規則不阻擋、G1／G2 照常；L3 的升級規則仍在
    real_l1, real_l3 = Policy(risk_tier="L1"), Policy(risk_tier="L3")
    if real_l1.tier("vibesec.g3.sql-string-concat") != "advisory" or real_l1.tier("vibesec.g2.hardcoded-secret") != "blocking":
        fails.append("實際政策 L1：G3 規則應為 advisory、G2 規則照常 blocking")
    if real_l3.tier("vibesec.g4.missing-owner-filter") != "blocking":
        fails.append("實際政策 L3：missing-owner-filter 應升為 blocking")
    return fails


def main(argv: list[str]) -> int:
    if argv[1:2] == ["selftest"]:
        fails = selftest()
        for f in fails: print(f"FAIL {f}")
        print("selftest " + ("通過" if not fails else f"失敗 {len(fails)} 項"))
        return 1 if fails else 0
    if len(argv) < 2:
        print(__doc__); return 2
    p = Policy()
    for rid in argv[1:]:
        print(f"{rid} {p.tier(rid)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
