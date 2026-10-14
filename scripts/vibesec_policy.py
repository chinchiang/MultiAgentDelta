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
  e = p.exceptions_for(target=None, today=None)   # blocking-policy 的 exceptions（G0–G3 唯一的讀取與比對）
  e.match(rule_id, path, agent_id=None)           # 命中的例外或 None；呼叫端把 blocking 降為 advisory、發現保留
  e.ignored / e.applies / e.note                  # 被忽略的例外說明／是否套用／外部專案的說明

exceptions：欄位（rule_id、path_glob、reason、approved_by、expires）缺一、expires 格式無效、已過期（expires < today；
到期當日仍有效）→ 不套用並列入 ignored；path_glob 以 fnmatch.fnmatchcase 比對（單一 * 也會跨越 /）。
p.is_this_repo(target)：None、root，或 project_root（存在的目錄）→ 本 repo；其他 → 外部專案，例外全部不套用
（例外只核准給本 repo 路徑）。project_root 是「判定程式與受驗樹分開」時的受驗樹（CI：_trusted/ 與 workspace），
預設取環境變數 VIBESEC_PROJECT_ROOT（由受信任的 workflow 設定）；明確傳 None ＝ 沒有（selftest 用）。

  python3 scripts/vibesec_policy.py <rule_id>...    # 每行印出「<rule_id> <有效 tier>」（給 shell 步驟用）
  python3 scripts/vibesec_policy.py selftest

政策檔缺席或無法解析、risk_tier／tier_overrides／applies_only_to_gates／incomplete_gate_is_blocking_in_enforce
不合法 → 例外（incomplete ≠ pass，CLAUDE.md #2）；要改政策必須由人類在獨立 PR 決定（規則 1）。
"""
from __future__ import annotations
import fnmatch, os, pathlib, sys
from datetime import date

try:
    import yaml
except ImportError:
    print("工具缺席：PyYAML；無法讀取阻擋政策", file=sys.stderr)
    sys.exit(2)

DEFAULT_ROOT = pathlib.Path(__file__).resolve().parent.parent
# Policy(project_root=…) 的預設：取環境變數 VIBESEC_PROJECT_ROOT；明確傳 None ＝ 沒有 project_root（selftest 用，不受環境影響）
FROM_ENV = object()
TIERS = ("blocking", "advisory")
GATES = ("G0", "G1", "G2", "G3", "G4", "G5", "G6")
EXCEPTION_FIELDS = ("rule_id", "path_glob", "reason", "approved_by", "expires")   # exceptions 必填（缺一 → 不套用）
RISK_TIERS = ("L1", "L2", "L3")             # vibesec.yaml risk_tier（docs/01 決策樹）
# 外部工具規則前綴 → 閘門（applies_only_to_gates 用）。trivy 同時用於 G1（漏洞）與 G3（IaC 設定），
# 從規則 ID 分不出閘門 → 不列，不因 applies_only_to_gates 降級（fail closed）。
TOOL_GATE = {"gitleaks": "G2", "semgrep": "G3", "checkov": "G3", "zap": "G5", "promptfoo": "G6", "garak": "G6", "grype": "G1"}


def rule_gate(rule_id: str) -> str | None:
    """規則所屬閘門：vibesec.g<N>.* → G<N>；外部工具依 TOOL_GATE；分不出 → None。"""
    rid = str(rule_id)
    if rid.startswith("vibesec.g") and rid[9:10].isdigit() and rid[10:11] == ".":
        return f"G{rid[9]}"
    return TOOL_GATE.get(rid.split(":", 1)[0]) if ":" in rid else None


class Policy:
    def __init__(self, root: pathlib.Path | str | None = None, risk_tier: str | None = None,
                 project_root: pathlib.Path | str | None | object = FROM_ENV):
        self.root = pathlib.Path(root) if root else DEFAULT_ROOT
        if project_root is FROM_ENV:
            project_root = os.environ.get("VIBESEC_PROJECT_ROOT")
        self.project_root = pathlib.Path(project_root) if project_root else None
        pol = yaml.safe_load((self.root / "config/policy/blocking-policy.yaml").read_text(encoding="utf-8")) or {}
        if risk_tier is None:
            vb = yaml.safe_load((self.root / "vibesec.yaml").read_text(encoding="utf-8")) or {}
            risk_tier = vb.get("risk_tier", "L2")
        overrides = pol.get("tier_overrides") or {}
        # risk_tier 必須是 vibesec.yaml 定義的層級（L1／L2／L3）：以前 l3、L4 這類打錯的值靜默取不到任何 override，
        # L3 的升級規則就消失了（例如 missing-owner-filter 變回 advisory）。打錯 → 例外（fail closed）
        if risk_tier not in RISK_TIERS:
            raise ValueError(f"risk_tier 不合法：{risk_tier!r}（須為 {'／'.join(RISK_TIERS)}）")
        if not set(overrides) <= set(RISK_TIERS):
            raise ValueError(f"blocking-policy tier_overrides 有未知層級：{sorted(set(overrides) - set(RISK_TIERS))}")
        self.risk_tier = risk_tier
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
        self._exceptions = pol.get("exceptions") or []   # 政策檔只讀一次；exceptions_for 再篩選

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

    def exceptions_for(self, target=None, today=None) -> "Exceptions":
        # 外部專案（target 不是本 repo）：例外只核准給本 repo 路徑 → 全部不套用（fail closed）
        if not self.is_this_repo(target):
            return Exceptions([], [], note=f"目標專案 {pathlib.Path(target).name}：blocking-policy exceptions 只核准給本 repo 路徑，未套用")
        today = today or date.today()
        valid, ignored = [], []
        for ex in self._exceptions:
            if not isinstance(ex, dict):
                continue
            missing = [k for k in EXCEPTION_FIELDS if not ex.get(k)]
            if missing:
                ignored.append(f"{ex.get('rule_id', '?')}：缺少欄位 {', '.join(missing)}")
                continue
            exp = ex["expires"]
            try:
                exp = exp if isinstance(exp, date) else date.fromisoformat(str(exp))
            except ValueError:
                ignored.append(f"{ex['rule_id']}：expires 格式無效（{ex['expires']}）")
                continue
            if exp < today:
                ignored.append(f"{ex['rule_id']} @ {ex['path_glob']}：已於 {exp} 過期")
                continue
            valid.append(dict(ex, expires=str(exp)))
        return Exceptions(valid, ignored)


class Exceptions:
    """blocking-policy 的 exceptions（Policy.exceptions_for 產生）。"""
    def __init__(self, valid: list[dict], ignored: list[str], note: str | None = None):
        self.valid, self.ignored, self.note = valid, ignored, note
        self.applies = note is None          # False：外部專案，note 說明為何未套用

    def matches(self, rule_id: str, path: str) -> list[dict]:
        """rule_id 相等且 fnmatchcase(path, path_glob) 的全部例外（不看 agent_id）。"""
        return [ex for ex in self.valid if ex["rule_id"] == rule_id and fnmatch.fnmatchcase(path, ex["path_glob"])]

    def match(self, rule_id: str, path: str, agent_id: str | None = None) -> dict | None:
        """matches 的第一筆；沒有 → None。
        傳了 agent_id（G0）→ 例外也必須寫明相同的 agent_id：只寫 path_glob 會連同之後新增的 agent 一起放行。"""
        return next((ex for ex in self.matches(rule_id, path) if agent_id is None or ex.get("agent_id") == agent_id), None)


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
        (root / "vibesec.yaml").write_text("risk_tier: L3\n")
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
            (root / "vibesec.yaml").write_text(yaml.safe_dump({"risk_tier": bad}))
            try:
                Policy(root); fails.append(f"risk_tier={bad!r} 應拋出例外")
            except ValueError:
                pass
        (root / "vibesec.yaml").write_text("project: {name: x}\n")
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
        # exceptions_for：rule_id 相等且 fnmatchcase(path, path_glob) → 命中（只降為 advisory、發現保留由呼叫端處理）
        ok_ex = {"rule_id": "vibesec.g9.a", "path_glob": "lab/**", "reason": "靶場", "approved_by": "@o", "expires": "2099-01-01"}

        def exs(entries, target=None, today=date(2026, 10, 13)):
            (root / "config/policy/blocking-policy.yaml").write_text(yaml.safe_dump({"exceptions": entries}))
            return Policy(root, risk_tier="L2", project_root=None).exceptions_for(target, today=today)

        e = exs([ok_ex])
        hit = e.match("vibesec.g9.a", "lab/app/main.py")
        if not hit or hit["approved_by"] != "@o" or hit["expires"] != "2099-01-01":
            fails.append(f"rule_id 與 path_glob 都符合 → 命中並帶核准資訊；得到 {hit!r}")
        if e.match("vibesec.g9.b", "lab/app/main.py") or e.match("vibesec.g9.a", "src/main.py"):
            fails.append("rule_id 或 path_glob 不符 → 不命中")
        # 缺欄位、expires 格式無效、非 dict → 不套用（fail closed）；ignored 文字與舊 g1_slopcheck.load_exceptions 逐字相同
        no_owner = {k: v for k, v in ok_ex.items() if k not in ("approved_by", "reason")}
        e = exs(["不是 dict", no_owner, dict(ok_ex, expires="明年")])
        if e.match("vibesec.g9.a", "lab/app/main.py"):
            fails.append("缺欄位或 expires 無效的例外不得命中")
        if e.ignored != ["vibesec.g9.a：缺少欄位 reason, approved_by", "vibesec.g9.a：expires 格式無效（明年）"]:
            fails.append(f"ignored 文字不符：{e.ignored!r}")
        if exs([{"path_glob": "lab/**"}]).ignored != ["?：缺少欄位 rule_id, reason, approved_by, expires"]:
            fails.append("缺 rule_id → ignored 以 ? 代替")
        # 過期：expires < today 才算過期（到期當日仍有效）；YAML 的日期值與字串同樣處理
        due = dict(ok_ex, expires="2026-10-13")
        if not exs([due]).match("vibesec.g9.a", "lab/x") or not exs([dict(due, expires=date(2026, 10, 13))]).match("vibesec.g9.a", "lab/x"):
            fails.append("到期當日的例外仍有效")
        e = exs([due], today=date(2026, 10, 14))
        if e.match("vibesec.g9.a", "lab/x") or e.ignored != ["vibesec.g9.a @ lab/**：已於 2026-10-13 過期"]:
            fails.append(f"過期的例外不得命中且記入 ignored；得到 {e.ignored!r}")
        # agent_id（G0）：有傳時例外必須寫明相同的 agent_id；只寫 path_glob 的例外不放行任何 agent。沒傳 → 不看 agent_id
        e = exs([dict(ok_ex, agent_id="a")])
        if not e.match("vibesec.g9.a", "lab/x", agent_id="a") or e.match("vibesec.g9.a", "lab/x", agent_id="b"):
            fails.append("agent_id 相同才命中")
        if exs([ok_ex]).match("vibesec.g9.a", "lab/x", agent_id="a"):
            fails.append("傳了 agent_id 時，未寫 agent_id 的例外不得命中")
        if not e.match("vibesec.g9.a", "lab/x"):
            fails.append("沒傳 agent_id → 不看例外的 agent_id")
        # matches：rule_id 與 path_glob 都符合的全部例外（不看 agent_id；G0 用來註明缺 agent_id 的例外）
        e = exs([dict(ok_ex, agent_id="a"), ok_ex, dict(ok_ex, path_glob="src/**")])
        if [x.get("agent_id") for x in e.matches("vibesec.g9.a", "lab/x")] != ["a", None]:
            fails.append(f"matches 回傳 rule_id 與 path_glob 都符合的全部例外；得到 {e.matches('vibesec.g9.a', 'lab/x')!r}")
        # 外部專案：例外只核准給本 repo 路徑 → 不套用、不列 ignored，附說明；target 為 None 或本 repo → 套用
        (root / "other").mkdir()
        e = exs([ok_ex, no_owner], target=root / "other")
        if e.applies or e.match("vibesec.g9.a", "lab/x") or e.ignored \
                or e.note != "目標專案 other：blocking-policy exceptions 只核准給本 repo 路徑，未套用":
            fails.append(f"外部專案 → 不套用例外並附說明；得到 applies={e.applies!r} note={e.note!r} ignored={e.ignored!r}")
        for same in (None, root, root / "other" / ".."):
            e = exs([ok_ex], target=same)
            if not e.applies or e.note is not None or not e.match("vibesec.g9.a", "lab/x"):
                fails.append(f"target={same!r} 是本 repo → 套用例外")
        # project_root（CI：判定程式在 _trusted/、受驗樹在 workspace，兩者都是本 repo）：等於它的 target 也算本 repo
        (root / "proj").mkdir()
        pp = Policy(root, risk_tier="L2", project_root=root / "proj")
        got = [pp.is_this_repo(t) for t in (None, root, root / "proj", root / "other" / ".." / "proj", root / "other")]
        if got != [True, True, True, True, False]:
            fails.append(f"is_this_repo（None、root、project_root、project_root 別名、其他目錄）應為 T T T T F；得到 {got}")
        e = pp.exceptions_for(root / "proj", today=date(2026, 10, 13))
        if not e.applies or e.note is not None or not e.match("vibesec.g9.a", "lab/x"):
            fails.append("target 等於 project_root → 本 repo，套用例外")
        # project_root 不是存在的目錄（打錯、未取出）→ 不因此認定本 repo（fail closed：例外不套用）
        for bad in (root / "nope", root / "vibesec.yaml"):
            if Policy(root, risk_tier="L2", project_root=bad).is_this_repo(bad):
                fails.append(f"project_root={bad.name} 不是存在的目錄 → 不算本 repo")
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
