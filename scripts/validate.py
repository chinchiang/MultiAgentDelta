#!/usr/bin/env python3
"""VibeSec 自我驗證：YAML 語法、JSON Schema、範例檔、catalogs 與規則 ID 一致性。

退出碼 0 = 全通過；1 = 有錯誤。缺少的可選檔案只警告（WARN），不算失敗，
以便在部分檔案尚未產出時仍能先行驗證已存在者。
"""
from __future__ import annotations
import json, sys, glob, re, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
errors: list[str] = []
warns: list[str] = []
oks: list[str] = []

def ok(m): oks.append(m)
def err(m): errors.append(m)
def warn(m): warns.append(m)

# --- YAML 語法 ---
try:
    import yaml
except ImportError:
    yaml = None
    warn("PyYAML 未安裝，略過 YAML 語法檢查")

def load_yaml(p: pathlib.Path):
    if yaml is None:
        return None
    docs = list(yaml.safe_load_all(p.read_text()))
    return docs[0] if len(docs) == 1 else docs

if yaml is not None:
    for f in sorted(glob.glob(str(ROOT / "**/*.yaml"), recursive=True)) + \
             sorted(glob.glob(str(ROOT / "**/*.yml"), recursive=True)):
        rel = pathlib.Path(f).relative_to(ROOT)
        try:
            list(yaml.safe_load_all(open(f)))
            ok(f"YAML ok: {rel}")
        except Exception as e:
            err(f"YAML 解析失敗 {rel}: {e}")

# --- TOML 語法 ---
try:
    import tomllib
    gl = ROOT / "config/gitleaks.toml"
    if gl.exists():
        tomllib.loads(gl.read_text()); ok("TOML ok: config/gitleaks.toml")
    else:
        warn("缺 config/gitleaks.toml")
except Exception as e:
    err(f"TOML 解析失敗 config/gitleaks.toml: {e}")

# --- JSON 語法（schemas + 範例 + reports 範例）---
for f in sorted(glob.glob(str(ROOT / "schemas/*.json"))) + \
         sorted(glob.glob(str(ROOT / "docs/templates/*.json"))):
    rel = pathlib.Path(f).relative_to(ROOT)
    try:
        json.load(open(f)); ok(f"JSON ok: {rel}")
    except Exception as e:
        err(f"JSON 解析失敗 {rel}: {e}")

# --- JSON Schema 本身合法，且範例通過 schema ---
try:
    from jsonschema import Draft202012Validator
    schemas = {}
    for name in ("finding", "gate-result", "threat-model"):
        p = ROOT / f"schemas/{name}.schema.json"
        if p.exists():
            s = json.load(open(p)); Draft202012Validator.check_schema(s)
            schemas[name] = Draft202012Validator(s); ok(f"schema 合法: {name}")
        else:
            err(f"缺 schemas/{name}.schema.json")
    # 範例 finding
    ex = ROOT / "docs/templates/finding.example.json"
    if ex.exists() and "finding" in schemas:
        errs = sorted(schemas["finding"].iter_errors(json.load(open(ex))), key=str)
        if errs:
            for e in errs: err(f"finding.example.json 不符 schema: {e.message} @ {list(e.path)}")
        else: ok("finding.example.json 通過 schema")
    # 威脅模型模板
    tm = ROOT / "docs/templates/threat-model.yaml"
    if tm.exists() and "threat-model" in schemas and yaml is not None:
        errs = sorted(schemas["threat-model"].iter_errors(load_yaml(tm)), key=str)
        if errs:
            for e in errs: err(f"threat-model.yaml 不符 schema: {e.message} @ {list(e.path)}")
        else: ok("threat-model.yaml 通過 schema")
except ImportError:
    warn("jsonschema 未安裝，略過 schema 驗證")

# --- catalogs 與規則 ID 一致性 ---
def flatten_strings(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str): yield k        # 也收 mapping 的 key（rule_id/control_id 常為 key）
            yield from flatten_strings(v)
    elif isinstance(obj, list):
        for v in obj: yield from flatten_strings(v)
    elif isinstance(obj, str):
        yield obj

known_controls: set[str] = set()
known_cwes: set[str] = set()
known_rules: set[str] = set()

if yaml is not None:
    cwe_map = ROOT / "config/catalogs/cwe-map.yaml"
    if cwe_map.exists():
        data = load_yaml(cwe_map) or {}
        for s in flatten_strings(data):
            if re.fullmatch(r"CWE-\d+", s): known_cwes.add(s)
            if re.fullmatch(r"vibesec\.g[0-6]\.[a-z0-9-]+", s): known_rules.add(s)
            if re.fullmatch(r"(ASVS5-V\d+\.\d+(\.\d+)?|LLM\d{2}:2025|MAESTRO-L[1-7]|VS-G[0-6]-[A-Z0-9-]+)", s):
                known_controls.add(s)
    for cat in ("asvs-5.0-controls.yaml", "llm-top10-2025.yaml", "maestro-layers.yaml"):
        p = ROOT / "config/catalogs" / cat
        if p.exists():
            for s in flatten_strings(load_yaml(p) or {}):
                if re.fullmatch(r"(ASVS5-V\d+\.\d+(\.\d+)?|LLM\d{2}:2025|MAESTRO-L[1-7]|VS-G[0-6]-[A-Z0-9-]+)", s):
                    known_controls.add(s)
    sem = ROOT / "config/semgrep/vibesec-rules.yaml"
    if sem.exists():
        for s in flatten_strings(load_yaml(sem) or {}):
            if re.fullmatch(r"vibesec\.g[0-6]\.[a-z0-9-]+", s): known_rules.add(s)

    # 檢查 eval 案例引用的 control_id / rule_id 是否在目錄中
    for f in glob.glob(str(ROOT / "evals/cases/**/*.yaml"), recursive=True):
        rel = pathlib.Path(f).relative_to(ROOT)
        c = load_yaml(pathlib.Path(f)) or {}
        exp = (c.get("expected") or {})
        cid, rid = exp.get("control_id"), exp.get("rule_id")
        if cid and known_controls and cid not in known_controls:
            warn(f"{rel}: control_id {cid} 不在 catalogs（待 catalogs 補齊）")
        if rid and known_rules and rid not in known_rules:
            warn(f"{rel}: rule_id {rid} 不在 cwe-map/semgrep（待補齊）")

    # 範例 finding 的 control_id/cwe 一致性
    ex = ROOT / "docs/templates/finding.example.json"
    if ex.exists() and known_controls:
        d = json.load(open(ex))
        if d.get("control_id") and d["control_id"] not in known_controls:
            warn(f"finding.example.json control_id {d['control_id']} 不在 catalogs")

# --- 實際發出的規則 ID／控制 ID 必須在 catalogs（CLAUDE.md #3）---
# workflow 與 scripts 中寫死的 vibesec.gN.* 與 VS-G*-* 若不在目錄，該發現就查不到 CWE 與阻擋政策（等於被靜默降級）。
if yaml is not None and known_rules:
    _VARIANT = re.compile(r"-(supabase-)?js$")
    _emitters = sorted(glob.glob(str(ROOT / ".github/workflows/*.yml"))) + \
                sorted(f for f in glob.glob(str(ROOT / "scripts/*.py")) if not f.endswith("validate.py"))
    for f in _emitters:
        rel = pathlib.Path(f).relative_to(ROOT); txt = pathlib.Path(f).read_text(encoding="utf-8")
        bad_r = sorted({r for r in re.findall(r"vibesec\.g[0-6]\.[a-z0-9-]+", txt)
                        if r not in known_rules and _VARIANT.sub("", r) not in known_rules})
        bad_c = sorted({c for c in re.findall(r"VS-G[0-6]-[A-Z0-9-]*[A-Z0-9]", txt) if c not in known_controls})
        for r in bad_r: err(f"{rel}: 規則 ID {r} 不在 config/catalogs/cwe-map.yaml")
        for c in bad_c: err(f"{rel}: 控制 ID {c} 不在 config/catalogs")
        if not bad_r and not bad_c: ok(f"ID 一致: {rel}")

# --- cwe-map 的 implemented_by 必須指向 CI 實際會跑的工具規則 ---
# gitleaks:<id> 要在 config/gitleaks.toml；checkov:<id> 要在 .checkov.yaml 的 check allow-list（否則 CI 根本不跑），
# 自訂 CKV2_VIBESEC_* 還要在 config/checkov/custom 有定義。對不上 → 評測與報告會把沒跑的東西當成有覆蓋。
if yaml is not None:
    _rules = (load_yaml(ROOT / "config/catalogs/cwe-map.yaml") or {}).get("rules") or {}
    _gl = set(re.findall(r'^id\s*=\s*"([^"]+)"', (ROOT / "config/gitleaks.toml").read_text(encoding="utf-8"), re.M)) \
        if (ROOT / "config/gitleaks.toml").exists() else set()
    _ck_cfg = load_yaml(ROOT / "config/checkov/.checkov.yaml") or {}
    _ck_allow = set(_ck_cfg.get("check") or [])
    _ck_custom = {((load_yaml(pathlib.Path(f)) or {}).get("metadata") or {}).get("id")
                  for f in glob.glob(str(ROOT / "config/checkov/custom/*.yaml"))}
    _pf_cfg = load_yaml(ROOT / "config/promptfoo/promptfooconfig.yaml") or {}
    _pf_plugins = {(x.get("id") if isinstance(x, dict) else x) for x in ((_pf_cfg.get("redteam") or {}).get("plugins") or [])}
    _zap = {}
    if (ROOT / "config/zap/api-scan.conf").exists():
        for ln in (ROOT / "config/zap/api-scan.conf").read_text(encoding="utf-8").splitlines():
            parts = ln.split("\t")
            if len(parts) >= 2 and parts[0].strip().isdigit():
                _zap[parts[0].strip()] = parts[1].strip().upper()
    # 人工／LLM 審查流程（非自動偵測）：docs/01 威脅模型、docs/09 多模型審查
    _REVIEWS = {"G0-threat-model", "G4-llm-review"}
    for rid, meta in _rules.items():
        for ref in (meta or {}).get("implemented_by") or []:
            tool, _, ext = str(ref).partition(":")
            if tool == "gitleaks":
                good = ext in _gl; why = "config/gitleaks.toml 沒有此規則"
            elif tool == "checkov":
                good = ext in _ck_allow and (not ext.startswith("CKV2_VIBESEC_") or ext in _ck_custom)
                why = "不在 .checkov.yaml 的 check allow-list，或自訂政策不存在"
            elif tool == "promptfoo":
                good = ext in _pf_plugins; why = "config/promptfoo/promptfooconfig.yaml 的 redteam.plugins 沒有此 plugin"
            elif tool == "zap":
                good = _zap.get(ext, "IGNORE") != "IGNORE"; why = "config/zap/api-scan.conf 沒有啟用此 ZAP 規則（缺或 IGNORE）"
            elif tool == "review":
                good = ext in _REVIEWS; why = f"未知的審查流程（可用：{', '.join(sorted(_REVIEWS))}）"
            else:
                good = False; why = "未知工具（支援 gitleaks、checkov、promptfoo、zap、review）"
            if good: ok(f"implemented_by ok: {rid} ← {ref}")
            else: err(f"cwe-map {rid}: implemented_by {ref}：{why}")

# --- 每條目錄規則都要有實作（CLAUDE.md #1、#2）---
# 「政策說會擋、實際沒有任何東西發出這條規則」是最危險的落差：enforce 模式下等於靜默放行。
#   自動實作 = semgrep 規則、workflow／scripts 中實際發出的 "vibesec.gN.x" 字面值、implemented_by 的工具規則（review: 除外）
#   blocking（blocking-policy.yaml 的 blocking 或任一 tier_overrides.promote_to_blocking）→ 必須有自動實作，否則錯誤
#   advisory → 自動實作，或 implemented_by: [review:…]（人工／LLM 審查），或 not_implemented: "<理由>"（列為警告）
if yaml is not None:
    _pol = load_yaml(ROOT / "config/policy/blocking-policy.yaml") or {}
    _blocking = {r.get("rule_id") for r in _pol.get("blocking") or [] if isinstance(r, dict)}
    for _t in (_pol.get("tier_overrides") or {}).values():
        _blocking |= set((_t or {}).get("promote_to_blocking") or [])
    _auto = {_VARIANT.sub("", r) for r in known_rules
             if r in set(re.findall(r"vibesec\.g[0-6]\.[a-z0-9-]+", (ROOT / "config/semgrep/vibesec-rules.yaml").read_text(encoding="utf-8")))}
    for f in _emitters:
        if pathlib.Path(f).name in ("run_evals.py", "ruling.py"):   # 評測執行器與裁決工具只「引用」規則，不發出
            continue
        # 字面值可能在 shell echo 內被跳脫（\"vibesec…\"），結尾容許反斜線
        _auto |= {_VARIANT.sub("", r) for r in re.findall(r'"(vibesec\.g[0-6]\.[a-z0-9-]+)\\?"', pathlib.Path(f).read_text(encoding="utf-8"))}
    # promptfoo 決定性測試以 metadata.vibesec_rule_id 發出（scripts/g6_gate.py 讀取）
    for f in glob.glob(str(ROOT / "config/promptfoo/*.yaml")):
        _auto |= set(re.findall(r"vibesec_rule_id:\s*(vibesec\.g[0-6]\.[a-z0-9-]+)", pathlib.Path(f).read_text(encoding="utf-8")))
    _todo = []
    for rid, meta in _rules.items():
        meta = meta or {}
        refs = [str(x) for x in meta.get("implemented_by") or []]
        machine = rid in _auto or any(not x.startswith("review:") for x in refs)
        review = any(x.startswith("review:") for x in refs)
        reason = str(meta.get("not_implemented") or "").strip()
        if machine and reason:
            err(f"cwe-map {rid}: 已有實作卻仍標 not_implemented，請移除該欄")
        elif machine:
            ok(f"規則有實作: {rid}")
        elif rid in _blocking:
            err(f"cwe-map {rid}: blocking 規則沒有任何自動實作（review／not_implemented 不能取代）——政策會擋、實際不會擋")
        elif review:
            ok(f"規則由人工／LLM 審查涵蓋: {rid}")
        elif reason:
            _todo.append(rid)
        else:
            err(f"cwe-map {rid}: 沒有任何實作，也沒有標 implemented_by: [review:…] 或 not_implemented 理由")
    if _todo:
        warn(f"{len(_todo)} 條 advisory 規則尚未實作（not_implemented）：{', '.join(sorted(_todo))}")

# --- evals 結構：id／檔名、split 一致、held_out ≥ 1/3、每領域正反例 ---
if yaml is not None:
    case_files = sorted(glob.glob(str(ROOT / "evals/cases/**/*.yaml"), recursive=True))
    cases = {}
    for f in case_files:
        p = pathlib.Path(f); rel = p.relative_to(ROOT)
        c = load_yaml(p) or {}
        cid = c.get("id")
        if cid != p.stem:
            err(f"{rel}: id {cid!r} 與檔名不一致")
        if (c.get("gate") or "").lower() != p.parent.name:
            err(f"{rel}: gate {c.get('gate')!r} 與目錄 {p.parent.name} 不一致")
        gs = (c.get("expected") or {}).get("gate_status")
        if gs is not None and gs not in ("pass", "fail", "incomplete", "not_applicable"):
            err(f"{rel}: expected.gate_status {gs!r} 不合法")
        if cid in cases:
            err(f"{rel}: 重複的 case id {cid}")
        cases[cid] = c
    split_p = ROOT / "evals/split.yaml"
    if cases and split_p.exists():
        split = load_yaml(split_p) or {}
        ho, hi = set(split.get("held_out") or []), set(split.get("held_in") or [])
        if ho & hi:
            err(f"evals/split.yaml: 同時列於 held_out 與 held_in：{sorted(ho & hi)}")
        if (ho | hi) != set(cases):
            err(f"evals/split.yaml 與案例不一致：缺 {sorted(set(cases) - ho - hi)}，多 {sorted((ho | hi) - set(cases))}")
        for cid, c in cases.items():
            if bool(c.get("held_out")) != (cid in ho):
                err(f"{cid}: held_out 欄位與 evals/split.yaml 不一致")
        if len(ho) * 3 < len(cases):
            err(f"held_out {len(ho)}/{len(cases)} 少於 1/3")
        polarity = {}
        for c in cases.values():
            polarity.setdefault(c.get("domain"), set()).add(bool((c.get("expected") or {}).get("should_flag")))
        lacking = sorted(d for d, s in polarity.items() if s != {True, False})
        if lacking:
            warn(f"evals 領域缺正例或反例：{lacking}")
        if len(cases) < 60:
            warn(f"evals 共 {len(cases)} 案例，未達目標 60")
        ok(f"evals {len(cases)} 案例、held_out {len(ho)}、{len(polarity)} 領域")

# --- 人工裁決：schema、範例、規則自我測試、rulings/*.yaml ---
try:
    from jsonschema import Draft202012Validator as _V
    rs = ROOT / "schemas/human-ruling.schema.json"
    if rs.exists() and yaml is not None:
        _s = json.load(open(rs)); _V.check_schema(_s); ok("schema 合法: human-ruling")
        _val = _V(_s, format_checker=_V.FORMAT_CHECKER)
        _files = [ROOT / "docs/templates/human-ruling.example.yaml"] + sorted((ROOT / "rulings").glob("*.yaml"))
        for _f in _files:
            if not _f.exists():
                err(f"缺 {_f.relative_to(ROOT)}"); continue
            _d = load_yaml(_f)
            _es = sorted(_val.iter_errors(_d), key=str)
            if _es:
                for e in _es: err(f"{_f.relative_to(ROOT)} 不符 schema: {e.message} @ {list(e.path)}")
            elif _f.parent.name == "rulings" and _f.stem != _d.get("finding_id"):
                err(f"{_f.relative_to(ROOT)}: 檔名與 finding_id {_d.get('finding_id')} 不一致")
            else:
                ok(f"人工裁決 ok: {_f.relative_to(ROOT)}")
        # G4 LLM 審查紀錄：schema、範例、reviews/g4/*.yaml（規則與 provider／family 一致性；對 PR head 是否過期由 CI 的 G4 job 判斷）
        _gs = ROOT / "schemas/g4-review.schema.json"
        _s4 = json.load(open(_gs)); _V.check_schema(_s4); ok("schema 合法: g4-review")
        sys.path.insert(0, str(ROOT / "scripts"))
        import g4_review as _g4
        _cfg4 = _g4.load_cfg()
        for _f in [ROOT / "docs/templates/g4-review.example.yaml"] + sorted((ROOT / "reviews/g4").glob("*.yaml")):
            if not _f.exists():
                err(f"缺 {_f.relative_to(ROOT)}"); continue
            _ev = _g4.evaluate(load_yaml(_f), _cfg4, known_controls, _f)
            for e in _ev["errors"]: err(f"{_f.relative_to(ROOT)}: {e}")
            if not _ev["errors"]: ok(f"G4 審查紀錄 ok: {_f.relative_to(ROOT)}")
        import subprocess
        for _tool in ("ruling.py", "g4_review.py", "sarif_gate.py", "g0_trifecta.py", "vibesec_policy.py", "g1_kev.py", "g1_maintenance.py", "g1_provenance.py"):
            _r = subprocess.run([sys.executable, str(ROOT / "scripts" / _tool), "selftest"], capture_output=True, text=True)
            if _r.returncode == 0: ok(f"{_tool} selftest")
            else: err(f"{_tool} selftest 失敗：" + (_r.stdout + _r.stderr).strip()[:300])
except ImportError:
    warn("jsonschema 未安裝，略過人工裁決驗證")

# --- G0 威脅模型：vibesec.yaml 引用的必須是本 repo 的真實模型（不是範本），通過 schema，risk_tier 一致性 ---
# 範本（docs/templates/、system.name: example-project）也能通過 schema，所以要另外擋，否則 G0 的輸入是虛構系統。
try:
    from jsonschema import Draft202012Validator as _V
    if yaml is not None:
        _vb = load_yaml(ROOT / "vibesec.yaml") or {}
        _tm_rel = ((_vb.get("project") or {}).get("threat_model") or "").strip()
        _tm = ROOT / _tm_rel if _tm_rel else None
        if not _tm or not _tm.is_file():
            err(f"vibesec.yaml project.threat_model 不存在：{_tm_rel or '(未設定)'}")
        elif "docs/templates/" in _tm_rel:
            err(f"project.threat_model 指向範本 {_tm_rel}：G0 需要描述本 repo 的威脅模型")
        else:
            _d = load_yaml(_tm) or {}
            _es = sorted(_V(json.load(open(ROOT / "schemas/threat-model.schema.json"))).iter_errors(_d), key=str)
            if _es:
                for e in _es: err(f"{_tm_rel} 不符 schema: {e.message} @ {list(e.path)}")
            elif ((_d.get("system") or {}).get("name") or "") == "example-project":
                err(f"{_tm_rel} 仍是範本內容（system.name: example-project）")
            else:
                ok(f"威脅模型 ok: {_tm_rel}")
                sys.path.insert(0, str(ROOT / "scripts"))
                from g0_trifecta import trifecta_findings
                for f in trifecta_findings(_d):
                    err(f"{_tm_rel}：{f['rule_id']}（blocking）— {f['reason']}")
                _order = {"L1": 1, "L2": 2, "L3": 3}
                _decl, _model = _vb.get("risk_tier"), _d.get("risk_tier")
                if _decl != _model:
                    # docs/01：兩者應一致，且推導值不得高於宣告值。改 vibesec.yaml risk_tier 是政策決定（CLAUDE.md 規則 1），
                    # 由人類在獨立 PR 決定；在那之前以警告呈現，G0 會照實標出差異。
                    _msg = f"risk_tier 不一致：vibesec.yaml {_decl}、威脅模型 {_model}"
                    if _order.get(_model, 0) > _order.get(_decl, 0):
                        warn(_msg + "（模型推導較高；調整 vibesec.yaml 須由人類在獨立 PR 決定）")
                    else:
                        warn(_msg)
except ImportError:
    warn("jsonschema 未安裝，略過威脅模型驗證")

# --- tier 一致性：blocking-policy 是唯一來源（scripts/vibesec_policy.py）；cwe-map／semgrep metadata／evals／docs 政策表
#     的 tier 必須等於政策的「基礎 tier」（不含 tier_overrides），否則文件說會擋、CI 實際不擋（或相反）。
if yaml is not None:
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        from vibesec_policy import Policy as _Policy
        _P = _Policy(ROOT)
    except Exception as _e:
        err(f"無法載入阻擋政策：{_e}"); _P = None
    if _P:
        _n = 0
        for _rid, _meta in ((load_yaml(ROOT / "config/catalogs/cwe-map.yaml") or {}).get("rules") or {}).items():
            _t = (_meta or {}).get("policy_tier")
            if _t != _P.base_tier(_rid):
                err(f"cwe-map {_rid}: policy_tier {_t} ≠ 政策基礎 tier {_P.base_tier(_rid)}（以 blocking-policy.yaml 為準）")
            else:
                _n += 1
        ok(f"cwe-map policy_tier 與政策一致：{_n} 條")
        for _r in (load_yaml(ROOT / "config/semgrep/vibesec-rules.yaml") or {}).get("rules") or []:
            _id = str(_r.get("id", ""))
            if not _id.startswith("vibesec."):
                continue
            _want = _P.base_tier(_VARIANT.sub("", _id))
            _mt = (_r.get("metadata") or {}).get("policy_tier")
            if _mt != _want:
                err(f"semgrep {_id}: metadata.policy_tier {_mt} ≠ 政策基礎 tier {_want}")
            if (_r.get("severity") == "ERROR") != (_want == "blocking"):
                err(f"semgrep {_id}: severity 應為 {'ERROR' if _want == 'blocking' else 'WARNING'}（政策 {_want}）")
        ok("semgrep metadata.policy_tier／severity 與政策一致")
        for _f in sorted(glob.glob(str(ROOT / "evals/cases/**/*.yaml"), recursive=True)):
            _e = (load_yaml(pathlib.Path(_f)) or {}).get("expected") or {}
            if _e.get("rule_id") and _e.get("policy_tier") and _e["policy_tier"] != _P.base_tier(_e["rule_id"]):
                err(f"{pathlib.Path(_f).relative_to(ROOT)}: expected.policy_tier {_e['policy_tier']} ≠ 政策基礎 tier {_P.base_tier(_e['rule_id'])}")
        ok("evals expected.policy_tier 與政策一致")
        for _f in sorted(glob.glob(str(ROOT / "docs/0[1-7]-*.md"))):
            for _i, _ln in enumerate(pathlib.Path(_f).read_text(encoding="utf-8").splitlines(), 1):
                _m = re.match(r"^\| `(vibesec\.g\d\.[a-z0-9-]+)`", _ln)
                if not _m:
                    continue
                _m2 = re.search(r"\b(blocking|advisory)\b", _ln[_m.end():])
                if _m2 and _m2.group(1) != _P.base_tier(_m.group(1)):
                    err(f"{pathlib.Path(_f).name}:{_i}: {_m.group(1)} 政策表寫 {_m2.group(1)}，政策基礎 tier 為 {_P.base_tier(_m.group(1))}")
        ok("docs 政策表的 tier 與政策一致")

# 通過細項靜音；僅印摘要與警告/錯誤
print(f"通過 {len(oks)} 項；警告 {len(warns)}；錯誤 {len(errors)}")
for w in warns: print(f"  WARN {w}")
for e in errors: print(f"  ERR  {e}")
sys.exit(1 if errors else 0)
