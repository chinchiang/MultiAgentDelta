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
        import subprocess
        _r = subprocess.run([sys.executable, str(ROOT / "scripts/ruling.py"), "selftest"], capture_output=True, text=True)
        if _r.returncode == 0: ok("ruling.py selftest")
        else: err("ruling.py selftest 失敗：" + (_r.stdout + _r.stderr).strip()[:300])
except ImportError:
    warn("jsonschema 未安裝，略過人工裁決驗證")

# 通過細項靜音；僅印摘要與警告/錯誤
print(f"通過 {len(oks)} 項；警告 {len(warns)}；錯誤 {len(errors)}")
for w in warns: print(f"  WARN {w}")
for e in errors: print(f"  ERR  {e}")
sys.exit(1 if errors else 0)
