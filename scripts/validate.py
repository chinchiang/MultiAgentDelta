#!/usr/bin/env python3
"""VibeSec 自我驗證：YAML 語法、JSON Schema、範例檔、catalogs 與規則 ID 一致性。

退出碼 0 = 全通過；1 = 有錯誤。缺少的可選檔案只警告（WARN），不算失敗，
以便在部分檔案尚未產出時仍能先行驗證已存在者。
"""
from __future__ import annotations
import json, os, sys, glob, re, pathlib

# 受驗的樹：預設是本腳本所在的 repo。CI 另以 default branch 的 validate.py 驗 PR head（VIBESEC_PROJECT_ROOT），
# 讓 PR 不能先削弱 validate.py 再轉綠（第一輪審查 C1）
ROOT = pathlib.Path(os.environ.get("VIBESEC_PROJECT_ROOT") or pathlib.Path(__file__).resolve().parent.parent).resolve()
# 判定模組（g4_review、g0_trifecta、vibesec_policy）一律從「本腳本所在的樹」import：CI 跑的是 default branch 的 validate.py，
# 以前卻 sys.path.insert(ROOT/scripts) 去 import PR head 的模組，PR 改 scripts/g4_review.py 在 import 時把
# __main__.err 換掉，「受信任版本」那一步就轉綠了（第二輪審查 M3）。資料（受驗的檔案）仍讀 ROOT。
CODE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(CODE))
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
    # 工具缺席不能等於通過（CLAUDE.md 規則 2）：以前只 warn 並 exit 0，所有檢查與 selftest 都被略過（第四次審視 S-14）
    print("ERROR: PyYAML 未安裝，無法驗證（incomplete ≠ pass）", file=sys.stderr)
    sys.exit(2)

def load_yaml(p: pathlib.Path):
    if yaml is None:
        return None
    docs = list(yaml.safe_load_all(p.read_text()))
    return docs[0] if len(docs) == 1 else docs

# 不受驗的目錄：CI 的受信任副本（_trusted/）、本機 agent worktree、git 內部、第三方套件與虛擬環境
_YAML_SKIP_DIRS = {".git", "node_modules", ".venv"}
_YAML_SKIP_PREFIXES = (("_trusted",), (".claude", "worktrees"))

def yaml_files(root: pathlib.Path) -> list[pathlib.Path]:
    """列出受驗樹中所有 *.yaml／*.yml，含隱藏目錄與隱藏檔。
    glob("**") 預設略過以 . 開頭的路徑，以前 .github/workflows、.github/dependabot.yml、
    .pre-commit-config.yaml、.claude/** 都沒做語法檢查；改用 os.walk 一併納入。"""
    out = []
    for d, dirs, files in os.walk(root):
        rel_d = pathlib.Path(d).relative_to(root)
        dirs[:] = sorted(x for x in dirs if x not in _YAML_SKIP_DIRS
                         and not any((rel_d / x).parts[:len(p)] == p for p in _YAML_SKIP_PREFIXES))
        out += [pathlib.Path(d, f) for f in files if f.endswith((".yaml", ".yml"))]
    return sorted(out)

if yaml is not None:
    for f in yaml_files(ROOT):
        rel = f.relative_to(ROOT)
        try:
            list(yaml.safe_load_all(open(f)))
            ok(f"YAML ok: {rel}")
        except Exception as e:
            err(f"YAML 解析失敗 {rel}: {e}")

# --- TOML 語法 ---
import tomllib
# gitleaks-packet.toml：審查包遮罩專用（scripts/review_packet.py），缺席時審查包無法產生
for _toml in ("config/gitleaks.toml", "config/gitleaks-packet.toml"):
    try:
        gl = ROOT / _toml
        if gl.exists():
            tomllib.loads(gl.read_text()); ok(f"TOML ok: {_toml}")
        else:
            warn(f"缺 {_toml}")
    except Exception as e:
        err(f"TOML 解析失敗 {_toml}: {e}")

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
    # 執行期實際產物（harness／本機跑過才有；CI 的乾淨 checkout 沒有 reports/ → 略過）：
    # 不只驗範本，實際輸出也要符合 schema，否則 schema 很完整但正式輸出沒人用機器把關（incomplete ≠ pass）。
    fj = ROOT / "reports/findings.json"
    if fj.exists() and "finding" in schemas:
        try:
            data = json.load(open(fj))
        except (ValueError, OSError) as e:
            err(f"reports/findings.json 無法解析：{e}"); data = None
        items = data.get("findings", []) if isinstance(data, dict) else (data if isinstance(data, list) else None)
        if data is not None and items is None:
            err("reports/findings.json 應為 finding 陣列或含 findings 的物件")
        elif items is not None:
            bad = 0
            for i, f in enumerate(items):
                fe = sorted(schemas["finding"].iter_errors(f), key=str)
                for e in fe:
                    bad += 1
                    err(f"reports/findings.json[{i}]（{f.get('id') if isinstance(f, dict) else '?'}）不符 schema: {e.message} @ {list(e.path)}")
            if not bad:
                ok(f"reports/findings.json 通過 schema（{len(items)} 筆）")
    # 執行期 gate JSON：reports/gates/G*.json 與 reports/*-gate.json（存在才驗）
    if "gate-result" in schemas:
        for gp in sorted(glob.glob(str(ROOT / "reports/gates/G*.json"))) + sorted(glob.glob(str(ROOT / "reports/*-gate.json"))):
            try:
                ge = sorted(schemas["gate-result"].iter_errors(json.load(open(gp))), key=str)
            except (ValueError, OSError) as e:
                err(f"{pathlib.Path(gp).name} 無法解析：{e}"); continue
            if ge:
                for e in ge: err(f"{pathlib.Path(gp).name} 不符 gate-result schema: {e.message} @ {list(e.path)}")
            else:
                ok(f"{pathlib.Path(gp).name} 通過 gate-result schema")
    # 威脅模型模板
    tm = ROOT / "docs/templates/threat-model.yaml"
    if tm.exists() and "threat-model" in schemas and yaml is not None:
        errs = sorted(schemas["threat-model"].iter_errors(load_yaml(tm)), key=str)
        if errs:
            for e in errs: err(f"threat-model.yaml 不符 schema: {e.message} @ {list(e.path)}")
        else: ok("threat-model.yaml 通過 schema")
except ImportError:
    print("ERROR: jsonschema 未安裝，無法驗證（incomplete ≠ pass）", file=sys.stderr); sys.exit(2)

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
            err(f"{rel}: control_id {cid} 不在 catalogs（CLAUDE.md 規則 3：ID 只能查目錄）")
        if rid and known_rules and rid not in known_rules:
            err(f"{rel}: rule_id {rid} 不在 cwe-map/semgrep（CLAUDE.md 規則 3：ID 只能查目錄）")

    # 文件與設定內出現的 ID 也只能來自目錄（CLAUDE.md 規則 3）：以前只查 eval 案例，
    # 文件寫錯的 rule_id／控制 ID（例如不存在的 vibesec.g5.bola-idor）一路沒被發現（第一輪審查 D）。
    # 結尾接 -* 或 * 的是萬用寫法（vibesec.g3.sql-*），不是 ID；scripts/ 的 selftest 會故意用目錄外的 ID，不掃。
    _docs = sorted({*glob.glob(str(ROOT / "**/*.md"), recursive=True), *glob.glob(str(ROOT / ".claude/**/*.md"), recursive=True),
                    *glob.glob(str(ROOT / ".github/**/*.md"), recursive=True), *glob.glob(str(ROOT / "docs/templates/*"))})
    _docs = [f for f in _docs if pathlib.Path(f).relative_to(ROOT).parts[0] not in ("_trusted", "node_modules")
             and pathlib.Path(f).relative_to(ROOT).parts[:2] != (".claude", "worktrees")]
    _cfg = sorted(glob.glob(str(ROOT / "config/**/*.yaml"), recursive=True) + glob.glob(str(ROOT / "evals/**/*.yaml"), recursive=True))
    _id_pats = [("rule_id", re.compile(r"\bvibesec\.g[0-6]\.[a-z0-9]+(?:-[a-z0-9]+)*(?![a-z0-9*-])"), known_rules),
                ("控制 ID", re.compile(r"\b(?:ASVS5-V\d+\.\d+(?:\.\d+)?|LLM\d{2}:2025|MAESTRO-L\d+|VS-G[0-6]-[A-Z0-9]+(?:-[A-Z0-9]+)*)(?![\w*-])"), known_controls)]
    _cwe_pat = re.compile(r"\bCWE-\d+\b")
    # 文件中以反引號引用、指向 repo 內的路徑（指令、檔案）必須存在；含萬用字元／佔位符／範圍（g0..g6）者略過
    _path_pat = re.compile(r"`((?:scripts|schemas|config|evals|tests|examples|reviews|rulings|docs/templates)/[^`\s]+?)`")
    _bad_ids = _bad_paths = 0
    for f in _docs + _cfg:
        rel = pathlib.Path(f).relative_to(ROOT)
        try:
            lines = pathlib.Path(f).read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        for i, line in enumerate(lines, 1):
            if known_cwes:
                for m in _cwe_pat.finditer(line):
                    if m.group(0) not in known_cwes:
                        err(f"{rel}:{i}: {m.group(0)} 不在 cwe-map.yaml 的 cwes（CLAUDE.md 規則 3）"); _bad_ids += 1
            if f in _cfg:
                continue
            for label, pat, known in _id_pats:
                for m in pat.finditer(line):
                    if known and m.group(0) not in known:
                        err(f"{rel}:{i}: {label} {m.group(0)} 不在 catalogs（CLAUDE.md 規則 3）"); _bad_ids += 1
            for m in _path_pat.finditer(line):
                p = re.sub(r":\d+(?:-\d+)?(?:,\d+)*$", "", m.group(1)).rstrip("/")
                if re.search(r"[*<>{}\[\]$…]|\.\.", p):
                    continue
                if not (ROOT / p).exists():
                    err(f"{rel}:{i}: 引用的路徑 {m.group(1)} 不存在"); _bad_paths += 1
    if not _bad_ids: ok(f"文件／設定中的 CWE、rule_id、控制 ID 皆在目錄（{len(_docs) + len(_cfg)} 檔）")
    if not _bad_paths: ok("文件以反引號引用的 repo 路徑皆存在")

    # CVE 也只能來自目錄（CLAUDE.md 規則 3）：以前 catalogs 沒有 CVE 目錄、這裡也不檢查，
    # CVE-2026-33634 等引用從未查證（第五次審查 #5）。判定在 scripts/cve_catalog.py（有 selftest）
    import cve_catalog
    _cve_cat = ROOT / cve_catalog.CATALOG
    _cves = ((load_yaml(_cve_cat) or {}).get("cves") or {}) if _cve_cat.exists() else None
    if _cves is None:
        err(f"缺 {cve_catalog.CATALOG}：無法核對文件與設定引用的 CVE（CLAUDE.md 規則 3）")
    else:
        _p = cve_catalog.catalog_problems(_cves)
        for m in _p: err(m)
        if not _p: ok(f"cve-references.yaml：{len(_cves)} 筆 CVE 欄位完整")
        # 掃描範圍：文件、config/、evals/、docs/*.yaml、.github/（workflow 註解也會引用 CVE）；scripts/ 的 selftest 刻意用虛構 ID，不掃
        _cve_files = sorted(set(_docs + _cfg) | {*glob.glob(str(ROOT / "docs/**/*.yaml"), recursive=True),
                                                  *glob.glob(str(ROOT / ".github/**/*.yml"), recursive=True)})
        _p = cve_catalog.reference_problems(_cves, _cve_files, ROOT)
        for m in _p: err(m)
        if not _p: ok(f"文件／設定／workflow 引用的 CVE 皆在 cve-references.yaml（{len(_cve_files)} 檔）")

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
                if ext == "*":   # 內建規則：要 config/gitleaks.toml 真的載入預設規則集
                    good = bool(re.search(r"^\s*useDefault\s*=\s*true", (ROOT / "config/gitleaks.toml").read_text(encoding="utf-8"), re.M)) \
                        if (ROOT / "config/gitleaks.toml").exists() else False
                    why = "gitleaks:* 需要 config/gitleaks.toml 的 [extend] useDefault = true"
                else:
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
    # exceptions 的 path_glob 以 fnmatch 比對：單一 * 也會跨越 /（app/*.py 命中 app/x/y.py），範圍可能比核准者預期大。
    # 比對方式不改（是否改嚴格 glob 見 #159），只提醒
    for _ex in _pol.get("exceptions") or []:
        _g = str((_ex or {}).get("path_glob") or "") if isinstance(_ex, dict) else ""
        if re.search(r"(?<!\*)\*(?!\*)", _g):
            warn(f"blocking-policy exceptions {_ex.get('rule_id')} @ {_g}：單一 * 以 fnmatch 比對會跨越 /，範圍可能比預期大")
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
        # 每個閘門與領域都要有 held-out 案例：沒有的話，該閘門／領域的泛化能力完全沒被量測
        for _k in ("gate", "domain"):
            _no_ho = sorted({str(c.get(_k)) for c in cases.values()} - {str(cases[x].get(_k)) for x in ho if x in cases})
            if _no_ho:
                err(f"evals 沒有 held-out 案例的 {_k}：{_no_ho}")
        # 案例的 control_id 必須是該規則在 cwe-map 的 control_ids 之一（CLAUDE.md 規則 3：ID 只能查目錄）；
        # 以前 13 案寫成相鄰但不對應的 ID（ASVS5-V8.1 對 missing-owner-filter），報表依控制彙整時就錯位
        _cm = (load_yaml(ROOT / "config/catalogs/cwe-map.yaml") or {}).get("rules") or {}
        for cid, c in sorted(cases.items()):
            _e = c.get("expected") or {}
            _ids = (_cm.get(_e.get("rule_id")) or {}).get("control_ids")
            if _e.get("rule_id") in _cm and _e.get("control_id") not in (_ids or []):
                err(f"{cid}: control_id {_e.get('control_id')!r} 不在 {_e.get('rule_id')} 的 control_ids {_ids}")
        # 每條 vibesec 規則至少 1 正例、1 反例；沒有可重現案例者須列在下方豁免清單並寫明由哪個 selftest 覆蓋
        _EVAL_EXEMPT = {
            "vibesec.g1.unmaintained-dependency": "需即時查 deps.dev，無離線執行器；判定由 g1_maintenance.py selftest 覆蓋",
            "vibesec.g1.sbom-missing-provenance": "需 GitHub attestation，無離線執行器；判定由 g1_provenance.py selftest 覆蓋",
            "vibesec.g1.sbom-incomplete": "需 syft；判定由 g1_sbom.py selftest 覆蓋",
            "vibesec.g5.ssrf-metadata": "本機沒有雲端 metadata 端點，靶場只能以 loopback canary 證實（ssrf-internal-fetch 有正例）",
        }
        _pol = {}
        for c in cases.values():
            _e = c.get("expected") or {}
            if _e.get("rule_id") and _e.get("gate_status") is None:
                _pol.setdefault(_e["rule_id"], set()).add(bool(_e.get("should_flag")))
        for _r in sorted(r for r in _cm if r.startswith("vibesec.")):
            _have = _pol.get(_r, set())
            if _have == {True, False}:
                if _r in _EVAL_EXEMPT:
                    warn(f"{_r} 已有正反例，可自 validate.py 的 _EVAL_EXEMPT 移除")
            elif _r not in _EVAL_EXEMPT:
                err(f"{_r} 缺{'正例' if True not in _have else ''}{'反例' if False not in _have else ''}（evals/cases）")
        if len(cases) < 60:
            warn(f"evals 共 {len(cases)} 案例，未達目標 60")
        ok(f"evals {len(cases)} 案例、held_out {len(ho)}、{len(polarity)} 領域")
        # split.yaml 的 distribution 必須與案例一致（以前寫死 71 筆、沒人核對，第四次審視 E-4）
        import collections as _co
        _want = {
            "total": len(cases),
            "held_out_ratio": round(len(ho) / len(cases), 2),
            "by_gate": dict(sorted(_co.Counter(c.get("gate") for c in cases.values()).items())),
            "by_domain": dict(sorted(_co.Counter(c.get("domain") for c in cases.values()).items())),
            "by_polarity": {"neg": sum(1 for c in cases.values() if not (c.get("expected") or {}).get("should_flag")),
                            "pos": sum(1 for c in cases.values() if (c.get("expected") or {}).get("should_flag"))},
            # 依 expected.gate_status 判斷：以前用 id 正規式，名稱含連字號的 incomplete 案例（原 g6-observations-malformed-…，已改名）就漏了
            "incomplete_cases": sorted(cid for cid, c in cases.items() if (c.get("expected") or {}).get("gate_status") == "incomplete"),
        }
        _have = split.get("distribution") or {}
        _diff = [k for k, v in _want.items() if _have.get(k) != v]
        if _diff:
            err("evals/split.yaml distribution 與案例不一致（" + "、".join(_diff) + "）；正確值：" +
                json.dumps({k: _want[k] for k in _diff}, ensure_ascii=False))
        else:
            ok("evals/split.yaml distribution 與案例一致")
        # evals/README.md 的「目前 N」必須是實際案例數（以前寫死 91、案例增加後沒人改）
        _rm = re.search(r"（目前 (\d+)）", (ROOT / "evals/README.md").read_text(encoding="utf-8"))
        if not _rm:
            err("evals/README.md: 找不到「（目前 N）」案例數")
        elif int(_rm.group(1)) != len(cases):
            err(f"evals/README.md 寫「目前 {_rm.group(1)}」，實際 {len(cases)} 案例")
        else:
            ok(f"evals/README.md 案例數與實際一致（{len(cases)}）")
        # baseline 列出的案例必須存在：不存在的 ID 會讓 nightly 退步比對失真
        _bl = (load_yaml(ROOT / "evals/baseline.yaml") or {}).get("executed") or []
        _gone = sorted(set(_bl) - set(cases))
        if _gone:
            err(f"evals/baseline.yaml 列出不存在的案例：{_gone}")
        else:
            ok(f"evals/baseline.yaml {len(_bl)} 案例皆存在")

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
        # G4 LLM 審查紀錄：schema、範例、reviews/g4/*.yaml 與外部專案的 reviews/g4/external/*.yaml
        # （規則與 provider／family 一致性、檔名 = commit；對 PR head 是否過期由 CI 的 G4 job 判斷，外部紀錄由 g4_access.py 對目標 HEAD 判斷）
        _gs = ROOT / "schemas/g4-review.schema.json"
        _s4 = json.load(open(_gs)); _V.check_schema(_s4); ok("schema 合法: g4-review")
        import g4_review as _g4
        _cfg4 = _g4.load_cfg()
        from vibesec_policy import load_policy as _load_policy
        _g4_policy_load = _load_policy(CODE.parent)   # 只建立一次；讀不到 → 紀錄照樣驗證，未完成原因記在 incomplete
        for _f in ([ROOT / "docs/templates/g4-review.example.yaml"] + sorted((ROOT / "reviews/g4").glob("*.yaml"))
                   + sorted((ROOT / "reviews/g4/external").glob("*.yaml"))):
            if not _f.exists():
                err(f"缺 {_f.relative_to(ROOT)}"); continue
            _ev = _g4.evaluate(load_yaml(_f), _cfg4, known_controls, _f, policy_load=_g4_policy_load)
            for e in _ev["errors"]: err(f"{_f.relative_to(ROOT)}: {e}")
            if not _ev["errors"]: ok(f"G4 審查紀錄 ok: {_f.relative_to(ROOT)}")
        import subprocess
        # 有 selftest 的腳本：自動偵測（以前是手寫清單，新增腳本的 selftest 沒加進清單就永遠不會跑）。
        # 本腳本所在樹（CI 為 default branch）有 selftest 的腳本，受驗樹不得刪掉該腳本或它的 selftest。
        _has_st = lambda d: {q.name for q in d.glob("*.py") if re.search(r"^def selftest\(", q.read_text(encoding="utf-8"), re.M)}
        _selftest_tools = sorted(_has_st(ROOT / "scripts"))
        for _gone in sorted(_has_st(CODE) - set(_selftest_tools)):
            err(f"scripts/{_gone} 的 selftest 在受驗樹中被移除（default branch 有）")
        for _tool in _selftest_tools:
            _r = subprocess.run([sys.executable, str(ROOT / "scripts" / _tool), "selftest"], capture_output=True, text=True)
            if _r.returncode == 0: ok(f"{_tool} selftest")
            else: err(f"{_tool} selftest 失敗：" + (_r.stdout + _r.stderr).strip()[:300])
        # tests/ 的 unittest：沒有 selftest 子命令的模組測試（例如 Bedrock 呼叫邊界），與 selftest 同一層級把關
        # 以前 tests/ 不存在就靜默略過，Python 3.11 的 unittest 遇到 0 個測試也回 0：刪掉或清空測試照樣通過。
        # 現在：受驗樹必須有 tests/；本腳本所在樹（CI 為 default branch）有的測試檔不得被刪，且 def test_ 數量不得變少；
        # 實際執行的測試數必須 > 0。
        _ref_tests = sorted((CODE.parent / "tests").glob("test_*.py"))
        for _t in _ref_tests:
            _mine = ROOT / "tests" / _t.name
            if not _mine.is_file():
                err(f"tests/{_t.name} 在受驗樹中被刪除（default branch 有此測試）")
                continue
            _need = len(re.findall(r"^\s*def test_", _t.read_text(encoding="utf-8"), re.M))
            _have = len(re.findall(r"^\s*def test_", _mine.read_text(encoding="utf-8"), re.M))
            if _have < _need:
                err(f"tests/{_t.name} 的測試由 {_need} 個減為 {_have} 個")
        if not (ROOT / "tests").is_dir():
            err("缺 tests/ 目錄（unittest 無法執行；incomplete ≠ pass）")
        else:
            _r = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"], cwd=ROOT,
                                capture_output=True, text=True)
            _ran = re.search(r"Ran (\d+) tests?", _r.stderr or "")
            if _r.returncode != 0:
                err("tests/ unittest 失敗：" + (_r.stdout + _r.stderr).strip()[-400:])
            elif not _ran or int(_ran.group(1)) == 0:
                err("tests/ 沒有執行任何測試（0 個測試不算通過）")
            else:
                ok(f"tests/ unittest（{_ran.group(1)} 個測試）")
except ImportError:
    print("ERROR: jsonschema 未安裝，無法驗證（incomplete ≠ pass）", file=sys.stderr); sys.exit(2)

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
                from g0_trifecta import trifecta_findings
                from vibesec_policy import load_policy as _load_policy
                # 政策取自本腳本所在的樹（CI 為 default branch），綁定受驗樹 ROOT（CI 以 VIBESEC_PROJECT_ROOT 認出是本 repo）
                _g0_policy, _g0_policy_problem = _load_policy(CODE.parent)
                if _g0_policy_problem:
                    err(f"{_tm_rel}：G0 致命三要素無法判定（incomplete ≠ pass）：{_g0_policy_problem}")
                for f in trifecta_findings(_d, ROOT, str(_tm_rel), project=_g0_policy.for_project(ROOT)) if _g0_policy else []:
                    if f["policy_tier"] == "blocking":
                        err(f"{_tm_rel}：{f['rule_id']}（blocking）— {f['reason']}")
                    else:   # blocking-policy 例外（已接受風險、有到期日）：不擋，但每次都看得到
                        warn(f"{_tm_rel}：{f['rule_id']}（advisory，例外）— {f['reason']}")
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
    print("ERROR: jsonschema 未安裝，無法驗證（incomplete ≠ pass）", file=sys.stderr); sys.exit(2)

# --- tier 一致性：blocking-policy 是唯一來源（scripts/vibesec_policy.py）；cwe-map／semgrep metadata／evals／docs 政策表
#     的 tier 必須等於政策的「基礎 tier」（不含 tier_overrides），否則文件說會擋、CI 實際不擋（或相反）。
if yaml is not None:
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
        # 擴充（第四次審視 D-文件）：同列多條規則、萬用字元（xss-*）、同前綴簡寫（`command-injection`），
        # 以及內文「`vibesec.gN.x`（blocking…」。宣稱的 tier 須等於基礎 tier 或 risk_tier 覆寫後的有效 tier。
        _all_rules = sorted(_rules)
        def _expand(tok, prefix):
            full = tok if tok.startswith("vibesec.") else f"{prefix}.{tok}"
            if "*" in full:
                import fnmatch as _fn
                return [r for r in _all_rules if _fn.fnmatchcase(r, full)]
            return [full] if full in _rules else []
        for _f in sorted(glob.glob(str(ROOT / "docs/*.md"))) + [str(ROOT / "README.md")]:
            for _i, _ln in enumerate(pathlib.Path(_f).read_text(encoding="utf-8").splitlines(), 1):
                _claims = []
                if _ln.startswith("|"):
                    _cells = [c.strip() for c in _ln.strip().strip("|").split("|")]
                    if len(_cells) >= 2 and "vibesec.g" in _cells[0]:
                        _m2 = re.match(r"(blocking|advisory)\b", _cells[1])
                        _toks = re.findall(r"`([a-z0-9.*-]+)`", _cells[0])
                        _first = next((t for t in _toks if t.startswith("vibesec.g")), None)
                        if _m2 and _first:
                            _prefix = _first.rsplit(".", 1)[0]
                            for _t in _toks:
                                if _t.startswith("vibesec.") or re.fullmatch(r"[a-z0-9]+(-[a-z0-9*]+)+\*?|[a-z0-9]+-\*", _t):
                                    for _r in _expand(_t, _prefix):
                                        _claims.append((_r, _m2.group(1)))
                # 規則 ID 後緊接的全形括號內，第一個 tier 字（「advisory（L3 升 blocking）」取 advisory；略過 blocking-policy）
                for _m3 in re.finditer(r"`?(vibesec\.g\d\.[a-z0-9-]+)`?（([^）]*)）", _ln):
                    _m4 = re.search(r"(?<![\w-])(blocking|advisory)(?![\w-])", _m3.group(2))
                    if _m4:
                        _claims.append((_m3.group(1), _m4.group(1)))
                for _r, _c in _claims:
                    if _c not in (_P.base_tier(_r), _P.tier(_r)):
                        err(f"{pathlib.Path(_f).name}:{_i}: {_r} 文件寫 {_c}，政策為 {_P.base_tier(_r)}"
                            + (f"（{_P.risk_tier} 有效 {_P.tier(_r)}）" if _P.tier(_r) != _P.base_tier(_r) else ""))
        ok("docs 政策表的 tier 與政策一致")

# --- CI 的 pip install 一律走雜湊鎖定檔（G1 供應鏈；.github/actions/vibesec-pip-install）---
# workflow／composite action 中每個 pip install 都要 --require-hashes -r <鎖定檔>；確實需要例外時，在同一行或上一行
# 加註解標記 `vibesec: allow-unlocked-pip` 並寫明理由。鎖定檔的每個套件都要有 SHA-256，且版本與 workflow 中釘選的一致。
_PIP_RE = re.compile(r"\bpip3?\s+install\b|\bpython3?\s+-m\s+pip\s+install\b")
_PIP_ALLOW = "vibesec: allow-unlocked-pip"
_ci_files = sorted(glob.glob(str(ROOT / ".github/workflows/*.yml"))) + \
            sorted(glob.glob(str(ROOT / ".github/actions/**/action.yml"), recursive=True))
_pip_sites = 0
for _f in _ci_files:
    _rel = pathlib.Path(_f).relative_to(ROOT)
    _lines = pathlib.Path(_f).read_text(encoding="utf-8").splitlines()
    for _i, _ln in enumerate(_lines):
        _code = _ln.split(" #", 1)[0] if not _ln.lstrip().startswith("#") else ""
        if not _PIP_RE.search(_code) or "name:" in _code.split("pip", 1)[0]:
            continue   # 註解、步驟名稱裡提到 pip install 不算安裝
        _j, _full = _i, _code
        while _full.rstrip().endswith("\\") and _j + 1 < len(_lines):   # shell 續行
            _j += 1; _full = _full.rstrip()[:-1] + " " + _lines[_j]
        _pip_sites += 1
        if _PIP_ALLOW in _ln or (_i and _PIP_ALLOW in _lines[_i - 1]):
            warn(f"{_rel}:{_i + 1}: pip install 標記為允許不鎖定（{_PIP_ALLOW}）")
        elif not (re.search(r"--require-hashes\b", _full) and re.search(r"(?:^|\s)-r\s", _full)):
            err(f"{_rel}:{_i + 1}: pip install 未使用 --require-hashes -r <鎖定檔>（改用 .github/actions/vibesec-pip-install）")
for _f in _ci_files:
    for _m in re.finditer(r"uses:\s*\./\.github/actions/vibesec-pip-install\s*\n\s*with:\s*\n\s*requirements:\s*(\S+)",
                          pathlib.Path(_f).read_text(encoding="utf-8")):
        if not (ROOT / _m.group(1)).is_file():
            err(f"{pathlib.Path(_f).relative_to(ROOT)}: vibesec-pip-install 指向不存在的鎖定檔 {_m.group(1)}")
_locks = {}
for _f in sorted(glob.glob(str(ROOT / "requirements-*.txt"))):
    _name = pathlib.Path(_f).name
    _pins, _cur = {}, None
    for _ln in pathlib.Path(_f).read_text(encoding="utf-8").splitlines():
        _s = _ln.strip()
        _m = re.match(r"([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==(\S+)", _s)
        if _m:
            _cur = _m.group(1).lower().replace("_", "-"); _pins[_cur] = [_m.group(2).rstrip(" \\;"), 0]
        elif _s.startswith("--hash=sha256:") and _cur:
            _pins[_cur][1] += 1
        elif _s and not _s.startswith("#"):
            err(f"{_name}: 無法辨識的行（鎖定檔只能有 name==version 與 --hash）：{_s[:80]}")
    for _p, (_v, _h) in _pins.items():
        if not _h:
            err(f"{_name}: {_p}=={_v} 沒有 --hash（--require-hashes 會拒絕安裝）")
    if not _pins:
        err(f"{_name}: 沒有任何鎖定的套件")
    _locks[_name] = {_p: _v for _p, (_v, _h) in _pins.items()}
_sb = ROOT / ".github/workflows/staging-blackbox.yml"
if _sb.is_file() and "requirements-garak.txt" in _locks:
    _sbt = _sb.read_text(encoding="utf-8")
    for _env, _pkg, _suffix in (("GARAK_VERSION", "garak", ""), ("TORCH_VERSION", "torch", "+cpu")):
        _m = re.search(rf'^\s*{_env}:\s*"([^"]+)"', _sbt, re.M)
        _have = _locks["requirements-garak.txt"].get(_pkg)
        if not _m or _have != _m.group(1) + _suffix:
            err(f"staging-blackbox.yml 的 {_env}（{_m.group(1) if _m else '缺席'}）與 requirements-garak.txt 的 {_pkg}=={_have} 不一致")
if "requirements-evals.txt" in _locks:
    for _f in _ci_files:
        for _m in re.finditer(r"image:\s*semgrep/semgrep:(\S+)", pathlib.Path(_f).read_text(encoding="utf-8")):
            if _locks["requirements-evals.txt"].get("semgrep") != _m.group(1):
                err(f"{pathlib.Path(_f).name}: semgrep 容器 {_m.group(1)} 與 requirements-evals.txt 的 semgrep=="
                    f"{_locks['requirements-evals.txt'].get('semgrep')} 不一致（評測與閘門會用不同版本）")
ok(f"CI 的 pip install 一律走雜湊鎖定檔（{_pip_sites} 處；鎖定檔 {len(_locks)} 份）")

# --- 靶場驗收的必要工具（scripts/gate_verdict.py 的 TOOL_ALIASES）：vibesec.yaml G5／G6 的每個工具，對應後的名稱
# 都要是閘門程式實際寫進 gate JSON tools[].name 的名稱；對不上時靶場驗收會永遠判「必要工具未執行」，或漏驗該工具 ---
import gate_verdict as _gv
_tool_src = "\n".join((ROOT / "scripts" / f).read_text(encoding="utf-8") for f in ("g5_api_probes.py", "g5_zap.py", "g6_gate.py")
                      if (ROOT / "scripts" / f).is_file())
_bad_tools = [f"{_g}:{_t}" for _g, _ts in _gv.required_tools(load_yaml(ROOT / "vibesec.yaml") or {}).items() for _t in _ts
              if f'"{_t}"' not in _tool_src]
if _bad_tools:
    err(f"靶場驗收的必要工具在閘門程式中找不到對應的 gate JSON 工具名稱（更新 gate_verdict.TOOL_ALIASES）：{'、'.join(_bad_tools)}")
else:
    ok("靶場驗收的必要工具皆對應到閘門程式寫入的工具名稱")

# --- CI 設定的不變式（判定在 scripts/ci_invariants.py，有 selftest）：防止已修過的弱點被改回去 ---
import ci_invariants as _ci
_wf = {pathlib.Path(_f).name: pathlib.Path(_f).read_text(encoding="utf-8") for _f in sorted(glob.glob(str(ROOT / ".github/workflows/*.yml")))}
_n_ci = 0
# workflow 層級只給唯讀、寫入權限按 job 宣告
for _name, _t in _wf.items():
    for _p in _ci.workflow_write_permissions(_t):
        err(f".github/workflows/{_name}: workflow 層級 permissions 有 {_p}（寫入權限須在 job 層級宣告）"); _n_ci += 1
    for _j in _ci.sarif_jobs_without_permission(yaml.safe_load(_t) or {}):
        err(f".github/workflows/{_name}: job {_j} 上傳 SARIF 但有效權限沒有 security-events: write（上傳會失敗）"); _n_ci += 1
    for _s in _ci.self_sarif_uploads_without_hashfiles(yaml.safe_load(_t) or {}):
        err(f".github/workflows/{_name}: {_s} 上傳自產 SARIF 卻沒有 hashFiles 條件（閘門沒有判定任何發現時不寫 SARIF，"
            f"上傳步驟會失敗）"); _n_ci += 1
    for _s in _ci.gate_mode_channels(yaml.safe_load(_t) or {}):
        err(f".github/workflows/{_name}: {_s} 以 --mode／VIBESEC_MODE 把 mode 傳給閘門腳本（mode 只取自受信任政策，ADR 0002）"); _n_ci += 1
    for _s in _ci.step_mode_decisions(yaml.safe_load(_t) or {}):
        err(f".github/workflows/{_name}: {_s} 讀 mode 自己做阻擋判定（判定一律由 scripts/gate_verdict.py 執行，#209）"); _n_ci += 1
_action = ROOT / ".github/actions/vibesec-trusted/action.yml"
if _action.is_file():
    for _p in _ci.action_mode_reader_problems(yaml.safe_load(_action.read_text(encoding="utf-8")) or {}):
        err(f".github/actions/vibesec-trusted/action.yml: {_p}"); _n_ci += 1
else:
    err("缺 .github/actions/vibesec-trusted/action.yml：無法確認受信任設定 action 讀 mode 的方式"); _n_ci += 1
for _f in sorted(set(glob.glob(str(ROOT / ".github/**/*.yml"), recursive=True) + glob.glob(str(ROOT / ".github/**/*.js"), recursive=True))):
    for _i in _ci.unpaginated_list_comments(pathlib.Path(_f).read_text(encoding="utf-8")):
        err(f"{pathlib.Path(_f).relative_to(ROOT)}:{_i}: issues.listComments 未經 github.paginate（只會拿到第一頁 30 則）"); _n_ci += 1
_pc = ROOT / ".pre-commit-config.yaml"
_rules = (((load_yaml(ROOT / "vibesec.yaml") or {}).get("gates") or {}).get("g3_sast_iac") or {}).get("semgrep_rules") or []
if _pc.is_file() and _rules:
    _miss, _extra = _ci.precommit_semgrep_drift(_pc.read_text(encoding="utf-8"), _rules)
    if _miss or _extra:
        err(f".pre-commit-config.yaml 的 semgrep 規則集與 vibesec.yaml g3_sast_iac.semgrep_rules 不一致（少：{_miss or '無'}；多：{_extra or '無'}）"); _n_ci += 1
# staging 可由 workflow_dispatch 在任何分支觸發、步驟持有帳號 token：判定程式只能取自 _trusted/，目標 URL 不得經 sed 代入
if "staging-blackbox.yml" in _wf:
    for _i in _ci.untrusted_script_runs(_wf["staging-blackbox.yml"]):
        err(f".github/workflows/staging-blackbox.yml:{_i}: 執行本分支的 scripts/（判定程式只能取自 _trusted/）"); _n_ci += 1
    for _i in _ci.sed_target_substitution(_wf["staging-blackbox.yml"]):
        err(f".github/workflows/staging-blackbox.yml:{_i}: 以 sed 代入 VIBESEC_TARGET_URL（URL 含 # 或 & 會壞；改用 scripts/garak_config.py）"); _n_ci += 1
if "pr-gates.yml" in _wf and "staging-blackbox.yml" in _wf:
    for _m in _ci.verdict_wiring(yaml.safe_load(_wf["pr-gates.yml"]) or {}, yaml.safe_load(_wf["staging-blackbox.yml"]) or {}):
        err(f"{_m}（判定規則只有 scripts/gate_verdict.py 一份，docs/08 §8）"); _n_ci += 1
if "pr-gates.yml" in _wf:
    for _m in _ci.g4_static_wiring(yaml.safe_load(_wf["pr-gates.yml"]) or {}):
        err(f".github/workflows/pr-gates.yml：{_m}（#152）"); _n_ci += 1
if not _n_ci:
    ok("CI 設定不變式：workflow 層級唯讀、listComments 分頁、pre-commit semgrep 與 CI 一致、staging 只跑 _trusted/ 且不以 sed 代入目標、判定交給 gate_verdict、G4 靜態檢查以受信任腳本執行")

# 通過細項靜音；僅印摘要與警告/錯誤
print(f"通過 {len(oks)} 項；警告 {len(warns)}；錯誤 {len(errors)}")
for w in warns: print(f"  WARN {w}")
for e in errors: print(f"  ERR  {e}")
sys.exit(1 if errors else 0)
