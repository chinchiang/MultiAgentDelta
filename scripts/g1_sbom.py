#!/usr/bin/env python3
"""VibeSec G1：產生 CycloneDX SBOM 並驗證它（控制 VS-G1-SBOM）。

做三件事，任何一件做不到都不算通過：
  1. 從受測 commit 匯出乾淨的樹（`git archive`，不讀工作目錄，所以本機裝過的 node_modules／.venv 不會混進來），
     以 syft 產生兩次 CycloneDX JSON；兩次的 components 集合必須相同（docs/02「驗證方式」第 4 項：SBOM 可重現）。
  2. 結構檢查：bomFormat 為 CycloneDX、specVersion 1.4 以上、components 是清單。
  3. 完整性：受測樹中每個鎖定檔（package-lock.json、uv.lock、poetry.lock、requirements*.txt 中以 == 釘選者）
     釘選的每個套件版本，都必須以 purl 出現在 SBOM。缺漏 → vibesec.g1.sbom-incomplete（tier 依 blocking-policy），
     一個鎖定檔一筆，並讓 VS-G1-SBOM 為 fail。
     syft 預設不收 npm devDependencies；建置工具在建置時會執行，屬供應鏈範圍，所以這裡固定開啟
     SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES。

不可違反：
  - incomplete ≠ pass（CLAUDE.md #2）：缺 syft、syft 失敗、SBOM 無法解析或格式不符、兩次產出不同、
    受測樹含尚無解析器的鎖定檔（pnpm-lock.yaml、yarn.lock）→ status=incomplete、退出碼 2。
  - 本程式不放寬也不改寫政策：tier 一律取自 config/policy/blocking-policy.yaml（scripts/vibesec_policy.py）。

用法：
  python3 scripts/g1_sbom.py --target . --sbom reports/sbom.cdx.json \\
      --sarif reports/g1-sbom.sarif --json reports/g1-sbom.json --merge-gate reports/g1-gate.json
  python3 scripts/g1_sbom.py selftest
syft 路徑：$VIBESEC_SYFT，否則 PATH 上的 syft。
退出碼：0 已完成（含 advisory 發現）；1 有 blocking 發現；2 incomplete。
"""
from __future__ import annotations
import argparse, importlib.util, io, json, os, pathlib, re, shutil, subprocess, sys, tarfile, tempfile
from urllib.parse import unquote

ROOT = pathlib.Path(__file__).resolve().parent.parent
RULE = "vibesec.g1.sbom-incomplete"
CONTROL = "VS-G1-SBOM"
VERSION = "1.0.0"
SPEC = re.compile(r"^1\.(\d+)$")
# 與 g1_slopcheck.MANIFEST_RE 一致：檔名含 requirements 的 .txt 都算（例如 locks/python-requirements.txt）
LOCKFILE = re.compile(r"(?:(?:^|/)(?:package-lock\.json|uv\.lock|poetry\.lock)|requirements[^/]*\.txt)$")
UNPARSED = re.compile(r"(?:^|/)(pnpm-lock\.yaml|yarn\.lock)$")
PURL = re.compile(r"^pkg:(npm|pypi)/([^@?#]+)@([^?#]+)")
SYFT_ENV = {"SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES": "true", "SYFT_CHECK_FOR_APP_UPDATE": "false"}
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}
EXAMPLES = 10


class SbomError(Exception):
    """無法產生或解讀 SBOM：一律 incomplete。"""


def _slopcheck():
    """沿用 g1_slopcheck 的鎖定檔解析器，兩支程式對「釘選了哪些套件」的認定才會一致。"""
    spec = importlib.util.spec_from_file_location("g1_slopcheck", ROOT / "scripts" / "g1_slopcheck.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def norm(eco: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if eco == "pypi" else name.lower()


def component_keys(sbom: dict) -> set[tuple[str, str, str]]:
    """結構檢查並回傳 {(ecosystem, 正規化名稱, 版本)}（只收 npm、pypi 的 purl）。"""
    if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX":
        raise SbomError("不是 CycloneDX 文件（bomFormat ≠ CycloneDX）")
    m = SPEC.match(str(sbom.get("specVersion") or ""))
    if not m or int(m.group(1)) < 4:
        raise SbomError(f"CycloneDX specVersion {sbom.get('specVersion')!r} 不支援（需 1.4 以上）")
    comps = sbom.get("components")
    if not isinstance(comps, list):
        raise SbomError("components 不是清單")
    keys = set()
    for c in comps:
        p = PURL.match(str((c or {}).get("purl") or "")) if isinstance(c, dict) else None
        if p:
            keys.add((p.group(1), norm(p.group(1), unquote(p.group(2))), unquote(p.group(3))))
    return keys


def _identity(sbom: dict) -> set[tuple]:
    """比較可重現性用：忽略 serialNumber、timestamp 與 bom-ref（syft 每次重新產生）。"""
    return {(c.get("type"), c.get("name"), c.get("version"), c.get("purl"))
            for c in sbom.get("components") or [] if isinstance(c, dict)}


def export_tree(target: pathlib.Path, commit: str, dest: pathlib.Path) -> str:
    try:
        sha = subprocess.run(["git", "-C", str(target), "rev-parse", "--verify", f"{commit}^{{commit}}"],
                             capture_output=True, text=True, check=True).stdout.strip()
        data = subprocess.run(["git", "-C", str(target), "archive", "--format=tar", sha],
                              capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        raise SbomError(f"無法從 {target} 匯出 {commit}（需要 git repo）：{e}") from e
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        tf.extractall(dest, filter="data")
    return sha


def syft_binary() -> str:
    wanted = os.environ.get("VIBESEC_SYFT")
    found = shutil.which(wanted) if wanted else shutil.which("syft")
    if not found:
        raise SbomError(f"VIBESEC_SYFT={wanted!r} 不是可執行檔" if wanted else "PATH 上找不到 syft")
    return str(pathlib.Path(found).resolve())


def run_syft(tree: pathlib.Path, out: pathlib.Path, binary: str) -> dict:
    env = {**os.environ, **SYFT_ENV}
    try:
        r = subprocess.run([binary, f"dir:{tree}", "-q", "-o", f"cyclonedx-json={out}"],
                           capture_output=True, text=True, env=env, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise SbomError(f"syft 無法執行：{e}") from e
    if r.returncode != 0 or not out.is_file():
        raise SbomError(f"syft 失敗（exit {r.returncode}）：{(r.stderr or '').strip()[:200]}")
    try:
        return json.loads(out.read_text(encoding="utf-8"))
    except ValueError as e:
        raise SbomError(f"syft 輸出不是 JSON：{e}") from e


def generate(tree: pathlib.Path, out: pathlib.Path, syft=run_syft) -> dict:
    """產生兩次並比對；可重現才寫到 out。"""
    binary = syft_binary() if syft is run_syft else "syft"
    with tempfile.TemporaryDirectory(prefix="vibesec-sbom-") as d:
        first = syft(tree, pathlib.Path(d) / "a.json", binary)
        second = syft(tree, pathlib.Path(d) / "b.json", binary)
    a, b = _identity(first), _identity(second)
    if a != b:
        raise SbomError(f"同一棵樹兩次產生的 SBOM 不同（差異 {len(a ^ b)} 筆）：無法確認內容")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(first, ensure_ascii=False, indent=2), encoding="utf-8")
    return first


def lockfiles(tree: pathlib.Path) -> tuple[list[str], list[str]]:
    found, unparsed = [], []
    for d, dirs, names in os.walk(tree):
        dirs[:] = sorted(x for x in dirs if x not in SKIP_DIRS)
        for n in sorted(names):
            rel = pathlib.Path(d, n).relative_to(tree).as_posix()
            if LOCKFILE.search(rel):
                found.append(rel)
            elif UNPARSED.search(rel):
                unparsed.append(rel)
    return found, unparsed


def check(sbom: dict, tree: pathlib.Path) -> dict:
    """回傳摘要：status（pass／fail／incomplete）、每個鎖定檔的釘選數與缺漏。"""
    try:
        have = component_keys(sbom)
    except SbomError as e:
        return {"status": "incomplete", "status_reason": f"SBOM 格式不符：{e}", "lockfiles": {}}
    sc = _slopcheck()
    found, unparsed = lockfiles(tree)
    per = {}
    for rel in found:
        pinned = sorted({(e, n, v) for e, n, v in sc.parse_added([tree / rel]) if v})
        missing = [f"{n}@{v}" for e, n, v in pinned if (e, norm(e, n), v) not in have]
        per[rel] = {"pinned": len(pinned), "missing": missing}
    reasons = []
    if unparsed:
        reasons.append(f"鎖定檔尚無解析器，無法核對 SBOM 是否完整：{', '.join(unparsed)}")
    gaps = {k: v for k, v in per.items() if v["missing"]}
    if reasons:
        status = "incomplete"
    else:
        status = "fail" if gaps else "pass"
    if gaps:
        reasons.append("SBOM 缺少釘選套件：" + "、".join(f"{k} {len(v['missing'])}/{v['pinned']}" for k, v in gaps.items()))
    return {"status": status, "status_reason": "；".join(reasons) or None, "lockfiles": per,
            "components": len(sbom.get("components") or []), "spec_version": sbom.get("specVersion")}


def findings(summary: dict) -> list[dict]:
    sys.path.insert(0, str(ROOT / "scripts"))
    from vibesec_policy import Policy
    tier = Policy(ROOT).tier(RULE)
    out = []
    for rel, v in sorted((summary.get("lockfiles") or {}).items()):
        if v["missing"]:
            sample = "、".join(v["missing"][:EXAMPLES]) + ("…" if len(v["missing"]) > EXAMPLES else "")
            out.append({"rule_id": RULE, "policy_tier": tier, "path": rel, "missing": len(v["missing"]),
                        "pinned": v["pinned"],
                        "message": f"{rel} 釘選的 {v['pinned']} 個套件中，有 {len(v['missing'])} 個不在 SBOM：{sample}"})
    return out


def to_sarif(found: list[dict]) -> dict:
    level = {"blocking": "error", "advisory": "warning"}
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "vibesec-g1-sbom", "version": VERSION,
                                          "informationUri": "https://github.com/chinchiang/MultiAgentDelta",
                                          "rules": [{"id": RULE, "name": RULE, "shortDescription": {"text": "SBOM 缺少鎖定檔釘選的套件"}}]
                                          if found else []}},
                      "results": [{"ruleId": f["rule_id"], "level": level.get(f["policy_tier"], "warning"),
                                   "message": {"text": f["message"]},
                                   "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["path"]}}}],
                                   "partialFingerprints": {"vibesecSbom": f"{RULE}|{f['path']}"},
                                   "properties": {"policy_tier": f["policy_tier"], "missing": f["missing"], "pinned": f["pinned"]}}
                                  for f in found]}]}


_RANK = {"pass": 0, "incomplete": 1, "fail": 2}


def merge_gate(gate: dict, summary: dict, found: list[dict], sarif_ref: str | None) -> dict:
    """併入 G1 gate-result：取代 VS-G1-SBOM 的 coverage；status 只升不降（incomplete ≠ pass）。
    只有 blocking 發現會讓 G1 變 fail；advisory 發現只計數，但 VS-G1-SBOM 仍記 fail（控制本身沒有達成）。"""
    g = json.loads(json.dumps(gate))
    st = summary["status"]
    blocking = sum(f["policy_tier"] == "blocking" for f in found)
    effect = "incomplete" if st == "incomplete" else ("fail" if blocking else "pass")
    cur = g.get("status", "pass")
    if cur in _RANK and _RANK[effect] > _RANK[cur]:
        g["status"] = effect
    reasons = [r for r in [g.get("status_reason")] if r]
    if summary.get("status_reason"):
        reasons.append(f"SBOM：{summary['status_reason']}")
    g["status_reason"] = "；".join(reasons) or None
    fc = g.setdefault("findings_count", {"blocking": 0, "advisory": 0})
    fc["blocking"] = int(fc.get("blocking") or 0) + blocking
    fc["advisory"] = int(fc.get("advisory") or 0) + len(found) - blocking
    g.setdefault("tools", []).append({"name": "vibesec-g1-sbom", "version": VERSION, "state": "ran",
                                      "exit_code": 2 if st == "incomplete" else (1 if blocking else 0),
                                      "output_ref": sarif_ref, "duration_seconds": None})
    state = {"pass": "pass", "fail": "fail", "incomplete": "untested"}[st]
    cov = [c for c in g.get("coverage") or [] if c.get("control_id") != CONTROL]
    cov.append({"control_id": CONTROL, "state": state, "reason": summary.get("status_reason")})
    g["coverage"] = cov
    return g


def run(target: pathlib.Path, commit: str, out: pathlib.Path, syft=run_syft) -> dict:
    with tempfile.TemporaryDirectory(prefix="vibesec-sbom-tree-") as d:
        tree = pathlib.Path(d) / "src"
        tree.mkdir()
        try:
            sha = export_tree(target, commit, tree)
            sbom = generate(tree, out, syft)
        except SbomError as e:
            return {"status": "incomplete", "status_reason": str(e), "lockfiles": {}, "commit": None}
        summary = check(sbom, tree)
    summary["commit"] = sha
    summary["syft_env"] = SYFT_ENV
    return summary


def selftest() -> list[str]:
    from jsonschema import Draft202012Validator
    fails: list[str] = []
    schema = Draft202012Validator(json.loads((ROOT / "schemas/gate-result.schema.json").read_text(encoding="utf-8")))

    def bom(*purls, spec="1.6"):
        return {"bomFormat": "CycloneDX", "specVersion": spec,
                "components": [{"type": "library", "name": p, "version": "x", "purl": p} for p in purls]}

    with tempfile.TemporaryDirectory() as d:
        repo = pathlib.Path(d) / "repo"
        (repo / "web").mkdir(parents=True)
        git = lambda *a: subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True, check=True)
        git("init", "-q")
        git("config", "user.email", "t@example.invalid"); git("config", "user.name", "t"); git("config", "commit.gpgsign", "false")
        (repo / "web/package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
            "": {"devDependencies": {"@babel/core": "^7"}},
            "node_modules/@babel/core": {"version": "7.29.7", "resolved": "https://registry.npmjs.org/@babel/core/-/core-7.29.7.tgz", "dev": True},
            "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}))
        (repo / "requirements.lock.txt").write_text("Typing_Extensions==4.12.2\nrequests>=2\n")
        (repo / "requirements-dev.txt").write_text("pytest\n")
        (repo / "locks").mkdir()
        (repo / "locks/python-requirements.txt").write_text("idna==3.10\n")
        git("add", "-A"); git("commit", "-qm", "init")
        (repo / "web/package-lock.json").write_text("{}")            # 工作目錄的改動不得影響結果（只讀 commit）
        full = bom("pkg:npm/%40babel/core@7.29.7", "pkg:npm/left-pad@1.3.0", "pkg:pypi/typing-extensions@4.12.2", "pkg:pypi/idna@3.10")

        def fake(sboms):
            seq = iter(sboms)
            return lambda tree, out, binary: json.loads(json.dumps(next(seq)))

        out = pathlib.Path(d) / "sbom.json"
        s = run(repo, "HEAD", out, fake([full, full]))
        if s["status"] != "pass" or not out.is_file():
            fails.append(f"完整且可重現的 SBOM 應為 pass：{s}")
        if s["lockfiles"].get("requirements.lock.txt", {}).get("pinned") != 1:
            fails.append("requirements 只核對以 == 釘選者")
        if s["lockfiles"].get("locks/python-requirements.txt", {}).get("pinned") != 1:
            fails.append("檔名含 requirements 的 .txt（locks/python-requirements.txt）也要核對")
        if "requirements-dev.txt" in s["lockfiles"] and s["lockfiles"]["requirements-dev.txt"]["pinned"]:
            fails.append("沒有釘選的 requirements 不應產生核對項目")
        nodev = bom("pkg:npm/left-pad@1.3.0", "pkg:pypi/typing-extensions@4.12.2", "pkg:pypi/idna@3.10")
        s = run(repo, "HEAD", out, fake([nodev, nodev]))
        if s["status"] != "fail" or s["lockfiles"]["web/package-lock.json"]["missing"] != ["@babel/core@7.29.7"]:
            fails.append(f"缺 devDependency 應為 fail 並列出套件：{s}")
        f = findings(s)
        if len(f) != 1 or f[0]["path"] != "web/package-lock.json" or f[0]["policy_tier"] not in ("advisory", "blocking"):
            fails.append(f"每個有缺漏的鎖定檔一筆發現：{f}")
        s = run(repo, "HEAD", out, fake([full, nodev]))
        if s["status"] != "incomplete" or "兩次" not in s["status_reason"]:
            fails.append(f"兩次產出不同應為 incomplete：{s}")
        for bad, why in ((bom(spec="1.3"), "specVersion"), ({**bom("pkg:npm/left-pad@1.3.0"), "bomFormat": "SPDX"}, "bomFormat"),
                         ({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": {}}, "components")):
            s = run(repo, "HEAD", out, fake([bad, bad]))
            if s["status"] != "incomplete":
                fails.append(f"格式不符（{why}）應為 incomplete：{s}")
        def boom(tree, out, binary): raise SbomError("syft 失敗（exit 1）")
        if run(repo, "HEAD", out, boom)["status"] != "incomplete":
            fails.append("syft 失敗應為 incomplete")
        if run(pathlib.Path(d) / "not-a-repo", "HEAD", out, fake([full, full]))["status"] != "incomplete":
            fails.append("無法匯出 commit 應為 incomplete")
        (repo / "yarn.lock").write_text("# yarn\n"); git("add", "-A"); git("commit", "-qm", "yarn")
        s = run(repo, "HEAD", out, fake([full, full]))
        if s["status"] != "incomplete" or "yarn.lock" not in s["status_reason"]:
            fails.append(f"含無解析器的鎖定檔應為 incomplete：{s}")
        old = os.environ.get("VIBESEC_SYFT")
        try:
            os.environ["VIBESEC_SYFT"] = str(pathlib.Path(d) / "missing-syft")
            try:
                syft_binary(); fails.append("VIBESEC_SYFT 指向不存在的檔案應拒絕")
            except SbomError:
                pass
        finally:
            os.environ.pop("VIBESEC_SYFT", None)
            if old is not None:
                os.environ["VIBESEC_SYFT"] = old

    base = {"gate": "G1", "status": "pass", "status_reason": None, "mode": "shadow", "risk_tier": "L3", "scope": "full",
            "diff_base": None, "commit": None, "started_at": "2026-01-01T00:00:00Z", "finished_at": "2026-01-01T00:00:00Z",
            "tools": [], "findings_count": {"blocking": 0, "advisory": 0},
            "coverage": [{"control_id": CONTROL, "state": "pending", "reason": None}]}
    adv = [{"rule_id": RULE, "policy_tier": "advisory", "path": "a", "missing": 1, "pinned": 2, "message": "m"}]
    m = merge_gate(base, {"status": "fail", "status_reason": "缺"}, adv, "r.sarif")
    sb = [c for c in m["coverage"] if c["control_id"] == CONTROL]
    if m["status"] != "pass" or len(sb) != 1 or sb[0]["state"] != "fail" or m["findings_count"] != {"blocking": 0, "advisory": 1}:
        fails.append(f"advisory 缺漏：G1 不變、VS-G1-SBOM 只留一筆且為 fail：{m}")
    m = merge_gate(base, {"status": "fail", "status_reason": "缺"}, [{**adv[0], "policy_tier": "blocking"}], "r.sarif")
    if m["status"] != "fail" or m["findings_count"]["blocking"] != 1:
        fails.append("blocking 缺漏應讓 G1 fail")
    m = merge_gate(base, {"status": "incomplete", "status_reason": "缺 syft"}, [], None)
    if m["status"] != "incomplete" or "缺 syft" not in m["status_reason"] or m["coverage"][-1]["state"] != "untested":
        fails.append("incomplete 應讓 G1 incomplete 並記 untested")
    m = merge_gate({**base, "status": "fail"}, {"status": "pass", "status_reason": None}, [], "r.sarif")
    if m["status"] != "fail" or m["coverage"][-1]["state"] != "pass":
        fails.append("pass 不得降低既有的 fail")
    if base["coverage"][0]["state"] != "pending":
        fails.append("merge_gate 不得修改輸入物件")
    for e in schema.iter_errors(merge_gate(base, {"status": "fail", "status_reason": "缺"}, adv, "r.sarif")):
        fails.append(f"merge_gate 輸出不符 gate-result schema：{e.message}")
    return fails


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if argv[:1] == ["selftest"]:
        fails = selftest()
        print("\n".join(f"FAIL {x}" for x in fails) or "g1_sbom selftest ok")
        return 1 if fails else 0
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--target", default=".", help="受測專案的 git repo 根目錄")
    ap.add_argument("--commit", default="HEAD")
    ap.add_argument("--sbom", required=True, help="SBOM 輸出位置（CycloneDX JSON，供 grype 使用）")
    ap.add_argument("--sarif", required=True)
    ap.add_argument("--json", required=True)
    ap.add_argument("--merge-gate", help="併入既有的 G1 gate-result（就地更新）；檔案不存在則略過")
    a = ap.parse_args(argv)
    summary = run(pathlib.Path(a.target), a.commit, pathlib.Path(a.sbom))
    found = []
    if summary["status"] != "incomplete":
        try:
            found = findings(summary)
        except ImportError as e:       # 缺 PyYAML：查不到政策 tier，不自行假設
            summary = {**summary, "status": "incomplete", "status_reason": f"無法讀取阻擋政策（{e}），不能決定發現的 tier"}
    for p in (a.sarif, a.json):
        pathlib.Path(p).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(a.json).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    pathlib.Path(a.sarif).write_text(json.dumps(to_sarif(found), ensure_ascii=False, indent=2), encoding="utf-8")
    if a.merge_gate:
        gp = pathlib.Path(a.merge_gate)
        if gp.is_file():
            merged = merge_gate(json.loads(gp.read_text(encoding="utf-8")), summary, found,
                                a.sarif if summary["status"] != "incomplete" else None)
            gp.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
        else:
            print(f"::warning::{gp} 不存在，SBOM 結果未併入 G1 gate")
    if summary["status"] == "incomplete":
        print(f"::error::SBOM 檢查未完成（incomplete ≠ pass）：{summary['status_reason']}")
        return 2
    for f in found:
        print(f"::warning::{f['message']}" if f["policy_tier"] == "advisory" else f"::error::{f['message']}")
    print(f"SBOM {summary['status']}：{summary['components']} 個元件（CycloneDX {summary['spec_version']}），"
          f"核對 {sum(v['pinned'] for v in summary['lockfiles'].values())} 個釘選套件")
    return 1 if any(f["policy_tier"] == "blocking" for f in found) else 0


if __name__ == "__main__":
    sys.exit(main())
