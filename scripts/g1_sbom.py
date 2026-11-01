#!/usr/bin/env python3
"""VibeSec G1：產生 CycloneDX SBOM 並驗證它（控制 VS-G1-SBOM）。

做三件事，任何一件做不到都不算通過：
  1. 從受測 commit 匯出乾淨的樹（`git archive`，不讀工作目錄，所以本機裝過的 node_modules／.venv 不會混進來），
     以 syft 產生兩次 CycloneDX JSON；兩次的 components 集合必須相同（docs/02「驗證方式」第 4 項：SBOM 可重現）。
  2. 結構檢查：bomFormat 為 CycloneDX、specVersion 1.4 以上、components 是清單。
  3. 完整性：受測樹中每個鎖定檔（package-lock.json、npm-shrinkwrap.json、uv.lock、poetry.lock、requirements*.txt 中以 == 釘選者）
     釘選的每個套件版本，都必須以 purl 出現在 SBOM。缺漏 → vibesec.g1.sbom-incomplete（tier 依 blocking-policy），
     一個鎖定檔一筆，並讓 VS-G1-SBOM 為 fail。
     syft 預設不收 npm devDependencies；建置工具在建置時會執行，屬供應鏈範圍，所以這裡固定開啟
     SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES。

不可違反：
  - incomplete ≠ pass（AGENTS.md #2）：缺 syft、syft 失敗、SBOM 無法解析或格式不符、兩次產出不同、
    受測樹含尚無解析器的鎖定檔（pnpm-lock.yaml、yarn.lock、bun.lock、Pipfile.lock、pdm.lock、pylock.toml）→ status=incomplete、退出碼 2。
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
TOOL_NAME = "vibesec-g1-sbom"
sys.path.insert(0, str(ROOT / "scripts"))
import gate_result  # noqa: E402  併入的 tool 列與自產 SARIF 骨架只有一份寫法（#182）；不依賴 PyYAML
SPEC = re.compile(r"^1\.(\d+)$")
# 與 g1_slopcheck.REQUIREMENTS_RE 一致：檔名含 requirements 的 .txt（locks/python-requirements.txt），
# 或 requirements/ 目錄下的 .txt（requirements/base.txt）
LOCKFILE = re.compile(r"(?:(?:^|/)(?:package-lock\.json|npm-shrinkwrap\.json|uv\.lock|poetry\.lock)"
                      r"|[^/]*requirements[^/]*\.txt|(?:^|/)requirements/(?:[^/]+/)*[^/]+\.txt)$")
# npm／PyPI 生態系中尚無解析器的鎖定檔：裡面釘選的套件無法逐一核對是否出現在 SBOM → incomplete（不是 pass）。
# 以前只認 pnpm-lock.yaml、yarn.lock：npm-shrinkwrap.json、Pipfile.lock 等被當成「沒有鎖定檔」，核對直接通過。
UNPARSED = re.compile(r"(?:^|/)(pnpm-lock\.yaml|yarn\.lock|bun\.lockb?|Pipfile\.lock|pdm\.lock|pylock(?:\.[^/]+)?\.toml)$")
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
    try:
        with tarfile.open(fileobj=io.BytesIO(data)) as tf:
            tf.extractall(dest, filter="data")
    except (tarfile.TarError, OSError) as e:
        # 例如 `* export-ignore` 讓 git archive 輸出空的 tar：以前未捕捉、整支崩潰
        raise SbomError(f"無法解開 {sha[:12]} 的匯出內容（{type(e).__name__}）；可能是 .gitattributes 的 export-ignore 略過了所有檔案") from e
    _check_export_attrs(target, sha, dest)
    return sha


def _check_export_attrs(target: pathlib.Path, sha: str, dest: pathlib.Path) -> None:
    """git archive 會套用受測樹自己 .gitattributes 的 export-ignore／export-subst：PR 加一行
    `package-lock.json export-ignore`，syft 與鎖定檔核對看到的是同一棵被刪過的樹（結果一致），KEV 命中就消失了。
    比對 commit 的檔案清單與匯出結果；有檔案被略過，或有檔案設了 export-subst（內容會被改寫）→ SbomError（incomplete）。"""
    try:
        ls = subprocess.run(["git", "-C", str(target), "ls-tree", "-r", "-z", sha],
                            capture_output=True, check=True).stdout.decode("utf-8", "surrogateescape")
        tracked = [e.split("\t", 1)[1] for e in ls.split("\0") if "\t" in e and not e.startswith("160000 ")]
        attrs = subprocess.run(["git", "-C", str(target), "check-attr", "--source", sha, "-z", "--stdin",
                                "export-ignore", "export-subst"], input="\0".join(tracked).encode("utf-8", "surrogateescape"),
                               capture_output=True, check=True).stdout.decode("utf-8", "surrogateescape").split("\0")
    except (OSError, subprocess.CalledProcessError) as e:
        raise SbomError(f"無法核對 {sha[:12]} 的匯出屬性（git ls-tree／check-attr 失敗）：{e}") from e
    flagged = sorted({attrs[i] for i in range(0, len(attrs) - 2, 3) if attrs[i + 2] not in ("unspecified", "unset", "")})
    missing = sorted(p for p in tracked if not os.path.lexists(dest / p))
    if flagged or missing:
        shown = (flagged or missing)[:EXAMPLES]
        raise SbomError(f"受測樹以 .gitattributes 的 export-ignore／export-subst 改變了匯出內容（{len(set(flagged) | set(missing))} 個檔案，"
                        f"例如 {', '.join(shown)}）：SBOM 與鎖定檔核對看不到原始內容，無法確認")


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
    reasons = []
    for rel in found:
        entries, bad = sc.parse_manifest([tree / rel])
        pinned = sorted({(e, n, v) for e, n, v in entries if v})
        missing = [f"{n}@{v}" for e, n, v in pinned if (e, norm(e, n), v) not in have]
        per[rel] = {"pinned": len(pinned), "missing": missing}
        if bad:
            # 解析失敗或非 registry 來源：pinned 會是 0，以前因此「核對通過」（第四次審視 S-9）
            reasons.append(f"{rel}：{len(bad)} 筆無法解析或不是 registry 來源，SBOM 核對不完整")
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


def findings(summary: dict, policy: "Policy") -> list[dict]:
    """policy：tier 唯一來源（blocking-policy）；由進入點建立一次傳入。"""
    tier = policy.tier(RULE)
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
    rules = [{"id": RULE, "name": RULE, "shortDescription": {"text": "SBOM 缺少鎖定檔釘選的套件"}}] if found else []
    results = [{"ruleId": f["rule_id"], "level": level.get(f["policy_tier"], "warning"),
                "message": {"text": f["message"]},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["path"]}}}],
                "partialFingerprints": {"vibesecSbom": f"{RULE}|{f['path']}"},
                "properties": {"policy_tier": f["policy_tier"], "missing": f["missing"], "pinned": f["pinned"]}}
               for f in found]
    return gate_result.sarif({"name": TOOL_NAME, "version": VERSION}, rules, results)


def run(target: pathlib.Path, commit: str, out: pathlib.Path, syft=run_syft) -> dict:
    out.unlink(missing_ok=True)   # 不讓上一次的 SBOM 被 grype／維護狀態／provenance 當成這次的結果
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
    fails: list[str] = []
    sys.path.insert(0, str(ROOT / "scripts"))
    from vibesec_policy import Policy
    P = Policy(ROOT)

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
        if not LOCKFILE.search("requirements/base.txt") or LOCKFILE.search("docs/notes.txt"):
            fails.append("requirements/ 目錄下的 .txt 也要核對（與 g1_slopcheck.REQUIREMENTS_RE 一致），其他 .txt 不算")
        if "requirements-dev.txt" in s["lockfiles"] and s["lockfiles"]["requirements-dev.txt"]["pinned"]:
            fails.append("沒有釘選的 requirements 不應產生核對項目")
        nodev = bom("pkg:npm/left-pad@1.3.0", "pkg:pypi/typing-extensions@4.12.2", "pkg:pypi/idna@3.10")
        s = run(repo, "HEAD", out, fake([nodev, nodev]))
        if s["status"] != "fail" or s["lockfiles"]["web/package-lock.json"]["missing"] != ["@babel/core@7.29.7"]:
            fails.append(f"缺 devDependency 應為 fail 並列出套件：{s}")
        f = findings(s, P)
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
        out.write_text(json.dumps(full))              # 上一次留下的 SBOM
        if run(repo, "HEAD", out, boom)["status"] != "incomplete":
            fails.append("syft 失敗應為 incomplete")
        if out.exists():
            fails.append("SbomError 時應刪除上一次的 --sbom 輸出，不讓下游用到舊 SBOM")
        if run(pathlib.Path(d) / "not-a-repo", "HEAD", out, fake([full, full]))["status"] != "incomplete":
            fails.append("無法匯出 commit 應為 incomplete")
        # .gitattributes export-ignore／export-subst：git archive 會略過或改寫檔案，SBOM 與核對看到的是被刪過的樹
        for attr in ("web/package-lock.json export-ignore", "requirements.lock.txt export-subst", "* export-ignore"):
            (repo / ".gitattributes").write_text(attr + "\n"); git("add", "-A"); git("commit", "-qm", "attr")
            s = run(repo, "HEAD", out, fake([full, full]))
            if s["status"] != "incomplete" or "export-" not in (s["status_reason"] or ""):
                fails.append(f".gitattributes「{attr}」應讓 SBOM incomplete（得到 {s['status']}：{s.get('status_reason')}）")
        (repo / ".gitattributes").write_text("*.png binary\n"); git("add", "-A"); git("commit", "-qm", "attr-ok")
        if run(repo, "HEAD", out, fake([full, full]))["status"] != "pass":
            fails.append("與匯出無關的 .gitattributes（binary）不應影響結果")
        git("rm", "-q", ".gitattributes"); git("commit", "-qm", "rm-attr")
        (repo / "yarn.lock").write_text("# yarn\n"); git("add", "-A"); git("commit", "-qm", "yarn")
        s = run(repo, "HEAD", out, fake([full, full]))
        if s["status"] != "incomplete" or "yarn.lock" not in s["status_reason"]:
            fails.append(f"含無解析器的鎖定檔應為 incomplete：{s}")
        for name in ("Pipfile.lock", "sub/bun.lock", "pdm.lock", "pylock.toml", "pylock.dev.toml"):
            if not UNPARSED.search(name):
                fails.append(f"{name} 是尚無解析器的鎖定檔，應讓 SBOM 核對 incomplete（以前被當成沒有鎖定檔）")
        if UNPARSED.search("docs/pylock-notes.md") or UNPARSED.search("Pipfile.lock.bak"):
            fails.append("非鎖定檔不應被當成無解析器的鎖定檔")
        if not LOCKFILE.search("app/npm-shrinkwrap.json"):
            fails.append("npm-shrinkwrap.json（格式同 package-lock.json）應核對 SBOM 是否完整")
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
    # 接線：政策讀不到時經過共用的檢查執行（生命週期本身在 gate_result 測，#245）；SBOM 自己的特例是刪掉舊 SBOM
    import contextlib, io
    from vibesec_policy import POLICY_UNREADABLE, broken_policy_root, temp_policy_root
    with broken_policy_root() as pr, tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
        js, gp = pathlib.Path(d, "out.json"), pathlib.Path(d, "G1.json")
        gp.write_text(json.dumps(base), encoding="utf-8")
        so = pathlib.Path(d, "s.cdx.json"); so.write_text("上一次的 SBOM", encoding="utf-8")   # 不得被下游當成這次的 SBOM
        rc = main(["--target", d, "--sbom", str(so), "--sarif", str(pathlib.Path(d, "out.sarif")), "--json", str(js),
                   "--merge-gate", str(gp)], policy_root=pr)
        sm, g = json.loads(js.read_text(encoding="utf-8")), json.loads(gp.read_text(encoding="utf-8"))
        if rc != 2 or not str(sm.get("status_reason")).startswith(POLICY_UNREADABLE + "（") or sm.get("lockfiles") != {} \
                or g["tools"][-1:] != [gate_result.tool(TOOL_NAME, "error", version=VERSION)] or so.exists():
            fails.append(f"SBOM：政策讀不到 → 經過檢查執行（退出碼 2、SBOM 的 tool 列 error）並刪掉舊 SBOM"
                         f"（得到 {rc}、SBOM 存在={so.exists()}、{sm}、{g['tools']}）")
    # 接線：判定完成時從進入點經過 findings → SARIF → 併入（假的 syft 以 VIBESEC_SYFT 指向腳本，寫出 SBOM 到 -o 指定的位置）
    with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
        repo, fake_syft = pathlib.Path(d, "repo"), pathlib.Path(d, "syft")
        repo.mkdir()
        git = lambda *a: subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True, check=True)
        git("init", "-q"); git("config", "user.email", "t@example.invalid"); git("config", "user.name", "t"); git("config", "commit.gpgsign", "false")
        (repo / "package-lock.json").write_text(json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},
            "node_modules/is-odd": {"version": "3.0.1", "resolved": "https://registry.npmjs.org/is-odd/-/is-odd-3.0.1.tgz"}}}))
        git("add", "-A"); git("commit", "-qm", "init")
        doc = json.dumps(bom("pkg:npm/left-pad@1.3.0"))   # 缺 is-odd
        fake_syft.write_text("#!/bin/sh\nfor a; do case $a in cyclonedx-json=*) printf '%s' '" + doc + "' > \"${a#cyclonedx-json=}\";; esac; done\n")
        fake_syft.chmod(0o755)
        js, sf, gp = pathlib.Path(d, "out.json"), pathlib.Path(d, "out.sarif"), pathlib.Path(d, "G1.json")
        gp.write_text(json.dumps(base), encoding="utf-8")
        old = os.environ.get("VIBESEC_SYFT"); os.environ["VIBESEC_SYFT"] = str(fake_syft)
        try:
            with temp_policy_root() as pr:
                rc = main(["--target", str(repo), "--sbom", str(pathlib.Path(d, "s.cdx.json")), "--sarif", str(sf), "--json", str(js),
                           "--merge-gate", str(gp)], policy_root=pr)
                tier = Policy(pr).tier(RULE)
        finally:
            os.environ.pop("VIBESEC_SYFT") if old is None else os.environ.__setitem__("VIBESEC_SYFT", old)
        sm, g = json.loads(js.read_text(encoding="utf-8")), json.loads(gp.read_text(encoding="utf-8"))
        res = json.loads(sf.read_text(encoding="utf-8"))["runs"][0]["results"] if sf.exists() else None
        want_fc = {"blocking": 1, "advisory": 0} if tier == "blocking" else {"blocking": 0, "advisory": 1}
        if sm.get("status") != "fail" or rc != (1 if tier == "blocking" else 0) or not res or len(res) != 1 \
                or res[0]["properties"]["policy_tier"] != tier or g["findings_count"] != want_fc:
            fails.append(f"SBOM 進入點：鎖定檔缺 1 個套件 → fail、SARIF 1 筆（{tier}）、併入計數 {want_fc}、退出碼依 tier"
                         f"（得到 {rc}、{sm.get('status')}、{res}、{g['findings_count']}）")
    return fails


def main(argv=None, policy_root: pathlib.Path = ROOT) -> int:
    """policy_root：阻擋政策所在的 repo（selftest 指向壞政策檔）。"""
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
    sbom = pathlib.Path(a.sbom)

    def unreadable(problem):   # 政策讀不到：不產生 SBOM、不分類發現
        sbom.unlink(missing_ok=True)   # 不讓上一次的 SBOM 被 grype／維護狀態／provenance 當成這次的結果
        return {"status": "incomplete", "status_reason": problem, "lockfiles": {}, "commit": None}

    def report(summary, found, policy):
        for f in found:
            print(f"::warning::{f['message']}" if f["policy_tier"] == "advisory" else f"::error::{f['message']}")
        print(f"SBOM {summary['status']}：{summary['components']} 個元件（CycloneDX {summary['spec_version']}），"
              f"核對 {sum(v['pinned'] for v in summary['lockfiles'].values())} 個釘選套件")

    # 生命週期（政策讀不到、摘要、SARIF 寫出或刪掉舊檔、併入 G1、退出碼）由檢查執行負責（#245）
    return gate_result.CheckRun(
        label="SBOM", tool_name=TOOL_NAME, version=VERSION, merge_into=("G1", CONTROL),
        check=lambda policy: run(pathlib.Path(a.target), a.commit, sbom),
        findings=findings, to_sarif=lambda summary, found, policy: to_sarif(found),
        unreadable=unreadable, report=report,
    ).execute(policy_root=policy_root, sarif_path=a.sarif, json_path=a.json, merge_gate=a.merge_gate)

if __name__ == "__main__":
    sys.exit(main())
