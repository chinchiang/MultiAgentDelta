#!/usr/bin/env python3
"""VibeSec G1：SBOM 缺少可驗證的來源證明（SLSA provenance）→ vibesec.g1.sbom-missing-provenance（advisory）。

nightly 以 actions/attest-build-provenance 為 reports/sbom.cdx.json 簽發來源證明（Sigstore，記錄於 GitHub attestations）。
本腳本以 `gh attestation verify` 驗證：證明存在、簽章有效，且簽發者是本 repo 指定的 workflow（--signer-workflow），
避免「任何人替這份檔案簽了一張證明」也算通過。

判定：
  - verify 成功 → pass
  - gh 明確回報找不到證明或驗證失敗 → 命中 vibesec.g1.sbom-missing-provenance（advisory）
  - 缺 SBOM、缺 gh、權限／網路錯誤等無法判定 → incomplete，退出碼 2（incomplete ≠ pass，CLAUDE.md #2）

用法：
  python3 scripts/g1_provenance.py --sbom reports/sbom.cdx.json --repo owner/repo \\
      --signer-workflow owner/repo/.github/workflows/nightly-full.yml \\
      --sarif reports/g1-provenance.sarif --json reports/g1-provenance.json
  python3 scripts/g1_provenance.py selftest
退出碼：0 已完成（有無命中皆是）；2 incomplete。
"""
from __future__ import annotations
import argparse, datetime, json, os, pathlib, re, shlex, shutil, subprocess, sys

RULE = "vibesec.g1.sbom-missing-provenance"
TOOL_NAME, TOOL_VERSION = "vibesec-g1-provenance", "1.0.0"
# gh 對「沒有證明／證明不符」的訊息（其餘錯誤一律視為無法判定）
MISSING = re.compile(r"no attestations? (were )?found|failed to verify|verification failed|no matching attestations?|"
                     r"none of the attestations matched|"
                     # 實測：該 digest 在 GitHub 沒有任何證明時，gh 回報 attestations/sha256:<digest> 端點 404
                     r"HTTP 404: Not Found \(https://api\.github\.com/repos/[^/\s]+/[^/\s]+/attestations/sha256:", re.I)


def gh_verify(sbom: pathlib.Path, repo: str, signer_workflow: str) -> tuple[int, str]:
    gh = shutil.which("gh")
    if not gh:
        raise FileNotFoundError("gh CLI 不存在")
    p = subprocess.run([gh, "attestation", "verify", str(sbom), "--repo", repo,
                        "--signer-workflow", signer_workflow, "--format", "json"],
                       capture_output=True, text=True, timeout=180)
    return p.returncode, (p.stdout or "") + "\n" + (p.stderr or "")


def run(sbom: pathlib.Path, repo: str, signer_workflow: str, verify=gh_verify) -> tuple[dict, bool]:
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    base = {"rule_id": RULE, "checked_at": now, "subject": str(sbom), "repo": repo, "signer_workflow": signer_workflow}
    if not sbom.is_file():
        return {**base, "status": "incomplete", "status_reason": f"缺 SBOM：{sbom}"}, False
    try:
        code, out = verify(sbom, repo, signer_workflow)
    except (OSError, subprocess.SubprocessError) as e:
        return {**base, "status": "incomplete", "status_reason": f"無法執行驗證：{type(e).__name__}: {e}"}, False
    tail = out.strip().splitlines()[-1][:300] if out.strip() else ""
    if code == 0:
        return {**base, "status": "pass", "status_reason": None, "verified": True}, False
    if MISSING.search(out):
        return {**base, "status": "pass", "status_reason": None, "verified": False, "detail": tail}, True
    return {**base, "status": "incomplete", "status_reason": f"gh attestation verify 失敗且無法判定原因（exit {code}）：{tail}"}, False


ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import gate_result  # noqa: E402  自產 SARIF 骨架只有一份寫法（#182）；不依賴 PyYAML


def to_sarif(summary: dict, hit: bool, policy: "Policy") -> dict:
    """policy：tier 唯一來源（blocking-policy，第四次審視 S-11）；由進入點建立一次傳入。"""
    _TIER = policy.tier(RULE); _LEVEL = "error" if _TIER == "blocking" else "warning"
    rule = {"id": RULE, "name": RULE, "shortDescription": {"text": "SBOM 缺少可驗證的 SLSA provenance 來源證明"},
            "defaultConfiguration": {"level": _LEVEL}, "properties": {"policy_tier": _TIER}}
    results = []
    if hit:
        results.append({"ruleId": RULE, "level": _LEVEL,
                        "message": {"text": f"{summary['subject']} 沒有由 {summary['signer_workflow']} 簽發的有效來源證明："
                                            f"{summary.get('detail') or ''}"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": ".github/workflows/nightly-full.yml"}}}],
                        "properties": {"policy_tier": _TIER, "subject": summary["subject"],
                                       "signer_workflow": summary["signer_workflow"]}})
    return gate_result.sarif({"name": TOOL_NAME, "version": TOOL_VERSION}, [rule], results)


def selftest() -> list[str]:
    sys.path.insert(0, str(ROOT / "scripts"))
    from vibesec_policy import Policy
    import tempfile
    fails: list[str] = []
    with tempfile.TemporaryDirectory() as d:
        sb = pathlib.Path(d, "sbom.json"); sb.write_text("{}")
        cases = [
            ("驗證成功", lambda *a: (0, "[{...}]"), "pass", False),
            ("找不到證明", lambda *a: (1, "✗ Loading attestations from GitHub API failed\nError: no attestations found"), "pass", True),
            ("簽發者不符", lambda *a: (1, "Error: verifying with issuer \"x\"\nfailed to verify signer workflow"), "pass", True),
            ("查無證明（實測訊息）", lambda *a: (1, "Error: HTTP 404: Not Found (https://api.github.com/repos/o/r/attestations/"
                                              "sha256:ca3d?per_page=30&predicate_type=https://slsa.dev/provenance/v1)"), "pass", True),
            ("repo 不存在（非證明端點的 404）", lambda *a: (1, "HTTP 404: Not Found (https://api.github.com/repos/o/nope)"), "incomplete", False),
            ("權限／網路錯誤", lambda *a: (1, "HTTP 403: Resource not accessible by integration"), "incomplete", False),
        ]
        for label, fake, want_status, want_hit in cases:
            s, hit = run(sb, "o/r", "o/r/.github/workflows/nightly-full.yml", verify=fake)
            if s["status"] != want_status or hit != want_hit:
                fails.append(f"{label}：應為 {want_status}/hit={want_hit}，得到 {s['status']}/hit={hit}")
        def boom(*a):
            raise FileNotFoundError("gh CLI 不存在")
        if run(sb, "o/r", "w", verify=boom)[0]["status"] != "incomplete":
            fails.append("缺 gh 應為 incomplete")
        if run(pathlib.Path(d, "none"), "o/r", "w", verify=cases[0][1])[0]["status"] != "incomplete":
            fails.append("缺 SBOM 應為 incomplete")
        s, hit = run(sb, "o/r", "w", verify=cases[1][1])
        r = to_sarif(s, hit, Policy(ROOT))["runs"][0]["results"]
        if len(r) != 1 or r[0]["ruleId"] != RULE or r[0]["properties"]["policy_tier"] != "advisory":
            fails.append("命中時 SARIF 應有 1 筆 advisory")
        if to_sarif(*run(sb, "o/r", "w", verify=cases[0][1]), Policy(ROOT))["runs"][0]["results"]:
            fails.append("驗證成功時 SARIF 不應有結果")
        # gh_verify 必須把 --repo 與 --signer-workflow 傳給 gh：少了 --signer-workflow，任何 workflow（含 PR 的）簽發的
        # 證明都會驗過；以前 selftest 全部用假的 verify，這個參數從沒被檢查
        seen = []
        _run0, _which0 = subprocess.run, shutil.which
        try:
            shutil.which = lambda name: "/usr/bin/gh"
            subprocess.run = lambda argv, **k: (seen.append(argv), subprocess.CompletedProcess(argv, 0, "[]", ""))[1]
            gh_verify(sb, "o/r", "o/r/.github/workflows/nightly-full.yml")
        finally:
            subprocess.run, shutil.which = _run0, _which0
        argv = seen[0] if seen else []
        pair = lambda flag: argv[argv.index(flag) + 1] if flag in argv[:-1] else None
        if argv[1:3] != ["attestation", "verify"] or pair("--signer-workflow") != "o/r/.github/workflows/nightly-full.yml" \
                or pair("--repo") != "o/r":
            fails.append(f"gh_verify 應以 attestation verify --repo o/r --signer-workflow <workflow> 呼叫 gh（得到 {argv}）")
    # 政策檔讀不到 → 進入點就停：摘要 incomplete 並寫明未完成原因、不寫 SARIF（舊檔刪除；上傳步驟以 hashFiles 略過）、退出碼 2
    # （不再以例外結束；也不執行檢查，因為無法決定發現的 tier）
    import contextlib, io, tempfile
    from vibesec_policy import POLICY_UNREADABLE, broken_policy_root
    with broken_policy_root() as pr, tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
        js, sf = pathlib.Path(d, "out.json"), pathlib.Path(d, "out.sarif")
        sf.write_text("上一次的結果", encoding="utf-8")
        rc = main(["--sbom", str(pathlib.Path(d, "none.json")), "--repo", "o/r", "--signer-workflow", "o/r/w.yml",
                       "--sarif", str(sf), "--json", str(js)], policy_root=pr)
        s, stale = json.loads(js.read_text(encoding="utf-8")), sf.exists()
    if rc != 2 or s.get("status") != "incomplete" or not str(s.get("status_reason")).startswith(POLICY_UNREADABLE + "（") or stale:
        fails.append(f"來源證明：政策檔讀不到 → 退出碼 2、incomplete 並寫明原因、不留 SARIF（得到 {rc}、{s}、SARIF 存在：{stale}）")
    # 一般 incomplete（缺 SBOM、gh 缺席、gh 失敗且無法判定原因）：沒有驗證任何東西 → 刪掉舊 SARIF、不寫新檔（#192）。
    # 以前寫一份只有 rule、沒有 result 的 SARIF，Code Scanning 會當成「驗證過、沒有發現」而關閉既有 alert。
    # 從 main() 實測：以 PATH 控制 gh（空目錄 → 缺 gh；假 gh 腳本 → 指定的退出碼與訊息），不新增命令列參數。
    def fake_gh(bindir, code, text):
        g = pathlib.Path(bindir, "gh")
        g.write_text(f"#!/bin/sh\nprintf '%s\\n' {shlex.quote(text)} >&2\nexit {code}\n", encoding="utf-8")
        g.chmod(0o755)
    path0 = os.environ.get("PATH")
    with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
        tmp = pathlib.Path(d)
        sb = tmp / "sbom.json"; sb.write_text("{}", encoding="utf-8")
        empty, bindir = tmp / "empty", tmp / "bin"
        empty.mkdir(); bindir.mkdir()
        with_fake = f"{bindir}{os.pathsep}{path0 or ''}"
        def run_main(label, sbom, path):
            js, sf = tmp / f"{label}.json", tmp / f"{label}.sarif"
            sf.write_text('{"stale": true}', encoding="utf-8")   # 上一次留下的 SARIF（合法 JSON：留著時斷言回報失敗，不是解析崩潰）
            os.environ["PATH"] = path
            try:
                rc = main(["--sbom", str(sbom), "--repo", "o/r", "--signer-workflow", "o/r/w.yml", "--sarif", str(sf), "--json", str(js)])
            finally:   # 還原 PATH：原本沒設定 → 移除，不留下空字串
                if path0 is None:
                    os.environ.pop("PATH", None)
                else:
                    os.environ["PATH"] = path0
            sarif = json.loads(sf.read_text(encoding="utf-8")) if sf.exists() else None
            return rc, json.loads(js.read_text(encoding="utf-8")), sarif, sf.exists()
        def results_of(sarif):
            runs = sarif.get("runs") if isinstance(sarif, dict) else None
            return runs[0].get("results") if isinstance(runs, list) and runs and isinstance(runs[0], dict) else None
        # (label, SBOM, PATH, 假 gh 的 (退出碼, 訊息) 或 None)
        for label, sbom, path, gh in (("缺 SBOM", tmp / "none.json", path0 or "", None),
                                      ("gh 缺席", sb, str(empty), None),
                                      ("gh 失敗且無法判定", sb, with_fake, (1, "HTTP 403: Resource not accessible by integration"))):
            if gh:
                fake_gh(bindir, *gh)
            rc, sm, _, exists = run_main(label, sbom, path)
            if rc != 2 or sm.get("status") != "incomplete" or exists:
                fails.append(f"來源證明：{label} → 退出碼 2、incomplete、舊 SARIF 刪掉且不寫新檔（得到 {rc}、{sm.get('status')}、SARIF 存在：{exists}）")
        # 正常路徑照常寫出 SARIF：驗證成功 → 有 rule、沒有 result；找不到證明 → 1 筆 advisory
        for label, code, text, n in (("驗證成功", 0, "[]", 0), ("找不到證明", 1, "Error: no attestations found", 1)):
            fake_gh(bindir, code, text)
            rc, sm, sarif, _ = run_main(label, sb, with_fake)
            res = results_of(sarif)
            if rc != 0 or sm.get("status") != "pass" or res is None or len(res) != n:
                fails.append(f"來源證明：{label} → 退出碼 0、pass、SARIF 照常寫出且有 {n} 筆結果（得到 {rc}、{sm.get('status')}、{res}）")
    return fails


def main(argv=None, policy_root: pathlib.Path = ROOT) -> int:
    """policy_root：阻擋政策所在的 repo（selftest 指向壞政策檔）。"""
    if (argv if argv is not None else sys.argv[1:])[:1] == ["selftest"]:
        fails = selftest()
        print("\n".join(f"FAIL {x}" for x in fails) or "g1_provenance selftest ok")
        return 1 if fails else 0
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--sbom", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--signer-workflow", required=True)
    ap.add_argument("--sarif", required=True)
    ap.add_argument("--json", required=True)
    a = ap.parse_args(argv)
    sys.path.insert(0, str(ROOT / "scripts"))
    from vibesec_policy import load_policy
    policy, problem = load_policy(policy_root)   # 進入點只建立一次；讀不到 → incomplete，不執行檢查
    if problem:
        summary, hit = {"rule_id": RULE, "status": "incomplete", "status_reason": problem}, False
    else:
        summary, hit = run(pathlib.Path(a.sbom), a.repo, a.signer_workflow)
    for out in (a.sarif, a.json):
        pathlib.Path(out).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(a.json).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    if summary["status"] == "incomplete":
        # 沒有驗證任何東西（政策讀不到、缺 SBOM、gh 缺席或失敗且無法判定）：不寫 SARIF（上傳步驟以 hashFiles 略過），
        # 也不讓上一次的結果被當成這次的。以前一般 incomplete 會寫一份沒有 result 的 SARIF，看起來像「驗證過、沒有發現」（#192）
        gate_result.remove_stale(a.sarif)
    else:
        pathlib.Path(a.sarif).write_text(json.dumps(to_sarif(summary, hit, policy), ensure_ascii=False, indent=2), encoding="utf-8")
    if summary["status"] == "incomplete":
        print(f"::error::SBOM 來源證明檢查未完成（incomplete ≠ pass）：{summary['status_reason']}")
        return 2
    print("SBOM 來源證明：" + ("已驗證" if summary.get("verified") else f"缺少或無效（{RULE}，advisory）"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
