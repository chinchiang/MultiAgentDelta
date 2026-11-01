#!/usr/bin/env python3
"""VibeSec G1：SBOM 缺少可驗證的來源證明（SLSA provenance）→ vibesec.g1.sbom-missing-provenance（advisory）。

nightly 以 actions/attest-build-provenance 為 reports/sbom.cdx.json 簽發來源證明（Sigstore，記錄於 GitHub attestations）。
本腳本以 `gh attestation verify` 驗證：證明存在、簽章有效，且簽發者是本 repo 指定的 workflow（--signer-workflow），
避免「任何人替這份檔案簽了一張證明」也算通過。

判定：
  - verify 成功 → pass
  - gh 明確回報找不到證明或驗證失敗 → 命中 vibesec.g1.sbom-missing-provenance（advisory）
  - 缺 SBOM、缺 gh、權限／網路錯誤等無法判定 → incomplete，退出碼 2（incomplete ≠ pass，AGENTS.md #2）

用法：
  python3 scripts/g1_provenance.py --sbom reports/sbom.cdx.json --repo owner/repo \\
      --signer-workflow owner/repo/.github/workflows/nightly-full.yml \\
      --sarif reports/g1-provenance.sarif --json reports/g1-provenance.json
  python3 scripts/g1_provenance.py selftest
退出碼：0 已完成（有無命中皆是）；2 incomplete。
"""
from __future__ import annotations
import argparse, datetime, json, pathlib, re, shutil, subprocess, sys

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
    # 接線（#246）：生命週期（SARIF 寫出或刪掉舊檔、退出碼）在 gate_result 測；這裡確認來源證明經過檢查執行、
    # 驗證經由工廠注入（gh 怎麼被呼叫見上方 gh_verify 的測試），以及來源證明自己的輸出
    import contextlib, io
    from vibesec_policy import POLICY_UNREADABLE, broken_policy_root, temp_policy_root
    for label, broken, verify, want_rc, want_results, want_out in [
        ("政策讀不到", True, None, 2, None, "::error::SBOM 來源證明檢查未完成（incomplete ≠ pass）：" + POLICY_UNREADABLE),
        ("驗證成功", False, lambda *a: (0, "ok"), 0, 0, "SBOM 來源證明：已驗證"),
        ("找不到證明", False, lambda *a: (1, "no attestations found"), 0, 1, f"SBOM 來源證明：缺少或無效（{RULE}，advisory）"),
        # 退出碼依政策 tier（#242 Q5）：政策把規則升為 blocking 時退出 1 並說明原因（現行政策是 advisory）
        ("規則升為 blocking、找不到證明", "promote", lambda *a: (1, "no attestations found"), 1, 1, f"::error::SBOM 缺少可驗證的來源證明（{RULE}，blocking）"),
    ]:
        out = io.StringIO()
        with (broken_policy_root() if broken is True else temp_policy_root()) as pr, tempfile.TemporaryDirectory() as d, \
                contextlib.redirect_stdout(out):
            if broken == "promote":   # 每個風險層級都升級：不依賴 repo 目前的 risk_tier
                import yaml
                from vibesec_policy import write_policy_key
                pol = yaml.safe_load((pr / "config/policy/blocking-policy.yaml").read_text(encoding="utf-8"))
                write_policy_key(pr, "tier_overrides", {k: {**ov, "promote_to_blocking": [*(ov.get("promote_to_blocking") or []), RULE]}
                                                        for k, ov in (pol.get("tier_overrides") or {}).items()})
            sb, js, sf = pathlib.Path(d, "sbom.json"), pathlib.Path(d, "out.json"), pathlib.Path(d, "out.sarif")
            sb.write_text("{}")
            a = parse_args(["--sbom", str(sb), "--repo", "o/r", "--signer-workflow", "o/r/w.yml", "--sarif", str(sf), "--json", str(js)])
            cr = check_run(a, verify=verify) if verify else check_run(a)
            rc = cr.execute(policy_root=pr, sarif_path=a.sarif, json_path=a.json)
            res = len(json.loads(sf.read_text(encoding="utf-8"))["runs"][0]["results"]) if sf.exists() else None
        if (rc, res) != (want_rc, want_results) or want_out not in out.getvalue():
            fails.append(f"來源證明接線「{label}」：應為退出碼 {want_rc}、SARIF 結果 {want_results}、輸出含 {want_out!r}"
                         f"（得到 {rc}、{res}、{out.getvalue()!r}）")
    return fails


def parse_args(argv) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--sbom", required=True)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--signer-workflow", required=True)
    ap.add_argument("--sarif", required=True)
    ap.add_argument("--json", required=True)
    return ap.parse_args(argv)


def check_run(a: argparse.Namespace, *, verify=gh_verify) -> gate_result.CheckRun:
    """SBOM 來源證明的檢查執行（nightly，不併入閘門結果）；verify 是 gh attestation verify，只給 selftest 注入（#246）。"""
    def findings(summary, policy):   # 找不到證明（verified 為 False）才是發現；驗證成功或無法判定都不是
        return [{"rule_id": RULE, "policy_tier": policy.tier(RULE)}] if summary.get("verified") is False else []

    def report(summary, found, policy):
        tier = policy.tier(RULE)
        print("SBOM 來源證明：" + ("已驗證" if summary.get("verified") else f"缺少或無效（{RULE}，{tier}）"))
        if found and tier == "blocking":   # 政策升為 blocking 時說明為何退出 1（現行政策是 advisory）
            print(f"::error::SBOM 缺少可驗證的來源證明（{RULE}，blocking）")

    # 生命週期（政策讀不到、摘要、SARIF 寫出或刪掉舊檔、依政策 tier 的退出碼）由檢查執行負責（#246）。
    # 一般 incomplete（缺 SBOM、gh 缺席或失敗且無法判定）不寫 SARIF：沒有 result 的 SARIF 會被當成「驗證過、沒有發現」（#192）
    return gate_result.CheckRun(
        label="SBOM 來源證明", tool_name=TOOL_NAME, version=TOOL_VERSION,
        check=lambda policy: run(pathlib.Path(a.sbom), a.repo, a.signer_workflow, verify)[0],
        findings=findings, to_sarif=lambda summary, found, policy: to_sarif(summary, bool(found), policy),
        unreadable=lambda problem: {"rule_id": RULE, "status": "incomplete", "status_reason": problem},
        report=report,
    )


def main(argv=None, policy_root: pathlib.Path = ROOT) -> int:
    """policy_root：阻擋政策所在的 repo（selftest 指向壞政策檔）。"""
    if (argv if argv is not None else sys.argv[1:])[:1] == ["selftest"]:
        fails = selftest()
        print("\n".join(f"FAIL {x}" for x in fails) or "g1_provenance selftest ok")
        return 1 if fails else 0
    a = parse_args(argv)
    return check_run(a).execute(policy_root=policy_root, sarif_path=a.sarif, json_path=a.json)


if __name__ == "__main__":
    sys.exit(main())
