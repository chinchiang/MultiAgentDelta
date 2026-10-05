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
import argparse, datetime, json, pathlib, re, shutil, subprocess, sys

RULE = "vibesec.g1.sbom-missing-provenance"
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


def to_sarif(summary: dict, hit: bool) -> dict:
    rule = {"id": RULE, "name": RULE, "shortDescription": {"text": "SBOM 缺少可驗證的 SLSA provenance 來源證明"},
            "defaultConfiguration": {"level": "warning"}, "properties": {"policy_tier": "advisory"}}
    results = []
    if hit:
        results.append({"ruleId": RULE, "level": "warning",
                        "message": {"text": f"{summary['subject']} 沒有由 {summary['signer_workflow']} 簽發的有效來源證明："
                                            f"{summary.get('detail') or ''}"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": ".github/workflows/nightly-full.yml"}}}],
                        "properties": {"policy_tier": "advisory", "subject": summary["subject"],
                                       "signer_workflow": summary["signer_workflow"]}})
    return {"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "vibesec-g1-provenance", "version": "1.0.0",
                                          "informationUri": "https://github.com/chinchiang/MultiAgentDelta",
                                          "rules": [rule]}}, "results": results}]}


def selftest() -> list[str]:
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
        r = to_sarif(s, hit)["runs"][0]["results"]
        if len(r) != 1 or r[0]["ruleId"] != RULE or r[0]["properties"]["policy_tier"] != "advisory":
            fails.append("命中時 SARIF 應有 1 筆 advisory")
        if to_sarif(*run(sb, "o/r", "w", verify=cases[0][1]))["runs"][0]["results"]:
            fails.append("驗證成功時 SARIF 不應有結果")
    return fails


def main(argv=None) -> int:
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
    summary, hit = run(pathlib.Path(a.sbom), a.repo, a.signer_workflow)
    for out in (a.sarif, a.json):
        pathlib.Path(out).parent.mkdir(parents=True, exist_ok=True)
    pathlib.Path(a.json).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    pathlib.Path(a.sarif).write_text(json.dumps(to_sarif(summary, hit), ensure_ascii=False, indent=2), encoding="utf-8")
    if summary["status"] == "incomplete":
        print(f"::error::SBOM 來源證明檢查未完成（incomplete ≠ pass）：{summary['status_reason']}")
        return 2
    print("SBOM 來源證明：" + ("已驗證" if summary.get("verified") else f"缺少或無效（{RULE}，advisory）"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
