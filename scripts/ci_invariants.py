#!/usr/bin/env python3
"""CI 設定的不變式（由 scripts/validate.py 呼叫）：防止已修過的 CI 弱點被改回去。

  workflow_write_permissions(text)        workflow 層級的 permissions 不得有 write（寫入權限按 job 宣告）
  unpaginated_list_comments(text)         issues.listComments 必須經 github.paginate（否則只拿到第一頁 30 則）
  precommit_semgrep_drift(pc, rules)      pre-commit 的 semgrep --config 與 vibesec.yaml g3 semgrep_rules 一致
  untrusted_script_runs(text)             workflow 不得執行本分支的 scripts/（判定程式只採用 _trusted/）
  sed_target_substitution(text)           不得以 sed 把受測目標 URL 代入設定（URL 含 # 或 & 會壞）
  sarif_jobs_without_permission(wf)       有 upload-sarif 的 job，有效權限須含 security-events: write

  python3 scripts/ci_invariants.py selftest
"""
from __future__ import annotations
import re, sys

_WRITE = re.compile(r"^\s+[a-z-]+:\s*write\b")


def workflow_write_permissions(text: str) -> list[str]:
    """workflow 層級 permissions 區塊中的 write 權限（'scope: write'）。"""
    out, inside = [], False
    for ln in text.splitlines():
        if re.match(r"^permissions:\s*(?:#.*)?$", ln):
            inside = True; continue
        if re.match(r"^permissions:\s*write-all\b", ln):
            out.append("write-all"); continue
        if inside:
            if ln and not ln[0].isspace() and not ln.lstrip().startswith("#"):
                inside = False; continue
            if _WRITE.match(ln):
                out.append(ln.strip().split("#", 1)[0].strip())
    return out


def unpaginated_list_comments(text: str) -> list[int]:
    """呼叫 rest.issues.listComments(…) 但不是傳給 github.paginate 的行號（1 起算）。"""
    return [i for i, ln in enumerate(text.splitlines(), 1)
            if re.search(r"issues\.listComments\s*\(", ln) and not ln.lstrip().startswith("//")]


def precommit_semgrep_drift(precommit: str, rules: list[str]) -> tuple[list[str], list[str]]:
    """(pre-commit 少了的規則集, pre-commit 多出的規則集)。只比對 semgrep hook 的 --config。"""
    have = set(re.findall(r"--config=(\S+?)\"?\s*(?:#|$)", precommit, re.M))
    want = set(rules or [])
    return sorted(want - have), sorted(have - want)


def untrusted_script_runs(text: str) -> list[int]:
    """執行或指向本分支 scripts/（不經 _trusted/）的行號：python3／bash／node scripts/…、S=scripts/…。註解行略過。"""
    pat = re.compile(r"(?:\b(?:python3?|bash|sh|node)(?:\s+-\S+)*\s+|=\s*[\"']?)(?:\./)?scripts/")
    return [i for i, ln in enumerate(text.splitlines(), 1)
            if not ln.lstrip().startswith("#") and pat.search(ln.split(" #", 1)[0])]


def sed_target_substitution(text: str) -> list[int]:
    """以 sed 代入受測目標 URL（VIBESEC_TARGET_URL）的行號。"""
    return [i for i, ln in enumerate(text.splitlines(), 1)
            if not ln.lstrip().startswith("#") and re.search(r"\bsed\b", ln) and "VIBESEC_TARGET_URL" in ln]


def sarif_jobs_without_permission(wf: dict) -> list[str]:
    """有 upload-sarif 步驟、但有效權限（job 層級，未宣告則取 workflow 層級）沒有 security-events: write 的 job。
    寫入權限從 workflow 層級移到 job 層級後，新增上傳 SARIF 的 job 忘了宣告就會上傳失敗——而這些步驟多半
    continue-on-error，失敗不會被注意到。"""
    top = wf.get("permissions")
    out = []
    for name, job in (wf.get("jobs") or {}).items():
        steps = (job or {}).get("steps") or []
        if not any("github/codeql-action/upload-sarif" in str(st.get("uses", "")) for st in steps):
            continue
        eff = job.get("permissions", top)
        if eff != "write-all" and not (isinstance(eff, dict) and eff.get("security-events") == "write"):
            out.append(name)
    return out


def selftest() -> list[str]:
    fails: list[str] = []
    wf_ok = "on: push\npermissions:\n  contents: read\n\njobs:\n  a:\n    permissions:\n      security-events: write\n"
    wf_bad = "on: push\npermissions:\n  contents: read\n  # 說明\n  security-events: write\n  actions: read\njobs: {}\n"
    for label, got, want in [
        ("workflow 層級只有 read", workflow_write_permissions(wf_ok), []),
        ("workflow 層級有 write", workflow_write_permissions(wf_bad), ["security-events: write"]),
        ("write-all", workflow_write_permissions("permissions: write-all\njobs: {}\n"), ["write-all"]),
        ("listComments 未分頁", unpaginated_list_comments(
            "const c = await github.rest.issues.listComments({owner, repo, issue_number});\n"), [1]),
        ("listComments 經 paginate", unpaginated_list_comments(
            "const c = await github.paginate(github.rest.issues.listComments, {owner, repo});\n// issues.listComments( 註解\n"), []),
        ("執行本分支 scripts", untrusted_script_runs(
            "  python3 scripts/g5_api_probes.py\n  S=scripts/g5_api_probes.py\n  python3 -I ./scripts/x.py\n"), [1, 2, 3]),
        ("只用 _trusted", untrusted_script_runs(
            '  python3 _trusted/scripts/g5_api_probes.py\n  S="${X:-_trusted/scripts/g5.py}"\n  # python3 scripts/x.py\n'
            "  sparse-checkout: .github/scripts\n"), []),
        ("sed 代入目標 URL", sed_target_substitution('  sed "s#a#${VIBESEC_TARGET_URL}/chat#" f > g\n'), [1]),
        ("沒有 sed 代入", sed_target_substitution("  python3 x.py --target \"$VIBESEC_TARGET_URL\"\n  sed -n 1p f\n"), []),
    ]:
        if got != want:
            fails.append(f"{label}：預期 {want}，得到 {got}")
    up = {"uses": "github/codeql-action/upload-sarif@abc"}
    for label, wf, want in [
        ("job 層級有權限", {"permissions": {"contents": "read"},
                           "jobs": {"a": {"permissions": {"security-events": "write"}, "steps": [up]}}}, []),
        ("job 沒宣告、workflow 層級唯讀", {"permissions": {"contents": "read"}, "jobs": {"a": {"steps": [up]}}}, ["a"]),
        ("job 宣告了但沒有 security-events", {"jobs": {"a": {"permissions": {"contents": "read"}, "steps": [up]}}}, ["a"]),
        ("沒有上傳 SARIF 的 job 不檢查", {"permissions": {"contents": "read"}, "jobs": {"a": {"steps": [{"run": "x"}]}}}, []),
    ]:
        if sarif_jobs_without_permission(wf) != want:
            fails.append(f"sarif_jobs_without_permission「{label}」：預期 {want}，得到 {sarif_jobs_without_permission(wf)}")
    pc = ('        args:\n          - "--config=config/semgrep/vibesec-rules.yaml"\n'
          '          - "--config=p/owasp-top-ten"\n          - "--config=p/security-audit"   # 與 CI 一致\n          - "--error"\n')
    rules = ["config/semgrep/vibesec-rules.yaml", "p/owasp-top-ten", "p/security-audit"]
    if precommit_semgrep_drift(pc, rules) != ([], []):
        fails.append(f"pre-commit 與 CI 一致時不應回報差異（得到 {precommit_semgrep_drift(pc, rules)}）")
    if precommit_semgrep_drift(pc.replace('          - "--config=p/security-audit"   # 與 CI 一致\n', ""), rules) != (["p/security-audit"], []):
        fails.append("pre-commit 少了 p/security-audit 應回報")
    return fails


if __name__ == "__main__":
    if sys.argv[1:2] == ["selftest"]:
        _fails = selftest()
        for f in _fails:
            print(f"FAIL {f}")
        print("selftest 通過" if not _fails else f"selftest 失敗 {len(_fails)} 項")
        sys.exit(1 if _fails else 0)
    print(__doc__.strip()); sys.exit(4)
