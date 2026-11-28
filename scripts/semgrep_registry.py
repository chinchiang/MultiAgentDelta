#!/usr/bin/env python3
"""semgrep registry 規則集（p/…、r/…）：只下載一次、算 SHA-256，再把同一份檔案交給 semgrep（#374）。

以前各處以 `--config p/<名稱>` 讓 semgrep 自己在執行時下載，沒有固定版本、也沒有記錄下載到什麼：同一份程式碼在
不同時間掃描，G3 結果時有時無（#374：validate.py:520 的 tainted-env-args），卻無從分辨是規則集變了還是 semgrep 不穩定。
另外下載一份來算雜湊也沒用：semgrep 會自己再下載一次，兩次可能不同。所以這裡下載後把檔案路徑交給 `--config`，
記下的雜湊就是 semgrep 實際用的內容。

  python3 -I scripts/semgrep_registry.py fetch --out <下載目錄> --record <紀錄 JSON> <config> [<config> …]
      config：registry 規則集（p/…、r/…）或規則檔路徑；路徑原樣輸出、不下載。
      stdout：每行一個要交給 semgrep 的 --config 值（registry 規則集換成下載的檔案路徑），順序與輸入相同。
      紀錄：{"rulesets": [{name, url, sha256, bytes, fetched_at}], "problems": [...]}；log 印出每份的 SHA-256。
      退出碼：0 全部取得；2 任一份取得失敗（stdout 不輸出任何 --config 值；呼叫端不得改用 p/<名稱> 退回）。
  python3 -I scripts/semgrep_registry.py annotate --sarif <semgrep 的 SARIF> --record <紀錄 JSON>
      把紀錄寫進 SARIF 每個 run 的 properties.vibesec_semgrep_rulesets（CI 的 Code scanning／artifact 都看得到雜湊）。
      退出碼：0 寫入；2 檔案讀不到或不是 SARIF。
  python3 scripts/semgrep_registry.py selftest

下載走 scripts/https_only.py 的 UrllibHttpsOnly：只允許 HTTPS、驗證憑證、不跟隨轉址（3xx 當成 HTTP 錯誤）。
下載失敗（任何連線、截斷、URL 錯誤）、HTTP 狀態不是 200、內容不是含 `rules:` 的 YAML、超過大小上限、寫檔失敗
→ 該份記入 problems（incomplete ≠ pass，規則 2），不拋例外。
不需要 PyYAML：semgrep 的容器映像不一定有，判斷內容只看是否為 UTF-8 且有一行以 `rules:` 開頭。
規則集不收進 repo（registry 規則多半採 Semgrep Rules License，公開 repo 重新散布可能不被允許），只記錄雜湊。
"""
from __future__ import annotations
import argparse, datetime, hashlib, http.client, json, pathlib, re, sys, urllib.error
from typing import Callable, NamedTuple

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))   # python3 -I 時腳本目錄不在 sys.path
import https_only  # noqa: E402  只走 HTTPS、驗證憑證、不跟隨轉址

REGISTRY_URL = "https://semgrep.dev/c/{name}"
REGISTRY_NAME = re.compile(r"^[pr]/[A-Za-z0-9][A-Za-z0-9._-]*$")
MAX_BYTES = 50 * 1024 * 1024
TIMEOUT_SECONDS = 60
USER_AGENT = "vibesec-semgrep-registry/1"
SARIF_KEY = "vibesec_semgrep_rulesets"

# get(url) → (HTTP 狀態, 內容)；連線失敗拋 OSError。selftest 注入假的，不連網
Getter = Callable[[str], tuple[int, bytes]]


class Fetched(NamedTuple):
    name: str
    url: str
    path: pathlib.Path
    sha256: str
    size: int
    fetched_at: str


def is_registry(config: str) -> bool:
    return bool(re.match(r"^[pr]/", config))


def _https_get(url: str) -> tuple[int, bytes]:
    """生產用的下載：成功 → (200, 本文)；HTTP 錯誤（含 3xx，不跟隨轉址）→ (狀態碼, b"")；其他失敗拋例外，由 fetch 記成 problem。"""
    try:
        return 200, https_only.UrllibHttpsOnly(user_agent=USER_AGENT).get(url, TIMEOUT_SECONDS)
    except urllib.error.HTTPError as e:
        return e.code, b""


def fetch(name: str, dest: pathlib.Path, *, get: Getter | None = None, now: str | None = None) -> Fetched | str:
    """下載一份 registry 規則集到 dest → Fetched；失敗 → 未完成原因（字串）。"""
    if not REGISTRY_NAME.match(name):
        return f"registry 規則集名稱不合法：{name!r}"
    url = REGISTRY_URL.format(name=name)
    try:
        status, body = (get or _https_get)(url)
    except (OSError, http.client.HTTPException, ValueError) as e:   # 連線、截斷（IncompleteRead）、URL 錯誤
        return f"registry 規則集 {name} 下載失敗（{type(e).__name__}）"
    if status != 200:
        return f"registry 規則集 {name} 下載失敗（HTTP {status}）"
    if len(body) > MAX_BYTES:
        return f"registry 規則集 {name} 超過大小上限 {MAX_BYTES} bytes"
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return f"registry 規則集 {name} 的內容不是 UTF-8"
    if not re.search(r"^rules:", text, re.M):
        return f"registry 規則集 {name} 的內容不是 semgrep 規則檔（沒有 rules:）"
    path = dest / (name.replace("/", "_") + ".yaml")
    try:
        dest.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
    except OSError as e:
        return f"registry 規則集 {name} 無法寫入 {path}（{type(e).__name__}）"
    fetched_at = now or datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()
    return Fetched(name, url, path, hashlib.sha256(body).hexdigest(), len(body), fetched_at)


def resolve(configs: list[str], dest: pathlib.Path, *, get: Getter | None = None,
            now: str | None = None) -> tuple[list[str], list[Fetched], list[str]]:
    """semgrep 的 config 清單 → (交給 --config 的值, 下載紀錄, 未完成原因)。有任何未完成原因時，呼叫端不得執行 semgrep。"""
    values, fetched, problems = [], [], []
    for c in configs:
        if not is_registry(c):
            values.append(c)
            continue
        got = fetch(c, dest, get=get, now=now)
        if isinstance(got, str):
            problems.append(got)
        else:
            fetched.append(got)
            values.append(str(got.path))
    return values, fetched, problems


def record(fetched: list[Fetched], problems: list[str]) -> dict:
    return {"rulesets": [{"name": f.name, "url": f.url, "sha256": f.sha256, "bytes": f.size, "fetched_at": f.fetched_at}
                         for f in fetched],
            "problems": list(problems)}


def annotate_sarif(sarif: pathlib.Path, rec: dict) -> str | None:
    """把紀錄寫進 SARIF 每個 run 的 properties[SARIF_KEY]；成功 → None，失敗 → 原因。"""
    try:
        data = json.loads(sarif.read_text(encoding="utf-8"))
        runs = data.get("runs") if isinstance(data, dict) else None
        if not isinstance(runs, list) or not runs:
            return f"{sarif} 不是有 runs 的 SARIF"
        for run in runs:
            run.setdefault("properties", {})[SARIF_KEY] = rec
        sarif.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except (OSError, ValueError) as e:
        return f"無法在 {sarif} 寫入規則集紀錄（{type(e).__name__}）"
    return None


def log_lines(fetched: list[Fetched], problems: list[str]) -> list[str]:
    return ([f"registry 規則集 {f.name}：sha256 {f.sha256}，{f.size} bytes，{f.fetched_at}" for f in fetched]
            + [f"registry 規則集未取得：{p}" for p in problems])


def main(argv=None, *, get: Getter | None = None) -> int:
    ap = argparse.ArgumentParser(description="下載 semgrep registry 規則集並記錄 SHA-256（#374）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fetch")
    f.add_argument("--out", required=True, type=pathlib.Path, help="下載目錄")
    f.add_argument("--record", required=True, type=pathlib.Path, help="紀錄 JSON 的輸出路徑")
    f.add_argument("configs", nargs="+")
    n = sub.add_parser("annotate")
    n.add_argument("--sarif", required=True, type=pathlib.Path)
    n.add_argument("--record", required=True, type=pathlib.Path)
    a = ap.parse_args(argv)
    if a.cmd == "annotate":
        try:
            rec = json.loads(a.record.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            print(f"無法讀取紀錄 {a.record}（{type(e).__name__}）", file=sys.stderr)
            return 2
        why = annotate_sarif(a.sarif, rec)
        if why:
            print(why, file=sys.stderr)
            return 2
        return 0
    values, fetched, problems = resolve(a.configs, a.out, get=get)
    for ln in log_lines(fetched, problems):
        print(ln, file=sys.stderr)
    try:
        a.record.parent.mkdir(parents=True, exist_ok=True)
        a.record.write_text(json.dumps(record(fetched, problems), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except OSError as e:
        print(f"無法寫出紀錄 {a.record}（{type(e).__name__}）", file=sys.stderr)
        return 2
    if problems:
        return 2
    for v in values:
        print(v)
    return 0


def selftest() -> list[str]:
    import contextlib, io, tempfile
    fails: list[str] = []
    good = b"rules:\n- id: x\n  pattern: foo()\n  message: m\n  languages: [python]\n  severity: INFO\n"
    calls: list[str] = []

    def fake(table):
        def get(url):
            calls.append(url)
            v = table.get(url.rsplit("/c/", 1)[-1])
            if isinstance(v, Exception):
                raise v
            return v
        return get

    with tempfile.TemporaryDirectory() as d:
        D = pathlib.Path(d)
        ok_get = fake({"p/security-audit": (200, good), "p/owasp-top-ten": (200, good + b"# 2\n")})
        # 混合 registry 與本地路徑：順序不變、本地路徑原樣、registry 換成下載的檔案；雜湊是檔案內容的 SHA-256
        values, fetched, problems = resolve(["config/x.yaml", "p/security-audit", "p/owasp-top-ten"], D / "a",
                                            get=ok_get, now="2026-11-28T00:00:00+00:00")
        want = ["config/x.yaml", str(D / "a/p_security-audit.yaml"), str(D / "a/p_owasp-top-ten.yaml")]
        if problems or values != want:
            fails.append(f"resolve：本地路徑原樣、registry 換成下載的檔案、順序不變（得到 {values}，{problems}）")
        elif any(hashlib.sha256(pathlib.Path(v).read_bytes()).hexdigest() != f.sha256 for v, f in zip(values[1:], fetched)):
            fails.append("resolve：記錄的 SHA-256 必須是交給 semgrep 的那份檔案的內容")
        if calls[-2:] != ["https://semgrep.dev/c/p/security-audit", "https://semgrep.dev/c/p/owasp-top-ten"]:
            fails.append(f"resolve：只下載 registry 規則集、每份一次（得到 {calls}）")
        rec = record(fetched, problems)
        if [r["name"] for r in rec["rulesets"]] != ["p/security-audit", "p/owasp-top-ten"] \
                or rec["rulesets"][0]["bytes"] != len(good) or rec["rulesets"][0]["fetched_at"] != "2026-11-28T00:00:00+00:00":
            fails.append(f"record：每份規則集的名稱、位元組數、下載時間（得到 {rec}）")
        # 失敗：連線失敗、非 200、不是規則檔、不是 UTF-8、名稱不合法 → 未完成原因，不回傳路徑
        for label, table, name, needle in [
            ("連線失敗", {"p/a": OSError("down")}, "p/a", "下載失敗（OSError）"),
            ("HTTP 404", {"p/a": (404, b"")}, "p/a", "HTTP 404"),
            ("HTML 錯誤頁", {"p/a": (200, b"<html>rate limited</html>")}, "p/a", "rules:"),
            ("不是 UTF-8", {"p/a": (200, b"rules:\n\xff\xfe")}, "p/a", "UTF-8"),
            ("超過大小上限", {"p/a": (200, b"rules:\n" + b"#" * (MAX_BYTES + 1))}, "p/a", "大小上限"),
            ("名稱含路徑", {}, "p/../../etc", "不合法"),
            ("傳輸截斷（IncompleteRead）", {"p/a": http.client.IncompleteRead(b"rul")}, "p/a", "下載失敗（IncompleteRead）"),
            ("URL 錯誤（ValueError）", {"p/a": ValueError("bad url")}, "p/a", "下載失敗（ValueError）"),
        ]:
            try:
                got = fetch(name, D / "b", get=fake(table))
            except Exception as e:   # 紅燈要是 FAIL、不是崩潰（例如名稱含 ../ 時寫檔出錯）
                got = f"例外 {type(e).__name__}"
            if not isinstance(got, str) or needle not in got:
                fails.append(f"fetch「{label}」→ 未完成原因含 {needle!r}（得到 {got!r}）")
        # 寫檔失敗（下載目錄其實是檔案）→ problem，不拋例外
        (D / "not-a-dir").write_text("x")
        try:
            got = fetch("p/a", D / "not-a-dir", get=fake({"p/a": (200, good)}))
        except Exception as e:
            got = f"例外 {type(e).__name__}"
        if not isinstance(got, str) or "無法寫入" not in got:
            fails.append(f"fetch：寫檔失敗 → 未完成原因，不拋例外（得到 {got!r}）")
        # annotate：每個 run 的 properties 都寫入紀錄；不是 SARIF → 原因
        sarif = D / "s.sarif"
        sarif.write_text(json.dumps({"version": "2.1.0", "runs": [{"tool": {}}, {"tool": {}, "properties": {"k": 1}}]}))
        why = annotate_sarif(sarif, {"rulesets": [{"name": "p/a"}], "problems": []})
        runs = json.loads(sarif.read_text())["runs"]
        if why or any(r.get("properties", {}).get(SARIF_KEY) != {"rulesets": [{"name": "p/a"}], "problems": []} for r in runs) \
                or runs[1]["properties"].get("k") != 1:
            fails.append(f"annotate_sarif：每個 run 的 properties 都寫入紀錄、保留既有欄位（得到 {why}，{runs}）")
        (D / "bad.sarif").write_text("{}")
        if not annotate_sarif(D / "bad.sarif", {}) or not annotate_sarif(D / "missing.sarif", {}):
            fails.append("annotate_sarif：沒有 runs 或檔案不存在 → 回傳原因")
        values, _, problems = resolve(["p/security-audit", "p/a"], D / "c", get=fake({"p/security-audit": (200, good), "p/a": (500, b"")}))
        if problems != ["registry 規則集 p/a 下載失敗（HTTP 500）"]:
            fails.append(f"resolve：一份失敗就記入 problems（得到 {problems}）")
        if any(is_registry(v) for v in values):   # 不得退回讓 semgrep 自己下載
            fails.append(f"resolve：取得失敗時不得退回 p/<名稱>（得到 {values}）")
        # CLI：成功 → stdout 每行一個 --config 值、紀錄寫出；任一份失敗 → exit 2、stdout 沒有任何 --config 值
        for label, table, want_rc in (("成功", {"p/security-audit": (200, good)}, 0), ("失敗", {"p/security-audit": (503, b"")}, 2)):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = main(["fetch", "--out", str(D / f"cli-{want_rc}"), "--record", str(D / f"rec-{want_rc}.json"),
                           "config/x.yaml", "p/security-audit"], get=fake(table))
            lines = out.getvalue().splitlines()
            rec = json.loads((D / f"rec-{want_rc}.json").read_text(encoding="utf-8")) if (D / f"rec-{want_rc}.json").exists() else None
            if rc != want_rc:
                fails.append(f"CLI「{label}」→ exit {want_rc}（得到 {rc}）")
            elif want_rc == 0 and (lines != ["config/x.yaml", str(D / "cli-0/p_security-audit.yaml")]
                                   or "sha256" not in err.getvalue() or not rec or not rec["rulesets"]):
                fails.append(f"CLI 成功：stdout 是 --config 值、log 印 SHA-256、紀錄有規則集（得到 {lines}）")
            elif want_rc == 2 and (lines or not rec or not rec["problems"]):
                fails.append(f"CLI 失敗：stdout 不得輸出 --config 值、紀錄寫明原因（得到 {lines}，{rec}）")
    return fails


if __name__ == "__main__":
    if sys.argv[1:] == ["selftest"]:
        _fails = selftest()
        for _f in _fails:
            print(f"FAIL {_f}")
        print("selftest " + ("通過" if not _fails else f"失敗 {len(_fails)} 項"))
        sys.exit(1 if _fails else 0)
    sys.exit(main())
