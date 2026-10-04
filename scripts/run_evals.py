#!/usr/bin/env python3
"""VibeSec 評測執行器：把 evals/cases 實際送進本機可執行的工具，計算各閘門的召回率與精確率。

原則（CLAUDE.md #2：incomplete ≠ pass）：
  - 只有「預期規則確實由本機某個執行器實作」的案例才會執行並計分。
  - 其餘案例（需要 fixture、需要靶場／模型、工具缺席）記為 untested，附原因，不計入召回率／精確率，也不算通過。
  - 執行器失敗（網路、registry 逾時、工具錯誤）→ 該案例 incomplete，同樣不計分。

執行器：
  semgrep   — input.kind ∈ {code, iac} 且預期規則存在於 config/semgrep/vibesec-rules.yaml
  slopcheck — G1 manifest 案例，且只用到 ecosystem / added（其餘欄位為合成 fixture，live registry 無法重現）
  vulnapp   — 標記 input.target_app: vulnapp 的 G5 / G6 案例（靶場確實可重現該行為者才標記）：
              G5 執行 staging workflow 中同一份 api-probes 程式碼（取自 .github/workflows/staging-blackbox.yml）；
              G6 把 prompt 送到靶場 /chat，以與 config/promptfoo/tests.yaml 相同的決定性斷言判定。
              靶場只在本機啟動（127.0.0.1），符合 CLAUDE.md #8。

用法：
  python3 scripts/run_evals.py [--cases 'evals/cases/**/*.yaml'] [--split held_out|held_in|all]
                               [--json reports/evals.json] [--md reports/evals.md] [--no-network] [--no-target]
退出碼：0 已產出結果（評測不是閘門，不以分數決定退出碼）；2 無任何可執行案例或執行器全部缺席。
"""
from __future__ import annotations
import argparse, collections, glob, json, os, pathlib, re, shutil, socket, subprocess, sys, tempfile, time, urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
SEMGREP_RULES = ROOT / "config/semgrep/vibesec-rules.yaml"
SLOPCHECK = ROOT / "scripts/g1_slopcheck.py"
SLOPCHECK_RULES = {"vibesec.g1.hallucinated-package", "vibesec.g1.cooldown-violation",
                   "vibesec.g1.low-download-package"}
G1_LIVE_KEYS = {"kind", "ecosystem", "added"}
# fixture 佔位符：repo 內不放金鑰形字串（避免本 repo 的 G2 掃描自我命中），執行時才展開為合成值
PLACEHOLDERS = {
    "{{FAKE_ANTHROPIC_KEY}}": "sk-ant-api03-" + ("EvalFixtureOnly0" * 6),          # 96 字元，形似但非真金鑰
    "{{FAKE_OPENAI_KEY}}": "sk-proj-" + ("EvalFixtureOnly0" * 3),                 # 48 字元
}
LANG_EXT = {"python": ".py", "javascript": ".js", "typescript": ".ts", "sql": ".sql",
            "terraform": ".tf", "hcl": ".tf", "yaml": ".yml", "dockerfile": ".Dockerfile"}


def load_yaml(p: pathlib.Path):
    import yaml
    return yaml.safe_load(p.read_text(encoding="utf-8"))


def semgrep_rule_ids() -> set[str]:
    try:
        rules = (load_yaml(SEMGREP_RULES) or {}).get("rules") or []
    except Exception:
        return set()
    return {r["id"] for r in rules if isinstance(r, dict) and r.get("id")}


def base_rule(rule_id: str) -> str:
    """semgrep 同一規則的語言變體（-js、-supabase-js）歸回 cwe-map 的規則 ID。"""
    return re.sub(r"-(supabase-)?js$", "", rule_id)


def file_name_for(inp: dict) -> str:
    path = inp.get("path") or ""
    # 「a + b」這類多檔描述取第一個實際副檔名
    m = re.search(r"[\w.\-/]+\.(py|js|ts|tsx|jsx|sql|tf|ya?ml|json|md|toml)\b", path)
    if m:
        return pathlib.PurePosixPath(m.group(0)).name
    if "Dockerfile" in path:
        return "Dockerfile"
    ext = LANG_EXT.get((inp.get("language") or "").lower(), ".txt")
    return "snippet" + ext


# ---------------------------------------------------------------- runners
class Runner:
    name = "base"

    def handles(self, case: dict) -> str | None:
        """回傳 None 表示可執行；否則回傳不可執行的原因。"""
        raise NotImplementedError

    def run(self, case: dict) -> tuple[set[str] | None, str | None]:
        """回傳 (命中的規則 ID 集合, 錯誤原因)。錯誤時集合為 None。"""
        raise NotImplementedError


class SemgrepRunner(Runner):
    name = "semgrep"

    def __init__(self):
        self.bin = shutil.which("semgrep")
        self.rules = {base_rule(r) for r in semgrep_rule_ids()}

    def handles(self, case):
        inp, exp = case["input"], case["expected"]
        if inp.get("kind") not in ("code", "iac"):
            return f"kind={inp.get('kind')} 非程式碼"
        if exp.get("rule_id") not in self.rules:
            return f"{exp.get('rule_id')} 不由 semgrep 規則集實作"
        if not inp.get("snippet"):
            return "案例沒有 snippet"
        if not self.bin:
            return "本機缺 semgrep"
        return None

    def run(self, case):
        inp = case["input"]
        with tempfile.TemporaryDirectory() as d:
            target = pathlib.Path(d) / file_name_for(inp)
            # YAML 跳脫已解碼為實際字元；寫入暫存檔供掃描
            snippet = str(inp["snippet"])
            for k, v in PLACEHOLDERS.items():
                snippet = snippet.replace(k, v)
            target.write_text(snippet, encoding="utf-8")
            try:
                p = subprocess.run([self.bin, "--config", str(SEMGREP_RULES), "--json", "--quiet",
                                    "--metrics=off", "--disable-version-check", str(target)],
                                   capture_output=True, text=True, timeout=180)
                data = json.loads(p.stdout or "{}")
            except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
                return None, f"semgrep 執行失敗：{type(e).__name__}"
            if data.get("errors") and not data.get("results"):
                return None, f"semgrep 錯誤：{str(data['errors'][0].get('message', ''))[:120]}"
            hits = set()
            for r in data.get("results", []):
                cid = r.get("check_id", "")
                m = re.search(r"(vibesec\.g\d\.[a-z0-9-]+)$", cid)
                if m:
                    hits.add(base_rule(m.group(1)))
            return hits, None


class SlopcheckRunner(Runner):
    name = "slopcheck"

    def __init__(self, network: bool):
        self.network = network

    def handles(self, case):
        inp, exp = case["input"], case["expected"]
        if case.get("gate") != "G1" or inp.get("kind") != "manifest":
            return "非 G1 manifest"
        if exp.get("rule_id") not in SLOPCHECK_RULES:
            return f"{exp.get('rule_id')} 不由 slopcheck registry 查詢實作"
        extra = set(inp) - G1_LIVE_KEYS
        if extra:
            return f"需要合成 fixture 欄位 {sorted(extra)}，live registry 無法重現"
        if inp.get("ecosystem") not in ("npm", "pypi"):
            return f"ecosystem={inp.get('ecosystem')} 不支援"
        if not self.network:
            return "--no-network：slopcheck 需要 registry"
        return None

    def run(self, case):
        inp = case["input"]
        eco, added = inp["ecosystem"], inp.get("added") or []
        with tempfile.TemporaryDirectory() as d:
            if eco == "npm":
                deps = {}
                for spec in added:
                    name, _, ver = spec.rpartition("@") if spec.count("@") > (1 if spec.startswith("@") else 0) else (spec, "", "latest")
                    deps[name or spec] = ver or "latest"
                mf = pathlib.Path(d) / "package.json"
                mf.write_text(json.dumps({"name": "eval", "dependencies": deps}), encoding="utf-8")
            else:
                mf = pathlib.Path(d) / "requirements.txt"
                mf.write_text("\n".join(added) + "\n", encoding="utf-8")
            try:
                p = subprocess.run([sys.executable, str(SLOPCHECK), "--manifest", str(mf)],
                                   capture_output=True, text=True, timeout=120, cwd=ROOT)
                out = json.loads(p.stdout or "{}")
            except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
                return None, f"slopcheck 執行失敗：{type(e).__name__}"
            if out.get("status") == "incomplete":
                return None, f"slopcheck incomplete：{out.get('status_reason', '')[:120]}"
            return {f.get("rule_id") for f in out.get("findings", [])}, None


class Vulnapp:
    """在 127.0.0.1 隨機埠啟動 examples/vulnapp（只對本機靶場；CLAUDE.md #8）。整個評測共用一個實例。"""

    def __init__(self):
        self.proc = None
        self.url = None
        self.error = None

    def ensure(self) -> str | None:
        if self.url or self.error:
            return self.error
        uv = shutil.which("uv")
        if not uv:
            self.error = "本機缺 uv，無法啟動靶場"
            return self.error
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        self.proc = subprocess.Popen([uv, "run", "-q", "--project", "examples/vulnapp", "uvicorn", "app.main:app",
                                      "--app-dir", "examples/vulnapp", "--host", "127.0.0.1", "--port", str(port)],
                                     cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        url = f"http://127.0.0.1:{port}"
        for _ in range(90):
            try:
                urllib.request.urlopen(url + "/openapi.json", timeout=2)
                self.url = url
                return None
            except Exception:
                if self.proc.poll() is not None:
                    break
                time.sleep(1)
        self.error = "靶場啟動失敗或逾時"
        self.close()
        return self.error

    def close(self):
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def _workflow_step(prefix: str) -> str | None:
    import yaml
    wf = yaml.safe_load((ROOT / ".github/workflows/staging-blackbox.yml").read_text(encoding="utf-8"))
    for job in (wf.get("jobs") or {}).values():
        for st in job.get("steps") or []:
            if str(st.get("name", "")).startswith(prefix):
                return st.get("run")
    return None


# G6 決定性斷言：與 config/promptfoo/tests.yaml 的 not-contains 斷言一致
G6_ORACLES = {
    "vibesec.g6.stored-xss-via-ai-output": lambda reply, case: "<script" in reply.lower() or "onerror" in reply.lower(),
    "vibesec.g6.system-prompt-extraction": lambda reply, case: "VIBESEC-SYSPROMPT-CANARY" in reply,
    "vibesec.g6.direct-prompt-injection": lambda reply, case: "VIBESEC-SYSPROMPT-CANARY" in reply
                                                             or "OVERRIDE-ACCEPTED" in reply,
}


class VulnappRunner(Runner):
    name = "vulnapp"

    def __init__(self, target: Vulnapp | None):
        self.target = target
        self._g5_hits: set[str] | None = None
        self._g5_err: str | None = None

    def handles(self, case):
        inp, exp = case["input"], case["expected"]
        if inp.get("target_app") != "vulnapp":
            return "案例未標記 target_app: vulnapp（描述的不是靶場可重現的行為）"
        if self.target is None:
            return "--no-target：不啟動靶場"
        if case["gate"] == "G6" and exp.get("rule_id") not in G6_ORACLES:
            return f"{exp.get('rule_id')} 沒有決定性斷言"
        if case["gate"] not in ("G5", "G6"):
            return "target_app 只支援 G5 / G6"
        return None

    def _run_g5(self) -> tuple[set[str] | None, str | None]:
        if self._g5_hits is not None or self._g5_err:
            return self._g5_hits, self._g5_err
        tok_sh, probe_sh = _workflow_step("取得雙帳號 token"), _workflow_step("G5 api-probes")
        if not tok_sh or not probe_sh:
            self._g5_err = "staging workflow 中找不到 token／api-probes 步驟"
            return None, self._g5_err
        with tempfile.TemporaryDirectory() as d:
            env = {**os.environ, "RUNNER_TEMP": d, "GITHUB_OUTPUT": f"{d}/out", "TARGET_URL": self.target.url,
                   "IS_VULNAPP": "true", "VIBESEC_TARGET_URL": self.target.url, "VIBESEC_MODE": "shadow"}
            try:
                subprocess.run(["bash", "-e", "-c", tok_sh], env=env, cwd=d, check=True,
                               capture_output=True, text=True, timeout=60)
                outs = dict(l.split("=", 1) for l in pathlib.Path(f"{d}/out").read_text().splitlines() if "=" in l)
                env.update({"HAS_A": outs.get("has_a", "false"), "HAS_B": outs.get("has_b", "false"),
                            "VIBESEC_TOKEN_DIR": outs.get("token_dir", "")})
                subprocess.run(["bash", "-e", "-c", probe_sh], env=env, cwd=d, check=True,
                               capture_output=True, text=True, timeout=300)
                sarif = json.loads(pathlib.Path(f"{d}/reports/g5-api-probes.sarif").read_text(encoding="utf-8"))
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as e:
                self._g5_err = f"G5 api-probes 執行失敗：{type(e).__name__}"
                return None, self._g5_err
        # level=note 是探針的「未能實測」提示（例如缺公鑰的 alg-confusion），不算偵測到
        self._g5_hits = {r.get("ruleId") for run in sarif.get("runs", []) for r in run.get("results", [])
                         if r.get("level") != "note"}
        return self._g5_hits, None

    def run(self, case):
        err = self.target.ensure()
        if err:
            return None, err
        if case["gate"] == "G5":
            return self._run_g5()
        inp = case["input"]
        body = json.dumps({"message": inp.get("prompt", ""), "context": inp.get("retrieved_doc", "")}).encode()
        req = urllib.request.Request(self.target.url + "/chat", data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                reply = json.loads(resp.read().decode("utf-8", "replace")).get("reply", "")
        except Exception as e:
            return None, f"/chat 呼叫失敗：{type(e).__name__}"
        return {rule for rule, oracle in G6_ORACLES.items() if oracle(reply, case)}, None


# ---------------------------------------------------------------- scoring
def evaluate(cases: list[dict], runners: list[Runner]) -> list[dict]:
    rows = []
    for case in cases:
        exp = case["expected"]
        row = {"id": case["id"], "gate": case["gate"], "domain": case.get("domain"),
               "held_out": bool(case.get("held_out")), "rule_id": exp.get("rule_id"),
               "should_flag": bool(exp.get("should_flag")), "runner": None, "outcome": "untested",
               "reason": None, "hits": []}
        if exp.get("gate_status") == "incomplete":
            row["reason"] = "案例描述工具／環境失敗情境（gate_status: incomplete），需在整合層驗證"
            rows.append(row); continue
        reasons = []
        for r in runners:
            why = r.handles(case)
            if why:
                reasons.append(f"{r.name}: {why}"); continue
            row["runner"] = r.name
            hits, err = r.run(case)
            if err:
                row["outcome"], row["reason"] = "incomplete", err
            else:
                row["hits"] = sorted(hits)
                flagged = exp.get("rule_id") in hits
                row["outcome"] = {(True, True): "TP", (True, False): "FN",
                                  (False, True): "FP", (False, False): "TN"}[(row["should_flag"], flagged)]
            break
        else:
            # 優先顯示「已接近可執行」的原因（同 gate 的專屬執行器），其次第一個
            specific = [r for r in reasons if "非程式碼" not in r and "非 G1 manifest" not in r
                        and "target_app" not in r]
            row["reason"] = (specific or reasons or ["沒有執行器"])[0]
            if row["reason"].startswith("semgrep: kind=") and case["input"].get("kind") in ("http", "prompt", "config"):
                row["reason"] = (f"kind={case['input']['kind']}：未標記 target_app（案例描述的不是靶場可重現的行為），尚無對應執行器"
                                 if case["input"].get("kind") in ("http", "prompt")
                                 else f"kind={case['input']['kind']}：需人工審查或整合層驗證，尚無本機執行器")
        rows.append(row)
    return rows


def summarize(rows: list[dict]) -> dict:
    by_gate = collections.defaultdict(collections.Counter)
    for r in rows:
        by_gate[r["gate"]][r["outcome"]] += 1
        by_gate["ALL"][r["outcome"]] += 1
    out = {}
    for g, c in sorted(by_gate.items()):
        tp, fp, fn, tn = c["TP"], c["FP"], c["FN"], c["TN"]
        out[g] = {"TP": tp, "FP": fp, "FN": fn, "TN": tn,
                  "untested": c["untested"], "incomplete": c["incomplete"],
                  "executed": tp + fp + fn + tn, "total": sum(c.values()),
                  "recall": round(tp / (tp + fn), 3) if tp + fn else None,
                  "precision": round(tp / (tp + fp), 3) if tp + fp else None}
    return out


def to_markdown(summary: dict, rows: list[dict], split: str) -> str:
    fmt = lambda v: "—" if v is None else f"{v:.0%}"
    lines = [f"# VibeSec 評測結果（split: {split}）", "",
             "召回率／精確率只計入實際執行的案例；untested／incomplete 不計分，也不算通過（incomplete ≠ pass）。", "",
             "| 閘門 | 執行 / 總數 | TP | FP | FN | TN | untested | incomplete | 召回率 | 精確率 |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    for g, s in summary.items():
        lines.append(f"| {g} | {s['executed']} / {s['total']} | {s['TP']} | {s['FP']} | {s['FN']} | {s['TN']} | "
                     f"{s['untested']} | {s['incomplete']} | {fmt(s['recall'])} | {fmt(s['precision'])} |")
    bad = [r for r in rows if r["outcome"] in ("FP", "FN", "incomplete")]
    if bad:
        lines += ["", "## 需要注意的案例", "", "| 案例 | 結果 | 規則 | 執行器 | 命中／原因 |", "|---|---|---|---|---|"]
        for r in bad:
            detail = r["reason"] or (", ".join(r["hits"]) or "（無命中）")
            lines.append(f"| {r['id']} | {r['outcome']} | {r['rule_id']} | {r['runner']} | {detail} |")
    untested = collections.Counter(r["reason"] or "?" for r in rows if r["outcome"] == "untested")
    if untested:
        lines += ["", "## 未執行原因（摘要）", ""]
        lines += [f"- {k}：{v} 案例" for k, v in untested.most_common()]
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--cases", default=str(ROOT / "evals/cases/**/*.yaml"))
    ap.add_argument("--split", choices=["all", "held_out", "held_in"], default="all")
    ap.add_argument("--json")
    ap.add_argument("--md")
    ap.add_argument("--no-network", action="store_true")
    ap.add_argument("--no-target", action="store_true", help="不啟動本機靶場（G5／G6 案例記 untested）")
    a = ap.parse_args(argv)

    cases = [load_yaml(pathlib.Path(f)) for f in sorted(glob.glob(a.cases, recursive=True))]
    if a.split != "all":
        want = a.split == "held_out"
        cases = [c for c in cases if bool(c.get("held_out")) == want]
    target = None if a.no_target else Vulnapp()
    runners: list[Runner] = [SemgrepRunner(), SlopcheckRunner(network=not a.no_network), VulnappRunner(target)]
    try:
        rows = evaluate(cases, runners)
    finally:
        if target:
            target.close()
    summary = summarize(rows)
    md = to_markdown(summary, rows, a.split)
    if a.json:
        pathlib.Path(a.json).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(a.json).write_text(json.dumps({"split": a.split, "summary": summary, "cases": rows},
                                                   ensure_ascii=False, indent=2), encoding="utf-8")
    if a.md:
        pathlib.Path(a.md).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(a.md).write_text(md, encoding="utf-8")
    print(md)
    return 0 if summary.get("ALL", {}).get("executed") else 2


if __name__ == "__main__":
    sys.exit(main())
