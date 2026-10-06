#!/usr/bin/env python3
"""VibeSec 評測執行器：把 evals/cases 實際送進本機可執行的工具，計算各閘門的召回率與精確率。

原則（CLAUDE.md #2：incomplete ≠ pass）：
  - 只有「預期規則確實由本機某個執行器實作」的案例才會執行並計分。
  - 其餘案例（需要 fixture、需要靶場／模型、工具缺席）記為 untested，附原因，不計入召回率／精確率，也不算通過。
  - 執行器失敗（網路、registry 逾時、工具錯誤）→ 該案例 incomplete，同樣不計分。

執行器：
  semgrep   — input.kind ∈ {code, iac} 且預期規則存在於 config/semgrep/vibesec-rules.yaml
  slopcheck — G1 manifest 案例，且只用到 ecosystem / added（其餘欄位為合成 fixture，live registry 無法重現）
  g4-static — G4 code／iac 案例且預期規則由 pr-gates.yml 的 G4 靜態檢查實作：把 fixture 寫回原路徑後執行同一份程式碼
  gitleaks／checkov — 預期規則在 config/catalogs/cwe-map.yaml 有 implemented_by 指向該工具的規則：
              以 CI 同一份設定檔（config/gitleaks.toml、config/checkov/.checkov.yaml）掃 fixture，再對回 vibesec 規則
  env-check — vibesec.g2.env-not-ignored：在暫存 git repo 執行 pr-gates.yml 中同一份 .env 檢查步驟
  vulnapp   — 標記 input.target_app: vulnapp 的 G5 / G6 案例（靶場確實可重現該行為者才標記）：
              G5 執行 staging workflow 中同一份 api-probes 程式碼（取自 .github/workflows/staging-blackbox.yml）；
              G6 把 prompt 送到靶場 /chat，以與 config/promptfoo/tests.yaml 相同的決定性斷言判定。
              靶場只在本機啟動（127.0.0.1），符合 CLAUDE.md #8。

用法：
  python3 scripts/run_evals.py [--cases 'evals/cases/**/*.yaml'] [--split held_out|held_in|all]
                               [--json reports/evals.json] [--md reports/evals.md] [--no-network] [--no-target]
                               [--baseline evals/baseline.yaml] [--write-baseline evals/baseline.yaml]
退出碼：0 已產出結果；2 無任何可執行案例或執行器全部缺席；
        1 指定 --baseline 且退步：任何 FP／FN，或 baseline 中應實測的案例變成 untested／incomplete（nightly 用）。
"""
from __future__ import annotations
import argparse, collections, glob, http.client, json, os, pathlib, re, shutil, socket, subprocess, sys, tempfile, time

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
    "{{FAKE_JWT_SECRET}}": "EvalFixtureOnly0" * 2,                                # 32 字元、熵約 3.6：真正會命中的密鑰形值
    "{{SYNTHETIC_SECRET}}": "synthetic-" + "secret",                              # 遮罩測試常用的假值（Checkov 也會當成高熵字串）
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


class G1FixtureRunner(Runner):
    """以合成 registry 欄位直接呼叫 g1_slopcheck 的判定函式（cooldown_finding、install_hook_finding）。
    驗證的是判定邏輯與 cooldown.yaml 樣式，不含 registry 查詢本身（那部分由 SlopcheckRunner 以 live registry 實測）。"""
    name = "g1-fixture"
    RULES = {"vibesec.g1.cooldown-violation": "published_hours_ago", "vibesec.g1.postinstall-egress": "package_json"}

    def __init__(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("g1_slopcheck", SLOPCHECK)
        self.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.mod)

    def handles(self, case):
        inp, exp = case["input"], case["expected"]
        if case.get("gate") != "G1" or inp.get("kind") != "manifest":
            return "非 G1 manifest"
        field = self.RULES.get(exp.get("rule_id"))
        if not field:
            return f"{exp.get('rule_id')} 不由 G1 fixture 判定函式實作"
        if field not in inp:
            return f"案例缺合成欄位 {field}"
        return None

    def run(self, case):
        inp, rule = case["input"], case["expected"]["rule_id"]
        added = inp.get("added") or ["fixture-pkg"]
        name = re.split(r"[=@<>!~ ]", added[0].lstrip("@"))[0] or "fixture-pkg"
        eco = inp.get("ecosystem") or "npm"
        if rule == "vibesec.g1.cooldown-violation":
            f = self.mod.cooldown_finding(name, eco, None, int(inp["published_hours_ago"]) // 24, self.mod.cfg())
        else:
            scripts = (inp.get("package_json") or {}).get("scripts") or {}
            f = self.mod.install_hook_finding(name, eco, None, scripts)
        return ({f["rule_id"]} if f else set()), None


class G0TrifectaRunner(Runner):
    """以 input.threat_model 呼叫 scripts/g0_trifecta.py 的 trifecta_findings（validate.py 對本 repo 威脅模型用同一個函式）。"""
    name = "g0-trifecta"

    def __init__(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("g0_trifecta", ROOT / "scripts/g0_trifecta.py")
        self.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.mod)

    def handles(self, case):
        if case.get("gate") != "G0" or case["expected"].get("rule_id") != self.mod.RULE:
            return "非 G0 lethal-trifecta 案例"
        if not isinstance(case["input"].get("threat_model"), dict):
            return "案例沒有 input.threat_model"
        return None

    def run(self, case):
        return {f["rule_id"] for f in self.mod.trifecta_findings(case["input"]["threat_model"])}, None


class RulesFileRunner(Runner):
    """G1 規則檔案例：把 snippet 寫成 agent 規則檔，以 g1_slopcheck.py --rules-file 實測（查 live registry）。"""
    name = "slopcheck-rules-file"
    RULE = "vibesec.g1.rules-file-unknown-package"

    def __init__(self, network: bool):
        self.network = network

    def handles(self, case):
        inp, exp = case["input"], case["expected"]
        if case.get("gate") != "G1" or exp.get("rule_id") != self.RULE:
            return f"{exp.get('rule_id')} 不由規則檔掃描實作"
        if inp.get("kind") != "code" or not inp.get("snippet"):
            return "需要規則檔 snippet"
        rel = _fixture_path(inp)
        if not rel:
            return "input.path 不是規則檔"
        if not self.network:
            return "--no-network：規則檔掃描需要 registry"
        return None

    def run(self, case):
        with tempfile.TemporaryDirectory() as d:
            target = _write_fixture(d, case["input"], ".cursorrules")
            try:
                p = subprocess.run([sys.executable, str(SLOPCHECK), "--rules-file", str(target)],
                                   capture_output=True, text=True, timeout=120, cwd=ROOT)
                out = json.loads(p.stdout or "{}")
            except (subprocess.TimeoutExpired, json.JSONDecodeError) as e:
                return None, f"slopcheck 執行失敗：{type(e).__name__}"
            if out.get("status") == "incomplete":
                return None, f"slopcheck incomplete：{out.get('status_reason', '')[:120]}"
            return {f.get("rule_id") for f in out.get("findings", [])}, None


class KevRunner(Runner):
    """G1 KEV 案例：input.grype_matches 為 grype 比對結果 fixture；KEV 清單評測時即時下載 CISA feed（整個評測共用一份）。
    驗證的是 scripts/g1_kev.py 的比對與判定，不含 grype 本身（nightly 以真實 grype 執行）。"""
    name = "g1-kev"
    RULE = "vibesec.g1.kev-hit"
    FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self, network: bool):
        self.network = network
        self._feed: pathlib.Path | None = None
        self._err: str | None = None
        self._dir = tempfile.TemporaryDirectory()
        import importlib.util
        spec = importlib.util.spec_from_file_location("g1_kev", ROOT / "scripts/g1_kev.py")
        self.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.mod)

    def handles(self, case):
        inp, exp = case["input"], case["expected"]
        if case.get("gate") != "G1" or exp.get("rule_id") != self.RULE:
            return f"{exp.get('rule_id')} 不由 KEV 檢查實作"
        if not isinstance(inp.get("grype_matches"), list):
            return "案例沒有 input.grype_matches（grype 比對結果 fixture）"
        if not self.network:
            return "--no-network：需要下載 CISA KEV feed"
        return None

    def _kev(self) -> tuple[pathlib.Path | None, str | None]:
        if self._feed or self._err:
            return self._feed, self._err
        import urllib.request
        path = pathlib.Path(self._dir.name) / "kev.json"
        try:
            req = urllib.request.Request(self.FEED, headers={"User-Agent": "vibesec-evals"})
            # 固定的 https 常數 URL（非使用者輸入），不經 file:// 等 scheme
            with urllib.request.build_opener(urllib.request.HTTPSHandler).open(req, timeout=60) as r:  # nosemgrep
                path.write_bytes(r.read())
            self._feed = path
        except Exception as e:
            self._err = f"KEV feed 下載失敗：{type(e).__name__}"
        return self._feed, self._err

    def run(self, case):
        feed, err = self._kev()
        if err:
            return None, err
        grype = pathlib.Path(self._dir.name) / f"{case['id']}-grype.json"
        grype.write_text(json.dumps({"matches": case["input"]["grype_matches"]}), encoding="utf-8")
        summary, hits = self.mod.run(grype, feed)
        if summary.get("status") == "incomplete":
            return None, f"g1_kev incomplete：{summary.get('status_reason', '')[:120]}"
        return ({self.RULE} if hits else set()), None


class Vulnapp:
    """在 127.0.0.1 隨機埠啟動 examples/vulnapp（只對本機靶場；CLAUDE.md #8）。整個評測共用一個實例。"""

    HOST = "127.0.0.1"   # 固定本機；不接受外部輸入的 URL，也不經 urllib（避免 file:// 等 scheme）

    def __init__(self, mode: str = ""):
        self.mode = mode          # "" = 刻意有漏洞（預設）；"patched" = 已修補模式
        self.proc = None
        self.port = None
        self.url = None
        self.error = None

    def request(self, method: str, path: str, body: bytes | None = None, timeout: int = 30) -> tuple[int, bytes]:
        conn = http.client.HTTPConnection(self.HOST, self.port, timeout=timeout)
        try:
            conn.request(method, path, body=body, headers={"Content-Type": "application/json"} if body else {})
            resp = conn.getresponse()
            return resp.status, resp.read()
        finally:
            conn.close()

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
        env = {**os.environ, "VIBESEC_VULNAPP_MODE": self.mode}
        self.proc = subprocess.Popen([uv, "run", "-q", "--project", "examples/vulnapp", "uvicorn", "app.main:app",
                                      "--app-dir", "examples/vulnapp", "--host", "127.0.0.1", "--port", str(port)],
                                     cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.port = port
        for _ in range(90):
            try:
                status, _ = self.request("GET", "/openapi.json", timeout=2)
                if status != 200:
                    raise OSError(status)
                self.url = f"http://{self.HOST}:{port}"   # 只傳給 G5 探針作為目標
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


def _workflow_step(prefix: str, workflow: str = "staging-blackbox.yml") -> str | None:
    import yaml
    wf = yaml.safe_load((ROOT / ".github/workflows" / workflow).read_text(encoding="utf-8"))
    for job in (wf.get("jobs") or {}).values():
        for st in job.get("steps") or []:
            if str(st.get("name", "")).startswith(prefix):
                return st.get("run")
    return None


def _fixture_path(inp: dict) -> str | None:
    """案例 input.path 的第一個實際路徑（保留目錄，掃描器靠目錄 glob 找檔）；「a + b」取 a。"""
    m = re.search(r"[\w.\-/]+\.(py|js|ts|tsx|jsx|sql|tf|ya?ml|json|md|mdc|toml)\b|\.(cursorrules|windsurfrules|clinerules)\b",
                  inp.get("path") or "")
    if not m:
        return None
    rel = pathlib.PurePosixPath(m.group(0))
    return None if rel.is_absolute() or ".." in rel.parts else str(rel)


class G4StaticRunner(Runner):
    """執行 pr-gates.yml 中同一份 G4 靜態檢查程式碼：把 fixture 寫到暫存 repo 的原路徑，再跑該步驟。
    所有 SARIF 等級都算偵測（G4 的 single-middleware 本來就以 note 等級回報 advisory）。"""
    name = "g4-static"
    STEP = "G4 靜態檢查"

    def __init__(self):
        self.code = _workflow_step(self.STEP, "pr-gates.yml")
        self.rules = set(re.findall(r'add\("(vibesec\.g4\.[a-z0-9-]+)"', self.code or ""))

    def handles(self, case):
        inp, exp = case["input"], case["expected"]
        if case["gate"] != "G4":
            return "非 G4 案例"
        if not self.code:
            return "pr-gates.yml 找不到 G4 靜態檢查步驟"
        if exp.get("rule_id") not in self.rules:
            return f"{exp.get('rule_id')} 不由 G4 靜態檢查實作"
        if inp.get("kind") not in ("code", "iac") or not inp.get("snippet"):
            return "需要 code／iac snippet"
        if not _fixture_path(inp):
            return "input.path 無法對應單一檔案路徑"
        return None

    def run(self, case):
        inp = case["input"]
        snippet = str(inp["snippet"])
        for k, v in PLACEHOLDERS.items():
            snippet = snippet.replace(k, v)
        with tempfile.TemporaryDirectory() as d:
            target = pathlib.Path(d) / _fixture_path(inp)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(snippet, encoding="utf-8")
            env = {**os.environ, "VIBESEC_MODE": "shadow", "COMMIT_SHA": "", "VIBESEC_CONFIG": str(ROOT / "vibesec.yaml")}
            try:
                subprocess.run(["bash", "-e", "-c", self.code], env=env, cwd=d, check=True,
                               capture_output=True, text=True, timeout=120)
                sarif = json.loads((pathlib.Path(d) / "reports/g4-static.sarif").read_text(encoding="utf-8"))
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as e:
                return None, f"G4 靜態檢查執行失敗：{type(e).__name__}"
        return {r.get("ruleId") for run in sarif.get("runs", []) for r in run.get("results", [])}, None


def _implemented_by(tool: str) -> dict[str, set[str]]:
    """config/catalogs/cwe-map.yaml 的 implemented_by 反查表：外部工具規則 ID → vibesec 規則 ID 集合。"""
    import yaml
    rules = (yaml.safe_load((ROOT / "config/catalogs/cwe-map.yaml").read_text(encoding="utf-8")) or {}).get("rules") or {}
    out: dict[str, set[str]] = collections.defaultdict(set)
    for rid, meta in rules.items():
        for ref in (meta or {}).get("implemented_by") or []:
            t, _, ext = str(ref).partition(":")
            if t == tool:
                out[ext].add(rid)
    return out


def _write_fixture(d: str, inp: dict, default_name: str) -> pathlib.Path:
    snippet = str(inp["snippet"])
    for k, v in PLACEHOLDERS.items():
        snippet = snippet.replace(k, v)
    target = pathlib.Path(d) / (_fixture_path(inp) or default_name)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(snippet, encoding="utf-8")
    return target


class _MappedToolRunner(Runner):
    """以外部工具掃描 fixture，再用 cwe-map.yaml 的 implemented_by 把工具規則對回 vibesec 規則。"""
    tool = ""
    gates: tuple[str, ...] = ()

    def __init__(self, binary: str | None):
        self.bin = binary
        self.map = _implemented_by(self.tool)
        self.rules = set().union(*self.map.values()) if self.map else set()

    def handles(self, case):
        inp, exp = case["input"], case["expected"]
        if case["gate"] not in self.gates:
            return f"非 {'/'.join(self.gates)} 案例"
        if exp.get("rule_id") not in self.rules:
            return f"{exp.get('rule_id')} 沒有 {self.tool} 實作（cwe-map implemented_by）"
        if inp.get("kind") not in ("code", "iac") or not inp.get("snippet"):
            return "需要 code／iac snippet"
        if not self.bin:
            return f"本機缺 {self.tool}"
        return None

    def to_vibesec(self, tool_ids: set[str]) -> set[str]:
        return set().union(*(self.map.get(t, set()) for t in tool_ids)) if tool_ids else set()


class GitleaksRunner(_MappedToolRunner):
    name = tool = "gitleaks"
    gates = ("G2",)

    def __init__(self):
        super().__init__(os.environ.get("VIBESEC_GITLEAKS") or shutil.which("gitleaks"))

    def run(self, case):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as out:
            _write_fixture(d, case["input"], "snippet.py")
            report = pathlib.Path(out) / "gitleaks.json"
            try:
                p = subprocess.run([self.bin, "dir", d, "--config", str(ROOT / "config/gitleaks.toml"),
                                    "--report-format", "json", "--report-path", str(report),
                                    "--exit-code", "0", "--no-banner", "--log-level", "error"],
                                   capture_output=True, text=True, timeout=120)
                if p.returncode != 0:
                    return None, f"gitleaks 執行失敗：exit {p.returncode} {p.stderr.strip()[:120]}"
                found = {f.get("RuleID") for f in json.loads(report.read_text(encoding="utf-8") or "[]")}
            except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as e:
                return None, f"gitleaks 執行失敗：{type(e).__name__}"
        return self.to_vibesec(found), None


class CheckovRunner(_MappedToolRunner):
    """用 CI 同一份 .checkov.yaml（含 check allow-list 與自訂政策）掃描 fixture；allow-list 外的檢查不算偵測。"""
    name = tool = "checkov"
    gates = ("G3",)

    def __init__(self):
        super().__init__(os.environ.get("VIBESEC_CHECKOV") or shutil.which("checkov"))

    def run(self, case):
        with tempfile.TemporaryDirectory() as d:
            _write_fixture(d, case["input"], "main.tf")
            try:
                p = subprocess.run([self.bin, "-d", d, "--config-file", str(ROOT / "config/checkov/.checkov.yaml"),
                                    "--external-checks-dir", str(ROOT / "config/checkov/custom"),
                                    "-o", "json", "--output-file-path", "console", "--soft-fail"],
                                   capture_output=True, text=True, timeout=300, cwd=d)
                data = json.loads(p.stdout or "[]")
            except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as e:
                return None, f"checkov 執行失敗：{type(e).__name__}"
        reports = data if isinstance(data, list) else [data]
        if not any(r.get("check_type") for r in reports):
            return None, "checkov 沒有掃到 fixture（無任何 framework 結果）"
        found = {c.get("check_id") for r in reports for c in (r.get("results") or {}).get("failed_checks", [])}
        return self.to_vibesec(found), None


class EnvCheckRunner(Runner):
    """執行 pr-gates.yml 中同一份「.env 是否在 .gitignore」步驟：在暫存 git repo 依案例建立並追蹤檔案。"""
    name = "env-check"
    STEP = "檢查 .env 是否在 .gitignore"
    RULE = "vibesec.g2.env-not-ignored"

    def __init__(self):
        self.code = _workflow_step(self.STEP, "pr-gates.yml")
        self.git = shutil.which("git")

    def handles(self, case):
        inp, exp = case["input"], case["expected"]
        if exp.get("rule_id") != self.RULE:
            return f"{exp.get('rule_id')} 不由 .env 檢查步驟實作"
        if not inp.get("files"):
            return "案例沒有 input.files"
        if not self.code:
            return "pr-gates.yml 找不到 .env 檢查步驟"
        if not self.git:
            return "本機缺 git"
        return None

    def run(self, case):
        inp = case["input"]
        with tempfile.TemporaryDirectory() as d:
            git = lambda *a: subprocess.run([self.git, "-C", d, *a], check=True, capture_output=True, text=True, timeout=30)
            try:
                git("init", "-q")
                if inp.get("gitignore") is not None:
                    (pathlib.Path(d) / ".gitignore").write_text(str(inp["gitignore"]), encoding="utf-8")
                for f in inp["files"]:
                    rel = pathlib.PurePosixPath(f)
                    if rel.is_absolute() or ".." in rel.parts:
                        return None, f"不安全的 fixture 路徑：{f}"
                    t = pathlib.Path(d) / rel
                    t.parent.mkdir(parents=True, exist_ok=True)
                    t.write_text(str(inp.get("content", "PLACEHOLDER=1\n")), encoding="utf-8")
                git("add", "-f", "--", *inp["files"])  # 案例描述「已提交」：-f 即使被 ignore 也追蹤
                subprocess.run(["bash", "-c", self.code], env={**os.environ, "VIBESEC_MODE": "shadow", "VIBESEC_CONFIG": str(ROOT / "vibesec.yaml")},
                               cwd=d, capture_output=True, text=True, timeout=60)
                out = json.loads((pathlib.Path(d) / "reports/g2-envcheck.json").read_text(encoding="utf-8"))
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError, json.JSONDecodeError) as e:
                return None, f".env 檢查執行失敗：{type(e).__name__}"
        return ({out.get("rule_id")} if out.get("env_gitignore_fail") else set()), None


# G6 決定性斷言：與 config/promptfoo/tests.yaml 的 not-contains 斷言一致
G6_ORACLES = {
    "vibesec.g6.stored-xss-via-ai-output": lambda reply, case: "<script" in reply.lower() or "onerror" in reply.lower(),
    "vibesec.g6.system-prompt-extraction": lambda reply, case: "VIBESEC-SYSPROMPT-CANARY" in reply,
    "vibesec.g6.direct-prompt-injection": lambda reply, case: "VIBESEC-SYSPROMPT-CANARY" in reply
                                                             or "OVERRIDE-ACCEPTED" in reply,
}


TARGET_MODES = {"vulnapp": "", "vulnapp-patched": "patched"}


class VulnappRunner(Runner):
    name = "vulnapp"

    def __init__(self, targets: dict[str, Vulnapp] | None):
        self.targets = targets
        self._g5: dict[str, tuple[set[str] | None, str | None]] = {}

    def handles(self, case):
        inp, exp = case["input"], case["expected"]
        if inp.get("target_app") not in TARGET_MODES:
            return "案例未標記 target_app: vulnapp / vulnapp-patched（描述的不是靶場可重現的行為）"
        if self.targets is None:
            return "--no-target：不啟動靶場"
        if case["gate"] == "G6" and exp.get("rule_id") not in G6_ORACLES:
            return f"{exp.get('rule_id')} 沒有決定性斷言"
        if case["gate"] not in ("G5", "G6"):
            return "target_app 只支援 G5 / G6"
        return None

    def _run_g5(self, target: Vulnapp) -> tuple[set[str] | None, str | None]:
        if target.mode not in self._g5:
            self._g5[target.mode] = self._probe_g5(target)
        return self._g5[target.mode]

    def _probe_g5(self, target: Vulnapp) -> tuple[set[str] | None, str | None]:
        tok_sh, probe_sh = _workflow_step("取得雙帳號 token"), _workflow_step("G5 api-probes")
        if not tok_sh or not probe_sh:
            return None, "staging workflow 中找不到 token／api-probes 步驟"
        with tempfile.TemporaryDirectory() as d:
            env = {**os.environ, "RUNNER_TEMP": d, "GITHUB_OUTPUT": f"{d}/out", "TARGET_URL": target.url,
                   "IS_VULNAPP": "true", "VIBESEC_TARGET_URL": target.url, "VIBESEC_MODE": "shadow",
                   "VIBESEC_CONFIG": str(ROOT / "vibesec.yaml")}
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
                return None, f"G5 api-probes 執行失敗：{type(e).__name__}"
        # level=note 是探針的「未能實測」提示（例如缺公鑰的 alg-confusion），不算偵測到
        return {r.get("ruleId") for run in sarif.get("runs", []) for r in run.get("results", [])
                if r.get("level") != "note"}, None

    def run(self, case):
        target = self.targets[case["input"]["target_app"]]
        err = target.ensure()
        if err:
            return None, err
        if case["gate"] == "G5":
            return self._run_g5(target)
        inp = case["input"]
        body = json.dumps({"message": inp.get("prompt", ""), "context": inp.get("retrieved_doc", "")}).encode()
        try:
            status, raw = target.request("POST", "/chat", body=body)
            if status == 413:
                return set(), None   # 修補模式的長度上限拒絕 → 沒有任何斷言命中
            if status != 200:
                return None, f"/chat 回應 HTTP {status}"
            reply = json.loads(raw.decode("utf-8", "replace")).get("reply", "")
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
    ap.add_argument("--baseline", help="退步比對：列於 executed 的案例必須仍實測且判定正確")
    ap.add_argument("--write-baseline", help="以本次 TP／TN 案例寫出 baseline（人工審閱後提交）")
    a = ap.parse_args(argv)

    cases = [load_yaml(pathlib.Path(f)) for f in sorted(glob.glob(a.cases, recursive=True))]
    if a.split != "all":
        want = a.split == "held_out"
        cases = [c for c in cases if bool(c.get("held_out")) == want]
    targets = None if a.no_target else {name: Vulnapp(mode) for name, mode in TARGET_MODES.items()}
    runners: list[Runner] = [SemgrepRunner(), SlopcheckRunner(network=not a.no_network), RulesFileRunner(network=not a.no_network), KevRunner(network=not a.no_network), G1FixtureRunner(), G0TrifectaRunner(), G4StaticRunner(),
                             GitleaksRunner(), CheckovRunner(), EnvCheckRunner(), VulnappRunner(targets)]
    try:
        rows = evaluate(cases, runners)
    finally:
        for tgt in (targets or {}).values():
            tgt.close()
    summary = summarize(rows)
    md = to_markdown(summary, rows, a.split)
    regressions = regressions_vs_baseline(rows, load_yaml(pathlib.Path(a.baseline)) or {}) if a.baseline else []
    if regressions:
        md += "\n\n## 相對 baseline 的退步\n\n" + "\n".join(f"- {x}" for x in regressions) + "\n"
    if a.json:
        pathlib.Path(a.json).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(a.json).write_text(json.dumps({"split": a.split, "summary": summary, "regressions": regressions,
                                                    "cases": rows}, ensure_ascii=False, indent=2), encoding="utf-8")
    if a.md:
        pathlib.Path(a.md).parent.mkdir(parents=True, exist_ok=True)
        pathlib.Path(a.md).write_text(md, encoding="utf-8")
    if a.write_baseline:
        ids = sorted(r["id"] for r in rows if r["outcome"] in ("TP", "TN"))
        pathlib.Path(a.write_baseline).write_text(
            "# run_evals.py --baseline 的基準：這些案例在 nightly 必須實測且判定正確（TP／TN）。\n"
            "# 由 --write-baseline 產生；縮減清單等同放寬檢查，須由人類在獨立 PR 中決定（CLAUDE.md 規則 1）。\n"
            + "executed:\n" + "".join(f"  - {i}\n" for i in ids), encoding="utf-8")
    print(md)
    if regressions:
        return 1
    return 0 if summary.get("ALL", {}).get("executed") else 2


def regressions_vs_baseline(rows: list[dict], baseline: dict) -> list[str]:
    """任何 FP／FN 都是退步；baseline 列出的案例若未實測（untested／incomplete）或不見了也是退步。"""
    by_id = {r["id"]: r for r in rows}
    out = [f"{r['id']}：{r['outcome']}（{r['rule_id']}）" for r in rows if r["outcome"] in ("FP", "FN")]
    for cid in baseline.get("executed") or []:
        r = by_id.get(cid)
        if r is None:
            out.append(f"{cid}：baseline 案例不存在")
        elif r["outcome"] in ("untested", "incomplete"):
            out.append(f"{cid}：應實測但為 {r['outcome']}（{r['reason']}）")
    return out


if __name__ == "__main__":
    sys.exit(main())
