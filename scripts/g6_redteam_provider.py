#!/usr/bin/env python3
"""G6 promptfoo redteam 的評分 provider：依目標回應的資料分級挑選，不符 AGENTS.md 規則 7 就不送（#356）。

  python3 -I scripts/g6_redteam_provider.py --target-kind lab|external --out <臨時 promptfoo 設定>
  python3 scripts/g6_redteam_provider.py selftest

redteam 會把目標的回應送給 provider 生成攻擊與評分。目標回應的資料分級由本腳本決定（受信任樹），workflow 只傳目標種類：
  - lab（examples/vulnapp 靶場）：internal；
  - external（其他受測服務）：未分類 → 一律不送（規則 7：未分類資料留在地端；宣告分級的途徑見 #359）。
候選依序為 anthropic-cloud、openai-cloud（只看有設定金鑰的；金鑰只看環境變數名稱是否有值，不讀出、不輸出），
每個候選都要通過 vibesec_providers.may_send（enabled、allowed_data_classes、sensitive_data_providers）。

輸出（stdout 一行）：
  provider=<名稱>     已挑到：--out 寫出臨時設定（redteam.provider 與 defaultTest.options.provider 換成該 provider 的模型）
  skipped=<原因>      不執行：--out 不寫出（已存在就刪除），呼叫端以 g6_gate.py --redteam-skipped 記 untested
退出碼：0 = 已做出決定（provider 或 skipped）；2 = 設定讀不到或格式不符、--out 寫不出（呼叫端一律當 skipped，不送出）。
"""
from __future__ import annotations
import argparse, os, pathlib, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))   # 以 python3 -I 執行時腳本目錄不在 sys.path
try:
    import yaml
    import vibesec_providers   # noqa: E402
except ImportError as e:
    print(f"工具缺席：{e.name}", file=sys.stderr); sys.exit(2)

# (providers.yaml 的名稱, promptfoo provider ID 前綴)：順序即優先序（與以前 workflow 內的選法相同）
CANDIDATES = (("anthropic-cloud", "anthropic:messages:"), ("openai-cloud", "openai:chat:"))
# 目標種類 → 目標回應的資料分級。None = 未分類（沒有任何 provider 可以收）
TARGET_DATA_CLASS = {"lab": "internal", "external": None}
EXTERNAL_REASON = "外部目標的回應未分類，依規則 7 不送雲端評分"
# 固定文字（與 #356 以前的 workflow 相同）：不從 providers.yaml 的 api_key_env 組字串再印出，
# CodeQL 會依名稱把它當成密碼（py/clear-text-logging-sensitive-data，#230、#356）
NO_KEY_REASON = "未設定 ANTHROPIC_API_KEY / OPENAI_API_KEY secret"
PROMPTFOO_CONFIG = "config/promptfoo/promptfooconfig.yaml"


def choose(config: dict, target_kind: str, environ) -> tuple[str | None, str | None, str | None]:
    """→ (provider 名稱, promptfoo provider ID, None)，或 (None, None, skipped 原因)。"""
    data_class = TARGET_DATA_CLASS[target_kind]
    if data_class is None:
        return None, None, EXTERNAL_REASON
    providers = config.get("providers") or {}
    names = [vibesec_providers.setting(providers.get(n) or {}, "api_key_env") for n, _ in CANDIDATES]   # 環境變數的名稱
    keyed = [(n, prefix) for (n, prefix), var in zip(CANDIDATES, names) if var and environ.get(var)]
    if not keyed:
        return None, None, NO_KEY_REASON
    refused = []
    for name, prefix in keyed:
        allowed, why = vibesec_providers.may_send(config, name, data_class)
        model = str((providers.get(name) or {}).get("model") or "")
        if allowed and model:
            return name, prefix + model, None
        refused.append(f"{name}：{why or 'providers.yaml 沒有 model'}")
    return None, None, f"沒有可收 {data_class} 的 provider（" + "；".join(refused) + "）"


def main(argv=None, environ=None, root: pathlib.Path = ROOT) -> int:
    environ = os.environ if environ is None else environ
    ap = argparse.ArgumentParser(description="G6 redteam 的評分 provider（規則 7）")
    ap.add_argument("--target-kind", required=True, choices=sorted(TARGET_DATA_CLASS))
    ap.add_argument("--out", required=True, type=pathlib.Path, help="臨時 promptfoo 設定的輸出路徑")
    a = ap.parse_args(argv)
    try:
        config = vibesec_providers.load_config(root)
        pf = yaml.safe_load((root / PROMPTFOO_CONFIG).read_text(encoding="utf-8"))
        if not isinstance(pf, dict):
            raise ValueError(f"{PROMPTFOO_CONFIG} 不是 YAML 物件")
        name, pid, reason = choose(config, a.target_kind, environ)
    except Exception as e:   # 讀不到、格式不符：無法判定 → 呼叫端當 skipped（不送出）。只印例外型別（比照 review_provider）
        print(f"無法判定 redteam 的 provider：讀取 providers.yaml 或 {PROMPTFOO_CONFIG} 失敗（{type(e).__name__}）", file=sys.stderr)
        return 2
    try:
        if reason is not None:
            a.out.unlink(missing_ok=True)   # 不留舊的臨時設定：skipped 就一定沒有可執行的設定
            print(f"skipped={' '.join(reason.split())}")   # 一行：workflow 直接寫進 GITHUB_OUTPUT，換行會變成另一個輸出鍵
            return 0
        pf.setdefault("redteam", {})["provider"] = pid
        pf.setdefault("defaultTest", {}).setdefault("options", {})["provider"] = pid
        a.out.write_text(yaml.safe_dump(pf, allow_unicode=True, sort_keys=False), encoding="utf-8")
    except OSError as e:
        print(f"無法寫出臨時設定 {a.out}（{type(e).__name__}）", file=sys.stderr)
        return 2
    print(f"provider={name}")
    return 0


def selftest() -> list[str]:
    import contextlib, io, shutil, tempfile
    fails: list[str] = []
    # 假金鑰在執行時組出：完整字面會被 config/gitleaks.toml 的 vibesec-openai-api-key 判成金鑰（#356 PR CI 的 G2 fail）
    secret = "-".join(("sk", "selftest", "fake", "356"))
    with tempfile.TemporaryDirectory() as d:
        D = pathlib.Path(d)

        def tree(label: str, mutate=None, providers_text: str | None = None) -> pathlib.Path:
            r = D / label
            (r / "config/promptfoo").mkdir(parents=True)
            shutil.copy(ROOT / PROMPTFOO_CONFIG, r / PROMPTFOO_CONFIG)
            if providers_text is not None:
                (r / "config/providers.yaml").write_text(providers_text, encoding="utf-8")
            else:
                data = yaml.safe_load((ROOT / "config/providers.yaml").read_text(encoding="utf-8"))
                if mutate:
                    mutate(data["providers"])
                (r / "config/providers.yaml").write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
            return r

        def run(root, kind, env, out=None):
            out = out or (D / "out.yaml")
            buf, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(err):
                rc = main(["--target-kind", kind, "--out", str(out)], environ=env, root=root)
            text = out.read_text(encoding="utf-8") if out.exists() else None
            if secret in buf.getvalue() + err.getvalue() + (text or ""):
                fails.append(f"{kind}：金鑰值出現在輸出或臨時設定中")
            return rc, buf.getvalue().strip(), text

        real = tree("real")
        real_cfg = yaml.safe_load((ROOT / "config/providers.yaml").read_text(encoding="utf-8"))["providers"]
        both = {"ANTHROPIC_API_KEY": secret, "OPENAI_API_KEY": secret}
        stale = D / "out.yaml"

        # lab：依序挑 anthropic、openai；臨時設定的兩個 provider 欄位都換成該模型，其餘設定照舊
        for label, env, want_name, want_pid in [
            ("lab＋anthropic", both, "anthropic-cloud", f"anthropic:messages:{real_cfg['anthropic-cloud']['model']}"),
            ("lab＋只有 openai", {"OPENAI_API_KEY": secret}, "openai-cloud", f"openai:chat:{real_cfg['openai-cloud']['model']}"),
        ]:
            rc, out, text = run(real, "lab", env)
            cfg = yaml.safe_load(text) if text else {}
            if rc != 0 or out != f"provider={want_name}" or (cfg.get("redteam") or {}).get("provider") != want_pid \
                    or ((cfg.get("defaultTest") or {}).get("options") or {}).get("provider") != want_pid \
                    or not (cfg.get("redteam") or {}).get("plugins"):
                fails.append(f"{label} → exit 0、provider={want_name}、臨時設定換成 {want_pid}（得到 {rc}、{out!r}）")

        # skipped：stdout 寫原因、不寫出臨時設定（先放一份舊檔，必須被刪掉）
        for label, root, kind, env, needle in [
            ("lab 沒有金鑰", real, "lab", {}, "未設定 ANTHROPIC_API_KEY / OPENAI_API_KEY secret"),
            ("external 有兩種金鑰", real, "external", both, EXTERNAL_REASON),
            ("external 沒有金鑰", real, "external", {}, EXTERNAL_REASON),
            ("兩個都 enabled: false", tree("off", lambda p: [p[n].update(enabled=False) for n, _ in CANDIDATES]),
             "lab", both, "enabled: false"),
            ("兩個都不收 internal", tree("pub", lambda p: [p[n].update(allowed_data_classes=["public"]) for n, _ in CANDIDATES]),
             "lab", both, "只收"),
        ]:
            stale.write_text("old: config\n", encoding="utf-8")
            rc, out, text = run(root, kind, env)
            if rc != 0 or not out.startswith("skipped=") or needle not in out or text is not None:
                fails.append(f"{label} → exit 0、skipped（原因含 {needle!r}）、不留臨時設定（得到 {rc}、{out!r}、設定 {text is not None}）")

        # anthropic 不能收 internal → 換下一個有金鑰的候選
        for label, mutate in (("停用", lambda p: p["anthropic-cloud"].update(enabled=False)),
                              ("不收 internal", lambda p: p["anthropic-cloud"].update(allowed_data_classes=["public"]))):
            rc, out, _ = run(tree(f"one-{len(label)}", mutate), "lab", both)
            if rc != 0 or out != "provider=openai-cloud":
                fails.append(f"anthropic-cloud {label}、兩種金鑰都有 → 改挑 openai-cloud（得到 {rc}、{out!r}）")

        # skipped 原因含換行也只輸出一行（workflow 直接寫進 GITHUB_OUTPUT）：暫時換掉原因常數來驗證這道防線
        saved = globals()["EXTERNAL_REASON"]
        globals()["EXTERNAL_REASON"] = "第一行\nexit_code=0"   # choose() 讀的是同一份模組全域變數
        try:
            rc, out, _ = run(real, "external", both)
        finally:
            globals()["EXTERNAL_REASON"] = saved
        if rc != 0 or "\n" in out or not out.startswith("skipped="):
            fails.append(f"skipped 原因必須是一行（得到 {out!r}）")

        # 設定讀不到或格式不符 → exit 2，不寫出臨時設定
        broken = tree("broken", providers_text="- not a mapping\n")
        missing = tree("missing"); (missing / "config/providers.yaml").unlink()
        no_pf = tree("no-pf"); (no_pf / PROMPTFOO_CONFIG).unlink()
        for label, root in (("providers.yaml 格式不符", broken), ("providers.yaml 缺席", missing), ("promptfoo 設定缺席", no_pf)):
            stale.unlink(missing_ok=True)
            rc, out, text = run(root, "lab", both)
            if rc != 2 or out or text is not None:
                fails.append(f"{label} → exit 2、沒有 stdout、不寫出設定（得到 {rc}、{out!r}）")

        # 參數：--target-kind 只收 lab／external
        try:
            with contextlib.redirect_stderr(io.StringIO()):
                main(["--target-kind", "staging", "--out", str(stale)], environ=both, root=real)
            fails.append("--target-kind staging → argparse exit 2")
        except SystemExit as e:
            if e.code != 2:
                fails.append(f"--target-kind staging → exit 2（得到 {e.code}）")
    return fails


if __name__ == "__main__":
    if sys.argv[1:] == ["selftest"]:
        _fails = selftest()
        for _f in _fails:
            print(f"FAIL {_f}")
        print("selftest " + ("通過" if not _fails else f"失敗 {len(_fails)} 項"))
        sys.exit(1 if _fails else 0)
    sys.exit(main())
