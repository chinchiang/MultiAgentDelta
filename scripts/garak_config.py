#!/usr/bin/env python3
"""G6 garak 設定：把 config/garak/vibesec.probes.yaml 的佔位 uri 換成實際受測目標（不修改 repo 內設定檔）。

staging-blackbox.yml 以前用 `sed "s#http://localhost:8000/chat#${VIBESEC_TARGET_URL}/chat#"`：
  - URL 含 `#` 會截斷 sed 的替換字串、含 `&` 會被換成整段比對文字 → 產生錯誤的目標；
  - 設定檔的佔位字串若被改掉，sed 不報錯，garak 會照原設定去打 localhost:8000（靜默 fail-open）。
這裡改為：佔位字串（含引號）必須恰好出現一次，以字串替換（不經正則），新值以 JSON 字串寫入
（JSON 字串也是合法的 YAML 雙引號純量，任何字元都正確跳脫）；目標必須是 http(s) URL。不符 → exit 2，不產生設定。

  python3 scripts/garak_config.py --template config/garak/vibesec.probes.yaml --target "$VIBESEC_TARGET_URL" --out garak.yaml
  python3 scripts/garak_config.py selftest

授權檢查（config/targets.yaml）不在這裡：呼叫端只在 target_guard 通過後才執行 garak（AGENTS.md 規則 8）。
"""
from __future__ import annotations
import argparse, json, pathlib, sys
from urllib.parse import urlsplit

PLACEHOLDER = '"http://localhost:8000/chat"'


def render(template: str, target: str) -> str:
    """回傳把佔位 uri 換成 <target>/chat 的設定內容。佔位字串不是恰好一次、或 target 不是 http(s) URL → ValueError。"""
    n = template.count(PLACEHOLDER)
    if n != 1:
        raise ValueError(f"設定中的佔位 uri {PLACEHOLDER} 應恰好出現一次（實際 {n} 次）：不產生設定，以免 garak 打錯目標")
    parts = urlsplit(target or "")
    if parts.scheme not in ("http", "https") or not parts.netloc or any(c in target for c in "\r\n"):
        raise ValueError("受測目標不是 http(s) URL：不產生設定")
    return template.replace(PLACEHOLDER, json.dumps(target.rstrip("/") + "/chat", ensure_ascii=False))


def selftest() -> list[str]:
    import yaml
    fails: list[str] = []
    tpl = (pathlib.Path(__file__).resolve().parent.parent / "config/garak/vibesec.probes.yaml").read_text(encoding="utf-8")

    def uris(text):   # 設定中所有 uri 值（遞迴）
        out = []
        def walk(o):
            if isinstance(o, dict):
                for k, v in o.items():
                    (out.append(v) if k == "uri" else walk(v))
            elif isinstance(o, list):
                for v in o: walk(v)
        walk(yaml.safe_load(text)); return out

    for target, want in [
        ("https://staging.example.com", "https://staging.example.com/chat"),
        ("https://staging.example.com/", "https://staging.example.com/chat"),
        ("https://staging.example.com/app?a=1&b=2", "https://staging.example.com/app?a=1&b=2/chat"),   # & 不得被展開
        ("https://staging.example.com/#frag", "https://staging.example.com/#frag/chat"),             # # 不得截斷
        ('https://staging.example.com/a"b\\c', 'https://staging.example.com/a"b\\c/chat'),            # 引號與反斜線正確跳脫
        ("http://127.0.0.1:8000", "http://127.0.0.1:8000/chat"),
    ]:
        try:
            out = render(tpl, target)
        except ValueError as e:
            fails.append(f"render({target!r}) 不應失敗：{e}"); continue
        if uris(out) != [want]:
            fails.append(f"render({target!r}) 的 uri 應為 {want!r}（得到 {uris(out)}）")
        if out.replace(json.dumps(want, ensure_ascii=False), PLACEHOLDER) != tpl:
            fails.append(f"render({target!r}) 只能改動佔位 uri，其餘設定不變")
    for target in ("", "ftp://x", "staging.example.com", "https://", "https://x\nuri: http://evil"):
        try:
            render(tpl, target); fails.append(f"render({target!r}) 應拒絕不是 http(s) 的目標")
        except ValueError:
            pass
    for label, t in [("佔位字串被改掉", tpl.replace(PLACEHOLDER, '"http://localhost:9000/chat"')),
                     ("佔位字串出現兩次", tpl + f"\n# {PLACEHOLDER}\n")]:
        try:
            render(t, "https://staging.example.com"); fails.append(f"{label} → 應拒絕產生設定（以前 sed 會靜默不替換）")
        except ValueError:
            pass
    return fails


def main(argv: list[str]) -> int:
    if argv[1:2] == ["selftest"]:
        fails = selftest()
        for f in fails: print(f"FAIL {f}")
        print("selftest 通過" if not fails else f"selftest 失敗 {len(fails)} 項")
        return 1 if fails else 0
    ap = argparse.ArgumentParser(description="以實際受測目標產生 garak 設定")
    ap.add_argument("--template", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args(argv[1:])
    try:
        out = render(pathlib.Path(a.template).read_text(encoding="utf-8"), a.target)
    except (OSError, ValueError) as e:
        print(f"garak 設定無法產生：{e}", file=sys.stderr)
        return 2
    pathlib.Path(a.out).write_text(out, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
