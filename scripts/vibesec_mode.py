#!/usr/bin/env python3
"""VibeSec 執行模式（mode）的解析：合法值清單與「從 vibesec.yaml 讀出最上層 mode」的唯一一份寫法（#199、#200）。

只用標準函式庫：受信任設定 action 在沒有 PyYAML 的 semgrep 容器裡也要能用（vibesec_policy 缺 PyYAML 時 import 就
exit 2，所以 action 不能依賴它）。閘門不直接呼叫本 module，而是透過 vibesec_policy.load_policy 取得 mode
（GLOSSARY.md「執行模式」）；「只能把 shadow 升為 enforce」的規則在 vibesec_policy（Policy 的 mode_override）。

  MODES                              合法值（全 repo 唯一的一份）
  read_mode(text) -> (mode, problem) 讀最上層的 `mode:`：只認行首沒有縮排的鍵、去掉尾端註解與成對引號、大小寫敏感。
                                     合法 → (mode, None)；缺席或不合法 → (None, 原因)，不合法時附上讀到的值。沒有預設值。
  apply_override(mode, override) -> (mode, note)
                                     覆寫只能把 shadow 升為 enforce（GLOSSARY.md「執行模式」）：None／空字串 → 不覆寫；
                                     覆寫 enforce → enforce；設定 enforce 遇到覆寫 shadow → 維持 enforce 並附註；不合法 → ValueError
                                     （打錯的覆寫值不得默默以設定值執行）。Policy 與阻擋判定共用這一份。

  python3 scripts/vibesec_mode.py selftest
"""
from __future__ import annotations
import re, sys

MODES = ("shadow", "enforce")


_TOP_MODE = re.compile(r"^mode[ \t]*:[ \t]*(.*)$", re.M)


def read_mode(text: str) -> tuple[str | None, str | None]:
    """規則沿用受信任設定 action 原本內嵌的 regex（#200 把它搬到這裡）：mode 永遠是最上層的純量，不需要 YAML。
    帶引號時要去掉（以前 `mode: "enforce"` 用 awk 讀會得到含引號的值，enforce 就不擋）。"""
    m = _TOP_MODE.search(text)
    if not m:
        return None, f"vibesec.yaml 缺 mode；須為 {'／'.join(MODES)}"
    v = re.sub(r"[ \t]+#.*$", "", m.group(1)).strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1].strip()
    if v not in MODES:
        return None, f"vibesec.yaml 的 mode 不合法：{v!r}；須為 {'／'.join(MODES)}"
    return v, None


def apply_override(mode: str, override) -> tuple[str, str | None]:
    if override in (None, ""):
        return mode, None
    if override not in MODES:
        raise ValueError(f"mode 覆寫值不合法：{override!r}；須為 {'／'.join(MODES)}")
    if override == "shadow" and mode == "enforce":
        return mode, "mode 覆寫值 shadow 不能把受信任設定的 enforce 降級，已忽略"
    return override, None


# ------------------------------------------------------------------ selftest
def selftest() -> list[str]:
    import pathlib, subprocess
    fails: list[str] = []
    MISSING = "vibesec.yaml 缺 mode；須為 shadow／enforce"
    bad = lambda v: f"vibesec.yaml 的 mode 不合法：{v!r}；須為 shadow／enforce"
    cases = [
        ("最上層 shadow", "version: 1\nmode: shadow\nrisk_tier: L3\n", ("shadow", None)),
        ("最上層 enforce", "mode: enforce\n", ("enforce", None)),
        ("尾端註解", "mode: enforce   # 試點後改 enforce\n", ("enforce", None)),
        ("雙引號", 'mode: "enforce"\n', ("enforce", None)),
        ("單引號加註解", "mode: 'shadow' # x\n", ("shadow", None)),
        ("冒號前有空白", "mode : enforce\n", ("enforce", None)),
        ("CRLF", "mode: enforce\r\nrisk_tier: L2\r\n", ("enforce", None)),
        ("有縮排的同名鍵不認", "gates:\n  g1:\n    mode: enforce\n", (None, MISSING)),
        ("其他鍵含 mode 字樣", "modes: enforce\nmode_x: shadow\n# mode: enforce\n", (None, MISSING)),
        ("缺席", "version: 1\nrisk_tier: L3\n", (None, MISSING)),
        ("空檔", "", (None, MISSING)),
        ("大小寫錯誤", "mode: Enforce\n", (None, bad("Enforce"))),
        ("不合法", "mode: x\n", (None, bad("x"))),
        ("空字串", 'mode: ""\n', (None, bad(""))),
        ("空值", "mode:\n", (None, bad(""))),
        ("引號不成對", "mode: \"enforce\n", (None, bad('"enforce'))),
        ("註解前沒有空白", "mode: enforce#x\n", (None, bad("enforce#x"))),
        ("只取第一個最上層 mode", "mode: shadow\nmode: enforce\n", ("shadow", None)),
    ]
    for label, text, want in cases:
        try:
            got = read_mode(text)
        except Exception as e:
            got = f"例外 {type(e).__name__}：{e}"
        if got != want:
            fails.append(f"read_mode：{label} → 應為 {want}（得到 {got}）")
    # 只用標準函式庫：PyYAML 不可 import、以 -I 執行（不把腳本目錄放進 sys.path）時仍可使用
    here = pathlib.Path(__file__).resolve().parent
    code = ("import sys; sys.modules['yaml'] = None; sys.path.insert(0, %r)\n"
            "import vibesec_mode as m\n"
            "print(m.read_mode('mode: enforce\\n')[0], 'yaml' in sys.modules and sys.modules['yaml'] is not None)") % str(here)
    p = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60)
    if p.returncode != 0 or p.stdout.split() != ["enforce", "False"]:
        fails.append(f"PyYAML 不可 import 時仍可使用、不 import PyYAML（得到 exit {p.returncode}：{p.stdout.strip()} {p.stderr.strip()[-200:]}）")
    for mode, override, want in [("shadow", None, ("shadow", False)), ("shadow", "", ("shadow", False)),
                                 ("shadow", "enforce", ("enforce", False)), ("enforce", "enforce", ("enforce", False)),
                                 ("shadow", "shadow", ("shadow", False)), ("enforce", "shadow", ("enforce", True)),
                                 ("enforce", None, ("enforce", False))]:
        m, note = apply_override(mode, override)
        if (m, bool(note)) != want:
            fails.append(f"apply_override：設定 {mode}、覆寫 {override!r} → {want}（得到 {(m, note)}）")
    for bad_override in ("x", "Enforce", 3):
        try:
            apply_override("shadow", bad_override); fails.append(f"apply_override：覆寫 {bad_override!r} 應拋 ValueError")
        except ValueError as e:
            if repr(bad_override) not in str(e):
                fails.append(f"apply_override：錯誤訊息應附上讀到的值（得到 {e}）")
    if MODES != ("shadow", "enforce"):
        fails.append(f"MODES 應為 shadow、enforce（得到 {MODES}）")
    return fails


if __name__ == "__main__":
    if sys.argv[1:] == ["selftest"]:
        _fails = selftest()
        for _f in _fails:
            print(f"FAIL {_f}")
        print("selftest " + ("通過" if not _fails else f"失敗 {len(_fails)} 項"))
        sys.exit(1 if _fails else 0)
    print(__doc__)
    sys.exit(2)
