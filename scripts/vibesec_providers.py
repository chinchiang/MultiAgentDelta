#!/usr/bin/env python3
"""VibeSec provider 的送出判斷（AGENTS.md 規則 7「不得外傳」）：某份內容能不能送給某個 provider，只有這一份判斷。

  load_config(root)                         讀 config/providers.yaml（整份：providers 與 rotation）
  may_send(config, name, data_class)         → (True, None) 或 (False, 原因)
  setting(p, name)                           provider 設定裡某個鍵的字串值（例如 api_key_env：環境變數的名稱）

依序檢查三項，任一不符就不能送（原因寫明是哪一項）：
  1. provider 存在且 enabled: true；
  2. allowed_data_classes 包含 data_class；
  3. confidential／pii 只能送 rotation.sensitive_data_providers 列出的地端／內網 provider。
     這是 allowed_data_classes 之外的第二道硬防線：就算有人誤把某雲端 provider 的 allowed_data_classes 開到 pii，
     這裡仍會擋下（與 prepare_comparison.py 的判定對齊，不只靠逐一維護每個 provider 的清單）。
本模組不替內容判定分級、也不降級；分級由呼叫端決定。data_class 為 None（未分類）一律不能送。
使用者：scripts/review_provider.py（多模型審查）、scripts/g6_redteam_provider.py（G6 redteam 評分，#356）。

  python3 scripts/vibesec_providers.py selftest
"""
from __future__ import annotations
import pathlib, sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
SENSITIVE_CLASSES = ("confidential", "pii")


def load_config(root: pathlib.Path = ROOT) -> dict:
    """config/providers.yaml 的內容；檔案讀不到或不是 YAML 物件 → 拋例外（呼叫端決定 fail-closed 的方式）。"""
    data = yaml.safe_load((root / "config/providers.yaml").read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("providers"), dict):
        raise ValueError("config/providers.yaml 必須是含 providers 物件的 YAML")
    return data


def setting(p: dict, name: str) -> str:
    """provider 設定裡某個鍵的字串值（沒有則空字串）。
    要寫出「哪個環境變數沒設定」時用它：直接用 p.get("api_key_env") 組字串，CodeQL 依字面上的 api_key
    把它判成 password（#230 PR C；#356 在 g6_redteam_provider 再次遇到）。值只是環境變數的名稱，不是金鑰；
    由本函式取出、存進中性名稱的變數，config/providers.yaml 的設定鍵不變。"""
    return str(p.get(name) or "")


def may_send(config: dict, name: str, data_class: str | None) -> tuple[bool, str | None]:
    """data_class 的內容能不能送給 provider name；不能 → (False, 原因)。原因文字沿用 review_provider 的 note（行為不變）。"""
    p = (config.get("providers") or {}).get(name)
    if not isinstance(p, dict):
        return False, f"providers.yaml 沒有 provider {name!r}（未送出任何內容）"
    if data_class is None:
        return False, f"內容未分類：依 AGENTS.md 規則 7 不送 {name}（未送出任何內容）"
    if not p.get("enabled", False):
        return False, "provider 未啟用（enabled: false）"
    allowed = p.get("allowed_data_classes") or []
    if data_class not in allowed:
        return False, f"no provider allowed for data_class={data_class}：{name} 只收 {allowed}（未送出任何內容）"
    sensitive = set((config.get("rotation") or {}).get("sensitive_data_providers") or [])
    if data_class in SENSITIVE_CLASSES and name not in sensitive:
        return False, (f"data_class={data_class} 只能送 rotation.sensitive_data_providers；{name} 不在清單"
                       "（未送出任何內容，AGENTS.md 規則 7）")
    return True, None


def selftest() -> list[str]:
    fails: list[str] = []
    cloud = {"enabled": True, "allowed_data_classes": ["public", "internal"]}
    cfg = {"providers": {"cloud": cloud, "off": {**cloud, "enabled": False}, "noenable": {"allowed_data_classes": ["internal"]},
                         "pub": {**cloud, "allowed_data_classes": ["public"]},
                         "leaky": {**cloud, "allowed_data_classes": ["public", "internal", "confidential", "pii"]},
                         "onprem": {**cloud, "allowed_data_classes": ["public", "internal", "confidential", "pii"]}},
           "rotation": {"sensitive_data_providers": ["onprem"]}}
    for name, dc, want, needle in [
        ("cloud", "internal", True, None),
        ("cloud", "public", True, None),
        ("cloud", None, False, "未分類"),
        ("off", "internal", False, "enabled: false"),
        ("noenable", "internal", False, "enabled: false"),   # 沒寫 enabled → 視為未啟用
        ("pub", "internal", False, "只收"),
        ("cloud", "confidential", False, "只收"),
        ("leaky", "pii", False, "sensitive_data_providers"),   # allowed_data_classes 誤開到 pii 仍要擋下
        ("onprem", "pii", True, None),
        ("missing", "internal", False, "沒有 provider"),
    ]:
        ok, why = may_send(cfg, name, dc)
        if ok is not want or (needle is None) != (why is None) or (needle and needle not in (why or "")):
            fails.append(f"may_send({name}, {dc}) → {want}（原因含 {needle!r}）；得到 {ok}、{why!r}")
    try:
        real = load_config(ROOT)
        if not may_send(real, "anthropic-cloud", "internal")[0] or may_send(real, "anthropic-cloud", "pii")[0]:
            fails.append("本 repo 的 providers.yaml：anthropic-cloud 應收 internal、不收 pii")
    except Exception as e:
        fails.append(f"load_config 讀不到本 repo 的 providers.yaml：{type(e).__name__}: {e}")
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        (pathlib.Path(d) / "config").mkdir()
        for label, text in (("不是物件", "- a\n"), ("沒有 providers", "rotation: {}\n")):
            (pathlib.Path(d) / "config/providers.yaml").write_text(text, encoding="utf-8")
            try:
                load_config(pathlib.Path(d)); fails.append(f"load_config：{label} → 應拋例外")
            except ValueError:
                pass
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
