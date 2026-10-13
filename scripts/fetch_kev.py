#!/usr/bin/env python3
"""VibeSec G1：取得 CISA KEV feed（known_exploited_vulnerabilities.json）。

來源依序嘗試（固定常數，不接受外部輸入的 URL）：
  1. CISA 官網 feed
  2. CISA 維護的官方 GitHub 鏡像（cisagov/kev-data）
兩者皆失敗時，若既有快取（--out 指向的檔案）仍是結構完整的 feed，沿用並標記 source=cache；
連快取都沒有 → KEV 未知（incomplete ≠ pass，CLAUDE.md #2）：不寫出 feed，下游 g1_kev.py 會記 incomplete、
nightly 富化的 kev 欄位記 null（未知），絕不記 false。

每次執行都寫出來源紀錄（--meta），分欄記錄使用的來源、feed 的 dateReleased、取得時間與失敗原因，
讓「下載失敗、改用鏡像或舊快取」從報告看得出來。

用法：
  python3 scripts/fetch_kev.py --out .cache/kev.json --meta reports/kev-source.json
  python3 scripts/fetch_kev.py selftest
退出碼：0 取得新 feed；3 下載失敗、沿用快取（feed 可用但可能過舊）；2 incomplete（沒有可用的 feed）。
"""
from __future__ import annotations
import argparse, datetime, json, pathlib, sys
from typing import Callable

SOURCES = (
    ("cisa", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),
    ("cisagov-kev-data-mirror", "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"),
)
MAX_BYTES = 64 * 1024 * 1024   # feed 目前約 1–2 MB；上限防止異常回應塞爆磁碟
# 快取年齡上限：CISA 每週更新 KEV 數次；快取的 dateReleased 超過此天數就不採用（記 incomplete）。
# 以前任何年齡的快取都接受，而快取可能來自很久以前的 Actions cache，甚至是 PR 強制提交的 .cache/kev.json（第二輪審查 M11）
MAX_CACHE_AGE_DAYS = 7


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()


def http_fetch(url: str) -> bytes:
    import urllib.request
    req = urllib.request.Request(url, headers={"User-Agent": "vibesec-kev"})
    # 固定的 https 常數 URL（SOURCES），不經 file:// 等 scheme
    with urllib.request.build_opener(urllib.request.HTTPSHandler).open(req, timeout=60) as r:  # nosemgrep
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("回應超過大小上限")
    return data


def validate_feed(raw: bytes) -> dict:
    """與 g1_kev.load_kev 相同的結構要求，另要求 dateReleased（來源紀錄要寫）。不合格 → ValueError。"""
    try:
        data = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f"不是合法 JSON：{type(e).__name__}") from e
    if not isinstance(data, dict):
        raise ValueError("feed 頂層不是物件")
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list) or not vulns:
        raise ValueError("feed 沒有 vulnerabilities 清單")
    if not any(isinstance(v, dict) and v.get("cveID") for v in vulns):
        raise ValueError("vulnerabilities 沒有任何 cveID")
    if not data.get("dateReleased"):
        raise ValueError("feed 缺 dateReleased")
    return data


def _age_days(released: str | None, now: datetime.datetime | None = None) -> float | None:
    try:
        t = datetime.datetime.fromisoformat(str(released).replace("Z", "+00:00"))
        if t.tzinfo is None:
            t = t.replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None
    return ((now or datetime.datetime.now(datetime.timezone.utc)) - t).total_seconds() / 86400


def fetch(out: pathlib.Path, fetcher: Callable[[str], bytes] = http_fetch, max_age_days: float = MAX_CACHE_AGE_DAYS,
          now: datetime.datetime | None = None) -> dict:
    """依序嘗試 SOURCES，成功即原子寫入 out。回傳來源紀錄（status: fetched／cached／incomplete）。"""
    errors: list[str] = []
    for name, url in SOURCES:
        try:
            raw = fetcher(url)
            data = validate_feed(raw)
        except Exception as e:   # 網路、HTTP、結構錯誤一律換下一個來源，原因留在紀錄
            errors.append(f"{name}: {type(e).__name__}: {str(e)[:160]}")
            continue
        out.parent.mkdir(parents=True, exist_ok=True)
        tmp = out.with_name(out.name + ".download")
        tmp.write_bytes(raw); tmp.replace(out)
        return {"status": "fetched", "status_reason": None, "source": name, "source_url": url,
                "date_released": data.get("dateReleased"), "catalog_size": len(data["vulnerabilities"]),
                "fetched_at": _now(), "errors": errors}
    # 兩個來源都失敗：既有快取若結構完整則沿用（標記 cached，dateReleased 看得出新舊）
    if out.is_file():
        try:
            data = validate_feed(out.read_bytes())
            age = _age_days(data.get("dateReleased"), now)
            if age is None or age > max_age_days:
                raise ValueError(f"快取過舊或發布時間無法解析（dateReleased {data.get('dateReleased')}，上限 {max_age_days:g} 天）")
            return {"status": "cached", "status_reason": "所有來源下載失敗，沿用快取",
                    "source": "cache", "source_url": None, "date_released": data.get("dateReleased"),
                    "catalog_size": len(data["vulnerabilities"]), "fetched_at": None, "errors": errors}
        except (OSError, ValueError) as e:
            errors.append(f"cache: {type(e).__name__}: {str(e)[:160]}")
            out.unlink(missing_ok=True)   # 壞快取不留給下游，避免被誤讀
    return {"status": "incomplete", "status_reason": "KEV feed 無法取得（官網、鏡像、快取皆不可用）",
            "source": None, "source_url": None, "date_released": None, "catalog_size": None,
            "fetched_at": None, "errors": errors}


def selftest() -> list[str]:
    import tempfile
    fails: list[str] = []
    good = json.dumps({"dateReleased": "2026-10-10T12:00:00Z",
                       "vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"}]}).encode()
    old = json.dumps({"dateReleased": "2026-01-01T00:00:00Z",
                      "vulnerabilities": [{"cveID": "CVE-2021-44228", "dateAdded": "2021-12-10"}]}).encode()

    def fake(responses: dict[str, object]):
        calls: list[str] = []
        def f(url: str) -> bytes:
            calls.append(url)
            r = responses.get(url, OSError("network down"))
            if isinstance(r, Exception):
                raise r
            return r
        f.calls = calls
        return f

    cisa, mirror = SOURCES[0][1], SOURCES[1][1]
    with tempfile.TemporaryDirectory() as d:
        out = pathlib.Path(d, "c", "kev.json")
        # 1. 官網成功 → 不打鏡像
        f = fake({cisa: good})
        m = fetch(out, f)
        if m["status"] != "fetched" or m["source"] != "cisa" or m["date_released"] != "2026-10-10T12:00:00Z" \
                or f.calls != [cisa] or not out.is_file():
            fails.append(f"官網成功應直接採用：{m} {f.calls}")
        # 2. 官網失敗 → 鏡像
        out.unlink()
        m = fetch(out, fake({mirror: good}))
        if m["status"] != "fetched" or m["source"] != "cisagov-kev-data-mirror" or len(m["errors"]) != 1:
            fails.append(f"官網失敗應改用鏡像並記錄官網錯誤：{m}")
        # 3. 官網回應結構不符（例如維護頁 HTML、空清單、缺 dateReleased）→ 不採用，改用鏡像
        for bad in (b"<html>maintenance</html>", json.dumps({"vulnerabilities": []}).encode(),
                    json.dumps({"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}).encode(), b"[]"):
            out.unlink(missing_ok=True)
            m = fetch(out, fake({cisa: bad, mirror: good}))
            if m["source"] != "cisagov-kev-data-mirror":
                fails.append(f"結構不符的 feed 不得採用：{bad[:40]!r} → {m}")
        # 4. 兩者皆失敗、有年齡上限內的快取 → cached，帶 dateReleased（看得出新舊）
        _now_fixed = datetime.datetime(2026, 1, 3, tzinfo=datetime.timezone.utc)
        out.write_bytes(old)
        m = fetch(out, fake({}), now=_now_fixed)
        if m["status"] != "cached" or m["date_released"] != "2026-01-01T00:00:00Z" or len(m["errors"]) != 2 \
                or out.read_bytes() != old:
            fails.append(f"兩來源皆失敗應沿用快取並標記：{m}")
        # 4b. 快取超過年齡上限 → incomplete（不採用舊資料判 KEV pass），並刪除
        out.write_bytes(old)
        m = fetch(out, fake({}), now=datetime.datetime(2026, 3, 1, tzinfo=datetime.timezone.utc))
        if m["status"] != "incomplete" or out.exists() or not any("過舊" in e for e in m["errors"]):
            fails.append(f"超過年齡上限的快取應為 incomplete 並刪除：{m}")
        # 5. 兩者皆失敗、快取壞掉 → incomplete，且刪除壞快取
        out.write_bytes(b"{not json")
        m = fetch(out, fake({}))
        if m["status"] != "incomplete" or out.exists() or m["date_released"] is not None:
            fails.append(f"壞快取應視為無 feed（incomplete）並刪除：{m}")
        # 6. 兩者皆失敗、無快取 → incomplete，不寫出任何 feed
        m = fetch(out, fake({cisa: ValueError("HTTP 503"), mirror: b"oops"}))
        if m["status"] != "incomplete" or out.exists() or not m["status_reason"] or len(m["errors"]) != 2:
            fails.append(f"無可用 feed 應為 incomplete（不是 pass）：{m}")
        # 7. 鏡像下載失敗時不得覆蓋既有的好快取為半成品
        out.write_bytes(old)
        fetch(out, fake({cisa: b"{", mirror: b"{"}), now=_now_fixed)
        if out.read_bytes() != old or out.with_name(out.name + ".download").exists():
            fails.append("下載失敗不得覆蓋快取或留下暫存檔")
        # 8. 下游 g1_kev.load_kev 能讀取 fetch 寫出的 feed。load_kev 以真實時鐘檢查 feed 年齡，
        #    所以這裡的 dateReleased 以現在往回推（寫死日期的 good 過幾天就會被判過期）
        released_now = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).replace(microsecond=0).isoformat()
        fetch(out, fake({cisa: json.dumps({**json.loads(good), "dateReleased": released_now}).encode()}))
        try:
            sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
            from g1_kev import load_kev
            kev, released = load_kev(out)
            if kev != {"CVE-2021-44228": "2021-12-10"} or released != released_now:
                fails.append(f"g1_kev.load_kev 讀回結果不符：{kev} {released}")
        except Exception as e:
            fails.append(f"g1_kev.load_kev 無法讀取 fetch 結果：{e}")
    return fails


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if argv[:1] == ["selftest"]:
        fails = selftest()
        print("\n".join(f"FAIL {x}" for x in fails) or "fetch_kev selftest ok")
        return 1 if fails else 0
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--out", required=True, help="feed 輸出路徑（也是快取：下載失敗時沿用）")
    ap.add_argument("--meta", help="來源紀錄 JSON 輸出路徑")
    a = ap.parse_args(argv)
    meta = fetch(pathlib.Path(a.out))
    if a.meta:
        mp = pathlib.Path(a.meta); mp.parent.mkdir(parents=True, exist_ok=True)
        mp.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    for e in meta["errors"]:
        print(f"KEV 來源失敗：{e}")
    if meta["status"] == "fetched":
        print(f"KEV feed：{meta['source']}（dateReleased {meta['date_released']}，{meta['catalog_size']} 筆）")
        return 0
    if meta["status"] == "cached":
        print(f"::warning::KEV feed 下載失敗，沿用快取（dateReleased {meta['date_released']}）")
        return 3
    print(f"::error::{meta['status_reason']}（incomplete ≠ pass）")
    return 2


if __name__ == "__main__":
    sys.exit(main())
