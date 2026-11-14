#!/usr/bin/env python3
"""套件登錄庫（registry）接縫：向 npm、PyPI 查一個套件，結果是三態值，不丟例外（#264，#260 的 S3）。

介面（Registry）只有兩個方法：
  facts(eco, name, ver) -> Found(Facts) | NotFound | Unavailable(reason)
      Found       查得到：Facts 是 npm 與 PyPI 翻譯成同一個形狀的事實，判定（冷卻期、低下載量、安裝腳本）由呼叫端做
      NotFound    registry 說查無此套件（HTTP 404）：這是正常發現（疑似幻覺／搶註套件），不是失敗
      Unavailable 逾時、5xx、連線失敗、回應格式不符：沒有證據，呼叫端必須記未完成（AGENTS.md 規則 2：不是通過）
  requires(name, ver) -> set[str]   PyPI 該版本宣告的相依名稱（PEP 503 正規化）；查不到回空集合，因為結果只用來把鎖定檔中的
                                     間接相依排除在名稱相似度之外，查不到就照直接相依檢查，不會少查
Facts 的欄位三態：有值；Unknown（這個生態系查得到、這次沒拿到）；None（這個生態系沒有這項資料可查，例如 PyPI 沒有週下載量）。
Unknown 與 None 不能混為一談：前者要讓呼叫端記未完成，後者不是缺漏。

生產轉接器 HttpRegistry 使用 https_only 的傳輸層；測試與評測用 FakeRegistry（腳本化的結果、記錄呼叫）。
名稱規則（valid_name、canon、same_pep440）是各 registry 自己的規則，放在這裡。只用標準函式庫、沒有全域狀態。
"""
from __future__ import annotations
import re, urllib.error, urllib.parse
from dataclasses import dataclass
from typing import Mapping

import https_only
from g1_manifests import pep508

# ---------------------------------------------------------------- 名稱規則

# 套件名稱來自 PR 內的 manifest（不可信）：先依 registry 命名規則驗證，再 percent-encode 組 URL。
# 不合法的名稱不送出查詢，記為 incomplete（incomplete ≠ pass）。
NPM_NAME = re.compile(r"^(?:@[a-z0-9~-][a-z0-9._~-]*/)?[a-z0-9~-][a-z0-9._~-]*$", re.I)
PYPI_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")


def valid_name(eco, pkg):
    if not pkg or len(pkg) > 214:
        return False
    return bool((NPM_NAME if eco == "npm" else PYPI_NAME).match(pkg))


def canon(eco, name):
    """比對用的套件名稱。PyPI 依 PEP 503 正規化：大小寫不分，連續的 -、_、. 視為同一個 -
    （typing_extensions 與 typing-extensions 是同一個專案，不能另外註冊）；npm 只轉小寫（_ 與 - 是不同套件）。"""
    name = str(name).lower()
    return re.sub(r"[-_.]+", "-", name) if eco == "pypi" else name


def same_pep440(a, b):
    """PEP 440 版本是否相等（2.32 == 2.32.0、1.0RC1 == 1.0rc1）。packaging 缺席時只補齊尾端的 .0 並轉小寫。"""
    try:
        from packaging.version import Version, InvalidVersion
        try:
            return Version(str(a)) == Version(str(b))
        except InvalidVersion:
            return str(a) == str(b)
    except ImportError:
        def k(v):
            m = re.fullmatch(r"v?(\d+(?:\.\d+)*)(.*)", str(v).strip().lower())
            if not m:
                return str(v)
            rel = [int(x) for x in m.group(1).split(".")]
            while len(rel) > 1 and rel[-1] == 0:
                rel.pop()
            return (tuple(rel), m.group(2))
        return k(a) == k(b)


# ---------------------------------------------------------------- 結果的型別

@dataclass(frozen=True)
class Unknown:
    why: str = ""        # 沒拿到的原因（錯誤型別名稱等），給呼叫端寫進未完成原因


@dataclass(frozen=True)
class Facts:
    eco: str
    name: str
    version: str | None                              # 解析後的目標版本：鎖定版本，或沒給時 registry 的最新版；都沒有則 None
    published_at: str | Unknown                      # 該版本的發布時間（ISO 字串）；不在發布紀錄或時間不明 → Unknown
    install_scripts: Mapping | Unknown | None        # npm：該版本的 scripts；版本不在發布紀錄 → Unknown；PyPI 沒有這項資料 → None
    weekly_downloads: int | Unknown | None           # npm：上週下載量；查不到或格式不符 → Unknown；PyPI 沒有這項資料 → None


@dataclass(frozen=True)
class Found:
    facts: Facts


@dataclass(frozen=True)
class NotFound:
    pass


@dataclass(frozen=True)
class Unavailable:
    reason: str          # 例如 "HTTP 500"、逾時訊息；呼叫端把它組進「registry 查詢失敗」的未完成原因


# ---------------------------------------------------------------- 生產轉接器

class HttpRegistry:
    """向 npm 與 PyPI 查詢。逾時、重試與退避數值是 G1 現有的（8 秒、重試 2 次、退避 1 秒）。"""

    def __init__(self, *, timeout: float = 8, retries: int = 2, backoff: float = 1.0, transport=None, user_agent: str = "vibesec-g1/0.1"):
        self.timeout, self.retries, self.backoff = timeout, retries, backoff
        self._transport = transport or https_only.UrllibHttpsOnly(user_agent=user_agent)

    def _get(self, url):
        return https_only.get_json(url, timeout=self.timeout, retries=self.retries, backoff=self.backoff, transport=self._transport)

    def facts(self, eco, name, ver):
        if not valid_name(eco, name):
            return Unavailable(f"套件名稱不合法，未查詢 registry：{name!r}")
        if eco not in ("npm", "pypi"):
            return Unavailable(f"不支援的生態系：{eco!r}")
        return (self._npm if eco == "npm" else self._pypi)(name, ver)     # 不丟例外：傳輸失敗與回應格式不符都在裡面轉成 Unavailable

    def _metadata(self, url):
        """(meta, None) 或 (None, 三態結果)。404 是 NotFound；其他 HTTP 錯誤與任何例外是 Unavailable。"""
        try:
            return self._get(url), None
        except urllib.error.HTTPError as e:
            return None, (NotFound() if e.code == 404 else Unavailable(f"HTTP {e.code}"))
        except Exception as e:
            return None, Unavailable(str(e) or type(e).__name__)      # 沒有訊息的例外（TimeoutError()）也要說得出原因

    def _npm(self, name, ver):
        q = urllib.parse.quote(name, safe="@/")
        meta, bad = self._metadata(f"https://registry.npmjs.org/{q}")
        if bad:
            return bad
        try:
            times = meta.get("time", {}) or {}
            versions = meta.get("versions", {}) or {}
            target = ver or (meta.get("dist-tags", {}) or {}).get("latest")
            target = next((v for v in versions if target and v == str(target).lstrip("v")), target)
            published = times.get(target) if target else None
            vmeta = versions.get(target or "")
            scripts = (vmeta.get("scripts", {}) or {}) if isinstance(vmeta, dict) else Unknown("版本不在發布紀錄")
        except Exception as e:
            return Unavailable(f"回應格式不符（{type(e).__name__}）")
        # 週下載：查不到就不知道信譽（存在性已確認，其他資料照給）
        try:
            dl = self._get(f"https://api.npmjs.org/downloads/point/last-week/{q}").get("downloads")
            if not isinstance(dl, int):
                raise ValueError(f"downloads 欄位缺漏或格式不符（{dl!r}）")
        except Exception as e:
            dl = Unknown(type(e).__name__)
        return Found(Facts("npm", name, target, published if isinstance(published, str) and published else Unknown("發布時間不明"), scripts, dl))

    def _pypi(self, name, ver):
        meta, bad = self._metadata(f"https://pypi.org/pypi/{urllib.parse.quote(name, safe='')}/json")
        if bad:
            return bad
        try:
            releases = meta.get("releases", {}) or {}
            target = ver or (meta.get("info", {}) or {}).get("version")
            if target and target not in releases:     # ==2.32 與發布的 2.32.0 是同一版（PEP 440）
                target = next((v for v in releases if same_pep440(v, target)), target)
            rel = releases.get(target or "") or []
            upload = ((rel[0] or {}).get("upload_time_iso_8601") or "") if rel and isinstance(rel[0], dict) else ""
        except Exception as e:
            return Unavailable(f"回應格式不符（{type(e).__name__}）")
        return Found(Facts("pypi", name, target, upload if isinstance(upload, str) and upload else Unknown("版本不在發布紀錄或發布時間不明"), None, None))

    def requires(self, name, ver):
        """該版本在 PyPI 宣告的相依名稱（PEP 503 正規化；含 extra 與環境標記限定的相依）。查不到回空集合。"""
        if not ver or not valid_name("pypi", name):
            return set()
        try:
            info = self._get(f"https://pypi.org/pypi/{urllib.parse.quote(name, safe='')}/"
                             f"{urllib.parse.quote(ver, safe='')}/json").get("info") or {}
            return {canon("pypi", x[0]) for x in map(pep508, info.get("requires_dist") or []) if x}
        except Exception:
            return set()


# ---------------------------------------------------------------- 替身

class FakeRegistry:
    """腳本化的替身（測試與評測用）：facts 是 {(生態系, 名稱, 版本): Found | NotFound | Unavailable}，requires 是 {(名稱, 版本): 名稱集合}。
    沒有腳本的查詢回 Unavailable，不是 Found：不能悄悄變成「查得到、沒有問題」而讓測試或評測誤判為通過。
    calls 依序記錄每次 facts 查詢。"""

    def __init__(self, facts=None, requires=None):
        self._facts = dict(facts or {})
        self._requires = {k: set(v) for k, v in (requires or {}).items()}
        self.calls = []

    def facts(self, eco, name, ver):
        self.calls.append((eco, name, ver))
        r = self._facts.get((eco, name, ver))
        return r if r is not None else Unavailable(f"FakeRegistry 沒有 {eco} {name}@{ver} 的腳本")

    def requires(self, name, ver):
        return set(self._requires.get((name, ver), ()))
