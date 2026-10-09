"""
⚠️⚠️⚠️ 刻意有漏洞的測試靶場（VibeSec vulnapp）⚠️⚠️⚠️
僅供 VibeSec G5（DAST/API）與 G6（LLM/Agent 紅隊）閘門在**隔離/本機/staging**環境演練。
嚴禁部署到任何正式或公開可達環境。每個端點都內建已知弱點，詳見 README.md。

啟動：uv run --project examples/vulnapp uvicorn app.main:app --port 8000
seeded 帳號：alice/alice-pass（id 1）、bob/bob-pass（id 2）
"""
import base64
import hashlib
import hmac
import html
import json
import os
import pathlib
import traceback
import urllib.request

import jwt  # PyJWT
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse

# RS256 簽章金鑰：每次啟動在記憶體產生，不落地。公鑰經 /.well-known/jwks.json 公開（正常做法）；
# 漏洞版的問題在驗章端：接受 HS256 並把公鑰 PEM 當 HMAC 金鑰（G5 jwt_alg_confusion）。
_PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUBLIC_KEY = _PRIVATE_KEY.public_key()
PUBLIC_PEM = PUBLIC_KEY.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
JWT_ALG = "RS256"
JWT_KID = "vibesec-vulnapp-1"

# VIBESEC_VULNAPP_MODE=patched → 已修補模式：同一份程式碼切換到安全行為，用來證明閘門在修補後不誤報。
# 預設（未設定）維持刻意有漏洞，CI 的 staging 演練行為不變。
PATCHED = os.environ.get("VIBESEC_VULNAPP_MODE", "").lower() == "patched"

_DATA = json.loads((pathlib.Path(__file__).parent.parent / "seed_users.json").read_text(encoding="utf-8"))
USERS_BY_NAME = {u["username"]: u for u in _DATA["users"]}
USERS_BY_ID = {u["id"]: u for u in _DATA["users"]}

app = FastAPI(
    title="VibeSec VulnApp (DELIBERATELY VULNERABLE — do not deploy)",
    description="刻意有漏洞的測試靶場。僅供 VibeSec G5/G6 閘門演練。",
    version="0.1.0",
    # 開發便利設定外溢：Swagger /docs、/redoc、/openapi.json 全部對外（G5 swagger_exposed）
)


# ---- CORS 錯誤設定：反射任意 Origin 並允許 credentials（G5 cors_reflect_origin）----
# 修補版只允許固定白名單（靶場沒有前端，清單只放示意網域），不反射、也不對陌生 Origin 帶 credentials。
CORS_ALLOWED_ORIGINS = {"https://app.vulnapp.example"}


@app.middleware("http")
async def cors_middleware(request: Request, call_next):
    response = await call_next(request)
    origin = request.headers.get("origin")
    if origin and (not PATCHED or origin in CORS_ALLOWED_ORIGINS):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Vary"] = "Origin"
    return response

# ---- Debug 模式錯誤回應：未處理例外回吐 stack trace（G5 debug_stacktrace）----
@app.exception_handler(Exception)
async def debug_exception_handler(request: Request, exc: Exception):
    if PATCHED:
        # 修補：只回通用訊息，不外洩 stack trace
        return JSONResponse(status_code=500, content={"error": "internal error"})
    tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    return JSONResponse(status_code=500, content={"error": str(exc), "traceback": tb})


# ---- 認證弱點：alg 取自 header；接受 alg:none 未簽章 token，以及以公鑰當 HMAC 金鑰的 HS256（G5 jwt_alg_none / jwt_alg_confusion）----
def _decode_token(token: str) -> dict:
    if PATCHED:
        # 修補：固定演算法並驗證簽章；alg:none 與演算法混淆一律拒絕
        return jwt.decode(token, PUBLIC_KEY, algorithms=[JWT_ALG])
    # 先嘗試讀 header 的 alg；若為 none 則完全不驗簽（典型漏洞）
    try:
        header_b64 = token.split(".")[0]
        header_b64 += "=" * (-len(header_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))
    except Exception:
        header = {}

    alg = (header.get("alg") or "").lower()
    if alg == "none":
        # 漏洞：接受未簽章 token，直接信任 payload
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(payload_b64))

    if alg == "hs256":
        # 漏洞：演算法取自 header；HS256 時拿「公鑰 PEM」當 HMAC 金鑰驗章 → 任何人都能用公開的公鑰偽造 token。
        # （PyJWT 會拒絕以非對稱金鑰做 HMAC，這裡以 stdlib 重現存在此缺陷的函式庫行為。）
        h, p, sig = token.split(".")
        expect = base64.urlsafe_b64encode(hmac.new(PUBLIC_PEM, f"{h}.{p}".encode(), hashlib.sha256).digest()).rstrip(b"=")
        if not hmac.compare_digest(expect, sig.encode()):
            raise ValueError("bad signature")
        p += "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p))
    return jwt.decode(token, PUBLIC_KEY, algorithms=[JWT_ALG])


def current_user(authorization: str = Header(default="")) -> dict:
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="缺少 Bearer token")
    token = authorization.split(" ", 1)[1].strip()
    try:
        payload = _decode_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="token 無法解析")
    sub = payload.get("sub")
    user = USERS_BY_NAME.get(sub)
    if not user:
        # 即使查無此人也僅回 401；但注意：下方端點根本沒用到這個 user 做 owner 綁定
        raise HTTPException(status_code=401, detail="未知主體")
    return user


@app.get("/")
def root():
    return {
        "app": "VibeSec VulnApp",
        "warning": "DELIBERATELY VULNERABLE — local/staging target only. DO NOT DEPLOY.",
        "docs": "/docs",
    }


@app.post("/login")
def login(body: dict = Body(...)):
    username = body.get("username")
    password = body.get("password")
    user = USERS_BY_NAME.get(username)
    if not user or user["password"] != password:
        # 漏洞：無 rate limiting / 無 captcha（G5 rate_limit、G6 DoW 的相鄰面）
        raise HTTPException(status_code=401, detail="帳號或密碼錯誤")
    token = jwt.encode({"sub": user["username"], "uid": user["id"]}, _PRIVATE_KEY, algorithm=JWT_ALG,
                       headers={"kid": JWT_KID})
    return {"access_token": token, "token_type": "bearer"}


@app.get("/.well-known/jwks.json")
def jwks():
    nums = PUBLIC_KEY.public_numbers()
    b64 = lambda i: base64.urlsafe_b64encode(i.to_bytes((i.bit_length() + 7) // 8, "big")).decode().rstrip("=")
    return {"keys": [{"kty": "RSA", "use": "sig", "alg": JWT_ALG, "kid": JWT_KID, "n": b64(nums.n), "e": b64(nums.e)}]}


@app.get("/me")
def me(user: dict = Depends(current_user)):
    return {"id": user["id"], "username": user["username"]}


@app.get("/users/{user_id}/notes")
def get_notes(user_id: int, user: dict = Depends(current_user)):
    # 漏洞（BOLA / IDOR）：只驗證「有合法 token」，完全未綁定 user_id == 當前主體。
    # bob（id 2）的 token 可讀 alice（id 1）的私密筆記。這是 G5 bola_idor 主要目標。
    if PATCHED and user_id != user["id"]:
        # 修補：資源 owner 必須等於當前主體
        raise HTTPException(status_code=403, detail="無權存取他人資源")
    target = USERS_BY_ID.get(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="查無此使用者")
    return {"id": target["id"], "username": target["username"], "notes": target["notes"]}


# 便於 G5 探針列舉資源 ID：回傳所有 user 的 id（無授權限制，示範用）
@app.get("/users")
def list_users(user: dict = Depends(current_user)):
    return [{"id": u["id"], "username": u["username"]} for u in _DATA["users"]]


@app.get("/admin/users")
def admin_users(authorization: str = Header(default="")):
    # 漏洞（缺 Session 驗證 / 前端防禦假象）：前端只對管理員顯示此頁，後端卻完全沒驗 token →
    # 匿名請求即可取得全部帳號與筆記。G5 session_check 目標（vibesec.g5.missing-session-check）。
    if PATCHED:
        # 修補：與其他受保護端點相同，先驗證 Bearer token（缺少或無效 → 401）
        current_user(authorization)
    return [{"id": u["id"], "username": u["username"], "notes": u["notes"]} for u in _DATA["users"]]


@app.get("/fetch")
def fetch(url: str = Query(...), user: dict = Depends(current_user)):
    # 漏洞（SSRF）：對使用者提供的 URL 直接發出 server-side GET，無 allow-list、無私網封鎖。
    # 可讀 http://169.254.169.254/latest/meta-data/（雲端 metadata）。G5 ssrf_metadata 目標。
    if PATCHED:
        # 修補：allow-list（靶場不需要對外抓取，清單為空）→ 一律明確拒絕，含私網與 metadata 位址
        raise HTTPException(status_code=400, detail="URL 不在允許清單（blocked）")
    req = urllib.request.Request(url, headers={"User-Agent": "vibesec-vulnapp-fetch"})
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 刻意漏洞
        body = resp.read(65536).decode("utf-8", "replace")
        return {"status": resp.status, "url": url, "body": body}


@app.post("/chat")
def chat(body: dict = Body(...)):
    # G6 目標：無認證、無 rate limiting；行為由 deterministic llm_stub 決定。
    from app.llm_stub import generate_reply

    message = body.get("message", "")
    context = body.get("context", "")
    if PATCHED:
        # 修補：長度上限（Denial of Wallet）、不洩漏 system prompt、輸出 HTML 編碼
        if len(message) > 4000:
            raise HTTPException(status_code=413, detail="訊息過長")
        return {"reply": html.escape(generate_reply(message, patched=True)), "tool_events": [],
                "usage": {"input_tokens": len(message), "cost_usd": 0, "source": "deterministic_fixture"}}
    reply = generate_reply(message + ("\n" + context if context else ""))
    # 合成工具事件與用量；不執行刪除、不呼叫模型、不產生真實費用。
    events = [{"name": "delete_customers", "executed": True, "human_approved": False}] if "清掉" in message else []
    return {"reply": reply, "tool_events": events,
            "usage": {"input_tokens": len(message), "cost_usd": len(message) * 0.00001, "source": "deterministic_fixture"}}


# 最小 GraphQL stub，introspection 開啟（G5 graphql_introspection 目標）
@app.post("/graphql")
def graphql(body: dict = Body(...)):
    query = (body or {}).get("query", "")
    if "__schema" in query:
        return {
            "data": {
                "__schema": {
                    "types": [
                        {"name": "Query"},
                        {"name": "User"},
                        {"name": "Note"},
                    ]
                }
            }
        }
    return {"data": None, "errors": [{"message": "only introspection stub is implemented"}]}
