"""
⚠️⚠️⚠️ 刻意有漏洞的測試靶場（VibeSec vulnapp）⚠️⚠️⚠️
僅供 VibeSec G5（DAST/API）與 G6（LLM/Agent 紅隊）閘門在**隔離/本機/staging**環境演練。
嚴禁部署到任何正式或公開可達環境。每個端點都內建已知弱點，詳見 README.md。

啟動：uv run --project examples/vulnapp uvicorn app.main:app --port 8000
seeded 帳號：alice/alice-pass（id 1）、bob/bob-pass（id 2）
"""
import base64
import json
import pathlib
import traceback
import urllib.request

import jwt  # PyJWT
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse

# 刻意寫死的弱 secret（G2/示範用；真實系統絕不可如此）
JWT_SECRET = "vibesec-vulnapp-insecure-secret"
JWT_ALG = "HS256"

_DATA = json.loads((pathlib.Path(__file__).parent.parent / "seed_users.json").read_text(encoding="utf-8"))
USERS_BY_NAME = {u["username"]: u for u in _DATA["users"]}
USERS_BY_ID = {u["id"]: u for u in _DATA["users"]}

app = FastAPI(
    title="VibeSec VulnApp (DELIBERATELY VULNERABLE — do not deploy)",
    description="刻意有漏洞的測試靶場。僅供 VibeSec G5/G6 閘門演練。",
    version="0.1.0",
    # 開發便利設定外溢：Swagger /docs、/redoc、/openapi.json 全部對外（G5 swagger_exposed）
)


# ---- Debug 模式錯誤回應：未處理例外回吐 stack trace（G5 debug_stacktrace）----
@app.exception_handler(Exception)
async def debug_exception_handler(request: Request, exc: Exception):
    tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    return JSONResponse(status_code=500, content={"error": str(exc), "traceback": tb})


# ---- 認證弱點：接受真實 HS256，也接受 alg:none 未簽章 token（G5 jwt_alg_none / jwt_alg_confusion）----
def _decode_token(token: str) -> dict:
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

    # 漏洞：verify_signature=False，等同不驗簽（RS256/HS256 混淆也能過）
    return jwt.decode(token, options={"verify_signature": False, "verify_exp": False})


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
    token = jwt.encode({"sub": user["username"], "uid": user["id"]}, JWT_SECRET, algorithm=JWT_ALG)
    return {"access_token": token, "token_type": "bearer"}


@app.get("/me")
def me(user: dict = Depends(current_user)):
    return {"id": user["id"], "username": user["username"]}


@app.get("/users/{user_id}/notes")
def get_notes(user_id: int, user: dict = Depends(current_user)):
    # 漏洞（BOLA / IDOR）：只驗證「有合法 token」，完全未綁定 user_id == 當前主體。
    # bob（id 2）的 token 可讀 alice（id 1）的私密筆記。這是 G5 bola_idor 主要目標。
    target = USERS_BY_ID.get(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="查無此使用者")
    return {"id": target["id"], "username": target["username"], "notes": target["notes"]}


# 便於 G5 探針列舉資源 ID：回傳所有 user 的 id（無授權限制，示範用）
@app.get("/users")
def list_users(user: dict = Depends(current_user)):
    return [{"id": u["id"], "username": u["username"]} for u in _DATA["users"]]


@app.get("/fetch")
def fetch(url: str = Query(...), user: dict = Depends(current_user)):
    # 漏洞（SSRF）：對使用者提供的 URL 直接發出 server-side GET，無 allow-list、無私網封鎖。
    # 可讀 http://169.254.169.254/latest/meta-data/（雲端 metadata）。G5 ssrf_metadata 目標。
    req = urllib.request.Request(url, headers={"User-Agent": "vibesec-vulnapp-fetch"})
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 刻意漏洞
        body = resp.read(65536).decode("utf-8", "replace")
        return {"status": resp.status, "url": url, "body": body}


@app.post("/chat")
def chat(body: dict = Body(...)):
    # G6 目標：無認證、無 rate limiting；行為由 deterministic llm_stub 決定。
    from app.llm_stub import generate_reply

    message = body.get("message", "")
    reply = generate_reply(message)
    return {"reply": reply}


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
