from fastapi import FastAPI, UploadFile, BackgroundTasks, Header, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, Response, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import bcrypt as _bcrypt_lib
from jose import jwt, JWTError
import httpx
import asyncio
import os
import uuid
import re
import html as html_lib
import urllib.parse
import sqlite3
import smtplib
import random
import hashlib
import time
from pathlib import Path
from datetime import datetime, timedelta
from dotenv import load_dotenv
from google import genai
from email.mime.text import MIMEText

load_dotenv()
app = FastAPI(title="AI Mobile Sec Scanner")

_tasks: dict = {}

# ── Auth helpers ────────────────────────────────────────────
def _hash_pw(password: str) -> str:
    return _bcrypt_lib.hashpw(password.encode(), _bcrypt_lib.gensalt()).decode()

def _verify_pw(password: str, hashed: str) -> bool:
    return _bcrypt_lib.checkpw(password.encode(), hashed.encode())

_bearer = HTTPBearer(auto_error=False)
JWT_SECRET = os.getenv("JWT_SECRET", "change-me")
JWT_ALG = "HS256"
JWT_EXP_DAYS = 7

# ── Payment packages ────────────────────────────────────────
PACKAGES = {
    "p10":  {"credits": 10,  "amount": 9.9,   "usdt": "1.50"},
    "p50":  {"credits": 50,  "amount": 39.9,  "usdt": "5.50"},
    "p100": {"credits": 100, "amount": 69.9,  "usdt": "10.00"},
    "p200": {"credits": 200, "amount": 129.9, "usdt": "18.00"},
}

# ── SQLite database ────────────────────────────────────────────
_DB_PATH = Path(os.getenv("DB_PATH", "/app/data/scanner.db"))

def _db():
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def _init_db():
    with _db() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                token      TEXT PRIMARY KEY,
                credits    INTEGER DEFAULT 0,
                total_scans INTEGER DEFAULT 0,
                created_at TEXT DEFAULT (datetime('now')),
                updated_at TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS codes (
                code        TEXT PRIMARY KEY,
                credits     INTEGER NOT NULL,
                note        TEXT DEFAULT '',
                created_at  TEXT DEFAULT (datetime('now')),
                expires_at  TEXT,
                max_uses    INTEGER DEFAULT 1,
                uses_count  INTEGER DEFAULT 0,
                is_revoked  INTEGER DEFAULT 0,
                used_by     TEXT,
                used_at     TEXT
            );
            CREATE TABLE IF NOT EXISTS code_uses (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                code     TEXT NOT NULL,
                user_id  INTEGER NOT NULL,
                used_at  TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS users_v2 (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                email         TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_verified   INTEGER DEFAULT 0,
                credits       INTEGER DEFAULT 0,
                total_scans   INTEGER DEFAULT 0,
                created_at    TEXT DEFAULT (datetime('now')),
                updated_at    TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS verify_codes (
                email      TEXT PRIMARY KEY,
                code       TEXT NOT NULL,
                expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS orders (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                order_no     TEXT UNIQUE NOT NULL,
                user_id      INTEGER NOT NULL,
                credits      INTEGER NOT NULL,
                amount       REAL NOT NULL,
                status       TEXT DEFAULT 'pending',
                pay_method   TEXT,
                pay_trade_no TEXT,
                created_at   TEXT DEFAULT (datetime('now')),
                paid_at      TEXT
            );
        """)

def _migrate_db():
    """Add new columns to existing databases (safe to re-run)."""
    migrations = [
        "ALTER TABLE codes ADD COLUMN expires_at  TEXT",
        "ALTER TABLE codes ADD COLUMN max_uses    INTEGER DEFAULT 1",
        "ALTER TABLE codes ADD COLUMN uses_count  INTEGER DEFAULT 0",
        "ALTER TABLE codes ADD COLUMN is_revoked  INTEGER DEFAULT 0",
    ]
    with _db() as c:
        for sql in migrations:
            try:
                c.execute(sql)
            except Exception:
                pass  # Column already exists

_init_db()
_migrate_db()


# ── Redemption code helpers ──────────────────────────────────

# Unambiguous charset: no 0/O/I/1 to avoid confusion when read aloud or handwritten
_CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

def _gen_code() -> str:
    """Generate a human-readable code in XXXX-XXXX-XXXX format."""
    seg = lambda: "".join(random.choices(_CODE_CHARS, k=4))
    return f"{seg()}-{seg()}-{seg()}"

# Simple in-memory rate limiter: {user_id: [timestamps]}
_redeem_attempts: dict = {}
_REDEEM_WINDOW = 60   # seconds
_REDEEM_MAX    = 5    # max attempts per window

def _check_redeem_rate(user_id: int) -> bool:
    """Return True if allowed, False if rate-limited."""
    now = time.time()
    prev = [t for t in _redeem_attempts.get(user_id, []) if now - t < _REDEEM_WINDOW]
    if len(prev) >= _REDEEM_MAX:
        return False
    prev.append(now)
    _redeem_attempts[user_id] = prev
    return True


# ── Admin auth helpers ───────────────────────────────────────

_ADMIN_USER = os.getenv("ADMIN_USERNAME", "admin")
_ADMIN_PASS = os.getenv("ADMIN_PASSWORD", "admin")


def _make_admin_jwt() -> str:
    exp = datetime.utcnow() + timedelta(hours=8)
    return jwt.encode({"sub": "admin", "role": "admin", "exp": exp}, JWT_SECRET, algorithm=JWT_ALG)


def _is_admin_jwt(token: str) -> bool:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return payload.get("role") == "admin"
    except Exception:
        return False


async def _require_admin(
    request: Request,
    creds: HTTPAuthorizationCredentials = Depends(_bearer),
) -> None:
    """Accepts admin JWT Bearer (web UI) or admin_key query param (API)."""
    if creds and _is_admin_jwt(creds.credentials):
        return
    env_key = os.getenv("ADMIN_KEY", "")
    qkey = request.query_params.get("admin_key", "")
    if env_key and qkey == env_key:
        return
    raise HTTPException(status_code=403, detail="Admin access required")


# ── Auth & payment helpers ──────────────────────────────────

def _make_jwt(user_id: int) -> str:
    exp = datetime.utcnow() + timedelta(days=JWT_EXP_DAYS)
    return jwt.encode({"sub": str(user_id), "exp": exp}, JWT_SECRET, algorithm=JWT_ALG)


def _decode_jwt(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return int(payload["sub"])
    except (JWTError, Exception):
        return None


async def _current_user(creds: HTTPAuthorizationCredentials = Depends(_bearer)) -> dict:
    if not creds:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user_id = _decode_jwt(creds.credentials)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    with _db() as c:
        row = c.execute("SELECT * FROM users_v2 WHERE id=?", (user_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="User not found")
    return dict(row)


def _send_verify_email(email: str, code: str):
    host = os.getenv("SMTP_HOST", "")
    port = int(os.getenv("SMTP_PORT", "465"))
    user = os.getenv("SMTP_USER", "")
    pwd  = os.getenv("SMTP_PASS", "")
    frm  = os.getenv("SMTP_FROM", user)
    if not host:
        print(f"[DEV] Verify code for {email}: {code}")
        return
    msg = MIMEText(f"您的验证码是：{code}，10分钟内有效。\n\nYour verification code is: {code} (valid 10 minutes).", "plain", "utf-8")
    msg["Subject"] = "邮箱验证码 - AI 移动安全扫描器"
    msg["From"] = frm
    msg["To"] = email
    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port) as s:
                s.login(user, pwd)
                s.sendmail(frm, [email], msg.as_string())
        else:
            with smtplib.SMTP(host, port) as s:
                s.starttls()
                s.login(user, pwd)
                s.sendmail(frm, [email], msg.as_string())
    except Exception as e:
        print(f"[SMTP ERROR] {e}")


def _make_order_no() -> str:
    return f"ORD{int(time.time() * 1000)}{random.randint(100, 999)}"


def _cryptomus_sign(body_str: str) -> str:
    """MD5 signature for Cryptomus: md5(base64(json_body) + api_key)."""
    import base64
    api_key = os.getenv("CRYPTOMUS_API_KEY", "")
    return hashlib.md5((base64.b64encode(body_str.encode()).decode() + api_key).encode()).hexdigest()


_CRYPTOMUS_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"


# ── Auth request bodies ─────────────────────────────────────

class RegisterBody(BaseModel):
    email: str
    password: str

class VerifyBody(BaseModel):
    email: str
    code: str

class ResendBody(BaseModel):
    email: str

class LoginBody(BaseModel):
    email: str
    password: str

class OrderCreateBody(BaseModel):
    package_id: str
    pay_type: str = "alipay"   # "alipay" or "wechat"


# ── Report HTML labels (zh / en) ──────────────────────────────
_LABELS = {
    "zh": {
        "report_title": "📱 移动应用安全分析报告",
        "generated":    "生成于",
        "app_info":     "应用基本信息",
        "app_name":     "应用名称",
        "package":      "包名 / Bundle ID",
        "version":      "版本号",
        "build":        "Build 号",
        "size":         "文件大小",
        "platform":     "平台",
        "risk":         "风险概览",
        "critical":     "严重",
        "high":         "高危",
        "warning":      "中危",
        "trackers":     "追踪器",
        "perms":        "权限列表",
        "perms_android":"危险权限",
        "perm_name":    "权限名称",
        "perm_desc":    "说明",
        "no_perms":     "无权限",
        "issues":       "安全问题",
        "issues_android":"清单文件安全问题",
        "issues_ios":   "二进制安全分析",
        "sev":          "级别",
        "issue":        "问题",
        "detail":       "描述",
        "no_issues":    "无问题",
        "ai_title":     "AI 安全分析摘要",
        "footer":       "AI Mobile Security Scanner · MobSF v4.4.5 + Gemini 2.5 Flash · 仅供安全研究参考",
        "sev_map":      {"critical": "严重", "high": "高危", "warning": "中危", "info": "信息"},
        "html_lang":    "zh-CN",
    },
    "en": {
        "report_title": "📱 Mobile App Security Analysis Report",
        "generated":    "Generated at",
        "app_info":     "App Information",
        "app_name":     "App Name",
        "package":      "Package / Bundle ID",
        "version":      "Version",
        "build":        "Build",
        "size":         "File Size",
        "platform":     "Platform",
        "risk":         "Risk Overview",
        "critical":     "Critical",
        "high":         "High",
        "warning":      "Medium",
        "trackers":     "Trackers",
        "perms":        "Permissions",
        "perms_android":"Dangerous Permissions",
        "perm_name":    "Permission",
        "perm_desc":    "Description",
        "no_perms":     "No permissions found",
        "issues":       "Security Issues",
        "issues_android":"Manifest Security Issues",
        "issues_ios":   "Binary Security Analysis",
        "sev":          "Severity",
        "issue":        "Issue",
        "detail":       "Details",
        "no_issues":    "No issues found",
        "ai_title":     "AI Security Analysis",
        "footer":       "AI Mobile Security Scanner · MobSF v4.4.5 + Gemini 2.5 Flash · For security research only",
        "sev_map":      {"critical": "CRITICAL", "high": "HIGH", "warning": "MEDIUM", "info": "INFO"},
        "html_lang":    "en",
    },
}


def _mobsf_headers():
    return {"Authorization": os.getenv("MOBSF_API_KEY")}


# ── Credits API ───────────────────────────────────────────────

@app.get("/credits/{token}")
async def get_credits(token: str):
    """Return credits balance for a token."""
    with _db() as c:
        row = c.execute("SELECT credits, total_scans FROM users WHERE token=?", (token,)).fetchone()
    if row:
        return {"credits": row["credits"], "total_scans": row["total_scans"]}
    # New token: create with 0 credits
    with _db() as c:
        c.execute("INSERT OR IGNORE INTO users(token, credits) VALUES(?,0)", (token,))
    return {"credits": 0, "total_scans": 0}


@app.post("/credits/redeem")
async def redeem_code(token: str, code: str):
    """Redeem a one-time code to add credits."""
    code = code.strip().upper()
    with _db() as c:
        row = c.execute(
            "SELECT * FROM codes WHERE code=? AND used_by IS NULL", (code,)
        ).fetchone()
        if not row:
            return JSONResponse({"ok": False, "error": "兑换码无效或已使用"}, status_code=400)
        c.execute(
            "UPDATE codes SET used_by=?, used_at=datetime('now') WHERE code=?",
            (token, code),
        )
        c.execute(
            """INSERT INTO users(token, credits) VALUES(?,?)
               ON CONFLICT(token) DO UPDATE SET
                 credits=credits+excluded.credits,
                 updated_at=datetime('now')""",
            (token, row["credits"]),
        )
        new_bal = c.execute("SELECT credits FROM users WHERE token=?", (token,)).fetchone()["credits"]
    return {"ok": True, "credits": new_bal, "added": row["credits"]}


@app.post("/admin/login")
async def admin_login(username: str, password: str):
    """Login to the admin panel; returns a short-lived admin JWT."""
    if username == _ADMIN_USER and password == _ADMIN_PASS:
        return {"ok": True, "token": _make_admin_jwt()}
    return JSONResponse({"ok": False, "error": "用户名或密码错误"}, status_code=401)


@app.get("/admin", response_class=HTMLResponse)
async def admin_page():
    """Serve the admin panel HTML."""
    html_path = os.path.join(os.path.dirname(__file__), "static", "admin.html")
    with open(html_path, encoding="utf-8") as f:
        return f.read()


@app.post("/admin/generate-codes")
async def generate_codes(
    credits: int = 10,
    count: int = 1,
    note: str = "",
    expires_days: int = 0,
    max_uses: int = 1,
    _: None = Depends(_require_admin),
):
    """Generate redemption codes (admin only).

    - expires_days: 0 = never expire; >0 = expire after N days
    - max_uses: 1 = one-time; >1 = shared promo code usable by N users
    """
    if not (1 <= credits <= 10000) or not (1 <= count <= 500):
        return JSONResponse({"error": "invalid params"}, status_code=400)
    if not (1 <= max_uses <= 100000):
        return JSONResponse({"error": "max_uses must be 1–100000"}, status_code=400)

    expires_at = None
    if expires_days > 0:
        expires_at = (datetime.utcnow() + timedelta(days=expires_days)).isoformat()

    display_codes = [_gen_code() for _ in range(count)]
    # Store without dashes; redeem endpoint also strips dashes so lookup always matches
    db_codes = [c.replace("-", "") for c in display_codes]
    with _db() as c:
        c.executemany(
            "INSERT INTO codes(code, credits, note, expires_at, max_uses) VALUES(?,?,?,?,?)",
            [(code, credits, note, expires_at, max_uses) for code in db_codes],
        )
    return {
        "codes": display_codes,  # return formatted (with dashes) for display
        "credits_each": credits,
        "count": count,
        "max_uses": max_uses,
        "expires_at": expires_at,
    }


@app.get("/admin/codes")
async def admin_list_codes(
    limit: int = 500,
    offset: int = 0,
    _: None = Depends(_require_admin),
):
    """List redemption codes with usage stats (admin only)."""
    limit = min(limit, 500)
    with _db() as c:
        rows = c.execute(
            """SELECT code, credits, note, created_at, expires_at,
                      max_uses, uses_count, is_revoked, used_by, used_at
               FROM codes ORDER BY created_at DESC LIMIT ? OFFSET ?""",
            (limit, offset),
        ).fetchall()
        total = c.execute("SELECT COUNT(*) FROM codes").fetchone()[0]
    return {"total": total, "codes": [dict(r) for r in rows]}


@app.post("/admin/codes/{code}/revoke")
async def admin_revoke_code(code: str, _: None = Depends(_require_admin)):
    """Revoke a redemption code so it can no longer be used (admin only)."""
    code = re.sub(r"[-\s]", "", code.strip().upper())
    with _db() as c:
        r = c.execute("UPDATE codes SET is_revoked=1 WHERE code=?", (code,))
        if r.rowcount == 0:
            return JSONResponse({"error": "Code not found"}, status_code=404)
    return {"ok": True, "revoked": code}


@app.get("/admin/stats")
async def admin_stats(_: None = Depends(_require_admin)):
    """Usage stats (admin only)."""
    with _db() as c:
        users         = c.execute("SELECT COUNT(*) FROM users_v2").fetchone()[0]
        total_scans   = c.execute("SELECT SUM(total_scans) FROM users_v2").fetchone()[0] or 0
        codes_total   = c.execute("SELECT COUNT(*) FROM codes").fetchone()[0]
        codes_revoked = c.execute("SELECT COUNT(*) FROM codes WHERE is_revoked=1").fetchone()[0]
        code_uses     = c.execute("SELECT COUNT(*) FROM code_uses").fetchone()[0]
        codes_active  = c.execute(
            "SELECT COUNT(*) FROM codes WHERE is_revoked=0 AND uses_count < max_uses"
            " AND (expires_at IS NULL OR expires_at > datetime('now'))"
        ).fetchone()[0]
    return {
        "users": users,
        "total_scans": total_scans,
        "codes_total": codes_total,
        "codes_revoked": codes_revoked,
        "codes_active": codes_active,
        "code_uses_total": code_uses,
    }


# ── Auth Endpoints ─────────────────────────────────────────

@app.post("/auth/register")
async def auth_register(body: RegisterBody):
    """Register with email + password; send 6-digit verification code."""
    email = body.email.strip().lower()
    if not email or "@" not in email:
        return JSONResponse({"ok": False, "error": "邮箱格式不正确"}, status_code=400)
    if len(body.password) < 6:
        return JSONResponse({"ok": False, "error": "密码至少6位"}, status_code=400)
    pw_hash = _hash_pw(body.password)
    try:
        with _db() as c:
            c.execute(
                "INSERT INTO users_v2(email, password_hash) VALUES(?,?)",
                (email, pw_hash),
            )
    except sqlite3.IntegrityError:
        # Email already exists — allow re-registration if not verified
        with _db() as c:
            row = c.execute("SELECT is_verified FROM users_v2 WHERE email=?", (email,)).fetchone()
        if row and row["is_verified"]:
            return JSONResponse({"ok": False, "error": "该邮箱已注册，请直接登录"}, status_code=400)
        # Update password hash and re-send verification
        with _db() as c:
            c.execute("UPDATE users_v2 SET password_hash=? WHERE email=?", (pw_hash, email))
    code = str(random.randint(100000, 999999))
    expires = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
    with _db() as c:
        c.execute(
            "INSERT OR REPLACE INTO verify_codes(email, code, expires_at) VALUES(?,?,?)",
            (email, code, expires),
        )
    _send_verify_email(email, code)
    return {"ok": True, "message": "验证码已发送，请查收邮件"}


@app.post("/auth/verify")
async def auth_verify(body: VerifyBody):
    """Verify email with 6-digit code; return JWT on success."""
    email = body.email.strip().lower()
    with _db() as c:
        row = c.execute("SELECT * FROM verify_codes WHERE email=?", (email,)).fetchone()
    if not row:
        return JSONResponse({"ok": False, "error": "验证码不存在，请重新发送"}, status_code=400)
    if datetime.utcnow().isoformat() > row["expires_at"]:
        return JSONResponse({"ok": False, "error": "验证码已过期，请重新发送"}, status_code=400)
    if row["code"] != body.code.strip():
        return JSONResponse({"ok": False, "error": "验证码错误"}, status_code=400)
    with _db() as c:
        c.execute("UPDATE users_v2 SET is_verified=1, updated_at=datetime('now') WHERE email=?", (email,))
        c.execute("DELETE FROM verify_codes WHERE email=?", (email,))
        user = c.execute("SELECT * FROM users_v2 WHERE email=?", (email,)).fetchone()
    token = _make_jwt(user["id"])
    return {
        "ok": True,
        "token": token,
        "user": {"id": user["id"], "email": user["email"], "credits": user["credits"], "total_scans": user["total_scans"]},
    }


@app.post("/auth/resend")
async def auth_resend(body: ResendBody):
    """Resend verification code (rate-limit: not if sent < 60s ago)."""
    email = body.email.strip().lower()
    with _db() as c:
        existing = c.execute("SELECT expires_at FROM verify_codes WHERE email=?", (email,)).fetchone()
    if existing:
        # expires_at is 10 min from send; if more than 9 min remain, deny
        expires = datetime.fromisoformat(existing["expires_at"])
        sent_at = expires - timedelta(minutes=10)
        if (datetime.utcnow() - sent_at).total_seconds() < 60:
            return JSONResponse({"ok": False, "error": "请等待60秒后再重新发送"}, status_code=429)
    with _db() as c:
        row = c.execute("SELECT id FROM users_v2 WHERE email=?", (email,)).fetchone()
    if not row:
        return JSONResponse({"ok": False, "error": "邮箱未注册"}, status_code=400)
    code = str(random.randint(100000, 999999))
    expires = (datetime.utcnow() + timedelta(minutes=10)).isoformat()
    with _db() as c:
        c.execute(
            "INSERT OR REPLACE INTO verify_codes(email, code, expires_at) VALUES(?,?,?)",
            (email, code, expires),
        )
    _send_verify_email(email, code)
    return {"ok": True, "message": "验证码已重新发送"}


@app.post("/auth/login")
async def auth_login(body: LoginBody):
    """Login with email + password; return JWT."""
    email = body.email.strip().lower()
    with _db() as c:
        user = c.execute("SELECT * FROM users_v2 WHERE email=?", (email,)).fetchone()
    if not user:
        return JSONResponse({"ok": False, "error": "邮箱或密码错误"}, status_code=401)
    if not _verify_pw(body.password, user["password_hash"]):
        return JSONResponse({"ok": False, "error": "邮箱或密码错误"}, status_code=401)
    if not user["is_verified"]:
        return JSONResponse({"ok": False, "error": "邮箱尚未验证，请查收验证码邮件", "need_verify": True, "email": email}, status_code=403)
    token = _make_jwt(user["id"])
    return {
        "ok": True,
        "token": token,
        "user": {"id": user["id"], "email": user["email"], "credits": user["credits"], "total_scans": user["total_scans"]},
    }


@app.get("/auth/me")
async def auth_me(user: dict = Depends(_current_user)):
    """Return current user info from JWT."""
    return {"id": user["id"], "email": user["email"], "credits": user["credits"], "total_scans": user["total_scans"]}


# ── Payment Endpoints ───────────────────────────────────────

@app.post("/orders/create")
async def orders_create(body: OrderCreateBody, user: dict = Depends(_current_user)):
    """Create an order via Cryptomus USDT and return pay_url."""
    pkg = PACKAGES.get(body.package_id)
    if not pkg:
        raise HTTPException(status_code=400, detail="Invalid package_id")
    merchant = os.getenv("CRYPTOMUS_MERCHANT", "")
    api_key  = os.getenv("CRYPTOMUS_API_KEY", "")
    site_url = os.getenv("SITE_URL", "http://localhost:8080").rstrip("/")
    if not merchant or not api_key:
        raise HTTPException(status_code=503, detail="支付功能暂未开放")
    order_no = _make_order_no()
    with _db() as c:
        c.execute(
            "INSERT INTO orders(order_no, user_id, credits, amount) VALUES(?,?,?,?)",
            (order_no, user["id"], pkg["credits"], pkg["amount"]),
        )
    payload = {
        "amount":       pkg["usdt"],
        "currency":     "USDT",
        "network":      "tron",
        "order_id":     order_no,
        "url_callback": f"{site_url}/payment/notify",
        "url_return":   f"{site_url}/payment/return",
        "url_success":  f"{site_url}/payment/return",
        "lifetime":     3600,
        "to_currency":  "USDT",
    }
    import json as _json
    body_str = _json.dumps(payload, separators=(",", ":"))
    sign = _cryptomus_sign(body_str)
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(
                "https://api.cryptomus.com/v1/payment",
                content=body_str.encode(),
                headers={
                    "merchant": merchant,
                    "sign": sign,
                    "Content-Type": "application/json",
                    "User-Agent": _CRYPTOMUS_UA,
                },
            )
            result = resp.json()
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"支付网关请求失败: {e}")
    if result.get("state") != 0:
        raise HTTPException(status_code=400, detail=result.get("message", "支付创建失败"))
    pay_url = result.get("result", {}).get("url", "")
    return {"order_no": order_no, "pay_url": pay_url}


@app.post("/payment/notify")
async def payment_notify(request: Request):
    """Cryptomus server-to-server POST callback to confirm payment."""
    import json as _json
    data = await request.json()
    received_sign = data.pop("sign", "")
    body_str = _json.dumps(data, separators=(",", ":"))
    if not received_sign or received_sign != _cryptomus_sign(body_str):
        return Response("fail")
    status   = data.get("status", "")
    order_no = data.get("order_id", "")
    trade_no = data.get("uuid", "")
    if status not in ("paid", "paid_over"):
        return Response("ok")
    with _db() as c:
        order = c.execute("SELECT * FROM orders WHERE order_no=?", (order_no,)).fetchone()
        if not order:
            return Response("fail")
        if order["status"] == "paid":
            return Response("ok")   # idempotent
        c.execute(
            "UPDATE orders SET status='paid', pay_trade_no=?, paid_at=datetime('now') WHERE order_no=?",
            (trade_no, order_no),
        )
        c.execute(
            "UPDATE users_v2 SET credits=credits+?, updated_at=datetime('now') WHERE id=?",
            (order["credits"], order["user_id"]),
        )
    return Response("ok")


@app.get("/payment/return")
async def payment_return():
    """Epay browser redirect after payment; send user back to home page."""
    return HTMLResponse(
        '<html><head><meta http-equiv="refresh" content="0;url=/?payment=success"></head>'
        "<body>支付成功，正在跳转...</body></html>"
    )


@app.post("/auth/redeem")
async def auth_redeem(code: str, user: dict = Depends(_current_user)):
    """Redeem a code to add credits to users_v2. Supports multi-use and expiry."""
    if not _check_redeem_rate(user["id"]):
        return JSONResponse({"ok": False, "error": "操作过于频繁，请稍后再试"}, status_code=429)

    # Normalize: strip whitespace, uppercase, remove dashes
    code = re.sub(r"[-\s]", "", code.strip().upper())
    if not code:
        return JSONResponse({"ok": False, "error": "兑换码不能为空"}, status_code=400)

    with _db() as c:
        row = c.execute(
            """SELECT * FROM codes
               WHERE code=? AND is_revoked=0
                 AND (expires_at IS NULL OR expires_at > datetime('now'))
                 AND uses_count < max_uses""",
            (code,),
        ).fetchone()
        if not row:
            return JSONResponse({"ok": False, "error": "兑换码无效、已用完或已过期"}, status_code=400)

        # Each user can only redeem the same code once
        already = c.execute(
            "SELECT 1 FROM code_uses WHERE code=? AND user_id=?",
            (code, user["id"]),
        ).fetchone()
        if already:
            return JSONResponse({"ok": False, "error": "您已使用过此兑换码"}, status_code=400)

        # Record usage in audit log
        c.execute(
            "INSERT INTO code_uses(code, user_id) VALUES(?,?)",
            (code, user["id"]),
        )
        # Increment counter; for first use also set used_by/used_at for backwards compat
        c.execute(
            """UPDATE codes
               SET uses_count = uses_count + 1,
                   used_by    = COALESCE(used_by, ?),
                   used_at    = COALESCE(used_at, datetime('now'))
               WHERE code=?""",
            (f"user_v2:{user['id']}", code),
        )
        c.execute(
            "UPDATE users_v2 SET credits=credits+?, updated_at=datetime('now') WHERE id=?",
            (row["credits"], user["id"]),
        )
        new_bal = c.execute(
            "SELECT credits FROM users_v2 WHERE id=?", (user["id"],)
        ).fetchone()["credits"]
    return {"ok": True, "credits": new_bal, "added": row["credits"]}


@app.get("/orders/list")
async def orders_list(user: dict = Depends(_current_user)):
    """Return order history for the current user."""
    with _db() as c:
        rows = c.execute(
            "SELECT order_no, credits, amount, status, pay_method, created_at, paid_at "
            "FROM orders WHERE user_id=? ORDER BY created_at DESC LIMIT 50",
            (user["id"],),
        ).fetchall()
    return {"orders": [dict(r) for r in rows]}


@app.get("/health")
async def health():
    """Check MobSF connectivity."""
    mobsf_url = os.getenv("MOBSF_URL", "http://localhost:8000")
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{mobsf_url}/api/v1/api_docs",
                                    headers=_mobsf_headers())
            ok = resp.status_code < 500
    except Exception:
        ok = False
    return {"mobsf": "ok" if ok else "unreachable", "mobsf_url": mobsf_url}


@app.get("/favicon.svg")
async def favicon():
    svg_path = os.path.join(os.path.dirname(__file__), "static", "favicon.svg")
    with open(svg_path, encoding="utf-8") as f:
        return Response(content=f.read(), media_type="image/svg+xml")


@app.get("/", response_class=HTMLResponse)
async def index():
    html_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    with open(html_path, encoding="utf-8") as f:
        return f.read()


def _first(*vals) -> str:
    """Return the first non-empty string value from args."""
    for v in vals:
        if v is not None and str(v).strip():
            return str(v).strip()
    return ""


@app.post("/scan")
async def scan_app(file: UploadFile, background_tasks: BackgroundTasks,
                   lang: str = "zh", token: str = "",
                   authorization: str = Header(default="")):
    """Submit APK/IPA for scanning. Accepts JWT Bearer header (v2) or legacy token query param."""
    auth_type = None
    user_id   = None

    # ── JWT path (new users_v2 system) ──────────────────────
    bearer = authorization.removeprefix("Bearer ").strip() if authorization.startswith("Bearer ") else ""
    if bearer:
        uid = _decode_jwt(bearer)
        if uid:
            with _db() as c:
                row = c.execute("SELECT credits FROM users_v2 WHERE id=?", (uid,)).fetchone()
            if not row or row["credits"] <= 0:
                return JSONResponse(
                    {"error": "credits_exhausted", "message": "扫描次数不足，请购买次数包后继续使用。"},
                    status_code=402,
                )
            auth_type = "jwt"
            user_id   = uid

    # ── Legacy token path (users table) ─────────────────────
    if auth_type is None:
        if not token:
            return JSONResponse({"error": "missing_token", "message": "请先登录或提供用户 Token"}, status_code=400)
        with _db() as c:
            row = c.execute("SELECT credits FROM users WHERE token=?", (token,)).fetchone()
        if not row or row["credits"] <= 0:
            return JSONResponse(
                {"error": "credits_exhausted", "message": "扫描次数不足，请购买次数包后继续使用。"},
                status_code=402,
            )
        auth_type = "legacy"

    task_id = str(uuid.uuid4())
    file_data = await file.read()
    _tasks[task_id] = {
        "status":    "uploading",
        "filename":  file.filename,
        "lang":      lang,
        "token":     token,        # legacy
        "auth_type": auth_type,
        "user_id":   user_id,      # jwt
        "started_at": datetime.now().isoformat(),
    }
    background_tasks.add_task(_run_scan, task_id, file.filename, file_data, lang)
    return {"task_id": task_id}


async def _run_scan(task_id: str, filename: str, file_data: bytes, lang: str = "zh"):
    mobsf_url = os.getenv("MOBSF_URL", "http://localhost:8000")
    headers = _mobsf_headers()
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=30, read=300, write=120, pool=30)
        ) as client:
            # 1. Upload to MobSF
            _tasks[task_id]["status"] = "uploading"
            resp = await client.post(
                f"{mobsf_url}/api/v1/upload",
                files={"file": (filename, file_data, "application/octet-stream")},
                headers=headers,
            )
            upload_data = resp.json()
            if "hash" not in upload_data:
                _tasks[task_id].update({"status": "error", "error": str(upload_data)})
                return
            scan_id = upload_data["hash"]
            scan_type = upload_data.get("scan_type", "apk")
            _tasks[task_id]["scan_type"] = scan_type

            # 2. Trigger scan
            _tasks[task_id]["status"] = "scanning"
            resp = await client.post(
                f"{mobsf_url}/api/v1/scan",
                data={"hash": scan_id, "scan_type": scan_type},
                headers=headers,
            )
            scan_result = resp.json()
            if "error" in scan_result:
                _tasks[task_id].update({"status": "error", "error": str(scan_result["error"])})
                return

            # 3. Poll for report (max 300s)
            _tasks[task_id]["status"] = "analyzing"
            report = None
            for _ in range(60):
                await asyncio.sleep(5)
                resp = await client.post(
                    f"{mobsf_url}/api/v1/report_json",
                    data={"hash": scan_id},
                    headers=headers,
                )
                data = resp.json()
                if "report" not in data:
                    report = data
                    break

        if report is None:
            _tasks[task_id].update({"status": "error", "error": "Scan timed out (300s)"})
            return

        # 4. Gemini AI summary (bilingual prompt)
        _tasks[task_id]["status"] = "summarizing"
        is_ios = scan_type == "ipa"
        platform_name = "iOS" if is_ios else "Android"
        raw_perms = report.get("permissions")
        perms_keys = list(raw_perms.keys())[:20] if isinstance(raw_perms, dict) else []
        raw_trackers = report.get("trackers")
        trackers_val = raw_trackers.get("detected_trackers", []) if isinstance(raw_trackers, dict) else []
        ai_client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
        summary_input = {
            "platform":     platform_name,
            "app_name":     _first(report.get("app_name")),
            "package_name": _first(report.get("bundle_id"), report.get("package_name"), report.get("identifier")),
            "version_name": _first(report.get("app_version"), report.get("version_name")),
            "build":        _first(report.get("build"), report.get("version_code")) if is_ios else "",
            "permissions":  perms_keys,
            "security_score": report.get("security_score") or "N/A",
            "trackers":     trackers_val,
        }
        if lang == "zh":
            prompt = (
                f"你是一名专业的移动安全研究员，请用中文分析以下 {platform_name} 应用安全扫描摘要，提供：\n"
                "1. 应用安全状况的专业摘要\n"
                "2. 基于权限和追踪器的主要安全风险\n"
                "3. 针对开发者的安全改进建议\n\n"
                f"扫描摘要：\n{summary_input}"
            )
        else:
            prompt = (
                f"You are a mobile security researcher. Analyze this {platform_name} app security "
                "scan summary and provide:\n"
                "1. A professional summary of the app's security posture\n"
                "2. The top security risks based on permissions and trackers\n"
                "3. Recommended security improvements for the developer\n\n"
                f"Scan summary:\n{summary_input}"
            )
        _GEMINI_MODELS = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash"]
        ai_text = None
        for _model in _GEMINI_MODELS:
            try:
                ai_resp = ai_client.models.generate_content(model=_model, contents=prompt)
                ai_text = ai_resp.text
                break
            except Exception as _e:
                _emsg = str(_e)
                if "429" in _emsg or "RESOURCE_EXHAUSTED" in _emsg or "quota" in _emsg.lower():
                    continue
                raise
        if ai_text is None:
            ai_text = (
                "⚠️ AI 分析暂时不可用（Gemini API 请求已达每日免费限额），"
                "MobSF 静态分析结果已正常生成，请查看上方各项数据。"
                if lang == "zh" else
                "⚠️ AI analysis unavailable (Gemini API free tier daily quota exceeded). "
                "MobSF static analysis results are complete — please review the data above."
            )
        # Deduct 1 credit on successful scan
        _auth_type = _tasks[task_id].get("auth_type", "legacy")
        if _auth_type == "jwt":
            _uid = _tasks[task_id].get("user_id")
            if _uid:
                with _db() as c:
                    c.execute(
                        "UPDATE users_v2 SET credits=credits-1, total_scans=total_scans+1,"
                        " updated_at=datetime('now') WHERE id=? AND credits>0",
                        (_uid,),
                    )
        else:
            _token = _tasks[task_id].get("token", "")
            if _token:
                with _db() as c:
                    c.execute(
                        "UPDATE users SET credits=credits-1, total_scans=total_scans+1,"
                        " updated_at=datetime('now') WHERE token=? AND credits>0",
                        (_token,),
                    )
        _tasks[task_id].update({
            "status": "done",
            "report": report,
            "ai_summary": ai_text,
            "finished_at": datetime.now().isoformat(),
        })

    except httpx.ConnectError:
        mobsf_url = os.getenv("MOBSF_URL", "http://localhost:8000")
        _tasks[task_id].update({
            "status": "error",
            "error": f"无法连接 MobSF ({mobsf_url})，请确认 MobSF 服务已启动。",
            "error_en": f"Cannot connect to MobSF ({mobsf_url}). Please make sure MobSF is running.",
            "error_code": "mobsf_unreachable",
        })
    except httpx.TimeoutException:
        _tasks[task_id].update({
            "status": "error",
            "error": "MobSF 响应超时，文件可能过大或服务繁忙，请稍后重试。",
            "error_en": "MobSF timed out. The file may be too large or the service is busy.",
            "error_code": "timeout",
        })
    except Exception as e:
        _tasks[task_id].update({"status": "error", "error": str(e)})


@app.get("/scan/status/{task_id}")
async def get_status(task_id: str):
    task = _tasks.get(task_id)
    if not task:
        return {"status": "not_found"}
    return {
        "status": task.get("status", "unknown"),
        "error":  task.get("error"),
    }


def _count_sev(sev: str, risk: dict):
    sev = sev.lower()
    if "critical" in sev:
        risk["critical"] += 1
    elif sev in ("high", "danger"):
        risk["high"] += 1
    elif "warn" in sev or "medium" in sev:
        risk["warning"] += 1
    else:
        risk["info"] += 1


def _extract_summary(task: dict) -> dict:
    report = task["report"]
    is_ios = task.get("scan_type", "apk") == "ipa"

    # ── Multi-key field extraction ────────────────────────────
    # iOS: bundle_id / app_version / build  (confirmed from MobSF v4.4.5)
    # Android: package_name / version_name / version_code
    _ps = report.get("playstore_details") or {}
    _ps = _ps if isinstance(_ps, dict) else {}
    _ps_title   = _ps.get("title", "")
    _ps_version = _ps.get("version", "")
    _pkg = report.get("package_name", "") or ""
    _pkg_derived = _pkg.split(".")[-1].capitalize() if _pkg else ""
    app_name     = _first(report.get("app_name"), _ps_title, _pkg_derived)
    package_name = _first(
        report.get("bundle_id"),        # iOS
        report.get("package_name"),     # Android
        report.get("identifier"),
    )
    version_name = _first(
        report.get("app_version"),      # iOS
        report.get("version_name"),     # Android
        _ps_version,                    # Play Store version string (e.g. "5.8.8")
        report.get("version_code"),     # last resort: internal build number
    )
    build_version = _first(report.get("build"), report.get("version_code")) if is_ios else ""

    # iOS platform string: "18.2" → "iOS 18.2"
    if is_ios:
        _plat_raw = report.get("platform", "")
        platform_display = f"iOS {_plat_raw}".strip() if _plat_raw else "iOS"
    else:
        platform_display = "Android"

    # ── Pre-compute shared Android manifest data ───────────────
    _appsec = report.get("appsec") or {}
    _appsec = _appsec if isinstance(_appsec, dict) else {}
    _manifest_raw = report.get("manifest_analysis") or []
    _manifest_findings = (
        _manifest_raw.get("manifest_findings", []) if isinstance(_manifest_raw, dict)
        else (_manifest_raw if isinstance(_manifest_raw, list) else [])
    )
    _manifest_summary = (
        _manifest_raw.get("manifest_summary", {}) if isinstance(_manifest_raw, dict) else {}
    )

    # ── Risk counting ──────────────────────────────────────────
    risk = {"critical": 0, "high": 0, "warning": 0, "info": 0}

    if is_ios:
        # binary_analysis: {"findings": {title: {severity, detailed_desc, ...}}}
        ba = report.get("binary_analysis") or {}
        ba_findings = ba.get("findings", {}) if isinstance(ba, dict) else {}
        for detail in ba_findings.values():
            if isinstance(detail, dict):
                _count_sev(detail.get("severity", "info"), risk)
        # ats_analysis: {"ats_findings": [...], "ats_summary": ...}
        ats_data = report.get("ats_analysis") or {}
        ats_list = ats_data.get("ats_findings", []) if isinstance(ats_data, dict) else []
        for item in (ats_list if isinstance(ats_list, list) else []):
            if isinstance(item, dict):
                _count_sev(item.get("severity", "warning"), risk)
    else:
        # Android: use manifest_summary totals directly (most reliable)
        if isinstance(_manifest_summary, dict) and _manifest_summary:
            for k in ("critical", "high", "warning", "info"):
                risk[k] += int(_manifest_summary.get(k, 0) or 0)
        else:
            # fallback: count from manifest_findings list
            for item in _manifest_findings:
                if isinstance(item, dict):
                    _count_sev(item.get("severity") or item.get("level", "info"), risk)
        # code_analysis findings
        code = report.get("code_analysis")
        if isinstance(code, dict):
            for _, fdata in (code.get("findings") or {}).items():
                if isinstance(fdata, dict):
                    meta = fdata.get("metadata")
                    sev = meta.get("severity", "info") if isinstance(meta, dict) else "info"
                    _count_sev(sev, risk)

    # ── Permissions ────────────────────────────────────────────
    raw_perms = report.get("permissions")
    perms = raw_perms if isinstance(raw_perms, dict) else {}
    # Both iOS and Android have status:"dangerous"; show all for iOS
    if is_ios:
        perm_list = [
            {"name": k, "info": _first(v.get("description"), v.get("info")) if isinstance(v, dict) else str(v)}
            for k, v in perms.items()
        ]
    else:
        perm_list = [
            {"name": k, "info": v.get("info", ""), "description": v.get("description", "")}
            for k, v in perms.items()
            if isinstance(v, dict) and v.get("status") == "dangerous"
        ]

    # ── Security issues ────────────────────────────────────────
    sec_issues = []
    if is_ios:
        # binary_analysis.findings: {title: {severity, detailed_desc, cvss, cwe, ...}}
        ba = report.get("binary_analysis") or {}
        ba_findings = ba.get("findings", {}) if isinstance(ba, dict) else {}
        for title, detail in ba_findings.items():
            if isinstance(detail, dict):
                sec_issues.append({
                    "title":       title,
                    "severity":    detail.get("severity", "warning"),
                    "description": detail.get("detailed_desc", ""),
                })
        # ats_analysis.ats_findings: [{issue, severity, description}, ...]
        ats_data = report.get("ats_analysis") or {}
        ats_list = ats_data.get("ats_findings", []) if isinstance(ats_data, dict) else []
        for item in (ats_list if isinstance(ats_list, list) else []):
            if isinstance(item, dict):
                sec_issues.append({
                    "title":       item.get("issue", ""),
                    "severity":    item.get("severity", "warning"),
                    "description": item.get("description", ""),
                })
    else:
        for item in _manifest_findings:  # reuse pre-computed list
            if isinstance(item, dict):
                sec_issues.append({
                    "title":       item.get("title") or item.get("rule", ""),
                    "severity":    item.get("severity") or item.get("level", ""),
                    "description": item.get("description", ""),
                })

    raw_trackers = report.get("trackers")
    trackers_data = raw_trackers if isinstance(raw_trackers, dict) else {}
    tracker_count = trackers_data.get("detected_trackers", 0)
    if isinstance(tracker_count, list):
        tracker_count = len(tracker_count)

    return {
        "platform":            platform_display,
        "app_name":            app_name or "Unknown",
        "package_name":        package_name,
        "version_name":        version_name,
        "build_version":       build_version,
        "size":                report.get("size", ""),
        "md5":                 report.get("md5", ""),
        "security_score":      str(report.get("security_score") or _appsec.get("security_score") or "N/A"),
        "risk_counts":         risk,
        "dangerous_permissions": perm_list[:20],
        "tracker_count":       tracker_count,
        "manifest_issues":     sec_issues[:25],
        "is_ios":              is_ios,
        "ai_summary":          task["ai_summary"],
        "finished_at":         task.get("finished_at", ""),
    }


@app.get("/scan/summary/{task_id}")
async def get_summary(task_id: str):
    task = _tasks.get(task_id)
    if not task or task.get("status") != "done":
        return {"error": "Report not ready"}
    return _extract_summary(task)


@app.get("/scan/report/{task_id}/download")
async def download_report(task_id: str, lang: str = "zh"):
    task = _tasks.get(task_id)
    if not task or task.get("status") != "done":
        return Response(content="Report not ready", status_code=404)
    summary = _extract_summary(task)
    filename = task.get("filename", "unknown.apk")
    app_name = summary.get("app_name", task_id[:8])
    # HTTP headers require latin-1; use ASCII-only fallback for filename param
    ascii_name = "".join(c for c in app_name if c.isascii() and (c.isalnum() or c in "-_"))
    safe_name = ascii_name or task_id[:8]
    # RFC 5987 (filename*) lets modern browsers show the full Unicode name
    encoded_name = urllib.parse.quote(f"security-report-{app_name}.html", safe="")
    content_disposition = (
        f'attachment; filename="security-report-{safe_name}.html"; '
        f"filename*=UTF-8''{encoded_name}"
    )
    html_content = _build_report_html(summary, filename, lang)
    return Response(
        content=html_content.encode("utf-8"),
        media_type="text/html; charset=utf-8",
        headers={"Content-Disposition": content_disposition},
    )


def _md_to_html(text: str) -> str:
    """Convert basic markdown to HTML."""
    t = html_lib.escape(text)
    t = re.sub(r"^#{3}\s+(.+)$",  r"<h3>\1</h3>",  t, flags=re.MULTILINE)
    t = re.sub(r"^#{2}\s+(.+)$",  r"<h2>\1</h2>",  t, flags=re.MULTILINE)
    t = re.sub(r"^#{1}\s+(.+)$",  r"<h1>\1</h1>",  t, flags=re.MULTILINE)
    t = re.sub(r"\*\*(.+?)\*\*",  r"<strong>\1</strong>", t)
    t = re.sub(r"\*(.+?)\*",      r"<em>\1</em>",         t)
    t = re.sub(r"`(.+?)`",        r"<code>\1</code>",      t)
    t = re.sub(r"^\s*[\*\-]\s+(.+)$", r"<li>\1</li>", t, flags=re.MULTILINE)
    t = re.sub(r"((?:<li>.*?</li>\n?)+)", r"<ul>\1</ul>", t, flags=re.DOTALL)
    blocks = re.split(r"\n{2,}", t)
    out = []
    for b in blocks:
        b = b.strip()
        if not b:
            continue
        if re.match(r"^<(h[1-3]|ul|ol|li)", b):
            out.append(b)
        else:
            out.append(f"<p>{b.replace(chr(10), '<br>')}</p>")
    return "\n".join(out)


def _build_report_html(s: dict, filename: str, lang: str = "zh") -> str:
    """Generate a self-contained HTML report for download."""
    L = _LABELS.get(lang, _LABELS["zh"])

    def e(v):
        return html_lib.escape(str(v or ""))

    is_ios  = s.get("is_ios", False)
    rc      = s.get("risk_counts", {})
    perms   = s.get("dangerous_permissions", [])
    issues  = s.get("manifest_issues", [])
    now     = datetime.now().strftime("%Y-%m-%d %H:%M")
    ai_html = _md_to_html(s.get("ai_summary", ""))
    issues_label = L["issues_ios"] if is_ios else L["issues_android"]
    perms_label  = L["perms"] if is_ios else L["perms_android"]

    SEV_BG    = {"critical": "#fef2f2", "high": "#fff7ed", "warning": "#fffbeb", "info": "#eff6ff"}
    SEV_COLOR = {"critical": "#dc2626", "high": "#ea580c", "warning": "#d97706", "info": "#2563eb"}
    sev_map   = L["sev_map"]

    # ── Permission rows ───────────────────────────────────────
    perm_rows = ""
    for i, p in enumerate(perms):
        bg = "#f8fafc" if i % 2 == 0 else "#ffffff"
        perm_rows += (
            f"<tr style='background:{bg}'>"
            f"<td class='mono' style='width:50%'>{e(p['name'])}</td>"
            f"<td>{e(p['info'])}</td>"
            f"</tr>\n"
        )
    if not perm_rows:
        perm_rows = f'<tr><td colspan="2" class="empty">{L["no_perms"]}</td></tr>'

    # ── Issue rows ────────────────────────────────────────────
    issue_rows = ""
    for i, item in enumerate(issues):
        bg  = "#f8fafc" if i % 2 == 0 else "#ffffff"
        sev = str(item.get("severity", "info")).lower()
        lbl = sev_map.get(sev, sev.upper())
        fg  = SEV_COLOR.get(sev, "#6b7280")
        ibg = SEV_BG.get(sev, "#f1f5f9")
        desc = str(item.get("description", ""))
        issue_rows += (
            f"<tr style='background:{bg}'>"
            f"<td style='width:9%;white-space:nowrap'>"
            f"<span class='badge' style='background:{ibg};color:{fg}'>{lbl}</span></td>"
            f"<td style='width:32%;font-weight:600'>{e(item.get('title',''))}</td>"
            f"<td class='muted'>{e(desc)}</td>"
            f"</tr>\n"
        )
    if not issue_rows:
        issue_rows = f'<tr><td colspan="3" class="empty">{L["no_issues"]}</td></tr>'

    # ── Meta rows ─────────────────────────────────────────────
    def meta_row(label, value, mono=False):
        val = f"<span class='mono'>{e(value)}</span>" if mono else e(value)
        return (
            f"<tr>"
            f"<td class='meta-label'>{label}</td>"
            f"<td class='meta-value'>{val}</td>"
            f"</tr>"
        )

    build_row = meta_row(L["build"], s.get("build_version", "")) if s.get("build_version") else ""
    meta_rows = (
        meta_row(L["app_name"],  s.get("app_name", ""))
        + meta_row(L["package"], s.get("package_name", ""))
        + meta_row(L["version"], s.get("version_name", ""))
        + build_row
        + meta_row(L["platform"], s.get("platform", ""))
        + meta_row(L["size"],    s.get("size", ""))
        + meta_row("MD5",        s.get("md5", ""), mono=True)
        + meta_row(L["generated"], now)
    )

    # ── Risk cards ────────────────────────────────────────────
    def risk_card(num, label, bg, fg):
        return (
            f"<div class='risk-card' style='background:{bg}'>"
            f"<div class='risk-num' style='color:{fg}'>{num}</div>"
            f"<div class='risk-label' style='color:{fg}'>{label}</div>"
            f"</div>"
        )

    risk_cards = (
        risk_card(rc.get("critical", 0), L["critical"], "#fef2f2", "#dc2626")
        + risk_card(rc.get("high", 0),   L["high"],     "#fff7ed", "#ea580c")
        + risk_card(rc.get("warning", 0),L["warning"],  "#fffbeb", "#d97706")
        + risk_card(s.get("tracker_count", 0), L["trackers"], "#eff6ff", "#2563eb")
    )

    return f"""<!DOCTYPE html>
<html lang="{L['html_lang']}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(s.get('app_name',''))} — Security Report</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'PingFang SC',
                 'Microsoft YaHei', Arial, sans-serif;
    font-size: 14px;
    line-height: 1.6;
    color: #1e293b;
    background: #f1f5f9;
  }}
  a {{ color: #2563eb; text-decoration: none; }}

  /* Header */
  .header {{
    background: #1e3a8a;
    color: white;
    padding: 32px 40px 28px;
  }}
  .header-badge {{
    font-size: 11px;
    letter-spacing: .12em;
    text-transform: uppercase;
    opacity: .65;
    margin-bottom: 8px;
  }}
  .header h1 {{
    font-size: 26px;
    font-weight: 800;
    margin-bottom: 6px;
  }}
  .header-sub {{
    font-size: 13px;
    opacity: .7;
  }}

  /* Layout */
  .content {{
    max-width: 960px;
    margin: 32px auto;
    padding: 0 24px 64px;
  }}

  /* Section */
  .section {{
    background: white;
    border-radius: 10px;
    box-shadow: 0 1px 4px rgba(0,0,0,.07);
    margin-bottom: 24px;
    overflow: hidden;
  }}
  .section-head {{
    padding: 16px 24px;
    border-bottom: 1px solid #e2e8f0;
    display: flex;
    align-items: center;
    gap: 10px;
  }}
  .section-num {{
    width: 26px;
    height: 26px;
    border-radius: 50%;
    background: #1e3a8a;
    color: white;
    font-size: 12px;
    font-weight: 700;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }}
  .section-title {{
    font-size: 15px;
    font-weight: 700;
    color: #1e293b;
  }}

  /* Risk cards */
  .risk-grid {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    padding: 20px 24px;
  }}
  .risk-card {{
    border-radius: 8px;
    padding: 20px 12px;
    text-align: center;
  }}
  .risk-num {{
    font-size: 36px;
    font-weight: 900;
    line-height: 1;
  }}
  .risk-label {{
    font-size: 12px;
    font-weight: 700;
    margin-top: 6px;
  }}

  /* Meta table */
  table.meta {{
    width: 100%;
    border-collapse: collapse;
  }}
  .meta-label {{
    width: 28%;
    padding: 11px 24px;
    background: #f8fafc;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: .05em;
    color: #64748b;
    border-bottom: 1px solid #e2e8f0;
    white-space: nowrap;
  }}
  .meta-value {{
    padding: 11px 24px;
    font-size: 14px;
    font-weight: 500;
    border-bottom: 1px solid #e2e8f0;
    word-break: break-all;
  }}

  /* Data table */
  table.data {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
  }}
  table.data thead th {{
    background: #1e3a8a;
    color: white;
    padding: 10px 16px;
    text-align: left;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: .05em;
  }}
  table.data td {{
    padding: 10px 16px;
    vertical-align: top;
    border-bottom: 1px solid #e2e8f0;
    font-size: 13px;
  }}
  .badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
  }}
  .mono {{
    font-family: 'SF Mono', 'Fira Code', Consolas, monospace;
    font-size: 12px;
    color: #1e3a8a;
    word-break: break-all;
  }}
  .muted {{ color: #4b5563; }}
  .empty {{
    text-align: center;
    color: #94a3b8;
    padding: 20px;
    font-style: italic;
  }}

  /* AI section */
  .ai-body {{
    padding: 20px 24px;
    border-left: 4px solid #1e3a8a;
    margin: 20px 24px;
    background: #f8fafc;
    border-radius: 0 8px 8px 0;
    line-height: 1.75;
  }}
  .ai-body h1, .ai-body h2, .ai-body h3 {{
    color: #1e3a8a;
    margin: 16px 0 6px;
  }}
  .ai-body h1 {{ font-size: 18px; }}
  .ai-body h2 {{ font-size: 16px; }}
  .ai-body h3 {{ font-size: 14px; }}
  .ai-body p  {{ margin: 8px 0; }}
  .ai-body ul, .ai-body ol {{ padding-left: 22px; margin: 8px 0; }}
  .ai-body li {{ margin: 4px 0; }}
  .ai-body code {{
    font-family: monospace;
    font-size: 12px;
    background: #e2e8f0;
    padding: 1px 5px;
    border-radius: 3px;
  }}
  .ai-body strong {{ color: #0f172a; }}

  /* Footer */
  .footer {{
    text-align: center;
    font-size: 12px;
    color: #94a3b8;
    padding: 20px 0 0;
  }}
</style>
</head>
<body>

<div class="header">
  <div class="header-badge">Mobile Application Security Report</div>
  <h1>{L['report_title']}</h1>
  <div class="header-sub">Static Analysis · AI Security Assessment &nbsp;·&nbsp; {now}</div>
</div>

<div class="content">

  <!-- § 1 App Info -->
  <div class="section">
    <div class="section-head">
      <div class="section-num">1</div>
      <div class="section-title">{L['app_info']}</div>
    </div>
    <table class="meta">
      {meta_rows}
    </table>
  </div>

  <!-- § 2 Risk Overview -->
  <div class="section">
    <div class="section-head">
      <div class="section-num">2</div>
      <div class="section-title">{L['risk']}</div>
    </div>
    <div class="risk-grid">
      {risk_cards}
    </div>
  </div>

  <!-- § 3 Permissions -->
  <div class="section">
    <div class="section-head">
      <div class="section-num">3</div>
      <div class="section-title">{perms_label} ({len(perms)})</div>
    </div>
    <table class="data">
      <thead>
        <tr>
          <th style="width:50%">{L['perm_name']}</th>
          <th>{L['perm_desc']}</th>
        </tr>
      </thead>
      <tbody>{perm_rows}</tbody>
    </table>
  </div>

  <!-- § 4 Security Issues -->
  <div class="section">
    <div class="section-head">
      <div class="section-num">4</div>
      <div class="section-title">{issues_label} ({len(issues)})</div>
    </div>
    <table class="data">
      <thead>
        <tr>
          <th style="width:9%">{L['sev']}</th>
          <th style="width:32%">{L['issue']}</th>
          <th>{L['detail']}</th>
        </tr>
      </thead>
      <tbody>{issue_rows}</tbody>
    </table>
  </div>

  <!-- § 5 AI Analysis -->
  <div class="section">
    <div class="section-head">
      <div class="section-num">5</div>
      <div class="section-title">{L['ai_title']}</div>
    </div>
    <div class="ai-body">{ai_html}</div>
  </div>

  <div class="footer">
    AI Mobile Security Scanner &nbsp;·&nbsp; MobSF v4.4.5 + Gemini 2.5 Flash
    &nbsp;·&nbsp; {e(filename)}
  </div>

</div>
</body>
</html>"""
