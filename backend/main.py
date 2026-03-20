from fastapi import FastAPI, UploadFile, BackgroundTasks, Header, Depends, HTTPException, Request, Form
from fastapi.responses import FileResponse
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
import shutil
import tempfile
import html as html_lib
import urllib.parse
import sqlite3
import smtplib
import random
import hashlib
import time
import base64
import plistlib
import zipfile as _zipfile
import string as _str_mod
from pathlib import Path
from datetime import datetime, timedelta
from dotenv import load_dotenv
from google import genai
from email.mime.text import MIMEText

load_dotenv()
app = FastAPI(title="AI Mobile Sec Scanner")


# ── Baidu Active Push ────────────────────────────────────────
_BAIDU_PUSH_TOKEN = os.getenv("BAIDU_PUSH_TOKEN", "ZFlLGrlXeVX5FYFZ")
_BAIDU_PUSH_SITE  = os.getenv("BAIDU_PUSH_SITE",  "https://www.maclechen.top")
_BAIDU_PUSH_URLS  = [
    "https://www.maclechen.top/",
    "https://www.maclechen.top/app",
    "https://www.maclechen.top/sitemap.xml",
]

async def _baidu_push():
    """Push all site URLs to Baidu on startup to accelerate indexing."""
    url = f"http://data.zz.baidu.com/urls?site={_BAIDU_PUSH_SITE}&token={_BAIDU_PUSH_TOKEN}"
    body = "\n".join(_BAIDU_PUSH_URLS)
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(url, content=body,
                                  headers={"Content-Type": "text/plain"})
            print(f"[Baidu Push] {r.text}")
    except Exception as e:
        print(f"[Baidu Push] failed: {e}")


@app.on_event("startup")
async def startup_event():
    asyncio.create_task(_baidu_push())
    # Run metadata backfill in background so startup isn't blocked
    asyncio.get_event_loop().run_in_executor(None, _backfill_metadata)

_tasks: dict = {}
_dl_tokens: dict = {}   # one-time download tokens: hex -> {slug, expires_at}

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

# ── Distribution file support ────────────────────────────────
_ALLOWED_EXTS = {"apk", "ipa", "exe", "msi", "dmg", "pkg", "deb", "rpm", "appimage", "zip"}
_PLATFORM_MAP = {
    "apk":      "android",
    "ipa":      "ios",
    "exe":      "windows",
    "msi":      "windows",
    "dmg":      "macos",
    "pkg":      "macos",
    "deb":      "linux",
    "rpm":      "linux",
    "appimage": "linux",
    "zip":      "other",
}
_PLAT_GRADIENT = {
    "android": "linear-gradient(135deg,rgba(59,130,246,.4),rgba(99,102,241,.4))",
    "ios":     "linear-gradient(135deg,rgba(139,92,246,.4),rgba(168,85,247,.4))",
    "windows": "linear-gradient(135deg,rgba(56,189,248,.4),rgba(99,102,241,.4))",
    "macos":   "linear-gradient(135deg,rgba(52,211,153,.4),rgba(16,185,129,.4))",
    "linux":   "linear-gradient(135deg,rgba(251,146,60,.4),rgba(249,115,22,.4))",
}
_PLAT_EMOJI = {"android": "🤖", "ios": "🍎", "windows": "🪟", "macos": "🍏", "linux": "🐧"}

def _fmt_name(raw: str) -> str:
    """Convert filename-style strings to readable app names."""
    if not raw:
        return ""
    # Only reformat if it looks like a filename (no spaces, has separators)
    if " " not in raw and ("-" in raw or "_" in raw):
        import re as _re
        parts = _re.split(r"[-_]+", raw)
        return " ".join(p.capitalize() for p in parts if p).strip()
    return raw

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
            CREATE TABLE IF NOT EXISTS admin_accounts (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                is_super      INTEGER DEFAULT 0,
                created_at    TEXT DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS app_releases (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                slug           TEXT UNIQUE NOT NULL,
                user_id        INTEGER NOT NULL,
                app_name       TEXT NOT NULL DEFAULT '',
                version        TEXT NOT NULL DEFAULT '',
                file_type      TEXT NOT NULL,
                file_size      INTEGER DEFAULT 0,
                description    TEXT DEFAULT '',
                created_at     TEXT DEFAULT (datetime('now')),
                expires_at     TEXT,
                max_downloads  INTEGER DEFAULT 0,
                download_count INTEGER DEFAULT 0,
                is_active      INTEGER DEFAULT 1,
                pkg_name       TEXT DEFAULT '',
                display_name   TEXT DEFAULT '',
                icon_b64       TEXT DEFAULT '',
                platform       TEXT DEFAULT '',
                is_public      INTEGER DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users_v2(id)
            );
            CREATE TABLE IF NOT EXISTS app_reviews (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                slug        TEXT NOT NULL,
                user_id     INTEGER NOT NULL,
                rating      INTEGER NOT NULL DEFAULT 5,
                comment     TEXT DEFAULT '',
                created_at  TEXT DEFAULT (datetime('now')),
                UNIQUE(slug, user_id)
            );
            CREATE TABLE IF NOT EXISTS app_likes (
                slug        TEXT NOT NULL,
                user_id     INTEGER NOT NULL,
                created_at  TEXT DEFAULT (datetime('now')),
                PRIMARY KEY(slug, user_id)
            );
        """)

def _migrate_db():
    """Add new columns to existing databases (safe to re-run)."""
    migrations = [
        "ALTER TABLE codes ADD COLUMN expires_at  TEXT",
        "ALTER TABLE codes ADD COLUMN max_uses    INTEGER DEFAULT 1",
        "ALTER TABLE codes ADD COLUMN uses_count  INTEGER DEFAULT 0",
        "ALTER TABLE codes ADD COLUMN is_revoked  INTEGER DEFAULT 0",
        "ALTER TABLE app_releases ADD COLUMN pkg_name     TEXT DEFAULT ''",
        "ALTER TABLE app_releases ADD COLUMN display_name TEXT DEFAULT ''",
        "ALTER TABLE app_releases ADD COLUMN icon_b64     TEXT DEFAULT ''",
        "ALTER TABLE app_releases ADD COLUMN platform     TEXT DEFAULT ''",
        "ALTER TABLE app_releases ADD COLUMN is_public    INTEGER DEFAULT 0",
        "ALTER TABLE app_releases ADD COLUMN category     TEXT DEFAULT ''",
        "ALTER TABLE users_v2 ADD COLUMN nickname   TEXT DEFAULT ''",
        "ALTER TABLE users_v2 ADD COLUMN bio        TEXT DEFAULT ''",
        "ALTER TABLE users_v2 ADD COLUMN avatar_b64 TEXT DEFAULT ''",
    ]
    with _db() as c:
        for sql in migrations:
            try:
                c.execute(sql)
            except Exception:
                pass  # Column already exists
        # Backfill platform for existing records that have empty platform
        c.execute("UPDATE app_releases SET platform='android' WHERE file_type='apk'  AND (platform IS NULL OR platform='')")
        c.execute("UPDATE app_releases SET platform='ios'     WHERE file_type='ipa'  AND (platform IS NULL OR platform='')")
        c.execute("UPDATE app_releases SET platform='windows' WHERE file_type IN ('exe','msi') AND (platform IS NULL OR platform='')")
        c.execute("UPDATE app_releases SET platform='macos'   WHERE file_type IN ('dmg','pkg') AND (platform IS NULL OR platform='')")
        c.execute("UPDATE app_releases SET platform='linux'   WHERE file_type IN ('deb','rpm','appimage') AND (platform IS NULL OR platform='')")
        pass  # backfill runs in startup_event after all functions are defined

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


def _seed_admin():
    """Ensure at least one admin account exists (seeded from env vars)."""
    with _db() as c:
        n = c.execute("SELECT COUNT(*) as n FROM admin_accounts").fetchone()["n"]
        if n == 0:
            c.execute(
                "INSERT OR IGNORE INTO admin_accounts (username, password_hash, is_super) VALUES (?, ?, 1)",
                (_ADMIN_USER, _hash_pw(_ADMIN_PASS)),
            )

_seed_admin()


def _make_admin_jwt(username: str) -> str:
    exp = datetime.utcnow() + timedelta(hours=8)
    return jwt.encode({"sub": username, "role": "admin", "exp": exp}, JWT_SECRET, algorithm=JWT_ALG)


def _get_admin_from_jwt(token: str) -> str | None:
    """Returns admin username if token is a valid admin JWT, else None."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        if payload.get("role") == "admin":
            return payload.get("sub", "admin")
    except Exception:
        pass
    return None


def _is_admin_jwt(token: str) -> bool:
    return _get_admin_from_jwt(token) is not None


async def _require_admin(
    request: Request,
    creds: HTTPAuthorizationCredentials = Depends(_bearer),
) -> str:
    """Returns admin username. Accepts JWT Bearer (web UI) or admin_key query param (API)."""
    if creds:
        u = _get_admin_from_jwt(creds.credentials)
        if u:
            return u
    env_key = os.getenv("ADMIN_KEY", "")
    qkey = request.query_params.get("admin_key", "")
    if env_key and qkey == env_key:
        return _ADMIN_USER
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


def _get_alipay_client():
    """Return (AliPay instance, is_sandbox). Raises 503 if not configured."""
    from alipay import AliPay as _AliPay
    app_id      = os.getenv("ALIPAY_APP_ID", "").strip()
    private_key = os.getenv("ALIPAY_PRIVATE_KEY", "").replace("\\n", "\n").strip()
    public_key  = os.getenv("ALIPAY_PUBLIC_KEY", "").replace("\\n", "\n").strip()
    sandbox     = os.getenv("ALIPAY_SANDBOX", "false").lower() == "true"
    if not app_id or not private_key or not public_key:
        raise HTTPException(status_code=503, detail="支付宝支付暂未开放，请联系管理员")
    client = _AliPay(
        appid=app_id,
        app_notify_url=None,
        app_private_key_string=private_key,
        alipay_public_key_string=public_key,
        sign_type="RSA2",
        debug=sandbox,
    )
    return client, sandbox


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

class ReviewBody(BaseModel):
    rating: int = 5
    comment: str = ""

class ProfileUpdate(BaseModel):
    nickname: str = ""
    bio: str = ""


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
    with _db() as c:
        row = c.execute(
            "SELECT password_hash FROM admin_accounts WHERE username=?", (username,)
        ).fetchone()
    if row and _verify_pw(password, row["password_hash"]):
        return {"ok": True, "token": _make_admin_jwt(username)}
    return JSONResponse({"ok": False, "error": "用户名或密码错误"}, status_code=401)


@app.get("/admin/me")
async def admin_me(admin_user: str = Depends(_require_admin)):
    return {"username": admin_user}


@app.post("/admin/change-password")
async def admin_change_password(
    current_password: str,
    new_password: str,
    admin_user: str = Depends(_require_admin),
):
    if len(new_password) < 6:
        return JSONResponse({"ok": False, "error": "新密码至少 6 位"}, status_code=400)
    with _db() as c:
        row = c.execute(
            "SELECT password_hash FROM admin_accounts WHERE username=?", (admin_user,)
        ).fetchone()
    if not row or not _verify_pw(current_password, row["password_hash"]):
        return JSONResponse({"ok": False, "error": "当前密码不正确"}, status_code=400)
    with _db() as c:
        c.execute(
            "UPDATE admin_accounts SET password_hash=? WHERE username=?",
            (_hash_pw(new_password), admin_user),
        )
    return {"ok": True}


@app.get("/admin/accounts")
async def admin_list_accounts(_: str = Depends(_require_admin)):
    with _db() as c:
        rows = c.execute(
            "SELECT username, is_super, created_at FROM admin_accounts ORDER BY id"
        ).fetchall()
    return {"accounts": [dict(r) for r in rows]}


@app.post("/admin/accounts")
async def admin_create_account(
    username: str,
    password: str,
    _: str = Depends(_require_admin),
):
    username = username.strip()
    if len(username) < 2:
        return JSONResponse({"ok": False, "error": "用户名至少 2 个字符"}, status_code=400)
    if len(password) < 6:
        return JSONResponse({"ok": False, "error": "密码至少 6 位"}, status_code=400)
    try:
        with _db() as c:
            c.execute(
                "INSERT INTO admin_accounts (username, password_hash) VALUES (?, ?)",
                (username, _hash_pw(password)),
            )
        return {"ok": True}
    except Exception:
        return JSONResponse({"ok": False, "error": "用户名已存在"}, status_code=400)


@app.delete("/admin/accounts/{username}")
async def admin_delete_account(username: str, admin_user: str = Depends(_require_admin)):
    if username == admin_user:
        return JSONResponse({"ok": False, "error": "不能删除当前登录账号"}, status_code=400)
    with _db() as c:
        row = c.execute(
            "SELECT is_super FROM admin_accounts WHERE username=?", (username,)
        ).fetchone()
        if not row:
            return JSONResponse({"ok": False, "error": "账号不存在"}, status_code=404)
        if row["is_super"]:
            return JSONResponse({"ok": False, "error": "超级管理员账号不可删除"}, status_code=400)
        c.execute("DELETE FROM admin_accounts WHERE username=?", (username,))
    return {"ok": True}


@app.get("/admin", response_class=HTMLResponse)
async def admin_page():
    """Serve the admin panel HTML."""
    html_path = os.path.join(os.path.dirname(__file__), "static", "admin.html")
    with open(html_path, encoding="utf-8") as f:
        content = f.read()
    return HTMLResponse(content=content, headers={"Cache-Control": "no-store"})


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
    return {
        "id": user["id"], "email": user["email"],
        "credits": user["credits"], "total_scans": user["total_scans"],
        "nickname": user.get("nickname") or "",
        "avatar_b64": user.get("avatar_b64") or "",
    }


# ── Payment Endpoints ───────────────────────────────────────

@app.post("/orders/create")
async def orders_create(body: OrderCreateBody, user: dict = Depends(_current_user)):
    """Create an order (alipay or usdt) and return pay_url."""
    pkg = PACKAGES.get(body.package_id)
    if not pkg:
        raise HTTPException(status_code=400, detail="Invalid package_id")
    site_url = os.getenv("SITE_URL", "http://localhost:8080").rstrip("/")
    order_no = _make_order_no()
    with _db() as c:
        c.execute(
            "INSERT INTO orders(order_no, user_id, credits, amount, pay_method) VALUES(?,?,?,?,?)",
            (order_no, user["id"], pkg["credits"], pkg["amount"], body.pay_type),
        )

    # ── Alipay ──────────────────────────────────────────────
    if body.pay_type == "alipay":
        alipay, sandbox = _get_alipay_client()
        order_str = alipay.api_alipay_trade_page_pay(
            out_trade_no=order_no,
            total_amount=str(pkg["amount"]),
            subject=f"AI扫描器 {pkg['credits']}Credits",
            return_url=f"{site_url}/payment/alipay/return",
            notify_url=f"{site_url}/payment/alipay/notify",
        )
        gateway = "https://openapi.alipaydev.com/gateway.do" if sandbox \
                  else "https://openapi.alipay.com/gateway.do"
        pay_url = f"{gateway}?{order_str}"
        return {"order_no": order_no, "pay_url": pay_url}

    # ── Cryptomus USDT ──────────────────────────────────────
    merchant = os.getenv("CRYPTOMUS_MERCHANT", "")
    api_key  = os.getenv("CRYPTOMUS_API_KEY", "")
    if not merchant or not api_key:
        raise HTTPException(status_code=503, detail="USDT支付暂未开放")
    import json as _json
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
    """Cryptomus browser redirect after payment."""
    return HTMLResponse(
        '<html><head><meta http-equiv="refresh" content="0;url=/?payment=success"></head>'
        "<body>支付成功，正在跳转...</body></html>"
    )


@app.post("/payment/alipay/notify")
async def alipay_notify(request: Request):
    """Alipay async server-to-server POST callback."""
    form = await request.form()
    data = dict(form)
    sign = data.pop("sign", None)
    data.pop("sign_type", None)
    try:
        alipay, _ = _get_alipay_client()
        verified = alipay.verify(data, sign)
    except Exception:
        return Response("fail")
    if not verified:
        return Response("fail")
    trade_status = data.get("trade_status", "")
    if trade_status not in ("TRADE_SUCCESS", "TRADE_FINISHED"):
        return Response("success")  # ack other statuses without crediting
    order_no = data.get("out_trade_no", "")
    trade_no = data.get("trade_no", "")
    with _db() as c:
        order = c.execute("SELECT * FROM orders WHERE order_no=?", (order_no,)).fetchone()
        if not order:
            return Response("fail")
        if order["status"] == "paid":
            return Response("success")  # idempotent
        c.execute(
            "UPDATE orders SET status='paid', pay_trade_no=?, paid_at=datetime('now') WHERE order_no=?",
            (trade_no, order_no),
        )
        c.execute(
            "UPDATE users_v2 SET credits=credits+?, updated_at=datetime('now') WHERE id=?",
            (order["credits"], order["user_id"]),
        )
    return Response("success")


@app.get("/payment/alipay/return")
async def alipay_return(request: Request):
    """Alipay sync browser redirect after payment — verify and redirect."""
    params = dict(request.query_params)
    sign = params.pop("sign", None)
    params.pop("sign_type", None)
    try:
        alipay, _ = _get_alipay_client()
        verified = alipay.verify(params, sign)
    except Exception:
        verified = False
    if verified:
        return HTMLResponse(
            '<html><head><meta http-equiv="refresh" content="0;url=/?payment=success"></head>'
            "<body>支付成功，正在跳转...</body></html>"
        )
    return HTMLResponse(
        '<html><head><meta http-equiv="refresh" content="0;url=/?payment=fail"></head>'
        "<body>支付验证失败，正在跳转...</body></html>"
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
        return Response(content=f.read(), media_type="image/svg+xml",
                        headers={"Cache-Control": "public, max-age=86400"})


@app.get("/baidu_verify_codeva-IaLOMzArPV.html")
async def baidu_verify():
    """Baidu HTML file verification (backup to meta tag)."""
    return Response(content="codeva-IaLOMzArPV", media_type="text/html",
                    headers={"Cache-Control": "public, max-age=86400"})


# ══════════════════════════════════════════════════════════════
# ── App Distribution Platform ────────────────────────────────
# ══════════════════════════════════════════════════════════════

DIST_DIR = Path("/app/data/releases")
DIST_DIR.mkdir(parents=True, exist_ok=True)
_SLUG_ABC = _str_mod.ascii_lowercase + _str_mod.digits


def _decode_cgbi_png(data: bytes) -> bytes:
    """Convert Apple CgBI (Xcode-crushed) PNG to standard PNG.

    Xcode's pngcrush produces PNGs with:
      - A CgBI chunk inserted before IHDR
      - IDAT compressed with raw DEFLATE (no zlib header)
      - Pixels stored as BGRA with pre-multiplied alpha
    This function reverses those transforms and returns a standard RGBA PNG.
    Returns the original bytes unchanged on any error.
    """
    import zlib as _zlib, struct as _struct
    try:
        if b'CgBI' not in data[8:20]:
            return data  # not CgBI

        # ── Parse chunks ────────────────────────────────────────
        ihdr_body = None
        idat_parts: list[bytes] = []
        off = 8
        while off + 12 <= len(data):
            length = _struct.unpack_from('>I', data, off)[0]
            tag    = data[off + 4: off + 8]
            body   = data[off + 8: off + 8 + length]
            off   += 12 + length
            if tag == b'IHDR':
                ihdr_body = body
            elif tag == b'IDAT':
                idat_parts.append(body)
            elif tag == b'IEND':
                break

        if not ihdr_body or not idat_parts:
            return data

        w, h = _struct.unpack_from('>II', ihdr_body)

        # ── Decompress — CgBI uses raw DEFLATE (wbits = -15) ────
        compressed = b''.join(idat_parts)
        try:
            raw = _zlib.decompress(compressed, -15)
        except Exception:
            raw = _zlib.decompress(compressed)   # fallback: standard zlib

        # ── Reconstruct RGBA pixels ──────────────────────────────
        row_len = w * 4          # bytes per row (no filter byte in output)
        stride  = 1 + row_len    # input row: 1 filter byte + BGRA pixels
        img_out = bytearray(h * row_len)

        for y in range(h):
            in_off      = y * stride
            filter_byte = raw[in_off]
            src         = bytearray(raw[in_off + 1: in_off + 1 + row_len])
            out_off     = y * row_len

            # Apply PNG reconstruction filter
            if filter_byte == 1:       # Sub
                for i in range(4, row_len):
                    src[i] = (src[i] + src[i - 4]) & 0xFF
            elif filter_byte == 2:     # Up
                if y > 0:
                    for i in range(row_len):
                        src[i] = (src[i] + img_out[out_off - row_len + i]) & 0xFF
            elif filter_byte == 3:     # Average
                for i in range(row_len):
                    a = src[i - 4] if i >= 4 else 0
                    b = img_out[out_off - row_len + i] if y > 0 else 0
                    src[i] = (src[i] + (a + b) // 2) & 0xFF
            elif filter_byte == 4:     # Paeth
                for i in range(row_len):
                    a = src[i - 4]                          if i >= 4 else 0
                    b = img_out[out_off - row_len + i]      if y > 0 else 0
                    c = img_out[out_off - row_len + i - 4]  if (y > 0 and i >= 4) else 0
                    p  = a + b - c
                    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                    pr = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
                    src[i] = (src[i] + pr) & 0xFF

            # Convert BGRA (pre-multiplied) → RGBA (straight alpha)
            for i in range(0, row_len, 4):
                bv, gv, rv, av = src[i], src[i+1], src[i+2], src[i+3]
                if av > 0:
                    src[i]   = min(255, rv * 255 // av)   # R
                    src[i+1] = min(255, gv * 255 // av)   # G
                    src[i+2] = min(255, bv * 255 // av)   # B
                else:
                    src[i], src[i+1], src[i+2] = rv, gv, bv
                src[i+3] = av

            img_out[out_off: out_off + row_len] = src

        # ── Re-encode as standard PNG ────────────────────────────
        def _chunk(tag: bytes, body: bytes) -> bytes:
            crc = _zlib.crc32(tag + body) & 0xFFFFFFFF
            return _struct.pack('>I', len(body)) + tag + body + _struct.pack('>I', crc)

        ihdr_new  = _struct.pack('>II', w, h) + bytes([8, 6, 0, 0, 0])  # RGBA
        # PNG IDAT requires a filter-type byte (0 = None) before every scanline
        png_rows = bytearray()
        for y in range(h):
            png_rows.append(0)   # filter type 0 (no filter)
            png_rows.extend(img_out[y * row_len: (y + 1) * row_len])
        idat_new  = _zlib.compress(bytes(png_rows), 6)

        return (b'\x89PNG\r\n\x1a\n'
                + _chunk(b'IHDR', ihdr_new)
                + _chunk(b'IDAT', idat_new)
                + _chunk(b'IEND', b''))
    except Exception:
        return data


def _resize_icon(data: bytes, size: int = 128) -> bytes:
    """Resize icon to `size x size` PNG; auto-decodes Apple CgBI format."""
    try:
        from PIL import Image
        import io
        # CgBI detection: try direct open; on failure attempt CgBI decode first
        try:
            img = Image.open(io.BytesIO(data))
            img.load()   # force decode to catch CgBI errors early
        except Exception:
            decoded = _decode_cgbi_png(data)
            if decoded is data:
                return data
            img = Image.open(io.BytesIO(decoded))
        img = img.convert("RGBA").resize((size, size), Image.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format="PNG", optimize=True)
        return buf.getvalue()
    except Exception:
        return data


def _extract_app_info(path: Path, ext: str) -> dict:
    """Extract pkg_name, display_name, version, icon_b64 from APK or IPA."""
    info = {"pkg_name": "", "display_name": "", "version": "", "icon_b64": ""}
    if ext == "apk":
        # ── Metadata via pyaxmlparser (each field in its own try/except) ──
        apk = None
        try:
            from pyaxmlparser import APK as _APK
            apk = _APK(str(path))
        except Exception:
            pass
        if apk is not None:
            try:
                info["pkg_name"] = apk.get_package() or ""
            except Exception:
                pass
            try:
                info["display_name"] = apk.get_app_name() or ""
            except Exception:
                pass
            try:
                info["version"] = apk.get_androidversion_name() or ""
            except Exception:
                pass

        # ── Icon extraction ──────────────────────────────────────────
        _DPI_RANK = {"xxxhdpi": 0, "xxhdpi": 1, "xhdpi": 2, "hdpi": 3, "mdpi": 4, "ldpi": 5}

        def _dpi_cfg_rank(cfg_str):
            s = str(cfg_str)
            for dpi, rank in _DPI_RANK.items():
                if dpi in s:
                    return rank
            return 9

        def _dpi_name_rank(name):
            for dpi, rank in _DPI_RANK.items():
                if dpi in name:
                    return rank
            return 9

        try:
            import struct as _struct
            with _zipfile.ZipFile(str(path)) as z:
                names_set = set(z.namelist())
                chosen = None

                # ── Step 1: use pyaxmlparser icon path ──────────────────
                icon_path = None
                if apk is not None:
                    try:
                        icon_path = apk.get_app_icon()
                    except Exception:
                        pass

                if icon_path and icon_path.lower().endswith(('.png', '.webp')) \
                        and icon_path in names_set:
                    chosen = icon_path

                elif icon_path and icon_path.lower().endswith('.xml') \
                        and icon_path in names_set:
                    # Adaptive icon XML — resolve via resources.arsc
                    try:
                        xml_data = z.read(icon_path)
                        res_ids = set()
                        for i in range(0, len(xml_data) - 3, 4):
                            val = _struct.unpack_from("<I", xml_data, i)[0]
                            if 0x7F000000 <= val <= 0x7FFFFFFF:
                                res_ids.add(val)
                        arsc = apk.get_android_resources()
                        best_rank = 99
                        for rid in res_ids:
                            try:
                                for cfg, fname in arsc.get_resolved_res_configs(rid):
                                    if fname.lower().endswith(('.png', '.webp')) \
                                            and fname in names_set:
                                        rank = _dpi_cfg_rank(cfg)
                                        if rank < best_rank:
                                            best_rank = rank
                                            chosen = fname
                            except Exception:
                                pass
                    except Exception:
                        pass

                # ── Step 2: fallback — standard mipmap/drawable folder scan ──
                if not chosen:
                    candidates = [
                        n for n in names_set
                        if re.search(
                            r'(mipmap|drawable)[^/]*/ic_launcher(_round)?\.(png|webp)$',
                            n, re.I)
                    ]
                    candidates.sort(
                        key=lambda n: (1 if "_round" in n else 0, _dpi_name_rank(n)))
                    if not candidates:
                        candidates = sorted(
                            [n for n in names_set
                             if re.search(r'mipmap[^/]+/\w+\.(png|webp)$', n, re.I)],
                            key=_dpi_name_rank,
                        )
                    if candidates:
                        chosen = candidates[0]

                # ── Step 3: size-based heuristic fallback ─────────────────
                if not chosen:
                    size_candidates = [
                        (z.getinfo(n).file_size, n) for n in names_set
                        if n.startswith("res/") and n.lower().endswith((".png", ".webp"))
                        and 3 * 1024 <= z.getinfo(n).file_size <= 200 * 1024
                    ]
                    if size_candidates:
                        chosen = sorted(size_candidates, reverse=True)[0][1]

                if chosen:
                    raw = z.read(chosen)
                    info["icon_b64"] = base64.b64encode(_resize_icon(raw, 128)).decode()
        except Exception:
            pass

    elif ext == "ipa":
        try:
            with _zipfile.ZipFile(str(path)) as z:
                names = z.namelist()
                pl = {}
                plists = [n for n in names
                          if re.match(r'Payload/[^/]+\.app/Info\.plist$', n)]
                if plists:
                    pdata = z.read(plists[0])
                    pl = plistlib.loads(pdata)
                    info["pkg_name"]    = pl.get("CFBundleIdentifier", "")
                    info["display_name"] = (pl.get("CFBundleDisplayName")
                                            or pl.get("CFBundleName", ""))
                    info["version"] = (pl.get("CFBundleShortVersionString")
                                       or pl.get("CFBundleVersion", ""))

                # ── Icon ────────────────────────────────────────────────
                app_dir = plists[0].rsplit("/", 1)[0] + "/" if plists else "Payload/"
                names_set = set(names)

                def _ipa_res_rank(name):
                    if "@3x" in name: return 0
                    if "@2x" in name: return 1
                    return 2

                icon_file_names = []
                for key in ("CFBundleIcons", "CFBundleIcons~ipad"):
                    bi = pl.get(key, {})
                    if isinstance(bi, dict):
                        pi = bi.get("CFBundlePrimaryIcon", {})
                        if isinstance(pi, dict):
                            icon_file_names.extend(pi.get("CFBundleIconFiles", []))
                icon_file_names.extend(pl.get("CFBundleIconFiles", []))

                suffix_ranks = [("@3x.png", 0), ("@2x.png", 1), (".png", 2), ("", 3)]
                candidates = []
                for base_name in set(icon_file_names):
                    for suffix, rank in suffix_ranks:
                        full = app_dir + base_name + suffix
                        if full in names_set:
                            candidates.append((rank, full))
                chosen = sorted(candidates)[0][1] if candidates else None

                if not chosen:
                    app_icons = [
                        n for n in names_set
                        if n.startswith(app_dir)
                        and re.search(r'AppIcon.*\.png$', n, re.I)
                        and "/PlugIns/" not in n
                    ]
                    if app_icons:
                        chosen = sorted(app_icons, key=_ipa_res_rank)[0]

                if chosen:
                    raw = z.read(chosen)
                    info["icon_b64"] = base64.b64encode(_resize_icon(raw, 128)).decode()
        except Exception:
            pass

    elif ext in ("dmg", "pkg"):
        # Extract .icns from DMG/PKG via 7z (best-effort; requires p7zip installed)
        try:
            import subprocess, tempfile, io as _io
            with tempfile.TemporaryDirectory() as tmp:
                subprocess.run(
                    ["7z", "e", str(path), f"-o{tmp}", "*.icns", "-r", "-y"],
                    capture_output=True, timeout=30,
                )
                icns_files = sorted(
                    Path(tmp).glob("*.icns"),
                    key=lambda f: f.stat().st_size, reverse=True,
                )
                if icns_files:
                    from PIL import Image as _PILImage
                    with _PILImage.open(str(icns_files[0])) as img:
                        img = img.convert("RGBA").resize((128, 128), _PILImage.LANCZOS)
                        buf = _io.BytesIO()
                        img.save(buf, format="PNG", optimize=True)
                        info["icon_b64"] = base64.b64encode(buf.getvalue()).decode()
        except Exception:
            pass

    elif ext in ("exe", "msi"):
        # ── Version info via pefile ───────────────────────────────
        try:
            import pefile as _pefile
            pe = _pefile.PE(str(path), fast_load=True)
            pe.parse_data_directories(directories=[
                _pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"],
            ])
            if hasattr(pe, "VS_VERSIONINFO"):
                for vinfo in pe.VS_VERSIONINFO:
                    if hasattr(vinfo, "StringTable"):
                        for st in vinfo.StringTable:
                            entries = {
                                k.decode("utf-8", errors="replace"): v.decode("utf-8", errors="replace")
                                for k, v in st.entries.items()
                            }
                            if not info["display_name"]:
                                info["display_name"] = (
                                    entries.get("FileDescription") or
                                    entries.get("ProductName") or ""
                                ).strip()
                            if not info["version"]:
                                info["version"] = (
                                    entries.get("ProductVersion") or
                                    entries.get("FileVersion") or ""
                                ).strip()
                            if not info["pkg_name"]:
                                info["pkg_name"] = (
                                    entries.get("OriginalFilename") or
                                    entries.get("InternalName") or ""
                                ).strip()
            pe.close()
        except Exception:
            pass
        # ── Icon via wrestool + Pillow ────────────────────────────
        try:
            import subprocess, tempfile, io as _io
            with tempfile.TemporaryDirectory() as _tmp:
                _ico_dir = Path(_tmp) / "ico"
                _ico_dir.mkdir()
                subprocess.run(
                    ["wrestool", "-x", "-t14", str(path), "-o", str(_ico_dir)],
                    capture_output=True, timeout=30,
                )
                _ico_files = sorted(
                    _ico_dir.glob("*.ico"),
                    key=lambda f: f.stat().st_size, reverse=True,
                )
                if _ico_files:
                    from PIL import Image as _PILImg
                    _img = _PILImg.open(str(_ico_files[0]))
                    # ICO may have multiple sizes; pick the largest
                    _frames = []
                    try:
                        for _i in range(getattr(_img, "n_frames", 1)):
                            _img.seek(_i)
                            _frames.append((_img.size[0], _i))
                    except Exception:
                        pass
                    if _frames:
                        _img.seek(sorted(_frames, reverse=True)[0][1])
                    _buf = _io.BytesIO()
                    _img.convert("RGBA").resize((128, 128), _PILImg.LANCZOS).save(_buf, "PNG", optimize=True)
                    info["icon_b64"] = base64.b64encode(_buf.getvalue()).decode()
        except Exception:
            pass

    return info

def _gen_slug(n: int = 8) -> str:
    return ''.join(random.choices(_SLUG_ABC, k=n))

def _backfill_metadata():
    """Re-extract version/icon/name for existing records that are missing them.
    Called from startup_event so _extract_app_info is guaranteed to be defined."""
    try:
        with _db() as c:
            stale = c.execute(
                "SELECT slug, file_type, app_name, display_name, version FROM app_releases"
                " WHERE is_active=1"
                " AND (version='' OR version IS NULL OR icon_b64='' OR icon_b64 IS NULL"
                " OR display_name='' OR display_name IS NULL)"
            ).fetchall()
        _dist_dir = Path("/app/data/releases")
        for row in stale:
            slug, ext = row["slug"], row["file_type"]
            app_name = row["app_name"] or ""
            fpath = _dist_dir / f"{slug}.{ext}"
            if not fpath.exists():
                continue
            try:
                meta = _extract_app_info(fpath, ext)
                # Fallback: extract version from app_name (original filename) for EXE/DMG
                if not meta["version"] and app_name:
                    m = re.search(r'[._\-](\d+(?:[._\-]\d+){1,3})', app_name)
                    if m:
                        meta["version"] = m.group(1).replace('_', '.').replace('-', '.')
                # Fallback: format display_name from app_name if extraction gave nothing
                if not meta["display_name"] and app_name:
                    meta["display_name"] = _fmt_name(app_name)
                with _db() as c2:
                    c2.execute(
                        "UPDATE app_releases SET"
                        " version=CASE WHEN ?!='' THEN ? ELSE version END,"
                        " icon_b64=CASE WHEN ?!='' THEN ? ELSE icon_b64 END,"
                        " display_name=CASE WHEN ?!='' THEN ? ELSE display_name END,"
                        " pkg_name=CASE WHEN ?!='' THEN ? ELSE pkg_name END"
                        " WHERE slug=?",
                        (meta["version"], meta["version"],
                         meta["icon_b64"], meta["icon_b64"],
                         meta["display_name"], meta["display_name"],
                         meta["pkg_name"], meta["pkg_name"],
                         slug),
                    )
                print("[backfill] %s.%s: ver=%r display=%r icon=%s" % (
                    slug, ext, meta["version"], meta["display_name"], bool(meta["icon_b64"])))
            except Exception as e:
                print("[backfill] %s.%s error: %s" % (slug, ext, e))
    except Exception as e:
        print("[backfill] failed: %s" % e)

def _fmt_size(n: int) -> str:
    if n >= 1024**2: return f"{n/1024**2:.1f} MB"
    if n >= 1024:    return f"{n/1024:.1f} KB"
    return f"{n} B"

def _dist_expired(r: dict) -> bool:
    if not r.get('expires_at'): return False
    try:
        return datetime.fromisoformat(r['expires_at']) < datetime.now()
    except Exception:
        return False

def _dist_exhausted(r: dict) -> bool:
    m = r.get('max_downloads', 0)
    return m > 0 and r.get('download_count', 0) >= m

def _dist_preview_html(r: dict) -> str:
    site         = os.getenv("SITE_URL", "https://maclechen.top")
    slug         = r['slug']
    app_name     = html_lib.escape(r.get('app_name') or r.get('display_name') or '未命名应用')
    display_name = html_lib.escape(r.get('display_name') or '')
    pkg_name     = html_lib.escape(r.get('pkg_name') or '')
    version      = r.get('version') or ''
    description  = html_lib.escape(r.get('description') or '')
    file_type    = r['file_type'].upper()
    platform     = r.get('platform') or _PLATFORM_MAP.get(r['file_type'].lower(), 'other')
    size_str     = _fmt_size(r.get('file_size', 0))
    dl_count     = r.get('download_count', 0)
    max_dl       = r.get('max_downloads', 0)
    icon_b64     = r.get('icon_b64') or ''
    page_url     = f"{site}/dist/{slug}"
    dl_url       = f"{site}/dist/{slug}/download"
    qr_url       = f"https://api.qrserver.com/v1/create-qr-code/?size=240x240&data={urllib.parse.quote(page_url, safe='')}&ecc=H&margin=8"
    _BADGE_COLORS = {
        "android": ("#3b82f6", "rgba(59,130,246,.2)", "rgba(59,130,246,.4)"),
        "ios":     ("#a78bfa", "rgba(139,92,246,.2)", "rgba(139,92,246,.4)"),
        "windows": ("#38bdf8", "rgba(56,189,248,.2)", "rgba(56,189,248,.4)"),
        "macos":   ("#34d399", "rgba(52,211,153,.2)", "rgba(52,211,153,.4)"),
        "linux":   ("#fb923c", "rgba(251,146,60,.2)",  "rgba(251,146,60,.4)"),
    }
    badge_col, badge_bg, badge_brd = _BADGE_COLORS.get(platform, ("#94a3b8", "rgba(148,163,184,.2)", "rgba(148,163,184,.4)"))
    # Icon html: base64 image or gradient placeholder
    if icon_b64:
        icon_html = f'<img src="data:image/png;base64,{icon_b64}" class="app-icon-img" alt="icon">'
    else:
        icon_html = '<div class="app-icon-placeholder">📱</div>'
    ver_html     = f'<div class="app-version">v{html_lib.escape(version)}</div>' if version else ''
    pkg_html     = f'<div class="app-pkg">{pkg_name}</div>' if pkg_name else ''
    desc_html    = f'<div class="app-desc">{description}</div>' if description else ''
    expires_at  = r.get('expires_at')
    if expires_at:
        try:
            exp = datetime.fromisoformat(expires_at)
            remaining = (exp - datetime.now()).days
            if remaining < 0:   exp_html = '<span style="color:#f87171">已过期</span>'
            elif remaining == 0: exp_html = '<span style="color:#fbbf24">今天过期</span>'
            else:                exp_html = f'<span style="color:#34d399">{remaining} 天后过期</span>'
        except Exception:
            exp_html = html_lib.escape(expires_at[:10])
    else:
        exp_html = '<span style="color:#34d399">永不过期</span>'
    dl_html      = f'{dl_count} / {max_dl} 次' if max_dl > 0 else f'{dl_count} 次'
    created_at   = r.get('created_at') or ''
    upload_html  = html_lib.escape(created_at[:16].replace('T', ' ')) if created_at else '—'
    expired    = _dist_expired(r)
    exhausted  = _dist_exhausted(r)
    unavail    = expired or exhausted or not r.get('is_active', 1)
    btn_html   = (
        '<div class="dl-btn disabled">⚠️ 链接已失效</div>'
        if unavail else
        f'<button class="dl-btn" id="dl-btn" onclick="handleDownload()">⬇️ 点击下载 {file_type}</button>'
    )
    # page_url_enc for use inside JS (no f-string conflict)
    page_url_enc = urllib.parse.quote(page_url, safe='')
    # Platform display name
    plat_name = {"android":"Android","ios":"iOS","windows":"Windows","macos":"macOS","linux":"Linux"}.get(platform, file_type)
    # Platform gradient colors
    plat_grad = {"android":"135deg,#22c55e,#16a34a","ios":"135deg,#a78bfa,#7c3aed",
                 "windows":"135deg,#38bdf8,#0284c7","macos":"135deg,#34d399,#059669",
                 "linux":"135deg,#fb923c,#ea580c"}.get(platform,"135deg,#60a5fa,#3b82f6")
    # Platform placeholder emoji (pre-computed to avoid nested dict in f-string)
    plat_emoji = {"android":"🤖","ios":"🍏","windows":"🪟","macos":"🍎","linux":"🐧"}.get(platform,"📦")
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{app_name}{' v'+html_lib.escape(version) if version else ''} — 下载</title>
  <meta name="robots" content="noindex,nofollow">
  <link rel="icon" href="{site}/favicon.svg" type="image/svg+xml">
  <style>
    *,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
          background:#060c1a;color:#e2e8f0;min-height:100vh;
          display:flex;flex-direction:column;align-items:center;padding:32px 16px 48px}}
    /* ── Page wrapper ── */
    .page{{width:100%;max-width:860px}}
    /* ── Header bar ── */
    .topbar{{display:flex;align-items:center;justify-content:space-between;
             margin-bottom:28px}}
    .brand{{display:flex;align-items:center;gap:8px;text-decoration:none;color:#94a3b8;
            font-size:.82em}}
    .brand img{{width:22px;height:22px;opacity:.8}}
    /* ── Main card ── */
    .main-card{{background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.08);
                border-radius:24px;overflow:hidden;
                box-shadow:0 24px 80px rgba(0,0,0,.5),0 0 0 1px rgba(255,255,255,.04)}}
    /* ── Hero banner ── */
    .hero{{background:linear-gradient({plat_grad});
           padding:36px 40px 32px;display:flex;align-items:flex-start;gap:28px;
           position:relative;overflow:hidden}}
    .hero::after{{content:'';position:absolute;inset:0;
                  background:radial-gradient(ellipse at top left,rgba(255,255,255,.12) 0%,transparent 60%);
                  pointer-events:none}}
    .hero-icon{{flex-shrink:0;width:100px;height:100px;border-radius:24px;
                box-shadow:0 8px 32px rgba(0,0,0,.4),0 0 0 3px rgba(255,255,255,.2);
                overflow:hidden;background:rgba(255,255,255,.12)}}
    .hero-icon img{{width:100%;height:100%;object-fit:cover;display:block}}
    .hero-icon-ph{{width:100%;height:100%;display:flex;align-items:center;
                   justify-content:center;font-size:3em}}
    .hero-info{{flex:1;min-width:0}}
    .hero-badges{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}}
    .badge{{display:inline-flex;align-items:center;gap:4px;padding:3px 12px;
            border-radius:20px;font-size:.7em;font-weight:700;letter-spacing:.05em;
            background:rgba(255,255,255,.18);color:white;border:1px solid rgba(255,255,255,.28);
            backdrop-filter:blur(4px)}}
    .hero-name{{font-size:1.7em;font-weight:900;color:white;letter-spacing:-.02em;
                line-height:1.2;word-break:break-word}}
    .hero-version{{font-size:.9em;color:rgba(255,255,255,.7);margin-top:6px;font-weight:500}}
    .hero-pkg{{font-size:.75em;color:rgba(255,255,255,.55);margin-top:4px;
               font-family:'SF Mono',monospace;word-break:break-all}}
    /* ── Body: two columns ── */
    .body{{display:grid;grid-template-columns:1fr 280px;gap:0}}
    @media(max-width:640px){{
      .hero{{flex-direction:column;gap:20px;padding:28px 24px}}
      .hero-icon{{width:80px;height:80px}}
      .hero-name{{font-size:1.4em}}
      .body{{grid-template-columns:1fr}}
      .sidebar{{border-left:none!important;border-top:1px solid rgba(255,255,255,.07)}}
    }}
    /* ── Left: main content ── */
    .content{{padding:32px 36px;border-right:1px solid rgba(255,255,255,.07)}}
    @media(max-width:640px){{.content{{padding:24px 20px}}}}
    /* Description */
    .section-label{{font-size:.7em;font-weight:700;letter-spacing:.1em;text-transform:uppercase;
                    color:#475569;margin-bottom:10px}}
    .desc-box{{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);
               border-radius:12px;padding:16px;font-size:.88em;color:#94a3b8;
               line-height:1.7;white-space:pre-wrap;word-break:break-word}}
    /* Meta grid */
    .meta-grid{{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:24px}}
    @media(max-width:400px){{.meta-grid{{grid-template-columns:1fr}}}}
    .meta-item{{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);
                border-radius:12px;padding:14px 16px}}
    .meta-item-label{{font-size:.7em;color:#475569;font-weight:600;letter-spacing:.06em;
                      text-transform:uppercase;margin-bottom:4px}}
    .meta-item-val{{font-size:.9em;color:#cbd5e1;font-weight:600}}
    /* AI promo */
    .ai-promo{{margin-top:24px;background:linear-gradient(135deg,rgba(99,102,241,.07),rgba(139,92,246,.07));
               border:1px solid rgba(99,102,241,.2);border-radius:14px;padding:20px}}
    .ai-promo-hd{{font-size:.9em;font-weight:800;margin-bottom:5px;
                  background:linear-gradient(135deg,#60a5fa,#a78bfa);
                  -webkit-background-clip:text;-webkit-text-fill-color:transparent}}
    .ai-promo-copy{{font-size:.8em;color:#64748b;margin-bottom:12px;line-height:1.5}}
    .ai-feats{{list-style:none;display:flex;flex-direction:column;gap:4px;margin-bottom:12px}}
    .ai-feats li{{font-size:.78em;color:#94a3b8}}
    .ai-cta{{display:inline-block;background:linear-gradient(135deg,#6366f1,#8b5cf6);
             color:white!important;padding:9px 20px;border-radius:8px;font-size:.82em;
             font-weight:800;text-decoration:none!important;transition:opacity .2s}}
    .ai-cta:hover{{opacity:.85}}
    /* ── Sidebar ── */
    .sidebar{{padding:28px 24px;display:flex;flex-direction:column;gap:20px}}
    /* Download button */
    .dl-btn{{width:100%;padding:15px;border-radius:14px;
             background:linear-gradient(135deg,#3b82f6,#7c3aed);color:white;border:none;
             font-size:1em;font-weight:800;cursor:pointer;text-align:center;
             box-shadow:0 8px 28px rgba(59,130,246,.35);transition:opacity .2s,transform .1s;
             display:block;text-decoration:none}}
    .dl-btn:hover{{opacity:.9;transform:translateY(-1px)}}
    .dl-btn:active{{transform:translateY(0)}}
    .dl-btn.disabled{{background:rgba(255,255,255,.07);color:#475569;
                      box-shadow:none;cursor:default;transform:none}}
    /* Copy link */
    .copy-wrap{{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07);
                border-radius:10px;padding:10px 12px;cursor:pointer;
                display:flex;align-items:center;gap:8px}}
    .copy-wrap:hover{{background:rgba(255,255,255,.06)}}
    .copy-url{{flex:1;font-size:.72em;color:#64748b;overflow:hidden;
               text-overflow:ellipsis;white-space:nowrap;font-family:monospace}}
    .copy-icon{{flex-shrink:0;font-size:.9em;color:#475569}}
    /* QR */
    .qr-box{{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);
             border-radius:14px;padding:16px;text-align:center}}
    .qr-box-title{{font-size:.72em;color:#475569;margin-bottom:12px;font-weight:600;
                   text-transform:uppercase;letter-spacing:.08em}}
    .qr-container{{position:relative;display:inline-block}}
    .qr-container img.qr-img{{width:160px;height:160px;border-radius:10px;display:block}}
    .qr-logo{{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);
              width:38px;height:38px;background:white;border-radius:8px;padding:3px;
              display:flex;align-items:center;justify-content:center;
              box-shadow:0 2px 8px rgba(0,0,0,.4)}}
    .qr-logo img{{width:30px;height:30px}}
    .qr-hint{{font-size:.7em;color:#475569;margin-top:8px}}
    /* ── Overlay modals ── */
    .overlay{{display:none;position:fixed;inset:0;z-index:200;
              background:rgba(6,12,26,.85);backdrop-filter:blur(10px);
              align-items:center;justify-content:center;padding:20px}}
    .overlay.show{{display:flex}}
    .ov-card{{background:#0f172a;border:1px solid rgba(255,255,255,.12);
              border-radius:22px;padding:40px 32px;max-width:360px;width:100%;
              text-align:center;box-shadow:0 32px 80px rgba(0,0,0,.7)}}
    .ov-icon{{font-size:2.8em;margin-bottom:16px}}
    .ov-title{{font-size:1.2em;font-weight:800;margin-bottom:10px;
               background:linear-gradient(135deg,#60a5fa,#a78bfa);
               -webkit-background-clip:text;-webkit-text-fill-color:transparent}}
    .ov-body{{font-size:.88em;color:#94a3b8;margin-bottom:26px;line-height:1.65}}
    .ov-btn{{display:block;width:100%;padding:13px;border-radius:11px;
             font-size:.95em;font-weight:800;text-decoration:none;
             cursor:pointer;border:none;margin-bottom:10px}}
    .ov-btn-primary{{background:linear-gradient(135deg,#3b82f6,#8b5cf6);color:white;
                     box-shadow:0 6px 20px rgba(59,130,246,.3)}}
    .ov-btn-secondary{{background:rgba(255,255,255,.06);color:#94a3b8;
                       border:1px solid rgba(255,255,255,.1)}}
    .ov-btn:hover{{opacity:.85}}
    /* ── Footer ── */
    .footer{{margin-top:28px;font-size:.75em;color:#334155;
             display:flex;align-items:center;gap:6px;justify-content:center}}
    .footer a{{color:#3b82f6;text-decoration:none;display:flex;align-items:center;gap:5px}}
    .footer img{{width:16px;height:16px;opacity:.6}}
    /* ── Social stats bar ── */
    .social-stats{{display:flex;align-items:center;gap:18px;margin-top:14px;flex-wrap:wrap}}
    .sstat{{display:flex;align-items:center;gap:5px;font-size:.82em;
             color:rgba(255,255,255,.7);font-weight:600}}
    .sstat-val{{font-weight:800;color:white}}
    .sstat-sep{{width:1px;height:14px;background:rgba(255,255,255,.25)}}
    /* ── Like button ── */
    .like-btn{{width:100%;padding:12px;border-radius:12px;border:1px solid rgba(255,255,255,.12);
               background:rgba(255,255,255,.05);color:#94a3b8;font-size:.9em;font-weight:700;
               cursor:pointer;display:flex;align-items:center;justify-content:center;gap:8px;
               transition:all .2s}}
    .like-btn:hover{{background:rgba(248,113,113,.1);border-color:rgba(248,113,113,.35);color:#f87171}}
    .like-btn.liked{{background:rgba(248,113,113,.15);border-color:rgba(248,113,113,.45);color:#f87171}}
    .like-btn .heart{{font-size:1.1em;transition:transform .15s}}
    .like-btn.liked .heart{{transform:scale(1.2)}}
    /* ── Reviews ── */
    .reviews-section{{margin-top:28px;padding-top:24px;border-top:1px solid rgba(255,255,255,.06)}}
    .reviews-hd{{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}}
    .reviews-title{{font-size:.82em;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#475569}}
    .avg-stars{{display:flex;align-items:center;gap:6px;font-size:.85em;color:#fbbf24;font-weight:700}}
    /* Star rating input */
    .star-row{{display:flex;gap:4px;margin-bottom:10px}}
    .star-pick{{font-size:1.6em;cursor:pointer;color:#334155;transition:color .1s;user-select:none}}
    .star-pick.on{{color:#fbbf24}}
    .review-textarea{{width:100%;background:rgba(255,255,255,.04);border:1px solid rgba(255,255,255,.1);
                      border-radius:10px;padding:12px;color:#e2e8f0;font-size:.88em;
                      resize:vertical;min-height:80px;font-family:inherit;line-height:1.6}}
    .review-textarea:focus{{outline:none;border-color:rgba(99,102,241,.5)}}
    .review-submit{{margin-top:10px;width:100%;padding:11px;border-radius:10px;border:none;
                    background:linear-gradient(135deg,#6366f1,#8b5cf6);color:white;
                    font-size:.88em;font-weight:800;cursor:pointer;transition:opacity .2s}}
    .review-submit:hover{{opacity:.85}}
    .review-login-prompt{{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.07);
                           border-radius:12px;padding:16px;text-align:center;margin-bottom:16px}}
    .review-login-prompt a{{color:#60a5fa;text-decoration:none;font-weight:700}}
    /* Review cards */
    .review-card{{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.06);
                  border-radius:14px;padding:16px;margin-bottom:12px}}
    .review-card.mine{{border-color:rgba(99,102,241,.35);background:rgba(99,102,241,.05)}}
    .review-top{{display:flex;align-items:flex-start;gap:12px;margin-bottom:10px}}
    .av-circle{{width:40px;height:40px;border-radius:50%;flex-shrink:0;overflow:hidden;
                display:flex;align-items:center;justify-content:center;
                font-size:.9em;font-weight:800;color:white}}
    .av-circle img{{width:100%;height:100%;object-fit:cover}}
    .review-meta{{flex:1;min-width:0}}
    .review-nick{{font-size:.88em;font-weight:700;color:#cbd5e1}}
    .review-date{{font-size:.72em;color:#475569;margin-top:1px}}
    .review-stars{{display:flex;gap:2px;margin-top:4px}}
    .rstar{{font-size:.85em;color:#fbbf24}}
    .rstar.empty{{color:#334155}}
    .review-comment{{font-size:.85em;color:#94a3b8;line-height:1.65;white-space:pre-wrap;word-break:break-word}}
    .review-actions{{display:flex;gap:8px;margin-top:10px}}
    .review-act-btn{{font-size:.75em;color:#475569;background:none;border:none;cursor:pointer;padding:0}}
    .review-act-btn:hover{{color:#94a3b8}}
    .empty-reviews{{text-align:center;padding:32px;color:#334155;font-size:.88em}}
    .review-form-wrap{{background:rgba(255,255,255,.03);border:1px solid rgba(255,255,255,.08);
                        border-radius:14px;padding:18px;margin-bottom:20px}}
    .review-form-title{{font-size:.78em;font-weight:700;color:#64748b;margin-bottom:12px;
                        text-transform:uppercase;letter-spacing:.08em}}
  </style>
</head>
<body>
  <!-- Login overlay -->
  <div class="overlay" id="ov-login">
    <div class="ov-card">
      <div class="ov-icon">🔐</div>
      <div class="ov-title">登录后即可下载</div>
      <div class="ov-body">请先登录或注册账号，下载无需消耗次数（仅非上传者需要 1 Credit）</div>
      <a class="ov-btn ov-btn-primary" href="{site}/app?action=login&return={page_url_enc}">登录账号</a>
      <a class="ov-btn ov-btn-secondary" href="{site}/app?action=register&return={page_url_enc}">注册账号</a>
    </div>
  </div>
  <!-- Credits overlay -->
  <div class="overlay" id="ov-credits">
    <div class="ov-card">
      <div class="ov-icon">💳</div>
      <div class="ov-title">Credits 不足</div>
      <div class="ov-body">每次下载消耗 1 Credit，购买套餐即可获得 Credits，上传者下载免费</div>
      <a class="ov-btn ov-btn-primary" href="{site}/app?action=buy&return={page_url_enc}">立即购买 Credits</a>
      <button class="ov-btn ov-btn-secondary" onclick="document.getElementById('ov-credits').classList.remove('show')">取消</button>
    </div>
  </div>

  <div class="page">
    <!-- Top bar -->
    <div class="topbar">
      <a class="brand" href="{site}" target="_blank" rel="noopener">
        <img src="{site}/favicon.svg" alt="logo"> AppSec AI
      </a>
      <span style="font-size:.75em;color:#334155">安全应用分发平台</span>
    </div>

    <!-- Main card -->
    <div class="main-card">
      <!-- Hero -->
      <div class="hero">
        <div class="hero-icon">
          {f'<img src="data:image/png;base64,{icon_b64}" alt="icon">' if icon_b64 else f'<div class="hero-icon-ph">{plat_emoji}</div>'}
        </div>
        <div class="hero-info">
          <div class="hero-badges">
            <span class="badge">{plat_name}</span>
            <span class="badge">{file_type}</span>
          </div>
          <div class="hero-name">{app_name}</div>
          {f'<div class="hero-version">版本 {html_lib.escape(version)}</div>' if version else ''}
          {f'<div class="hero-pkg">{pkg_name}</div>' if pkg_name else ''}
          <div class="social-stats">
            <div class="sstat">❤ <span class="sstat-val" id="ss-likes">…</span> 喜欢</div>
            <div class="sstat-sep"></div>
            <div class="sstat" id="ss-avg-wrap">★ <span class="sstat-val" id="ss-avg">…</span></div>
            <div class="sstat-sep"></div>
            <div class="sstat"><span class="sstat-val" id="ss-cnt">…</span> 条评价</div>
          </div>
        </div>
      </div>

      <!-- Body -->
      <div class="body">
        <!-- Left: content -->
        <div class="content">
          {f'''<div class="section-label">应用介绍</div>
          <div class="desc-box">{description}</div>''' if description else ''}

          <div class="meta-grid" style="{'margin-top:0' if not description else ''}">
            {f'<div class="meta-item"><div class="meta-item-label">版本</div><div class="meta-item-val">v{html_lib.escape(version)}</div></div>' if version else ''}
            <div class="meta-item"><div class="meta-item-label">文件大小</div><div class="meta-item-val">{size_str}</div></div>
            <div class="meta-item"><div class="meta-item-label">下载次数</div><div class="meta-item-val">{dl_html}</div></div>
            <div class="meta-item"><div class="meta-item-label">上传时间</div><div class="meta-item-val">{upload_html}</div></div>
            <div class="meta-item"><div class="meta-item-label">有效期</div><div class="meta-item-val">{exp_html}</div></div>
          </div>

          <div class="ai-promo">
            <div class="ai-promo-hd">🔍 AppSec AI 安全扫描</div>
            <div class="ai-promo-copy">使用 AI 深度检测此应用的安全风险，保护你的用户</div>
            <ul class="ai-feats">
              <li>✓ 深度漏洞扫描 &amp; CVE 检测</li>
              <li>✓ 隐私数据追踪 &amp; 合规分析</li>
              <li>✓ 恶意行为 &amp; 后门识别</li>
            </ul>
            <a class="ai-cta" href="{site}" target="_blank" rel="noopener">免费扫描此应用 →</a>
          </div>

          <!-- Reviews section -->
          <div class="reviews-section">
            <div class="reviews-hd">
              <div class="reviews-title">用户评价</div>
              <div class="avg-stars" id="avg-stars-display" style="display:none">
                <span id="avg-stars-text"></span>
              </div>
            </div>
            <!-- Review form (filled by JS) -->
            <div id="review-form-area"></div>
            <!-- Reviews list -->
            <div id="reviews-list"></div>
          </div>
        </div>

        <!-- Right: sidebar -->
        <div class="sidebar">
          {btn_html}
          <!-- Like button -->
          <button class="like-btn" id="like-btn" onclick="toggleLike()">
            <span class="heart">♥</span>
            <span id="like-btn-text">喜欢</span>
            <span id="like-btn-count"></span>
          </button>
          <div class="copy-wrap" onclick="copyLink()" title="复制链接">
            <span class="copy-url" id="lnk">{page_url}</span>
            <span class="copy-icon">📋</span>
          </div>
          <div class="qr-box">
            <div class="qr-box-title">📱 扫码访问</div>
            <div class="qr-container">
              <img class="qr-img" src="{qr_url}" alt="扫码下载" loading="lazy">
              <div class="qr-logo">{f'<img src="data:image/png;base64,{icon_b64}" alt="logo" style="border-radius:18%">' if icon_b64 else f'<img src="{site}/favicon.svg" alt="logo">'}</div>
            </div>
            <div class="qr-hint">手机扫码直接访问</div>
          </div>
        </div>
      </div>
    </div>

    <div class="footer">
      Powered by
      <a href="{site}" target="_blank" rel="noopener">
        <img src="{site}/favicon.svg" alt="logo"> AppSec AI
      </a>
    </div>
  </div>

  <script>
  // ── Utilities ───────────────────────────────────────────────
  const _jwt = () => localStorage.getItem('jwt') || '';
  const _authHdr = () => _jwt() ? {{'Authorization':'Bearer '+_jwt()}} : {{}};

  function copyLink(){{
    navigator.clipboard.writeText('{page_url}').then(()=>{{
      const el=document.getElementById('lnk');
      el.textContent='✅ 链接已复制！';
      setTimeout(()=>el.textContent='{page_url}',2000);
    }});
  }}

  // ── Download ─────────────────────────────────────────────────
  async function handleDownload(){{
    const btn = document.getElementById('dl-btn');
    btn.disabled = true; btn.textContent = '⏳ 准备中…';
    try {{
      const resp = await fetch('/dist/{slug}/request-download', {{
        method: 'POST', headers: _authHdr()
      }});
      if (resp.status === 401) {{
        document.getElementById('ov-login').classList.add('show');
        btn.disabled=false; btn.textContent='⬇️ 点击下载 {file_type}'; return;
      }}
      if (resp.status === 402) {{
        document.getElementById('ov-credits').classList.add('show');
        btn.disabled=false; btn.textContent='⬇️ 点击下载 {file_type}'; return;
      }}
      if (!resp.ok) {{
        const err = await resp.json().catch(()=>({{detail:'下载失败，请稍后重试'}}));
        alert(err.detail||'下载失败，请稍后重试');
        btn.disabled=false; btn.textContent='⬇️ 点击下载 {file_type}'; return;
      }}
      const data = await resp.json();
      btn.textContent='✅ 开始下载…';
      window.location.href='/dist/{slug}/download?token='+data.token;
      setTimeout(()=>{{btn.disabled=false;btn.textContent='⬇️ 点击下载 {file_type}';}},3000);
    }} catch(e){{
      alert('网络错误，请稍后重试');
      btn.disabled=false; btn.textContent='⬇️ 点击下载 {file_type}';
    }}
  }}

  // ── Avatar helper ────────────────────────────────────────────
  const _AV_COLORS=['#6366f1','#8b5cf6','#0ea5e9','#10b981','#f59e0b','#ef4444'];
  function avatarHtml(nick, av64){{
    if(av64) return `<img src="data:image/png;base64,${{av64}}" alt="${{nick}}" style="width:100%;height:100%;object-fit:cover;display:block">`;
    const ch=(nick||'U')[0].toUpperCase();
    const col=_AV_COLORS[(nick||'U').charCodeAt(0)%_AV_COLORS.length];
    return `<span style="background:${{col}};width:100%;height:100%;display:flex;align-items:center;justify-content:center">${{ch}}</span>`;
  }}

  // ── Stars render ─────────────────────────────────────────────
  function starsHtml(n, cls='rstar'){{
    return [1,2,3,4,5].map(i=>`<span class="${{cls}}${{i<=n?'':' empty'}}">★</span>`).join('');
  }}

  // ── Social data ──────────────────────────────────────────────
  let _myRating = 5;
  let _liked = false;

  async function loadSocial(){{
    try{{
      const resp = await fetch('/dist/{slug}/reviews', {{headers: _authHdr()}});
      if(!resp.ok) return;
      const d = await resp.json();
      renderSocial(d);
    }}catch(e){{}}
  }}

  function renderSocial(d){{
    // Stats bar
    document.getElementById('ss-likes').textContent = d.likes;
    document.getElementById('ss-cnt').textContent = d.count;
    const avgWrap = document.getElementById('ss-avg-wrap');
    if(d.avg){{
      document.getElementById('ss-avg').textContent = d.avg+'★';
    }}else{{
      avgWrap.style.display='none';
      document.querySelector('.sstat-sep')&&(()=>{{
        const seps=document.querySelectorAll('.sstat-sep');
        if(seps.length>0) seps[0].style.display='none';
      }})();
    }}
    // Like button
    _liked = d.liked;
    updateLikeBtn(d.likes, d.liked);
    // Avg display in reviews header
    if(d.avg){{
      const ad=document.getElementById('avg-stars-display');
      ad.style.display='flex';
      document.getElementById('avg-stars-text').innerHTML=starsHtml(Math.round(d.avg))+` ${{d.avg}}`;
    }}
    // Review form area
    const fa=document.getElementById('review-form-area');
    if(_jwt()){{
      const mr=d.my_review;
      if(mr) _myRating=mr.rating;
      fa.innerHTML=`
        <div class="review-form-wrap">
          <div class="review-form-title">${{mr?'修改你的评价':'写评价'}}</div>
          <div class="star-row" id="star-row">
            ${{[1,2,3,4,5].map(i=>`<span class="star-pick${{i<=_myRating?' on':''}}" onclick="setRating(${{i}})" onmouseover="hoverRating(${{i}})" onmouseout="resetRating()">★</span>`).join('')}}
          </div>
          <textarea class="review-textarea" id="review-text" placeholder="分享你对这个应用的看法（选填）..." maxlength="500">${{mr?mr.comment:''}}</textarea>
          <button class="review-submit" onclick="submitReview()">${{mr?'更新评价':'发布评价'}}</button>
          ${{mr?`<button class="review-act-btn" onclick="deleteReview()" style="margin-top:8px;display:block;font-size:.78em;color:#475569">删除我的评价</button>`:''}}
        </div>`;
    }}else{{
      fa.innerHTML=`<div class="review-login-prompt">
        <a href="{site}/app?action=login&return={page_url_enc}">登录</a> 后发表评价
      </div>`;
    }}
    // Reviews list
    const rl=document.getElementById('reviews-list');
    if(!d.reviews.length){{
      rl.innerHTML='<div class="empty-reviews">暂无评价，成为第一个评价者 ✨</div>';
      return;
    }}
    rl.innerHTML=d.reviews.map(r=>`
      <div class="review-card${{r.is_mine?' mine':''}}">
        <div class="review-top">
          <div class="av-circle">${{avatarHtml(r.nickname,r.avatar_b64)}}</div>
          <div class="review-meta">
            <div class="review-nick">${{r.nickname}}${{r.is_mine?' <span style="font-size:.7em;color:#6366f1;font-weight:700">（我）</span>':''}}</div>
            <div class="review-stars">${{starsHtml(r.rating)}}</div>
            <div class="review-date">${{r.created_at}}</div>
          </div>
        </div>
        ${{r.comment?`<div class="review-comment">${{r.comment}}</div>`:''}}
      </div>`).join('');
  }}

  // ── Like toggle ───────────────────────────────────────────────
  function updateLikeBtn(count, liked){{
    const btn=document.getElementById('like-btn');
    const txt=document.getElementById('like-btn-text');
    const cnt=document.getElementById('like-btn-count');
    btn.classList.toggle('liked', liked);
    txt.textContent=liked?'已喜欢':'喜欢';
    cnt.textContent=count>0?`(${{count}})`:''
  }}

  async function toggleLike(){{
    if(!_jwt()){{
      document.getElementById('ov-login').classList.add('show'); return;
    }}
    try{{
      const r=await fetch('/dist/{slug}/like',{{method:'POST',headers:_authHdr()}});
      if(r.ok){{
        const d=await r.json();
        _liked=d.liked;
        updateLikeBtn(d.count,d.liked);
        document.getElementById('ss-likes').textContent=d.count;
      }}
    }}catch(e){{}}
  }}

  // ── Review form ───────────────────────────────────────────────
  function setRating(n){{
    _myRating=n;
    document.querySelectorAll('.star-pick').forEach((s,i)=>
      s.classList.toggle('on',i<n));
  }}
  function hoverRating(n){{
    document.querySelectorAll('.star-pick').forEach((s,i)=>
      s.classList.toggle('on',i<n));
  }}
  function resetRating(){{
    document.querySelectorAll('.star-pick').forEach((s,i)=>
      s.classList.toggle('on',i<_myRating));
  }}

  async function submitReview(){{
    const comment=document.getElementById('review-text')?.value||'';
    try{{
      const r=await fetch('/dist/{slug}/review',{{
        method:'POST',
        headers:{{..._authHdr(),'Content-Type':'application/json'}},
        body:JSON.stringify({{rating:_myRating,comment}})
      }});
      if(r.ok) loadSocial();
    }}catch(e){{alert('提交失败，请重试');}}
  }}

  async function deleteReview(){{
    if(!confirm('确定删除你的评价？')) return;
    try{{
      const r=await fetch('/dist/{slug}/review',{{method:'DELETE',headers:_authHdr()}});
      if(r.ok) loadSocial();
    }}catch(e){{}}
  }}

  // ── Overlays & init ───────────────────────────────────────────
  document.querySelectorAll('.overlay').forEach(el=>{{
    el.addEventListener('click',e=>{{if(e.target===el)el.classList.remove('show');}});
  }});
  loadSocial();
  </script>
</body>
</html>"""


# ── User Profile ────────────────────────────────────────────

@app.get("/auth/profile")
async def get_profile(user: dict = Depends(_current_user)):
    return {
        "id": user["id"], "email": user["email"],
        "nickname": user.get("nickname") or "",
        "bio": user.get("bio") or "",
        "avatar_b64": user.get("avatar_b64") or "",
        "credits": user.get("credits", 0),
    }

@app.put("/auth/profile")
async def update_profile(body: ProfileUpdate, user: dict = Depends(_current_user)):
    nickname = body.nickname.strip()[:32]
    bio = body.bio.strip()[:200]
    with _db() as c:
        c.execute("UPDATE users_v2 SET nickname=?, bio=? WHERE id=?",
                  (nickname, bio, user["id"]))
    return {"ok": True, "nickname": nickname, "bio": bio}

@app.post("/auth/avatar")
async def update_avatar(file: UploadFile, user: dict = Depends(_current_user)):
    data = await file.read()
    if len(data) > 5 * 1024 * 1024:
        raise HTTPException(400, "图片太大（最大 5MB）")
    try:
        from PIL import Image as _PILImg, ImageOps as _PILOps
        import io as _io
        img = _PILImg.open(_io.BytesIO(data)).convert("RGBA")
        # Center-crop to square (preserves aspect ratio, no stretching), then resize
        img = _PILOps.fit(img, (160, 160), _PILImg.LANCZOS)
        buf = _io.BytesIO()
        img.save(buf, "PNG", optimize=True)
        avatar_b64 = base64.b64encode(buf.getvalue()).decode()
    except Exception:
        raise HTTPException(400, "无效的图片文件")
    with _db() as c:
        c.execute("UPDATE users_v2 SET avatar_b64=? WHERE id=?", (avatar_b64, user["id"]))
    return {"ok": True, "avatar_b64": avatar_b64}

# ── App Likes ────────────────────────────────────────────────

@app.post("/dist/{slug}/like")
async def dist_toggle_like(slug: str, user: dict = Depends(_current_user)):
    with _db() as c:
        if not c.execute("SELECT 1 FROM app_releases WHERE slug=? AND is_active=1", (slug,)).fetchone():
            raise HTTPException(404, "Not found")
        existing = c.execute("SELECT 1 FROM app_likes WHERE slug=? AND user_id=?",
                              (slug, user["id"])).fetchone()
        if existing:
            c.execute("DELETE FROM app_likes WHERE slug=? AND user_id=?", (slug, user["id"]))
            liked = False
        else:
            c.execute("INSERT INTO app_likes(slug, user_id) VALUES(?,?)", (slug, user["id"]))
            liked = True
        count = c.execute("SELECT COUNT(*) FROM app_likes WHERE slug=?", (slug,)).fetchone()[0]
    return {"liked": liked, "count": count}

# ── App Reviews ──────────────────────────────────────────────

def _review_display_name(nickname: str, email: str) -> str:
    if nickname:
        return nickname
    local = (email or "").split("@")[0]
    return local[:2] + "***" if len(local) > 2 else local or "用户"

@app.get("/dist/{slug}/reviews")
async def dist_get_reviews(slug: str, request: Request):
    # Optional auth
    user = None
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        try:
            payload = jwt.decode(auth[7:], JWT_SECRET, algorithms=[JWT_ALG])
            uid = payload.get("sub")
            with _db() as c:
                u = c.execute("SELECT * FROM users_v2 WHERE id=?", (uid,)).fetchone()
                if u:
                    user = dict(u)
        except Exception:
            pass
    with _db() as c:
        rows = c.execute("""
            SELECT r.id, r.rating, r.comment, r.created_at,
                   u.nickname, u.avatar_b64, u.email
            FROM app_reviews r
            JOIN users_v2 u ON u.id = r.user_id
            WHERE r.slug=?
            ORDER BY r.created_at DESC
        """, (slug,)).fetchall()
        likes = c.execute("SELECT COUNT(*) FROM app_likes WHERE slug=?", (slug,)).fetchone()[0]
        my_review = None
        liked = False
        if user:
            mr = c.execute("SELECT * FROM app_reviews WHERE slug=? AND user_id=?",
                           (slug, user["id"])).fetchone()
            if mr:
                my_review = dict(mr)
            liked = bool(c.execute("SELECT 1 FROM app_likes WHERE slug=? AND user_id=?",
                                   (slug, user["id"])).fetchone())
    reviews = [
        {
            "id": r["id"],
            "rating": r["rating"],
            "comment": r["comment"] or "",
            "created_at": (r["created_at"] or "")[:10],
            "nickname": _review_display_name(r["nickname"], r["email"]),
            "avatar_b64": r["avatar_b64"] or "",
            "is_mine": bool(user and my_review and r["id"] == my_review["id"]),
        }
        for r in rows
    ]
    ratings = [r["rating"] for r in reviews] if reviews else []
    avg = round(sum(ratings) / len(ratings), 1) if ratings else None
    return {
        "reviews": reviews,
        "likes": likes,
        "liked": liked,
        "my_review": my_review,
        "avg": avg,
        "count": len(reviews),
    }

@app.post("/dist/{slug}/review")
async def dist_post_review(slug: str, body: ReviewBody, user: dict = Depends(_current_user)):
    if not 1 <= body.rating <= 5:
        raise HTTPException(400, "评分需在 1-5 之间")
    with _db() as c:
        if not c.execute("SELECT 1 FROM app_releases WHERE slug=? AND is_active=1", (slug,)).fetchone():
            raise HTTPException(404, "Not found")
        c.execute("""
            INSERT INTO app_reviews(slug, user_id, rating, comment)
            VALUES(?,?,?,?)
            ON CONFLICT(slug, user_id) DO UPDATE SET
                rating=excluded.rating,
                comment=excluded.comment,
                created_at=datetime('now')
        """, (slug, user["id"], body.rating, body.comment.strip()[:500]))
    return {"ok": True}

@app.delete("/dist/{slug}/review")
async def dist_delete_review(slug: str, user: dict = Depends(_current_user)):
    with _db() as c:
        c.execute("DELETE FROM app_reviews WHERE slug=? AND user_id=?", (slug, user["id"]))
    return {"ok": True}


@app.post("/dist/upload")
async def dist_upload(
    file: UploadFile,
    app_name:      str = Form(""),
    version:       str = Form(""),
    description:   str = Form(""),
    expires_days:  int = Form(0),
    max_downloads: int = Form(0),
    is_public:     int = Form(0),
    category:      str = Form(""),
    user: dict = Depends(_current_user),
):
    ext = (file.filename or "").rsplit(".", 1)[-1].lower()
    if ext not in _ALLOWED_EXTS:
        raise HTTPException(400, "不支持的文件格式")

    # ── Credits check ────────────────────────────────────────────
    with _db() as c:
        _u = c.execute("SELECT credits FROM users_v2 WHERE id=?", (user["id"],)).fetchone()
    if not _u or _u["credits"] <= 0:
        raise HTTPException(402, "Credits 不足，请先购买")

    resolved_name = app_name.strip() or (file.filename or "未命名").rsplit(".", 1)[0]

    # ── Deduplication: same user + app_name + file_type → update existing ──
    with _db() as c:
        existing = c.execute(
            "SELECT slug FROM app_releases WHERE user_id=? AND app_name=? AND file_type=?",
            (user["id"], resolved_name, ext),
        ).fetchone()

    if existing:
        slug = existing["slug"]
        old_file = DIST_DIR / f"{slug}.{ext}"
        if old_file.exists():
            old_file.unlink()
        is_update = True
    else:
        for _ in range(10):
            slug = _gen_slug()
            with _db() as c:
                if not c.execute("SELECT 1 FROM app_releases WHERE slug=?", (slug,)).fetchone():
                    break
        is_update = False

    # Save file
    dest = DIST_DIR / f"{slug}.{ext}"
    size = 0
    with dest.open("wb") as f:
        while chunk := await file.read(1024 * 256):
            f.write(chunk)
            size += len(chunk)

    # Extract metadata (icon, package name, display name) from the saved file
    meta = _extract_app_info(dest, ext)

    # Use extracted display_name to fill resolved_name if user left app_name blank
    if not app_name.strip() and meta["display_name"]:
        resolved_name = meta["display_name"]

    # Use extracted version if user didn't provide one
    resolved_version = version.strip() or meta.get("version", "")

    # Compute expiry
    expires_at = None
    if expires_days and expires_days > 0:
        expires_at = (datetime.now() + timedelta(days=expires_days)).strftime("%Y-%m-%d %H:%M:%S")

    platform = _PLATFORM_MAP.get(ext, "other")
    with _db() as c:
        pub = 1 if is_public else 0
        if is_update:
            c.execute(
                """UPDATE app_releases SET
                   version=?, file_size=?, description=?, expires_at=?,
                   max_downloads=?, download_count=0, is_active=1,
                   created_at=datetime('now'),
                   pkg_name=?, display_name=?, icon_b64=?, platform=?, is_public=?, category=?
                   WHERE slug=?""",
                (resolved_version, size, description.strip(), expires_at,
                 max(0, max_downloads),
                 meta["pkg_name"], meta["display_name"], meta["icon_b64"], platform, pub, category.strip(), slug),
            )
        else:
            c.execute(
                """INSERT INTO app_releases
                   (slug, user_id, app_name, version, file_type, file_size,
                    description, expires_at, max_downloads, pkg_name, display_name, icon_b64, platform, is_public, category)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (slug, user["id"], resolved_name, resolved_version, ext, size,
                 description.strip(), expires_at, max(0, max_downloads),
                 meta["pkg_name"], meta["display_name"], meta["icon_b64"], platform, pub, category.strip()),
            )

    # ── Deduct 1 credit ─────────────────────────────────────────
    with _db() as c:
        c.execute(
            "UPDATE users_v2 SET credits=credits-1, updated_at=datetime('now')"
            " WHERE id=? AND credits>0",
            (user["id"],),
        )
        _row = c.execute("SELECT credits FROM users_v2 WHERE id=?", (user["id"],)).fetchone()
        credits_left = _row["credits"] if _row else 0

    site = os.getenv("SITE_URL", "https://maclechen.top")
    return {"ok": True, "slug": slug, "url": f"{site}/dist/{slug}",
            "updated": is_update, "credits_left": credits_left}


@app.get("/dist/list")
async def dist_list(
    q: str = "",
    platform: str = "",
    category: str = "",
    offset: int = 0,
    limit: int = 20,
    user: dict = Depends(_current_user),
):
    where = "user_id=? AND is_active=1"
    params: list = [user["id"]]
    if platform:
        where += " AND platform=?"
        params.append(platform)
    if category:
        where += " AND category=?"
        params.append(category)
    if q:
        like = f"%{q}%"
        where += " AND (app_name LIKE ? OR display_name LIKE ? OR pkg_name LIKE ?)"
        params.extend([like, like, like])
    with _db() as c:
        total = c.execute(f"SELECT COUNT(*) FROM app_releases WHERE {where}", params).fetchone()[0]
        rows = c.execute(
            f"""SELECT slug, app_name, version, file_type, file_size,
                      created_at, expires_at, max_downloads, download_count, is_active,
                      pkg_name, display_name, icon_b64, platform, is_public, category
               FROM app_releases WHERE {where}
               ORDER BY created_at DESC LIMIT ? OFFSET ?""",
            (*params, limit, offset),
        ).fetchall()
    return {"releases": [dict(r) for r in rows], "total": total}


@app.delete("/dist/{slug}")
async def dist_delete(slug: str, user: dict = Depends(_current_user)):
    with _db() as c:
        row = c.execute("SELECT * FROM app_releases WHERE slug=?", (slug,)).fetchone()
        if not row:
            raise HTTPException(404, "不存在")
        if dict(row)["user_id"] != user["id"]:
            raise HTTPException(403, "无权限")
        c.execute("UPDATE app_releases SET is_active=0 WHERE slug=?", (slug,))
    # Delete file
    for ext in _ALLOWED_EXTS:
        p = DIST_DIR / f"{slug}.{ext}"
        if p.exists():
            p.unlink()
    return {"ok": True}


@app.post("/dist/{slug}/request-download")
async def dist_request_download(slug: str, request: Request):
    """Authenticate user, check/deduct credits, return one-time download token."""
    # Clean up expired tokens
    now = time.time()
    expired_keys = [k for k, v in list(_dl_tokens.items()) if v["expires_at"] < now]
    for k in expired_keys:
        _dl_tokens.pop(k, None)

    with _db() as c:
        row = c.execute("SELECT * FROM app_releases WHERE slug=?", (slug,)).fetchone()
    if not row:
        raise HTTPException(404, "链接不存在")
    r = dict(row)
    if not r.get("is_active", 1):
        raise HTTPException(410, "链接已停用")
    if _dist_expired(r):
        raise HTTPException(410, "链接已过期")
    if _dist_exhausted(r):
        raise HTTPException(410, "下载次数已达上限")

    # Try to extract user from Authorization header (optional)
    user = None
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        try:
            payload = jwt.decode(auth_header[7:], JWT_SECRET, algorithms=[JWT_ALG])
            uid = payload.get("sub")
            with _db() as c:
                u = c.execute("SELECT * FROM users_v2 WHERE id=?", (uid,)).fetchone()
                if u:
                    user = dict(u)
        except Exception:
            pass

    if not user:
        raise HTTPException(401, detail={"need": "login", "msg": "请登录后下载"})

    is_owner = user["id"] == r["user_id"]
    credits_left = user.get("credits", 0)

    if not is_owner:
        if credits_left <= 0:
            raise HTTPException(402, detail={"need": "credits", "msg": "Credits 不足，请先购买", "credits": 0})
        with _db() as c:
            updated = c.execute(
                "UPDATE users_v2 SET credits=credits-1 WHERE id=? AND credits>0",
                (user["id"],)
            ).rowcount
        if updated == 0:
            raise HTTPException(402, detail={"need": "credits", "msg": "Credits 不足，请先购买", "credits": 0})
        credits_left -= 1

    dl_token = uuid.uuid4().hex
    _dl_tokens[dl_token] = {"slug": slug, "expires_at": now + 300}
    return {"token": dl_token, "is_owner": is_owner, "credits_left": credits_left if not is_owner else None}


@app.get("/dist/{slug}/download")
async def dist_download(slug: str, token: str = ""):
    # Validate one-time token
    if not token:
        raise HTTPException(403, "请通过详情页下载")
    entry = _dl_tokens.get(token)
    if not entry:
        raise HTTPException(403, "下载链接已失效，请重新获取")
    if entry["slug"] != slug:
        raise HTTPException(403, "下载链接无效")
    if time.time() > entry["expires_at"]:
        _dl_tokens.pop(token, None)
        raise HTTPException(403, "下载链接已过期，请重新获取")
    del _dl_tokens[token]   # one-time use

    with _db() as c:
        row = c.execute("SELECT * FROM app_releases WHERE slug=?", (slug,)).fetchone()
    if not row:
        raise HTTPException(404, "链接不存在")
    r = dict(row)
    if not r.get("is_active", 1):
        raise HTTPException(410, "链接已停用")
    if _dist_expired(r):
        raise HTTPException(410, "链接已过期")
    # Find file
    file_path = DIST_DIR / f"{slug}.{r['file_type']}"
    if not file_path.exists():
        raise HTTPException(404, "文件不存在")
    # Increment counter
    with _db() as c:
        c.execute("UPDATE app_releases SET download_count=download_count+1 WHERE slug=?", (slug,))
    ext      = r['file_type']
    app_name = (r.get("app_name") or slug).strip()
    ascii_name  = f"{slug}.{ext}"
    utf8_name   = urllib.parse.quote(f"{app_name}.{ext}", safe="")
    disp        = f'attachment; filename="{ascii_name}"; filename*=UTF-8\'\'{utf8_name}'
    media       = "application/vnd.android.package-archive" if ext == "apk" else "application/octet-stream"
    return FileResponse(str(file_path), media_type=media,
                        headers={"Content-Disposition": disp})


@app.get("/dist/{slug}", response_class=HTMLResponse)
async def dist_preview(slug: str):
    with _db() as c:
        row = c.execute("SELECT * FROM app_releases WHERE slug=?", (slug,)).fetchone()
    if not row:
        raise HTTPException(404, "链接不存在")
    return HTMLResponse(_dist_preview_html(dict(row)))


@app.post("/dist/{slug}/toggle-public")
async def dist_toggle_public(slug: str, user: dict = Depends(_current_user)):
    with _db() as c:
        row = c.execute("SELECT user_id, is_public FROM app_releases WHERE slug=? AND is_active=1", (slug,)).fetchone()
        if not row:
            raise HTTPException(404, "不存在")
        if dict(row)["user_id"] != user["id"]:
            raise HTTPException(403, "无权限")
        new_val = 0 if dict(row)["is_public"] else 1
        c.execute("UPDATE app_releases SET is_public=? WHERE slug=?", (new_val, slug))
    return {"ok": True, "is_public": bool(new_val)}


@app.get("/market/list")
async def market_list(
    platform: str = "",
    category: str = "",
    q: str = "",
    sort: str = "newest",
    offset: int = 0,
    limit: int = 24,
):
    where = "is_active=1 AND is_public=1"
    params: list = []
    if platform:
        where += " AND platform=?"
        params.append(platform)
    if category:
        where += " AND category=?"
        params.append(category)
    if q:
        like = f"%{q}%"
        where += " AND (app_name LIKE ? OR display_name LIKE ? OR pkg_name LIKE ?)"
        params.extend([like, like, like])
    order = "download_count DESC, created_at DESC" if sort == "popular" else "created_at DESC"
    with _db() as c:
        total = c.execute(
            f"SELECT COUNT(*) FROM app_releases WHERE {where}", params
        ).fetchone()[0]
        rows = c.execute(
            f"""SELECT slug, app_name, version, file_type, file_size,
                        display_name, icon_b64, platform, category, description,
                        download_count, created_at
                FROM app_releases WHERE {where}
                ORDER BY {order} LIMIT ? OFFSET ?""",
            (*params, limit, offset),
        ).fetchall()
    return {"apps": [dict(r) for r in rows], "total": total}


def _market_html() -> str:  # noqa: PLR0915
    site = os.getenv("SITE_URL", "https://maclechen.top")
    css = """*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#060d1c;--border:rgba(255,255,255,.07);--text:#f1f5f9;--muted:#64748b;--muted2:#475569;--pr:#6366f1;--pr2:#8b5cf6;--card:rgba(13,20,38,.85)}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
a{text-decoration:none;color:inherit}
#prog{position:fixed;top:0;left:0;width:100%;height:2px;background:linear-gradient(90deg,var(--pr),var(--pr2),#06b6d4);transform:scaleX(0);transform-origin:left;transition:transform .35s;z-index:9999}
#prog.show{transform:scaleX(.88)}
header{position:sticky;top:0;z-index:100;background:rgba(6,13,28,.94);backdrop-filter:blur(24px);border-bottom:1px solid var(--border);padding:0 20px;height:58px;display:flex;align-items:center;gap:14px}
.logo{display:flex;align-items:center;gap:8px;font-weight:800;font-size:1em;white-space:nowrap;flex-shrink:0}
.logo img{width:24px;height:24px}
.logo-sep{width:1px;height:20px;background:var(--border);margin:0 2px;flex-shrink:0}
.logo-sub{font-weight:400;font-size:.88em;color:var(--muted)}
.h-search{flex:1;max-width:420px;position:relative}
.h-search input{width:100%;background:rgba(255,255,255,.06);border:1px solid var(--border);border-radius:22px;padding:7px 40px 7px 16px;color:var(--text);font-size:.85em;outline:none;transition:border-color .2s,background .2s}
.h-search input:focus{border-color:rgba(99,102,241,.5);background:rgba(255,255,255,.09)}
.h-search input::placeholder{color:var(--muted)}
.h-sbtn{position:absolute;right:4px;top:50%;transform:translateY(-50%);width:30px;height:30px;border-radius:50%;background:rgba(99,102,241,.2);border:none;color:#a5b4fc;cursor:pointer;display:flex;align-items:center;justify-content:center;font-size:.9em;transition:background .15s}
.h-sbtn:hover{background:rgba(99,102,241,.38)}
.h-cta{flex-shrink:0;background:linear-gradient(135deg,var(--pr),var(--pr2));color:#fff;padding:6px 14px;border-radius:20px;font-size:.8em;font-weight:700;white-space:nowrap;transition:opacity .2s}
.h-cta:hover{opacity:.83}
.hero{text-align:center;padding:44px 20px 28px;background:radial-gradient(ellipse 90% 60% at 50% -10%,rgba(99,102,241,.1) 0%,transparent 65%)}
.hero-title{font-size:1.9em;font-weight:900;letter-spacing:-.025em;background:linear-gradient(135deg,#93c5fd 20%,#c4b5fd 60%,#6ee7b7 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:8px}
.hero-sub{color:var(--muted);font-size:.9em;margin-bottom:20px}
.hero-tags{display:flex;gap:9px;justify-content:center;flex-wrap:wrap}
.hero-tag{padding:5px 12px;border-radius:20px;font-size:.75em;background:rgba(255,255,255,.04);border:1px solid var(--border);color:var(--muted)}
.hero-tag b{color:var(--text)}
.filters{border-bottom:1px solid var(--border);padding:2px 20px 0;max-width:1440px;margin:0 auto}
.frow{display:flex;align-items:center;gap:10px;padding:9px 0;border-top:1px solid rgba(255,255,255,.04)}
.frow:first-child{border-top:none}
.flbl{font-size:.7em;color:var(--muted);width:30px;flex-shrink:0}
.chips{display:flex;gap:5px;overflow-x:auto;scrollbar-width:none;padding-bottom:1px}
.chips::-webkit-scrollbar{display:none}
.chip{flex-shrink:0;padding:4px 12px;border-radius:16px;border:1px solid var(--border);background:transparent;color:var(--muted);cursor:pointer;font-size:.78em;transition:all .15s;white-space:nowrap}
.chip.on{background:rgba(99,102,241,.2);border-color:rgba(99,102,241,.45);color:#a5b4fc;font-weight:600}
.chip:hover:not(.on){background:rgba(255,255,255,.06);color:var(--text);border-color:rgba(255,255,255,.15)}
.toolbar{max-width:1440px;margin:0 auto;padding:10px 20px;display:flex;align-items:center;justify-content:space-between;gap:8px;min-height:40px}
#stats{font-size:.8em;color:var(--muted)}
.sort-sel{background:rgba(255,255,255,.05);border:1px solid var(--border);color:var(--text);padding:4px 8px;border-radius:7px;font-size:.78em;cursor:pointer;outline:none}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(168px,1fr));gap:14px;padding:0 20px 24px;max-width:1440px;margin:0 auto}
@media(min-width:1440px){.grid{grid-template-columns:repeat(7,1fr)}}
@media(max-width:480px){.grid{grid-template-columns:repeat(2,1fr);gap:10px;padding:0 12px 20px}}
.acard{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:14px 11px 12px;display:flex;flex-direction:column;align-items:center;text-align:center;cursor:pointer;transition:transform .2s,border-color .2s,box-shadow .2s;position:relative;overflow:hidden}
.acard::before{content:'';position:absolute;top:0;left:0;right:0;height:38px;background:linear-gradient(180deg,rgba(99,102,241,.08),transparent);opacity:0;transition:opacity .2s}
.acard:hover{transform:translateY(-3px);border-color:rgba(99,102,241,.32);box-shadow:0 10px 36px rgba(0,0,0,.55)}
.acard:hover::before{opacity:1}
.ac-icon{width:64px;height:64px;border-radius:14px;margin-bottom:10px;object-fit:cover;display:block;box-shadow:0 4px 14px rgba(0,0,0,.4)}
.ac-icon-ph{width:64px;height:64px;border-radius:14px;margin-bottom:10px;background:linear-gradient(135deg,rgba(59,130,246,.22),rgba(139,92,246,.22));border:1px solid rgba(255,255,255,.08);display:flex;align-items:center;justify-content:center;font-size:1.6em}
.ac-name{font-weight:700;font-size:.85em;line-height:1.3;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;margin-bottom:4px;width:100%}
.ac-ver{font-size:.64em;color:var(--muted);margin-bottom:6px}
.ac-badges{display:flex;gap:3px;flex-wrap:wrap;justify-content:center;margin-bottom:6px}
.badge{padding:2px 7px;border-radius:8px;font-size:.6em;font-weight:700;letter-spacing:.02em}
.b-android{background:rgba(59,130,246,.15);color:#60a5fa;border:1px solid rgba(59,130,246,.25)}
.b-ios{background:rgba(139,92,246,.15);color:#a78bfa;border:1px solid rgba(139,92,246,.25)}
.b-windows{background:rgba(56,189,248,.15);color:#38bdf8;border:1px solid rgba(56,189,248,.25)}
.b-macos{background:rgba(52,211,153,.15);color:#34d399;border:1px solid rgba(52,211,153,.25)}
.b-linux{background:rgba(251,146,60,.15);color:#fb923c;border:1px solid rgba(251,146,60,.25)}
.b-other{background:rgba(148,163,184,.15);color:#94a3b8;border:1px solid rgba(148,163,184,.25)}
.b-cat{background:rgba(99,102,241,.12);color:#818cf8;border:1px solid rgba(99,102,241,.2)}
.ac-desc{font-size:.68em;color:var(--muted2);line-height:1.4;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;margin-bottom:6px;width:100%;text-align:left}
.ac-dl{font-size:.64em;color:#334155;margin-top:auto;padding-top:5px}
.ac-btn{display:block;width:100%;margin-top:7px;padding:6px 0;background:rgba(99,102,241,.14);border:1px solid rgba(99,102,241,.24);border-radius:7px;color:#818cf8;font-size:.72em;font-weight:700;transition:all .15s}
.ac-btn:hover{background:rgba(99,102,241,.28);color:#a5b4fc;border-color:rgba(99,102,241,.44)}
.pages{display:flex;gap:5px;justify-content:center;padding:8px 20px 40px;flex-wrap:wrap}
.pg{min-width:34px;height:34px;padding:0 8px;border-radius:7px;border:1px solid var(--border);background:rgba(255,255,255,.04);color:var(--muted);cursor:pointer;font-size:.82em;display:inline-flex;align-items:center;justify-content:center;transition:all .15s}
.pg:hover:not(.off){background:rgba(255,255,255,.08);color:var(--text)}
.pg.on{background:rgba(99,102,241,.22);border-color:rgba(99,102,241,.45);color:#a5b4fc;font-weight:700}
.pg.off{opacity:.25;cursor:default}
.pg-dot{color:var(--muted);font-size:.85em;padding:0 4px;line-height:34px}
.skc{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:14px 11px;display:flex;flex-direction:column;align-items:center;gap:8px}
.sk{background:rgba(255,255,255,.06);border-radius:6px;animation:pulse 1.6s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:.35}50%{opacity:.75}}
.empty{text-align:center;padding:80px 20px;max-width:360px;margin:0 auto}
.empty-em{font-size:3.2em;margin-bottom:14px}
.empty-t{font-size:1em;font-weight:700;color:var(--muted2);margin-bottom:8px}
.empty-s{font-size:.83em;color:var(--muted);line-height:1.7}
footer{text-align:center;padding:24px;font-size:.73em;color:#1e293b;border-top:1px solid var(--border)}
footer a{color:#3b82f6}"""
    js = """const PS=24;
let q='',plat='',cat='',srt='newest',pg=1,total=0;
const PL={android:'Android',ios:'iOS',windows:'Windows',macos:'macOS',linux:'Linux',other:'Other'};
const CL={tools:'工具',social:'社交',games:'游戏',finance:'金融',entertainment:'娱乐',education:'教育',productivity:'效率',health:'健康',other:'其他'};
const CI={tools:'🔧',social:'💬',games:'🎮',finance:'💰',entertainment:'🎬',education:'📚',productivity:'⚡',health:'💪',other:'📦'};
function esc(s){const d=document.createElement('div');d.textContent=s||'';return d.innerHTML}
function showProg(on){document.getElementById('prog').classList.toggle('show',on)}
function doSearch(){q=document.getElementById('si').value.trim();pg=1;load()}
function setCat(c,el){cat=c;pg=1;document.querySelectorAll('#cc .chip').forEach(b=>b.classList.remove('on'));el.classList.add('on');load()}
function setPlat(p,el){plat=p;pg=1;document.querySelectorAll('#pc .chip').forEach(b=>b.classList.remove('on'));el.classList.add('on');load()}
function setSort(s){srt=s;pg=1;load()}
function goPage(p){pg=p;load();window.scrollTo({top:300,behavior:'smooth'})}
function renderSkeleton(){
  const g=document.getElementById('grid');g.innerHTML='';
  for(let i=0;i<12;i++){
    const d=document.createElement('div');d.className='skc';
    d.innerHTML='<div class="sk" style="width:64px;height:64px;border-radius:14px"></div><div class="sk" style="width:72%;height:10px"></div><div class="sk" style="width:52%;height:8px"></div><div class="sk" style="width:60%;height:8px"></div>';
    g.appendChild(d);
  }
}
function renderCards(apps){
  const g=document.getElementById('grid');g.innerHTML='';
  apps.forEach(app=>{
    const name=esc(app.display_name||app.app_name||'未命名');
    const ver=app.version?`<div class="ac-ver">v${esc(app.version)}</div>`:'';
    const p=app.platform||'other';
    const c=app.category||'';
    const icon=app.icon_b64?`<img class="ac-icon" src="data:image/png;base64,${app.icon_b64}" alt="${name}" loading="lazy">`:`<div class="ac-icon-ph">📦</div>`;
    const catBadge=c&&CL[c]?`<span class="badge b-cat">${CI[c]||''} ${CL[c]}</span>`:'';
    const platBadge=`<span class="badge b-${p}">${PL[p]||p}</span>`;
    const desc=app.description?`<div class="ac-desc">${esc(app.description)}</div>`:'';
    const a=document.createElement('a');
    a.className='acard';a.href='/dist/'+app.slug;a.target='_blank';a.rel='noopener';
    a.innerHTML=`${icon}<div class="ac-name">${name}</div>${ver}<div class="ac-badges">${catBadge}${platBadge}</div>${desc}<div class="ac-dl">⬇️ ${app.download_count||0} 次下载</div><div class="ac-btn">查看详情</div>`;
    g.appendChild(a);
  });
}
function renderPages(){
  const el=document.getElementById('pages');
  const tp=Math.ceil(total/PS);
  if(tp<=1){el.innerHTML='';return;}
  let h=`<button class="pg${pg<=1?' off':''}" onclick="if(${pg>1})goPage(${pg-1})">‹ 上一页</button>`;
  const arr=[];
  for(let i=1;i<=tp;i++){
    if(i===1||i===tp||Math.abs(i-pg)<=2) arr.push(i);
    else if(arr[arr.length-1]!=='…') arr.push('…');
  }
  arr.forEach(p=>{
    if(p==='…') h+=`<span class="pg-dot">…</span>`;
    else h+=`<button class="pg${p===pg?' on':''}" onclick="goPage(${p})">${p}</button>`;
  });
  h+=`<button class="pg${pg>=tp?' off':''}" onclick="if(${pg<tp})goPage(${pg+1})">下一页 ›</button>`;
  el.innerHTML=h;
}
async function load(){
  showProg(true);renderSkeleton();
  document.getElementById('empty').hidden=true;
  document.getElementById('pages').innerHTML='';
  document.getElementById('stats').textContent='';
  try{
    const p=new URLSearchParams({q,platform:plat,category:cat,sort:srt,offset:String((pg-1)*PS),limit:String(PS)});
    const r=await fetch('/market/list?'+p,{cache:'no-store'});
    if(!r.ok) throw new Error('HTTP '+r.status);
    const d=await r.json();
    total=d.total||0;
    const apps=d.apps||[];
    if(!apps.length){
      document.getElementById('grid').innerHTML='';
      document.getElementById('empty').hidden=false;
      document.getElementById('stats').textContent='共 0 个应用';
    }else{
      renderCards(apps);
      renderPages();
      const s=(pg-1)*PS+1,e=Math.min(pg*PS,total);
      document.getElementById('stats').textContent=`共 ${total} 个应用  第 ${s}–${e} 个`;
    }
  }catch(e){
    document.getElementById('grid').innerHTML=`<div style="padding:40px;color:#ef4444;grid-column:1/-1;text-align:center">⚠️ 加载失败，<u style="cursor:pointer" onclick="load()">点击重试</u></div>`;
    console.error('[market]',e);
  }
  showProg(false);
}
load();"""
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>应用市场 — AppSec AI</title>
  <meta name="description" content="浏览下载多平台应用，所有应用均可通过 AI 安全扫描认证">
  <link rel="icon" href="/favicon.svg" type="image/svg+xml">
  <style>{css}</style>
</head>
<body>
<div id="prog"></div>
<header>
  <a class="logo" href="{site}">
    <img src="/favicon.svg" alt="logo">
    <div class="logo-sep"></div>
    <span class="logo-sub">应用市场</span>
  </a>
  <div class="h-search">
    <input id="si" type="search" placeholder="搜索应用名称、包名…" onkeydown="if(event.key==='Enter')doSearch()">
    <button class="h-sbtn" onclick="doSearch()">↵</button>
  </div>
  <a class="h-cta" href="{site}/app">⬆️ 上传应用</a>
</header>
<section class="hero">
  <h1 class="hero-title">发现 · 下载 · 安全</h1>
  <p class="hero-sub">所有应用均可通过 AppSec AI 进行专业安全扫描，放心下载</p>
  <div class="hero-tags">
    <div class="hero-tag">🤖 <b>AI 安全检测</b></div>
    <div class="hero-tag">🌐 <b>多平台支持</b></div>
    <div class="hero-tag">⚡ <b>极速分发</b></div>
    <div class="hero-tag">🔒 <b>隐私安全</b></div>
    <div class="hero-tag">📦 <b>10+ 应用分类</b></div>
  </div>
</section>
<div class="filters">
  <div class="frow">
    <span class="flbl">分类</span>
    <div class="chips" id="cc">
      <button class="chip on" onclick="setCat('',this)">全部</button>
      <button class="chip" onclick="setCat('tools',this)">🔧 工具</button>
      <button class="chip" onclick="setCat('social',this)">💬 社交</button>
      <button class="chip" onclick="setCat('games',this)">🎮 游戏</button>
      <button class="chip" onclick="setCat('finance',this)">💰 金融</button>
      <button class="chip" onclick="setCat('entertainment',this)">🎬 娱乐</button>
      <button class="chip" onclick="setCat('education',this)">📚 教育</button>
      <button class="chip" onclick="setCat('productivity',this)">⚡ 效率</button>
      <button class="chip" onclick="setCat('health',this)">💪 健康</button>
      <button class="chip" onclick="setCat('other',this)">📦 其他</button>
    </div>
  </div>
  <div class="frow">
    <span class="flbl">平台</span>
    <div class="chips" id="pc">
      <button class="chip on" onclick="setPlat('',this)">全部</button>
      <button class="chip" onclick="setPlat('android',this)">🤖 Android</button>
      <button class="chip" onclick="setPlat('ios',this)">🍎 iOS</button>
      <button class="chip" onclick="setPlat('windows',this)">🪟 Windows</button>
      <button class="chip" onclick="setPlat('macos',this)">🍏 macOS</button>
      <button class="chip" onclick="setPlat('linux',this)">🐧 Linux</button>
    </div>
  </div>
</div>
<div class="toolbar">
  <span id="stats"></span>
  <select class="sort-sel" onchange="setSort(this.value)">
    <option value="newest">最新上传</option>
    <option value="popular">下载最多</option>
  </select>
</div>
<div id="grid" class="grid"></div>
<div id="empty" class="empty" hidden>
  <div class="empty-em">📭</div>
  <div class="empty-t">暂无应用</div>
  <div class="empty-s">当前筛选条件下没有找到应用<br>换个分类或平台试试？</div>
</div>
<div id="pages" class="pages"></div>
<footer>Powered by <a href="{site}" target="_blank">AppSec AI</a> — 安全扫描 · 应用分发 · 应用市场</footer>
<script>{js}</script>
</body>
</html>"""




@app.get("/market", response_class=HTMLResponse)
async def market_page():
    return HTMLResponse(_market_html())


@app.get("/robots.txt")
async def robots_txt():
    content = (
        "User-agent: *\n"
        "Allow: /\n"
        "Disallow: /app\n"
        "Disallow: /admin\n"
        "Disallow: /auth/\n"
        "Disallow: /orders/\n"
        "Disallow: /scan/\n"
        "Disallow: /payment/\n"
        "Disallow: /dist/list\n"
        "Disallow: /dist/upload\n"
        "\n"
        "Sitemap: https://maclechen.top/sitemap.xml\n"
    )
    return Response(content=content, media_type="text/plain",
                    headers={"Cache-Control": "public, max-age=86400"})


@app.get("/sitemap.xml")
async def sitemap_xml():
    content = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"\n'
        '        xmlns:xhtml="http://www.w3.org/1999/xhtml">\n'
        '  <url>\n'
        '    <loc>https://www.maclechen.top/</loc>\n'
        '    <lastmod>2026-03-17</lastmod>\n'
        '    <changefreq>weekly</changefreq>\n'
        '    <priority>1.0</priority>\n'
        '  </url>\n'
        '  <url>\n'
        '    <loc>https://www.maclechen.top/app</loc>\n'
        '    <lastmod>2026-03-17</lastmod>\n'
        '    <changefreq>monthly</changefreq>\n'
        '    <priority>0.5</priority>\n'
        '  </url>\n'
        '</urlset>\n'
    )
    return Response(content=content, media_type="application/xml",
                    headers={"Cache-Control": "public, max-age=86400"})


@app.get("/", response_class=HTMLResponse)
async def landing():
    html_path = os.path.join(os.path.dirname(__file__), "static", "landing.html")
    with open(html_path, encoding="utf-8") as f:
        content = f.read()
    # Allow crawlers to cache landing page for 1 hour
    return HTMLResponse(content=content, headers={"Cache-Control": "public, max-age=3600"})


@app.get("/app", response_class=HTMLResponse)
async def index():
    html_path = os.path.join(os.path.dirname(__file__), "static", "index.html")
    with open(html_path, encoding="utf-8") as f:
        content = f.read()
    return HTMLResponse(content=content, headers={"Cache-Control": "no-store"})


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

    # Stream upload to a temp file — avoids loading the full APK into memory,
    # which can exhaust RAM on large files and crash the container.
    suffix = Path(file.filename or "file.apk").suffix or ".apk"
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=suffix, prefix=f"scan_{task_id}_")
    try:
        with os.fdopen(tmp_fd, "wb") as tmp_f:
            shutil.copyfileobj(file.file, tmp_f)
    except Exception:
        os.unlink(tmp_path)
        raise

    _tasks[task_id] = {
        "status":    "uploading",
        "filename":  file.filename,
        "lang":      lang,
        "token":     token,        # legacy
        "auth_type": auth_type,
        "user_id":   user_id,      # jwt
        "started_at": datetime.now().isoformat(),
    }
    background_tasks.add_task(_run_scan, task_id, file.filename, tmp_path, lang)
    return {"task_id": task_id}


async def _run_scan(task_id: str, filename: str, tmp_path: str, lang: str = "zh"):
    """Run MobSF scan. tmp_path is a temp file on disk; deleted when done."""
    mobsf_url = os.getenv("MOBSF_URL", "http://localhost:8000")
    headers = _mobsf_headers()
    scan_id: str | None = None   # set after upload; used in finally to delete from MobSF
    try:
        # 1. Upload file to MobSF
        _tasks[task_id]["status"] = "uploading"
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=30, read=120, write=300, pool=30)
        ) as client:
            with open(tmp_path, "rb") as fh:
                resp = await client.post(
                    f"{mobsf_url}/api/v1/upload",
                    files={"file": (filename, fh, "application/octet-stream")},
                    headers=headers,
                )
        upload_data = resp.json()
        if "hash" not in upload_data:
            _tasks[task_id].update({"status": "error", "error": str(upload_data)})
            return
        scan_id = upload_data["hash"]
        scan_type = upload_data.get("scan_type", "apk")
        _tasks[task_id]["scan_type"] = scan_type

        # 2. Trigger scan — MobSF /api/v1/scan blocks until analysis completes.
        #    If the HTTP read times out, MobSF still keeps scanning in the background;
        #    we catch ReadTimeout here and fall through to polling in step 3.
        _tasks[task_id]["status"] = "scanning"
        _tasks[task_id]["scan_started_at"] = time.time()
        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(connect=30, read=1800, write=60, pool=30)
            ) as client:
                resp = await client.post(
                    f"{mobsf_url}/api/v1/scan",
                    data={"hash": scan_id, "scan_type": scan_type},
                    headers=headers,
                )
            scan_result = resp.json()
            if "error" in scan_result:
                _tasks[task_id].update({"status": "error", "error": str(scan_result["error"])})
                return
        except httpx.ReadTimeout:
            # Scan is still running on MobSF side — will poll for the report below
            pass

        # 3. Poll report_json until MobSF finishes (budget: 35 min from scan start).
        #    For fast scans, /api/v1/scan already returned and report is ready on first try.
        #    For slow scans (large APKs), we poll every 10s until done or budget exhausted.
        _tasks[task_id]["status"] = "analyzing"
        report = None
        scan_budget = 35 * 60  # 35 min total from scan_started_at
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(connect=30, read=60, write=60, pool=30)
        ) as client:
            while True:
                elapsed = time.time() - _tasks[task_id]["scan_started_at"]
                if elapsed > scan_budget:
                    break
                resp = await client.post(
                    f"{mobsf_url}/api/v1/report_json",
                    data={"hash": scan_id},
                    headers=headers,
                )
                data = resp.json()
                if "report" not in data:
                    report = data
                    break
                await asyncio.sleep(10)

        if report is None:
            _tasks[task_id].update({
                "status": "error",
                "error": "MobSF 静态分析超时（超过35分钟），请检查服务器资源或尝试较小的文件。",
                "error_en": "MobSF static analysis timed out (>35 min). Check server resources or try a smaller file.",
                "error_code": "timeout",
            })
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
    finally:
        # 1. Delete the local temp file
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        # 2. Delete the file from MobSF storage (protects user privacy, frees disk)
        if scan_id:
            try:
                async with httpx.AsyncClient(
                    timeout=httpx.Timeout(connect=10, read=30, write=10, pool=10)
                ) as client:
                    await client.post(
                        f"{mobsf_url}/api/v1/delete_scan",
                        data={"hash": scan_id},
                        headers=headers,
                    )
            except Exception:
                pass  # deletion failure is non-fatal


@app.get("/scan/status/{task_id}")
async def get_status(task_id: str):
    task = _tasks.get(task_id)
    if not task:
        return {"status": "not_found"}
    resp: dict = {
        "status": task.get("status", "unknown"),
        "error":  task.get("error"),
        "error_en": task.get("error_en"),
        "error_code": task.get("error_code"),
    }
    # Expose elapsed seconds so frontend can show a timer
    if "scan_started_at" in task:
        resp["scan_elapsed"] = int(time.time() - task["scan_started_at"])
    return resp


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
        "security_score":      str(
            s if (s := report.get("security_score")) is not None else
            s if (s := _appsec.get("security_score")) is not None else "N/A"
        ),
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
