from datetime import datetime, timezone, timedelta
from html import escape
from pathlib import Path
from urllib.parse import urljoin, urlparse, urldefrag
import json
import sqlite3
from io import BytesIO
from collections import deque
import ipaddress
import socket
import os
import re
import hmac
import hashlib
import secrets
import smtplib
from email.message import EmailMessage
from fastapi import Request

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel, Field

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "websentinel_history.db"

app = FastAPI(
    title="WebSentinel Web Vulnerability Scanner",
    description="A web security configuration checker for local labs and authorized public websites.",
    version="1.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}
LOCAL_PORTS = {3000, 8080, 8081}
PUBLIC_PORTS = {80, 443}
USER_AGENT = "WebSentinel-Authorized-Scanner/1.1"

class ScanRequest(BaseModel):
    target: str

class CrawlRequest(BaseModel):
    target: str
    max_pages: int = Field(default=10, ge=1, le=30)

class XSSCheckRequest(BaseModel):
    target: str

def connect_db():
    connection = sqlite3.connect(DB_PATH, timeout=10)
    connection.row_factory = sqlite3.Row
    return connection

def init_db():
    with connect_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                http_status INTEGER NOT NULL,
                headers_checked INTEGER NOT NULL,
                missing_headers INTEGER NOT NULL,
                findings_json TEXT NOT NULL,
                note TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                display_name TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS password_resets (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        db.commit()

init_db()

class SignupRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=8, max_length=128)

class LoginRequest(BaseModel):
    email: str
    password: str

class ForgotPasswordRequest(BaseModel):
    email: str

class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=8, max_length=128)

def utc_now():
    return datetime.now(timezone.utc)

def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 310_000)
    return salt.hex() + ":" + derived.hex()

def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, expected = stored.split(":", 1)
        actual = hash_password(password, bytes.fromhex(salt_hex)).split(":", 1)[1]
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False

def make_session(user_id: int) -> str:
    token = secrets.token_urlsafe(40)
    expires = (utc_now() + timedelta(hours=12)).isoformat()
    with connect_db() as db:
        db.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)",
                   (token_digest(token), user_id, expires))
        db.commit()
    return token

def current_user_from_token(token: str):
    digest = token_digest(token)
    with connect_db() as db:
        row = db.execute("""SELECT u.id,u.email,u.display_name,s.expires_at FROM sessions s
            JOIN users u ON u.id=s.user_id WHERE s.token_hash=?""", (digest,)).fetchone()
        if row is None:
            return None
        if datetime.fromisoformat(row["expires_at"]) <= utc_now():
            db.execute("DELETE FROM sessions WHERE token_hash=?", (digest,))
            db.commit()
            return None
        return {"id": row["id"], "email": row["email"], "name": row["display_name"]}

def send_reset_email(email: str, reset_url: str) -> bool:
    host = os.getenv("WEBSENTINEL_SMTP_HOST", "").strip()
    if not host:
        return False
    msg = EmailMessage()
    msg["Subject"] = "Reset your WebSentinel password"
    msg["From"] = os.getenv("WEBSENTINEL_SMTP_FROM", os.getenv("WEBSENTINEL_SMTP_USER", "websentinel@localhost"))
    msg["To"] = email
    msg.set_content(f"A password reset was requested for your WebSentinel account. This link expires in 30 minutes:\n\n{reset_url}\n\nIf you did not request this, ignore this email.")
    port = int(os.getenv("WEBSENTINEL_SMTP_PORT", "587"))
    user = os.getenv("WEBSENTINEL_SMTP_USER", "")
    password = os.getenv("WEBSENTINEL_SMTP_PASSWORD", "")
    with smtplib.SMTP(host, port, timeout=10) as server:
        server.starttls()
        if user:
            server.login(user, password)
        server.send_message(msg)
    return True

@app.middleware("http")
async def require_login(request: Request, call_next):
    open_paths = {"/", "/health", "/auth/signup", "/auth/login", "/auth/forgot-password", "/auth/reset-password", "/openapi.json", "/docs", "/docs/oauth2-redirect", "/redoc"}
    if request.method == "OPTIONS" or request.url.path in open_paths or request.url.path.startswith("/auth/"):
        return await call_next(request)
    authorization = request.headers.get("authorization", "")
    if not authorization.lower().startswith("bearer "):
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=401, content={"detail": "Please log in to use WebSentinel."})
    user = current_user_from_token(authorization[7:].strip())
    if not user:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=401, content={"detail": "Your session expired. Please log in again."})
    request.state.user = user
    return await call_next(request)

@app.post("/auth/signup")
def signup(request: SignupRequest):
    name = request.name.strip()
    email = request.email.strip().lower()
    if not name:
        raise HTTPException(status_code=400, detail="Enter your name.")
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise HTTPException(status_code=400, detail="Enter a valid email address.")
    if len(request.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
    try:
        with connect_db() as db:
            cur = db.execute("INSERT INTO users(email,display_name,password_hash,created_at) VALUES(?,?,?,?)",
                (email, name, hash_password(request.password), utc_now().isoformat()))
            user_id = cur.lastrowid
            db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="An account with this email already exists. Please log in.")
    return {"token": make_session(user_id), "user": {"id": user_id, "email": email, "name": name}}

@app.post("/auth/login")
def login(request: LoginRequest):
    with connect_db() as db:
        user = db.execute("SELECT * FROM users WHERE email=? COLLATE NOCASE", (request.email.strip(),)).fetchone()
    if user is None or not verify_password(request.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password.")
    return {"token": make_session(user["id"]), "user": {"id": user["id"], "email": user["email"], "name": user["display_name"]}}

@app.get("/auth/me")
def auth_me(request: Request):
    authorization = request.headers.get("authorization", "")
    user = current_user_from_token(authorization[7:].strip()) if authorization.lower().startswith("bearer ") else None
    if not user:
        raise HTTPException(status_code=401, detail="Please log in again.")
    return {"user": user}

@app.post("/auth/logout")
def logout(request: Request):
    authorization = request.headers.get("authorization", "")
    if authorization.lower().startswith("bearer "):
        with connect_db() as db:
            db.execute("DELETE FROM sessions WHERE token_hash=?", (token_digest(authorization[7:].strip()),))
            db.commit()
    return {"message": "Logged out."}

@app.post("/auth/forgot-password")
def forgot_password(request: ForgotPasswordRequest):
    email = request.email.strip().lower()
    generic = {"message": "If an account exists for that email, password reset instructions have been prepared."}
    with connect_db() as db:
        user = db.execute("SELECT id,email FROM users WHERE email=? COLLATE NOCASE", (email,)).fetchone()
        if user is None:
            return generic
        raw_token = secrets.token_urlsafe(36)
        expires = (utc_now() + timedelta(minutes=30)).isoformat()
        db.execute("DELETE FROM password_resets WHERE user_id=?", (user["id"],))
        db.execute("INSERT INTO password_resets(token_hash,user_id,expires_at,used) VALUES(?,?,?,0)",
                    (token_digest(raw_token), user["id"], expires))
        db.commit()
    frontend = os.getenv("WEBSENTINEL_FRONTEND_URL", "http://localhost:5173").rstrip("/")
    reset_url = f"{frontend}/?reset_token={raw_token}"
    try:
        sent = send_reset_email(user["email"], reset_url)
    except Exception:
        sent = False
    if sent:
        return generic
    # Local-development fallback only: never expose reset tokens in a deployed environment.
    if os.getenv("WEBSENTINEL_DEV_RESET_LINKS", "true").lower() == "true":
        return {**generic, "development_reset_url": reset_url, "development_only": True}
    return generic

@app.post("/auth/reset-password")
def reset_password(request: ResetPasswordRequest):
    if len(request.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters.")
    digest = token_digest(request.token.strip())
    with connect_db() as db:
        row = db.execute("SELECT user_id,expires_at,used FROM password_resets WHERE token_hash=?", (digest,)).fetchone()
        if row is None or row["used"] or datetime.fromisoformat(row["expires_at"]) <= utc_now():
            raise HTTPException(status_code=400, detail="This reset link is invalid or expired. Request a new one.")
        db.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(request.new_password), row["user_id"]))
        db.execute("UPDATE password_resets SET used=1 WHERE token_hash=?", (digest,))
        db.execute("DELETE FROM sessions WHERE user_id=?", (row["user_id"],))
        db.commit()
    return {"message": "Password reset successful. Please log in with your new password."}

def validate_target(target: str):
    """Allow local lab ports or public HTTP(S) websites on standard ports.

    Public targets must resolve only to globally routable IP addresses. Redirects
    are not followed, reducing the chance of a target redirecting into a private network.
    Only scan websites you own or are explicitly authorized to assess.
    """
    parsed = urlparse(target.strip())
    try:
        port = parsed.port
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid target port.") from exc

    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None):
        raise HTTPException(status_code=400, detail="Enter a valid HTTP or HTTPS website URL without a username or password.")

    host = parsed.hostname.rstrip(".").lower()
    effective_port = port or (443 if parsed.scheme == "https" else 80)

    if host in LOCAL_HOSTS:
        if parsed.scheme != "http" or effective_port not in LOCAL_PORTS:
            raise HTTPException(status_code=400, detail="Local targets are limited to HTTP ports 3000, 8080, and 8081.")
        return parsed

    if effective_port not in PUBLIC_PORTS:
        raise HTTPException(status_code=400, detail="Public targets are limited to standard HTTP/HTTPS ports 80 and 443.")

    try:
        addresses = {item[4][0] for item in socket.getaddrinfo(host, effective_port, type=socket.SOCK_STREAM)}
        if not addresses:
            raise ValueError("No addresses found")
        for address in addresses:
            ip = ipaddress.ip_address(address.split("%", 1)[0])
            if not ip.is_global:
                raise HTTPException(status_code=400, detail="Target resolves to a private or reserved address and is blocked.")
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Could not safely resolve this public target. Check the URL and DNS.") from exc
    return parsed

def same_origin(url_a, url_b):
    a, b = urlparse(url_a), urlparse(url_b)
    return a.scheme == b.scheme and a.hostname == b.hostname and a.port == b.port

def finding(name, present, severity, message, recommendation, evidence="Not returned by the target"):
    return {
        "header": name,
        "present": bool(present),
        "severity": severity,
        "message": message,
        "recommendation": recommendation,
        "evidence": evidence if evidence else "Not returned by the target",
    }

def evaluate_response(response):
    headers = response.headers
    findings = []
    checks = [
        ("Content-Security-Policy", "Helps restrict the sources from which a browser may load content.",
         "Review the application's content sources and configure a restrictive CSP. Avoid blindly copying a policy that could break the site."),
        ("X-Content-Type-Options", "Helps prevent browsers from MIME-sniffing a response.",
         "For applicable responses, configure X-Content-Type-Options: nosniff."),
        ("X-Frame-Options", "Can help restrict framing and reduce clickjacking risk.",
         "Choose an appropriate framing policy, or use the CSP frame-ancestors directive."),
        ("Referrer-Policy", "Controls how much referrer information the browser sends.",
         "Choose a policy appropriate for the application's privacy and navigation requirements."),
        ("Permissions-Policy", "Can restrict access to browser features such as camera or microphone.",
         "Define a Permissions-Policy for browser features the application does not need."),
        ("Cross-Origin-Opener-Policy", "Can isolate a browsing context from cross-origin windows.",
         "Review whether Cross-Origin-Opener-Policy is suitable for the application's window and authentication flows."),
        ("Cross-Origin-Resource-Policy", "Can control whether other origins may load a response as a resource.",
         "Review whether Cross-Origin-Resource-Policy is suitable for the resources served by this application."),
    ]
    for header, explanation, recommendation in checks:
        value = headers.get(header)
        findings.append(finding(header, bool(value), "Info" if value else "Low",
            f"Header present. {explanation}" if value else f"Header missing. {explanation}",
            recommendation, value or "Not returned by the target"))

    findings.append(finding(
        "Strict-Transport-Security", True, "Info",
        "Not assessed: the target uses HTTP. HSTS is a browser policy delivered over HTTPS.",
        "When testing an HTTPS deployment, verify HSTS is configured deliberately with a suitable max-age and subdomain policy.",
        "Skipped for HTTP target"))

    csp = headers.get("Content-Security-Policy", "")
    if csp:
        csp_lower = csp.lower()
        unsafe_markers = [token for token in ("'unsafe-inline'", "'unsafe-eval'", "*") if token in csp_lower]
        findings.append(finding(
            "Content-Security-Policy configuration review", not unsafe_markers,
            "Medium" if unsafe_markers else "Info",
            ("The CSP contains potentially permissive tokens: " + ", ".join(unsafe_markers) + ". Human review is needed.")
            if unsafe_markers else "No basic permissive-token heuristic matched; this does not prove the policy is safe.",
            "Review whether permissive tokens are necessary. Prefer nonces or hashes for inline scripts where feasible, and narrowly scoped sources.",
            csp))

    cookies = []
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    if raw_headers is not None and hasattr(raw_headers, "getlist"):
        cookies = raw_headers.getlist("Set-Cookie") or []
    if not cookies and headers.get("Set-Cookie"):
        cookies = [headers.get("Set-Cookie")]
    if not cookies:
        findings.append(finding(
            "Cookie security attributes", True, "Info",
            "No Set-Cookie header was observed in this response; cookie flags could not be assessed.",
            "If authentication/session cookies are set on other routes, review Secure, HttpOnly, and SameSite on those responses.",
            "No Set-Cookie header observed"))
    else:
        for index, cookie in enumerate(cookies, start=1):
            cookie_name = cookie.split("=", 1)[0].strip() or f"Cookie {index}"
            parts = [part.strip().lower() for part in cookie.split(";")[1:]]
            missing = []
            if not any(part == "secure" for part in parts): missing.append("Secure")
            if not any(part == "httponly" for part in parts): missing.append("HttpOnly")
            if not any(part.startswith("samesite=") for part in parts): missing.append("SameSite")
            findings.append(finding(
                f"Cookie attributes: {cookie_name}", not missing, "Low" if missing else "Info",
                "Cookie appears to omit: " + ", ".join(missing) + ". Suitability depends on the cookie's purpose."
                if missing else "Observed cookie includes Secure, HttpOnly, and SameSite attributes.",
                "For session cookies, review Secure (HTTPS), HttpOnly, and an appropriate SameSite value. Cookie values are not stored in evidence.",
                "Set-Cookie observed; cookie value omitted from evidence"))

    return findings

def perform_request(url):
    try:
        return requests.get(url, timeout=5, allow_redirects=False, headers={"User-Agent": USER_AGENT})
    except requests.RequestException:
        return None

def calculate_risk(findings):
    """
    Transparent heuristic score from 0 (lower observed risk) to 100 (higher observed risk).
    This is a prioritization aid, not a validated security rating.
    """
    weights = {"Critical": 30, "High": 20, "Medium": 10, "Low": 3}
    total = 0
    review_items = 0
    for item in findings:
        severity = item.get("severity", "Info")
        if not item.get("present") and severity in weights:
            total += weights[severity]
            review_items += 1
    score = min(100, total)
    if score >= 70:
        label = "High"
    elif score >= 35:
        label = "Elevated"
    elif score >= 10:
        label = "Moderate"
    else:
        label = "Low"
    return {
        "score": score,
        "label": label,
        "review_items": review_items,
        "method": "Adds heuristic weights for missing/review findings (Critical 30, High 20, Medium 10, Low 3), capped at 100. Informational and not-assessed items do not add points. This is not a validated security rating."
    }

def row_to_result(row):
    result = {
        "id": row["id"], "target": row["target"], "scanned_at": row["scanned_at"],
        "http_status": row["http_status"], "headers_checked": row["headers_checked"],
        "missing_headers": row["missing_headers"], "findings": json.loads(row["findings_json"]),
        "note": row["note"],
    }
    result["risk"] = calculate_risk(result["findings"])
    return result

def save_scan(target, response, findings, note):
    result = {
        "target": target,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "http_status": response.status_code,
        "headers_checked": len(findings),
        "missing_headers": sum(1 for item in findings if not item["present"] and item["severity"] != "Info"),
        "findings": findings,
        "note": note,
    }
    with connect_db() as db:
        cursor = db.execute(
            """INSERT INTO scans
            (target, scanned_at, http_status, headers_checked, missing_headers, findings_json, note)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (result["target"], result["scanned_at"], result["http_status"],
             result["headers_checked"], result["missing_headers"], json.dumps(result["findings"]), result["note"]),
        )
        result["id"] = cursor.lastrowid
        db.commit()
    result["risk"] = calculate_risk(result["findings"])
    return result

def crawl_pages(start_url, max_pages):
    # Crawl only the exact starting origin, only HTML pages, no form submission,
    # no query-string mutation, no external hosts, and no redirect following.
    queue = deque([start_url])
    visited = set()
    pages = []
    base = urlparse(start_url)

    while queue and len(visited) < max_pages:
        current = queue.popleft()
        current, _fragment = urldefrag(current)
        if current in visited:
            continue
        if not same_origin(start_url, current):
            continue
        parsed = urlparse(current)
        if parsed.scheme not in {"http", "https"}:
            continue
        visited.add(current)
        response = perform_request(current)
        if response is None:
            pages.append({"url": current, "status": None, "content_type": None, "note": "Request failed or timed out.", "findings": []})
            continue

        content_type = response.headers.get("Content-Type", "")
        is_html = "text/html" in content_type.lower()
        page_findings = evaluate_response(response) if is_html else []
        pages.append({
            "url": current,
            "status": response.status_code,
            "content_type": content_type or "Not supplied",
            "note": "HTML response checked." if is_html else "Non-HTML response; link extraction and header checks skipped.",
            "findings": page_findings,
            "missing_headers": sum(1 for item in page_findings if not item["present"] and item["severity"] != "Info"),
        })

        if not is_html or response.status_code >= 400:
            continue
        try:
            soup = BeautifulSoup(response.text, "html.parser")
        except Exception:
            continue
        for link in soup.find_all("a", href=True):
            href = link.get("href", "").strip()
            if not href or href.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
                continue
            absolute = urljoin(current, href)
            absolute, _frag = urldefrag(absolute)
            link_parsed = urlparse(absolute)
            # Avoid query URLs for this first crawler version to reduce duplicate
            # dynamic endpoints and accidental state changes.
            if link_parsed.query:
                continue
            if link_parsed.path.lower().endswith((
                ".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".pdf",
                ".zip", ".woff", ".woff2", ".ico", ".mp4", ".webm"
            )):
                continue
            if same_origin(start_url, absolute) and absolute not in visited and absolute not in queue:
                queue.append(absolute)

    return pages

@app.get("/")
def home():
    return {"message": "WebSentinel backend is running.", "status": "ready", "version": "1.0.0"}

@app.get("/health")
def health():
    with connect_db() as db:
        count = db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    return {"status": "ok", "version": "1.0.0", "saved_scans": count}

@app.post("/scan")
def scan(request: ScanRequest):
    target = request.target.strip()
    validate_target(target)
    response = perform_request(target)
    if response is None:
        raise HTTPException(status_code=502, detail="Could not reach the target. Check the URL, network connection, and whether the website is available.")
    findings = evaluate_response(response)
    note = (
        "Checks include response-header presence, basic CSP token heuristics, and cookie attributes when Set-Cookie is observed. "
        "These are lightweight observations, not proof of exploitable vulnerabilities. HSTS is not meaningfully assessed on HTTP targets. Only authorized targets should be scanned."
    )
    return save_scan(target, response, findings, note)

@app.post("/crawl")
def crawl(request: CrawlRequest):
    target = request.target.strip()
    validate_target(target)
    pages = crawl_pages(target, request.max_pages)
    if not pages:
        raise HTTPException(status_code=502, detail="No pages could be fetched from the local target.")
    all_findings = sum(len(page.get("findings", [])) for page in pages)
    return {
        "target": target,
        "max_pages": request.max_pages,
        "pages_visited": len(pages),
        "findings_checked": all_findings,
        "pages": pages,
        "note": "Crawler follows same-origin HTTP(S) HTML links only, does not submit forms, does not follow redirects, skips query-string URLs, and is limited to 30 pages maximum. This is a passive crawl, not a full vulnerability scan.",
    }

@app.post("/xss-check")
def xss_check(request: XSSCheckRequest):
    target = request.target.strip()
    validate_target(target)

    # Harmless canary string only: no HTML/JavaScript payload is sent or executed.
    canary = "WEBSENTINEL_REFLECTION_CANARY_7F3A9C"
    parsed = urlparse(target)
    from urllib.parse import parse_qsl, urlencode, urlunparse
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query["websentinel_probe"] = canary
    probe_url = urlunparse(parsed._replace(query=urlencode(query)))

    response = perform_request(probe_url)
    if response is None:
        raise HTTPException(
            status_code=502,
            detail="Could not reach the target. Check the URL, network connection, and whether the website is available.",
        )

    body = response.text[:1_000_000]
    reflected = canary in body
    escaped_reflection = (
        canary in body
        and any(token in body for token in ("&lt;", "&#", "&gt;"))
    )

    return {
        "target": target,
        "probe_parameter": "websentinel_probe",
        "http_status": response.status_code,
        "canary_reflected": reflected,
        "result": (
            "Canary string was reflected in the response. This is only a reflection signal; it does not prove XSS."
            if reflected
            else "Canary string was not found in the response body. This does not rule out XSS in other parameters or routes."
        ),
        "note": (
            "Non-destructive reflection check only. It sends a plain text marker, not executable HTML or JavaScript. "
            "It does not submit forms, execute scripts, or confirm exploitability. Only test websites you own or are authorized to assess."
        ),
    }

@app.get("/history")
def history(limit: int = 50):
    limit = max(1, min(limit, 200))
    with connect_db() as db:
        rows = db.execute(
            """SELECT id, target, scanned_at, http_status, headers_checked,
            missing_headers, findings_json, note FROM scans ORDER BY id DESC LIMIT ?""", (limit,)
        ).fetchall()
    return {"count": len(rows), "scans": [row_to_result(row) for row in rows]}

@app.get("/history/{scan_id}")
def scan_detail(scan_id: int):
    with connect_db() as db:
        row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return row_to_result(row)

@app.get("/report", response_class=HTMLResponse)
def report(scan_id: int | None = None):
    with connect_db() as db:
        row = db.execute("SELECT * FROM scans WHERE id = ?" if scan_id is not None else "SELECT * FROM scans ORDER BY id DESC LIMIT 1",
                         (scan_id,) if scan_id is not None else ()).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="No saved scan found. Run a scan first.")
    result = row_to_result(row)
    findings = result["findings"]
    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    severity_counts = {key: sum(1 for item in findings if item.get("severity", "Info") == key) for key in severity_order}
    status_counts = {
        "Present": sum(1 for item in findings if item.get("present")),
        "Review": sum(1 for item in findings if not item.get("present") and item.get("severity") != "Info"),
        "Not assessed": sum(1 for item in findings if not item.get("present") and item.get("severity") == "Info"),
    }
    severity_colors = {"Critical": "#991b1b", "High": "#dc2626", "Medium": "#d97706", "Low": "#2563eb", "Info": "#64748b"}
    max_sev = max(severity_counts.values(), default=0) or 1
    severity_bars = "".join(
        f'<div class="bar-row"><span>{escape(key)}</span><div class="track"><div class="bar" style="width:{severity_counts[key] / max_sev * 100:.1f}%;background:{severity_colors[key]}"></div></div><b>{severity_counts[key]}</b></div>'
        for key in severity_order
    )
    status_total = max(sum(status_counts.values()), 1)
    status_cards = "".join(
        f'<div class="mini"><span>{escape(key)}</span><strong>{value}</strong><div class="track"><div class="bar" style="width:{value / status_total * 100:.1f}%;background:{color}"></div></div></div>'
        for key, value, color in [("Present", status_counts["Present"], "#15803d"), ("Review", status_counts["Review"], "#d97706"), ("Not assessed", status_counts["Not assessed"], "#64748b")]
    )
    rows = []
    for item in findings:
        name, message = escape(str(item.get("header", ""))), escape(str(item.get("message", "")))
        recommendation, evidence = escape(str(item.get("recommendation", ""))), escape(str(item.get("evidence", "")))
        severity = escape(str(item.get("severity", "Unspecified")))
        if item.get("present"):
            status, color = "Present / informational", "#16794b"
        elif severity == "Info":
            status, color = "Not assessed", "#555b73"
        else:
            status, color = "Review recommended", "#a65b00"
        rows.append(f"<tr><td>{name}</td><td style='color:{color};font-weight:700'>{status}</td><td><span class='severity'>{severity}</span></td><td>{message}<br><strong>Evidence:</strong> {evidence}<br><strong>Recommendation:</strong> {recommendation}</td></tr>")
    risk = result["risk"]
    document = f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>WebSentinel Security Report #{result['id']}</title><style>
:root{{--ink:#172033;--muted:#667085;--line:#e4e7ec;--paper:#f7f8fc;--purple:#6040b0}}*{{box-sizing:border-box}}body{{font-family:Inter,Segoe UI,Arial,sans-serif;max-width:1120px;margin:32px auto;padding:0 22px;color:var(--ink);background:white;line-height:1.5}}.top{{background:linear-gradient(120deg,#201445,#6040b0);color:white;padding:30px;border-radius:18px}}.top h1{{margin:0 0 8px;font-size:30px}}.top p{{margin:4px 0;color:#eee8ff;overflow-wrap:anywhere}}.eyebrow{{text-transform:uppercase;letter-spacing:2px;font-size:11px;font-weight:700;color:#d8ccff}}h2{{font-size:18px;margin:28px 0 12px}}.summary{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:18px}}.card,.chart-card{{border:1px solid var(--line);background:#fff;padding:17px;border-radius:12px;min-width:0}}.card span,.mini span{{display:block;color:var(--muted);font-size:12px}}.card strong{{font-size:25px;display:block;margin-top:6px}}.riskline{{height:9px;border-radius:10px;background:#eee;overflow:hidden;margin-top:12px}}.riskfill{{height:100%;background:#6040b0}}.charts{{display:grid;grid-template-columns:1fr 1fr;gap:14px}}.bar-row{{display:grid;grid-template-columns:92px 1fr 24px;gap:10px;align-items:center;margin:13px 0;font-size:13px}}.track{{height:10px;background:#eef0f5;border-radius:10px;overflow:hidden}}.bar{{height:100%;border-radius:10px;min-width:0}}.mini{{margin:12px 0}}.mini strong{{float:right}}.mini .track{{clear:both;position:relative;top:5px}}table{{width:100%;border-collapse:collapse;margin-top:14px;font-size:13px}}th,td{{border:1px solid var(--line);padding:11px;text-align:left;overflow-wrap:anywhere;vertical-align:top}}th{{background:#f1edfb;color:#30204e}}.severity{{display:inline-block;background:#f1f3f7;padding:3px 7px;border-radius:5px;font-weight:600}}.note{{margin-top:20px;background:#fff8e6;border-left:4px solid #d97706;padding:14px;border-radius:7px}}.foot{{color:var(--muted);font-size:12px;margin:22px 0}}button{{padding:10px 15px;border:0;border-radius:8px;background:#6040b0;color:white;cursor:pointer}}@media(max-width:700px){{.summary{{grid-template-columns:repeat(2,minmax(0,1fr))}}.charts{{grid-template-columns:1fr}}}}@media print{{button{{display:none}}body{{margin:0;max-width:none}}.top{{print-color-adjust:exact;-webkit-print-color-adjust:exact}}.card,.chart-card,table{{break-inside:avoid}}}}
</style></head><body><header class="top"><div class="eyebrow">WebSentinel · Security assessment</div><h1>Web Application Security Report</h1><p><strong>Target:</strong> {escape(result['target'])}</p><p><strong>Scan ID:</strong> {result['id']} &nbsp; · &nbsp; <strong>Scan time (UTC):</strong> {escape(result['scanned_at'])}</p></header>
<div class="summary"><div class="card"><span>HTTP status</span><strong>{result['http_status']}</strong></div><div class="card"><span>Checks recorded</span><strong>{result['headers_checked']}</strong></div><div class="card"><span>Items for review</span><strong>{result['missing_headers']}</strong></div><div class="card"><span>Heuristic risk score</span><strong>{risk['score']}<small style="font-size:13px"> / 100</small></strong><span>{escape(risk['label'])} · indicative only</span><div class="riskline"><div class="riskfill" style="width:{risk['score']}%"></div></div></div></div>
<h2>Visual summary</h2><div class="charts"><section class="chart-card"><h3>Findings by severity</h3>{severity_bars}</section><section class="chart-card"><h3>Check status breakdown</h3>{status_cards}<p style="font-size:12px;color:var(--muted)">Status describes whether checks were present, require review, or were not assessed.</p></section></div>
<h2>Detailed findings</h2><table><thead><tr><th>Check</th><th>Status</th><th>Severity</th><th>Details, evidence and recommendation</th></tr></thead><tbody>{''.join(rows)}</tbody></table><div class="note"><strong>Scope and interpretation:</strong> {escape(result['note'])}<br><br>The risk score is a transparent heuristic for prioritization, not a validated security rating. A missing header is not by itself proof of an exploitable vulnerability. This report covers only the checks implemented in WebSentinel.</div><p class="foot">Generated by WebSentinel · Scan #{result['id']} · Use only for systems you own or are authorized to assess.</p><button onclick="window.print()">Print / Save as PDF</button></body></html>"""
    return HTMLResponse(document, headers={"Content-Disposition": f'attachment; filename="websentinel-report-{result["id"]}.html"'})


@app.get("/report.pdf")
def report_pdf(scan_id: int | None = None):
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_LEFT, TA_CENTER
        from reportlab.lib.units import inch
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
        from reportlab.graphics.shapes import Drawing, String, Rect, Line
        from reportlab.graphics.charts.barcharts import HorizontalBarChart
    except ImportError as exc:
        raise HTTPException(status_code=500, detail="PDF support is not installed. Run: backend\\.venv\\Scripts\\python.exe -m pip install reportlab") from exc

    with connect_db() as db:
        row = db.execute("SELECT * FROM scans WHERE id = ?" if scan_id is not None else "SELECT * FROM scans ORDER BY id DESC LIMIT 1",
                         (scan_id,) if scan_id is not None else ()).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="No saved scan found. Run a scan first.")
    result = row_to_result(row)
    findings = result["findings"]
    severity_order = ["Critical", "High", "Medium", "Low", "Info"]
    severity_counts = {key: sum(1 for item in findings if item.get("severity", "Info") == key) for key in severity_order}
    status_counts = {
        "Present": sum(1 for item in findings if item.get("present")),
        "Review recommended": sum(1 for item in findings if not item.get("present") and item.get("severity") != "Info"),
        "Not assessed": sum(1 for item in findings if not item.get("present") and item.get("severity") == "Info"),
    }
    palette = {"Critical": colors.HexColor("#991b1b"), "High": colors.HexColor("#dc2626"), "Medium": colors.HexColor("#d97706"), "Low": colors.HexColor("#2563eb"), "Info": colors.HexColor("#64748b")}
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=.55*inch, leftMargin=.55*inch, topMargin=.62*inch, bottomMargin=.62*inch, title=f"WebSentinel Security Report #{result['id']}", author="WebSentinel")
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="WSSubtitle", parent=styles["Normal"], fontSize=9, leading=13, textColor=colors.HexColor("#667085"), spaceAfter=4))
    styles.add(ParagraphStyle(name="WSSection", parent=styles["Heading2"], fontSize=15, leading=18, textColor=colors.HexColor("#35205f"), spaceBefore=12, spaceAfter=8))
    styles.add(ParagraphStyle(name="WSTable", parent=styles["BodyText"], fontSize=7.4, leading=9.2, spaceAfter=0, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="WSTableHead", parent=styles["BodyText"], fontSize=7.6, leading=9, textColor=colors.white, fontName="Helvetica-Bold"))
    styles.add(ParagraphStyle(name="WSKPI", parent=styles["Normal"], fontSize=9, leading=12, textColor=colors.HexColor("#475467"), alignment=TA_CENTER))
    styles.add(ParagraphStyle(name="WSKPIValue", parent=styles["Heading2"], fontSize=19, leading=22, textColor=colors.HexColor("#35205f"), alignment=TA_CENTER, spaceAfter=0))

    def draw_page(canvas, document):
        canvas.saveState()
        width, height = letter
        canvas.setFillColor(colors.HexColor("#35205f")); canvas.rect(0, height - .18*inch, width, .18*inch, stroke=0, fill=1)
        canvas.setStrokeColor(colors.HexColor("#e4e7ec")); canvas.line(.55*inch, .43*inch, width - .55*inch, .43*inch)
        canvas.setFont("Helvetica", 7.5); canvas.setFillColor(colors.HexColor("#667085"))
        canvas.drawString(.55*inch, .27*inch, f"WebSentinel · Scan #{result['id']} · Authorized assessment only")
        canvas.drawRightString(width - .55*inch, .27*inch, f"Page {document.page}")
        canvas.restoreState()

    story = [Paragraph("WEBSENTINEL", ParagraphStyle("WSBrand", parent=styles["Title"], fontSize=11, leading=13, textColor=colors.HexColor("#6040b0"), alignment=TA_LEFT, spaceAfter=5)),
             Paragraph("Web Application Security Report", ParagraphStyle("WSMainTitle", parent=styles["Title"], fontSize=24, leading=28, textColor=colors.HexColor("#172033"), alignment=TA_LEFT, spaceAfter=9)),
             Paragraph(f"<b>Target:</b> {escape(result['target'])}", styles["Normal"]),
             Paragraph(f"<b>Scan ID:</b> {result['id']} &nbsp;&nbsp; <b>Scan time (UTC):</b> {escape(result['scanned_at'])}", styles["WSSubtitle"]),
             Spacer(1, 10)]
    kpi_data = [[Paragraph("HTTP STATUS", styles["WSKPI"]), Paragraph("CHECKS", styles["WSKPI"]), Paragraph("REVIEW ITEMS", styles["WSKPI"]), Paragraph("RISK SCORE", styles["WSKPI"])],
                [Paragraph(str(result["http_status"]), styles["WSKPIValue"]), Paragraph(str(result["headers_checked"]), styles["WSKPIValue"]), Paragraph(str(result["missing_headers"]), styles["WSKPIValue"]), Paragraph(f"{result['risk']['score']} / 100", styles["WSKPIValue"])],
                [Paragraph("HTTP response", styles["WSKPI"]), Paragraph("Recorded checks", styles["WSKPI"]), Paragraph("Need review", styles["WSKPI"]), Paragraph(escape(result["risk"]["label"])+" · heuristic", styles["WSKPI"])]]
    kpi = Table(kpi_data, colWidths=[1.78*inch]*4, rowHeights=[.25*inch, .38*inch, .25*inch])
    kpi.setStyle(TableStyle([("BACKGROUND", (0,0),(-1,-1), colors.HexColor("#f5f3fb")), ("BOX",(0,0),(-1,-1),.6,colors.HexColor("#e3def1")), ("INNERGRID",(0,0),(-1,-1),.4,colors.HexColor("#e3def1")), ("VALIGN",(0,0),(-1,-1),"MIDDLE"), ("TOPPADDING",(0,0),(-1,-1),5), ("BOTTOMPADDING",(0,0),(-1,-1),5)]))
    story += [kpi, Spacer(1, 10)]
    risk_drawing = Drawing(500, 24)
    risk_drawing.add(String(0, 13, "Heuristic risk score", fontName="Helvetica-Bold", fontSize=8, fillColor=colors.HexColor("#475467")))
    risk_drawing.add(Rect(130, 8, 300, 10, rx=5, ry=5, fillColor=colors.HexColor("#e8e7ee"), strokeColor=None))
    if result["risk"]["score"] > 0:
        risk_drawing.add(Rect(130, 8, 300*result["risk"]["score"]/100, 10, rx=5, ry=5, fillColor=colors.HexColor("#6040b0"), strokeColor=None))
    risk_drawing.add(String(442, 10, f"{result['risk']['score']}%", fontName="Helvetica-Bold", fontSize=9, fillColor=colors.HexColor("#35205f")))
    story += [risk_drawing, Paragraph("Visual summary", styles["WSSection"])]

    # Horizontal bar chart for severity counts.
    chart = HorizontalBarChart()
    chart.width = 310; chart.height = 145
    chart.x = 105; chart.y = 18
    chart.data = [tuple(severity_counts[k] for k in severity_order)]
    chart.categoryAxis.categoryNames = severity_order
    chart.categoryAxis.labels.fontName = "Helvetica"; chart.categoryAxis.labels.fontSize = 8
    chart.categoryAxis.labels.dx = -4
    chart.valueAxis.valueMin = 0; chart.valueAxis.valueMax = max(max(severity_counts.values(), default=0), 1)
    chart.valueAxis.valueStep = max(1, (chart.valueAxis.valueMax + 3) // 4)
    chart.valueAxis.labels.fontName = "Helvetica"; chart.valueAxis.labels.fontSize = 7
    chart.bars[0].fillColor = colors.HexColor("#6040b0")
    chart.bars[0].strokeColor = None
    chart.barWidth = 10; chart.groupSpacing = 8
    chart.valueAxis.visibleGrid = True
    chart.valueAxis.gridStrokeColor = colors.HexColor("#e4e7ec")
    chart.categoryAxis.strokeColor = colors.HexColor("#c9cbd5")
    chart.valueAxis.strokeColor = colors.HexColor("#c9cbd5")
    chart_drawing = Drawing(430, 175); chart_drawing.add(chart)
    status_drawing = Drawing(430, 175)
    status_drawing.add(String(0, 155, "Check status breakdown", fontName="Helvetica-Bold", fontSize=10, fillColor=colors.HexColor("#35205f")))
    status_colors = [colors.HexColor("#15803d"), colors.HexColor("#d97706"), colors.HexColor("#64748b")]
    y = 125
    total_status = max(sum(status_counts.values()), 1)
    for (label, count), color in zip(status_counts.items(), status_colors):
        status_drawing.add(String(0, y+2, label, fontName="Helvetica", fontSize=8, fillColor=colors.HexColor("#344054")))
        status_drawing.add(Rect(125, y, 230, 11, rx=4, ry=4, fillColor=colors.HexColor("#eef0f5"), strokeColor=None))
        if count:
            status_drawing.add(Rect(125, y, 230*count/total_status, 11, rx=4, ry=4, fillColor=color, strokeColor=None))
        status_drawing.add(String(365, y+2, str(count), fontName="Helvetica-Bold", fontSize=8, fillColor=colors.HexColor("#172033")))
        y -= 35
    status_drawing.add(String(0, 10, "Present, review recommended, and not assessed.", fontName="Helvetica-Oblique", fontSize=7, fillColor=colors.HexColor("#667085")))
    charts = Table([[chart_drawing, status_drawing]], colWidths=[3.65*inch, 3.35*inch])
    charts.setStyle(TableStyle([("VALIGN",(0,0),(-1,-1),"TOP"), ("LEFTPADDING",(0,0),(-1,-1),0), ("RIGHTPADDING",(0,0),(-1,-1),2), ("TOPPADDING",(0,0),(-1,-1),2), ("BOTTOMPADDING",(0,0),(-1,-1),2)]))
    story += [charts, Paragraph("Detailed findings", styles["WSSection"])]
    data = [[Paragraph("CHECK", styles["WSTableHead"]), Paragraph("STATUS", styles["WSTableHead"]), Paragraph("SEVERITY", styles["WSTableHead"]), Paragraph("DETAILS, EVIDENCE & RECOMMENDATION", styles["WSTableHead"])]]
    for item in findings:
        status = "Present / info" if item.get("present") else ("Not assessed" if item.get("severity") == "Info" else "Review")
        details = f"{item.get('message', '')}<br/><b>Evidence:</b> {item.get('evidence', '')}<br/><b>Recommendation:</b> {item.get('recommendation', '')}"
        data.append([Paragraph(escape(str(item.get("header", ""))), styles["WSTable"]), Paragraph(escape(status), styles["WSTable"]), Paragraph(escape(str(item.get("severity", ""))), styles["WSTable"]), Paragraph(escape(details), styles["WSTable"])])
    table = Table(data, colWidths=[1.28*inch, .88*inch, .62*inch, 4.22*inch], repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#35205f")), ("GRID",(0,0),(-1,-1),.4,colors.HexColor("#d0d5dd")), ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,colors.HexColor("#faf9fd")]), ("VALIGN",(0,0),(-1,-1),"TOP"), ("LEFTPADDING",(0,0),(-1,-1),5), ("RIGHTPADDING",(0,0),(-1,-1),5), ("TOPPADDING",(0,0),(-1,-1),5), ("BOTTOMPADDING",(0,0),(-1,-1),5)]))
    story += [table, Spacer(1, 12), Paragraph("Scope and interpretation", styles["WSSection"]), Paragraph(escape(result["note"]), styles["Normal"]), Spacer(1, 6), Paragraph(escape(result["risk"]["method"]), styles["WSSubtitle"]), Paragraph("This report covers only the checks implemented in WebSentinel. A missing header is not proof of an exploitable vulnerability. The heuristic score is a prioritization aid, not a validated security rating. Scan only systems you own or are authorized to assess.", styles["WSSubtitle"])]
    doc.build(story, onFirstPage=draw_page, onLaterPages=draw_page)
    buffer.seek(0)
    return StreamingResponse(buffer, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="websentinel-report-{result["id"]}.pdf"'})
