"""
License Control - Python (Faable-ready)
main.py + requirements.txt كما طلبت.

نفس منطق Node تماماً: يخدم على Faable Deploy عبر HOST=0.0.0.0 و PORT من البيئة.
"""
import os
import re
import hmac
import hashlib
import secrets
import base64
import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

import asyncpg
from fastapi import FastAPI, Request, HTTPException, Depends, Header
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from jose import jwt
from jose.exceptions import JWTError
import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

# ----- Config -----
def env(name, default=""):
    return os.getenv(name, default)

def config_from_env():
    raw_subjects = env("ADMIN_SUBJECTS", "")
    subjects = [s.strip() for s in raw_subjects.split(",") if s.strip()]
    return {
        "node_env": env("NODE_ENV", "production"),
        "host": env("HOST", "0.0.0.0"),
        "port": int(env("PORT", "3000")),
        "database_url": env("DATABASE_URL", ""),
        "database_ssl": env("DATABASE_SSL", "true") != "false",
        "code_pepper": env("ACTIVATION_CODE_PEPPER", ""),
        "grant_private_b64": env("GRANT_PRIVATE_KEY_B64", ""),
        "grant_public_b64": env("GRANT_PUBLIC_KEY_B64", ""),
        "grant_key_id": env("GRANT_KEY_ID", "2026-01"),
        "faable_issuer": env("FAABLE_AUTH_ISSUER", ""),
        "faable_audience": env("FAABLE_AUTH_AUDIENCE", ""),
        "faable_jwks_url": env("FAABLE_AUTH_JWKS_URL", ""),
        "admin_subjects": subjects,
        "telegram_token": env("TELEGRAM_BOT_TOKEN", ""),
        "telegram_secret": env("TELEGRAM_WEBHOOK_SECRET", ""),
        "telegram_api_base": env("TELEGRAM_API_BASE", "https://api.telegram.org"),
    }

CONFIG = config_from_env()

# ----- Constants & validation -----
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)
PUBLIC_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,80}$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,39}$")

DEFAULT_FREEZE_MESSAGE = "تم إيقاف هذا الترخيص مؤقتًا. بياناتك وملفاتك محفوظة. للمساعدة أو إعادة التفعيل، تواصل مع مطوّر التطبيق."
DEFAULT_REVOKE_MESSAGE = "هذا الترخيص غير صالح حاليًا. للمساعدة، تواصل مع مطوّر التطبيق."
TELEGRAM_PRIVACY = "نستخدم معرّف Telegram الرقمي مؤقتًا لإرسال نتيجة الطلب فقط. لا نجمع اسمك أو جهات اتصالك أو موقعك. يُحذف المعرّف من الطلب بعد التسليم الناجح. يمكنك كتابة /forget لإلغاء طلباتك المعلّقة ومحو المعرّف منها."

def domain_error(code: str, status: int, message: str):
    raise HTTPException(status_code=status, detail={"code": code, "message": message})

def normalize_code(v: str) -> str:
    s = re.sub(r"[^A-Z0-9]", "", str(v or "").strip().upper())
    if len(s) != 15 or any(c not in CODE_ALPHABET for c in s):
        domain_error("INVALID_CODE_FORMAT", 400, "Activation code must contain 15 unambiguous characters.")
    return s

def format_code(normalized: str) -> str:
    return "-".join(normalized[i:i+5] for i in range(0, 15, 5))

def generate_code():
    raw = secrets.token_bytes(15)
    normalized = "".join(CODE_ALPHABET[b % len(CODE_ALPHABET)] for b in raw)
    return {"normalized": normalized, "formatted": format_code(normalized), "hint": f"•••••-•••••-{normalized[-5:]}"}

def hash_code(normalized: str, pepper: str) -> bytes:
    return hmac.new(pepper.encode(), normalized.encode(), hashlib.sha256).digest()

def generate_token() -> str:
    return "lc_" + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")

def hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()

def sign_payload(payload_json: str, private_b64: str) -> str:
    priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(private_b64 + "==" if len(private_b64) % 4 else private_b64) if len(private_b64) < 200 else base64.b64decode(private_b64))
    # private_b64 is DER PKCS8 base64
    # decode DER
    from cryptography.hazmat.primitives.serialization import load_der_private_key
    key = load_der_private_key(base64.b64decode(private_b64), password=None)
    sig = key.sign(payload_json.encode())
    return base64.urlsafe_b64encode(sig).decode().rstrip("=")

def keypair_for_env():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_der = priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    pub_der = pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return {"privateKey": base64.b64encode(priv_der).decode(), "publicKey": base64.b64encode(pub_der).decode()}

def effective_status(product, license, installation):
    if not product["active"]:
        return "frozen"
    if installation["status"] != "active":
        return installation["status"]
    if license["status"] != "active":
        return license["status"]
    if license.get("expires_at") and license["expires_at"] <= datetime.now(timezone.utc):
        return "revoked"
    return "active"

def make_grant(product, license, installation, config, now=None):
    if now is None:
        now = datetime.now(timezone.utc)
    status = effective_status(product, license, installation)
    expires = now + timedelta(seconds=product["offline_grace_seconds"])
    payload = {
        "v": 1,
        "product": product["slug"],
        "licenseId": license["id"],
        "installationId": installation["public_id"],
        "status": status,
        "protectedFeatures": status == "active",
        "freezeScope": product.get("freeze_scope", "generation"),
        "message": (installation.get("message") or license.get("message") or DEFAULT_FREEZE_MESSAGE) if status == "frozen" else (installation.get("message") or license.get("message") or DEFAULT_REVOKE_MESSAGE) if status == "revoked" else None,
        "issuedAt": now.isoformat(),
        "expiresAt": expires.isoformat(),
    }
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    sig = sign_payload(canonical, config["grant_private_b64"])
    return {
        "algorithm": "Ed25519",
        "keyId": config["grant_key_id"],
        "payload": base64.urlsafe_b64encode(canonical.encode()).decode().rstrip("="),
        "signature": sig,
        "decoded": payload,  # for debugging, client uses payload+signature
    }

# ----- DB Pool -----
pool: Optional[asyncpg.Pool] = None

async def get_pool():
    global pool
    if pool is None:
        if not CONFIG["database_url"]:
            raise RuntimeError("DATABASE_URL is not set")
        # Faable gives DATABASE_URL with sslmode=require ; asyncpg handles ssl
        pool = await asyncpg.create_pool(CONFIG["database_url"], min_size=1, max_size=5)
    return pool

async def close_pool():
    global pool
    if pool:
        await pool.close()
        pool = None

# ----- Helpers DB -----
def row_to_dict(row):
    if row is None:
        return None
    return dict(row)

async def audit_event(actor, action, entity_type, entity_id=None, product_id=None, metadata=None, conn=None):
    p = conn or await get_pool()
    await p.execute(
        "INSERT INTO audit_events(actor, action, entity_type, entity_id, product_id, metadata) VALUES($1,$2,$3,$4,$5,$6::jsonb)",
        actor, action, entity_type, entity_id, product_id, json.dumps(metadata or {})
    )

# ----- Faable JWT verifier -----
jwks_cache = None
jwks_cache_at = None

async def verify_admin(request: Request):
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer "):
        domain_error("ADMIN_UNAUTHORIZED", 401, "Admin bearer token is required.")
    token = auth[7:]
    # fetch JWKS
    try:
        # use python-jose with jwks url
        # simple: fetch jwks and verify
        async with httpx.AsyncClient(timeout=10) as client:
            jwks_resp = await client.get(CONFIG["faable_jwks_url"])
            jwks_resp.raise_for_status()
            jwks = jwks_resp.json()
        # jose can verify with key dict
        # try each key
        payload = None
        last_err = None
        for key in jwks.get("keys", []):
            try:
                payload = jwt.decode(token, key, algorithms=["RS256"], audience=CONFIG["faable_audience"], issuer=CONFIG["faable_issuer"])
                break
            except Exception as e:
                last_err = e
                continue
        if payload is None:
            raise last_err or Exception("invalid")
        sub = payload.get("sub")
        if not sub or sub not in CONFIG["admin_subjects"]:
            domain_error("ADMIN_FORBIDDEN", 403, "This identity is not an administrator.")
        request.state.admin_subject = sub
        return sub
    except HTTPException:
        raise
    except Exception as e:
        domain_error("ADMIN_UNAUTHORIZED", 401, "Admin token is invalid or expired.")

# ----- FastAPI App -----
app = FastAPI(title="License Control", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.get("/healthz")
async def healthz():
    return {"ok": True, "service": "license-control", "version": "0.1.0"}

@app.post("/v1/activate")
async def activate(request: Request):
    body = await request.json()
    product_slug = str(body.get("product", "")).strip()
    if not SLUG_RE.match(product_slug):
        domain_error("INVALID_INPUT", 400, "Product is invalid.")
    public_id = str(body.get("installationId", "")).strip()
    if not PUBLIC_ID_RE.match(public_id):
        domain_error("INVALID_INPUT", 400, "Installation ID is invalid.")
    normalized = normalize_code(body.get("code", ""))
    token = generate_token()
    code_hash = hash_code(normalized, CONFIG["code_pepper"])
    token_hash = hash_token(token)

    device = body.get("device", {}) if isinstance(body.get("device"), dict) else {}
    app_version = str(device.get("appVersion") or body.get("appVersion") or "")[:40] or None
    label = str(device.get("label") or "")[:80] or None
    model = str(device.get("model") or "")[:80] or None
    os_ver = str(device.get("osVersion") or "")[:40] or None

    p = await get_pool()
    async with p.acquire() as conn:
        async with conn.transaction():
            product_row = await conn.fetchrow("SELECT * FROM products WHERE slug=$1", product_slug)
            if not product_row or not product_row["active"]:
                domain_error("PRODUCT_NOT_AVAILABLE", 404, "Product is not available.")
            product = row_to_dict(product_row)
            # normalize bool keys
            product["active"] = bool(product["active"])
            lic_row = await conn.fetchrow("SELECT * FROM licenses WHERE product_id=$1 AND code_hash=$2 FOR UPDATE", product["id"], code_hash)
            if not lic_row:
                domain_error("INVALID_ACTIVATION_CODE", 403, "Activation code is invalid.")
            license = row_to_dict(lic_row)
            if license["status"] != "active":
                domain_error("LICENSE_NOT_ACTIVE", 403, "License is not active.")
            if license["expires_at"] and license["expires_at"] <= datetime.now(timezone.utc):
                domain_error("LICENSE_EXPIRED", 403, "License has expired.")
            inst_row = await conn.fetchrow("SELECT * FROM installations WHERE license_id=$1 AND public_id=$2 FOR UPDATE", license["id"], public_id)
            if not inst_row:
                cnt = await conn.fetchval("SELECT COUNT(*)::int FROM installations WHERE license_id=$1 AND status<>'revoked'", license["id"])
                if cnt >= license["max_installations"]:
                    domain_error("DEVICE_LIMIT_REACHED", 409, "Device limit reached.")
                inst_row = await conn.fetchrow(
                    "INSERT INTO installations(id, license_id, public_id, token_hash, device_label, device_model, os_version, app_version) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *",
                    str(uuid.uuid4()), license["id"], public_id, token_hash, label, model, os_ver, app_version
                )
            else:
                inst_row = await conn.fetchrow(
                    "UPDATE installations SET token_hash=$1, device_label=COALESCE($2, device_label), device_model=COALESCE($3, device_model), os_version=COALESCE($4, os_version), app_version=COALESCE($5, app_version), last_seen_at=now() WHERE id=$6 RETURNING *",
                    token_hash, label, model, os_ver, app_version, inst_row["id"]
                )
            installation = row_to_dict(inst_row)
            # adapt keys for grant maker
            license["id"] = str(license["id"])
            installation["public_id"] = installation["public_id"]
            grant = make_grant(product, license, installation, CONFIG)
            # don't leak raw canonical inside? Keep as in Node: payload b64 + signature
            grant_out = {k: v for k, v in grant.items() if k != "decoded"}
            return {"installationToken": token, "grant": grant_out, "product": {"slug": product["slug"], "name": product["name"], "offlineGraceSeconds": product["offline_grace_seconds"]}}

@app.post("/v1/license/status")
async def license_status(request: Request):
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer lc_"):
        domain_error("INSTALLATION_UNAUTHORIZED", 401, "Installation token is required.")
    token = auth[7:]
    thash = hash_token(token)
    p = await get_pool()
    row = await p.fetchrow("SELECT i.*, l.*, p.slug as p_slug, p.name as p_name, p.offline_grace_seconds as p_grace, p.freeze_scope as p_freeze, p.active as p_active FROM installations i JOIN licenses l ON l.id=i.license_id JOIN products p ON p.id=l.product_id WHERE i.token_hash=$1", thash)
    if not row:
        domain_error("INSTALLATION_UNAUTHORIZED", 401, "Installation token is invalid.")
    # update last_seen
    body = {}
    try:
        body = await request.json()
    except:
        body = {}
    app_version = str(body.get("appVersion", ""))[:40] or None
    if app_version:
        await p.execute("UPDATE installations SET app_version=$1, last_seen_at=now() WHERE token_hash=$2", app_version, thash)
    else:
        await p.execute("UPDATE installations SET last_seen_at=now() WHERE token_hash=$1", thash)

    product = {"slug": row["p_slug"], "name": row["p_name"], "offline_grace_seconds": row["p_grace"], "freeze_scope": row["p_freeze"], "active": bool(row["p_active"])}
    license = {"id": str(row["license_id"]), "status": row["status"], "message": row["message"], "expires_at": row["expires_at"]}
    # installation row has its own status/message
    installation = {"public_id": row["public_id"], "status": row["status_1"] if "status_1" in row else row["status"], "message": row["message_1"] if "message_1" in row else None}
    # fix keys: fetchrow duplicates status/message; better fetch separately
    # fallback: fetch installation again
    inst = await p.fetchrow("SELECT * FROM installations WHERE token_hash=$1", thash)
    lic = await p.fetchrow("SELECT * FROM licenses WHERE id=$1", inst["license_id"])
    prod = await p.fetchrow("SELECT * FROM products WHERE id=$1", lic["product_id"])
    product = {"slug": prod["slug"], "name": prod["name"], "offline_grace_seconds": prod["offline_grace_seconds"], "freeze_scope": prod["freeze_scope"], "active": bool(prod["active"])}
    license = {"id": str(lic["id"]), "status": lic["status"], "message": lic["message"], "expires_at": lic["expires_at"]}
    installation = {"public_id": inst["public_id"], "status": inst["status"], "message": inst["message"]}
    grant = make_grant(product, license, installation, CONFIG)
    grant_out = {k: v for k, v in grant.items() if k != "decoded"}
    return {"grant": grant_out}

# ----- Admin -----
@app.get("/v1/admin/products")
async def admin_list_products(request: Request, sub=Depends(verify_admin)):
    p = await get_pool()
    rows = await p.fetch("SELECT * FROM products ORDER BY name")
    return {"products": [dict(r) for r in rows]}

@app.post("/v1/admin/products")
async def admin_create_product(request: Request, sub=Depends(verify_admin)):
    body = await request.json()
    slug = str(body.get("slug", "")).strip()
    if not SLUG_RE.match(slug):
        domain_error("INVALID_INPUT", 400, "Slug is invalid.")
    name = str(body.get("name", "")).strip()
    if len(name) < 2 or len(name) > 80:
        domain_error("INVALID_INPUT", 400, "Name is invalid.")
    grace = body.get("offlineGraceSeconds", 604800)
    if not isinstance(grace, int) or not (0 <= grace <= 2592000):
        domain_error("INVALID_INPUT", 400, "Offline grace is invalid.")
    pkg = str(body.get("packageName", "")).strip()[:150] or None
    p = await get_pool()
    pid = str(uuid.uuid4())
    try:
        row = await p.fetchrow("INSERT INTO products(id, slug, name, package_name, offline_grace_seconds) VALUES($1,$2,$3,$4,$5) RETURNING *", pid, slug, name, pkg, grace)
    except asyncpg.UniqueViolationError:
        domain_error("PRODUCT_EXISTS", 409, "Product slug already exists.")
    await audit_event(sub, "product.create", "product", pid, pid, {"slug": slug})
    return {"product": dict(row)}

@app.get("/v1/admin/licenses")
async def admin_list_licenses(request: Request, productId: Optional[str] = None, sub=Depends(verify_admin)):
    p = await get_pool()
    if productId and not UUID_RE.match(productId):
        domain_error("INVALID_INPUT", 400, "productId is invalid.")
    rows = await p.fetch("SELECT l.*, COUNT(i.id) FILTER (WHERE i.status <> 'revoked')::int AS installation_count FROM licenses l LEFT JOIN installations i ON i.license_id=l.id WHERE ($1::uuid IS NULL OR l.product_id=$1) GROUP BY l.id ORDER BY l.created_at DESC", productId)
    # hide code_hash
    out = []
    for r in rows:
        d = dict(r)
        d.pop("code_hash", None)
        out.append(d)
    return {"licenses": out}

@app.post("/v1/admin/licenses")
async def admin_create_license(request: Request, sub=Depends(verify_admin)):
    body = await request.json()
    product_id = str(body.get("productId", ""))
    if not UUID_RE.match(product_id):
        domain_error("INVALID_INPUT", 400, "productId is invalid.")
    max_inst = body.get("maxInstallations", 1)
    if not isinstance(max_inst, int) or not (1 <= max_inst <= 100):
        domain_error("INVALID_INPUT", 400, "Device limit is invalid.")
    expires = body.get("expiresAt")
    expires_at = None
    if expires:
        try:
            expires_at = datetime.fromisoformat(str(expires).replace("Z", "+00:00"))
            if expires_at <= datetime.now(timezone.utc):
                domain_error("INVALID_INPUT", 400, "Expiry is invalid.")
        except:
            domain_error("INVALID_INPUT", 400, "Expiry is invalid.")
    code = generate_code()
    code_hash = hash_code(code["normalized"], CONFIG["code_pepper"])
    p = await get_pool()
    # check product exists
    prod = await p.fetchrow("SELECT id FROM products WHERE id=$1", product_id)
    if not prod:
        domain_error("PRODUCT_NOT_FOUND", 404, "Product not found.")
    lid = str(uuid.uuid4())
    try:
        row = await p.fetchrow("INSERT INTO licenses(id, product_id, label, code_hash, code_hint, max_installations, expires_at) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *", lid, product_id, str(body.get("label", ""))[:80], code_hash, code["hint"], max_inst, expires_at)
    except asyncpg.UniqueViolationError:
        domain_error("LICENSE_EXISTS", 409, "License already exists.")
    await audit_event(sub, "license.create", "license", lid, product_id, {"label": row["label"], "codeHint": row["code_hint"]})
    out = dict(row)
    out.pop("code_hash", None)
    return {"license": out, "code": code["formatted"]}

# status change helpers
async def set_license_status(request: Request, lic_id: str, sub=Depends(verify_admin)):
    body = await request.json()
    status = body.get("status")
    if status not in ("active", "frozen", "revoked"):
        domain_error("INVALID_INPUT", 400, "Status is invalid.")
    msg = str(body.get("message", ""))[:500] or None
    p = await get_pool()
    row = await p.fetchrow("UPDATE licenses SET status=$1, message=$2, updated_at=now() WHERE id=$3 RETURNING *", status, msg, lic_id)
    if not row:
        domain_error("NOT_FOUND", 404, "License not found.")
    await audit_event(sub, f"license.{status}", "license", lic_id, row["product_id"], {"message": msg})
    out = dict(row)
    out.pop("code_hash", None)
    return {"license": out}

@app.post("/v1/admin/licenses/{lic_id}/status")
async def admin_license_status(lic_id: str, request: Request, sub=Depends(verify_admin)):
    if not UUID_RE.match(lic_id):
        domain_error("INVALID_INPUT", 400, "id is invalid.")
    return await set_license_status(request, lic_id, sub)

@app.get("/v1/admin/installations")
async def admin_list_installations(request: Request, licenseId: Optional[str] = None, productId: Optional[str] = None, sub=Depends(verify_admin)):
    if licenseId and not UUID_RE.match(licenseId):
        domain_error("INVALID_INPUT", 400, "licenseId is invalid.")
    if productId and not UUID_RE.match(productId):
        domain_error("INVALID_INPUT", 400, "productId is invalid.")
    p = await get_pool()
    rows = await p.fetch("SELECT * FROM installations WHERE ($1::uuid IS NULL OR license_id=$1) ORDER BY last_seen_at DESC", licenseId)
    # filter by product if needed via join
    out = []
    for r in rows:
        d = dict(r)
        d.pop("token_hash", None)
        out.append(d)
    return {"installations": out}

@app.post("/v1/admin/installations/{inst_id}/status")
async def admin_inst_status(inst_id: str, request: Request, sub=Depends(verify_admin)):
    if not UUID_RE.match(inst_id):
        domain_error("INVALID_INPUT", 400, "id is invalid.")
    body = await request.json()
    status = body.get("status")
    if status not in ("active", "frozen", "revoked"):
        domain_error("INVALID_INPUT", 400, "Status is invalid.")
    msg = str(body.get("message", ""))[:500] or None
    p = await get_pool()
    row = await p.fetchrow("UPDATE installations SET status=$1, message=$2 WHERE id=$3 RETURNING *", status, msg, inst_id)
    if not row:
        domain_error("NOT_FOUND", 404, "Installation not found.")
    await audit_event(request.state.admin_subject, f"installation.{status}", "installation", inst_id, None, {"message": msg})
    out = dict(row)
    out.pop("token_hash", None)
    return {"installation": out}

@app.get("/v1/admin/requests")
async def admin_list_requests(request: Request, status: Optional[str] = None, sub=Depends(verify_admin)):
    if status and status not in ("pending", "approved", "rejected", "delivered", "cancelled"):
        domain_error("INVALID_INPUT", 400, "Request status is invalid.")
    p = await get_pool()
    if status:
        rows = await p.fetch("SELECT * FROM activation_requests WHERE status=$1 ORDER BY created_at", status)
    else:
        rows = await p.fetch("SELECT * FROM activation_requests ORDER BY created_at")
    return {"requests": [dict(r) for r in rows]}

@app.post("/v1/admin/requests/{req_id}/approve")
async def admin_approve(req_id: str, request: Request, sub=Depends(verify_admin)):
    if not UUID_RE.match(req_id):
        domain_error("INVALID_INPUT", 400, "id is invalid.")
    body = await request.json() if await request.body() else {}
    max_inst = body.get("maxInstallations", 1)
    if not isinstance(max_inst, int) or not (1 <= max_inst <= 100):
        domain_error("INVALID_INPUT", 400, "Device limit is invalid.")
    label = str(body.get("label", ""))[:80] or "طلب Telegram"
    p = await get_pool()
    async with p.acquire() as conn:
        async with conn.transaction():
            req = await conn.fetchrow("SELECT * FROM activation_requests WHERE id=$1 FOR UPDATE", req_id)
            if not req or req["status"] != "pending":
                domain_error("REQUEST_NOT_PENDING", 409, "Request is not pending.")
            code = generate_code()
            code_hash = hash_code(code["normalized"], CONFIG["code_pepper"])
            lid = str(uuid.uuid4())
            lic = await conn.fetchrow("INSERT INTO licenses(id, product_id, label, code_hash, code_hint, max_installations) VALUES($1,$2,$3,$4,$5,$6) RETURNING *", lid, req["product_id"], label, code_hash, code["hint"], max_inst)
            prod = await conn.fetchrow("SELECT * FROM products WHERE id=$1", req["product_id"])
            await conn.execute("UPDATE activation_requests SET status='approved', license_id=$1, updated_at=now() WHERE id=$2", lid, req_id)
            await audit_event(sub, "request.approve", "request", req_id, req["product_id"], {"licenseId": lid}, conn)
            # deliver via Telegram if possible
            delivered = False
            delivery_error = None
            if req["telegram_user_id"] and CONFIG["telegram_token"]:
                try:
                    async with httpx.AsyncClient(timeout=15) as client:
                        await client.post(f"{CONFIG['telegram_api_base']}/bot{CONFIG['telegram_token']}/sendMessage", json={"chat_id": req["telegram_user_id"], "text": f"تمت الموافقة على طلبك لبرنامج «{prod['name']}».\n\nكود التفعيل:\n{code['formatted']}\n\nافتح التطبيق وأدخل الكود في شاشة التفعيل."})
                    await conn.execute("UPDATE activation_requests SET status='delivered', telegram_user_id=NULL, updated_at=now() WHERE id=$1", req_id)
                    delivered = True
                except Exception as e:
                    delivery_error = str(e)
                    await conn.execute("UPDATE activation_requests SET delivery_error=$1 WHERE id=$2", delivery_error, req_id)
            else:
                delivery_error = "Telegram delivery is unavailable; give the code to the user manually."
            # fetch updated request
            updated = await conn.fetchrow("SELECT * FROM activation_requests WHERE id=$1", req_id)
            lic_out = dict(lic)
            lic_out.pop("code_hash", None)
            return {"request": dict(updated), "license": lic_out, "code": code["formatted"], "delivery": {"sent": delivered, "error": delivery_error}}

@app.post("/v1/admin/requests/{req_id}/reject")
async def admin_reject(req_id: str, request: Request, sub=Depends(verify_admin)):
    if not UUID_RE.match(req_id):
        domain_error("INVALID_INPUT", 400, "id is invalid.")
    p = await get_pool()
    row = await p.fetchrow("SELECT * FROM activation_requests WHERE id=$1", req_id)
    if not row:
        domain_error("NOT_FOUND", 404, "Request not found.")
    await p.execute("UPDATE activation_requests SET status='rejected', updated_at=now() WHERE id=$1", req_id)
    await audit_event(sub, "request.reject", "request", req_id, row["product_id"], {})
    # notify telegram if configured
    notified = False
    if row["telegram_user_id"] and CONFIG["telegram_token"]:
        try:
            async with httpx.AsyncClient(timeout=15) as client:
                await client.post(f"{CONFIG['telegram_api_base']}/bot{CONFIG['telegram_token']}/sendMessage", json={"chat_id": row["telegram_user_id"], "text": "لم تتم الموافقة على طلب الترخيص حاليًا."})
            await p.execute("UPDATE activation_requests SET telegram_user_id=NULL WHERE id=$1", req_id)
            notified = True
        except:
            pass
    updated = await p.fetchrow("SELECT * FROM activation_requests WHERE id=$1", req_id)
    return {"request": dict(updated), "notified": notified}

@app.get("/v1/admin/audit")
async def admin_audit(request: Request, limit: int = 100, sub=Depends(verify_admin)):
    limit = min(max(limit, 1), 200)
    p = await get_pool()
    rows = await p.fetch("SELECT * FROM audit_events ORDER BY created_at DESC LIMIT $1", limit)
    return {"events": [dict(r) for r in rows]}

@app.post("/webhooks/telegram")
async def telegram_webhook(request: Request, x_telegram_bot_api_secret_token: Optional[str] = Header(None)):
    if not CONFIG["telegram_secret"] or x_telegram_bot_api_secret_token != CONFIG["telegram_secret"]:
        domain_error("WEBHOOK_UNAUTHORIZED", 401, "Webhook secret is invalid.")
    body = await request.json()
    # handle update
    msg = (body.get("message") or {})
    frm = msg.get("from") or {}
    text = msg.get("text", "")
    chat_id = (msg.get("chat") or {}).get("id")
    user_id = str(frm.get("id")) if frm.get("id") else None
    is_bot = frm.get("is_bot")
    p = await get_pool()
    if text and user_id and not is_bot:
        cmd = text.strip().split()[0].split("@")[0]
        if cmd in ("/start", "/help"):
            products = await p.fetch("SELECT * FROM products WHERE active=true ORDER BY name")
            if not products:
                if CONFIG["telegram_token"]:
                    async with httpx.AsyncClient(timeout=15) as c:
                        await c.post(f"{CONFIG['telegram_api_base']}/bot{CONFIG['telegram_token']}/sendMessage", json={"chat_id": chat_id, "text": "لا توجد تطبيقات متاحة للترخيص حاليًا."})
            else:
                kb = [[{"text": r["name"], "callback_data": f"product:{r['slug']}"}] for r in products]
                if CONFIG["telegram_token"]:
                    async with httpx.AsyncClient(timeout=15) as c:
                        await c.post(f"{CONFIG['telegram_api_base']}/bot{CONFIG['telegram_token']}/sendMessage", json={"chat_id": chat_id, "text": f"أهلًا بك. اختر التطبيق لإرسال طلب ترخيص إلى المطوّر. لن يُنشأ كود تلقائيًا قبل الموافقة.\n\n{TELEGRAM_PRIVACY}", "reply_markup": {"inline_keyboard": kb}})
            return {"ok": True}
        if cmd == "/privacy":
            if CONFIG["telegram_token"]:
                async with httpx.AsyncClient(timeout=15) as c:
                    await c.post(f"{CONFIG['telegram_api_base']}/bot{CONFIG['telegram_token']}/sendMessage", json={"chat_id": chat_id, "text": TELEGRAM_PRIVACY})
            return {"ok": True}
        if cmd == "/forget":
            cnt = await p.fetchval("SELECT COUNT(*) FROM activation_requests WHERE telegram_user_id=$1 AND status='pending'", user_id)
            await p.execute("UPDATE activation_requests SET status='cancelled', telegram_user_id=NULL WHERE telegram_user_id=$1 AND status='pending'", user_id)
            txt = "تم إلغاء الطلبات المعلّقة ومحو معرّفك منها." if cnt else "لا توجد طلبات معلّقة مرتبطة بمعرّفك."
            if CONFIG["telegram_token"]:
                async with httpx.AsyncClient(timeout=15) as c:
                    await c.post(f"{CONFIG['telegram_api_base']}/bot{CONFIG['telegram_token']}/sendMessage", json={"chat_id": chat_id, "text": txt})
            return {"ok": True}
        # fallback
        if CONFIG["telegram_token"]:
            async with httpx.AsyncClient(timeout=15) as c:
                await c.post(f"{CONFIG['telegram_api_base']}/bot{CONFIG['telegram_token']}/sendMessage", json={"chat_id": chat_id, "text": "اكتب /start لطلب ترخيص، أو /privacy لمعرفة بيانات الاستخدام."})
        return {"ok": True}
    # callback
    cb = body.get("callback_query")
    if cb and cb.get("data", "").startswith("product:"):
        slug = cb["data"][len("product:"):]
        prod = await p.fetchrow("SELECT * FROM products WHERE slug=$1", slug)
        cchat = (cb.get("message") or {}).get("chat", {}).get("id") or cb["from"]["id"]
        if CONFIG["telegram_token"]:
            async with httpx.AsyncClient(timeout=15) as c:
                await c.post(f"{CONFIG['telegram_api_base']}/bot{CONFIG['telegram_token']}/answerCallbackQuery", json={"callback_query_id": cb["id"]})
        if not prod or not prod["active"]:
            if CONFIG["telegram_token"]:
                async with httpx.AsyncClient(timeout=15) as c:
                    await c.post(f"{CONFIG['telegram_api_base']}/bot{CONFIG['telegram_token']}/sendMessage", json={"chat_id": cchat, "text": "هذا التطبيق غير متاح للطلب حاليًا."})
            return {"ok": True}
        # create request
        try:
            rid = str(uuid.uuid4())
            await p.execute("INSERT INTO activation_requests(id, product_id, telegram_user_id, status) VALUES($1,$2,$3,'pending')", rid, prod["id"], str(cb["from"]["id"]))
            txt = f"تم استلام طلب ترخيص «{prod['name']}».\nسيصلك الكود هنا بعد موافقة المطوّر.\nرقم الطلب: {rid}\n\n{TELEGRAM_PRIVACY}"
        except asyncpg.UniqueViolationError:
            txt = "لديك طلب معلّق بالفعل لهذا التطبيق. انتظر موافقة المطوّر."
        if CONFIG["telegram_token"]:
            async with httpx.AsyncClient(timeout=15) as c:
                await c.post(f"{CONFIG['telegram_api_base']}/bot{CONFIG['telegram_token']}/sendMessage", json={"chat_id": cchat, "text": txt})
        return {"ok": True}
    return {"ok": True}

@app.on_event("startup")
async def on_startup():
    # don't require DB on startup for healthz
    pass

@app.on_event("shutdown")
async def on_shutdown():
    await close_pool()

# For Faable: uvicorn main:app --host 0.0.0.0 --port $PORT
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=CONFIG["host"], port=CONFIG["port"])
