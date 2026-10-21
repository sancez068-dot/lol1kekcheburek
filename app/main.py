from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import time
from pathlib import Path
from dotenv import load_dotenv

# Load bundled .env for zero-manual-config deployment. Render-provided env vars take precedence.
load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=False)
from datetime import datetime, timedelta, timezone
from typing import Generator, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy import Boolean, DateTime, Integer, String, Text, create_engine, select, update
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from starlette.middleware.trustedhost import TrustedHostMiddleware
from starlette.staticfiles import StaticFiles

APP_NAME = "KM2.0 License API"
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
KEY_PEPPER = os.getenv("KEY_PEPPER", "")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./km20.db")
ALLOWED_HOSTS = [x.strip() for x in os.getenv("ALLOWED_HOSTS", "*").split(",") if x.strip()]
TRUST_PROXY = os.getenv("TRUST_PROXY", "false").lower() == "true"

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
elif DATABASE_URL.startswith("postgresql://") and "+psycopg" not in DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

if not ADMIN_PASSWORD or len(ADMIN_PASSWORD) < 16:
    raise RuntimeError("Set ADMIN_PASSWORD to a unique value of at least 16 characters.")
if not KEY_PEPPER or len(KEY_PEPPER) < 32:
    raise RuntimeError("Set KEY_PEPPER to a random secret of at least 32 characters.")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

class License(Base):
    __tablename__ = "licenses"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    key_prefix: Mapped[str] = mapped_column(String(24), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    device_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True, index=True)
    device_label: Mapped[Optional[str]] = mapped_column(String(80), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    note: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)

Base.metadata.create_all(engine)
app = FastAPI(title=APP_NAME, docs_url=None, redoc_url=None, openapi_url=None)
if ALLOWED_HOSTS != ["*"]:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=ALLOWED_HOSTS)
app.mount("/static", StaticFiles(directory="static"), name="static")
security = HTTPBasic(auto_error=False)

def db_session() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def normalize_key(key: str) -> str:
    return "".join(key.strip().upper().split())

def hash_secret(value: str) -> str:
    return hmac.new(KEY_PEPPER.encode(), value.encode(), hashlib.sha256).hexdigest()

def new_license_key() -> str:
    groups = [secrets.token_hex(4).upper() for _ in range(4)]
    return "KM20-" + "-".join(groups)

def is_expired(item: License) -> bool:
    if item.expires_at is None:
        return False
    exp = item.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    return exp <= now_utc()

def client_device_hash(device_id: str) -> str:
    return hash_secret("device:" + device_id.strip())

def find_key(db: Session, key: str) -> Optional[License]:
    return db.scalar(select(License).where(License.key_hash == hash_secret(normalize_key(key))))

def require_admin(credentials: HTTPBasicCredentials | None = Depends(security)) -> str:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Admin authentication required",
                            headers={"WWW-Authenticate": "Basic"})
    ok_user = hmac.compare_digest(credentials.username.encode(), ADMIN_USERNAME.encode())
    ok_pass = hmac.compare_digest(credentials.password.encode(), ADMIN_PASSWORD.encode())
    if not (ok_user and ok_pass):
        raise HTTPException(status_code=401, detail="Invalid admin credentials",
                            headers={"WWW-Authenticate": "Basic"})
    return credentials.username

# Lightweight per-process abuse throttle. For multiple replicas, put a rate-limiting
# proxy/WAF in front of the service; this in-memory limiter is not a distributed control.
_attempts: dict[str, list[float]] = {}
def throttle(request: Request, bucket: str, limit: int, window_seconds: int) -> None:
    host = request.client.host if request.client else "unknown"
    key = f"{bucket}:{host}"
    now = time.monotonic()
    recent = [t for t in _attempts.get(key, []) if now - t < window_seconds]
    if len(recent) >= limit:
        raise HTTPException(status_code=429, detail="Too many requests; try again later.")
    recent.append(now)
    _attempts[key] = recent
    if len(_attempts) > 5000:
        for k in list(_attempts)[:1000]:
            if not _attempts[k] or now - _attempts[k][-1] > window_seconds:
                _attempts.pop(k, None)

class ActivateIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    key: str = Field(min_length=10, max_length=80)
    deviceId: str = Field(min_length=8, max_length=200)
    deviceLabel: Optional[str] = Field(default=None, max_length=80)

class ValidateIn(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    key: str = Field(min_length=10, max_length=80)
    deviceId: str = Field(min_length=8, max_length=200)

class CreateKeyIn(BaseModel):
    hours: int = Field(default=0, ge=0, le=87600)
    days: int = Field(default=0, ge=0, le=3650)
    note: Optional[str] = Field(default=None, max_length=200)

class NoteIn(BaseModel):
    note: Optional[str] = Field(default=None, max_length=200)

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store, private, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

@app.get("/", response_class=HTMLResponse)
def root():
    return '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>KM2.0 API</title></head><body style="font:16px system-ui;max-width:720px;margin:3rem auto;padding:0 1rem"><h1>KM2.0 License API</h1><p>Service is running.</p><p><a href="/admin">Open admin panel</a></p></body></html>'

@app.get("/health")
def health():
    return {"ok": True, "service": "km20-license-api"}

@app.get("/admin", response_class=HTMLResponse)
def admin_page():
    return open("static/admin.html", "r", encoding="utf-8").read()

@app.post("/api/activate")
def activate(payload: ActivateIn, request: Request, db: Session = Depends(db_session)):
    throttle(request, "activate", 12, 900)
    item = find_key(db, payload.key)
    if not item or not item.active or is_expired(item):
        raise HTTPException(status_code=403, detail="Invalid, expired, or revoked license.")
    device_hash = client_device_hash(payload.deviceId)
    if item.device_hash is None:
        # Conditional update avoids two simultaneous activations binding to different devices.
        result = db.execute(
            update(License).where(License.id == item.id, License.device_hash.is_(None))
            .values(device_hash=device_hash, device_label=payload.deviceLabel, last_seen_at=now_utc())
        )
        db.commit()
        db.refresh(item)
        if result.rowcount == 0 and item.device_hash != device_hash:
            raise HTTPException(status_code=403, detail="License is already bound to another device.")
    elif not hmac.compare_digest(item.device_hash, device_hash):
        raise HTTPException(status_code=403, detail="License is already bound to another device.")
    item.last_seen_at = now_utc()
    db.commit()
    return {"ok": True, "status": "active", "expiresAt": item.expires_at.isoformat() if item.expires_at else None}

@app.post("/api/validate")
def validate(payload: ValidateIn, request: Request, db: Session = Depends(db_session)):
    throttle(request, "validate", 60, 60)
    item = find_key(db, payload.key)
    if not item or not item.active or is_expired(item):
        raise HTTPException(status_code=403, detail="Invalid, expired, or revoked license.")
    expected = client_device_hash(payload.deviceId)
    if item.device_hash is None or not hmac.compare_digest(item.device_hash, expected):
        raise HTTPException(status_code=403, detail="License/device mismatch.")
    item.last_seen_at = now_utc()
    db.commit()
    return {"ok": True, "status": "active", "expiresAt": item.expires_at.isoformat() if item.expires_at else None}

@app.post("/api/admin/keys")
def create_key(payload: CreateKeyIn, request: Request, _: str = Depends(require_admin), db: Session = Depends(db_session)):
    throttle(request, "admin-create", 30, 60)
    if payload.hours > 0 and payload.days > 0:
        raise HTTPException(status_code=422, detail="Set hours OR days, not both. Use both 0 for unlimited.")
    key = new_license_key()
    expires = None if payload.hours == 0 and payload.days == 0 else now_utc() + timedelta(hours=payload.hours, days=payload.days)
    item = License(key_hash=hash_secret(normalize_key(key)), key_prefix=key[:13],
                   expires_at=expires, note=payload.note)
    db.add(item)
    db.commit()
    return {"id": item.id, "key": key, "expiresAt": expires.isoformat() if expires else None,
            "note": item.note, "message": "Copy this key now; it cannot be retrieved later."}

@app.get("/api/admin/keys")
def list_keys(_: str = Depends(require_admin), db: Session = Depends(db_session)):
    rows = db.scalars(select(License).order_by(License.id.desc()).limit(1000)).all()
    return {"items": [{
        "id": x.id, "prefix": x.key_prefix, "active": x.active, "expired": is_expired(x),
        "expiresAt": x.expires_at.isoformat() if x.expires_at else None,
        "deviceBound": bool(x.device_hash), "deviceLabel": x.device_label,
        "createdAt": x.created_at.isoformat() if x.created_at else None,
        "lastSeenAt": x.last_seen_at.isoformat() if x.last_seen_at else None, "note": x.note
    } for x in rows]}

@app.delete("/api/admin/keys/{key_id}")
def revoke_key(key_id: int, _: str = Depends(require_admin), db: Session = Depends(db_session)):
    item = db.get(License, key_id)
    if not item:
        raise HTTPException(status_code=404, detail="Key not found.")
    item.active = False
    db.commit()
    return {"ok": True, "status": "revoked"}

@app.post("/api/admin/keys/{key_id}/reset-device")
def reset_device(key_id: int, _: str = Depends(require_admin), db: Session = Depends(db_session)):
    item = db.get(License, key_id)
    if not item:
        raise HTTPException(status_code=404, detail="Key not found.")
    item.device_hash = None
    item.device_label = None
    db.commit()
    return {"ok": True, "status": "device_binding_reset"}

@app.patch("/api/admin/keys/{key_id}/note")
def update_note(key_id: int, payload: NoteIn, _: str = Depends(require_admin), db: Session = Depends(db_session)):
    item = db.get(License, key_id)
    if not item:
        raise HTTPException(status_code=404, detail="Key not found.")
    item.note = payload.note
    db.commit()
    return {"ok": True}

@app.get("/api/admin/me")
def admin_me(_: str = Depends(require_admin)):
    return {"ok": True}
