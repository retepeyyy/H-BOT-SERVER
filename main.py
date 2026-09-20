# =====================================================================
#  H-BOT Sunucu - SQLAdmin + Güvenlik Paneli + Kullanıcı Sync
# =====================================================================

from fastapi import FastAPI, Depends, HTTPException, Header, Request, UploadFile, File
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from pydantic import BaseModel
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from sqladmin import Admin, ModelView
from datetime import datetime, timedelta
from collections import defaultdict
import bcrypt
import jwt
import os
import json
import base64
from dotenv import load_dotenv

load_dotenv()

# =====================================================================
# AYARLAR
# =====================================================================
API_KEY = os.getenv("HBOT_API_KEY", "hbot-ege-2026-gizli-anahtar-a7x9k2m5")
SECRET_KEY = os.getenv("SECRET_KEY", "jwt-icin-uzun-bir-anahtar-degistir-bunu")
REGISTRATION_OPEN = os.getenv("REGISTRATION_OPEN", "false").lower() == "true"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 30

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "rt1886_admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Hb0t!Adm1n-2026#Ege")

# Güvenlik ayarlari
RATE_LIMIT_PER_MINUTE = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))
DDOS_THRESHOLD = int(os.getenv("DDOS_THRESHOLD", "200"))       # dakikada max istek
BRUTEFORCE_THRESHOLD = int(os.getenv("BRUTEFORCE_THRESHOLD", "5"))  # max basarisiz giris
AUTO_BAN_DURATION_HOURS = int(os.getenv("AUTO_BAN_DURATION_HOURS", "24"))

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./hbot_server.db")
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# =====================================================================
# MODELLER
# =====================================================================
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True)
    display_name = Column(String)
    hashed_password = Column(String, nullable=False)
    google_sub = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


class Chat(Base):
    __tablename__ = "chats"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True, nullable=False)
    title = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)


class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    chat_id = Column(Integer, index=True, nullable=False)
    role = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class ActivityLog(Base):
    __tablename__ = "activity_logs"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, index=True)
    username = Column(String)
    action = Column(String)
    details = Column(Text)
    ip_address = Column(String)
    user_agent = Column(String)
    success = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


class SecurityLog(Base):
    """Güvenlik olaylari - DDOS, brute-force, supheli aktivite."""
    __tablename__ = "security_logs"
    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String, nullable=False)   # "ddos", "bruteforce", "suspicious", "banned"
    ip_address = Column(String, index=True)
    severity = Column(String)                     # "low", "medium", "high", "critical"
    details = Column(Text)
    request_count = Column(Integer)               # dakikadaki istek sayisi
    user_agent = Column(String)
    endpoint = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


class BannedIP(Base):
    """Yasakli IP adresleri."""
    __tablename__ = "banned_ips"
    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String, unique=True, index=True, nullable=False)
    reason = Column(String)
    banned_until = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)


# =====================================================================
# IN-MEMORY RATE LIMITING
# =====================================================================
# {ip: [timestamp1, timestamp2, ...]}
_request_counts = defaultdict(list)
_failed_logins = defaultdict(list)


def check_rate_limit(ip: str) -> bool:
    """IP'nin dakikada kac istek yaptigini kontrol et."""
    now = datetime.utcnow()
    one_minute_ago = now - timedelta(minutes=1)

    # Eski timestamp'leri temizle
    _request_counts[ip] = [
        ts for ts in _request_counts[ip] if ts > one_minute_ago
    ]

    # Yeni timestamp ekle
    _request_counts[ip].append(now)

    # Limit kontrolu
    if len(_request_counts[ip]) > RATE_LIMIT_PER_MINUTE:
        return False
    return True


def get_request_count(ip: str) -> int:
    """IP'nin son dakikadaki istek sayisi."""
    now = datetime.utcnow()
    one_minute_ago = now - timedelta(minutes=1)
    return len([ts for ts in _request_counts[ip] if ts > one_minute_ago])


def is_ip_banned(ip: str) -> bool:
    """IP yasakli mi?"""
    try:
        db = SessionLocal()
        banned = db.query(BannedIP).filter(BannedIP.ip_address == ip).first()
        db.close()
        if banned and banned.banned_until and banned.banned_until > datetime.utcnow():
            return True
    except Exception:
        pass
    return False


def log_security_event(
    event_type: str,
    ip: str,
    severity: str,
    details: str,
    request_count: int = 0,
    user_agent: str = "",
    endpoint: str = "",
):
    """Güvenlik olayini kaydet."""
    try:
        db = SessionLocal()
        log = SecurityLog(
            event_type=event_type,
            ip_address=ip,
            severity=severity,
            details=details,
            request_count=request_count,
            user_agent=user_agent[:200] if user_agent else "",
            endpoint=endpoint,
        )
        db.add(log)
        db.commit()
        db.close()
    except Exception as e:
        print(f"[SECURITY] Log hatasi: {e}", flush=True)


def ban_ip(ip: str, reason: str, hours: int = AUTO_BAN_DURATION_HOURS):
    """IP'yi banla."""
    try:
        db = SessionLocal()
        existing = db.query(BannedIP).filter(BannedIP.ip_address == ip).first()
        banned_until = datetime.utcnow() + timedelta(hours=hours)

        if existing:
            existing.reason = reason
            existing.banned_until = banned_until
        else:
            new_ban = BannedIP(
                ip_address=ip,
                reason=reason,
                banned_until=banned_until,
            )
            db.add(new_ban)

        db.commit()
        db.close()

        log_security_event(
            event_type="banned",
            ip=ip,
            severity="high",
            details=f"IP banlandi: {reason} ({hours} saat)",
        )
    except Exception as e:
        print(f"[SECURITY] Ban hatasi: {e}", flush=True)


# =====================================================================
# SEMA
# =====================================================================
class UserCreate(BaseModel):
    username: str
    email: str = ""
    password: str


class UserLogin(BaseModel):
    username: str
    password: str


class ChatCreate(BaseModel):
    title: str = "Yeni Sohbet"


class MessageCreate(BaseModel):
    role: str
    content: str


class SyncUser(BaseModel):
    username: str
    email: str = ""
    display_name: str = ""
    hashed_password: str = ""
    google_sub: str = ""


# =====================================================================
# YARDIMCILAR
# =====================================================================
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != API_KEY:
        raise HTTPException(401, "Gecersiz API anahtari")
    return True


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(401, "Gecersiz token")
    except jwt.PyJWTError:
        raise HTTPException(401, "Gecersiz token")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(401, "Kullanici bulunamadi")
    return user


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def log_activity(db, user_id, username, action, details, request, success=True):
    try:
        ip = get_client_ip(request)
        user_agent = request.headers.get("user-agent", "")[:200]
        log = ActivityLog(
            user_id=user_id, username=username, action=action,
            details=details, ip_address=ip, user_agent=user_agent,
            success="true" if success else "false",
        )
        db.add(log)
        db.commit()
    except Exception as e:
        print(f"[ACTIVITY] Hata: {e}", flush=True)


# =====================================================================
# APP
# =====================================================================
app = FastAPI(title="H-BOT Sunucu", version="1.0.0")

app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =====================================================================
# GÜVENLİK MIDDLEWARE
# =====================================================================
class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        ip = get_client_ip(request)
        path = request.url.path
        ua = request.headers.get("user-agent", "")

        # Admin panel haric (Basic Auth var)
        if path.startswith("/admin"):
            return await call_next(request)

        # Banli mi?
        if is_ip_banned(ip):
            log_security_event(
                event_type="banned_access",
                ip=ip,
                severity="medium",
                details=f"Banli IP erisim denedi: {path}",
                endpoint=path,
                user_agent=ua,
            )
            return Response("Banned", status_code=403)

        # Rate limit
        if not check_rate_limit(ip):
            count = get_request_count(ip)
            log_security_event(
                event_type="rate_limit",
                ip=ip,
                severity="medium",
                details=f"Rate limit asildi: {count} istek/dk",
                request_count=count,
                endpoint=path,
                user_agent=ua,
            )
            return Response("Rate limit exceeded", status_code=429)

        # DDOS tespiti
        count = get_request_count(ip)
        if count > DDOS_THRESHOLD:
            log_security_event(
                event_type="ddos",
                ip=ip,
                severity="critical",
                details=f"DDOS supheli: {count} istek/dk (esik: {DDOS_THRESHOLD})",
                request_count=count,
                endpoint=path,
                user_agent=ua,
            )
            ban_ip(ip, f"DDOS supheli: {count} istek/dk", hours=1)

        response = await call_next(request)
        return response


app.add_middleware(SecurityMiddleware)


@app.get("/")
def root():
    return {"service": "H-BOT Server", "status": "running"}


@app.get("/health")
def health():
    return {"status": "healthy", "time": datetime.now().isoformat()}


# ---------------------------------------------------------------------
# KAYIT
# ---------------------------------------------------------------------
@app.post("/register")
def register(request: Request, user: UserCreate, db: Session = Depends(get_db), _: bool = Depends(verify_api_key)):
    if not REGISTRATION_OPEN:
        raise HTTPException(403, "Kayit su anda kapali")
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(400, "Kullanici adi zaten var")
    if user.email and db.query(User).filter(User.email == user.email).first():
        raise HTTPException(400, "Email zaten kayitli")

    new_user = User(
        username=user.username, email=user.email or None,
        display_name=user.username, hashed_password=hash_password(user.password),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    log_activity(db, new_user.id, user.username, "register", f"Kayit: {user.username}", request, True)
    return {"message": "Kayit basarili", "user_id": new_user.id}


# ---------------------------------------------------------------------
# GIRIS
# ---------------------------------------------------------------------
@app.post("/login")
def login_json(request: Request, data: UserLogin, db: Session = Depends(get_db), _: bool = Depends(verify_api_key)):
    ip = get_client_ip(request)

    user = db.query(User).filter(User.username == data.username).first()
    if not user or not verify_password(data.password, user.hashed_password):
        # Basarisiz giris sayaci
        now = datetime.utcnow()
        _failed_logins[ip] = [ts for ts in _failed_logins[ip] if ts > now - timedelta(minutes=5)]
        _failed_logins[ip].append(now)

        # Brute-force tespiti
        if len(_failed_logins[ip]) >= BRUTEFORCE_THRESHOLD:
            log_security_event(
                event_type="bruteforce",
                ip=ip,
                severity="high",
                details=f"Brute-force: {len(_failed_logins[ip])} basarisiz giris (5 dk)",
                request_count=len(_failed_logins[ip]),
                endpoint="/login",
                user_agent=request.headers.get("user-agent", ""),
            )
            ban_ip(ip, f"Brute-force: {len(_failed_logins[ip])} deneme", hours=1)

        log_activity(db, user.id if user else 0, data.username, "login_failed",
                     "Basarisiz giris", request, False)
        raise HTTPException(401, "Kullanici adi veya sifre yanlis")

    # Basarili giris - sayaci sifirla
    _failed_logins[ip] = []

    log_activity(db, user.id, user.username, "login", "Basarili giris", request, True)
    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer",
            "display_name": user.display_name or user.username}


# ---------------------------------------------------------------------
# KULLANICI SYNC (Yerel -> Sunucu)
# ---------------------------------------------------------------------
@app.post("/sync/users")
def sync_users(
    request: Request,
    users: list[SyncUser],
    db: Session = Depends(get_db),
    _: bool = Depends(verify_api_key),
):
    """Yerel H-BOT'tan kullanici listesini al ve sunucuya kaydet."""
    imported = 0
    skipped = 0
    errors = []

    for u in users:
        try:
            if not u.username:
                skipped += 1
                continue

            # Zaten var mi?
            existing = db.query(User).filter(User.username == u.username).first()
            if existing:
                # Guncelle
                existing.email = u.email or existing.email
                existing.display_name = u.display_name or existing.display_name
                existing.google_sub = u.google_sub or existing.google_sub
                skipped += 1
                continue

            # Yeni kullanici
            new_user = User(
                username=u.username,
                email=u.email or None,
                display_name=u.display_name or u.username,
                hashed_password=u.hashed_password or hash_password("degistir123"),
                google_sub=u.google_sub or None,
            )
            db.add(new_user)
            imported += 1
        except Exception as e:
            errors.append(f"{u.username}: {str(e)}")

    db.commit()

    log_activity(db, 0, "system", "sync_users",
                 f"{imported} yeni, {skipped} mevcut", request, True)

    return {
        "imported": imported,
        "skipped": skipped,
        "errors": errors,
        "total": len(users),
    }


# ---------------------------------------------------------------------
# MEVCUT KULLANICI
# ---------------------------------------------------------------------
@app.get("/me")
def me(current_user: User = Depends(get_current_user)):
    return {"id": current_user.id, "username": current_user.username,
            "email": current_user.email, "display_name": current_user.display_name}


# ---------------------------------------------------------------------
# SOHBETLER
# ---------------------------------------------------------------------
@app.get("/chats")
def list_chats(current_user: User = Depends(get_current_user), db: Session = Depends(get_db), _: bool = Depends(verify_api_key)):
    chats = db.query(Chat).filter(Chat.user_id == current_user.id).order_by(Chat.updated_at.desc()).all()
    return [{"id": c.id, "title": c.title,
             "created_at": c.created_at.isoformat(),
             "updated_at": c.updated_at.isoformat()} for c in chats]


@app.post("/chats")
def create_chat(request: Request, data: ChatCreate,
                current_user: User = Depends(get_current_user),
                db: Session = Depends(get_db), _: bool = Depends(verify_api_key)):
    chat = Chat(user_id=current_user.id, title=data.title)
    db.add(chat)
    db.commit()
    db.refresh(chat)
    log_activity(db, current_user.id, current_user.username, "chat_create",
                 f"Yeni sohbet: {data.title}", request, True)
    return {"id": chat.id, "title": chat.title}


@app.get("/chats/{chat_id}/messages")
def get_messages(chat_id: int, current_user: User = Depends(get_current_user),
                 db: Session = Depends(get_db), _: bool = Depends(verify_api_key)):
    chat = db.query(Chat).filter(Chat.id == chat_id, Chat.user_id == current_user.id).first()
    if not chat:
        raise HTTPException(404, "Sohbet bulunamadi")
    msgs = db.query(Message).filter(Message.chat_id == chat_id).order_by(Message.id.asc()).all()
    return [{"role": m.role, "content": m.content,
             "created_at": m.created_at.isoformat()} for m in msgs]


@app.post("/chats/{chat_id}/messages")
def add_message(request: Request, chat_id: int, data: MessageCreate,
                current_user: User = Depends(get_current_user),
                db: Session = Depends(get_db), _: bool = Depends(verify_api_key)):
    chat = db.query(Chat).filter(Chat.id == chat_id, Chat.user_id == current_user.id).first()
    if not chat:
        raise HTTPException(404, "Sohbet bulunamadi")
    msg = Message(chat_id=chat_id, role=data.role, content=data.content)
    db.add(msg)
    chat.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(msg)
    log_activity(db, current_user.id, current_user.username, "message",
                 f"Sohbet #{chat_id}", request, True)
    return {"id": msg.id, "message": "Kaydedildi"}


# ---------------------------------------------------------------------
# SETUP ADMIN
# ---------------------------------------------------------------------
@app.post("/setup-admin")
def setup_admin(user: UserCreate, db: Session = Depends(get_db), _: bool = Depends(verify_api_key)):
    if db.query(User).count() > 0:
        raise HTTPException(400, "Sistemde zaten kullanici var")
    new_user = User(
        username=user.username, email=user.email or None,
        display_name=user.username, hashed_password=hash_password(user.password),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "Admin olusturuldu", "user_id": new_user.id}


# =====================================================================
# SQLADMIN - Görsel Admin Panel
# =====================================================================
class UserAdmin(ModelView, model=User):
    name = "Kullanici"
    name_plural = "Kullanicilar"
    icon = "fa-solid fa-user"
    column_list = [User.id, User.username, User.email, User.display_name, User.created_at]
    column_searchable_list = [User.username, User.email]
    column_sortable_list = [User.id, User.username, User.created_at]
    can_create = False
    can_delete = True
    can_edit = True


class ChatAdmin(ModelView, model=Chat):
    name = "Sohbet"
    name_plural = "Sohbetler"
    icon = "fa-solid fa-comments"
    column_list = [Chat.id, Chat.user_id, Chat.title, Chat.created_at, Chat.updated_at]
    column_searchable_list = [Chat.title]
    column_sortable_list = [Chat.id, Chat.user_id, Chat.updated_at]
    can_create = False
    can_delete = True


class MessageAdmin(ModelView, model=Message):
    name = "Mesaj"
    name_plural = "Mesajlar"
    icon = "fa-solid fa-envelope"
    column_list = [Message.id, Message.chat_id, Message.role, Message.created_at]
    column_searchable_list = [Message.content]
    column_sortable_list = [Message.id, Message.created_at]
    can_create = False
    can_delete = True


class ActivityLogAdmin(ModelView, model=ActivityLog):
    name = "Aktivite"
    name_plural = "Aktiviteler"
    icon = "fa-solid fa-list"
    column_list = [ActivityLog.id, ActivityLog.username, ActivityLog.action,
                   ActivityLog.ip_address, ActivityLog.success, ActivityLog.created_at]
    column_searchable_list = [ActivityLog.username, ActivityLog.action]
    column_sortable_list = [ActivityLog.id, ActivityLog.created_at]
    can_create = False
    can_edit = False
    can_delete = True


class SecurityLogAdmin(ModelView, model=SecurityLog):
    name = "Güvenlik Olayi"
    name_plural = "Güvenlik Olaylari"
    icon = "fa-solid fa-shield-halved"
    column_list = [SecurityLog.id, SecurityLog.event_type, SecurityLog.ip_address,
                   SecurityLog.severity, SecurityLog.request_count, SecurityLog.created_at]
    column_searchable_list = [SecurityLog.ip_address, SecurityLog.event_type]
    column_sortable_list = [SecurityLog.id, SecurityLog.created_at, SecurityLog.severity]
    can_create = False
    can_edit = False
    can_delete = True


class BannedIPAdmin(ModelView, model=BannedIP):
    name = "Yasakli IP"
    name_plural = "Yasakli IP'ler"
    icon = "fa-solid fa-ban"
    column_list = [BannedIP.id, BannedIP.ip_address, BannedIP.reason,
                   BannedIP.banned_until, BannedIP.created_at]
    column_searchable_list = [BannedIP.ip_address, BannedIP.reason]
    column_sortable_list = [BannedIP.id, BannedIP.banned_until]
    can_create = True
    can_edit = True
    can_delete = True


admin = Admin(
    app,
    engine,
    base_url="/admin",
    title="H-BOT Yonetim Paneli",
)

admin.add_view(UserAdmin)
admin.add_view(ChatAdmin)
admin.add_view(MessageAdmin)
admin.add_view(ActivityLogAdmin)
admin.add_view(SecurityLogAdmin)
admin.add_view(BannedIPAdmin)


# =====================================================================
# ADMIN AUTH
# =====================================================================
class AdminAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/admin"):
            auth = request.headers.get("authorization", "")
            if not auth.startswith("Basic "):
                return Response("Unauthorized", status_code=401,
                                headers={"WWW-Authenticate": "Basic"})
            try:
                decoded = base64.b64decode(auth[6:]).decode("utf-8")
                username, password = decoded.split(":", 1)
                if username != ADMIN_USERNAME or password != ADMIN_PASSWORD:
                    return Response("Unauthorized", status_code=401,
                                    headers={"WWW-Authenticate": "Basic"})
            except Exception:
                return Response("Unauthorized", status_code=401,
                                headers={"WWW-Authenticate": "Basic"})
        return await call_next(request)


app.add_middleware(AdminAuthMiddleware)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
