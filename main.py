# =====================================================================
#  H-BOT Sunucu - Honeypot (Tuzak) Sistemi Dahil
#  ------------------------------------------------------------------
#  Ozellikler:
#   - API Key korumasi
#   - JWT auth + bcrypt
#   - TUZAK kullanicilar (admin, root, test)
#   - Email uyarisi (Gmail SMTP)
#   - Sohbet yonetimi
# =====================================================================

from fastapi import FastAPI, Depends, HTTPException, Header, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from pydantic import BaseModel
import bcrypt
import jwt
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
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

# SMTP ayarlari
SMTP_EMAIL = os.getenv("SMTP_EMAIL", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
ALERT_SECRET = "hbot-alert-2026"  # Tuzak guvenlik anahtari

# Tuzak kullanici adlari (biri bunlarla giris denerse email gelir)
HONEYPOT_USERNAMES = ["admin", "root", "test", "honeypot", "superuser", "moderator"]

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


class AlertLog(Base):
    """Tuzak tetiklendiginde log kaydi."""
    __tablename__ = "alert_logs"
    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(String, nullable=False)
    username = Column(String)
    password_attempt = Column(String)
    ip_address = Column(String)
    user_agent = Column(String)
    details = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)


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


# =====================================================================
# EMAIL ALERT
# =====================================================================
def send_alert_email(subject: str, body: str) -> bool:
    """Gmail SMTP ile uyari emaili gonder."""
    if not SMTP_EMAIL or not SMTP_PASSWORD:
        print("[ALERT] SMTP ayarlari eksik, email gonderilemedi", flush=True)
        return False

    try:
        msg = MIMEMultipart()
        msg["From"] = SMTP_EMAIL
        msg["To"] = SMTP_EMAIL
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain", "utf-8"))

        with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as server:
            server.starttls()
            server.login(SMTP_EMAIL, SMTP_PASSWORD)
            server.send_message(msg)

        print(f"[ALERT] Email gonderildi: {subject}", flush=True)
        return True
    except Exception as e:
        print(f"[ALERT] Email hatasi: {e}", flush=True)
        return False


def trigger_honeypot_alert(
    alert_type: str,
    username: str,
    password_attempt: str,
    request: Request,
    details: str = ""
) -> None:
    """Tuzak tetiklendiginde email gonder ve log kaydet."""
    ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")[:200]

    # Email icerigi
    subject = f"🚨 H-BOT ALERT: {alert_type}"
    body = f"""
╔══════════════════════════════════════════╗
║  🚨 H-BOT GUVENLIK UYARISI 🚨            ║
╚══════════════════════════════════════════╝

TUR: {alert_type}

KULLANICI: {username}
SIFRE DENEMESI: {password_attempt}
IP ADRESI: {ip}
USER-AGENT: {user_agent}
ZAMAN: {datetime.now().isoformat()}

DETAYLAR:
{details}

AKSIYON:
1. Google Cloud Console'a git
2. client_secret'i iptal et
3. Yeni client_secret olustur
4. .env dosyasini guncelle
5. Render'i yeniden deploy et

Bu email H-BOT honeypot sistemi tarafindan gonderildi.
"""

    send_alert_email(subject, body)

    # Log kaydet
    try:
        db = SessionLocal()
        log = AlertLog(
            alert_type=alert_type,
            username=username,
            password_attempt=password_attempt,
            ip_address=ip,
            user_agent=user_agent,
            details=details,
        )
        db.add(log)
        db.commit()
        db.close()
    except Exception as e:
        print(f"[ALERT] Log kaydi hatasi: {e}", flush=True)


# =====================================================================
# APP
# =====================================================================
app = FastAPI(title="H-BOT Sunucu", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {"service": "H-BOT Server", "status": "running"}


@app.get("/health")
def health():
    return {"status": "healthy", "time": datetime.now().isoformat()}


# ---------------------------------------------------------------------
# Kayit
# ---------------------------------------------------------------------
@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db), _: bool = Depends(verify_api_key)):
    if not REGISTRATION_OPEN:
        raise HTTPException(403, "Kayit su anda kapali")

    # Tuzak: bu kullanici adlariyla kayit denemesi
    if user.username.lower() in HONEYPOT_USERNAMES:
        raise HTTPException(400, "Bu kullanici adi kullanilamaz")

    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(400, "Kullanici adi zaten var")
    if user.email and db.query(User).filter(User.email == user.email).first():
        raise HTTPException(400, "Email zaten kayitli")

    new_user = User(
        username=user.username,
        email=user.email or None,
        display_name=user.username,
        hashed_password=hash_password(user.password),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "Kayit basarili", "user_id": new_user.id}


# ---------------------------------------------------------------------
# Giris (OAuth2 form)
# ---------------------------------------------------------------------
@app.post("/token")
def login_form(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    # TUZAK: Tuzak kullanici adi denemesi
    if form.username.lower() in HONEYPOT_USERNAMES:
        trigger_honeypot_alert(
            alert_type="HONEYPOT_USERNAME_DENENDI",
            username=form.username,
            password_attempt=form.password,
            request=request,
            details="OAuth2 form uzerinden tuzak kullanici adi denendi.",
        )
        raise HTTPException(401, "Kullanici adi veya sifre yanlis")

    user = db.query(User).filter(User.username == form.username).first()
    if not user or not verify_password(form.password, user.hashed_password):
        # Normal hatali giris - cok fazla olursa uyari
        raise HTTPException(401, "Kullanici adi veya sifre yanlis")

    token = create_access_token({"sub": user.username})
    return {"access_token": token, "token_type": "bearer"}


# ---------------------------------------------------------------------
# Giris (JSON)
# ---------------------------------------------------------------------
@app.post("/login")
def login_json(
    request: Request,
    data: UserLogin,
    db: Session = Depends(get_db),
    _: bool = Depends(verify_api_key),
):
    # TUZAK: Tuzak kullanici adi denemesi
    if data.username.lower() in HONEYPOT_USERNAMES:
        trigger_honeypot_alert(
            alert_type="HONEYPOT_USERNAME_DENENDI",
            username=data.username,
            password_attempt=data.password,
            request=request,
            details="JSON login uzerinden tuzak kullanici adi denendi.",
        )
        raise HTTPException(401, "Kullanici adi veya sifre yanlis")

    user = db.query(User).filter(User.username == data.username).first()
    if not user or not verify_password(data.password, user.hashed_password):
        raise HTTPException(401, "Kullanici adi veya sifre yanlis")

    token = create_access_token({"sub": user.username})
    return {
        "access_token": token,
        "token_type": "bearer",
        "display_name": user.display_name or user.username,
    }


# ---------------------------------------------------------------------
# Mevcut kullanici
# ---------------------------------------------------------------------
@app.get("/me")
def me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "display_name": current_user.display_name,
    }


# ---------------------------------------------------------------------
# Sohbetler
# ---------------------------------------------------------------------
@app.get("/chats")
def list_chats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    _: bool = Depends(verify_api_key),
):
    chats = (
        db.query(Chat)
        .filter(Chat.user_id == current_user.id)
        .order_by(Chat.updated_at.desc())
        .all()
    )
    return [
        {
            "id": c.id,
            "title": c.title,
            "created_at": c.created_at.isoformat(),
            "updated_at": c.updated_at.isoformat(),
        }
        for c in chats
    ]


@app.post("/chats")
def create_chat(
    data: ChatCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    _: bool = Depends(verify_api_key),
):
    chat = Chat(user_id=current_user.id, title=data.title)
    db.add(chat)
    db.commit()
    db.refresh(chat)
    return {"id": chat.id, "title": chat.title}


@app.get("/chats/{chat_id}/messages")
def get_messages(
    chat_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    _: bool = Depends(verify_api_key),
):
    chat = (
        db.query(Chat)
        .filter(Chat.id == chat_id, Chat.user_id == current_user.id)
        .first()
    )
    if not chat:
        raise HTTPException(404, "Sohbet bulunamadi")
    msgs = (
        db.query(Message)
        .filter(Message.chat_id == chat_id)
        .order_by(Message.id.asc())
        .all()
    )
    return [
        {
            "role": m.role,
            "content": m.content,
            "created_at": m.created_at.isoformat(),
        }
        for m in msgs
    ]


@app.post("/chats/{chat_id}/messages")
def add_message(
    chat_id: int,
    data: MessageCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    _: bool = Depends(verify_api_key),
):
    chat = (
        db.query(Chat)
        .filter(Chat.id == chat_id, Chat.user_id == current_user.id)
        .first()
    )
    if not chat:
        raise HTTPException(404, "Sohbet bulunamadi")
    msg = Message(chat_id=chat_id, role=data.role, content=data.content)
    db.add(msg)
    chat.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(msg)
    return {"id": msg.id, "message": "Kaydedildi"}


@app.delete("/chats/{chat_id}")
def delete_chat(
    chat_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    _: bool = Depends(verify_api_key),
):
    chat = (
        db.query(Chat)
        .filter(Chat.id == chat_id, Chat.user_id == current_user.id)
        .first()
    )
    if not chat:
        raise HTTPException(404, "Sohbet bulunamadi")
    db.query(Message).filter(Message.chat_id == chat_id).delete()
    db.delete(chat)
    db.commit()
    return {"message": "Sohbet silindi"}


# ---------------------------------------------------------------------
# TUZAK: /alert/email endpoint
# ---------------------------------------------------------------------
class AlertRequest(BaseModel):
    secret: str
    message: str = "Tuzak tetiklendi"
    details: str = ""


@app.post("/alert/email")
def alert_email(
    request: Request,
    data: AlertRequest,
):
    """Dis kaynaktan alert gonderme endpoint'i."""
    if data.secret != ALERT_SECRET:
        raise HTTPException(401, "Yetkisiz")

    ip = request.client.host if request.client else "unknown"

    subject = f"🚨 H-BOT ALERT: {data.message}"
    body = f"""
H-BOT TUZAK TETIKLENDI

MESAJ: {data.message}
DETAYLAR: {data.details}
IP: {ip}
ZAMAN: {datetime.now().isoformat()}

AKSIYON:
1. Google Cloud Console'a git
2. client_secret'i iptal et
3. Yeni client_secret olustur
4. .env dosyasini guncelle
"""

    success = send_alert_email(subject, body)
    return {"status": "ok" if success else "error", "email_sent": success}


# ---------------------------------------------------------------------
# TUZAK LOGLARI (sadece senin gorebilecegin)
# ---------------------------------------------------------------------
@app.get("/alert/logs")
def alert_logs(
    _: bool = Depends(verify_api_key),
    db: Session = Depends(get_db),
):
    """Tuzak log kayitlarini listele. Sadece API key ile."""
    logs = db.query(AlertLog).order_by(AlertLog.created_at.desc()).limit(100).all()
    return [
        {
            "id": log.id,
            "type": log.alert_type,
            "username": log.username,
            "ip": log.ip_address,
            "created_at": log.created_at.isoformat(),
        }
        for log in logs
    ]


# ---------------------------------------------------------------------
# Ilk kurulum icin: admin olustur
# ---------------------------------------------------------------------
@app.post("/setup-admin")
def setup_admin(
    user: UserCreate,
    db: Session = Depends(get_db),
    _: bool = Depends(verify_api_key),
):
    if db.query(User).count() > 0:
        raise HTTPException(400, "Sistemde zaten kullanici var")
    if user.username.lower() in HONEYPOT_USERNAMES:
        raise HTTPException(400, "Bu kullanici adi kullanilamaz")

    new_user = User(
        username=user.username,
        email=user.email or None,
        display_name=user.username,
        hashed_password=hash_password(user.password),
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "Admin olusturuldu", "user_id": new_user.id}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
