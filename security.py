# backend/security.py

import os
from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- JWT (Giriş Kartı) Ayarları ---
SECRET_KEY = os.environ.get("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# YENİ: E-posta Doğrulama Bileti (Token) için ayrı ayarlar
EMAIL_VERIFICATION_SECRET_KEY = SECRET_KEY + "_email_verification" # Ana anahtardan yeni bir anahtar türetiyoruz
EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS = 24 # Doğrulama linki 24 saat geçerli olacak

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def hash_password(password: str):
    return pwd_context.hash(password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# YENİ: E-posta doğrulama "bileti" oluşturan fonksiyon
def create_email_verification_token(email: str):
    expire = datetime.now(timezone.utc) + timedelta(hours=EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS)
    to_encode = {"exp": expire, "sub": email}
    encoded_jwt = jwt.encode(to_encode, EMAIL_VERIFICATION_SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# YENİ: E-posta doğrulama "biletini" kontrol eden fonksiyon
def verify_email_verification_token(token: str):
    try:
        payload = jwt.decode(token, EMAIL_VERIFICATION_SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            return None
        return email
    except JWTError:
        return None