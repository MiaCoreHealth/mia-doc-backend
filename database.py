# backend/database.py

import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Online veritabanı adresini Vercel'in ortam değişkenlerinden oku
SQLALCHEMY_DATABASE_URL = os.environ.get("DATABASE_URL")

# ---- İŞTE DÜZELTME BURADA ----
# Vercel "postgres://" ile başlayan bir adres verir, ama SQLAlchemy "postgresql://" bekler.
# Bu satır, adresin başını doğru formata çevirir.
if SQLALCHEMY_DATABASE_URL and SQLALCHEMY_DATABASE_URL.startswith("postgres://"):
    SQLALCHEMY_DATABASE_URL = SQLALCHEMY_DATABASE_URL.replace("postgres://", "postgresql://", 1)
# -----------------------------

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()