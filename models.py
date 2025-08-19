# backend/models.py

import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean, Date, Float
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=False)

    # --- KAPSAMLI PROFİL ALANLARI ---
    # Önceki alanlar
    chronic_diseases = Column(Text, nullable=True)
    medications = Column(Text, nullable=True)

    # Yeni eklenen alanlar
    date_of_birth = Column(Date, nullable=True)            # Doğum Tarihi
    gender = Column(String, nullable=True)                 # Cinsiyet
    height_cm = Column(Float, nullable=True)               # Boy (cm)
    weight_kg = Column(Float, nullable=True)               # Kilo (kg)
    pregnancy_status = Column(String, nullable=True)       # Hamilelik Durumu
    smoking_status = Column(String, nullable=True)         # Sigara Kullanımı
    alcohol_status = Column(String, nullable=True)         # Alkol Kullanımı
    family_history = Column(Text, nullable=True)           # Aile Öyküsü

    reports = relationship("Report", back_populates="owner")

class Report(Base):
    __tablename__ = "reports"
    # ... (Report sınıfı aynı kalıyor, değişiklik yok)
    id = Column(Integer, primary_key=True, index=True)
    original_filename = Column(String)
    analysis_result = Column(Text)
    upload_date = Column(DateTime(timezone=True), server_default=func.now())
    owner_id = Column(Integer, ForeignKey("users.id"))
    owner = relationship("User", back_populates="reports")