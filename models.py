# backend/models.py (Veritabanı İlişki Düzeltmesi)

from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Date, Float, DateTime
from sqlalchemy.orm import relationship
from datetime import date, datetime, timezone

from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    
    date_of_birth = Column(Date, nullable=True)
    gender = Column(String, nullable=True)
    height_cm = Column(Integer, nullable=True)
    weight_kg = Column(Float, nullable=True)
    chronic_diseases = Column(String, nullable=True)
    family_history = Column(String, nullable=True)
    smoking_status = Column(String, nullable=True)
    alcohol_status = Column(String, nullable=True)
    pregnancy_status = Column(String, nullable=True)
    
    reports = relationship("Report", back_populates="owner")
    # DÜZELTME: İlişki adları basitleştirildi
    medications = relationship("Medication", back_populates="owner")
    weight_entries = relationship("WeightEntry", back_populates="owner")

class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    original_filename = Column(String)
    analysis_result = Column(String)
    upload_date = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    owner_id = Column(Integer, ForeignKey("users.id"))

    owner = relationship("User", back_populates="reports")

class Medication(Base):
    # Tablo adını v2 olarak tutuyoruz ki yeni ve temiz bir tablo oluşsun
    __tablename__ = "medications_v2"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    dosage = Column(String)
    quantity = Column(String)
    times = Column(String)
    notes = Column(String, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"))

    # DÜZELTME: back_populates User modelindeki basitleştirilmiş adla eşleşiyor
    owner = relationship("User", back_populates="medications")

class WeightEntry(Base):
    # Tablo adını v2 olarak tutuyoruz ki yeni ve temiz bir tablo oluşsun
    __tablename__ = "weight_entries_v2" 

    id = Column(Integer, primary_key=True, index=True)
    weight_kg = Column(Float, nullable=False)
    date = Column(Date, nullable=False, default=date.today)
    owner_id = Column(Integer, ForeignKey("users.id"))

    # DÜZELTME: back_populates User modelindeki basitleştirilmiş adla eşleşiyor
    owner = relationship("User", back_populates="weight_entries")

