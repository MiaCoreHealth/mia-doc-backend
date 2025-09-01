# backend/schemas.py (Veri Tipi Senkronize Edildi)

from pydantic import BaseModel
from datetime import date, datetime # datetime eklendi
from typing import Optional

# --- İlaç Şemaları ---
class MedicationBase(BaseModel):
    name: str
    dosage: str
    quantity: str
    times: str
    notes: Optional[str] = None

class MedicationCreate(MedicationBase):
    pass

class MedicationUpdate(BaseModel):
    name: Optional[str] = None
    dosage: Optional[str] = None
    quantity: Optional[str] = None
    times: Optional[str] = None
    notes: Optional[str] = None

class Medication(MedicationBase):
    id: int
    owner_id: int
    class Config:
        from_attributes = True

# --- Kilo Takibi Şemaları ---
class WeightEntryBase(BaseModel):
    weight_kg: float

class WeightEntryCreate(WeightEntryBase):
    pass

class WeightEntry(WeightEntryBase):
    id: int
    owner_id: int
    date: date
    class Config:
        from_attributes = True

# --- Rapor Şemaları ---
class Report(BaseModel):
    id: int
    original_filename: str
    analysis_result: str
    # DÜZELTME: Veri tipi 'date' yerine 'datetime' olarak değiştirildi
    upload_date: datetime
    class Config:
        from_attributes = True

# --- Kullanıcı Şemaları ---
class UserBase(BaseModel):
    email: str

class UserCreate(UserBase):
    password: str

class ProfileUpdate(BaseModel):
    date_of_birth: Optional[date] = None
    gender: Optional[str] = None
    height_cm: Optional[int] = None
    weight_kg: Optional[float] = None
    chronic_diseases: Optional[str] = None
    family_history: Optional[str] = None
    smoking_status: Optional[str] = None
    alcohol_status: Optional[str] = None
    pregnancy_status: Optional[str] = None

class User(UserBase):
    id: int
    is_active: bool
    date_of_birth: Optional[date] = None
    gender: Optional[str] = None
    height_cm: Optional[int] = None
    weight_kg: Optional[float] = None
    chronic_diseases: Optional[str] = None
    family_history: Optional[str] = None
    smoking_status: Optional[str] = None
    alcohol_status: Optional[str] = None
    pregnancy_status: Optional[str] = None
    reports: list[Report] = []
    
    medications_v2: list[Medication] = []
    weight_entries_v2: list[WeightEntry] = []

    class Config:
        from_attributes = True

