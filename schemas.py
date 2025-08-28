from pydantic import BaseModel
from datetime import date, datetime
from typing import Optional, List

# YENİ: Kilo takibi şemaları
class WeightEntryBase(BaseModel):
    weight_kg: float

class WeightEntryCreate(WeightEntryBase):
    pass

class WeightEntry(WeightEntryBase):
    id: int
    entry_date: datetime
    owner_id: int

    class Config:
        from_attributes = True

class MedicationBase(BaseModel):
    name: str
    dosage: str
    quantity: str
    times: str
    notes: Optional[str] = None

class MedicationCreate(MedicationBase):
    pass

class MedicationUpdate(MedicationBase):
    pass

class Medication(MedicationBase):
    id: int
    owner_id: int

    class Config:
        from_attributes = True

class ReportBase(BaseModel):
    original_filename: str
    analysis_result: str

class ReportCreate(ReportBase):
    pass

class Report(ReportBase):
    id: int
    upload_date: datetime
    owner_id: int

    class Config:
        from_attributes = True

class ProfileUpdate(BaseModel):
    date_of_birth: Optional[date] = None
    gender: Optional[str] = None
    height_cm: Optional[int] = None
    weight_kg: Optional[int] = None
    chronic_diseases: Optional[str] = None
    medications: Optional[str] = None
    family_history: Optional[str] = None
    smoking_status: Optional[str] = None
    alcohol_status: Optional[str] = None
    pregnancy_status: Optional[str] = None

class UserBase(BaseModel):
    email: str

class UserCreate(UserBase):
    password: str

class User(UserBase, ProfileUpdate):
    id: int
    is_active: bool
    reports: List[Report] = []
    meds: List[Medication] = []
    weight_entries: List[WeightEntry] = [] # YENİ: Kullanıcının kilo geçmişi

    class Config:
        from_attributes = True
