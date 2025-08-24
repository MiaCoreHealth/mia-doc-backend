# backend/schemas.py

import datetime
from pydantic import BaseModel, Field
from typing import Optional, List

# YENİ: Sohbet mesajlarını temsil eden model
class ChatMessage(BaseModel):
    sender: str
    text: str

# YENİ: Frontend'den gelecek olan konuşma isteğini temsil eden model
class ConversationRequest(BaseModel):
    question: Optional[str] = None
    # Dosya yüklemesi ilk istekte olacağı için, geçmiş artık sadece metin tabanlı mesajları içerir.
    history: List[ChatMessage] = []

class ProfileUpdate(BaseModel):
    chronic_diseases: Optional[str] = None
    medications: Optional[str] = None
    date_of_birth: Optional[datetime.date] = None
    gender: Optional[str] = None
    height_cm: Optional[float] = None
    weight_kg: Optional[float] = None
    pregnancy_status: Optional[str] = None
    smoking_status: Optional[str] = None
    alcohol_status: Optional[str] = None
    family_history: Optional[str] = None

class User(BaseModel):
    id: int
    email: str
    chronic_diseases: Optional[str] = None
    medications: Optional[str] = None
    date_of_birth: Optional[datetime.date] = None
    gender: Optional[str] = None
    height_cm: Optional[float] = None
    weight_kg: Optional[float] = None
    pregnancy_status: Optional[str] = None
    smoking_status: Optional[str] = None
    alcohol_status: Optional[str] = None
    family_history: Optional[str] = None

    class Config:
        from_attributes = True

class Report(BaseModel):
    id: int
    original_filename: str
    analysis_result: str
    upload_date: datetime.datetime
    class Config:
        from_attributes = True

class UserCreate(BaseModel):
    email: str
    password: str