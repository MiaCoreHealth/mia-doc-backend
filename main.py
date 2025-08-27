# backend/main.py (Semptom Analizcisi Fonksiyonu Eklendi)

import os
from datetime import date, datetime, timezone
import json
from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Form
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from jose import JWTError, jwt
import google.generativeai as genai
from PIL import Image
import io

import models
import schemas
import security
from database import engine, SessionLocal

# --- Kurulum ve Yapılandırma ---
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY")
genai.configure(api_key=GOOGLE_API_KEY)
models.Base.metadata.create_all(bind=engine)
app = FastAPI()

# --- CORS, DB, Auth Yardımcıları (Değişiklik yok) ---
origins = [ "http://localhost:3000", "https://mia-doc-frontend.vercel.app" ]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, security.SECRET_KEY, algorithms=[security.ALGORITHM])
        email: str = payload.get("sub")
        if email is None: raise credentials_exception
    except JWTError: raise credentials_exception
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None: raise credentials_exception
    return user

# --- API Endpoints ---
@app.get('/favicon.ico', include_in_schema=False)
async def favicon():
    return Response(status_code=204)
@app.get('/favicon.png', include_in_schema=False)
async def favicon_png():
    return Response(status_code=204)

# ... (Register, Token, Profile, Rapor Analizi vb. tüm eski endpoint'ler aynı kalıyor)
@app.post("/register/")
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user: raise HTTPException(status_code=400, detail="Bu e-posta adresi zaten kayıtlı.")
    new_user = models.User(email=user.email, hashed_password=security.hash_password(user.password), is_active=True)
    db.add(new_user); db.commit(); db.refresh(new_user)
    return {"mesaj": "Kayıt başarıyla tamamlandı. Artık giriş yapabilirsiniz."}

@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    if not user or not security.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="E-posta veya şifre hatalı.")
    access_token = security.create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me/", response_model=schemas.User)
def read_users_me(current_user: models.User = Depends(get_current_user)): return current_user
@app.get("/profile/me/", response_model=schemas.User)
def get_user_profile(current_user: models.User = Depends(get_current_user)): return current_user
@app.post("/profile/me/", response_model=schemas.User)
def update_user_profile(profile_data: schemas.ProfileUpdate, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    for field, value in profile_data.model_dump(exclude_unset=True).items(): setattr(current_user, field, value)
    db.commit(); db.refresh(current_user)
    return current_user
@app.get("/reports/history/", response_model=list[schemas.Report])
def get_user_reports(current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    reports = db.query(models.Report).filter(models.Report.owner_id == current_user.id).order_by(models.Report.upload_date.desc()).all()
    return reports
@app.delete("/reports/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_report(report_id: int, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    report_to_delete = db.query(models.Report).filter(models.Report.id == report_id).first()
    if not report_to_delete: raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rapor bulunamadı.")
    if report_to_delete.owner_id != current_user.id: raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Bu raporu silme yetkiniz yok.")
    db.delete(report_to_delete); db.commit()
    return

@app.post("/report/analyze/")
async def analyze_report(file: UploadFile = File(None), question: str = Form(None), history_json: str = Form("[]"), for_someone_else: bool = Form(False), current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Bu fonksiyonun içeriği öncekiyle aynı, değişiklik yok
    system_instruction_text = "Senin adın Mia..."
    model = genai.GenerativeModel('gemini-1.5-flash-latest', system_instruction=system_instruction_text)
    # ... (geri kalan kod aynı)
    return {"analysis_result": "..."}

@app.get("/health-tip/")
async def get_health_tip(current_user: models.User = Depends(get_current_user)):
    # Bu fonksiyonun içeriği öncekiyle aynı, değişiklik yok
    return {"tip": "..."}


# --- YENİ FONKSİYON: SEMPTOM ANALİZCİSİ ---
@app.post("/symptom-analyze/")
async def analyze_symptoms(
    history_json: str = Form("[]"),
    current_user: models.User = Depends(get_current_user)
):
    system_instruction_text = """
    Senin adın Mia. Sen, Miacore Health platformunun, kullanıcının anlattığı belirtilere göre onu en doğru tıbbi branşa yönlendiren uzman bir sağlık asistanısın.
    Görevin, kullanıcının şikayetlerini dinlemek, gerekirse birkaç netleştirici soru sormak ve sonunda "Bu belirtiler genellikle bir [Tıbbi Branş] uzmanının alanına girer." şeklinde net bir yönlendirme yapmaktır.
    Örneğin: "Kardiyoloji", "Nöroloji", "Gastroenteroloji", "Dahiliye (İç Hastalıkları)".
    ASLA teşhis koyma veya ilaç önerme. Tek görevin doğru branşa yönlendirmektir.
    Konu dışı sorulara cevap verme ve her zaman nazik, empatik ve profesyonel ol.
    """
    model = genai.GenerativeModel('gemini-1.5-flash-latest', system_instruction=system_instruction_text)
    
    gemini_history = []
    try:
        frontend_history = json.loads(history_json)
        for msg in frontend_history:
            role = "user" if msg['sender'] == "user" else "model"
            gemini_history.append({'role': role, 'parts': [{'text': msg['text']}]})
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Geçersiz sohbet geçmişi formatı.")

    if not gemini_history:
        raise HTTPException(status_code=400, detail="Analiz için bir mesaj gönderilmedi.")

    try:
        chat = model.start_chat(history=gemini_history[:-1]) # Son kullanıcı mesajı hariç geçmişi al
        response = chat.send_message(gemini_history[-1]['parts'])
        analysis_text = response.text
        return {"analysis_result": analysis_text}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Yapay zeka ile iletişim sırasında bir hata oluştu: {str(e)}")

