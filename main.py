# backend/main.py

import os
from datetime import date, datetime, timezone
import shutil
import uuid
import json
from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Form
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from jose import JWTError, jwt

# Gemini ve Resim işleme kütüphaneleri
import google.generativeai as genai
from PIL import Image
import io

# Projemizin diğer dosyaları
import models
import schemas
import security
from database import engine, SessionLocal

# --- Kurulum ve Yapılandırma ---
GOOGLE_API_KEY = os.environ.get("GOOGLE_API_KEY")
genai.configure(api_key=GOOGLE_API_KEY)
models.Base.metadata.create_all(bind=engine)
app = FastAPI()

# --- CORS, DB, Auth Yardımcıları ---
origins = [
    "http://localhost:3000",
    "https://mia-doc-frontend.vercel.app",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, security.SECRET_KEY, algorithms=[security.ALGORITHM])
        email: str = payload.get("sub")
        if email is None: raise credentials_exception
    except JWTError: raise credentials_exception
    user = db.query(models.User).filter(models.User.email == email).first()
    if user is None: raise credentials_exception
    return user

# --- API Endpoints ---

@app.post("/register/")
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Bu e-posta adresi zaten kayıtlı.")
    new_user = models.User(email=user.email, hashed_password=security.hash_password(user.password), is_active=True)
    db.add(new_user); db.commit(); db.refresh(new_user)
    return {"mesaj": "Kayıt başarıyla tamamlandı. Artık giriş yapabilirsiniz."}

@app.post("/token")
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == form_data.username).first()
    if not user or not security.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="E-posta veya şifre hatalı.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = security.create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me/", response_model=schemas.User)
def read_users_me(current_user: models.User = Depends(get_current_user)):
    return current_user

@app.get("/profile/me/", response_model=schemas.User)
def get_user_profile(current_user: models.User = Depends(get_current_user)):
    return current_user

@app.post("/profile/me/", response_model=schemas.User)
def update_user_profile(profile_data: schemas.ProfileUpdate, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    for field, value in profile_data.model_dump(exclude_unset=True).items():
        setattr(current_user, field, value)
    db.commit(); db.refresh(current_user)
    return current_user

@app.get("/reports/history/", response_model=list[schemas.Report])
def get_user_reports(current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(models.Report).filter(models.Report.owner_id == current_user.id).order_by(models.Report.upload_date.desc()).all()

@app.delete("/reports/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_report(report_id: int, current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    report_to_delete = db.query(models.Report).filter(models.Report.id == report_id).first()
    if not report_to_delete:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rapor bulunamadı.")
    if report_to_delete.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Bu raporu silme yetkiniz yok.")
    db.delete(report_to_delete); db.commit()
    return

@app.post("/report/analyze/")
async def analyze_report(
    file: UploadFile = File(None), 
    question: str = Form(None),
    history_json: str = Form("[]"),
    for_someone_else: bool = Form(False),
    current_user: models.User = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    model = genai.GenerativeModel('gemini-1.5-flash-latest')
    
    gemini_history = []
    
    system_prompt = """
    Senin adın MiaCore Health Sağlık Asistanı. Sen, bir doktorun hastasıyla konuşuyormuş gibi davranan, empatik, sakin ve profesyonel bir yapay zeka sağlık asistanısın. Görevin, sana verilen tıbbi rapor görselini ve takip sorularını, hastanın kişisel sağlık geçmişini de dikkate alarak yorumlamaktır.
    """
    if not for_someone_else:
        profile_info = "\nHASTANIN BİLİNEN SAĞLIK GEÇMİŞİ (Yorumlarını bu bilgilere göre kişiselleştir):\n"
        if current_user.date_of_birth:
            today = date.today()
            age = today.year - current_user.date_of_birth.year - ((today.month, today.day) < (current_user.date_of_birth.month, current_user.date_of_birth.day))
            profile_info += f"- Yaş: {age}\n"
        else:
            profile_info += "- Yaş: Belirtilmemiş\n"
        profile_info += f"- Cinsiyet: {current_user.gender or 'Belirtilmemiş'}\n"
        if current_user.height_cm and current_user.weight_kg:
            bmi = round(current_user.weight_kg / ((current_user.height_cm / 100) ** 2), 1)
            profile_info += f"- Boy: {current_user.height_cm} cm, Kilo: {current_user.weight_kg} kg (VKİ: {bmi})\n"
        profile_info += f"- Kronik Hastalıkları: {current_user.chronic_diseases or 'Belirtilmemiş'}\n"
        profile_info += f"- Sürekli Kullandığı İlaçlar: {current_user.medications or 'Belirtilmemiş'}\n"
        profile_info += f"- Aile Öyküsü: {current_user.family_history or 'Belirtilmemiş'}\n"
        profile_info += f"- Sigara Kullanımı: {current_user.smoking_status or 'Belirtilmemiş'}\n"
        profile_info += f"- Alkol Kullanımı: {current_user.alcohol_status or 'Belirtilmemiş'}\n"
        profile_info += f"- Hamilelik Durumu: {current_user.pregnancy_status or 'Belirtilmemiş'}\n"
        system_prompt += profile_info

    system_prompt += """
    \nYORUMLAMA KURALLARIN:
    1.  **ÖNCELİK 1: GÖREV DIŞI KONTROLÜ:** Sana sorulan takip sorularının, hastanın sağlık durumu veya sana sunulan tıbbi raporla ilgili olup olmadığını kontrol et. Eğer soru, "Türkiye borsaları ne olacak?", "Bugün hava nasıl?" gibi tamamen alakasız bir konuysa, raporu yorumlama. Bunun yerine, kibarca ve net bir şekilde şu cevabı ver: 'Ben bir sağlık asistanıyım ve sadece tıbbi raporlarınız ve sağlık durumunuzla ilgili sorularınıza yardımcı olabilirim.'
    2.  **ÖNCELİK 2: GÜVENLİK VE MANTIK KONTROLÜ:** Yorum yapmadan önce, sana verilen raporun içeriği ile hastanın profil bilgileri (özellikle yaş ve cinsiyet) arasında bariz bir biyolojik veya mantıksal çelişki olup olmadığını KESİNLİKLE kontrol et. Örneğin, bir erkeğe ait profilde hamilelik ultrasonu veya bir çocuğa ait profilde prostat raporu olması gibi. EĞER BÖYLE BİR ÇELİŞKİ VARSA, raporu normal şekilde yorumlama. Bunun yerine, kibarca ve net bir şekilde şu uyarıyı ver: 'Yüklediğiniz rapor ile profil bilgileriniz arasında bir tutarsızlık tespit ettim. Lütfen doğru raporu yüklediğinizden veya profil bilgilerinizin güncel olduğundan emin olun.' Bu durumda başka bir yorum yapma.
    3.  **YORUMLAMA (Eğer çelişki yoksa):** Yorumlarını MUTLAKA hastanın sağlık geçmişine göre yap. Örneğin, diyabeti olan birinin kan şekeri değerini yorumlarken bu bilgiyi kullan.
    4.  **ASLA TEŞHİS KOYMA.**
    5.  **ASLA TEDAVİ ÖNERME.**
    6.  **BAĞLAMI KORU:** Eğer bir konuşma geçmişi varsa, yeni cevabını o geçmişe uygun bir şekilde ver.
    7.  **DOKTORA YÖNLENDİR.**
    8.  **ZORUNLU UYARI:** Cevabının en sonunda MUTLAKA şu uyarıyı ekle: "Bu yorumlar tıbbi bir teşhis niteliği taşımaz. Lütfen sonuçlarınızı sizi takip eden hekimle veya başka bir sağlık profesyoneliyle yüz yüze görüşünüz."
    """
    
    try:
        frontend_history = json.loads(history_json)
        for msg in frontend_history:
            role = "user" if msg['sender'] == "user" else "model"
            gemini_history.append({'role': role, 'parts': [{'text': msg['text']}]})
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Geçersiz sohbet geçmişi formatı.")

    new_content = []
    if file:
        contents = await file.read()
        img = Image.open(io.BytesIO(contents))
        # Resim yüklenirken her zaman sistem talimatını gönderiyoruz
        new_content.append(system_prompt + "\n\nLütfen bu rapordaki sonuçları yorumla.")
        new_content.append(img)
    if question:
        # Takip sorularında sadece soruyu gönderiyoruz, sistem talimatı chat geçmişinde zaten var
        new_content.append(question)
    
    try:
        chat = model.start_chat(history=gemini_history)
        response = chat.send_message(new_content)
        analysis_text = response.text

        if file and not for_someone_else:
            new_report = models.Report(
                original_filename=file.filename,
                analysis_result=analysis_text,
                owner_id=current_user.id,
                upload_date=datetime.now(timezone.utc)
            )
            db.add(new_report); db.commit(); db.refresh(new_report)
        
        return {"analysis_result": analysis_text}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Yapay zeka ile iletişim sırasında bir hata oluştu: {str(e)}")