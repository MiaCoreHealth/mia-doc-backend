# backend/main.py (E-posta doğrulaması devre dışı bırakılmış son hali)

# --- Gerekli Kütüphaneler ---
import os
from datetime import date, datetime, timezone
import shutil
import uuid
from fastapi import FastAPI, Depends, HTTPException, status, Request, File, UploadFile
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

# --- CORS Ayarları ---
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

# --- Veritabanı ve Kimlik Doğrulama Yardımcıları ---
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
    # is_active=True olduğu için kullanıcı direkt aktif olacak
    new_user = models.User(email=user.email, hashed_password=security.hash_password(user.password))
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
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
    # E-posta doğrulama kontrolü buradan kaldırıldı.
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
    db.commit()
    db.refresh(current_user)
    return current_user

@app.post("/report/analyze/")
async def analyze_report(file: UploadFile = File(...), current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    contents = await file.read()
    img = Image.open(io.BytesIO(contents))
    model = genai.GenerativeModel('gemini-1.5-flash-latest')
    
    profile_info = "HASTANIN BİLİNEN SAĞLIK GEÇMİŞİ (Yorumlarını bu bilgilere göre kişiselleştir):\n"
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
    
    prompt_final = f"""
    Senin adın MİA-DOC. Sen, bir doktorun hastasıyla konuşuyormuş gibi davranan, empatik, sakin ve profesyonel bir yapay zeka sağlık asistanısın. Görevin, sana verilen tıbbi rapor görselini, aşağıda verilen hastanın kişisel sağlık geçmişini de dikkate alarak yorumlamaktır.

    {profile_info}

    YORUMLAMA KURALLARIN:
    1.  Yorumlarını MUTLAKA hastanın sağlık geçmişine göre yap. Örneğin, diyabeti olan birinin kan şekeri değerini yorumlarken bu bilgiyi kullan veya bir ilacın kan değerlerini etkileyebileceğini belirt.
    2.  **ASLA TEŞHİS KOYMA:** "Şu hastalığınız olabilir" gibi ifadeler KESİNLİKLE KULLANMA.
    3.  **ASLA TEDAVİ ÖNERME:** "Şu ilacı alın" gibi önerilerde BULUNMA.
    4.  **YORUMLA VE BİLGİLENDİR:** Her bir anormal sonucu tek tek ele al. Bu sonucun hangi organla ilgili olduğunu ve genel olarak ne anlama gelebileceğini, hastanın yaşı, cinsiyeti ve diğer bilgileriyle ilişkilendirerek açıkla.
    5.  **DOKTORA YÖNLENDİR:** Yorumunun sonunda, hastayı bu sonuçları kendi doktoruyla konuşmaya teşvik et.
    6.  **ZORUNLU UYARI:** Cevabının en sonunda MUTLAKA şu uyarıyı ekle: "Bu yorumlar tıbbi bir teşhis niteliği taşımaz. Lütfen sonuçlarınızı sizi takip eden hekimle veya başka bir sağlık profesyoneliyle yüz yüze görüşünüz."
    """
    
    try:
        response = model.generate_content([prompt_final, img], stream=True)
        response.resolve()
        analysis_text = response.text
        new_report = models.Report(
            original_filename=file.filename,
            analysis_result=analysis_text,
            owner_id=current_user.id,
            upload_date=datetime.now(timezone.utc)
        )
        db.add(new_report)
        db.commit()
        db.refresh(new_report)
        return {"analysis_result": analysis_text}
    except Exception as e:
        print(f"DETAYLI HATA RAPORU: {e}")
        raise HTTPException(status_code=500, detail=f"Yapay zeka ile iletişim sırasında bir hata oluştu: {str(e)}")

@app.get("/reports/history/", response_model=list[schemas.Report])
def get_user_reports(current_user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    reports = db.query(models.Report).filter(models.Report.owner_id == current_user.id).order_by(models.Report.upload_date.desc()).all()
    return reports