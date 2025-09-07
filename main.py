# backend/main.py (Daha Akıllı ve Odaklı Asistanlar)

import os
from datetime import date, datetime, timezone
import json
from fastapi import FastAPI, Depends, HTTPException, status, File, UploadFile, Form
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session, joinedload
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

# --- CORS, DB, Auth Yardımcıları ---
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
    
    user = db.query(models.User).options(
        joinedload(models.User.reports),
        joinedload(models.User.medications_v4),
        joinedload(models.User.weight_entries_v4)
    ).filter(models.User.email == email).first()

    if user is None: raise credentials_exception
    return user

# --- API Endpoints ---
@app.get("/", include_in_schema=False)
def read_root():
    return {"message": "MiaCore Health Backend is running."}

@app.get('/favicon.ico', include_in_schema=False)
async def favicon():
    return Response(status_code=204)
@app.get('/favicon.png', include_in_schema=False)
async def favicon_png():
    return Response(status_code=204)

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

# --- İLAÇ YÖNETİMİ ENDPOINT'LERİ ---
@app.post("/medications/", response_model=schemas.Medication)
def create_medication_for_user(med: schemas.MedicationCreate, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    db_med = models.Medication(**med.model_dump(), owner_id=current_user.id)
    db.add(db_med)
    db.commit()
    db.refresh(db_med)
    return db_med

@app.get("/medications/", response_model=list[schemas.Medication])
def read_user_medications(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return db.query(models.Medication).filter(models.Medication.owner_id == current_user.id).all()

@app.put("/medications/{med_id}", response_model=schemas.Medication)
def update_medication( med_id: int, med_update: schemas.MedicationUpdate, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    db_med = db.query(models.Medication).filter(models.Medication.id == med_id).first()
    if not db_med: raise HTTPException(status_code=404, detail="İlaç bulunamadı")
    if db_med.owner_id != current_user.id: raise HTTPException(status_code=403, detail="Bu ilacı düzenleme yetkiniz yok")
    update_data = med_update.model_dump(exclude_unset=True)
    for key, value in update_data.items(): setattr(db_med, key, value)
    db.add(db_med)
    db.commit()
    db.refresh(db_med)
    return db_med

@app.delete("/medications/{med_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_medication(med_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    med_to_delete = db.query(models.Medication).filter(models.Medication.id == med_id).first()
    if not med_to_delete: raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="İlaç bulunamadı.")
    if med_to_delete.owner_id != current_user.id: raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Bu ilacı silme yetkiniz yok.")
    db.delete(med_to_delete)
    db.commit()
    return

# --- KİLO TAKİBİ ENDPOINT'LERİ ---
@app.post("/weight-entries/", response_model=schemas.WeightEntry)
def create_weight_entry_for_user(entry: schemas.WeightEntryCreate, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    db_entry = models.WeightEntry(**entry.model_dump(), owner_id=current_user.id, date=date.today())
    db.add(db_entry)
    db.commit()
    db.refresh(db_entry)
    current_user.weight_kg = entry.weight_kg
    db.commit()
    return db_entry

@app.get("/weight-entries/", response_model=list[schemas.WeightEntry])
def read_user_weight_entries(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    try:
        entries = db.query(models.WeightEntry).filter(models.WeightEntry.owner_id == current_user.id).order_by(models.WeightEntry.date).all()
        return entries
    except Exception as e:
        print(f"--- KİLO GEÇMİŞİ HATASI ---: {str(e)}")
        raise HTTPException(status_code=500, detail="Kilo geçmişi verileri işlenirken bir sunucu hatası oluştu.")

@app.delete("/weight-entries/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_weight_entry(entry_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    entry_to_delete = db.query(models.WeightEntry).filter(models.WeightEntry.id == entry_id).first()
    if not entry_to_delete: raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Kilo kaydı bulunamadı.")
    if entry_to_delete.owner_id != current_user.id: raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Bu kaydı silme yetkiniz yok.")
    db.delete(entry_to_delete)
    db.commit()
    return


# --- YAPAY ZEKA FONKSİYONLARI ---

def get_user_profile_summary(user: models.User) -> str:
    summary = "Hastanın bilinen sağlık geçmişi:\n"
    if user.date_of_birth:
        today = date.today()
        age = today.year - user.date_of_birth.year - ((today.month, today.day) < (user.date_of_birth.month, user.date_of_birth.day))
        summary += f"- Yaş: {age}\n"
    if user.gender: 
        summary += f"- Cinsiyet: {user.gender}\n"
    if user.chronic_diseases: 
        summary += f"- Kronik Hastalıklar: {user.chronic_diseases}\n"
    
    if user.medications_v4:
        summary += "- Kullandığı İlaçlar: " + ", ".join([f"{m.name} {m.dosage}" for m in user.medications_v4]) + "\n"
    
    return summary


@app.post("/report/analyze/")
async def analyze_report(
    file: UploadFile = File(None),
    question: str = Form(None),
    history_json: str = Form("[]"),
    for_someone_else: bool = Form(False),
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # DÜZELTME: Bu asistanın görev tanımı daha spesifik hale getirildi
    system_instruction_text = """
    Senin adın Mia. Sen, Miacore Health platformunun RAPOR ANALİZİ asistanısın.
    Görevin, SADECE sana yüklenen tıbbi raporları ve bu raporlar hakkındaki takip sorularını yorumlamaktır.
    
    EN ÖNEMLİ KURALLAR:
    1. GÖREV SINIRI: Eğer sana bir rapor yüklenmeden genel bir sağlık sorusu (örn: "başım ağrıyor", "göğsümde ağrı var") sorulursa, bu soruyu KESİNLİKLE CEVAPLAMA. Bunun yerine, kullanıcıyı doğru yere yönlendirerek kibarca şu cevabı ver: "Anladım, yaşadığın belirtiyi analiz etmemi istersen, lütfen ana menüdeki 'Hangi Doktora Gitmeliyim?' bölümünü kullan. Bu bölümde sadece yüklediğin raporları yorumlayabiliyorum."
    2. DİL VE ÜSLUP: Cevapların her zaman basit, sade ve anlaşılır olsun. Tıbbi jargondan kaçın.
    3. YASAL UYARI: Her cevabının sonunda MUTLAKA "Unutma, bu yorumlar tıbbi tavsiye yerine geçmez. Lütfen doktoruna danış." uyarısını ekle.
    4. KESİNLİKLE YAPMA: Asla net bir teşhis koyma. Asla ilaç veya tedavi önerme.
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
    chat = model.start_chat(history=gemini_history)
    
    new_content = []
    
    if file:
        task_prompt = "Aşağıdaki tıbbi raporu, sana verdiğim genel kurallar ve hastanın profili çerçevesinde yorumla. Cevapların kısa, net ve aksiyon odaklı olsun.\n\n"
        greeting = "Merhaba! Raporunu inceliyorum." if not for_someone_else else "Merhaba! Gönderdiğin raporu inceliyorum."
        task_prompt += f"""
        YORUMLAMA SÜRECİ (Bu adımları kullanıcıya gösterme, sadece uygula):
        1. GÜVENLİK KONTROLÜ: Raporun içeriği (örn: uterus, prostat) hastanın cinsiyetiyle biyolojik olarak uyumlu mu? Uyumsuzsa, yorum yapma ve SADECE şu cevabı ver: 'Yüklediğin rapor ile profil bilgilerin arasında bir tutarsızlık var gibi görünüyor. Lütfen doğru raporu yüklediğinden emin ol.'
        2. RAPOR TÜRÜNÜ BELİRLE VE GİRİŞ YAP: Raporun türünü anla (örn: kan tahlili, ultrason) ve cevabına şu şekilde başla: "{greeting} Gördüğüm kadarıyla bu bir [Rapor Türü] sonucu."
        3. AKILLI ANALİZ: Rapordaki anormal bulguları hastanın bilinen kronik hastalıklarıyla ilişkilendir.
        4. ÖZETLE VE YÖNLENDİR: Yorumunun sonunda her zaman hangi branşa gidilmesi gerektiğini kısaca belirt.
        """
        if not for_someone_else:
            profile_summary = get_user_profile_summary(current_user)
            task_prompt += "\n" + profile_summary
        task_prompt += "\nİşte yorumlaman gereken rapor:"
        new_content.append(task_prompt)
        contents = await file.read()
        img = Image.open(io.BytesIO(contents))
        new_content.append(img)

    if question:
        new_content.append(question)
    
    if not new_content:
        raise HTTPException(status_code=400, detail="Analiz için rapor veya soru gönderilmedi.")
        
    try:
        response = chat.send_message(new_content)
        analysis_text = response.text
        if file and not for_someone_else:
            new_report = models.Report(original_filename=file.filename, analysis_result=analysis_text, owner_id=current_user.id, upload_date=datetime.now(timezone.utc))
            db.add(new_report); db.commit(); db.refresh(new_report)
        return {"analysis_result": analysis_text}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Yapay zeka ile iletişim sırasında bir hata oluştu: {str(e)}")


@app.get("/health-tip/")
async def get_health_tip(current_user: models.User = Depends(get_current_user)):
    try:
        model = genai.GenerativeModel('gemini-1.5-flash-latest')
        profile_summary = get_user_profile_summary(current_user)
        prompt = f"""
        Senin adın Mia. Pozitif ve motive edici bir sağlık koçusun. 
        Aşağıdaki profiline göre kullanıcıya özel, kısa (tek cümle), uygulanabilir ve arkadaşça bir "günün sağlık tavsiyesi" oluştur. 
        Cevabın SADECE tavsiye metnini içersin.
        {profile_summary}
        """
        response = model.generate_content(prompt)
        return {"tip": response.text.strip()}
    except Exception as e:
        return {"tip": "Bugün kendine iyi bakmayı unutma, bol su içmek harika bir başlangıç olabilir!"}


@app.post("/symptom-analyze/")
async def analyze_symptoms(
    history_json: str = Form("[]"),
    current_user: models.User = Depends(get_current_user)
):
    profile_summary = get_user_profile_summary(current_user)
    
    # DÜZELTME: Bu asistanın görev tanımı da daha katı hale getirildi
    system_instruction_text = f"""
    Senin adın Mia. Sen, kullanıcının anlattığı belirtilere ve sağlık geçmişine göre onu en doğru tıbbi branşa yönlendiren SEMPTOM ANALİZİ asistanısın.
    
    EN ÖNEMLİ KURALLAR:
    1. GÖREV SINIRI: Senin tek görevin sağlıkla ilgili belirtileri analiz etmektir. Finans, siyaset, spor gibi konu dışı sorulara KESİNLİKLE cevap verme. Kibarca, "Bu konu benim uzmanlık alanımın dışında, sana en iyi sağlık konularında yardımcı olabilirim." de.
    2. BÜTÜNSEL YAKLAŞIM: Yönlendirme yaparken aşağıda verilen sağlık geçmişini MUTLAKA dikkate al.
    3. NETLİK: Gerekirse birkaç netleştirici soru sor, ardından "Bu belirtiler ve sağlık geçmişin göz önünde bulundurulduğunda, bir [Tıbbi Branş] uzmanına danışman faydalı olabilir." şeklinde net bir yönlendirme yap.
    4. SINIRLAR: Asla teşhis koyma veya ilaç önerme. Her cevabının sonunda mutlaka "Bu bir tıbbi tavsiye değildir, en doğru bilgi için lütfen doktoruna danış." uyarısını ekle.
    
    {profile_summary}
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
        chat = model.start_chat(history=gemini_history[:-1])
        response = chat.send_message(gemini_history[-1]['parts'])
        analysis_text = response.text
        return {"analysis_result": analysis_text}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Yapay zeka ile iletişim sırasında bir hata oluştu: {str(e)}")

def get_medication_info_from_ai(med_name: str):
    try:
        model = genai.GenerativeModel('gemini-1.5-flash-latest')
        prompt = f"""
        "{med_name}" adlı ilaç hakkında, bir hastanın anlayabileceği basitlikte, kısa ve öz bir bilgi ver. Cevabın şu başlıkları içersin:
        - **Ne İçin Kullanılır?:** İlacın ana kullanım amacı.
        - **Yaygın Yan Etkiler:** En sık görülen 2-3 yan etki.
        - **Önemli Not:** Hastanın bilmesi gereken kritik bir uyarı (varsa).
        Cevabın sadece bu bilgileri içeren, formatlanmış bir metin olsun. Tıbbi jargon kullanma.
        """
        response = model.generate_content(prompt, request_options={"timeout": 60})
        
        if response and response.parts:
            text_part = next((part.text for part in response.parts if part.text), None)
            if text_part:
                return text_part
        return "Bu ilaç hakkında güvenilir bir bilgi bulunamadı. Lütfen doktorunuza veya eczacınıza danışın."
    except Exception as e:
        print(f"--- İLAÇ BİLGİSİ HATASI: {str(e)} ---")
        raise HTTPException(status_code=500, detail="Yapay zeka servisinden ilaç bilgisi alınırken bir sorun oluştu.")

@app.get("/medication-info/{med_name}")
def get_medication_info(med_name: str, current_user: models.User = Depends(get_current_user)):
    info = get_medication_info_from_ai(med_name)
    return {"info": info}

