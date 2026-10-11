from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

import os
import uuid
import logging
import requests
import bcrypt
import jwt
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional

from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, Form, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI()
api_router = APIRouter(prefix="/api")
security = HTTPBearer(auto_error=False)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

JWT_ALGORITHM = "HS256"

# ---------- Object Storage ----------
STORAGE_BASE = (os.environ.get("INTEGRATION_PROXY_URL") or "").strip() or "https://integrations.emergentagent.com"
STORAGE_URL = STORAGE_BASE.rstrip("/") + "/objstore/api/v1/storage"
EMERGENT_KEY = os.environ.get("EMERGENT_LLM_KEY")
APP_NAME = "hirehost"
storage_key = None


def init_storage(force: bool = False):
    global storage_key
    if storage_key and not force:
        return storage_key
    resp = requests.post(f"{STORAGE_URL}/init", json={"emergent_key": EMERGENT_KEY}, timeout=30)
    resp.raise_for_status()
    storage_key = resp.json()["storage_key"]
    return storage_key


def put_object(path: str, data: bytes, content_type: str) -> dict:
    key = init_storage()
    resp = requests.put(
        f"{STORAGE_URL}/objects/{path}",
        headers={"X-Storage-Key": key, "Content-Type": content_type},
        data=data, timeout=120,
    )
    resp.raise_for_status()
    return resp.json()


def get_object(path: str):
    key = init_storage()
    resp = requests.get(f"{STORAGE_URL}/objects/{path}", headers={"X-Storage-Key": key}, timeout=60)
    resp.raise_for_status()
    return resp.content, resp.headers.get("Content-Type", "application/octet-stream")


# ---------- Auth ----------
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def create_token(user_id: str, email: str) -> str:
    payload = {"sub": user_id, "email": email, "exp": datetime.now(timezone.utc) + timedelta(hours=12), "type": "access"}
    return jwt.encode(payload, os.environ["JWT_SECRET"], algorithm=JWT_ALGORITHM)


async def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    if not creds:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(creds.credentials, os.environ["JWT_SECRET"], algorithms=[JWT_ALGORITHM])
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = await db.users.find_one({"email": payload.get("email")})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return {"id": str(user["_id"]), "email": user["email"], "role": user.get("role", "admin")}


class LoginInput(BaseModel):
    email: str
    password: str


@api_router.post("/auth/login")
async def login(input: LoginInput):
    user = await db.users.find_one({"email": input.email.lower().strip()})
    if not user or not verify_password(input.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_token(str(user["_id"]), user["email"])
    return {"token": token, "user": {"email": user["email"], "role": user.get("role", "admin")}}


@api_router.get("/auth/me")
async def me(user=Depends(get_current_user)):
    return user


# ---------- Models ----------
class VacancyIn(BaseModel):
    title: str
    country: str
    industry: str
    salary: str
    currency: str = "SAR"
    openings: int = 1


class InquiryIn(BaseModel):
    company_name: str
    entity_type: str
    contact_person: str = ""
    phone: str = ""
    email: str = ""
    categories: List[Dict[str, Any]] = []
    notes: str = ""


class ApplicationIn(BaseModel):
    name: str
    phone: str
    email: str = ""
    category: str = ""
    experience_years: str = ""
    gulf_experience: str = ""
    city: str = ""
    notes: str = ""


# ---------- Public endpoints ----------
@api_router.get("/")
async def root():
    return {"message": "Hire Host API"}


@api_router.get("/vacancies")
async def list_vacancies():
    return await db.vacancies.find({}, {"_id": 0}).sort("created_at", -1).to_list(200)


@api_router.get("/hires")
async def list_hires():
    return await db.hires.find({}, {"_id": 0}).sort("created_at", -1).to_list(200)


@api_router.post("/inquiries")
async def create_inquiry(input: InquiryIn):
    doc = input.model_dump()
    doc["id"] = str(uuid.uuid4())
    doc["status"] = "new"
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    await db.inquiries.insert_one(doc)
    doc.pop("_id", None)
    return {"ok": True, "id": doc["id"]}


@api_router.post("/applications")
async def create_application(input: ApplicationIn):
    doc = input.model_dump()
    doc["id"] = str(uuid.uuid4())
    doc["status"] = "new"
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    await db.applications.insert_one(doc)
    doc.pop("_id", None)
    return {"ok": True, "id": doc["id"]}


@api_router.get("/files/{path:path}")
async def serve_file(path: str):
    record = await db.files.find_one({"storage_path": path, "is_deleted": False})
    if not record:
        raise HTTPException(status_code=404, detail="File not found")
    try:
        data, content_type = get_object(path)
    except Exception:
        raise HTTPException(status_code=404, detail="File not found in storage")
    return Response(content=data, media_type=record.get("content_type", content_type))


# ---------- Admin endpoints ----------
@api_router.post("/admin/vacancies")
async def create_vacancy(input: VacancyIn, user=Depends(get_current_user)):
    doc = input.model_dump()
    doc["id"] = str(uuid.uuid4())
    doc["created_at"] = datetime.now(timezone.utc).isoformat()
    await db.vacancies.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api_router.delete("/admin/vacancies/{vid}")
async def delete_vacancy(vid: str, user=Depends(get_current_user)):
    await db.vacancies.delete_one({"id": vid})
    return {"ok": True}


@api_router.post("/admin/hires")
async def create_hire(
    name: str = Form(...),
    profession: str = Form(...),
    country: str = Form(...),
    visa_status: str = Form("Visa Stamped"),
    photo_url: str = Form(""),
    photo: Optional[UploadFile] = File(None),
    user=Depends(get_current_user),
):
    storage_path = ""
    if photo and photo.filename:
        ext = photo.filename.split(".")[-1] if "." in photo.filename else "jpg"
        path = f"{APP_NAME}/hires/{uuid.uuid4()}.{ext}"
        data = await photo.read()
        result = put_object(path, data, photo.content_type or "image/jpeg")
        storage_path = result["path"]
        await db.files.insert_one({
            "id": str(uuid.uuid4()),
            "storage_path": storage_path,
            "original_filename": photo.filename,
            "content_type": photo.content_type or "image/jpeg",
            "size": result.get("size", 0),
            "is_deleted": False,
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    doc = {
        "id": str(uuid.uuid4()),
        "name": name,
        "profession": profession,
        "country": country,
        "visa_status": visa_status,
        "photo_url": photo_url,
        "storage_path": storage_path,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    await db.hires.insert_one(doc)
    doc.pop("_id", None)
    return doc


@api_router.delete("/admin/hires/{hid}")
async def delete_hire(hid: str, user=Depends(get_current_user)):
    await db.hires.delete_one({"id": hid})
    return {"ok": True}


@api_router.get("/admin/inquiries")
async def list_inquiries(user=Depends(get_current_user)):
    return await db.inquiries.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)


@api_router.get("/admin/applications")
async def list_applications(user=Depends(get_current_user)):
    return await db.applications.find({}, {"_id": 0}).sort("created_at", -1).to_list(500)


@api_router.patch("/admin/applications/{aid}")
async def update_application(aid: str, payload: Dict[str, Any], user=Depends(get_current_user)):
    await db.applications.update_one({"id": aid}, {"$set": {"status": payload.get("status", "new")}})
    return {"ok": True}


@api_router.patch("/admin/inquiries/{iid}")
async def update_inquiry(iid: str, payload: Dict[str, Any], user=Depends(get_current_user)):
    await db.inquiries.update_one({"id": iid}, {"$set": {"status": payload.get("status", "new")}})
    return {"ok": True}


# ---------- Seed ----------
SAMPLE_VACANCIES = [
    {"title": "Heavy Driver (Trailer)", "country": "Saudi Arabia", "industry": "Transport & Logistics", "salary": "1800", "currency": "SAR", "openings": 25},
    {"title": "Civil Site Engineer", "country": "UAE", "industry": "Construction", "salary": "6000", "currency": "AED", "openings": 8},
    {"title": "HVAC Technician", "country": "Qatar", "industry": "MEP & HVAC", "salary": "2200", "currency": "QAR", "openings": 15},
    {"title": "Staff Nurse", "country": "Saudi Arabia", "industry": "Healthcare", "salary": "3500", "currency": "SAR", "openings": 20},
    {"title": "Restaurant Waiter", "country": "Kuwait", "industry": "Hospitality", "salary": "320", "currency": "KWD", "openings": 30},
    {"title": "Warehouse Associate", "country": "Bahrain", "industry": "Logistics", "salary": "280", "currency": "BHD", "openings": 40},
]

SAMPLE_HIRES = [
    {"name": "Mohammed Rizwan", "profession": "Heavy Driver", "country": "Saudi Arabia", "visa_status": "Visa Stamped",
     "photo_url": "https://images.unsplash.com/photo-1672748341520-6a839e6c05bb?crop=entropy&cs=srgb&fm=jpg&ixid=M3w4NjA1NTN8MHwxfHNlYXJjaHwxfHxwb3J0cmFpdCUyMGVuZ2luZWVyfGVufDB8fHx8MTc4OTUwMDgyM3ww&ixlib=rb-4.1.0&q=85"},
    {"name": "Arif Shaikh", "profession": "Civil Engineer", "country": "UAE", "visa_status": "Flight Dispatched",
     "photo_url": "https://images.unsplash.com/photo-1579580033453-2327e067baa9?crop=entropy&cs=srgb&fm=jpg&ixid=M3w4NjA1NTN8MHwxfHNlYXJjaHw0fHxwb3J0cmFpdCUyMGVuZ2luZWVyfGVufDB8fHx8MTc4OTUwMDgyM3ww&ixlib=rb-4.1.0&q=85"},
    {"name": "Salman Ansari", "profession": "HVAC Technician", "country": "Qatar", "visa_status": "Visa Stamped",
     "photo_url": "https://images.unsplash.com/photo-1688841747582-41097036109d?crop=entropy&cs=srgb&fm=jpg&ixid=M3w4NjA1NTN8MHwxfHNlYXJjaHwzfHxwb3J0cmFpdCUyMGVuZ2luZWVyfGVufDB8fHx8MTc4OTUwMDgyM3ww&ixlib=rb-4.1.0&q=85"},
    {"name": "Imran Khan", "profession": "Welder / Fabricator", "country": "Kuwait", "visa_status": "Flight Dispatched",
     "photo_url": "https://images.unsplash.com/photo-1672748341520-6a839e6c05bb?crop=entropy&cs=srgb&fm=jpg&ixid=M3w4NjA1NTN8MHwxfHNlYXJjaHwxfHxwb3J0cmFpdCUyMGVuZ2luZWVyfGVufDB8fHx8MTc4OTUwMDgyM3ww&ixlib=rb-4.1.0&q=85"},
    {"name": "Feroz Alam", "profession": "Chef de Partie", "country": "Bahrain", "visa_status": "Visa Stamped",
     "photo_url": "https://images.unsplash.com/photo-1579580033453-2327e067baa9?crop=entropy&cs=srgb&fm=jpg&ixid=M3w4NjA1NTN8MHwxfHNlYXJjaHw0fHxwb3J0cmFpdCUyMGVuZ2luZWVyfGVufDB8fHx8MTc4OTUwMDgyM3ww&ixlib=rb-4.1.0&q=85"},
    {"name": "Wasim Akhtar", "profession": "Electrician", "country": "Saudi Arabia", "visa_status": "Flight Dispatched",
     "photo_url": "https://images.unsplash.com/photo-1688841747582-41097036109d?crop=entropy&cs=srgb&fm=jpg&ixid=M3w4NjA1NTN8MHwxfHNlYXJjaHwzfHxwb3J0cmFpdCUyMGVuZ2luZWVyfGVufDB8fHx8MTc4OTUwMDgyM3ww&ixlib=rb-4.1.0&q=85"},
]


async def seed():
    await db.users.create_index("email", unique=True)
    admin_email = os.environ.get("ADMIN_EMAIL", "admin@hirehost.in").lower()
    admin_password = os.environ.get("ADMIN_PASSWORD", "HireHost@2026")
    existing = await db.users.find_one({"email": admin_email})
    if not existing:
        await db.users.insert_one({
            "email": admin_email,
            "password_hash": hash_password(admin_password),
            "name": "Hire Host Admin",
            "role": "admin",
            "created_at": datetime.now(timezone.utc).isoformat(),
        })
    elif not verify_password(admin_password, existing["password_hash"]):
        await db.users.update_one({"email": admin_email}, {"$set": {"password_hash": hash_password(admin_password)}})

    if await db.vacancies.count_documents({}) == 0:
        now = datetime.now(timezone.utc).isoformat()
        await db.vacancies.insert_many([{**v, "id": str(uuid.uuid4()), "created_at": now} for v in SAMPLE_VACANCIES])
    if await db.hires.count_documents({}) == 0:
        now = datetime.now(timezone.utc).isoformat()
        await db.hires.insert_many([{**h, "id": str(uuid.uuid4()), "storage_path": "", "created_at": now} for h in SAMPLE_HIRES])


@app.on_event("startup")
async def startup():
    try:
        init_storage()
        logger.info("Object storage initialized")
    except Exception:
        logger.exception("Storage initialization failed")

    try:
        await seed()
        logger.info("Database seeded")
    except Exception:
        # Keep the API process running if MongoDB is temporarily unreachable.
        # Database-dependent endpoints will still require a working MongoDB connection.
        logger.exception("Database seeding failed; API startup will continue")


app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
