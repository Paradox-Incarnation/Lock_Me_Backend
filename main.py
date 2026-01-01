from fastapi import FastAPI, APIRouter, HTTPException
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
import hashlib
from datetime import datetime, timezone, timedelta
import uuid

# =======================
# ENV SETUP
# =======================

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

MONGO_URL = os.environ.get("MONGO_URL")
DB_NAME = os.environ.get("DB_NAME")

if not MONGO_URL or not DB_NAME:
    raise RuntimeError("MONGO_URL or DB_NAME not set")

# =======================
# DATABASE
# =======================

client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

# =======================
# APP
# =======================

app = FastAPI()
api_router = APIRouter(prefix="/api")

# =======================
# MODELS
# =======================

class EncryptRequest(BaseModel):
    imageBase64: str
    message: str


class VerifyRequest(BaseModel):
    imageBase64: str


class EncryptResponse(BaseModel):
    linkId: str
    expiresAt: str


class VerifyResponse(BaseModel):
    success: bool
    message: str = ""


class CheckResponse(BaseModel):
    exists: bool
    message: str = ""


class EncryptedLink(BaseModel):
    model_config = ConfigDict(extra="ignore")

    linkId: str = Field(default_factory=lambda: str(uuid.uuid4()))
    imageHash: str
    message: str
    createdAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expiresAt: datetime


# =======================
# UTILS
# =======================

def generate_hash(base64_string: str) -> str:
    return hashlib.sha256(base64_string.encode()).hexdigest()


# =======================
# ROUTES
# =======================

@api_router.post("/encrypt", response_model=EncryptResponse)
async def encrypt_message(request: EncryptRequest):
    try:
        image_hash = generate_hash(request.imageBase64)

        link_data = EncryptedLink(
            imageHash=image_hash,
            message=request.message,
            expiresAt=datetime.now(timezone.utc) + timedelta(hours=24),
        )

        doc = link_data.model_dump()
        doc["createdAt"] = doc["createdAt"].isoformat()
        doc["expiresAt"] = doc["expiresAt"].isoformat()

        await db.encrypted_links.insert_one(doc)

        return EncryptResponse(
            linkId=link_data.linkId,
            expiresAt=doc["expiresAt"],
        )

    except Exception as e:
        logging.error(f"Encrypt error: {e}")
        raise HTTPException(status_code=500, detail="Encryption failed")


@api_router.post("/verify/{link_id}", response_model=VerifyResponse)
async def verify_image(link_id: str, request: VerifyRequest):
    try:
        link_doc = await db.encrypted_links.find_one(
            {"linkId": link_id}, {"_id": 0}
        )

        if not link_doc:
            return VerifyResponse(success=False, message="Link not found")

        expires_at = datetime.fromisoformat(link_doc["expiresAt"])
        if datetime.now(timezone.utc) > expires_at:
            await db.encrypted_links.delete_one({"linkId": link_id})
            return VerifyResponse(success=False, message="Link expired")

        uploaded_hash = generate_hash(request.imageBase64)

        if uploaded_hash == link_doc["imageHash"]:
            return VerifyResponse(success=True, message=link_doc["message"])

        return VerifyResponse(success=False, message="Incorrect image")

    except Exception as e:
        logging.error(f"Verify error: {e}")
        raise HTTPException(status_code=500, detail="Verification failed")


@api_router.get("/check/{link_id}", response_model=CheckResponse)
async def check_link(link_id: str):
    try:
        link_doc = await db.encrypted_links.find_one(
            {"linkId": link_id}, {"_id": 0}
        )

        if not link_doc:
            return CheckResponse(exists=False, message="Link does not exist")

        expires_at = datetime.fromisoformat(link_doc["expiresAt"])
        if datetime.now(timezone.utc) > expires_at:
            await db.encrypted_links.delete_one({"linkId": link_id})
            return CheckResponse(exists=False, message="Link expired")

        return CheckResponse(exists=True)

    except Exception as e:
        logging.error(f"Check error: {e}")
        raise HTTPException(status_code=500, detail="Check failed")


# =======================
# MIDDLEWARE
# =======================

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

# =======================
# LOGGING
# =======================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

# =======================
# SHUTDOWN
# =======================

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

