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

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

app = FastAPI()
api_router = APIRouter(prefix="/api")

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

def generate_hash(base64_string: str) -> str:
    """Generate SHA-256 hash from base64 string"""
    return hashlib.sha256(base64_string.encode()).hexdigest()

@api_router.post("/encrypt", response_model=EncryptResponse)
async def encrypt_message(request: EncryptRequest):
    """Encrypt a message with an image hash"""
    try:
        image_hash = generate_hash(request.imageBase64)
        
        link_data = EncryptedLink(
            imageHash=image_hash,
            message=request.message,
            expiresAt=datetime.now(timezone.utc) + timedelta(hours=24)
        )
        
        doc = link_data.model_dump()
        doc['createdAt'] = doc['createdAt'].isoformat()
        doc['expiresAt'] = doc['expiresAt'].isoformat()
        
        await db.encrypted_links.insert_one(doc)
        
        return EncryptResponse(
            linkId=link_data.linkId,
            expiresAt=doc['expiresAt']
        )
    except Exception as e:
        logging.error(f"Error encrypting message: {e}")
        raise HTTPException(status_code=500, detail="Failed to encrypt message")

@api_router.post("/verify/{link_id}", response_model=VerifyResponse)
async def verify_image(link_id: str, request: VerifyRequest):
    """Verify image and return message if correct"""
    try:
        link_doc = await db.encrypted_links.find_one({"linkId": link_id}, {"_id": 0})
        
        if not link_doc:
            return VerifyResponse(
                success=False,
                message="Link not found or expired"
            )
        
        expires_at = datetime.fromisoformat(link_doc['expiresAt'])
        if datetime.now(timezone.utc) > expires_at:
            await db.encrypted_links.delete_one({"linkId": link_id})
            return VerifyResponse(
                success=False,
                message="This link has expired"
            )
        
        uploaded_hash = generate_hash(request.imageBase64)
        
        if uploaded_hash == link_doc['imageHash']:
            return VerifyResponse(
                success=True,
                message=link_doc['message']
            )
        else:
            return VerifyResponse(
                success=False,
                message="Incorrect image. Please try again."
            )
    except Exception as e:
        logging.error(f"Error verifying image: {e}")
        raise HTTPException(status_code=500, detail="Failed to verify image")

@api_router.get("/check/{link_id}", response_model=CheckResponse)
async def check_link(link_id: str):
    """Check if a link exists and is not expired"""
    try:
        link_doc = await db.encrypted_links.find_one({"linkId": link_id}, {"_id": 0})
        
        if not link_doc:
            return CheckResponse(
                exists=False,
                message="This link does not exist"
            )
        
        expires_at = datetime.fromisoformat(link_doc['expiresAt'])
        if datetime.now(timezone.utc) > expires_at:
            await db.encrypted_links.delete_one({"linkId": link_id})
            return CheckResponse(
                exists=False,
                message="This link has expired (24 hours)"
            )
        
        return CheckResponse(exists=True)
    except Exception as e:
        logging.error(f"Error checking link: {e}")
        raise HTTPException(status_code=500, detail="Failed to check link")

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():

client.close()
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8000)),
        reload=False
    )

