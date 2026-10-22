import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from motor.motor_asyncio import AsyncIOMotorClient
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import jwt
import httpx

app = FastAPI(title="T-Rex Cloud Core API", docs_url=None, redoc_url=None)

# CORS Configuration - Apne Hostinger Custom Domain ko yahan allow karein
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Production me: ["https://yourdomain.com"]
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Environment Variables
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://user:pass@cluster.mongodb.net/trex_cloud")
JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-trex-enterprise-key-change-me")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "your-google-client-id.apps.googleusercontent.com")
WORKER_SHARED_SECRET = os.getenv("WORKER_SHARED_SECRET", "trex-edge-sync-secret-99")
SUPER_ADMIN_EMAIL = os.getenv("SUPER_ADMIN_EMAIL", "admin@yourdomain.com")

client = AsyncIOMotorClient(MONGO_URI)
db = client.trex_cloud

# ==========================================
# PYDANTIC SCHEMAS
# ==========================================

class GoogleLoginRequest(BaseModel):
    credential: str  # Google ID Token from frontend

class ChunkMeta(BaseModel):
    index: int
    file_id: str
    bot_index: int
    size: int

class FileRegisterRequest(BaseModel):
    file_name: str
    file_size: int
    mime_type: str
    sender_note: Optional[str] = ""
    custom_slug: Optional[str] = None
    password: Optional[str] = None
    chunks: List[ChunkMeta]

class SystemConfigUpdate(BaseModel):
    guest_expiry_days: int = Field(ge=1, le=365)
    channel_id: str
    bot_tokens: List[str]

class UserStatusUpdate(BaseModel):
    status: str  # "active" | "suspended"
    role: str    # "user" | "admin"


# ==========================================
# STARTUP: INITIALIZE DB & TTL INDEX
# ==========================================

@app.on_event("startup")
async def startup_db():
    # 1. TTL Index: Jis document me `expires_at` timestamp hoga, wo us time par auto-delete ho jayega.
    # Registered users ki files me `expires_at = None` rahega, to wo kabhi expire nahi hongi!
    await db.files.create_index("expires_at", expireAfterSeconds=0)
    await db.files.create_index("slug", unique=True)
    await db.users.create_index("email", unique=True)

    # 2. Default System Settings (Admin Webpage se change kar sakta hai)
    config = await db.config.find_one({"_id": "global_settings"})
    if not config:
        await db.config.insert_one({
            "_id": "global_settings",
            "guest_expiry_days": 3,
            "channel_id": os.getenv("DEFAULT_CHANNEL_ID", "-1001234567890"),
            "bot_tokens": [
                os.getenv("DEFAULT_BOT_TOKEN_1", "YOUR_BOT_TOKEN_1")
            ],
            "updated_at": datetime.now(timezone.utc)
        })


# ==========================================
# AUTHENTICATION HELPERS
# ==========================================

def create_jwt(user_data: dict) -> str:
    payload = {
        "sub": str(user_data["_id"]),
        "email": user_data["email"],
        "name": user_data["name"],
        "role": user_data["role"],
        "exp": datetime.now(timezone.utc) + timedelta(days=30)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

async def get_optional_user(authorization: Optional[str] = Header(None)):
    """Guest mode me None return karega, Logged-in user me user dict return karega."""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user = await db.users.find_one({"email": payload["email"]})
        if not user or user.get("status") == "suspended":
            raise HTTPException(status_code=403, detail="Account suspended or invalid.")
        return user
    except Exception:
        return None

async def require_admin(user=Depends(get_optional_user)):
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required.")
    return user


# ==========================================
# 1. GOOGLE OAUTH & SESSION ENDPOINTS
# ==========================================

@app.post("/api/auth/google")
async def google_login(req: GoogleLoginRequest):
    try:
        idinfo = id_token.verify_oauth2_token(
            req.credential, google_requests.Request(), GOOGLE_CLIENT_ID
        )
        email = idinfo["email"].lower()
        name = idinfo.get("name", email.split("@")[0])
        picture = idinfo.get("picture", "")
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid Google token")

    user = await db.users.find_one({"email": email})
    now = datetime.now(timezone.utc)

    if not user:
        role = "admin" if email == SUPER_ADMIN_EMAIL.lower() else "user"
        new_user = {
            "email": email,
            "name": name,
            "picture": picture,
            "role": role,
            "status": "active",
            "total_uploads": 0,
            "total_bytes": 0,
            "created_at": now,
            "last_login": now
        }
        res = await db.users.insert_one(new_user)
        new_user["_id"] = res.inserted_id
        user = new_user
    else:
        if user.get("status") == "suspended":
            raise HTTPException(status_code=403, detail="Your account has been suspended by Admin.")
        await db.users.update_one({"_id": user["_id"]}, {"$set": {"last_login": now, "picture": picture}})

    token = create_jwt(user)
    return {
        "token": token,
        "user": {
            "name": user["name"],
            "email": user["email"],
            "picture": user.get("picture"),
            "role": user["role"]
        }
    }

@app.get("/api/public/policy")
async def get_public_policy():
    """Frontend ko batata hai ki abhi Guest Mode me kitne din ki expiry chal rahi hai."""
    config = await db.config.find_one({"_id": "global_settings"})
    return {
        "guest_expiry_days": config.get("guest_expiry_days", 3),
        "chunk_size_bytes": 19 * 1024 * 1024  # 19 MB safe chunk size
    }


# ==========================================
# 2. FILE REGISTRATION & METADATA (USER + GUEST)
# ==========================================

@app.post("/api/files/register")
async def register_uploaded_file(req: FileRegisterRequest, request: Request, user=Depends(get_optional_user)):
    config = await db.config.find_one({"_id": "global_settings"})
    guest_days = config.get("guest_expiry_days", 3)

    slug = req.custom_slug.strip() if req.custom_slug else secrets.token_urlsafe(5)
    existing = await db.files.find_one({"slug": slug})
    if existing:
        slug = f"{slug}-{secrets.token_hex(2)}"

    now = datetime.now(timezone.utc)
    is_guest = user is None

    # Guest file expires after `guest_days`, Registered user file NEVER expires (`None`)
    expires_at = (now + timedelta(days=guest_days)) if is_guest else None

    file_doc = {
        "slug": slug,
        "file_name": req.file_name,
        "file_size": req.file_size,
        "mime_type": req.mime_type or "application/octet-stream",
        "sender_note": req.sender_note.strip() if req.sender_note else "",
        "password": req.password,
        "chunks": [c.model_dump() for c in sorted(req.chunks, key=lambda x: x.index)],
        "uploader_Mode": "guest" if is_guest else "registered",
        "uploader_email": user["email"] if user else "Guest User",
        "uploader_name": user["name"] if user else "Guest",
        "uploader_ip": request.headers.get("cf-connecting-ip", request.client.host),
        "created_at": now,
        "expires_at": expires_at,
        "views_count": 0,
        "downloads_count": 0,
        "active": True
    }

    await db.files.insert_one(file_doc)

    if user:
        await db.users.update_one(
            {"_id": user["_id"]},
            {"$inc": {"total_uploads": 1, "total_bytes": req.file_size}}
        )

    return {
        "slug": slug,
        "share_url": f"/d/{slug}",
        "expires_at": expires_at.isoformat() if expires_at else "Permanent"
    }

@app.get("/api/files/my-history")
async def get_my_files(user=Depends(get_optional_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Login required to view upload history")
    
    cursor = db.files.find({"uploader_email": user["email"]}, {"chunks": 0, "_id": 0}).sort("created_at", -1)
    files = await cursor.to_list(length=200)
    return {"files": files}

@app.get("/api/files/info/{slug}")
async def get_public_file_info(slug: str):
    """Download page khulne par file ka naam, size, aur Sender Note return karta hai."""
    f = await db.files.find_one({"slug": slug, "active": True}, {"chunks": 0, "_id": 0, "password": 0})
    if not f:
        raise HTTPException(status_code=404, detail="Link expired or does not exist.")
    return f


# ==========================================
# 3. ADMIN CONTROL CENTER (BOTS, CHANNEL, USERS)
# ==========================================

@app.get("/api/admin/settings")
async def get_admin_settings(admin=Depends(require_admin)):
    config = await db.config.find_one({"_id": "global_settings"})
    # Mask tokens slightly for UI or send full to Admin
    return {
        "guest_expiry_days": config.get("guest_expiry_days", 3),
        "channel_id": config.get("channel_id", ""),
        "bot_tokens": config.get("bot_tokens", [])
    }

@app.put("/api/admin/settings")
async def update_admin_settings( body: SystemConfigUpdate, admin=Depends(require_admin)):
    """Admin webpage se Bot API Tokens, Channel ID, ya Guest Expiry Days update karega."""
    if not body.bot_tokens:
        raise HTTPException(status_code=400, detail="At least one active storage node token is required.")

    await db.config.update_one(
        {"_id": "global_settings"},
        {"$set": {
            "guest_expiry_days": body.guest_expiry_days,
            "channel_id": body.channel_id.strip(),
            "bot_tokens": [t.strip() for t in body.bot_tokens if t.strip()],
            "updated_at": datetime.now(timezone.utc)
        }},
        upsert=True
    )
    return {"status": "updated", "guest_expiry_days": body.guest_expiry_days, "active_bots": len(body.bot_tokens)}

@app.post("/api/admin/verify-storage")
async def verify_storage_nodes(admin=Depends(require_admin)):
    """Webpage par 'Test Bot & Channel Ping' button dabane par live check karega."""
    config = await db.config.find_one({"_id": "global_settings"})
    channel_id = config.get("channel_id")
    tokens = config.get("bot_tokens", [])
    results = []

    async with httpx.AsyncClient(timeout=10.0) as client_http:
        for idx, token in enumerate(tokens):
            try:
                r = await client_http.get(f"https://api.telegram.org/bot{token}/getChat?chat_id={channel_id}")
                data = r.json()
                results.append({
                    "node": f"Node #{idx + 1}",
                    "ok": data.get("ok", False),
                    "channel_title": data.get("result", {}).get("title", "Unknown")
                })
            except Exception as e:
                results.append({"node": f"Node #{idx + 1}", "ok": False, "error": str(e)})

    return {"results": results}

@app.get("/api/admin/users")
async def list_all_users(admin=Depends(require_admin)):
    cursor = db.users.find({}, {"_id": 0}).sort("created_at", -1)
    users = await cursor.to_list(length=500)
    return {"users": users}

@app.patch("/api/admin/users/{email}")
async def manage_user(email: str, body: UserStatusUpdate, admin=Depends(require_admin)):
    await db.users.update_one(
        {"email": email.lower()},
        {"$set": {"status": body.status, "role": body.role}}
    )
    return {"status": "success"}


# ==========================================
# 4. INTERNAL EDGE WORKER SYNC ENDPOINT
# ==========================================

@app.get("/api/internal/edge-config")
async def get_edge_config(
    slug: Optional[str] = None,
    x_edge_secret: str = Header(None)
):
    """
    Yeh endpoint SIRF hamare Cloudflare Worker ko Bot Tokens, Channel ID, 
    aur File Chunks deta hai. Normal user ko kabhi nahi dikhta!
    """
    if x_edge_secret != WORKER_SHARED_SECRET:
        raise HTTPException(status_code=403, detail="Forbidden")

    config = await db.config.find_one({"_id": "global_settings"})
    response = {
        "channel_id": config.get("channel_id"),
        "bot_tokens": config.get("bot_tokens", [])
    }

    if slug:
        file_doc = await db.files.find_one({"slug": slug, "active": True}, {"_id": 0})
        if not file_doc:
            raise HTTPException(status_code=404, detail="File not found")
        await db.files.update_one({"slug": slug}, {"$inc": {"downloads_count": 1}})
        response["file"] = file_doc

    return response

  # Connect Phase 3 (Telemetry) & Phase 4 (WebRTC P2P) Routers
from telemetry_routes import router as telemetry_router
from webrtc_signaling import webrtc_router

app.include_router(telemetry_router)
app.include_router(webrtc_router)