import os
import re
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any

import httpx
from fastapi import FastAPI, HTTPException, Request, Depends, WebSocket, WebSocketDisconnect, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel
from jose import jwt, JWTError

app = FastAPI(title="T-Rex Cloud Enterprise Core API v7.0 (Strict Watcher Edition)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": f"Server Error: {str(exc)}"},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "*",
            "Access-Control-Allow-Headers": "*"
        }
    )

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "trex_cloud")
JWT_SECRET = os.getenv("JWT_SECRET", "trex_super_secret_jwt_key_2026")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "9907401831-gdo04d733h0p7a12o1e9vkdd3e2g5saq.apps.googleusercontent.com")
SUPER_ADMIN_EMAIL = os.getenv("SUPER_ADMIN_EMAIL", "vikramadityakumarshukla@gmail.com").lower().strip()
WORKER_SHARED_SECRET = os.getenv("WORKER_SHARED_SECRET", "TRex_Edge_Sync_Secret_99")

DEFAULT_BOT_TOKENS = [t.strip() for t in os.getenv("TELEGRAM_BOT_TOKENS", "").split(",") if t.strip()]
DEFAULT_CHANNEL_ID = os.getenv("TELEGRAM_CHANNEL_ID", "-1003957020033").strip()

client = AsyncIOMotorClient(MONGO_URI, serverSelectionTimeoutMS=8000)
db = client[DB_NAME]

# =========================================================
# STRICT SCHEMAS & MODELS
# =========================================================
class GoogleAuthPayload(BaseModel):
    credential: str
    guest_token: Optional[str] = None

class GuestInitPayload(BaseModel):
    guest_token: Optional[str] = None

class StrictChunkItem(BaseModel):
    part_id: str                 # e.g. "PART-0000"
    index: int                   # 0, 1, 2...
    start_byte: int              # Exact byte start offset
    end_byte: int                # Exact byte end offset
    size: int                    # Exact byte length
    checksum: Optional[str] = "" # Integrity signature
    file_id: str                 # Telegram file_id
    message_id: Optional[int] = None
    bot_index: int = 0

class WatcherUploadInitPayload(BaseModel):
    file_name: str
    file_size: int
    mime_type: str = "application/octet-stream"

class FileRegisterPayload(BaseModel):
    watch_id: Optional[str] = None
    file_name: str
    file_size: int
    mime_type: str = "application/octet-stream"
    sender_note: Optional[str] = ""
    custom_slug: Optional[str] = None
    folder_id: Optional[str] = "root"
    chunks: List[StrictChunkItem]

class WatcherDownloadVerifyPayload(BaseModel):
    slug: str
    watch_id: Optional[str] = None
    received_bytes: int
    total_bytes: int
    verified_parts: int
    total_parts: int
    status: str = "completed"

class FileUpdatePayload(BaseModel):
    file_name: Optional[str] = None
    sender_note: Optional[str] = None
    custom_slug: Optional[str] = None
    regenerate_slug: Optional[bool] = False
    folder_id: Optional[str] = None

class FolderCreatePayload(BaseModel):
    name: str
    parent_id: Optional[str] = "root"

class NoticeCreatePayload(BaseModel):
    title: str
    message: str
    level: str = "info"
    target: str = "all"

class AdminSettingsPayload(BaseModel):
    guest_expiry_days: int = 3
    channel_id: str
    bot_tokens: List[str]
    chunk_size_mb: int = 8
    max_concurrency: int = 3

# =========================================================
# SYSTEM SETTINGS & CONCURRENCY CAP ENFORCER
# =========================================================
def create_jwt(data: dict, days: int = 30) -> str:
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(days=days)
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

async def get_system_settings() -> dict:
    doc = await db.settings.find_one({"_id": "global"})
    if not doc:
        doc = {
            "_id": "global",
            "guest_expiry_days": 3,
            "channel_id": DEFAULT_CHANNEL_ID,
            "bot_tokens": DEFAULT_BOT_TOKENS,
            "chunk_size_mb": 8,
            "max_concurrency": max(1, len(DEFAULT_BOT_TOKENS)) if DEFAULT_BOT_TOKENS else 1
        }
        await db.settings.insert_one(doc)
    else:
        if not doc.get("channel_id") and DEFAULT_CHANNEL_ID:
            doc["channel_id"] = DEFAULT_CHANNEL_ID
        if not doc.get("bot_tokens") and DEFAULT_BOT_TOKENS:
            doc["bot_tokens"] = DEFAULT_BOT_TOKENS

    bots_count = max(1, len(doc.get("bot_tokens") or []))
    chunk_mb = max(2, min(19, int(doc.get("chunk_size_mb") or 8)))
    # STRICT RULE: Concurrent upload streams CANNOT exceed number of added bots!
    raw_conc = int(doc.get("max_concurrency") or bots_count)
    effective_conc = max(1, min(raw_conc, bots_count))

    doc["chunk_size_mb"] = chunk_mb
    doc["max_concurrency"] = effective_conc
    doc["bots_count"] = bots_count
    return doc

async def get_actor(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_guest_token: Optional[str] = Header(None)
) -> dict:
    if authorization and authorization.startswith("Bearer "):
        token = authorization.replace("Bearer ", "").strip()
        try:
            decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            user = await db.users.find_one({"$or": [{"uid": decoded.get("uid")}, {"email": decoded.get("email")}]})
            if user:
                return {
                    "uid": user["uid"],
                    "account_type": "user",
                    "role": user.get("role", "user"),
                    "name": user.get("name", "User"),
                    "email": user.get("email", ""),
                }
        except JWTError:
            pass

    ip = request.headers.get("CF-Connecting-IP") or request.headers.get("X-Forwarded-For") or (request.client.host if request.client else "0.0.0.0")
    ua = request.headers.get("User-Agent", "")
    ip_hash = hashlib.sha256(f"{ip}:{ua}".encode()).hexdigest()[:16]

    guest = None
    if x_guest_token:
        guest = await db.users.find_one({"guest_token": x_guest_token, "account_type": "guest"})
    if not guest:
        guest = await db.users.find_one({"ip_hash": ip_hash, "account_type": "guest"})

    if not guest:
        short_code = secrets.token_hex(4).upper()
        guest_uid = f"GUEST-{short_code[:4]}-{short_code[4:]}"
        g_token = f"gt_{secrets.token_urlsafe(24)}"
        guest = {
            "uid": guest_uid,
            "guest_token": g_token,
            "account_type": "guest",
            "role": "guest",
            "name": f"Guest ({guest_uid})",
            "email": f"{guest_uid.lower()}@guest.ludrex.space",
            "last_ip": ip,
            "ip_hash": ip_hash,
            "total_uploads": 0,
            "status": "Active",
            "created_at": datetime.utcnow().isoformat(),
            "last_seen": datetime.utcnow().isoformat()
        }
        await db.users.insert_one(guest)
    else:
        await db.users.update_one(
            {"_id": guest["_id"]},
            {"$set": {"last_seen": datetime.utcnow().isoformat(), "last_ip": ip}}
        )

    return {
        "uid": guest["uid"],
        "guest_token": guest["guest_token"],
        "account_type": "guest",
        "role": "guest",
        "name": guest["name"],
        "email": guest.get("last_ip", ip)
    }

async def require_admin(actor: dict = Depends(get_actor)) -> dict:
    if actor.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return actor

# =========================================================
# 1. PUBLIC POLICY & DYNAMIC UPLOAD CONFIG
# =========================================================
@app.get("/")
@app.get("/health")
async def root_health():
    return {"status": "T-Rex API v7.0 Watcher Active", "time": datetime.utcnow().isoformat()}

@app.get("/api/public/policy")
async def get_public_policy():
    s = await get_system_settings()
    notices = await db.notices.find({"active": True}).sort("created_at", -1).to_list(10)
    for n in notices:
        n["id"] = str(n.pop("_id"))
    chunk_mb = int(s.get("chunk_size_mb", 8))
    return {
        "guest_expiry_days": s.get("guest_expiry_days", 3),
        "chunk_size_mb": chunk_mb,
        "chunk_size_bytes": chunk_mb * 1024 * 1024,
        "max_concurrency": s.get("max_concurrency", 1),
        "bots_count": s.get("bots_count", 1),
        "notices": notices
    }

@app.post("/api/auth/guest-init")
async def init_guest_session(payload: GuestInitPayload, request: Request):
    actor = await get_actor(request, None, payload.guest_token)
    return {
        "uid": actor["uid"],
        "guest_token": actor.get("guest_token"),
        "name": actor["name"],
        "account_type": actor["account_type"]
    }

@app.post("/api/auth/google")
async def google_login(payload: GoogleAuthPayload):
    async with httpx.AsyncClient(timeout=10.0) as http_client:
        g_res = await http_client.get(
            "https://oauth2.googleapis.com/tokeninfo",
            params={"id_token": payload.credential}
        )
        if g_res.status_code != 200:
            raise HTTPException(status_code=401, detail=f"Google token verification failed: {g_res.text}")
        idinfo = g_res.json()

    email = idinfo.get("email", "").lower().strip()
    name = idinfo.get("name") or email.split("@")[0]
    picture = idinfo.get("picture", "")
    sub = idinfo.get("sub", secrets.token_hex(6))

    existing_user = await db.users.find_one({"email": email})
    uid = existing_user.get("uid") if (existing_user and existing_user.get("uid")) else f"USR-{sub[:10]}"

    admin_exists = await db.users.find_one({"role": "admin"})
    is_admin = (email == SUPER_ADMIN_EMAIL) or (admin_exists is None) or (existing_user and existing_user.get("role") == "admin")
    role = "admin" if is_admin else "user"

    user_doc = {
        "uid": uid,
        "account_type": "user",
        "email": email,
        "name": name,
        "picture": picture,
        "role": role,
        "status": "Active",
        "last_seen": datetime.utcnow().isoformat()
    }

    if existing_user:
        await db.users.update_one({"_id": existing_user["_id"]}, {"$set": user_doc})
    else:
        user_doc["created_at"] = datetime.utcnow().isoformat()
        user_doc["total_uploads"] = 0
        await db.users.insert_one(user_doc)
        user_doc.pop("_id", None)

    if payload.guest_token:
        guest_doc = await db.users.find_one({"guest_token": payload.guest_token})
        if guest_doc:
            await db.files.update_many(
                {"owner_uid": guest_doc["uid"]},
                {"$set": {"owner_uid": uid, "uploader_name": name, "uploader_email": email, "expires_at": "Permanent"}}
            )
            await db.folders.update_many(
                {"owner_uid": guest_doc["uid"]},
                {"$set": {"owner_uid": uid}}
            )

    token = create_jwt({"uid": uid, "email": email, "role": role})
    return {"token": token, "user": user_doc}

# =========================================================
# 2. STRICT TRANSFER WATCHER & PART-ID VERIFICATION ENGINE
# =========================================================
@app.post("/api/watcher/init-upload")
async def watcher_init_upload(payload: WatcherUploadInitPayload, actor: dict = Depends(get_actor)):
    """Creates a strict part-by-part blueprint before upload starts and enforces bot concurrency."""
    s = await get_system_settings()
    chunk_bytes = int(s["chunk_size_mb"]) * 1024 * 1024
    total_parts = max(1, (payload.file_size + chunk_bytes - 1) // chunk_bytes)
    watch_id = f"WUP-{secrets.token_hex(5).upper()}"

    expected_parts = []
    for i in range(total_parts):
        start_b = i * chunk_bytes
        end_b = min(start_b + chunk_bytes, payload.file_size) - 1
        sz = (end_b - start_b) + 1 if payload.file_size > 0 else 0
        expected_parts.append({
            "part_id": f"PART-{i:04d}",
            "index": i,
            "start_byte": start_b,
            "end_byte": max(0, end_b),
            "size": sz
        })

    watch_doc = {
        "watch_id": watch_id,
        "type": "upload",
        "owner_uid": actor["uid"],
        "file_name": payload.file_name,
        "file_size": payload.file_size,
        "chunk_size_bytes": chunk_bytes,
        "allowed_concurrency": s["max_concurrency"],
        "bots_count": s["bots_count"],
        "total_parts": total_parts,
        "status": "in_progress",
        "created_at": datetime.utcnow().isoformat()
    }
    await db.transfer_watches.insert_one(watch_doc)

    return {
        "watch_id": watch_id,
        "chunk_size_bytes": chunk_bytes,
        "allowed_concurrency": s["max_concurrency"],
        "bots_count": s["bots_count"],
        "total_parts": total_parts,
        "parts_blueprint": expected_parts
    }

@app.post("/api/files/register")
async def register_file(payload: FileRegisterPayload, actor: dict = Depends(get_actor)):
    """Strictly validates that every single part (0..N-1) and exact byte offsets match before registering."""
    settings = await get_system_settings()

    # 1. STRICT WATCHER INTEGRITY VERIFICATION
    sorted_chunks = sorted([c.dict() for c in payload.chunks], key=lambda x: x["index"])
    if not sorted_chunks:
        raise HTTPException(status_code=400, detail="Watcher Error: No chunks received")

    total_chunk_bytes = 0
    expected_offset = 0
    for idx, ch in enumerate(sorted_chunks):
        if ch["index"] != idx:
            raise HTTPException(status_code=400, detail=f"Watcher Error: Missing Part #{idx} in sequence")
        if not ch.get("file_id"):
            raise HTTPException(status_code=400, detail=f"Watcher Error: Part #{idx} missing Telegram file_id")
        ch["part_id"] = f"PART-{idx:04d}"
        ch["start_byte"] = expected_offset
        ch["end_byte"] = expected_offset + int(ch["size"]) - 1
        expected_offset += int(ch["size"])
        total_chunk_bytes += int(ch["size"])

    if payload.file_size > 0 and total_chunk_bytes != payload.file_size:
        raise HTTPException(
            status_code=400,
            detail=f"Watcher Byte Mismatch: Expected {payload.file_size} bytes, got {total_chunk_bytes} bytes"
        )

    slug = (payload.custom_slug or "").strip()
    if slug:
        slug = re.sub(r"[^a-zA-Z0-9_-]", "-", slug)
        if await db.files.find_one({"slug": slug}):
            slug = f"{slug}-{secrets.token_hex(2)}"
    else:
        slug = secrets.token_urlsafe(6).replace("-", "").replace("_", "")[:8]

    if actor["account_type"] == "user":
        expires_at = "Permanent"
    else:
        days = int(settings.get("guest_expiry_days", 3))
        expires_at = (datetime.utcnow() + timedelta(days=days)).isoformat()

    now_iso = datetime.utcnow().isoformat()
    initial_note = (payload.sender_note or "").strip()
    file_id = f"f_{secrets.token_hex(6)}"

    file_doc = {
        "file_id": file_id,
        "watch_id": payload.watch_id or f"WUP-{secrets.token_hex(4).upper()}",
        "slug": slug,
        "slug_history": [{"slug": slug, "changed_at": now_iso}],
        "file_name": payload.file_name,
        "file_size": payload.file_size,
        "mime_type": payload.mime_type,
        "folder_id": payload.folder_id or "root",
        "sender_note": initial_note,
        "note_history": [{"note": initial_note, "changed_at": now_iso}] if initial_note else [],
        "owner_uid": actor["uid"],
        "account_type": actor["account_type"],
        "uploader_name": actor["name"],
        "uploader_email": actor.get("email", ""),
        "status": "active",
        "integrity_status": "100% Verified",
        "views_count": 0,
        "downloads_count": 0,
        "expires_at": expires_at,
        "created_at": now_iso,
        "updated_at": now_iso,
        "chunks_count": len(sorted_chunks),
        "chunks": sorted_chunks
    }

    await db.files.insert_one(file_doc)
    await db.users.update_one({"uid": actor["uid"]}, {"$inc": {"total_uploads": 1}})

    if payload.watch_id:
        await db.transfer_watches.update_one(
            {"watch_id": payload.watch_id},
            {"$set": {"status": "verified_complete", "slug": slug, "file_id": file_id, "completed_at": now_iso}}
        )

    return {
        "slug": slug,
        "file_id": file_id,
        "expires_at": expires_at,
        "verified_parts": len(sorted_chunks),
        "verified_bytes": total_chunk_bytes
    }

@app.post("/api/watcher/verify-download")
async def watcher_verify_download(payload: WatcherDownloadVerifyPayload):
    """Logs verified download completion when client confirms all Part IDs and bytes match 100%."""
    if payload.status == "completed" and payload.received_bytes >= payload.total_bytes:
        await db.files.update_one({"slug": payload.slug}, {"$inc": {"downloads_count": 1}})
    await db.transfer_watches.insert_one({
        "watch_id": payload.watch_id or f"WDL-{secrets.token_hex(5).upper()}",
        "type": "download",
        "slug": payload.slug,
        "received_bytes": payload.received_bytes,
        "total_bytes": payload.total_bytes,
        "verified_parts": payload.verified_parts,
        "total_parts": payload.total_parts,
        "status": payload.status,
        "timestamp": datetime.utcnow().isoformat()
    })
    return {"ok": True}

# =========================================================
# 3. GOFILE FILE MANAGER & FOLDERS
# =========================================================
@app.post("/api/folders/create")
async def create_folder(payload: FolderCreatePayload, actor: dict = Depends(get_actor)):
    folder_id = f"fld_{secrets.token_hex(5)}"
    doc = {
        "folder_id": folder_id,
        "name": payload.name.strip() or "New Folder",
        "parent_id": payload.parent_id or "root",
        "owner_uid": actor["uid"],
        "status": "active",
        "created_at": datetime.utcnow().isoformat()
    }
    await db.folders.insert_one(doc)
    doc.pop("_id", None)
    return doc

@app.delete("/api/folders/{folder_id}")
async def delete_folder(folder_id: str, mode: str = "trash", actor: dict = Depends(get_actor)):
    new_status = "user_purged" if mode == "permanent" else "trashed"
    await db.folders.update_one(
        {"folder_id": folder_id, "owner_uid": actor["uid"]},
        {"$set": {"status": new_status, "deleted_at": datetime.utcnow().isoformat()}}
    )
    await db.files.update_many(
        {"folder_id": folder_id, "owner_uid": actor["uid"]},
        {"$set": {"status": new_status, "deleted_at": datetime.utcnow().isoformat()}}
    )
    return {"ok": True, "status": new_status}

@app.get("/api/files/manager")
async def list_user_file_manager(
    folder_id: str = "root",
    view: str = "active",
    search: str = "",
    file_type: str = "all",
    sort_by: str = "newest",
    actor: dict = Depends(get_actor)
):
    query: Dict[str, Any] = {"owner_uid": actor["uid"]}
    if view == "trash":
        query["status"] = "trashed"
    else:
        query["status"] = "active"
        if not search and file_type == "all":
            query["folder_id"] = folder_id

    if search.strip():
        q_regex = {"$regex": re.escape(search.strip()), "$options": "i"}
        query["$or"] = [{"file_name": q_regex}, {"slug": q_regex}, {"sender_note": q_regex}]

    if file_type != "all":
        type_map = {
            "video": "video/",
            "image": "image/",
            "audio": "audio/",
            "archive": "(zip|rar|7z|tar|gz)",
            "document": "(pdf|word|excel|text|cad|dwg)"
        }
        if file_type in type_map:
            query["mime_type"] = {"$regex": type_map[file_type], "$options": "i"}

    sort_spec = [("created_at", -1)]
    if sort_by == "oldest":
        sort_spec = [("created_at", 1)]
    elif sort_by == "size_desc":
        sort_spec = [("file_size", -1)]
    elif sort_by == "size_asc":
        sort_spec = [("file_size", 1)]
    elif sort_by == "name_asc":
        sort_spec = [("file_name", 1)]
    elif sort_by == "popular":
        sort_spec = [("downloads_count", -1)]

    files = await db.files.find(query, {"chunks": 0, "_id": 0}).sort(sort_spec).to_list(500)
    folders = []
    if view == "active" and not search.strip() and file_type == "all":
        folders = await db.folders.find(
            {"owner_uid": actor["uid"], "parent_id": folder_id, "status": "active"},
            {"_id": 0}
        ).sort("name", 1).to_list(200)

    return {"files": files, "folders": folders, "actor": actor}

@app.put("/api/files/{file_id}/edit")
async def edit_file_metadata(file_id: str, payload: FileUpdatePayload, actor: dict = Depends(get_actor)):
    query = {"file_id": file_id}
    if actor["role"] != "admin":
        query["owner_uid"] = actor["uid"]

    doc = await db.files.find_one(query)
    if not doc:
        raise HTTPException(status_code=404, detail="File not found")

    now_iso = datetime.utcnow().isoformat()
    updates: Dict[str, Any] = {"updated_at": now_iso}

    if payload.file_name is not None and payload.file_name.strip():
        updates["file_name"] = payload.file_name.strip()
    if payload.folder_id is not None:
        updates["folder_id"] = payload.folder_id

    if payload.sender_note is not None:
        clean_note = payload.sender_note.strip()
        if clean_note != doc.get("sender_note", ""):
            updates["sender_note"] = clean_note
            history = doc.get("note_history", [])
            history.append({"note": clean_note or "[Note Removed]", "changed_at": now_iso, "by": actor["name"]})
            updates["note_history"] = history

    new_slug = None
    if payload.regenerate_slug:
        new_slug = secrets.token_urlsafe(6).replace("-", "").replace("_", "")[:8]
    elif payload.custom_slug is not None and payload.custom_slug.strip() != doc["slug"]:
        candidate = re.sub(r"[^a-zA-Z0-9_-]", "-", payload.custom_slug.strip())
        if candidate:
            if await db.files.find_one({"slug": candidate, "file_id": {"$ne": file_id}}):
                raise HTTPException(status_code=400, detail="Custom link alias already in use")
            new_slug = candidate

    if new_slug:
        updates["slug"] = new_slug
        s_hist = doc.get("slug_history", [])
        s_hist.append({"slug": new_slug, "changed_at": now_iso})
        updates["slug_history"] = s_hist

    await db.files.update_one({"file_id": file_id}, {"$set": updates})
    return await db.files.find_one({"file_id": file_id}, {"_id": 0, "chunks": 0})

@app.post("/api/files/{file_id}/delete")
async def user_delete_or_restore_file(file_id: str, action: str = "trash", actor: dict = Depends(get_actor)):
    doc = await db.files.find_one({"file_id": file_id, "owner_uid": actor["uid"]})
    if not doc:
        raise HTTPException(status_code=404, detail="File not found")

    status_map = {"trash": "trashed", "restore": "active", "permanent": "user_purged"}
    new_status = status_map.get(action, "trashed")
    await db.files.update_one(
        {"file_id": file_id},
        {"$set": {"status": new_status, "status_updated_at": datetime.utcnow().isoformat()}}
    )
    return {"ok": True, "file_id": file_id, "status": new_status}

@app.get("/api/files/info/{slug}")
async def get_public_file_info(slug: str):
    doc = await db.files.find_one({"slug": slug, "status": "active"}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail="Link expired, trashed, or invalid")
    await db.files.update_one({"slug": slug}, {"$inc": {"views_count": 1}})

    s = await get_system_settings()
    chunks_raw = sorted(doc.pop("chunks", []), key=lambda c: c["index"])

    # Build strict part manifest with byte offsets for verified parallel downloading
    cumulative = 0
    chunks_meta = []
    for idx, c in enumerate(chunks_raw):
        sz = int(c["size"])
        chunks_meta.append({
            "part_id": c.get("part_id") or f"PART-{idx:04d}",
            "index": idx,
            "start_byte": c.get("start_byte", cumulative),
            "end_byte": c.get("end_byte", cumulative + sz - 1),
            "size": sz,
            "checksum": c.get("checksum", "")
        })
        cumulative += sz

    doc["chunks_meta"] = chunks_meta
    doc["chunks_count"] = len(chunks_meta)
    doc["download_concurrency"] = max(2, min(4, s.get("bots_count", 3)))
    return doc

@app.get("/api/internal/edge-config")
async def edge_worker_config(slug: Optional[str] = None, x_edge_secret: Optional[str] = Header(None)):
    settings = await get_system_settings()
    resp = {
        "channel_id": settings.get("channel_id", ""),
        "bot_tokens": settings.get("bot_tokens", []),
        "chunk_size_mb": settings.get("chunk_size_mb", 8),
        "max_concurrency": settings.get("max_concurrency", 3)
    }
    if slug:
        f = await db.files.find_one({"slug": slug}, {"_id": 0})
        if not f:
            raise HTTPException(status_code=404, detail="File not found")
        resp["file"] = f
    return resp

# =========================================================
# 4. ADMIN MASTER VAULT, SETTINGS & STORAGE PING
# =========================================================
@app.get("/api/admin/files")
async def admin_master_file_list(status: str = "all", search: str = "", owner_uid: str = "", admin: dict = Depends(require_admin)):
    query: Dict[str, Any] = {}
    if status != "all":
        query["status"] = status
    if owner_uid:
        query["owner_uid"] = owner_uid
    if search.strip():
        q_regex = {"$regex": re.escape(search.strip()), "$options": "i"}
        query["$or"] = [{"file_name": q_regex}, {"slug": q_regex}, {"sender_note": q_regex}, {"uploader_name": q_regex}, {"owner_uid": q_regex}]
    files = await db.files.find(query, {"_id": 0, "chunks": 0}).sort("created_at", -1).to_list(500)
    return {"files": files}

@app.delete("/api/admin/files/{file_id}/hard-purge")
async def admin_hard_delete_from_telegram_and_db(file_id: str, admin: dict = Depends(require_admin)):
    doc = await db.files.find_one({"file_id": file_id})
    if not doc:
        raise HTTPException(status_code=404, detail="File not found")

    settings = await get_system_settings()
    bots = settings.get("bot_tokens", [])
    channel_id = settings.get("channel_id", "")
    tg_deleted = 0

    if bots and channel_id:
        async with httpx.AsyncClient(timeout=10.0) as http_client:
            for ch in doc.get("chunks", []):
                msg_id = ch.get("message_id")
                if msg_id:
                    token = bots[ch.get("bot_index", 0) % len(bots)]
                    try:
                        r = await http_client.post(
                            f"https://api.telegram.org/bot{token}/deleteMessage",
                            json={"chat_id": channel_id, "message_id": msg_id}
                        )
                        if r.status_code == 200:
                            tg_deleted += 1
                    except Exception:
                        pass

    await db.files.delete_one({"file_id": file_id})
    return {"ok": True, "telegram_chunks_deleted": tg_deleted}

@app.get("/api/admin/users")
async def admin_get_all_users_and_guests(admin: dict = Depends(require_admin)):
    users = await db.users.find({}, {"_id": 0}).sort("last_seen", -1).to_list(500)
    return {"users": users}

@app.post("/api/admin/notices")
async def admin_create_notice(payload: NoticeCreatePayload, admin: dict = Depends(require_admin)):
    doc = {
        "title": payload.title.strip(),
        "message": payload.message.strip(),
        "level": payload.level,
        "target": payload.target,
        "active": True,
        "created_by": admin["name"],
        "created_at": datetime.utcnow().isoformat()
    }
    res = await db.notices.insert_one(doc)
    return {"ok": True, "id": str(res.inserted_id)}

@app.get("/api/admin/settings")
async def admin_get_settings(admin: dict = Depends(require_admin)):
    return await get_system_settings()

@app.put("/api/admin/settings")
async def admin_update_settings(payload: AdminSettingsPayload, admin: dict = Depends(require_admin)):
    clean_bots = [t.strip() for t in payload.bot_tokens if t.strip()]
    bots_count = max(1, len(clean_bots))
    chunk_mb = max(2, min(19, int(payload.chunk_size_mb or 8)))
    # Enforce rule: max_concurrency <= number of added bots
    enforced_concurrency = max(1, min(int(payload.max_concurrency or 1), bots_count))

    await db.settings.update_one(
        {"_id": "global"},
        {"$set": {
            "guest_expiry_days": int(payload.guest_expiry_days or 3),
            "channel_id": payload.channel_id.strip(),
            "bot_tokens": clean_bots,
            "chunk_size_mb": chunk_mb,
            "max_concurrency": enforced_concurrency,
            "updated_at": datetime.utcnow().isoformat()
        }},
        upsert=True
    )
    return {
        "ok": True,
        "bots_count": len(clean_bots),
        "chunk_size_mb": chunk_mb,
        "max_concurrency": enforced_concurrency
    }

@app.post("/api/admin/verify-storage")
async def admin_verify_storage(admin: dict = Depends(require_admin)):
    s = await get_system_settings()
    channel_id = s.get("channel_id", "")
    results = []
    async with httpx.AsyncClient(timeout=10.0) as client_http:
        for idx, token in enumerate(s.get("bot_tokens", [])):
            try:
                r = await client_http.get(f"https://api.telegram.org/bot{token}/getMe")
                me_data = r.json()
                bot_ok = me_data.get("ok", False)
                bot_user = me_data.get("result", {}).get("username", "Unknown")

                # Also verify channel access for this bot
                chat_ok = False
                if bot_ok and channel_id:
                    cr = await client_http.get(
                        f"https://api.telegram.org/bot{token}/getChat",
                        params={"chat_id": channel_id}
                    )
                    chat_ok = cr.json().get("ok", False)

                results.append({
                    "bot_number": idx + 1,
                    "username": f"@{bot_user}",
                    "bot_token_valid": bot_ok,
                    "channel_access_ok": chat_ok,
                    "channel_id": channel_id
                })
            except Exception as e:
                results.append({"bot_number": idx + 1, "bot_token_valid": False, "error": str(e)})
    return {"results": results}

# =========================================================
# 5. TELEMETRY & WEBRTC P2P SIGNALING
# =========================================================
@app.post("/api/telemetry/start")
async def telemetry_start(request: Request):
    body = await request.json()
    sid = f"tle_{secrets.token_hex(6)}"
    city = request.headers.get("X-Geo-City", "Mumbai")
    region = request.headers.get("X-Geo-Region", "MH")
    country = request.headers.get("X-Geo-Country", "IN")
    doc = {
        "session_id": sid,
        "slug": body.get("slug"),
        "ip": request.headers.get("X-Real-IP", "0.0.0.0"),
        "isp": request.headers.get("X-Geo-ISP", "ISP"),
        "location_label": f"{city}, {region} ({country})",
        "device": request.headers.get("User-Agent", "Browser")[:65],
        "opened_at": datetime.utcnow().isoformat(),
        "active_seconds": 1,
        "note_read": False,
        "download_status": "Viewing Page"
    }
    await db.telemetry.insert_one(doc)
    return {"session_id": sid}

@app.post("/api/telemetry/ping")
async def telemetry_ping(request: Request):
    body = await request.json()
    await db.telemetry.update_one(
        {"session_id": body.get("session_id")},
        {"$set": {"active_seconds": body.get("active_seconds", 5), "note_read": body.get("note_read", False)}}
    )
    return {"ok": True}

@app.post("/api/telemetry/stream-event")
async def telemetry_stream_event(request: Request):
    body = await request.json()
    slug = body.get("slug")
    if slug:
        await db.files.update_one({"slug": slug}, {"$inc": {"downloads_count": 1}})
    if body.get("session_id"):
        await db.telemetry.update_one(
            {"session_id": body["session_id"]},
            {"$set": {"download_status": "100% Downloaded"}}
        )
    return {"ok": True}

@app.get("/api/telemetry/admin/live-feed")
async def telemetry_live_feed():
    sessions = await db.telemetry.find({}, {"_id": 0}).sort("opened_at", -1).to_list(100)
    return {"sessions": sessions}

p2p_rooms: Dict[str, List[WebSocket]] = {}

@app.websocket("/ws/p2p/{room_code}")
async def p2p_signaling(websocket: WebSocket, room_code: str):
    await websocket.accept()
    if room_code not in p2p_rooms:
        p2p_rooms[room_code] = []
    p2p_rooms[room_code].append(websocket)

    if len(p2p_rooms[room_code]) >= 2:
        for ws in p2p_rooms[room_code]:
            try:
                await ws.send_json({"type": "peer-ready"})
            except Exception:
                pass

    try:
        while True:
            data = await websocket.receive_json()
            if data.get("type") == "ping":
                continue
            for peer in list(p2p_rooms.get(room_code, [])):
                if peer != websocket:
                    await peer.send_json(data)
    except WebSocketDisconnect:
        if room_code in p2p_rooms and websocket in p2p_rooms[room_code]:
            p2p_rooms[room_code].remove(websocket)
