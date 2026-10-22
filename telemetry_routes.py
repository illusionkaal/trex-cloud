import re
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Request, Header, HTTPException, Depends
from pydantic import BaseModel

# Note: `db`, `get_optional_user`, `require_admin`, aur `WORKER_SHARED_SECRET` 
# aapke Phase 2 ke `main.py` se import honge.

router = APIRouter(prefix="/api/telemetry", tags=["Telemetry"])

# ==========================================
# USER-AGENT PARSER (Lightweight & Dependency-Free)
# ==========================================

def parse_user_agent(ua: str) -> dict:
    ua_lower = ua.lower()
    
    # Detect OS
    if "windows nt 10" in ua_lower or "windows nt 11" in ua_lower:
        os_name = "Windows 10/11"
    elif "android" in ua_lower:
        os_name = "Android"
    elif "iphone" in ua_lower or "ipad" in ua_lower:
        os_name = "iOS / iPadOS"
    elif "mac os x" in ua_lower:
        os_name = "macOS"
    elif "linux" in ua_lower:
        os_name = "Linux"
    else:
        os_name = "Unknown OS"

    # Detect Browser
    if "edg/" in ua_lower:
        browser = "Edge"
    elif "opr/" in ua_lower or "opera" in ua_lower:
        browser = "Opera"
    elif "chrome/" in ua_lower and "safari/" in ua_lower:
        browser = "Chrome"
    elif "firefox/" in ua_lower:
        browser = "Firefox"
    elif "safari/" in ua_lower and "chrome/" not in ua_lower:
        browser = "Safari"
    else:
        browser = "Browser"

    # Detect Device Type
    is_mobile = any(k in ua_lower for k in ["mobile", "android", "iphone", "ipad"])
    device_type = "Mobile" if is_mobile else "Desktop"

    return {
        "os": os_name,
        "browser": browser,
        "device_type": device_type,
        "display": f"{browser} · {os_name} ({device_type})"
    }


# ==========================================
# PYDANTIC SCHEMAS FOR TELEMETRY
# ==========================================

class SessionStartRequest(BaseModel):
    slug: str
    screen_res: Optional[str] = "Unknown"
    referrer: Optional[str] = "Direct"
    timezone: Optional[str] = "Asia/Kolkata"

class SessionHeartbeatRequest(BaseModel):
    session_id: str
    slug: str
    total_seconds: int          # Page khulne se ab tak ka kul samay
    active_seconds: int         # Jab user sach me tab dekh raha tha (focused)
    note_read: bool = False     # Kya Sender Note padha gaya?
    note_dwell_ms: int = 0      # Note par kitni der nazar ruki
    download_clicked: bool = False
    event: Optional[str] = "heartbeat"  # "heartbeat" | "download_click" | "page_close"

class StreamProgressWebhook(BaseModel):
    session_id: Optional[str] = None
    slug: str
    status: str                 # "started" | "completed" | "aborted"
    bytes_sent: int
    total_bytes: int


# ==========================================
# 1. START SESSION (Jab Download Link Open Hota Hai)
# ==========================================

@router.post("/start")
async def start_telemetry_session(
    body: SessionStartRequest,
    request: Request,
    x_geo_city: Optional[str] = Header(None),
    x_geo_country: Optional[str] = Header(None),
    x_geo_region: Optional[str] = Header(None),
    x_geo_isp: Optional[str] = Header(None),
    x_real_ip: Optional[str] = Header(None)
):
    from main import db  # Uses MongoDB instance from Phase 2
    import secrets

    session_id = f" tx_{secrets.token_hex(8)}".strip()
    now = datetime.now(timezone.utc)

    # Extract IP & Geo headers forwarded by our Edge Worker or Cloudflare proxy
    client_ip = (
        x_real_ip
        or request.headers.get("cf-connecting-ip")
        or request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or request.client.host
    )
    city = x_geo_city or request.headers.get("cf-ipcity") or "Mumbai"
    country = x_geo_country or request.headers.get("cf-ipcountry") or "IN"
    region = x_geo_region or request.headers.get("cf-region") or "Maharashtra"
    isp = x_geo_isp or "Broadband Network"

    ua_string = request.headers.get("user-agent", "Unknown")
    ua_info = parse_user_agent(ua_string)

    session_doc = {
        "session_id": session_id,
        "slug": body.slug,
        "ip": client_ip,
        "city": city,
        "region": region,
        "country": country,
        "isp": isp,
        "location_label": f"{city}, {region} ({country})",
        "device": ua_info["display"],
        "device_type": ua_info["device_type"],
        "os": ua_info["os"],
        "browser": ua_info["browser"],
        "screen_res": body.screen_res,
        "referrer": body.referrer or "Direct Link",
        "timezone": body.timezone,
        "opened_at": now,
        "last_ping_at": now,
        "total_seconds": 1,
        "active_seconds": 1,
        "note_read": False,
        "note_dwell_ms": 0,
        "download_status": "Viewing Page",  # Viewing Page -> Downloading -> Completed / Cancelled (64%)
        "download_progress_pct": 0,
        "bytes_transferred": 0,
        "is_live": True
    }

    await db.telemetry_sessions.insert_one(session_doc)
    await db.files.update_one({"slug": body.slug}, {"$inc": {"views_count": 1}})

    return {"session_id": session_id, "opened_at": now.isoformat()}


# ==========================================
# 2. HEARTBEAT & PAGE-CLOSE BEACON (Har 5s me)
# ==========================================

@router.post("/ping")
async def ping_telemetry_session(body: SessionHeartbeatRequest):
    from main import db

    now = datetime.now(timezone.utc)
    update_fields = {
        "last_ping_at": now,
        "total_seconds": max(1, body.total_seconds),
        "active_seconds": max(1, body.active_seconds),
        "is_live": body.event != "page_close"
    }

    if body.note_read:
        update_fields["note_read"] = True
        update_fields["note_dwell_ms"] = body.note_dwell_ms

    if body.download_clicked:
        # Only set to "Download Initiated" if not already Completed
        existing = await db.telemetry_sessions.find_one({"session_id": body.session_id})
        if existing and existing.get("download_status") == "Viewing Page":
            update_fields["download_status"] = "Download Initiated"

    await db.telemetry_sessions.update_one(
        {"session_id": body.session_id},
        {"$set": update_fields}
    )
    return {"ok": True}


# ==========================================
# 3. STREAM COMPLETION WEBHOOK (From Edge Worker)
# ==========================================

@router.post("/stream-event")
async def record_stream_progress(
    body: StreamProgressWebhook,
    x_edge_secret: Optional[str] = Header(None)
):
    """
    Jab Edge Worker file stream karta hai, to wo batata hai ki user ne 
    100% file download ki ya beech me hi cancel kar diya!
    """
    from main import db, WORKER_SHARED_SECRET

    if x_edge_secret != WORKER_SHARED_SECRET:
        raise HTTPException(status_code=403, detail="Unauthorized")

    pct = round((body.bytes_sent / max(1, body.total_bytes)) * 100)
    if body.status == "completed":
        status_label = "Completed (100%)"
        pct = 100
    elif body.status == "started":
        status_label = "Streaming..."
    else:
        status_label = f"Interrupted ({pct}%)"

    if body.session_id:
        await db.telemetry_sessions.update_one(
            {"session_id": body.session_id},
            {"$set": {
                "download_status": status_label,
                "download_progress_pct": pct,
                "bytes_transferred": body.bytes_sent,
                "last_ping_at": datetime.now(timezone.utc)
            }}
        )

    return {"ok": True}


# ==========================================
# 4. ANALYTICS DASHBOARD ENDPOINTS (USER & ADMIN)
# ==========================================

@router.get("/file/{slug}")
async def get_file_analytics(slug: str, user=Depends(lambda: None)):
    """User apni kisi specific file ki har ek open session ki detail dekh sakta hai."""
    from main import db

    cursor = db.telemetry_sessions.find({"slug": slug}, {"_id": 0}).sort("opened_at", -1)
    sessions = await cursor.to_list(length=200)

    # Calculate aggregated insights
    total_views = len(sessions)
    completed_downloads = sum(1 for s in sessions if "Completed" in s.get("download_status", ""))
    avg_duration = round(sum(s.get("active_seconds", 0) for s in sessions) / max(1, total_views))
    note_reads = sum(1 for s in sessions if s.get("note_read"))

    return {
        "slug": slug,
        "summary": {
            "total_views": total_views,
            "completed_downloads": completed_downloads,
            "avg_active_seconds": avg_duration,
            "note_read_count": note_reads
        },
        "sessions": sessions
    }

@router.get("/admin/live-feed")
async def get_admin_global_telemetry():
    """Admin Panel ke Tab 1 me saari files ka combined real-time telemetry feed dikhata hai."""
    from main import db

    now = datetime.now(timezone.utc)
    cursor = db.telemetry_sessions.find({}, {"_id": 0}).sort("opened_at", -1).limit(300)
    sessions = await cursor.to_list(length=300)

    # Agar aakhiri ping 15 second se purana hai, to session ko offline mark karein
    for s in sessions:
        last_ping = s.get("last_ping_at")
        if last_ping:
            if last_ping.tzinfo is None:
                last_ping = last_ping.replace(tzinfo=timezone.utc)
            if (now - last_ping).total_seconds() > 15:
                s["is_live"] = False

    return {"sessions": sessions}