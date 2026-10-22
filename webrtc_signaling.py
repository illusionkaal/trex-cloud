from typing import Dict, List
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

webrtc_router = APIRouter()

# Memory map: { "842910": [websocket_sender, websocket_receiver] }
p2p_rooms: Dict[str, List[WebSocket]] = {}

@webrtc_router.websocket("/ws/p2p/{room_code}")
async def p2p_signaling_endpoint(websocket: WebSocket, room_code: str):
    await websocket.accept()
    clean_code = room_code.replace("-", "").strip()

    if clean_code not in p2p_rooms:
        p2p_rooms[clean_code] = []

    # Ek room me max 2 peers (Sender + Receiver)
    if len(p2p_rooms[clean_code]) >= 2:
        await websocket.send_json({"type": "error", "message": "Room is full"})
        await websocket.close()
        return

    p2p_rooms[clean_code].append(websocket)
    peer_index = len(p2p_rooms[clean_code])

    # Agar 2nd user join hua hai, to 1st user (Sender) ko batao ki WebRTC Offer bheje
    if peer_index == 2:
        for peer in p2p_rooms[clean_code]:
            await peer.send_json({"type": "peer-ready", "peers_count": 2})

    try:
        while True:
            data = await websocket.receive_json()
            # SDP Offer, Answer, aur ICE Candidates dusre peer ko forward karo
            for peer in p2p_rooms.get(clean_code, []):
                if peer != websocket:
                    await peer.send_json(data)
    except WebSocketDisconnect:
        if clean_code in p2p_rooms and websocket in p2p_rooms[clean_code]:
            p2p_rooms[clean_code].remove(websocket)
            for peer in p2p_rooms[clean_code]:
                await peer.send_json({"type": "peer-left"})
            if not p2p_rooms[clean_code]:
                del p2p_rooms[clean_code]