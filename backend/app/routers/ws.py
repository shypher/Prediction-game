from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from ..realtime import hub

router = APIRouter()

@router.websocket("/ws/notify")
async def ws_notify(websocket: WebSocket):
    user_id = websocket.headers.get("X-User-Id")
    if not user_id:
        await websocket.close(code=4401)  
        return

    await hub.connect(websocket, user_id)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        hub.disconnect(websocket, user_id)