from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from ..realtime import hub

router = APIRouter()

@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    user_id = websocket.headers.get("X-User-Id")
    if not user_id:
        await websocket.close(code=4001)
        return
    
    try:
        user_id = int(user_id)  
        await hub.connect(websocket, str(user_id))
        try:
            while True:
                data = await websocket.receive_text()
                # ... existing code ...
        except WebSocketDisconnect:
            hub.disconnect(websocket, str(user_id)) 
    except ValueError:
        await websocket.close(code=4001)