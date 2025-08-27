from __future__ import annotations
from collections import defaultdict
from typing import Dict, Set, Iterable
import asyncio
from fastapi import WebSocket, WebSocketDisconnect

class Hub:
    def __init__(self) -> None:
        self._conns: Dict[str, Set[WebSocket]] = defaultdict(set)
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket, user_id: str) -> None:
        await ws.accept()
        async with self._lock:
            self._conns[user_id].add(ws)

    def disconnect(self, ws: WebSocket, user_id: str) -> None:
        s = self._conns.get(user_id)
        if not s:
            return
        s.discard(ws)
        if not s:
            self._conns.pop(user_id, None)

    def users(self) -> Iterable[str]:
        return list(self._conns.keys())

    async def send_to_user(self, user_id: str, payload: dict) -> None:
        conns = list(self._conns.get(user_id, []))
        dead: list[WebSocket] = []
        for ws in conns:
            try:
                await ws.send_json(payload)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self._conns[user_id].discard(ws)
                if not self._conns[user_id]:
                    self._conns.pop(user_id, None)

hub = Hub()