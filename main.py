import ctypes
import threading
import asyncio
import uvicorn
from collections import deque
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

# --- ctype config ---
lib = ctypes.CDLL('./libnetsentinel.so')

class PacketInfo(ctypes.Structure):
    _fields_ = [
        ("source_ip", ctypes.c_char * 16),
        ("dest_ip", ctypes.c_char * 16),
        ("src_port", ctypes.c_int),
        ("dst_port", ctypes.c_int),
        ("protocol", ctypes.c_int),
        ("size", ctypes.c_int),
        ("is_alert", ctypes.c_int)
    ]

lib.init_sniffer.restype = ctypes.c_int
lib.get_packet.argtypes = [ctypes.POINTER(PacketInfo)]
lib.get_packet.restype = ctypes.c_int

# --- . BUFFER ---
packet_buffer = deque(maxlen=1000)

def recolector_de_paquetes():
    if lib.init_sniffer() < 0:
        print("Error: No se pudo inicializar el sniffer")
        return

    packet = PacketInfo()
    print("Recolección en segundo plano iniciada...")

    while True:
        try:
            result = lib.get_packet(ctypes.byref(packet))
            if result == 0:
                src = packet.source_ip.decode('utf-8')
                dst = packet.dest_ip.decode('utf-8')

                if src != "127.0.0.1" and dst != "127.0.0.1":
                    proto_name = "DESCONOCIDO"
                    if packet.protocol == 1: proto_name = "ICMP"
                    elif packet.protocol == 6: proto_name = "TCP"
                    elif packet.protocol == 17: proto_name = "UDP"

                    data = {
                        "src": src, "sport": packet.src_port,
                        "dst": dst, "dport": packet.dst_port,
                        "protocol": proto_name, "size": packet.size,
                        "alert": packet.is_alert
                    }
                    packet_buffer.append(data)
        except Exception as e:
            print(f"ERROR en recolector: {e}")

# --- . BROADCASTER (new) ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)
        print(f"Cliente conectado. Total: {len(self.active_connections)}")

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            self.active_connections.remove(websocket)
        print(f"Cliente desconectado. Total: {len(self.active_connections)}")

    async def broadcast(self, data: dict):
        async with self._lock:
            targets = list(self.active_connections)  # copia para no iterar mientras se modifica

        dead = []
        for ws in targets:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)  # conexión rota, la marcamos para sacar

        # limpiar conexiones muertas
        if dead:
            async with self._lock:
                for ws in dead:
                    self.active_connections.remove(ws)

manager = ConnectionManager()

# --- async buffer drain ---
async def broadcast_loop():
    while True:
        try:
            packet = packet_buffer.popleft()  #no race condition now heh
            if manager.active_connections:
                await manager.broadcast(packet)
        except IndexError:
            # buffer vacío, esperamos un poco
            await asyncio.sleep(0.01)

# --- 5. SERVIDOR FASTAPI ---
html_dashboard = """
<!DOCTYPE html>
<html>
    <head>
        <title>NetSentinel Live</title>
        <style>
            body { background-color: #1e1e1e; color: #00ff00; font-family: monospace; }
            .alert { color: #ff0000; font-weight: bold; }
        </style>
    </head>
    <body>
        <h2>NetSentinel Live Traffic</h2>
        <ul id="traffic"></ul>
        <script>
            // Bug #4 corregido: URL dinámica en lugar de localhost hardcodeado
            var ws = new WebSocket("ws://" + window.location.host + "/ws");
            ws.onmessage = function(event) {
                var list = document.getElementById('traffic');
                var packet = JSON.parse(event.data);
                var li = document.createElement('li');

                var text = `[${packet.protocol}] ${packet.src}:${packet.sport} -> ${packet.dst}:${packet.dport} (${packet.size} bytes)`;
                if (packet.alert === 1) {
                    li.className = "alert";
                    text = "⚠ ALERTA DDoS: " + text;
                }

                li.textContent = text;
                list.prepend(li);

                if (list.childNodes.length > 20) {
                    list.removeChild(list.lastChild);
                }
            };
        </script>
    </body>
</html>
"""

app = FastAPI(title="NetSentinel API")

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(broadcast_loop())

@app.get("/")
async def root():
    return HTMLResponse(html_dashboard)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # mantenemos el WebSocket vivo esperando mensajes del cliente
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(websocket)

# --- 6. ARRANQUE ---
if __name__ == "__main__":
    hilo = threading.Thread(target=recolector_de_paquetes, daemon=True)
    hilo.start()
    uvicorn.run(app, host="0.0.0.0", port=8000)