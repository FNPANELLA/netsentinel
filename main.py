import ctypes
import threading
import asyncio
import uvicorn
from collections import deque
from fastapi import FastAPI, WebSocket
from fastapi.responses import HTMLResponse

# --- 1. CONFIGURACIÓN DE CTYPES (Igual que antes) ---
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

# --- 2. EL BUFFER EN MEMORIA ---
# Esta lista guarda los paquetes temporalmente
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
# --- 3. EL SERVIDOR FASTAPI ---
app = FastAPI(title="NetSentinel API")

# Un mini dashboard 
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
            var ws = new WebSocket("ws://localhost:8000/ws");
            ws.onmessage = function(event) {
                var list = document.getElementById('traffic');
                var packet = JSON.parse(event.data);
                var li = document.createElement('li');
                
                var text = `[${packet.protocol}] ${packet.src}:${packet.sport} -> ${packet.dst}:${packet.dport} (${packet.size} bytes)`;
                if (packet.alert === 1) {
                    li.className = "alert";
                    text = " ALERTA DDoS: " + text;
                }
                
                li.textContent = text;
                list.prepend(li); // Agrega arriba de todo
                
                // Mantener solo los últimos 20 en pantalla para no trabar el navegador
                if (list.childNodes.length > 20) {
                    list.removeChild(list.lastChild);
                }
            };
        </script>
    </body>
</html>
"""

@app.get("/")
async def root():
    return HTMLResponse(html_dashboard)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            if packet_buffer:
                packet = packet_buffer.popleft()
                await websocket.send_json(packet)
            else:
                await asyncio.sleep(0.01)
    except Exception as e:
        print(f"WebSocket error: {e}")  
# --- 4. ARRANQUE DEL SISTEMA ---
if __name__ == "__main__":
    
    hilo = threading.Thread(target=recolector_de_paquetes, daemon=True)
    hilo.start()
    
    #  servidor web
    uvicorn.run(app, host="0.0.0.0", port=8000)