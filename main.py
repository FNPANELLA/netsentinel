import asyncio
import ctypes
import json
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import asyncpg

# --- ESTRUCTURA CTYPES ---
class PacketInfo(ctypes.Structure):
    _fields_ = [
        ("source_ip", ctypes.c_char * 16),
        ("dest_ip", ctypes.c_char * 16),
        ("src_port", ctypes.c_int),
        ("dst_port", ctypes.c_int),
        ("protocol", ctypes.c_int),
        ("size", ctypes.c_int),
        ("is_alert", ctypes.c_int),
    ]

# Carga de la librería nativa
try:
    sentinel_lib = ctypes.CDLL('./libnetsentinel.so')
    sentinel_lib.init_sniffer.restype = ctypes.c_int
    sentinel_lib.get_packet.argtypes = [ctypes.POINTER(PacketInfo)]
    sentinel_lib.get_packet.restype = ctypes.c_int
    
    if sentinel_lib.init_sniffer() < 0:
        print("ERROR: No se pudo inicializar el socket crudo. ¿Lo corriste con sudo?")
except Exception as e:
    print(f"Error cargando libnetsentinel.so: {e}")

# --- BASE DE DATOS Y ESTADO ---
DB_DSN = "postgres://sentinel:tu_contraseña_aqui@localhost:5432/netsentinel" # Ajustá las credenciales si difieren
pool = None

# --- GESTOR DE WEBSOCKETS ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except Exception:
                pass

manager = ConnectionManager()

# --- FUNCIONES DE BASE DE DATOS ---
async def save_event_batch(batch: list):
    """Guarda un lote entero de paquetes en PostgreSQL de una sola vez."""
    if not pool or not batch:
        return
    
    query = """
        INSERT INTO events (src_ip, dst_ip, src_port, dst_port, protocol, size, is_alert)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
    """
    
    # Preparamos los datos como una lista de tuplas para executemany
    datos = [
        (
            p['source_ip'], p['dest_ip'], p['src_port'], p['dst_port'],
            p['protocol'], p['size'], p['is_alert']
        ) for p in batch
    ]
    
    try:
        async with pool.acquire() as conn:
            await conn.executemany(query, datos)
    except Exception as e:
        print(f"Error en Bulk Insert: {e}")

# --- BUCLE PRINCIPAL DE CAPTURA (BATCHING) ---
def get_protocol_name(proto_num):
    mapping = {6: "TCP", 17: "UDP", 1: "ICMP"}
    return mapping.get(proto_num, str(proto_num))

async def broadcast_loop():
    print("Iniciando motor de captura en segundo plano...")
    info = PacketInfo()
    
    while True:
        batch = []
        loop = asyncio.get_event_loop()
        start_time = loop.time()
        
        
        while loop.time() - start_time < 0.5:
            result = sentinel_lib.get_packet(ctypes.byref(info))
            
            if result == 0:
                packet_dict = {
                    "source_ip": info.source_ip.decode('utf-8'),
                    "dest_ip": info.dest_ip.decode('utf-8'),
                    "src_port": info.src_port,
                    "dst_port": info.dst_port,
                    "protocol": get_protocol_name(info.protocol),
                    "size": info.size,
                    "is_alert": bool(info.is_alert)
                }
                batch.append(packet_dict)
            else:
                
                await asyncio.sleep(0.005) 
                
        
        if batch:
            #
            await manager.broadcast(json.dumps(batch))
            

            alert_batch = [p for p in batch if p['is_alert']]
            await save_event_batch(batch)

# --- CICLO DE VIDA DE FASTAPI ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    # STARTUP
    global pool
    try:
        pool = await asyncpg.create_pool(DB_DSN)
        print("Conectado a PostgreSQL.")
    except Exception as e:
        print(f"Error conectando a Postgres: {e}")
        
    asyncio.create_task(broadcast_loop())
    
    yield
    
    # SHUTDOWN
    if pool:
        await pool.close()
        print("Conexión a PostgreSQL cerrada.")

# --- INICIALIZACIÓN DE LA APP ---
app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Mantenemos viva la conexión
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    # Importante correrlo en host 0.0.0.0
    uvicorn.run(app, host="0.0.0.0", port=8000)