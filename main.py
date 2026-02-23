import ctypes 
import os 
import time

class PacketInfo(ctypes.Structure):
    _fields_ = [
        ("source_ip", ctypes.c_char *16),
        ("dest_ip", ctypes.c_char *16),
        ("src_port", ctypes.c_int),
        ("dst_port", ctypes.c_int),
        ("protocol", ctypes.c_int),
        ("size", ctypes.c_int)
    ]
    
lib_path = os.path.abspath("./libnetsentinel.so")
lib = ctypes.CDLL(lib_path)

lib.init_sniffer.restype = ctypes.c_int
lib.get_packet.argtypes = [ctypes.POINTER(PacketInfo)]
lib.get_packet.restype = ctypes.c_int

def start_engine():
    print(" NETSENTINEL ")
    if lib.init_sniffer() != 0:
        print("Error, no se pudo abrir el socket!, estas en root??")
        return
    
    print("... escuchando el trafico!")
    packet = PacketInfo()
    
    try: 
        while True:    
            if lib.get_packet(ctypes.byref(packet)) == 0:
                
                # Decodificamos los bytes a strings de Python
                src = packet.source_ip.decode('utf-8')
                dst = packet.dest_ip.decode('utf-8')
                size = packet.size
                sport = packet.src_port
                dport = packet.dst_port
                
                if src != "127.0.0.1" and dst != "127.0.0.1":
                    print(f"[ALERTA] Trafico externo: {src}:{sport} -> {dst}:{dport} ({size} bytes)")
            
    except KeyboardInterrupt:
        print("deteniendo el motor...")
if __name__ == "__main__":
    start_engine()
    