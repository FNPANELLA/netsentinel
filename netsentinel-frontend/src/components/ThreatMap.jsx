import { useState, useEffect, useRef } from 'react';
import { MapContainer, TileLayer, CircleMarker, Tooltip } from 'react-leaflet';
import 'leaflet/dist/leaflet.css';

export default function ThreatMap({ alerts = [] }) {
  const [markers, setMarkers] = useState([]);
  // El caché en memoria: clave IP, valor [Latitud, Longitud]
  const ipCache = useRef({}); 

  useEffect(() => {
    const fetchGeoData = async () => {
      const safeAlerts = Array.isArray(alerts) ? alerts : [];
      const newMarkers = [];

      for (const alert of safeAlerts) {
        const ip = alert.source_ip;
        if (!ip) continue;

        // 1. Si la IP ya está en caché, la graficamos al instante sin llamar a la API
        if (ipCache.current[ip]) {
          newMarkers.push({ ...alert, coords: ipCache.current[ip] });
          continue;
        }

        // 2. Si es tráfico local (Docker, Loopback, LAN), le asignamos una coordenada fija de prueba
        // (Seteado en Buenos Aires para la telemetría de prueba local)
        if (ip.startsWith("127.") || ip.startsWith("192.168.") || ip.startsWith("172.") || ip.startsWith("10.")) {
          ipCache.current[ip] = [-34.6037, -58.3816];
          newMarkers.push({ ...alert, coords: ipCache.current[ip] });
          continue;
        }

        // 3. Si es una IP pública nueva, la buscamos en ip-api.com
        try {
          const res = await fetch(`http://ip-api.com/json/${ip}`);
          const data = await res.json();
          if (data.status === "success") {
            ipCache.current[ip] = [data.lat, data.lon];
            newMarkers.push({ ...alert, coords: ipCache.current[ip] });
          }
        } catch (err) {
          console.error(`Error geolocalizando la IP ${ip}:`, err);
        }
      }
      
      setMarkers(newMarkers);
    };

    // Solo procesamos si realmente hay alertas
    if (alerts && alerts.length > 0) {
      fetchGeoData();
    }
  }, [alerts]);

  return (
    <div className="map-card" style={{ display: "flex", flexDirection: "column" }}>
      <h2 style={{ marginBottom: "10px" }}>Mapa de amenazas</h2>
      {/* El contenedor debe tener un alto fijo para que Leaflet sepa cómo renderizar */}
      <div style={{ flexGrow: 1, minHeight: "300px", borderRadius: "8px", overflow: "hidden" }}>
        <MapContainer 
          center={[20, 0]} 
          zoom={2} 
          style={{ height: "100%", width: "100%", zIndex: 1 }} 
          scrollWheelZoom={false}
        >
          {/* Basemap oscuro para que resalten las alertas */}
          <TileLayer
            url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
            attribution='&copy; OpenStreetMap &copy; CARTO'
          />
          {markers.map((marker, idx) => (
            <CircleMarker 
              key={idx} 
              center={marker.coords} 
              radius={8}
              fillColor="#ff4d4d"
              color="#ff0000"
              weight={1}
              opacity={0.8}
              fillOpacity={0.6}
            >
              <Tooltip>
                <strong>IP Origen:</strong> {marker.source_ip} <br/>
                <strong>Protocolo:</strong> {marker.protocol} <br/>
                <strong>Puerto:</strong> {marker.src_port} <br/>
                <strong>Tamaño:</strong> {marker.size}B
              </Tooltip>
            </CircleMarker>
          ))}
        </MapContainer>
      </div>
    </div>
  );
}