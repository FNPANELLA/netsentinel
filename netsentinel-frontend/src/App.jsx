import { useState, useEffect } from "react"
import TrafficChart from "./components/TrafficChart"
import AlertsTable from "./components/AlertsTable"
import ThreatMap from "./components/ThreatMap"
import StatsBar from "./components/StatsBar"
import "./App.css"

const WS_URL = "ws://localhost:8000/ws"

export default function App() {
  // Mantenemos tus estados originales
  const [packets, setPackets] = useState([]) 
  const [alerts, setAlerts] = useState([])
  const [stats, setStats] = useState({ total: 0, tcp: 0, udp: 0, icmp: 0, alerts: 0 })

  useEffect(() => {
    const ws = new WebSocket(WS_URL)

    ws.onmessage = (event) => {
      // El backend ahora manda un array de paquetes cada 0.5s
      const batch = JSON.parse(event.data)
      if (!Array.isArray(batch) || batch.length === 0) return;

      let newTotal = 0, newTcp = 0, newUdp = 0, newIcmp = 0, newAlertsCount = 0;
      const newAlertsList = [];

      // Procesamos el lote entero en memoria (rapidísimo)
      batch.forEach(packet => {
        newTotal++;
        if (packet.protocol === "TCP") newTcp++;
        else if (packet.protocol === "UDP") newUdp++;
        else if (packet.protocol === "ICMP") newIcmp++;
        
        // Atento acá: el backend de Python ahora manda 'is_alert' como booleano
        if (packet.is_alert) { 
          newAlertsCount++;
          newAlertsList.push(packet);
        }
      });

      // 1. Actualizamos la barra superior
      setStats(prev => ({
        total: prev.total + newTotal,
        tcp: prev.tcp + newTcp,
        udp: prev.udp + newUdp,
        icmp: prev.icmp + newIcmp,
        alerts: prev.alerts + newAlertsCount
      }));

      // 2. Colapsamos el tráfico de este medio segundo para el gráfico (O(1) visual)
      const timestamp = new Date().toLocaleTimeString([], { hour12: false, second: '2-digit', minute: '2-digit' });
      
      setPackets(prev => {
        const newData = [...prev, { sec: timestamp, TCP: newTcp, UDP: newUdp, ICMP: newIcmp }];
        return newData.slice(-40); // Mantenemos el buffer limpio
      });

      // 3. Agregamos las alertas a la tabla
      if (newAlertsList.length > 0) {
        setAlerts(prev => [...newAlertsList, ...prev].slice(0, 100));
      }
    }

    ws.onerror = (e) => console.error("WS error", e)

    return () => ws.close()
  }, [])

  return (
    <div className="dashboard">
      <h1>🛡 NetSentinel</h1>
      <StatsBar stats={stats} />
      {/* Volvemos a tu grid original para arreglar el layout */}
      <div className="grid">
        {/* Le pasamos 'data={packets}' si usaste el TrafficChart optimizado que te pasé antes */}
        <TrafficChart data={packets} /> 
        <ThreatMap alerts={alerts} />
      </div>
      <AlertsTable alerts={alerts} />
    </div>
  )
}