import { useState, useEffect } from "react"
import TrafficChart from "./components/TrafficChart"
import AlertsTable from "./components/AlertsTable"
import ThreatMap from "./components/ThreatMap"
import StatsBar from "./components/StatsBar"
import "./App.css"

const WS_URL = "ws://localhost:8000/ws"

export default function App() {
  const [packets, setPackets] = useState([])
  const [alerts, setAlerts] = useState([])
  const [stats, setStats] = useState({ total: 0, tcp: 0, udp: 0, icmp: 0, alerts: 0 })

  useEffect(() => {
    const ws = new WebSocket(WS_URL)

    ws.onmessage = (event) => {
      const packet = JSON.parse(event.data)

      setPackets(prev => [...prev.slice(-60), { ...packet, ts: Date.now() }])

      if (packet.alert === 1) {
        setAlerts(prev => [packet, ...prev.slice(0, 99)])
      }

      setStats(prev => ({
        total: prev.total + 1,
        tcp: prev.tcp + (packet.protocol === "TCP" ? 1 : 0),
        udp: prev.udp + (packet.protocol === "UDP" ? 1 : 0),
        icmp: prev.icmp + (packet.protocol === "ICMP" ? 1 : 0),
        alerts: prev.alerts + (packet.alert === 1 ? 1 : 0)
      }))
    }

    ws.onerror = (e) => console.error("WS error", e)

    return () => ws.close()
  }, [])

  return (
    <div className="dashboard">
      <h1>🛡 NetSentinel</h1>
      <StatsBar stats={stats} />
      <div className="grid">
        <TrafficChart packets={packets} />
        <ThreatMap alerts={alerts} />
      </div>
      <AlertsTable alerts={alerts} />
    </div>
  )
}