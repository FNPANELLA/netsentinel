import { useEffect, useState } from "react"
import { MapContainer, TileLayer, CircleMarker, Popup } from "react-leaflet"
import "leaflet/dist/leaflet.css"

async function geolocate(ip) {
  try {
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=lat,lon,country,city`)
    return await res.json()
  } catch {
    return null
  }
}

export default function ThreatMap({ alerts }) {
  const [markers, setMarkers] = useState([])

  useEffect(() => {
    if (alerts.length === 0) return
    const latest = alerts[0]
    geolocate(latest.src).then(geo => {
      if (geo && geo.lat) {
        setMarkers(prev => {
          const exists = prev.find(m => m.ip === latest.src)
          if (exists) return prev
          return [...prev.slice(-50), { ip: latest.src, lat: geo.lat, lon: geo.lon, country: geo.country, city: geo.city }]
        })
      }
    })
  }, [alerts])

  return (
    <div className="chart-card">
      <h2>Mapa de amenazas</h2>
      <MapContainer center={[20, 0]} zoom={2} style={{ height: "200px", width: "100%" }}>
        <TileLayer
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          attribution="© OpenStreetMap"
        />
        {markers.map((m, i) => (
          <CircleMarker key={i} center={[m.lat, m.lon]} radius={8} color="#ff0000">
            <Popup>{m.ip}<br />{m.city}, {m.country}</Popup>
          </CircleMarker>
        ))}
      </MapContainer>
    </div>
  )
}