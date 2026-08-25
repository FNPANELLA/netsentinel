import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts"

export default function TrafficChart({ data = [] }) {
  // Nos aseguramos de que siempre haya un array válido para evitar crasheos
  const safeData = Array.isArray(data) ? data : [];

  return (
    <div className="chart-card">
      <h2>Tráfico en tiempo real</h2>
      <ResponsiveContainer width="100%" height={200}>
        <LineChart data={safeData}>
          {/* El eje X ahora lee la clave "sec" que manda App.jsx */}
          <XAxis dataKey="sec" hide />
          <YAxis />
          <Tooltip />
          {/* Apagamos animaciones para que el tiempo real sea instantáneo y no consuma CPU extra */}
          <Line type="monotone" dataKey="TCP" stroke="#00ff00" dot={false} isAnimationActive={false} />
          <Line type="monotone" dataKey="UDP" stroke="#00aaff" dot={false} isAnimationActive={false} />
          <Line type="monotone" dataKey="ICMP" stroke="#ffaa00" dot={false} isAnimationActive={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}