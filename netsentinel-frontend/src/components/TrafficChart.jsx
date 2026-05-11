import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts"

export default function TrafficChart({ packets }) {
  // agrupa paquetes por segundo
  const data = packets.reduce((acc, p) => {
    const sec = Math.floor(p.ts / 1000)
    const existing = acc.find(d => d.sec === sec)
    if (existing) {
      existing.count++
      existing[p.protocol] = (existing[p.protocol] || 0) + 1
    } else {
      acc.push({ sec, count: 1, [p.protocol]: 1 })
    }
    return acc
  }, []).slice(-30)

  return (
    <div className="chart-card">
      <h2>Tráfico en tiempo real</h2>
      <ResponsiveContainer width="100%" height={200}>
        <LineChart data={data}>
          <XAxis dataKey="sec" hide />
          <YAxis />
          <Tooltip />
          <Line type="monotone" dataKey="TCP" stroke="#00ff00" dot={false} />
          <Line type="monotone" dataKey="UDP" stroke="#00aaff" dot={false} />
          <Line type="monotone" dataKey="ICMP" stroke="#ffaa00" dot={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}