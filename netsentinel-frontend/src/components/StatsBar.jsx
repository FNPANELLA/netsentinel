export default function StatsBar({ stats }) {
  return (
    <div className="stats-bar">
      <div className="stat">
        <span className="stat-label">Total</span>
        <span className="stat-value">{stats.total}</span>
      </div>
      <div className="stat">
        <span className="stat-label">TCP</span>
        <span className="stat-value tcp">{stats.tcp}</span>
      </div>
      <div className="stat">
        <span className="stat-label">UDP</span>
        <span className="stat-value udp">{stats.udp}</span>
      </div>
      <div className="stat">
        <span className="stat-label">ICMP</span>
        <span className="stat-value icmp">{stats.icmp}</span>
      </div>
      <div className="stat">
        <span className="stat-label">Alertas</span>
        <span className="stat-value alert">{stats.alerts}</span>
      </div>
    </div>
  )
}