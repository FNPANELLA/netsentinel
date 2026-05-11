export default function AlertsTable({ alerts }) {
  if (alerts.length === 0) return (
    <div className="table-card">
      <h2>Alertas</h2>
      <p className="no-alerts">Sin alertas detectadas</p>
    </div>
  )

  return (
    <div className="table-card">
      <h2>Alertas ({alerts.length})</h2>
      <table>
        <thead>
          <tr>
            <th>Protocolo</th>
            <th>Origen</th>
            <th>Puerto</th>
            <th>Destino</th>
            <th>Tamaño</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((a, i) => (
            <tr key={i} className="alert-row">
              <td>{a.protocol}</td>
              <td>{a.src}</td>
              <td>{a.sport}</td>
              <td>{a.dst}</td>
              <td>{a.size}B</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}