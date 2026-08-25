export default function AlertsTable({ alerts = [] }) {
  // Aseguramos que alerts sea un array para evitar crasheos del DOM
  const safeAlerts = Array.isArray(alerts) ? alerts : [];

  return (
    <div className="alerts-card">
      <h2>Alertas ({safeAlerts.length})</h2>
      
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Protocolo</th>
              <th>Origen</th>
              <th>Puerto Origen</th>
              <th>Destino</th>
              <th>Puerto Destino</th>
              <th>Tamaño</th>
            </tr>
          </thead>
          <tbody>
            {safeAlerts.length === 0 ? (
              <tr>
                <td colSpan="6" style={{ textAlign: "center", color: "#888", padding: "20px" }}>
                  Sin alertas detectadas
                </td>
              </tr>
            ) : (
              safeAlerts.map((alert, index) => (
                <tr key={index} style={{ color: "#ff4d4d" }}>
                  {/* Mapeamos EXACTAMENTE las claves que manda FastAPI */}
                  <td>{alert.protocol}</td>
                  <td>{alert.source_ip}</td>
                  <td>{alert.src_port}</td>
                  <td>{alert.dest_ip}</td>
                  <td>{alert.dst_port}</td>
                  <td>{alert.size}B</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}