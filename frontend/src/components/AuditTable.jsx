export default function AuditTable({ trace }) {
  const rows = (trace.steps || []).map((s, i) => ({
    id: i + 1,
    step: s.split(':')[0],
    detail: s,
  }))
  return (
    <section className="panel">
      <h2>Audit trail — this run</h2>
      <p className="footer" style={{ marginTop: 0 }}>
        Every step is also written to SQLite (<code>sentinel_x.db</code>, tables <code>audit_events</code> and <code>traces</code>)
        and to <code>reports/trace_{trace.trace_id}.json</code>. At the evaluation run the database held 21 traces and 229 audit events.
      </p>
      <table className="audit">
        <thead><tr><th>#</th><th>Step</th><th>Detail</th><th>Verdict</th></tr></thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id}><td>{r.id}</td><td>{r.step}</td><td>{r.detail}</td><td>{trace.verdict}</td></tr>
          ))}
        </tbody>
      </table>
    </section>
  )
}
