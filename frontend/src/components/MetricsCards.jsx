export default function MetricsCards({ trace }) {
  const verdictClass =
    trace.verdict === 'MALICIOUS' ? 'red' : trace.verdict === 'BENIGN' ? 'green' : 'amber'
  const evidenceCount = trace.graph ? `${trace.graph.nodes} nodes, ${trace.graph.edges} edges` : '—'
  return (
    <div className="cards">
      <div className="card"><div className="label">Verdict</div><div className={`value ${verdictClass}`}>{trace.verdict}</div><div className="sub">Trace {trace.trace_id}</div></div>
      <div className="card"><div className="label">Risk</div><div className={`value ${trace.risk === 'HIGH' ? 'red' : trace.risk === 'LOW' ? 'green' : 'amber'}`}>{trace.risk}</div><div className="sub">Draft: {trace.draft_verdict}</div></div>
      <div className="card"><div className="label">Evidence score</div><div className="value">{trace.score}</div><div className="sub">MALICIOUS ≥ 3.0 · BENIGN ≤ 1.0</div></div>
      <div className="card"><div className="label">Evidence graph</div><div className="value" style={{ fontSize: 20 }}>{evidenceCount}</div><div className="sub">{trace.graph ? `${trace.graph.malicious_supporting_edges} malicious / ${trace.graph.benign_supporting_edges} benign edges` : ''}</div></div>
      <div className="card"><div className="label">Tool calls</div><div className="value">{trace.tool_calls}</div><div className="sub">analyse_logs, check_ip, threat intel, graph</div></div>
      <div className="card"><div className="label">Time</div><div className="value">{trace.execution_time_seconds}s</div><div className="sub">Mode: {trace.mode}</div></div>
    </div>
  )
}
