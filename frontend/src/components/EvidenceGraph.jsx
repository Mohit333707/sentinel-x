// Hand-drawn SVG evidence graph. No graph library: the graph is small
// (7 nodes, 7 edges), so fixed positions by node kind are enough.
const POSITIONS = {
  ip: [400, 180],
  user: [110, 60],
  device: [690, 60],
  time: [400, 42],
  country: [400, 330],
  'event:failed': [110, 300],
  'event:success': [690, 300],
}

function positionFor(name) {
  if (name.startsWith('ip:')) return POSITIONS.ip
  if (name.startsWith('user:')) return POSITIONS.user
  if (name.startsWith('device:')) return POSITIONS.device
  if (name.startsWith('time:')) return POSITIONS.time
  if (name.startsWith('country:')) return POSITIONS.country
  if (name.startsWith('event:failed')) return POSITIONS['event:failed']
  if (name.startsWith('event:success')) return POSITIONS['event:success']
  return [400, 180]
}

function shortName(name) {
  return name.length > 22 ? name.slice(0, 21) + '…' : name
}

const EDGE_COLORS = { malicious: '#f87171', benign: '#4ade80', neutral: '#64748b' }

export default function EvidenceGraph({ graph }) {
  if (!graph || !graph.node_list) return <section className="panel"><h2>Evidence graph</h2><p>No graph data.</p></section>
  const nodes = graph.node_list
  const edges = graph.edge_list || []
  return (
    <section className="panel">
      <h2>Evidence graph — {graph.nodes} nodes, {graph.edges} edges</h2>
      <svg className="graph-svg" viewBox="0 0 800 380" role="img" aria-label="Evidence graph">
        {edges.map((e, i) => {
          const [x1, y1] = positionFor(e.from)
          const [x2, y2] = positionFor(e.to)
          const color = EDGE_COLORS[e.supports] || '#64748b'
          return (
            <g key={i}>
              <line x1={x1} y1={y1} x2={x2} y2={y2} stroke={color} strokeWidth="2" />
              <text x={(x1 + x2) / 2} y={(y1 + y2) / 2 - 6} fill={color} fontSize="11" textAnchor="middle">
                {e.relation} ({e.supports})
              </text>
            </g>
          )
        })}
        {nodes.map((n) => {
          const [x, y] = positionFor(n)
          const isIp = n.startsWith('ip:')
          return (
            <g key={n}>
              <circle cx={x} cy={y} r={isIp ? 34 : 28} fill={isIp ? '#1e3a5f' : '#111c33'} stroke="#38bdf8" strokeWidth="2" />
              <text x={x} y={y + 4} fill="#e2e8f0" fontSize="11" textAnchor="middle">{shortName(n)}</text>
            </g>
          )
        })}
      </svg>
      <div className="graph-legend">
        <span><span className="dot" style={{ background: '#f87171' }} />malicious-supporting ({graph.malicious_supporting_edges})</span><br />
        <span><span className="dot" style={{ background: '#4ade80' }} />benign-supporting ({graph.benign_supporting_edges})</span><br />
        <span><span className="dot" style={{ background: '#64748b' }} />neutral</span><br />
        A verdict only stands when the graph backs it — the verifier needs at least 3 malicious-supporting edges for MALICIOUS.
      </div>
    </section>
  )
}
