export default function InvestigationRun({ trace }) {
  const v = trace.verification || {}
  return (
    <section className="panel">
      <h2>Self-verification</h2>
      <p className="verdict-line">
        Draft verdict: <b>{trace.draft_verdict}</b> (score {trace.score}) → Final verdict: <b>{trace.verdict}</b>.
        Revised by verifier: <b>{v.revised ? 'Yes' : 'No'}</b>.
      </p>
      {(v.reasons || []).map((r, i) => <p key={i} className="verdict-line">{r}</p>)}
      <p className="verdict-line">
        Supporting edges — malicious: <b>{v.malicious_supporting}</b>, benign: <b>{v.benign_supporting}</b>.
        Rule: MALICIOUS needs at least 3 malicious-supporting edges, or the verifier revises it to INSUFFICIENT_EVIDENCE.
      </p>
      <h3>Uncertainty and abstention</h3>
      {trace.missing_evidence && trace.missing_evidence.length > 0 ? (
        <p className="missing">Missing evidence: {trace.missing_evidence.join('; ')}</p>
      ) : (
        <p>Missing evidence: none — the score ({trace.score}) is outside the abstention band (1.0 to 3.0), so the agent gave a firm verdict.</p>
      )}
      <h3>Human-approval gate</h3>
      <p>{trace.approval_status}</p>
    </section>
  )
}
