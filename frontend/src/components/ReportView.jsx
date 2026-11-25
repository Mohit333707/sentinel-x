export default function ReportView({ trace }) {
  const lines = [
    `Trace ID: ${trace.trace_id}`,
    `Mode: ${trace.mode} (offline evidence-graph mode — NOT a live Gemini run)`,
    `Goal: ${trace.goal}`,
    `Verdict: ${trace.verdict} | Risk: ${trace.risk} | Evidence score: ${trace.score}`,
    `Draft verdict: ${trace.draft_verdict} | Verification revised: ${trace.verification ? String(trace.verification.revised) : '—'}`,
    `Tool calls: ${trace.tool_calls} | Execution time: ${trace.execution_time_seconds}s`,
    `Report file: ${trace.report_path || ''}`,
    '',
    'Recommendation: Block the IP, force password reset, review the account — only after human approval.',
    '',
    trace.approval_status || '',
  ]
  return (
    <section className="panel">
      <h2>Final report</h2>
      <pre className="report">{lines.join('\n')}</pre>
    </section>
  )
}
