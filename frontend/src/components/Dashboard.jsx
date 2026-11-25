import InvestigationRun from './InvestigationRun.jsx'
import EvidenceGraph from './EvidenceGraph.jsx'
import TraceTimeline from './TraceTimeline.jsx'
import MetricsCards from './MetricsCards.jsx'
import AuditTable from './AuditTable.jsx'
import ReportView from './ReportView.jsx'

export default function Dashboard({ goal, setGoal, trace, evaluation, source, running, notice, onRun, onDemo }) {
  const metrics = evaluation && evaluation.metrics ? evaluation.metrics : null
  return (
    <div>
      <header className="topbar">
        <h1>SENTINEL<span>-X</span></h1>
        <span className="tagline">Evidence-driven autonomous cyber incident investigation</span>
        <span className="mode">{trace ? `Mode: ${trace.mode} — ${source === 'backend' ? 'live backend' : 'bundled sample data'}` : 'Loading…'}</span>
      </header>
      <main className="wrap">
        <div className="goalbar">
          <input
            value={goal}
            onChange={(e) => setGoal(e.target.value)}
            placeholder="Investigation goal, e.g. Investigate suspicious login activity. IP: 192.0.2.45, Failed logins: 35, Successful login: 1, Time: 02:30 AM, Device: Unknown"
            aria-label="Investigation goal"
          />
          <button onClick={onRun} disabled={running}>{running ? 'Investigating…' : 'Run Investigation'}</button>
          <button className="secondary" onClick={onDemo} disabled={running}>Demo (192.0.2.45)</button>
        </div>
        {notice && <div className="notice">{notice}</div>}
        {!trace && <div className="loading">Loading the demo trace…</div>}
        {trace && (
          <>
            <MetricsCards trace={trace} />
            <div className="grid2">
              <TraceTimeline steps={trace.steps || []} />
              <EvidenceGraph graph={trace.graph} />
            </div>
            <InvestigationRun trace={trace} />
            <ReportView trace={trace} />
            <AuditTable trace={trace} />
          </>
        )}
        {metrics && (
          <section className="panel">
            <h2>Evaluation — 20 synthetic traces (offline evidence-graph mode)</h2>
            <div className="eval-grid">
              <div>Precision<b>{metrics.precision}</b></div>
              <div>Recall<b>{metrics.recall}</b></div>
              <div>F1 score<b>{metrics.f1_score}</b></div>
              <div>False positive rate<b>{metrics.false_positive_rate}</b></div>
              <div>Completion rate<b>{metrics.investigation_completion_rate}</b></div>
              <div>Avg tool calls<b>{metrics.avg_tool_calls}</b></div>
              <div>Avg time (s)<b>{metrics.avg_execution_time_seconds}</b></div>
              <div>TP / FP / FN / TN<b>{metrics.true_positives} / {metrics.false_positives} / {metrics.false_negatives} / {metrics.true_negatives}</b></div>
            </div>
            <p className="footer">LLM not exercised in this evaluation; a live Gemini run is pending a free key. Full per-trace analysis is in docs/submission/monitoring_report.md.</p>
          </section>
        )}
        <p className="footer">
          SENTINEL-X by Mohit Kumar, B.Tech CSE (final year), Amity University Rajasthan. Synthetic data only — TEST-NET IPs
          (192.0.2.x, 198.51.100.x, 203.0.113.x), no real users. No dangerous action is ever executed without human approval.
          Backend: POST http://localhost:8000/investigate — if it is not running, this dashboard falls back to the bundled sample trace.
        </p>
      </main>
    </div>
  )
}
