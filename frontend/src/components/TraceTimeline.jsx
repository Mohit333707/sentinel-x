export default function TraceTimeline({ steps }) {
  return (
    <section className="panel">
      <h2>Investigation steps</h2>
      <ol className="timeline">
        {steps.map((s, i) => (
          <li key={i}><span className="step-no">Step {i + 1}</span>{s}</li>
        ))}
      </ol>
    </section>
  )
}
