import { useEffect, useState } from 'react'
import Dashboard from './components/Dashboard.jsx'

const DEMO_GOAL =
  'Investigate suspicious login activity. IP: 192.0.2.45, Failed logins: 35, Successful login: 1, Time: 02:30 AM, Device: Unknown'
const API_BASE = 'http://localhost:8000'

export default function App() {
  const [goal, setGoal] = useState(DEMO_GOAL)
  const [trace, setTrace] = useState(null)
  const [evaluation, setEvaluation] = useState(null)
  const [source, setSource] = useState('sample')
  const [running, setRunning] = useState(false)
  const [notice, setNotice] = useState('')

  useEffect(() => {
    fetch('/sample_trace.json')
      .then((r) => r.json())
      .then((d) => { setTrace(d); setSource('sample') })
      .catch(() => setNotice('Could not load the bundled sample trace.'))
    fetch('/evaluation_report.json')
      .then((r) => r.json())
      .then((d) => setEvaluation(d))
      .catch(() => {})
  }, [])

  async function runInvestigation(useDemo) {
    const g = useDemo ? DEMO_GOAL : goal
    if (useDemo) setGoal(DEMO_GOAL)
    setRunning(true)
    setNotice('')
    try {
      const res = await fetch(`${API_BASE}/investigate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ goal: g }),
      })
      if (!res.ok) throw new Error('backend returned ' + res.status)
      const data = await res.json()
      if (data.error) throw new Error(data.error)
      setTrace(data)
      setSource('backend')
      setNotice('Live result from the FastAPI backend at localhost:8000.')
    } catch (e) {
      setSource('sample')
      setNotice(
        'Backend at localhost:8000 is not running (' + e.message + '). Showing the bundled sample trace SX-DBB1B7B7 instead. Start the backend with: uvicorn backend.api:app --port 8000',
      )
      try {
        const r = await fetch('/sample_trace.json')
        setTrace(await r.json())
      } catch (_) {}
    } finally {
      setRunning(false)
    }
  }

  return (
    <Dashboard
      goal={goal}
      setGoal={setGoal}
      trace={trace}
      evaluation={evaluation}
      source={source}
      running={running}
      notice={notice}
      onRun={() => runInvestigation(false)}
      onDemo={() => runInvestigation(true)}
    />
  )
}
