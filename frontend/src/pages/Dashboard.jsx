import { useState, useEffect, useCallback } from "react"
import Layout from "../components/Layout"
import DashboardCards from "../components/DashboardCards"
import ReportsTable from "../components/ReportsTable"
import RiskBadge from "../components/RiskBadge"
import API from "../services/api"
import { downloadReport } from "../utils/risk"

function Dashboard() {
  const [url, setUrl] = useState("")
  const [scanning, setScanning] = useState(false)
  const [scanError, setScanError] = useState("")
  const [scanResult, setScanResult] = useState(null)
  const [scans, setScans] = useState([])
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(true)

  const refresh = useCallback(async () => {
    try {
      const [historyRes, statsRes] = await Promise.all([
        API.get("/api/history", { params: { limit: 10 } }),
        API.get("/api/stats"),
      ])
      setScans(historyRes.data.scans)
      setStats(statsRes.data)
    } catch {
      /* handled by interceptor */
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    refresh()
  }, [refresh])

  const handleAnalyze = async () => {
    if (!url.trim()) return
    setScanning(true)
    setScanError("")
    setScanResult(null)

    try {
      const { data } = await API.post("/api/scan", { url: url.trim() })
      setScanResult(data)
      setUrl("")
      await refresh()
    } catch (err) {
      const detail = err.response?.data?.detail
      setScanError(typeof detail === "string" ? detail : "Scan failed. Is the backend running?")
    } finally {
      setScanning(false)
    }
  }

  return (
    <Layout>
      <DashboardCards stats={stats} />

      <div className="panel p-6 mt-8">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-5">
          <div>
            <h2 className="text-lg font-semibold text-slate-100">URL Threat Scanner</h2>
            <p className="text-sm text-slate-500 mt-1">
              ML inference + VirusTotal, URLHaus, WHOIS/DNS & typosquatting
            </p>
          </div>
          <span className="text-xs text-cyan-400/80 mono">POST /api/scan</span>
        </div>

        <div className="flex flex-col md:flex-row gap-3">
          <input
            type="url"
            placeholder="https://suspicious-link.example/login"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleAnalyze()}
            className="input-field flex-1 mono text-sm"
          />
          <button
            type="button"
            onClick={handleAnalyze}
            disabled={scanning || !url.trim()}
            className="btn-primary px-8 shrink-0"
          >
            {scanning ? "Analyzing…" : "Analyze URL"}
          </button>
        </div>

        {scanError && (
          <p className="mt-4 text-sm text-red-300 bg-red-500/10 border border-red-500/20 rounded-lg px-4 py-3">
            {scanError}
          </p>
        )}

        {scanResult && (
          <div className="mt-6 p-5 rounded-xl bg-slate-900/50 border border-slate-700/60">
            <div className="flex flex-wrap items-start justify-between gap-4 mb-4">
              <div>
                <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Analysis complete</p>
                <p className="mono text-sm text-cyan-200 break-all">{scanResult.url}</p>
              </div>
              <div className="flex items-center gap-2">
                <RiskBadge level={scanResult.risk_level} />
                <button
                  type="button"
                  onClick={() => downloadReport(scanResult)}
                  className="text-xs px-3 py-1.5 rounded-lg border border-slate-600 text-slate-300 hover:border-cyan-500/50 hover:text-cyan-300 transition-colors"
                >
                  Export IOC
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-sm">
              <div>
                <p className="text-slate-500 text-xs mb-1">Risk score</p>
                <p className="text-xl font-bold text-white">{scanResult.risk_score}%</p>
              </div>
              <div>
                <p className="text-slate-500 text-xs mb-1">Verdict</p>
                <p className="text-lg font-semibold capitalize text-slate-200">{scanResult.prediction}</p>
              </div>
              <div>
                <p className="text-slate-500 text-xs mb-1">Scan ID</p>
                <p className="mono text-xs text-slate-400 truncate">{scanResult.scan_id}</p>
              </div>
            </div>

            <p className="mt-4 text-sm text-slate-400 leading-relaxed">
              <span className="text-slate-500">Analysis: </span>
              {scanResult.explanation}
            </p>
          </div>
        )}
      </div>

      <ReportsTable scans={scans} loading={loading} />
    </Layout>
  )
}

export default Dashboard
