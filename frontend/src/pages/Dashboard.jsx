import { useState, useEffect, useCallback } from "react"
import Layout from "../components/Layout"
import DashboardCards from "../components/DashboardCards"
import ReportsTable from "../components/ReportsTable"
import ScanResultPanel from "../components/ScanResultPanel"
import API from "../services/api"

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
      setScanError(
        typeof detail === "string"
          ? detail
          : "Scan failed. Ensure the backend is running and you are signed in."
      )
    } finally {
      setScanning(false)
    }
  }

  return (
    <Layout>
      {/* Primary action — URL scanner at top */}
      <div className="panel p-6 mb-8 border-cyan-500/20 shadow-[0_0_40px_rgba(34,211,238,0.06)]">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-5">
          <div>
            <h2 className="text-xl font-bold text-slate-100">URL Threat Scanner</h2>
            <p className="text-sm text-slate-500 mt-1">
              XGBoost ML · VirusTotal · URLHaus · WHOIS/DNS · Typosquatting
            </p>
          </div>
          <span className="text-xs text-cyan-400/80 mono shrink-0">POST /api/scan</span>
        </div>

        <div className="flex flex-col md:flex-row gap-3">
          <input
            type="url"
            placeholder="https://suspicious-link.example/login"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleAnalyze()}
            className="input-field flex-1 mono text-sm"
            autoFocus
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

        <ScanResultPanel scan={scanResult} />
      </div>

      <DashboardCards stats={stats} />
      <ReportsTable scans={scans} loading={loading} />
    </Layout>
  )
}

export default Dashboard
