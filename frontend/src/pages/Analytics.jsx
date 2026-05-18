import { useEffect, useState } from "react"
import Layout from "../components/Layout"
import RiskChart from "../components/RiskChart"
import API from "../services/api"

function Analytics() {
  const [stats, setStats] = useState(null)

  useEffect(() => {
    API.get("/api/stats").then((res) => setStats(res.data))
  }, [])

  return (
    <Layout>
      <p className="text-slate-400 text-sm mb-8 max-w-2xl">
        Visualize your scan portfolio — risk distribution and severity breakdown from live MongoDB history.
      </p>
      <RiskChart byLevel={stats?.by_risk_level} />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-8">
        <div className="panel p-6">
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Pipeline Components</h3>
          <ul className="space-y-3 text-sm text-slate-400">
            {[
              "XGBoost ML classifier (≥95% target accuracy)",
              "VirusTotal & URLHaus live CTI",
              "Passive DNS / WHOIS forensics",
              "Typosquatting & URL deobfuscation",
            ].map((item) => (
              <li key={item} className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-cyan-400" />
                {item}
              </li>
            ))}
          </ul>
        </div>
        <div className="panel p-6">
          <h3 className="text-sm font-semibold text-slate-300 mb-4">Session Summary</h3>
          <dl className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <dt className="text-slate-500 text-xs">Total scans</dt>
              <dd className="text-2xl font-bold text-cyan-300 mt-1">{stats?.total_scans ?? 0}</dd>
            </div>
            <div>
              <dt className="text-slate-500 text-xs">Phishing detected</dt>
              <dd className="text-2xl font-bold text-red-300 mt-1">{stats?.threats_detected ?? 0}</dd>
            </div>
            <div>
              <dt className="text-slate-500 text-xs">Safe verdicts</dt>
              <dd className="text-2xl font-bold text-emerald-300 mt-1">{stats?.safe_urls ?? 0}</dd>
            </div>
            <div>
              <dt className="text-slate-500 text-xs">Detection rate</dt>
              <dd className="text-2xl font-bold text-amber-300 mt-1">
                {stats?.total_scans
                  ? `${Math.round((stats.threats_detected / stats.total_scans) * 100)}%`
                  : "—"}
              </dd>
            </div>
          </dl>
        </div>
      </div>
    </Layout>
  )
}

export default Analytics
