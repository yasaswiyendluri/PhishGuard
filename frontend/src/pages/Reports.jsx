import { useEffect, useState } from "react"
import Layout from "../components/Layout"
import RiskBadge from "../components/RiskBadge"
import API from "../services/api"
import { downloadReport, formatTime } from "../utils/risk"

function Reports() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    API.get("/api/history", { params: { limit: 50 } })
      .then((res) => setScans(res.data.scans))
      .finally(() => setLoading(false))
  }, [])

  const counts = scans.reduce(
    (acc, s) => {
      const level = (s.risk_level || "").toUpperCase()
      if (level === "HIGH" || level === "CRITICAL") acc.high++
      else if (level === "MEDIUM") acc.medium++
      else acc.safe++
      return acc
    },
    { high: 0, medium: 0, safe: 0 }
  )

  return (
    <Layout>
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
        {[
          { label: "High / Critical", value: counts.high, color: "text-red-300" },
          { label: "Medium Risk", value: counts.medium, color: "text-amber-300" },
          { label: "Low Risk", value: counts.safe, color: "text-emerald-300" },
        ].map((card) => (
          <div key={card.label} className="panel p-6">
            <p className="text-slate-500 text-xs uppercase tracking-wider mb-2">{card.label}</p>
            <p className={`text-4xl font-bold ${card.color}`}>{card.value}</p>
          </div>
        ))}
      </div>

      {loading ? (
        <p className="text-slate-500">Loading threat reports…</p>
      ) : scans.length === 0 ? (
        <div className="panel p-12 text-center text-slate-400">
          No reports yet. Analyze URLs from the Overview page.
        </div>
      ) : (
        <div className="space-y-4">
          {scans.map((report) => (
            <article key={report.scan_id} className="panel p-6">
              <div className="flex flex-wrap items-start justify-between gap-4 mb-4">
                <h2 className="text-lg font-semibold mono text-slate-200 break-all">{report.url}</h2>
                <div className="flex items-center gap-2 shrink-0">
                  <RiskBadge level={report.risk_level} />
                  <button
                    type="button"
                    onClick={() => downloadReport(report)}
                    className="text-xs px-3 py-1.5 rounded-lg border border-slate-600 text-slate-300 hover:border-cyan-500/50 hover:text-cyan-300"
                  >
                    Download IOC
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-sm mb-4">
                <div>
                  <p className="text-slate-500 text-xs mb-1">Risk score</p>
                  <p className="font-semibold text-white">{report.risk_score}%</p>
                </div>
                <div>
                  <p className="text-slate-500 text-xs mb-1">Verdict</p>
                  <p className="capitalize text-slate-300">{report.prediction}</p>
                </div>
                <div>
                  <p className="text-slate-500 text-xs mb-1">Scanned</p>
                  <p className="text-slate-300">{formatTime(report.timestamp)}</p>
                </div>
                <div>
                  <p className="text-slate-500 text-xs mb-1">Report ID</p>
                  <p className="mono text-xs text-slate-500 truncate">{report.scan_id}</p>
                </div>
              </div>

              <p className="text-sm text-slate-400 leading-relaxed border-t border-slate-800/80 pt-4">
                {report.explanation}
              </p>
            </article>
          ))}
        </div>
      )}
    </Layout>
  )
}

export default Reports
