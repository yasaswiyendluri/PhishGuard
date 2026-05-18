import { formatTime } from "../utils/risk"

function StatCard({ title, value, accent, sub }) {
  return (
    <div className="panel p-6">
      <p className="text-slate-500 text-xs font-medium uppercase tracking-wider mb-2">{title}</p>
      <p className={`text-3xl font-bold ${accent}`}>{value}</p>
      {sub && <p className="text-slate-500 text-sm mt-2">{sub}</p>}
    </div>
  )
}

function DashboardCards({ stats }) {
  const total = stats?.total_scans ?? 0
  const threats = stats?.threats_detected ?? 0
  const safe = stats?.safe_urls ?? 0
  const highRisk =
    (stats?.by_risk_level?.HIGH ?? 0) + (stats?.by_risk_level?.CRITICAL ?? 0)

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard title="Total Scans" value={total} accent="text-cyan-300" />
        <StatCard title="Threats Detected" value={threats} accent="text-red-300" />
        <StatCard title="Safe URLs" value={safe} accent="text-emerald-300" />
        <StatCard title="High / Critical" value={highRisk} accent="text-amber-300" />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatCard
          title="System Status"
          value="Operational"
          accent="text-emerald-300"
          sub="ML + CTI pipeline active"
        />
        <StatCard
          title="Active Threat Level"
          value={highRisk > 5 ? "Elevated" : highRisk > 0 ? "Moderate" : "Low"}
          accent={highRisk > 5 ? "text-red-300" : "text-cyan-300"}
          sub="Based on recent scan profile"
        />
        <StatCard
          title="Last Scan"
          value={formatTime(stats?.last_scan)}
          accent="text-slate-200"
          sub="Most recent analysis"
        />
      </div>
    </div>
  )
}

export default DashboardCards
