import RiskBadge from "./RiskBadge"
import { formatTime, mlDisplay } from "../utils/risk"

function ReportsTable({ scans = [], loading }) {
  if (loading) {
    return (
      <div className="panel p-8 mt-8 text-center text-slate-500">
        Loading scan history…
      </div>
    )
  }

  if (!scans.length) {
    return (
      <div className="panel p-8 mt-8 text-center">
        <p className="text-slate-400">No scans yet. Run your first URL analysis above.</p>
      </div>
    )
  }

  return (
    <div className="panel p-6 mt-8">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-lg font-semibold text-slate-100">Recent Scan History</h2>
        <span className="text-xs text-slate-500 uppercase tracking-wider">{scans.length} records</span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-slate-800 text-slate-500 text-xs uppercase tracking-wider">
              <th className="pb-3 pr-4 font-medium">URL</th>
              <th className="pb-3 pr-4 font-medium">Risk</th>
              <th className="pb-3 pr-4 font-medium">ML Score</th>
              <th className="pb-3 pr-4 font-medium">Composite</th>
              <th className="pb-3 pr-4 font-medium">Verdict</th>
              <th className="pb-3 font-medium">When</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((scan) => (
              <tr key={scan.scan_id} className="border-b border-slate-800/60 hover:bg-slate-800/20">
                <td className="py-4 pr-4 max-w-xs truncate mono text-slate-300" title={scan.url}>
                  {scan.url}
                </td>
                <td className="py-4 pr-4">
                  <RiskBadge level={scan.risk_level} />
                </td>
                <td className="py-4 pr-4 text-cyan-300 font-medium">{mlDisplay(scan)}</td>
                <td className="py-4 pr-4 text-slate-300">{scan.risk_score}%</td>
                <td className="py-4 pr-4 capitalize text-slate-400">{scan.prediction}</td>
                <td className="py-4 text-slate-500">{formatTime(scan.timestamp)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

export default ReportsTable
