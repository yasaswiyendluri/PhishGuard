import { riskBadgeClass, riskLabel } from "../utils/risk"

function RiskBadge({ level, className = "" }) {
  return (
    <span
      className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold border ${riskBadgeClass(level)} ${className}`}
    >
      {riskLabel(level)}
    </span>
  )
}

export default RiskBadge
