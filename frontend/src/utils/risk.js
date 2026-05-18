export function riskLabel(level) {
  if (!level) return "Unknown"
  const map = {
    LOW: "Low",
    MEDIUM: "Medium",
    HIGH: "High",
    CRITICAL: "Critical",
  }
  return map[level.toUpperCase()] || level
}

export function riskBadgeClass(level) {
  const key = (level || "").toUpperCase()
  if (key === "CRITICAL" || key === "HIGH") {
    return "bg-red-500/15 text-red-300 border-red-500/30"
  }
  if (key === "MEDIUM") {
    return "bg-amber-500/15 text-amber-300 border-amber-500/30"
  }
  return "bg-emerald-500/15 text-emerald-300 border-emerald-500/30"
}

export function formatTime(ts) {
  if (!ts) return "—"
  const d = new Date(ts)
  const diff = Date.now() - d.getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return "Just now"
  if (mins < 60) return `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`
  return d.toLocaleDateString()
}

export function downloadReport(scan) {
  const blob = new Blob([JSON.stringify(scan, null, 2)], { type: "application/json" })
  const url = URL.createObjectURL(blob)
  const a = document.createElement("a")
  a.href = url
  a.download = `phishguard-ioc-${scan.scan_id}.json`
  a.click()
  URL.revokeObjectURL(url)
}
