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

/** Parse API timestamps (naive UTC ISO or with offset) reliably. */
export function parseTimestamp(ts) {
  if (!ts) return null
  if (ts instanceof Date) return ts
  let s = String(ts).trim()
  if (!s) return null
  if (!s.endsWith("Z") && !/[+-]\d{2}:\d{2}$/.test(s)) {
    s = `${s}Z`
  }
  const d = new Date(s)
  return Number.isNaN(d.getTime()) ? null : d
}

export function formatTime(ts) {
  const d = parseTimestamp(ts)
  if (!d) return "—"

  const diff = Date.now() - d.getTime()
  if (diff < 0) return "Just now"

  const secs = Math.floor(diff / 1000)
  if (secs < 60) return "Just now"

  const mins = Math.floor(secs / 60)
  if (mins < 60) return `${mins}m ago`

  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}h ago`

  const days = Math.floor(hrs / 24)
  if (days < 7) return `${days}d ago`

  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  })
}

export function formatExactTime(ts) {
  const d = parseTimestamp(ts)
  if (!d) return "—"
  return d.toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  })
}

export function mlDisplay(scan) {
  if (scan?.ml_ready && scan.ml_confidence != null) {
    return `${scan.ml_confidence}%`
  }
  const ml = scan?.threat_intel?.ml
  if (ml?.ml_ready && ml.ml_confidence != null) {
    return `${ml.ml_confidence}%`
  }
  return "—"
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

export function authErrorMessage(err) {
  if (!err.response) {
    return "Cannot reach the API. Start the backend with: uvicorn app.main:app --reload"
  }
  const detail = err.response.data?.detail
  if (typeof detail === "string") return detail
  if (Array.isArray(detail)) return detail.map((d) => d.msg).join(", ")
  return "Authentication failed. Please try again."
}
