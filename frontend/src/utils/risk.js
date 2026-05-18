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

function pickNum(v) {
  if (v === null || v === undefined) return null
  if (typeof v === "number" && Number.isFinite(v)) return v
  if (typeof v === "string" && v.trim() !== "") {
    const n = Number(v)
    return Number.isFinite(n) ? n : null
  }
  return null
}

/** Read ML block from any API shape (snake_case, camelCase, nested). */
export function getMlBlock(scan) {
  if (!scan || typeof scan !== "object") return null

  const intel = scan.threat_intel || scan.threatIntel || {}
  const nested = intel.ml || intel.ML || scan.ml || null

  if (nested && typeof nested === "object") return nested

  if (
    scan.ml_confidence != null ||
    scan.mlConfidence != null ||
    scan.ml_score != null ||
    scan.mlScore != null
  ) {
    return {
      ml_confidence: scan.ml_confidence ?? scan.mlConfidence,
      ml_score: scan.ml_score ?? scan.mlScore,
      ml_ready: scan.ml_ready ?? scan.mlReady,
      ml_prediction: scan.ml_prediction ?? scan.mlPrediction,
    }
  }

  return null
}

/** Returns { percent: number|null, label: string, ready: boolean } */
export function extractMlConfidence(scan) {
  const ml = getMlBlock(scan)
  const ready =
    scan?.ml_ready === true ||
    scan?.mlReady === true ||
    ml?.ml_ready === true ||
    ml?.mlReady === true

  const tryConf = (v) => {
    const n = pickNum(v)
    if (n == null) return null
    if (n >= 0 && n <= 1) return Math.round(n * 100)
    if (n >= 0 && n <= 100) return Math.round(n)
    return null
  }

  const sources = [
    scan?.ml_confidence,
    scan?.mlConfidence,
    ml?.ml_confidence,
    ml?.mlConfidence,
  ]

  for (const s of sources) {
    const p = tryConf(s)
    if (p != null) return { percent: p, label: `${p}%`, ready: ready || p > 0 }
  }

  const scoreSources = [scan?.ml_score, scan?.mlScore, ml?.ml_score, ml?.mlScore]
  for (const s of scoreSources) {
    const p = tryConf(s)
    if (p != null) return { percent: p, label: `${p}%`, ready: true }
  }

  if (ready) return { percent: 0, label: "0%", ready: true }
  return { percent: null, label: "Offline", ready: false }
}

export function mlDisplay(scan) {
  return extractMlConfidence(scan).label
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
