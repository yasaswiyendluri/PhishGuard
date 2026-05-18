import RiskBadge from "./RiskBadge"
import { mlDisplay, extractMlConfidence, downloadReport } from "../utils/risk"

function CTICard({ title, subtitle, value, detail, accent = "text-cyan-300" }) {
  return (
    <div className="panel p-5 flex flex-col gap-2">
      <p className="text-[10px] uppercase tracking-widest text-slate-500 font-medium">{title}</p>
      <p className={`text-2xl font-bold ${accent}`}>{value}</p>
      {subtitle && <p className="text-xs text-slate-400 capitalize">{subtitle}</p>}
      {detail && <p className="text-xs text-slate-500 mt-auto leading-relaxed">{detail}</p>}
    </div>
  )
}

function ScanResultPanel({ scan }) {
  if (!scan) return null

  const intel = scan.threat_intel || {}
  const ml = intel.ml || {}
  const vt = intel.virustotal || {}
  const urlhaus = intel.urlhaus || {}
  const typo = intel.typosquatting || {}
  const whois = scan.features || {}

  const mlPrediction = scan.ml_prediction ?? ml.ml_prediction
  const mlReady = scan.ml_ready ?? ml.ml_ready
  const mlInfo = extractMlConfidence(scan)

  return (
    <div className="mt-6 space-y-5">
      <div className="p-5 rounded-xl bg-slate-900/50 border border-slate-700/60">
        <div className="flex flex-wrap items-start justify-between gap-4 mb-4">
          <div>
            <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Analysis complete</p>
            <p className="mono text-sm text-cyan-200 break-all">{scan.url}</p>
          </div>
          <div className="flex items-center gap-2">
            <RiskBadge level={scan.risk_level} />
            <button
              type="button"
              onClick={() => downloadReport(scan)}
              className="text-xs px-3 py-1.5 rounded-lg border border-slate-600 text-slate-300 hover:border-cyan-500/50 hover:text-cyan-300 transition-colors"
            >
              Export IOC
            </button>
          </div>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-sm">
          <div>
            <p className="text-slate-500 text-xs mb-1">Composite risk</p>
            <p className="text-xl font-bold text-white">{scan.risk_score}%</p>
          </div>
          <div>
            <p className="text-slate-500 text-xs mb-1">ML confidence</p>
            <p
              className={`text-xl font-bold ${
                mlInfo.label === "Offline" ? "text-slate-500" : "text-cyan-300"
              }`}
            >
              {mlInfo.label}
            </p>
          </div>
          <div>
            <p className="text-slate-500 text-xs mb-1">Verdict</p>
            <p className="text-lg font-semibold capitalize text-slate-200">{scan.prediction}</p>
          </div>
          <div>
            <p className="text-slate-500 text-xs mb-1">Scan ID</p>
            <p className="mono text-xs text-slate-400 truncate">{scan.scan_id}</p>
          </div>
        </div>

        <p className="mt-4 text-sm text-slate-400 leading-relaxed">
          <span className="text-slate-500">Analysis: </span>
          {scan.explanation}
        </p>
      </div>

      <div>
        <h3 className="text-xs uppercase tracking-widest text-slate-500 mb-3 font-medium">
          Threat intelligence breakdown
        </h3>
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-5 gap-3">
          <CTICard
            title="ML Classifier"
            value={mlDisplay(scan)}
            subtitle={
              mlInfo.ready && mlPrediction
                ? mlPrediction
                : mlInfo.label === "Offline"
                  ? "Restart backend — see /api/ml/status"
                  : "—"
            }
            detail={
              mlInfo.ready
                ? "RandomForest phishing probability"
                : "Model not loaded (backend/app/ml/phishing_detector_enhanced.pkl)"
            }
            accent={mlPrediction === "phishing" ? "text-red-300" : "text-emerald-300"}
          />
          <CTICard
            title="VirusTotal"
            value={vt.malicious_count != null ? `${vt.malicious_count}/${vt.total_vendors || "?"}` : "—"}
            subtitle={vt.malicious_count > 0 ? "Flagged" : "Clean"}
            detail={
              vt.malicious_count > 0
                ? `${vt.malicious_count} vendors flagged this URL`
                : "No vendor detections"
            }
            accent={vt.malicious_count > 0 ? "text-red-300" : "text-emerald-300"}
          />
          <CTICard
            title="URLHaus"
            value={urlhaus.is_blacklisted != null ? (urlhaus.is_blacklisted ? "Listed" : "Clear") : "—"}
            subtitle="Malware feed"
            detail={
              urlhaus.is_blacklisted
                ? "Found in URLHaus malicious database"
                : "Not in URLHaus blacklist"
            }
            accent={urlhaus.is_blacklisted ? "text-red-300" : "text-emerald-300"}
          />
          <CTICard
            title="WHOIS / DNS"
            value={whois.domain_age_days != null ? `${whois.domain_age_days}d` : "—"}
            subtitle="Domain age"
            detail={
              whois.domain
                ? `${whois.domain}${whois.dns_suspicious ? " · DNS flags raised" : ""}`
                : "Forensics unavailable"
            }
            accent={whois.domain_age_days != null && whois.domain_age_days < 30 ? "text-amber-300" : "text-slate-200"}
          />
          <CTICard
            title="Typosquatting"
            value={typo.is_typosquat != null ? (typo.is_typosquat ? "Detected" : "None") : "—"}
            subtitle={typo.closest_domain || "Brand similarity"}
            detail={
              typo.is_typosquat
                ? `Resembles ${typo.closest_domain} (distance ${typo.distance})`
                : "No brand impersonation detected"
            }
            accent={typo.is_typosquat ? "text-amber-300" : "text-emerald-300"}
          />
        </div>
      </div>
    </div>
  )
}

export default ScanResultPanel
