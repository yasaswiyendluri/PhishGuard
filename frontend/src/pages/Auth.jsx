import { useState } from "react"
import { useNavigate, Navigate } from "react-router-dom"
import { useAuth } from "../context/AuthContext"
import { apiErrorMessage } from "../utils/errors"

function Auth() {
  const [isLogin, setIsLogin] = useState(true)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  const [formData, setFormData] = useState({
    username: "",
    email: "",
    password: "",
  })

  const { login, register, isAuthenticated } = useAuth()
  const navigate = useNavigate()

  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />
  }

  const handleChange = (e) => {
    setError("")
    setFormData({ ...formData, [e.target.name]: e.target.value })
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError("")

    try {
      if (isLogin) {
        await login(formData.email, formData.password)
      } else {
        await register(formData.username, formData.email, formData.password)
      }
      navigate("/dashboard")
    } catch (err) {
      setError(apiErrorMessage(err, "Authentication failed. Please try again."))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-[#070b12] flex">
      <div className="hidden lg:flex lg:w-1/2 relative overflow-hidden border-r border-slate-800/80">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_top_left,_rgba(34,211,238,0.12),_transparent_50%),radial-gradient(ellipse_at_bottom_right,_rgba(16,185,129,0.1),_transparent_50%)]" />
        <div className="relative z-10 flex flex-col justify-center p-16 max-w-xl">
          <p className="text-cyan-400 text-xs font-semibold uppercase tracking-[0.25em] mb-4">
            ML + Cyber Threat Intelligence
          </p>
          <h1 className="text-4xl xl:text-5xl font-bold text-white leading-tight mb-6">
            Real-time phishing detection for security analysts
          </h1>
          <p className="text-slate-400 text-lg leading-relaxed mb-10">
            PhishGuard mirrors SOC workflows: ML classification, VirusTotal & URLHaus feeds,
            passive DNS/WHOIS forensics, and typosquatting analysis — synthesized into exportable IOC reports.
          </p>
          <ul className="space-y-4">
            {[
              "Sub-500ms URL analysis pipeline",
              "Live threat intelligence integration",
              "Structured analyst dashboard & reports",
            ].map((item) => (
              <li key={item} className="flex items-center gap-3 text-slate-300">
                <span className="h-6 w-6 rounded-full bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 text-xs">
                  ✓
                </span>
                {item}
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="flex-1 flex items-center justify-center p-8">
        <div className="w-full max-w-md">
          <div className="lg:hidden flex items-center gap-3 mb-8">
            <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-cyan-500 to-emerald-500 flex items-center justify-center text-black font-black">
              P
            </div>
            <span className="text-xl font-bold text-white">PhishGuard</span>
          </div>

          <div className="bg-[#0d131c] border border-slate-800/80 rounded-2xl p-8 shadow-2xl shadow-black/40">
            <h2 className="text-2xl font-bold text-white mb-1">
              {isLogin ? "Analyst sign in" : "Create analyst account"}
            </h2>
            <p className="text-slate-400 text-sm mb-6">
              {isLogin
                ? "Access your threat operations dashboard"
                : "Register to save scans and generate IOC reports"}
            </p>

            {error && (
              <div className="mb-5 px-4 py-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-300 text-sm">
                {error}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
              {!isLogin && (
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1.5 uppercase tracking-wide">
                    Username
                  </label>
                  <input
                    type="text"
                    name="username"
                    required={!isLogin}
                    placeholder="analyst_name"
                    value={formData.username}
                    onChange={handleChange}
                    className="input-field"
                  />
                </div>
              )}

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1.5 uppercase tracking-wide">
                  Email
                </label>
                <input
                  type="email"
                  name="email"
                  required
                  placeholder="you@security.org"
                  value={formData.email}
                  onChange={handleChange}
                  className="input-field"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1.5 uppercase tracking-wide">
                  Password
                </label>
                <input
                  type="password"
                  name="password"
                  required
                  minLength={6}
                  placeholder="••••••••"
                  value={formData.password}
                  onChange={handleChange}
                  className="input-field"
                />
              </div>

              <button type="submit" disabled={loading} className="btn-primary w-full mt-2">
                {loading ? "Please wait…" : isLogin ? "Sign in" : "Create account"}
              </button>
            </form>

            <p className="text-slate-500 text-center mt-6 text-sm">
              {isLogin ? "New analyst?" : "Already registered?"}{" "}
              <button
                type="button"
                onClick={() => {
                  setIsLogin(!isLogin)
                  setError("")
                }}
                className="text-cyan-400 hover:text-cyan-300 font-medium"
              >
                {isLogin ? "Create account" : "Sign in"}
              </button>
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Auth
