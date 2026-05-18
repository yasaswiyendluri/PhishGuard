import { NavLink, useNavigate, useLocation } from "react-router-dom"
import { useAuth } from "../context/AuthContext"

const navItems = [
  { to: "/dashboard", label: "Overview", icon: "◉" },
  { to: "/reports", label: "Threat Reports", icon: "⚑" },
  { to: "/analytics", label: "Analytics", icon: "▤" },
]

const pageTitles = {
  "/dashboard": "Security Operations Overview",
  "/reports": "Threat Intelligence Reports",
  "/analytics": "Risk Analytics & Trends",
}

function Layout({ children }) {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const title = pageTitles[location.pathname] || "PhishGuard SOC"

  const initials = user?.username
    ? user.username.slice(0, 2).toUpperCase()
    : "AN"

  const handleLogout = () => {
    logout()
    navigate("/login")
  }

  return (
    <div className="min-h-screen bg-[#070b12] text-slate-100 flex">
      <aside className="w-64 shrink-0 border-r border-slate-800/80 bg-[#0a1019] flex flex-col">
        <div className="p-6 border-b border-slate-800/80">
          <div className="flex items-center gap-3">
            <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-cyan-500 to-emerald-500 flex items-center justify-center text-black font-black text-lg">
              P
            </div>
            <div>
              <h1 className="font-bold text-lg tracking-tight">PhishGuard</h1>
              <p className="text-[10px] uppercase tracking-widest text-cyan-400/80">Analyst Console</p>
            </div>
          </div>
        </div>

        <nav className="flex-1 p-4 space-y-1">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all ${
                  isActive
                    ? "bg-cyan-500/10 text-cyan-300 border border-cyan-500/25 shadow-[0_0_20px_rgba(34,211,238,0.08)]"
                    : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent"
                }`
              }
            >
              <span className="text-base opacity-80">{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="p-4 border-t border-slate-800/80">
          <div className="flex items-center gap-3 px-3 py-3 rounded-xl bg-slate-900/60 border border-slate-800/60">
            <div className="h-9 w-9 rounded-full bg-gradient-to-br from-cyan-400 to-emerald-400 flex items-center justify-center text-black text-xs font-bold">
              {initials}
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-sm font-medium truncate">{user?.username}</p>
              <p className="text-xs text-slate-500 truncate">{user?.email}</p>
            </div>
          </div>
          <button
            type="button"
            onClick={handleLogout}
            className="mt-3 w-full text-left px-4 py-2 text-sm text-slate-400 hover:text-red-300 hover:bg-red-500/5 rounded-lg transition-colors"
          >
            Sign out
          </button>
        </div>
      </aside>

      <div className="flex-1 flex flex-col min-w-0">
        <header className="h-16 shrink-0 border-b border-slate-800/80 bg-[#0a1019]/80 backdrop-blur flex items-center justify-between px-8">
          <div>
            <p className="text-xs text-cyan-400/70 uppercase tracking-widest mb-0.5">SOC Workspace</p>
            <h2 className="text-lg font-semibold text-slate-100">{title}</h2>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/20">
              <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-xs text-emerald-300 font-medium">Live CTI Feeds</span>
            </div>
          </div>
        </header>

        <main className="flex-1 overflow-auto p-8">{children}</main>
      </div>
    </div>
  )
}

export default Layout
