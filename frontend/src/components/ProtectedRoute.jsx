import { Navigate } from "react-router-dom"
import { useAuth } from "../context/AuthContext"

function ProtectedRoute({ children }) {
  const { isAuthenticated, loading } = useAuth()

  if (loading) {
    return (
      <div className="min-h-screen bg-[#070b12] flex items-center justify-center">
        <div className="flex flex-col items-center gap-4">
          <div className="h-10 w-10 rounded-full border-2 border-cyan-500/30 border-t-cyan-400 animate-spin" />
          <p className="text-slate-400 text-sm tracking-wide">Initializing SOC workspace…</p>
        </div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }

  return children
}

export default ProtectedRoute
