import { createContext, useContext, useEffect, useState } from "react"
import API from "../services/api"

const AuthContext = createContext(null)

const TOKEN_KEY = "phishguard_token"
const USER_KEY = "phishguard_user"

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    const stored = localStorage.getItem(USER_KEY)
    return stored ? JSON.parse(stored) : null
  })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const token = localStorage.getItem(TOKEN_KEY)
    if (!token) {
      setLoading(false)
      return
    }

    API.get("/api/auth/me")
      .then((res) => {
        setUser(res.data)
        localStorage.setItem(USER_KEY, JSON.stringify(res.data))
      })
      .catch(() => {
        localStorage.removeItem(TOKEN_KEY)
        localStorage.removeItem(USER_KEY)
        setUser(null)
      })
      .finally(() => setLoading(false))
  }, [])

  const persistSession = (token, userData) => {
    localStorage.setItem(TOKEN_KEY, token)
    localStorage.setItem(USER_KEY, JSON.stringify(userData))
    setUser(userData)
  }

  const login = async (email, password) => {
    const { data } = await API.post("/api/auth/login", { email, password })
    persistSession(data.access_token, data.user)
    return data.user
  }

  const register = async (username, email, password) => {
    const { data } = await API.post("/api/auth/register", {
      username,
      email,
      password,
    })
    persistSession(data.access_token, data.user)
    return data.user
  }

  const logout = () => {
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem(USER_KEY)
    setUser(null)
  }

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout, isAuthenticated: !!user }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error("useAuth must be used within AuthProvider")
  return ctx
}
