import axios from "axios"

const API = axios.create({
  baseURL: import.meta.env.VITE_API_URL || "http://localhost:8000",
})

API.interceptors.request.use((config) => {
  const token = localStorage.getItem("phishguard_token")
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

API.interceptors.response.use(
  (res) => res,
  (error) => {
    if (error.response?.status === 401) {
      const path = window.location.pathname
      if (!path.startsWith("/login")) {
        localStorage.removeItem("phishguard_token")
        localStorage.removeItem("phishguard_user")
        window.location.href = "/login"
      }
    }
    return Promise.reject(error)
  }
)

export default API
