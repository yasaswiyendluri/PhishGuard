export function apiErrorMessage(err, fallback = "Something went wrong. Please try again.") {
  if (!err.response) {
    return "Cannot reach the API. Start the backend: uvicorn app.main:app --reload (in backend/)"
  }

  const detail = err.response.data?.detail
  if (typeof detail === "string") return detail

  if (Array.isArray(detail)) {
    return detail.map((d) => d.msg || d.message || String(d)).join(". ")
  }

  return fallback
}
