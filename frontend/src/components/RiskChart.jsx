import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
} from "recharts"

const COLORS = ["#34d399", "#fbbf24", "#f87171", "#ef4444"]

function RiskChart({ byLevel = {} }) {
  const pieData = [
    { name: "Low", value: byLevel.LOW || 0 },
    { name: "Medium", value: byLevel.MEDIUM || 0 },
    { name: "High", value: byLevel.HIGH || 0 },
    { name: "Critical", value: byLevel.CRITICAL || 0 },
  ].filter((d) => d.value > 0)

  const barData = pieData.length
    ? pieData
    : [{ name: "No data", value: 0 }]

  const empty = pieData.length === 0

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <div className="panel p-6">
        <h3 className="text-sm font-semibold text-slate-300 mb-4">Risk Distribution</h3>
        <div className="h-64">
          {empty ? (
            <div className="h-full flex items-center justify-center text-slate-500 text-sm">
              Run scans to populate analytics
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={pieData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={85}
                  paddingAngle={3}
                >
                  {pieData.map((_, i) => (
                    <Cell key={i} fill={COLORS[i % COLORS.length]} stroke="transparent" />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: "#0d131c",
                    border: "1px solid #1e293b",
                    borderRadius: 8,
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      <div className="panel p-6">
        <h3 className="text-sm font-semibold text-slate-300 mb-4">Threats by Severity</h3>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={barData}>
              <XAxis dataKey="name" stroke="#64748b" fontSize={12} />
              <YAxis stroke="#64748b" fontSize={12} allowDecimals={false} />
              <Tooltip
                contentStyle={{
                  background: "#0d131c",
                  border: "1px solid #1e293b",
                  borderRadius: 8,
                }}
              />
              <Bar dataKey="value" fill="#22d3ee" radius={[6, 6, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  )
}

export default RiskChart
