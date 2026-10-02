import React, { useEffect, useState } from "react";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from "recharts";
import {
  ShieldCheck,
  AlertCircle,
  ShieldBan,
  Files,
  RefreshCw,
  Cpu,
  Layers,
} from "lucide-react";
import { fetchStats, type StatsData } from "../api";

export const StatsView: React.FC = () => {
  const [stats, setStats] = useState<StatsData | null>(null);
  const [loading, setLoading] = useState(true);

  const loadStats = async () => {
    setLoading(true);
    try {
      const data = await fetchStats();
      setStats(data);
    } catch (err) {
      console.error("Failed to load statistics:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadStats();
  }, []);

  const total = stats?.total_scans || 0;
  const passedPct = total > 0 ? Math.round(((stats?.passed || 0) / total) * 100) : 0;
  const reviewPct = total > 0 ? Math.round(((stats?.review || 0) / total) * 100) : 0;
  const blockedPct = total > 0 ? Math.round(((stats?.blocked || 0) / total) * 100) : 0;

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-base font-bold text-slate-100">Telemetry & Analytics</h2>
          <p className="text-xs text-slate-400 mt-1">
            Real-time pipeline throughput, detection rates, and verdict telemetry.
          </p>
        </div>
        <button
          onClick={loadStats}
          disabled={loading}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          Refresh Stats
        </button>
      </div>

      {/* 4 KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Scans */}
        <div className="p-5 rounded-xl bg-[#0f172a] border border-slate-800 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono">
              Total Scans
            </span>
            <div className="p-2 rounded-lg bg-slate-800 text-cyan-400">
              <Files className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100 mt-2">
            {stats?.total_scans || 0}
          </div>
          <div className="text-[11px] text-slate-500 mt-1">Processed by pipeline</div>
        </div>

        {/* Passed */}
        <div className="p-5 rounded-xl bg-[#0f172a] border border-slate-800 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono">
              Passed Clean
            </span>
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400 mt-2">
            {stats?.passed || 0}
          </div>
          <div className="text-[11px] text-emerald-500/80 mt-1">{passedPct}% of total volume</div>
        </div>

        {/* Review */}
        <div className="p-5 rounded-xl bg-[#0f172a] border border-slate-800 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono">
              In Review
            </span>
            <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400 border border-amber-500/20">
              <AlertCircle className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400 mt-2">
            {stats?.review || 0}
          </div>
          <div className="text-[11px] text-amber-500/80 mt-1">{reviewPct}% suspicious / unsigned</div>
        </div>

        {/* Blocked */}
        <div className="p-5 rounded-xl bg-[#0f172a] border border-slate-800 shadow-lg">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider font-mono">
              Quarantined
            </span>
            <div className="p-2 rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
              <ShieldBan className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-bold font-mono text-rose-400 mt-2">
            {stats?.blocked || 0}
          </div>
          <div className="text-[11px] text-rose-500/80 mt-1">{blockedPct}% malware / tampered</div>
        </div>
      </div>

      {/* Recharts Analytics Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Donut Chart: Verdict Distribution */}
        <div className="p-6 rounded-xl bg-[#0f172a] border border-slate-800 shadow-lg flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              Verdict Distribution
            </h3>
            <p className="text-xs text-slate-400 mt-1">Split between Pass, Review, and Block verdicts.</p>
          </div>

          <div className="h-64 my-4 flex items-center justify-center">
            {total === 0 ? (
              <div className="text-xs text-slate-500">No scan verdicts recorded yet.</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={stats?.verdict_split || []}
                    cx="50%"
                    cy="50%"
                    innerRadius={60}
                    outerRadius={90}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {stats?.verdict_split?.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#090d16",
                      borderColor: "#334155",
                      borderRadius: "8px",
                      fontSize: "12px",
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* Donut Legend */}
          <div className="flex items-center justify-center gap-6 pt-2 border-t border-slate-800 text-xs">
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-emerald-500" />
              <span className="text-slate-300">Pass ({stats?.passed || 0})</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-amber-500" />
              <span className="text-slate-300">Review ({stats?.review || 0})</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-3 h-3 rounded-full bg-rose-500" />
              <span className="text-slate-300">Block ({stats?.blocked || 0})</span>
            </div>
          </div>
        </div>

        {/* Bar Chart: Hourly Throughput */}
        <div className="p-6 rounded-xl bg-[#0f172a] border border-slate-800 shadow-lg flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-200 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              24-Hour Scan Activity
            </h3>
            <p className="text-xs text-slate-400 mt-1">Hourly ingestion rate from inbox directory.</p>
          </div>

          <div className="h-64 my-4">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={stats?.scans_per_hour || []}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="hour" stroke="#64748b" fontSize={10} tickLine={false} />
                <YAxis stroke="#64748b" fontSize={10} tickLine={false} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#090d16",
                    borderColor: "#334155",
                    borderRadius: "8px",
                    fontSize: "12px",
                  }}
                />
                <Bar dataKey="count" fill="#06b6d4" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="text-[11px] text-slate-500 text-center border-t border-slate-800 pt-3">
            Showing aggregate hourly counts for the preceding 24 hours.
          </div>
        </div>
      </div>
    </div>
  );
};
