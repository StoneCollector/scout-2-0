import React, { useEffect, useState } from "react";
import {
  ExternalLink,
  RefreshCw,
  Download,
  Printer,
  ShieldAlert,
  ChevronDown,
  ChevronUp,
  Search,
  Wrench,
} from "lucide-react";
import { type VulnItem, fetchVulns, refreshVulns } from "../api";

export const VulnsView: React.FC = () => {
  const [vulns, setVulns] = useState<VulnItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [expandedRows, setExpandedRows] = useState<Record<string, boolean>>({});

  const loadVulns = async (force: boolean = false) => {
    if (force) setRefreshing(true);
    else setLoading(true);

    try {
      const data = force ? await refreshVulns() : await fetchVulns();
      setVulns(data);
    } catch (err) {
      console.error("Failed to load vulnerabilities:", err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    loadVulns(false);
  }, []);

  const toggleExpand = (id: string) => {
    setExpandedRows((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const exportCsv = () => {
    const headers = ["CVE ID", "CVSS Score", "Severity", "Remediation", "Description", "NVD URL"];
    const rows = filteredVulns.map((v) => [
      v.id,
      v.cvss_score,
      v.severity,
      v.remediation,
      v.description,
      v.url,
    ]);

    const csvContent = [
      headers.map((h) => `"${h.replace(/"/g, '""')}"`).join(","),
      ...rows.map((row) =>
        row.map((val) => `"${String(val).replace(/"/g, '""')}"`).join(",")
      ),
    ].join("\n");

    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", "Task4_GLPI_Vulnerabilities.csv");
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const filteredVulns = vulns.filter((v) => {
    const matchesSearch =
      v.id.toLowerCase().includes(search.toLowerCase()) ||
      v.description.toLowerCase().includes(search.toLowerCase());
    const matchesSev =
      severityFilter === "all" ? true : v.severity.toLowerCase() === severityFilter.toLowerCase();
    return matchesSearch && matchesSev;
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto">
      {/* Header and Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-5 rounded-xl bg-[#0f172a] border border-slate-800 shadow-xl">
        <div>
          <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-amber-400" />
            Task 4: Vulnerability Assessment (GLPI 9.5.5 & Barcode Plugin)
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            NVD API 2.0 assessment of known security advisories, CVSS severity, and remediation guidance.
          </p>
        </div>

        <div className="flex items-center gap-2 no-print">
          <button
            onClick={() => loadVulns(true)}
            disabled={refreshing}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-200 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? "animate-spin" : ""}`} />
            {refreshing ? "Querying NVD..." : "Refresh NVD"}
          </button>
          <button
            onClick={exportCsv}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-200 transition"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            Export CSV
          </button>
          <button
            onClick={() => window.print()}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition"
          >
            <Printer className="w-3.5 h-3.5" />
            Print Report
          </button>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-center justify-between gap-3 no-print">
        <div className="flex items-center gap-3 w-full sm:w-auto flex-1 max-w-md">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search CVE ID or description..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </div>
        <span className="text-xs text-slate-400 font-mono">
          Showing {filteredVulns.length} of {vulns.length} CVEs
        </span>
      </div>

      {/* Vulnerabilities Table */}
      <div className="rounded-xl border border-slate-800 bg-[#0f172a] overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-[#090d16] font-mono text-[11px] uppercase tracking-wider text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">CVE ID</th>
                <th className="py-3 px-4">CVSS Severity</th>
                <th className="py-3 px-4">Description</th>
                <th className="py-3 px-4">Remediation / Workaround</th>
                <th className="py-3 px-4 text-right">Published</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800">
              {loading ? (
                <tr>
                  <td colSpan={5} className="text-center py-12 text-slate-500">
                    <RefreshCw className="w-6 h-6 animate-spin mx-auto mb-2 text-cyan-400" />
                    Fetching CVE assessment from NVD...
                  </td>
                </tr>
              ) : filteredVulns.length === 0 ? (
                <tr>
                  <td colSpan={5} className="text-center py-10 text-slate-500">
                    No vulnerabilities found matching criteria.
                  </td>
                </tr>
              ) : (
                filteredVulns.map((v) => {
                  const isExpanded = !!expandedRows[v.id];
                  const isCritical = v.severity === "CRITICAL";
                  const isHigh = v.severity === "HIGH";
                  const isMedium = v.severity === "MEDIUM";

                  return (
                    <tr key={v.id} className="hover:bg-slate-800/40 transition">
                      <td className="py-3 px-4 font-mono font-bold whitespace-nowrap">
                        <a
                          href={v.url}
                          target="_blank"
                          rel="noreferrer"
                          className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
                        >
                          {v.id}
                          <ExternalLink className="w-3 h-3 text-slate-500" />
                        </a>
                      </td>

                      <td className="py-3 px-4 whitespace-nowrap">
                        <div className="flex items-center gap-2">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider ${
                              isCritical
                                ? "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                                : isHigh
                                ? "bg-orange-500/20 text-orange-400 border border-orange-500/30"
                                : isMedium
                                ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                                : "bg-sky-500/20 text-sky-400 border border-sky-500/30"
                            }`}
                          >
                            {v.severity}
                          </span>
                          <span className="font-mono font-bold text-slate-200">
                            {v.cvss_score.toFixed(1)}
                          </span>
                        </div>
                      </td>

                      <td className="py-3 px-4 max-w-md">
                        <div className="text-slate-300 text-[11px] leading-relaxed">
                          {isExpanded
                            ? v.description
                            : v.description.length > 140
                            ? `${v.description.slice(0, 140)}...`
                            : v.description}
                        </div>
                        {v.description.length > 140 && (
                          <button
                            onClick={() => toggleExpand(v.id)}
                            className="text-[10px] text-cyan-400 hover:text-cyan-300 mt-1 flex items-center gap-0.5 no-print"
                          >
                            {isExpanded ? (
                              <>
                                Show Less <ChevronUp className="w-3 h-3" />
                              </>
                            ) : (
                              <>
                                Show More <ChevronDown className="w-3 h-3" />
                              </>
                            )}
                          </button>
                        )}
                      </td>

                      <td className="py-3 px-4 max-w-xs">
                        <div className="flex items-start gap-1.5 text-slate-300 text-[11px]">
                          <Wrench className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
                          {v.remediation.startsWith("http") ? (
                            <a
                              href={v.remediation}
                              target="_blank"
                              rel="noreferrer"
                              className="text-cyan-400 hover:underline truncate"
                              title={v.remediation}
                            >
                              Official Patch Advisory &rarr;
                            </a>
                          ) : (
                            <span>{v.remediation}</span>
                          )}
                        </div>
                      </td>

                      <td className="py-3 px-4 text-right text-slate-500 font-mono text-[10px] whitespace-nowrap">
                        {v.published ? v.published.split("T")[0] : "-"}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
