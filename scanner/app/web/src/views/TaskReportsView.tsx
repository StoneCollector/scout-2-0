import React, { useEffect, useState, useMemo } from "react";
import {
  Download,
  Printer,
  Copy,
  Check,
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  FileCheck2,
  Binary,
  RefreshCw,
  Search,
  ChevronDown,
  ChevronRight,
  Layers,
  Fingerprint,
  FileText,
  Trash2,
} from "lucide-react";
import {
  fetchUnifiedReport,
  clearScans,
  type UnifiedReportData,
} from "../api";
import { ConfirmModal } from "../components/ConfirmModal";

export const TaskReportsView: React.FC = () => {
  const [data, setData] = useState<UnifiedReportData | null>(null);
  const [loading, setLoading] = useState(true);
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<"all" | "block" | "review" | "pass">("all");
  const [expandedEntities, setExpandedEntities] = useState<Record<number, boolean>>({});
  const [confirmClear, setConfirmClear] = useState(false);
  const [clearing, setClearing] = useState(false);

  const loadReport = async () => {
    setLoading(true);
    try {
      const res = await fetchUnifiedReport();
      setData(res);
      // Auto-expand blocked/critical entities
      const autoExpand: Record<number, boolean> = {};
      res.entities.forEach((e) => {
        if (e.verdict === "block" || e.verdict === "review") {
          autoExpand[e.id] = true;
        }
      });
      setExpandedEntities(autoExpand);
    } catch (err) {
      console.error("Failed to load unified security report:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadReport();
  }, []);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const toggleExpand = (id: number) => {
    setExpandedEntities((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const toggleAll = (expand: boolean) => {
    if (!data) return;
    const next: Record<number, boolean> = {};
    data.entities.forEach((e) => {
      next[e.id] = expand;
    });
    setExpandedEntities(next);
  };

  // Filtered entities
  const filteredEntities = useMemo(() => {
    if (!data) return [];
    return data.entities.filter((entity) => {
      const matchesSeverity =
        severityFilter === "all" ? true : entity.verdict.toLowerCase() === severityFilter;
      const q = searchQuery.toLowerCase().trim();
      const matchesSearch =
        !q ||
        entity.filename.toLowerCase().includes(q) ||
        entity.sha256.toLowerCase().includes(q) ||
        (entity.signature.signer && entity.signature.signer.toLowerCase().includes(q)) ||
        entity.findings.some(
          (f) =>
            f.title.toLowerCase().includes(q) ||
            f.description.toLowerCase().includes(q) ||
            f.checker.toLowerCase().includes(q)
        );
      return matchesSeverity && matchesSearch;
    });
  }, [data, severityFilter, searchQuery]);

  // Export full report to JSON
  const exportJson = () => {
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", `Scout_Report_${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Export entities to CSV
  const exportCsv = () => {
    if (!data) return;
    const headers = [
      "ID",
      "Filename",
      "SHA256",
      "Verdict",
      "Threat Score",
      "Signer",
      "Signature Verified",
      "Vendor Hash Match",
      "Total Findings",
    ];
    const rows = data.entities.map((e) => [
      e.id,
      `"${e.filename.replace(/"/g, '""')}"`,
      e.sha256,
      e.verdict.toUpperCase(),
      e.score,
      `"${(e.signature.signer || "Unsigned").replace(/"/g, '""')}"`,
      e.signature.verified ? "YES" : "NO",
      e.hash_verification.match === true ? "MATCH" : e.hash_verification.match === false ? "MISMATCH" : "N/A",
      e.findings.length,
    ]);
    const csvContent = [headers.join(","), ...rows.map((r) => r.join(","))].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", `Scout_Audit_${new Date().toISOString().slice(0, 10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const sevBadge = (sev: string) => {
    switch (sev.toLowerCase()) {
      case "critical":
        return "bg-rose-500/10 text-rose-400 border-rose-500/30";
      case "high":
        return "bg-orange-500/10 text-orange-400 border-orange-500/30";
      case "medium":
        return "bg-amber-500/10 text-amber-400 border-amber-500/30";
      case "low":
        return "bg-blue-500/10 text-blue-400 border-blue-500/30";
      default:
        return "bg-slate-500/10 text-slate-400 border-slate-500/30";
    }
  };

  const verdictBadge = (verdict: string) => {
    switch (verdict.toLowerCase()) {
      case "block":
        return {
          label: "QUARANTINED",
          bg: "bg-rose-500/10 text-rose-400 border-rose-500/30",
          dot: "bg-rose-400",
        };
      case "review":
        return {
          label: "REVIEW",
          bg: "bg-amber-500/10 text-amber-400 border-amber-500/30",
          dot: "bg-amber-400",
        };
      case "pass":
        return {
          label: "CLEAN",
          bg: "bg-emerald-500/10 text-emerald-400 border-emerald-500/30",
          dot: "bg-emerald-400",
        };
      default:
        return {
          label: verdict.toUpperCase(),
          bg: "bg-slate-500/10 text-slate-400 border-slate-500/30",
          dot: "bg-slate-400",
        };
    }
  };

  return (
    <div className="space-y-6 pb-12 max-w-7xl mx-auto">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-slate-800/80">
        <div>
          <h1 className="text-lg font-bold text-slate-100 flex items-center gap-2">
            <FileText className="w-5 h-5 text-cyan-400" />
            Reports
          </h1>
          <p className="text-xs text-slate-400 mt-0.5">
            Findings ordered by severity (high to low)
          </p>
        </div>

        {/* Global Actions */}
        <div className="flex items-center gap-2 flex-wrap no-print">
          <button
            onClick={() => setConfirmClear(true)}
            disabled={!data || data.entities.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/80 hover:bg-rose-500/10 border border-slate-700/80 hover:border-rose-500/30 text-xs font-medium text-slate-300 hover:text-rose-400 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            title="Clear all scan history"
          >
            <Trash2 className="w-3.5 h-3.5" />
            Clear history
          </button>
          <button
            onClick={loadReport}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-800 border border-slate-700/80 text-xs font-medium text-slate-200 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <button
            onClick={exportJson}
            disabled={!data || data.entities.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-800 border border-slate-700/80 text-xs font-medium text-slate-200 transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            JSON
          </button>
          <button
            onClick={exportCsv}
            disabled={!data || data.entities.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-800 border border-slate-700/80 text-xs font-medium text-slate-200 transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-emerald-400" />
            CSV
          </button>
          <button
            onClick={() => window.print()}
            className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-xs font-semibold text-white transition-all shadow-md shadow-cyan-950/40"
          >
            <Printer className="w-3.5 h-3.5" />
            Print Report
          </button>
        </div>
      </div>

      {/* 1. Surface-Level Executive Summary Metrics */}
      {data && (
        <div className="grid grid-cols-2 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
          <div className="bg-slate-900/70 border border-slate-800/80 rounded-xl p-4 shadow-sm">
            <div className="flex items-center justify-between text-slate-400 mb-1.5">
              <span className="text-[11px] font-mono uppercase tracking-wider">Total Evaluated</span>
              <Layers className="w-4 h-4 text-cyan-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-slate-100">{data.summary.total_scans}</div>
            <div className="text-[10px] text-slate-500 mt-1">Ingested binaries & installers</div>
          </div>

          <div className="bg-slate-900/70 border border-slate-800/80 rounded-xl p-4 shadow-sm">
            <div className="flex items-center justify-between text-rose-400 mb-1.5">
              <span className="text-[11px] font-mono uppercase tracking-wider">Quarantined</span>
              <ShieldAlert className="w-4 h-4 text-rose-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-rose-400">{data.summary.blocked_count}</div>
            <div className="text-[10px] text-slate-500 mt-1">Confirmed threats & malware</div>
          </div>

          <div className="bg-slate-900/70 border border-slate-800/80 rounded-xl p-4 shadow-sm">
            <div className="flex items-center justify-between text-amber-400 mb-1.5">
              <span className="text-[11px] font-mono uppercase tracking-wider">Review Required</span>
              <AlertTriangle className="w-4 h-4 text-amber-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-amber-400">{data.summary.review_count}</div>
            <div className="text-[10px] text-slate-500 mt-1">Suspicious / unsigned binaries</div>
          </div>

          <div className="bg-slate-900/70 border border-slate-800/80 rounded-xl p-4 shadow-sm">
            <div className="flex items-center justify-between text-emerald-400 mb-1.5">
              <span className="text-[11px] font-mono uppercase tracking-wider">Certified Clean</span>
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-emerald-400">{data.summary.clean_count}</div>
            <div className="text-[10px] text-slate-500 mt-1">Passed signature & hash checks</div>
          </div>

          <div className="col-span-2 sm:col-span-2 lg:col-span-1 bg-slate-900/70 border border-slate-800/80 rounded-xl p-4 shadow-sm">
            <div className="flex items-center justify-between text-slate-400 mb-1.5">
              <span className="text-[11px] font-mono uppercase tracking-wider">Threat Ratio</span>
              <Fingerprint className="w-4 h-4 text-purple-400" />
            </div>
            <div className="text-2xl font-bold font-mono text-purple-400">{data.summary.threat_ratio}%</div>
            <div className="text-[10px] text-slate-500 mt-1">Fleet risk density</div>
          </div>
        </div>
      )}

      {/* Search, Filter & View Controls */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 bg-slate-900/50 border border-slate-800/80 rounded-xl p-3 no-print">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search by file name, SHA256, signer, or threat..."
            className="w-full pl-9 pr-3 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Severity Filter Tabs */}
        <div className="flex items-center gap-1.5 flex-wrap">
          {(
            [
              { key: "all", label: "All Entities" },
              { key: "block", label: "Quarantined" },
              { key: "review", label: "Review" },
              { key: "pass", label: "Clean" },
            ] as const
          ).map((t) => (
            <button
              key={t.key}
              onClick={() => setSeverityFilter(t.key)}
              className={`px-3 py-1 text-xs rounded-lg font-medium transition-all ${
                severityFilter === t.key
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/50"
              }`}
            >
              {t.label}
            </button>
          ))}

          <div className="h-4 w-px bg-slate-800 mx-1 hidden sm:block" />

          {/* Expand/Collapse All */}
          <button
            onClick={() => toggleAll(true)}
            className="text-[11px] text-slate-500 hover:text-slate-300 px-2 py-1"
          >
            Expand All
          </button>
          <button
            onClick={() => toggleAll(false)}
            className="text-[11px] text-slate-500 hover:text-slate-300 px-2 py-1"
          >
            Collapse All
          </button>
        </div>
      </div>

      {/* 2. Detected Entities Ranked by Severity (High to Low) */}
      <div className="space-y-4">
        {loading && (
          <div className="text-center py-16 text-slate-500 flex flex-col items-center gap-3">
            <RefreshCw className="w-8 h-8 animate-spin text-cyan-400" />
            <p className="text-sm">Synthesizing comprehensive security dossier...</p>
          </div>
        )}

        {!loading && filteredEntities.length === 0 && (
          <div className="text-center py-16 text-slate-500 bg-slate-900/30 border border-slate-800/60 rounded-xl">
            <ShieldCheck className="w-12 h-12 text-slate-600 mx-auto mb-3" />
            <p className="text-sm text-slate-400 font-medium">No matching entities found</p>
            <p className="text-xs text-slate-600 mt-1">Adjust your search term or severity filter.</p>
          </div>
        )}

        {!loading &&
          filteredEntities.map((entity) => {
            const isExpanded = !!expandedEntities[entity.id];
            const vConfig = verdictBadge(entity.verdict);
            const highSevCount = entity.findings.filter((f) => f.severity === "critical" || f.severity === "high").length;

            return (
              <div
                key={entity.id}
                className={`rounded-xl border transition-all overflow-hidden ${
                  entity.verdict === "block"
                    ? "bg-slate-900/90 border-rose-950/60 hover:border-rose-900/80 shadow-lg shadow-rose-950/10"
                    : entity.verdict === "review"
                    ? "bg-slate-900/90 border-amber-950/60 hover:border-amber-900/80 shadow-lg shadow-amber-950/10"
                    : "bg-slate-900/90 border-slate-800/80 hover:border-slate-700/80"
                }`}
              >
                {/* Surface-Level Entity Header (Summary Card) */}
                <div
                  onClick={() => toggleExpand(entity.id)}
                  className="p-4 cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3 select-none"
                >
                  <div className="flex items-start gap-3 min-w-0">
                    <button className="mt-0.5 text-slate-500 hover:text-slate-300">
                      {isExpanded ? <ChevronDown className="w-4 h-4 text-cyan-400" /> : <ChevronRight className="w-4 h-4" />}
                    </button>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-semibold text-sm text-slate-100 truncate">{entity.filename}</span>
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border flex items-center gap-1.5 ${vConfig.bg}`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${vConfig.dot}`} />
                          {vConfig.label}
                        </span>
                        {highSevCount > 0 && (
                          <span className="px-1.5 py-0.5 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30 text-[10px] font-mono">
                            {highSevCount} Critical Finding{highSevCount > 1 ? "s" : ""}
                          </span>
                        )}
                      </div>

                      {/* Surface-level metadata chips */}
                      <div className="flex items-center gap-3 mt-1.5 text-xs text-slate-400 flex-wrap">
                        <div className="flex items-center gap-1 font-mono text-[11px] text-slate-400">
                          <span>SHA256:</span>
                          <span className="text-slate-300">{entity.sha256.slice(0, 16)}...</span>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleCopy(entity.sha256);
                            }}
                            className="text-slate-500 hover:text-cyan-400"
                            title="Copy full SHA256"
                          >
                            {copiedText === entity.sha256 ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                          </button>
                        </div>
                        <span className="text-slate-600">•</span>
                        <span>{(entity.size / 1024).toFixed(1)} KB</span>
                        {entity.created_at && (
                          <>
                            <span className="text-slate-600">•</span>
                            <span className="text-slate-500">{new Date(entity.created_at).toLocaleString()}</span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>

                  {/* Threat Score & Progress Bar */}
                  <div className="flex items-center gap-4 shrink-0 sm:self-center">
                    <div className="text-right">
                      <div className="text-[10px] font-mono uppercase text-slate-500">Threat Score</div>
                      <div
                        className={`text-lg font-bold font-mono ${
                          entity.score >= 60 ? "text-rose-400" : entity.score >= 25 ? "text-amber-400" : "text-emerald-400"
                        }`}
                      >
                        {entity.score}
                        <span className="text-xs text-slate-600">/100</span>
                      </div>
                    </div>
                    <div className="w-24 bg-slate-950 border border-slate-800 rounded-full h-2 overflow-hidden hidden sm:block">
                      <div
                        className={`h-full transition-all ${
                          entity.score >= 60 ? "bg-rose-500" : entity.score >= 25 ? "bg-amber-500" : "bg-emerald-500"
                        }`}
                        style={{ width: `${Math.min(entity.score, 100)}%` }}
                      />
                    </div>
                  </div>
                </div>

                {/* 3. Deep Findings per Entity (Ordered High to Low) */}
                {isExpanded && (
                  <div className="px-5 pb-5 pt-2 border-t border-slate-800/80 bg-slate-950/40 space-y-4">
                    {/* Integrity & Authenticode Surface Strip */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-2">
                      {/* Authenticode Card */}
                      <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800/80 text-xs">
                        <div className="flex items-center justify-between text-slate-400 mb-1.5 font-medium">
                          <span className="flex items-center gap-1.5">
                            <FileCheck2 className="w-3.5 h-3.5 text-cyan-400" /> Authenticode Digital Signature
                          </span>
                          <span
                            className={`px-1.5 py-0.5 rounded text-[9px] font-mono uppercase ${
                              entity.signature.verified
                                ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                                : entity.signature.signed
                                ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                                : "bg-slate-800 text-slate-400"
                            }`}
                          >
                            {entity.signature.verified ? "Verified" : entity.signature.signed ? "Untrusted" : "Unsigned"}
                          </span>
                        </div>
                        <div className="text-slate-300 font-mono text-[11px] truncate">
                          Signer: {entity.signature.signer || "None (Unsigned Binary)"}
                        </div>
                        <div className="text-slate-500 text-[10px] mt-0.5">
                          Digest Algorithm: {entity.signature.digest_algorithm || "N/A"}
                        </div>
                      </div>

                      {/* Vendor Hash Feed Match Card */}
                      <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800/80 text-xs">
                        <div className="flex items-center justify-between text-slate-400 mb-1.5 font-medium">
                          <span className="flex items-center gap-1.5">
                            <Binary className="w-3.5 h-3.5 text-cyan-400" /> Vendor Checksum Verification
                          </span>
                          <span
                            className={`px-1.5 py-0.5 rounded text-[9px] font-mono uppercase ${
                              entity.hash_verification.match === true
                                ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                                : entity.hash_verification.match === false
                                ? "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                                : "bg-slate-800 text-slate-400"
                            }`}
                          >
                            {entity.hash_verification.match === true
                              ? "Match"
                              : entity.hash_verification.match === false
                              ? "Mismatch"
                              : "No Feed"}
                          </span>
                        </div>
                        <div className="text-slate-300 font-mono text-[11px] truncate">
                          Feed Source: {entity.hash_verification.source || "No registered feed for filename"}
                        </div>
                        <div className="text-slate-500 text-[10px] mt-0.5">
                          Calculated: {entity.hash_verification.calculated ? `${entity.hash_verification.calculated.slice(0, 20)}...` : "SHA256"}
                        </div>
                      </div>
                    </div>

                    {/* Detailed Findings List (Ordered High to Low) */}
                    <div>
                      <div className="text-[11px] font-mono uppercase text-slate-400 font-semibold mb-2 flex items-center justify-between">
                        <span>Findings & Check Results ({entity.findings.length})</span>
                        <span className="text-[10px] text-slate-500 normal-case">Ordered by severity (Critical &rarr; Info)</span>
                      </div>

                      {entity.findings.length === 0 ? (
                        <div className="p-3 rounded-lg bg-slate-900/40 border border-slate-800 text-xs text-slate-500 text-center">
                          No abnormal security findings detected for this entity.
                        </div>
                      ) : (
                        <div className="space-y-2">
                          {entity.findings.map((f, fIdx) => (
                            <div
                              key={fIdx}
                              className="p-3 rounded-lg bg-slate-900/70 border border-slate-800 flex items-start gap-3 text-xs"
                            >
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border shrink-0 mt-0.5 ${sevBadge(
                                  f.severity
                                )}`}
                              >
                                {f.severity}
                              </span>
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center gap-2">
                                  <span className="font-semibold text-slate-200">{f.title}</span>
                                  <span className="px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 text-[10px] font-mono">
                                    {f.checker}
                                  </span>
                                </div>
                                <p className="text-slate-400 mt-0.5 text-[11px] leading-relaxed">{f.description}</p>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
      </div>

      <ConfirmModal
        isOpen={confirmClear}
        onClose={() => setConfirmClear(false)}
        onConfirm={async () => {
          setClearing(true);
          try {
            await clearScans();
            setConfirmClear(false);
            await loadReport();
          } catch (err) {
            console.error("Clear report error:", err);
          } finally {
            setClearing(false);
          }
        }}
        title="Clear scan history"
        message="Delete all scan records and reset the report? This cannot be undone."
        confirmLabel="Clear"
        loading={clearing}
      />
    </div>
  );
};
