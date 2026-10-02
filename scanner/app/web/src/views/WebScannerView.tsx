import React, { useState, useEffect, useCallback, useRef } from "react";
import {
  Globe,
  Play,
  RefreshCw,
  ChevronRight,
  ChevronDown,
  Shield,
  AlertTriangle,
  AlertCircle,
  Info,
  CheckCircle2,
  XCircle,
  Loader2,
  FileText,
  Download,
  Printer,
  Copy,
  ShieldCheck,
  CheckCheck,
  Trash2,
} from "lucide-react";
import {
  startWebScan,
  fetchWebScans,
  fetchWebScan,
  clearWebScans,
  deleteWebScan,
  type WebScanItem,
  type WebScanDetail,
  type WebFindingItem,
} from "../api";
import { ConfirmModal } from "../components/ConfirmModal";

// ---------------------------------------------------------------------------
// Severity helpers
// ---------------------------------------------------------------------------
const SEV_CONFIG = {
  critical: { label: "CRITICAL", color: "text-rose-400", bg: "bg-rose-500/10 border-rose-500/25", dot: "bg-rose-400" },
  high:     { label: "HIGH",     color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/25", dot: "bg-orange-400" },
  medium:   { label: "MEDIUM",   color: "text-amber-400",  bg: "bg-amber-500/10 border-amber-500/25",   dot: "bg-amber-400" },
  low:      { label: "LOW",      color: "text-sky-400",    bg: "bg-sky-500/10 border-sky-500/25",       dot: "bg-sky-400" },
  info:     { label: "INFO",     color: "text-slate-400",  bg: "bg-slate-500/10 border-slate-500/25",   dot: "bg-slate-400" },
} as const;

type Sev = keyof typeof SEV_CONFIG;

function SevBadge({ severity }: { severity: string }) {
  const cfg = SEV_CONFIG[severity as Sev] ?? SEV_CONFIG.info;
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${cfg.bg} ${cfg.color}`}>
      <span className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  );
}

function GradeBadge({ grade, score }: { grade: string | null; score: number | null }) {
  const color =
    grade === "A" ? "text-emerald-400 border-emerald-500/30 bg-emerald-500/10" :
    grade === "B" ? "text-sky-400 border-sky-500/30 bg-sky-500/10" :
    grade === "C" ? "text-amber-400 border-amber-500/30 bg-amber-500/10" :
    grade === "D" ? "text-orange-400 border-orange-500/30 bg-orange-500/10" :
    "text-rose-400 border-rose-500/30 bg-rose-500/10";

  return (
    <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-lg border font-mono text-sm font-bold ${color}`}>
      Grade {grade ?? "–"}
      {score !== null && <span className="text-xs font-normal opacity-80">({score}/100)</span>}
    </span>
  );
}

function StatusPill({ status }: { status: string }) {
  if (status === "running") return (
    <span className="inline-flex items-center gap-1.5 text-amber-400 text-xs">
      <Loader2 className="w-3.5 h-3.5 animate-spin" /> Running
    </span>
  );
  if (status === "complete") return (
    <span className="inline-flex items-center gap-1.5 text-emerald-400 text-xs">
      <CheckCircle2 className="w-3.5 h-3.5" /> Complete
    </span>
  );
  return (
    <span className="inline-flex items-center gap-1.5 text-rose-400 text-xs">
      <XCircle className="w-3.5 h-3.5" /> Error
    </span>
  );
}

// ---------------------------------------------------------------------------
// Finding card (expandable)
// ---------------------------------------------------------------------------
function FindingCard({ finding }: { finding: WebFindingItem }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rounded-lg border border-slate-800 bg-slate-900/60 overflow-hidden transition-all">
      <button
        className="w-full flex items-start gap-3 p-3.5 text-left hover:bg-slate-800/30 transition-colors"
        onClick={() => setOpen((o) => !o)}
      >
        <div className="mt-0.5">
          {finding.severity === "critical" && <AlertCircle className="w-4 h-4 text-rose-400" />}
          {finding.severity === "high"     && <AlertTriangle className="w-4 h-4 text-orange-400" />}
          {finding.severity === "medium"   && <AlertTriangle className="w-4 h-4 text-amber-400" />}
          {finding.severity === "low"      && <Shield className="w-4 h-4 text-sky-400" />}
          {finding.severity === "info"     && <Info className="w-4 h-4 text-slate-400" />}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-slate-200">{finding.title}</span>
            <SevBadge severity={finding.severity} />
          </div>
          <div className="text-[11px] text-slate-500 mt-0.5 font-mono truncate">{finding.check_name} · {finding.url}</div>
        </div>
        <div className="text-slate-600 mt-0.5">
          {open ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
        </div>
      </button>
      {open && (
        <div className="border-t border-slate-800 px-4 py-3 space-y-3 bg-slate-900/40">
          <div>
            <div className="text-[10px] font-mono text-slate-500 uppercase mb-1">Evidence</div>
            <pre className="text-xs text-slate-300 whitespace-pre-wrap break-words font-mono bg-slate-950/60 rounded p-2.5 border border-slate-800">
              {finding.evidence || "—"}
            </pre>
          </div>
          <div>
            <div className="text-[10px] font-mono text-slate-500 uppercase mb-1">Remediation Action</div>
            <p className="text-xs text-slate-300 leading-relaxed">{finding.remediation}</p>
          </div>
          <div className="flex items-center gap-2 text-[10px] font-mono text-slate-500">
            <span className="px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
              {finding.owasp_category}
            </span>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Scan detail panel with Executive Report Generator
// ---------------------------------------------------------------------------
function ScanDetailPanel({
  scanId,
  onClose,
  onDeleted,
}: {
  scanId: number;
  onClose: () => void;
  onDeleted?: () => void;
}) {
  const [detail, setDetail] = useState<WebScanDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [viewMode, setViewMode] = useState<"findings" | "report">("findings");
  const [copied, setCopied] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const pollRef = useRef<number | null>(null);

  const load = useCallback(async () => {
    try {
      const d = await fetchWebScan(scanId);
      setDetail(d);
      if (d.status !== "running") {
        if (pollRef.current) clearInterval(pollRef.current);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    load();
    pollRef.current = window.setInterval(load, 3000);
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [load]);

  if (loading) return (
    <div className="flex-1 flex items-center justify-center">
      <Loader2 className="w-8 h-8 animate-spin text-cyan-500" />
    </div>
  );
  if (!detail) return null;

  const bySev = (sev: string) => detail.findings.filter(f => f.severity === sev);
  const groups = [
    { key: "critical", items: bySev("critical") },
    { key: "high",     items: bySev("high") },
    { key: "medium",   items: bySev("medium") },
    { key: "low",      items: bySev("low") },
    { key: "info",     items: bySev("info") },
  ].filter(g => g.items.length > 0);

  // Markdown Report Generator
  const generateMarkdownReport = () => {
    const lines = [
      `# Web Security Audit Executive Report`,
      `**Target:** ${detail.target_url}`,
      `**Audit ID:** #${detail.id}`,
      `**Final Grade:** Grade ${detail.grade ?? "N/A"} (${detail.score ?? 0}/100)`,
      `**Pages Crawled:** ${detail.pages_crawled}`,
      `**Total Findings:** ${detail.findings_count}`,
      `**Status:** ${detail.status.toUpperCase()}`,
      `**Audit Completed:** ${detail.completed_at ? new Date(detail.completed_at).toLocaleString() : "In Progress"}`,
      ``,
      `---`,
      `## Severity Summary`,
      `| Severity | Count |`,
      `| :--- | :--- |`,
      `| Critical | ${bySev("critical").length} |`,
      `| High | ${bySev("high").length} |`,
      `| Medium | ${bySev("medium").length} |`,
      `| Low | ${bySev("low").length} |`,
      `| Info | ${bySev("info").length} |`,
      ``,
      `---`,
      `## Detailed Findings (Ranked by Severity)`,
      ``,
    ];

    detail.findings.forEach((f, idx) => {
      lines.push(`### ${idx + 1}. [${f.severity.toUpperCase()}] ${f.title}`);
      lines.push(`- **URL:** \`${f.url}\``);
      lines.push(`- **OWASP Category:** ${f.owasp_category}`);
      lines.push(`- **Check Type:** \`${f.check_name}\``);
      lines.push(`- **Evidence:**`);
      lines.push(`\`\`\``);
      lines.push(f.evidence);
      lines.push(`\`\`\``);
      lines.push(`- **Remediation:** ${f.remediation}`);
      lines.push(``);
    });

    return lines.join("\n");
  };

  const handleExportMarkdown = () => {
    const md = generateMarkdownReport();
    const blob = new Blob([md], { type: "text/markdown;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `Scout_Web_Audit_${detail.id}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(detail, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `Scout_Web_Audit_${detail.id}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const handleCopyReport = () => {
    const md = generateMarkdownReport();
    navigator.clipboard.writeText(md);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="flex-1 flex flex-col overflow-hidden bg-[#080c14]">
      {/* Header */}
      <div className="flex items-start justify-between p-5 border-b border-slate-800 bg-[#0d1322]">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <Globe className="w-4 h-4 text-cyan-400" />
            <span className="text-sm font-semibold text-slate-100 font-mono">{detail.target_url}</span>
          </div>
          <div className="flex items-center gap-3">
            <StatusPill status={detail.status} />
            {detail.status === "complete" && (
              <GradeBadge grade={detail.grade} score={detail.score} />
            )}
            <span className="text-xs text-slate-400">
              {detail.pages_crawled ? `${detail.pages_crawled} ${detail.pages_crawled === 1 ? 'page' : 'pages'} · ` : ""}
              {detail.findings_count} findings
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Mode Switcher */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-0.5 flex text-xs font-medium">
            <button
              onClick={() => setViewMode("findings")}
              className={`px-3 py-1 rounded-md transition-all ${
                viewMode === "findings"
                  ? "bg-cyan-600 text-white shadow-sm"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Findings
            </button>
            <button
              onClick={() => setViewMode("report")}
              className={`px-3 py-1 rounded-md transition-all flex items-center gap-1.5 ${
                viewMode === "report"
                  ? "bg-cyan-600 text-white shadow-sm"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              <FileText className="w-3.5 h-3.5" />
              Audit Report
            </button>
          </div>

          <button
            onClick={() => setConfirmDelete(true)}
            className="text-slate-500 hover:text-rose-400 transition-colors p-1.5 rounded-lg hover:bg-slate-800"
            title="Delete this audit record"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>

          <button
            onClick={onClose}
            className="text-slate-500 hover:text-slate-300 transition-colors p-1.5 rounded-lg hover:bg-slate-800"
            title="Close panel"
          >
            <XCircle className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Main Content Area */}
      {viewMode === "findings" ? (
        <>
          {/* Severity summary bar */}
          {detail.status === "complete" && (
            <div className="flex gap-2.5 p-3.5 border-b border-slate-800/80 bg-slate-950/40 flex-wrap">
              {(["critical", "high", "medium", "low", "info"] as Sev[]).map(sev => {
                const count = bySev(sev).length;
                const cfg = SEV_CONFIG[sev];
                return (
                  <div key={sev} className={`flex items-center gap-1.5 px-2.5 py-1 rounded-lg border text-xs ${cfg.bg} ${cfg.color}`}>
                    <span className={`w-2 h-2 rounded-full ${cfg.dot}`} />
                    <span className="font-semibold">{count}</span> {cfg.label}
                  </div>
                );
              })}
            </div>
          )}

          {/* Findings list */}
          <div className="flex-1 overflow-y-auto p-4 space-y-2">
            {detail.status === "running" && (
              <div className="flex items-center gap-3 text-amber-400 bg-amber-500/10 border border-amber-500/20 rounded-lg p-3.5 text-sm">
                <Loader2 className="w-4 h-4 animate-spin shrink-0" />
                Scan in progress — evaluating security headers, CORS, sensitive paths & injections…
              </div>
            )}
            {detail.status === "error" && (
              <div className="bg-rose-500/10 border border-rose-500/20 rounded-lg p-3.5 text-sm text-rose-400">
                {detail.error || "An error occurred during scanning."}
              </div>
            )}
            {groups.length === 0 && detail.status === "complete" && (
              <div className="flex flex-col items-center gap-2 py-16 text-emerald-400">
                <ShieldCheck className="w-12 h-12" />
                <p className="text-sm font-semibold">No vulnerabilities detected</p>
                <p className="text-xs text-slate-500">Target matches baseline security configurations.</p>
              </div>
            )}
            {groups.map(g => (
              <div key={g.key}>
                <div className={`text-[10px] font-mono uppercase font-bold mb-1.5 mt-2 ${SEV_CONFIG[g.key as Sev].color}`}>
                  {SEV_CONFIG[g.key as Sev].label} · {g.items.length}
                </div>
                <div className="space-y-1.5">
                  {g.items.map(f => <FindingCard key={f.id} finding={f} />)}
                </div>
              </div>
            ))}
          </div>
        </>
      ) : (
        /* Executive Audit Report View */
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {/* Action Ribbon */}
          <div className="flex items-center justify-between bg-slate-900/60 border border-slate-800 rounded-xl p-3.5 no-print">
            <div>
              <div className="text-xs font-semibold text-slate-200">Report</div>
              <div className="text-[11px] text-slate-400">Export or print scan report</div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={handleCopyReport}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
              >
                {copied ? <CheckCheck className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? "Copied" : "Copy Markdown"}
              </button>
              <button
                onClick={handleExportMarkdown}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
              >
                <Download className="w-3.5 h-3.5 text-cyan-400" />
                Export .md
              </button>
              <button
                onClick={handleExportJson}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
              >
                <Download className="w-3.5 h-3.5 text-emerald-400" />
                JSON
              </button>
              <button
                onClick={() => window.print()}
                className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white transition-all shadow-md shadow-cyan-950"
              >
                <Printer className="w-3.5 h-3.5" />
                Print / PDF
              </button>
            </div>
          </div>

          {/* Report Cover / Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="md:col-span-2 bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm">
              <div className="text-[10px] font-mono uppercase text-slate-400 mb-1">Target</div>
              <div className="text-base font-bold font-mono text-slate-100 truncate">{detail.target_url}</div>
              <div className="mt-3 flex items-center gap-3">
                <GradeBadge grade={detail.grade} score={detail.score} />
                <span className="text-xs text-slate-400 font-mono">Scan #{detail.id}</span>
              </div>
            </div>

            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm">
              <div className="text-[10px] font-mono uppercase text-slate-400 mb-1">Pages Crawled</div>
              <div className="text-2xl font-bold font-mono text-cyan-400">{detail.pages_crawled}</div>
              <div className="text-xs text-slate-500 mt-1">Depth 2</div>
            </div>

            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm">
              <div className="text-[10px] font-mono uppercase text-slate-400 mb-1">Findings</div>
              <div className={`text-2xl font-bold font-mono ${detail.findings_count > 0 ? "text-rose-400" : "text-emerald-400"}`}>
                {detail.findings_count}
              </div>
              <div className="text-xs text-slate-500 mt-1">Total issues</div>
            </div>
          </div>

          {/* Severity Matrix */}
          <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-5 space-y-3">
            <div className="text-xs font-semibold text-slate-200">Severity Breakdown</div>
            <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
              {(["critical", "high", "medium", "low", "info"] as Sev[]).map(sev => {
                const count = bySev(sev).length;
                const cfg = SEV_CONFIG[sev];
                return (
                  <div key={sev} className={`p-3 rounded-lg border ${cfg.bg}`}>
                    <div className={`text-[10px] font-mono font-bold ${cfg.color}`}>{cfg.label}</div>
                    <div className={`text-xl font-bold font-mono mt-1 ${cfg.color}`}>{count}</div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Ordered Findings Section */}
          <div className="space-y-4">
            <div className="text-xs font-semibold text-slate-200 flex items-center justify-between">
              <span>Findings (High to Low)</span>
              <span className="text-[10px] text-slate-500 font-mono">{detail.findings.length} findings</span>
            </div>

            {detail.findings.map((f, idx) => (
              <div key={f.id} className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-2.5">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-slate-500 font-mono text-xs">#{idx + 1}</span>
                    <span className="font-semibold text-sm text-slate-100">{f.title}</span>
                    <SevBadge severity={f.severity} />
                  </div>
                  <span className="text-[10px] font-mono text-slate-500 shrink-0">{f.check_name}</span>
                </div>

                <div className="text-xs text-slate-400 font-mono truncate">
                  Endpoint: <span className="text-slate-200">{f.url}</span>
                </div>

                <div className="bg-slate-950/70 rounded-lg p-2.5 border border-slate-800/80">
                  <div className="text-[10px] font-mono uppercase text-slate-500 mb-1">Evidence</div>
                  <pre className="text-xs text-slate-300 font-mono whitespace-pre-wrap break-words">{f.evidence}</pre>
                </div>

                <div className="text-xs text-slate-300">
                  <span className="text-slate-500 font-semibold">Recommended Fix: </span>
                  {f.remediation}
                </div>

                <div className="text-[10px] font-mono text-slate-500 pt-1 border-t border-slate-800/60">
                  OWASP Category: <span className="text-slate-400">{f.owasp_category}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <ConfirmModal
        isOpen={confirmDelete}
        onClose={() => setConfirmDelete(false)}
        onConfirm={async () => {
          if (!detail) return;
          setDeleting(true);
          try {
            await deleteWebScan(detail.id);
            setConfirmDelete(false);
            onDeleted?.();
            onClose();
          } catch (e) {
            console.error("Delete web scan failed:", e);
          } finally {
            setDeleting(false);
          }
        }}
        title="Delete audit record"
        message="Delete this audit record from history? This cannot be undone."
        confirmLabel="Delete"
        loading={deleting}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Scan history list
// ---------------------------------------------------------------------------
function ScanHistoryRow({
  scan,
  active,
  onClick,
}: {
  scan: WebScanItem;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`w-full text-left flex items-center gap-3 px-3.5 py-3 rounded-lg border transition-all ${
        active
          ? "bg-cyan-500/10 border-cyan-500/30 shadow shadow-cyan-950"
          : "border-slate-800 hover:border-slate-700 hover:bg-slate-800/30"
      }`}
    >
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <Globe className="w-3.5 h-3.5 text-slate-500 shrink-0" />
          <span className="text-xs font-mono text-slate-300 truncate">{scan.target_url}</span>
        </div>
        <div className="flex items-center gap-2 mt-0.5">
          <StatusPill status={scan.status} />
          {scan.status === "complete" && (
            <GradeBadge grade={scan.grade} score={scan.score} />
          )}
          <span className="text-[10px] text-slate-600">
            {scan.created_at ? new Date(scan.created_at).toLocaleTimeString() : ""}
          </span>
        </div>
      </div>
      <ChevronRight className="w-4 h-4 text-slate-600 shrink-0" />
    </button>
  );
}

// ---------------------------------------------------------------------------
// Main View
// ---------------------------------------------------------------------------
export const WebScannerView: React.FC = () => {
  const [targetUrl, setTargetUrl] = useState("http://127.0.0.1:5000");
  const [scans, setScans] = useState<WebScanItem[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [launching, setLaunching] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loadingHistory, setLoadingHistory] = useState(true);
  const [confirmClear, setConfirmClear] = useState(false);
  const [clearing, setClearing] = useState(false);

  const loadHistory = useCallback(async () => {
    try {
      const list = await fetchWebScans(50);
      setScans(list);
      if (list.length > 0 && selectedScanId === null) {
        setSelectedScanId(list[0].id);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingHistory(false);
    }
  }, [selectedScanId]);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  const handleStartScan = async () => {
    setError(null);
    if (!targetUrl.trim()) return;
    setLaunching(true);
    try {
      const res = await startWebScan(targetUrl.trim());
      setSelectedScanId(res.scan_id);
      await loadHistory();
    } catch (e: any) {
      setError(e.message ?? "Failed to start audit");
    } finally {
      setLaunching(false);
    }
  };

  return (
    <div className="flex flex-col h-full bg-[#080c14] text-slate-100 rounded-xl overflow-hidden border border-slate-800">
      {/* Top bar */}
      <div className="border-b border-slate-800 px-6 py-4 flex items-center justify-between shrink-0 bg-[#0d1322]">
        <div className="flex items-center gap-2.5">
          <Globe className="w-4 h-4 text-cyan-400" />
          <h1 className="text-sm font-semibold text-slate-200">Web Security & OWASP Auditor</h1>
          <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 font-mono uppercase tracking-wider">
            OWASP ASVS
          </span>
        </div>
        <button
          onClick={loadHistory}
          className="text-slate-400 hover:text-slate-200 transition-colors p-1.5 rounded-lg hover:bg-slate-800"
          title="Refresh history"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {/* URL input bar */}
      <div className="px-6 py-4 border-b border-slate-800 bg-[#0d1322]/50 shrink-0">
        <div className="flex gap-2.5">
          <div className="flex-1 relative">
            <Globe className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 pointer-events-none" />
            <input
              type="url"
              value={targetUrl}
              onChange={e => setTargetUrl(e.target.value)}
              onKeyDown={e => e.key === "Enter" && !launching && handleStartScan()}
              placeholder="http://127.0.0.1:5000"
              className="w-full pl-10 pr-4 py-2.5 rounded-lg bg-slate-900 border border-slate-700/80 text-sm font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 transition-all shadow-inner"
            />
          </div>
          <button
            onClick={handleStartScan}
            disabled={launching || !targetUrl.trim()}
            className="flex items-center gap-2 px-5 py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 disabled:cursor-not-allowed text-white text-sm font-semibold transition-all shadow-lg shadow-cyan-950"
          >
            {launching ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Play className="w-4 h-4" />
            )}
            {launching ? "Auditing…" : "Run Audit"}
          </button>
        </div>
        {error && (
          <p className="mt-2 text-xs text-rose-400 flex items-center gap-1.5">
            <XCircle className="w-3.5 h-3.5 shrink-0" />
            {error}
          </p>
        )}
        <div className="mt-2.5 flex flex-wrap items-center gap-2">
          <span className="text-[10px] text-slate-500 font-medium">Presets:</span>
          {[
            { label: "Banking Target (:5000)", url: "http://127.0.0.1:5000" },
            { label: "Local Server (:8000)", url: "http://127.0.0.1:8000" },
            { label: "Network Gateway (:192.168.1.1)", url: "http://192.168.1.1" },
          ].map(p => (
            <button
              key={p.url}
              onClick={() => setTargetUrl(p.url)}
              className="px-2.5 py-1 rounded-md bg-slate-900 hover:bg-slate-800 text-[10px] font-mono text-slate-300 hover:text-cyan-400 transition-colors border border-slate-800"
            >
              {p.label}
            </button>
          ))}
          <span className="text-[10px] text-slate-600 ml-1">— localhost / private subnets strictly enforced</span>
        </div>
      </div>

      {/* Body: history + detail split */}
      <div className="flex flex-1 overflow-hidden">
        {/* Left: scan history */}
        <div className="w-80 border-r border-slate-800 flex flex-col overflow-hidden shrink-0 bg-[#0a0f1c]">
          <div className="px-4 py-2.5 text-[10px] font-mono uppercase text-slate-500 border-b border-slate-800 flex items-center justify-between">
            <span>Audit History ({scans.length})</span>
            {scans.length > 0 && (
              <button
                onClick={() => setConfirmClear(true)}
                className="text-slate-500 hover:text-rose-400 transition-colors flex items-center gap-1 normal-case font-sans text-xs"
                title="Clear all audit history"
              >
                <Trash2 className="w-3 h-3" />
                Clear
              </button>
            )}
          </div>
          <div className="flex-1 overflow-y-auto p-2.5 space-y-1.5">
            {loadingHistory && scans.length === 0 && (
              <div className="flex justify-center py-12">
                <Loader2 className="w-5 h-5 animate-spin text-slate-600" />
              </div>
            )}
            {!loadingHistory && scans.length === 0 && (
              <div className="text-center py-12 text-slate-600 text-xs">
                <Globe className="w-8 h-8 mx-auto mb-2 opacity-30" />
                No audits performed yet
              </div>
            )}
            {scans.map(s => (
              <ScanHistoryRow
                key={s.id}
                scan={s}
                active={selectedScanId === s.id}
                onClick={() => setSelectedScanId(s.id)}
              />
            ))}
          </div>
        </div>

        {/* Right: detail or empty state */}
        {selectedScanId !== null ? (
          <ScanDetailPanel
            key={selectedScanId}
            scanId={selectedScanId}
            onClose={() => setSelectedScanId(null)}
            onDeleted={loadHistory}
          />
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center gap-4 text-slate-700 bg-[#080c14]">
            <div className="w-16 h-16 rounded-2xl bg-slate-900 border border-slate-800 flex items-center justify-center">
              <Shield className="w-8 h-8 text-slate-700" />
            </div>
            <p className="text-sm font-medium text-slate-500">Select an audit from history or enter a target URL</p>
          </div>
        )}
      </div>

      <ConfirmModal
        isOpen={confirmClear}
        onClose={() => setConfirmClear(false)}
        onConfirm={async () => {
          setClearing(true);
          try {
            await clearWebScans();
            setConfirmClear(false);
            setSelectedScanId(null);
            await loadHistory();
          } catch (e) {
            console.error("Failed to clear web scans:", e);
          } finally {
            setClearing(false);
          }
        }}
        title="Clear audit history"
        message="Delete all web security audit records? This cannot be undone."
        confirmLabel="Clear"
        loading={clearing}
      />
    </div>
  );
};
