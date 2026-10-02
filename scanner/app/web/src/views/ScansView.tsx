import React, { useEffect, useState } from "react";
import {
  FileText,
  Search,
  RefreshCw,
  X,
  Trash2,
  Copy,
  Check,
} from "lucide-react";
import {
  type ScanItem,
  type ScanDetail,
  fetchScans,
  fetchScanDetail,
  releaseScan,
  deleteScan,
  clearScans,
} from "../api";
import { ConfirmModal } from "../components/ConfirmModal";

export const ScansView: React.FC = () => {
  const [scans, setScans] = useState<ScanItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [verdictFilter, setVerdictFilter] = useState<string>("all");
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [scanDetail, setScanDetail] = useState<ScanDetail | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);
  const [clearing, setClearing] = useState(false);

  // Dialog states
  const [actionConfirm, setActionConfirm] = useState<{
    type: "release" | "delete";
    scanId: number;
    filename: string;
  } | null>(null);
  const [actionLoading, setActionLoading] = useState(false);

  const loadScans = async () => {
    setLoading(true);
    try {
      const data = await fetchScans(100);
      setScans(data);
    } catch (err) {
      console.error("Failed to fetch scans:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadScans();
  }, []);

  const handleRowClick = async (id: number) => {
    setSelectedScanId(id);
    setLoadingDetail(true);
    try {
      const detail = await fetchScanDetail(id);
      setScanDetail(detail);
    } catch (err) {
      console.error("Failed to load scan detail:", err);
    } finally {
      setLoadingDetail(false);
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const handleConfirmAction = async () => {
    if (!actionConfirm) return;
    setActionLoading(true);
    try {
      if (actionConfirm.type === "release") {
        await releaseScan(actionConfirm.scanId);
      } else {
        await deleteScan(actionConfirm.scanId);
      }
      setActionConfirm(null);
      // Reload scans and refresh detail if open
      await loadScans();
      if (selectedScanId === actionConfirm.scanId) {
        const updated = await fetchScanDetail(actionConfirm.scanId);
        setScanDetail(updated);
      }
    } catch (err) {
      console.error("Action error:", err);
    } finally {
      setActionLoading(false);
    }
  };

  const handleClearHistory = async () => {
    setClearing(true);
    try {
      await clearScans();
      setConfirmClear(false);
      setSelectedScanId(null);
      setScanDetail(null);
      await loadScans();
    } catch (err) {
      console.error("Clear scans error:", err);
    } finally {
      setClearing(false);
    }
  };

  const filteredScans = scans.filter((s) => {
    const matchesSearch =
      s.filename.toLowerCase().includes(search.toLowerCase()) ||
      s.sha256.toLowerCase().includes(search.toLowerCase());
    const matchesVerdict =
      verdictFilter === "all" ? true : s.verdict === verdictFilter;
    return matchesSearch && matchesVerdict;
  });

  return (
    <div className="space-y-6 max-w-7xl mx-auto relative">
      {/* Header controls: Search & Filter */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-4">
        <div className="flex items-center gap-3 flex-1 max-w-md">
          <div className="relative flex-1">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search by file name or SHA-256..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-4 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
          <select
            value={verdictFilter}
            onChange={(e) => setVerdictFilter(e.target.value)}
            className="px-3 py-2 rounded-lg bg-slate-900 border border-slate-800 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Verdicts</option>
            <option value="pass">Pass</option>
            <option value="review">Review</option>
            <option value="block">Block</option>
          </select>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setConfirmClear(true)}
            disabled={scans.length === 0}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-900 hover:bg-rose-500/10 border border-slate-800 hover:border-rose-500/30 text-xs text-slate-400 hover:text-rose-400 transition disabled:opacity-40 disabled:cursor-not-allowed"
            title="Clear all scan history"
          >
            <Trash2 className="w-3.5 h-3.5" />
            Clear history
          </button>
          <button
            onClick={loadScans}
            disabled={loading}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 text-xs text-slate-300 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      {/* Scans Table */}
      <div className="rounded-xl border border-slate-800 bg-[#0f172a] overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300">
            <thead className="bg-[#090d16] text-[11px] uppercase tracking-wider text-slate-400 border-b border-slate-800 font-mono">
              <tr>
                <th className="py-3 px-4">ID</th>
                <th className="py-3 px-4">File Name</th>
                <th className="py-3 px-4">SHA-256 Digest</th>
                <th className="py-3 px-4">Score</th>
                <th className="py-3 px-4">Verdict</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/80">
              {loading && scans.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-10 text-slate-500">
                    Loading scan records...
                  </td>
                </tr>
              ) : filteredScans.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-10 text-slate-500">
                    No scans found matching criteria.
                  </td>
                </tr>
              ) : (
                filteredScans.map((s) => (
                  <tr
                    key={s.id}
                    onClick={() => handleRowClick(s.id)}
                    className="hover:bg-slate-800/50 cursor-pointer transition"
                  >
                    <td className="py-3 px-4 font-mono text-slate-400">#{s.id}</td>
                    <td className="py-3 px-4 font-medium text-slate-100 flex items-center gap-2">
                      <FileText className="w-4 h-4 text-cyan-400" />
                      {s.filename}
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-400">
                      <div className="flex items-center gap-1.5">
                        <span>{s.sha256.slice(0, 10)}...{s.sha256.slice(-6)}</span>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleCopy(s.sha256);
                          }}
                          className="hover:text-cyan-400 transition"
                          title="Copy SHA-256"
                        >
                          {copiedHash === s.sha256 ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </td>
                    <td className="py-3 px-4 font-mono font-bold">
                      <span
                        className={
                          (s.score || 0) >= 70
                            ? "text-rose-400"
                            : (s.score || 0) >= 30
                            ? "text-amber-400"
                            : "text-emerald-400"
                        }
                      >
                        {s.score ?? "-"}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      {s.verdict ? (
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase tracking-wide ${
                            s.verdict === "pass"
                              ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                              : s.verdict === "review"
                              ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                              : "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                          }`}
                        >
                          {s.verdict}
                        </span>
                      ) : (
                        <span className="text-slate-500 font-mono text-[10px]">Scanning</span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {s.created_at ? new Date(s.created_at).toLocaleString() : "-"}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleRowClick(s.id);
                        }}
                        className="text-cyan-400 hover:text-cyan-300 font-medium text-xs"
                      >
                        Details &rarr;
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Side Slide-Over Drawer for Selected Scan Details */}
      {selectedScanId && (
        <div className="fixed inset-0 z-50 overflow-hidden bg-black/60 backdrop-blur-sm flex justify-end">
          <div className="w-full max-w-2xl bg-[#0d1322] border-l border-slate-800 shadow-2xl h-full flex flex-col">
            {/* Drawer Header */}
            <div className="p-6 border-b border-slate-800 flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-bold text-slate-100">
                    {scanDetail?.filename || "Scan Details"}
                  </h3>
                  {scanDetail?.verdict && (
                    <span
                      className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                        scanDetail.verdict === "pass"
                          ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                          : scanDetail.verdict === "review"
                          ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                          : "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                      }`}
                    >
                      {scanDetail.verdict}
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-400 font-mono mt-1 truncate">
                  SHA-256: {scanDetail?.sha256}
                </p>
              </div>
              <button
                onClick={() => {
                  setSelectedScanId(null);
                  setScanDetail(null);
                }}
                className="p-1.5 rounded-lg hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Drawer Content */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              {loadingDetail ? (
                <div className="py-20 text-center text-slate-500 flex flex-col items-center">
                  <RefreshCw className="w-6 h-6 animate-spin text-cyan-400 mb-2" />
                  Loading checker analysis...
                </div>
              ) : scanDetail ? (
                <>
                  {/* Summary Metric Cards */}
                  <div className="grid grid-cols-3 gap-3">
                    <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                      <div className="text-[10px] uppercase font-mono text-slate-400">Total Score</div>
                      <div className="text-lg font-bold font-mono text-cyan-400 mt-1">
                        {scanDetail.score} / 100
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                      <div className="text-[10px] uppercase font-mono text-slate-400">File Size</div>
                      <div className="text-lg font-bold font-mono text-slate-200 mt-1">
                        {(scanDetail.size / 1024).toFixed(1)} KB
                      </div>
                    </div>
                    <div className="p-3 rounded-lg bg-slate-900 border border-slate-800">
                      <div className="text-[10px] uppercase font-mono text-slate-400">Status</div>
                      <div className="text-lg font-bold font-mono text-emerald-400 mt-1 capitalize">
                        {scanDetail.status}
                      </div>
                    </div>
                  </div>

                  {/* Per-Check Breakdown */}
                  <div>
                    <h4 className="text-xs uppercase font-mono font-bold text-slate-400 mb-3 tracking-wider">
                      Individual Engine Findings
                    </h4>
                    <div className="space-y-3">
                      {scanDetail.check_results?.map((res) => (
                        <div
                          key={res.id}
                          className="p-4 rounded-lg bg-slate-900/80 border border-slate-800 text-xs"
                        >
                          <div className="flex items-center justify-between mb-2">
                            <span className="font-semibold text-slate-200 uppercase tracking-wide text-[11px]">
                              {res.checker.replace("_", " ")}
                            </span>
                            <div className="flex items-center gap-2">
                              <span
                                className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                                  res.status === "pass"
                                    ? "bg-emerald-500/10 text-emerald-400"
                                    : res.status === "warn"
                                    ? "bg-amber-500/10 text-amber-400"
                                    : res.status === "fail"
                                    ? "bg-rose-500/10 text-rose-400"
                                    : "bg-slate-800 text-slate-400"
                                }`}
                              >
                                {res.status}
                              </span>
                              <span className="font-mono text-slate-400 font-bold">
                                {res.score > 0 ? `+${res.score}` : res.score}
                              </span>
                            </div>
                          </div>

                          {/* Specific detail render per checker */}
                          <div className="text-slate-400 space-y-1 font-mono text-[11px] bg-slate-950/60 p-2.5 rounded border border-slate-800/60">
                            {res.checker === "signature" && (
                              <>
                                <div>Signed: {res.details?.signed ? "Yes" : "No"}</div>
                                <div>Verified: {res.details?.verified ? "Valid" : "Invalid/Untrusted"}</div>
                                <div>Publisher: {res.details?.signer || "None"}</div>
                                <div>Digest Algorithm: {res.details?.digest_algorithm || "None"}</div>
                                <div>Trusted Signer: {res.details?.trusted ? "Yes" : "No"}</div>
                              </>
                            )}

                            {res.checker === "vendor_hash" && (
                              <>
                                <div>Given Hash: {res.details?.given_digest || "N/A"}</div>
                                <div>Calculated: {res.details?.calculated_digest || "N/A"}</div>
                                <div>Match: {res.details?.match ? "Yes" : "No"}</div>
                                <div className="truncate">Feed URL: {res.details?.source_url || "N/A"}</div>
                              </>
                            )}

                            {res.checker === "circl" && (
                              <>
                                <div>Known in CIRCL: {res.details?.known ? "Yes (Benign)" : "No"}</div>
                                {res.details?.source && <div>Source: {res.details.source}</div>}
                              </>
                            )}

                            {res.checker === "malware_bazaar" && (
                              <>
                                <div>Malware Hit: {res.status === "fail" ? "Yes" : "No"}</div>
                                {res.details?.signature && <div>Signature: {res.details.signature}</div>}
                                {res.details?.tags && <div>Tags: {res.details.tags.join(", ")}</div>}
                              </>
                            )}

                            {res.checker === "clamav" && (
                              <>
                                <div>Clean: {res.details?.clean ? "Yes" : "Infected"}</div>
                                {res.details?.signature && <div>Virus Name: {res.details.signature}</div>}
                                {res.details?.error && <div className="text-amber-400">Notice: {res.details.error}</div>}
                              </>
                            )}

                            {res.checker === "yara" && (
                              <>
                                <div>Rules Matched: {res.details?.count || 0}</div>
                                {res.details?.rules?.length > 0 && (
                                  <div>Signatures: {res.details.rules.join(", ")}</div>
                                )}
                              </>
                            )}

                            {res.checker === "pe_static" && (
                              <>
                                <div>Overall Entropy: {res.details?.overall_entropy}</div>
                                <div>Packer Detected: {res.details?.packer_detected ? "Yes" : "No"}</div>
                                {res.details?.packer_sections?.length > 0 && (
                                  <div>Packer Sections: {res.details.packer_sections.join(", ")}</div>
                                )}
                                {res.details?.suspicious_apis?.length > 0 && (
                                  <div>Suspicious APIs: {res.details.suspicious_apis.join(", ")}</div>
                                )}
                              </>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </>
              ) : null}
            </div>

            {/* Drawer Actions Footer */}
            {scanDetail && (
              <div className="p-4 border-t border-slate-800 bg-slate-900/90 flex items-center justify-end gap-3">
                <button
                  onClick={() =>
                    setActionConfirm({
                      type: "release",
                      scanId: scanDetail.id,
                      filename: scanDetail.filename,
                    })
                  }
                  className="px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs transition"
                >
                  Release to Clean
                </button>
                <button
                  onClick={() =>
                    setActionConfirm({
                      type: "delete",
                      scanId: scanDetail.id,
                      filename: scanDetail.filename,
                    })
                  }
                  className="px-3.5 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white font-medium text-xs transition flex items-center gap-1.5"
                >
                  <Trash2 className="w-3.5 h-3.5" />
                  Delete File
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Confirmation Modal */}
      {actionConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-sm rounded-xl bg-slate-900 border border-slate-800 p-5 shadow-2xl">
            <h4 className="text-sm font-bold text-slate-100 mb-2">
              Confirm {actionConfirm.type === "release" ? "Release" : "Deletion"}
            </h4>
            <p className="text-xs text-slate-400 mb-4">
              Are you sure you want to{" "}
              {actionConfirm.type === "release"
                ? `release ${actionConfirm.filename} to the clean directory?`
                : `permanently delete ${actionConfirm.filename}?`}
            </p>
            <div className="flex items-center justify-end gap-2 text-xs">
              <button
                onClick={() => setActionConfirm(null)}
                className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700 transition"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmAction}
                disabled={actionLoading}
                className={`px-3 py-1.5 rounded-lg text-white font-semibold transition ${
                  actionConfirm.type === "release"
                    ? "bg-emerald-600 hover:bg-emerald-500"
                    : "bg-rose-600 hover:bg-rose-500"
                }`}
              >
                {actionLoading ? "Processing..." : "Confirm"}
              </button>
            </div>
          </div>
        </div>
      )}

      <ConfirmModal
        isOpen={confirmClear}
        onClose={() => setConfirmClear(false)}
        onConfirm={handleClearHistory}
        title="Clear scan history"
        message="Delete all scan records and logs? This cannot be undone."
        confirmLabel="Clear"
        loading={clearing}
      />
    </div>
  );
};
