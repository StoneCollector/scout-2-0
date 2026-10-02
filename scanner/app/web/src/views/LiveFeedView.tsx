import { useEffect, useState } from "react";
import {
  CheckCircle2,
  AlertTriangle,
  XCircle,
  MinusCircle,
  Loader2,
  Clock,
  FileCode,
  FolderSymlink,
  Trash2,
} from "lucide-react";
import { fetchWatchFolder, type WatchFolderInfo } from "../api";
import { ConfirmModal } from "../components/ConfirmModal";

export interface ActiveScanCard {
  scan_id: number;
  filename: string;
  sha256?: string;
  size?: number;
  checks: Record<string, { status: string; score: number; details?: any }>;
  verdict?: "pass" | "review" | "block";
  score?: number;
  reasons?: string[];
  destination?: string;
  timestamp: string;
}

const CHECKER_NAMES = [
  { id: "signature", label: "Signature" },
  { id: "vendor_hash", label: "Vendor Hash" },
  { id: "circl", label: "CIRCL" },
  { id: "malware_bazaar", label: "MalwareBazaar" },
  { id: "clamav", label: "ClamAV" },
  { id: "yara", label: "YARA Rules" },
  { id: "pe_static", label: "PE Static" },
];

interface LiveFeedViewProps {
  activeCards: ActiveScanCard[];
  onClear?: () => void;
}

export const LiveFeedView: React.FC<LiveFeedViewProps> = ({ activeCards, onClear }) => {
  const [folderInfo, setFolderInfo] = useState<WatchFolderInfo | null>(null);
  const [confirmClear, setConfirmClear] = useState(false);

  useEffect(() => {
    fetchWatchFolder().then(setFolderInfo).catch(() => {});
  }, [activeCards]);

  const folderName = folderInfo
    ? (folderInfo.watch_dir.split(/[/\\]/).pop() || folderInfo.watch_dir)
    : "watch folder";

  return (
    <div className="space-y-4 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between p-4 rounded-xl bg-slate-900 border border-slate-800">
        <div>
          <h2 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400" />
            Live Monitor
            <span className="text-xs font-mono font-normal text-slate-400">
              ({folderName})
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Drop files into <span className="font-mono text-cyan-300">{folderName}</span> to scan
          </p>
        </div>
        <div className="flex items-center gap-2">
          {activeCards.length > 0 && onClear && (
            <button
              onClick={() => setConfirmClear(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-800/80 hover:bg-rose-500/10 hover:border-rose-500/30 text-slate-400 hover:text-rose-400 text-xs transition"
              title="Clear active feed items"
            >
              <Trash2 className="w-3.5 h-3.5" />
              Clear feed
            </button>
          )}
          <span className="px-2.5 py-1 rounded-md bg-slate-800 text-slate-300 text-xs font-mono">
            {activeCards.length} active
          </span>
        </div>
      </div>

      <ConfirmModal
        isOpen={confirmClear}
        onClose={() => setConfirmClear(false)}
        onConfirm={() => {
          onClear?.();
          setConfirmClear(false);
        }}
        title="Clear live feed"
        message="Remove all active items from the live feed display?"
        confirmLabel="Clear"
      />

      {/* Cards List */}
      {activeCards.length === 0 ? (
        <div className="flex flex-col items-center justify-center p-14 rounded-xl border border-dashed border-slate-800 bg-slate-900/20 text-center">
          <Clock className="w-8 h-8 text-slate-600 mb-2" />
          <h3 className="text-sm font-medium text-slate-300">No active scans</h3>
          <p className="text-xs text-slate-500 mt-0.5">
            Folder <span className="font-mono text-slate-400">{folderName}</span> is currently empty
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {activeCards.map((card) => {
            const isCompleted = !!card.verdict;
            return (
              <div
                key={card.scan_id}
                className="p-5 rounded-xl bg-[#0f172a] border border-slate-800 shadow-lg hover:border-slate-700 transition"
              >
                {/* Top card bar: filename, sha256 short, final verdict */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800/80">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-lg bg-slate-800 flex items-center justify-center text-cyan-400">
                      <FileCode className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="text-sm font-bold text-slate-100 flex items-center gap-2">
                        {card.filename}
                        <span className="text-[10px] text-slate-500 font-mono font-normal">
                          ID: #{card.scan_id}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                        SHA256: {card.sha256 ? `${card.sha256.slice(0, 16)}...${card.sha256.slice(-8)}` : "Computing..."}
                      </div>
                    </div>
                  </div>

                  {/* Verdict Badge */}
                  <div className="flex items-center gap-3">
                    {card.score !== undefined && (
                      <div className="text-right">
                        <div className="text-[10px] text-slate-500 uppercase font-mono">Threat Score</div>
                        <div
                          className={`text-sm font-bold font-mono ${
                            card.score >= 70
                              ? "text-rose-400"
                              : card.score >= 30
                              ? "text-amber-400"
                              : "text-emerald-400"
                          }`}
                        >
                          {card.score} / 100
                        </div>
                      </div>
                    )}

                    {card.verdict ? (
                      <span
                        className={`px-3 py-1.5 rounded-lg text-xs font-bold font-mono uppercase tracking-wider ${
                          card.verdict === "pass"
                            ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                            : card.verdict === "review"
                            ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                            : "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                        }`}
                      >
                        {card.verdict}
                      </span>
                    ) : (
                      <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                        <Loader2 className="w-3.5 h-3.5 animate-spin" />
                        SCANNING...
                      </span>
                    )}
                  </div>
                </div>

                {/* 7-Step Progress Stepper */}
                <div className="pt-4 grid grid-cols-2 sm:grid-cols-4 md:grid-cols-7 gap-2">
                  {CHECKER_NAMES.map((chk, idx) => {
                    const result = card.checks[chk.id];
                    let icon = <Clock className="w-4 h-4 text-slate-600" />;
                    let statusColor = "text-slate-500 border-slate-800 bg-slate-900/50";
                    let statusLabel = "Pending";

                    if (result) {
                      if (result.status === "pass") {
                        icon = <CheckCircle2 className="w-4 h-4 text-emerald-400" />;
                        statusColor = "text-emerald-300 border-emerald-500/20 bg-emerald-500/5";
                        statusLabel = "Pass";
                      } else if (result.status === "warn") {
                        icon = <AlertTriangle className="w-4 h-4 text-amber-400" />;
                        statusColor = "text-amber-300 border-amber-500/20 bg-amber-500/5";
                        statusLabel = `Warn (+${result.score})`;
                      } else if (result.status === "fail") {
                        icon = <XCircle className="w-4 h-4 text-rose-400" />;
                        statusColor = "text-rose-300 border-rose-500/20 bg-rose-500/5";
                        statusLabel = `Fail (+${result.score})`;
                      } else if (result.status === "skip") {
                        icon = <MinusCircle className="w-4 h-4 text-slate-500" />;
                        statusColor = "text-slate-400 border-slate-800 bg-slate-900/50";
                        statusLabel = "Skip";
                      }
                    } else if (!isCompleted && idx === Object.keys(card.checks).length) {
                      // Currently active step
                      icon = <Loader2 className="w-4 h-4 text-cyan-400 animate-spin" />;
                      statusColor = "text-cyan-300 border-cyan-500/30 bg-cyan-500/10";
                      statusLabel = "Checking...";
                    }

                    return (
                      <div
                        key={chk.id}
                        className={`p-2.5 rounded-lg border flex flex-col justify-between ${statusColor}`}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-[10px] font-semibold tracking-tight uppercase">
                            {chk.label}
                          </span>
                          {icon}
                        </div>
                        <div className="text-[10px] font-mono opacity-80">{statusLabel}</div>
                      </div>
                    );
                  })}
                </div>

                {/* Bottom metadata / Reasons if finished */}
                {card.reasons && card.reasons.length > 0 && (
                  <div className="mt-4 pt-3 border-t border-slate-800/60 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
                    <div className="text-slate-400 flex items-center gap-1.5 flex-wrap">
                      <span className="font-semibold text-slate-300">Findings:</span>
                      {card.reasons.map((r, i) => (
                        <span key={i} className="inline-block px-2 py-0.5 rounded bg-slate-800 text-[11px] text-slate-300">
                          {r}
                        </span>
                      ))}
                    </div>

                    {card.destination && (
                      <div className="text-slate-500 flex items-center gap-1 font-mono text-[11px] whitespace-nowrap">
                        <FolderSymlink className="w-3.5 h-3.5 text-slate-400" />
                        Moved to: <span className="text-slate-300">{card.destination.split("\\").pop()}</span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
