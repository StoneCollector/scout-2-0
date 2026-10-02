import React, { useEffect, useState } from "react";
import { Link, useLocation } from "react-router-dom";
import {
  Activity,
  FileSearch,
  ClipboardList,
  BarChart3,
  ShieldCheck,
  Power,
  RefreshCw,
  FolderOpen,
  Globe,
  Settings2,
} from "lucide-react";
import {
  fetchSystemClamav,
  triggerStartClamav,
  fetchWatchFolder,
  type ClamAvStatus,
  type WatchFolderInfo,
} from "../api";
import { WatchFolderModal } from "./WatchFolderModal";

interface LayoutProps {
  children: React.ReactNode;
  wsConnected: boolean;
}

export const Layout: React.FC<LayoutProps> = ({ children, wsConnected }) => {
  const location = useLocation();
  const [clamav, setClamav] = useState<ClamAvStatus | null>(null);
  const [startingClamav, setStartingClamav] = useState(false);
  const [watchFolder, setWatchFolderState] = useState<WatchFolderInfo | null>(null);
  const [folderModalOpen, setFolderModalOpen] = useState(false);

  const loadStatus = async () => {
    try {
      const [st, wf] = await Promise.all([
        fetchSystemClamav().catch(() => null),
        fetchWatchFolder().catch(() => null),
      ]);
      if (st) setClamav(st);
      if (wf) setWatchFolderState(wf);
    } catch (err) {
      console.error("Status check failed:", err);
    }
  };

  useEffect(() => {
    loadStatus();
    const interval = setInterval(loadStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleStartClamav = async () => {
    setStartingClamav(true);
    try {
      const res = await triggerStartClamav();
      setClamav(res.status);
    } catch (err) {
      console.error("Failed to start ClamAV:", err);
    } finally {
      setStartingClamav(false);
    }
  };

  const navLinks = [
    { name: "Files", path: "/", icon: Activity },
    { name: "Scans", path: "/scans", icon: FileSearch },
    { name: "Web Scanner", path: "/webscan", icon: Globe },
    { name: "Reports", path: "/tasks", icon: ClipboardList },
    { name: "Stats", path: "/stats", icon: BarChart3 },
  ];

  return (
    <div className="flex h-screen bg-[#080c14] text-slate-100 overflow-hidden font-sans">
      {/* Sidebar */}
      <aside className="w-60 bg-[#0d1322] border-r border-slate-800/80 flex flex-col justify-between no-print select-none shrink-0">
        <div>
          {/* Scout Branding */}
          <div className="h-16 px-5 flex items-center gap-3 border-b border-slate-800/80">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-cyan-600 to-emerald-400 flex items-center justify-center shadow-md shadow-cyan-950/40">
              <ShieldCheck className="w-4 h-4 text-white" />
            </div>
            <div className="font-bold text-base tracking-wide text-slate-100">
              Scout
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="p-3 space-y-1">
            {navLinks.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path;
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  className={`flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-medium transition-all ${
                    isActive
                      ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20"
                      : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
                  }`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? "text-cyan-400" : "text-slate-400"}`} />
                  {item.name}
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Status footer */}
        <div className="p-3 border-t border-slate-800/80 space-y-2 bg-[#0a0f1c]">
          {/* Watch Folder Card */}
          <div className="rounded-lg bg-slate-900 border border-slate-800 p-2.5">
            <div className="flex items-center justify-between text-xs mb-1">
              <span className="text-slate-400 flex items-center gap-1.5">
                <FolderOpen className="w-3.5 h-3.5 text-cyan-400" /> Watch folder
              </span>
              <button
                onClick={() => setFolderModalOpen(true)}
                className="text-slate-400 hover:text-cyan-300 p-0.5 rounded hover:bg-slate-800 transition"
                title="Change folder"
              >
                <Settings2 className="w-3.5 h-3.5" />
              </button>
            </div>
            <div className="text-[11px] text-slate-300 font-mono truncate" title={watchFolder?.watch_dir || ""}>
              {watchFolder ? (
                watchFolder.is_default ? "inbox/ (default)" : (watchFolder.watch_dir.split(/[/\\]/).pop() || watchFolder.watch_dir)
              ) : (
                "inbox/"
              )}
            </div>
          </div>

          {/* ClamAV Card */}
          <div className="rounded-lg bg-slate-900 border border-slate-800 p-2.5">
            <div className="flex items-center justify-between text-xs mb-1.5">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Power className="w-3.5 h-3.5 text-slate-500" /> ClamAV
              </span>
              <span
                className={`px-1.5 py-0.5 rounded text-[10px] font-mono uppercase font-semibold ${
                  clamav?.status === "ready"
                    ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                    : clamav?.status === "starting"
                    ? "bg-amber-500/10 text-amber-400 border border-amber-500/20 animate-pulse"
                    : "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                }`}
              >
                {clamav?.status || "offline"}
              </span>
            </div>
            {clamav?.status !== "ready" && (
              <button
                onClick={handleStartClamav}
                disabled={startingClamav || clamav?.status === "starting"}
                className="w-full flex items-center justify-center gap-1.5 py-1 px-2 rounded text-[11px] font-medium bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition disabled:opacity-50"
              >
                <RefreshCw className={`w-3 h-3 ${startingClamav ? "animate-spin" : ""}`} />
                {startingClamav ? "Starting..." : "Start ClamAV"}
              </button>
            )}
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Navbar */}
        <header className="h-14 bg-[#0d1322]/80 backdrop-blur border-b border-slate-800 px-6 flex items-center justify-between no-print z-10 shrink-0">
          <div className="flex items-center gap-3">
            <h1 className="text-sm font-semibold text-slate-200">
              {navLinks.find((l) => l.path === location.pathname)?.name || "Scout"}
            </h1>
          </div>

          {/* Status indicators */}
          <div className="flex items-center gap-3 text-xs">
            <div className="flex items-center gap-2 px-2.5 py-1 rounded-full bg-slate-900 border border-slate-800 text-slate-400">
              <span
                className={`w-2 h-2 rounded-full ${
                  wsConnected ? "bg-emerald-400" : "bg-rose-500"
                }`}
              />
              <span className="text-xs">
                {wsConnected ? "Connected" : "Disconnected"}
              </span>
            </div>

            {/* Print action if on tasks */}
            {location.pathname === "/tasks" && (
              <button
                onClick={() => window.print()}
                className="px-3 py-1 text-xs rounded-md bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition"
              >
                Print Report
              </button>
            )}
          </div>
        </header>

        {/* Page Views Render */}
        <main className="flex-1 overflow-y-auto p-6 bg-[#080c14]">{children}</main>
      </div>

      {/* Watch Folder Configuration Modal */}
      <WatchFolderModal
        isOpen={folderModalOpen}
        onClose={() => setFolderModalOpen(false)}
        watchFolder={watchFolder}
        onUpdated={(newWf) => setWatchFolderState(newWf)}
      />
    </div>
  );
};
