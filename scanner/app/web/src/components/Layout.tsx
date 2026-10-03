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
  Award,
  PanelLeftClose,
  PanelLeftOpen,
} from "lucide-react";
import {
  fetchSystemClamav,
  triggerStartClamav,
  fetchWatchFolder,
  fetchTrustedSigners,
  type ClamAvStatus,
  type WatchFolderInfo,
} from "../api";
import { WatchFolderModal } from "./WatchFolderModal";
import { TrustedSignersModal } from "./TrustedSignersModal";

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
  const [signersModalOpen, setSignersModalOpen] = useState(false);
  const [trustedSignersCount, setTrustedSignersCount] = useState<number>(0);
  const [isCollapsed, setIsCollapsed] = useState<boolean>(() => {
    try {
      return localStorage.getItem("scout_sidebar_collapsed") === "true";
    } catch {
      return false;
    }
  });

  const toggleSidebar = () => {
    setIsCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem("scout_sidebar_collapsed", String(next));
      } catch {}
      return next;
    });
  };

  const loadStatus = async () => {
    try {
      const [st, wf, ts] = await Promise.all([
        fetchSystemClamav().catch(() => null),
        fetchWatchFolder().catch(() => null),
        fetchTrustedSigners().catch(() => null),
      ]);
      if (st) {
        setClamav((prev) => {
          if (prev && prev.status === st.status && prev.running === st.running) {
            return prev;
          }
          return st;
        });
      }
      if (wf) {
        setWatchFolderState((prev) => {
          if (
            prev &&
            prev.watch_dir === wf.watch_dir &&
            prev.default_dir === wf.default_dir &&
            prev.is_default === wf.is_default
          ) {
            return prev;
          }
          return wf;
        });
      }
      if (ts && Array.isArray(ts.signers)) {
        setTrustedSignersCount(ts.signers.length);
      }
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
      <aside
        className={`${
          isCollapsed ? "w-16" : "w-60"
        } bg-[#0d1322] border-r border-slate-800/80 flex flex-col justify-between no-print select-none shrink-0 transition-all duration-200 ease-in-out`}
      >
        <div>
          {/* Scout Branding & Sidebar Toggle */}
          {isCollapsed ? (
            <div className="h-16 px-2 flex items-center justify-center border-b border-slate-800/80">
              <button
                onClick={toggleSidebar}
                className="w-10 h-10 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 flex items-center justify-center text-slate-400 hover:text-cyan-400 transition"
                title="Expand sidebar"
              >
                <PanelLeftOpen className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <div className="h-16 px-4 flex items-center justify-between border-b border-slate-800/80">
              <div className="flex items-center gap-3">
                <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-cyan-600 to-emerald-400 flex items-center justify-center shadow-md shadow-cyan-950/40 shrink-0">
                  <ShieldCheck className="w-4 h-4 text-white" />
                </div>
                <div className="font-bold text-base tracking-wide text-slate-100">
                  Scout
                </div>
              </div>
              <button
                onClick={toggleSidebar}
                className="text-slate-400 hover:text-slate-200 p-1.5 rounded-lg hover:bg-slate-800/60 transition"
                title="Collapse sidebar"
              >
                <PanelLeftClose className="w-4 h-4" />
              </button>
            </div>
          )}

          {/* Navigation Links */}
          <nav className={`${isCollapsed ? "p-2" : "p-3"} space-y-1`}>
            {navLinks.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path;
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  title={isCollapsed ? item.name : undefined}
                  className={`flex items-center ${
                    isCollapsed ? "justify-center px-0 py-2.5" : "gap-3 px-3 py-2"
                  } rounded-lg text-xs font-medium transition-all ${
                    isActive
                      ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20"
                      : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40"
                  }`}
                >
                  <Icon
                    className={`w-4 h-4 shrink-0 ${
                      isActive ? "text-cyan-400" : "text-slate-400"
                    }`}
                  />
                  {!isCollapsed && <span>{item.name}</span>}
                </Link>
              );
            })}
          </nav>
        </div>

        {/* Status & Settings Footer */}
        {isCollapsed ? (
          <div className="p-2 border-t border-slate-800/80 space-y-2 bg-[#0a0f1c] flex flex-col items-center">
            {/* Watch Folder Button */}
            <button
              onClick={() => setFolderModalOpen(true)}
              title={`Watch folder: ${
                watchFolder?.is_default
                  ? "inbox/ (default)"
                  : watchFolder?.watch_dir || "inbox/"
              }`}
              className="w-10 h-10 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-center text-cyan-400 hover:text-cyan-300 hover:border-cyan-500/40 hover:bg-slate-850 transition"
            >
              <FolderOpen className="w-4 h-4" />
            </button>

            {/* Trusted Signers Button */}
            <button
              onClick={() => setSignersModalOpen(true)}
              title={`Trusted Signers: ${trustedSignersCount} active (click to manage)`}
              className="w-10 h-10 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-center text-emerald-400 hover:text-emerald-300 hover:border-emerald-500/40 hover:bg-slate-850 transition"
            >
              <Award className="w-4 h-4" />
            </button>

            {/* ClamAV Button */}
            <button
              onClick={clamav?.status !== "ready" ? handleStartClamav : undefined}
              disabled={startingClamav || clamav?.status === "starting"}
              title={`ClamAV: ${clamav?.status || "offline"}${
                clamav?.status !== "ready" ? " (click to start)" : ""
              }`}
              className={`w-10 h-10 rounded-lg bg-slate-900 border border-slate-800 relative flex items-center justify-center transition ${
                clamav?.status !== "ready"
                  ? "hover:border-rose-500/40 hover:bg-slate-850 cursor-pointer"
                  : "hover:border-emerald-500/40"
              }`}
            >
              {startingClamav ? (
                <RefreshCw className="w-4 h-4 text-amber-400 animate-spin" />
              ) : (
                <Power
                  className={`w-4 h-4 ${
                    clamav?.status === "ready" ? "text-emerald-400" : "text-rose-400"
                  }`}
                />
              )}
              <span
                className={`absolute top-1.5 right-1.5 w-2 h-2 rounded-full ${
                  clamav?.status === "ready"
                    ? "bg-emerald-400 shadow-sm shadow-emerald-400/50"
                    : clamav?.status === "starting"
                    ? "bg-amber-400 animate-pulse"
                    : "bg-rose-500 shadow-sm shadow-rose-500/50"
                }`}
              />
            </button>
          </div>
        ) : (
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
              <div
                className="text-[11px] text-slate-300 font-mono truncate"
                title={watchFolder?.watch_dir || ""}
              >
                {watchFolder ? (
                  watchFolder.is_default
                    ? "inbox/ (default)"
                    : watchFolder.watch_dir.split(/[/\\]/).pop() || watchFolder.watch_dir
                ) : (
                  "inbox/"
                )}
              </div>
            </div>

            {/* Trusted Signers Card */}
            <div className="rounded-lg bg-slate-900 border border-slate-800 p-2.5">
              <div className="flex items-center justify-between text-xs mb-1">
                <span className="text-slate-400 flex items-center gap-1.5">
                  <Award className="w-3.5 h-3.5 text-emerald-400" /> Trusted signers
                </span>
                <button
                  onClick={() => setSignersModalOpen(true)}
                  className="text-slate-400 hover:text-emerald-300 p-0.5 rounded hover:bg-slate-800 transition"
                  title="Manage trusted signers"
                >
                  <Settings2 className="w-3.5 h-3.5" />
                </button>
              </div>
              <div
                onClick={() => setSignersModalOpen(true)}
                className="text-[11px] text-slate-300 font-mono cursor-pointer hover:text-cyan-300 transition flex items-center justify-between"
                title="Click to view and edit trusted signers"
              >
                <span>
                  {trustedSignersCount} active {trustedSignersCount === 1 ? "signer" : "signers"}
                </span>
                <span className="text-[10px] text-slate-500 font-sans">manage</span>
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
                  <RefreshCw
                    className={`w-3 h-3 ${startingClamav ? "animate-spin" : ""}`}
                  />
                  {startingClamav ? "Starting..." : "Start ClamAV"}
                </button>
              )}
            </div>
          </div>
        )}
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

      {/* Trusted Signers Whitelist Modal */}
      <TrustedSignersModal
        isOpen={signersModalOpen}
        onClose={() => setSignersModalOpen(false)}
        onSignersUpdated={(updatedSigners) => setTrustedSignersCount(updatedSigners.length)}
      />
    </div>
  );
};
