import React, { useEffect, useState } from "react";
import {
  FolderOpen,
  Check,
  X,
  RotateCcw,
  AlertCircle,
  Loader2,
  ExternalLink,
} from "lucide-react";
import {
  browseNativeFolder,
  setWatchFolder,
  type WatchFolderInfo,
} from "../api";

interface WatchFolderModalProps {
  isOpen: boolean;
  onClose: () => void;
  watchFolder: WatchFolderInfo | null;
  onUpdated: (info: WatchFolderInfo) => void;
}

export const WatchFolderModal: React.FC<WatchFolderModalProps> = ({
  isOpen,
  onClose,
  watchFolder,
  onUpdated,
}) => {
  const [addressInput, setAddressInput] = useState<string>("");
  const [nativeBrowsing, setNativeBrowsing] = useState<boolean>(false);
  const [updating, setUpdating] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen && watchFolder) {
      setAddressInput(watchFolder.watch_dir);
      setErrorMessage(null);
    }
  }, [isOpen, watchFolder]);

  const handleNativeBrowse = async () => {
    setNativeBrowsing(true);
    setErrorMessage(null);
    try {
      const res = await browseNativeFolder(addressInput);
      if (res.path) {
        setAddressInput(res.path);
      }
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to open folder browser.");
    } finally {
      setNativeBrowsing(false);
    }
  };

  const handleSave = async (resetDefault: boolean = false) => {
    setUpdating(true);
    setErrorMessage(null);
    try {
      const pathToSend = resetDefault ? undefined : addressInput.trim();
      const res = await setWatchFolder(pathToSend, resetDefault);
      onUpdated(res);
      setAddressInput(res.watch_dir);
      onClose();
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to update directory.");
    } finally {
      setUpdating(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#0f172a] border border-slate-700/80 rounded-2xl max-w-md w-full shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        {/* Header */}
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/40">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <FolderOpen className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-slate-100">
                Select target directory
              </h3>
              <p className="text-xs text-slate-400">
                Choose a folder to monitor
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 p-1 rounded-lg hover:bg-slate-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body Content */}
        <div className="p-5 space-y-3">
          <div>
            <label className="text-xs font-medium text-slate-300 block mb-1.5">
              Path
            </label>
            <input
              type="text"
              value={addressInput}
              onChange={(e) => setAddressInput(e.target.value)}
              placeholder="e.g. C:\path\to\folder"
              className="w-full px-3 py-2 text-xs font-mono bg-slate-900 border border-slate-700 rounded-lg text-slate-100 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
            />
          </div>

          <div>
            <button
              type="button"
              onClick={handleNativeBrowse}
              disabled={nativeBrowsing}
              className="w-full flex items-center justify-center gap-2 py-2 text-xs font-medium rounded-lg bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition disabled:opacity-50"
            >
              {nativeBrowsing ? (
                <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-400" />
              ) : (
                <ExternalLink className="w-3.5 h-3.5 text-cyan-400" />
              )}
              {nativeBrowsing ? "Opening Windows Explorer..." : "Browse with Windows Explorer"}
            </button>
          </div>

          {errorMessage && (
            <div className="flex items-center gap-2 text-xs text-rose-400 bg-rose-500/10 border border-rose-500/20 p-2.5 rounded-lg">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{errorMessage}</span>
            </div>
          )}
        </div>

        {/* Footer Actions */}
        <div className="px-5 py-3.5 border-t border-slate-800 bg-slate-900/60 flex items-center justify-between">
          <button
            type="button"
            onClick={() => handleSave(true)}
            disabled={updating || (watchFolder?.is_default ?? true)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200 transition disabled:opacity-30"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            Reset
          </button>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200 transition"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => handleSave(false)}
              disabled={updating || !addressInput.trim()}
              className="flex items-center gap-1.5 px-4 py-1.5 text-xs font-semibold text-white bg-cyan-600 hover:bg-cyan-500 rounded-lg transition disabled:opacity-50"
            >
              {updating ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Check className="w-3.5 h-3.5" />}
              {updating ? "Saving..." : "Save"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
