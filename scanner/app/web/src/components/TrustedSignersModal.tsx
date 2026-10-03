import React, { useEffect, useState } from "react";
import {
  Award,
  Plus,
  Trash2,
  X,
  AlertCircle,
  Loader2,
  CheckCircle2,
  ShieldCheck,
  ChevronDown,
} from "lucide-react";
import {
  fetchTrustedSigners,
  addTrustedSigner,
  removeTrustedSigner,
} from "../api";

interface TrustedSignersModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSignersUpdated?: (signers: string[]) => void;
}

export const TrustedSignersModal: React.FC<TrustedSignersModalProps> = ({
  isOpen,
  onClose,
  onSignersUpdated,
}) => {
  const [signers, setSigners] = useState<string[]>([]);
  const [presets, setPresets] = useState<string[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [manualInput, setManualInput] = useState<string>("");
  const [selectedPreset, setSelectedPreset] = useState<string>("");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const loadData = async () => {
    setLoading(true);
    setErrorMessage(null);
    try {
      const res = await fetchTrustedSigners();
      setSigners(res.signers || []);
      setPresets(res.presets || []);
      if (onSignersUpdated) {
        onSignersUpdated(res.signers || []);
      }
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to load trusted signers.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      loadData();
      setManualInput("");
      setSelectedPreset("");
      setErrorMessage(null);
      setSuccessMessage(null);
    }
  }, [isOpen]);

  // Filter available presets that are not already present in the whitelist
  const availablePresets = presets.filter(
    (p) => !signers.some((s) => s.toLowerCase() === p.toLowerCase())
  );

  const handleAddSigner = async (nameToAdd: string) => {
    const trimmed = nameToAdd.trim();
    if (!trimmed) {
      setErrorMessage("Please enter a valid signer name.");
      return;
    }

    if (signers.some((s) => s.toLowerCase() === trimmed.toLowerCase())) {
      setErrorMessage(`"${trimmed}" is already in your trusted signers whitelist.`);
      return;
    }

    setActionLoading(true);
    setErrorMessage(null);
    setSuccessMessage(null);
    try {
      const res = await addTrustedSigner(trimmed);
      setSigners(res.signers || []);
      setManualInput("");
      setSelectedPreset("");
      setSuccessMessage(`Added "${trimmed}" to trusted signers.`);
      if (onSignersUpdated) {
        onSignersUpdated(res.signers || []);
      }
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to add trusted signer.");
    } finally {
      setActionLoading(false);
    }
  };

  const handleRemoveSigner = async (nameToRemove: string) => {
    setActionLoading(true);
    setErrorMessage(null);
    setSuccessMessage(null);
    try {
      const res = await removeTrustedSigner(nameToRemove);
      setSigners(res.signers || []);
      setSuccessMessage(`Removed "${nameToRemove}".`);
      if (onSignersUpdated) {
        onSignersUpdated(res.signers || []);
      }
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (err: any) {
      setErrorMessage(err.message || "Failed to remove trusted signer.");
    } finally {
      setActionLoading(false);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#0f172a] border border-slate-700/80 rounded-2xl max-w-lg w-full shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150 flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-900/40 shrink-0">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                Trusted Certificate Signers
                <span className="text-[11px] font-normal px-2 py-0.5 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">
                  {signers.length} active
                </span>
              </h3>
              <p className="text-xs text-slate-400">
                Verified binaries from these publishers pass without penalty
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

        {/* Content Body */}
        <div className="p-5 space-y-4 overflow-y-auto flex-1 text-xs">
          {/* Alerts */}
          {errorMessage && (
            <div className="flex items-center gap-2 text-rose-400 bg-rose-500/10 border border-rose-500/20 p-2.5 rounded-lg">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{errorMessage}</span>
            </div>
          )}

          {successMessage && (
            <div className="flex items-center gap-2 text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 p-2.5 rounded-lg">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>{successMessage}</span>
            </div>
          )}

          {/* Add Signer Controls */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-xl p-3.5 space-y-3">
            <div className="text-[11px] font-medium uppercase tracking-wider text-slate-400 flex items-center justify-between">
              <span>Add Trusted Signer</span>
              {actionLoading && (
                <span className="text-cyan-400 flex items-center gap-1 font-normal lowercase">
                  <Loader2 className="w-3 h-3 animate-spin" /> updating...
                </span>
              )}
            </div>

            {/* 1. Preset Dropdown */}
            <div>
              <label className="text-slate-400 block mb-1 text-[11px]">
                Select from popular presets:
              </label>
              <div className="flex items-center gap-2">
                <div className="relative flex-1">
                  <select
                    value={selectedPreset}
                    onChange={(e) => setSelectedPreset(e.target.value)}
                    disabled={actionLoading || loading || availablePresets.length === 0}
                    className="w-full appearance-none px-3 py-2 text-xs bg-slate-950 border border-slate-700/80 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 disabled:opacity-50 pr-8"
                  >
                    <option value="">
                      {availablePresets.length === 0
                        ? "All presets are currently added"
                        : "-- Choose a verified preset --"}
                    </option>
                    {availablePresets.map((preset) => (
                      <option key={preset} value={preset}>
                        {preset}
                      </option>
                    ))}
                  </select>
                  <ChevronDown className="w-4 h-4 text-slate-500 absolute right-2.5 top-2.5 pointer-events-none" />
                </div>
                <button
                  type="button"
                  onClick={() => selectedPreset && handleAddSigner(selectedPreset)}
                  disabled={!selectedPreset || actionLoading}
                  className="flex items-center gap-1 px-3 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg font-medium transition disabled:opacity-50 shrink-0"
                >
                  <Plus className="w-3.5 h-3.5" />
                  Add Preset
                </button>
              </div>
            </div>

            <div className="flex items-center gap-2 my-1">
              <div className="h-[1px] bg-slate-800 flex-1" />
              <span className="text-[10px] text-slate-500 uppercase tracking-widest">or</span>
              <div className="h-[1px] bg-slate-800 flex-1" />
            </div>

            {/* 2. Manual Custom Signer Input */}
            <div>
              <label className="text-slate-400 block mb-1 text-[11px]">
                Add custom publisher / signer name:
              </label>
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={manualInput}
                  onChange={(e) => setManualInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && manualInput.trim()) {
                      e.preventDefault();
                      handleAddSigner(manualInput);
                    }
                  }}
                  placeholder="e.g. Acme Corp Inc."
                  disabled={actionLoading || loading}
                  className="flex-1 px-3 py-2 text-xs bg-slate-950 border border-slate-700/80 rounded-lg text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono disabled:opacity-50"
                />
                <button
                  type="button"
                  onClick={() => handleAddSigner(manualInput)}
                  disabled={!manualInput.trim() || actionLoading}
                  className="flex items-center gap-1 px-3 py-2 bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 rounded-lg font-medium transition disabled:opacity-50 shrink-0"
                >
                  <Plus className="w-3.5 h-3.5" />
                  Add Custom
                </button>
              </div>
            </div>
          </div>

          {/* Current Whitelist List */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                Active Whitelist
              </span>
              <span className="text-[11px] text-slate-500">
                {signers.length} {signers.length === 1 ? "signer" : "signers"} configured
              </span>
            </div>

            {loading ? (
              <div className="flex items-center justify-center p-6 text-slate-400 gap-2">
                <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
                <span>Loading signers...</span>
              </div>
            ) : signers.length === 0 ? (
              <div className="text-center p-6 rounded-xl border border-dashed border-slate-800 bg-slate-950/40 text-slate-500">
                <Award className="w-6 h-6 mx-auto mb-1.5 opacity-40 text-slate-400" />
                <p className="font-medium text-slate-400">No trusted signers configured</p>
                <p className="text-[11px] mt-0.5">
                  Signed binaries will be flagged for review (+25 penalty).
                </p>
              </div>
            ) : (
              <div className="space-y-1.5 max-h-56 overflow-y-auto pr-1">
                {signers.map((signerName) => {
                  const isPresetMatch = presets.some(
                    (p) => p.toLowerCase() === signerName.toLowerCase()
                  );
                  return (
                    <div
                      key={signerName}
                      className="group flex items-center justify-between px-3 py-2 rounded-lg bg-slate-900/60 border border-slate-800/80 hover:border-slate-700 hover:bg-slate-850 transition"
                    >
                      <div className="flex items-center gap-2.5 min-w-0 pr-2">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                        <span className="font-medium text-slate-200 truncate font-mono text-[11px]">
                          {signerName}
                        </span>
                        {isPresetMatch && (
                          <span className="px-1.5 py-0.2 rounded text-[9px] font-medium bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shrink-0">
                            Preset
                          </span>
                        )}
                      </div>
                      <button
                        type="button"
                        onClick={() => handleRemoveSigner(signerName)}
                        disabled={actionLoading}
                        className="text-slate-500 hover:text-rose-400 p-1 rounded hover:bg-rose-500/10 transition opacity-80 group-hover:opacity-100 disabled:opacity-30 shrink-0"
                        title={`Remove "${signerName}"`}
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-slate-800 bg-slate-900/60 flex items-center justify-between shrink-0">
          <span className="text-[11px] text-slate-500">
            Signers are automatically persisted to config.yaml
          </span>
          <button
            type="button"
            onClick={onClose}
            className="px-4 py-1.5 text-xs font-semibold text-white bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
};
