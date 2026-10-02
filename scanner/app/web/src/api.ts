import { useEffect, useRef, useState, useCallback } from "react";

const API_BASE = import.meta.env.DEV ? "http://localhost:8000" : "";
const WS_BASE = import.meta.env.DEV
  ? "ws://localhost:8000/ws"
  : `${window.location.protocol === "https:" ? "wss:" : "ws:"}//${window.location.host}/ws`;

export interface ScanItem {
  id: number;
  filename: string;
  path: string;
  sha256: string;
  size: number;
  verdict: "pass" | "review" | "block" | null;
  score: number;
  status: string;
  created_at: string | null;
  updated_at: string | null;
  results_count?: number;
}

export interface CheckResultItem {
  id: number;
  checker: string;
  status: "pass" | "warn" | "fail" | "skip";
  score: number;
  details: Record<string, any>;
}

export interface ScanDetail extends ScanItem {
  check_results: CheckResultItem[];
}

export interface ClamAvStatus {
  status: "ready" | "starting" | "offline" | "failed";
  running: boolean;
  host: string;
  port: number;
  pid: number | null;
  message: string;
  error?: string | null;
}

export interface StatsData {
  total_scans: number;
  passed: number;
  review: number;
  blocked: number;
  verdict_split: { name: string; value: number; color: string }[];
  scans_per_hour: { hour: string; count: number }[];
  clamav?: ClamAvStatus;
}

export interface Task1Signature {
  scan_id: number;
  app: string;
  signed: boolean;
  signer: string;
  digest_algorithm: string;
}

export interface Task2Hash {
  scan_id: number;
  app: string;
  given_digest: string;
  calculated_digest: string;
  match: boolean | null;
  source_url?: string;
}

export interface Task3Malware {
  scan_id: number;
  file: string;
  malicious: string;
  verdict: string;
  score: number;
  top_reasons: string[];
}

export interface VulnItem {
  id: string;
  description: string;
  cvss_score: number;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE" | "UNKNOWN";
  published: string;
  remediation: string;
  url: string;
}

export interface WebSocketEvent {
  type: "scan_started" | "check_done" | "scan_finished" | "scan_released" | "scan_deleted" | "connected" | "watch_folder_updated" | "history_cleared";
  scan_id?: number;
  filename?: string;
  sha256?: string;
  checker?: string;
  status?: string;
  score?: number;
  details?: Record<string, any>;
  verdict?: "pass" | "review" | "block";
  reasons?: string[];
  destination?: string;
  message?: string;
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, options);
  if (!res.ok) {
    const errorText = await res.text();
    throw new Error(`API ${res.status}: ${errorText || res.statusText}`);
  }
  return res.json();
}

export async function fetchScans(limit: number = 100): Promise<ScanItem[]> {
  return request<ScanItem[]>(`/api/scans?limit=${limit}`);
}

export async function fetchScanDetail(id: number): Promise<ScanDetail> {
  return request<ScanDetail>(`/api/scans/${id}`);
}

export async function releaseScan(id: number): Promise<{ message: string; scan_id: number }> {
  return request(`/api/scans/${id}/release`, { method: "POST" });
}

export async function deleteScan(id: number): Promise<{ message: string; scan_id: number }> {
  return request(`/api/scans/${id}/delete`, { method: "POST" });
}

export async function clearScans(): Promise<{ message: string; success: boolean }> {
  return request("/api/scans/clear", { method: "POST" });
}

export async function fetchStats(): Promise<StatsData> {
  return request<StatsData>("/api/stats");
}

export async function fetchSystemClamav(): Promise<ClamAvStatus> {
  return request<ClamAvStatus>("/api/system/clamav");
}

export async function triggerStartClamav(): Promise<{ success: boolean; status: ClamAvStatus }> {
  return request<{ success: boolean; status: ClamAvStatus }>("/api/system/clamav/start", { method: "POST" });
}

export async function fetchTask1Signatures(): Promise<Task1Signature[]> {
  return request<Task1Signature[]>("/api/tasks/signatures");
}

export async function fetchTask2Hashes(): Promise<Task2Hash[]> {
  return request<Task2Hash[]>("/api/tasks/hashes");
}

export async function fetchTask3Malware(): Promise<Task3Malware[]> {
  return request<Task3Malware[]>("/api/tasks/malware");
}

export async function fetchVulns(): Promise<VulnItem[]> {
  return request<VulnItem[]>("/api/vulns");
}

export async function refreshVulns(): Promise<VulnItem[]> {
  return request<VulnItem[]>("/api/vulns/refresh", { method: "POST" });
}

// ---------------------------------------------------------------------------
// Web Scanner API
// ---------------------------------------------------------------------------

export interface WebFindingItem {
  id: number;
  finding_id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  evidence: string;
  remediation: string;
  owasp_category: string;
  url: string;
  check_name: string;
}

export interface WebScanItem {
  id: number;
  target_url: string;
  status: "running" | "complete" | "error";
  score: number | null;
  grade: string | null;
  pages_crawled: number;
  findings_count: number;
  created_at: string | null;
  completed_at: string | null;
}

export interface WebScanDetail extends WebScanItem {
  error: string | null;
  findings: WebFindingItem[];
  severity_counts?: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

export async function startWebScan(url: string): Promise<{ scan_id: number; status: string; target: string }> {
  return request("/api/web/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
}

export async function fetchWebScans(limit = 50): Promise<WebScanItem[]> {
  return request<WebScanItem[]>(`/api/web/scans?limit=${limit}`);
}

export async function fetchWebScan(id: number): Promise<WebScanDetail> {
  return request<WebScanDetail>(`/api/web/scans/${id}`);
}

export async function clearWebScans(): Promise<{ message: string; success: boolean }> {
  return request("/api/web/scans/clear", { method: "POST" });
}

export async function deleteWebScan(id: number): Promise<{ message: string; scan_id: number }> {
  return request(`/api/web/scans/${id}/delete`, { method: "POST" });
}

// ---------------------------------------------------------------------------
// Watch Folder & Unified Report APIs
// ---------------------------------------------------------------------------

export interface WatchFolderInfo {
  watch_dir: string;
  default_dir: string;
  is_default: boolean;
}

export async function fetchWatchFolder(): Promise<WatchFolderInfo> {
  return request<WatchFolderInfo>("/api/watcher/folder");
}

export async function setWatchFolder(folder_path?: string, reset_default: boolean = false): Promise<WatchFolderInfo> {
  return request<WatchFolderInfo>("/api/watcher/folder", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ folder_path, reset_default }),
  });
}


export async function browseNativeFolder(currentPath?: string): Promise<{ path: string | null }> {
  return request<{ path: string | null }>("/api/watcher/browse-native", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ folder_path: currentPath }),
  });
}

export async function clearScanHistory(): Promise<{ status: string }> {
  return request<{ status: string }>("/api/scans/clear", {
    method: "POST",
  });
}

export interface UnifiedReportFinding {
  severity: "critical" | "high" | "medium" | "low" | "info";
  checker: string;
  title: string;
  description: string;
}

export interface UnifiedReportEntity {
  id: number;
  filename: string;
  sha256: string;
  size: number;
  verdict: "pass" | "review" | "block" | string;
  score: number;
  path: string;
  created_at: string | null;
  signature: {
    signed?: boolean;
    verified?: boolean;
    signer?: string;
    digest_algorithm?: string;
    trusted?: boolean;
  };
  hash_verification: {
    given?: string;
    calculated?: string;
    match?: boolean | null;
    source?: string;
  };
  findings: UnifiedReportFinding[];
}

export interface UnifiedReportData {
  summary: {
    total_scans: number;
    blocked_count: number;
    review_count: number;
    clean_count: number;
    threat_ratio: number;
  };
  entities: UnifiedReportEntity[];
}

export async function fetchUnifiedReport(): Promise<UnifiedReportData> {
  return request<UnifiedReportData>("/api/reports/unified");
}


export function useScanSocket(onEvent?: (event: WebSocketEvent) => void) {
  const [connected, setConnected] = useState<boolean>(false);
  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);

  const connect = useCallback(() => {
    try {
      const ws = new WebSocket(WS_BASE);
      socketRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
      };

      ws.onmessage = (e) => {
        try {
          const parsed: WebSocketEvent = JSON.parse(e.data);
          if (onEvent) {
            onEvent(parsed);
          }
        } catch (err) {
          console.error("WebSocket message JSON parse error:", err);
        }
      };

      ws.onclose = () => {
        setConnected(false);
        // Auto-reconnect after 3s
        reconnectTimeoutRef.current = window.setTimeout(() => {
          connect();
        }, 3000);
      };

      ws.onerror = (err) => {
        console.warn("WebSocket error:", err);
        ws.close();
      };
    } catch (e) {
      console.error("WebSocket creation failed:", e);
      reconnectTimeoutRef.current = window.setTimeout(() => {
        connect();
      }, 3000);
    }
  }, [onEvent]);

  useEffect(() => {
    connect();
    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (socketRef.current) {
        socketRef.current.close();
      }
    };
  }, [connect]);

  return { connected };
}
