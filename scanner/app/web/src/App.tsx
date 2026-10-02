import React, { useState, useCallback } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { Layout } from "./components/Layout";
import { LiveFeedView, type ActiveScanCard } from "./views/LiveFeedView";
import { ScansView } from "./views/ScansView";
import { TaskReportsView } from "./views/TaskReportsView";
import { StatsView } from "./views/StatsView";
import { WebScannerView } from "./views/WebScannerView";
import { useScanSocket, type WebSocketEvent } from "./api";

export const App: React.FC = () => {
  const [activeCards, setActiveCards] = useState<ActiveScanCard[]>([]);

  const handleSocketEvent = useCallback((event: WebSocketEvent) => {
    const etype = event.type;
    const scanId = event.scan_id;

    if (etype === "watch_folder_updated") {
      // Clear live feed when monitored directory changes
      setActiveCards([]);
    } else if (etype === "history_cleared") {
      setActiveCards([]);
    } else if (etype === "scan_started" && scanId) {
      setActiveCards((prev) => {
        const existing = prev.filter((c) => c.scan_id !== scanId);
        const newCard: ActiveScanCard = {
          scan_id: scanId,
          filename: event.filename || "file",
          sha256: event.sha256,
          size: event.details?.size,
          checks: {},
          timestamp: new Date().toLocaleTimeString(),
        };
        return [newCard, ...existing].slice(0, 20);
      });
    } else if (etype === "check_done" && scanId && event.checker) {
      setActiveCards((prev) =>
        prev.map((card) => {
          if (card.scan_id === scanId) {
            return {
              ...card,
              checks: {
                ...card.checks,
                [event.checker!]: {
                  status: event.status || "skip",
                  score: event.score || 0,
                  details: event.details,
                },
              },
            };
          }
          return card;
        })
      );
    } else if (etype === "scan_finished" && scanId) {
      setActiveCards((prev) =>
        prev.map((card) => {
          if (card.scan_id === scanId) {
            return {
              ...card,
              verdict: event.verdict,
              score: event.score,
              reasons: event.reasons,
              destination: event.destination,
            };
          }
          return card;
        })
      );
    } else if (etype === "scan_deleted" && scanId) {
      setActiveCards((prev) => prev.filter((c) => c.scan_id !== scanId));
    }
  }, []);

  const { connected } = useScanSocket(handleSocketEvent);

  return (
    <BrowserRouter>
      <Layout wsConnected={connected}>
        <Routes>
          <Route path="/" element={<LiveFeedView activeCards={activeCards} onClear={() => setActiveCards([])} />} />
          <Route path="/scans" element={<ScansView />} />
          <Route path="/webscan" element={<WebScannerView />} />
          <Route path="/tasks" element={<TaskReportsView />} />
          <Route path="/stats" element={<StatsView />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>
    </BrowserRouter>
  );
};

export default App;
