import { useCallback, useEffect, useRef, useState } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { toast } from "sonner";
import type { Language } from "@/lib/i18n";

export type ProviderKind = "tailscale" | "cloudflare_named";
export interface ProviderSettings { kind: ProviderKind; tunnel_id: string; hostname: string }
export interface BridgeConfig { port: number; read_only: boolean; roots: Record<string, string> }
export type FileAccessMode = "folders" | "full";
export type FileGrantScope = "off" | "folders" | "all_local";
export interface FolderGrant { search: boolean; read: boolean; write: boolean }
export interface IndexStatus {
  state: "waiting" | "indexing" | "ready" | "directory_search" | "unavailable" | "clearing" | "cleared" | "clear_failed";
  bytes: number | null;
}
export interface FileAccessPolicy {
  mode: FileAccessMode;
  roots: Record<string, string>;
  search: FileGrantScope;
  read: FileGrantScope;
  write: FileGrantScope;
  folder_grants?: Record<string, FolderGrant> | null;
  disks?: string[] | null;
}

export interface TunnelStatus {
  health: "Up" | "Degraded" | "Down" | "Paused" | "Unknown" | "Starting" | "Stopping" | "Conflict";
  api_up: boolean; funnel_up: boolean; url: string | null; enabled: boolean;
  last_check: string; note: string; api_port: number; public_verified: boolean | null; agent_public_verified: boolean | null;
}
export type DeviceNameUpdate = { id: string; pending: boolean };
export type ExecMode = "direct" | "powershell" | "cmd";
export type RiskTier = "auto" | "session" | "always";
export type ApprovalDecision = "allow_once" | "allow_session" | "deny";
export interface ApprovalView {
  id: string;
  job_id: string;
  kind: string;
  tier: RiskTier;
  allow_session: boolean;
  root: string;
  cwd: string;
  workspace_path: string;
  mode: ExecMode;
  command: string;
  sandboxed: boolean;
  risk_tags: string[];
  reason: string | null;
  created_at: string;
  expires_at_ms: number;
}
export interface SessionGrantView {
  workspace_path: string;
  expires_at_ms: number;
}
export interface Snapshot {
  run_id: string; profile: "development" | "production"; initialized: boolean; fresh_setup: boolean; setup_error: string | null;
  file_token_version: string | null;
  file_access: FileAccessPolicy | null;
  ntfs_search_service: boolean | null;
  index_status: IndexStatus;
  access_configured: boolean;
  connection_configured: boolean;
  agent_enabled: boolean;
  agent_ready: boolean;
  agent_token_version?: string | null;
  exec_enabled: boolean;
  pending_approvals: ApprovalView[];
  exec_sessions: SessionGrantView[];
  home: string; config: BridgeConfig;
  desktop: { desired_enabled: boolean; provider: ProviderSettings; start_minimized: boolean; close_to_tray: boolean; permission_mode: string; language: Language; device_name: string; device_name_update?: DeviceNameUpdate | null; exec_enabled?: boolean };
  suggested_device_name: string | null;
  status: TunnelStatus;
  stats: ActivityStats & { file_activity: ActivityStats };
  dependencies: { tailscale: boolean; cloudflared: boolean; simulated: boolean };
  capabilities: { enabled: boolean; tools: string[] }; version: string;
  autostart: boolean | null; update_configured: boolean;
  log_bytes: number;
  log_errors: string[];
}
export interface LegacyState {
  tasks: Array<{ name: string; exists: boolean; enabled: boolean; running: boolean }>;
  port_occupied: boolean; needs_takeover: boolean; can_restore: boolean; migration_phase: string | null;
}
export interface ActivityStats { total: number; authed: number; auth_failures: number; completed: number; errors: number; read_bytes: number; written_bytes: number; last_request: string | null; trend: Array<{ minute: number; requests: number; errors: number }> }
export interface LogRecord { seq: number; kind: "audit" | "runtime"; text: string; persisted: boolean }
export interface LogBatch { entries: LogRecord[]; last_seq: number; gap: boolean; error: string | null }

export function useBridge() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [legacy, setLegacy] = useState<LegacyState | null>(null);
  const [nativeVisible, setNativeVisible] = useState(false);
  const [documentVisible, setDocumentVisible] = useState(() => !document.hidden);
  const windowVisible = nativeVisible && documentVisible;
  const legacyRequest = useRef(0);
  const request = useRef(0);
  const operationId = useRef(0);
  const operations = useRef(new Map<number, string>());
  const legacyChecked = useRef(false);
  const refresh = useCallback(async (refreshDependencies = false) => {
    if (!isTauri()) { setError("请从 Muse 连接器桌面程序打开。浏览器页面不会连接或操作本机服务。"); return; }
    const id = ++request.current;
    try { const result = await invoke<Snapshot>("get_snapshot", { refreshDependencies }); if (id === request.current) setSnapshot(result); }
    catch (e) { if (id === request.current) setError(`读取连接器状态失败：${String(e)}`); }
  }, []);
  const refreshNow = useCallback(() => refresh(true), [refresh]);
  const checkLegacy = useCallback(async () => {
    if (!isTauri()) return;
    const id = ++legacyRequest.current;
    try { const value = await invoke<LegacyState>("check_legacy"); if (id === legacyRequest.current) setLegacy(value); }
    catch { return; }
  }, []);
  useEffect(() => {
    if (!windowVisible || legacyChecked.current) return;
    legacyChecked.current = true;
    void checkLegacy();
  }, [checkLegacy, windowVisible]);

  useEffect(() => {
    if (!isTauri()) { void refresh(); return; }
    let disposed = false;
    let visibilityVersion = 0;
    const onDocumentVisibility = () => setDocumentVisible(!document.hidden);
    document.addEventListener("visibilitychange", onDocumentVisibility);
    onDocumentVisibility();
    const subscription = listen<boolean>("desktop-visibility", ({ payload }) => {
      visibilityVersion++;
      if (!disposed) setNativeVisible(payload);
    }).catch(() => undefined);
    void subscription.then(async () => {
      const version = visibilityVersion;
      const visible = await getCurrentWindow().isVisible().catch(() => !document.hidden);
      if (!disposed && version === visibilityVersion) setNativeVisible(visible);
    });
    return () => {
      disposed = true;
      document.removeEventListener("visibilitychange", onDocumentVisibility);
      void subscription.then(stop => stop?.());
    };
  }, [refresh]);
  useEffect(() => {
    let disposed = false;
    const subscriptions = isTauri() ? Promise.allSettled([
      listen<Snapshot>("bridge-snapshot", ({ payload }) => { if (!disposed) setSnapshot(previous => previous ? { ...previous, ...payload } : previous); }),
      listen<string>("update-progress", ({ payload }) => { if (!disposed) toast.info(payload, { id: "update-progress" }); }),
    ]).then(results => {
      const stops = results.flatMap(result => result.status === "fulfilled" ? [result.value] : []);
      if (!disposed && results.some(result => result.status === "rejected")) setError("状态事件订阅失败，已使用定时刷新；请重启连接器恢复实时状态。");
      return stops;
    }) : Promise.resolve([]);
    return () => { disposed = true; void subscriptions.then(stops => stops.forEach(stop => stop())); };
  }, []);
  const fastPoll = snapshot?.index_status?.state === "indexing"
    || Boolean(snapshot?.file_access && snapshot.file_access.search !== "off" && snapshot.index_status?.state === "waiting")
    || Boolean(snapshot?.pending_approvals?.length);
  useEffect(() => {
    if (!windowVisible) return;
    void refresh();
    const timer = setInterval(refresh, fastPoll ? 1500 : 15000);
    return () => clearInterval(timer);
  }, [refresh, windowVisible, fastPoll]);
  const run = useCallback(async <T,>(label: string, command: string, args?: Record<string, unknown>, success?: string, reportError = true): Promise<{ ok: true; data: T } | { ok: false; error: string }> => {
    const id = ++operationId.current;
    operations.current.set(id, label); setBusy(label); setError(null);
    try {
      const data = await invoke<T>(command, args);
      if (success) toast.success(success);
      await refresh();
      if (command === "takeover_legacy" || command === "restore_legacy") await checkLegacy();
      return { ok: true, data };
    } catch (e) { const message = String(e); if (reportError) setError(message); return { ok: false, error: message }; }
    finally { operations.current.delete(id); setBusy([...operations.current.values()][operations.current.size - 1] ?? null); }
  }, [refresh, checkLegacy]);
  return { snapshot, error, setError, busy, run, refresh: refreshNow, legacy, windowVisible };
}
export type BridgeModel = ReturnType<typeof useBridge>;
export const providerLabels = { tailscale: "Tailscale Funnel", cloudflare_named: "Cloudflare 命名隧道（自有域名）" } as const satisfies Record<ProviderKind, string>;
export const formatTime = (value: string, language: Language) => new Date(value).toLocaleString(language, { hour12: false });
export function formatBytes(value: number) { if (value < 1024) return `${value} B`; if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`; return `${(value / 1024 / 1024).toFixed(2)} MiB`; }
