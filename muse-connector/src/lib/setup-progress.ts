import type { Snapshot } from "@/lib/use-bridge";

export type SetupVerification = { scope: string; alias: string; address: string; read: boolean };

export function setupStorageKey(snapshot: Pick<Snapshot, "profile" | "home">) {
  return `muse-connector:setup:${snapshot.profile}:${snapshot.home}`;
}

export function readSetupVerification(key: string): SetupVerification | null {
  try {
    const stored = JSON.parse(localStorage.getItem(`${key}:verification`) ?? "null");
    if (typeof stored?.scope === "string" && typeof stored.alias === "string" && typeof stored.address === "string" && typeof stored.read === "boolean") {
      return stored;
    }
  } catch {
    // 损坏或不可用的前端记录不影响连接配置。
  }
  return null;
}

export function saveSetupVerification(key: string, value: SetupVerification | null) {
  try {
    if (value) localStorage.setItem(`${key}:verification`, JSON.stringify(value));
    else localStorage.removeItem(`${key}:verification`);
  } catch {
    // 浏览器存储不可用时，保留本次会话内的结果。
  }
}

export function providerToolAvailable(snapshot: Snapshot) {
  return snapshot.desktop.provider.kind === "tailscale"
    ? snapshot.dependencies.tailscale : snapshot.dependencies.cloudflared;
}

export function publicAddress(snapshot: Snapshot) {
  const { api_up, funnel_up, url } = snapshot.status;
  if (snapshot.profile === "development" || !api_up || !funnel_up || !url) return null;
  try {
    const address = new URL(url);
    if (address.protocol === "https:" && !address.username && !address.password
      && address.pathname === "/" && !address.search && !address.hash) return address.origin;
  } catch {
    // 地址解析失败时等待连接器报告有效入口。
  }
  return null;
}

export function setupRootTarget(alias: string) {
  return `setup-root-${encodeURIComponent(alias)}`;
}
