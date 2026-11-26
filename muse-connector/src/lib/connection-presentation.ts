import type { StatusTone } from "@/components/status-badge";
import type { Snapshot } from "@/lib/use-bridge";
import type { Translate } from "@/lib/i18n";

export interface ConnectionPresentation { label: string; tone: StatusTone; pending: boolean }

export function connectionPresentation(t: Translate, snapshot: Snapshot | null, busy: string | null): ConnectionPresentation {
  if (!snapshot) return { label: t("正在读取状态"), tone: "neutral", pending: true };
  const { status } = snapshot;
  if (busy === "pauseConnection" || status.health === "Stopping") return { label: t("正在暂停"), tone: "neutral", pending: true };
  if (busy === "startConnection" || status.health === "Starting") return { label: t("正在连接"), tone: "neutral", pending: true };
  if (snapshot.access_configured && !snapshot.connection_configured && !snapshot.setup_error) return { label: t("本机授权已保存"), tone: "neutral", pending: false };
  if (snapshot.setup_error || !snapshot.connection_configured) return { label: t("等待设置"), tone: "warning", pending: false };
  if (status.health === "Conflict") return { label: t("端口冲突"), tone: "error", pending: false };
  if (status.health === "Down") return { label: t("连接失败"), tone: "error", pending: false };
  if (status.health === "Degraded") return { label: t("连接需要检查"), tone: "warning", pending: false };
  if (status.health === "Paused") return { label: t("已暂停"), tone: "neutral", pending: false };
  if (status.health === "Up" && status.api_up && status.funnel_up) {
    if ((snapshot.agent_ready ? status.agent_public_verified : status.public_verified) === false) return { label: t("公网检查未通过"), tone: "warning", pending: false };
    return { label: snapshot.profile === "development" ? t("模拟已连接") : t("已连接"), tone: "success", pending: false };
  }
  return { label: status.health === "Unknown" ? t("状态待确认") : t("连接尚未就绪"), tone: "warning", pending: false };
}
