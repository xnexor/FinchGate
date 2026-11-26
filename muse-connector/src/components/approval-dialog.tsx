import { useEffect, useState } from "react";
import { Clock, FolderOpen, ShieldAlert, Terminal } from "lucide-react";
import { useLanguage } from "@/lib/i18n";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import type { ApprovalDecision, ApprovalView, BridgeModel } from "@/lib/use-bridge";

const riskTagLabels = {
  sensitive_path: "涉及敏感目录",
  unsandboxed: "跳出写受限沙箱",
  shell_powershell: "PowerShell 脚本",
  shell_cmd: "cmd 命令行",
  system_admin_tool: "系统管理工具",
  obfuscated_command: "疑似编码或混淆命令",
  remote_force_push: "强制推送远端仓库",
  remote_push: "推送至远端仓库",
  remote_mutation: "修改远端配置",
  destructive_git: "高风险 Git 重置或删除",
  destructive_delete: "递归或强制删除",
  git_config_override: "覆盖 Git 配置",
  package_mutation: "安装或变更依赖包",
  inline_script: "内联脚本执行",
  path_escape_attempt: "参数含跨目录路径",
  custom_command: "白名单外命令",
} as const;

type RiskTagKey = keyof typeof riskTagLabels;

function modeLabel(mode: ApprovalView["mode"]) {
  if (mode === "powershell") return "PowerShell";
  if (mode === "cmd") return "cmd";
  return "直调程序";
}

export default function ApprovalDialog({ bridge }: { bridge: BridgeModel }) {
  const { t } = useLanguage();
  const approvals = bridge.snapshot?.pending_approvals ?? [];
  const current = approvals[0] ?? null;
  const [now, setNow] = useState(() => Date.now());
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (!current) return;
    setNow(Date.now());
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [current?.id]);

  if (!current) return null;

  const remaining = Math.max(0, Math.ceil((current.expires_at_ms - now) / 1000));
  const expired = remaining <= 0;
  const highRisk = current.tier === "always" || !current.sandboxed;
  const disabled = submitting || !!bridge.busy || expired;

  const decide = async (decision: ApprovalDecision) => {
    if (disabled) return;
    setSubmitting(true);
    try {
      await bridge.run(
        t("正在处理命令审批"),
        "resolve_exec_approval",
        { id: current.id, decision },
        decision === "deny"
          ? t("已拒绝该命令执行")
          : decision === "allow_session"
            ? t("已允许并在本会话记住此项目")
            : t("已允许本次命令执行"),
      );
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open onOpenChange={() => undefined}>
      <DialogContent
        showCloseButton={false}
        onEscapeKeyDown={(event) => {
          event.preventDefault();
          void decide("deny");
        }}
        onPointerDownOutside={(event) => event.preventDefault()}
        className="max-w-lg"
      >
        <DialogHeader>
          <div className="flex flex-wrap items-center gap-2">
            <ShieldAlert className="size-4 shrink-0" />
            <DialogTitle>
              {highRisk ? t("允许执行高风险命令？") : t("允许 Muse 运行此命令？")}
            </DialogTitle>
            {approvals.length > 1 ? (
              <Badge variant="outline">1 / {approvals.length}</Badge>
            ) : null}
          </div>
          <DialogDescription>
            {t("以下目录、命令与风险标签由本机直接解析。请核对后再决定是否放行。")}
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-3 text-sm">
          <div className="flex flex-wrap items-center gap-2">
            <Badge variant={highRisk ? "destructive" : "secondary"}>
              {current.sandboxed ? t("写受限沙箱") : t("无沙箱（高风险）")}
            </Badge>
            <Badge variant="outline">
              {current.mode === "direct" ? t("直调程序") : modeLabel(current.mode)}
            </Badge>
            <span className="ml-auto inline-flex items-center gap-1 text-caption tabular-nums text-muted-foreground">
              <Clock className="size-3.5" />
              {t("剩余 {0} 秒", remaining)}
            </span>
          </div>

          <div className="flex flex-col gap-1 rounded-md border bg-muted/40 p-3">
            <span className="inline-flex items-center gap-1.5 text-caption text-muted-foreground">
              <FolderOpen className="size-3.5" />
              {t("目标项目目录")}
            </span>
            <code className="break-all text-caption text-foreground">
              {current.workspace_path}
            </code>
          </div>

          <div className="flex flex-col gap-1 rounded-md border bg-muted/40 p-3">
            <span className="inline-flex items-center gap-1.5 text-caption text-muted-foreground">
              <Terminal className="size-3.5" />
              {t("实际执行命令")}
            </span>
            <pre className="max-h-36 overflow-auto whitespace-pre-wrap break-all text-caption text-foreground">
              {current.command}
            </pre>
          </div>

          {current.risk_tags.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {current.risk_tags.map((tag) => (
                <Badge key={tag} variant="outline">
                  {tag in riskTagLabels ? t(riskTagLabels[tag as RiskTagKey]) : tag}
                </Badge>
              ))}
            </div>
          ) : null}

          {current.reason ? (
            <>
              <Separator />
              <div className="flex flex-col gap-1 text-caption">
                <span className="text-muted-foreground">
                  {t("来自 Muse 的说明（仅供参考）")}
                </span>
                <p className="break-words text-foreground">{current.reason}</p>
              </div>
            </>
          ) : null}
        </div>

        <DialogFooter className="flex-wrap gap-2">
          <Button
            type="button"
            variant="outline"
            disabled={disabled}
            onClick={() => void decide("deny")}
          >
            {t("拒绝")}
          </Button>
          {current.allow_session ? (
            <Button
              type="button"
              variant="secondary"
              disabled={disabled}
              onClick={() => void decide("allow_session")}
            >
              {t("本会话允许此项目")}
            </Button>
          ) : null}
          <Button
            type="button"
            disabled={disabled}
            onClick={() => void decide("allow_once")}
          >
            {t("仅允许本次")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
