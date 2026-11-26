import { useLanguage } from "@/lib/i18n";
import FileAccessPanel from "@/components/file-access-panel";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import type { Confirmation } from "@/components/feedback";
import type { BridgeModel } from "@/lib/use-bridge";

export default function Roots({
  bridge,
  guided,
  guiding,
  onAccessSaved,
  confirm,
}: {
  bridge: BridgeModel;
  guided: boolean;
  guiding: boolean;
  onAccessSaved: () => void;
  confirm: (value: Confirmation) => void;
}) {
  const { t } = useLanguage();
  const snapshot = bridge.snapshot;
  if (!snapshot) return null;

  const busy = !!bridge.busy;
  const execEnabled = snapshot.exec_enabled;
  const execSessions = snapshot.exec_sessions;

  return (
    <div className="page-stack">
      <Card>
        <CardContent className="flex flex-col gap-5">
          <FileAccessPanel bridge={bridge} snapshot={snapshot} guided={guided} onSaved={onAccessSaved} />
          {!guided && !guiding && snapshot.agent_enabled ? (
            <>
              <Separator />
              <div className="flex flex-col gap-2.5 rounded-md border px-3.5 py-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex min-w-0 flex-col gap-1.5">
                    <div className="flex flex-wrap items-center gap-2">
                      <label htmlFor="exec-enabled-switch" className="text-sm font-medium text-foreground">
                        {t("允许 Muse 执行本机命令")}
                      </label>
                      <Badge variant="outline">{execEnabled ? t("写受限沙箱") : t("已关闭")}</Badge>
                    </div>
                    <p className="text-caption text-muted-foreground">
                      {t("开启后，Muse 可在已授权的非敏感项目文件夹内调用常见开发工具（如 git、cargo、pnpm、python）以及受控 PowerShell/cmd。命令默认运行在 Windows 写受限沙箱中（仅允许写入当前项目目录与隔离临时目录，且受内存、进程数与超时约束）；首次在项目内使用 Shell、安装依赖、推送远端、触碰敏感目录或请求跳出沙箱时，本机将弹出审批窗由你确认。关闭开关会立即停用并终止运行中的命令。")}
                    </p>
                  </div>
                  <Switch
                    id="exec-enabled-switch"
                    checked={execEnabled}
                    disabled={busy}
                    onCheckedChange={(next) => {
                      if (next) {
                        confirm({
                          title: t("开启 Muse 本机命令执行？"),
                          description: t("开启后，持有当前 Muse 专用令牌的请求可在授权项目文件夹内运行开发工具与受控 PowerShell/cmd（默认限制于 Windows 写受限沙箱）。高风险与敏感目录操作仍需本机弹窗确认。开启后请重新复制接入说明发给 Muse。"),
                          action: t("开启命令执行"),
                          execute: async () => (await bridge.run(t("正在开启命令执行"), "set_exec_enabled", { enabled: true }, t("命令执行已开启，可重新复制接入说明发给 Muse"))).ok,
                        });
                      } else {
                        void bridge.run(t("正在关闭命令执行"), "set_exec_enabled", { enabled: false }, t("命令执行已关闭"));
                      }
                    }}
                  />
                </div>
                {execEnabled && execSessions.length > 0 ? (
                  <div className="flex flex-wrap items-center justify-between gap-2 border-t pt-3">
                    <span className="text-caption text-muted-foreground">
                      {t("本会话已免打扰放行 {0} 个项目目录", execSessions.length)}
                    </span>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="text-status-error hover:text-status-error"
                      disabled={busy}
                      onClick={() => void bridge.run(t("正在收回会话授权"), "revoke_exec_sessions", undefined, t("已收回所有项目会话执行授权"))}
                    >
                      {t("收回会话授权")}
                    </Button>
                  </div>
                ) : null}
              </div>
            </>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}
