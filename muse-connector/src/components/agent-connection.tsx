import { useEffect, useState } from "react";
import { Clipboard, Copy } from "lucide-react";
import { useLanguage } from "@/lib/i18n";
import type { Confirmation } from "@/components/feedback";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { providerToolAvailable, publicAddress } from "@/lib/setup-progress";
import { agentCredentialIssue, agentTrial, connectorBrief, hasFileGrant } from "@/lib/agent-setup";
import type { DeviceNameModel } from "@/lib/use-device-name";
import type { BridgeModel, Snapshot } from "@/lib/use-bridge";

export default function AgentConnection({
  bridge,
  snapshot,
  deviceName,
  onEditDeviceName,
  confirm,
}: {
  bridge: BridgeModel;
  snapshot: Snapshot;
  deviceName: DeviceNameModel;
  onEditDeviceName: () => void;
  confirm: (value: Confirmation) => void;
}) {
  const { language, t } = useLanguage();
  const [clipboard, setClipboard] = useState<{ instructions: string; version: string | null; copied: boolean } | null>(null);
  const [tokenCopyFailure, setTokenCopyFailure] = useState<{ version: string | null } | null>(null);
  const { file_access: policy, agent_ready: ready, agent_enabled: enabled, agent_token_version: tokenVersion, exec_enabled: execEnabled } = snapshot;
  const hasPermission = hasFileGrant(policy);
  const canIssue = hasPermission && !snapshot.setup_error;
  const origin = publicAddress(snapshot);
  const instructions = ready && origin && deviceName.canCopy ? connectorBrief(language, origin, agentTrial(t, policy).instruction, deviceName.saved, execEnabled) : null;
  const version = tokenVersion ?? null;
  const copyResult = instructions && clipboard?.instructions === instructions && clipboard.version === version ? clipboard : null;
  const busy = !!bridge.busy;
  const development = snapshot.profile === "development";
  const providerAvailable = providerToolAvailable(snapshot);

  useEffect(() => setClipboard(null), [deviceName.saved]);

  const issueCredential = () => {
    const details = agentCredentialIssue(t);
    confirm({
      title: details.title,
      description: details.description,
      action: details.action,
      execute: async () => {
        const result = await bridge.run(details.busy, "set_agent_access", { enabled: true }, details.done);
        if (result.ok) {
          setClipboard(null);
          setTokenCopyFailure(null);
        }
        return result.ok;
      },
    });
  };

  const copy = async () => {
    if (!instructions) return;
    try {
      await navigator.clipboard.writeText(instructions);
      setClipboard({ instructions, version, copied: true });
    } catch {
      setClipboard({ instructions, version, copied: false });
    }
  };

  const copyToken = async () => {
    setTokenCopyFailure(null);
    const result = await bridge.run(t("正在复制专用令牌"), "copy_agent_token", undefined, t("令牌已复制，请粘贴到 Muse 安全卡片"), false);
    if (!result.ok) setTokenCopyFailure({ version });
  };

  const description = !enabled
    ? !policy
      ? t("在「文件权限」保存授权后，即可生成 Muse 专用令牌。")
      : !hasPermission
        ? t("保存至少一项访问权限后，即可生成 Muse 专用令牌。")
        : t("授权已保存。生成专用令牌后，即可将接入说明发给 Muse。")
    : !ready
      ? t("请检查「文件权限」中已保存的文件授权。")
      : development
        ? t("此环境使用独立的测试令牌与模拟连接。")
        : !origin
          ? providerAvailable
            ? t("在右上角开启连接。连接就绪后即可复制接入说明。")
            : t("请先安装并登录所选公网转发工具。")
          : deviceName.canCopy
            ? t("先把接入说明发给 Muse。打开 Muse 的安全卡片后，再复制专用令牌进行粘贴。")
            : t(deviceName.dirty ? "请先保存或取消设备名称的更改。" : "请先保存设备名称，再复制接入说明。");

  return (
    <Card id="muse-agent-connection" tabIndex={-1} className="focus-visible:outline focus-visible:outline-ring">
      <CardHeader>
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <CardTitle>{t("Muse 接入说明")}</CardTitle>
          <Badge variant="outline" role="status">
            {ready ? t("专用令牌已生成") : enabled ? t("当前授权不可用") : t("未生成专用令牌")}
          </Badge>
        </div>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {!enabled ? (
          <div>
            <Button size="sm" disabled={busy || !canIssue} onClick={issueCredential}>
              {t("生成 Muse 专用令牌")}
            </Button>
          </div>
        ) : (
          <>
            <div className="flex flex-wrap gap-2">
              <Button size="sm" disabled={busy || !instructions} onClick={() => void copy()}>
                <Clipboard data-icon="inline-start" />
                {t("复制 Muse 接入说明")}
              </Button>
              <Button size="sm" variant="outline" disabled={busy} onClick={() => void copyToken()}>
                <Copy data-icon="inline-start" />
                {t("复制专用令牌")}
              </Button>
              {ready && origin && !deviceName.canCopy ? (
                <Button size="sm" variant="ghost" onClick={onEditDeviceName}>
                  {t("设置设备名称")}
                </Button>
              ) : null}
            </div>
            {tokenCopyFailure?.version === version ? (
              <p className="text-caption" role="alert">
                {t("复制令牌失败。请重试，或在「设置 → 数据」打开本机令牌目录后手动复制。")}
              </p>
            ) : null}
            {copyResult?.copied ? (
              <p className="text-caption text-muted-foreground" role="status">
                {t("说明已复制，可以发给 Muse。")}
              </p>
            ) : copyResult ? (
              <div className="flex flex-col gap-2">
                <label className="text-caption text-muted-foreground" htmlFor="muse-agent-instructions">
                  {t("请手动复制这段接入说明。")}
                </label>
                <textarea
                  id="muse-agent-instructions"
                  className="max-h-48 min-h-24 w-full resize-y rounded-md border border-input bg-transparent p-2 text-caption"
                  value={copyResult.instructions}
                  readOnly
                  onFocus={event => event.currentTarget.select()}
                />
              </div>
            ) : null}
          </>
        )}
      </CardContent>
    </Card>
  );
}
