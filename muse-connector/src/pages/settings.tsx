import { useState } from "react";
import { isTauri } from "@tauri-apps/api/core";
import { useLanguage } from "@/lib/i18n";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Field, FieldGroup, FieldLabel, FieldContent, FieldDescription } from "@/components/ui/field";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import LogExportDialog from "@/components/log-export-dialog";
import type { Confirmation } from "@/components/feedback";
import { hasFileGrant } from "@/lib/agent-setup";
import type { Language } from "@/lib/i18n";
import { formatBytes, type BridgeModel, type IndexStatus } from "@/lib/use-bridge";

const indexLabels = {
  waiting: "等待建立索引",
  indexing: "正在建立索引",
  ready: "NTFS 索引已就绪",
  directory_search: "目录索引已就绪",
  unavailable: "索引暂不可用",
  clearing: "正在清除索引",
  cleared: "索引已清除，自动建库已暂停",
  clear_failed: "索引清除失败，自动建库已暂停",
} as const satisfies Record<IndexStatus["state"], string>;

export default function Settings({
  bridge,
  confirm,
}: {
  bridge: BridgeModel;
  confirm: (value: Confirmation) => void;
}) {
  const { t } = useLanguage();
  const { snapshot: s, busy, run } = bridge;
  const [exportOpen, setExportOpen] = useState(false);
  if (!s) return null;

  const development = s.profile === "development";
  const policy = s.file_access;
  const savedSearch = !!policy && policy.search !== "off";
  const showNtfsHelp = policy?.search === "all_local" && s.ntfs_search_service === false;
  const indexStatus = s.index_status;
  const canClearIndex = (savedSearch || (indexStatus.bytes ?? 0) > 0 || indexStatus.state === "clear_failed")
    && indexStatus.state !== "cleared" && indexStatus.state !== "clearing";
  const canRebuildIndex = indexStatus.state === "cleared" && savedSearch;
  const canRotateToken = s.agent_enabled && hasFileGrant(policy) && !s.setup_error;

  const indexDescription = `${
    !savedSearch && indexStatus.state === "waiting"
      ? t("保存搜索授权后，连接器会在后台建立索引。")
      : t(indexLabels[indexStatus.state])
  }${indexStatus.bytes != null ? t(" · 占用 {0}", formatBytes(indexStatus.bytes)) : ""}`;

  return (
    <div className="page-stack">
      <Card>
        <CardHeader>
          <CardTitle>{t("常规")}</CardTitle>
        </CardHeader>
        <CardContent>
          <FieldGroup className="gap-5">
            <Field orientation="horizontal">
              <FieldLabel htmlFor="display-language">{t("界面语言")}</FieldLabel>
              <Select
                value={s.desktop.language ?? "zh-CN"}
                disabled={!!busy}
                onValueChange={(language: Language) => void run(t("正在切换界面语言"), "set_language", { language })}
              >
                <SelectTrigger id="display-language" className="w-40">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="zh-CN"><span lang="zh-CN">简体中文</span></SelectItem>
                  <SelectItem value="en"><span lang="en">English</span></SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Field orientation="horizontal">
              <FieldContent>
                <FieldLabel htmlFor="autostart">{t("开机自动启动")}</FieldLabel>
                <FieldDescription>
                  {development
                    ? t("开发模式不修改正式自启项。")
                    : s.autostart === null
                      ? t("无法读取系统注册状态，请稍后重试。")
                      : t("开启后 Muse连接器 会在你登录电脑后自动启动")}
                </FieldDescription>
              </FieldContent>
              <Switch
                id="autostart"
                checked={s.autostart === true}
                disabled={!!busy || development || s.autostart === null}
                onCheckedChange={enable => void run(t("正在设置登录自启"), "set_autostart", { enable }, t("登录自启设置已更新"))}
              />
            </Field>
            <Field orientation="horizontal">
              <FieldContent>
                <FieldLabel htmlFor="close-to-tray">{t("关闭时最小化到托盘")}</FieldLabel>
                <FieldDescription>{t("关闭 Muse连接器 时自动最小化到托盘，不会退出。")}</FieldDescription>
              </FieldContent>
              <Switch
                id="close-to-tray"
                checked={s.desktop.close_to_tray ?? true}
                disabled={!!busy}
                onCheckedChange={closeToTray => void run(t("正在保存窗口偏好"), "save_preferences", { closeToTray }, t("窗口偏好已保存"))}
              />
            </Field>
          </FieldGroup>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{t("数据")}</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-5">
          {/* 1. 本机数据 */}
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex min-w-0 flex-col gap-1">
              <p className="text-sm font-medium text-foreground">{t("本机数据")}</p>
              <p className="select-text break-all text-caption text-muted-foreground">{t("存放于 {0}", s.home)}</p>
            </div>
            <div className="flex shrink-0 flex-wrap items-center gap-2">
              <Button variant="outline" size="sm" disabled={!!busy} onClick={() => void run(t("正在打开数据目录"), "open_local_folder")}>
                {t("打开目录")}
              </Button>
            </div>
          </div>

          {/* 2. 本机文件索引 */}
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex min-w-0 flex-col gap-1">
              <p className="text-sm font-medium text-foreground">{t("本机文件索引")}</p>
              <p aria-live="polite" className="text-caption text-muted-foreground">{indexDescription}</p>
            </div>
            <div className="flex shrink-0 flex-wrap items-center gap-2">
              {showNtfsHelp ? (
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={!!busy}
                  onClick={() => void run(t("正在打开快速索引设置说明"), "open_tool_setup", { tool: "everything" })}
                >
                  {t("启用说明")}
                </Button>
              ) : null}
              {canRebuildIndex ? (
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={!!busy}
                  onClick={() => void run(t("正在恢复索引"), "rebuild_search_index", undefined, t("已开始重新建立索引"))}
                >
                  {t("重新建立索引")}
                </Button>
              ) : null}
              {canClearIndex ? (
                <Button
                  variant="ghost"
                  size="sm"
                  disabled={!!busy}
                  onClick={() => confirm({
                    title: t("清除本机索引？"),
                    description: t("将清除连接器的搜索索引。下次使用 Muse 搜索前，需要手动重新建立索引。"),
                    action: t("清除索引"),
                    execute: async () => (await run(t("正在清除本机索引"), "clear_search_index", undefined, t("本机索引已清除"))).ok,
                  })}
                >
                  {indexStatus.state === "clear_failed" ? t("重试清除索引") : t("清除本机索引")}
                </Button>
              ) : null}
              <Button variant="outline" size="sm" disabled={!!busy} onClick={() => void run(t("正在打开索引目录"), "open_index_folder")}>
                {t("打开目录")}
              </Button>
            </div>
          </div>

          {/* 3. 日志数据 */}
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex min-w-0 flex-col gap-1">
              <p className="text-sm font-medium text-foreground">{t("日志数据")}</p>
              <p className="text-caption text-muted-foreground">
                {t("保存程序运行日志 · 占用 {0}", formatBytes(s.log_bytes ?? 0))}
              </p>
            </div>
            <div className="flex shrink-0 flex-wrap items-center gap-2">
              <Button
                variant="ghost"
                size="sm"
                disabled={!!busy || !isTauri()}
                onClick={() => confirm({
                  title: t("清除所有日志？"),
                  description: t("将清空内存缓存并删除本机历史日志文件，此操作不可恢复。"),
                  action: t("清除日志"),
                  execute: async () => (await run(t("正在清除日志"), "clear_logs", undefined, t("日志已清除"))).ok,
                })}
              >
                {t("清除日志")}
              </Button>
              <Button variant="ghost" size="sm" disabled={!!busy || !isTauri()} onClick={() => setExportOpen(true)}>
                {t("导出日志")}
              </Button>
              <Button variant="outline" size="sm" disabled={!!busy || !isTauri()} onClick={() => void run(t("正在打开日志目录"), "open_logs_folder", { kind: "audit" })}>
                {t("打开目录")}
              </Button>
            </div>
          </div>

          {/* 4. 本机令牌 */}
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="flex min-w-0 flex-col gap-1">
              <p className="text-sm font-medium text-foreground">{t("本机令牌")}</p>
              <p className="text-caption text-muted-foreground">
                {s.agent_enabled ? t("用于和 Muse 连接的专属密钥") : t("用于和 Muse 连接的专属密钥（尚未生成）")}
              </p>
            </div>
            <div className="flex shrink-0 flex-wrap items-center gap-2">
              <Button
                variant="ghost"
                size="sm"
                className="text-status-error hover:text-status-error"
                disabled={!!busy || !s.agent_enabled}
                onClick={() => confirm({
                  title: t("撤销 Muse 专用令牌？"),
                  description: t("现有 Muse 文件工具的令牌会立即失效。文件权限及旧版 File Bridge 连接仍可单独管理。"),
                  action: t("撤销令牌"),
                  execute: async () => (await run(t("正在撤销 Muse 专用令牌"), "set_agent_access", { enabled: false }, t("Muse 专用令牌已撤销"))).ok,
                })}
              >
                {t("撤销令牌")}
              </Button>
              <Button
                variant="ghost"
                size="sm"
                disabled={!!busy || !canRotateToken}
                onClick={() => confirm({
                  title: t("轮换 Muse 专用令牌？"),
                  description: t("当前 Muse 专用令牌会立刻失效。轮换后请更新 Muse 安全卡片中的令牌。"),
                  action: t("轮换令牌"),
                  execute: async () => (await run(t("正在轮换 Muse 专用令牌"), "set_agent_access", { enabled: true }, t("Muse 专用令牌已轮换"))).ok,
                })}
              >
                {t("轮换令牌")}
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={!!busy || !s.agent_enabled}
                onClick={() => void run(t("正在定位令牌文件"), "open_agent_token", undefined, undefined, false)}
              >
                {t("打开目录")}
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      <LogExportDialog open={exportOpen} onOpenChange={setExportOpen} bridge={bridge} />
    </div>
  );
}
