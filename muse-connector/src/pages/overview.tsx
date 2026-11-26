import { useLanguage } from "@/lib/i18n";
import { lazy, Suspense, useState } from "react";
import { Check, Copy, Link2, Server, Globe, ShieldCheck, RefreshCw } from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent, CardFooter } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Notice, type Confirmation } from "@/components/feedback";
import { formatBytes, formatTime, providerLabels, type BridgeModel } from "@/lib/use-bridge";
const RequestTrend = lazy(() => import("@/components/request-trend"));

export default function Overview({ bridge, confirm, guideVisible, guiding, onStartGuide, onOpenConnection, onTestPublicConnection }: {
  bridge: BridgeModel;
  confirm: (value: Confirmation) => void;
  guideVisible: boolean;
  guiding: boolean;
  onStartGuide: () => void;
  onOpenConnection: () => void;
  onTestPublicConnection: () => void;
}) {
  const { language, t } = useLanguage();
  const { snapshot: s, run, busy, legacy } = bridge;
  const [copied, setCopied] = useState(false);
  if (!s) return null;
  if (s.fresh_setup) return guiding ? null : <Card>
    <CardHeader><CardTitle>{t("首次配置")}</CardTitle><CardDescription>{t("选择 Muse 的文件管理方式。")}</CardDescription></CardHeader>
    {!guideVisible ? <CardFooter><Button size="sm" onClick={onStartGuide}>{t("开始指引")}</Button></CardFooter> : null}
  </Card>;
  const accessCard = guiding ? null : <Card>
    <CardHeader><CardTitle>{t("本机文件授权已保存")}</CardTitle><CardDescription>
      {s.agent_ready ? t("专用令牌已生成。在连接页查看 Muse 接入说明。") : t("在连接页生成专用令牌，继续接入 Muse 文件工具。")}
    </CardDescription></CardHeader>
    <CardFooter><Button size="sm" onClick={onOpenConnection}>{t("前往连接页")}</Button></CardFooter>
  </Card>;
  if (!s.connection_configured) return s.access_configured ? accessCard : null;
  const development = s.profile === "development";
  const verified = s.agent_ready ? s.status.agent_public_verified : s.status.public_verified;
  const stats = s.stats.file_activity;
  const timeLabel = (value: string | null) => value ? formatTime(value, language) : t("尚无记录");
  const errorRate = stats.completed ? `${(100 * stats.errors / stats.completed).toFixed(1)}%` : t("尚未统计");
  return <div className="page-stack">
    {!s.initialized ? accessCard : null}
    {legacy?.needs_takeover && !development && legacy.migration_phase !== "active" ? <Notice title={t("检测到旧计划任务")}>
      <p>{t("接管前会保存原状态，先停止看门狗，再切换文件服务。旧任务保留，可按快照恢复。")}</p>
      <div className="flex flex-wrap gap-3"><Button size="sm" disabled={!!busy || !s.initialized} onClick={() => confirm({ title: t("接管旧文件服务？"), description: t("将保存当前任务状态，停用旧看门狗与文件服务，并由本程序接管。失败会尝试按快照恢复。"), action: t("确认接管"), execute: async () => (await run(t("正在接管旧服务"), "takeover_legacy", undefined, t("接管完成，仍需 Muse 实际读写验收"))).ok })}>{t("接管旧系统")}</Button></div>
    </Notice> : null}
    <Card><CardHeader><CardTitle>{t("连接入口")}</CardTitle><CardDescription>{t(providerLabels[s.desktop.provider.kind])}</CardDescription></CardHeader>
      <CardContent className="flex flex-col gap-5">
        {s.status.url ? (
          <div className="flex min-w-0 items-center gap-3">
            <code className="flex min-h-10 min-w-0 flex-1 items-center select-text break-all rounded-md border border-input bg-transparent px-3 py-2 text-sm font-normal">{s.status.url}</code>
            <Button
              variant="outline"
              aria-label={t("复制公网地址")}
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(s.status.url!);
                  setCopied(true);
                  setTimeout(() => setCopied(false), 1800);
                } catch {
                  bridge.setError(t("复制地址失败，请选择地址后手动复制。"));
                }
              }}
            >
              {copied ? <Check data-icon="inline-start" /> : <Copy data-icon="inline-start" />}
              {copied ? t("已复制") : t("复制")}
            </Button>
          </div>
        ) : <p className="text-muted-foreground">{development ? t("开发模式使用模拟连接，不创建公网地址。") : t("开启连接后将在此显示实际地址。")}</p>}
        <dl className="detail-grid">
          <div><dt className="flex items-center gap-2 text-muted-foreground"><Server className="size-4" />{t("本地文件服务")}</dt><dd className="flex flex-wrap items-center gap-x-3 gap-y-1"><span>{s.status.api_up ? t("运行中") : t("已停止监听")}</span>{s.status.api_up ? <span className="tabular-nums">127.0.0.1:{s.status.api_port}</span> : null}</dd></div>
          <div><dt className="flex items-center gap-2 text-muted-foreground"><Link2 className="size-4" />{t("入口状态")}</dt><dd>{development ? s.status.funnel_up ? t("模拟入口就绪") : t("模拟入口已暂停") : s.status.funnel_up ? t("转发已配置") : s.desktop.desired_enabled ? t("尚未就绪") : t("已暂停")}</dd></div>
          <div className="min-[600px]:col-span-2"><dt className="flex items-center gap-2 text-muted-foreground"><Globe className="size-4" />{t("公网健康检查")}</dt><dd>{development ? t("开发隔离，不执行") : verified === true ? t("检查已通过") : verified === false ? t("检查未通过，请重试") : t("尚未进行公网健康检查")}</dd></div>
          <div><dt className="text-muted-foreground">{t("最近探测")}</dt><dd className="tabular-nums">{timeLabel(s.status.last_check)}</dd></div>
          <div><dt className="text-muted-foreground">{t("最近文件访问（已鉴权）")}</dt><dd className="tabular-nums">{timeLabel(stats.last_request)}</dd></div>
        </dl>
        {!guiding ? <div className="flex flex-wrap gap-3"><Button variant="outline" size="sm" disabled={!!busy || development || !s.status.api_up || !s.status.funnel_up || !s.status.url} onClick={onTestPublicConnection}><ShieldCheck data-icon="inline-start" />{t("测试公网健康")}</Button><Button size="sm" variant="ghost" disabled={!!busy} onClick={() => void bridge.refresh()}><RefreshCw data-icon="inline-start" />{t("刷新状态")}</Button></div> : null}
      </CardContent>
    </Card>
    <Card><CardHeader><CardTitle>{t("本次会话的文件活动")}</CardTitle><CardDescription>{t("统计目录列表、读取、写入和新建目录，包含失败请求，不含健康探测。")}</CardDescription></CardHeader><CardContent className="flex flex-col gap-5">
      <dl className="metric-grid">{[[t("文件请求"), stats.total.toLocaleString(language)], [t("鉴权失败"), stats.auth_failures.toLocaleString(language)], [t("读取"), formatBytes(stats.read_bytes)], [t("写入"), formatBytes(stats.written_bytes)]].map(([label, value]) => <div key={label}><dt className="text-caption text-muted-foreground">{label}</dt><dd className="mt-1 text-xl font-semibold tabular-nums">{value}</dd></div>)}</dl>
      <div className="flex flex-wrap items-center justify-between gap-2"><span className="text-caption text-muted-foreground">{t("最近 15 分钟 · 实线请求，虚线错误")}</span><Badge variant="outline">{t("文件请求错误率 {0}", errorRate)}</Badge></div>
      {stats.trend.length > 1 ? <Suspense fallback={<Skeleton className="h-36 w-full" />}><RequestTrend data={stats.trend} /></Suspense> : <p className="py-4 text-center text-caption text-muted-foreground">{t("等待更多分钟的数据后显示趋势。")}</p>}
    </CardContent></Card>
  </div>;
}
