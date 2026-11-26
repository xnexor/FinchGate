import { useLanguage } from "@/lib/i18n";
import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type CSSProperties } from "react";
import { Play, Pause, X } from "lucide-react";
import { toast } from "sonner";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Spinner } from "@/components/ui/spinner";
import { StatusBadge } from "@/components/status-badge";
import { ConfirmAction, Notice, type Confirmation } from "@/components/feedback";
import ApprovalDialog from "@/components/approval-dialog";
import { useBridge, type BridgeModel } from "@/lib/use-bridge";
import { LanguageProvider } from "@/lib/i18n";
import { connectionPresentation } from "@/lib/connection-presentation";
import { providerToolAvailable, readSetupVerification, setupStorageKey } from "@/lib/setup-progress";
import { hasFileGrant } from "@/lib/agent-setup";
import { useDeviceName } from "@/lib/use-device-name";
import Overview from "@/pages/overview";

const Connection = lazy(() => import("@/pages/connection"));
const Roots = lazy(() => import("@/pages/roots"));
const Logs = lazy(() => import("@/pages/logs"));
const Settings = lazy(() => import("@/pages/settings"));
const About = lazy(() => import("@/pages/about"));
const SetupGuide = lazy(() => import("@/components/setup-guide"));
const pages = [["overview", "概览"], ["connection", "连接"], ["roots", "文件权限"], ["logs", "日志"], ["settings", "设置"], ["about", "关于"]] as const;
const legacyGuidePreference = "muse-connector:setup-in-progress";

function shouldResumeGuide(key: string, useLegacy: boolean) {
  try {
    return localStorage.getItem(key) === "1" || (useLegacy && localStorage.getItem(legacyGuidePreference) === "1");
  } catch {
    return false;
  }
}

export default function App() {
  const bridge = useBridge();
  return <LanguageProvider language={bridge.snapshot?.desktop.language ?? "zh-CN"}>
    <AppContent bridge={bridge} />
  </LanguageProvider>;
}

function AppContent({ bridge }: { bridge: BridgeModel }) {
  const { t, diagnostic } = useLanguage();
  const loadingPage = <div className="page-stack" aria-label={t("正在加载")}><Skeleton className="h-48 w-full" /><Skeleton className="h-36 w-full" /></div>;
  const { snapshot: s, busy, error } = bridge;
  const [page, setPage] = useState("overview");
  const [visited, setVisited] = useState(() => new Set<string>());
  const [connectionDirty, setConnectionDirty] = useState(false);
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const [focusRequest, setFocusRequest] = useState<{ page: string; target: string } | null>(null);
  const [guideOverride, setGuideMode] = useState<"collapsed" | "expanded" | null>(null);
  const [guideSpace, setGuideSpace] = useState(0);
  const [guideActivation, setGuideActivation] = useState(0);
  const [dialogOpen, setDialogOpen] = useState(false);
  const scroll = useRef<HTMLDivElement>(null);
  const confirmationTrigger = useRef<HTMLElement | null>(null);
  const clearGuideTestError = useRef(false);
  const storageKey = s ? setupStorageKey(s) : "";
  const useLegacyGuide = s?.profile === "production" && s.initialized;
  const resumeGuide = useMemo(() => !!storageKey && shouldResumeGuide(storageKey, useLegacyGuide), [storageKey, useLegacyGuide]);
  const guideMode = guideOverride ?? (resumeGuide ? "collapsed" : "hidden");
  const guideVisible = guideMode !== "hidden";
  const guiding = guideMode === "expanded";
  const guideSuspended = dialogOpen || confirmation !== null;
  const rememberGuide = useCallback((inProgress: boolean) => {
    if (!storageKey) return;
    try {
      if (inProgress) localStorage.setItem(storageKey, "1");
      else localStorage.removeItem(storageKey);
      if (useLegacyGuide) localStorage.removeItem(legacyGuidePreference);
    } catch {
      // 浏览器存储不可用时仍保留本次会话的进度。
    }
  }, [storageKey, useLegacyGuide]);
  const verified = !!storageKey && readSetupVerification(storageKey + ":agent")?.read === true;
  const deviceName = useDeviceName(bridge, verified || (!guiding && page === "connection" && !!s?.agent_ready && !!s.desktop.device_name), (name, copy, pending) => {
    if (!pending) { toast.success(t("设备名称已保存")); return; }
    toast(t("本机已改名为「{0}」", name), {
      id: "device-name-update",
      position: guiding ? "top-left" : "bottom-right",
      description: t("请在 Muse 中更新这台设备的名称。"),
      action: {
        label: t(copy ? "复制改名说明" : "查看改名状态"),
        onClick: () => {
          if (copy) void copy().then(ok => {
            if (ok) toast.success(t("改名说明已复制，请粘贴给 Muse。"));
            else navigate("connection", "connection-device-name");
          });
          else navigate("connection", "connection-device-name");
        },
      },
    });
  });
  useEffect(() => {
    if (!deviceName.pending) toast.dismiss("device-name-update");
  }, [deviceName.pending]);
  useEffect(() => { scroll.current?.querySelector('[data-slot="scroll-area-viewport"]')?.scrollTo(0, 0); }, [page]);
  useEffect(() => {
    if (!guideVisible) return;
    const checkDialogs = () => setDialogOpen(!!document.querySelector('[data-slot="dialog-content"], [data-slot="alert-dialog-content"]'));
    const observer = new MutationObserver(checkDialogs);
    // Radix 将模态弹层挂到 body，避免观察页面里的普通渲染。
    observer.observe(document.body, { childList: true });
    checkDialogs();
    return () => observer.disconnect();
  }, [guideVisible]);
  useEffect(() => {
    if (!focusRequest || focusRequest.page !== page || confirmation || dialogOpen) return;
    const content = scroll.current;
    if (!content) return;
    const focusTarget = () => {
      const target = document.getElementById(focusRequest.target);
      if (!target || !content.contains(target) || !target.getClientRects().length || target.matches(":disabled")) return;
      observer.disconnect();
      target.scrollIntoView({ block: "start", inline: "nearest" });
      target.focus({ preventScroll: true });
      setFocusRequest(current => current === focusRequest ? null : current);
    };
    const observer = new MutationObserver(focusTarget);
    observer.observe(content, { childList: true, subtree: true, attributes: true, attributeFilter: ["hidden", "disabled"] });
    focusTarget();
    return () => observer.disconnect();
  }, [confirmation, dialogOpen, focusRequest, page]);
  const confirm = (value: Confirmation) => { confirmationTrigger.current = document.activeElement instanceof HTMLElement ? document.activeElement : null; bridge.setError(null); setConfirmation(value); };
  const selectPage = (next: string, target?: string) => {
    setVisited(previous => previous.has(next) ? previous : new Set(previous).add(next));
    setPage(next);
    setFocusRequest(target ? { page: next, target } : null);
  };
  const navigate = (next: string, target?: string) => {
    if (next === page) {
      if (target) setFocusRequest({ page, target });
      return;
    }
    if (page === "connection" && connectionDirty) {
      confirm({ title: t("连接方式尚未应用"), description: t("草稿会保留。当前连接继续使用已生效的配置，返回连接页后可继续编辑。"), action: t("保留草稿并离开"), execute: async () => { selectPage(next, target); return true; } });
    } else selectPage(next, target);
  };
  const expandGuide = () => {
    setGuideMode("expanded");
    setGuideActivation(value => value + 1);
  };
  const testPublicConnection = (fromGuide = false) => {
    const address = s?.status.url;
    if (!s || !address || s.profile !== "production" || !s.status.api_up || !s.status.funnel_up || busy) return;
    const agent = fromGuide || s.agent_ready;
    if (agent && !s.agent_ready) return;
    clearGuideTestError.current = fromGuide;
    confirm({
      title: t("测试此公网入口？"),
      description: agent
        ? t("将使用 Muse 专用令牌检查 {0} 的文件权限接口。通过后即可接入 Muse。", address)
        : t("将使用文件令牌检查 {0} 的 File Bridge 健康接口。", address),
      action: t("测试公网健康"),
      execute: async () => (await bridge.run(t("正在测试公网"), "test_public_connection", { agent }, t("公网健康接口已验证"))).ok,
    });
  };
  const paused = !s?.desktop.desired_enabled;
  const connectionBusy = busy === "startConnection" || busy === "pauseConnection";
  const transitional = connectionBusy || s?.status.health === "Starting" || s?.status.health === "Stopping";
  const stopping = busy === "pauseConnection" || s?.status.health === "Stopping";
  const presentation = connectionPresentation(t, s, busy);
  const needsAttention = !!s?.connection_configured && !s.setup_error && (presentation.tone === "warning" || presentation.tone === "error");
  const showConnectionControl = !!s && (!paused || s.connection_configured && !guiding);
  return <TooltipProvider><main className="flex h-dvh flex-col" style={{ "--setup-guide-space": `${guideSpace}px` } as CSSProperties}>
    <header className="app-shell app-header flex shrink-0 items-center justify-between gap-3">
      <div className="flex min-w-0 flex-col gap-2">
        <div className="flex flex-wrap items-center gap-3"><h1 className="text-xl leading-7 font-semibold">{t("Muse连接器")}</h1>{s ? <Badge variant="outline">{s.profile === "development" ? t("开发隔离") : `v${s.version}`}</Badge> : null}</div>
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1" role="status" aria-atomic="true"><StatusBadge tone={presentation.tone} pending={presentation.pending}>{presentation.label}</StatusBadge>{connectionDirty ? <span className="text-caption text-muted-foreground">{t("连接草稿未应用")}</span> : null}</div>
      </div>
      {showConnectionControl ? <Button disabled={!s || transitional || (paused && (!!s.setup_error || !!busy || (s.profile === "production" && !providerToolAvailable(s))))} onClick={() => void bridge.run(paused ? "startConnection" : "pauseConnection", "toggle_connection", { enable: paused }, paused ? undefined : t("本应用连接已暂停"))}>
        {transitional ? <Spinner data-icon="inline-start" aria-hidden="true" role="presentation" /> : paused ? <Play data-icon="inline-start" /> : <Pause data-icon="inline-start" />}{transitional ? stopping ? t("正在暂停…") : t("正在开启…") : paused ? t("开启连接") : t("暂停连接")}
      </Button> : null}
    </header>
    <Tabs value={page} onValueChange={navigate} className="min-h-0 flex-1 gap-0">
      <nav className="app-shell app-navigation shrink-0" aria-label={t("主导航")}><TabsList className="grid h-auto w-full grid-cols-6">{pages.map(([value, label]) => <TabsTrigger key={value} value={value} className="min-w-0 px-1 text-center text-xs leading-tight whitespace-normal sm:text-sm">{t(label)}</TabsTrigger>)}</TabsList></nav>
      <ScrollArea ref={scroll} className="app-scroll min-h-0 flex-1" type="hover" scrollHideDelay={150}>
        <div className="app-shell app-page flex flex-col gap-4">
          {error && !confirmation && !(needsAttention && error === s?.status.note) ? <Notice title={t("操作未完成")} error><p>{diagnostic(error)}</p><Button variant="ghost" size="sm" onClick={() => bridge.setError(null)}><X data-icon="inline-start" />{t("收起提示")}</Button></Notice> : null}
          {s?.setup_error && !s.fresh_setup ? <Notice title={t("配置需要修复")} tone="warning">{diagnostic(s.setup_error)}</Notice> : null}
          {needsAttention && !guiding ? <Notice title={s.status.health === "Conflict" ? t("本地端口冲突") : t("连接需要处理")} tone={presentation.tone === "error" ? "error" : "warning"}>{s.agent_ready && s.status.agent_public_verified === false && s.status.health === "Up" ? t("Muse 专用令牌的公网验证未通过，请重试。") : diagnostic(s.status.note)}</Notice> : null}
          {s?.log_errors?.length ? <Notice title={t("日志未能完整保存")} error>{s.log_errors.map(diagnostic).join(" · ")}</Notice> : null}
          {s ? <>
            <TabsContent value="overview"><Overview bridge={bridge} confirm={confirm} guideVisible={guideVisible} guiding={guiding} onStartGuide={expandGuide} onOpenConnection={() => navigate("connection", "muse-agent-connection")} onTestPublicConnection={() => testPublicConnection()} /></TabsContent>
            {visited.has("connection") ? <TabsContent value="connection" forceMount className="data-[state=inactive]:hidden"><Suspense fallback={loadingPage}><Connection bridge={bridge} deviceName={deviceName} confirm={confirm} guiding={guiding} onDirtyChange={setConnectionDirty} onStartGuide={expandGuide} onCollapseGuide={() => setGuideMode("collapsed")} /></Suspense></TabsContent> : null}
            <TabsContent value="roots">{page === "roots" ? <Suspense fallback={loadingPage}><Roots bridge={bridge} guided={guideVisible && !hasFileGrant(s.file_access)} guiding={guiding} onAccessSaved={expandGuide} confirm={confirm} /></Suspense> : null}</TabsContent>
            {visited.has("logs") ? <TabsContent value="logs" forceMount className="data-[state=inactive]:hidden"><Suspense fallback={loadingPage}><Logs key={s.run_id} bridge={bridge} selected={page === "logs"} /></Suspense></TabsContent> : null}
            {visited.has("settings") ? <TabsContent value="settings" forceMount className="data-[state=inactive]:hidden"><Suspense fallback={loadingPage}><Settings bridge={bridge} confirm={confirm} /></Suspense></TabsContent> : null}
            <TabsContent value="about">{page === "about" ? <Suspense fallback={loadingPage}><About version={s.version} onError={bridge.setError} /></Suspense> : null}</TabsContent>
          </> : loadingPage}
        </div>
      </ScrollArea>
    </Tabs>
    {s && guideVisible ? <Suspense fallback={null}>
      <SetupGuide key={storageKey} snapshot={s} bridge={bridge} deviceName={deviceName} storageKey={storageKey} page={page} expanded={guiding} suspended={guideSuspended} activation={guideActivation}
        onExpand={expandGuide} onCollapse={() => setGuideMode("collapsed")} onNavigate={navigate}
        onHeightChange={setGuideSpace} onProgressChange={rememberGuide} confirm={confirm} onTestPublicConnection={() => testPublicConnection(true)} />
    </Suspense> : null}
    <ConfirmAction value={confirmation} close={() => {
      if (clearGuideTestError.current) bridge.setError(null);
      clearGuideTestError.current = false;
      setConfirmation(null);
    }} busy={!!busy} error={error} restoreFocus={() => {
      if (focusRequest) return;
      const target = confirmationTrigger.current;
      if (target?.isConnected && target.getClientRects().length && !target.matches(":disabled")) target.focus();
      else document.querySelector<HTMLElement>('[role="tab"][aria-selected="true"]')?.focus();
    }} />
    <ApprovalDialog bridge={bridge} />
  </main><Toaster theme="dark" richColors={false} containerAriaLabel={t("通知")}
    position={guideVisible ? "top-left" : "bottom-right"}
    toastOptions={{ className: guideVisible ? "setup-guide-toast" : undefined, closeButtonAriaLabel: t("关闭") }} closeButton /></TooltipProvider>;
}
