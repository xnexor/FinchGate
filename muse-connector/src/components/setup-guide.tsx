import { useLanguage } from "@/lib/i18n";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { ArrowRight, Check, ChevronDown, ChevronUp, Clipboard, Copy, ExternalLink, RefreshCw } from "lucide-react";
import type { Confirmation } from "@/components/feedback";
import DeviceNameField from "@/components/device-name-field";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Field, FieldLabel } from "@/components/ui/field";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { providerToolAvailable, publicAddress, readSetupVerification, saveSetupVerification, setupRootTarget, type SetupVerification } from "@/lib/setup-progress";
import { accessPolicyKey, agentCredentialIssue, agentTrial, connectorBrief, hasFileGrant } from "@/lib/agent-setup";
import { providerLabels, type BridgeModel, type Snapshot } from "@/lib/use-bridge";
import type { DeviceNameModel } from "@/lib/use-device-name";
import { cn } from "@/lib/utils";

const steps = ["选择文件管理方式", "准备公网连接", "接入 Muse", "确认首次试用"] as const;

type GuideProps = {
  snapshot: Snapshot;
  bridge: BridgeModel;
  deviceName: DeviceNameModel;
  storageKey: string;
  page: string;
  expanded: boolean;
  suspended: boolean;
  activation: number;
  onExpand: () => void;
  onCollapse: () => void;
  onNavigate: (page: string, target?: string) => void;
  onHeightChange: (height: number) => void;
  onProgressChange: (inProgress: boolean) => void;
  confirm: (value: Confirmation) => void;
  onTestPublicConnection: () => void;
};

export default function SetupGuide({
  snapshot, bridge, deviceName, storageKey, page, expanded, suspended, activation, onExpand, onCollapse,
  onNavigate, onHeightChange, onProgressChange, confirm, onTestPublicConnection,
}: GuideProps) {
  const { language, t, diagnostic } = useLanguage();
  const container = useRef<HTMLElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const collapsedTrigger = useRef<HTMLButtonElement>(null);
  const activeRow = useRef<HTMLLIElement>(null);
  const scroll = useRef<HTMLDivElement>(null);
  const footer = useRef<HTMLDivElement>(null);
  const copyFallback = useRef<HTMLTextAreaElement>(null);
  const focusedActivation = useRef(0);
  const restoreCollapsedFocus = useRef(false);
  const focusNext = useRef(false);
  const [review, setReview] = useState<{ step: number; recommended: number } | null>(null);
  const verificationKey = storageKey + ":agent";
  const [verification, setVerification] = useState<SetupVerification | null>(() => readSetupVerification(verificationKey));
  const [selectedAlias, setSelectedAlias] = useState<string | null>(verification?.alias ?? null);
  const [copied, setCopied] = useState<{ text: string; scope: string | null; ok: boolean } | null>(null);
  const [actionError, setActionError] = useState<{ step: number; message: string } | null>(null);
  const [credentialErrorScope, setCredentialErrorScope] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [showTailscaleHelp, setShowTailscaleHelp] = useState(false);
  const { desktop, status, file_access: policy, agent_token_version: tokenVersion } = snapshot;
  const trial = agentTrial(t, policy, selectedAlias);
  const { aliases, alias } = trial;
  const accessReady = hasFileGrant(policy) && !snapshot.setup_error;
  const agentReady = accessReady && snapshot.agent_ready;
  const address = agentReady ? publicAddress(snapshot) : null;
  const development = snapshot.profile === "development";
  const stepLabels = (development ? [steps[0], "启动本机模拟", steps[2], steps[3]] as const : steps).map(label => t(label));
  const localReady = development && agentReady && status.api_up && status.funnel_up;
  const { kind, tunnel_id, hostname } = desktop.provider;
  let scope = null;
  if (agentReady && policy && tokenVersion) {
    const scopeValues = [kind, tunnel_id, hostname, tokenVersion, accessPolicyKey(policy), alias];
    // A rename is confirmed separately from the first file-access test.
    scope = JSON.stringify(scopeValues);
  }
  const saved = scope && verification?.scope === scope && (!address || verification.address === address) ? verification : null;
  const readConfirmed = saved?.read === true;
  const handedOff = !!saved && !!address;
  const publicReady = !!address && status.agent_public_verified === true;
  const canHandoff = publicReady || (handedOff && status.agent_public_verified !== false);
  const recommended = !accessReady ? 0 : readConfirmed ? 3 : !canHandoff ? 1 : handedOff ? 3 : 2;
  const selectable = [true, accessReady, canHandoff, handedOff || readConfirmed];
  const active = review?.recommended === recommended && selectable[review.step] ? review.step : recommended;
  const completed = [accessReady, canHandoff || readConfirmed || localReady, handedOff || readConfirmed, readConfirmed];
  const finished = readConfirmed || localReady;
  const guideLabel = readConfirmed ? t("首次配置已完成") : localReady ? t("本机阶段已完成")
    : t("继续配置 · {0}/{1}", recommended + 1, steps.length);
  const busy = !!bridge.busy;
  const waiting = status.health === "Starting" || status.health === "Stopping";
  const tailscale = kind === "tailscale";
  const installed = providerToolAvailable(snapshot);
  const instructions = address && deviceName.canCopy ? connectorBrief(language, address, trial.instruction, deviceName.saved, snapshot.exec_enabled) : null;

  useEffect(() => setCopied(null), [deviceName.saved]);

  useEffect(() => {
    if (verification && !saved) {
      saveSetupVerification(verificationKey, null);
      setVerification(null);
    }
  }, [saved, verificationKey, verification]);

  useEffect(() => onProgressChange(!readConfirmed), [onProgressChange, readConfirmed]);

  useEffect(() => {
    const element = container.current;
    if (!element) return;
    const measure = () => {
      const height = Math.ceil(element.getBoundingClientRect().height);
      onHeightChange(height > 0 ? height + 16 : 0);
    };
    const observer = new ResizeObserver(measure);
    observer.observe(element);
    measure();
    return () => { observer.disconnect(); onHeightChange(0); };
  }, [onHeightChange]);

  useEffect(() => {
    if (suspended) return;
    if (expanded && activation > focusedActivation.current) {
      heading.current?.focus({ preventScroll: true });
      focusedActivation.current = activation;
    } else if (!expanded && restoreCollapsedFocus.current) {
      collapsedTrigger.current?.focus({ preventScroll: true });
      restoreCollapsedFocus.current = false;
    }
  }, [activation, expanded, suspended]);

  useEffect(() => {
    if (!expanded || suspended) return;
    const viewport = scroll.current?.querySelector('[data-slot="scroll-area-viewport"]');
    const row = activeRow.current;
    if (viewport && row) {
      const area = viewport.getBoundingClientRect();
      const current = row.getBoundingClientRect();
      if (current.top < area.top || current.top + 64 > area.bottom) viewport.scrollTop += current.top - area.top;
    }
    if (focusNext.current) {
      (footer.current?.querySelector("button") ?? heading.current)?.focus({ preventScroll: true });
      focusNext.current = false;
    }
  }, [active, expanded, readConfirmed, suspended]);

  useEffect(() => {
    const field = copyFallback.current;
    if (!field) return;
    field.scrollIntoView({ block: "nearest" });
    field.focus({ preventScroll: true });
    field.select();
  }, [copied]);

  const showStep = (step: number) => {
    setReview({ step, recommended });
    setActionError(null);
  };
  const run = async (label: string, command: string, args?: Record<string, unknown>) => {
    setActionError(null);
    const result = await bridge.run(label, command, args, undefined, false);
    if (!result.ok) setActionError({ step: active, message: result.error });
  };
  const openSetup = (tool: string) => void run(t("正在打开工具说明"), "open_tool_setup", { tool });
  const refreshTools = async () => {
    setRefreshing(true);
    setActionError(null);
    try { await bridge.refresh(); }
    finally { setRefreshing(false); }
  };
  const copyInstructions = async () => {
    if (!instructions || busy) return;
    try {
      await navigator.clipboard.writeText(instructions);
      setCopied({ text: instructions, scope, ok: true });
    } catch {
      setCopied({ text: instructions, scope, ok: false });
    }
  };
  const issueToken = () => {
    const issue = agentCredentialIssue(t);
    confirm({ title: issue.title, description: issue.description, action: issue.action,
      execute: async () => (await bridge.run(issue.busy, "set_agent_access", { enabled: true }, issue.done)).ok });
  };
  const copyToken = async () => {
    setCredentialErrorScope(null);
    const result = await bridge.run(t("正在复制专用令牌"), "copy_agent_token", undefined, t("令牌已复制，请粘贴到 Muse 安全卡片"), false);
    if (!result.ok) setCredentialErrorScope(scope);
  };
  const next = (read: boolean) => {
    if (!address || !scope || busy || (read ? !handedOff : !publicReady || !instructions)) return;
    const value = { scope, alias, address, read };
    saveSetupVerification(verificationKey, value);
    setVerification(value);
    setReview(null);
    focusNext.current = true;
  };
  const collapse = () => {
    restoreCollapsedFocus.current = true;
    onCollapse();
  };

  const aliasPicker = aliases.length > 1 ? <Field>
    <FieldLabel htmlFor="setup-guide-alias">{t("试用目录")}</FieldLabel>
    <Select value={alias} onValueChange={value => setSelectedAlias(value)}>
      <SelectTrigger id="setup-guide-alias" className="w-full"><SelectValue /></SelectTrigger>
      <SelectContent><SelectGroup>{aliases.map(name => <SelectItem key={name} value={name}>{name}</SelectItem>)}</SelectGroup></SelectContent>
    </Select>
  </Field> : null;

  let content: ReactNode;
  let action: ReactNode;
  if (active === 0) {
    content = <p>{t("选择文件夹或磁盘。Muse 可以在你保存的范围内搜索、读取和写入文件。")}</p>;
    action = accessReady ? <Button size="sm" onClick={() => showStep(1)}>{t("继续到公网连接")}<ArrowRight data-icon="inline-end" /></Button>
      : <Button size="sm" onClick={() => { onNavigate("roots", "setup-file-access"); onCollapse(); }}>{t("去设置文件权限")}<ArrowRight data-icon="inline-end" /></Button>;
  } else if (active === 1) {
    if (!agentReady) {
      content = <p>{t("文件授权已保存。生成 Muse 专用令牌后，就可以准备连接。搜索索引在后台建立，你可以继续配置。")}</p>;
      action = <Button size="sm" disabled={busy} onClick={issueToken}>{t("生成 Muse 专用令牌")}</Button>;
    } else if (development) {
      content = <p>{localReady
        ? t("模拟连接已启动。本机阶段已完成，公网验证和 Muse 试用需在正式环境完成。")
        : t("此环境只启动本机模拟连接。公网验证将在正式环境完成。")}</p>;
      action = localReady ? <Button size="sm" onClick={collapse}>{t("收起引导")}</Button>
        : <Button size="sm" disabled={busy || waiting} onClick={() => void run("startConnection", "toggle_connection", { enable: true })}>
          {waiting || busy ? t("正在开启…") : t("开启模拟连接")}
        </Button>;
    } else if (address) {
      content = <>
        <p className="break-all">{t("公网地址")} <span className="select-text text-foreground">{address}</span></p>
        <p role="status">{publicReady ? t("Muse 专用令牌的公网验证已通过。") : status.agent_public_verified === false ? t("公网验证未通过，请重试。") : t("使用 Muse 专用令牌验证此公网入口。")}</p>
      </>;
      action = publicReady ? <Button size="sm" onClick={() => showStep(handedOff ? 3 : 2)}>{t("继续到 Muse")}<ArrowRight data-icon="inline-end" /></Button>
        : <Button size="sm" disabled={busy} onClick={onTestPublicConnection}>{status.agent_public_verified === false ? t("重试公网验证") : t("验证公网连接")}</Button>;
    } else {
      content = <>
        {readConfirmed && !desktop.desired_enabled ? <p>{t("首次试用已确认，当前连接已暂停。")}</p> : null}
        <p>{tailscale
          ? installed ? t("在 Windows 托盘登录 Tailscale，按提示完成首次 Funnel 授权。") : t("先下载安装 Tailscale for Windows，完成后重新检测。")
          : installed ? t("当前使用 {0}。开启连接后会生成公网地址。", t(providerLabels[kind])) : t("先安装 Cloudflare 的 cloudflared 工具，完成后重新检测。")}</p>
        {desktop.desired_enabled && status.note !== actionError?.message ? <p className="break-words" role="status">{diagnostic(status.note)}</p> : null}
        <div className="flex flex-wrap gap-2">
          {!installed ? <Button size="sm" variant="outline" disabled={busy || refreshing} onClick={() => void refreshTools()}>
            <RefreshCw data-icon="inline-start" />{refreshing ? t("正在检测…") : t("重新检测")}
          </Button> : null}
          {page !== "connection" && !tailscale ? <Button size="sm" variant="outline" onClick={() => onNavigate("connection", "provider")}>{t("查看连接设置")}</Button> : null}
        </div>
        {tailscale && installed ? <>
          <Button className="self-start px-0" size="sm" variant="link" aria-expanded={showTailscaleHelp} aria-controls="setup-tailscale-help" onClick={() => setShowTailscaleHelp(value => !value)}>{t("查看登录与 Funnel 授权")}</Button>
          {showTailscaleHelp ? <div id="setup-tailscale-help" className="flex flex-wrap gap-2">
            <Button size="sm" variant="outline" disabled={busy} onClick={() => openSetup("tailscale_login")}>{t("Windows 登录说明")}<ExternalLink data-icon="inline-end" /></Button>
            <Button size="sm" variant="outline" disabled={busy} onClick={() => openSetup("tailscale_funnel")}>{t("Funnel 授权说明")}<ExternalLink data-icon="inline-end" /></Button>
          </div> : null}
        </> : null}
      </>;
      action = installed ? <Button size="sm" disabled={busy || waiting} onClick={() => void run("startConnection", "toggle_connection", { enable: true })}>
        {waiting || bridge.busy === "startConnection" ? t("正在开启…") : desktop.desired_enabled ? t("重试开启连接") : t("开启连接")}
      </Button> : <Button size="sm" disabled={busy} onClick={() => openSetup(tailscale ? "tailscale" : "cloudflared")}>
        {tailscale ? t("下载 Tailscale") : t("下载 cloudflared")}<ExternalLink data-icon="inline-end" />
      </Button>;
    }
  } else if (active === 2) {
    const copyState = copied?.text === instructions && copied.scope === scope ? copied : null;
    const showCredentialActions = !!instructions && (!!copyState || handedOff);
    content = <>
      <DeviceNameField id="setup-device-name" deviceName={deviceName} />
      <p>{t("把接入说明发给 Muse。打开 Muse 发来的安全卡片，再复制并粘贴专用令牌。")}</p>
      {aliasPicker}
      <div className="flex flex-wrap items-center gap-2 pt-0.5">
        <Button
          size="sm"
          variant={showCredentialActions ? "outline" : "default"}
          disabled={busy || !instructions}
          onClick={() => void copyInstructions()}
        >
          <Clipboard data-icon="inline-start" />
          {showCredentialActions ? t("重新复制说明") : t("复制接入说明")}
        </Button>
        <Button size="sm" variant="outline" disabled={busy} onClick={() => void copyToken()}>
          <Copy data-icon="inline-start" />
          {t("复制专用令牌")}
        </Button>
      </div>
      {copyState ? copyState.ok
        ? <p role="status">{t("已复制，可以发给 Muse。")}</p>
        : <div className="flex flex-col gap-2">
          <p role="status">{t("复制失败，请手动复制下方说明。")}</p>
          <textarea ref={copyFallback} aria-label={t("给 Muse 的连接说明")} readOnly rows={3} value={instructions ?? ""}
            className="w-full resize-none rounded-md border border-input bg-transparent p-2 text-caption text-foreground" />
        </div> : null}
    </>;
    // 步骤正文并排提供复制说明与复制令牌，底部专注流程推进。
    action = <Button
      size="sm"
      variant={showCredentialActions ? "default" : "outline"}
      disabled={busy || !scope || (!publicReady && !handedOff) || (!showCredentialActions)}
      onClick={() => handedOff ? showStep(3) : next(false)}
    >
      {handedOff ? t("查看试用") : t("已填写，继续")}
    </Button>;
  } else if (readConfirmed) {
    content = <p role="status" className="text-foreground">{t("已在 Muse 完成首次试用。")}</p>;
    action = <Button size="sm" onClick={collapse}>{t("收起引导")}</Button>;
  } else {
    content = <>
      {deviceName.saved ? <p>{t("请在 Muse 中指定设备「{0}」。", deviceName.saved)}</p> : null}
      <p>{trial.prepare} {trial.operation === "search" ? t("让 Muse 搜索该文件名，确认返回的路径。") : trial.operation === "read" ? t("让 Muse 读取文件，核对返回内容。") : t("让 Muse 列出各操作授权的目录。")}</p>
      <details>
        <summary className="cursor-pointer text-foreground">{t("试用遇到问题？")}</summary>
        <div className="mt-2 flex flex-col gap-2">
          <p>{t("提示未授权时，检查安全卡片里的专用令牌。搜索仍在索引时，稍后用同一个文件名重试。")}</p>
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="outline" onClick={() => showStep(2)}>{t("返回安全卡片说明")}</Button>
            <Button size="sm" variant="outline" onClick={() => { onNavigate("roots", alias ? setupRootTarget(alias) : "setup-file-access"); onCollapse(); }}>{t("检查文件权限")}</Button>
          </div>
        </div>
      </details>
    </>;
    action = <Button size="sm" disabled={busy || !address} onClick={() => next(true)}>{trial.confirm}</Button>;
  }

  return <aside ref={container} className={cn("setup-guide", expanded && "setup-guide-expanded")} aria-label={t("首次配置指引")} hidden={suspended}>
    {expanded ? <Card id="muse-setup-guide" className="setup-guide-panel gap-0 overflow-hidden py-0 max-[600px]:py-0">
      <CardHeader className="border-b">
        <div className="flex min-w-0 flex-wrap items-baseline gap-x-2">
          <CardTitle ref={heading} tabIndex={-1}>{t("首次配置")}</CardTitle>
          <span className="text-caption tabular-nums text-muted-foreground" role="status">
            {finished ? readConfirmed ? t("已完成") : t("本机阶段已完成") : (active + 1) + " / " + steps.length}
          </span>
        </div>
        <CardAction><Button size="icon-sm" variant="ghost" aria-label={t("收起配置指引")} aria-expanded aria-controls="muse-setup-guide" onClick={collapse}><ChevronDown /></Button></CardAction>
      </CardHeader>
      <ScrollArea ref={scroll} className="min-h-0 overflow-hidden" type="auto">
        <ol className="setup-guide-steps px-3 py-2">
          {stepLabels.map((label, step) => <li key={label} ref={step === active ? activeRow : undefined} className="setup-guide-step">
            <Button className="setup-guide-step-trigger w-full justify-start gap-2.5 px-2 text-left" size="sm" variant="ghost"
              disabled={!selectable[step]} aria-current={step === active ? "step" : undefined} aria-expanded={step === active}
              aria-label={completed[step] ? t("{0}，已完成", label) : label} onClick={() => showStep(step)}>
              <span className={cn("setup-guide-marker", step === active ? "bg-primary text-primary-foreground" : "border bg-card text-muted-foreground")} aria-hidden="true">
                {completed[step] ? <Check /> : step + 1}
              </span>
              <span>{label}</span>
            </Button>
            {step === active ? <div className="flex min-w-0 flex-col gap-2 pb-2 pl-10 pr-1 text-caption text-muted-foreground">
              {content}
              {actionError?.step === step ? <p className="break-words text-foreground" role="alert">{diagnostic(actionError.message)}</p> : null}
            </div> : null}
          </li>)}
        </ol>
      </ScrollArea>
      {action ? <CardFooter ref={footer} className="setup-guide-footer flex-wrap justify-end gap-2 border-t">
        {active === 2 && scope && credentialErrorScope === scope ? <div className="flex w-full flex-wrap items-center gap-x-2 text-caption">
          <p role="alert">{t("复制令牌失败，请重试。")}</p>
          <Button variant="link" size="sm" className="px-0" disabled={busy} onClick={() => void run(t("正在定位令牌文件"), "open_agent_token")}>{t("定位令牌文件")}</Button>
        </div> : null}
        {action}
      </CardFooter> : null}
    </Card> : <Button ref={collapsedTrigger} variant="outline" aria-label={t("展开配置指引，{0}", guideLabel)} aria-expanded={false} className="shadow-sm" onClick={onExpand}>
      {guideLabel}<ChevronUp data-icon="inline-end" aria-hidden="true" />
    </Button>}
  </aside>;
}
