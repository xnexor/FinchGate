import { useLanguage, type Translate } from "@/lib/i18n";
import { useEffect, useRef, useState } from "react";
import { ExternalLink, RefreshCw, Save } from "lucide-react";
import { toast } from "sonner";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Field, FieldGroup, FieldLabel, FieldDescription, FieldError } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select, SelectTrigger, SelectValue, SelectContent, SelectGroup, SelectItem } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { Notice, type Confirmation } from "@/components/feedback";
import DeviceNameField from "@/components/device-name-field";
import AgentConnection from "@/components/agent-connection";
import type { DeviceNameModel } from "@/lib/use-device-name";
import { providerLabels, type BridgeModel, type ProviderKind, type ProviderSettings } from "@/lib/use-bridge";

const normalize = (v: ProviderSettings): ProviderSettings => ({
  kind: v.kind,
  tunnel_id: v.kind === "cloudflare_named" ? v.tunnel_id.trim() : "",
  hostname: v.kind === "cloudflare_named" ? v.hostname.trim() : "",
});
const keyOf = (v: ProviderSettings) => JSON.stringify(normalize(v));
function validate(t: Translate, v: ProviderSettings) {
  const errors: { tunnel_id?: string; hostname?: string } = {};
  if (v.kind !== "cloudflare_named") return errors;
  if (!/^[a-zA-Z0-9_-]{1,100}$/.test(v.tunnel_id.trim())) errors.tunnel_id = t("填写 1–100 个字母、数字、连字符或下划线。");
  const host = v.hostname.trim();
  if (host.length > 253 || !host.includes(".") || !host.split(".").every(part => /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(part))) errors.hostname = t("填写有效域名，不含协议、端口或路径。");
  return errors;
}

export default function Connection({
  bridge,
  deviceName,
  confirm,
  guiding,
  onDirtyChange,
  onStartGuide,
  onCollapseGuide,
}: {
  bridge: BridgeModel;
  deviceName: DeviceNameModel;
  confirm: (value: Confirmation) => void;
  guiding: boolean;
  onDirtyChange: (dirty: boolean) => void;
  onStartGuide: () => void;
  onCollapseGuide: () => void;
}) {
  const { t } = useLanguage();
  const { snapshot: s, busy, run } = bridge;
  const current: ProviderSettings = s?.desktop.provider ?? { kind: "tailscale", tunnel_id: "", hostname: "" };
  const [draft, setDraft] = useState<ProviderSettings>(current);
  const previous = useRef(current);
  const [touched, setTouched] = useState({ tunnel_id: false, hostname: false });
  const tunnelInput = useRef<HTMLInputElement>(null);
  const hostnameInput = useRef<HTMLInputElement>(null);
  const [tunnels, setTunnels] = useState<Array<{ id: string; name: string }>>([]);
  const [newName, setNewName] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [routed, setRouted] = useState(false);
  useEffect(() => {
    const before = previous.current;
    previous.current = current;
    setDraft(value => keyOf(value) === keyOf(before) ? current : value);
  }, [current.kind, current.tunnel_id, current.hostname]);
  const dirty = keyOf(draft) !== keyOf(current);
  useEffect(() => { onDirtyChange(dirty); }, [dirty, onDirtyChange]);
  if (!s) return null;
  const development = s.profile === "development";
  const needsCloudflare = draft.kind !== "tailscale";
  const installed = needsCloudflare ? s.dependencies.cloudflared : s.dependencies.tailscale;
  const errors = validate(t, draft);
  const valid = !errors.tunnel_id && !errors.hostname;
  const command = async (action: string, extra?: Record<string, string>) => run<{ message?: string; tunnels?: Array<{ id: string; name: string }> }>(t("正在处理 Cloudflare 操作"), "cloudflare_action", { action, ...extra });
  const refreshTunnels = async () => { const result = await command("list"); if (result.ok) { setTunnels(result.data.tunnels ?? []); setAuthorized(true); } };

  const statusHint = dirty
    ? !installed && !development
      ? t("请先安装所需工具，再应用更改。")
      : !valid
        ? t("填写有效的隧道和主机名后可应用。")
        : s.desktop.desired_enabled
          ? t("切换将短暂中断连接。")
          : t("更改将在下次开启连接时使用。")
    : !installed && !development
      ? t("未检测到所需工具")
      : null;

  return <div className="page-stack">
    {development ? <Notice title={t("开发隔离模式")}>{t("提供方切换只修改开发配置并使用模拟连接。真实登录、隧道创建、DNS 和公网测试已禁用。")}</Notice> : null}

    <Card>
      <CardContent className="flex items-center justify-between gap-4">
        <CardTitle>{t("指引")}</CardTitle>
        <Button size="sm" variant={guiding ? "outline" : "default"} onClick={guiding ? onCollapseGuide : onStartGuide}>
          {guiding ? t("收起指引") : t("开始指引")}
        </Button>
      </CardContent>
    </Card>

    {!guiding && (!s.fresh_setup || s.access_configured) ? (
      <Card>
        <CardHeader>
          <CardTitle>{t("设备")}</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <DeviceNameField id="connection-device-name" deviceName={deviceName} layout="inline" />
          {deviceName.pending ? (
            <div className="flex flex-col gap-2 border-t pt-4">
              <p role="status" className="text-sm">{t("待在 Muse 中更新")}</p>
              <p className="text-caption text-muted-foreground">{t(deviceName.copyRename ? "复制说明并粘贴给 Muse，改名确认后会自动清除这条状态。" : "恢复公网连接后可复制改名说明。")}</p>
              {deviceName.manualCopy ? (
                <textarea
                  aria-label={t("改名说明")}
                  readOnly
                  rows={4}
                  className="w-full rounded-md border border-input bg-transparent p-2 text-caption"
                  value={deviceName.manualCopy}
                  onFocus={event => event.currentTarget.select()}
                />
              ) : null}
              <div className="flex flex-wrap gap-2">
                <Button type="button" size="sm" disabled={!deviceName.copyRename} onClick={() => void deviceName.copyRename?.().then(ok => {
                  if (ok) toast.success(t("改名说明已复制，请粘贴给 Muse。"));
                })}>{t("复制改名说明")}</Button>
                <Button type="button" size="sm" variant="outline" disabled={!!busy} onClick={() => void deviceName.confirmUpdate()}>{t("我已在 Muse 更新")}</Button>
              </div>
            </div>
          ) : null}
        </CardContent>
      </Card>
    ) : null}

    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center gap-2">
          <CardTitle>{t("连接方式")}</CardTitle>
          {dirty ? <Badge variant="outline">{t("未应用更改")}</Badge> : null}
        </div>
        <CardDescription>{t("当前生效：{0}", t(providerLabels[current.kind]))}{current.kind === "cloudflare_named" ? " · " + current.hostname : ""}</CardDescription>
      </CardHeader>
      <CardContent><form noValidate className="flex flex-col gap-5" onSubmit={event => {
        event.preventDefault();
        if (!dirty || busy || (!installed && !development)) return;
        if (!valid) { setTouched({ tunnel_id: true, hostname: true }); (errors.tunnel_id ? tunnelInput : hostnameInput).current?.focus(); return; }
        const provider = normalize(draft);
        const providerName = t(providerLabels[provider.kind]);
        const timing = s.desktop.desired_enabled ? t("切换将短暂中断连接。") : t("更改将在下次开启连接时使用。");
        confirm({ title: t("应用连接更改？"), description: t("将使用 {0}。{1}入口地址改变后需要在 Muse 更新地址。", providerName, timing), action: t("应用更改"), execute: async () => {
          const result = await run(t("正在应用连接方式"), "save_provider", { provider }, t("连接方式已应用"));
          if (result.ok) setDraft(provider);
          return result.ok;
        } });
      }}>
        <FieldGroup>
          <Field>
            <FieldLabel htmlFor="provider">{t("提供方")}</FieldLabel>
            <Select name="provider" value={draft.kind} onValueChange={value => { setDraft(v => ({ ...v, kind: value as ProviderKind })); setRouted(false); }}>
              <SelectTrigger id="provider" className="w-full"><SelectValue /></SelectTrigger>
              <SelectContent><SelectGroup>{Object.entries(providerLabels).map(([value, label]) => <SelectItem value={value} key={value}>{t(label)}</SelectItem>)}</SelectGroup></SelectContent>
            </Select>
            {!development ? <FieldDescription>{draft.kind === "tailscale" ? t("需要 Tailscale 已登录，并具备 Funnel 授权。") : t("需要 Cloudflare 账户下的可用域名与命名隧道。")}</FieldDescription> : null}
          </Field>
          {draft.kind === "cloudflare_named" ? <>
            <Field data-invalid={touched.tunnel_id && !!errors.tunnel_id}>
              <FieldLabel htmlFor="tunnel-id">{t("隧道 ID 或名称")}</FieldLabel>
              <Input ref={tunnelInput} id="tunnel-id" name="tunnel_id" autoComplete="off" spellCheck={false} required value={draft.tunnel_id} onBlur={() => setTouched(v => ({ ...v, tunnel_id: true }))} onChange={e => { setDraft(v => ({ ...v, tunnel_id: e.target.value })); setRouted(false); }} aria-invalid={touched.tunnel_id && !!errors.tunnel_id} aria-describedby={touched.tunnel_id && errors.tunnel_id ? "tunnel-id-error" : undefined} placeholder={t("输入或从下方已授权列表选择")} />
              {touched.tunnel_id && errors.tunnel_id ? <FieldError id="tunnel-id-error">{errors.tunnel_id}</FieldError> : null}
            </Field>
            <Field data-invalid={touched.hostname && !!errors.hostname}>
              <FieldLabel htmlFor="hostname">{t("主机名")}</FieldLabel>
              <Input ref={hostnameInput} id="hostname" name="hostname" autoComplete="off" spellCheck={false} required value={draft.hostname} onBlur={() => setTouched(v => ({ ...v, hostname: true }))} onChange={e => { setDraft(v => ({ ...v, hostname: e.target.value })); setRouted(false); }} aria-invalid={touched.hostname && !!errors.hostname} aria-describedby={touched.hostname && errors.hostname ? "hostname-error" : "hostname-help"} placeholder={t("例如 muse.example.com")} />
              <FieldDescription id="hostname-help">{t("只填写域名，不含 https://、端口或路径。")}</FieldDescription>
              {touched.hostname && errors.hostname ? <FieldError id="hostname-error">{errors.hostname}</FieldError> : null}
            </Field>
          </> : null}
        </FieldGroup>
        {statusHint ? <p className="text-caption text-muted-foreground" role="status">{statusHint}</p> : null}
        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" disabled={!!busy || !dirty || !valid || (!installed && !development)}>
            <Save data-icon="inline-start" />
            {s.desktop.desired_enabled ? t("应用并切换") : t("应用更改")}
          </Button>
          {!guiding || dirty ? (
            <Button type="button" variant="ghost" disabled={!!busy} onClick={() => void run(t("正在打开工具说明"), "open_tool_setup", { tool: needsCloudflare ? "cloudflared" : installed ? "tailscale_login" : "tailscale" })}>
              <ExternalLink data-icon="inline-start" />
              {installed ? t("登录帮助") : t("安装与登录")}
            </Button>
          ) : null}
          {dirty ? (
            <Button type="button" variant="ghost" disabled={!!busy} onClick={() => { setDraft(current); setTouched({ tunnel_id: false, hostname: false }); setRouted(false); }}>
              {t("撤销更改")}
            </Button>
          ) : null}
        </div>
      </form></CardContent>
    </Card>

    {draft.kind === "cloudflare_named" ? <Card><CardHeader><CardTitle>{t("命名隧道向导")}</CardTitle><CardDescription>{t("授权、隧道、主机名依次配置。没有域名时可保留 Tailscale。")}</CardDescription></CardHeader><CardContent className="flex flex-col gap-5">
      <Progress value={((authorized ? 1 : 0) + (draft.tunnel_id ? 1 : 0) + (routed ? 1 : 0)) / 3 * 100} aria-label={t("域名向导配置进度")} />
      <FieldGroup>
        <Field><FieldLabel>{t("账户授权")}</FieldLabel><FieldDescription>{t("在浏览器选择可用域名并完成授权，凭证保存在本机。")}</FieldDescription><div className="flex flex-wrap gap-3"><Button variant="outline" disabled={!!busy || development || !installed} onClick={async () => { const result = await command("login"); if (result.ok) { setAuthorized(true); await refreshTunnels(); } }}><ExternalLink data-icon="inline-start" />{t("打开浏览器授权")}</Button><Button variant="ghost" disabled={!!busy || development} onClick={() => void run(t("正在打开域名控制台"), "open_tool_setup", { tool: "domains" })}>{t("查看账户域名")}</Button></div></Field><Separator />
        <Field><FieldLabel htmlFor="existing-tunnel">{t("已有隧道")}</FieldLabel><Select name="existing_tunnel" value={tunnels.some(t => t.id === draft.tunnel_id) ? draft.tunnel_id : ""} onValueChange={value => { setDraft(v => ({ ...v, tunnel_id: value })); setRouted(false); }}><SelectTrigger id="existing-tunnel" className="w-full"><SelectValue placeholder={t("授权后刷新列表")} /></SelectTrigger><SelectContent><SelectGroup>{tunnels.map(t => <SelectItem value={t.id} key={t.id}>{t.name} · {t.id.slice(0, 8)}</SelectItem>)}</SelectGroup></SelectContent></Select><Button variant="outline" className="self-start" disabled={!!busy || development || !installed} onClick={() => void refreshTunnels()}><RefreshCw data-icon="inline-start" />{t("刷新隧道列表")}</Button></Field>
        <Field><FieldLabel htmlFor="new-tunnel-name">{t("创建新隧道")}</FieldLabel><Input id="new-tunnel-name" name="new_tunnel_name" autoComplete="off" spellCheck={false} value={newName} onChange={e => setNewName(e.target.value)} placeholder={t("例如 muse-files")} /><Button variant="outline" className="self-start" disabled={!!busy || development || !installed || !/^[a-zA-Z0-9_-]{1,100}$/.test(newName.trim())} onClick={() => confirm({ title: t("创建 Cloudflare 隧道？"), description: t("将在当前已授权账户创建 {0}，不会覆盖已有隧道。", newName.trim()), action: t("创建隧道"), execute: async () => { const result = await command("create", { name: newName.trim() }); if (result.ok) await refreshTunnels(); return result.ok; } })}>{t("确认创建隧道")}</Button></Field><Separator />
        <Field><FieldLabel>{t("绑定主机名")}</FieldLabel><FieldDescription>{t("将上方主机名绑定到所选隧道。已有冲突记录将报错。")}</FieldDescription><Button variant="outline" className="self-start" disabled={!!busy || development || !installed || !valid} onClick={() => confirm({ title: t("绑定此主机名？"), description: t("将在 Cloudflare 将 {0} 绑定至隧道 {1}。成功后再应用连接更改。", draft.hostname.trim(), draft.tunnel_id.trim()), action: t("确认绑定"), execute: async () => { const result = await command("route", { name: draft.tunnel_id.trim(), hostname: draft.hostname.trim() }); if (result.ok) setRouted(true); return result.ok; } })}>{routed ? t("主机名已绑定") : t("确认绑定主机名")}</Button></Field>
      </FieldGroup>
    </CardContent></Card> : null}

    {!guiding ? (
      <AgentConnection
        bridge={bridge}
        snapshot={s}
        deviceName={deviceName}
        onEditDeviceName={() => {
          const input = document.getElementById("connection-device-name");
          input?.scrollIntoView({ block: "center", behavior: "smooth" });
          input?.focus();
        }}
        confirm={confirm}
      />
    ) : null}
  </div>;
}
