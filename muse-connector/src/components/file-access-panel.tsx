import { useLanguage, type Translate } from "@/lib/i18n";
import { useId, useRef, useState } from "react";
import { Check, ChevronDown, FolderOpen, Trash2 } from "lucide-react";
import { invoke } from "@tauri-apps/api/core";
import { DropdownMenu } from "radix-ui";
import { Button } from "@/components/ui/button";
import { CardTitle } from "@/components/ui/card";
import { FieldError } from "@/components/ui/field";
import { setupRootTarget } from "@/lib/setup-progress";
import { accessOperations, accessPolicyKey, editFileAccessPolicy, folderGrantEnabled } from "@/lib/agent-setup";
import type { BridgeModel, FileAccessMode, FileAccessPolicy, Snapshot } from "@/lib/use-bridge";

const modes = [
  { key: "folders", label: "管理指定文件夹（推荐）" },
  { key: "full", label: "管理本机磁盘（整机授权）" },
] as const;

function completeScope(saved: FileAccessPolicy) {
  const scope = saved.mode === "full" ? "all_local" : "folders";
  return accessOperations.every(operation => saved[operation] === scope && (scope === "all_local"
    || Object.keys(saved.roots).every(alias => folderGrantEnabled(saved, operation, alias))));
}

function folderAlias(path: string, roots: Record<string, string>) {
  const parts = path.replace(/[\\/]+$/, "").split(/[\\/]/);
  const leaf = (parts[parts.length - 1] ?? "").trim();
  const encoder = new TextEncoder();
  const base = /[\\/:\p{Cc}]/u.test(leaf) || encoder.encode(leaf).length > 58 ? "folder" : leaf || "folder";
  let alias = base;
  for (let suffix = 2; Object.prototype.hasOwnProperty.call(roots, alias); suffix++) alias = `${base}-${suffix}`;
  return alias;
}

function diskLabel(t: Translate, alias: string) {
  return alias === "test-disk" ? t("测试磁盘") : alias.slice("drive-".length).toUpperCase() + ":";
}

function DiskPicker({ selected, onChange, disabled }: { selected: string[] | null; onChange: (value: string[] | null) => void; disabled: boolean }) {
  const { t } = useLanguage();
  const [available, setAvailable] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);
  const request = useRef(0);
  const options = [...new Set([...available, ...(selected ?? [])])].sort();
  const itemClass = "relative flex cursor-default items-center rounded-sm py-1.5 pl-8 pr-2 text-sm outline-none focus:bg-accent focus:text-accent-foreground";
  const indicator = <DropdownMenu.ItemIndicator className="absolute left-2 flex size-4 items-center justify-center"><Check className="size-4" /></DropdownMenu.ItemIndicator>;
  const open = async (opened: boolean) => {
    if (!opened) return;
    const current = ++request.current;
    setLoading(true);
    setError(false);
    try {
      const aliases = await invoke<string[]>("list_local_disks");
      if (current === request.current) setAvailable(aliases);
    } catch {
      if (current === request.current) { setAvailable([]); setError(true); }
    } finally {
      if (current === request.current) setLoading(false);
    }
  };
  const toggle = (alias: string, checked: boolean) => {
    const current = selected ?? available;
    onChange(checked ? [...current, alias].sort() : current.filter(value => value !== alias));
  };
  return <DropdownMenu.Root onOpenChange={open}>
    <DropdownMenu.Trigger asChild>
      <Button type="button" variant="outline" size="sm" className="h-auto min-h-9 w-fit max-w-full justify-between" disabled={disabled} aria-label={t("选择磁盘")}>
        <span className="whitespace-normal text-left">{selected === null ? t("所有磁盘") : selected.length ? selected.map(alias => diskLabel(t, alias)).join(", ") : t("选择磁盘")}</span>
        <ChevronDown data-icon="inline-end" />
      </Button>
    </DropdownMenu.Trigger>
    <DropdownMenu.Portal>
      <DropdownMenu.Content align="start" sideOffset={4} className="z-50 max-h-64 min-w-40 overflow-y-auto rounded-md border bg-popover p-1 text-popover-foreground shadow-md">
        <DropdownMenu.CheckboxItem className={itemClass} checked={selected === null} onSelect={event => event.preventDefault()} onCheckedChange={checked => onChange(checked ? null : [])}>
          {indicator}{t("所有磁盘")}
        </DropdownMenu.CheckboxItem>
        {options.map(alias => <DropdownMenu.CheckboxItem key={alias} className={itemClass}
          checked={selected === null ? available.includes(alias) : selected.includes(alias)} disabled={loading}
          onSelect={event => event.preventDefault()} onCheckedChange={checked => toggle(alias, checked)}>
          {indicator}{diskLabel(t, alias)}{!available.includes(alias) && !loading ? t("（当前不可用）") : ""}
        </DropdownMenu.CheckboxItem>)}
        {loading || error || !options.length ? <p role="status" className="px-2 py-1.5 text-caption text-muted-foreground">
          {loading ? t("正在读取本机磁盘…") : error ? t("读取失败，重新打开可重试。") : t("暂无可选磁盘。")}
        </p> : null}
      </DropdownMenu.Content>
    </DropdownMenu.Portal>
  </DropdownMenu.Root>;
}

export default function FileAccessPanel({ bridge, snapshot, guided = false, onSaved }: {
  bridge: BridgeModel;
  snapshot: Snapshot;
  guided?: boolean;
  onSaved: () => void;
}) {
  const saved = snapshot.file_access;
  const initialRoots = saved?.roots ?? snapshot.config.roots;
  const savedKey = saved ? accessPolicyKey(saved) : JSON.stringify(Object.entries(initialRoots).sort());
  return <AccessEditor key={savedKey} bridge={bridge} saved={saved} initialRoots={initialRoots} guided={guided} onSaved={onSaved} />;
}

function AccessEditor({ bridge, saved, initialRoots, guided, onSaved }: {
  bridge: BridgeModel;
  saved: FileAccessPolicy | null;
  initialRoots: FileAccessPolicy["roots"];
  guided: boolean;
  onSaved: () => void;
}) {
  const { t, diagnostic } = useLanguage();
  const prefix = useId();
  const [mode, setMode] = useState<FileAccessMode>(saved?.mode ?? "folders");
  const [roots, setRoots] = useState(initialRoots);
  const [disks, setDisks] = useState<string[] | null>(saved?.disks ?? null);
  const [enableAllOperations, setEnableAllOperations] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const folders = Object.entries(roots);
  const modeChanged = saved !== null && saved.mode !== mode;
  const diskConfirmationRequired = modeChanged && mode === "full" && !enableAllOperations;
  const policy = editFileAccessPolicy(enableAllOperations ? null : saved, mode, roots, disks);
  const showFolders = mode === "folders" || (!diskConfirmationRequired && accessOperations.some(operation => policy[operation] === "folders"));
  const showDisks = diskConfirmationRequired || accessOperations.some(operation => policy[operation] === "all_local");
  const missingFolder = showFolders && !folders.length;
  const missingDisk = showDisks && disks?.length === 0;
  const canEnableAll = saved !== null && (modeChanged || !completeScope(saved));
  const changed = !saved || accessPolicyKey(policy) !== accessPolicyKey(saved);
  const busy = !!bridge.busy;
  const canSave = !busy && !missingFolder && !missingDisk && !diskConfirmationRequired && changed;

  const removeFolder = (name: string) => {
    setRoots(current => Object.fromEntries(Object.entries(current).filter(([key]) => key !== name)));
    setError(null);
  };

  const selectFolder = async () => {
    setError(null);
    const result = await bridge.run<string | null>(t("正在选择目录"), "pick_directory", undefined, undefined, false);
    if (!result.ok) {
      setError(result.error);
      return;
    }
    const path = result.data;
    if (!path) return;
    setRoots(current => Object.values(current).some(existing => existing.toLowerCase() === path.toLowerCase())
      ? current : { ...current, [folderAlias(path, current)]: path });
  };

  const save = async () => {
    if (!canSave) return;
    setError(null);
    const edit = { expected_mode: saved?.mode ?? null, enable_all_operations: enableAllOperations };
    const result = await bridge.run(t("正在保存文件授权"), "save_file_access", { policy, edit }, t("文件授权已保存"), false);
    if (!result.ok) setError(result.error);
    else if (guided) onSaved();
  };

  return (
    <form id="setup-file-access" tabIndex={-1} className="flex min-w-0 flex-col gap-5 focus-visible:outline focus-visible:outline-ring" onSubmit={event => {
      event.preventDefault();
      void save();
    }}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <CardTitle>{t("文件权限")}</CardTitle>
        <Button type="submit" size="sm" disabled={!canSave}>
          {guided ? t("确认并继续") : t("保存授权")}
        </Button>
      </div>
      <fieldset disabled={busy} className="m-0 flex min-w-0 flex-col gap-5 border-0 p-0">
        <div className="flex min-w-0 flex-col gap-3.5">
          <p className="text-sm font-medium text-foreground">{t("选择 Muse 的文件管理方式")}</p>
          <div className="grid min-w-0 gap-2" data-slot="radio-group" role="radiogroup" aria-label={t("选择 Muse 的文件管理方式")}>
            {modes.map(({ key, label }) => (
              <label key={key} className="flex min-w-0 cursor-pointer items-center gap-2.5 rounded-md border px-3 py-2.5 text-sm text-foreground transition-[border-color,background-color] hover:border-ring/70 has-checked:border-foreground/50 has-checked:bg-accent/50 has-disabled:cursor-not-allowed">
                <input
                  type="radio"
                  name={`${prefix}-access-mode`}
                  value={key}
                  checked={mode === key}
                  className="shrink-0 accent-primary focus-visible:outline focus-visible:outline-ring"
                  onChange={() => {
                    setMode(key);
                    setEnableAllOperations(false);
                    setError(null);
                  }}
                />
                <span>{key === "full" && canEnableAll && !enableAllOperations ? t("管理本机磁盘") : t(label)}</span>
              </label>
            ))}
          </div>
        </div>
        <div className="flex min-w-0 flex-col gap-3.5">
          <p className="text-caption text-muted-foreground">
            {diskConfirmationRequired
              ? t("切换到磁盘模式前，请确认对所选范围启用全部操作。")
              : modeChanged && !enableAllOperations
                ? t("各文件夹只保留当前授权范围内的搜索、读取和写入权限。")
                : canEnableAll && !enableAllOperations
                  ? t("调整范围时会保留当前的搜索、读取和写入权限。")
                  : mode === "full"
                    ? t("Muse 可搜索、读取和写入所选磁盘中当前 Windows 账户可访问的文件。")
                    : t("Muse 可搜索、读取和写入所选文件夹及其子文件夹。")}
          </p>
          {showDisks ? <DiskPicker selected={disks} disabled={busy} onChange={selection => { setDisks(selection); setError(null); }} /> : null}
          {showFolders ? (
            <div className="flex min-w-0 flex-col gap-2">
              <Button id={guided ? undefined : "add-directory"} type="button" variant="outline" size="sm" className="self-start" disabled={busy} onClick={() => void selectFolder()}>
                <FolderOpen data-icon="inline-start" />
                {t("选择文件夹")}
              </Button>
              {folders.map(([name, path]) => (
                <div
                  key={name}
                  id={guided ? undefined : setupRootTarget(name)}
                  tabIndex={-1}
                  className="flex min-w-0 items-center gap-2 rounded-md border px-3 py-2 focus-visible:outline focus-visible:outline-ring"
                >
                  <span className="min-w-0 flex-1 break-all text-caption">{path}</span>
                  <Button variant="ghost" type="button" size="icon-sm" aria-label={t("移除目录 {0}", name)} disabled={busy} onClick={() => removeFolder(name)}>
                    <Trash2 />
                  </Button>
                </div>
              ))}
            </div>
          ) : null}
          {canEnableAll ? (
            <label className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                className="mt-1 shrink-0 accent-primary focus-visible:outline focus-visible:outline-ring"
                checked={enableAllOperations}
                onChange={event => { setEnableAllOperations(event.target.checked); setError(null); }}
              />
              {t("对所选范围启用搜索、读取和写入")}
            </label>
          ) : null}
          {missingFolder ? <p className="text-caption text-muted-foreground">{t("请选择至少一个文件夹。")}</p> : null}
          {missingDisk ? <p className="text-caption text-muted-foreground">{t("请至少选择一个磁盘。")}</p> : null}
          {error ? <FieldError>{diagnostic(error)}</FieldError> : null}
        </div>
      </fieldset>
    </form>
  );
}
