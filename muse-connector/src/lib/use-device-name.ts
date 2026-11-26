import { useState } from "react";
import { useLanguage } from "@/lib/i18n";
import { deviceRenameBrief } from "@/lib/agent-setup";
import { publicAddress } from "@/lib/setup-progress";
import type { BridgeModel, DeviceNameUpdate } from "@/lib/use-bridge";

function validDeviceName(name: string) {
  const length = [...name].length;
  return length >= 1 && length <= 32 && !name.startsWith(" ") && !name.endsWith(" ")
    && !/[^\p{Alphabetic}0-9 _-]/u.test(name);
}

type CopyRename = () => Promise<boolean>;
export function useDeviceName(bridge: BridgeModel, updateMuse: boolean, onSaved: (name: string, copy: CopyRename | null, pending: boolean) => void) {
  const { t, language, diagnostic } = useLanguage();
  const [draft, setDraft] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [manualCopy, setManualCopy] = useState<{ id: string; text: string } | null>(null);
  const stored = bridge.snapshot?.desktop.device_name ?? "";
  const saved = validDeviceName(stored) ? stored : "";
  const value = draft ?? (saved || bridge.snapshot?.suggested_device_name || "");
  const dirty = draft !== null && (!saved || value !== saved);
  const valid = validDeviceName(value);
  const disabled = !!bridge.busy;
  const canSave = valid && value !== saved && !disabled;
  const receipt = bridge.snapshot?.desktop.device_name_update;
  const pending = receipt?.pending ? receipt : null;
  const origin = bridge.snapshot && publicAddress(bridge.snapshot);

  const copyAction = (id: string, name: string): CopyRename | null => origin && name ? async () => {
    const text = deviceRenameBrief(language, origin, name, id);
    try {
      await navigator.clipboard.writeText(text);
      setManualCopy(null);
      return true;
    } catch {
      setManualCopy({ id, text });
      return false;
    }
  } : null;

  const update = (next: string | null) => {
    setDraft(next);
    setSaveError(null);
  };

  const save = async () => {
    if (!canSave) return;
    // Keep the submitted value visible until the desktop snapshot reflects the save.
    update(value);
    const result = await bridge.run<DeviceNameUpdate | null>(t("正在保存设备名称"), "save_device_name", { name: value, updateMuse }, undefined, false);
    if (!result.ok) { setSaveError(result.error); return; }
    setManualCopy(null);
    const pending = result.data?.pending ? result.data : null;
    onSaved(value, pending && copyAction(pending.id, value), !!pending);
  };

  const confirmUpdate = async () => {
    if (!pending || disabled) return;
    await bridge.run(t("正在确认 Muse 改名"), "confirm_device_name", { id: pending.id }, t("Muse 改名已确认"));
  };

  return { saved, value, dirty, disabled, canSave, canCopy: !!saved && !dirty, save, update, pending,
    copyRename: pending && copyAction(pending.id, saved),
    confirmUpdate,
    manualCopy: manualCopy && manualCopy.id === pending?.id && origin && manualCopy.text === deviceRenameBrief(language, origin, saved, pending.id) ? manualCopy.text : null,
    invalid: dirty && !valid,
    error: saveError ? diagnostic(saveError) : null,
  };
}

export type DeviceNameModel = ReturnType<typeof useDeviceName>;
