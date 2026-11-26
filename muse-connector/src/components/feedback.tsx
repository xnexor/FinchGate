import { useLanguage } from "@/lib/i18n";
import { TriangleAlert, Info } from "lucide-react";
import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import { AlertDialog, AlertDialogContent, AlertDialogHeader, AlertDialogTitle, AlertDialogDescription, AlertDialogFooter, AlertDialogCancel, AlertDialogAction } from "@/components/ui/alert-dialog";
export function Notice({ title, children, error = false, tone }: { title: string; children: React.ReactNode; error?: boolean; tone?: "warning" | "error" }) {
  const variant = tone ?? (error ? "error" : "default");
  const Icon = variant === "default" ? Info : TriangleAlert;
  return <Alert variant={variant}><Icon aria-hidden="true" /><AlertTitle>{title}</AlertTitle><AlertDescription>{children}</AlertDescription></Alert>;
}
export interface Confirmation { title: string; description: string; action: string; execute: () => Promise<boolean> }
export function ConfirmAction({ value, close, busy, error, restoreFocus }: { value: Confirmation | null; close: () => void; busy: boolean; error: string | null; restoreFocus: () => void }) {
  const { t, diagnostic } = useLanguage();
  return <AlertDialog open={value !== null} onOpenChange={open => { if (!open && !busy) close(); }}>
    <AlertDialogContent onCloseAutoFocus={event => { event.preventDefault(); restoreFocus(); }}><AlertDialogHeader><AlertDialogTitle>{value?.title}</AlertDialogTitle><AlertDialogDescription>{value?.description}</AlertDialogDescription></AlertDialogHeader>
      {error ? <Notice title={t("操作未完成")} error>{diagnostic(error)}</Notice> : null}
      <AlertDialogFooter><AlertDialogCancel disabled={busy}>{t("取消")}</AlertDialogCancel><AlertDialogAction disabled={busy} onClick={async event => { event.preventDefault(); if (await value?.execute()) close(); }}>{busy ? t("正在处理…") : value?.action}</AlertDialogAction></AlertDialogFooter>
    </AlertDialogContent>
  </AlertDialog>;
}
