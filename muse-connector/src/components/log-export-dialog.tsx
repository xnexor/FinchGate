import { useEffect, useMemo, useState } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { Download } from "lucide-react";
import { toast } from "sonner";
import { useLanguage } from "@/lib/i18n";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import type { BridgeModel, LogBatch, LogRecord } from "@/lib/use-bridge";

export type LogKind = "audit" | "runtime";
export type LogScope = "files" | "exec" | "audit" | "runtime";
export type ExportScope = LogScope | "all_combined";
export type ExportFormat = "jsonl" | "csv";

export const fileEndpoints = new Set([
  "/api/list",
  "/api/read",
  "/api/write",
  "/api/mkdir",
  "/agent/v1/list",
  "/agent/v1/read",
  "/agent/v1/write",
  "/agent/v1/mkdir",
  "/agent/v1/search",
  "/agent/v1/locations/desktop",
]);

export type ParsedLog = {
  record: LogRecord;
  time: string | null;
  timeMs: number;
  summary: string;
  code: string;
  searchText: string;
  object: Record<string, unknown> | null;
};

export function parseLog(record: LogRecord): ParsedLog {
  const searchText = record.text.toLocaleLowerCase();
  try {
    const object = JSON.parse(record.text) as Record<string, unknown>;
    const time = typeof object.ts === "string" ? object.ts : null;
    const timeMs = time ? Date.parse(time) : NaN;
    return {
      record, time, timeMs, searchText, object,
      summary: [object.method, object.endpoint, object.root, object.path, object.message].filter(Boolean).join(" "),
      code: String(object.code ?? object.level ?? "—"),
    };
  } catch {
    return { record, time: null, timeMs: NaN, summary: record.text, code: "—", searchText, object: null };
  }
}

export function filterLogRows(
  entries: ParsedLog[],
  scope: ExportScope,
  search: string,
  windowMinutes: string,
  resultFilter: string,
  nowMs: number,
) {
  return entries.filter(row => {
    if (scope === "files" && !fileEndpoints.has(String(row.object?.endpoint))) return false;
    if (scope === "exec" && !String(row.object?.endpoint ?? "").startsWith("/agent/v1/exec")) return false;
    if (search && !row.searchText.includes(search)) return false;
    if (windowMinutes !== "all" && (!row.time || row.timeMs < nowMs - Number(windowMinutes) * 60000)) return false;
    const failure = Number(row.code) >= 400 || row.code === "error" || row.code === "warning";
    return resultFilter === "all" || (resultFilter === "errors" ? failure : !failure);
  });
}

function csvCell(value: unknown) {
  const text = value === null || value === undefined ? "" : String(value);
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

function formatExportContent(rows: ParsedLog[], format: ExportFormat, includeKind: boolean) {
  if (format === "jsonl") {
    return rows.map(entry => {
      if (entry.object) {
        return includeKind
          ? JSON.stringify({ kind: entry.record.kind, ...entry.object })
          : entry.record.text;
      }
      return JSON.stringify(
        includeKind
          ? { kind: entry.record.kind, message: entry.record.text }
          : { message: entry.record.text },
      );
    }).join("\n") + (rows.length ? "\n" : "");
  }
  const header = ["ts", "kind", "result", "method", "endpoint", "root", "path", "message", "bytes", "persisted"];
  const lines = [header.join(",")];
  for (const entry of rows) {
    const obj = entry.object;
    lines.push([
      entry.time ?? "",
      entry.record.kind,
      entry.code,
      obj?.method ?? "",
      obj?.endpoint ?? "",
      obj?.root ?? "",
      obj?.path ?? "",
      obj ? (obj.message ?? "") : entry.record.text,
      obj?.bytes ?? "",
      entry.record.persisted ? "true" : "false",
    ].map(csvCell).join(","));
  }
  return `\uFEFF${lines.join("\r\n")}\r\n`;
}

function defaultExportFileName(scope: ExportScope, format: ExportFormat) {
  const now = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  const stamp = `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}-${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
  const tag = scope === "all_combined" ? "all" : scope;
  return `muselink-logs-${tag}-${stamp}.${format}`;
}

export default function LogExportDialog({
  open,
  onOpenChange,
  bridge,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  bridge: BridgeModel;
}) {
  const { t, diagnostic } = useLanguage();
  const [records, setRecords] = useState<Record<LogKind, ParsedLog[]>>({ audit: [], runtime: [] });
  const [loading, setLoading] = useState(false);
  const [exportScope, setExportScope] = useState<ExportScope>("all_combined");
  const [exportResult, setExportResult] = useState("all");
  const [exportWindow, setExportWindow] = useState("all");
  const [exportQuery, setExportQuery] = useState("");
  const [exportFormat, setExportFormat] = useState<ExportFormat>("jsonl");
  const [exporting, setExporting] = useState(false);

  useEffect(() => {
    if (!open || !isTauri()) return;
    let disposed = false;
    setLoading(true);
    void Promise.all([
      invoke<LogBatch>("get_logs", { kind: "audit", after: null }),
      invoke<LogBatch>("get_logs", { kind: "runtime", after: null }),
    ]).then(([audit, runtime]) => {
      if (disposed) return;
      setRecords({
        audit: audit.entries.map(parseLog),
        runtime: runtime.entries.map(parseLog),
      });
    }).catch(e => {
      if (!disposed) bridge.setError(t("读取日志失败：{0}", diagnostic(String(e))));
    }).finally(() => {
      if (!disposed) setLoading(false);
    });
    return () => { disposed = true; };
  }, [open, bridge, diagnostic, t]);

  const exportRows = useMemo(() => {
    if (!open) return [];
    const base = exportScope === "all_combined"
      ? [...records.audit, ...records.runtime].sort((a, b) => {
        const ta = Number.isFinite(a.timeMs) ? a.timeMs : 0;
        const tb = Number.isFinite(b.timeMs) ? b.timeMs : 0;
        return ta !== tb ? ta - tb : a.record.seq - b.record.seq;
      })
      : exportScope === "runtime"
        ? records.runtime
        : records.audit;
    return filterLogRows(base, exportScope, exportQuery.toLocaleLowerCase(), exportWindow, exportResult, Date.now());
  }, [open, exportScope, exportQuery, exportWindow, exportResult, records.audit, records.runtime]);

  const runExport = async () => {
    if (!exportRows.length || exporting) return;
    setExporting(true);
    try {
      const content = formatExportContent(exportRows, exportFormat, exportScope === "all_combined");
      const defaultName = defaultExportFileName(exportScope, exportFormat);
      const saved = await invoke<string | null>("export_logs", { defaultName, format: exportFormat, content });
      if (saved) {
        toast.success(t("已导出 {0} 条日志", exportRows.length));
        onOpenChange(false);
      }
    } catch (e) {
      bridge.setError(t("导出日志失败：{0}", String(e)));
    } finally {
      setExporting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={next => { if (!exporting) onOpenChange(next); }}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{t("导出日志")}</DialogTitle>
          <DialogDescription>{t("选择要导出的日志范围与格式。导出内容按时间顺序排列，且已自动脱敏令牌。")}</DialogDescription>
        </DialogHeader>
        <FieldGroup className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Field className="sm:col-span-2">
            <FieldLabel htmlFor="export-scope">{t("日志范围")}</FieldLabel>
            <Select value={exportScope} onValueChange={value => setExportScope(value as ExportScope)}>
              <SelectTrigger id="export-scope" className="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value="all_combined">{t("全部日志（访问与运行）")}</SelectItem>
                  <SelectItem value="files">{t("文件操作")}</SelectItem>
                  <SelectItem value="exec">{t("命令执行")}</SelectItem>
                  <SelectItem value="audit">{t("全部访问（含健康探测）")}</SelectItem>
                  <SelectItem value="runtime">{t("连接器运行日志")}</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
          </Field>
          <Field>
            <FieldLabel htmlFor="export-result">{t("结果")}</FieldLabel>
            <Select value={exportResult} onValueChange={setExportResult}>
              <SelectTrigger id="export-result" className="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value="all">{t("所有结果")}</SelectItem>
                  <SelectItem value="errors">{t("错误与警告")}</SelectItem>
                  <SelectItem value="success">{t("正常记录")}</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
          </Field>
          <Field>
            <FieldLabel htmlFor="export-window">{t("时间范围")}</FieldLabel>
            <Select value={exportWindow} onValueChange={setExportWindow}>
              <SelectTrigger id="export-window" className="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value="all">{t("全部缓存")}</SelectItem>
                  <SelectItem value="5">{t("最近 5 分钟")}</SelectItem>
                  <SelectItem value="15">{t("最近 15 分钟")}</SelectItem>
                  <SelectItem value="60">{t("最近 1 小时")}</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
          </Field>
          <Field className="sm:col-span-2">
            <FieldLabel htmlFor="export-query">{t("关键词（可选）")}</FieldLabel>
            <Input id="export-query" autoComplete="off" spellCheck={false} value={exportQuery} onChange={e => setExportQuery(e.target.value)} placeholder={t("查找记录…")} />
          </Field>
          <Field className="sm:col-span-2">
            <FieldLabel htmlFor="export-format">{t("导出格式")}</FieldLabel>
            <Select value={exportFormat} onValueChange={value => setExportFormat(value as ExportFormat)}>
              <SelectTrigger id="export-format" className="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value="jsonl">{t("JSONL（保留原始字段，适合排查与反馈问题）")}</SelectItem>
                  <SelectItem value="csv">{t("CSV（表格格式，适合 Excel 直接查看）")}</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
          </Field>
        </FieldGroup>
        <p className="text-caption text-muted-foreground" role="status">
          {loading ? t("正在读取日志…") : exportRows.length ? t("匹配 {0} 条日志，点击导出后选择保存位置。", exportRows.length) : t("当前筛选条件下没有可导出的日志。")}
        </p>
        <DialogFooter>
          <Button variant="outline" disabled={exporting} onClick={() => onOpenChange(false)}>{t("取消")}</Button>
          <Button disabled={loading || exporting || exportRows.length === 0} onClick={() => void runExport()}>
            <Download data-icon="inline-start" />
            {exporting ? t("正在导出…") : t("导出 ({0})", exportRows.length)}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
