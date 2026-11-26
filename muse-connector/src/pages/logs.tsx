import { useLanguage } from "@/lib/i18n";
import { memo, useCallback, useDeferredValue, useEffect, useMemo, useRef, useState } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { ScrollText, Copy, Check, Pause, Play, Search } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableHeader, TableHead, TableBody, TableRow, TableCell } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { Empty, EmptyHeader, EmptyMedia, EmptyTitle, EmptyDescription } from "@/components/ui/empty";
import { Tooltip, TooltipTrigger, TooltipContent } from "@/components/ui/tooltip";
import { Notice } from "@/components/feedback";
import { fileEndpoints, filterLogRows, parseLog, type LogKind, type LogScope, type ParsedLog } from "@/components/log-export-dialog";
import { formatTime, type BridgeModel, type LogRecord, type LogBatch } from "@/lib/use-bridge";

const kinds = ["audit", "runtime"] as const;
const logLimit = 1000;
const clock = { en: logClock("en"), "zh-CN": logClock("zh-CN") };

function logClock(language: string) {
  return new Intl.DateTimeFormat(language, { hour: "numeric", minute: "numeric", second: "numeric", hour12: false });
}

type LogEntries = Record<LogKind, ParsedLog[]>;

function useLogFeed(active: boolean) {
  const { t, diagnostic } = useLanguage();
  const [records, setRecords] = useState<LogEntries>({ audit: [], runtime: [] });
  const after = useRef<Record<LogKind, number | null>>({ audit: null, runtime: null });
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    if (!active || !isTauri()) return;
    let disposed = false;
    let reading = false;
    let readAgain = false;
    let subscriptionFailed = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let pending: Record<LogKind, LogRecord[]> = { audit: [], runtime: [] };

    const merge = (kind: LogKind, incoming: LogRecord[], replaceThrough?: number) => {
      if (incoming.length === 0 && replaceThrough === undefined) return;
      setRecords(previous => {
        const before = previous[kind];
        const cache = new Map(before.map(entry => [entry.record.seq, entry]));
        const entries = new Map(cache);
        if (replaceThrough !== undefined) {
          for (const seq of entries.keys()) {
            if (seq <= replaceThrough) entries.delete(seq);
          }
        }
        for (const record of incoming) {
          const cached = cache.get(record.seq);
          entries.set(record.seq, cached?.record.text === record.text && cached.record.persisted === record.persisted
            ? cached : parseLog(record));
        }
        const next = [...entries.values()].sort((a, b) => a.record.seq - b.record.seq).slice(-logLimit);
        return next.length === before.length && next.every((entry, index) => entry === before[index])
          ? previous : { ...previous, [kind]: next };
      });
    };

    const refresh = async () => {
      if (disposed) return;
      if (reading) { readAgain = true; return; }
      reading = true;
      try {
        const batches = await Promise.all(kinds.map(kind => invoke<LogBatch>("get_logs", { kind, after: after.current[kind] })));
        if (disposed) return;
        batches.forEach((batch, index) => {
          const kind = kinds[index];
          after.current[kind] = batch.last_seq;
          merge(kind, batch.entries, batch.gap ? batch.last_seq : undefined);
        });
        const errors = batches.flatMap(batch => batch.error ? [diagnostic(batch.error)] : []);
        if (subscriptionFailed) errors.push(t("日志事件订阅失败，已使用定时补齐。"));
        setError(errors.join(" · ") || null);
      } catch (e) {
        if (!disposed) setError(t("读取日志失败：{0}", diagnostic(String(e))));
      } finally {
        reading = false;
        if (readAgain && !disposed) { readAgain = false; void refresh(); }
      }
    };

    const subscriptions = Promise.allSettled([
      listen<LogRecord>("bridge-log", ({ payload }) => {
        if (disposed) return;
        const entries = pending[payload.kind];
        entries.push(payload);
        if (entries.length > logLimit) entries.shift();
        timer ??= setTimeout(() => {
          for (const kind of kinds) merge(kind, pending[kind]);
          pending = { audit: [], runtime: [] };
          timer = undefined;
        }, 100);
      }),
      listen("bridge-log-gap", () => { void refresh(); }),
    ]).then(results => {
      subscriptionFailed = results.some(result => result.status === "rejected");
      if (!disposed) void refresh();
      return results.flatMap(result => result.status === "fulfilled" ? [result.value] : []);
    });
    const fallback = setInterval(() => void refresh(), 15000);
    return () => {
      disposed = true;
      clearInterval(fallback);
      clearTimeout(timer);
      void subscriptions.then(stops => stops.forEach(stop => stop()));
    };
  }, [active, diagnostic, t]);
  return { records, error };
}

const LogTableRow = memo(function LogTableRow({ entry, show }: { entry: ParsedLog; show: (entry: ParsedLog, trigger: HTMLButtonElement) => void }) {
  const { language, t } = useLanguage();
  return (
    <TableRow className="log-row">
      <TableCell className="text-sm tabular-nums">{entry.time && Number.isFinite(entry.timeMs) ? clock[language].format(entry.timeMs) : "—"}</TableCell>
      <TableCell className="max-w-72 text-sm">
        <Tooltip>
          <TooltipTrigger asChild><span className="block truncate">{entry.summary}</span></TooltipTrigger>
          <TooltipContent className="max-w-sm break-all">{entry.summary}</TooltipContent>
        </Tooltip>
      </TableCell>
      <TableCell><Badge variant="outline">{entry.code}</Badge></TableCell>
      <TableCell><Button variant="ghost" size="sm" onClick={event => show(entry, event.currentTarget)} aria-label={t("查看日志 {0} 详情", entry.record.seq)}>{t("详情")}</Button></TableCell>
    </TableRow>
  );
});

export default function Logs({ bridge, selected }: { bridge: BridgeModel; selected: boolean }) {
  const feed = useLogFeed(selected && bridge.windowVisible);
  return selected ? <LogView bridge={bridge} feed={feed} /> : null;
}

function LogView({ bridge, feed }: { bridge: BridgeModel; feed: ReturnType<typeof useLogFeed> }) {
  const { language, t } = useLanguage();
  const [scope, setScope] = useState<LogScope>("files");
  const kind: LogKind = scope === "runtime" ? "runtime" : "audit";
  const [query, setQuery] = useState("");
  const search = useDeferredValue(query.toLocaleLowerCase());
  const [resultFilter, setResultFilter] = useState("all");
  const [windowMinutes, setWindowMinutes] = useState("all");
  const [frozen, setFrozen] = useState<ParsedLog[] | null>(null);
  const [detail, setDetail] = useState<ParsedLog | null>(null);
  const [copied, setCopied] = useState(false);
  const [limit, setLimit] = useState(200);
  const detailTrigger = useRef<HTMLButtonElement | null>(null);
  const searchInput = useRef<HTMLInputElement>(null);
  const source = frozen ?? feed.records[kind];
  const rows = useMemo(
    () => filterLogRows(source, scope, search, windowMinutes, resultFilter, Date.now()).reverse(),
    [source, scope, search, windowMinutes, resultFilter],
  );
  const newCount = frozen ? feed.records[kind].filter(entry => entry.record.seq > (frozen[frozen.length - 1]?.record.seq ?? 0) && (scope === "files" ? fileEndpoints.has(String(entry.object?.endpoint)) : scope === "exec" ? String(entry.object?.endpoint ?? "").startsWith("/agent/v1/exec") : true)).length : 0;
  const show = useCallback((entry: ParsedLog, trigger: HTMLButtonElement) => { detailTrigger.current = trigger; setDetail(entry); }, []);

  return <div className="page-stack">
    {feed.error ? <Notice title={t("日志存储需要检查")} error>{feed.error}</Notice> : null}
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <CardTitle>{t("日志")}</CardTitle>
          <Button size="sm" onClick={() => setFrozen(value => value ? null : [...feed.records[kind]])}>
            {frozen ? <Play data-icon="inline-start" /> : <Pause data-icon="inline-start" />}
            {frozen ? t("继续同步") + (newCount > 0 ? ` (${newCount})` : "") : t("暂停同步")}
          </Button>
        </div>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div className="grid grid-cols-2 gap-3 min-[600px]:grid-cols-[auto_auto_auto_minmax(0,1fr)]">
          <Select value={windowMinutes} onValueChange={setWindowMinutes}>
            <SelectTrigger id="log-time" aria-label={t("时间范围")} className="w-full min-[600px]:w-auto">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">{t("全部缓存")}</SelectItem>
                <SelectItem value="5">{t("最近 5 分钟")}</SelectItem>
                <SelectItem value="15">{t("最近 15 分钟")}</SelectItem>
                <SelectItem value="60">{t("最近 1 小时")}</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
          <Select value={resultFilter} onValueChange={setResultFilter}>
            <SelectTrigger id="log-result" aria-label={t("结果")} className="w-full min-[600px]:w-auto">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="all">{t("所有结果")}</SelectItem>
                <SelectItem value="errors">{t("错误与警告")}</SelectItem>
                <SelectItem value="success">{t("正常记录")}</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
          <Select value={scope} onValueChange={value => { setScope(value as LogScope); setFrozen(null); setLimit(200); }}>
            <SelectTrigger id="log-kind" aria-label={t("显示内容")} className="w-full min-[600px]:w-auto">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectGroup>
                <SelectItem value="files">{t("文件操作")}</SelectItem>
                <SelectItem value="exec">{t("命令执行")}</SelectItem>
                <SelectItem value="audit">{t("全部访问（含健康探测）")}</SelectItem>
                <SelectItem value="runtime">{t("连接器运行日志")}</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
          <div className="relative col-span-2 min-[600px]:col-span-1">
            <Search aria-hidden="true" className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              ref={searchInput}
              id="log-query"
              name="log_query"
              aria-label={t("检索")}
              autoComplete="off"
              spellCheck={false}
              className="pl-9"
              value={query}
              onChange={e => setQuery(e.target.value)}
              placeholder={t("查找记录…")}
            />
          </div>
        </div>
        {rows.length ? (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("时间")}</TableHead>
                  <TableHead>{t("操作或消息")}</TableHead>
                  <TableHead>{t("结果")}</TableHead>
                  <TableHead><span className="sr-only">{t("详情操作")}</span></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>{rows.slice(0, limit).map(entry => <LogTableRow key={entry.record.seq} entry={entry} show={show} />)}</TableBody>
            </Table>
            {rows.length > limit ? <Button variant="outline" onClick={() => setLimit(value => value + 200)}>{t("再显示 200 条")}</Button> : null}
          </>
        ) : (
          <Empty>
            <EmptyHeader>
              <EmptyMedia variant="icon"><ScrollText /></EmptyMedia>
              <EmptyTitle>{t("暂无匹配记录")}</EmptyTitle>
              <EmptyDescription>{t("连接器收到请求或发生状态变化后会记录日志，也可以调整筛选条件。")}</EmptyDescription>
            </EmptyHeader>
          </Empty>
        )}
      </CardContent>
    </Card>
    <Dialog open={detail !== null} onOpenChange={open => { if (!open) { setDetail(null); setCopied(false); } }}>
      <DialogContent onCloseAutoFocus={event => { event.preventDefault(); (detailTrigger.current?.isConnected ? detailTrigger.current : searchInput.current)?.focus(); }}>
        <DialogHeader>
          <DialogTitle>{t("日志详情")}</DialogTitle>
          <DialogDescription>{detail?.time ? formatTime(detail.time, language) : t("尚无记录")} · {detail?.record.persisted ? t("已写入日志文件") : t("尚未写入文件，请检查存储")}</DialogDescription>
        </DialogHeader>
        <pre className="max-h-[55vh] overflow-auto whitespace-pre-wrap break-all rounded-md bg-muted p-3 text-caption">{detail?.object ? JSON.stringify(detail.object, null, 2) : detail?.record.text}</pre>
        <DialogFooter>
          <Button variant="outline" onClick={async () => { try { await navigator.clipboard.writeText(detail?.record.text ?? ""); setCopied(true); } catch { bridge.setError(t("日志复制失败，请选择内容后手动复制。")); } }}>{copied ? <Check data-icon="inline-start" /> : <Copy data-icon="inline-start" />}{copied ? t("已复制") : t("复制此条")}</Button>
          <Button onClick={() => setDetail(null)}>{t("关闭")}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>;
}
