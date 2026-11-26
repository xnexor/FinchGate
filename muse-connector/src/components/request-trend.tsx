import { useLanguage } from "@/lib/i18n";
import { Line, LineChart, CartesianGrid, XAxis } from "recharts";
import { ChartContainer, ChartTooltip, ChartTooltipContent } from "@/components/ui/chart";
import type { Snapshot } from "@/lib/use-bridge";
export default function RequestTrend({ data }: { data: Snapshot["stats"]["trend"] }) {
  const { language, t } = useLanguage();
  const config = { requests: { label: t("请求"), color: "var(--chart-1)" }, errors: { label: t("错误"), color: "var(--chart-2)" } };
  return <ChartContainer config={config} className="h-36 w-full" aria-label={t("最近十五分钟请求与错误趋势")}>
    <LineChart accessibilityLayer data={data} margin={{ left: 12, right: 12 }}>
      <CartesianGrid vertical={false} />
      <XAxis dataKey="minute" tickLine={false} axisLine={false} minTickGap={32} tickFormatter={minute => new Date(Number(minute) * 60000).toLocaleTimeString(language, { hour: "2-digit", minute: "2-digit" })} />
      <ChartTooltip content={<ChartTooltipContent />} />
      <Line name={t("请求")} dataKey="requests" type="linear" stroke="var(--color-requests)" strokeWidth={2} dot={false} isAnimationActive={false} />
      <Line name={t("错误")} dataKey="errors" type="linear" stroke="var(--color-errors)" strokeWidth={2} strokeDasharray="4 4" dot={false} isAnimationActive={false} />
    </LineChart>
  </ChartContainer>;
}
