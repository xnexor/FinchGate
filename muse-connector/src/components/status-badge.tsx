import { Badge } from "@/components/ui/badge";
import { Spinner } from "@/components/ui/spinner";
import { cn } from "@/lib/utils";

export type StatusTone = "success" | "warning" | "error" | "neutral";

export function StatusBadge({ tone = "neutral", pending = false, children, className }: {
  tone?: StatusTone; pending?: boolean; children: React.ReactNode; className?: string;
}) {
  return <Badge variant="status" data-tone={tone} className={cn("status-badge", className)}>
    {pending ? <Spinner data-icon="inline-start" role="presentation" aria-hidden="true" /> : <span aria-hidden="true" className="size-1.5 shrink-0 rounded-full bg-current" />}
    {children}
  </Badge>;
}
