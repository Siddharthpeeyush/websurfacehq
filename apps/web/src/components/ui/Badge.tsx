import type { ReactNode } from "react";

type Tone = "default" | "success" | "danger" | "warning" | "info";

const toneClasses: Record<Tone, string> = {
  default: "bg-slate-700 text-slate-200",
  success: "bg-[var(--success-bg)] text-[var(--success)]",
  danger: "bg-[var(--danger-bg)] text-[var(--danger)]",
  warning: "bg-yellow-950 text-[var(--warning)]",
  info: "bg-sky-950 text-[var(--info)]",
};

export function Badge({ tone = "default", children }: { tone?: Tone; children: ReactNode }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ${toneClasses[tone]}`}
    >
      {children}
    </span>
  );
}
