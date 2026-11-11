"use client";

import type { ReactNode } from "react";
import { Button } from "./Button";

/** Loading skeleton — a pulsing placeholder block. */
export function Skeleton({ className = "" }: { className?: string }) {
  return (
    <div
      aria-hidden="true"
      className={`animate-pulse rounded-md bg-slate-700 ${className}`}
    />
  );
}

export function SkeletonRows({ rows = 3 }: { rows?: number }) {
  return (
    <div className="flex flex-col gap-2" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-10 w-full" />
      ))}
    </div>
  );
}

/** Empty state — shown when a query succeeded with zero rows. */
export function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center gap-2 py-8 text-center">
      <p className="font-medium text-[var(--text)]">{title}</p>
      {description && (
        <p className="max-w-md text-sm text-[var(--text-muted)]">{description}</p>
      )}
      {action}
    </div>
  );
}

/** Error state — shown when a request fails, with a retry button. */
export function ErrorState({
  message,
  onRetry,
}: {
  message: string;
  onRetry: () => void;
}) {
  return (
    <div
      role="alert"
      className="flex flex-col items-center gap-3 rounded-lg border border-red-900 bg-[var(--danger-bg)] px-4 py-6 text-center"
    >
      <p className="text-sm text-[var(--danger)]">{message}</p>
      <Button variant="secondary" size="sm" onClick={onRetry}>
        Try again
      </Button>
    </div>
  );
}
