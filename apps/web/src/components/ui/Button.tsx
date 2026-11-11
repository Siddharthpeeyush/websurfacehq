"use client";

import type { ButtonHTMLAttributes, ReactNode } from "react";

type Variant = "primary" | "secondary" | "danger" | "ghost";
type Size = "sm" | "md";

const variantClasses: Record<Variant, string> = {
  primary:
    "bg-[var(--brand)] text-[var(--brand-contrast)] hover:bg-[var(--brand-hover)] hover:text-white disabled:hover:bg-[var(--brand)]",
  secondary:
    "border border-[var(--surface-overlay)] bg-[var(--surface-raised)] text-[var(--text)] hover:bg-slate-700",
  danger:
    "bg-red-600 text-white hover:bg-red-500 disabled:hover:bg-red-600",
  ghost: "text-[var(--text)] hover:bg-[var(--surface-raised)]",
};

const sizeClasses: Record<Size, string> = {
  sm: "px-3 py-1.5 text-sm",
  md: "px-4 py-2 text-sm",
};

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  size?: Size;
  loading?: boolean;
  ref?: React.Ref<HTMLButtonElement>;
  children: ReactNode;
}

export function Button({
  variant = "primary",
  size = "md",
  loading = false,
  disabled,
  ref,
  children,
  className = "",
  ...rest
}: ButtonProps) {
  return (
    <button
      type="button"
      ref={ref}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
      className={`inline-flex items-center justify-center gap-2 rounded-md font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-60 ${variantClasses[variant]} ${sizeClasses[size]} ${className}`}
      {...rest}
    >
      {loading && (
        <span
          aria-hidden="true"
          className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-current border-t-transparent"
        />
      )}
      {children}
    </button>
  );
}
