"use client";

import type { ReactNode } from "react";

interface TableProps {
  columns: string[];
  children: ReactNode;
  /** True when the query succeeded but returned no rows. */
  isEmpty: boolean;
  emptyState?: ReactNode;
}

/** Simple table with a built-in empty state row. */
export function Table({ columns, children, isEmpty, emptyState }: TableProps) {
  return (
    <div className="overflow-x-auto rounded-lg border border-[var(--surface-overlay)]">
      <table className="w-full min-w-[480px] border-collapse text-left text-sm">
        <thead>
          <tr className="border-b border-[var(--surface-overlay)] bg-[var(--surface-raised)]">
            {columns.map((col) => (
              <th
                key={col}
                scope="col"
                className="px-4 py-3 font-medium text-[var(--text-muted)]"
              >
                {col}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {isEmpty ? (
            <tr>
              <td colSpan={columns.length} className="px-4 py-8 text-center">
                {emptyState ?? (
                  <span className="text-[var(--text-muted)]">No rows yet.</span>
                )}
              </td>
            </tr>
          ) : (
            children
          )}
        </tbody>
      </table>
    </div>
  );
}
