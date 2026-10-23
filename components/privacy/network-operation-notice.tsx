import type { ReactNode } from "react";

type NetworkOperationNoticeProps = {
  title?: string;
  children: ReactNode;
};

export function NetworkOperationNotice({
  title = "Network request",
  children,
}: NetworkOperationNoticeProps) {
  return (
    <p
      className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-950 dark:border-amber-900/50 dark:bg-amber-950/30 dark:text-amber-100"
      role="note"
    >
      <span className="font-medium">{title}: </span>
      {children}
    </p>
  );
}

/** Returns true when the user confirms a visible network operation. */
export function confirmNetworkOperation(message: string): boolean {
  if (typeof window === "undefined") {
    return false;
  }
  return window.confirm(message);
}
