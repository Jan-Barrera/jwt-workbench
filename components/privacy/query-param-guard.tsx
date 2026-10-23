"use client";

import { usePathname, useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";

import { buildCleanUrl, sanitizeUrlSearchParams } from "@/lib/privacy/url";

export function QueryParamGuard() {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const [removedParams, setRemovedParams] = useState<string[]>([]);

  useEffect(() => {
    const current = new URLSearchParams(searchParams.toString());
    const { removed } = sanitizeUrlSearchParams(current);
    if (removed.length === 0) {
      return;
    }

    const cleanUrl = buildCleanUrl(pathname, current);
    window.history.replaceState(null, "", cleanUrl);
    setRemovedParams(removed);
  }, [pathname, searchParams]);

  if (removedParams.length === 0) {
    return null;
  }

  return (
    <p
      className="border-b border-amber-200 bg-amber-50 px-4 py-2 text-center text-sm text-amber-950 dark:border-amber-900/50 dark:bg-amber-950/40 dark:text-amber-100"
      role="alert"
    >
      Removed sensitive query parameter
      {removedParams.length === 1 ? "" : "s"} from the URL (
      {removedParams.join(", ")}). JWT Workbench never reads tokens from the
      address bar.
    </p>
  );
}
