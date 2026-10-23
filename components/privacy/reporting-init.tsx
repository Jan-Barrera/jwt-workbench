"use client";

import { useEffect } from "react";

import { installPrivacyReportingHooks } from "@/lib/privacy/reporting";

export function ReportingInit() {
  useEffect(() => {
    installPrivacyReportingHooks();
  }, []);

  return null;
}
