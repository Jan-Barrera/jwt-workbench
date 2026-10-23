import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { Suspense } from "react";

import { QueryParamGuard } from "@/components/privacy/query-param-guard";
import { ReportingInit } from "@/components/privacy/reporting-init";
import { ThemeScript } from "@/components/theme/theme-script";

import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "JWT Workbench",
  description:
    "Local-first tools to decode, inspect, validate, and troubleshoot JWTs.",
  referrer: "no-referrer",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      data-theme="system"
      suppressHydrationWarning
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <head>
        <ThemeScript />
      </head>
      <body className="min-h-full flex flex-col">
        <a
          href="#main-content"
          className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-white focus:px-4 focus:py-2 focus:text-sm focus:font-medium focus:text-zinc-900 focus:shadow-lg focus:outline focus:outline-2 focus:outline-offset-2 focus:outline-zinc-500 dark:focus:bg-zinc-900 dark:focus:text-zinc-50"
        >
          Skip to main content
        </a>
        <ReportingInit />
        <Suspense fallback={null}>
          <QueryParamGuard />
        </Suspense>
        {children}
      </body>
    </html>
  );
}
