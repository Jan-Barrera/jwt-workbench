import {
  formatErrorForReporting,
  scrubSensitiveText,
  scrubSensitiveValue,
} from "./scrub";

let hooksInstalled = false;

function scrubConsoleArgs(args: unknown[]): unknown[] {
  return args.map((arg) => {
    if (typeof arg === "string") {
      return scrubSensitiveText(arg);
    }
    return scrubSensitiveValue(arg);
  });
}

/**
 * Installs global hooks that scrub JWTs and key material from console output
 * and unhandled errors before they reach logs or future telemetry handlers.
 * Safe to call multiple times.
 */
export function installPrivacyReportingHooks(): void {
  if (typeof window === "undefined" || hooksInstalled) {
    return;
  }
  hooksInstalled = true;

  const originalConsoleError = console.error.bind(console);
  console.error = (...args: unknown[]) => {
    originalConsoleError(...scrubConsoleArgs(args));
  };

  window.addEventListener("error", (event) => {
    void formatErrorForReporting(event.error ?? event.message);
  });

  window.addEventListener("unhandledrejection", (event) => {
    void formatErrorForReporting(event.reason);
  });
}
