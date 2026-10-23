type LocalPrivacyIndicatorProps = {
  variant?: "local" | "development";
  message?: string;
};

const DEFAULT_MESSAGES = {
  local: "Processed locally in your browser — not sent to the server",
  development:
    "Development / testing tokens — sign locally; nothing is uploaded or saved",
} as const;

const VARIANT_STYLES = {
  local: {
    text: "text-emerald-800 dark:text-emerald-300",
    dot: "bg-emerald-500",
  },
  development: {
    text: "text-amber-900 dark:text-amber-200",
    dot: "bg-amber-500",
  },
} as const;

export function LocalPrivacyIndicator({
  variant = "local",
  message,
}: LocalPrivacyIndicatorProps) {
  const styles = VARIANT_STYLES[variant];
  const label = message ?? DEFAULT_MESSAGES[variant];

  return (
    <p
      className={`inline-flex items-center gap-2 text-sm font-medium ${styles.text}`}
      role="status"
    >
      <span
        className={`inline-block h-2 w-2 rounded-full ${styles.dot}`}
        aria-hidden
      />
      {label}
    </p>
  );
}
