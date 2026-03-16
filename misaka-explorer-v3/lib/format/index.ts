// lib/format/index.ts — Display formatting helpers

/** Truncate a hex hash: abcdef...123456 */
export function truncateHash(hash: string, startLen = 8, endLen = 6): string {
  if (!hash || hash.length <= startLen + endLen + 3) return hash;
  return `${hash.slice(0, startLen)}...${hash.slice(-endLen)}`;
}

/** Format a timestamp to locale string */
export function formatTimestamp(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false,
    });
  } catch { return iso; }
}

/** Relative time: "3m ago", "2h ago", "5d ago" */
export function relativeTime(iso: string): string {
  try {
    const diff = Date.now() - new Date(iso).getTime();
    const sec = Math.floor(diff / 1000);
    if (sec < 60) return `${sec}s ago`;
    const min = Math.floor(sec / 60);
    if (min < 60) return `${min}m ago`;
    const hr = Math.floor(min / 60);
    if (hr < 24) return `${hr}h ago`;
    const day = Math.floor(hr / 24);
    return `${day}d ago`;
  } catch { return '—'; }
}

/** Format MISAKA amounts (base unit → display) */
export function formatAmount(amount: number, decimals = 9): string {
  const val = amount / Math.pow(10, decimals);
  if (val >= 1_000_000) return `${(val / 1_000_000).toFixed(2)}M`;
  if (val >= 1_000) return `${(val / 1_000).toFixed(2)}K`;
  return val.toFixed(4);
}

/** Format fee in MISAKA */
export function formatFee(fee: number): string {
  if (fee >= 1_000_000) return `${(fee / 1_000_000).toFixed(4)} MSK`;
  return `${fee} μMSK`;
}

/** Format bytes to human-readable */
export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

/** Format percentage */
export function formatPercent(value: number, decimals = 1): string {
  return `${value.toFixed(decimals)}%`;
}

/** Format large numbers with commas */
export function formatNumber(n: number): string {
  return n.toLocaleString('en-US');
}

/** Format block time in seconds */
export function formatBlockTime(seconds: number): string {
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  const m = Math.floor(seconds / 60);
  const s = Math.floor(seconds % 60);
  return `${m}m ${s}s`;
}
