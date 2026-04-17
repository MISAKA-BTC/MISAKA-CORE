export function formatNumber(n: number | string | undefined | null): string {
  if (n == null) return '—';
  return Number(n).toLocaleString();
}

export function formatAmount(n: number | string | undefined | null): string {
  if (n == null) return '—';
  // convert base units (1e9)
  const val = Number(n) / 1e9;
  // Use up to 9 decimal places without trailing zeros
  return val.toFixed(9).replace(/\.?0+$/, '') + ' MSK';
}

export function formatDate(ms: number | string | undefined | null): string {
  if (!ms) return '—';
  const d = new Date(Number(ms));
  return d.toLocaleString('ja-JP', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZoneName: 'short'
  });
}

export function timeAgo(ms: number | string | undefined | null): string {
  if (!ms) return '—';
  const s = Math.floor((Date.now() - Number(ms)) / 1000);
  if (s < 0) return 'just now';
  if (s < 60) return s + 's ago';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}

export function shortHash(hash: string, n: number = 10): string {
  if (!hash) return '—';
  if (hash.length <= n * 2) return hash;
  return `${hash.slice(0, n)}…${hash.slice(-6)}`;
}

export function shortAddress(addr: string, n: number = 14): string {
  if (!addr) return '—';
  if (addr.length <= n + 6) return addr;
  return `${addr.slice(0, n)}…${addr.slice(-6)}`;
}
