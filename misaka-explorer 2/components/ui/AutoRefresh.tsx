'use client';

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';

interface AutoRefreshProps {
  intervalMs?: number;
}

export function AutoRefresh({ intervalMs = 15000 }: AutoRefreshProps) {
  const [enabled, setEnabled] = useState(false);
  const [countdown, setCountdown] = useState(0);
  const router = useRouter();

  const refresh = useCallback(() => {
    router.refresh();
    setCountdown(intervalMs / 1000);
  }, [router, intervalMs]);

  useEffect(() => {
    if (!enabled) return;
    setCountdown(intervalMs / 1000);

    const tick = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          refresh();
          return intervalMs / 1000;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(tick);
  }, [enabled, intervalMs, refresh]);

  return (
    <button
      onClick={() => setEnabled(!enabled)}
      className={`
        inline-flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-all
        ${enabled
          ? 'bg-accent-green/10 text-accent-green border border-accent-green/20'
          : 'bg-surface-200 text-slate-500 border border-surface-300/50 hover:text-slate-300 hover:bg-surface-300'
        }
      `}
      title={enabled ? `Refreshing in ${countdown}s` : 'Enable auto-refresh'}
    >
      <svg
        width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round"
        className={enabled ? 'animate-spin' : ''}
        style={enabled ? { animationDuration: '2s' } : undefined}
      >
        <polyline points="23 4 23 10 17 10" />
        <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" />
      </svg>
      {enabled ? `${countdown}s` : 'Auto'}
    </button>
  );
}
