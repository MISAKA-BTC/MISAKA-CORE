'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { SearchBar } from '@/components/explorer/SearchBar';
import { cn } from '@/lib/utils/cn';

const NAV_ITEMS = [
  { href: '/', label: 'Dashboard' },
  { href: '/blocks', label: 'Blocks' },
  { href: '/txs', label: 'Transactions' },
  { href: '/validators', label: 'Validators' },
  { href: '/faucet', label: 'Faucet' },
];

export function Header() {
  const pathname = usePathname();

  return (
    <header className="sticky top-0 z-50 backdrop-blur-xl bg-surface-0/80 border-b border-surface-300/40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6">
        <div className="flex items-center justify-between h-16 gap-6">
          {/* Logo */}
          <Link href="/" className="flex items-center gap-2.5 shrink-0 group">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-misaka-500 to-misaka-700 flex items-center justify-center shadow-lg shadow-misaka-500/20 group-hover:shadow-misaka-500/40 transition-shadow">
              <span className="text-white font-display font-bold text-sm">M</span>
            </div>
            <div className="hidden sm:block">
              <span className="font-display font-semibold text-white text-sm tracking-tight">MISAKA</span>
              <span className="text-slate-500 text-xs ml-1.5 font-medium">Explorer</span>
            </div>
          </Link>

          {/* Nav links */}
          <nav className="hidden md:flex items-center gap-1">
            {NAV_ITEMS.map(({ href, label }) => {
              const isActive = href === '/' ? pathname === '/' : pathname.startsWith(href);
              return (
                <Link
                  key={href}
                  href={href}
                  className={cn(
                    'px-3 py-1.5 rounded-lg text-sm font-medium transition-all',
                    isActive
                      ? 'bg-misaka-500/10 text-misaka-400'
                      : 'text-slate-400 hover:text-white hover:bg-surface-200',
                  )}
                >
                  {label}
                </Link>
              );
            })}
          </nav>

          {/* Search */}
          <div className="flex-1 max-w-md">
            <SearchBar compact />
          </div>
        </div>
      </div>
    </header>
  );
}
