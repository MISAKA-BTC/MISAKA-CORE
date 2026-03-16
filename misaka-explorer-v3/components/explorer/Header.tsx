'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { SearchBar } from '@/components/explorer/SearchBar';

const NAV = [
  { href: '/', label: 'Home' },
  { href: '/blocks', label: 'Blocks' },
  { href: '/txs', label: 'Transactions' },
  { href: '/validators', label: 'Validators' },
  { href: '/peers', label: 'Peers' },
  { href: '/faucet', label: 'Faucet' },
];

export function Header() {
  const pathname = usePathname();

  return (
    <header className="sticky top-0 z-50 bg-bg/90 backdrop-blur-md border-b border-line">
      <div className="max-w-content mx-auto px-6 sm:px-8">
        <div className="flex items-center justify-between h-14 gap-8">
          <Link href="/" className="flex items-center gap-3 shrink-0 group">
            <span className="text-[13px] font-medium tracking-[0.25em] uppercase text-fg/90 group-hover:text-fg transition-colors">
              MISAKA
            </span>
            <span className="text-[10px] tracking-[0.15em] uppercase text-muted">Explorer</span>
          </Link>

          <nav className="hidden md:flex items-center gap-0.5">
            {NAV.map(({ href, label }) => {
              const isActive = href === '/' ? pathname === '/' : pathname.startsWith(href);
              return (
                <Link
                  key={href}
                  href={href}
                  className={`px-3 py-1.5 text-[12px] tracking-wider uppercase font-medium transition-colors duration-150 ${
                    isActive ? 'text-fg' : 'text-muted hover:text-fg'
                  }`}
                >
                  {label}
                </Link>
              );
            })}
          </nav>

          <div className="flex-1 max-w-sm">
            <SearchBar compact />
          </div>
        </div>
      </div>
    </header>
  );
}
