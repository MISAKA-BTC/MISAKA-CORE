'use client';

import { truncateHash } from '@/lib/format';
import { CopyButton } from './CopyButton';
import Link from 'next/link';

interface HashDisplayProps {
  hash: string;
  href?: string;
  startLen?: number;
  endLen?: number;
  full?: boolean;
  copyable?: boolean;
}

export function HashDisplay({ hash, href, startLen = 8, endLen = 6, full = false, copyable = true }: HashDisplayProps) {
  const display = full ? hash : truncateHash(hash, startLen, endLen);

  const text = href ? (
    <Link href={href} className="text-misaka-400 hover:text-misaka-300 transition-colors link-underline">
      {display}
    </Link>
  ) : (
    <span className="text-slate-300">{display}</span>
  );

  return (
    <span className="inline-flex items-center gap-1 hash-text">
      {text}
      {copyable && <CopyButton text={hash} />}
    </span>
  );
}
