import type { Metadata } from 'next';
import './globals.css';
import { Header } from '@/components/explorer/Header';

export const metadata: Metadata = {
  title: 'MISAKA Explorer',
  description: 'Block explorer for the MISAKA Network — post-quantum, privacy-by-default Layer 1',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen">
        <Header />
        <main className="max-w-content mx-auto px-6 sm:px-8 py-12">
          {children}
        </main>
        <footer className="border-t border-line mt-24">
          <div className="max-w-content mx-auto px-6 sm:px-8 py-10 flex flex-col sm:flex-row items-center justify-between gap-4">
            <span className="text-[11px] uppercase tracking-[0.2em] text-muted font-medium">MISAKA Network</span>
            <p className="text-[11px] text-dim text-center leading-relaxed max-w-md">
              This explorer shows only publicly verifiable transaction metadata. Privacy-protected details are not deanonymized.
            </p>
            <span className="text-[11px] text-dim tracking-wider">v0.4.1</span>
          </div>
        </footer>
      </body>
    </html>
  );
}
