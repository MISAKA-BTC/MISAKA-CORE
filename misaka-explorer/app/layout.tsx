import type { Metadata } from 'next';
import './globals.css';
import { Header } from '@/components/explorer/Header';

export const metadata: Metadata = {
  title: 'MISAKA Explorer',
  description: 'Block explorer for the MISAKA Network — post-quantum, privacy-by-default Layer 1 blockchain',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-surface-0 text-slate-200 antialiased">
        <Header />
        <main className="max-w-7xl mx-auto px-4 sm:px-6 py-8">
          {children}
        </main>
        <footer className="border-t border-surface-300/30 mt-16">
          <div className="max-w-7xl mx-auto px-4 sm:px-6 py-8 flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <div className="w-5 h-5 rounded bg-gradient-to-br from-misaka-500 to-misaka-700 flex items-center justify-center">
                <span className="text-white font-display font-bold text-[9px]">M</span>
              </div>
              <span className="text-xs text-slate-500">MISAKA Explorer</span>
            </div>
            <p className="text-xs text-slate-600 text-center">
              This explorer shows only publicly verifiable transaction metadata.
              Privacy-protected recipient and ring-member details are not deanonymized.
            </p>
            <span className="text-xs text-slate-600">v1.0.0</span>
          </div>
        </footer>
      </body>
    </html>
  );
}
