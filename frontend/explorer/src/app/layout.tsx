import type { Metadata } from "next";
import "./globals.css";
import Header from "../components/Header";

export const metadata: Metadata = {
  title: "MISAKA Explorer",
  description: "MISAKA Network Testnet Block Explorer",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-misaka-bg text-misaka-text">
        <Header />
        <main className="mx-auto max-w-6xl w-full px-4 sm:px-6 py-6 pb-20">
          {children}
        </main>
      </body>
    </html>
  );
}
