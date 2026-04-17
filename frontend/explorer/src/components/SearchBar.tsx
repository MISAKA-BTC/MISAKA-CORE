"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Search } from "lucide-react";

export default function SearchBar() {
  const [query, setQuery] = useState("");
  const router = useRouter();

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    const q = query.trim();
    if (!q) return;

    if (q.startsWith("misaka1") || q.startsWith("misakatest1") || q.startsWith("msk1")) {
      router.push(`/address/${encodeURIComponent(q)}`);
    } else if (q.length === 64) {
      router.push(`/tx/${encodeURIComponent(q)}`);
    } else if (!isNaN(Number(q))) {
      router.push(`/block/${encodeURIComponent(q)}`);
    } else {
      router.push(`/tx/${encodeURIComponent(q)}`); // fallback
    }
  };

  return (
    <form
      onSubmit={handleSearch}
      className="flex-1 max-w-2xl relative flex items-center bg-misaka-bg3 border border-misaka-border2 rounded-xl focus-within:border-white/20 transition-colors"
    >
      <Search className="w-4 h-4 text-misaka-text3 absolute left-4" />
      <input
        type="text"
        className="w-full bg-transparent border-none outline-none py-3 pl-11 pr-4 text-sm font-mono text-misaka-text placeholder:text-misaka-text3 placeholder:font-sans"
        placeholder="TX Hash / Address / Block Height を検索..."
        value={query}
        onChange={(e) => setQuery(e.target.value)}
      />
    </form>
  );
}
