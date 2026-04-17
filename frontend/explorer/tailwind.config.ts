import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        background: "var(--background)",
        foreground: "var(--foreground)",
        // Custom branding colors based on previous CSS variables
        misaka: {
          bg: "#09090b",
          bg2: "#111113",
          bg3: "#18181b",
          bg4: "#1e1e22",
          border: "rgba(255,255,255,0.06)",
          border2: "rgba(255,255,255,0.1)",
          text: "#fafafa",
          text2: "#a1a1aa",
          text3: "#71717a",
        }
      },
    },
  },
  plugins: [],
};
export default config;
