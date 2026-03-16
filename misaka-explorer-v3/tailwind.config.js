/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './app/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        bg:      '#0a0a0a',
        fg:      '#f5f5f5',
        muted:   '#666666',
        subtle:  '#999999',
        dim:     '#333333',
        line:    '#1a1a1a',
        surface: '#111111',
        hover:   '#1a1a1a',
        card:    '#0f0f0f',
      },
      fontFamily: {
        sans:    ['"Neue Haas Grotesk"', '"Helvetica Neue"', 'Helvetica', 'Arial', 'sans-serif'],
        mono:    ['"JetBrains Mono"', '"SF Mono"', '"Fira Code"', 'monospace'],
        display: ['"Neue Haas Grotesk"', '"Helvetica Neue"', 'Helvetica', 'sans-serif'],
      },
      maxWidth: {
        content: '1360px',
      },
      animation: {
        'fade-in':  'fadeIn 0.4s ease-out',
        'slide-up': 'slideUp 0.35s ease-out',
      },
      keyframes: {
        fadeIn:  { '0%': { opacity: '0' }, '100%': { opacity: '1' } },
        slideUp: { '0%': { opacity: '0', transform: 'translateY(8px)' }, '100%': { opacity: '1', transform: 'translateY(0)' } },
      },
    },
  },
  plugins: [],
};
