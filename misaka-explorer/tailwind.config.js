/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './app/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        misaka: {
          50:  '#edfcff',
          100: '#d6f7ff',
          200: '#b5f0ff',
          300: '#83e8ff',
          400: '#48d5ff',
          500: '#1eb5ff',
          600: '#0698ff',
          700: '#007fff',
          800: '#0066cc',
          900: '#08569f',
          950: '#0a3461',
        },
        surface: {
          0:   '#0a0e14',
          50:  '#0d1117',
          100: '#111820',
          200: '#161d27',
          300: '#1c2533',
          400: '#243040',
          500: '#2d3b4e',
        },
        accent: {
          cyan:    '#22d3ee',
          blue:    '#3b82f6',
          purple:  '#a78bfa',
          green:   '#34d399',
          orange:  '#fb923c',
          red:     '#f87171',
          yellow:  '#fbbf24',
        },
      },
      fontFamily: {
        sans:  ['var(--font-sans)', 'system-ui', 'sans-serif'],
        mono:  ['var(--font-mono)', 'JetBrains Mono', 'Fira Code', 'monospace'],
        display: ['var(--font-display)', 'system-ui', 'sans-serif'],
      },
      animation: {
        'fade-in':     'fadeIn 0.5s ease-out',
        'slide-up':    'slideUp 0.4s ease-out',
        'pulse-glow':  'pulseGlow 2s ease-in-out infinite',
        'shimmer':     'shimmer 1.5s ease-in-out infinite',
      },
      keyframes: {
        fadeIn:    { '0%': { opacity: '0' }, '100%': { opacity: '1' } },
        slideUp:   { '0%': { opacity: '0', transform: 'translateY(12px)' }, '100%': { opacity: '1', transform: 'translateY(0)' } },
        pulseGlow: { '0%, 100%': { opacity: '1' }, '50%': { opacity: '0.7' } },
        shimmer:   { '0%': { backgroundPosition: '-200% 0' }, '100%': { backgroundPosition: '200% 0' } },
      },
    },
  },
  plugins: [],
};
