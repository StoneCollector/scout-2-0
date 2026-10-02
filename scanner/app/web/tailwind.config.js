/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        background: "#090d16",
        surface: "#0f172a",
        "surface-light": "#1e293b",
        border: "#334155",
        accent: {
          DEFAULT: "#06b6d4",
          hover: "#0891b2",
        },
        pass: "#10b981",
        warn: "#f59e0b",
        fail: "#ef4444",
        skip: "#64748b",
      },
    },
  },
  plugins: [],
}
