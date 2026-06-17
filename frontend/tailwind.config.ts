import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./src/**/*.{js,ts,jsx,tsx,mdx}"],
  theme: {
    extend: {
      colors: {
        kiro: {
          bg: "#0f1117",
          surface: "#1a1d27",
          border: "#2a2d3a",
          accent: "#3b82f6",
          success: "#10b981",
          danger: "#ef4444",
          warning: "#f59e0b",
          muted: "#6b7280",
          text: "#e5e7eb",
        },
      },
    },
  },
  plugins: [],
};
export default config;
