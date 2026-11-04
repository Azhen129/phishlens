import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
export default defineConfig({
  plugins: [react(), tailwindcss()],
  root: "frontend",
  server: {
    host: "127.0.0.1",
    port: Number(process.env.PHISHLENS_FRONTEND_PORT || "5173"),
    strictPort: true,
    proxy: {
      "/api": process.env.PHISHLENS_API_TARGET || "http://127.0.0.1:8000",
    },
    headers: {
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
    },
  },
  build: { outDir: "../dist", emptyOutDir: true },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test-setup.ts"],
    include: ["src/**/*.test.{ts,tsx}"],
  },
});
