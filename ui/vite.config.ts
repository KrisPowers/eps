import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Builds into dist, which `portscan --serve` serves with `--web ui/dist`.
// `npm run dev` proxies the API to a dashboard on the default port.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    modulePreload: { polyfill: false },
  },
  server: {
    proxy: { "/api": { target: "http://127.0.0.1:8090", changeOrigin: true } },
  },
});
