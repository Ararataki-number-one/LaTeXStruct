import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "../latexstruct/server/static-react",
    emptyOutDir: true,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes("vite/preload-helper")) {
            return "runtime";
          }
          if (
            id.includes("node_modules/react/")
            || id.includes("node_modules/react-dom/")
            || id.includes("node_modules/scheduler/")
          ) {
            return "react";
          }
          if (id.includes("node_modules/monaco-editor") || id.includes("node_modules/@monaco-editor")) {
            return "monaco";
          }
        },
      },
    },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8080",
    },
  },
});
