import { defineConfig } from "vite";

export default defineConfig({
  server: {
    port: 3000,
    host: "0.0.0.0",
    proxy: {
      "/api": {
        target: "http://127.0.0.1:5000",
        changeOrigin: false,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: false,
    target: "es2022",
  },
  test: {
    environment: "jsdom",
    include: ["tests/**/*.test.js"],
  },
});
