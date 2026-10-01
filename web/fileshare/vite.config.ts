import preact from "@preact/preset-vite";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [preact()],
  build: {
    emptyOutDir: true,
    manifest: true,
    outDir: "../dist/fileshare",
    sourcemap: false,
    target: "es2022",
  },
  test: {
    environment: "jsdom",
    include: ["test/**/*.test.ts", "test/**/*.test.tsx"],
  },
});
