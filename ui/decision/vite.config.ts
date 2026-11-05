import { svelte } from "@sveltejs/vite-plugin-svelte";
import { svelteTesting } from "@testing-library/svelte/vite";
import { defineConfig } from "vitest/config";

const tauriDevHost = process.env.TAURI_DEV_HOST;
const tauriPlatform = process.env.TAURI_ENV_PLATFORM;
const tauriDebug = process.env.TAURI_ENV_DEBUG === "true";
const isWindowsTarget =
  tauriPlatform === "windows" ||
  (tauriPlatform === undefined && process.platform === "win32");

export default defineConfig({
  plugins: [svelte(), svelteTesting()],
  clearScreen: false,
  // The production bundle is served by Tauri's embedded application
  // protocol. Relative URLs work both there and from Vite's dev server.
  base: "./",
  envPrefix: ["VITE_", "TAURI_ENV_*"],
  server: {
    host: tauriDevHost || "127.0.0.1",
    port: 5173,
    strictPort: true,
    hmr: tauriDevHost
      ? {
          protocol: "ws",
          host: tauriDevHost,
          port: 5174,
        }
      : undefined,
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },
  build: {
    target: isWindowsTarget ? "chrome105" : "safari15",
    minify: tauriDebug ? false : "esbuild",
    sourcemap: tauriDebug,
  },
  test: {
    environment: "jsdom",
    include: ["src/**/*.test.ts"],
    setupFiles: ["./src/vitest-setup.ts"],
  },
});
