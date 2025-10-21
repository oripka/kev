import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

const projectRoot = path.resolve(fileURLToPath(new URL(".", import.meta.url)));

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
  },
  resolve: {
    alias: {
      "~": path.join(projectRoot, "app"),
      "~~": projectRoot,
      "@": path.join(projectRoot, "app"),
    },
  },
});
