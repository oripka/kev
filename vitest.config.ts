import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";
import path from "node:path";

const projectRoot = path.dirname(fileURLToPath(new URL("./", import.meta.url)));

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
