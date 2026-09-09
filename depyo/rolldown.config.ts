import { dirname } from "node:path"
import { fileURLToPath } from "node:url"
import { defineConfig } from "rolldown"
import { importGlobPlugin } from "rolldown/experimental"
import pkg from "./package.json" with { type: "json" }

const _dirname = dirname(fileURLToPath(import.meta.url))

const BANNER =
  `#!/usr/bin/env node\n` +
  `/**\n` +
  ` * ${pkg.description}\n` +
  ` * Version: ${pkg.version}\n` +
  ` * Source code at https://github.com/Lil-House/Pyarmor-Static-Unpack-1shot\n` +
  ` */`

export default defineConfig({
  platform: "node",
  input: "src/main.ts",
  output: {
    file: "dist/main.js",
    // minify: true,
    sourcemap: true,
    postBanner: BANNER,
  },
  plugins: [
    importGlobPlugin({
      root: _dirname,
    }),
  ],
})
