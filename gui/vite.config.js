import { defineConfig } from 'vite';

// Monaco and xterm are bundled from node_modules, never fetched from a CDN:
// the Tauri CSP forbids remote origins, and an analysis tool that phones home
// for its editor is not one you can run on an air-gapped build machine.
export default defineConfig({
  build: { outDir: 'dist', emptyOutDir: true, target: 'esnext' },
  server: { port: 5173, strictPort: true },
  optimizeDeps: { include: ['monaco-editor'] },
});
