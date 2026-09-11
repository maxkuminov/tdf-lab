import { defineConfig } from 'vite';
export default defineConfig({
  build: {
    ssr: true,
    outDir: 'e2e/dist',
    emptyOutDir: true,
    target: 'node22',
    rollupOptions: { input: 'e2e/e2e.ts', output: { entryFileNames: 'e2e.mjs', format: 'es' } },
  },
});
