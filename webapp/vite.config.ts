import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Everything is bundled and emitted into dist/ - no runtime CDN, no external
// font host, no dynamic import from anywhere but our own origin. nginx serves
// dist/ as-is behind the reverse proxy.
export default defineConfig({
  plugins: [react()],
  build: {
    target: 'es2022',
    // Fonts are inlined only if tiny; woff2 files are emitted as assets and
    // fetched from our own origin, which is what the zero-CDN rule requires.
    assetsInlineLimit: 4096,
    chunkSizeWarningLimit: 1200,
    sourcemap: false,
  },
});
