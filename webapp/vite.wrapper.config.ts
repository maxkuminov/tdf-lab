import { defineConfig } from 'vite';

/**
 * Stage 1 of the two-stage build: the sealed page's runtime, bundled with the
 * real `@opentdf/sdk` inside it, into ONE self-contained file.
 *
 * A wrapper has to work from a USB stick on a machine that has never heard of
 * this lab, so it cannot fetch a runtime from anywhere - the code has to be in
 * the document. `inlineDynamicImports` forbids code splitting, so what comes
 * out is a single chunk with no `import` of its own.
 *
 * Stage 2 (`scripts/build-wrapper-template.mjs`) injects it into
 * `src/wrapper/page.template.html` and writes `src/wrapper/generated/page.html`,
 * which `wrapper/html.ts` imports with `?raw`. Both stages run before the app
 * build - see the `build` script in package.json.
 */
export default defineConfig({
  build: {
    target: 'es2022',
    outDir: 'src/wrapper/generated',
    emptyOutDir: false,
    // Vite 8 bundles with rolldown; 'esbuild' is not installed here, and the
    // default minifier is the right one anyway.
    minify: true,
    sourcemap: false,
    lib: {
      entry: 'src/wrapper/sealed-page.ts',
      formats: ['iife'],
      name: '__sealedPage',
      fileName: () => 'sealed-page.iife.js',
    },
    rollupOptions: {
      output: { inlineDynamicImports: true },
    },
  },
});
