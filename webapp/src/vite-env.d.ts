/// <reference types="vite/client" />
//
// Pulls in Vite's ambient module declarations. Two things in this app need
// them: `import ... from './wrapper/page.html?raw'` (the sealed-page template
// is imported as a string so its bytes are exactly the bytes that ship), and
// `import.meta.env` in `sealed-runtime.ts`.
