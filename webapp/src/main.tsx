import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

// Self-hosted, bundled at build time. Nothing is fetched from a font CDN.
import '@fontsource-variable/archivo/wdth.css';
import '@fontsource-variable/newsreader/opsz.css';
import '@fontsource/ibm-plex-mono/400.css';
import '@fontsource/ibm-plex-mono/600.css';
import './styles.css';

import { App } from './app';

const root = document.getElementById('root');
if (!root) throw new Error('missing #root');
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
