import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';

// Self-hosted, bundled at build time. Nothing is fetched from a font CDN.
import '@fontsource-variable/archivo/wdth.css';
import '@fontsource-variable/newsreader/opsz.css';
import '@fontsource/ibm-plex-mono/400.css';
import '@fontsource/ibm-plex-mono/600.css';
import './styles.css';

import { CONFIG_ERROR } from './config';

const root = document.getElementById('root');
if (!root) throw new Error('missing #root');

if (CONFIG_ERROR) {
  // No usable /config.js: nothing can sign in or reach the platform, so say
  // that plainly instead of rendering a console wired to placeholder hosts.
  // textContent only - the message never becomes markup.
  const p = document.createElement('p');
  p.style.cssText = 'font: 15px/1.5 system-ui, sans-serif; margin: 48px auto; max-width: 40rem; padding: 0 16px;';
  p.textContent = `The TDF Lab Console is not configured: ${CONFIG_ERROR}. The operator must supply /config.js (see the web image section of the README).`;
  root.appendChild(p);
} else {
  // Imported only once the configuration is known to be good: auth.ts builds
  // its OIDC client from it at module load.
  void import('./app').then(({ App }) => {
    createRoot(root).render(
      <StrictMode>
        <App />
      </StrictMode>,
    );
  });
}
