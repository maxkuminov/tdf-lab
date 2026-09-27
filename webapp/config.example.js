// Runtime configuration for the TDF Lab Console.
//
// The web image renders this file at container start from environment
// variables (web/entrypoint.sh) and serves it at /config.js; you never edit it
// there. For `npm run dev`, copy this file to public/config.js (gitignored)
// and set your own hostnames. Every value is validated by src/config.ts:
// origins must be exactly https://host[:port], ids [A-Za-z0-9._-].
window.__TDF_LAB_CONFIG__ = {
  platformUrl: 'https://platform.lab.example',
  keycloakUrl: 'https://keycloak.lab.example',
  realm: 'lab-realm',
  clientId: 'web-console',
  wrapperClientId: 'wrapper',
  attributeNamespace: 'https://lab.example',
};
