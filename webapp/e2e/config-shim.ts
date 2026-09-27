// Imported FIRST by e2e.ts: src/config.ts reads globalThis.__TDF_LAB_CONFIG__
// when it is evaluated, and in node there is no /config.js to set it. Values
// come from the environment, with the same placeholders as config.example.js.
const env = process.env;
globalThis.__TDF_LAB_CONFIG__ = {
  platformUrl: env.TDF_PLATFORM_URL ?? 'https://platform.lab.example',
  keycloakUrl: env.TDF_KEYCLOAK_URL ?? 'https://keycloak.lab.example',
  realm: env.TDF_KEYCLOAK_REALM ?? 'lab-realm',
  clientId: env.TDF_OIDC_CLIENT_ID ?? 'web-console',
  wrapperClientId: env.TDF_OIDC_WRAPPER_CLIENT_ID ?? 'wrapper',
  attributeNamespace: env.TDF_ATTRIBUTE_NAMESPACE ?? 'https://lab.example',
  appOrigin: env.TDF_APP_ORIGIN ?? 'https://tdf.lab.example',
};
export {};
