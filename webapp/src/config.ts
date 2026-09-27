/**
 * Deployment configuration for the lab, supplied at RUNTIME, never at build
 * time. The same built bundle (and the same container image) serves any
 * deployment; nothing below names a real host.
 *
 * Nothing here is a secret: `web-console` is a PUBLIC OIDC client
 * (authorization code + PKCE, no client secret), and every URL is a public
 * endpoint of the deployment anyway.
 *
 * Where the values come from:
 *
 *   - The console: `/config.js`, a classic script loaded by index.html BEFORE
 *     the module bundle, sets `window.__TDF_LAB_CONFIG__`. The web image
 *     renders it at container start from validated environment variables
 *     (see web/entrypoint.sh); `npm run dev` serves webapp/public/config.js.
 *   - A self-decrypting wrapper (sealed-page.ts): the console copies the
 *     wrapper-relevant values into the page's base64 metadata when it builds
 *     the wrapper, so the inline runtime itself carries no hostname and its
 *     SHA-256 (the /sealed/ CSP hash) is the same for every deployment.
 *   - The node e2e harness: e2e/config-shim.ts, from process.env.
 *
 * Every value is validated against a strict shape before use: an origin is
 * `https://host[:port]` and nothing else, an identifier is `[A-Za-z0-9._-]`.
 * A value that fails leaves the placeholders below in place and sets
 * CONFIG_ERROR, which the console and the wrapper render instead of running.
 *
 * If any of these change, they change in `keycloak_data.yaml` / the Keycloak
 * `web-console` client / `opentdf.yaml` CORS at the same time.
 */

export type LabConfig = {
  /** OpenTDF platform: policy, authorization, KAS and the well-known document. */
  platformUrl: string;
  /** Keycloak base URL (served at the root path, no /auth). */
  keycloakUrl: string;
  /** Realm name inside that Keycloak. */
  realm: string;
  /** Public client created for this console. No secret exists for it. */
  clientId: string;
  /** Public device-grant client used by self-decrypting wrappers. */
  wrapperClientId: string;
  /** The policy namespace attribute FQNs are built from. */
  attributeNamespace: string;
  /** Where the console is served. Defaults to the current page's origin. */
  appOrigin?: string;
};

declare global {
  // eslint-disable-next-line no-var
  var __TDF_LAB_CONFIG__: unknown;
}

const ORIGIN_RE = /^https:\/\/[a-z0-9.-]+(:[0-9]{1,5})?$/i;
const ID_RE = /^[A-Za-z0-9._-]{1,64}$/;

// Used only while CONFIG_ERROR is set, and never contacted: nothing runs
// without a valid configuration. `.invalid` cannot resolve (RFC 6761).
const PLACEHOLDER: LabConfig = {
  platformUrl: 'https://unconfigured.invalid',
  keycloakUrl: 'https://unconfigured.invalid',
  realm: 'lab-realm',
  clientId: 'web-console',
  wrapperClientId: 'wrapper',
  attributeNamespace: 'https://unconfigured.invalid',
};

/** Checks one untrusted object; returns the config or a reason. */
export function validateConfig(raw: unknown): LabConfig | string {
  if (!raw || typeof raw !== 'object') return 'no configuration object was supplied';
  const r = raw as Record<string, unknown>;
  const origin = (k: string): string | null =>
    typeof r[k] === 'string' && ORIGIN_RE.test(r[k] as string) ? (r[k] as string) : null;
  const id = (k: string): string | null =>
    typeof r[k] === 'string' && ID_RE.test(r[k] as string) ? (r[k] as string) : null;

  const out = {
    platformUrl: origin('platformUrl'),
    keycloakUrl: origin('keycloakUrl'),
    realm: id('realm'),
    clientId: id('clientId'),
    wrapperClientId: id('wrapperClientId'),
    attributeNamespace: origin('attributeNamespace'),
  };
  for (const [k, v] of Object.entries(out)) {
    if (v === null) return `configuration value "${k}" is missing or malformed`;
  }
  let appOrigin: string | undefined;
  if (r.appOrigin !== undefined) {
    const a = origin('appOrigin');
    if (a === null) return 'configuration value "appOrigin" is malformed';
    appOrigin = a;
  }
  return { ...(out as Omit<LabConfig, 'appOrigin'>), appOrigin };
}

/** A self-decrypting wrapper carries its config in the base64 metadata input. */
function fromWrapperMeta(): unknown {
  if (typeof document === 'undefined') return undefined;
  const el = document.getElementById('meta-input') as HTMLInputElement | null;
  if (!el || !/^[A-Za-z0-9+/]+={0,2}$/.test(el.value)) return undefined;
  try {
    const bin = atob(el.value);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const meta = JSON.parse(new TextDecoder().decode(bytes)) as { cfg?: unknown };
    return meta?.cfg;
  } catch {
    return undefined;
  }
}

function load(): { cfg: LabConfig; error: string | null } {
  const raw = globalThis.__TDF_LAB_CONFIG__ ?? fromWrapperMeta();
  const v = validateConfig(raw);
  if (typeof v === 'string') return { cfg: PLACEHOLDER, error: v };
  return { cfg: v, error: null };
}

const LOADED = load();

/** Non-null when no usable configuration was found. Callers must not proceed. */
export const CONFIG_ERROR: string | null = LOADED.error;

/** The validated configuration (placeholders if CONFIG_ERROR is set). */
export const CONFIG: Readonly<LabConfig> = Object.freeze({ ...LOADED.cfg });

/** OpenTDF platform: policy, authorization, KAS and the well-known document. */
export const PLATFORM_URL = CONFIG.platformUrl;

/**
 * KAS endpoint as registered in the platform's KAS registry
 * (`otdfctl policy kas-registry create --uri <platform>/kas`).
 * The SDK strips the trailing `/kas` to find the platform root, so this string
 * must match the registry entry exactly or `decrypt` refuses the file before
 * it ever calls rewrap.
 */
export const KAS_URL = `${PLATFORM_URL}/kas`;

/** Keycloak realm issuer. Must equal the `iss` claim the platform verifies. */
export const OIDC_AUTHORITY = `${CONFIG.keycloakUrl}/realms/${CONFIG.realm}`;

/** Public client created for this console. No secret exists for it. */
export const OIDC_CLIENT_ID = CONFIG.clientId;

/**
 * Public client used by a self-decrypting HTML wrapper.
 *
 * Separate from `web-console` on purpose. It has NO redirect URIs and no standard
 * flow at all - it only has the device authorization grant, which is the one
 * OAuth flow that needs no redirect and therefore works from a document whose
 * origin is the literal `null`. Keeping it apart means the console's client
 * never had to be loosened to make wrappers work, and the two can be revoked
 * independently.
 */
export const OIDC_WRAPPER_CLIENT_ID = CONFIG.wrapperClientId;

/** Where the console itself is served. */
export const APP_ORIGIN =
  CONFIG.appOrigin ??
  (typeof location !== 'undefined' && ORIGIN_RE.test(location.origin) ? location.origin : 'https://unconfigured.invalid');

/** The realm name, for display. */
export const REALM = CONFIG.realm;

/** Ceiling on files this console will encrypt, in bytes. */
export const MAX_UPLOAD_BYTES = 20 * 1024 * 1024;

/** Keycloak admin console, linked from the identity panel for the user-b flip. */
export const KEYCLOAK_ADMIN_URL = `${CONFIG.keycloakUrl}/admin/master/console/#/${CONFIG.realm}/users`;

/**
 * The policy namespace attribute FQNs are built from. Deliberately NOT this
 * site's hostname: it is an identifier inside the policy model and nothing is
 * served there. Showing them side by side stops the two being read as the
 * same thing.
 */
export const ATTRIBUTE_NAMESPACE = CONFIG.attributeNamespace;

/** What a wrapper needs to authenticate and reach the KAS on its own. */
export function wrapperConfig(): LabConfig {
  const { platformUrl, keycloakUrl, realm, clientId, wrapperClientId, attributeNamespace } = CONFIG;
  return { platformUrl, keycloakUrl, realm, clientId, wrapperClientId, attributeNamespace };
}
