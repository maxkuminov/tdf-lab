/**
 * Build-time constants for the lab. Nothing here is a secret: `web-console` is a
 * PUBLIC OIDC client (authorization code + PKCE, no client secret), and every
 * URL below is a public endpoint of the deployment anyway. Replace the
 * `*.lab.example` placeholders with your own hostnames before building.
 *
 * If any of these change, they change in `keycloak_data.yaml` / the Keycloak
 * `web-console` client / `opentdf.yaml` CORS at the same time - see lab journal §10.
 */

/** OpenTDF platform: policy, authorization, KAS and the well-known document. */
export const PLATFORM_URL = 'https://platform.lab.example';

/**
 * KAS endpoint as registered in the platform's KAS registry
 * (`otdfctl policy kas-registry create --uri https://platform.lab.example/kas`).
 * The SDK strips the trailing `/kas` to find the platform root, so this string
 * must match the registry entry exactly or `decrypt` refuses the file before
 * it ever calls rewrap.
 */
export const KAS_URL = `${PLATFORM_URL}/kas`;

/** Keycloak realm issuer. Must equal the `iss` claim the platform verifies. */
export const OIDC_AUTHORITY = 'https://keycloak.lab.example/realms/lab-realm';

/** Public client created for this console. No secret exists for it. */
export const OIDC_CLIENT_ID = 'web-console';

/**
 * Public client used by a self-decrypting HTML wrapper (lab journal §10l).
 *
 * Separate from `web-console` on purpose. It has NO redirect URIs and no standard
 * flow at all - it only has the device authorization grant, which is the one
 * OAuth flow that needs no redirect and therefore works from a document whose
 * origin is the literal `null`. Keeping it apart means the console's client
 * never had to be loosened to make wrappers work, and the two can be revoked
 * independently.
 */
export const OIDC_WRAPPER_CLIENT_ID = 'wrapper';

/** Where the console itself is served. */
export const APP_ORIGIN = 'https://tdf.lab.example';

/** Ceiling on files this console will encrypt, in bytes. */
export const MAX_UPLOAD_BYTES = 20 * 1024 * 1024;

/** Keycloak admin console, linked from the identity panel for the user-b flip. */
export const KEYCLOAK_ADMIN_URL = 'https://keycloak.lab.example/admin/master/console/#/lab-realm/users';

/**
 * The policy namespace attribute FQNs are built from. Deliberately NOT this
 * site's hostname: `lab.example` is an identifier inside the policy model
 * and nothing is served there. Showing them side by side stops the two being
 * read as the same thing.
 */
export const ATTRIBUTE_NAMESPACE = 'https://lab.example';
