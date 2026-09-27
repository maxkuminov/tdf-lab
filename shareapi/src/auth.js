import { createRemoteJWKSet, jwtVerify, errors as joseErrors } from 'jose';

/**
 * Bearer-token verification against the lab realm.
 *
 * There are no sessions and no cookies here. Every request carries a Keycloak
 * access token and is verified from scratch: RS256 signature against the
 * realm's published JWKS, then issuer, expiry, audience and a couple of shape
 * checks. Nothing about the caller is trusted except what survives that.
 *
 * The JWKS is fetched over the Traefik hairpin at the PUBLIC issuer name, the
 * same way the platform itself fetches it, so the `iss` this service verifies
 * is byte-identical to the one the platform verifies.
 */

/**
 * The deployment's issuer and audience come from the environment only. There
 * is deliberately no default: a pod that silently fell back to a placeholder
 * issuer would start, pass its health check, and reject every real token.
 * Refusing to start makes the misconfiguration visible where it is made.
 */
function required(name) {
  const v = process.env[name];
  if (!v || !/^https:\/\/\S+$/.test(v)) {
    console.error(`share-api: ${name} must be set to an https:// URL`);
    process.exit(64);
  }
  return v;
}
const ISSUER = required('OIDC_ISSUER');
const AUDIENCE = required('OIDC_AUDIENCE');
const JWKS_URL = process.env.OIDC_JWKS_URL ?? `${ISSUER}/protocol/openid-connect/certs`;

/**
 * Which clients may drive this API.
 *
 * `web-console` is the browser console. `cli` is here deliberately: it is
 * the only way to obtain a *user* token headlessly, so the verification
 * harness uses it. Both are realm clients that already had to authenticate a
 * real user; neither is a service account. Widen this only on purpose.
 */
const ALLOWED_AZP = (process.env.ALLOWED_AZP ?? 'web-console,cli')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

// createRemoteJWKSet caches the key set and refetches when it meets a `kid` it
// has not seen, rate-limited by cooldownDuration so an unknown kid cannot be
// used to hammer Keycloak.
const jwks = createRemoteJWKSet(new URL(JWKS_URL), {
  cacheMaxAge: 10 * 60 * 1000, // 10 minutes
  cooldownDuration: 30 * 1000, // at most one refetch per 30s
  timeoutDuration: 5000,
});

/** A rejected credential. Maps to 401. */
export class AuthError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AuthError';
  }
}

/**
 * Our side failed - the JWKS could not be fetched, timed out, or did not
 * parse. Maps to 503, NOT 401: a Keycloak outage is not a bad credential, and
 * reporting it as one sends whoever is on call hunting an auth bug instead of
 * a dead IdP.
 */
export class AuthBackendError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AuthBackendError';
  }
}

function bearerFrom(req) {
  const h = req.get('authorization');
  if (!h) throw new AuthError('no Authorization header');
  const m = /^Bearer\s+(\S+)$/i.exec(h);
  if (!m) throw new AuthError('Authorization header is not a Bearer token');
  return m[1];
}

/**
 * jose folds "no key matched this kid" and "the key set could not be fetched"
 * into failures raised from the same call, and only the first is the caller's
 * fault. Separate them: a JWKSNoMatchingKey after jose has already tried a
 * fresh fetch is a 401 (a token signed by a key this realm does not publish);
 * anything that looks like a fetch/timeout/parse failure is a 503.
 */
function isBackendOutage(err) {
  if (err instanceof joseErrors.JWKSTimeout) return true;
  if (err instanceof joseErrors.JOSEError && err.code === 'ERR_JWKS_INVALID') return true;
  // createRemoteJWKSet surfaces a transport failure as a plain Error whose
  // message names the fetch; jose does not wrap it in a typed class.
  const msg = String(err?.message ?? '');
  if (/failed to fetch|fetch failed|ENOTFOUND|ECONNREFUSED|ETIMEDOUT|network|getaddrinfo/i.test(msg)) {
    return true;
  }
  return false;
}

export async function verifyRequest(req) {
  const token = bearerFrom(req);
  let payload;
  try {
    ({ payload } = await jwtVerify(token, jwks, {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ['RS256'],
      clockTolerance: 5,
      // exp is REQUIRED, not just validated-if-present: a signed realm token
      // that simply omits exp must not be a permanent credential.
      requiredClaims: ['exp'],
    }));
  } catch (err) {
    if (err instanceof joseErrors.JWTExpired) throw new AuthError('token has expired');
    if (err instanceof joseErrors.JWTClaimValidationFailed) {
      throw new AuthError(`token claim rejected: ${err.claim}`);
    }
    if (isBackendOutage(err)) {
      throw new AuthBackendError(`could not verify against the identity provider: ${err.message}`);
    }
    // JWKSNoMatchingKey (after jose's own refresh) and every signature/format
    // failure land here: the token is bad, not the backend.
    throw new AuthError('token signature or format is not valid');
  }

  // Shape checks the signature alone does not give us.
  //
  // typ is required to be exactly "Bearer". Keycloak stamps access tokens
  // "Bearer" and ID tokens "ID"; the audience mapper puts the API's audience
  // on BOTH, so without this an ID token would be accepted as if it were an
  // access token. An access token is the only thing that belongs here.
  if (payload.typ !== 'Bearer') {
    throw new AuthError(`token typ is ${payload.typ ?? '(absent)'}, expected Bearer - is this an access token?`);
  }
  if (!payload.azp || !ALLOWED_AZP.includes(payload.azp)) {
    throw new AuthError(`client ${payload.azp ?? '(none)'} is not allowed to use this API`);
  }
  if (typeof payload.sub !== 'string' || !payload.sub) {
    throw new AuthError('token has no subject');
  }
  const username = typeof payload.preferred_username === 'string' ? payload.preferred_username : null;
  if (!username) throw new AuthError('token has no preferred_username - this API is for users, not service accounts');

  return { sub: payload.sub, username, azp: payload.azp, exp: payload.exp };
}

export function requireAuth(req, res, next) {
  verifyRequest(req)
    .then((principal) => {
      req.principal = principal;
      next();
    })
    .catch((err) => {
      if (err instanceof AuthError) {
        res.status(401).json({ error: 'unauthorized', detail: err.message });
        return;
      }
      if (err instanceof AuthBackendError) {
        // The IdP is unreachable - that is our problem, not a bad credential.
        console.error('[tdf-share-api] auth backend:', err.message);
        res.status(503).json({ error: 'auth_backend_unavailable', detail: 'could not reach the identity provider' });
        return;
      }
      console.error('[tdf-share-api] unexpected auth error:', err);
      res.status(503).json({ error: 'auth_backend_unavailable', detail: 'could not reach the identity provider' });
    });
}

export const authConfig = { ISSUER, AUDIENCE, JWKS_URL, ALLOWED_AZP };
