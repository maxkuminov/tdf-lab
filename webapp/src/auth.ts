import { UserManager, WebStorageStateStore, type User } from 'oidc-client-ts';
import { OIDC_AUTHORITY, OIDC_CLIENT_ID } from './config';

/**
 * Authorization code + PKCE against the lab realm.
 *
 * `web-console` is a public client, so there is no secret anywhere in this bundle.
 * The realm requires PKCE S256 (`pkce.code.challenge.method` on the client),
 * which oidc-client-ts sends by default for `response_type: 'code'`.
 *
 * Session renewal uses the refresh token grant, NOT a hidden iframe: the IdP
 * is on a different origin (tdfkc) than this console (tdflab), so an iframe
 * silent renew would depend on third-party cookies and fail in most browsers.
 * The refresh grant is a plain XHR to the token endpoint, allowed by the
 * client's `webOrigins` entry.
 */
const userManager = new UserManager({
  authority: OIDC_AUTHORITY,
  client_id: OIDC_CLIENT_ID,
  redirect_uri: `${window.location.origin}/`,
  post_logout_redirect_uri: `${window.location.origin}/`,
  response_type: 'code',
  scope: 'openid profile email',
  loadUserInfo: false,
  automaticSilentRenew: true,
  accessTokenExpiringNotificationTimeInSeconds: 60,
  // Session monitoring uses a hidden iframe against the IdP; same cross-origin
  // cookie problem as silent renew, and nothing here needs it.
  monitorSession: false,
  revokeTokensOnSignout: true,
  // sessionStorage, not localStorage: a lab token should not outlive the tab.
  userStore: new WebStorageStateStore({ store: window.sessionStorage }),
  stateStore: new WebStorageStateStore({ store: window.sessionStorage }),
});

export { userManager };

/** True when the current URL looks like an OIDC redirect landing. */
export function isSigninCallback(): boolean {
  const q = new URLSearchParams(window.location.search);
  return q.has('code') || q.has('error');
}

/**
 * Completes the redirect, then strips the code/state out of the address bar so
 * a refresh does not try to redeem a one-time code twice.
 */
export async function completeSignin(): Promise<User | null> {
  try {
    return await userManager.signinRedirectCallback();
  } finally {
    window.history.replaceState({}, '', window.location.pathname);
  }
}

/**
 * @param loginHint pre-fills the Keycloak username field. Passing one also
 * forces a fresh login prompt, which is how you switch between user-a and user-b
 * without clearing cookies by hand.
 */
export async function signIn(loginHint?: string): Promise<void> {
  await userManager.signinRedirect(
    loginHint ? { login_hint: loginHint, prompt: 'login' } : {},
  );
}

export async function signOut(): Promise<void> {
  await userManager.signoutRedirect();
}

/** Drops the local session without contacting the IdP. */
export async function forgetSession(): Promise<void> {
  await userManager.removeUser();
}

/** Decoded JWT payload. Display only - nothing here is trusted by the app. */
export type Claims = Record<string, unknown>;

export function decodeJwt(token: string): Claims | null {
  try {
    const seg = token.split('.')[1];
    if (!seg) return null;
    const pad = seg.length % 4 === 0 ? '' : '='.repeat(4 - (seg.length % 4));
    const json = atob(seg.replace(/-/g, '+').replace(/_/g, '/') + pad);
    const bytes = Uint8Array.from(json, (c) => c.charCodeAt(0));
    const parsed: unknown = JSON.parse(new TextDecoder().decode(bytes));
    return parsed && typeof parsed === 'object' ? (parsed as Claims) : null;
  } catch {
    return null;
  }
}

export function claimAsList(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.filter((v): v is string => typeof v === 'string');
  return [];
}
