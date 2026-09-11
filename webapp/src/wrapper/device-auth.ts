/**
 * OAuth 2.0 Device Authorization Grant (RFC 8628) for the sealed page.
 *
 * This is the mechanism that lets a wrapper opened from a filesystem
 * authenticate at all. Every other browser flow needs a redirect URI, and a
 * `file://` document cannot have one: its origin is the literal `null`, and no
 * OAuth client should ever register a redirect back to that. The device grant
 * needs no redirect at all. The page asks the realm for a short user code, the
 * person types it into the realm's own page in a normal browser tab, and the
 * page polls until the realm hands over a token.
 *
 * What that buys, precisely: the password is typed into Keycloak, on Keycloak's
 * origin, exactly as it is for the console. This page never sees it. What it
 * DOES see, and what the console's flow never gave it, is the resulting access
 * token - see the security note in `sealed-page.ts`.
 *
 * Both calls are `application/x-www-form-urlencoded` POSTs with no custom
 * headers, so they are CORS-*simple* and generate no preflight. They still need
 * `Access-Control-Allow-Origin: null` to be READABLE, which is what the
 * `wrapper` client's `webOrigins: ["null"]` provides. Measured from a real
 * file:// page, not assumed: device endpoint 200 with a readable body, token
 * endpoint 400 `authorization_pending` with a readable body.
 */

import { OIDC_AUTHORITY, OIDC_WRAPPER_CLIENT_ID } from '../config';

const DEVICE_ENDPOINT = `${OIDC_AUTHORITY}/protocol/openid-connect/auth/device`;
const TOKEN_ENDPOINT = `${OIDC_AUTHORITY}/protocol/openid-connect/token`;
const GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

export type DeviceStart = {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  /** Pre-fills the code. RFC 8628 calls it optional; Keycloak sends it. */
  verificationUriComplete: string | null;
  expiresAt: number;
  /** Seconds between polls. The server may raise this with `slow_down`. */
  interval: number;
};

export type DeviceTokens = {
  accessToken: string;
  refreshToken: string | null;
  expiresAt: number;
};

export class DeviceAuthError extends Error {
  override name = 'DeviceAuthError';
  constructor(
    message: string,
    /** The RFC 8628 / OAuth error code, when the server gave one. */
    readonly code?: string,
  ) {
    super(message);
  }
}

async function form(url: string, body: Record<string, string>): Promise<{ status: number; json: any }> {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(body).toString(),
  });
  let json: any = null;
  try {
    json = await res.json();
  } catch {
    /* a body we cannot parse is handled by the caller from the status */
  }
  return { status: res.status, json };
}

/** Asks the realm for a user code. Nothing is authenticated yet. */
export async function startDeviceAuth(): Promise<DeviceStart> {
  let out: { status: number; json: any };
  try {
    out = await form(DEVICE_ENDPOINT, { client_id: OIDC_WRAPPER_CLIENT_ID, scope: 'openid' });
  } catch (err) {
    // A CORS refusal and an offline machine look identical from here - the
    // browser deliberately hides which. Say both rather than guess.
    throw new DeviceAuthError(
      `Could not reach the identity provider at ${new URL(OIDC_AUTHORITY).host}. Either this machine is offline, or that realm does not allow a request from this page's origin (${location.origin}).`,
      'network',
    );
  }
  if (out.status !== 200 || !out.json?.device_code) {
    throw new DeviceAuthError(
      `The identity provider refused to start a device login (HTTP ${out.status}${out.json?.error ? `, ${out.json.error}` : ''}).`,
      out.json?.error,
    );
  }
  const j = out.json;
  return {
    deviceCode: String(j.device_code),
    userCode: String(j.user_code),
    verificationUri: String(j.verification_uri),
    verificationUriComplete: j.verification_uri_complete ? String(j.verification_uri_complete) : null,
    expiresAt: Date.now() + Number(j.expires_in ?? 600) * 1000,
    interval: Math.max(1, Number(j.interval ?? 5)),
  };
}

export type PollEvent =
  | { kind: 'pending'; secondsLeft: number }
  | { kind: 'slow-down'; interval: number };

/**
 * Polls until the person approves, refuses, or the code expires.
 *
 * Honours the server's pacing rather than hammering it: `interval` from the
 * device response, and `slow_down` raises it by 5s as RFC 8628 requires. A
 * client that ignores `slow_down` gets itself rate-limited and then reports the
 * rate-limit as a login failure.
 */
export async function pollForTokens(
  start: DeviceStart,
  onEvent: (ev: PollEvent) => void,
  shouldStop: () => boolean,
): Promise<DeviceTokens> {
  let interval = start.interval;
  for (;;) {
    if (shouldStop()) throw new DeviceAuthError('Cancelled.', 'cancelled');
    await new Promise((r) => setTimeout(r, interval * 1000));
    if (shouldStop()) throw new DeviceAuthError('Cancelled.', 'cancelled');

    if (Date.now() > start.expiresAt) {
      throw new DeviceAuthError('That code expired before it was approved. Start again for a fresh one.', 'expired_token');
    }

    let out: { status: number; json: any };
    try {
      out = await form(TOKEN_ENDPOINT, {
        grant_type: GRANT,
        device_code: start.deviceCode,
        client_id: OIDC_WRAPPER_CLIENT_ID,
      });
    } catch {
      // A transient network blip should not end a login the user is halfway
      // through; keep polling until the code genuinely expires.
      onEvent({ kind: 'pending', secondsLeft: Math.max(0, Math.round((start.expiresAt - Date.now()) / 1000)) });
      continue;
    }

    if (out.status === 200 && out.json?.access_token) {
      return {
        accessToken: String(out.json.access_token),
        refreshToken: out.json.refresh_token ? String(out.json.refresh_token) : null,
        expiresAt: Date.now() + Number(out.json.expires_in ?? 300) * 1000,
      };
    }

    const code = out.json?.error;
    if (code === 'authorization_pending') {
      onEvent({ kind: 'pending', secondsLeft: Math.max(0, Math.round((start.expiresAt - Date.now()) / 1000)) });
      continue;
    }
    if (code === 'slow_down') {
      interval += 5;
      onEvent({ kind: 'slow-down', interval });
      continue;
    }
    if (code === 'expired_token') {
      throw new DeviceAuthError('That code expired before it was approved. Start again for a fresh one.', code);
    }
    if (code === 'access_denied') {
      throw new DeviceAuthError('The request was refused in the identity provider.', code);
    }
    throw new DeviceAuthError(
      `The identity provider ended the login: ${code ?? `HTTP ${out.status}`}${out.json?.error_description ? ` — ${out.json.error_description}` : ''}`,
      code,
    );
  }
}
