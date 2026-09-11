import {
  OpenTDF,
  authTokenInterceptor,
  DecryptError,
  IntegrityError,
  InvalidFileError,
  NetworkError,
  PermissionDeniedError,
} from '@opentdf/sdk';
import { PlatformClient } from '@opentdf/sdk/platform';
import { KAS_URL, PLATFORM_URL } from './config';
import { lastRpcFailure, rpcCursor, traceInterceptor } from './rpc';

/** Both clients share one token source and one trace. */
export type LabClients = {
  tdf: OpenTDF;
  platform: PlatformClient;
};

export function createClients(getAccessToken: () => Promise<string>): LabClients {
  // Order matters: the trace interceptor is listed first so it wraps the auth
  // interceptor and sees the final error the transport produced.
  const interceptors = [traceInterceptor, authTokenInterceptor(getAccessToken)];
  return {
    tdf: new OpenTDF({
      interceptors,
      platformUrl: PLATFORM_URL,
      policyEndpoint: PLATFORM_URL,
      defaultCreateOptions: { defaultKASEndpoint: KAS_URL },
      defaultReadOptions: { platformUrl: PLATFORM_URL },
    }),
    platform: new PlatformClient({ interceptors, platformUrl: PLATFORM_URL }),
  };
}

export type EncryptResult = {
  bytes: Uint8Array;
  filename: string;
};

/**
 * Wraps a fresh data encryption key for this lab's KAS, binds the chosen
 * attribute values into the policy, and returns the .tdf bytes.
 *
 * `autoconfigure` sends the attribute FQNs to the policy service first, so the
 * KAS is chosen by policy where an attribute names one. This lab's
 * `classification` values carry no KAS grants, so the plan comes back empty and
 * `defaultKASEndpoint` is used - the same path `otdfctl encrypt` takes here.
 */
export async function encryptToTdf(
  clients: LabClients,
  file: File,
  attributeFqns: string[],
): Promise<EncryptResult> {
  const mimeType = (file.type && file.type.includes('/') ? file.type : 'application/octet-stream') as `${string}/${string}`;
  const stream = await clients.tdf.createTDF({
    source: { type: 'file-browser', location: file },
    attributes: attributeFqns,
    autoconfigure: true,
    defaultKASEndpoint: KAS_URL,
    mimeType,
  });
  const bytes = new Uint8Array(await new Response(stream).arrayBuffer());
  return { bytes, filename: `${file.name}.tdf` };
}

export type DecryptSuccess = {
  outcome: 'granted';
  plaintext: Uint8Array;
  /** Set when the payload decodes as UTF-8 text. */
  text: string | null;
  mimeType: string;
};

export type DecryptFailureKind =
  | 'denied'
  /** The policy was edited after sealing; the policyBinding HMAC no longer matches. */
  | 'policy-binding'
  | 'unauthenticated'
  | 'integrity'
  | 'unsafe-kas'
  | 'malformed'
  | 'network'
  | 'unknown';

export type DecryptFailure = {
  outcome: 'refused';
  kind: DecryptFailureKind;
  /** Short headline for the result panel. */
  headline: string;
  /** What the SDK said. */
  sdkMessage: string;
  /** What the platform said, recovered from the RPC trace. */
  serviceCode?: string;
  serviceMessage?: string;
};

export type DecryptOutcome = DecryptSuccess | DecryptFailure;

const UTF8_STRICT = new TextDecoder('utf-8', { fatal: true });

export async function decryptTdf(clients: LabClients, bytes: Uint8Array): Promise<DecryptOutcome> {
  // Scope every later trace lookup to this call. Without it a denial earlier in
  // the session is offered as the explanation for an unrelated later failure.
  const cursor = rpcCursor();
  const reader = clients.tdf.open({
    source: { type: 'buffer', location: bytes },
    platformUrl: PLATFORM_URL,
  });
  try {
    const manifest = await reader.manifest();
    const stream = await reader.decrypt();
    const plaintext = new Uint8Array(await new Response(stream).arrayBuffer());
    let text: string | null = null;
    try {
      text = UTF8_STRICT.decode(plaintext);
    } catch {
      text = null;
    }
    return {
      outcome: 'granted',
      plaintext,
      text,
      mimeType: manifest?.payload?.mimeType || 'application/octet-stream',
    };
  } catch (err) {
    return classifyDecryptError(err, cursor);
  } finally {
    await reader.close().catch(() => undefined);
  }
}

function classifyDecryptError(err: unknown, cursor: number): DecryptFailure {
  const sdkMessage = err instanceof Error ? err.message : String(err);
  // Both lookups are scoped to this operation; a stale denial from an earlier
  // decrypt must never be offered as the reason for this one.
  const rewrap = lastRpcFailure('/kas.AccessService/Rewrap', cursor);
  const anyFailure = rewrap ?? lastRpcFailure(undefined, cursor);
  const service = { serviceCode: anyFailure?.code, serviceMessage: anyFailure?.rawMessage };

  // Tamper first: the KAS rejects a stale policyBinding with invalid_argument
  // (its log literally says "tamper detected"), which is a different statement
  // from "you are not entitled" and deserves its own answer.
  if (rewrap?.code === 'invalid_argument' || /tamper detected/i.test(rewrap?.rawMessage ?? '')) {
    return {
      outcome: 'refused',
      kind: 'policy-binding',
      headline: 'Policy binding mismatch',
      sdkMessage,
      ...service,
    };
  }
  if (err instanceof PermissionDeniedError && rewrap?.code !== 'invalid_argument') {
    return { outcome: 'refused', kind: 'denied', headline: 'Access denied', sdkMessage, ...service };
  }
  // A denial can also arrive as a raw ConnectError if it is raised outside the
  // SDK's own rewrap mapping, so trust the trace as well as the class.
  if (rewrap?.code === 'permission_denied') {
    return { outcome: 'refused', kind: 'denied', headline: 'Access denied', sdkMessage, ...service };
  }
  if (anyFailure?.code === 'unauthenticated' || /401|unauthenticated/i.test(sdkMessage)) {
    return {
      outcome: 'refused',
      kind: 'unauthenticated',
      headline: 'Token rejected',
      sdkMessage,
      ...service,
    };
  }
  // `UnsafeUrlError` is thrown by the SDK but not re-exported from its entry
  // point, so it can only be recognised by name.
  if (err instanceof Error && err.name === 'UnsafeUrlError') {
    return {
      outcome: 'refused',
      kind: 'unsafe-kas',
      headline: 'Unknown key server',
      sdkMessage,
      ...service,
    };
  }
  // IntegrityError is the segment-hash mismatch. DecryptError is the AES-GCM
  // authentication tag failing, which surfaces as a bare WebCrypto
  // `OperationError` - it means the ciphertext or the key is not what sealed
  // this payload, so it belongs with integrity and NOT with "unreadable file".
  // Note DecryptError extends InvalidFileError, so it must be tested first.
  if (err instanceof IntegrityError || err instanceof DecryptError) {
    return {
      outcome: 'refused',
      kind: 'integrity',
      headline: 'Payload failed its integrity check',
      sdkMessage,
      ...service,
    };
  }
  if (err instanceof InvalidFileError) {
    return { outcome: 'refused', kind: 'malformed', headline: 'File could not be read', sdkMessage, ...service };
  }
  if (err instanceof NetworkError || /failed to fetch/i.test(sdkMessage)) {
    return { outcome: 'refused', kind: 'network', headline: 'Platform unreachable', sdkMessage, ...service };
  }
  return { outcome: 'refused', kind: 'unknown', headline: 'Decrypt failed', sdkMessage, ...service };
}

/** Hands the browser a file to save. */
export function download(bytes: Uint8Array, filename: string, mimeType = 'application/octet-stream') {
  const blob = new Blob([bytes as BlobPart], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
