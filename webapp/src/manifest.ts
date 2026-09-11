import { readZipDirectory, readZipEntry, type ZipEntry } from './zip';

/**
 * A .tdf is a zip holding exactly two members: `0.manifest.json` describes how
 * the payload was encrypted and to whom the key was wrapped, and `0.payload`
 * is the ciphertext. Everything the Key Access Server decides on is in the
 * manifest, in the clear - which is why reading it by hand is the whole point.
 */

export type KeyAccessObject = {
  type?: string;
  url?: string;
  protocol?: string;
  wrappedKey?: string;
  policyBinding?: { alg?: string; hash?: string } | string;
  kid?: string;
  sid?: string;
  schemaVersion?: string;
  encryptedMetadata?: string;
  ephemeralPublicKey?: string;
};

export type EncryptionMethod = {
  algorithm?: string;
  isStreamable?: boolean;
  iv?: string;
};

export type Segment = {
  hash?: string;
  segmentSize?: number;
  encryptedSegmentSize?: number;
};

export type IntegrityInformation = {
  rootSignature?: { alg?: string; sig?: string };
  segmentHashAlg?: string;
  segmentSizeDefault?: number;
  encryptedSegmentSizeDefault?: number;
  segments?: Segment[];
};

export type TdfManifest = {
  schemaVersion?: string;
  payload?: {
    type?: string;
    url?: string;
    protocol?: string;
    mimeType?: string;
    isEncrypted?: boolean;
  };
  encryptionInformation?: {
    type?: string;
    policy?: string;
    keyAccess?: KeyAccessObject[];
    method?: EncryptionMethod;
    integrityInformation?: IntegrityInformation;
  };
  assertions?: unknown[];
};

export type PolicyBody = {
  dataAttributes?: { attribute?: string }[];
  dissem?: string[];
};

export type DecodedPolicy = {
  uuid?: string;
  body?: PolicyBody;
};

export type TdfFile = {
  /** Original bytes, kept so decrypt does not have to re-read the file. */
  bytes: Uint8Array;
  name: string;
  entries: ZipEntry[];
  manifest: TdfManifest;
  /** The manifest exactly as it sits on disk, for the raw view. */
  manifestJson: string;
  /** `encryptionInformation.policy`, base64-decoded. */
  policy: DecodedPolicy | null;
  policyError: string | null;
};

export class NotATdfError extends Error {
  override name = 'NotATdfError';
}

export function decodeBase64Text(b64: string): string {
  const binary = atob(b64);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

/**
 * Ceiling on `0.manifest.json`. The share API enforces the same intent
 * server-side against the ACTUAL extracted length rather than the declared one;
 * this is the client-side half, for a file that arrived by drag-and-drop and
 * never went near that server.
 */
export const MAX_MANIFEST_BYTES = 2 * 1024 * 1024;

/** Reads and parses a .tdf entirely in the browser. No network, no key needed. */
export async function openTdfFile(bytes: Uint8Array, name: string): Promise<TdfFile> {
  const entries = readZipDirectory(bytes);
  const manifestEntry = entries.find((e) => e.name.endsWith('manifest.json'));
  if (!manifestEntry) {
    throw new NotATdfError(
      `This zip has no manifest (it holds ${entries.map((e) => e.name).join(', ') || 'nothing'}). A .tdf always carries 0.manifest.json.`,
    );
  }
  const manifestBytes = await readZipEntry(bytes, manifestEntry, MAX_MANIFEST_BYTES);
  const manifestJson = new TextDecoder().decode(manifestBytes);

  let manifest: TdfManifest;
  try {
    manifest = JSON.parse(manifestJson) as TdfManifest;
  } catch (err) {
    throw new NotATdfError(`0.manifest.json is not valid JSON: ${(err as Error).message}`);
  }

  let policy: DecodedPolicy | null = null;
  let policyError: string | null = null;
  const encoded = manifest.encryptionInformation?.policy;
  if (encoded) {
    try {
      policy = JSON.parse(decodeBase64Text(encoded)) as DecodedPolicy;
    } catch (err) {
      policyError = (err as Error).message;
    }
  } else {
    policyError = 'the manifest carries no encryptionInformation.policy';
  }

  return { bytes, name, entries, manifest, manifestJson, policy, policyError };
}

/** Attribute value FQNs the policy binds this payload to. */
export function policyAttributes(policy: DecodedPolicy | null): string[] {
  return (policy?.body?.dataAttributes ?? [])
    .map((a) => a.attribute)
    .filter((a): a is string => typeof a === 'string');
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}
