import { readZipDirectory, readZipEntry, ZipFormatError } from './zip.js';

/**
 * Server-side validation of an uploaded .tdf.
 *
 * The point is not to trust the uploader. The client sends bytes and a display
 * filename and NOTHING else that matters: the attributes recorded against a
 * file are read out of the manifest the client already committed to, because
 * the manifest cannot lie about them without breaking the policyBinding HMAC
 * that the KAS checks at rewrap time. A client that declares "public" while
 * sealing to "secret" changes only the label in this listing, never who can
 * actually open the file.
 */

export class InvalidTdfError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InvalidTdfError';
  }
}

const MAX_MANIFEST_BYTES = 1024 * 1024;

export function inspectTdf(buf) {
  let entries;
  try {
    entries = readZipDirectory(buf);
  } catch (err) {
    if (err instanceof ZipFormatError) throw new InvalidTdfError(err.message);
    throw new InvalidTdfError('could not read the archive');
  }

  // Reject duplicate members. A zip may legally hold two entries with the same
  // name; a .tdf may not, and allowing it would let an uploader show one
  // manifest to this validator and leave a different one for a reader.
  const named = (n) => entries.filter((e) => e.name === n);
  if (named('0.manifest.json').length > 1) throw new InvalidTdfError('archive has more than one 0.manifest.json');
  if (named('0.payload').length > 1) throw new InvalidTdfError('archive has more than one 0.payload');

  const manifestEntry = entries.find((e) => e.name === '0.manifest.json');
  const payloadEntry = entries.find((e) => e.name === '0.payload');
  if (!manifestEntry) {
    throw new InvalidTdfError(
      `no 0.manifest.json in the archive (found: ${entries.map((e) => e.name).join(', ') || 'nothing'})`,
    );
  }
  if (!payloadEntry) throw new InvalidTdfError('no 0.payload in the archive');

  let manifest;
  try {
    // The cap is enforced on the ACTUAL extracted length, inside readZipEntry -
    // not on manifestEntry.uncompressedSize, which is a number the uploader
    // controls and could set to 1 while shipping a 2 MB manifest.
    manifest = JSON.parse(readZipEntry(buf, manifestEntry, MAX_MANIFEST_BYTES).toString('utf8'));
  } catch (err) {
    if (err instanceof ZipFormatError) throw new InvalidTdfError(err.message);
    throw new InvalidTdfError(`0.manifest.json is not valid JSON: ${err.message}`);
  }
  if (!manifest || typeof manifest !== 'object') {
    throw new InvalidTdfError('manifest is not an object');
  }

  // --- require the real ZTDF shape ------------------------------------------
  //
  // This does NOT prove the file is authentic. This service has no data
  // encryption key, so it cannot check the policyBinding HMAC - only a
  // successful KAS rewrap does that. What it does is reject files that are
  // structurally not TDFs, so the listing cannot be seeded with a plain zip
  // wearing a .tdf name and arbitrary declared attributes. The honest claim is
  // "well-formed", not "verified".
  const enc = manifest.encryptionInformation;
  if (!enc || typeof enc !== 'object') {
    throw new InvalidTdfError('manifest has no encryptionInformation');
  }
  const method = enc.method;
  if (!method || typeof method !== 'object' || typeof method.algorithm !== 'string' || !method.algorithm) {
    throw new InvalidTdfError('manifest has no encryptionInformation.method.algorithm');
  }
  if (!Array.isArray(enc.keyAccess) || enc.keyAccess.length === 0) {
    throw new InvalidTdfError('manifest has no keyAccess objects - nothing wraps a key here');
  }
  for (const kao of enc.keyAccess) {
    if (!kao || typeof kao !== 'object') throw new InvalidTdfError('a keyAccess object is not an object');
    if (typeof kao.wrappedKey !== 'string' || !kao.wrappedKey) {
      throw new InvalidTdfError('a keyAccess object carries no wrappedKey');
    }
    if (typeof kao.url !== 'string' || !kao.url) {
      throw new InvalidTdfError('a keyAccess object names no KAS url');
    }
    // policyBinding must be present. It is what a real KAS checks; a file
    // missing it is not a TDF a KAS would ever have produced.
    const pb = kao.policyBinding;
    const hasBinding =
      (typeof pb === 'string' && pb.length > 0) ||
      (pb && typeof pb === 'object' && typeof pb.hash === 'string' && pb.hash.length > 0);
    if (!hasBinding) {
      throw new InvalidTdfError('a keyAccess object has no policyBinding');
    }
  }
  if (typeof enc.policy !== 'string' || !enc.policy) {
    throw new InvalidTdfError('manifest carries no encryptionInformation.policy');
  }

  let policy;
  try {
    policy = JSON.parse(Buffer.from(enc.policy, 'base64').toString('utf8'));
  } catch (err) {
    throw new InvalidTdfError(`the base64 policy does not decode to JSON: ${err.message}`);
  }
  if (!policy || typeof policy !== 'object') {
    throw new InvalidTdfError('the decoded policy is not a JSON object');
  }

  const raw = policy?.body?.dataAttributes;
  const attributes = Array.isArray(raw)
    ? raw
        .map((a) => (a && typeof a.attribute === 'string' ? a.attribute : null))
        .filter((a) => a !== null && a.length <= 512)
    : [];

  return {
    attributes: [...new Set(attributes)],
    kasUrls: [
      ...new Set(
        enc.keyAccess.map((k) => (typeof k.url === 'string' ? k.url : '')).filter(Boolean),
      ),
    ],
    schemaVersion: typeof manifest.schemaVersion === 'string' ? manifest.schemaVersion : null,
    mimeType: typeof manifest.payload?.mimeType === 'string' ? manifest.payload.mimeType : null,
    payloadSize: payloadEntry.uncompressedSize,
  };
}

/**
 * Display-only. The stored path is a server-generated UUID and never contains
 * any part of this, so it cannot be a traversal vector; it is sanitised anyway
 * so it cannot smuggle control characters or a header break into a listing or
 * into a Content-Disposition value.
 */
export function sanitizeFilename(name) {
  if (typeof name !== 'string' || !name) return 'upload.tdf';
  const base = name.split(/[\\/]/).pop() ?? '';
  const safe = base
    .replace(/[\u0000-\u001f\u007f]/g, '')
    .replace(/["']/g, '')
    .replace(/\.{2,}/g, '.')
    .trim()
    .replace(/[^A-Za-z0-9._-]/g, '_')
    .replace(/^[.\-_]+/, '');
  return safe.slice(0, 120) || 'upload.tdf';
}
