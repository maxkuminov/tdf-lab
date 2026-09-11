import { randomUUID } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';

/**
 * Ciphertext store.
 *
 * Layout inside the named volume:
 *
 *   /data/index.json        the metadata index, rewritten atomically
 *   /data/blobs/<uuid>.tdf  one sealed file per record
 *
 * Every stored path is built from a server-generated UUID that is re-validated
 * against a strict pattern before it is ever joined to a directory, so no
 * caller-supplied string reaches the filesystem. The uploader's filename is
 * metadata only: it is displayed and returned in downloads, and never used to
 * name anything on disk.
 */

const DATA_DIR = process.env.DATA_DIR ?? '/data';
const BLOB_DIR = path.join(DATA_DIR, 'blobs');
const INDEX_PATH = path.join(DATA_DIR, 'index.json');

export const LIMITS = {
  maxFileBytes: Number(process.env.MAX_FILE_BYTES ?? 20 * 1024 * 1024),
  maxFilesPerUser: Number(process.env.MAX_FILES_PER_USER ?? 50),
  maxBytesPerUser: Number(process.env.MAX_BYTES_PER_USER ?? 200 * 1024 * 1024),
};

const ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export function isValidId(id) {
  return typeof id === 'string' && ID_RE.test(id);
}

/** Rejects anything that is not a server-shaped UUID, before any path work. */
function blobPath(id) {
  if (!isValidId(id)) throw new Error('refusing to build a path from a non-UUID id');
  return path.join(BLOB_DIR, `${id}.tdf`);
}

let index = null;

/** Serialises index writes: one Node process, but overlapping requests. */
let queue = Promise.resolve();
function exclusive(fn) {
  const run = queue.then(fn, fn);
  queue = run.then(
    () => undefined,
    () => undefined,
  );
  return run;
}

export async function init() {
  await fs.mkdir(BLOB_DIR, { recursive: true });
  try {
    const raw = await fs.readFile(INDEX_PATH, 'utf8');
    const parsed = JSON.parse(raw);
    index = Array.isArray(parsed?.files) ? parsed.files : [];
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
    index = [];
    await persist();
  }
  // Fail loudly at startup rather than on the first upload.
  const probe = path.join(DATA_DIR, '.writable');
  await fs.writeFile(probe, 'ok');
  await fs.unlink(probe);
  return { files: index.length, dataDir: DATA_DIR };
}

/** Write to a temp file in the same directory, then rename over the target. */
async function persist() {
  const tmp = path.join(DATA_DIR, `.index.${randomUUID()}.tmp`);
  await fs.writeFile(tmp, JSON.stringify({ version: 1, files: index }, null, 2));
  await fs.rename(tmp, INDEX_PATH);
}

export function list() {
  return index.map((f) => ({ ...f }));
}

export function get(id) {
  if (!isValidId(id)) return null;
  return index.find((f) => f.id === id) ?? null;
}

export function usageFor(sub) {
  const mine = index.filter((f) => f.uploaderSub === sub);
  return { files: mine.length, bytes: mine.reduce((n, f) => n + f.size, 0) };
}

export async function readBlob(id) {
  return fs.readFile(blobPath(id));
}

export async function add({ bytes, filename, principal, inspected }) {
  return exclusive(async () => {
    const used = usageFor(principal.sub);
    if (used.files >= LIMITS.maxFilesPerUser) {
      const e = new Error(
        `quota: you already have ${used.files} files, the limit is ${LIMITS.maxFilesPerUser}. Delete something first.`,
      );
      e.status = 409;
      throw e;
    }
    if (used.bytes + bytes.length > LIMITS.maxBytesPerUser) {
      const e = new Error(
        `quota: this upload would put you at ${used.bytes + bytes.length} bytes, the limit is ${LIMITS.maxBytesPerUser}.`,
      );
      e.status = 409;
      throw e;
    }

    const id = randomUUID();
    const record = {
      id,
      filename,
      size: bytes.length,
      attributes: inspected.attributes,
      kasUrls: inspected.kasUrls,
      schemaVersion: inspected.schemaVersion,
      mimeType: inspected.mimeType,
      payloadSize: inspected.payloadSize,
      uploader: principal.username,
      uploaderSub: principal.sub,
      uploadedAt: new Date().toISOString(),
    };

    // Blob first: an index entry pointing at a missing blob is worse than an
    // orphan blob, which is invisible and reclaimable.
    await fs.writeFile(blobPath(id), bytes, { flag: 'wx' });
    index.push(record);
    try {
      await persist();
    } catch (err) {
      index.pop();
      await fs.unlink(blobPath(id)).catch(() => undefined);
      throw err;
    }
    return record;
  });
}

export async function remove(id, principal) {
  return exclusive(async () => {
    const i = index.findIndex((f) => f.id === id);
    if (i === -1) {
      const e = new Error('no such file');
      e.status = 404;
      throw e;
    }
    // Compare the immutable subject, never the display name: two accounts can
    // share a preferred_username over a realm's lifetime, a sub cannot.
    if (index[i].uploaderSub !== principal.sub) {
      const e = new Error('only the uploader can delete a file');
      e.status = 403;
      throw e;
    }
    const [removed] = index.splice(i, 1);
    try {
      await persist();
    } catch (err) {
      index.splice(i, 0, removed);
      throw err;
    }
    await fs.unlink(blobPath(id)).catch(() => undefined);
    return removed;
  });
}
