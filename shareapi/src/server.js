import express from 'express';
import { requireAuth, authConfig } from './auth.js';
import { inspectTdf, sanitizeFilename, InvalidTdfError } from './tdf.js';
import * as store from './store.js';

/**
 * tdf-share-api - the untrusted half of the lab, on purpose.
 *
 * It stores sealed .tdf files and metadata. It never sees a plaintext byte, a
 * data encryption key, or a password: the browser encrypts before upload and
 * decrypts after download, and the only thing this service can do with a file
 * it holds is hand the same ciphertext back. Reading a file still costs a
 * rewrap against the KAS, which this service has no part in.
 *
 * It is reachable only through the nginx same-origin proxy on lab-net. It has
 * no Traefik router, no published port, and no CORS configuration, because
 * nothing ever calls it cross-origin.
 */

const PORT = Number(process.env.PORT ?? 3000);
const app = express();

app.disable('x-powered-by');
app.set('trust proxy', true);
// Strict routing, so `/files/` is NOT the same resource as `/files`. Without
// it a request for the file whose id is "." normalises to `/files/` on the way
// through and Express answers it with the whole LISTING - a 200 for something
// that is not a file id at all. Found by the verification harness.
app.set('strict routing', true);

// ---------------------------------------------------------------------------
// health - unauthenticated, but only reachable from inside lab-net
// ---------------------------------------------------------------------------
app.get('/healthz', (_req, res) => {
  res.json({ status: 'ok', files: store.list().length });
});

app.get('/config', requireAuth, (_req, res) => {
  res.json({
    issuer: authConfig.ISSUER,
    audience: authConfig.AUDIENCE,
    limits: store.LIMITS,
  });
});

// ---------------------------------------------------------------------------
// listing - every authenticated user sees EVERY file. That is the thesis:
// possession is not access. You can enumerate and download anything here; the
// key server still decides whether you can read it.
// ---------------------------------------------------------------------------
app.get('/files', requireAuth, (req, res) => {
  const files = store.list().map((f) => ({
    id: f.id,
    filename: f.filename,
    size: f.size,
    attributes: f.attributes,
    uploader: f.uploader,
    uploadedAt: f.uploadedAt,
    mimeType: f.mimeType,
    schemaVersion: f.schemaVersion,
    mine: f.uploaderSub === req.principal.sub,
  }));
  files.sort((a, b) => b.uploadedAt.localeCompare(a.uploadedAt));
  res.json({ files, usage: store.usageFor(req.principal.sub), limits: store.LIMITS });
});

// ---------------------------------------------------------------------------
// upload - raw body. No multipart, so there is no parser to confuse and no
// temp-file handling; the client PUTs the bytes it just produced.
// ---------------------------------------------------------------------------
app.post(
  '/files',
  requireAuth,
  express.raw({ type: () => true, limit: store.LIMITS.maxFileBytes }),
  async (req, res) => {
    const bytes = req.body;
    if (!Buffer.isBuffer(bytes) || bytes.length === 0) {
      res.status(400).json({ error: 'empty_body', detail: 'send the .tdf bytes as the request body' });
      return;
    }

    let inspected;
    try {
      // The manifest is the authority on what this file is bound to. Anything
      // the client *says* about attributes is ignored.
      inspected = inspectTdf(bytes);
    } catch (err) {
      if (err instanceof InvalidTdfError) {
        res.status(400).json({ error: 'not_a_tdf', detail: err.message });
        return;
      }
      throw err;
    }

    const filename = sanitizeFilename(req.get('x-filename') ?? 'upload.tdf');
    try {
      const record = await store.add({ bytes, filename, principal: req.principal, inspected });
      res.status(201).json({
        id: record.id,
        filename: record.filename,
        size: record.size,
        attributes: record.attributes,
        uploader: record.uploader,
        uploadedAt: record.uploadedAt,
        mine: true,
      });
    } catch (err) {
      if (err.status) {
        res.status(err.status).json({ error: 'quota_exceeded', detail: err.message });
        return;
      }
      throw err;
    }
  },
);

// ---------------------------------------------------------------------------
// download - available to every authenticated user, for every file
// ---------------------------------------------------------------------------
app.get('/files/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  if (!store.isValidId(id)) {
    res.status(400).json({ error: 'bad_id', detail: 'ids are server-generated UUIDs' });
    return;
  }
  const record = store.get(id);
  if (!record) {
    res.status(404).json({ error: 'not_found' });
    return;
  }
  let bytes;
  try {
    bytes = await store.readBlob(id);
  } catch {
    res.status(410).json({ error: 'blob_missing', detail: 'the index knows this file but its bytes are gone' });
    return;
  }
  res.setHeader('Content-Type', 'application/tdf');
  // The filename is already sanitised to [A-Za-z0-9._-], so it cannot break
  // out of these quotes.
  res.setHeader('Content-Disposition', `attachment; filename="${record.filename}"`);
  res.setHeader('X-Tdf-Attributes', record.attributes.join(' '));
  res.send(bytes);
});

app.delete('/files/:id', requireAuth, async (req, res) => {
  const { id } = req.params;
  if (!store.isValidId(id)) {
    res.status(400).json({ error: 'bad_id', detail: 'ids are server-generated UUIDs' });
    return;
  }
  try {
    const removed = await store.remove(id, req.principal);
    res.json({ deleted: removed.id, filename: removed.filename });
  } catch (err) {
    if (err.status === 404) {
      res.status(404).json({ error: 'not_found' });
      return;
    }
    if (err.status === 403) {
      res.status(403).json({ error: 'not_yours', detail: err.message });
      return;
    }
    throw err;
  }
});

app.use((_req, res) => res.status(404).json({ error: 'no_such_endpoint' }));

// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  // body-parser's own limit error, raised before any route runs
  if (err?.type === 'entity.too.large' || err?.status === 413) {
    res.status(413).json({
      error: 'too_large',
      detail: `files are capped at ${store.LIMITS.maxFileBytes} bytes`,
    });
    return;
  }
  console.error('[tdf-share-api]', err);
  res.status(500).json({ error: 'internal_error' });
});

const state = await store.init();
console.log(
  `[tdf-share-api] listening on :${PORT} | data=${state.dataDir} files=${state.files} | issuer=${authConfig.ISSUER} aud=${authConfig.AUDIENCE} azp=[${authConfig.ALLOWED_AZP}]`,
);
app.listen(PORT, '0.0.0.0');
