/**
 * Client for the shared library API.
 *
 * Everything here is same-origin: nginx proxies /api/ to tdf-share-api inside
 * the isolated lab network, so there is no preflight, no CORS configuration
 * and no cross-origin surface. The bearer token is the same Keycloak access
 * token the platform sees.
 *
 * Note what never crosses this boundary: plaintext, keys, passwords. The
 * browser seals a file before it is uploaded and opens it after it is
 * downloaded, so the server holds ciphertext and metadata and nothing else.
 */

export type LibraryFile = {
  id: string;
  filename: string;
  size: number;
  attributes: string[];
  uploader: string;
  uploadedAt: string;
  mimeType: string | null;
  schemaVersion: string | null;
  /** true when the signed-in user uploaded it (compared by token subject). */
  mine: boolean;
};

export type LibraryUsage = { files: number; bytes: number };
export type LibraryLimits = {
  maxFileBytes: number;
  maxFilesPerUser: number;
  maxBytesPerUser: number;
};

export type LibraryListing = {
  files: LibraryFile[];
  usage: LibraryUsage;
  limits: LibraryLimits;
};

export class ShareApiError extends Error {
  override name = 'ShareApiError';
  constructor(
    message: string,
    readonly status: number,
    readonly code?: string,
  ) {
    super(message);
  }
}

async function failure(res: Response): Promise<ShareApiError> {
  let detail = res.statusText;
  let code: string | undefined;
  try {
    const body = (await res.json()) as { error?: string; detail?: string };
    code = body.error;
    detail = body.detail ?? body.error ?? detail;
  } catch {
    /* a non-JSON error body (nginx's own 413 page, say) */
  }
  return new ShareApiError(detail, res.status, code);
}

export type TokenSource = () => Promise<string>;

/**
 * Empty in the browser: /api/ is same-origin, which is the whole point of the
 * nginx proxy. The verification harness runs under Node, where `fetch` has no
 * document to resolve a relative URL against, so it sets an absolute base.
 * Nothing in the shipped app ever calls this.
 */
let apiBase = '';
export function setApiBase(base: string): void {
  apiBase = base.replace(/\/+$/, '');
}
const api = (path: string) => `${apiBase}${path}`;

async function authHeaders(getToken: TokenSource): Promise<HeadersInit> {
  return { Authorization: `Bearer ${await getToken()}` };
}

export async function listFiles(getToken: TokenSource): Promise<LibraryListing> {
  const res = await fetch(api('/api/files'), { headers: await authHeaders(getToken) });
  if (!res.ok) throw await failure(res);
  return (await res.json()) as LibraryListing;
}

export async function uploadFile(
  getToken: TokenSource,
  bytes: Uint8Array,
  filename: string,
): Promise<LibraryFile> {
  const res = await fetch(api('/api/files'), {
    method: 'POST',
    headers: {
      ...(await authHeaders(getToken)),
      'Content-Type': 'application/octet-stream',
      // Display only. The server sanitises it and stores the blob under a
      // UUID it generates itself, so this can never name anything on disk.
      'X-Filename': filename.replace(/[^\x20-\x7e]/g, '_'),
    },
    body: bytes as BodyInit,
  });
  if (!res.ok) throw await failure(res);
  return (await res.json()) as LibraryFile;
}

/**
 * Publish bytes that are ALREADY a sealed .tdf, untouched — the "publish as-is"
 * path when someone drops a `.tdf` into the picker. Identical wire call to
 * uploadFile; separate so the intent reads clearly at the call site and the
 * display name is not given a second `.tdf`.
 */
export async function uploadSealed(
  getToken: TokenSource,
  bytes: Uint8Array,
  filename: string,
): Promise<LibraryFile> {
  const name = /\.tdf$/i.test(filename) ? filename : `${filename}.tdf`;
  return uploadFile(getToken, bytes, name);
}

export async function downloadFile(getToken: TokenSource, id: string): Promise<Uint8Array> {
  const res = await fetch(api(`/api/files/${encodeURIComponent(id)}`), {
    headers: await authHeaders(getToken),
  });
  if (!res.ok) throw await failure(res);
  return new Uint8Array(await res.arrayBuffer());
}

export async function deleteFile(getToken: TokenSource, id: string): Promise<void> {
  const res = await fetch(api(`/api/files/${encodeURIComponent(id)}`), {
    method: 'DELETE',
    headers: await authHeaders(getToken),
  });
  if (!res.ok) throw await failure(res);
}

/**
 * What we can honestly say about a file before trying to open it.
 *
 * The user's entitlements are NOT in their token — the platform resolves them
 * from Keycloak at decision time — and `GetEntitlements` is refused to
 * role:standard users, so the browser genuinely cannot know the answer in
 * advance. Rather than invent a prediction, the library learns from real
 * outcomes. `open` is the only thing that ever produces a fact.
 *
 * IMPORTANT subtleties this model gets right, and a naive one gets wrong:
 *
 *  - **ANY_OF over-generalisation.** A granted open on a file bound to
 *    {A, B} proves only that AT LEAST ONE of A or B passed, not both. So an
 *    observation is keyed on the file's WHOLE canonical attribute set, never
 *    on individual values. Another file bound to exactly {A, B} is genuinely
 *    predictable; a file bound to {A} or {A, C} is not, and stays `unknown`.
 *  - **Staleness.** Entitlements change server-side, so a later outcome for a
 *    set REPLACES the earlier one (a Map, last write wins) instead of a grant
 *    lingering forever and overriding a subsequent denial.
 *  - **Fact vs inference.** A verdict on a file you actually opened is a
 *    recorded fact for THAT file; the same verdict shown on a different file
 *    with an identical set is only an inference. Both are past observations,
 *    never a promise about the next rewrap.
 */
export type AccessGuess =
  | 'open-to-all'
  | 'opened' // you opened THIS file: granted (a fact)
  | 'refused' // you opened THIS file: denied (a fact)
  | 'likely-yes' // a DIFFERENT file with the same attribute set opened
  | 'likely-no' // a different file with the same attribute set was refused
  | 'unknown';

/** Canonical key for an attribute set: order-independent, ANY_OF-safe. */
export function attributeSetKey(attributes: string[]): string {
  return [...new Set(attributes)].sort().join('\n');
}

export type Observation = { outcome: 'granted' | 'denied'; fileId: string };
/** attributeSetKey → the most recent outcome seen for that exact set. */
export type Observations = ReadonlyMap<string, Observation>;

export function guessAccess(
  file: { id: string; attributes: string[] },
  observations: Observations,
): AccessGuess {
  if (file.attributes.length === 0) return 'open-to-all';
  const seen = observations.get(attributeSetKey(file.attributes));
  if (!seen) return 'unknown';
  if (seen.fileId === file.id) return seen.outcome === 'granted' ? 'opened' : 'refused';
  return seen.outcome === 'granted' ? 'likely-yes' : 'likely-no';
}

export function formatWhen(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : d.toLocaleString();
}
