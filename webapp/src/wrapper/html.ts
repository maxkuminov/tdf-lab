/**
 * HTML-wrapped TDF: generator and reader.
 *
 * There is no SDK support to lean on here. `@opentdf/sdk` 0.20.0 still ships
 * `unwrapHtml()` on the legacy tdf3 read path — it pulls a base64 payload out
 * of `<input id="data-input" value="…">` — but every WRITE entry point for the
 * format was removed: `EncryptParamsBuilder.setHtmlFormat()` and
 * `withHtmlFormat()` throw `ConfigurationError('HTML format is not supported')`,
 * and `Client.encrypt()` throws `'html mode not supported'` when `asHtml` is
 * set. The modern `OpenTDF` class this console uses does not unwrap HTML on
 * read either — only the legacy `tdf3` client does. So we generate the wrapper
 * ourselves, and we deliberately use the SAME `data-input` idiom so the file
 * we emit stays readable by that legacy path.
 *
 * THE INJECTION RULE, which the whole design hangs on:
 *
 *   Every attacker-influenced string — the filename, the attribute FQNs, the
 *   uploader, anything derived from a manifest — is either read at runtime out
 *   of the embedded TDF, or carried in as BASE64. Nothing but base64 is ever
 *   substituted into the HTML source. Base64 has no `<`, `"`, `'` or `&`, and
 *   both substitutions are validated against a strict charset before they are
 *   written, so a `.tdf` with a hostile filename or a hostile attribute value
 *   cannot introduce an element, an attribute or a script into the page.
 *
 * The knock-on benefit is that the inline `<script>` is byte-identical in every
 * page this ever produces, so its SHA-256 is a stable CSP hash — which is how
 * `location /sealed/` in nginx pins `script-src` to exactly this runtime.
 */

// The GENERATED template: markup + CSS + the whole runtime, bundled by
// `npm run build:wrapper` before every app build. Never edit it; edit
// `page.template.html` and `sealed-page.ts`.
import template from './generated/page.html?raw';
import { APP_ORIGIN } from '../config';

/** Placeholders in `page.html`. Both sit inside a double-quoted attribute. */
const TDF_SLOT = '__TDF_B64__';
const META_SLOT = '__META_B64__';

/**
 * Base64 above this and the browser starts to struggle: the wrapper inflates
 * the payload by 4/3 and the whole thing has to be held as one string, then as
 * one Blob, then written to disk. 8 MB of .tdf is ~11 MB of HTML, which is
 * comfortable; 20 MB is not.
 */
export const MAX_HTML_WRAP_BYTES = 8 * 1024 * 1024;

const B64_ONLY = /^[A-Za-z0-9+/]*={0,2}$/;

/**
 * Characters that make a filename LIE about itself when it is displayed.
 *
 * C0/C1 controls, the bidi overrides and isolates (U+061C, U+200E-200F,
 * U+202A-202E, U+2066-2069), the zero-width space/joiners and the BOM. The
 * classic use is U+202E RIGHT-TO-LEFT OVERRIDE, which renders
 * `invoice\u202Elmth.fdt.pdf` as something ending in `.pdf` while the file is
 * really `.tdf.html`. That trick is worth exactly nothing against the injection
 * boundary here - a filename never reaches markup - but it is worth a great
 * deal against a human deciding whether to open an executable document, which
 * is what this feature hands out.
 */
const SPOOFING_CHARS = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g;

export class WrapperError extends Error {
  override name = 'WrapperError';
}

function bytesToBase64(bytes: Uint8Array): string {
  // Chunked: String.fromCharCode.apply on a multi-megabyte array blows the
  // argument limit and throws RangeError rather than returning a wrong answer,
  // but only on some engines — so never rely on it.
  let binary = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

function utf8ToBase64(text: string): string {
  return bytesToBase64(new TextEncoder().encode(text));
}

/**
 * The only sanitising the filename gets, and it is for display and for the
 * `download` attribute of a save — NOT for safety. Safety comes from the fact
 * that this string never reaches the HTML source at all: it travels as base64
 * and is written with `textContent` / `.value` at runtime.
 */
function displayName(name: string): string {
  // Display-spoofing hygiene, not the injection boundary - see the header
  // comment for why those are different problems. NFC after stripping, so a
  // decomposed lookalike normalises to one form.
  let stripped = (name || 'sealed.tdf').replace(SPOOFING_CHARS, '');
  stripped = stripped.normalize ? stripped.normalize('NFC') : stripped;
  const base = stripped.split(/[\\/]/).pop() ?? '';
  return base.trim().slice(0, 180) || 'sealed.tdf';
}

export type SealedHtmlOptions = {
  /** The sealed .tdf bytes, exactly as they would be written to disk. */
  tdf: Uint8Array;
  /** Display name, e.g. `notes.txt.tdf`. Attacker-influenced; treated as such. */
  filename: string;
  /** Origin of the console that can actually open this. Defaults to APP_ORIGIN. */
  consoleOrigin?: string;
  /** Overridable for deterministic tests. */
  now?: Date;
};

/** Filename the wrapper should be saved under. */
export function sealedHtmlName(filename: string): string {
  return `${displayName(filename)}.html`;
}

/**
 * Builds the single self-contained page.
 *
 * Throws rather than emitting anything questionable: if either substitution is
 * not pure base64, that is a bug in this function and the right move is to fail
 * loudly, not to ship a page whose safety argument no longer holds.
 */
export function buildSealedHtml(opts: SealedHtmlOptions): string {
  const { tdf } = opts;
  if (!tdf || tdf.byteLength === 0) throw new WrapperError('there are no bytes to wrap');
  if (tdf.byteLength > MAX_HTML_WRAP_BYTES) {
    throw new WrapperError(
      `this file is ${tdf.byteLength} bytes; the HTML wrapper is capped at ${MAX_HTML_WRAP_BYTES} because base64 inflates it by a third`,
    );
  }
  const origin = opts.consoleOrigin ?? APP_ORIGIN;
  if (!/^https:\/\/[a-z0-9.-]+(:[0-9]+)?$/i.test(origin)) {
    throw new WrapperError(`refusing to bake a non-https console origin into the wrapper: ${origin}`);
  }

  const tdfB64 = bytesToBase64(tdf);
  const metaB64 = utf8ToBase64(
    JSON.stringify({
      v: 1,
      filename: displayName(opts.filename),
      origin,
      createdAt: (opts.now ?? new Date()).toISOString(),
    }),
  );

  if (!B64_ONLY.test(tdfB64) || !B64_ONLY.test(metaB64)) {
    throw new WrapperError('internal: a substitution was not pure base64');
  }
  if (!template.includes(TDF_SLOT) || !template.includes(META_SLOT)) {
    throw new WrapperError('internal: the page template lost one of its slots');
  }

  // Replacer FUNCTIONS, so a `$` sequence in a substitution can never be
  // interpreted as a replacement pattern. Base64 cannot contain `$`, so this is
  // belt and braces here - but the same call with a string replacement is what
  // silently corrupted the generated template, so the idiom is worth keeping
  // consistent.
  return template.replace(TDF_SLOT, () => tdfB64).replace(META_SLOT, () => metaB64);
}

/**
 * The exact regex `@opentdf/sdk`'s `tdf3/src/utils/unwrap.ts` uses, copied so
 * the console can read back what it wrote (and so a test can prove the format
 * we emit is the one the SDK's legacy reader still accepts). Deliberately not
 * imported: the package's `exports` map does not expose that deep path.
 */
const SDK_PAYLOAD_RE =
  /<input\s+[^>]*id=(?:['"]?)data-input(?:['"]?)[^>]*value=(?:['"]?)([a-zA-Z0-9+/=\-_]+)(?:['"]?)/;

const META_RE = /<input\s+[^>]*id=(?:['"]?)meta-input(?:['"]?)[^>]*value=(?:['"]?)([a-zA-Z0-9+/=]+)(?:['"]?)/;

/** Cheap sniff: is this an HTML document rather than a zip? */
export function looksLikeSealedHtml(bytes: Uint8Array): boolean {
  if (bytes.byteLength < 4) return false;
  // A .tdf is a zip and starts `PK\x03\x04`. Anything that does not, and that
  // contains our data-input, is worth trying to unwrap.
  if (bytes[0] === 0x50 && bytes[1] === 0x4b) return false;
  const head = new TextDecoder('utf-8', { fatal: false }).decode(bytes.subarray(0, 4096)).toLowerCase();
  return head.includes('<html') || head.includes('<!doctype html');
}

export type UnwrappedHtml = { bytes: Uint8Array; filename: string | null };

/**
 * Ceiling on the payload `extractSealedTdf` will decode out of a page.
 *
 * The generator caps a wrapper at 8 MB of .tdf. This is the READ side, where
 * the file came from somebody else: without a ceiling, a hand-built .html with
 * a 900 MB base64 blob turns one drag-and-drop into an allocation of roughly
 * three times that (the string, the binary string, the array) before anything
 * has been parsed. Checked against the base64 LENGTH, before `atob`.
 */
export const MAX_EXTRACT_BYTES = 24 * 1024 * 1024;

/**
 * Pulls the sealed .tdf back out of a wrapper page. Used when someone drops a
 * generated `.html` onto Decrypt or the library publisher instead of a `.tdf`.
 */
export function extractSealedTdf(bytes: Uint8Array): UnwrappedHtml {
  const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
  const m = SDK_PAYLOAD_RE.exec(text);
  if (!m) {
    throw new WrapperError(
      'This is an HTML file, but it carries no sealed payload: there is no data-input element in it.',
    );
  }
  // Length first, decode second: the point of the cap is to not allocate.
  if ((m[1].length * 3) / 4 > MAX_EXTRACT_BYTES) {
    throw new WrapperError(
      `the payload embedded in this page is larger than this console will decode (cap ${MAX_EXTRACT_BYTES} bytes)`,
    );
  }
  let payload: Uint8Array;
  try {
    payload = base64ToBytes(m[1].replace(/-/g, '+').replace(/_/g, '/'));
  } catch (err) {
    throw new WrapperError(`the embedded payload is not valid base64: ${(err as Error).message}`);
  }
  let filename: string | null = null;
  const mm = META_RE.exec(text);
  if (mm) {
    try {
      const meta = JSON.parse(new TextDecoder().decode(base64ToBytes(mm[1]))) as { filename?: unknown };
      if (typeof meta.filename === 'string') filename = displayName(meta.filename);
    } catch {
      /* metadata is a convenience; the payload is the thing that matters */
    }
  }
  return { bytes: payload, filename };
}

/**
 * Give the caller a `.tdf` no matter which of the two they were handed. Used at
 * every drop target so an HTML wrapper is simply accepted.
 */
export function unwrapIfHtml(bytes: Uint8Array, filename: string): { bytes: Uint8Array; filename: string } {
  if (!looksLikeSealedHtml(bytes)) return { bytes, filename };
  const out = extractSealedTdf(bytes);
  return { bytes: out.bytes, filename: out.filename ?? filename.replace(/\.html?$/i, '') };
}

/** The inline runtime, exactly as it is emitted. Only used to compute its hash. */
export function sealedRuntimeScript(): string {
  const m = /<script>([\s\S]*?)<\/script>/.exec(template);
  if (!m) throw new WrapperError('internal: the page template has no inline script');
  return m[1];
}
