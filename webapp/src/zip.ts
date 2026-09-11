/**
 * A minimal, ZIP64-aware reader, written for one specific job: opening a .tdf
 * without pulling in a general zip library.
 *
 * It has to be ZIP64-aware because the OpenTDF writers ALWAYS emit ZIP64
 * records, at any file size - `ZipWriter` sets `this.zip64 = true`
 * unconditionally and writes 0xffffffff size sentinels into every local file
 * header, with the real values living in the 0x0001 extra field of the central
 * directory. A reader that trusts the local header sees two zero-length
 * entries and reports a valid file as empty.
 *
 * Entries are also always STORED (compression method 0) in a TDF, but method 8
 * is handled too so a .tdf repacked by another tool still opens.
 */

export type ZipEntry = {
  name: string;
  compressionMethod: number;
  crc32: number;
  compressedSize: number;
  uncompressedSize: number;
  localHeaderOffset: number;
};

const SIG_EOCD = 0x06054b50;
const SIG_ZIP64_LOCATOR = 0x07064b50;
const SIG_ZIP64_EOCD = 0x06064b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_LOCAL = 0x04034b50;

const U32_MAX = 0xffffffff;
const U16_MAX = 0xffff;

export class ZipFormatError extends Error {
  override name = 'ZipFormatError';
}

function view(buf: Uint8Array): DataView {
  return new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
}

function u64(dv: DataView, off: number): number {
  const value = dv.getBigUint64(off, true);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new ZipFormatError('entry is larger than this browser can address');
  }
  return Number(value);
}

/**
 * Scans backwards for the end-of-central-directory record.
 *
 * A zip's index lives at the END of the file, so a download that stopped early
 * looks exactly like a non-zip to a naive check. Distinguish the two: a leading
 * local-file-header signature means this really is a zip whose tail is missing.
 */
function findEocd(buf: Uint8Array, dv: DataView): number {
  // 22-byte record + up to 65535 bytes of trailing comment.
  const floor = Math.max(0, dv.byteLength - 22 - 0xffff);
  for (let i = dv.byteLength - 22; i >= floor; i--) {
    if (dv.getUint32(i, true) === SIG_EOCD) return i;
  }
  const looksLikeZip =
    buf.byteLength >= 4 && buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04;
  throw new ZipFormatError(
    looksLikeZip
      ? 'This archive is incomplete or truncated: it starts like a zip but its central directory, which lives at the end of the file, is missing. Re-download the .tdf.'
      : 'This is not a zip archive, so it cannot be a .tdf. A .tdf is a zip holding 0.manifest.json and 0.payload.',
  );
}

/** Reads the central directory, resolving ZIP64 overrides. */
export function readZipDirectory(buf: Uint8Array): ZipEntry[] {
  const dv = view(buf);
  const eocd = findEocd(buf, dv);

  let entryCount = dv.getUint16(eocd + 10, true);
  let cdOffset = dv.getUint32(eocd + 16, true);

  // A ZIP64 locator sits immediately before the EOCD when the archive uses
  // ZIP64. Trusting the 32-bit EOCD fields alone is what breaks on TDFs.
  const locator = eocd - 20;
  if (locator >= 0 && dv.getUint32(locator, true) === SIG_ZIP64_LOCATOR) {
    const z64 = u64(dv, locator + 8);
    if (z64 >= 0 && z64 + 56 <= dv.byteLength && dv.getUint32(z64, true) === SIG_ZIP64_EOCD) {
      entryCount = u64(dv, z64 + 32);
      cdOffset = u64(dv, z64 + 48);
    }
  } else if (entryCount === U16_MAX || cdOffset === U32_MAX) {
    throw new ZipFormatError('archive claims ZIP64 but carries no ZIP64 locator');
  }

  const entries: ZipEntry[] = [];
  let p = cdOffset;
  for (let i = 0; i < entryCount; i++) {
    if (p + 46 > dv.byteLength || dv.getUint32(p, true) !== SIG_CENTRAL) {
      throw new ZipFormatError(`central directory record ${i + 1} is malformed`);
    }
    const compressionMethod = dv.getUint16(p + 10, true);
    const crc32 = dv.getUint32(p + 16, true);
    let compressedSize = dv.getUint32(p + 20, true);
    let uncompressedSize = dv.getUint32(p + 24, true);
    const nameLen = dv.getUint16(p + 28, true);
    const extraLen = dv.getUint16(p + 30, true);
    const commentLen = dv.getUint16(p + 32, true);
    let localHeaderOffset = dv.getUint32(p + 42, true);
    const name = new TextDecoder().decode(buf.subarray(p + 46, p + 46 + nameLen));

    // ZIP64 extended information: only the fields that were sentinelled are
    // present, in this fixed order.
    let e = p + 46 + nameLen;
    const extraEnd = e + extraLen;
    while (e + 4 <= extraEnd) {
      const headerId = dv.getUint16(e, true);
      const dataSize = dv.getUint16(e + 2, true);
      if (headerId === 0x0001) {
        let f = e + 4;
        if (uncompressedSize === U32_MAX) { uncompressedSize = u64(dv, f); f += 8; }
        if (compressedSize === U32_MAX) { compressedSize = u64(dv, f); f += 8; }
        if (localHeaderOffset === U32_MAX) { localHeaderOffset = u64(dv, f); f += 8; }
        break;
      }
      e += 4 + dataSize;
    }

    entries.push({ name, compressionMethod, crc32, compressedSize, uncompressedSize, localHeaderOffset });
    p = extraEnd + commentLen;
  }
  return entries;
}

/**
 * Ceiling on a single extracted entry, in bytes.
 *
 * STORED entries cost nothing to bound - the compressed length IS the length.
 * DEFLATED ones are the problem: a few hundred bytes of a well-chosen stream
 * inflates to gigabytes, and a `.tdf` is exactly the kind of file a stranger
 * hands you. `DecompressionStream` has no size limit of its own, so the limit
 * has to be enforced WHILE inflating - checking afterwards means the allocation
 * already happened, which is the whole attack.
 *
 * The share API refuses non-STORED members outright and validates declared
 * sizes against actual bytes; this is the same intent on the client side, where
 * a file can arrive by drag-and-drop without ever touching that server.
 */
export const MAX_ENTRY_BYTES = 24 * 1024 * 1024;

/**
 * Returns the raw bytes of one entry, inflating it if it was deflated.
 *
 * @param maxBytes refuse an entry that claims, or turns out, to be bigger.
 */
export async function readZipEntry(
  buf: Uint8Array,
  entry: ZipEntry,
  maxBytes: number = MAX_ENTRY_BYTES,
): Promise<Uint8Array> {
  const dv = view(buf);
  const lo = entry.localHeaderOffset;
  if (lo + 30 > dv.byteLength || dv.getUint32(lo, true) !== SIG_LOCAL) {
    throw new ZipFormatError(`local header for "${entry.name}" is missing or corrupt`);
  }
  // Sizes in the local header are sentinels for a TDF - always take the
  // central directory's word for them.
  const start = lo + 30 + dv.getUint16(lo + 26, true) + dv.getUint16(lo + 28, true);
  const end = start + entry.compressedSize;
  if (end > buf.byteLength) {
    throw new ZipFormatError(`"${entry.name}" runs past the end of the file: the archive is truncated`);
  }
  const raw = buf.subarray(start, end);

  // The declared size is a claim, so it is checked first (cheap) and the real
  // output is checked again as it arrives (correct).
  if (entry.uncompressedSize > maxBytes) {
    throw new ZipFormatError(
      `"${entry.name}" declares ${entry.uncompressedSize} bytes, over this console's ${maxBytes}-byte limit for a single member`,
    );
  }
  if (entry.compressionMethod === 0) {
    if (raw.byteLength > maxBytes) {
      throw new ZipFormatError(`"${entry.name}" is over this console's ${maxBytes}-byte limit for a single member`);
    }
    return raw;
  }
  if (entry.compressionMethod === 8) {
    const ds = new DecompressionStream('deflate-raw');
    // Count as it inflates and abort the stream the moment the cap is passed.
    // Reading to completion and measuring afterwards would have already done
    // the damage a zip bomb is for.
    let seen = 0;
    const guard = new TransformStream<Uint8Array, Uint8Array>({
      transform(chunk, controller) {
        seen += chunk.byteLength;
        if (seen > maxBytes) {
          throw new ZipFormatError(
            `"${entry.name}" expands past this console's ${maxBytes}-byte limit for a single member — refusing to keep inflating it`,
          );
        }
        controller.enqueue(chunk);
      },
    });
    const stream = new Blob([raw as BlobPart]).stream().pipeThrough(ds).pipeThrough(guard);
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }
  throw new ZipFormatError(`"${entry.name}" uses compression method ${entry.compressionMethod}, which this console cannot read`);
}
