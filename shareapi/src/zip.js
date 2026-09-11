/**
 * ZIP64-aware central-directory reader — the Node port of webapp/src/zip.ts.
 *
 * It has to be ZIP64-aware because the OpenTDF writers ALWAYS emit ZIP64
 * records at any file size, with 0xffffffff size sentinels in every local file
 * header and the real values in the 0x0001 extra field of the central
 * directory. A reader that trusts the local header sees a valid .tdf as two
 * empty entries and would reject every genuine upload.
 */

const SIG_EOCD = 0x06054b50;
const SIG_ZIP64_LOCATOR = 0x07064b50;
const SIG_ZIP64_EOCD = 0x06064b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_LOCAL = 0x04034b50;
const U32_MAX = 0xffffffff;
const U16_MAX = 0xffff;

export class ZipFormatError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ZipFormatError';
  }
}

function u64(dv, off) {
  const v = dv.getBigUint64(off, true);
  if (v > BigInt(Number.MAX_SAFE_INTEGER)) throw new ZipFormatError('entry size out of range');
  return Number(v);
}

function findEocd(buf, dv) {
  const floor = Math.max(0, dv.byteLength - 22 - 0xffff);
  for (let i = dv.byteLength - 22; i >= floor; i--) {
    if (dv.getUint32(i, true) === SIG_EOCD) return i;
  }
  const looksLikeZip =
    buf.length >= 4 && buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04;
  throw new ZipFormatError(
    looksLikeZip
      ? 'archive is incomplete or truncated: no central directory at the end of the file'
      : 'not a zip archive, so it cannot be a .tdf',
  );
}

export function readZipDirectory(buf) {
  if (buf.length < 22) throw new ZipFormatError('file is too small to be a zip archive');
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const eocd = findEocd(buf, dv);

  let entryCount = dv.getUint16(eocd + 10, true);
  let cdOffset = dv.getUint32(eocd + 16, true);

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

  if (entryCount > 64) throw new ZipFormatError('too many entries for a .tdf');

  const entries = [];
  let p = cdOffset;
  for (let i = 0; i < entryCount; i++) {
    if (p + 46 > dv.byteLength || dv.getUint32(p, true) !== SIG_CENTRAL) {
      throw new ZipFormatError(`central directory record ${i + 1} is malformed`);
    }
    const compressionMethod = dv.getUint16(p + 10, true);
    let compressedSize = dv.getUint32(p + 20, true);
    let uncompressedSize = dv.getUint32(p + 24, true);
    const nameLen = dv.getUint16(p + 28, true);
    const extraLen = dv.getUint16(p + 30, true);
    const commentLen = dv.getUint16(p + 32, true);
    let localHeaderOffset = dv.getUint32(p + 42, true);
    const name = buf.subarray(p + 46, p + 46 + nameLen).toString('utf8');

    let e = p + 46 + nameLen;
    const extraEnd = e + extraLen;
    while (e + 4 <= extraEnd) {
      const id = dv.getUint16(e, true);
      const size = dv.getUint16(e + 2, true);
      if (id === 0x0001) {
        let f = e + 4;
        if (uncompressedSize === U32_MAX) { uncompressedSize = u64(dv, f); f += 8; }
        if (compressedSize === U32_MAX) { compressedSize = u64(dv, f); f += 8; }
        if (localHeaderOffset === U32_MAX) { localHeaderOffset = u64(dv, f); f += 8; }
        break;
      }
      e += 4 + size;
    }
    // Only STORED (method 0) is accepted for a .tdf, and a stored entry cannot
    // compress, so its two size fields MUST agree. Rejecting a mismatch here is
    // what stops a lying central-directory record: a record that declares
    // uncompressedSize=1 while the payload on disk is 2 MB would otherwise slip
    // past a size check keyed on the declared value and then extract 2 MB.
    if (compressionMethod === 0 && compressedSize !== uncompressedSize) {
      throw new ZipFormatError(
        `"${name}" is stored but its compressed (${compressedSize}) and uncompressed (${uncompressedSize}) sizes disagree`,
      );
    }
    if (localHeaderOffset < 0 || localHeaderOffset + 30 > buf.length) {
      throw new ZipFormatError(`"${name}" has a local header offset outside the file`);
    }
    entries.push({ name, compressionMethod, compressedSize, uncompressedSize, localHeaderOffset });
    p = extraEnd + commentLen;
  }
  return entries;
}

/**
 * @param buf      the whole archive
 * @param entry    a directory record from readZipDirectory
 * @param maxBytes hard ceiling on the bytes this call will return, checked
 *                 against the ACTUAL slice length, never a declared field
 */
export function readZipEntry(buf, entry, maxBytes = Infinity) {
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const lo = entry.localHeaderOffset;
  if (lo + 30 > dv.byteLength || dv.getUint32(lo, true) !== SIG_LOCAL) {
    throw new ZipFormatError(`local header for "${entry.name}" is missing or corrupt`);
  }
  if (entry.compressionMethod !== 0) {
    throw new ZipFormatError(`"${entry.name}" uses compression method ${entry.compressionMethod}, not STORED`);
  }
  const start = lo + 30 + dv.getUint16(lo + 26, true) + dv.getUint16(lo + 28, true);
  const end = start + entry.compressedSize;
  if (start < 0 || end > buf.length) {
    throw new ZipFormatError(`"${entry.name}" runs past the end of the file`);
  }
  // The ACTUAL number of bytes, not a claim in the header.
  if (end - start > maxBytes) {
    throw new ZipFormatError(`"${entry.name}" is ${end - start} bytes, over the ${maxBytes}-byte limit`);
  }
  return buf.subarray(start, end);
}
