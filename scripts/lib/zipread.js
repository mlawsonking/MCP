// A minimal ZIP reader, so the rules pipeline can pull entries out of OSV's exports without taking
// a dependency on anything.
//
// It exists because the npm export is 213 MB holding a couple of hundred thousand advisories and we
// want the few thousand malicious-package ones. Extracting the whole archive to disk to then delete
// almost all of it is slow on every platform and painful on Windows. Reading the central directory
// and inflating only the matching entries takes seconds.
//
// It handles ZIP64, which is not optional here: an archive with more than 65,535 entries records
// its real entry count and central-directory offset in the ZIP64 records, and the classic
// end-of-central-directory fields hold 0xffff/0xffffffff placeholders. A reader that trusts the
// classic fields reads a handful of entries out of that archive and reports success.

const fs = require('fs');
const zlib = require('zlib');

const EOCD_SIG = 0x06054b50;
const ZIP64_EOCD_LOCATOR_SIG = 0x07064b50;
const ZIP64_EOCD_SIG = 0x06064b50;
const CENTRAL_SIG = 0x02014b50;
const LOCAL_SIG = 0x04034b50;

function findEocd(buf) {
  // The record is at the very end unless there is an archive comment, which is at most 64 KB.
  const start = Math.max(0, buf.length - 66560);
  for (let i = buf.length - 22; i >= start; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) return i;
  }
  return -1;
}

// Returns { entries, centralOffset, centralSize }.
function readDirectoryLocation(buf) {
  const eocd = findEocd(buf);
  if (eocd === -1) throw new Error('not a zip file: no end-of-central-directory record');

  let entries = buf.readUInt16LE(eocd + 10);
  let centralSize = buf.readUInt32LE(eocd + 12);
  let centralOffset = buf.readUInt32LE(eocd + 16);

  // A placeholder in any of the three means the real values live in the ZIP64 record.
  const needsZip64 = entries === 0xffff || centralSize === 0xffffffff || centralOffset === 0xffffffff;
  if (!needsZip64) return { entries, centralOffset, centralSize };

  const locator = eocd - 20;
  if (locator < 0 || buf.readUInt32LE(locator) !== ZIP64_EOCD_LOCATOR_SIG) {
    throw new Error('zip needs ZIP64 but has no ZIP64 locator');
  }
  const z64 = Number(buf.readBigUInt64LE(locator + 8));
  if (buf.readUInt32LE(z64) !== ZIP64_EOCD_SIG) throw new Error('ZIP64 locator points at something else');
  entries = Number(buf.readBigUInt64LE(z64 + 32));
  centralSize = Number(buf.readBigUInt64LE(z64 + 40));
  centralOffset = Number(buf.readBigUInt64LE(z64 + 48));
  return { entries, centralOffset, centralSize };
}

// A ZIP64 extra field replaces whichever of the sizes and the offset were written as placeholders,
// in that order and only for the ones that were.
function zip64Extra(extra, want) {
  let p = 0;
  while (p + 4 <= extra.length) {
    const id = extra.readUInt16LE(p);
    const size = extra.readUInt16LE(p + 2);
    if (id === 0x0001) {
      const field = extra.slice(p + 4, p + 4 + size);
      const out = {};
      let q = 0;
      for (const name of want) {
        if (q + 8 > field.length) break;
        out[name] = Number(field.readBigUInt64LE(q));
        q += 8;
      }
      return out;
    }
    p += 4 + size;
  }
  return {};
}

// Walk the central directory and yield { name, method, compressedSize, size, localOffset } for
// every entry `filter(name)` accepts.
function listEntries(buf, filter) {
  const { entries, centralOffset } = readDirectoryLocation(buf);
  const out = [];
  let p = centralOffset;
  for (let i = 0; i < entries; i++) {
    if (buf.readUInt32LE(p) !== CENTRAL_SIG) throw new Error(`central directory entry ${i} has a bad signature`);
    const method = buf.readUInt16LE(p + 10);
    let compressedSize = buf.readUInt32LE(p + 20);
    let size = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    let localOffset = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);

    if (size === 0xffffffff || compressedSize === 0xffffffff || localOffset === 0xffffffff) {
      const want = [];
      if (size === 0xffffffff) want.push('size');
      if (compressedSize === 0xffffffff) want.push('compressedSize');
      if (localOffset === 0xffffffff) want.push('localOffset');
      const z = zip64Extra(buf.slice(p + 46 + nameLen, p + 46 + nameLen + extraLen), want);
      if (z.size !== undefined) size = z.size;
      if (z.compressedSize !== undefined) compressedSize = z.compressedSize;
      if (z.localOffset !== undefined) localOffset = z.localOffset;
    }

    if (!filter || filter(name)) out.push({ name, method, compressedSize, size, localOffset });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}

// Pull one entry's bytes out. The local header repeats the name and carries its own extra field,
// whose length usually differs from the central one, so the data offset has to be read from here.
function readEntry(buf, entry) {
  const p = entry.localOffset;
  if (buf.readUInt32LE(p) !== LOCAL_SIG) throw new Error(`local header for ${entry.name} has a bad signature`);
  const nameLen = buf.readUInt16LE(p + 26);
  const extraLen = buf.readUInt16LE(p + 28);
  const start = p + 30 + nameLen + extraLen;
  const raw = buf.slice(start, start + entry.compressedSize);
  if (entry.method === 0) return raw;
  if (entry.method === 8) return zlib.inflateRawSync(raw);
  throw new Error(`${entry.name}: unsupported compression method ${entry.method}`);
}

// The whole job in one call: open a zip and hand back [{ name, text }] for matching entries.
function extract(zipPath, filter) {
  const buf = fs.readFileSync(zipPath);
  return listEntries(buf, filter).map((e) => ({ name: e.name, text: readEntry(buf, e).toString('utf8') }));
}

module.exports = { extract, listEntries, readEntry, readDirectoryLocation };
