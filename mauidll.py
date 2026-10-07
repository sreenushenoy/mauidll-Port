#!/usr/bin/env python3
"""mauidll.py - extract .NET assemblies from a MAUI Android assembly store.

A .NET Android app ships its managed code inside a shared library, normally
``libassemblies.<abi>.blob.so`` (older versions) or ``libassembly-store.so``.
That file is a regular ELF object in which the `.NET assembly store` lives in
a non-loadable ``payload`` section. The store is a sequence of records:

  payload section
    XABA header ......... 20 bytes: magic "XABA", version, entry count,
                          index entry count, index size
    index ................ skipped entirely (its size is in the header)
    descriptors ......... 28 bytes each: mapping index, data offset, data size
    name table ......... one uint32 little-endian length + UTF-8 name per entry
    data ............... the blobs (assemblies), at the offsets above

Each blob is either already a PE/COFF file (MZ ...) or an LZ4-compressed
PE/COFF file prefixed by a 12-byte XALZ header:

  XALZ blob .............. 12 bytes: magic "XALZ", descriptor index,
                          uncompressed size (bytes 8-11), then a raw LZ4
                          *block* (not the LZ4 frame format) from byte 12.

This program parses the ELF container, walks the store and writes every
extracted assembly to <outdir>/<name>. It needs no external libraries: the
LZ4 block decompressor is implemented inline below.

Python port of BishopFox/mauidll (mauidll.cr). Requires Python 3.6+.
Original: https://github.com/BishopFox/mauidll

Usage:
    python mauidll.py <libassemblies.*.blob.so> [outdir]
"""

import argparse
import os
import struct
import sys


def u16(b, p):
    return struct.unpack_from("<H", b, p)[0]


def u32(b, p):
    return struct.unpack_from("<I", b, p)[0]


def u64(b, p):
    return struct.unpack_from("<Q", b, p)[0]


def find_payload(data):
    """Locate the ``payload`` section of a (32- or 64-bit) ELF file.

    Returns (file_offset, size). Raises on non-ELF input or missing section.
    """
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    is64 = data[4] == 2
    if is64:
        shoff = u64(data, 0x28)
        shentsz = u16(data, 0x3A)
        shnum = u16(data, 0x3C)
        shstr = u16(data, 0x3E)
        a, b = 0x18, 0x20

        def sec_off(i):
            return u64(data, shoff + i * shentsz + a)

        def sec_sz(i):
            return u64(data, shoff + i * shentsz + b)
    else:
        shoff = u32(data, 0x20)
        shentsz = u16(data, 0x2E)
        shnum = u16(data, 0x30)
        shstr = u16(data, 0x32)
        a, b = 0x10, 0x14

        def sec_off(i):
            return u32(data, shoff + i * shentsz + a)

        def sec_sz(i):
            return u32(data, shoff + i * shentsz + b)

    s = shoff + shstr * shentsz
    stroff = sec_off(shstr)
    strsz = sec_sz(shstr)
    strtab = data[stroff : stroff + strsz]
    for i in range(shnum):
        base = shoff + i * shentsz
        name_off = u32(data, base)
        end = strtab.index(b"\x00", name_off)
        if strtab[name_off:end].decode() == "payload":
            return sec_off(i), sec_sz(i)
    raise ValueError("no 'payload' section found")


def lz4_block_decompress(src, expected_len):
    """Decompress a raw LZ4 *block* (as stored after the 12-byte XALZ header).

    LZ4 block layout, read left to right:
      token byte ...... high nibble = literal run length (15 means "extended",
                        keep adding following bytes until one is < 255)
      literals ........ copied verbatim
      match offset .... 2 bytes little-endian
      match length .... low nibble of the token + 4 (15 means "extended")
      match data ...... ``offset`` bytes back into the output, repeated
                        ``length`` times (matches may overlap the output)

    A last-literal sequence has no offset/match after it; an offset of zero
    marks the end of the block.
    """
    src = bytes(src)
    out = bytearray(expected_len)
    op = 0
    ip = 0
    n = len(src)
    while ip < n:
        t = src[ip]
        ip += 1
        lit = t >> 4
        if lit == 15:
            while True:
                b = src[ip]
                ip += 1
                lit += b
                if b != 255:
                    break
        out[op : op + lit] = src[ip : ip + lit]
        op += lit
        ip += lit
        if ip >= n or ip + 2 > n:
            break
        off = src[ip] | (src[ip + 1] << 8)
        ip += 2
        if off == 0:
            break
        m = (t & 0xF) + 4
        if (t & 0xF) == 15:
            while True:
                b = src[ip]
                ip += 1
                m += b
                if b != 255:
                    break
        if off >= m:
            out[op : op + m] = out[op - off : op - off + m]
            op += m
        else:
            while m > 0:  # overlapping-safe copy
                chunk = off if off < m else m
                out[op : op + chunk] = out[op - off : op - off + chunk]
                op += chunk
                m -= chunk
    return bytes(out[:op])


def extract(path, outdir):
    with open(path, "rb") as f:
        data = f.read()
    poff, psize = find_payload(data)
    p = poff
    if data[p : p + 4] != b"XABA":
        raise ValueError("bad assembly store magic: %r" % data[p : p + 4])
    # version (unreliable; ignored), count, index entry count (skipped), index size
    count = u32(data, p + 8)
    idx_size = u32(data, p + 16)
    dstart = p + 20 + idx_size  # descriptors start after header + index
    names_off = dstart + count * 28  # name table follows the descriptors

    # Assembly names: uint32 little-endian length + UTF-8 bytes, back to back.
    names = []
    np = names_off
    for _ in range(count):
        ln = u32(data, np)
        np += 4
        names.append(data[np : np + ln].decode("utf-8"))
        np += ln

    os.makedirs(outdir, exist_ok=True)
    valid = 0
    for i in range(count):
        d = dstart + i * 28
        # d+0: mapping index (unused)
        off = u32(data, d + 4)
        sz = u32(data, d + 8)
        blob = data[p + off : p + off + sz]
        if blob[:4] == b"XALZ":
            ulen = u32(blob, 8)  # uncompressed size at XALZ bytes 8-11
            raw = lz4_block_decompress(blob[12:], ulen)
        else:
            raw = blob
            ulen = sz
        ok = raw[:2] == b"MZ" and len(raw) == ulen
        valid += ok
        target = os.path.join(outdir, names[i])
        parent = os.path.dirname(target)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(target, "wb") as f:
            f.write(raw)
        print("%s: %d -> %d bytes, %s PE" % (names[i], sz, len(raw), "valid" if ok else "INVALID"))
    print("Extracted %d entries, valid PE (MZ) after extraction: %d/%d" % (count, valid, count))


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Extract .NET assemblies from a MAUI Android assembly store."
    )
    parser.add_argument("store", help="path to libassemblies.*.blob.so / libassembly-store.so")
    parser.add_argument("outdir", nargs="?", default="dlls", help="output directory (default: dlls)")
    args = parser.parse_args(argv)
    extract(args.store, args.outdir)


if __name__ == "__main__":
    main()
