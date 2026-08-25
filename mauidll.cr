#!/usr/bin/env crystal
#
# mauidll - extract .NET assemblies from a MAUI Android assembly store.
#
# A .NET Android app ships its managed code inside a shared library, normally
# `libassemblies.<abi>.blob.so` (older versions) or `libassembly-store.so`.
# That file is a regular ELF object in which the `.NET assembly store` lives in
# a non-loadable `payload` section. The store is a sequence of records:
#
#   payload section
#     XABA header ......... 20 bytes: magic "XABA", version, entry count,
#                           index entry count, index size
#     index ................ skipped entirely (its size is in the header)
#     descriptors ......... 28 bytes each: mapping index, data offset, data size
#     name table ......... one uint32 little-endian length + UTF-8 name per entry
#     data ............... the blobs (assemblies), at the offsets above
#
# Each blob is either already a PE/COFF file (MZ ...) or an LZ4-compressed
# PE/COFF file prefixed by a 12-byte XALZ header:
#
#   XALZ blob .............. 12 bytes: magic "XALZ", descriptor index,
#                           uncompressed size (bytes 8-11), then a raw LZ4
#                           *block* (not the LZ4 frame format) from byte 12.
#
# This program parses the ELF container, walks the store and writes every
# extracted assembly to <outdir>/<name>. It needs no external libraries: the
# LZ4 block decompressor is implemented inline below.
#
require "file_utils"

abort "usage: #{$0} <libassemblies.*.blob.so> [outdir]" unless ARGV.size >= 1
path = ARGV[0]
outdir = ARGV[1]? || "dlls"
FileUtils.mkdir_p(outdir)
data = File.read(path).to_slice
io = IO::Memory.new(data)

# Little-endian readers used for every integer in the ELF and store formats.
def u16(io, off)
  io.pos = off.to_i; io.read_bytes(UInt16, IO::ByteFormat::LittleEndian)
end

def u32(io, off)
  io.pos = off.to_i; io.read_bytes(UInt32, IO::ByteFormat::LittleEndian)
end

def u64(io, off)
  io.pos = off.to_i; io.read_bytes(UInt64, IO::ByteFormat::LittleEndian)
end

# Locate the `payload` section of a (32- or 64-bit) ELF file.
# ELF header fields at fixed offsets (64-bit / 32-bit):
#   section header table offset ......... 0x28 / 0x20
#   section header size / count / index  0x3a / 0x2e, 0x3c / 0x30, 0x3e / 0x32
# Each 64/32-bit section header holds its name offset (+0), offset (+0x18/0x10)
# and size (+0x20/0x14). The string table header (index `shstr`) points at the
# table used to resolve section names.
def find_payload(data, io)
  raise "not an ELF file" unless data[0] == 0x7f_u8 && data[1, 3] == "ELF".to_slice
  is64 = data[4] == 2_u8
  shoff = is64 ? u64(io, 0x28) : u32(io, 0x20)
  shentsz = u16(io, is64 ? 0x3a : 0x2e)
  shnum = u16(io, is64 ? 0x3c : 0x30)
  shstr = u16(io, is64 ? 0x3e : 0x32)
  a, b = is64 ? {0x18, 0x20} : {0x10, 0x14}
  s = shoff.to_i64 + shstr.to_i64 * shentsz
  stroff = (is64 ? u64(io, s + a) : u32(io, s + a)).to_i
  strsize = (is64 ? u64(io, s + b) : u32(io, s + b)).to_i
  shnum.to_i.times do |i|
    base = shoff.to_i64 + i.to_i64 * shentsz
    start = stroff + u32(io, base).to_i
    e = data.index(0_u8, start) || start
    if String.new(data[start, e - start]) == "payload"
      off = (is64 ? u64(io, base + a) : u32(io, base + a)).to_i32
      sz = (is64 ? u64(io, base + b) : u32(io, base + b)).to_i32
      return {off, sz}
    end
  end
  raise "no 'payload' section found"
end

# Decompress a raw LZ4 *block* (as stored after the 12-byte XALZ header).
#
# LZ4 block layout, read left to right:
#   token byte ...... high nibble = literal run length (15 means "extended",
#                     keep adding following bytes until one is < 255)
#   literals ........ copied verbatim
#   match offset .... 2 bytes little-endian
#   match length .... low nibble of the token + 4 (15 means "extended", as above)
#   match data ...... `offset` bytes back into the output, repeated `length`
#                     times, byte by byte (matches may overlap the output)
#
# A last-literal sequence has no offset/match after it; an offset of zero marks
# the end of the block.
def lz4_block(data : Bytes, dst : Bytes)
  ip = 0
  op = 0
  n = data.size
  while ip < n
    t = data[ip].to_i32
    ip += 1
    lit = t >> 4
    if lit == 15
      b = data[ip].to_i32; ip += 1
      lit += b
      while b == 255
        b = data[ip].to_i32; ip += 1
        lit += b
      end
    end
    (dst.to_unsafe + op).copy_from(data.to_unsafe + ip, lit)
    op += lit
    ip += lit
    break if ip >= n || ip + 2 > n
    off = data[ip].to_u32 | (data[ip + 1].to_u32 << 8)
    ip += 2
    break if off == 0
    m = (t & 0xf) + 4
    if (t & 0xf) == 15
      b = data[ip].to_i32; ip += 1
      m += b
      while b == 255
        b = data[ip].to_i32; ip += 1
        m += b
      end
    end
    m.times do
      dst[op] = dst[op - off.to_i32]
      op += 1
    end
  end
end

poff, psize = find_payload(data, io)
payload = data[poff, psize]
pio = IO::Memory.new(payload)
raise "bad assembly store" unless pio.read_string(4) == "XABA"
pio.read_bytes(UInt32, IO::ByteFormat::LittleEndian) # version (unreliable; ignored)
count = pio.read_bytes(UInt32, IO::ByteFormat::LittleEndian)
pio.read_bytes(UInt32, IO::ByteFormat::LittleEndian) # index entry count (skipped)
idx_size = pio.read_bytes(UInt32, IO::ByteFormat::LittleEndian)
dstart = 20 + idx_size.to_i          # descriptors start after header + index
names_off = dstart + count.to_i * 28 # name table follows the descriptors

# Assembly names: uint32 little-endian length + UTF-8 bytes, back to back.
names = [] of String
pio.pos = names_off
count.to_i.times do
  len = pio.read_bytes(UInt32, IO::ByteFormat::LittleEndian).to_i
  names << pio.read_string(len)
end

# Walk the descriptors; each 28-byte entry carries a mapping index, the blob's
# offset inside the payload and its size. Blobs are either raw PE files or
# XALZ-wrapped LZ4 blocks (an uncompressed entry starts with "MZ" directly).
valid = 0
count.to_i.times do |i|
  d = dstart + i * 28
  pio.pos = d
  pio.read_bytes(UInt32, IO::ByteFormat::LittleEndian) # mapping index
  off = pio.read_bytes(UInt32, IO::ByteFormat::LittleEndian).to_i32
  sz = pio.read_bytes(UInt32, IO::ByteFormat::LittleEndian).to_i32
  blob = payload[off, sz]
  if blob[0, 4] == "XALZ".to_slice
    ulen = u32(pio, off + 8).to_i32   # uncompressed size at XALZ bytes 8-11
    buf = Bytes.new(ulen)
    lz4_block(blob[12, sz - 12], buf) # compressed data starts at byte 12
    raw = buf
  else
    raw = blob
    ulen = sz
  end
  ok = raw[0, 2] == "MZ".to_slice && raw.size == ulen
  valid += 1 if ok
  target = File.join(outdir, names[i])
  FileUtils.mkdir_p(File.dirname(target))
  File.write(target, raw)
  puts "#{names[i]}: #{sz} -> #{raw.size} bytes, #{ok ? "valid" : "INVALID"} PE"
end
puts "Extracted #{count.to_i} entries, valid PE (MZ) after extraction: #{valid}/#{count.to_i}"
