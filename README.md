# mauidll

Extract the managed (.NET) assemblies out of a MAUI Android assembly store.

.NET Android apps ship their managed code inside a shared library, usually
`libassemblies.<abi>.blob.so` (older versions) or `libassembly-store.so`.
This repo gives you two Python-first ways to get the DLLs out, plus the
original Crystal tool:

- [`apk2dll.py`](apk2dll.py) — **APK in, DLLs out.** Detects the MAUI store,
  picks an ABI, extracts. Start here.
- [`mauidll.py`](mauidll.py) — store file in, DLLs out (Python port).
- [`mauidll.cr`](mauidll.cr) — original Crystal implementation.

All Python code is **stdlib only** (no `pip install` needed).

## Quick start

No build, no dependencies — just Python 3.6+:

```sh
# 1. Whole APK (or split-APK dir / zip) straight to DLLs:
python apk2dll.py app.apk dlls
python apk2dll.py splits/ dlls --abi arm64-v8a
python apk2dll.py splits.zip dlls

# 2. Already have the store .so (e.g. lib/arm64-v8a/libassembly-store.so)?
python mauidll.py libassembly-store.so extracted-dlls

# 3. Original Crystal binary (optional):
crystal build --release mauidll.cr -o mauidll
./mauidll libassembly-store.so extracted-dlls
```

Typical output:

```
APK: file:app.apk | ABI: arm64-v8a | store: lib/arm64-v8a/libassembly-store.so (9383262 bytes)
MALIYAH.dll: 22144 -> 37888 bytes, valid PE
...
Extracted 175 entries, valid PE (MZ) after extraction: 175/175
```

## Installation

### Python path (recommended — nothing to install)

1. Install Python 3.6+ from [python.org](https://www.python.org/downloads/)
   (or `sudo apt install python3` / `brew install python3`).
2. Clone this repo. Done — `apk2dll.py` + `mauidll.py` use only the standard
   library (`argparse`, `io`, `os`, `re`, `struct`, `sys`, `zipfile`).

Verify:

```sh
python -m py_compile apk2dll.py mauidll.py && echo OK
python apk2dll.py app.apk --list-abis
```

### Crystal path (original tool only)

Only needed if you want to build `mauidll.cr`:

#### macOS

```sh
brew install crystal
```

Crystal is also available as an official universal tarball from the
[downloads page](https://crystal-lang.org/install/).

#### Linux

```sh
curl -fsSL https://crystal-lang.org/install.sh | sudo bash
sudo apt install crystal
```

Or: `sudo snap install crystal --classic` / `sudo pacman -S crystal shards`.

#### Build

```sh
crystal build --release mauidll.cr -o mauidll
```

Developed and tested with Crystal 1.20.x; any reasonably recent release works.

## Usage

### apk2dll.py — APK in, DLLs out

```sh
python apk2dll.py <apk|dir|zip> [outdir] [--abi ABI] [--list-abis]
                  [--max-store-mb 256] [-q]
```

| Argument / flag         | Meaning                                                        |
| ----------------------- | -------------------------------------------------------------- |
| `input`                 | APK file, dir of split APKs, or zip of splits (`.zip`/`.apks`/`.xapk`/`.apkm`) |
| `outdir` (optional)     | Output directory, defaults to `dlls`                           |
| `--abi ABI`             | Force ABI (default: auto-pick `arm64-v8a` first)               |
| `--list-abis`           | List ABIs that contain an assembly store and exit              |
| `--max-store-mb N`      | Max store size to read (default 256, zip-bomb guard)           |
| `-q`                    | Quiet: only errors + summary                                   |

Detection: scans APK namelists for `lib/<abi>/libassembly-store.so` (new) or
`lib/<abi>/libassemblies.*.blob.so` (old). ABI auto-pick order: `arm64-v8a`,
`armeabi-v7a`, `x86_64`, `x86`.

Exit codes: `0` = extracted, `2` = not a MAUI app / usage error,
`1` = corrupt store / IO error.

### mauidll.py — store file in, DLLs out

```sh
python mauidll.py <assembly-store.so> [outdir]
```

| Argument                | Meaning                                                        |
| ----------------------- | -------------------------------------------------------------- |
| `assembly-store.so`     | Path to the store, e.g. `libassemblies.arm64-v8a.blob.so`      |
| `outdir` (optional)     | Output directory, defaults to `dlls` in the current directory  |

Example:

```sh
python mauidll.py /tmp/app64-v8a/libassembly-store.so /tmp/extracted
```

## How it works

1. The store file is an ELF object. The assembly store lives in a
   non-loadable `payload` section, located via the ELF section
   headers (32- and 64-bit ELF are both supported).
2. The payload begins with a 20-byte `XABA` header: magic, version, entry
   count, index entry count and index size.
3. After the index come the descriptors, 28 bytes each (mapping index, data
   offset, data size), then a table of names (uint32 little-endian length +
   UTF-8 bytes per entry).
4. Each blob is either an already-compressed assembly or a raw one. A blob
   starting with `XALZ` is a raw LZ4 *block* (not the LZ4 frame format)
   preceded by a 12-byte header that includes the uncompressed size; anything
   else (starting with `MZ`) is stored verbatim.
5. Decompressed blobs are written to disk under their assembly name and
   checked to start with the `MZ` PE signature. `apk2dll.py` adds the outer
   layer: unzip the APK, find the store for the best ABI, feed its bytes to
   the same parser.

## Credits

- Original Crystal tool [`mauidll`](https://github.com/BishopFox/mauidll) by
  [Bishop Fox](https://github.com/BishopFox) — ELF/XABA/XALZ format, LZ4
  block decompressor, and overall design.
- Python port (`mauidll.py`) + `apk2dll.py` APK wrapper in this fork by
  [sreenushenoy](https://github.com/sreenushenoy) — verified byte-identical
  (175/175 assemblies) against the Crystal implementation on a real MAUI app.
- Decompile the extracted DLLs with [ILSpy](https://github.com/icsharpcode/ILSpy).
