# mauidll

Extract the managed (.NET) assemblies out of a MAUI Android assembly store.

> **Python port:** [`mauidll.py`](mauidll.py) is a dependency-free Python 3 port
> of `mauidll.cr`, verified byte-identical on 175/175 assemblies:
>
> ```sh
> python mauidll.py libassembly-store.so extracted-dlls
> ```

.NET Android apps ship their managed code inside a shared library, usually
`libassemblies.<abi>.blob.so` (older versions) or `libassembly-store.so`.
`mauidll` parses that file and writes every assembly it contains to disk as a
standard `.dll`  file, ready for inspection in a decompiler such as
ILSpy.

The tool is a single self-contained Crystal program with no external
dependencies. The LZ4 decompressor it needs is implemented inline, so nothing
beyond the standard library is required.

## Quick start

```sh
crystal build --release mauidll.cr -o mauidll
./mauidll libassembly-store.so extracted-dlls
```

The binary produced by `crystal build` is self-contained: it only needs Crystal
on the build machine, not on any machine where you run it.

## Installation

### 1. Install Crystal

`mauidll` is compiled with the Crystal language. If you do not have Crystal yet:

#### macOS

The most popular way is Homebrew:

```sh
brew install crystal
```

Crystal is also available as an official universal tarball (Apple Silicon and
Intel) from the [downloads page](https://crystal-lang.org/install/).

#### Linux

On Debian, Ubuntu and related distributions, install the official package
repository and then the compiler:

```sh
curl -fsSL https://crystal-lang.org/install.sh | sudo bash
sudo apt install crystal
```

Alternatively, on any distribution that supports snaps:

```sh
sudo snap install crystal --classic
```

On Arch Linux:

```sh
sudo pacman -S crystal shards
```

### 2. Build

```sh
crystal build --release mauidll.cr -o mauidll
```

`mauidll` was developed and tested with Crystal 1.20.x. It uses only the standard
library, so any reasonably recent release should work.

## Usage

```sh
./mauidll <assembly-store.so> [outdir]
```

| Argument                | Meaning                                                        |
| ----------------------- | -------------------------------------------------------------- |
| `assembly-store.so`     | Path to the store, e.g. `libassemblies.arm64-v8a.blob.so`      |
| `outdir` (optional)     | Output directory, defaults to `dlls` in the current directory  |

Example:

```sh
./mauidll /tmp/app64-v8a/libassembly-store.so /tmp/extracted
```

Output lines report one line per assembly (`name: size -> decompressed size,
valid PE`), followed by a summary such as:

```
Extracted 235 entries, valid PE (MZ) after extraction: 235/235
```

## How it works

1. The store file is an ELF object. The assembly store lives in a
   non-loadable `payload` section, which `mauidll` locates via the ELF section
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
   checked to start with the `MZ` PE signature.

