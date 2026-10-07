#!/usr/bin/env python3
"""apk2dll.py - APK in, .NET DLLs out (with .NET MAUI detection).

Takes a single APK, a directory of split APKs, or a zip of split APKs
(.zip/.apks/.xapk/.apkm), checks whether it is a .NET MAUI/Xamarin app by
looking for the managed-code assembly store, and extracts the DLLs by reusing
``mauidll.py``. Stdlib only: argparse, os, re, struct, sys, zipfile.

Usage:
    python apk2dll.py <apk|dir|zip> [outdir] [--abi arm64-v8a] [--list-abis]
                      [--max-store-mb 256] [-q]

Exit codes: 0 = extracted, 2 = not a .NET MAUI app / usage error,
1 = corrupt store / IO error.
"""

import argparse
import io
import os
import re
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mauidll

ABI_PREFERENCE = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86")
STORE_RE = re.compile(
    r"^lib/(?P<abi>[^/]+)/(libassembly-store\.so|libassemblies\.[^/]+\.blob\.so)$"
)
ARCHIVE_EXTS = (".zip", ".apks", ".xapk", ".apkm")


def eprint(*a):
    print(*a, file=sys.stderr)


def collect_apks(inp):
    """Return list of (label, apk_bytes_or_path).

    - file .apk -> ("file:<path>", path)
    - dir -> one entry per *.apk
    - archive (.zip/.apks/.xapk/.apkm) -> one entry per inner *.apk, bytes pre-read
    """
    if os.path.isdir(inp):
        apks = sorted(
            os.path.join(inp, f)
            for f in os.listdir(inp)
            if f.lower().endswith(".apk")
            and os.path.isfile(os.path.join(inp, f))
        )
        return [("file:%s" % p, p) for p in apks]
    if os.path.isfile(inp):
        low = inp.lower()
        if low.endswith(".apk"):
            return [("file:%s" % inp, inp)]
        if low.endswith(ARCHIVE_EXTS):
            with zipfile.ZipFile(inp) as zf:
                names = sorted(
                    n for n in zf.namelist()
                    if n.lower().endswith(".apk") and not n.endswith("/")
                )
                return [("zip:%s!%s" % (inp, n), zf.read(n)) for n in names]
    return []


def scan_apk_bytes(apk_bytes, abi_filter=None):
    """Return ({abi: entry}, signals) from in-memory APK bytes (namelist-level)."""
    found, signals = {}, {"dex": False, "blazor": False, "mono": False}
    try:
        with zipfile.ZipFile(io.BytesIO(apk_bytes)) as zf:
            names = zf.namelist()
    except zipfile.BadZipFile:
        return found, dict(signals, bad_zip=True)
    for n in names:
        m = STORE_RE.match(n)
        if m and (abi_filter is None or m.group("abi") == abi_filter):
            found.setdefault(m.group("abi"), n)
    signals["dex"] = "classes.dex" in names
    signals["blazor"] = "assets/wwwroot/index.html" in names
    signals["mono"] = any("libmonodroid.so" in x or "libmonosgen" in x for x in names)
    return found, signals


def read_store_bytes(apk_ref, entry, max_bytes):
    """Read one store entry from a path or bytes ref. Returns bytes."""
    if isinstance(apk_ref, bytes):
        zf = zipfile.ZipFile(io.BytesIO(apk_ref))
    else:
        zf = zipfile.ZipFile(apk_ref)
    with zf:
        st = zf.getinfo(entry)
        if st.file_size > max_bytes:
            raise ValueError("store too large (%d bytes)" % st.file_size)
        return zf.read(entry)


def pick_abi(found, preferred=None):
    abis = list(found)
    if preferred:
        if preferred in found:
            return preferred
        return None
    for a in ABI_PREFERENCE:
        if a in found:
            return a
    return abis[0] if abis else None


def main(argv=None):
    ap = argparse.ArgumentParser(description="APK in, .NET DLLs out (MAUI detection + extract).")
    ap.add_argument("input", help="APK file, dir of split APKs, or zip of split APKs")
    ap.add_argument("outdir", nargs="?", default="dlls", help="output directory (default: dlls)")
    ap.add_argument("--abi", help="force ABI (default: auto arm64-v8a first)")
    ap.add_argument("--list-abis", action="store_true", help="list ABIs with assembly stores and exit")
    ap.add_argument("--max-store-mb", type=int, default=256, help="max store size to read (default 256 MB)")
    ap.add_argument("-q", "--quiet", action="store_true", help="only errors + summary")
    args = ap.parse_args(argv)

    cands = collect_apks(args.input)
    if not cands:
        # Maybe the input archive IS the store container (raw lib dir zip)?
        # Try: treat input zip itself as an APK-like container with lib/<abi>/ store.
        if os.path.isfile(args.input) and args.input.lower().endswith(ARCHIVE_EXTS):
            try:
                with open(args.input, "rb") as f:
                    raw = f.read()
                found, sig = scan_apk_bytes(raw, args.abi)
                if found:
                    cands = [("zip-self:%s" % args.input, raw)]
            except OSError:
                pass
    if not cands:
        eprint("error: no APK found in %r (need .apk, dir of .apk, or %s)" % (args.input, "/".join(ARCHIVE_EXTS)))
        return 2

    # Load APK bytes once (paths stream from disk, zip entries already in memory).
    apk_blobs = []  # (label, bytes|None(path), is_path)
    for label, ref in cands:
        try:
            if isinstance(ref, bytes):
                apk_blobs.append((label, ref, False))
            else:
                with open(ref, "rb") as f:
                    apk_blobs.append((label, f.read(), False))
        except OSError as e:
            eprint("warn: %s: %s" % (label, e))

    found_all = {}  # abi -> (label, entry)
    signals_all = {"dex": False, "blazor": False, "mono": False}
    for label, blob, _ in apk_blobs:
        found, sig = scan_apk_bytes(blob, args.abi)
        for abi, entry in found.items():
            found_all.setdefault(abi, (label, entry))
        for k in signals_all:
            signals_all[k] = signals_all[k] or sig.get(k, False)

    if args.list_abis:
        for abi in sorted(found_all):
            print("%s  (%s)" % (abi, found_all[abi][0]))
        return 0 if found_all else 2

    if not found_all:
        eprint("error: not a .NET MAUI app: no lib/<abi>/libassembly-store.so or "
               "libassemblies.*.blob.so in %d APK(s)" % len(apk_blobs))
        eprint("hint: classes.dex=%s blazor-wwwroot=%s mono-runtime=%s" % (
            signals_all["dex"], signals_all["blazor"], signals_all["mono"]))
        return 2

    abi = pick_abi(found_all, args.abi)
    if abi is None:
        eprint("error: requested ABI %r not found (available: %s)" % (args.abi, ", ".join(sorted(found_all))))
        return 2
    label, entry = found_all[abi]
    blob = dict((l, b) for l, b, _ in apk_blobs)[label]
    max_bytes = args.max_store_mb * 1024 * 1024
    try:
        store_bytes = read_store_bytes(blob, entry, max_bytes)
    except (OSError, zipfile.BadZipFile, KeyError, ValueError) as e:
        eprint("error: cannot read store %s from %s: %s" % (entry, label, e))
        return 1

    if not args.quiet:
        print("APK: %s | ABI: %s | store: %s (%d bytes)" % (label, abi, entry, len(store_bytes)))
    try:
        valid, total = mauidll.extract_bytes(store_bytes, args.outdir)
    except ValueError as e:
        eprint("error: %s" % e)
        return 1
    if valid != total:
        eprint("warning: %d/%d assemblies failed PE validation" % (total - valid, total))
    return 0


if __name__ == "__main__":
    sys.exit(main())
