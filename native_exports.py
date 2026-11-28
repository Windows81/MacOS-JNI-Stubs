#!/usr/bin/env python3
"""List the symbols Android's own libraries already export.

The bridge stubs every import of the Mach-O images.  A stub that shadows a
symbol bionic or libc++ already provides hides the real implementation: the
caller gets the bridge's placeholder instead of the working function, and the
breakage shows up far away from the stub.  This tool produces the list of
names the port must leave undefined, so the loader binds them to the real
library.

Usage:
  native_exports.py --libc LIB.so [--libcxx LIB.so]... --out FILE

  native_exports.py --libc /tmp/opencode/android_libc.so \\
      --libcxx /tmp/opencode/android_libcxx.so \\
      --out out/c5c97d45b6614310/reports/native_exports.txt

Reads each file as an ELF dynamic symbol table and writes one exported
global name per line, sorted, to --out.  Prints the count.
"""
import argparse
import subprocess
import sys


def exported_names(path):
    """Return the global names a shared object exports."""
    try:
        output = subprocess.run(
            ["readelf", "-sW", "--dyn-syms", path],
            check=True, capture_output=True, text=True).stdout
    except subprocess.CalledProcessError as failure:
        sys.exit("native_exports: cannot read %s: %s" % (path, failure))
    names = set()
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 8:
            continue
        value, bind, symbol_name = fields[1], fields[4], fields[7]
        if bind != "GLOBAL" or value == "UND" or not symbol_name:
            continue
        names.add(symbol_name.split("@")[0])
    return names


def main():
    parser = argparse.ArgumentParser(
        description="List symbols Android libraries already export.")
    parser.add_argument("--libc", required=True,
                        help="path to a bionic libc.so copy")
    parser.add_argument("--libcxx", action="append", default=[],
                        help="path to libc++_shared.so (repeatable)")
    parser.add_argument("--out", required=True,
                        help="file to write the sorted name list to")
    arguments = parser.parse_args()

    names = exported_names(arguments.libc)
    for extra in arguments.libcxx:
        names |= exported_names(extra)
    with open(arguments.out, "w") as handle:
        handle.write("\n".join(sorted(names)) + "\n")
    print("native_exports: %d names -> %s" % (len(names), arguments.out))


if __name__ == "__main__":
    main()
