# macos-jni-stubs

Standalone stage 2: scan macOS imports and replace them with JNI-backed stubs.

    pip install lief
    python3 jni_stubs.py --macho FILE [FILE ...] \
        --out-dir gen/ --bridge-out libs/libroblox_jni_bridge.so
    python3 jni_stubs.py --inventory macho_inventory.json \
        --out-dir gen/ --bridge-out libs/libroblox_jni_bridge.so
    python3 jni_stubs.py --no-compile --inventory INV.json --out-dir gen/
    python3 jni_stubs.py --inventory INV.json --out-dir gen/ \
        --bridge-out libs/bridge.so --include-qt \
        --stub-libs-dir libs/stubs/

What it does:

* classifies every import as Qt, Objective-C, libSystem call, C++ runtime or
  other, using symbol names and framework paths;
* writes `syscall_map.csv`, `SyscallBridge.java` and `Bridge.java`;
* generates `jni_bridge.c`, where one C stub per undefined symbol forwards
  its four argument registers and its name to `Bridge.dispatch`;
* compiles the C file with `clang -shared -fPIC -nostdlib` against the JDK
  `jni.h`, so the shim has no glibc dependency.

`Bridge.dispatch` currently returns zero. Replace that method body with real
Android behaviour to turn a stub into a working call. `selftest.py` exercises
the whole generator and checks the compiled ELF has no `NEEDED` entry.

## Hard requirement: libc++ strings stay native

`std::string` and `std::wstring` must be handled entirely in C inside the
bridge. No libc++ string operation may cross into Java, and no `std::string`
instance may depend on a Java object. The only Java-facing library in the port
is Qt, and Qt works through `QString`.

The native bodies reproduce the macOS libc++ 24-byte layout: long strings keep
the data pointer at offset 0, the size at offset 8 and the capacity at offset
`0x10` with the long flag in byte `0x17`; short strings keep their bytes inline
and store `size << 1` in byte `0x17`. The x8 indirect-result convention is
captured with a small assembly trampoline where a C function cannot see x8
before its prologue.

`jni_stubs.py` enforces this with native `SPECIAL_BODIES` entries for every
`basic_string` import. A new string import must get a native body here before
the bridge is rebuilt; a generated `bridge_call("...basic_string...")` is a
build defect.

## Bionic

The claim that the port needs no bionic library at all is a hypothesis, not a
rule. Studio itself still imports `malloc`, `pthread_*`, file IO, logging and
JNI entry points. Remove a bionic export only after a native or Qt replacement
has passed the launch test; do not break the working allocator or libc++ path
on a guess.

Licence: GNU General Public License v3 (see `LICENSE`).
