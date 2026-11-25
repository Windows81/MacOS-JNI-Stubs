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

Licence: GNU General Public License v3 (see `LICENSE`).
