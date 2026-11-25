#!/usr/bin/env python3
"""Self-test: generate and compile JNI stubs from a tiny inventory."""
import csv
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    rows = [{
        "path": "RobloxStudio.app/Contents/MacOS/RobloxStudio",
        "imports": ["_objc_msgSend", "_OBJC_CLASS_$_NSAlert", "_malloc",
                    "_mach_msg", "_QApplication_exec"],
    }]
    with tempfile.TemporaryDirectory(prefix="jni-stubs-selftest-") as tmp:
        inv = os.path.join(tmp, "inventory.json")
        with open(inv, "w") as fh:
            json.dump(rows, fh)
        out = os.path.join(tmp, "gen")
        bridge = os.path.join(tmp, "libroblox_jni_bridge.so")
        subprocess.run([sys.executable, os.path.join(HERE, "jni_stubs.py"),
                        "--inventory", inv, "--out-dir", out,
                        "--bridge-out", bridge], check=True,
                       stdout=subprocess.DEVNULL)
        with open(os.path.join(out, "syscall_map.csv")) as fh:
            data = list(csv.reader(fh))
        names = [r[1] for r in data[1:]]
        assert "objc_msgSend" in names, names
        assert "mach_msg" in names, names
        assert "QApplication_exec" not in names, names
        c = open(os.path.join(out, "jni_bridge.c")).read()
        assert '__asm__("objc_msgSend")' in c
        assert os.path.getsize(bridge) > 0
        print("selftest OK: %d stubs, bridge %d bytes" %
              (len(data) - 1, os.path.getsize(bridge)))


if __name__ == "__main__":
    main()
