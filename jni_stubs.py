#!/usr/bin/env python3
"""macOS syscall -> JNI stub generator (standalone project).

Reads Mach-O images (or a `macho_inventory.json`), finds Objective-C,
libSystem, C++ runtime and other macOS-facing imports, and emits:
  syscall_map.csv     one row per symbol with class, category and Java method
  SyscallBridge.java  Java native declarations for every stubbed symbol
  Bridge.java         the single JNI dispatch entry point
  jni_bridge.c        C stubs that forward every call through JNI
  libroblox_jni_bridge.so  compiled shim (unless --no-compile)

Usage:
  jni_stubs.py --inventory INVENTORY.json --out-dir DIR --bridge-out FILE.so
  jni_stubs.py --macho FILE [FILE ...] --out-dir DIR --bridge-out FILE.so
"""
import argparse
import csv
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from naming import (classify_symbol, elf_name, is_qt_symbol,
                    java_method)  # noqa: E402

CATEGORY_ID = {"qt": 1, "objc": 2, "syscall": 3, "cpp": 4, "other": 5}

SPECIAL_BODIES = {
    "mi_malloc": "return (long long)arena_allocate((unsigned long)a0);",
    "mi_calloc": "return (long long)arena_allocate((unsigned long)a0 *"
                 " (unsigned long)a1);",
    "mi_realloc": "return (long long)arena_allocate((unsigned long)a1);",
    "mi_free": "return 0;",
    "mi_get_category": "return (long long)category_name;",
    "__cxa_allocate_exception":
        "return (long long)arena_allocate((unsigned long)a0);",
    "__cxa_throw": "return 0;",
    "_ZNSt9bad_allocC1Ev": "return a0;",
    "malloc": "return (long long)arena_allocate((unsigned long)a0);",
    "calloc": "return (long long)arena_allocate((unsigned long)a0 *"
              " (unsigned long)a1);",
    "realloc": "return (long long)arena_allocate((unsigned long)a1);",
    "aligned_alloc": "return (long long)arena_allocate((unsigned long)a0);",
    "free": "return 0;",
    "munmap": "return 0;",
    "__cxa_free_exception": "return 0;",
    "mi_malloc_usable_size": "return 16;",
    "mmap": "return (long long)arena_allocate((unsigned long)a1);",
    "mprotect": "return 0;",
    "sysconf": "return 4096;",
    "pthread_key_create": "*(int *)a0 = 1; return 0;",
    "pthread_getspecific": "return 0;",
    "pthread_setspecific": "return 0;",
    "_ZN7QString16fromAscii_helperEPKci":
        "return (long long)qt_string_placeholder;",
    "_ZN16QCoreApplication11setAttributeEN2Qt20ApplicationAttributeEb":
        "return 0;",
    "_ZN15QGuiApplication35setHighDpiScaleFactorRoundingPolicyEN2Qt32HighDpiScaleFactorRoundingPolicyE":
        "return 0;",
    "_ZN16QCoreApplication18setApplicationNameERK7QString": "return 0;",
    "_ZN16QCoreApplication19setOrganizationNameERK7QString": "return 0;",
    "_ZN16QCoreApplication23setOrganizationDomainERK7QString": "return 0;",
    "_ZN16QCoreApplication19setApplicationVersionERK7QString": "return 0;",
}


def load_records(args):
    if args.inventory:
        with open(args.inventory) as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            data = data.get("files", [])
        return data
    records = []
    import lief
    for path in args.macho:
        binary = lief.MachO.parse(path)
        m = binary.at(0) if binary else None
        imports = [s.name for s in m.imported_symbols if s.name] if m else []
        records.append({"path": path, "imports": imports})
    return records


def collect(records, include_qt=False):
    symbols = {}
    for rec in records:
        for origin in rec.get("imports", []):
            if is_qt_symbol(origin) and not include_qt:
                continue
            name = elf_name(origin)
            if not name:
                continue
            entry = symbols.setdefault(name, {
                "original": origin, "category": classify_symbol(origin),
                "origins": set()})
            entry["origins"].add(os.path.basename(rec.get("path", "")))
    return symbols


def emit_stub_libs(records, out_dir):
    """Create empty .so files for macOS dylibs named by DT_NEEDED."""
    import re
    os.makedirs(out_dir, exist_ok=True)
    names = set()
    for rec in records:
        for lib in rec.get("imported_libs", []):
            base = os.path.basename(str(lib))
            base = re.sub(r"\.dylib$", ".so", base)
            if base.endswith(".so") and re.match(r"^[A-Za-z0-9_.+-]+$", base):
                names.add(base)
    source = os.path.join(out_dir, "_empty.c")
    with open(source, "w") as fh:
        fh.write("/* empty macOS compatibility stub */\n")
    made = []
    for name in sorted(names):
        out = os.path.join(out_dir, name)
        subprocess.run(["clang", "-shared", "-fPIC", "-nostdlib",
                        "-o", out, source], check=True,
                       stdout=subprocess.DEVNULL)
        made.append(name)
    os.remove(source)
    return made


def emit(symbols, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    rows = []
    for name, info in sorted(symbols.items()):
        rows.append([info["original"], name, info["category"],
                     "io.github.robloxport.SyscallBridge",
                     java_method("s", name),
                     "|".join(sorted(info["origins"]))])
    with open(os.path.join(out_dir, "syscall_map.csv"), "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["macho_symbol", "elf_symbol", "category", "jni_class",
                    "java_method", "origin"])
        w.writerows(rows)

    bridge_java = """package io.github.robloxport;

import android.content.Context;
import android.util.Log;

/** Single JNI entry point called by every generated C stub. */
public final class Bridge {
  private static Context application_context;
  private static final java.util.ArrayList<String> recorded_calls =
      new java.util.ArrayList<String>();

  private Bridge() {}

  public static void prepare(Context context) {
    application_context = context.getApplicationContext();
    try {
      java.io.FileOutputStream ready_file = application_context.openFileOutput(
          "java_ready.txt", Context.MODE_PRIVATE);
      ready_file.write("java prepared\\n".getBytes("UTF-8"));
      ready_file.close();
    } catch (Exception error) {
      Log.e("RobloxPort", "prepare failed", error);
    }
  }

  public static void reportLoadError(String message) {
    try {
      java.io.FileOutputStream error_file = application_context.openFileOutput(
          "dlerror.txt", Context.MODE_PRIVATE);
      error_file.write(message.getBytes("UTF-8"));
      error_file.close();
    } catch (Exception error) {
      Log.e("RobloxPort", "dlerror file failed", error);
    }
  }

  public static long dispatch(String name, int category,
                              long a0, long a1, long a2, long a3) {
    synchronized (recorded_calls) {
      recorded_calls.add(name);
      if (application_context != null) {
        try {
          java.io.FileOutputStream call_file = application_context.openFileOutput(
              "call_log.txt", Context.MODE_PRIVATE | Context.MODE_APPEND);
          call_file.write(("calls " + recorded_calls.size() + " latest "
              + name + "\\n").getBytes("UTF-8"));
          call_file.close();
        } catch (Exception log_error) {
          Log.e("RobloxPort", "call log failed", log_error);
        }
      }
    }
    if (name.contains("setAttribute") || name.contains("setOrganizationName"))
      Log.i("RobloxPort", "Qt setup call: " + name);
    if (category == 1) return QtBridge.dispatch(name, a0, a1, a2, a3);
    return SyscallBridge.dispatch(name, a0, a1, a2, a3);
  }

  public static String drainCalls() {
    StringBuilder builder = new StringBuilder();
    synchronized (recorded_calls) {
      for (String call_name : recorded_calls) {
        builder.append(call_name);
        builder.append("\\n");
      }
      recorded_calls.clear();
    }
    return builder.toString();
  }
}
"""
    with open(os.path.join(out_dir, "Bridge.java"), "w") as fh:
        fh.write(bridge_java)

    java = ["package io.github.robloxport;", "",
            "/** macOS system interfaces replaced by JNI-backed stubs. */",
            "public final class SyscallBridge {",
            "  private SyscallBridge() {}", "",
            "  public static long dispatch(String name, long a0, long a1,",
            "                              long a2, long a3) {",
            "    return 0L; // safe no-op; override for real Android behaviour",
            "  }", ""]
    for row in rows:
        java.append("  public static native long %s(long a0, long a1," % row[4])
        java.append("      long a2, long a3); // %s" % row[0])
    java.append("}")
    with open(os.path.join(out_dir, "SyscallBridge.java"), "w") as fh:
        fh.write("\n".join(java) + "\n")

    lines = [
        "/* Generated by jni_stubs.py: macOS symbol -> JNI bridge stubs. */",
        "#include <jni.h>", "",
        "static unsigned char allocation_arena[1 << 20];",
        "static unsigned long allocation_offset = 0;",
        "static const char category_name[] = \"RobloxPort\";",
        "static int qt_string_placeholder[4] = {-1, 0, 0, 0};",
        "static void *arena_allocate(unsigned long requested_size) {",
        "  unsigned long start = (allocation_offset + 15UL) & ~15UL;",
        "  if (start + requested_size > sizeof(allocation_arena)) return 0;",
        "  allocation_offset = start + requested_size;",
        "  return allocation_arena + start;", "}", "",
        "static int marker_attribute = 0;",
        "static int marker_organization = 0;",
        "static int contains_text(const char *text, const char *needle) {",
        "  int index = 0;", "  while (text[index]) {",
        "    int inner = 0;",
        "    while (needle[inner] && text[index + inner] == needle[inner])",
        "      inner++;",
        "    if (!needle[inner]) return 1;", "    index++;", "  }",
        "  return 0;", "}", "",
        "JNIEXPORT jint JNICALL",
        "Java_io_github_robloxport_MainActivity_markerStatus(JNIEnv *env,",
        "                                                       jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "  return marker_attribute | (marker_organization << 1);", "}", "",
        "static JavaVM *g_vm;", "static jclass g_bridge;",
        "static jmethodID g_dispatch;", "",
        "jint JNI_OnLoad(JavaVM *vm, void *reserved) {",
        "  (void)reserved;", "  g_vm = vm;", "  JNIEnv *env = 0;",
        "  if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK)",
        "    return JNI_VERSION_1_6;",
        "  jclass cls = (*env)->FindClass(env, \"io/github/robloxport/Bridge\");",
        "  if (cls) {",
        "    g_bridge = (jclass)(*env)->NewGlobalRef(env, cls);",
        "    g_dispatch = (*env)->GetStaticMethodID(env, g_bridge, \"dispatch\",",
        "        \"(Ljava/lang/String;IJJJJ)J\");", "  }",
        "  return JNI_VERSION_1_6;", "}", "",
        "static long long bridge_call(const char *name, int cat,",
        "                             long long a0, long long a1,",
        "                             long long a2, long long a3) {",
        "  if (contains_text(name, \"setAttribute\")) marker_attribute = 1;",
        "  if (contains_text(name, \"setOrganizationName\"))",
        "    marker_organization = 1;",
        "  if (!g_vm || !g_dispatch) return 0;",
        "  JNIEnv *env = 0;",
        "  if ((*g_vm)->GetEnv(g_vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK) {",
        "    if ((*g_vm)->AttachCurrentThread(g_vm, (void**)&env, 0) != JNI_OK)",
        "      return 0;", "  }",
        "  jstring jname = (*env)->NewStringUTF(env, name);",
        "  if (!jname) return 0;",
        "  return (long long)(*env)->CallStaticLongMethod(env, g_bridge,",
        "      g_dispatch, jname, (jint)cat, (jlong)a0, (jlong)a1,",
        "      (jlong)a2, (jlong)a3);", "}", "",
    ]
    for idx, row in enumerate(rows, 1):
        elf, cat = row[1], CATEGORY_ID.get(row[2], 5)
        lines += [
            "long long stub_%d(long long a0, long long a1," % idx,
            "    long long a2, long long a3) __asm__(\"%s\");" % elf,
            "long long stub_%d(long long a0, long long a1," % idx,
            "    long long a2, long long a3) {",
            ("  " + SPECIAL_BODIES[elf]) if elf in SPECIAL_BODIES else
            ("  return bridge_call(\"%s\", %d, a0, a1, a2, a3);" %
             (elf, cat)),
            "}", "",
        ]
    c_path = os.path.join(out_dir, "jni_bridge.c")
    with open(c_path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return rows, c_path


def compile_bridge(c_path, out_so):
    jdk = None
    for candidate in ("/usr/lib/jvm/java-17-openjdk",
                      "/usr/lib/jvm/java-27-openjdk"):
        if os.path.isfile(os.path.join(candidate, "include", "jni.h")):
            jdk = candidate
            break
    if not jdk:
        raise RuntimeError("no JDK jni.h found; cannot compile the bridge")
    os.makedirs(os.path.dirname(os.path.abspath(out_so)), exist_ok=True)
    cmd = ["clang", "-shared", "-fPIC", "-nostdlib", "-O1",
           "-I%s/include" % jdk, "-I%s/include/linux" % jdk,
           "-o", out_so, c_path]
    print("[jni_stubs] %s" % " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True)
    return out_so


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--inventory")
    ap.add_argument("--macho", nargs="*", default=[])
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--bridge-out")
    ap.add_argument("--no-compile", action="store_true")
    ap.add_argument("--include-qt", action="store_true",
                    help="also emit stubs for Qt symbols (needed for dlopen)")
    ap.add_argument("--stub-libs-dir",
                    help="emit empty .so files for macOS dylibs named by DT_NEEDED")
    args = ap.parse_args()
    if not args.inventory and not args.macho:
        ap.error("provide --inventory or --macho")
    if not args.no_compile and not args.bridge_out:
        ap.error("--bridge-out is required unless --no-compile is given")
    records = load_records(args)
    symbols = collect(records, args.include_qt)
    rows, c_path = emit(symbols, args.out_dir)
    if args.stub_libs_dir:
        made = emit_stub_libs(records, args.stub_libs_dir)
        print("jni_stubs: %d compatibility stub libraries" % len(made))
    if not args.no_compile:
        compile_bridge(c_path, args.bridge_out)
    print("jni_stubs: %d symbols -> %s" % (len(rows), args.out_dir))


if __name__ == "__main__":
    main()
