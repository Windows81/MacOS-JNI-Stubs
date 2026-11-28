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

# These are provided by bionic libc itself.  Defining them in the bridge
# would shadow libc and, worse, hand Studio slices of a 1 MiB bump arena;
# leaving them undefined makes the ELF loader resolve Studio's imports
# straight to the real heap.
BIONIC_ALLOCATORS = {"malloc", "calloc", "realloc", "aligned_alloc"}
# Filled in from --native-symbols.  A stub for a name that bionic or libc++
# already exports shadows the working implementation, so those imports are
# left undefined and the loader binds them to the real library.
NATIVE_EXPORTED = set()
# Darwin and Linux disagree on the MAP_ANONYMOUS bit.  These must stay
# stubbed so the bridge can translate the flags even though bionic exports
# the same names.
FORCE_STUBS = {"mmap", "snprintf", "sysconf", "vsnprintf"}
# Stubs written as assembly because their arguments live on the caller stack.
ASM_STUBS = {"snprintf"}
# Android's libc++_shared.so provides the real exception ABI. Our no-op stubs
# returned from __cxa_throw, which the caller assumes never returns.
BIONIC_C_FUNCTIONS = {
    "strnlen", "strcpy", "strncpy", "strcat", "strncat",
    "strcmp", "strncmp", "strchr", "strrchr", "strstr", "strdup",
    "strndup", "strcmp", "memset", "memcmp", "memmove", "memcpy",
    "sprintf", "printf", "fprintf", "puts",
    "atoi", "atol", "atoll", "strtol", "strtoul", "strtoll", "strtoull",
    "strtod", "strtof", "isdigit", "isalpha", "isspace", "tolower",
    "toupper", "pthread_self", "pthread_equal", "pthread_mutex_lock",
    "pthread_mutex_unlock", "pthread_mutex_init", "pthread_mutex_destroy",
    "fopen", "fclose", "fgets", "fread", "fwrite", "fprintf", "fputs",
}
LIBCXX_PROVIDED = {
    "__cxa_allocate_exception", "__cxa_bad_cast", "__cxa_bad_typeid",
    "__cxa_begin_catch", "__cxa_demangle", "__cxa_end_catch",
    "__cxa_free_exception", "__cxa_get_exception_ptr",
    "__cxa_get_globals", "__cxa_get_globals_fast", "__cxa_guard_abort",
    "__cxa_guard_acquire", "__cxa_guard_release", "__cxa_pure_virtual",
    "__cxa_rethrow", "__cxa_throw", "__cxa_throw_bad_array_new_length",
}

SPECIAL_BODIES = {
    # bionic has no mi_* symbols, so these thin forwarders are the minimum
    # needed to keep RobloxStudio.so loadable.  They route straight to the
    # bionic heap; malloc/calloc/realloc/free themselves are not stubbed at
    # all, so the ELF loader resolves those names to libc directly.
    "mi_malloc": "return (long long)port_allocate((unsigned long)a0);",
    "mi_calloc":
        "return (long long)port_callocate((unsigned long)a0,"
        " (unsigned long)a1);",
    "mi_realloc":
        "return (long long)port_reallocate((void *)a0,(unsigned long)a1);",
    "strlen": "return (long long)port_measure((const char *)a0);",
    "puts":
        "char b0[9]; void *handle = dlopen(\"libc.so\", 0); if (handle && !port_real_puts) port_real_puts = (int (*)(const char *)) dlsym(handle, \"puts\"); if (!port_real_puts) return 0; return port_real_puts((const char *)port_fix_arg(a0,b0));",
    "fputs":
        "char b0[9]; void *handle = dlopen(\"libc.so\", 0); if (handle && !port_real_fputs) port_real_fputs = (int (*)(const char *,void*)) dlsym(handle, \"fputs\"); if (!port_real_fputs) return 0; return port_real_fputs((const char *)port_fix_arg(a0,b0),(void *)a1);",
    "printf":
        "char b0[9],b1[9],b2[9]; void *handle = dlopen(\"libc.so\", 0); if (handle && !port_real_printf) port_real_printf = (int (*)(const char *,...)) dlsym(handle, \"printf\"); if (!port_real_printf) return 0; return port_real_printf((const char *)a0, port_fix_arg(a1,b0), port_fix_arg(a2,b1), port_fix_arg(a3,b2));",
    "sprintf":
        "char b0[9],b1[9],b2[9]; void *handle = dlopen(\"libc.so\", 0); if (handle && !port_real_sprintf) port_real_sprintf = (int (*)(char *,const char *,...)) dlsym(handle, \"sprintf\"); if (!port_real_sprintf) return 0; return port_real_sprintf((char *)a0,(const char *)a1, port_fix_arg(a2,b0), port_fix_arg(a3,b1), port_fix_arg(a4,b2));",
    "vsnprintf":
        "return (long long)port_darwin_snprintf((char *)a0,"
        " (unsigned long)a1, (const char *)a2,"
        " (const unsigned char *)a3);",
    "free": "port_release((void *)a0); return 0;",
    "mi_free": "port_deallocate((void *)a0); return 0;",
    "mi_get_category": "return (long long)category_name;",
    "__cxa_allocate_exception":
        "return (long long)port_allocate((unsigned long)a0);",
    "__cxa_throw":
        "__android_log_print(4, \"RobloxPortAlloc\","
        " \"__cxa_throw called (a0=%#llx)\", a0); return 0;",
    "_ZNSt9bad_allocC1Ev": "return a0;",
    "_ZNSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE6insertEmPKcm":
        "return a0;",  # insert returns *this
    "_ZN12QApplicationC2ERiPPci":
        "typedef void (*qt_ctor)(void *, long long, long long, int);"
        " __android_log_print(4, \"RobloxPortQt\","
        " \"QApplication ctor reached argc=%lld\", a1);"
        " void *qt_widgets = dlopen(\"libQt5Widgets_arm64-v8a.so\", 2);"
        " if (!qt_widgets) qt_widgets = dlopen(\"libQt5Widgets.so\", 2);"
        " qt_ctor real_ctor = qt_widgets ? (qt_ctor)dlsym(qt_widgets,"
        " \"_ZN12QApplicationC2ERiPPci\") : 0;"
        " __android_log_print(4, \"RobloxPortQt\","
        " \"QApplication handle=%p real_ctor=%p\", qt_widgets,"
        " (void *)real_ctor);"
        " void *qt_app = port_callocate(1, 4096);"
        " if (real_ctor) real_ctor(qt_app, a1, a2, (int)a3);"
        " return (long long)qt_app;",
    "munmap": "return port_syscall(215, a0, a1, 0, 0, 0, 0);",
    "__cxa_free_exception": "port_deallocate((void *)a0); return 0;",
    "mi_malloc_usable_size":
        "return (long long)malloc_usable_size((void *)a0);",
    # libc++'s bucket-count helper used to be a Java no-op that returned 0;
    # Studio then indexed a zero-sized hash table with a full-width hash.
    "_ZNSt3__112__next_primeEm": (
        "{ unsigned long candidate = (unsigned long)a0;"
        " if (port_next_prime_variant == 2) return 0;"
        " if (candidate <= 2) return 2;"
        " if (port_next_prime_variant == 1) {"
        "   unsigned long capacity = 2;"
        "   while (capacity < candidate) capacity <<= 1;"
        "   return (long long)capacity; }"
        " if ((candidate & 1UL) == 0) candidate++;"
        " for (;;) {"
        "   unsigned long divisor = 3;"
        "   while (divisor * divisor <= candidate) {"
        "     if (candidate % divisor == 0) break;"
        "     divisor += 2; }"
        "   if (divisor * divisor > candidate)"
        "     return (long long)candidate;"
        "   candidate += 2; } }"),
    "mmap":
        "{ unsigned long port_flags = (unsigned long)a3;"
        " long port_fd = (long)a4;"
        " if (port_flags & 0x1000UL) {"
        "   port_flags = (port_flags & ~0x1000UL) | 0x20UL;"
        "   port_fd = -1; }"
        " long result = port_syscall(222, a0, a1, a2,"
        "     port_flags, port_fd, a5);"
        " __android_log_print(4, \"RobloxPortNative\","
        " \"mmap(%#llx,%#llx,%#llx,%#llx->%#lx) -> %#lx from %#lx\","
        " a0, a1, a2, a3, port_flags, (unsigned long)result,"
        " (unsigned long)__builtin_return_address(0));"
        " return result; }",
    "mprotect":
        "{ long result = port_syscall(226, a0, a1, a2, 0, 0, 0);"
        " __android_log_print(4, \"RobloxPortNative\","
        " \"mprotect(%#llx,%#llx,%#llx) -> %#lx\","
        " a0, a1, a2, (unsigned long)result); return result; }",
    "sysconf":
        "{ if ((int)a0 != 29) return -1;"  # only _SC_PAGESIZE matters
        " return 16384; }",  # Apple silicon reports 16 KiB pages
    "_tlv_bootstrap": "return port_tlv_bootstrap_wrapped(a0);",
    "pthread_key_create":
        "return port_key_create((unsigned long)a0, (unsigned long)a1);",
    "pthread_getspecific": "return (long long)port_getspecific((int)a0);",
    "pthread_setspecific":
        "return port_setspecific((int)a0, (void *)a1);",
    "_ZN7QString16fromAscii_helperEPKci":
        "return (long long)qt_string_placeholder;",
    "_ZN16QCoreApplication11setAttributeEN2Qt20ApplicationAttributeEb":
        "marker_attribute = 1; return 0;",
    "_ZN15QGuiApplication35setHighDpiScaleFactorRoundingPolicyEN2Qt32HighDpiScaleFactorRoundingPolicyE":
        "return 0;",
    "_ZN16QCoreApplication18setApplicationNameERK7QString": "return 0;",
    "_ZN16QCoreApplication19setOrganizationNameERK7QString":
        "marker_organization = 1; return 0;",
    "_ZN16QCoreApplication23setOrganizationDomainERK7QString": "return 0;",
    "_ZN16QCoreApplication19setApplicationVersionERK7QString": "return 0;",
    # macOS C memory and string routines reached Studio through generic JNI
    # dispatch, so their no-op bodies left libc++ strings uncopied and every
    # strlen result zero.  Pure computations must be native: these bodies
    # restore the semantics without crossing into Java.
    "memcpy":
        "if (port_mem_native) { port_native_copy((unsigned char *)a0,"
        " (const unsigned char *)a1, (unsigned long)a2); return a0; }"
        " return bridge_call(\"memcpy\", 5, a0, a1, a2, a3);",
    "memmove":
        "if (port_mem_native) { port_native_move((void *)a0,"
        " (const void *)a1, (unsigned long)a2); return a0; }"
        " return bridge_call(\"memmove\", 5, a0, a1, a2, a3);",
    "memset":
        "if (port_mem_native) { port_native_set((void *)a0, (int)a1,"
        " (unsigned long)a2); return a0; }"
        " return bridge_call(\"memset\", 5, a0, a1, a2, a3);",
    "memcmp":
        "if (port_mem_native) return (long long)port_native_memcmp("
        "(const void *)a0, (const void *)a1, (unsigned long)a2);"
        " return bridge_call(\"memcmp\", 5, a0, a1, a2, a3);",
    "memchr":
        "if (port_mem_native) return (long long)port_native_memchr("
        "(const void *)a0, (int)a1, (unsigned long)a2);"
        " return bridge_call(\"memchr\", 5, a0, a1, a2, a3);",
    "strnlen":
        "if (port_mem_native) return (long long)port_native_strnlen("
        "(const char *)a0, (unsigned long)a1);"
        " return bridge_call(\"strnlen\", 5, a0, a1, a2, a3);",
    "strcmp":
        "if (port_mem_native) return (long long)port_native_strcmp("
        "(const char *)a0, (const char *)a1);"
        " return bridge_call(\"strcmp\", 5, a0, a1, a2, a3);",
    "strncmp":
        "if (port_mem_native) return (long long)port_native_strncmp("
        "(const char *)a0, (const char *)a1, (unsigned long)a2);"
        " return bridge_call(\"strncmp\", 5, a0, a1, a2, a3);",
    "strcpy":
        "if (port_mem_native) { char *destination = (char *)a0;"
        " const char *source = (const char *)a1;"
        " while (*source) *destination++ = *source++; *destination = 0;"
        " return a0; }"
        " return bridge_call(\"strcpy\", 5, a0, a1, a2, a3);",
    "strncpy":
        "if (port_mem_native) { char *destination = (char *)a0;"
        " const char *source = (const char *)a1;"
        " unsigned long count = (unsigned long)a2; unsigned long index = 0;"
        " for (; index < count && source[index]; index++)"
        "   destination[index] = source[index];"
        " for (; index < count; index++) destination[index] = 0;"
        " return a0; }"
        " return bridge_call(\"strncpy\", 5, a0, a1, a2, a3);",
    "strcat":
        "if (port_mem_native) { char *destination = (char *)a0;"
        " const char *source = (const char *)a1;"
        " while (*destination) destination++;"
        " while (*source) *destination++ = *source++; *destination = 0;"
        " return a0; }"
        " return bridge_call(\"strcat\", 5, a0, a1, a2, a3);",
    "strncat":
        "if (port_mem_native) { char *destination = (char *)a0;"
        " const char *source = (const char *)a1;"
        " unsigned long count = (unsigned long)a2;"
        " while (*destination) destination++;"
        " for (unsigned long index = 0; index < count && source[index];"
        " index++) destination[index] = source[index];"
        " destination[count] = 0; return a0; }"
        " return bridge_call(\"strncat\", 5, a0, a1, a2, a3);",
    "strstr":
        "if (port_mem_native) return (long long)port_native_strstr("
        "(const char *)a0, (const char *)a1);"
        " return bridge_call(\"strstr\", 5, a0, a1, a2, a3);",
    "strchr":
        "if (port_mem_native) return (long long)port_native_strchr("
        "(const char *)a0, (int)a1);"
        " return bridge_call(\"strchr\", 5, a0, a1, a2, a3);",
    "strrchr":
        "if (port_mem_native) return (long long)port_native_strrchr("
        "(const char *)a0, (int)a1);"
        " return bridge_call(\"strrchr\", 5, a0, a1, a2, a3);",
    "bzero":
        "if (port_mem_native) { port_native_set((void *)a0, 0,"
        " (unsigned long)a1); return 0; }"
        " return bridge_call(\"bzero\", 5, a0, a1, a2, a3);",
    "bcopy":
        "if (port_mem_native) { port_native_copy((unsigned char *)a1,"
        " (const unsigned char *)a0, (unsigned long)a2); return 0; }"
        " return bridge_call(\"bcopy\", 5, a0, a1, a2, a3);",
    "bcmp":
        "if (port_mem_native) return (long long)port_native_memcmp("
        "(const void *)a0, (const void *)a1, (unsigned long)a2);"
        " return bridge_call(\"bcmp\", 5, a0, a1, a2, a3);",
    "memset_pattern16":
        "if (port_mem_native) { unsigned char *destination ="
        " (unsigned char *)a0; const unsigned char *pattern ="
        " (const unsigned char *)a1; unsigned long count = (unsigned long)a2;"
        " for (unsigned long index = 0; index < count; index++)"
        "   destination[index] = pattern[index & 15]; return a0; }"
        " return bridge_call(\"memset_pattern16\", 5, a0, a1, a2, a3);",
    "memset_s":
        "if (port_mem_native) { port_native_set((void *)a0, (int)a2,"
        " (unsigned long)a1); return 0; }"
        " return bridge_call(\"memset_s\", 5, a0, a1, a2, a3);",
    "__memcpy_chk":
        "if (port_mem_native) { port_native_copy((unsigned char *)a0,"
        " (const unsigned char *)a1, (unsigned long)a2); return a0; }"
        " return bridge_call(\"__memcpy_chk\", 5, a0, a1, a2, a3);",
    "__memmove_chk":
        "if (port_mem_native) { port_native_move((void *)a0,"
        " (const void *)a1, (unsigned long)a2); return a0; }"
        " return bridge_call(\"__memmove_chk\", 5, a0, a1, a2, a3);",
    "__memset_chk":
        "if (port_mem_native) { port_native_set((void *)a0, (int)a1,"
        " (unsigned long)a2); return a0; }"
        " return bridge_call(\"__memset_chk\", 5, a0, a1, a2, a3);",
    "__strncpy_chk":
        "if (port_mem_native) { char *destination = (char *)a0;"
        " const char *source = (const char *)a1; unsigned long count ="
        " (unsigned long)a2; unsigned long index = 0;"
        " for (; index < count && source[index]; index++)"
        "   destination[index] = source[index];"
        " for (; index < count; index++) destination[index] = 0;"
        " return a0; }"
        " return bridge_call(\"__strncpy_chk\", 5, a0, a1, a2, a3);",
    "wmemcmp":
        "if (port_mem_native) { const unsigned int *left ="
        " (const unsigned int *)a0; const unsigned int *right ="
        " (const unsigned int *)a1;"
        " for (unsigned long index = 0; index < (unsigned long)a2; index++)"
        "   if (left[index] != right[index])"
        "     return (long long)left[index] - (long long)right[index];"
        " return 0; }"
        " return bridge_call(\"wmemcmp\", 5, a0, a1, a2, a3);",
    # mimalloc bookkeeping: in the converted image these are allocator
    # internals, so a Java dispatch only loses state.  Inert native bodies
    # are the correct behaviour when bionic owns the heap.
    "mi_free_prepare":
        "if (port_mi_native) {"
        "  if (port_ident_count < 20) {"
        "    port_ident_count++;"
        "    __android_log_print(4, \"RobloxPortIdent\","
        "        \"tid=%ld p=%#llx miheap=%#lx pmap=%s\","
        "        gettid(), a0, (unsigned long)port_mi_dummy_heap,"
        "        port_map_of((unsigned long)a0));"
        "  }"
        "  return 0;"
        " }"
        " return bridge_call(\"mi_free_prepare\", 3, a0, a1, a2, a3);",
    "mi_free_prepared":
        "if (port_mi_native) return 0;"
        " return bridge_call(\"mi_free_prepared\", 3, a0, a1, a2, a3);",
    "mi_collect":
        "if (port_mi_native) return 0;"
        " return bridge_call(\"mi_collect\", 3, a0, a1, a2, a3);",
    "mi_option_get":
        "if (port_mi_native) return (long long)port_mi_option_value("
        "(int)a0);"
        " return bridge_call(\"mi_option_get\", 3, a0, a1, a2, a3);",
    "mi_option_set":
        "if (port_mi_native) return 0;"
        " return bridge_call(\"mi_option_set\", 3, a0, a1, a2, a3);",
    "mi_is_in_heap_region":
        "if (port_mi_native) return 0;"
        " return bridge_call(\"mi_is_in_heap_region\", 3, a0, a1, a2, a3);",
    "mi_heap_get_default":
        "if (port_mi_native) return (long long)port_mi_dummy_heap;"
        " return bridge_call(\"mi_heap_get_default\", 3, a0, a1, a2, a3);",
    "mi_malloc_aligned":
        "if (port_mi_native) return (long long)port_allocate("
        "(unsigned long)a1);"
        " return bridge_call(\"mi_malloc_aligned\", 3, a0, a1, a2, a3);",
    "mi_realloc_aligned":
        "if (port_mi_native) return (long long)port_reallocate("
        "(void *)a0, (unsigned long)a2);"
        " return bridge_call(\"mi_realloc_aligned\", 3, a0, a1, a2, a3);",
    "mi_usable_size":
        "if (port_mi_native) return (long long)malloc_usable_size("
        "(void *)a0);"
        " return bridge_call(\"mi_usable_size\", 3, a0, a1, a2, a3);",
    "mi_category_visit_live_bytes_fast":
        "if (port_mi_native) return 0;"
        " return bridge_call(\"mi_category_visit_live_bytes_fast\", 3,"
        " a0, a1, a2, a3);",
    "mi_exchange_category":
        "if (port_mi_native) return 0;"
        " return bridge_call(\"mi_exchange_category\", 3, a0, a1, a2, a3);",
    "mi_exchange_category_masked":
        "if (port_mi_native) return 0;"
        " return bridge_call(\"mi_exchange_category_masked\", 3,"
        " a0, a1, a2, a3);",
    "mi_register_category_thread_done":
        "if (port_mi_native) return 0;"
        " return bridge_call(\"mi_register_category_thread_done\", 3,"
        " a0, a1, a2, a3);",
    "mi_register_output":
        "if (port_mi_native) return 0;"
        " return bridge_call(\"mi_register_output\", 3, a0, a1, a2, a3);",
    "mi_resolve_category":
        "if (port_mi_native) return 0;"
        " return bridge_call(\"mi_resolve_category\", 3, a0, a1, a2, a3);",
    "mi_thread_set_in_threadpool":
        "if (port_mi_native) return 0;"
        " return bridge_call(\"mi_thread_set_in_threadpool\", 3,"
        " a0, a1, a2, a3);",
    # libc++ string queries must return npos (-1), not the Java default 0.
    "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4findEcm":
        "if (port_string_native) return port_cxx_find_char((unsigned long)a0,"
        " (unsigned long)a1, (unsigned long)a2);"
        " return bridge_call(\"_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4findEcm\", 4, a0, a1, a2, a3);",
    "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4findEPKcmm":
        "if (port_string_native) return port_cxx_find_text((unsigned long)a0,"
        " (unsigned long)a1, (unsigned long)a2, (unsigned long)a3);"
        " return bridge_call(\"_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE4findEPKcmm\", 4, a0, a1, a2, a3);",
    "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5rfindEcm":
        "if (port_string_native) return port_cxx_rfind_char((unsigned long)a0,"
        " (unsigned long)a1, (unsigned long)a2);"
        " return bridge_call(\"_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE5rfindEcm\", 4, a0, a1, a2, a3);",
    "_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7compareEPKc":
        "if (port_string_native) return (long long)port_native_strcmp("
        "port_cxx_string_data((unsigned long)a0), (const char *)a1);"
        " return bridge_call(\"_ZNKSt3__112basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEE7compareEPKc\", 4, a0, a1, a2, a3);",
}

# Qt functions returning QString/QByteArray use the AArch64 x8
# indirect-result slot.  The generic long long stubs never wrote it, so
# callers dereferenced whatever x8 happened to hold (0x46 at 0x105b9c0c4).
# These bodies return a 24-byte struct so clang emits the x8 convention.
SRET_BODIES = {
    "_ZNK11QMetaObject2trEPKcS1_i",              # QMetaObject::tr
    "_ZN16QCoreApplication9translateEPKcS1_S1_i",  # QCoreApplication::translate
    "_ZNK7QObject10objectNameEv",                # QObject::objectName
    "_ZNK7QWidget11windowTitleEv",               # QWidget::windowTitle
    "_ZNK7QWidget6toolTipEv",                    # QWidget::toolTip
    "_ZNK7QWidget8statusTipEv",                  # QWidget::statusTip
    "_ZNK6QLabel4textEv",                        # QLabel::text
    "_ZNK15QAbstractButton4textEv",              # QAbstractButton::text
    "_ZNK7QAction4textEv",                        # QAction::text
    "_ZNK7QAction7toolTipEv",                    # QAction::toolTip
    "_ZNK8QVariant8toStringEv",                  # QVariant::toString
    "_ZN7QString6numberEdci",                    # QString::number(double)
    "_ZN7QString6numberEii",                     # QString::number(int)
    "_ZN7QString6numberEji",                     # QString::number(uint)
    "_ZN7QString6numberEli",                     # QString::number(long)
    "_ZN7QString6numberEmi",                     # QString::number(ulong)
    "_ZN7QString6numberExi",                     # QString::number(longlong)
    "_ZN7QString6numberEyi",                     # QString::number(ulonglong)
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
            if name in ("dlopen", "dlsym", "dlclose", "dlerror"):
                continue  # real bionic implementations
            if name in BIONIC_ALLOCATORS:
                continue  # resolve straight to bionic's real heap
            if name in LIBCXX_PROVIDED:
                continue  # real exception ABI from libc++_shared.so
            if name in BIONIC_C_FUNCTIONS:
                continue  # ordinary C runtime from bionic libc
            if name in NATIVE_EXPORTED and name not in FORCE_STUBS:
                continue  # bionic or libc++ already provides this one
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
    Log.i("RobloxPortJNI", name);
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
        "#define _GNU_SOURCE 1",
        "#include <jni.h>", "#include <string.h>", "#include <signal.h>",
        "#include <ucontext.h>",
        "#include <dlfcn.h>", "",
        "/* One fuzz bit: TRUE = plugin started, FALSE = declined. */",
        "#ifndef QT_PLUGIN_RESULT",
        "#define QT_PLUGIN_RESULT JNI_TRUE",
        "#endif", "",
        "extern void *dlsym(void *handle, const char *symbol);",
        "extern void *dlopen(const char *path, int mode);", "",
        "static const char category_name[] = \"RobloxPort\";",
        "static int qt_string_placeholder[4] = {-1, 0, 0, 0};",
        "",
        "/* bionic provides the real heap.  The bridge deliberately does not",
        "   define malloc/calloc/realloc/aligned_alloc/free, so Studio's",
        "   undefined symbols resolve to libc instead of to an arena. */",
        "extern void *malloc(unsigned long size);",
        "extern void *calloc(unsigned long count, unsigned long size);",
        "extern void *realloc(void *address, unsigned long size);",
        "extern void free(void *address);",
        "extern unsigned long malloc_usable_size(void *address);",
        "extern int __android_log_print(int priority, const char *tag,",
        "                               const char *format, ...);",
        "extern long syscall(long number, ...);",
        "static long port_syscall(long number, long p0, long p1, long p2,",
        "                         long p3, long p4, long p5) {",
        "  long result = syscall(number, p0, p1, p2, p3, p4, p5);",
        "  if (result < 0 && result > -4096) return -1;",
        "  return result;", "}", "",
        "extern int gettid(void);",
        "static int (*port_real_snprintf)(char *, unsigned long, const char *, ...);",
        "static long (*port_real_sysconf)(int);",
        "static unsigned long port_fix_arg(unsigned long value, char *buffer) {",
        "  if (value >= 0x10000UL && (value >> 48) != 0UL) {",
        "    unsigned long long inline_value = value;",
        "    for (unsigned int index = 0; index < 8; index++)",
        "      buffer[index] = (char)((inline_value >> (index * 8)) & 0xffU);",
        "    buffer[8] = 0;",
        "    __android_log_print(4, \"RobloxPortStr\",",
        "        \"snprintf arg %#lx inlined\", value);",
        "    return (unsigned long)buffer;", "  }",
        "  return value;", "}",
        "static long long port_snprintf_fixed(long long a0, long long a1,",
        "                                      long long a2, long long a3,",
        "                                      long long a4, long long a5) {",
        "  if (!port_real_snprintf) {",
        "    void *handle = dlopen(\"libc.so\", 0);",
        "    if (handle) port_real_snprintf = (void *)dlsym(handle,",
        "        \"snprintf\");",
        "  }",
        "  if (!port_real_snprintf) return 0;",
        "  char b0[9], b1[9], b2[9];",
        "  return port_real_snprintf((char *)a0, (unsigned long)a1,",
        "      (const char *)a2, (void *)port_fix_arg(a3,b0),",
        "      (void *)port_fix_arg(a4,b1), (void *)port_fix_arg(a5,b2));",
        "}",
        "static unsigned long (*port_real_strlen)(const char *) = 0;",
        "static unsigned long port_measure(const char *address) {",
        "  unsigned long value = (unsigned long)address;",
        "  if (value >= 0x10000UL && (value >> 48) != 0UL) {",
        "    char buffer[9];",
        "    unsigned long long inline_value = value;",
        "    for (unsigned int index = 0; index < 8; index++)",
        "      buffer[index] = (char)((inline_value >> (index * 8)) & 0xffU);",
        "    buffer[8] = 0;",
        "    unsigned long length = 0;",
        "    while (length < 8 && buffer[length] &&",
        "           buffer[length] >= 0x20 && buffer[length] < 0x7f)",
        "      length++;",
        "    __android_log_print(4, \"RobloxPortStr\",",
        "        \"inline strlen %#lx -> %lu\", value, length);",
        "    return length;", "  }",
        "  if (!port_real_strlen) {",
        "    void *handle = dlopen(\"libc.so\", 0);",
        "    if (handle)",
        "      port_real_strlen = (unsigned long (*)(const char *))",
        "          dlsym(handle, \"strlen\");",
        "  }",
        "  return port_real_strlen ? port_real_strlen(address) : 0;", "}",
        "static void (*port_real_free)(void *) = 0;",
        "static void port_release(void *address) {",
        "  unsigned long value = (unsigned long)address;",
        "  if (value < 0x10000UL || (value >> 48) != 0UL) {",
        "    __android_log_print(4, \"RobloxPortFree\",",
        "        \"skip tagged free %#lx\", value);",
        "    return;", "  }",
        "  if (!port_real_free) {",
        "    void *handle = dlopen(\"libc.so\", 0);",
        "    if (handle)",
        "      port_real_free = (void (*)(void *))dlsym(handle, \"free\");",
        "  }",
        "  if (port_real_free) port_real_free(address);", "}",
        "long long vlibc_strlen(long long a0, long long a1, long long a2,",
        "                        long long a3, long long a4, long long a5)",
        "    __asm__(\"vlibc_strlen\");",
        "long long vlibc_strlen(long long a0, long long a1, long long a2,",
        "                        long long a3, long long a4, long long a5) {",
        "  (void)a1;", "  (void)a2;", "  (void)a3;", "  (void)a4;", "  (void)a5;",
        "  return (long long)port_measure((const char *)a0);", "}",
        "long long vlibc_free(long long a0, long long a1, long long a2,",
        "                      long long a3, long long a4, long long a5)",
        "    __asm__(\"vlibc_free\");",
        "long long vlibc_free(long long a0, long long a1, long long a2,",
        "                      long long a3, long long a4, long long a5) {",
        "  (void)a1;", "  (void)a2;", "  (void)a3;", "  (void)a4;", "  (void)a5;",
        "  port_release((void *)a0);", "  return 0;", "}",
        "static unsigned int port_ident_count = 0;",
        "static char port_map_buffer[256];",
        "static unsigned long port_parse_hex(const char *text) {",
        "  unsigned long value = 0;",
        "  int digit;",
        "  while (*text == ' ') text++;",
        "  while ((digit = (*text >= '0' && *text <= '9') ? *text - '0' :",
        "      (*text >= 'a' && *text <= 'f') ? *text - 'a' + 10 :",
        "      (*text >= 'A' && *text <= 'F') ? *text - 'A' + 10 : -1)",
        "      >= 0) {",
        "    value = (value << 4) | (unsigned long)digit;",
        "    text++;", "  }",
        "  return value;", "}",
        "static const char *port_map_of(unsigned long address) {",
        "  FILE *file = fopen(\"/proc/self/maps\", \"r\");",
        "  int found = 0;",
        "  if (!file) return \"no-maps\";",
        "  while (fgets(port_map_buffer, sizeof(port_map_buffer), file)) {",
        "    const char *dash = port_map_buffer;",
        "    unsigned long low = port_parse_hex(port_map_buffer);",
        "    while (*dash && *dash != '-') dash++;",
        "    unsigned long high = *dash ? port_parse_hex(dash + 1) : 0;",
        "    if (address >= low && address < high) { found = 1; break; }",
        "  }",
        "  fclose(file);",
        "  if (!found) return \"unmapped\";",
        "  for (char *cursor = port_map_buffer; *cursor; cursor++)",
        "    if (*cursor == '\\n') { *cursor = 0; break; }",
        "  return port_map_buffer;", "}", "",
        "/* A reservation mapped with no permissions at all (---p) is a",
        "   placeholder that someone forgot to commit.  Grant read and",
        "   write on the whole map so the retried instruction can run, and",
        "   report the map so the producer becomes visible. */",
        "static int port_grant_map_access(unsigned long address) {",
        "  FILE *file = fopen(\"/proc/self/maps\", \"r\");",
        "  char line[512];",
        "  unsigned long low = 0, high = 0;",
        "  int placeholder = 0;",
        "  if (!file) return 0;",
        "  while (fgets(line, sizeof(line), file)) {",
        "    char *cursor = line;",
        "    low = port_parse_hex(cursor);",
        "    while (*cursor && *cursor != 45) cursor++;",
        "    high = *cursor ? port_parse_hex(cursor + 1) : 0;",
        "    if (address >= low && address < high) {",
        "      while (*cursor && *cursor != 32) cursor++;",
        "      while (*cursor == 32) cursor++;",
        "      placeholder = cursor[0] == 45 && cursor[1] == 45 &&",
        "                    cursor[2] == 45;",
        "      break;",
        "    }",
        "  }",
        "  fclose(file);",
        "  if (!placeholder || !low || high <= low) return 0;",
        "  long result = port_syscall(226, low, high - low, 3, 0, 0, 0);",
        "  __android_log_print(4, \"RobloxPortDiag\",",
        "      \"granted read+write %#lx-%#lx for fault at %#lx -> %#lx\",",
        "      low, high, address, (unsigned long)result);",
        "  return result == 0;",
        "}", "",
        "static int port_text_contains(const char *text, const char *needle) {",
        "  if (!text || !needle) return 0;",
        "  unsigned long needle_length = 0;",
        "  while (needle[needle_length]) needle_length++;",
        "  for (const char *cursor = text; *cursor; cursor++) {",
        "    unsigned long index = 0;",
        "    while (index < needle_length && cursor[index] &&",
        "           cursor[index] == needle[index]) index++;",
        "    if (index == needle_length) return 1;",
        "  }",
        "  return 0;",
        "}", "",
        "/* Walk the frame-pointer chain and log every return address with the",
        "   mapping that contains it, so a fault can be attributed to a caller",
        "   rather than only to the frame that touched the bad pointer. */",
        "static void port_log_stack(unsigned long *regs, unsigned long sp) {",
        "  unsigned long frame = regs[29];",
        "  for (int index = 0; index < 20; index++) {",
        "    if (frame < 0x10000UL) break;",
        "    if (frame < sp || frame - sp > 0x400000UL) break;",
        "    if ((frame & 15UL) != 0) break;",
        "    unsigned long next = *(unsigned long *)frame;",
        "    unsigned long ret = *(unsigned long *)(frame + 8);",
        "    __android_log_print(4, \"RobloxPortDiag\",",
        "        \"frame %d fp %#lx ret %#lx map %s\", index, frame, ret,",
        "        port_map_of(ret));",
        "    for (int word = -8; word < 8; word++) {",
        "      unsigned long slot = frame + (unsigned long)(word * 8);",
        "      if (slot < sp) continue;",
        "      __android_log_print(4, \"RobloxPortDiag\",",
        "          \"  f%d[%+d] %#lx\", index, word,",
        "          *(unsigned long *)slot);",
        "    }",
        "    if (next <= frame) break;",
        "    frame = next;",
        "  }",
        "}", "",
        "/* One build, runtime-selected allocator variants for the fuzz sweep.",
        "   0 = bionic heap, 1 = mmap-backed chunks, 2 = bionic + zeroing. */",
        "static int port_allocator_variant = 0;",
        "/* Bucket-count variants: 0 = real next-prime, 1 = next power of two,",
        "   2 = the old Java no-op that returned zero. */",
        "static int port_next_prime_variant = 0;",
        "static int port_init_patch = 0;",
        "/* Guard against pointer-as-length sizes reaching malloc. 0 = pass",
        "   through, 1 = clamp to 4 KiB, 2 = clamp to 1 MiB. */",
        "static int port_alloc_guard = 0;",
        "/* Clamp the libc++ string length at its source. A converted static",
        "   initialiser passes a heap pointer as the length; 0x1000 keeps the",
        "   copy and the stored length inside the allocation. */",
        "static int port_string_fix = 0;",
        "/* macOS libc++ string helpers and C memory primitives used to be",
        "   generic JNI no-ops that returned 0, so strings were never copied",
        "   and lengths were garbage pointers. 0 = old Java no-op,",
        "   1 = native pure-computation implementations. */",
        "static int port_string_native = 0;",
        "/* C memory/string primitives were no-op JNI stubs; making them",
        "   native broke the owning initialiser. Keep them separate",
        "   from the libc++ string helpers. */",
        "static int port_mem_native = 0;",
        "/* 1 = keep mimalloc internals native/inert (default), 0 = old JNI",
        "   dispatch.  Allocating variants still route to bionic. */",
        "static int port_mi_native = 1;",
        "/* Runtime load bias of libRobloxStudio, recorded once by",
        "   resetAndInit so the signal handler need not dlopen. */",
        "static unsigned long port_studio_bias = 0;",
        # Aggregate-returning Qt functions use the x8 indirect-result
        # convention, which the generic long long stubs never wrote.
        "static int port_x8_fix = 1;",
        # General proxy strategy: a small integer/tagged value used as a
        # base register is redirected to a zeroed bionic-heap page.
        # 0 = off, 1 = small-integer bases only, 2 = also redirect
        # macOS tagged/non-canonical pointer values.
        "static int port_proxy_fix = 1;",
        "static const char *port_studio_library =",
        "    \"libRobloxStudio_arm64-v8a.so\";",
        "static unsigned char *port_proxy_pages = 0;",
        "static unsigned long port_proxy_next = 0;",
        "static unsigned int port_proxy_intercepts = 0;",
        "static unsigned long port_proxy_seen_pc[64];",
        "static unsigned int port_proxy_seen_count[64];",
        "static void port_proxy_noop(void) {}",
        "static void *port_proxy_vtable[16] = {",
        "  (void *)port_proxy_noop, (void *)port_proxy_noop,",
        "  (void *)port_proxy_noop, (void *)port_proxy_noop,",
        "  (void *)port_proxy_noop, (void *)port_proxy_noop,",
        "  (void *)port_proxy_noop, (void *)port_proxy_noop,",
        "  (void *)port_proxy_noop, (void *)port_proxy_noop,",
        "  (void *)port_proxy_noop, (void *)port_proxy_noop,",
        "  (void *)port_proxy_noop, (void *)port_proxy_noop,",
        "  (void *)port_proxy_noop, (void *)port_proxy_noop,",
        "  (void *)port_proxy_noop, (void *)port_proxy_noop,",
        "};",
        "static unsigned char port_proxy_objects[64][256];",
        "static unsigned int port_proxy_object_next = 0;",
        "static unsigned long port_proxy_make_object(void) {",
        "  unsigned int index = port_proxy_object_next++ & 63U;",
        "  unsigned char *object = port_proxy_objects[index];",
        "  *(void **)object = port_proxy_vtable;",
        "  return (unsigned long)object;", "}",
        "typedef struct { unsigned long long word0, word1, word2; }",
        "    port_sret_result;",
        "/* Qt 5 QStringData: ref=-1 (shared null), size=0, offset=24. */",
        "static struct { int ref; int size; unsigned int flags; int pad;",
        "                unsigned long long offset; }",
        "    port_qt_empty_qstring_data = {-1, 0, 0, 0, 24};",
        # Load-time undo of an erroneous dyld rebase: a converted static
        # string length was rebased to bias+length, so subtract the bias
        # before the libc++ string constructor uses it as a size.
        "__asm__(\".globl port_string_len_trampoline\\n\"",
        "        \"port_string_len_trampoline:\\n\"",
        "        \"adrp x8, port_studio_bias\\n\"",
        "        \"add x8, x8, :lo12:port_studio_bias\\n\"",
        "        \"ldr x8, [x8]\\n\"",
        "        \"cmp x2, x8\\n\"",
        "        \"b.lo 1f\\n\"",
        "        \"sub x9, x2, x8\\n\"",
        "        \"cmp x9, #0x10000\\n\"",
        "        \"b.hi 1f\\n\"",
        "        \"mov x2, x9\\n\"",
        "        \"1: movz x9, #0x6464\\n\"",
        "        \"add x9, x9, x8\\n\"",
        "        \"br x9\\n\");",
        "extern void port_string_len_trampoline(void);",
        "/* Native logpoints for symbols with no Android equivalent. */",
        "static int port_logpoints = 0;",
        "/* Ordered startup: load Qt, run selected static initialisers,",
        "   pre-set the call-once guard, then call main. */",
        "static int port_ordered_start = 0;",
        "static int port_init_mask = 0;",
        "/* Write a word into Studio's code mapping. mprotect first: the",
        "   converted .text is mapped read-only by the Android linker. */",
        "static void port_patch_word(unsigned long address,",
        "                            unsigned int word) {",
        "  unsigned long page = address & ~0xfffUL;",
        "  long result = port_syscall(226, page, 0x1000, 7, 0, 0, 0);",
        "  *(unsigned int *)address = word;",
        "  __android_log_print(4, \"RobloxPortNative\",",
        "      \"patch %#lx = %#x (mprotect %#lx)\", address, word, result);",
        "}",
        "static void port_apply_init_patch(unsigned long bias) {",
        "  if (port_init_patch == 1) {",
        "    /* Skip the whole static-initializer call in main. */",
        "    port_patch_word(bias + 0x1000025d8UL, 0xd503201fUL);",
        "  } else if (port_init_patch == 2) {",
        "    /* Mark the call-once guard as already complete. */",
        "    unsigned long *guard = (unsigned long *)",
        "        (bias + 0x10c308a80UL);",
        "    *guard = 1;",
        "    __android_log_print(4, \"RobloxPortNative\",",
        "        \"init guard set to 1\");",
        "  } else if (port_init_patch == 3) {",
        "    /* Skip only the third initializer loop (four function calls). */",
        "    port_patch_word(bias + 0x103a68ba4UL, 0xd503201fUL);",
        "  } else if (port_init_patch >= 4 && port_init_patch <= 7) {",
        "    /* Neutralise one static initializer by making it return at once.",
        "       4 = 0x103a7b5cc, 5 = 0x103a7befc, 6 = 0x103a2ac68,",
        "       7 = 0x103ecd034. */",
        "    unsigned long targets[4] = {0x103a7b5ccUL, 0x103a7befcUL,",
        "                                0x103a2ac68UL, 0x103ecd034UL};",
        "    port_patch_word(bias + targets[port_init_patch - 4],",
        "                    0xd65f03c0UL); /* ret */",
        "  }",
        "  if (port_string_fix == 2) {",
        "    long branch_offset = ((long)port_string_len_trampoline",
        "        - (long)(bias + 0x100006458UL)) >> 2;",
        "    port_patch_word(bias + 0x100006458UL,",
        "        0x14000000UL | ((unsigned long)branch_offset & 0x03ffffffUL));",
        "    port_patch_word(bias + 0x10000645cUL, 0xd503201fUL);",
        "    port_patch_word(bias + 0x100006460UL, 0xd503201fUL);",
        "  } else if (port_string_fix == 1) {",
        "    port_patch_word(bias + 0x100006458UL, 0xf140045fUL);",
        "    port_patch_word(bias + 0x10000645cUL, 0x54000043UL);",
        "    port_patch_word(bias + 0x100006460UL, 0xd2820002UL);",
        "  }", "}", "",
        "/* Qt's Java bootstrap normally loads these. Do it natively so the",
        "   ordered path works from a plain Activity as well. */",
        "static void port_load_qt_runtime(void) {",
        "  static const char *names[] = {",
        "    \"libQt5Core_arm64-v8a.so\", \"libQt5Gui_arm64-v8a.so\",",
        "    \"libQt5Widgets_arm64-v8a.so\", \"libQt5Network_arm64-v8a.so\",",
        "    \"libQt5Concurrent_arm64-v8a.so\", \"libQt5Sql_arm64-v8a.so\",",
        "    \"libQt5Xml_arm64-v8a.so\", \"libQt5AndroidExtras_arm64-v8a.so\"};",
        "  for (unsigned int index = 0; index < 8; index++) {",
        "    void *handle = dlopen(names[index], 2);",
        "    __android_log_print(4, \"RobloxPortStart\",",
        "        \"qt load %s -> %p\", names[index], handle);",
        "  }", "}",
        "/* Run only the selected static initialisers, then mark the",
        "   call-once guard complete so main skips its own pass. */",
        "static void port_run_static_inits(unsigned long bias) {",
        "  unsigned long *table = (unsigned long *)",
        "      (bias + 0x10bf5f528UL);",
        "  for (unsigned int index = 0; index < 8; index++) {",
        "    if (!(port_init_mask & (1 << index))) continue;",
        "    unsigned long target = table[index];",
        "    if (!target) continue;",
        "    typedef void (*init_fn)(void);",
        "    __android_log_print(4, \"RobloxPortStart\",",
        "        \"init %u %#lx begin\", index, target);",
        "    ((init_fn)target)();",
        "    __android_log_print(4, \"RobloxPortStart\",",
        "        \"init %u done\", index);",
        "  }",
        "  unsigned long *guard = (unsigned long *)",
        "      (bias + 0x10c308a80UL);",
        "  *guard = 1; /* tbnz old,#0 skips; 1 means already entered */",
        "  __android_log_print(4, \"RobloxPortStart\",",
        "      \"init guard pre-set to 1\");",
        "}", "",
        "static void port_zero(void *address, unsigned long size) {",
        "  unsigned char *bytes = (unsigned char *)address;",
        "  for (unsigned long index = 0; index < size; index++)",
        "    bytes[index] = 0;", "}",
        "static void port_deallocate(void *address) {",
        "  if (!address) return;",
        "  if (port_allocator_variant == 1) {",
        "    unsigned long total = *((unsigned long *)address - 2);",
        "    port_syscall(215, (unsigned long)address - 16, total,",
        "                 0, 0, 0, 0);",
        "    return;", "  }",
        "  free(address);", "}",
        "static void *port_allocate(unsigned long size) {",
        "  if (port_alloc_guard && size > 0x40000000UL) {",
        "    unsigned long clamped = port_alloc_guard == 1 ? 0x1000UL",
        "        : 0x100000UL;",
        "    __android_log_print(4, \"RobloxPortAlloc\",",
        "        \"clamp size=%#lx -> %#lx\", size, clamped);",
        "    size = clamped;", "  }",
        "  if (port_allocator_variant == 1) {",
        "    unsigned long total = (size + 31UL) & ~15UL;",
        "    long address = port_syscall(222, 0, total, 3, 0x22, -1, 0);",
        "    if (address < 0 && address > -4096) return 0;",
        "    *(unsigned long *)address = total;",
        "    return (void *)(address + 16);", "  }",
        "  void *result = malloc(size);",
        "  if (!result || size > 0x40000000UL) {",
        "    __android_log_print(4, \"RobloxPortAlloc\",",
        "        \"malloc size=%#lx lr0=%#lx lr1=%#lx lr2=%#lx lr3=%#lx\",",
        "        size,",
        "        (unsigned long)__builtin_return_address(0),",
        "        (unsigned long)__builtin_return_address(1),",
        "        (unsigned long)__builtin_return_address(2),",
        "        (unsigned long)__builtin_return_address(3));",
        "  }",
        "  if (result && port_allocator_variant == 2) port_zero(result, size);",
        "  return result;", "}",
        "static void *port_callocate(unsigned long count, unsigned long size) {",
        "  unsigned long total = count * size;",
        "  void *result = port_allocate(total);",
        "  if (result) port_zero(result, total);",
        "  return result;", "}",
        "static void *port_reallocate(void *address, unsigned long size) {",
        "  if (port_allocator_variant != 1) return realloc(address, size);",
        "  void *result = port_allocate(size);",
        "  if (address) {",
        "    unsigned long old = *((unsigned long *)address - 2) - 16;",
        "    unsigned long copy = old < size ? old : size;",
        "    if (result && copy) {",
        "      unsigned char *source = (unsigned char *)address;",
        "      unsigned char *target = (unsigned char *)result;",
        "      for (unsigned long index = 0; index < copy; index++)",
        "        target[index] = source[index];", "    }",
        "    port_deallocate(address);", "  }",
        "  return result;", "}", "",
        "/* Thread-local storage for the pthread key stubs.  Studio's STM",
        "   manager keeps its per-thread state behind pthread_getspecific;",
        "   returning 0 unconditionally made its factory re-enter the",
        "   call-once initializer and deadlock. */",
        "static __thread void *port_tls_values[64];",
        "static void (*port_tls_destructors[64])(void *);",
        "static int port_next_key = 1;",
        "static int port_key_create(unsigned long key_pointer,",
        "                           unsigned long destructor) {",
        "  int key = port_next_key++;",
        "  if (key >= 64) return 1;",
        "  if (key_pointer) *(int *)key_pointer = key;",
        "  port_tls_destructors[key] = (void (*)(void *))destructor;",
        "  return 0;", "}",
        "static void *port_getspecific(int key) {",
        "  if (key < 0 || key >= 64) return 0;",
        "  return port_tls_values[key];", "}",
        "static int port_setspecific(int key, void *value) {",
        "  if (key < 0 || key >= 64) return 1;",
        "  port_tls_values[key] = value;",
        "  return 0;", "}", "",
        "/* macOS thread-local variables are reached through _tlv_bootstrap.",
        "   Hand each descriptor a stable per-thread scratch buffer instead of",
        "   returning zero, which made Studio dereference null. */",
        "#define PORT_TLV_SLOTS 128",
        "#define PORT_TLV_SIZE 128",
        "static __thread unsigned char port_tlv_storage[PORT_TLV_SLOTS]"
        "[PORT_TLV_SIZE] __attribute__((aligned(16)));",
        "static int port_tlv_slot_count = PORT_TLV_SLOTS;",
        "long long port_tlv_bootstrap(long long descriptor) {",
        "  unsigned long slot = ((unsigned long)descriptor >> 3)"
        " % (unsigned long)port_tlv_slot_count;",
        "  __android_log_print(4, \"RobloxPortNative\",",
        "      \"_tlv_bootstrap(%#llx) -> %#lx\",",
        "      descriptor, (unsigned long)port_tlv_storage[slot]);",
        "  return (long long)port_tlv_storage[slot];", "}", "",
        "/* Studio's caller keeps its object pointer in x8 across the",
        "   _tlv_bootstrap call; dyld's hand-written bootstrap preserves it.",
        "   Our C helper uses x8 for the thread-local base, so save and",
        "   restore x8 (and the link register) in a tiny trampoline. */",
        "__asm__(\".globl port_tlv_bootstrap_wrapped\\n\"",
        "        \"port_tlv_bootstrap_wrapped:\\n\"",
        "        \"stp x8, x30, [sp, #-16]!\\n\"",
        "        \"bl port_tlv_bootstrap\\n\"",
        "        \"ldp x8, x30, [sp], #16\\n\"",
        "        \"ret\\n\");",
        "extern long long port_tlv_bootstrap_wrapped(long long descriptor);",
        "",
        # Native libc++ string and C memory helpers.  These are pure
        # computations.  A Java no-op left string data uncopied and made
        # libc++ read pointers as lengths; native bodies restore the macOS
        # ABI semantics the converter cannot express.
        "static const char port_zero_byte = 0;",
        "static void port_native_copy(unsigned char *destination,",
        "                             const unsigned char *source,",
        "                             unsigned long count) {",
        "  for (unsigned long index = 0; index < count; index++)",
        "    destination[index] = source[index];", "}",
        "static void port_native_move(void *destination_pointer,",
        "                             const void *source_pointer,",
        "                             unsigned long count) {",
        "  unsigned char *destination = (unsigned char *)destination_pointer;",
        "  const unsigned char *source = (const unsigned char *)source_pointer;",
        "  if (!count || destination == source) return;",
        "  if (destination < source) {",
        "    for (unsigned long index = 0; index < count; index++)",
        "      destination[index] = source[index];",
        "  } else {",
        "    for (unsigned long index = count; index > 0; index--)",
        "      destination[index - 1] = source[index - 1];", "  }", "}",
        "static void port_native_set(void *destination_pointer, int value,",
        "                            unsigned long count) {",
        "  unsigned char *destination = (unsigned char *)destination_pointer;",
        "  unsigned char byte_value = (unsigned char)value;",
        "  for (unsigned long index = 0; index < count; index++)",
        "    destination[index] = byte_value;", "}",
        "static int port_native_memcmp(const void *left_pointer,",
        "                              const void *right_pointer,",
        "                              unsigned long count) {",
        "  const unsigned char *left = (const unsigned char *)left_pointer;",
        "  const unsigned char *right = (const unsigned char *)right_pointer;",
        "  for (unsigned long index = 0; index < count; index++) {",
        "    if (left[index] != right[index])",
        "      return (int)left[index] - (int)right[index];", "  }",
        "  return 0;", "}",
        "static unsigned long port_native_strlen(const char *text) {",
        "  unsigned long length = 0;",
        "  if (!text) return 0;",
        "  while (text[length]) length++;",
        "  return length;", "}",
        "static unsigned long port_native_strnlen(const char *text,",
        "                                         unsigned long maximum) {",
        "  unsigned long length = 0;",
        "  if (!text) return 0;",
        "  while (length < maximum && text[length]) length++;",
        "  return length;", "}",
        "static int port_native_strcmp(const char *left, const char *right) {",
        "  if (!left) left = &port_zero_byte;",
        "  if (!right) right = &port_zero_byte;",
        "  while (*left && *left == *right) { left++; right++; }",
        "  return (int)(unsigned char)*left - (int)(unsigned char)*right;", "}",
        "static int port_native_strncmp(const char *left, const char *right,",
        "                               unsigned long count) {",
        "  if (!left) left = &port_zero_byte;",
        "  if (!right) right = &port_zero_byte;",
        "  for (unsigned long index = 0; index < count; index++) {",
        "    unsigned char first = (unsigned char)left[index];",
        "    unsigned char second = (unsigned char)right[index];",
        "    if (first != second) return (int)first - (int)second;",
        "    if (!first) break;", "  }",
        "  return 0;", "}",
        "static char *port_native_strchr(const char *text, int character) {",
        "  if (!text) return 0;",
        "  for (unsigned long index = 0; ; index++) {",
        "    if ((unsigned char)text[index] == (unsigned char)character)",
        "      return (char *)(text + index);",
        "    if (!text[index]) return 0;", "  }", "}",
        "static char *port_native_strrchr(const char *text, int character) {",
        "  if (!text) return 0;",
        "  char *result = 0;",
        "  for (unsigned long index = 0; ; index++) {",
        "    if ((unsigned char)text[index] == (unsigned char)character)",
        "      result = (char *)(text + index);",
        "    if (!text[index]) break;", "  }",
        "  return result;", "}",
        "static char *port_native_strstr(const char *text, const char *needle) {",
        "  if (!text || !needle) return 0;",
        "  for (unsigned long index = 0; text[index]; index++) {",
        "    unsigned long inner = 0;",
        "    while (needle[inner] && text[index + inner] == needle[inner])",
        "      inner++;",
        "    if (!needle[inner]) return (char *)(text + index);", "  }",
        "  return 0;", "}",
        "static void *port_native_memchr(const void *block, int character,",
        "                                unsigned long count) {",
        "  const unsigned char *bytes = (const unsigned char *)block;",
        "  for (unsigned long index = 0; index < count; index++)",
        "    if (bytes[index] == (unsigned char)character)",
        "      return (void *)(bytes + index);",
        "  return 0;", "}",
        # mimalloc internals are allocator bookkeeping, not macOS system
        # calls with Java semantics.  A JNI no-op for mi_free_prepare leaves
        # freed blocks untracked and the collector spins.  Native bodies
        # keep those internals inert while allocation stays on bionic.
        "static unsigned char port_mi_dummy_heap[256]",
        "    __attribute__((aligned(16)));",
        "static long port_mi_option_value(int option) {",
        "  (void)option;",
        "  return 0;", "}",
        # libc++ basic_string<char>: byte 0x17 high bit set means long.
        # Long stores data at +0, size at +8 and capacity at +0x10;
        # short stores characters at +0 and the size in byte 0x17.
        "#define PORT_STRING_NPOS ((unsigned long)-1)",
        "static unsigned long port_cxx_string_size(unsigned long object) {",
        "  if (!object) return 0;",
        "  unsigned char last = *(unsigned char *)(object + 0x17);",
        "  if (last & 0x80) return *(unsigned long *)(object + 8);",
        "  return (unsigned long)last;", "}",
        "static const char *port_cxx_string_data(unsigned long object) {",
        "  if (!object) return &port_zero_byte;",
        "  unsigned char last = *(unsigned char *)(object + 0x17);",
        "  if (last & 0x80) return *(const char * const *)object;",
        "  return (const char *)object;", "}",
        "static long long port_cxx_find_char(unsigned long object,",
        "                                    unsigned long character,",
        "                                    unsigned long start) {",
        "  unsigned long size = port_cxx_string_size(object);",
        "  const char *data = port_cxx_string_data(object);",
        "  if (start >= size) return (long long)PORT_STRING_NPOS;",
        "  for (unsigned long index = start; index < size; index++)",
        "    if ((unsigned char)data[index] == (unsigned char)character)",
        "      return (long long)index;",
        "  return (long long)PORT_STRING_NPOS;", "}",
        "static long long port_cxx_rfind_char(unsigned long object,",
        "                                     unsigned long character,",
        "                                     unsigned long start) {",
        "  unsigned long size = port_cxx_string_size(object);",
        "  const char *data = port_cxx_string_data(object);",
        "  if (!size) return (long long)PORT_STRING_NPOS;",
        "  unsigned long last = start < size ? start : size - 1;",
        "  for (;;) {",
        "    if ((unsigned char)data[last] == (unsigned char)character)",
        "      return (long long)last;",
        "    if (!last) return (long long)PORT_STRING_NPOS;",
        "    last--;", "  }", "}",
        "static long long port_cxx_find_text(unsigned long object,",
        "                                    unsigned long needle_pointer,",
        "                                    unsigned long start,",
        "                                    unsigned long needle_size) {",
        "  unsigned long size = port_cxx_string_size(object);",
        "  const char *data = port_cxx_string_data(object);",
        "  const char *needle = (const char *)needle_pointer;",
        "  if (start > size) return (long long)PORT_STRING_NPOS;",
        "  unsigned long available = size - start;",
        "  unsigned long count = needle_size < available ? needle_size",
        "      : available;",
        "  if (!needle) return (long long)PORT_STRING_NPOS;",
        "  for (unsigned long index = start; index + count <= size; index++) {",
        "    unsigned long inner = 0;",
        "    while (inner < count && data[index + inner] == needle[inner])",
        "      inner++;",
        "    if (inner == count) return (long long)index;", "  }",
        "  return (long long)PORT_STRING_NPOS;", "}",
        "static int marker_attribute = 0;",
        "static int marker_organization = 0;",
        "static int contains_text(const char *text, const char *needle) {",
        "  int index = 0;", "  while (text[index]) {",
        "    int inner = 0;",
        "    while (needle[inner] && text[index + inner] == needle[inner])",
        "      inner++;",
        "    if (!needle[inner]) return 1;", "    index++;", "  }",
        "  return 0;", "}", "",
        "JNIEXPORT void JNICALL",
        "Java_io_github_robloxport_MainActivity_configurePort(JNIEnv *env,",
        "    jobject thiz, jint allocatorVariant, jint tlvSlots,",
        "    jint nextPrimeVariant, jint initPatch, jint allocGuard,",
        "    jint stringFix, jint logpoints, jint orderedStart,",
        "    jint initMask, jint stringNative, jint miNative,",
        "    jint memNative, jint x8Fix, jint proxyFix, jint tagSkip) {",
        "  (void)env;", "  (void)thiz;",
        "  port_allocator_variant = (allocatorVariant < 0 ||"
        " allocatorVariant > 2) ? 0 : (int)allocatorVariant;",
        "  port_tlv_slot_count = (tlvSlots <= 0 ||"
        " tlvSlots > PORT_TLV_SLOTS) ? PORT_TLV_SLOTS : (int)tlvSlots;",
        "  port_next_prime_variant = (nextPrimeVariant < 0 ||"
        " nextPrimeVariant > 2) ? 0 : (int)nextPrimeVariant;",
        "  port_init_patch = (initPatch < 0 || initPatch > 7)",
        "      ? 0 : (int)initPatch;",
        "  port_alloc_guard = (allocGuard < 0 || allocGuard > 2)",
        "      ? 0 : (int)allocGuard;",
        "  port_string_fix = (stringFix < 0 || stringFix > 2)",
        "      ? 0 : (int)stringFix;",
        "  port_logpoints = logpoints ? 1 : 0;",
        "  port_ordered_start = orderedStart ? 1 : 0;",
        "  port_init_mask = initMask & 0xff;",
        "  port_string_native = stringNative ? 1 : 0;",
        "  port_mi_native = miNative ? 1 : 0;",
        "  port_mem_native = memNative ? 1 : 0;",
        "  port_x8_fix = x8Fix ? 1 : 0;",
        "  port_proxy_fix = (proxyFix < 0 || proxyFix > 10)",
        "      ? 0 : (int)proxyFix;",
        "  port_studio_library = tagSkip",
        "      ? \"libRobloxStudioTag_arm64-v8a.so\"",
        "      : \"libRobloxStudio_arm64-v8a.so\";",
        "  __android_log_print(4, \"RobloxPortNative\",",
        "      \"configurePort variant %d nextPrime %d initPatch %d"
        " allocGuard %d stringFix %d logpoints %d ordered %d mask %#x"
        " native %d x8 %d proxy %d tag %d\",",
        "      (int)port_allocator_variant, (int)port_next_prime_variant,",
        "      (int)port_init_patch, (int)port_alloc_guard,",
        "      (int)port_string_fix, (int)port_logpoints,",
        "      (int)port_ordered_start, (int)port_init_mask,",
        "      (int)port_string_native, (int)port_x8_fix,",
        "      (int)port_proxy_fix, tagSkip ? 1 : 0);", "}",
        "",
        "/* bionic's AArch64 va_list: generic register offsets, floating",
        "   register offset, stack overflow area, register save area. */",
        "struct port_va_list {",
        "  unsigned long gp_offset;",
        "  unsigned long fp_offset;",
        "  void *overflow_arg_area;",
        "  void *reg_save_area;",
        "};", "",
        """\
/* The Darwin formatter calls the resolved bionic function pointer
   instead of an asm-labelled declaration, so no declaration is needed. */

/* Apple's arm64 ABI puts every anonymous argument on the stack, one
   8-byte slot each, so a Darwin va_list is a plain byte pointer into that
   block. bionic's va_list is a struct of register offsets, so a Darwin
   list handed to bionic's vsnprintf makes the formatter read garbage.
   Walk the block here and format each conversion with the type that the
   conversion asks for. */
static void port_write_number(char *target, unsigned int *at,
                              unsigned int limit, long value) {
  char digits[24];
  unsigned int count = 0;
  unsigned int index;
  unsigned long magnitude = value < 0 ? (unsigned long)(-value)
                                      : (unsigned long)value;
  if (value < 0 && *at < limit) target[(*at)++] = '-';
  do {
    digits[count++] = (char)(48 + (int)(magnitude % 10UL));
    magnitude /= 10UL;
  } while (magnitude && count < sizeof(digits));
  for (index = count; index > 0 && *at < limit; index--)
    target[(*at)++] = digits[index - 1];
}

__attribute__((used))
static int port_format_budget = 400;

__attribute__((used))
int port_darwin_snprintf(char *destination, unsigned long capacity,
                         const char *format,
                         const unsigned char *arguments) {
  if (port_format_budget > 0) {
    char short_format[97];
    unsigned int at = 0;
    port_format_budget--;
    while (at < 96 && format && format[at]) {
      short_format[at] = format[at];
      at++;
    }
    short_format[at] = 0;
    __android_log_print(4, "RobloxPortFmt",
        "snprintf cap %lu fmt '%s'", capacity, short_format);
  }
  if (!port_real_snprintf) {
    void *library = dlopen("libc.so", 0);
    if (library) port_real_snprintf = (void *)dlsym(library, "snprintf");
  }
  unsigned long written = 0;
  const unsigned char *slot = arguments;
  char spec[40];
  while (format && *format) {
    const char *cursor;
    unsigned int at = 0;
    unsigned char conversion;
    int produced = 0;
    unsigned long room;
    char *target;
    if (*format != 37) {
      if (written + 1 < capacity) destination[written] = *format;
      written++;
      format++;
      continue;
    }
    cursor = format + 1;
    spec[at++] = 37;
    while (*cursor == 45 || *cursor == 43 || *cursor == 32 ||
           *cursor == 35 || *cursor == 48 || *cursor == 39) {
      if (at < 30) spec[at++] = *cursor;
      cursor++;
    }
    if (*cursor == 42) {
      port_write_number(spec, &at, 34, (long)*(const unsigned long *)slot);
      slot += 8;
      cursor++;
    } else {
      while (*cursor >= 48 && *cursor <= 57) {
        if (at < 30) spec[at++] = *cursor;
        cursor++;
      }
    }
    if (*cursor == 46) {
      if (at < 30) spec[at++] = '.';
      cursor++;
      if (*cursor == 42) {
        port_write_number(spec, &at, 34,
                          (long)*(const unsigned long *)slot);
        slot += 8;
        cursor++;
      } else {
        while (*cursor >= 48 && *cursor <= 57) {
          if (at < 30) spec[at++] = *cursor;
          cursor++;
        }
      }
    }
    while (*cursor == 'h' || *cursor == 'l' || *cursor == 'j' ||
           *cursor == 'z' || *cursor == 't' || *cursor == 'q' ||
           *cursor == 'L') cursor++;
    conversion = (unsigned char)*cursor;
    if (!conversion) break;
    if (port_format_budget > 0) {
      port_format_budget--;
      __android_log_print(4, "RobloxPortFmt",
          "conversion %c slot %#lx", (int)conversion,
          *(const unsigned long *)slot);
    }
    room = written < capacity ? capacity - written : 0;
    target = destination
        ? destination + (written < capacity ? written : capacity - 1)
        : 0;
    switch (conversion) {
      case '%':
        spec[at++] = '%'; spec[at] = 0;
        produced = port_real_snprintf(target, room, spec);
        break;
      case 'd': case 'i':
        spec[at++] = 'l'; spec[at++] = 'l'; spec[at++] = 'd';
        spec[at] = 0;
        produced = port_real_snprintf(target, room, spec,
                                     (long long)*(const long *)slot);
        slot += 8;
        break;
      case 'u': case 'o': case 'x': case 'X':
        spec[at++] = 'l'; spec[at++] = 'l';
        spec[at++] = (char)conversion; spec[at] = 0;
        produced = port_real_snprintf(target, room, spec,
                        (unsigned long long)*(const unsigned long *)slot);
        slot += 8;
        break;
      case 'c':
        spec[at++] = 'c'; spec[at] = 0;
        produced = port_real_snprintf(target, room, spec,
                                     (int)*(const unsigned long *)slot);
        slot += 8;
        break;
      case 's': {
        const char *text = (const char *)*(const unsigned long *)slot;
        slot += 8;
        if (!text) text = "(null)";
        spec[at++] = 's'; spec[at] = 0;
        produced = port_real_snprintf(target, room, spec, text);
        break;
      }
      case 'p': {
        void *pointer = (void *)*(const unsigned long *)slot;
        slot += 8;
        spec[at++] = 'p'; spec[at] = 0;
        produced = port_real_snprintf(target, room, spec, pointer);
        break;
      }
      case 'f': case 'F': case 'e': case 'E':
      case 'g': case 'G': case 'a': case 'A': {
        union { unsigned long bits; double value; } number;
        number.bits = *(const unsigned long *)slot;
        slot += 8;
        spec[at++] = (char)conversion; spec[at] = 0;
        produced = port_real_snprintf(target, room, spec, number.value);
        break;
      }
      case 'n': {
        long *counter = (long *)*(const unsigned long *)slot;
        slot += 8;
        if (counter) *counter = (long)written;
        break;
      }
      default:
        if (written + 1 < capacity) destination[written] = 37;
        written++;
        if (written + 1 < capacity)
          destination[written] = (char)conversion;
        written++;
        break;
    }
    if (produced > 0) written += (unsigned long)produced;
    format = cursor + 1;
  }
  if (destination && capacity) {
    unsigned long last = written < capacity ? written : capacity - 1;
    destination[last] = 0;
  }
  return (int)written;
}
""",
        "static int (*port_real_vsnprintf_traced)(char *, unsigned long,",
        "                                          const char *, void *) = 0;",
        "static int (*port_real_snprintf_varargs)(char *, unsigned long,",
        "                                         const char *, ...) = 0;",
        "static int port_traced_vsnprintf(char *destination, unsigned long size,",
        "                                 const char *format, void *argument) {",
        "  char format_copy[96];",
        "  unsigned int index = 0;",
        "  if (format) {",
        "    while (index < sizeof(format_copy) - 1 && format[index]) {",
        "      format_copy[index] = format[index];",
        "      index++;",
        "    }",
        "  }",
        "  format_copy[index] = 0;",
        "  __android_log_print(4, \"RobloxPortFmt\",",
        "      \"vsnprintf fmt=\\\"%s\\\" size %lu arg %#lx\",",
        "      format_copy, size, (unsigned long)argument);",
        "  if (argument && (unsigned long)argument > 0x10000UL &&",
        "      ((unsigned long)argument >> 48) == 0UL) {",
        "    unsigned long *words = (unsigned long *)argument;",
        "    __android_log_print(4, \"RobloxPortFmt\",",
        "        \"  arg words %#lx %#lx %#lx %#lx %#lx %#lx\",",
        "        words[0], words[1], words[2], words[3], words[4], words[5]);",
        "    for (unsigned int slot = 0; slot < 4; slot++) {",
        "      unsigned long candidate = words[slot];",
        "      if (candidate > 0x10000UL && (candidate >> 48) == 0UL) {",
        "        char copy[97];",
        "        unsigned int at = 0;",
        "        while (at < 96 && ((char *)candidate)[at]) {",
        "          copy[at] = ((char *)candidate)[at]; at++;",
        "        }",
        "        copy[at] = 0;",
        "        __android_log_print(4, \"RobloxPortFmt\",",
        "            \"  word[%u] -> \\\"%s\\\"\", slot, copy);",
        "      }",
        "    }",
        "  }",
        "  /* Studio hands vsnprintf a Darwin-style pointer array in x3;",
        "     bionic reads x3 as its own va_list. Translate the common",
        "     all-pointer case into a real variadic call. */",
        "  if (port_real_snprintf_varargs && argument) {",
        "    unsigned long *values = (unsigned long *)argument;",
        "    unsigned int specifiers = 0;",
        "    for (const char *cursor = format; cursor && *cursor; cursor++)",
        "      if (cursor[0] == '%' && cursor[1] == 's') specifiers++;",
        "    if (specifiers == 2 && values[0] > 0x10000UL &&",
        "        values[1] > 0x10000UL) {",
        "      __android_log_print(4, \"RobloxPortFmt\",",
        "          \"  translated 2 pointer varargs\");",
        "      return port_real_snprintf_varargs(destination, size, format,",
        "          (char *)values[0], (char *)values[1]);",
        "    }",
        "  }",
        "  return port_real_vsnprintf_traced(destination, size, format, argument);",
        "}", "",
        "/* AArch64 has no cacheflush syscall; after rewriting instructions",
        "   the stale lines must be cleaned and invalidated by hand or the",
        "   core keeps executing the old stub. */",
        "static void port_clear_instruction_cache(unsigned long start,",
        "                                         unsigned long end) {",
        "  unsigned long address;",
        "  for (address = start & ~15UL; address < end; address += 16)",
        "    __asm__ __volatile__(\"dc cvau, %0\" : : \"r\"(address) : \"memory\");",
        "  __asm__ __volatile__(\"dsb ish\" : : : \"memory\");",
        "  for (address = start & ~15UL; address < end; address += 16)",
        "    __asm__ __volatile__(\"ic ivau, %0\" : : \"r\"(address) : \"memory\");",
        "  __asm__ __volatile__(\"dsb ish\" : : : \"memory\");",
        "  __asm__ __volatile__(\"isb\" : : : \"memory\");",
        "}", "",
        "static void port_write_branch_stub(unsigned long address,",
        "                                   unsigned long target) {",
        "  unsigned int instructions[5];",
        "  instructions[0] = 0xd2800000U | (unsigned int)((target & 0xffffUL) << 5)",
        "                    | 16U;",
        "  instructions[1] = 0xf2a00000U |",
        "                    (unsigned int)(((target >> 16) & 0xffffUL) << 5) | 16U;",
        "  instructions[2] = 0xf2c00000U |",
        "                    (unsigned int)(((target >> 32) & 0xffffUL) << 5) | 16U;",
        "  instructions[3] = 0xf2e00000U |",
        "                    (unsigned int)(((target >> 48) & 0xffffUL) << 5) | 16U;",
        "  instructions[4] = 0xd61f0200U; /* br x16 */",
        "  for (unsigned int index = 0; index < 5; index++)",
        "    port_patch_word(address + index * 4UL, instructions[index]);",
        "  port_clear_instruction_cache(address, address + 20);", "}", "",
        "/* Studio reaches mmap through a three-instruction trampoline that",
        "   loads a GOT slot.  The GOT slot resolves to bionic, whose flag",
        "   bits differ from Darwin's, so redirect the trampoline to the",
        "   bridge's translating entry point before any initializer runs. */",
        "extern void *port_bridge_mmap(void *, unsigned long, int, int,",
        "                              int, long long) __asm__(\"mmap\");",
        "static void port_hook_mmap(unsigned long bias) {",
        "  unsigned long trampoline = bias + 0x107b8013cUL;",
        "  port_write_branch_stub(trampoline,",
        "                         (unsigned long)port_bridge_mmap);",
        "  __android_log_print(4, \"RobloxPortNative\",",
        "      \"hooked mmap trampoline %#lx -> %p\", trampoline,",
        "      (void *)port_bridge_mmap);", "}", "",
        "static void port_trace_vsnprintf(unsigned long bias) {",
        "  if (port_real_vsnprintf_traced) return;",
        "  void *libc = dlopen(\"libc.so\", 0);",
        "  port_real_vsnprintf_traced =",
        "      (int (*)(char *, unsigned long, const char *, void *))",
        "      dlsym(libc, \"vsnprintf\");",
        "  port_real_snprintf_varargs =",
        "      (int (*)(char *, unsigned long, const char *, ...))",
        "      dlsym(libc, \"snprintf\");",
        "  port_write_branch_stub(bias + 0x107b81e68UL,",
        "                         (unsigned long)port_traced_vsnprintf);",
        "  __android_log_print(4, \"RobloxPortFmt\",",
        "      \"hooked vsnprintf stub %#lx real %p\",",
        "      bias + 0x107b81e68UL, (void *)port_real_vsnprintf_traced);",
        "}", "",
        "/* Resolve the load bias from /proc/self/maps instead of trusting a",
        "   hardcoded symbol offset: the converter may shift the image by a",
        "   page, which silently moved every hardcoded address by 0x1000. */",
        "static unsigned long port_library_bias(const char *path) {",
        "  FILE *file = fopen(\"/proc/self/maps\", \"r\");",
        "  if (!file) return 0;",
        "  char line[512];",
        "  unsigned long found = 0;",
        "  while (fgets(line, sizeof(line), file)) {",
        "    char *cursor = line;",
        "    unsigned long low = port_parse_hex(cursor);",
        "    while (*cursor && *cursor != '-') cursor++;",
        "    if (*cursor) cursor++;",
        "    while (*cursor && *cursor != ' ') cursor++;",
        "    while (*cursor == ' ') cursor++;",
        "    unsigned long file_offset = port_parse_hex(cursor);",
        "    if (file_offset != 0) continue;",
        "    if (port_text_contains(cursor, path)) { found = low; break; }",
        "  }",
        "  fclose(file);",
        "  return found ? found - 0x100000000UL : 0;",
        "}", "",
        "/* The stripped image imports the C++ exception ABI, which bionic",
        "   does not export. The Qt bundle ships the real libc++_shared in",
        "   the same directory as this bridge, so load it globally first. */",
        "/* Return the absolute path of the first mapped file whose name",
        "   contains needle, taken from /proc/self/maps. */",
        "static int port_mapped_path(const char *needle, char *out,",
        "                            unsigned int capacity) {",
        "  FILE *file = fopen(\"/proc/self/maps\", \"r\");",
        "  char line[512];",
        "  int found = 0;",
        "  if (!file) return 0;",
        "  while (fgets(line, sizeof(line), file)) {",
        "    char *hit = strstr(line, needle);",
        "    if (!hit || hit == line || hit[-1] != '/') continue;",
        "    while (hit > line && hit[-1] != 32 && hit[-1] != 9) hit--;",
        "    unsigned int length = 0;",
        "    while (hit[length] && hit[length] != 10 && length + 1 < capacity)",
        "      { out[length] = hit[length]; length++; }",
        "    out[length] = 0;",
        "    found = 1;",
        "    break;",
        "  }",
        "  fclose(file);",
        "  return found;",
        "}", "",
        "/* The stripped image imports the C++ exception ABI, which bionic",
        "   does not export. The Qt bundle ships the real libc++_shared, so",
        "   load it globally before Studio. */",
        "static void port_preload_libcxx(void) {",
        "  char candidate[512];",
        "  void *preloaded = 0;",
        "  if (!port_mapped_path(\"libc++_shared.so\", candidate,",
        "                        (unsigned int)sizeof(candidate))) {",
        "    __android_log_print(4, \"RobloxPortStep\",",
        "        \"preload libc++: not mapped\");",
        "    return;",
        "  }",
        "  preloaded = dlopen(candidate, 2);",
        "  __android_log_print(4, \"RobloxPortStep\",",
        "      \"preload libc++ %s -> %p\", candidate, preloaded);",
        "}", "",


        "JNIEXPORT jlong JNICALL",
        "Java_io_github_robloxport_MainActivity_resetAndInit(JNIEnv *env,",
        "                                                     jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "  port_preload_libcxx();",
        "  void *handle = dlopen(port_studio_library, 1);",
        "  if (!handle) {",
        '    const char *load_error = dlerror();'
        '    __android_log_print(6, "RobloxPortStep", "reset: dlopen failed %s",'
        '        load_error ? load_error : "(no error recorded)");'
        "    return -1;",
        "  }",
        "  void *onload = dlsym(handle, \"JNI_OnLoad\");",
        "  if (!onload) return -2;",
        "  unsigned long bias = port_library_bias(port_studio_library);",
        "  if (!bias) bias = (unsigned long)onload - 0x10e3b9000UL;",
        "  __android_log_print(4, \"RobloxPortStep\",",
        "      \"reset: bias from maps %#lx (onload %p)\", bias, onload);",
        "  port_studio_bias = bias;",
        "  port_trace_vsnprintf(bias);",
        "  port_hook_mmap(bias);",
        "  __android_log_print(4, \"RobloxPortStep\", \"reset: dlopen %p"
        " onload %p bias %#lx\", handle, onload, bias);",
        "  unsigned int *guard = (unsigned int *)(bias + 0x10c2b088cUL);",
        "  unsigned long *slot = (unsigned long *)(bias + 0x10c2b0898UL);",
        "  unsigned long singleton = bias + 0x10c295780UL;",
        "  __android_log_print(4, \"RobloxPortNative\",",
        "      \"bias %#lx guard %#lx slot %#lx singleton %#lx\",",
        "      bias, (unsigned long)guard, (unsigned long)slot, singleton);",
        "  port_apply_init_patch(bias);",
        "  if (port_ordered_start) {",
        "    port_load_qt_runtime();",
        "    port_run_static_inits(bias);",
        "  }",
        "  *guard = 0;",
        "  *slot = singleton;",
        "  /* proxyFix 7 is the experiment where Studio's own main is",
        "     allowed to initialise everything; the hand-built call into",
        "     the call-once block reads its arguments off the stack and",
        "     only works when another Studio frame set that stack up. */",
        "  unsigned long init_result = 0;",
        "  if (port_proxy_fix != 7) {",
        "    typedef unsigned long (*init_fn)(void);",
        "    init_fn init = (init_fn)(bias + 0x1026f7158UL);",
        "    __android_log_print(4, \"RobloxPortStep\","
        " \"reset: calling owning init %#lx\", (unsigned long)init);",
        "    init_result = init();",
        "    __android_log_print(4, \"RobloxPortStep\","
        " \"reset: owning init returned %#lx\", init_result);",
        "  } else {",
        "    __android_log_print(4, \"RobloxPortStep\",",
        "        \"reset: skipping manual init\");",
        "  }",
        "  return (jlong)init_result;", "}", "",
        "JNIEXPORT jint JNICALL",
        "Java_io_github_robloxport_MainActivity_launchStudio(JNIEnv *env,",
        "                                                     jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "  void *handle = dlopen(port_studio_library, 1);",
        "  if (!handle) return -1;",
        "  typedef int (*studio_main)(int, char **);",
        "  studio_main entry = (studio_main)dlsym(handle, \"main\");",
        "  if (!entry) return -2;",
        "  char name[] = \"RobloxStudio\";",
        "  char *arguments[] = {name, 0};",
        "  return entry(1, arguments);", "}", "",
        "JNIEXPORT jint JNICALL",
        "Java_io_github_robloxport_MainActivity_probeSingleton(JNIEnv *env,",
        "                                                      jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "  void *handle = dlopen(port_studio_library, 1);",
        "  if (!handle) return -1;",
        "  void *onload = dlsym(handle, \"JNI_OnLoad\");",
        "  if (!onload) return -2;",
        "  unsigned long bias = (unsigned long)onload - 0x10e3b8000UL;",
        "  unsigned int guard = *(unsigned int *)(bias + 0x10c2b088cUL);",
        "  unsigned long *slot = (unsigned long *)(bias + 0x10c2b0898UL);",
        "  unsigned long object = *slot;",
        "  int result = guard == 2 ? 1 : 0;",
        "  if (object) result |= 2;",
        "  if (object && *(unsigned long *)(object + 8)) result |= 4;",
        "  return result;", "}", "",
        "JNIEXPORT jint JNICALL",
        "Java_io_github_robloxport_MainActivity_globalizeMain(JNIEnv *env,",
        "                                                       jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "  void *handle = dlopen(port_studio_library, 258);",
        "  return handle ? 1 : 0;", "}", "",
        "JNIEXPORT jint JNICALL",
        "Java_io_github_robloxport_MainActivity_markerStatus(JNIEnv *env,",
        "                                                       jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "  return marker_attribute | (marker_organization << 1);", "}", "",
        "/* Diagnostic fault handler.  The bridge defines macOS signal stubs,",
        "   so sigaction()/signal()/raise() resolve to no-ops here.  Install",
        "   the handler with a direct rt_sigaction syscall instead. */",
        "struct port_kernel_sigaction {",
        "  void (*handler)(int, siginfo_t *, void *);",
        "  unsigned long flags;", "  unsigned long mask;", "};",
        "static void port_fault_handler(int, siginfo_t *, void *);",
        "static void port_install_fault_handler(int signal_number) {",
        "  struct port_kernel_sigaction action;",
        "  action.handler = port_fault_handler;",
        "  action.flags = 4; /* SA_SIGINFO */", "  action.mask = 0;",
        "  port_syscall(134, signal_number, (unsigned long)&action, 0,",
        "               8, 0, 0);", "}",
        "static void port_install_fault_handlers(void) {",
        "  port_install_fault_handler(11); /* SIGSEGV */",
        "  port_install_fault_handler(7);  /* SIGBUS */",
        "  port_install_fault_handler(4);  /* SIGILL */",
        "  port_install_fault_handler(6);  /* SIGABRT */", "}",
        "static void port_fault_handler(int signal_number, siginfo_t *info,",
        "                               void *context_pointer) {",
        "  ucontext_t *context = (ucontext_t *)context_pointer;",
        "  unsigned long long *regs = context->uc_mcontext.regs;",
        "  unsigned long object = regs[19];",
        "  /* dlopen/dlsym are not signal-safe and hid earlier faults.  Use",
        "     the bias recorded when resetAndInit linked the library. */",
        "  unsigned long studio_base = port_studio_bias;",
        "  /* dlopen runs the image's initialisers before resetAndInit has",
        "     recorded the bias, so resolve it here or every address below",
        "     is off by the whole load base. */",
        "  if (!studio_base) studio_base = port_library_bias(port_studio_library);",
        "  unsigned long fault_pc = (unsigned long)context->uc_mcontext.pc;",
        "  __android_log_print(4, \"RobloxPortDiag\",",
        "      \"fault sig %d addr %#lx pc_va %#lx lr_va %#lx base %#lx\",",
        "      signal_number, (unsigned long)info->si_addr,",
        "      0x100000000UL + fault_pc - studio_base,",
        "      0x100000000UL + regs[30] - studio_base, studio_base);",
        "  __android_log_print(4, \"RobloxPortDiag\",",
        "      \"fault map %s\", port_map_of(fault_pc));",
        "  __android_log_print(4, \"RobloxPortDiag\",",
        "      \"fault lr map %s\", port_map_of(regs[30]));",
        "  __android_log_print(4, \"RobloxPortDiag\",",
        "      \"fault addr map [%s]\", port_map_of((unsigned long)info->si_addr));",
        "  if (port_proxy_fix == 8 && (signal_number == 11 ||",
        "      signal_number == 7) &&",
        "      port_grant_map_access((unsigned long)info->si_addr))",
        "    return;",
        "  if (studio_base) {",
        "    unsigned int *stub = (unsigned int *)",
        "        (studio_base + 0x107b81e68UL);",
        "    __android_log_print(4, \"RobloxPortDiag\",",
        "        \"stub words %#x %#x %#x %#x %#x\",",
        "        stub[0], stub[1], stub[2], stub[3], stub[4]);",
        "  }",        "  port_log_stack((unsigned long *)regs,",
        "                 (unsigned long)context->uc_mcontext.sp);",
        "  __android_log_print(4, \"RobloxPortDiag\",",
        "      \"fault insn %#x at pc %#lx\",",
        "      *(unsigned int *)fault_pc, fault_pc);",
        "  __android_log_print(4, \"RobloxPortDiag\",",
        "      \"x0=%#llx x1=%#llx x2=%#llx x3=%#llx x4=%#llx x5=%#llx\",",
        "      regs[0], regs[1], regs[2], regs[3], regs[4], regs[5]);",
        "  { unsigned long *held = (unsigned long *)regs[0];",
        "    if (regs[0] > 0x1000UL && (regs[0] >> 48) == 0UL &&",
        "        port_map_of(regs[0])[0])",
        "      __android_log_print(4, \"RobloxPortDiag\",",
        "          \"x0 words %#lx %#lx %#lx %#lx %#lx %#lx\",",
        "          held[0], held[1], held[2], held[3], held[4], held[5]);",
        "  }",
        "  __android_log_print(4, \"RobloxPortDiag\",",
        "      \"x8=%#llx x9=%#llx x16=%#llx x17=%#llx x19=%#lx x20=%#llx\",",
        "      regs[8], regs[9], regs[16], regs[17], object, regs[20]);",
        "  __android_log_print(4, \"RobloxPortDiag\",",
        "      \"x21=%#llx x22=%#llx x23=%#llx x24=%#llx x25=%#llx x26=%#llx\",",
        "      regs[21], regs[22], regs[23], regs[24], regs[25], regs[26]);",
        "  if (object >= 0x1000UL && (object >> 48) == 0UL) {",
        "    unsigned char *bytes = (unsigned char *)object;",
        "    for (unsigned int offset = 0; offset < 0x60; offset += 8) {",
        "      unsigned long word = *(unsigned long *)(bytes + offset);",
        "      __android_log_print(4, \"RobloxPortDiag\",",
        "          \"x19+%#02x = %#lx\", offset, word);", "    }", "  }",
        "  if (regs[0] >= 0x1000UL && (regs[0] >> 48) == 0UL) {",
        "    unsigned char *argument = (unsigned char *)regs[0];",
        "    for (unsigned int offset = 0; offset < 0x40; offset += 8) {",
        "      unsigned long word = *(unsigned long *)(argument + offset);",
        "      __android_log_print(4, \"RobloxPortDiag\",",
        "          \"x0+%#02x = %#lx\", offset, word);", "    }", "  }",
        # A wrongly rebased static value appears at runtime as bias + k,
        # where k is a small original payload.  Undo the rebase generically
        # instead of patching each consumer site.
        "  if (port_proxy_fix == 3 && port_studio_bias &&",
        "      (signal_number == 11 || signal_number == 7)) {",
        "    for (unsigned int index = 0; index < 30; index++) {",
        "      unsigned long value = (unsigned long)regs[index];",
        "      if (value > port_studio_bias &&",
        "          value - port_studio_bias < 0x10000UL) {",
        "        unsigned long corrected = value - port_studio_bias;",
        "        regs[index] = corrected;",
        "        __android_log_print(4, \"RobloxPortProxy\",",
        "            \"unrebase x%u %#lx -> %#lx at pc %#lx\",",
        "            index, value, corrected, fault_pc);",
        "        return;", "      }", "    }", "  }",
        # A thrown exception object whose first field is a small tagged
        # value makes the real __cxa_throw dereference garbage.  The typeinfo
        # passed as the second argument is valid; use it for that field.
        "  if (port_proxy_fix == 4 && signal_number == 11 &&",
        "      regs[0] >= 0x1000UL && regs[1] >= 0x1000UL &&",
        "      *(unsigned long *)regs[0] < 0x10000UL) {",
        "    unsigned long old_value = *(unsigned long *)regs[0];",
        "    *(unsigned long *)regs[0] = regs[1];",
        "    for (unsigned int index = 0; index < 30; index++)",
        "      if ((unsigned long)regs[index] == old_value)",
        "        regs[index] = regs[1];",
        "    __android_log_print(4, \"RobloxPortProxy\",",
        "        \"repaired exception field %#lx -> %#lx\",",
        "        old_value, regs[1]);",
        "    return;", "  }",
        # General interception: if the fault address and the decoded base
        # register are both small, the converted image dereferenced a
        # tagged value as a pointer.  Redirect the base register to a
        # zeroed proxy page and resume instead of patching one site.
        "  if (port_proxy_fix == 5 &&",
        "      (signal_number == 11 || signal_number == 7) &&",
        "      port_proxy_intercepts < 512) {",
        "    unsigned int instruction = *(unsigned int *)fault_pc;",
        "    unsigned int base = (instruction >> 5) & 0x1fU;",
        "    unsigned long old_value = (unsigned long)regs[base];",
        "    if (old_value < 0x10000UL || (old_value >> 48) != 0UL) {",
        "      unsigned long object = port_proxy_make_object();",
        "      regs[base] = object;",
        "      for (unsigned int index = 0; index < 30; index++)",
        "        if (index != base && (unsigned long)regs[index] == old_value)",
        "          regs[index] = object;",
        "      port_proxy_intercepts++;",
        "      __android_log_print(4, \"RobloxPortProxy\",",
        "          \"typed proxy x%u %#lx -> %#lx\",",
        "          base, old_value, object);",
        "      return;", "    }", "  }",
        "  if (port_proxy_fix == 6 &&",
        "      (signal_number == 11 || signal_number == 7) &&",
        "      port_proxy_intercepts < 512) {",
        "    unsigned int instruction = *(unsigned int *)fault_pc;",
        "    unsigned int base = (instruction >> 5) & 0x1fU;",
        "    unsigned long old_value = (unsigned long)regs[base];",
        "    if (old_value < 0x10000UL || (old_value >> 48) != 0UL) {",
        "      unsigned long object = port_proxy_make_object();",
        "      regs[base] = object;",
        "      port_proxy_intercepts++;",
        "      __android_log_print(4, \"RobloxPortProxy\",",
        "          \"stack proxy x%u %#lx -> %#lx\",",
        "          base, old_value, object);",
        "      return;", "    }", "  }",
        "  if (port_proxy_fix == 7 &&",
        "      (signal_number == 11 || signal_number == 7) &&",
        "      port_proxy_intercepts < 512) {",
        "    unsigned int instruction = *(unsigned int *)fault_pc;",
        "    unsigned int base = (instruction >> 5) & 0x1fU;",
        "    unsigned long old_value = (unsigned long)regs[base];",
        "    if (old_value < 0x10000UL || (old_value >> 48) != 0UL) {",
        "      unsigned int slot = (unsigned int)(old_value & 63UL);",
        "      unsigned char *object = port_proxy_objects[slot];",
        "      *(void **)object = port_proxy_vtable;",
        "      regs[base] = (unsigned long)object;",
        "      for (unsigned int index = 0; index < 30; index++)",
        "        if (index != base && (unsigned long)regs[index] == old_value)",
        "          regs[index] = (unsigned long)object;",
        "      port_proxy_intercepts++;",
        "      __android_log_print(4, \"RobloxPortProxy\",",
        "          \"stable proxy x%u %#lx -> %#lx slot %u\",",
        "          base, old_value, (unsigned long)object, slot);",
        "      return;", "    }", "  }",
        "  if (port_proxy_fix == 8 &&",
        "      (signal_number == 11 || signal_number == 7) &&",
        "      port_proxy_intercepts < 512) {",
        "    unsigned int instruction = *(unsigned int *)fault_pc;",
        "    unsigned int base = (instruction >> 5) & 0x1fU;",
        "    unsigned long old_value = (unsigned long)regs[base];",
        "    if (old_value < 0x10000UL || (old_value >> 48) != 0UL) {",
        "      unsigned int slot = (unsigned int)(old_value & 63UL);",
        "      unsigned char *object = port_proxy_objects[slot];",
        "      *(void **)object = port_proxy_vtable;",
        "      regs[base] = (unsigned long)object;",
        "      port_proxy_intercepts++;",
        "      __android_log_print(4, \"RobloxPortProxy\",",
        "          \"stack patch x%u %#lx\",",
        "          base, old_value);",
        "      unsigned long *stack = (unsigned long *)context->uc_mcontext.sp;",
        "      for (unsigned int index = 0; index < 256; index++)",
        "        if (stack[index] == old_value)",
        "          stack[index] = (unsigned long)object;",
        "      return;", "    }", "  }",
        "  if (port_proxy_fix == 9 &&",
        "      (signal_number == 11 || signal_number == 7) &&",
        "      port_proxy_intercepts < 512) {",
        "    unsigned int instruction = *(unsigned int *)fault_pc;",
        "    unsigned int base = (instruction >> 5) & 0x1fU;",
        "    unsigned long old_value = (unsigned long)regs[base];",
        "    if (old_value < 0x10000UL || (old_value >> 48) != 0UL) {",
        "      void *chunk = malloc(256);",
        "      regs[base] = (unsigned long)chunk;",
        "      for (unsigned int index = 0; index < 30; index++)",
        "        if (index != base && (unsigned long)regs[index] == old_value)",
        "          regs[index] = (unsigned long)chunk;",
        "      port_proxy_intercepts++;",
        "      __android_log_print(4, \"RobloxPortProxy\",",
        "          \"heap proxy x%u %#lx -> %p\",",
        "          base, old_value, chunk);",
        "      return;", "    }", "  }",
        "  if (port_proxy_fix == 10 &&",
        "      (signal_number == 11 || signal_number == 7)) {",
        "    unsigned long function = (unsigned long)info->si_addr;",
        "    /* If the fault is inside bionic, skip the offending call by",
        "       returning to its caller. */",
        "    const char *map = port_map_of((unsigned long)fault_pc);",
        "    if (map && port_text_contains(map, \"/bionic/libc.so\")) {",
        "      __android_log_print(4, \"RobloxPortProxy\",",
        "          \"skip libc call at pc %#lx lr %#lx\", fault_pc,",
        "          (unsigned long)regs[30]);",
        "      context->uc_mcontext.pc = regs[30];",
        "      return;", "    }", "  }",
        "  __android_log_print(4, \"RobloxPortProxy\",",
        "      \"handler sig %d fix %d pages %p addr %#lx\",",
        "      signal_number, port_proxy_fix, port_proxy_pages,",
        "      (unsigned long)info->si_addr);",
        "  if (port_proxy_fix && port_proxy_pages &&",
        "      (signal_number == 11 || signal_number == 7) &&",
        "      port_proxy_intercepts < 512) {",
        "    unsigned long fault_addr = (unsigned long)info->si_addr;",
        "    unsigned int instruction = *(unsigned int *)fault_pc;",
        "    unsigned int base = (instruction >> 5) & 0x1fU;",
        "    unsigned long old_value = (unsigned long)regs[base];",
        "    if (!(old_value < 0x10000UL ||",
        "          (old_value >> 48) != 0UL)) {",
        "      for (unsigned int index = 0; index < 30; index++)",
        "        if (regs[index] == fault_addr",
        "            || (regs[index] >> 48) != 0UL) {",
        "          base = index;",
        "          old_value = (unsigned long)regs[index];",
        "          break;", "        }", "    }",
        "    unsigned int opcode = instruction & 0xfc000000UL;",
        "    int is_memory = !((opcode == 0xd6000000UL) ||",
        "                      (opcode == 0x14000000UL) ||",
        "                      (opcode == 0x94000000UL) ||",
        "                      (opcode == 0x34000000UL) ||",
        "                      (opcode == 0xb4000000UL) ||",
        "                      (opcode == 0x54000000UL));",
        "    int small_fault = (fault_addr < 0x10000UL);",
        "    int tagged_fault = ((fault_addr >> 48) != 0UL);",
        "    int eligible = is_memory &&",
        "        (small_fault || (port_proxy_fix >= 2 && tagged_fault));",
        "    if (eligible) {",
        "      unsigned int slot = 0;",
        "      while (slot < 64 && port_proxy_seen_pc[slot] != fault_pc",
        "             && port_proxy_seen_pc[slot] != 0) slot++;",
        "      if (slot >= 64) slot = port_proxy_next % 64;",
        "      port_proxy_seen_pc[slot] = fault_pc;",
        "      if (port_proxy_seen_count[slot] < 4) {",
        "        port_proxy_seen_count[slot]++;",
        "        unsigned long proxy = (unsigned long)(port_proxy_pages",
        "            + ((port_proxy_next++ & 0xffUL) << 12));",
        "        regs[base] = proxy;",
        "        for (unsigned int index = 0; index < 30; index++) {",
        "          unsigned long value = (unsigned long)regs[index];",
        "          if (index != base &&",
        "              (value < 0x10000UL || (value >> 48) != 0UL))",
        "            regs[index] = 0;", "        }",
        "        port_proxy_intercepts++;",
        "        __android_log_print(4, \"RobloxPortProxy\",",
        "            \"intercept pc %#lx sig %d insn %#x reg x%u\"",
        " \" old %#lx addr %#lx -> %#lx count %u\",",
        "            fault_pc, signal_number, instruction, base, old_value,",
        "            fault_addr, proxy, port_proxy_seen_count[slot]);",
        "        return;", "      }", "    }", "  }",
        "  port_syscall(94, 0, 0, 0, 0, 0, 0); /* exit_group */", "}", "",
        "static JavaVM *g_vm;", "static jclass g_bridge;",
        "static jmethodID g_dispatch;", "",
        "static jboolean port_qt_n_0(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "  return 0;", "}", "",
        "static jboolean port_qt_n_1(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "  return 0;", "}", "",
        "static void port_qt_n_2(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_3(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_4(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_5(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static jboolean port_qt_n_6(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "  return 0;", "}", "",
        "static void port_qt_n_7(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_8(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_9(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_10(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_11(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_12(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_13(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_14(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_15(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_16(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static jobject port_qt_n_17(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "  return 0;", "}", "",
        "static void port_qt_n_18(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static jboolean port_qt_n_19(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "  return 0;", "}", "",
        "static void port_qt_n_20(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_21(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_22(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static jboolean port_qt_n_23(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "  return 0;", "}", "",
        "static void port_qt_n_24(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static jboolean port_qt_n_25(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "  return 0;", "}", "",
        "static void port_qt_n_26(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_27(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_28(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_29(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_30(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_31(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_32(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_33(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static jboolean port_qt_n_34(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "  return QT_PLUGIN_RESULT;", "}", "",
        "static void port_qt_n_35(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_36(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_37(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_38(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_39(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_40(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_41(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_42(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static jboolean port_qt_n_43(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "  return 0;", "}", "",
        "static void port_qt_n_44(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "static void port_qt_n_45(JNIEnv *env, jobject thiz) {",
        "  (void)env;", "  (void)thiz;",
        "}", "",
        "jint JNI_OnLoad(JavaVM *vm, void *reserved) {",
        "  (void)reserved;", "  g_vm = vm;",
        "  __android_log_print(4, \"RobloxPortQt\","
        "      \"BRIDGE_V3 JNI_OnLoad entered\");"
        "  if (port_proxy_fix && !port_proxy_pages)",
        "    port_proxy_pages = (unsigned char *)calloc(1, 1 << 20);",
        "  port_install_fault_handlers();",
        "  JNIEnv *env = 0;",
        "  if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_6) != JNI_OK)",
        "    return JNI_VERSION_1_6;",
        "  jclass qt_native = (*env)->FindClass(env,"
        "      \"org/qtproject/qt5/android/QtNative\");"
        "  if (qt_native) {"
        "    static JNINativeMethod methods[] = {"
        "      {(char *)\"dispatchGenericMotionEvent\", (char *)\"(Landroid/view/MotionEvent;)Z\", (void *)port_qt_n_0},"
        "      {(char *)\"dispatchKeyEvent\", (char *)\"(Landroid/view/KeyEvent;)Z\", (void *)port_qt_n_1},"
        "      {(char *)\"fillContextMenu\", (char *)\"(Landroid/view/Menu;)V\", (void *)port_qt_n_2},"
        "      {(char *)\"handleLocationChanged\", (char *)\"(III)V\", (void *)port_qt_n_3},"
        "      {(char *)\"handleOrientationChanged\", (char *)\"(II)V\", (void *)port_qt_n_4},"
        "      {(char *)\"handleRefreshRateChanged\", (char *)\"(F)V\", (void *)port_qt_n_5},"
        "      {(char *)\"isTabletEventSupported\", (char *)\"()Z\", (void *)port_qt_n_6},"
        "      {(char *)\"keyDown\", (char *)\"(IIIZ)V\", (void *)port_qt_n_7},"
        "      {(char *)\"keyUp\", (char *)\"(IIIZ)V\", (void *)port_qt_n_8},"
        "      {(char *)\"keyboardGeometryChanged\", (char *)\"(IIII)V\", (void *)port_qt_n_9},"
        "      {(char *)\"keyboardVisibilityChanged\", (char *)\"(Z)V\", (void *)port_qt_n_10},"
        "      {(char *)\"longPress\", (char *)\"(III)V\", (void *)port_qt_n_11},"
        "      {(char *)\"mouseDown\", (char *)\"(III)V\", (void *)port_qt_n_12},"
        "      {(char *)\"mouseMove\", (char *)\"(III)V\", (void *)port_qt_n_13},"
        "      {(char *)\"mouseUp\", (char *)\"(III)V\", (void *)port_qt_n_14},"
        "      {(char *)\"mouseWheel\", (char *)\"(IIIFF)V\", (void *)port_qt_n_15},"
        "      {(char *)\"onActivityResult\", (char *)\"(IILandroid/content/Intent;)V\", (void *)port_qt_n_16},"
        "      {(char *)\"onBind\", (char *)\"(Landroid/content/Intent;)Landroid/os/IBinder;\", (void *)port_qt_n_17},"
        "      {(char *)\"onClipboardDataChanged\", (char *)\"()V\", (void *)port_qt_n_18},"
        "      {(char *)\"onContextItemSelected\", (char *)\"(IZ)Z\", (void *)port_qt_n_19},"
        "      {(char *)\"onContextMenuClosed\", (char *)\"(Landroid/view/Menu;)V\", (void *)port_qt_n_20},"
        "      {(char *)\"onCreateContextMenu\", (char *)\"(Landroid/view/ContextMenu;)V\", (void *)port_qt_n_21},"
        "      {(char *)\"onNewIntent\", (char *)\"(Landroid/content/Intent;)V\", (void *)port_qt_n_22},"
        "      {(char *)\"onOptionsItemSelected\", (char *)\"(IZ)Z\", (void *)port_qt_n_23},"
        "      {(char *)\"onOptionsMenuClosed\", (char *)\"(Landroid/view/Menu;)V\", (void *)port_qt_n_24},"
        "      {(char *)\"onPrepareOptionsMenu\", (char *)\"(Landroid/view/Menu;)Z\", (void *)port_qt_n_25},"
        "      {(char *)\"quitQtAndroidPlugin\", (char *)\"()V\", (void *)port_qt_n_26},"
        "      {(char *)\"quitQtCoreApplication\", (char *)\"()V\", (void *)port_qt_n_27},"
        "      {(char *)\"runPendingCppRunnables\", (char *)\"()V\", (void *)port_qt_n_28},"
        "      {(char *)\"sendRequestPermissionsResult\", (char *)\"(I[Ljava/lang/String;[I)V\", (void *)port_qt_n_29},"
        "      {(char *)\"setDisplayMetrics\", (char *)\"(IIIIDDDDF)V\", (void *)port_qt_n_30},"
        "      {(char *)\"setNativeActivity\", (char *)\"(Landroid/app/Activity;)V\", (void *)port_qt_n_31},"
        "      {(char *)\"setNativeService\", (char *)\"(Landroid/app/Service;)V\", (void *)port_qt_n_32},"
        "      {(char *)\"setSurface\", (char *)\"(ILjava/lang/Object;II)V\", (void *)port_qt_n_33},"
        "      {(char *)\"startQtAndroidPlugin\", (char *)\"(Ljava/lang/String;Ljava/lang/String;)Z\", (void *)port_qt_n_34},"
        "      {(char *)\"startQtApplication\", (char *)\"()V\", (void *)port_qt_n_35},"
        "      {(char *)\"tabletEvent\", (char *)\"(IIJIIIFFF)V\", (void *)port_qt_n_36},"
        "      {(char *)\"terminateQt\", (char *)\"()V\", (void *)port_qt_n_37},"
        "      {(char *)\"touchAdd\", (char *)\"(IIIZIIFFFF)V\", (void *)port_qt_n_38},"
        "      {(char *)\"touchBegin\", (char *)\"(I)V\", (void *)port_qt_n_39},"
        "      {(char *)\"touchCancel\", (char *)\"(I)V\", (void *)port_qt_n_40},"
        "      {(char *)\"touchEnd\", (char *)\"(II)V\", (void *)port_qt_n_41},"
        "      {(char *)\"updateApplicationState\", (char *)\"(I)V\", (void *)port_qt_n_42},"
        "      {(char *)\"updateNativeActivity\", (char *)\"()Z\", (void *)port_qt_n_43},"
        "      {(char *)\"updateWindow\", (char *)\"()V\", (void *)port_qt_n_44},"
        "      {(char *)\"waitForServiceSetup\", (char *)\"()V\", (void *)port_qt_n_45},"
        "    };"
        "    __android_log_print(4, \"RobloxPortQt\","
        "        \"qt method0 %p method34 %p\","
        "        (void *)methods[0].fnPtr,"
        "        (void *)methods[34].fnPtr);"
        "    int registered = (*env)->RegisterNatives(env, qt_native,"
        "        methods, 46);"
        "    __android_log_print(4, \"RobloxPortQt\","
        "        \"register QtNative -> %d\", registered);"
        "  } else {"
        "    __android_log_print(4, \"RobloxPortQt\","
        "        \"register QtNative -> class not found\");"
        "  }", "",
        "  { /* Qt registers its Java natives from JNI_OnLoad; repeat it now",
        "       that the app class loader is fully available. */",
        "    void *core = dlopen(\"libQt5Core_arm64-v8a.so\", 0);",
        "    if (core) {",
        "      typedef int (*qt_init_fn)(void *, void *);",
        "      qt_init_fn qt_init = (qt_init_fn)dlsym(core,",
        "          \"_ZN16QtAndroidPrivate7initJNIEP7_JavaVMP7_JNIEnv\");",
        "      if (qt_init) {",
        "        int qt_result = qt_init(vm, env);",
        "        __android_log_print(4, \"RobloxPortQt\",",
        "            \"qt initJNI retry -> %d\", qt_result);",
        "      }",
        "    }",
        "  }",
        "  jclass cls = (*env)->FindClass(env, \"io/github/robloxport/Bridge\");",
        "  if (cls) {",
        "    g_bridge = (jclass)(*env)->NewGlobalRef(env, cls);",
        "    g_dispatch = (*env)->GetStaticMethodID(env, g_bridge, \"dispatch\",",
        "        \"(Ljava/lang/String;IJJJJ)J\");", "  }",
        "  return JNI_VERSION_1_6;", "}", "",
        "static long long bridge_call(const char *name, int cat,",
        "                             long long a0, long long a1,",
        "                             long long a2, long long a3) {",
        "  if (port_logpoints) {",
        "    __android_log_print(4, \"RobloxPortLP\",",
        "        \"%s cat=%d a0=%#llx a1=%#llx\", name, cat, a0, a1);",
        "  }",
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
        "  long long result = (long long)(*env)->CallStaticLongMethod(",
        "      env, g_bridge, g_dispatch, jname, (jint)cat, (jlong)a0,",
        "      (jlong)a1, (jlong)a2, (jlong)a3);",
        "  if (((unsigned long long)result >> 48) != 0UL)",
        "    __android_log_print(4, \"RobloxPortTag\",",
        "        \"tagged return from %s = %#llx\", name, result);",
        "  return result;", "}", "",
    ]
    # Darwin arm64 passes every variadic argument on the stack, so the
    # formatter needs the caller's stack pointer at entry.  A C function
    # cannot read it before its own prologue runs, so snprintf is a small
    # assembly thunk instead of a generated C stub.
    lines += [
        '__asm__(".globl snprintf\\n"',
        '        ".type snprintf, %function\\n"',
        '        "snprintf:\\n"',
        '        "  mov x3, sp\\n"',
        '        "  b port_darwin_snprintf\\n");', '',
    ]
    for idx, row in enumerate(rows, 1):
        elf, cat = row[1], CATEGORY_ID.get(row[2], 5)
        if elf in ASM_STUBS:
            continue
        if elf in SRET_BODIES:
            lines += [
                "port_sret_result stub_%d(long long a0, long long a1," % idx,
                "    long long a2, long long a3, long long a4,",
                "    long long a5) __asm__(\"%s\");" % elf,
                "port_sret_result stub_%d(long long a0, long long a1," % idx,
                "    long long a2, long long a3, long long a4,",
                "    long long a5) {",
                "  port_sret_result result = {0, 0, 0};",
                "  if (port_x8_fix) result.word0 =",
                "      (unsigned long long)&port_qt_empty_qstring_data;",
                "  return result;", "}", "",
            ]
            continue
        lines += [
            "long long stub_%d(long long a0, long long a1," % idx,
            "    long long a2, long long a3, long long a4,",
            "    long long a5) __asm__(\"%s\");" % elf,
            "long long stub_%d(long long a0, long long a1," % idx,
            "    long long a2, long long a3, long long a4,",
            "    long long a5) {",
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
    import lief
    elf = lief.ELF.parse(out_so)
    needed = set(str(name) for name in elf.libraries)
    # bionic keeps dlopen/dlsym in libdl.so and __android_log_print in
    # liblog.so; the bridge is linked with -nostdlib and must name them
    # explicitly or ART cannot resolve its undefined symbols when the
    # bridge is the first library loaded into a plain Activity process.
    for library_name in ("libc.so", "libdl.so", "liblog.so"):
        if library_name not in needed:
            elf.add_library(library_name)
    elf.write(out_so)
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
    ap.add_argument("--native-symbols",
                    help="file of names bionic/libc++ already export; those "
                         "imports are left for the loader to bind")
    args = ap.parse_args()
    if not args.inventory and not args.macho:
        ap.error("provide --inventory or --macho")
    if not args.no_compile and not args.bridge_out:
        ap.error("--bridge-out is required unless --no-compile is given")
    if args.native_symbols:
        with open(args.native_symbols) as handle:
            for line in handle:
                name = line.strip()
                if name:
                    NATIVE_EXPORTED.add(name)
        print("jni_stubs: %d native names from %s"
              % (len(NATIVE_EXPORTED), args.native_symbols))
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
