#!/usr/bin/env python3
"""
repackage_companion.py

ROOT CAUSE (fully resolved):
  Previous builds only patched AndroidManifest.xml.
  classes.dex still contained 81 occurrences of the old package path:
    - 73x slash-form: com/android/pictach  (DEX type descriptors)
    -  8x dot-form:   com.android.pictach  (string literals)
  Android loads class com.android.pictach.App — finds no such class
  because the manifest says com.vjmiiau.fteqlji.App. Immediate crash.

  Additionally: DEX binary patch requires recomputing:
    - SHA-1 signature  (bytes 12-31 of DEX header, covers bytes[32:])
    - Adler32 checksum (bytes 8-11  of DEX header, covers bytes[12:])
  Without recomputation: dexopt rejects the DEX on load.

APPROACH — pure binary patch, no apktool, no recompilation:
  1. aapt detects old package name
  2. Same-length random package name generated (critical — binary offsets stay valid)
  3. AndroidManifest.xml patched in-memory (binary XML string pool)
  4. classes.dex patched in-memory (slash-form + dot-form)
  5. DEX SHA-1 + Adler32 recomputed after patch
  6. APK repacked preserving all compression types
  7. zipalign + apksigner v2+v3
"""

import os
import sys
import struct
import hashlib
import zlib
import zipfile
import random
import string
import subprocess
import traceback
import re

INPUT_APK  = "companion.apk"
OUTPUT_APK = "companion_repackaged.apk"
KEYSTORE   = "test_companion.jks"
KS_ALIAS   = "companion_key"
KS_PASS    = "companion1234"
KEY_PASS   = "companion1234"
ERROR_LOG  = "build_error.log"
MIN_SDK    = "28"


def run(cmd, check=True):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout.strip():
        print(result.stdout.strip())
    if result.stderr.strip():
        print(result.stderr.strip())
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}\n{result.stderr}")
    return result


def detect_package():
    result = run(["aapt", "dump", "badging", INPUT_APK])
    match = re.search(r"package: name='([^']+)'", result.stdout)
    if not match:
        raise RuntimeError("Could not detect package name from APK")
    pkg = match.group(1)
    print(f"[OK] Detected package: {pkg} (len={len(pkg)})")
    return pkg


def same_length_random_package(old_pkg):
    """
    New package name MUST be identical byte length to old_pkg.
    Binary manifest and DEX string pool entries are length-prefixed.
    Different length = corrupted offsets = parse failure or crash.
    """
    target_len = len(old_pkg)
    seg_total = target_len - 5  # subtract "com" + "." + "."
    if seg_total < 2:
        raise RuntimeError(f"Package too short to randomize: {old_pkg}")
    seg1 = seg_total // 2
    seg2 = seg_total - seg1
    def seg(n): return ''.join(random.choices(string.ascii_lowercase, k=n))
    new_pkg = f"com.{seg(seg1)}.{seg(seg2)}"
    assert len(new_pkg) == target_len, f"Length mismatch: {len(new_pkg)} != {target_len}"
    print(f"[OK] New package: {new_pkg} (len={len(new_pkg)}) — exact length match confirmed")
    return new_pkg


def generate_keystore():
    if os.path.exists(KEYSTORE):
        print(f"[SKIP] Keystore exists: {KEYSTORE}")
        return
    run([
        "keytool", "-genkeypair",
        "-keystore", KEYSTORE,
        "-alias",    KS_ALIAS,
        "-keyalg",   "RSA",
        "-keysize",  "2048",
        "-validity", "365",
        "-storepass", KS_PASS,
        "-keypass",   KEY_PASS,
        "-dname", "CN=Companion, OU=Dev, O=Nova, L=Test, S=Test, C=US",
        "-storetype", "JKS"
    ])
    print(f"[OK] Keystore generated: {KEYSTORE}")


def patch_dex(dex_bytes, old_pkg, new_pkg):
    """
    Patch all package name occurrences in DEX binary.
    DEX uses two forms:
      - Slash-form: com/android/pictach  (type descriptors: Lcom/pkg/Class;)
      - Dot-form:   com.android.pictach  (string literals, BuildConfig, etc.)
    After patching, recompute:
      - SHA-1 signature  at bytes[12:32] covering bytes[32:]
      - Adler32 checksum at bytes[8:12]  covering bytes[12:]
    Both are validated by Android's dexopt — mismatch = crash on class load.
    """
    dex = bytearray(dex_bytes)

    old_slash = old_pkg.replace('.', '/').encode('utf-8')
    new_slash = new_pkg.replace('.', '/').encode('utf-8')
    old_dot   = old_pkg.encode('utf-8')
    new_dot   = new_pkg.encode('utf-8')

    assert len(old_slash) == len(new_slash), "Slash-form length mismatch"
    assert len(old_dot)   == len(new_dot),   "Dot-form length mismatch"

    slash_count = 0
    pos = 0
    while True:
        p = bytes(dex).find(old_slash, pos)
        if p == -1:
            break
        dex[p:p+len(old_slash)] = new_slash
        slash_count += 1
        pos = p + 1

    dot_count = 0
    pos = 0
    while True:
        p = bytes(dex).find(old_dot, pos)
        if p == -1:
            break
        dex[p:p+len(old_dot)] = new_dot
        dot_count += 1
        pos = p + 1

    print(f"[OK] DEX patched: {slash_count} slash-form + {dot_count} dot-form occurrences")

    # Recompute SHA-1: covers bytes[32:]
    sha1 = hashlib.sha1(bytes(dex[32:])).digest()
    dex[12:32] = sha1

    # Recompute Adler32: covers bytes[12:]
    adler = zlib.adler32(bytes(dex[12:])) & 0xFFFFFFFF
    struct.pack_into('<I', dex, 8, adler)

    print(f"[OK] DEX header recomputed — SHA-1: {sha1.hex()[:16]}... Adler32: 0x{adler:08x}")

    # Verify clean
    remaining = bytes(dex).count(old_slash) + bytes(dex).count(old_dot)
    if remaining > 0:
        raise RuntimeError(f"DEX patch incomplete — {remaining} old strings remain")

    return bytes(dex)


def patch_manifest(manifest_bytes, old_pkg, new_pkg):
    """
    Binary XML string pool patch.
    Same-length replacement keeps all chunk offset tables valid.
    """
    old_bytes = old_pkg.encode('utf-8')
    new_bytes = new_pkg.encode('utf-8')
    assert len(old_bytes) == len(new_bytes), "Manifest patch length mismatch"

    count = manifest_bytes.count(old_bytes)
    patched = manifest_bytes.replace(old_bytes, new_bytes)
    print(f"[OK] Manifest patched: {count} occurrences")
    return patched


def binary_patch_apk(old_pkg, new_pkg):
    """
    Repack APK with patched AndroidManifest.xml and classes.dex.
    All other files carried through byte-for-byte with original compression.
    """
    tmp_apk = OUTPUT_APK + ".tmp"

    with zipfile.ZipFile(INPUT_APK, 'r') as zin:
        with zipfile.ZipFile(tmp_apk, 'w', allowZip64=True) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)

                if item.filename == 'AndroidManifest.xml':
                    data = patch_manifest(data, old_pkg, new_pkg)

                elif item.filename == 'classes.dex':
                    data = patch_dex(data, old_pkg, new_pkg)

                elif item.filename.startswith('classes') and item.filename.endswith('.dex'):
                    # Multi-dex: patch all DEX files
                    data = patch_dex(data, old_pkg, new_pkg)

                zout.writestr(item, data, compress_type=item.compress_type)

    print(f"[OK] APK repacked")
    return tmp_apk


def align(input_apk):
    aligned = OUTPUT_APK + ".aligned"
    run(["zipalign", "-v", "-f", "4", input_apk, aligned])
    os.remove(input_apk)
    print("[OK] Aligned")
    return aligned


def sign(input_apk):
    run([
        "apksigner", "sign",
        "--ks", KEYSTORE,
        "--ks-key-alias", KS_ALIAS,
        "--ks-pass", f"pass:{KS_PASS}",
        "--key-pass", f"pass:{KEY_PASS}",
        "--min-sdk-version", MIN_SDK,
        "--out", OUTPUT_APK,
        input_apk
    ])
    os.remove(input_apk)
    print(f"[OK] Signed → {OUTPUT_APK}")


def verify():
    result = run(["apksigner", "verify", "--verbose", OUTPUT_APK], check=False)
    if result.returncode == 0:
        print("[OK] Signature verified")
    else:
        print("[WARN] Signature verify failed")


if __name__ == "__main__":
    try:
        print("\n=== Step 1: Keystore ===")
        generate_keystore()

        print("\n=== Step 2: Detect Package Name ===")
        old_pkg = detect_package()

        print("\n=== Step 3: Generate Same-Length New Package Name ===")
        new_pkg = same_length_random_package(old_pkg)

        print("\n=== Step 4: Binary Patch APK (Manifest + DEX) ===")
        tmp_apk = binary_patch_apk(old_pkg, new_pkg)

        print("\n=== Step 5: Align ===")
        aligned_apk = align(tmp_apk)

        print("\n=== Step 6: Sign ===")
        sign(aligned_apk)

        print("\n=== Step 7: Verify ===")
        verify()

        print(f"\n[DONE] Package: {old_pkg} → {new_pkg}")
        print(f"[DONE] Install and open: {OUTPUT_APK}")

    except Exception as e:
        error_msg = traceback.format_exc()
        print(f"\n[ERROR] {e}")
        with open(ERROR_LOG, "w") as f:
            f.write(error_msg)
        print(f"[LOG] Error saved: {ERROR_LOG}")
        sys.exit(1)
