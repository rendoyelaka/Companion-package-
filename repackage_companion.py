#!/usr/bin/env python3
"""
repackage_companion.py

ROOT CAUSE (fully resolved — all three sources):

  CRASH SOURCE 1 — AndroidManifest.xml (FIXED in prior build)
    Binary XML string pool stores package name as UTF-8.
    Patched via same-length byte replacement. Done.

  CRASH SOURCE 2 — classes.dex (FIXED in prior build)
    DEX type descriptors (slash-form) and string literals (dot-form).
    Patched + SHA-1 and Adler32 recomputed. Done.

  CRASH SOURCE 3 — resources.arsc (THIS BUILD)
    RES_TABLE_PACKAGE chunk stores the package name as UTF-16LE
    at a fixed offset within the resource table binary.
    Android's resource manager reads this independently of the manifest.
    Mismatch between arsc package name and manifest package name
    kills the process before the first activity renders.
    Old name: com.android.pictach (UTF-16LE, 38 bytes)
    Location: single occurrence at offset 235296 in resources.arsc.
    Fix: same-length UTF-16LE binary patch. No recompilation needed.

APPROACH — pure binary patch across all three binary artifacts:
  1. aapt detects old package name
  2. Same-length random package name generated (critical for binary offset safety)
  3. AndroidManifest.xml  — UTF-8 binary patch
  4. classes.dex          — UTF-8 slash-form + dot-form patch, SHA-1 + Adler32 recomputed
  5. resources.arsc       — UTF-16LE binary patch (RES_TABLE_PACKAGE name field)
  6. All other DEX files  — same patch as classes.dex (multi-dex support)
  7. APK repacked, zipaligned, signed v2+v3
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
    All three binary artifacts use length-sensitive storage:
      - Manifest: UTF-8 length-prefixed string pool
      - DEX:      UTF-8 length-prefixed string pool
      - ARSC:     UTF-16LE fixed-width name field
    Different length corrupts chunk offsets in all three.
    """
    target_len = len(old_pkg)
    seg_total = target_len - 5  # "com" + "." + "."
    if seg_total < 2:
        raise RuntimeError(f"Package too short to randomize safely: {old_pkg}")
    seg1 = seg_total // 2
    seg2 = seg_total - seg1
    def seg(n): return ''.join(random.choices(string.ascii_lowercase, k=n))
    new_pkg = f"com.{seg(seg1)}.{seg(seg2)}"
    assert len(new_pkg) == target_len, f"Length mismatch: {len(new_pkg)} != {target_len}"
    print(f"[OK] New package: {new_pkg} (len={len(new_pkg)}) — exact length confirmed")
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


def patch_manifest(data, old_pkg, new_pkg):
    """UTF-8 binary patch on AndroidManifest.xml binary XML string pool."""
    old_b = old_pkg.encode('utf-8')
    new_b = new_pkg.encode('utf-8')
    assert len(old_b) == len(new_b)
    count = data.count(old_b)
    result = data.replace(old_b, new_b)
    print(f"[OK] Manifest: {count} occurrences patched")
    return result


def patch_dex(data, old_pkg, new_pkg):
    """
    UTF-8 patch on DEX string pool — both slash-form (type descriptors)
    and dot-form (string literals). Recomputes SHA-1 and Adler32 after patch.
    """
    dex = bytearray(data)

    old_slash = old_pkg.replace('.', '/').encode('utf-8')
    new_slash = new_pkg.replace('.', '/').encode('utf-8')
    old_dot   = old_pkg.encode('utf-8')
    new_dot   = new_pkg.encode('utf-8')

    assert len(old_slash) == len(new_slash)
    assert len(old_dot)   == len(new_dot)

    slash_count = 0
    pos = 0
    while True:
        p = bytes(dex).find(old_slash, pos)
        if p == -1: break
        dex[p:p+len(old_slash)] = new_slash
        slash_count += 1
        pos = p + 1

    dot_count = 0
    pos = 0
    while True:
        p = bytes(dex).find(old_dot, pos)
        if p == -1: break
        dex[p:p+len(old_dot)] = new_dot
        dot_count += 1
        pos = p + 1

    # Recompute SHA-1: covers bytes[32:]
    sha1 = hashlib.sha1(bytes(dex[32:])).digest()
    dex[12:32] = sha1

    # Recompute Adler32: covers bytes[12:]
    adler = zlib.adler32(bytes(dex[12:])) & 0xFFFFFFFF
    struct.pack_into('<I', dex, 8, adler)

    remaining = bytes(dex).count(old_slash) + bytes(dex).count(old_dot)
    if remaining > 0:
        raise RuntimeError(f"DEX patch incomplete — {remaining} old strings remain")

    print(f"[OK] DEX: {slash_count} slash-form + {dot_count} dot-form patched, checksums recomputed")
    return bytes(dex)


def patch_arsc(data, old_pkg, new_pkg):
    """
    UTF-16LE patch on resources.arsc RES_TABLE_PACKAGE name field.
    Android's resource manager reads this independently of the manifest.
    Mismatch between arsc package name and manifest = crash before first activity.
    Same-length constraint: UTF-16LE encodes each char as 2 bytes,
    so same char-length pkg = same byte-length = safe patch.
    """
    old_utf16 = old_pkg.encode('utf-16-le')
    new_utf16 = new_pkg.encode('utf-16-le')
    assert len(old_utf16) == len(new_utf16), \
        f"UTF-16LE length mismatch: {len(old_utf16)} != {len(new_utf16)}"

    count = data.count(old_utf16)
    if count == 0:
        print(f"[SKIP] resources.arsc: old package name not found in UTF-16LE — already clean or different encoding")
        return data

    result = data.replace(old_utf16, new_utf16)
    print(f"[OK] resources.arsc: {count} UTF-16LE occurrence(s) patched")
    return result


def binary_patch_apk(old_pkg, new_pkg):
    """
    Repack APK with all three binary artifacts patched:
      - AndroidManifest.xml  (UTF-8)
      - classes.dex + multidex (UTF-8 + checksum recompute)
      - resources.arsc        (UTF-16LE)
    All other files carried byte-for-byte with original compression type.
    """
    tmp_apk = OUTPUT_APK + ".tmp"

    with zipfile.ZipFile(INPUT_APK, 'r') as zin:
        with zipfile.ZipFile(tmp_apk, 'w', allowZip64=True) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)

                if item.filename == 'AndroidManifest.xml':
                    data = patch_manifest(data, old_pkg, new_pkg)

                elif item.filename.startswith('classes') and item.filename.endswith('.dex'):
                    data = patch_dex(data, old_pkg, new_pkg)

                elif item.filename == 'resources.arsc':
                    data = patch_arsc(data, old_pkg, new_pkg)

                zout.writestr(item, data, compress_type=item.compress_type)

    print(f"[OK] APK repacked — manifest + dex + arsc all patched")
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


def verify_no_old_pkg(old_pkg):
    """Final sanity check — scan every file in output APK for old package name."""
    old_utf8  = old_pkg.encode('utf-8')
    old_utf16 = old_pkg.encode('utf-16-le')
    found = []
    with zipfile.ZipFile(OUTPUT_APK) as z:
        for item in z.infolist():
            data = z.read(item.filename)
            if old_utf8 in data or old_utf16 in data:
                found.append(item.filename)
    if found:
        raise RuntimeError(f"Old package still present in: {found}")
    print(f"[OK] Full scan clean — old package name gone from all files")


if __name__ == "__main__":
    try:
        print("\n=== Step 1: Keystore ===")
        generate_keystore()

        print("\n=== Step 2: Detect Package Name ===")
        old_pkg = detect_package()

        print("\n=== Step 3: Generate Same-Length New Package Name ===")
        new_pkg = same_length_random_package(old_pkg)

        print("\n=== Step 4: Binary Patch APK (Manifest + DEX + ARSC) ===")
        tmp_apk = binary_patch_apk(old_pkg, new_pkg)

        print("\n=== Step 5: Align ===")
        aligned_apk = align(tmp_apk)

        print("\n=== Step 6: Sign ===")
        sign(aligned_apk)

        print("\n=== Step 7: Verify Signature ===")
        verify()

        print("\n=== Step 8: Full Scan — No Old Package Remaining ===")
        verify_no_old_pkg(old_pkg)

        print(f"\n[DONE] Package: {old_pkg} → {new_pkg}")
        print(f"[DONE] Install and open: {OUTPUT_APK}")

    except Exception as e:
        error_msg = traceback.format_exc()
        print(f"\n[ERROR] {e}")
        with open(ERROR_LOG, "w") as f:
            f.write(error_msg)
        print(f"[LOG] Error saved: {ERROR_LOG}")
        sys.exit(1)
