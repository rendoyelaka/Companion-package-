#!/usr/bin/env python3
"""
repackage_companion.py

ROOT CAUSE FIX:
  Previous approach used apktool decode + rebuild which:
  1. Lost 1155 bytes from the binary manifest (truncated string pool)
  2. Generated longer package names that corrupted binary manifest chunk offsets
  
  CORRECT APPROACH — pure binary patch:
  1. Detect old package name via aapt (no decode needed)
  2. Generate new package name with IDENTICAL byte length
  3. Binary-patch AndroidManifest.xml directly inside the APK (no recompilation)
  4. Repack ZIP preserving all compression levels and file order
  5. Re-sign with apksigner v2+v3

  No apktool. No rebuild. No resource recompilation. Manifest chunk sizes stay intact.
"""

import os
import sys
import shutil
import random
import string
import struct
import zipfile
import subprocess
import traceback
import re
import tempfile

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
    Generate random package name with IDENTICAL byte length to old_pkg.
    Binary manifest stores strings with length-prefixed UTF-8.
    Different length = corrupted chunk offsets = parse failure.
    Format: com.XXXXXXX.XXXXXXX where total length matches exactly.
    """
    target_len = len(old_pkg)
    # com. = 4 chars, one dot separator = 1 char, two segments = target - 5
    seg_total = target_len - 5  # subtract "com." + "."
    if seg_total < 2:
        raise RuntimeError(f"Package name too short to randomize safely: {old_pkg}")
    seg1 = seg_total // 2
    seg2 = seg_total - seg1
    def seg(n): return ''.join(random.choices(string.ascii_lowercase, k=n))
    new_pkg = f"com.{seg(seg1)}.{seg(seg2)}"
    assert len(new_pkg) == target_len, f"Length mismatch: {len(new_pkg)} != {target_len}"
    print(f"[OK] New package: {new_pkg} (len={len(new_pkg)}) — exact length match")
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


def binary_patch_apk(old_pkg, new_pkg):
    """
    Binary-patch the APK without recompilation:
    1. Read every file from the original APK
    2. For AndroidManifest.xml: replace old_pkg bytes with new_pkg bytes
    3. Repack into new ZIP preserving compression type per entry
    4. No alignment here — zipalign runs after
    """
    old_bytes = old_pkg.encode('utf-8')
    new_bytes = new_pkg.encode('utf-8')
    assert len(old_bytes) == len(new_bytes), "Package byte lengths must match"

    tmp_apk = OUTPUT_APK + ".tmp"
    patched_count = 0

    with zipfile.ZipFile(INPUT_APK, 'r') as zin:
        with zipfile.ZipFile(tmp_apk, 'w', allowZip64=True) as zout:
            for item in zin.infolist():
                data = zin.read(item.filename)

                if item.filename == 'AndroidManifest.xml':
                    before = data.count(old_bytes)
                    data = data.replace(old_bytes, new_bytes)
                    after = data.count(new_bytes)
                    patched_count = before
                    print(f"[OK] AndroidManifest.xml: patched {before} occurrences")

                # Preserve original compression type exactly
                zout.writestr(item, data, compress_type=item.compress_type)

    print(f"[OK] APK repacked — {patched_count} package name patches applied")
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
        print("[WARN] Signature verify failed — check manually")


if __name__ == "__main__":
    try:
        print("\n=== Step 1: Keystore ===")
        generate_keystore()

        print("\n=== Step 2: Detect Package Name ===")
        old_pkg = detect_package()

        print("\n=== Step 3: Generate Same-Length New Package Name ===")
        new_pkg = same_length_random_package(old_pkg)

        print("\n=== Step 4: Binary Patch APK ===")
        tmp_apk = binary_patch_apk(old_pkg, new_pkg)

        print("\n=== Step 5: Align ===")
        aligned_apk = align(tmp_apk)

        print("\n=== Step 6: Sign ===")
        sign(aligned_apk)

        print("\n=== Step 7: Verify ===")
        verify()

        print(f"\n[DONE] Package: {old_pkg} → {new_pkg}")
        print(f"[DONE] Install: {OUTPUT_APK}")

    except Exception as e:
        error_msg = traceback.format_exc()
        print(f"\n[ERROR] {e}")
        with open(ERROR_LOG, "w") as f:
            f.write(error_msg)
        print(f"[LOG] Error saved: {ERROR_LOG}")
        sys.exit(1)
