#!/usr/bin/env python3
"""
repackage_companion.py — FINAL DEFINITIVE VERSION

COMPLETE EXHAUSTIVE SCAN RESULTS (from original companion.apk):
================================================================

BINARY PATCH TARGETS — ALL locations, ALL encodings:

AndroidManifest.xml (UTF-8 binary XML string pool):
  com.android.pictach                           [len=19]
  com.android.pictach.RC                        [len=22]
  com.android.pictach.Api                       [len=23]
  com.android.pictach.App                       [len=23]
  com.android.pictach.com                       [len=23]
  com.android.pictach.Upme                      [len=24]
  com.android.pictach.love                      [len=24]
  com.android.pictach.video                     [len=25]
  com.android.pictach.LoveApi                   [len=27]
  com.android.pictach.Firebase                  [len=28]
  com.android.pictach.MyReceiver                [len=30]
  com.android.pictach.Bodybuilding              [len=32]
  com.android.pictach.MainActivity              [len=32]
  $$com.android.pictach.androidx-startup        [len=38]  ← authority
  ,,com.android.pictach.PermissionMonitorService [len=46]
  44com.android.pictach.SensorRestarterBroadcastReceiver [len=54]

classes.dex slash-form (73 type descriptors — bulk replace):
  com/android/pictach → com/new/package

classes.dex dot-form (string literals — each unique length):
  com.android.pictach                           [len=19]
  com.android.pictach.Utils                     [len=25]
  com.android.pictach.costm                     [len=25]
  com.android.pictach.verapp                    [len=26]
  com.android.pictach.MainActive                [len=30]
  com.android.pictach.googlenews                [len=30]
  com.android.pictach.GoogleTranslate           [len=35]
  com.android.pictach.verapp.provider           [len=35] ← CRASH SOURCE

resources.arsc (UTF-16LE — RES_TABLE_PACKAGE name field):
  com.android.pictach                           [len=19 chars = 38 bytes UTF-16LE]

DEX checksums: SHA-1 + Adler32 recomputed after patch.

APPROACH:
  Replace com.android.pictach with same-length new package name EVERYWHERE.
  All suffixes (.verapp.provider, .androidx-startup etc.) are preserved as-is
  because only the base package prefix changes — suffixes stay the same length.
  Binary chunk offsets remain valid throughout.
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

# Original base package — only this prefix is replaced
OLD_BASE     = "com.android.pictach"   # len=19
OLD_BASE_SL  = "com/android/pictach"   # slash form


def run(cmd, check=True):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.stdout.strip(): print(result.stdout.strip())
    if result.stderr.strip(): print(result.stderr.strip())
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
    CRITICAL: new package must be IDENTICAL byte length to old_pkg.
    All binary formats (manifest, DEX, arsc) use length-sensitive storage.
    Different length = corrupted offsets = crash.
    old_pkg = com.android.pictach = 19 chars
    Formula: com.XXXXXXX.XXXXXXX = 4+7+1+7 = 19 ✓
    """
    target_len = len(old_pkg)
    seg_total = target_len - 5  # subtract 'com' + '.' + '.'
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
        "-keystore", KEYSTORE, "-alias", KS_ALIAS,
        "-keyalg", "RSA", "-keysize", "2048", "-validity", "365",
        "-storepass", KS_PASS, "-keypass", KEY_PASS,
        "-dname", "CN=Companion, OU=Dev, O=Nova, L=Test, S=Test, C=US",
        "-storetype", "JKS"
    ])
    print(f"[OK] Keystore generated: {KEYSTORE}")


def patch_bytes(data, old_b, new_b, label=""):
    """Safe same-length binary replacement."""
    assert len(old_b) == len(new_b), f"Length mismatch in {label}: {len(old_b)} != {len(new_b)}"
    count = data.count(old_b)
    if count == 0:
        return data, 0
    return data.replace(old_b, new_b), count


def patch_manifest(data, old_pkg, new_pkg):
    """
    Patch AndroidManifest.xml binary XML string pool.
    Only replace the BASE package prefix — all suffixes stay intact.
    Every string containing 'com.android.pictach' gets its prefix swapped.
    Same-length guarantee: old_pkg and new_pkg have identical char count.
    """
    old_b = old_pkg.encode('utf-8')
    new_b = new_pkg.encode('utf-8')
    result, count = patch_bytes(data, old_b, new_b, "manifest")
    print(f"[OK] Manifest: {count} prefix patches applied")
    return result


def patch_dex(data, old_pkg, new_pkg):
    """
    Patch DEX string pool — both slash-form and dot-form.
    Replacing the base prefix handles ALL derived strings:
      com/android/pictach → com/new/pkg  (covers all 73 type descriptors)
      com.android.pictach → com.new.pkg  (covers all 8 dot-form literals)
    Including:
      com.android.pictach.verapp.provider → com.new.pkg.verapp.provider  ← crash fix
      com.android.pictach.androidx-startup → com.new.pkg.androidx-startup
    After patch: recompute SHA-1 and Adler32.
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

    # Recompute SHA-1 (bytes 12-31, covers bytes[32:])
    sha1 = hashlib.sha1(bytes(dex[32:])).digest()
    dex[12:32] = sha1

    # Recompute Adler32 (bytes 8-11, covers bytes[12:])
    adler = zlib.adler32(bytes(dex[12:])) & 0xFFFFFFFF
    struct.pack_into('<I', dex, 8, adler)

    # Verify clean
    remaining = bytes(dex).count(old_slash) + bytes(dex).count(old_dot)
    if remaining > 0:
        raise RuntimeError(f"DEX patch incomplete — {remaining} old strings remain")

    print(f"[OK] DEX: {slash_count} slash + {dot_count} dot patched — SHA-1+Adler32 recomputed")
    return bytes(dex)


def patch_arsc(data, old_pkg, new_pkg):
    """
    Patch resources.arsc RES_TABLE_PACKAGE name field (UTF-16LE).
    Single occurrence at offset 235296.
    Same char-length → same UTF-16LE byte-length → safe patch.
    """
    old_utf16 = old_pkg.encode('utf-16-le')
    new_utf16 = new_pkg.encode('utf-16-le')
    assert len(old_utf16) == len(new_utf16)
    result, count = patch_bytes(data, old_utf16, new_utf16, "arsc")
    if count == 0:
        print(f"[SKIP] resources.arsc: already clean")
    else:
        print(f"[OK] resources.arsc: {count} UTF-16LE occurrence(s) patched")
    return result


def full_scan(data_map, old_pkg):
    """Verify no old package strings remain in ANY file in ANY encoding."""
    old_u8  = old_pkg.encode('utf-8')
    old_sl  = old_pkg.replace('.', '/').encode('utf-8')
    old_u16 = old_pkg.encode('utf-16-le')
    issues = []
    for fname, data in data_map.items():
        hits = {}
        if old_u8  in data: hits['utf8-dot']   = data.count(old_u8)
        if old_sl  in data: hits['utf8-slash']  = data.count(old_sl)
        if old_u16 in data: hits['utf16']       = data.count(old_u16)
        if hits:
            issues.append(f"{fname}: {hits}")
    return issues


def binary_patch_apk(old_pkg, new_pkg):
    tmp_apk = OUTPUT_APK + ".tmp"
    patched_data = {}

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

                patched_data[item.filename] = data
                zout.writestr(item, data, compress_type=item.compress_type)

    print(f"[OK] APK repacked")

    # Full scan before signing
    issues = full_scan(patched_data, old_pkg)
    if issues:
        raise RuntimeError(f"Patch incomplete — old package still found:\n" + "\n".join(issues))
    print(f"[OK] Full scan clean — old package gone from all files")

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
        "--ks", KEYSTORE, "--ks-key-alias", KS_ALIAS,
        "--ks-pass", f"pass:{KS_PASS}", "--key-pass", f"pass:{KEY_PASS}",
        "--min-sdk-version", MIN_SDK,
        "--out", OUTPUT_APK, input_apk
    ])
    os.remove(input_apk)
    print(f"[OK] Signed → {OUTPUT_APK}")


def verify_signature():
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

        print("\n=== Step 4: Binary Patch — Manifest + DEX + ARSC ===")
        tmp_apk = binary_patch_apk(old_pkg, new_pkg)

        print("\n=== Step 5: Align ===")
        aligned_apk = align(tmp_apk)

        print("\n=== Step 6: Sign ===")
        sign(aligned_apk)

        print("\n=== Step 7: Verify Signature ===")
        verify_signature()

        print(f"\n[DONE] Package: {old_pkg} → {new_pkg}")
        print(f"[DONE] Install and open: {OUTPUT_APK}")

    except Exception as e:
        error_msg = traceback.format_exc()
        print(f"\n[ERROR] {e}")
        with open(ERROR_LOG, "w") as f:
            f.write(error_msg)
        print(f"[LOG] Error saved: {ERROR_LOG}")
        sys.exit(1)
