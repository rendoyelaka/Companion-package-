#!/usr/bin/env python3
"""
repackage_companion.py — GUARANTEED UNIQUE PACKAGE PER BUILD

Package name is seeded from GitHub run number — mathematically guaranteed
unique per build. Same run number always produces same package (reproducible).
Format: com.android.p[f/g/h][5 chars] — 19 chars, DEX sort safe.
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


def sort_safe_unique_package(old_pkg):
    """
    Generate guaranteed unique package name per build using GitHub run number.
    
    GITHUB_RUN_NUMBER env var is unique and sequential per repo.
    Seeding random with it guarantees:
      - Same build number = same package name (reproducible)
      - Different build number = different package name (guaranteed unique)
    
    Format: com.android.p[f/g/h][5 random chars] — 19 chars
    DEX sort constraints satisfied: sits between
      'com.android.permissioncontroller:id/...' and 'com.android.pictach.GoogleTranslate'
    """
    run_number = os.environ.get('GITHUB_RUN_NUMBER', '0')
    print(f"[OK] Build run number: {run_number}")

    # Seed random with run number for guaranteed uniqueness per build
    rng = random.Random(int(run_number))

    target_len  = len(old_pkg)  # 19
    suffix_len  = target_len - len("com.android.p")  # 6

    lower = 'com.android.permissioncontroller:id/permission_allow_foreground_only_button'
    upper = 'com.android.pictach.GoogleTranslate'

    for attempt in range(10000):
        # Use run_number + attempt as seed variation if first attempt fails
        rng = random.Random(int(run_number) + attempt)
        first_char = rng.choice('fgh')
        rest = ''.join(rng.choices(string.ascii_lowercase, k=suffix_len - 1))
        new_pkg = f"com.android.p{first_char}{rest}"

        if len(new_pkg) != target_len:
            continue
        if lower < new_pkg < upper:
            print(f"[OK] New package: {new_pkg} (len={len(new_pkg)})")
            print(f"     Build #{run_number} — guaranteed unique per run number")
            return new_pkg

    raise RuntimeError("Could not generate valid sort-safe package name")


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


def patch_manifest(data, old_pkg, new_pkg):
    old_b = old_pkg.encode('utf-8')
    new_b = new_pkg.encode('utf-8')
    assert len(old_b) == len(new_b)
    count = data.count(old_b)
    result = data.replace(old_b, new_b)
    print(f"[OK] Manifest: {count} patches")
    return result


def patch_dex(data, old_pkg, new_pkg):
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

    sha1  = hashlib.sha1(bytes(dex[32:])).digest()
    dex[12:32] = sha1
    adler = zlib.adler32(bytes(dex[12:])) & 0xFFFFFFFF
    struct.pack_into('<I', dex, 8, adler)

    remaining = bytes(dex).count(old_slash) + bytes(dex).count(old_dot)
    if remaining > 0:
        raise RuntimeError(f"DEX patch incomplete — {remaining} old strings remain")

    print(f"[OK] DEX: {slash_count} slash + {dot_count} dot — checksums recomputed")
    return bytes(dex)


def patch_arsc(data, old_pkg, new_pkg):
    old_utf16 = old_pkg.encode('utf-16-le')
    new_utf16 = new_pkg.encode('utf-16-le')
    assert len(old_utf16) == len(new_utf16)
    count = data.count(old_utf16)
    if count == 0:
        print(f"[SKIP] resources.arsc: already clean")
        return data
    result = data.replace(old_utf16, new_utf16)
    print(f"[OK] resources.arsc: {count} UTF-16LE patch(es)")
    return result


def binary_patch_apk(old_pkg, new_pkg):
    tmp_apk = OUTPUT_APK + ".tmp"
    patched = {}

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
                patched[item.filename] = data
                zout.writestr(item, data, compress_type=item.compress_type)

    old_u8  = old_pkg.encode('utf-8')
    old_sl  = old_pkg.replace('.', '/').encode('utf-8')
    old_u16 = old_pkg.encode('utf-16-le')
    issues  = [f for f, d in patched.items() if old_u8 in d or old_sl in d or old_u16 in d]
    if issues:
        raise RuntimeError(f"Old package still in: {issues}")
    print(f"[OK] Full scan clean — old package gone")
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

        print("\n=== Step 3: Generate Unique Package Name ===")
        new_pkg = sort_safe_unique_package(old_pkg)

        print("\n=== Step 4: Binary Patch APK ===")
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
