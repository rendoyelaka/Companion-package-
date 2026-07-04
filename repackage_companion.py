#!/usr/bin/env python3
"""
repackage_companion.py
- Auto-detects current package name from companion.apk
- Generates a random new package name
- Re-signs with auto-generated keystore
- Outputs installable APK
"""

import os
import sys
import shutil
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

WORK_DIR    = "/tmp/companion_repackage"
DECODED_DIR = os.path.join(WORK_DIR, "decoded")
REBUILT_APK = os.path.join(WORK_DIR, "rebuilt.apk")
ALIGNED_APK = os.path.join(WORK_DIR, "aligned.apk")


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
    result = run(["aapt", "dump", "badging", INPUT_APK], check=True)
    match = re.search(r"package: name='([^']+)'", result.stdout)
    if not match:
        raise RuntimeError("Could not detect package name from APK")
    pkg = match.group(1)
    print(f"[OK] Detected package: {pkg}")
    return pkg


def random_package():
    def seg(n): return ''.join(random.choices(string.ascii_lowercase, k=n))
    pkg = f"com.{seg(6)}.{seg(5)}.{seg(7)}"
    print(f"[OK] New package: {pkg}")
    return pkg


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


def decode():
    if os.path.exists(DECODED_DIR):
        shutil.rmtree(DECODED_DIR)
    run(["apktool", "d", INPUT_APK, "-o", DECODED_DIR, "--no-res", "-f"])
    print("[OK] Decoded")


def replace_package(old_pkg, new_pkg):
    old_path = old_pkg.replace(".", "/")
    new_path = new_pkg.replace(".", "/")

    manifest = os.path.join(DECODED_DIR, "AndroidManifest.xml")
    with open(manifest, "r", encoding="utf-8") as f:
        content = f.read()
    content = content.replace(old_pkg, new_pkg)
    with open(manifest, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"[OK] Manifest updated")

    count = 0
    for root, _, files in os.walk(DECODED_DIR):
        for fname in files:
            if not fname.endswith(".smali"):
                continue
            fpath = os.path.join(root, fname)
            with open(fpath, "rb") as f:
                raw = f.read()
            if old_path.encode() in raw or old_pkg.encode() in raw:
                raw = raw.replace(old_path.encode(), new_path.encode())
                raw = raw.replace(old_pkg.encode(), new_pkg.encode())
                with open(fpath, "wb") as f:
                    f.write(raw)
                count += 1
    print(f"[OK] Smali updated: {count} files")


def rebuild():
    run(["apktool", "b", DECODED_DIR, "-o", REBUILT_APK])
    print("[OK] Rebuilt")


def align():
    run(["zipalign", "-v", "-f", "4", REBUILT_APK, ALIGNED_APK])
    print("[OK] Aligned")


def sign():
    run([
        "apksigner", "sign",
        "--ks", KEYSTORE,
        "--ks-key-alias", KS_ALIAS,
        "--ks-pass", f"pass:{KS_PASS}",
        "--key-pass", f"pass:{KEY_PASS}",
        "--out", OUTPUT_APK,
        ALIGNED_APK
    ])
    print(f"[OK] Signed → {OUTPUT_APK}")


def verify():
    result = run(["apksigner", "verify", "--verbose", OUTPUT_APK], check=False)
    if result.returncode == 0:
        print("[OK] Signature verified")
    else:
        print("[WARN] Signature verify failed")


def cleanup():
    shutil.rmtree(WORK_DIR, ignore_errors=True)


if __name__ == "__main__":
    try:
        os.makedirs(WORK_DIR, exist_ok=True)

        print("\n=== Step 1: Keystore ===")
        generate_keystore()

        print("\n=== Step 2: Detect Package Name ===")
        old_pkg = detect_package()

        print("\n=== Step 3: Generate New Package Name ===")
        new_pkg = random_package()

        print("\n=== Step 4: Decode ===")
        decode()

        print("\n=== Step 5: Replace Package Name ===")
        replace_package(old_pkg, new_pkg)

        print("\n=== Step 6: Rebuild ===")
        rebuild()

        print("\n=== Step 7: Align ===")
        align()

        print("\n=== Step 8: Sign ===")
        sign()

        print("\n=== Step 9: Verify ===")
        verify()

        cleanup()
        print(f"\n[DONE] Package: {old_pkg} → {new_pkg}")
        print(f"[DONE] Install: {OUTPUT_APK}")

    except Exception as e:
        error_msg = traceback.format_exc()
        print(f"\n[ERROR] {e}")
        with open(ERROR_LOG, "w") as f:
            f.write(error_msg)
        print(f"[LOG] Error saved: {ERROR_LOG}")
        sys.exit(1)
