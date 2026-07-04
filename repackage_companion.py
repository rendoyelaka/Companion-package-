#!/usr/bin/env python3
"""
repackage_companion.py
- Auto-detects package name from companion.apk via aapt
- Generates a random new package name
- Decode with -r (skip resource decode, avoid res dir errors)
- Rebuild WITHOUT -r (re-encodes manifest to binary — required by apksigner)
- Adds --min-sdk-version 28 to apksigner as hard fallback
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
MIN_SDK    = "28"

WORK_DIR    = "/tmp/companion_repackage"
DECODED_DIR = os.path.join(WORK_DIR, "decoded")
REBUILT_APK = os.path.join(WORK_DIR, "rebuilt.apk")
ALIGNED_APK = os.path.join(WORK_DIR, "aligned.apk")

TEXT_EXTENSIONS = {".smali", ".xml", ".yml", ".yaml", ".txt", ".json", ".mf", ".sf"}


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
    """
    -r skips resource decoding — avoids aapt failing on non-standard res dir names.
    Manifest is still decoded to plain XML by apktool at this stage.
    """
    if os.path.exists(DECODED_DIR):
        shutil.rmtree(DECODED_DIR)
    run(["apktool", "d", INPUT_APK, "-o", DECODED_DIR, "-r", "-f"])
    print("[OK] Decoded — resources skipped, manifest decoded to plain XML")


def replace_package(old_pkg, new_pkg):
    old_path = old_pkg.replace(".", "/")
    new_path = new_pkg.replace(".", "/")
    count = 0

    for root, _, files in os.walk(DECODED_DIR):
        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in TEXT_EXTENSIONS:
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                if old_path in content or old_pkg in content:
                    content = content.replace(old_path, new_path)
                    content = content.replace(old_pkg, new_pkg)
                    with open(fpath, "w", encoding="utf-8") as f:
                        f.write(content)
                    count += 1
            except Exception as e:
                print(f"[SKIP] {fpath} — {e}")

    print(f"[OK] Package replaced in {count} files")


def rebuild():
    """
    No -r here — apktool re-encodes AndroidManifest.xml back to binary XML.
    Binary manifest is required by apksigner to read minSdkVersion.
    Resources are carried through from the original APK unchanged.
    """
    run(["apktool", "b", DECODED_DIR, "-o", REBUILT_APK])
    print("[OK] Rebuilt — manifest re-encoded to binary XML")


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
        "--min-sdk-version", MIN_SDK,
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
