#!/usr/bin/env python3
"""
repackage_companion.py
Purpose : Change companion APK package name, auto-sign, output installable APK.
Usage   : python3 repackage_companion.py
Requires: apktool, zipalign, apksigner, default-jdk
"""

import os
import sys
import shutil
import subprocess

# ─── CONFIG — edit these two lines only ───────────────────────────────────────
OLD_PKG  = "com.original.companion.package"       # current package name in APK
NEW_PKG  = "com.your.new.package.name"            # desired new package name
INPUT_APK = "companion.apk"                       # place companion.apk next to this script
# ──────────────────────────────────────────────────────────────────────────────

OUTPUT_APK  = "companion_repackaged.apk"
KEYSTORE    = "test_companion.jks"
KS_ALIAS    = "companion_key"
KS_PASS     = "companion1234"
KEY_PASS    = "companion1234"

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
        print(f"[FAIL] {' '.join(cmd)}")
        sys.exit(1)
    return result


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


def replace_package():
    old_path = OLD_PKG.replace(".", "/")
    new_path = NEW_PKG.replace(".", "/")

    manifest = os.path.join(DECODED_DIR, "AndroidManifest.xml")
    with open(manifest, "r") as f:
        content = f.read()
    content = content.replace(OLD_PKG, NEW_PKG)
    with open(manifest, "w") as f:
        f.write(content)
    print(f"[OK] Manifest: {OLD_PKG} → {NEW_PKG}")

    count = 0
    for root, _, files in os.walk(DECODED_DIR):
        for fname in files:
            if not fname.endswith(".smali"):
                continue
            fpath = os.path.join(root, fname)
            with open(fpath, "r", errors="ignore") as f:
                content = f.read()
            if old_path in content or OLD_PKG in content:
                content = content.replace(old_path, new_path)
                content = content.replace(OLD_PKG, NEW_PKG)
                with open(fpath, "w") as f:
                    f.write(content)
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
    os.makedirs(WORK_DIR, exist_ok=True)

    print("\n=== Step 1: Keystore ===")
    generate_keystore()

    print("\n=== Step 2: Decode ===")
    decode()

    print("\n=== Step 3: Replace Package Name ===")
    replace_package()

    print("\n=== Step 4: Rebuild ===")
    rebuild()

    print("\n=== Step 5: Align ===")
    align()

    print("\n=== Step 6: Sign ===")
    sign()

    print("\n=== Step 7: Verify ===")
    verify()

    cleanup()
    print(f"\n[DONE] Install this APK to test: {OUTPUT_APK}")
