#!/usr/bin/env python3
"""Optional release signing. Secrets come ONLY from environment variables and are never printed.

  ANDROID_KEYSTORE_BASE64   base64 of your .jks keystore
  ANDROID_KEYSTORE_PASSWORD keystore password
  ANDROID_KEY_ALIAS         key alias
  ANDROID_KEY_PASSWORD      key password

Without these the build stays a *testing build* signed with the automatically generated debug key.
The chosen mode is written to <project>/build/signing_mode.txt so the build report can state it honestly.
"""
from __future__ import annotations

import argparse
import base64
import os
import re
import sys
from pathlib import Path


def find_project(root: Path, explicit: str | None) -> Path:
    if explicit:
        return (root / explicit).resolve()
    for pubspec in sorted(root.rglob("pubspec.yaml")):
        if not ({"node_modules", ".dart_tool", "build", ".git"} & set(pubspec.parts)) and \
                "sdk: flutter" in pubspec.read_text(encoding="utf-8", errors="ignore"):
            return pubspec.parent
    sys.exit("ERROR: Flutter project not found")


def write_mode(project: Path, mode: str) -> None:
    out = project / "build"
    out.mkdir(exist_ok=True)
    (out / "signing_mode.txt").write_text(mode, encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--project")
    ap.add_argument("--root", default=".")
    args = ap.parse_args()
    project = find_project(Path(args.root).resolve(), args.project)
    android = project / "android"
    env = {k: os.environ.get(k, "") for k in ("ANDROID_KEYSTORE_BASE64", "ANDROID_KEYSTORE_PASSWORD",
                                              "ANDROID_KEY_ALIAS", "ANDROID_KEY_PASSWORD")}
    if not any(env.values()):
        write_mode(project, "debug (testing build, no release keystore configured)")
        print("No signing secrets set: building a TESTING build signed with the debug key.")
        return 0
    missing = [k for k, v in env.items() if not v]
    if missing:
        sys.exit("ERROR: signing secrets are partially configured; missing: " + ", ".join(missing))

    jks = android / "app" / "upload-keystore.jks"
    try:
        jks.write_bytes(base64.b64decode(env["ANDROID_KEYSTORE_BASE64"], validate=True))
    except ValueError:
        sys.exit("ERROR: ANDROID_KEYSTORE_BASE64 is not valid base64")
    (android / "key.properties").write_text(
        f"storePassword={env['ANDROID_KEYSTORE_PASSWORD']}\nkeyPassword={env['ANDROID_KEY_PASSWORD']}\n"
        f"keyAlias={env['ANDROID_KEY_ALIAS']}\nstoreFile=upload-keystore.jks\n", encoding="utf-8")

    kts = android / "app" / "build.gradle.kts"
    groovy = android / "app" / "build.gradle"
    if kts.is_file():
        text = kts.read_text(encoding="utf-8")
        loader = ('import java.util.Properties\nimport java.io.FileInputStream\n\n') if "import java.util.Properties" not in text else ""
        props = ('val keystoreProperties = Properties()\n'
                 'val keystorePropertiesFile = rootProject.file("key.properties")\n'
                 'if (keystorePropertiesFile.exists()) {\n    keystoreProperties.load(FileInputStream(keystorePropertiesFile))\n}\n\n')
        signing = ('    signingConfigs {\n        create("release") {\n'
                   '            keyAlias = keystoreProperties["keyAlias"] as String\n'
                   '            keyPassword = keystoreProperties["keyPassword"] as String\n'
                   '            storeFile = file(keystoreProperties["storeFile"] as String)\n'
                   '            storePassword = keystoreProperties["storePassword"] as String\n        }\n    }\n')
        if "android {" not in text:
            sys.exit("ERROR: could not find the android { } block in build.gradle.kts")
        text = loader + text if loader else text
        text = text.replace("android {", props + "android {\n" + signing, 1)
        new, n = re.subn(r'signingConfig\s*=\s*signingConfigs\.getByName\("debug"\)',
                         'signingConfig = signingConfigs.getByName("release")', text)
        if n == 0:
            sys.exit("ERROR: release signingConfig line not found; the Flutter template changed. Not building an unsigned release.")
        kts.write_text(new, encoding="utf-8")
    elif groovy.is_file():
        text = groovy.read_text(encoding="utf-8")
        props = ("def keystoreProperties = new Properties()\ndef keystorePropertiesFile = rootProject.file('key.properties')\n"
                 "if (keystorePropertiesFile.exists()) {\n    keystoreProperties.load(new FileInputStream(keystorePropertiesFile))\n}\n\n")
        signing = ("    signingConfigs {\n        release {\n            keyAlias keystoreProperties['keyAlias']\n"
                   "            keyPassword keystoreProperties['keyPassword']\n"
                   "            storeFile keystoreProperties['storeFile'] ? file(keystoreProperties['storeFile']) : null\n"
                   "            storePassword keystoreProperties['storePassword']\n        }\n    }\n")
        text = text.replace("android {", props + "android {\n" + signing, 1)
        new, n = re.subn(r"signingConfig\s+signingConfigs\.debug", "signingConfig signingConfigs.release", text)
        if n == 0:
            sys.exit("ERROR: release signingConfig line not found; not building an unsigned release.")
        groovy.write_text(new, encoding="utf-8")
    else:
        sys.exit("ERROR: app Gradle file not found")
    write_mode(project, "release keystore (from GitHub secrets)")
    print("Release signing configured (secrets were not printed).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
