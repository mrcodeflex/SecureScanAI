# Android app - build, signing and installation

The Android app (`mobile/`) is a **native Flutter app** (not a WebView) that talks to the same SecureScan AI backend and database as the web interface. It provides splash screen, login, dashboard, Beginner/Advanced scanning, website scans, source ZIP upload, live progress, results (Simple/Technical views), history, PDF/JSON/CSV report download, profile, logout, server settings with connection test/retry and Android back navigation.

* Application ID: `com.securescanai.app`
* Permissions: `INTERNET` only (files are chosen with the system picker)
* The server address is **entered in the app** and stored on the phone. It can be changed without rebuilding.
* Optional build-time default: set a **repository variable** named `SCANNER_URL` (Settings > Secrets and variables > Actions > Variables) - the workflow passes it as `--dart-define=SCANNER_URL=...`. The address typed in the app always wins.

## How the cloud build works
`.github/workflows/android-build.yml` (Ubuntu runner, Java 17, Flutter stable):

1. Finds the Flutter project by looking for a `pubspec.yaml` that depends on the Flutter SDK (it does not assume a folder).
2. `scripts/prepare_android.py` runs `flutter create --platforms=android` to generate Flutter's own Gradle files and wrapper, sets the application ID, and copies this project's customisations from `mobile/android_overrides/` (manifest, adaptive icon, network config, MainActivity). *Why generated?* Gradle/AGP versions change with every Flutter release and the Gradle wrapper contains a binary jar, so Flutter generates them to always match the SDK in use.
3. Optional signing (`scripts/configure_android_signing.py`) - only if all four secrets exist.
4. `flutter pub get`, Dart format check (advisory), `flutter analyze --no-fatal-infos`, `flutter test`.
5. `flutter build apk --release --build-number <run number>` (universal APK).
6. Verifies the APK exists, writes SHA-256 and `build-info.txt` (including the real signing mode and an `apksigner verify` result), uploads artifact **`SecureScanAI-Android-APK`**.

All third-party actions are pinned to full commit SHAs.

## Release signing (permanent installs and updates)
Skip this for private testing. Do it once if you want updates to install over older versions.

1. Install a JDK on your PC (for `keytool`), e.g. `winget install EclipseAdoptium.Temurin.17.JDK`.
2. Create the keystore (choose strong passwords, **write them down**):
   ```
   keytool -genkey -v -keystore upload-keystore.jks -keyalg RSA -keysize 2048 -validity 10000 -alias upload
   ```
3. Convert it to Base64 (PowerShell): 
   ```
   [Convert]::ToBase64String([IO.File]::ReadAllBytes("upload-keystore.jks")) | Set-Clipboard
   ```
4. In GitHub: *Settings > Secrets and variables > Actions > New repository secret*. Create:

   | Secret | Value |
   |---|---|
   | `ANDROID_KEYSTORE_BASE64` | the Base64 text from step 3 |
   | `ANDROID_KEYSTORE_PASSWORD` | the keystore password |
   | `ANDROID_KEY_ALIAS` | `upload` (the alias you chose) |
   | `ANDROID_KEY_PASSWORD` | the key password |

5. Run the workflow again. `build-info.txt` must say `Signing mode: release keystore (from GitHub secrets)` and `apksigner verify: OK`.
6. **Back up `upload-keystore.jks` and both passwords** somewhere safe (password manager + offline copy). If you lose them you can never publish a compatible update. **Never commit the keystore or passwords**; the workflow never prints them, and `.gitignore` blocks `*.jks`.

If only some of the four secrets are set the build stops with an error instead of silently producing an unsigned release.

## Install and connect
See `GITHUB_UPLOAD_GUIDE.md` (Step 5) and `README.md` (section 2). Summary: install the APK, enter `http://<your-PC-IPv4>:8000`, **Test connection**, **Save**, sign in.

* `http://` is accepted only for private/LAN addresses (10.x, 172.16-31.x, 192.168.x, 169.254.x, `*.local`, single-word host names). Use `https://` for everything else.
* `localhost`, `127.0.0.1` and `0.0.0.0` are rejected because on the phone they mean the phone itself.
* TLS certificates are always verified. A self-signed certificate on your server will be rejected - use a trusted certificate (for example from a local CA you install properly) or stay on trusted-LAN HTTP.

## If the build fails
1. Open the failed run and the step with the red cross. Download **SecureScanAI-build-logs** for the full Gradle output.
2. `Prepare Android platform files` fails: Flutter changed its template. The script prints which expected text was not found; send that message to the maintainer or adjust `scripts/prepare_android.py`.
3. `flutter analyze` fails: the output lists file and line. (Infos do not fail the build; warnings and errors do.)
4. Java errors mentioning an unsupported Java version: change `java-version: "17"` in the workflow to `"21"`.
5. Format step shows a warning: run `dart format .` inside `mobile/`; it does not block the build.

## Build locally (optional, for developers - not needed for you)
Install Flutter, then from the repository root:
```
cd mobile
flutter pub get
cd ..
python scripts/prepare_android.py --project mobile
cd mobile
flutter run            # or: flutter build apk --release
```
