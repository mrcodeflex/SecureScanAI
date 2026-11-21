# Publish SecureScan AI to GitHub and build the APK (no Claude/GitHub link, no Android Studio)

You upload the files yourself. Nobody needs your GitHub password, token or repository permissions.

The project has **about 100 files**. GitHub's browser uploader accepts **at most 100 files at a time**, so you will upload in **two or three batches** (instructions below). If you prefer, use **GitHub Desktop** (Step 2B) which has no such limit.

## Step 1 - Create the repository

1. Sign in at <https://github.com> and open <https://github.com/new>.
2. **Repository name:** `SecureScanAI`
3. Choose **Private** (recommended: this is a security tool).
4. Do **not** add a README, `.gitignore` or licence (this project already has them) - leave those unticked. (If you do tick README, uploading a new `README.md` later simply replaces it.)
5. Click **Create repository**.

## Step 2A - Upload with the browser (batches)

1. Download `SecureScanAI_Complete_Project.zip` and **extract it** (right-click > *Extract All*).
2. Open the extracted folder. You must see `README.md`, `app`, `mobile`, `scripts`, `docs`, `.github` **directly inside it**. (Do **not** upload the ZIP file itself, and do not upload an extra wrapper folder around these.)
   * If you cannot see `.github`: in File Explorer choose *View > Show > Hidden items*.
3. On your new repository page click **uploading an existing file** (or *Add file > Upload files*).
4. **Batch 1:** drag the folder **`app`** (44 files) and the folder **`.github`** (2 files) into the page. Wait until the file list finishes. Scroll down, keep **"Commit directly to the main branch"**, click **Commit changes**.
5. **Batch 2:** *Add file > Upload files*. Drag the folders **`mobile`**, **`scripts`** and **`docs`** (about 40 files). Commit to `main`.
6. **Batch 3:** *Add file > Upload files*. Select the **loose files in the root of the extracted folder** (everything that is not a folder: `README.md`, `.env.example`, `.gitignore`, `.gitattributes`, `LICENSE`, `requirements.txt`, `requirements-dev.txt`, `pytest.ini`, the four `.bat` files and the `.md` guides). Commit to `main`.
7. Check on the repository page that you see the folders `.github`, `app`, `docs`, `mobile`, `scripts` and the root files. Open `.github/workflows/` and confirm **`android-build.yml`** is there. If it is missing the APK cannot be built - upload it again.

> Never upload a file called `.env` (it is not in the ZIP) or any `.jks` / `.keystore` file.

## Step 2B - Alternative: GitHub Desktop (no 100-file limit)

1. Install GitHub Desktop from <https://desktop.github.com/> and sign in.
2. *File > Clone repository* > choose `SecureScanAI` > pick a local folder.
3. Copy **all contents** of the extracted project (including hidden `.github`) into that cloned folder.
4. In GitHub Desktop write a summary such as "Add SecureScan AI", click **Commit to main**, then **Push origin**.

## Step 3 - Run the Android build

1. Open the repository's **Actions** tab. If GitHub asks, click **"I understand my workflows, go ahead and enable them"**.
2. In the left list choose **Android APK** > **Run workflow** (button on the right) > keep branch `main` > **Run workflow**.
3. Wait about 10-20 minutes. The run turns green when finished. Click the run to watch progress.
   * If a repository policy blocks third-party actions: *Settings > Actions > General > Allow all actions* (the workflow uses `actions/*` and `subosito/flutter-action`, pinned to exact commits).
4. The workflow also runs automatically when files under `mobile/` change on `main`. Pushing a tag like `v1.0.0` also creates a GitHub release containing the APK.

## Step 4 - Download the APK

1. Open the finished run (green check).
2. Scroll to **Artifacts** at the bottom and click **`SecureScanAI-Android-APK`**. A ZIP downloads.
3. Extract it. You get:
   * `SecureScanAI.apk` - the app
   * `SecureScanAI.apk.sha256` - checksum (compare with `certutil -hashfile SecureScanAI.apk SHA256` on Windows)
   * `build-info.txt` - commit, Flutter version, **signing mode** and signature check

If the run failed (red cross), open the failed step to read the message; a `SecureScanAI-build-logs` artifact is attached with details. See `ANDROID_BUILD_GUIDE.md`.

## Step 5 - Install on your phone

1. Copy `SecureScanAI.apk` to the phone (USB cable, Google Drive, email to yourself...).
2. Tap the file. Android asks to allow installs from that source (Files / Chrome / Drive): allow it **for that app only**.
3. Open **SecureScan AI**.
4. On the first screen enter your server address, for example `http://192.168.1.20:8000` (see README, section 2 for how to find it), tap **Test connection**, then **Save**.
5. Sign in with the account your administrator created.

### About the signature
Without signing secrets the APK is a **testing build signed with a temporary debug key**. It installs and works, but each new build has a different key, so Android makes you **uninstall the old app before installing an update**. For permanent use configure your own keystore (ANDROID_BUILD_GUIDE.md, "Release signing").
