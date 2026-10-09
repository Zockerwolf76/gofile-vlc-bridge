# Gofile VLC Bridge v1.0.0

KernelSU module for Android ARM64 by **Zockerwolf76**. Browse a Gofile share folder, select a video, and stream it to VLC through a loopback HTTP Range proxy without downloading the whole file first.

## Features

- Embedded KernelSU WebUI and browser UI at `http://127.0.0.1:8765/`
- Gofile folder browsing (including nested folders) with API fallback
- VLC-compatible streaming endpoint `http://127.0.0.1:8765/video`
- HTTP Range seeking
- **Reset & Stop Proxy** clears the session and cancels active streams
- Android ARM64 (`arm64-v8a`), root with KernelSU

## Install

1. Download `gofile-vlc-bridge-v1.0.0.zip` from [Releases](../../releases).
2. Install it in KernelSU's Modules screen and reboot.
3. Open the module WebUI, paste a `https://gofile.io/d/...` URL, and tap **Load Files**.
4. Select a video, copy the VLC link, and open it as a network stream in VLC Android.
5. Tap **Reset & Stop Proxy** when finished.

## Updates via GitHub Actions

The workflow `.github/workflows/release.yml` builds the Android ARM64 executable, packages the module, publishes/updates the GitHub Release and writes `update.json` to `main`.

**Set up:** Create a **public** GitHub repository, upload all files from this source tree to its `main` branch, and enable GitHub Actions. In repository Settings → Actions → General → Workflow permissions, allow **Read and write permissions**. Run the workflow manually under Actions → Build and publish KernelSU module → Run workflow (or push a relevant code change). The workflow uses `github.repository` automatically, so the generated module ZIP includes the correct `updateJson` URL.

KernelSU's module update checker can detect a newer release using `updateJson`. **This is update availability, not silent unattended installation**; installing an update still depends on your KernelSU manager and user action.

**For future releases:** Change `VERSION` (e.g. `1.0.1`), update the matching version string in `cmd/bridge/main.go` and `module/webroot/index.html` if you want the UI/server display to match, commit and push. The Action produces `v1.0.1`. A new versionCode is needed for the manager to recognize an update. Merely re-running the workflow without increasing VERSION will replace the release asset but may not appear as a new update in KernelSU.

## Build locally

Requires Go 1.23+, Python 3 and zip/unzip. On Linux/macOS run `bash scripts/build.sh`. The output is `dist/gofile-vlc-bridge-v1.0.0.zip`. Local builds omit `updateJson` unless `GITHUB_REPOSITORY=owner/repo` is set.

## Notes

- Local server binds to `127.0.0.1:8765`, not a public interface.
- Gofile's API and share permissions can change. Some links may require a Gofile account token or accessible network route.
- The module does not bundle VLC. Install VLC separately.
- This project is not affiliated with Gofile, KernelSU or VLC.
- Do not share private account tokens or debug logs containing them.
- A network request can fail even if the folder is visible in your mobile browser.

## License

MIT. The bundled CA certificate bundle contains third-party trust anchors and is not covered by the project source-code license.
