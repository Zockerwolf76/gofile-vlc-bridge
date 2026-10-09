# Gofile VLC Bridge v1.0.0

KernelSU module for Android ARM64 by **Zockerwolf76**. Browse a Gofile share folder, select a video, and stream it to VLC through a loopback HTTP Range proxy without downloading the whole file first.

## Install

1. Download `gofile-vlc-bridge-v1.0.0.zip` from [Releases](../../releases).
2. Install it in KernelSU's Modules screen and reboot.
3. Open the module WebUI, paste a `https://gofile.io/d/...` URL, and tap **Load Files**.
4. Select a video, copy the VLC link, and open it as a network stream in VLC Android.
5. Tap **Reset & Stop Proxy** when finished.

## License

MIT. The bundled CA certificate bundle contains third-party trust anchors and is not covered by the project source-code license.
