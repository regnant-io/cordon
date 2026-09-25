# Cordon desktop

The desktop app: a Cordon node, the llama.cpp runtime, and the operator console
in one installable application for Windows, macOS and Linux. For what it does
and how to use it, see [Desktop app](../README.md#desktop-app) in the main
README. This file is about building it.

## Layout

| Path | What it is |
|---|---|
| `src-tauri/` | The application: a [Tauri 2](https://tauri.app) shell around `cordon-core` and `cordon-api`. |
| `src-tauri/src/engine.rs` | Starts, stops and restarts the node in-process. |
| `src-tauri/src/models.rs` | The first-run model list, local models, Hugging Face downloads. |
| `shell/` | The launcher: first run, startup progress, settings. Static HTML, no build step. |
| `src-tauri/llama/` | The bundled llama.cpp, filled by `scripts/fetch-llama`. Not committed. |
| `icons/source.svg` | The app icon; `npm run icons` regenerates `src-tauri/icons/`. |

The operator console is not duplicated here. Once the node is running, the
window loads it from the node (`http://127.0.0.1:8478/?shell=desktop`), which
is the same page `cordon run` serves to a browser. `?shell=desktop` only
changes window chrome: no text selection on controls, no browser context menu,
and a **Runtime settings** entry that returns to the launcher.

The console cannot call into the app. It is served from a loopback origin no
Tauri capability names, so it has exactly the reach it has in a browser. It
asks for the launcher by navigating to `/desktop/settings`, which the window's
navigation guard intercepts. Every other off-app link opens in the system
browser.

## Building

Requirements: Rust 1.89 or later, Node.js 20 or later, and the platform's
webview development files:

- **Windows**: nothing extra; WebView2 ships with Windows 10 and 11, and the
  installer bootstraps it where it is missing.
- **macOS**: Xcode command-line tools.
- **Linux**: `libwebkit2gtk-4.1-dev libappindicator3-dev librsvg2-dev patchelf`,
  and `libvulkan1` at runtime for GPU offload.

```bash
# 1. Put llama.cpp in src-tauri/llama (pinned release, digest-checked)
./scripts/fetch-llama.sh            # macOS, Linux
./scripts/fetch-llama.ps1           # Windows (PowerShell)

# 2. Build the installers
cd desktop
npm ci
npx tauri build
```

Installers land in `target/release/bundle/`: `nsis/*.exe` and `msi/*.msi` on
Windows, `dmg/*.dmg` on macOS, `deb/`, `rpm/` and `appimage/` on Linux.

For development, `npx tauri dev` runs the app from source. Without step 1 it
uses a `llama-server` from `PATH`, or `CORDON_LLAMA_SERVER`.

`scripts/fetch-llama.ps1 -From <dir>` bundles from an existing llama.cpp
install instead of downloading, for example a winget install of the same
build.

## Changing the bundled llama.cpp

The tag and the SHA-256 of each release asset are pinned in
`scripts/fetch-llama.sh` and `scripts/fetch-llama.ps1`. To move to a new
build, add its digests there (GitHub shows them on the release page and in
the releases API), change the default tag, and run the desktop workflow.
Cordon probes the binary's flags at startup, so a build without `--kv-unified`
or `--no-webui` still runs, with a warning in the log.

## Releases

`.github/workflows/desktop.yml` builds all three platforms on every pull request
that touches the app, the console or the core crates, and uploads the
installers as artifacts. Pushing a `v*` tag also attaches them to a draft
GitHub release for a maintainer to review and publish.

The builds are not code-signed. Windows SmartScreen will warn on first run,
and macOS will ask for the app to be opened from Finder with a right-click
the first time. Signing needs certificates this repository does not hold;
Tauri's `bundle.windows.certificateThumbprint` and `bundle.macOS.signingIdentity`
are where they go.
