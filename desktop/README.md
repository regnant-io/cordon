# Cordon desktop

The desktop app: a Cordon node, the llama.cpp runtime, and the operator console
in one installable application for Windows, macOS and Linux. For what it does
and how to use it, see [Desktop app](../README.md#desktop-app) in the main
README. This file is about building it.

## Layout

| Path | What it is |
|---|---|
| `src-tauri/` | The application: a [Tauri 2](https://tauri.app) shell around `cordon-core` and `cordon-api`. |
| `src-tauri/src/engine.rs` | Builds the node's configuration for any mode and starts, stops and restarts it in-process. |
| `src-tauri/src/posture.rs` | Deployment modes, and what each needs on this machine. |
| `src-tauri/src/keys.rs` | The Client Master Key the app keeps. |
| `src-tauri/src/bundles.rs` | The bundle store, and sealing, verifying, importing and exporting as background jobs. |
| `src-tauri/src/remote.rs` | Remote access: the CA, issued clients, revocation, and the client registry the node enforces. |
| `src-tauri/src/cli.rs` | Putting the bundled `cordon` on `PATH`, and taking it off again. |
| `src-tauri/src/models.rs` | The first-run model list, local models, Hugging Face downloads. |
| `src-tauri/capabilities/` | What each origin in the window may do. See below. |
| `src-tauri/windows/hooks.nsh` | Uninstaller hook that takes `cordon` off `PATH`. |
| `shell/` | The app's pages. Static HTML, no build step. |
| `scripts/stage-cli.mjs` | Builds `cordon` and stages it in `src-tauri/bin` before every installer build. |
| `src-tauri/llama/` | The bundled llama.cpp, filled by `scripts/fetch-llama`. Not committed. |
| `icons/source.svg` | The app icon; `npm run icons` regenerates `src-tauri/icons/`. |

The operator console is not duplicated here. While a Light-mode node runs, the
window loads it from the node (`http://127.0.0.1:8478/?shell=desktop`), the
same page `cordon run` serves to a browser. `?shell=desktop` changes chrome
only: the page draws the app's title bar and window controls, and its sidebar
adds the app's pages, which it reaches by navigating to `/desktop/<page>`. The
window's navigation guard turns those into navigations back to the app, and
`/desktop/stop` into stopping the node. Every other off-app link opens in the
system browser, so nothing a model writes into a transcript can take over the
window. Outside Light mode the node serves no console, and the app's own
Overview reads the node's state in-process instead.

The window has no system title bar on Windows and Linux, and an overlay title
bar on macOS; the pages draw it.

### What each origin may do

`capabilities/default.json` grants the app's own pages (the `tauri://` or
`tauri.localhost` origin) the app's commands and the window controls.
`capabilities/console.json` grants the console's loopback origin moving,
sizing, minimising, maximising and closing the window, and nothing else. Tauri
refuses app commands from a remote origin unless a capability names them, and
none does, so a page the node serves has no more reach into the app than it
would in a browser, plus the ability to move the window it is in.

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

`tauri build` first runs `scripts/stage-cli.mjs`, which builds the `cordon`
command line in release mode and copies it into `src-tauri/bin`, from where the
installer ships it. It lands in a `bin` folder beside the app rather than next
to it because `cordon.exe` and `Cordon.exe` are the same file on Windows.

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
