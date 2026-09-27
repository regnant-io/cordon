//! The `cordon` command line that ships with the app.
//!
//! The installer puts it in a `bin` folder beside the bundled llama.cpp, where
//! it finds that runtime on its own. It is kept out of the application folder
//! itself because `cordon.exe` and `Cordon.exe` are the same file name on
//! Windows. Putting it on `PATH` is the operator's choice, made here.

use std::path::{Path, PathBuf};

use serde::Serialize;

/// Where the command line stands.
#[derive(Debug, Clone, Serialize, Default)]
pub struct CliStatus {
    /// The shipped binary, when this build has one.
    pub path: Option<PathBuf>,
    /// Whether its folder is on the user's `PATH`.
    pub on_path: bool,
    /// Whether the app can change that itself.
    pub can_install: bool,
    /// What to do by hand when it cannot, or what changes after it does.
    pub hint: Option<String>,
}

/// The shipped `cordon` binary under the app's resources, if present.
pub fn locate(resource_dir: &Path) -> Option<PathBuf> {
    let name = if cfg!(windows) {
        "cordon.exe"
    } else {
        "cordon"
    };
    let path = resource_dir.join("bin").join(name);
    path.is_file().then_some(path)
}

/// Where the command line stands now.
pub fn status(cli: Option<&Path>) -> CliStatus {
    let Some(cli) = cli else {
        return CliStatus {
            hint: Some("This build does not include the command line.".into()),
            ..CliStatus::default()
        };
    };
    let dir = cli.parent().map(Path::to_path_buf).unwrap_or_default();
    platform::status(cli, &dir)
}

/// Put the command line on `PATH`.
pub fn install(cli: &Path) -> anyhow::Result<()> {
    let dir = cli.parent().map(Path::to_path_buf).unwrap_or_default();
    platform::install(cli, &dir)
}

/// Take the command line off `PATH`.
pub fn uninstall(cli: &Path) -> anyhow::Result<()> {
    let dir = cli.parent().map(Path::to_path_buf).unwrap_or_default();
    platform::uninstall(cli, &dir)
}

#[cfg(windows)]
mod platform {
    //! The user's `Path` in `HKCU\Environment`, edited as a list so nothing
    //! else in it is disturbed, then announced so new terminals see it.

    use super::*;
    use anyhow::Context;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    fn read() -> anyhow::Result<(RegKey, String)> {
        let env = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags("Environment", KEY_READ | KEY_WRITE)
            .context("cannot open the user environment")?;
        let path: String = env.get_value("Path").unwrap_or_default();
        Ok((env, path))
    }

    fn same(a: &str, dir: &Path) -> bool {
        let a = a.trim().trim_end_matches('\\');
        let b = dir.to_string_lossy();
        a.eq_ignore_ascii_case(b.trim_end_matches('\\'))
    }

    pub fn status(cli: &Path, dir: &Path) -> CliStatus {
        let on_path = read()
            .map(|(_, path)| path.split(';').any(|p| same(p, dir)))
            .unwrap_or(false);
        CliStatus {
            path: Some(cli.to_path_buf()),
            on_path,
            can_install: true,
            hint: on_path.then(|| "Open a new terminal to use it.".into()),
        }
    }

    pub fn install(_cli: &Path, dir: &Path) -> anyhow::Result<()> {
        let (env, path) = read()?;
        if path.split(';').any(|p| same(p, dir)) {
            return Ok(());
        }
        let mut parts: Vec<&str> = path.split(';').filter(|p| !p.trim().is_empty()).collect();
        let dir = dir.to_string_lossy().into_owned();
        parts.push(&dir);
        write(&env, &parts.join(";"))
    }

    pub fn uninstall(_cli: &Path, dir: &Path) -> anyhow::Result<()> {
        let (env, path) = read()?;
        let kept: Vec<&str> = path
            .split(';')
            .filter(|p| !p.trim().is_empty() && !same(p, dir))
            .collect();
        write(&env, &kept.join(";"))
    }

    fn write(env: &RegKey, value: &str) -> anyhow::Result<()> {
        // REG_EXPAND_SZ, as Windows writes it, so entries like %USERPROFILE%
        // already in the value keep expanding.
        let raw = winreg::RegValue {
            bytes: value
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(|u| u.to_le_bytes())
                .collect(),
            vtype: winreg::enums::RegType::REG_EXPAND_SZ,
        };
        env.set_raw_value("Path", &raw)
            .context("cannot update the user Path")?;
        broadcast();
        Ok(())
    }

    /// Tell running programs, Explorer above all, that the environment
    /// changed, so terminals opened from it see the new `Path`.
    fn broadcast() {
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            SendMessageTimeoutW, HWND_BROADCAST, SMTO_ABORTIFHUNG, WM_SETTINGCHANGE,
        };
        let name: Vec<u16> = "Environment\0".encode_utf16().collect();
        let mut result = 0usize;
        // SAFETY: a broadcast with a NUL-terminated UTF-16 string that lives
        // for the duration of the call, as WM_SETTINGCHANGE documents.
        unsafe {
            SendMessageTimeoutW(
                HWND_BROADCAST,
                WM_SETTINGCHANGE,
                0,
                name.as_ptr() as isize,
                SMTO_ABORTIFHUNG,
                2000,
                &mut result,
            );
        }
    }
}

#[cfg(not(windows))]
mod platform {
    //! A symlink in `~/.local/bin`, which needs no administrator rights and is
    //! on `PATH` in most shells.

    use super::*;
    use anyhow::Context;

    fn link() -> Option<PathBuf> {
        std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/bin/cordon"))
    }

    fn on_path(dir: &Path) -> bool {
        std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).any(|d| d == dir))
            .unwrap_or(false)
    }

    pub fn status(cli: &Path, _dir: &Path) -> CliStatus {
        let Some(link) = link() else {
            return CliStatus {
                path: Some(cli.to_path_buf()),
                ..CliStatus::default()
            };
        };
        let linked = std::fs::read_link(&link).is_ok_and(|t| t == cli);
        let link_dir = link.parent().map(Path::to_path_buf).unwrap_or_default();
        CliStatus {
            path: Some(cli.to_path_buf()),
            on_path: linked,
            can_install: true,
            hint: match (linked, on_path(&link_dir)) {
                (true, true) => Some("Open a new terminal to use it.".into()),
                (true, false) => Some(format!(
                    "Linked in {}. Add that folder to PATH in your shell profile.",
                    link_dir.display()
                )),
                _ => None,
            },
        }
    }

    pub fn install(cli: &Path, _dir: &Path) -> anyhow::Result<()> {
        let link = link().context("HOME is not set")?;
        if let Some(parent) = link.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if std::fs::symlink_metadata(&link).is_ok() {
            if std::fs::read_link(&link).is_ok_and(|t| t == cli) {
                return Ok(());
            }
            anyhow::bail!("{} already exists and is not Cordon's.", link.display());
        }
        std::os::unix::fs::symlink(cli, &link)
            .with_context(|| format!("cannot link {}", link.display()))
    }

    pub fn uninstall(cli: &Path, _dir: &Path) -> anyhow::Result<()> {
        let link = link().context("HOME is not set")?;
        if std::fs::read_link(&link).is_ok_and(|t| t == cli) {
            std::fs::remove_file(&link)?;
        }
        Ok(())
    }
}
