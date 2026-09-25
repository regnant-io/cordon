//! What this machine offers the runtime: the llama.cpp build that ships with
//! the app, the compute devices it can see, and the CPU.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use serde::Serialize;
use tokio::process::Command;

/// The bundled runtime, as found on disk.
#[derive(Debug, Clone, Serialize, Default)]
pub struct RuntimeInfo {
    /// Path to `llama-server`, when one was found.
    pub binary: Option<PathBuf>,
    /// Whether that binary is the one shipped with the app, rather than one
    /// found on PATH.
    pub bundled: bool,
    /// The version line llama.cpp prints, e.g. `version: 0.4.1 (build 11026, commit b49650adb)`.
    pub version: Option<String>,
    /// Devices the runtime can offload to.
    pub devices: Vec<Device>,
    /// Logical CPUs.
    pub cpu_threads: usize,
}

/// A compute device llama.cpp reports.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Device {
    /// Backend-qualified name, e.g. `Vulkan0`, `CUDA0`, `Metal`.
    pub id: String,
    /// Marketing name, e.g. `AMD Radeon(TM) Graphics`.
    pub name: String,
    /// Device memory in MiB, when reported.
    pub memory_mib: Option<u64>,
    /// Free device memory in MiB, when reported.
    pub free_mib: Option<u64>,
}

/// Locate the runtime and ask it about itself.
pub async fn probe(bundled: Option<PathBuf>) -> RuntimeInfo {
    let cpu_threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let (binary, is_bundled) = match bundled.map(plain_path).filter(|p| p.is_file()) {
        Some(path) => (Some(path), true),
        None => (cordon_core::runtime::discover_llama_server(None), false),
    };
    let Some(path) = binary.clone() else {
        return RuntimeInfo {
            cpu_threads,
            ..RuntimeInfo::default()
        };
    };

    let version = run(&path, "--version").await.and_then(|text| {
        text.lines()
            .find(|l| l.trim_start().starts_with("version"))
            .map(|l| l.trim().to_string())
    });
    let devices = run(&path, "--list-devices")
        .await
        .map(|text| parse_devices(&text))
        .unwrap_or_default();

    RuntimeInfo {
        binary,
        bundled: is_bundled,
        version,
        devices,
        cpu_threads,
    }
}

/// Drop the `\\?\` prefix Windows APIs return on resolved paths. The path
/// works either way, but it is shown to people, and for a drive path the
/// prefix only obscures it.
fn plain_path(path: PathBuf) -> PathBuf {
    match path.to_str().and_then(|s| s.strip_prefix(r"\\?\")) {
        Some(rest) if !rest.starts_with("UNC") => PathBuf::from(rest),
        _ => path,
    }
}

/// Run the binary with one flag and collect everything it prints.
async fn run(binary: &Path, flag: &str) -> Option<String> {
    let mut cmd = Command::new(binary);
    cmd.arg(flag)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    let output = tokio::time::timeout(std::time::Duration::from_secs(20), cmd.output())
        .await
        .ok()?
        .ok()?;
    Some(format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

/// Parse `--list-devices`, whose lines look like
/// `  Vulkan0: AMD Radeon(TM) Graphics (4008 MiB, 3807 MiB free)`.
///
/// Backends print their own diagnostics first (`ggml_vulkan: Found 1 Vulkan
/// devices:`), in the same `name: text` shape, so only lines after the
/// `Available devices:` heading are read.
fn parse_devices(text: &str) -> Vec<Device> {
    text.lines()
        .skip_while(|line| !line.trim_start().starts_with("Available devices"))
        .skip(1)
        .filter_map(|line| {
            let line = line.trim();
            let (id, rest) = line.split_once(": ")?;
            if id.is_empty() || id.contains(' ') {
                return None;
            }
            let (name, memory_mib, free_mib) = match rest.rsplit_once(" (") {
                Some((name, mem)) => {
                    let mem = mem.trim_end_matches(')');
                    let mut parts = mem.split(", ");
                    let total = parts.next().and_then(mib);
                    let free = parts.next().and_then(mib);
                    (name.to_string(), total, free)
                }
                None => (rest.to_string(), None, None),
            };
            Some(Device {
                id: id.to_string(),
                name,
                memory_mib,
                free_mib,
            })
        })
        .collect()
}

fn mib(part: &str) -> Option<u64> {
    part.split_whitespace().next()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn devices_are_read_from_the_runtimes_listing() {
        let text = "ggml_vulkan: Found 1 Vulkan devices:\n\
                    Available devices:\n  \
                    Vulkan0: AMD Radeon(TM) Graphics (4008 MiB, 3807 MiB free)\n  \
                    CUDA0: NVIDIA GeForce RTX 4090 (24564 MiB, 23000 MiB free)\n";
        let devices = parse_devices(text);
        assert_eq!(devices.len(), 2);
        assert_eq!(
            devices[0],
            Device {
                id: "Vulkan0".into(),
                name: "AMD Radeon(TM) Graphics".into(),
                memory_mib: Some(4008),
                free_mib: Some(3807),
            }
        );
        assert_eq!(devices[1].id, "CUDA0");
    }

    #[test]
    fn a_verbatim_drive_path_is_shown_plainly() {
        assert_eq!(
            plain_path(PathBuf::from(
                r"\\?\C:\Program Files\Cordon\llama\llama-server.exe"
            )),
            PathBuf::from(r"C:\Program Files\Cordon\llama\llama-server.exe")
        );
        let unc = PathBuf::from(r"\\?\UNC\server\share\llama-server.exe");
        assert_eq!(plain_path(unc.clone()), unc);
    }

    #[test]
    fn a_machine_with_no_devices_lists_none() {
        assert!(parse_devices("Available devices:\n").is_empty());
    }
}
