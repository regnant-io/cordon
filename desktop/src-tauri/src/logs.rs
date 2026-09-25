//! Log capture.
//!
//! A desktop application has no terminal to print to, so everything Cordon
//! and llama.cpp log goes two places: a file in the app's log directory, for a
//! bug report, and a bounded in-memory ring the launcher reads, so a model
//! that is slow to load or refuses to start says why on screen.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use tracing_subscriber::{fmt::MakeWriter, EnvFilter};

/// Lines kept in memory for the launcher.
const RING_CAPACITY: usize = 400;

/// The shared log sink.
#[derive(Clone)]
pub struct LogBuffer {
    inner: Arc<Inner>,
}

struct Inner {
    ring: Mutex<VecDeque<String>>,
    file: Mutex<Option<File>>,
    /// Incremented per line, so a reader can ask only for what is new.
    written: Mutex<u64>,
}

impl LogBuffer {
    fn new(file: Option<File>) -> Self {
        Self {
            inner: Arc::new(Inner {
                ring: Mutex::new(VecDeque::with_capacity(RING_CAPACITY)),
                file: Mutex::new(file),
                written: Mutex::new(0),
            }),
        }
    }

    /// Lines written after line number `after`, with the number of the last
    /// line returned. `after = 0` returns everything still held.
    pub fn since(&self, after: u64) -> (u64, Vec<String>) {
        let ring = self.inner.ring.lock();
        let written = *self.inner.written.lock();
        let held = ring.len() as u64;
        let first_held = written.saturating_sub(held);
        let skip = after.saturating_sub(first_held).min(held) as usize;
        (written, ring.iter().skip(skip).cloned().collect())
    }

    fn push(&self, text: &str) {
        if let Some(file) = self.inner.file.lock().as_mut() {
            let _ = file.write_all(text.as_bytes());
        }
        let mut ring = self.inner.ring.lock();
        let mut written = self.inner.written.lock();
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            if ring.len() >= RING_CAPACITY {
                ring.pop_front();
            }
            ring.push_back(line.to_string());
            *written += 1;
        }
    }
}

/// One formatted event, delivered to the buffer when the formatter is done.
pub struct EventWriter {
    sink: LogBuffer,
    pending: Vec<u8>,
}

impl Write for EventWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.pending.extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for EventWriter {
    fn drop(&mut self) {
        if !self.pending.is_empty() {
            self.sink.push(&String::from_utf8_lossy(&self.pending));
        }
    }
}

impl<'a> MakeWriter<'a> for LogBuffer {
    type Writer = EventWriter;
    fn make_writer(&'a self) -> Self::Writer {
        EventWriter {
            sink: self.clone(),
            pending: Vec::new(),
        }
    }
}

/// Install the global subscriber, writing to `log_file` and the ring.
///
/// llama.cpp's own output reaches the log through the supervisor at debug
/// level under the `llama` target; it is included, because "loading model
/// tensors" is exactly the line someone watching a progress screen wants.
pub fn init(log_file: &Path) -> LogBuffer {
    if let Some(dir) = log_file.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    // One file per session, replaced at each start, so the log never grows
    // without bound and always describes the most recent run.
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(log_file)
        .ok();
    let buffer = LogBuffer::new(file);

    let filter = EnvFilter::try_from_env("CORDON_LOG")
        .unwrap_or_else(|_| EnvFilter::new("info,llama=debug,hyper=warn,reqwest=warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_ansi(false)
        .with_target(false)
        .compact()
        .with_writer(buffer.clone())
        .try_init();
    buffer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reader_is_given_only_new_lines() {
        let buffer = LogBuffer::new(None);
        buffer.push("one\ntwo\n");
        let (mark, lines) = buffer.since(0);
        assert_eq!(lines, vec!["one", "two"]);
        buffer.push("three\n");
        let (next, lines) = buffer.since(mark);
        assert_eq!(lines, vec!["three"]);
        assert_eq!(next, 3);
    }

    #[test]
    fn the_ring_is_bounded() {
        let buffer = LogBuffer::new(None);
        for i in 0..(RING_CAPACITY + 50) {
            buffer.push(&format!("line {}\n", i));
        }
        let (written, lines) = buffer.since(0);
        assert_eq!(written as usize, RING_CAPACITY + 50);
        assert_eq!(lines.len(), RING_CAPACITY);
        assert_eq!(lines[0], "line 50");
        // A reader that fell behind the ring gets what is still held.
        assert_eq!(buffer.since(10).1.len(), RING_CAPACITY);
    }
}
