//! Where warnings go: the desktop shell writes them to a bounded log file,
//! the CLI to stderr. A warning names what its call site names (a kind and
//! id, an error), never request content or secrets: for example each stored
//! object that does not decode while the storage cleanup runs (see
//! [`crate::cleanup`]).

use parking_lot::Mutex;
use std::fmt::{self, Write as _};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

pub use tracing::level_filters::LevelFilter;

/// The environment variable that sets how much is logged: `off`, `error`,
/// `warn`, `info`, `debug` or `trace`. It applies to Anvil's own crates;
/// other crates log warnings and errors at most.
pub const LOG_ENV: &str = "ANVIL_LOG";

/// The desktop shell's log file, in the app's log directory.
pub const LOG_FILE: &str = "anvil.log";

/// How large a [`LogFile`] grows before it is rotated.
pub const LOG_FILE_LIMIT: u64 = 5 * 1024 * 1024;

/// Log to stderr, at `default` unless [`LOG_ENV`] sets another level. Does
/// nothing if a logger is already installed.
pub fn log_to_stderr(default: LevelFilter) {
    install(Box::new(io::stderr()), level_from_env(default));
}

/// Log to [`LOG_FILE`] in `dir` (created if missing), at `default` unless
/// [`LOG_ENV`] sets another level. The file is a [`LogFile`] of
/// [`LOG_FILE_LIMIT`]. Does nothing if a logger is already installed.
pub fn log_to_file(dir: &Path, default: LevelFilter) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let file = LogFile::open(dir.join(LOG_FILE), LOG_FILE_LIMIT)?;
    install(Box::new(file), level_from_env(default));
    Ok(())
}

/// The level [`LOG_ENV`] sets, or `default` when it is unset or not a level.
fn level_from_env(default: LevelFilter) -> LevelFilter {
    std::env::var(LOG_ENV).ok().filter(|v| !v.trim().is_empty()).and_then(|v| v.trim().parse().ok()).unwrap_or(default)
}

fn install(out: Box<dyn Write + Send>, level: LevelFilter) {
    let _ = tracing::subscriber::set_global_default(Logger { level, out: Mutex::new(out) });
}

/// A log file that stays bounded: once a write would take it past its limit,
/// it is renamed with a `.1` suffix (replacing the one before) and a new one
/// is started, so the log takes at most about twice the limit.
pub struct LogFile {
    path: PathBuf,
    file: Option<File>,
    len: u64,
    limit: u64,
}

impl LogFile {
    /// Open `path` to append to, creating it if missing.
    pub fn open(path: PathBuf, limit: u64) -> io::Result<LogFile> {
        let file = options().append(true).open(&path)?;
        let len = file.metadata()?.len();
        Ok(LogFile { path, file: Some(file), len, limit })
    }

    /// Where the file before this one is kept.
    pub fn rotated_path(&self) -> PathBuf {
        let mut name = self.path.as_os_str().to_owned();
        name.push(".1");
        PathBuf::from(name)
    }

    /// Start a new file, keeping the current one as [`LogFile::rotated_path`].
    /// If it cannot be renamed, it is emptied instead: the log stays bounded.
    fn rotate(&mut self) -> io::Result<()> {
        // Closed first: Windows does not rename an open file.
        self.file = None;
        self.len = 0;
        let file = match fs::rename(&self.path, self.rotated_path()) {
            Ok(()) => options().append(true).open(&self.path)?,
            Err(_) => options().write(true).truncate(true).open(&self.path)?,
        };
        self.file = Some(file);
        Ok(())
    }
}

/// Options that create a log file readable by its owner only: a warning
/// names stored objects by kind and id.
fn options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

impl Write for LogFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.file.is_none() || (self.len > 0 && self.len.saturating_add(buf.len() as u64) > self.limit) {
            self.rotate()?;
        }
        let Some(file) = self.file.as_mut() else { return Err(io::Error::other("the log file is not open")) };
        let n = file.write(buf)?;
        self.len += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.as_mut().map_or(Ok(()), |f| f.flush())
    }
}

/// Writes each event as one line: time, level, target, message and fields.
/// Spans are not recorded.
struct Logger {
    level: LevelFilter,
    out: Mutex<Box<dyn Write + Send>>,
}

impl Logger {
    /// The level for events from `target`: [`Logger::level`] for Anvil's own
    /// crates, at most warnings for others.
    fn level_for(&self, target: &str) -> LevelFilter {
        if target == "anvil" || target.starts_with("anvil_") { self.level } else { self.level.min(LevelFilter::WARN) }
    }
}

impl Subscriber for Logger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.is_event() && *metadata.level() <= self.level_for(metadata.target())
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(self.level)
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let metadata = event.metadata();
        let mut fields = Fields::default();
        event.record(&mut fields);
        let time = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ");
        let line = format!("{time} {} {}: {}{}", metadata.level().as_str(), metadata.target(), fields.message, fields.rest);
        // One event, one line.
        let line = line.replace('\r', "\\r").replace('\n', "\\n") + "\n";
        let mut out = self.out.lock();
        let _ = out.write_all(line.as_bytes());
        let _ = out.flush();
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

/// An event's message, and its other fields as ` name=value`.
#[derive(Default)]
struct Fields {
    message: String,
    rest: String,
}

impl Visit for Fields {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            let _ = write!(self.rest, " {}={value:?}", field.name());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.rest, " {}={value:?}", field.name());
        }
    }
}
