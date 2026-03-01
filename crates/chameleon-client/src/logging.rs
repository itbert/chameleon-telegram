use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

const LOG_FILE_NAME: &str = "chameleon-client.log";
const LOG_MAX_BYTES: u64 = 5 * 1024 * 1024;
const LOG_MAX_FILES: usize = 5;

pub struct LogOutput {
    pub log_dir: PathBuf,
    pub log_file: PathBuf,
    pub guard: WorkerGuard,
}

pub fn init_logging() -> io::Result<LogOutput> {
    let log_dir = select_log_dir()?;
    fs::create_dir_all(&log_dir)?;
    let log_file = log_dir.join(LOG_FILE_NAME);
    let writer = RotatingFileMakeWriter::new(log_dir.clone(), LOG_FILE_NAME, LOG_MAX_BYTES, LOG_MAX_FILES)?;
    let (non_blocking, guard) = tracing_appender::non_blocking(writer);

    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    let env_filter = EnvFilter::try_new(filter).unwrap_or_else(|_| EnvFilter::new("info"));

    let fmt_stdout = tracing_subscriber::fmt::layer().with_target(false);
    let fmt_file = tracing_subscriber::fmt::layer()
        .with_target(false)
        .with_ansi(false)
        .with_writer(non_blocking);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_stdout)
        .with(fmt_file)
        .init();

    Ok(LogOutput { log_dir, log_file, guard })
}

fn select_log_dir() -> io::Result<PathBuf> {
    if let Ok(dir) = std::env::var("CHAMELEON_LOG_DIR") {
        return Ok(PathBuf::from(dir));
    }

    #[cfg(windows)]
    {
        if let Ok(program_data) = std::env::var("ProgramData") {
            return Ok(PathBuf::from(program_data).join("Chameleon").join("logs"));
        }
    }

    #[cfg(unix)]
    {
        let system_path = PathBuf::from("/var/log/chameleon");
        if fs::create_dir_all(&system_path).is_ok() {
            return Ok(system_path);
        }
        if let Ok(home) = std::env::var("HOME") {
            return Ok(PathBuf::from(home).join(".chameleon").join("logs"));
        }
    }

    Ok(PathBuf::from("./logs"))
}

struct RotatingFileMakeWriter {
    inner: Arc<RotatingFile>,
}

impl RotatingFileMakeWriter {
    fn new(dir: PathBuf, file_name: &str, max_bytes: u64, max_files: usize) -> io::Result<Self> {
        let inner = RotatingFile::new(dir, file_name, max_bytes, max_files)?;
        Ok(Self { inner: Arc::new(inner) })
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for RotatingFileMakeWriter {
    type Writer = RotatingFileWriter;

    fn make_writer(&'a self) -> Self::Writer {
        RotatingFileWriter {
            inner: self.inner.clone(),
        }
    }
}

struct RotatingFileWriter {
    inner: Arc<RotatingFile>,
}

impl Write for RotatingFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct RotatingFile {
    dir: PathBuf,
    file_name: String,
    max_bytes: u64,
    max_files: usize,
    state: Mutex<RotatingState>,
}

struct RotatingState {
    file: File,
    size: u64,
}

impl RotatingFile {
    fn new(dir: PathBuf, file_name: &str, max_bytes: u64, max_files: usize) -> io::Result<Self> {
        let file_path = dir.join(file_name);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&file_path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            dir,
            file_name: file_name.to_string(),
            max_bytes,
            max_files: max_files.max(2),
            state: Mutex::new(RotatingState { file, size }),
        })
    }

    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        let mut state = self.state.lock().map_err(|_| io::Error::new(io::ErrorKind::Other, "log mutex poisoned"))?;
        if state.size + buf.len() as u64 > self.max_bytes {
            self.rotate(&mut state)?;
        }
        let written = state.file.write(buf)?;
        state.size += written as u64;
        Ok(written)
    }

    fn flush(&self) -> io::Result<()> {
        let mut state = self.state.lock().map_err(|_| io::Error::new(io::ErrorKind::Other, "log mutex poisoned"))?;
        state.file.flush()
    }

    fn rotate(&self, state: &mut RotatingState) -> io::Result<()> {
        state.file.flush()?;
        drop(&state.file);

        let base_path = self.dir.join(&self.file_name);
        for idx in (1..self.max_files).rev() {
            let from = rotated_path(&base_path, idx);
            let to = rotated_path(&base_path, idx + 1);
            if to.exists() {
                let _ = fs::remove_file(&to);
            }
            if from.exists() {
                let _ = fs::rename(&from, &to);
            }
        }
        let rotated = rotated_path(&base_path, 1);
        if rotated.exists() {
            let _ = fs::remove_file(&rotated);
        }
        if base_path.exists() {
            let _ = fs::rename(&base_path, &rotated);
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&base_path)?;
        state.file = file;
        state.size = 0;
        Ok(())
    }
}

fn rotated_path(base: &Path, idx: usize) -> PathBuf {
    let file_name = base
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| LOG_FILE_NAME.to_string());
    base.with_file_name(format!("{}.{}", file_name, idx))
}
