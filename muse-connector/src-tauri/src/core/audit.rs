//! 有界日志缓冲、序号和文件轮转。UI 订阅事件，重连按序号补齐。
use chrono::{SecondsFormat, Utc};
use serde::Serialize;
use std::collections::VecDeque;
use std::io::{self, BufRead, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
use tokio::sync::broadcast;

const LOG_CACHE_LIMIT: usize = 1000;

fn history_tail(mut file: std::fs::File) -> io::Result<Vec<u8>> {
    const CHUNK: u64 = 16 * 1024;
    let mut position = file.metadata()?.len();
    let mut chunks = Vec::new();
    let mut breaks = 0;
    while position > 0 && breaks <= LOG_CACHE_LIMIT {
        let length = position.min(CHUNK);
        position -= length;
        let mut bytes = vec![0; length as usize];
        file.seek(SeekFrom::Start(position))?;
        file.read_exact(&mut bytes)?;
        breaks += bytes.iter().filter(|&&b| b == b'\n').count();
        chunks.push(bytes);
    }
    let mut bytes: Vec<_> = chunks.into_iter().rev().flatten().collect();
    // A trailing newline closes the last record and does not add a record.
    let end = bytes.len() - usize::from(bytes.last() == Some(&b'\n'));
    if let Some((start, _)) = bytes[..end]
        .iter()
        .enumerate()
        .rev()
        .filter(|(_, byte)| **byte == b'\n')
        .nth(LOG_CACHE_LIMIT - 1)
    {
        bytes.drain(..=start);
    }
    Ok(bytes)
}

#[derive(Debug, Serialize)]
pub struct AuditEntry {
    pub ts: String,
    pub client: String,
    pub method: String,
    pub endpoint: Option<String>,
    pub authed: bool,
    pub root: Option<String>,
    pub path: Option<String>,
    pub code: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_backend: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search_ms: Option<u64>,
}
#[derive(Debug, Clone, Serialize)]
pub struct LogRecord {
    pub seq: u64,
    pub kind: String,
    pub text: String,
    pub persisted: bool,
}
#[derive(Debug, Serialize)]
pub struct LogBatch {
    pub entries: Vec<LogRecord>,
    pub last_seq: u64,
    pub gap: bool,
    pub error: Option<String>,
}
#[derive(Default)]
struct Buffer {
    seq: u64,
    cleared_seq: u64,
    entries: VecDeque<LogRecord>,
    error: Option<String>,
}
pub struct Audit {
    path: PathBuf,
    max_bytes: u64,
    keep: u32,
    kind: String,
    state: Mutex<Buffer>,
    tx: broadcast::Sender<String>,
    events: broadcast::Sender<LogRecord>,
    secrets: RwLock<Vec<String>>,
}
impl Audit {
    pub fn new(path: PathBuf, max_bytes: u64, keep: u32) -> (Self, broadcast::Receiver<String>) {
        Self::with_kind(path, max_bytes, keep, "audit")
    }
    pub fn runtime(path: PathBuf) -> Self {
        Self::with_kind(path, 10 * 1024 * 1024, 3, "runtime").0
    }
    fn with_kind(
        path: PathBuf,
        max_bytes: u64,
        keep: u32,
        kind: &str,
    ) -> (Self, broadcast::Receiver<String>) {
        let (tx, rx) = broadcast::channel(LOG_CACHE_LIMIT);
        let (events, _) = broadcast::channel(LOG_CACHE_LIMIT);
        let mut buffer = Buffer::default();
        if let Ok(file) = std::fs::File::open(&path) {
            match history_tail(file) {
                Ok(bytes) => {
                    // Cursors are local to this run and only cover retained history.
                    for line in io::Cursor::new(bytes).lines() {
                        let Ok(text) = line else {
                            buffer.error = Some("读取历史日志失败".into());
                            break;
                        };
                        buffer.seq += 1;
                        buffer.entries.push_back(LogRecord {
                            seq: buffer.seq,
                            kind: kind.into(),
                            text,
                            persisted: true,
                        });
                    }
                }
                Err(_) => buffer.error = Some("读取历史日志失败".into()),
            }
        }
        (
            Self {
                path,
                max_bytes,
                keep: keep.max(1),
                kind: kind.into(),
                state: Mutex::new(buffer),
                tx,
                events,
                secrets: RwLock::new(Vec::new()),
            },
            rx,
        )
    }
    pub fn record(&self, entry: &AuditEntry) {
        self.append(serde_json::to_string(entry).unwrap_or_default());
    }
    pub fn runtime_entry(&self, level: &str, message: &str) {
        self.append(
            serde_json::json!({"ts":now_iso(),"level":level,"message":message}).to_string(),
        );
    }
    fn append(&self, line: String) {
        let line = self.redact(&line);
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let result = self.rotate_if_needed().and_then(|_| {
            let mut f = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            writeln!(f, "{line}")
        });
        state.error = result.as_ref().err().map(|e| {
            format!(
                "{}日志写入失败：{}",
                if self.kind == "audit" {
                    "审计"
                } else {
                    "运行"
                },
                e.kind()
            )
        });
        state.seq += 1;
        let record = LogRecord {
            seq: state.seq,
            kind: self.kind.clone(),
            text: line.clone(),
            persisted: result.is_ok(),
        };
        state.entries.push_back(record.clone());
        if state.entries.len() > LOG_CACHE_LIMIT {
            state.entries.pop_front();
        }
        let _ = self.tx.send(line);
        let _ = self.events.send(record);
    }
    pub fn subscribe(&self) -> broadcast::Receiver<LogRecord> {
        self.events.subscribe()
    }
    pub fn protect_secret(&self, value: &str) {
        if value.is_empty() {
            return;
        }
        {
            let mut secrets = self.secrets.write().unwrap();
            if !secrets.iter().any(|s| s == value) {
                secrets.push(value.to_string());
            }
        }
        let mut buffer = self.state.lock().unwrap();
        for record in &mut buffer.entries {
            record.text = self.redact(&record.text);
        }
    }
    pub fn error(&self) -> Option<String> {
        self.state.lock().unwrap().error.clone()
    }
    pub(crate) fn redact_text(&self, value: &str) -> String {
        self.redact(value)
    }
    fn redact(&self, value: &str) -> String {
        let mut result = value.to_string();
        for secret in self.secrets.read().unwrap().iter() {
            result = result.replace(secret, "[已隐藏令牌]");
        }
        result = redact_agent_tokens(&result);
        let trimmed = result.trim();
        if trimmed.len() == 43 && trimmed.bytes().all(is_token_byte) {
            return "[已隐藏令牌]".into();
        }
        result
    }
    pub fn recent(&self, after: Option<u64>, limit: usize) -> LogBatch {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let gap = after.is_some_and(|seq| {
            seq < state.cleared_seq
                || state
                    .entries
                    .front()
                    .is_some_and(|r| seq.saturating_add(1) < r.seq)
                || seq > state.seq
        });
        let mut entries: Vec<_> = state
            .entries
            .iter()
            .filter(|r| gap || after.is_none_or(|s| r.seq > s))
            .cloned()
            .collect();
        if entries.len() > limit.min(LOG_CACHE_LIMIT) {
            entries.drain(..entries.len() - limit.min(LOG_CACHE_LIMIT));
        }
        LogBatch {
            entries,
            last_seq: state.seq,
            gap,
            error: state.error.clone(),
        }
    }
    pub fn disk_bytes(&self) -> u64 {
        let mut total = std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        for n in 1..=self.keep {
            total = total.saturating_add(
                std::fs::metadata(suffix(&self.path, n))
                    .map(|m| m.len())
                    .unwrap_or(0),
            );
        }
        total
    }
    pub fn clear(&self) -> Result<(), String> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        for path in
            std::iter::once(self.path.clone()).chain((1..=self.keep).map(|n| suffix(&self.path, n)))
        {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(format!("清除日志文件失败：{}", e.kind()));
                }
            }
        }
        state.entries.clear();
        state.error = None;
        state.seq += 1;
        state.cleared_seq = state.seq;
        Ok(())
    }
    fn rotate_if_needed(&self) -> io::Result<()> {
        match std::fs::metadata(&self.path) {
            Ok(md) if md.len() >= self.max_bytes => {}
            Ok(_) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        }
        let oldest = suffix(&self.path, self.keep);
        if oldest.exists() {
            std::fs::remove_file(oldest)?;
        }
        for n in (1..self.keep).rev() {
            let from = suffix(&self.path, n);
            if from.exists() {
                std::fs::rename(from, suffix(&self.path, n + 1))?;
            }
        }
        std::fs::rename(&self.path, suffix(&self.path, 1))
    }
}
fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-' || b == b'_'
}

fn redact_agent_tokens(value: &str) -> String {
    const PREFIX: &str = "mfa_";
    const BODY_LEN: usize = 43;
    const TOTAL_LEN: usize = PREFIX.len() + BODY_LEN;

    let bytes = value.as_bytes();
    let mut out = String::with_capacity(value.len());
    let mut cursor = 0;
    while let Some(offset) = value[cursor..].find(PREFIX) {
        let start = cursor + offset;
        let end = start + TOTAL_LEN;
        let valid_before = start == 0 || !is_token_byte(bytes[start - 1]);
        let valid_after = end == bytes.len() || (end < bytes.len() && !is_token_byte(bytes[end]));
        if valid_before
            && end <= bytes.len()
            && valid_after
            && bytes[start + PREFIX.len()..end]
                .iter()
                .all(|&b| is_token_byte(b))
        {
            out.push_str(&value[cursor..start]);
            out.push_str("[已隐藏令牌]");
            cursor = end;
        } else {
            let next = start + PREFIX.len();
            out.push_str(&value[cursor..next]);
            cursor = next;
        }
    }
    out.push_str(&value[cursor..]);
    out
}

fn suffix(path: &Path, n: u32) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}
pub fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reopens_the_last_thousand_utf8_records_and_continues_the_cursor() {
        let dir =
            std::env::temp_dir().join(format!("muse-log-tail-{}", crate::core::token::generate()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("runtime.log");
        let lines: Vec<_> = (0..1900).map(|i| format!("测试历史记录 {i}")).collect();
        for trailing_newline in ["", "\r\n"] {
            std::fs::write(&path, lines.join("\r\n") + trailing_newline).unwrap();
            let log = Audit::runtime(path.clone());
            let batch = log.recent(None, 1000);
            assert!(batch.error.is_none());
            assert_eq!(
                batch
                    .entries
                    .iter()
                    .map(|record| record.text.as_str())
                    .collect::<Vec<_>>(),
                lines[900..]
            );
            assert_eq!(batch.last_seq, 1000);
            log.runtime_entry("info", "next record");
            let next = log.recent(Some(batch.last_seq), 1000);
            assert!(!next.gap);
            assert_eq!(next.entries.len(), 1);
            assert_eq!(next.last_seq, 1001);
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn buffer_is_bounded_and_rotation_survives_more_than_three_rounds() {
        let dir = std::env::temp_dir().join(format!("muse-log-{}", crate::core::token::generate()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("runtime.log");
        let (log, _) = Audit::new(path.clone(), 128, 3);
        for n in 0..1100 {
            log.runtime_entry("info", &format!("message {n}"));
        }
        let batch = log.recent(Some(1), 1000);
        assert_eq!(batch.entries.len(), 1000);
        assert!(batch.gap);
        assert_eq!(batch.last_seq, 1100);
        assert!(batch.error.is_none());
        for n in 1..=3 {
            assert!(suffix(&path, n).is_file());
        }
        assert!(!suffix(&path, 4).exists());
        assert!(log.recent(Some(1100), 1000).entries.is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn disk_failure_is_visible_and_not_reported_as_persisted() {
        let dir =
            std::env::temp_dir().join(format!("muse-log-error-{}", crate::core::token::generate()));
        std::fs::create_dir_all(&dir).unwrap();
        let log = Audit::runtime(dir.clone());
        log.runtime_entry("error", "test");
        let b = log.recent(None, 5);
        assert!(b.error.is_some());
        assert!(!b.entries[0].persisted);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn secrets_are_redacted_from_loaded_and_new_visible_records() {
        let dir = std::env::temp_dir().join(format!(
            "muse-log-secret-{}",
            crate::core::token::generate()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server.log");
        let secret = crate::core::token::generate();
        std::fs::write(
            &path,
            format!("{secret}\nprevious error contains {secret}\n"),
        )
        .unwrap();
        let log = Audit::runtime(path.clone());
        log.protect_secret(&secret);
        log.runtime_entry("error", &format!("tool returned {secret}"));
        assert!(
            log.recent(None, 1000)
                .entries
                .iter()
                .all(|e| !e.text.contains(&secret))
        );
        assert!(
            !std::fs::read_to_string(path)
                .unwrap()
                .lines()
                .last()
                .unwrap()
                .contains(&secret)
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn rotated_agent_tokens_are_redacted_by_shape_without_touching_normal_text() {
        let dir =
            std::env::temp_dir().join(format!("muse-log-mfa-{}", crate::core::token::generate()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server.log");
        let rotated = format!("mfa_{}", crate::core::token::generate());
        let log = Audit::runtime(path.clone());
        log.runtime_entry(
            "error",
            &format!("header Bearer {rotated} failed; keep mfa_short_name and normal text"),
        );
        let entry = &log.recent(None, 10).entries[0].text;
        assert!(!entry.contains(&rotated));
        assert!(entry.contains("[已隐藏令牌]"));
        assert!(entry.contains("mfa_short_name"));
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn clear_removes_rotated_files_resets_disk_bytes_and_signals_gap() {
        let dir =
            std::env::temp_dir().join(format!("muse-log-clear-{}", crate::core::token::generate()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("server.log");
        let (log, _rx) = Audit::with_kind(path.clone(), 64, 3, "runtime");
        log.runtime_entry("info", "first line long enough to trigger rotation soon");
        log.runtime_entry("info", "second line long enough to rotate the log file");
        let before = log.recent(None, 100);
        assert!(!before.entries.is_empty());
        assert!(log.disk_bytes() > 0);

        log.clear().unwrap();
        assert_eq!(log.disk_bytes(), 0);
        let after_clear = log.recent(Some(before.last_seq), 100);
        assert!(after_clear.gap);
        assert!(after_clear.entries.is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
