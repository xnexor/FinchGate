//! A local, disposable index of filenames and basic metadata. The caller owns authorization.
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap, VecDeque};
use std::fmt;
use std::fs::{self, ReadDir};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, UNIX_EPOCH};

use super::access::{canonicalize_direct, is_reparse, protected_path, reject_reparse_ancestors};

const INDEX_VERSION: u32 = 1;
const DEFAULT_RESULTS: usize = 30;
const MAX_RESULTS: usize = 100;
const MAX_RESPONSE_BYTES: usize = 48 * 1024;
const MAX_PATH_BYTES: usize = 8192;
const MAX_INDEX_ENTRIES: usize = 4_000_000;
const MAX_INDEX_PATH_BYTES: usize = 384 * 1024 * 1024;
const MAX_CACHE_BYTES: u64 = 768 * 1024 * 1024;
const MAX_SCAN_DEPTH: usize = 256;
const SCAN_BATCH: usize = 2048;
const SCAN_SLICE: Duration = Duration::from_millis(180);
const CURSOR_TTL: Duration = Duration::from_secs(300);
const MAX_CURSORS: usize = 128;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct SearchRequest {
    pub root: Option<String>,
    pub name: String,
    pub extensions: Vec<String>,
    pub modified_since_ms: Option<u64>,
    pub modified_before_ms: Option<u64>,
    pub limit: Option<usize>,
    pub cursor: Option<String>,
    pub refresh: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct SearchHit {
    pub root: String,
    pub path: String,
    pub kind: FileKind,
    pub size: u64,
    pub modified_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SearchResponse {
    pub hits: Vec<SearchHit>,
    pub complete: bool,
    pub scanning: bool,
    pub next_cursor: Option<String>,
    pub backend: &'static str,
    pub scopes: Vec<SearchScope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u32>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SearchScope {
    pub root: String,
    pub state: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FileKind {
    File,
    Directory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SearchError {
    Invalid,
    Cancelled,
    Busy,
    CursorExpired,
    IndexCleared,
}

impl fmt::Display for SearchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Invalid => "搜索参数无效",
            Self::Cancelled => "搜索已取消",
            Self::Busy => "搜索正在处理，请稍后重试",
            Self::CursorExpired => "搜索结果已更新，请重新查询",
            Self::IndexCleared => "本机索引已清除，请在文件权限中重新建立索引",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for SearchError {}

#[derive(Deserialize, Serialize, PartialEq, Eq)]
struct Scope {
    roots: Vec<(String, PathBuf)>,
    excluded: Vec<PathBuf>,
}

impl Scope {
    fn new(roots: &BTreeMap<String, PathBuf>, excluded: &[PathBuf]) -> Result<Self, SearchError> {
        if roots.is_empty() || roots.values().any(|path| !path.is_absolute()) {
            return Err(SearchError::Invalid);
        }
        let roots = roots
            .iter()
            .map(|(alias, path)| {
                (
                    alias.clone(),
                    canonicalize_direct(path).unwrap_or_else(|| path.clone()),
                )
            })
            .collect();
        let mut excluded: Vec<_> = excluded
            .iter()
            .flat_map(|path| {
                [
                    path.clone(),
                    super::path_guard::canonical_non_strict(path).unwrap_or_else(|_| path.clone()),
                ]
            })
            .collect();
        excluded.sort_unstable();
        excluded.dedup();
        Ok(Self { roots, excluded })
    }

    fn allowed(&self, path: &Path) -> bool {
        !protected_path(path, &self.excluded)
    }
}

#[derive(Clone, Deserialize, Serialize)]
struct Entry {
    root: usize,
    path: String,
    kind: FileKind,
    modified_ms: Option<u64>,
}

impl Entry {
    fn rank(&self, other: &Self) -> Ordering {
        other
            .modified_ms
            .cmp(&self.modified_ms)
            .then_with(|| self.root.cmp(&other.root))
            .then_with(|| self.path.cmp(&other.path))
    }
}

#[derive(Eq, PartialEq)]
struct Ranked<'a>(&'a Entry);

impl Eq for Entry {}
impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.rank(other) == Ordering::Equal
    }
}

impl Ord for Ranked<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.rank(other.0)
    }
}

impl PartialOrd for Ranked<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Deserialize, Serialize)]
struct Snapshot {
    entries: Vec<Entry>,
    incomplete_roots: BTreeSet<usize>,
}

#[derive(Deserialize, Serialize)]
struct Cache<S, I> {
    version: u32,
    scope: S,
    snapshot: I,
}

#[derive(Default)]
struct Scan {
    entries: Vec<Entry>,
    incomplete_roots: BTreeSet<usize>,
    roots: VecDeque<usize>,
    active_root: usize,
    pending: Vec<ReadDir>,
    path_bytes: usize,
    worker: Option<Arc<()>>,
    priority: VecDeque<(usize, PathBuf)>,
    visited_priority: BTreeSet<PathBuf>,
}

impl Scan {
    fn step(&mut self, scope: &Scope, cancel: &AtomicBool) -> Result<bool, SearchError> {
        let started = Instant::now();
        for _ in 0..SCAN_BATCH {
            check_cancel(cancel)?;
            if started.elapsed() >= SCAN_SLICE {
                return Ok(false);
            }
            let Some(directory) = self.pending.last_mut() else {
                if let Some((root, path)) = self.priority.pop_front() {
                    self.active_root = root;
                    self.open_directory(&path);
                    self.visited_priority.insert(path);
                    continue;
                }
                let Some(root) = self.roots.pop_front() else {
                    return Ok(true);
                };
                self.active_root = root;
                let path = &scope.roots[root].1;
                if scope.allowed(path) {
                    if reject_reparse_ancestors(path).is_ok() {
                        self.open_directory(path);
                    } else {
                        self.incomplete_roots.insert(root);
                    }
                }
                continue;
            };
            let entry = match directory.next() {
                None => {
                    self.pending.pop();
                    continue;
                }
                Some(Ok(entry)) => entry,
                Some(Err(_)) => {
                    self.incomplete_roots.insert(self.active_root);
                    continue;
                }
            };
            let path = entry.path();
            if !scope.allowed(&path) {
                continue;
            }
            let Ok(metadata) = entry.metadata() else {
                self.incomplete_roots.insert(self.active_root);
                continue;
            };
            if is_reparse(&metadata) {
                continue;
            }
            let kind = if metadata.is_dir() {
                FileKind::Directory
            } else if metadata.is_file() {
                FileKind::File
            } else {
                continue;
            };
            let relative = path
                .strip_prefix(&scope.roots[self.active_root].1)
                .ok()
                .and_then(relative_name);
            let Some(relative) = relative else {
                self.incomplete_roots.insert(self.active_root);
                continue;
            };
            if self.entries.len() >= MAX_INDEX_ENTRIES
                || self.path_bytes.saturating_add(relative.len()) > MAX_INDEX_PATH_BYTES
            {
                self.incomplete_roots.insert(self.active_root);
                self.incomplete_roots.extend(self.roots.drain(..));
                self.pending.clear();
                return Ok(true);
            }
            self.path_bytes += relative.len();
            self.entries.push(Entry {
                root: self.active_root,
                path: relative,
                kind,
                modified_ms: modified_ms(&metadata),
            });
            if kind == FileKind::Directory && !self.visited_priority.contains(&path) {
                self.open_directory(&path);
            }
        }
        Ok(false)
    }

    fn open_directory(&mut self, path: &Path) {
        // Check the resolved directory again before traversing it. Cached candidates receive
        // a separate check against the live filesystem before their metadata is returned.
        let directory = (self.pending.len() < MAX_SCAN_DEPTH)
            .then(|| canonicalize_direct(path))
            .flatten()
            .and_then(|canonical| fs::read_dir(canonical).ok());
        if let Some(directory) = directory {
            self.pending.push(directory);
        } else {
            self.incomplete_roots.insert(self.active_root);
        }
    }
}

fn relative_name(path: &Path) -> Option<String> {
    let mut name = String::new();
    for component in path.components() {
        let Component::Normal(part) = component else {
            return None;
        };
        let part = part.to_str()?;
        if part.contains(['\\', ':']) || part.chars().any(char::is_control) {
            return None;
        }
        if !name.is_empty() {
            name.push('/');
        }
        name.push_str(part);
    }
    (!name.is_empty() && name.len() <= MAX_PATH_BYTES).then_some(name)
}

fn modified_ms(metadata: &fs::Metadata) -> Option<u64> {
    metadata
        .modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()?
        .as_millis()
        .try_into()
        .ok()
}

struct Query {
    root: Option<usize>,
    name: String,
    extensions: Vec<String>,
    since: Option<u64>,
    before: Option<u64>,
    limit: usize,
}

impl Query {
    fn new(request: &SearchRequest, scope: &Scope) -> Result<Self, SearchError> {
        let limit = request.limit.unwrap_or(DEFAULT_RESULTS);
        let invalid_dates = matches!((request.modified_since_ms, request.modified_before_ms),
            (Some(since), Some(before)) if since >= before);
        if request.name.len() > 512
            || request.extensions.len() > 32
            || !(1..=MAX_RESULTS).contains(&limit)
            || invalid_dates
            || request
                .cursor
                .as_ref()
                .is_some_and(|token| token.len() > 64 || request.refresh)
        {
            return Err(SearchError::Invalid);
        }
        let root = request
            .root
            .as_ref()
            .map(|alias| {
                scope
                    .roots
                    .iter()
                    .position(|(root, _)| root == alias)
                    .ok_or(SearchError::Invalid)
            })
            .transpose()?;
        let mut extensions = Vec::with_capacity(request.extensions.len());
        for extension in &request.extensions {
            let extension = extension.trim_start_matches('.');
            if extension.is_empty()
                || extension.len() > 32
                || extension.contains(['.', '/', '\\', ':'])
            {
                return Err(SearchError::Invalid);
            }
            extensions.push(extension.to_lowercase());
        }
        extensions.sort_unstable();
        extensions.dedup();
        Ok(Self {
            root,
            name: request.name.trim().to_lowercase(),
            extensions,
            since: request.modified_since_ms,
            before: request.modified_before_ms,
            limit,
        })
    }

    fn signature(&self) -> u64 {
        let mut state = DefaultHasher::new();
        (
            self.root,
            &self.name,
            &self.extensions,
            self.since,
            self.before,
        )
            .hash(&mut state);
        state.finish()
    }

    fn matches_time(&self, modified_ms: Option<u64>) -> bool {
        self.since
            .is_none_or(|since| modified_ms.is_some_and(|time| time >= since))
            && self
                .before
                .is_none_or(|before| modified_ms.is_some_and(|time| time < before))
    }

    fn matches(&self, entry: &Entry) -> bool {
        if self.root.is_some_and(|root| entry.root != root) || !self.matches_time(entry.modified_ms)
        {
            return false;
        }
        let name = entry.path.rsplit('/').next().unwrap_or_default();
        if !self.extensions.is_empty() {
            let Some(extension) = Path::new(name).extension().and_then(|part| part.to_str()) else {
                return false;
            };
            if entry.kind != FileKind::File
                || self
                    .extensions
                    .binary_search(&extension.to_lowercase())
                    .is_err()
            {
                return false;
            }
        }
        self.name.is_empty() || contains_folded(name, &self.name)
    }
}

fn contains_folded(name: &str, lower: &str) -> bool {
    if name.is_ascii() && lower.is_ascii() {
        name.as_bytes()
            .windows(lower.len())
            .any(|slice| slice.eq_ignore_ascii_case(lower.as_bytes()))
    } else {
        name.to_lowercase().contains(lower)
    }
}

struct Cursor {
    token: String,
    query: u64,
    position: usize,
    expires: Instant,
}

#[derive(Default)]
struct State {
    scope: Option<Arc<Scope>>,
    snapshot: Option<Arc<Snapshot>>,
    scan: Option<Scan>,
    root_stamps: Vec<Option<u64>>,
    current: bool,
    cursors: VecDeque<Cursor>,
    #[cfg(windows)]
    watches: Vec<Option<DirectoryWatch>>,
    changed_roots: BTreeSet<usize>,
    next_reconcile: Option<Instant>,
}

#[cfg(windows)]
struct DirectoryWatch(std::mem::ManuallyDrop<std::os::windows::io::OwnedHandle>);

#[cfg(windows)]
impl DirectoryWatch {
    fn new(path: &Path) -> Option<Self> {
        use std::os::windows::{ffi::OsStrExt, io::FromRawHandle};
        use windows_sys::Win32::{Foundation::INVALID_HANDLE_VALUE, Storage::FileSystem::*};
        let path: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
        let handle = unsafe {
            FindFirstChangeNotificationW(
                path.as_ptr(),
                1,
                FILE_NOTIFY_CHANGE_FILE_NAME
                    | FILE_NOTIFY_CHANGE_DIR_NAME
                    | FILE_NOTIFY_CHANGE_LAST_WRITE,
            )
        };
        (handle != INVALID_HANDLE_VALUE && !handle.is_null()).then(|| {
            Self(std::mem::ManuallyDrop::new(unsafe {
                std::os::windows::io::OwnedHandle::from_raw_handle(handle)
            }))
        })
    }

    fn poll(&self) -> bool {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::{
            Foundation::WAIT_OBJECT_0, Storage::FileSystem::FindNextChangeNotification,
            System::Threading::WaitForSingleObject,
        };
        let handle = self.0.as_raw_handle();
        if unsafe { WaitForSingleObject(handle, 0) } != WAIT_OBJECT_0 {
            return false;
        }
        unsafe { FindNextChangeNotification(handle) };
        true
    }
}

#[cfg(windows)]
impl Drop for DirectoryWatch {
    fn drop(&mut self) {
        use std::os::windows::io::AsRawHandle;
        unsafe {
            windows_sys::Win32::Storage::FileSystem::FindCloseChangeNotification(
                self.0.as_raw_handle(),
            )
        };
    }
}

pub struct SearchIndex {
    cache_path: PathBuf,
    cache_write: Mutex<()>,
    state: Mutex<State>,
    dirty: AtomicBool,
    #[cfg(windows)]
    external_pages: Mutex<VecDeque<ExternalCursor>>,
}

#[cfg(windows)]
struct ExternalCursor {
    token: String,
    signature: u64,
    scope: Arc<Scope>,
    entries: Arc<Vec<Entry>>,
    position: usize,
    covered: bool,
    backend: &'static str,
    expires: Instant,
}

impl SearchIndex {
    pub(super) fn reset(&self) {
        let _write = self.cache_write.lock().unwrap();
        *self.state.lock().unwrap() = State::default();
        self.mark_dirty();
    }

    pub fn new(cache_path: PathBuf) -> Self {
        Self {
            cache_path,
            cache_write: Mutex::new(()),
            state: Mutex::new(State::default()),
            dirty: AtomicBool::new(false),
            #[cfg(windows)]
            external_pages: Mutex::new(VecDeque::new()),
        }
    }

    pub fn mark_dirty(&self) {
        self.dirty.store(true, AtomicOrdering::Release);
        #[cfg(windows)]
        self.external_pages.lock().unwrap().clear();
    }

    #[cfg(windows)]
    pub(super) fn search_everything(
        &self,
        engine: &super::everything::Everything,
        roots: &BTreeMap<String, PathBuf>,
        authorized_roots: &[PathBuf],
        excluded: &[PathBuf],
        request: &SearchRequest,
        cancel: &AtomicBool,
        allows: &impl Fn(&str, &str) -> bool,
    ) -> Result<Option<SearchResponse>, SearchError> {
        check_cancel(cancel)?;
        let scope = Arc::new(Scope::new(roots, excluded)?);
        let query = Query::new(request, &scope)?;
        let signature = query.signature();
        let now = Instant::now();
        let (entries, position, covered, scanning, backend) = if let Some(cursor) = &request.cursor
        {
            if !cursor.starts_with("ev-") {
                return Ok(None);
            }
            let pages = self.external_pages.lock().unwrap();
            let page = pages
                .iter()
                .find(|page| {
                    page.token == *cursor
                        && page.signature == signature
                        && page.scope == scope
                        && page.expires > now
                })
                .ok_or(SearchError::CursorExpired)?;
            (
                page.entries.clone(),
                page.position,
                page.covered,
                false,
                page.backend,
            )
        } else {
            // Both the requested and authorized engine scopes must use the same root form.
            // Scope canonicalization above is for result validation and may add a Win32 prefix.
            let roots: Vec<_> = roots.values().cloned().collect();
            let Some(candidates) = engine.query(&roots, authorized_roots, &request.name, cancel)
            else {
                return Ok(None);
            };
            if !candidates.covered && !candidates.scanning {
                // The built-in index can keep paging and ranking past the IPC candidate budget.
                return Ok(None);
            }
            let fast_count = roots
                .iter()
                .filter(|root| candidates.ntfs_roots.contains(root))
                .count();
            let backend = if fast_count == 0 {
                "everything"
            } else if fast_count == roots.len() {
                "everything_ntfs"
            } else {
                "everything_mixed"
            };
            let covered = candidates.covered;
            let mut unique = BTreeSet::new();
            let mut entries = Vec::new();
            for path in candidates.paths {
                check_cancel(cancel)?;
                for (root, (alias, base)) in scope.roots.iter().enumerate() {
                    if let Some(entry) = external_entry(&path, root, alias, base, &scope, allows)
                        && query.matches(&entry)
                        && unique.insert((root, entry.path.to_uppercase()))
                    {
                        entries.push(entry);
                    }
                }
            }
            entries.sort_unstable_by(Entry::rank);
            (Arc::new(entries), 0, covered, candidates.scanning, backend)
        };

        let state = if scanning {
            "indexing"
        } else if covered {
            "ready"
        } else {
            "partial"
        };
        let mut output = SearchResponse {
            hits: Vec::new(),
            complete: covered && !scanning,
            scanning,
            next_cursor: None,
            backend,
            scopes: scope
                .roots
                .iter()
                .map(|(root, _)| SearchScope {
                    root: root.clone(),
                    state,
                })
                .collect(),
            retry_after_ms: scanning.then_some(3000),
        };
        let mut bytes = 512;
        for (index, entry) in entries.iter().enumerate().skip(position) {
            check_cancel(cancel)?;
            let path = scope.roots[entry.root].1.join(&entry.path);
            if path
                .parent()
                .is_none_or(|parent| fs::read_dir(parent).is_err())
            {
                continue;
            }
            let Some(hit) =
                live_hit(entry, &scope, allows).filter(|hit| query.matches_time(hit.modified_ms))
            else {
                continue;
            };
            if !add_hit(&mut output, hit, query.limit, &mut bytes) {
                if !scanning {
                    let token = format!("ev-{}", super::token::generate());
                    let mut pages = self.external_pages.lock().unwrap();
                    pages.retain(|page| page.expires > now);
                    if pages.len() >= 16 {
                        pages.pop_front();
                    }
                    pages.push_back(ExternalCursor {
                        token: token.clone(),
                        signature,
                        scope,
                        entries: entries.clone(),
                        position: index,
                        covered,
                        backend,
                        expires: now + CURSOR_TTL,
                    });
                    output.next_cursor = Some(token);
                }
                break;
            }
        }
        check_cancel(cancel)?;
        Ok(Some(output))
    }

    pub(crate) fn claim_pending_scan(&self, cancel: &AtomicBool) -> Option<Arc<()>> {
        let mut state = self.state.try_lock().ok()?;
        if self.dirty.load(AtomicOrdering::Acquire) || cancel.load(AtomicOrdering::Acquire) {
            return None;
        }
        let scan = state.scan.as_mut()?;
        if scan.worker.is_some() {
            return None;
        }
        let worker = Arc::new(());
        scan.worker = Some(worker.clone());
        Some(worker)
    }

    pub(crate) fn advance_pending_scan(&self, worker: &Arc<()>, cancel: &AtomicBool) -> bool {
        let mut state = self.state.lock().unwrap();
        if self.dirty.load(AtomicOrdering::Acquire)
            || !state
                .scan
                .as_ref()
                .and_then(|scan| scan.worker.as_ref())
                .is_some_and(|active| Arc::ptr_eq(active, worker))
        {
            return false;
        }
        match advance_scan(&mut state, cancel) {
            Ok(None) => true,
            Ok(Some(snapshot)) => {
                let scope = state.scope.clone().unwrap();
                drop(state);
                self.persist_if_current(&scope, &snapshot, cancel);
                false
            }
            Err(_) => false,
        }
    }

    pub fn search(
        &self,
        roots: &BTreeMap<String, PathBuf>,
        excluded: &[PathBuf],
        request: &SearchRequest,
        cancel: &AtomicBool,
        allows: impl Fn(&str, &str) -> bool,
    ) -> Result<SearchResponse, SearchError> {
        check_cancel(cancel)?;
        let mut state = self.state.lock().unwrap();
        check_cancel(cancel)?;
        let scope = Scope::new(roots, excluded)?;
        let query = Query::new(request, &scope)?;
        let stamps = scope
            .roots
            .iter()
            .map(|(_, path)| {
                fs::symlink_metadata(path)
                    .ok()
                    .as_ref()
                    .and_then(modified_ms)
            })
            .collect::<Vec<_>>();
        let now = Instant::now();
        let dirty = self.dirty.swap(false, AtomicOrdering::AcqRel);
        if state.scope.as_deref() != Some(&scope) {
            #[cfg(windows)]
            let watches = scope
                .roots
                .iter()
                .map(|(_, root)| DirectoryWatch::new(root))
                .collect();
            *state = State {
                snapshot: load_cache(&self.cache_path, &scope).map(Arc::new),
                scope: Some(Arc::new(scope)),
                root_stamps: stamps.clone(),
                #[cfg(windows)]
                watches,
                ..State::default()
            };
        }
        #[cfg(windows)]
        {
            let changed: Vec<_> = state
                .watches
                .iter()
                .enumerate()
                .filter_map(|(index, watch)| {
                    watch
                        .as_ref()
                        .is_some_and(DirectoryWatch::poll)
                        .then_some(index)
                })
                .collect();
            state.changed_roots.extend(changed);
        }
        if dirty || state.root_stamps != stamps {
            state.cursors.clear();
            state.current = false;
        }
        if dirty {
            state.scan = None;
        }
        let signature = query.signature();
        if let Some(token) = &request.cursor {
            let position = state
                .cursors
                .iter()
                .find(|cursor| {
                    cursor.token == *token && cursor.query == signature && cursor.expires > now
                })
                .map(|cursor| cursor.position)
                .ok_or(SearchError::CursorExpired)?;
            return page(&mut state, &query, position, cancel, &allows);
        }

        let awaiting_reconcile = !state.changed_roots.is_empty();
        let reconcile = awaiting_reconcile && state.next_reconcile.is_none_or(|time| time <= now);
        if state.scan.is_none() && (request.refresh || !state.current || reconcile) {
            let mut changed = state
                .root_stamps
                .iter()
                .zip(&stamps)
                .enumerate()
                .filter_map(|(index, (old, new))| (old != new).then_some(index))
                .collect::<BTreeSet<_>>();
            changed.append(&mut state.changed_roots);
            state.next_reconcile = Some(now + Duration::from_secs(15));
            let root_count = state.scope.as_ref().unwrap().roots.len();
            let roots =
                if dirty || request.refresh || changed.is_empty() || state.snapshot.is_none() {
                    (0..root_count).collect::<VecDeque<_>>()
                } else {
                    changed.into_iter().collect()
                };
            let mut scan = Scan {
                priority: scan_priority(state.scope.as_ref().unwrap(), &roots),
                roots,
                ..Scan::default()
            };
            if let Some(snapshot) = state
                .snapshot
                .as_ref()
                .filter(|_| scan.roots.len() < root_count)
            {
                scan.entries.extend(
                    snapshot
                        .entries
                        .iter()
                        .filter(|entry| !scan.roots.contains(&entry.root))
                        .cloned(),
                );
                scan.incomplete_roots.extend(
                    snapshot
                        .incomplete_roots
                        .iter()
                        .filter(|root| !scan.roots.contains(root)),
                );
                scan.path_bytes = scan.entries.iter().map(|entry| entry.path.len()).sum();
            }
            state.scan = Some(scan);
            state.cursors.clear();
            state.root_stamps = stamps;
            state.current = true;
        }

        let completed = if state
            .scan
            .as_ref()
            .is_some_and(|scan| scan.worker.is_none())
        {
            advance_scan(&mut state, cancel)?
        } else {
            None
        };
        let scope = state.scope.clone().unwrap();
        let response = page(&mut state, &query, 0, cancel, &allows);
        drop(state);
        if let Some(snapshot) = completed {
            self.persist_if_current(&scope, &snapshot, cancel);
        }
        response
    }

    fn persist_if_current(&self, scope: &Scope, snapshot: &Arc<Snapshot>, cancel: &AtomicBool) {
        let _write = self.cache_write.lock().unwrap();
        let current = self
            .state
            .lock()
            .unwrap()
            .snapshot
            .as_ref()
            .is_some_and(|latest| Arc::ptr_eq(latest, snapshot));
        if current && !self.dirty.load(AtomicOrdering::Acquire) && check_cancel(cancel).is_ok() {
            persist_cache(&self.cache_path, scope, snapshot);
        }
    }
}

fn scan_priority(scope: &Scope, scanning: &VecDeque<usize>) -> VecDeque<(usize, PathBuf)> {
    let mut paths = VecDeque::<(usize, PathBuf)>::new();
    for path in [
        dirs::desktop_dir(),
        dirs::document_dir(),
        dirs::download_dir(),
    ]
    .into_iter()
    .flatten()
    {
        let Some(root) = scanning
            .iter()
            .copied()
            .find(|root| protected_path(&path, &[scope.roots[*root].1.clone()]))
        else {
            continue;
        };
        if let Ok(path) = fs::canonicalize(&path)
            && path != scope.roots[root].1
            && scope.allowed(&path)
            && reject_reparse_ancestors(&path).is_ok()
            && !paths
                .iter()
                .any(|(_, existing)| protected_path(&path, &[existing.clone()]))
        {
            paths.push_back((root, path));
        }
    }
    paths
}

fn advance_scan(
    state: &mut State,
    cancel: &AtomicBool,
) -> Result<Option<Arc<Snapshot>>, SearchError> {
    let Some(work) = state.scan.as_mut() else {
        return Ok(None);
    };
    if !work.step(state.scope.as_deref().unwrap(), cancel)? {
        return Ok(None);
    }
    check_cancel(cancel)?;
    let mut work = state.scan.take().unwrap();
    work.entries.sort_unstable_by(Entry::rank);
    check_cancel(cancel)?;
    let snapshot = Arc::new(Snapshot {
        entries: work.entries,
        incomplete_roots: work.incomplete_roots,
    });
    state.snapshot = Some(snapshot.clone());
    Ok(Some(snapshot))
}

fn check_cancel(cancel: &AtomicBool) -> Result<(), SearchError> {
    if cancel.load(AtomicOrdering::Acquire) {
        Err(SearchError::Cancelled)
    } else {
        Ok(())
    }
}

fn load_cache(path: &Path, scope: &Scope) -> Option<Snapshot> {
    let file = fs::File::open(path).ok()?;
    if file.metadata().ok()?.len() > MAX_CACHE_BYTES {
        return None;
    }
    let cache: Cache<Scope, Snapshot> =
        serde_json::from_reader(std::io::BufReader::new(file.take(MAX_CACHE_BYTES))).ok()?;
    if cache.version != INDEX_VERSION
        || &cache.scope != scope
        || cache.snapshot.entries.len() > MAX_INDEX_ENTRIES
        || cache.snapshot.entries.iter().any(|entry| {
            entry.root >= scope.roots.len()
                || relative_name(Path::new(&entry.path)).as_deref() != Some(entry.path.as_str())
        })
        || cache
            .snapshot
            .entries
            .windows(2)
            .any(|pair| pair[0].rank(&pair[1]).is_gt())
    {
        return None;
    }
    Some(cache.snapshot)
}

fn persist_cache(path: &Path, scope: &Scope, snapshot: &Snapshot) {
    let cache = Cache {
        version: INDEX_VERSION,
        scope,
        snapshot,
    };
    let _ = super::storage::atomic_write_with(path, |file| {
        let mut buffered = std::io::BufWriter::with_capacity(128 * 1024, &mut *file);
        serde_json::to_writer(&mut buffered, &cache)?;
        buffered.flush()?;
        drop(buffered);
        if file.metadata()?.len() > MAX_CACHE_BYTES {
            return Err(std::io::Error::other(
                "search index exceeds the cache size limit",
            ));
        }
        Ok(())
    });
}

fn live_hit(
    entry: &Entry,
    scope: &Scope,
    allows: &impl Fn(&str, &str) -> bool,
) -> Option<SearchHit> {
    let (root, base) = &scope.roots[entry.root];
    if !allows(root, &entry.path) {
        return None;
    }
    let path = base.join(&entry.path);
    let actual = canonicalize_direct(&path)?;
    if !scope.allowed(&actual) {
        return None;
    }
    let metadata = fs::symlink_metadata(&actual).ok()?;
    if is_reparse(&metadata) {
        return None;
    }
    let current_kind = if metadata.is_dir() {
        FileKind::Directory
    } else if metadata.is_file() {
        FileKind::File
    } else {
        return None;
    };
    if current_kind != entry.kind {
        return None;
    }
    Some(SearchHit {
        root: root.clone(),
        path: entry.path.clone(),
        kind: current_kind,
        size: if current_kind == FileKind::File {
            metadata.len()
        } else {
            0
        },
        modified_ms: modified_ms(&metadata),
    })
}

#[cfg(windows)]
fn external_entry(
    path: &Path,
    root: usize,
    alias: &str,
    base: &Path,
    scope: &Scope,
    allows: &impl Fn(&str, &str) -> bool,
) -> Option<Entry> {
    if !path.is_absolute() || !protected_path(path, &[base.to_path_buf()]) || !scope.allowed(path) {
        return None;
    }
    let relative: PathBuf = path.components().skip(base.components().count()).collect();
    let path_relative = relative_name(&relative)?;
    if !allows(alias, &path_relative) || fs::read_dir(path.parent()?).is_err() {
        return None;
    }
    let metadata = fs::symlink_metadata(path).ok()?;
    if is_reparse(&metadata) {
        return None;
    }
    let kind = if metadata.is_dir() {
        FileKind::Directory
    } else if metadata.is_file() {
        FileKind::File
    } else {
        return None;
    };
    Some(Entry {
        root,
        path: path_relative,
        kind,
        modified_ms: modified_ms(&metadata),
    })
}

fn page(
    state: &mut State,
    query: &Query,
    position: usize,
    cancel: &AtomicBool,
    allows: &impl Fn(&str, &str) -> bool,
) -> Result<SearchResponse, SearchError> {
    let scope = state.scope.as_ref().unwrap();
    let scanning = state.scan.is_some() || !state.current;
    let mut output = SearchResponse {
        hits: Vec::new(),
        complete: false,
        scanning,
        next_cursor: None,
        backend: "built_in",
        scopes: scope
            .roots
            .iter()
            .enumerate()
            .map(|(index, (root, _))| {
                let state = if let Some(scan) = &state.scan {
                    if scan.roots.contains(&index) {
                        "queued"
                    } else if scan.active_root == index {
                        "indexing"
                    } else if scan.incomplete_roots.contains(&index) {
                        "partial"
                    } else {
                        "ready"
                    }
                } else if state
                    .snapshot
                    .as_ref()
                    .is_some_and(|snapshot| snapshot.incomplete_roots.contains(&index))
                {
                    "partial"
                } else if scanning {
                    "queued"
                } else {
                    "ready"
                };
                SearchScope {
                    root: root.clone(),
                    state,
                }
            })
            .collect(),
        retry_after_ms: scanning.then_some(3000),
    };
    let mut bytes = 512;
    let mut cursor_position = None;
    if let Some(snapshot) = &state.snapshot {
        output.complete = !scanning
            && match query.root {
                Some(root) => !snapshot.incomplete_roots.contains(&root),
                None => snapshot.incomplete_roots.is_empty(),
            };
        for (index, entry) in snapshot.entries.iter().enumerate().skip(position) {
            check_cancel(cancel)?;
            if query.matches(entry) {
                let Some(hit) = live_hit(entry, scope, allows) else {
                    continue;
                };
                if !query.matches_time(hit.modified_ms) {
                    output.complete = false;
                    continue;
                }
                if !add_hit(&mut output, hit, query.limit, &mut bytes) {
                    cursor_position = (!scanning).then_some(index);
                    break;
                }
            }
        }
    }
    // A cached snapshot stays usable during refresh. A new match may already be in the
    // scan, so fall back to its preview when the cached result has no live hits.
    if output.hits.is_empty()
        && let Some(scan) = &state.scan
    {
        let mut preview = BinaryHeap::new();
        for entry in &scan.entries {
            check_cancel(cancel)?;
            if query.matches(entry) {
                preview.push(Ranked(entry));
                if preview.len() > query.limit * 4 {
                    preview.pop();
                }
            }
        }
        for Ranked(entry) in preview.into_sorted_vec() {
            if let Some(hit) =
                live_hit(entry, scope, allows).filter(|hit| query.matches_time(hit.modified_ms))
            {
                if !add_hit(&mut output, hit, query.limit, &mut bytes) {
                    break;
                }
            }
        }
    }
    check_cancel(cancel)?;
    if let Some(position) = cursor_position {
        let mut nonce = [0u8; 16];
        getrandom::getrandom(&mut nonce).map_err(|_| SearchError::Busy)?;
        let token: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
        let now = Instant::now();
        state.cursors.retain(|cursor| cursor.expires > now);
        if state.cursors.len() >= MAX_CURSORS {
            state.cursors.pop_front();
        }
        state.cursors.push_back(Cursor {
            token: token.clone(),
            query: query.signature(),
            position,
            expires: now + CURSOR_TTL,
        });
        output.next_cursor = Some(token);
    }
    Ok(output)
}

fn add_hit(output: &mut SearchResponse, hit: SearchHit, limit: usize, bytes: &mut usize) -> bool {
    let size = serde_json::to_vec(&hit)
        .map(|value| value.len() + 1)
        .unwrap_or(MAX_RESPONSE_BYTES);
    if output.hits.len() >= limit || *bytes + size > MAX_RESPONSE_BYTES {
        return false;
    }
    *bytes += size;
    output.hits.push(hit);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::access::{AccessPolicy, GrantScope};
    use crate::core::access_runtime::AccessRuntime;
    use crate::profile::{ProfileKind, RuntimeProfile};
    use std::time::SystemTime;

    struct Fixture {
        base: PathBuf,
        roots: BTreeMap<String, PathBuf>,
        index: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let base = std::env::temp_dir().join(format!(
                "muse-search-test-{}",
                super::super::token::generate()
            ));
            let root = base.join("public");
            fs::create_dir_all(&root).unwrap();
            let index = base.join("cache/index.json");
            Self {
                base,
                roots: BTreeMap::from([("work".into(), root)]),
                index,
            }
        }

        fn add(&self, relative: &str, seconds: u64) {
            let path = self.roots["work"].join(relative);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let file = fs::File::create(path).unwrap();
            file.set_modified(UNIX_EPOCH + Duration::from_secs(seconds))
                .unwrap();
        }

        fn query(&self, search: &SearchIndex, request: &SearchRequest) -> SearchResponse {
            for _ in 0..32 {
                let result = search
                    .search(
                        &self.roots,
                        &[],
                        request,
                        &AtomicBool::new(false),
                        |_, _| true,
                    )
                    .unwrap();
                if !result.scanning {
                    return result;
                }
            }
            panic!("failed to complete fixture traversal");
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    #[cfg(windows)]
    #[test]
    fn nested_change_updates_a_warm_fallback_index() {
        let fixture = Fixture::new();
        fixture.add("nested/older.txt", 20);
        let search = SearchIndex::new(fixture.index.clone());
        let request = SearchRequest {
            name: "new.txt".into(),
            ..Default::default()
        };
        assert!(fixture.query(&search, &request).hits.is_empty());
        fixture.add("nested/new.txt", 21);
        // Skip the production coalescing delay while exercising real Windows notifications.
        search.state.lock().unwrap().next_reconcile = None;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let response = fixture.query(&search, &request);
            if let Some(hit) = response.hits.first() {
                assert_eq!(hit.path, "nested/new.txt");
                break;
            }
            assert!(Instant::now() < deadline, "nested change was not indexed");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn results_are_filtered_and_paginate_in_modification_order() {
        let fixture = Fixture::new();
        fixture.add("通过-Report.pdf", 20);
        fixture.add("REPORT.pdf", 30);
        fixture.add("report.pdfx", 40);
        fixture.add("other.pdf", 50);
        let search = SearchIndex::new(fixture.index.clone());
        let request = SearchRequest {
            root: Some("work".into()),
            name: "report".into(),
            extensions: vec![".PDF".into()],
            modified_since_ms: Some(20_000),
            modified_before_ms: Some(40_000),
            limit: Some(1),
            ..SearchRequest::default()
        };
        let first = fixture.query(&search, &request);
        assert!(first.complete);
        assert_eq!(first.hits[0].path, "REPORT.pdf");
        let second_request = SearchRequest {
            cursor: first.next_cursor,
            ..request
        };
        assert!(second_request.cursor.is_some());
        let second = fixture.query(&search, &second_request);
        assert_eq!(second.hits[0].path, "通过-Report.pdf");
        assert!(second.next_cursor.is_none());
        search.mark_dirty();
        assert!(matches!(
            search.search(
                &fixture.roots,
                &[],
                &second_request,
                &AtomicBool::new(false),
                |_, _| true
            ),
            Err(SearchError::CursorExpired)
        ));
    }

    #[test]
    fn excludes_protected_paths_before_indexing_and_checks_access_at_result() {
        let fixture = Fixture::new();
        fixture.add("protected/token.txt", 20);
        fixture.add("protected-sibling/other.txt", 10);
        fixture.add("currently-denied.txt", 30);
        let excluded = fixture.roots["work"].join("protected");
        #[cfg(windows)]
        let excluded = PathBuf::from(excluded.to_string_lossy().to_uppercase());
        let search = SearchIndex::new(fixture.index.clone());
        let request = SearchRequest {
            extensions: vec!["txt".into()],
            ..SearchRequest::default()
        };
        let response = search
            .search(
                &fixture.roots,
                &[excluded],
                &request,
                &AtomicBool::new(false),
                |_, path| path != "currently-denied.txt",
            )
            .unwrap();
        assert!(response.complete);
        assert_eq!(
            response
                .hits
                .iter()
                .map(|hit| hit.path.as_str())
                .collect::<Vec<_>>(),
            ["protected-sibling/other.txt"]
        );
        let file = fs::read_to_string(&fixture.index).unwrap();
        assert!(!file.contains("token.txt"));
    }

    #[test]
    fn validated_cache_reopens_and_reconciles_rename() {
        let fixture = Fixture::new();
        fixture.add("nested/old.md", 20);
        let search = SearchIndex::new(fixture.index.clone());
        let request = SearchRequest {
            extensions: vec!["md".into()],
            ..SearchRequest::default()
        };
        assert_eq!(
            fixture.query(&search, &request).hits[0].path,
            "nested/old.md"
        );
        drop(search);
        assert!(load_cache(&fixture.index, &Scope::new(&fixture.roots, &[]).unwrap()).is_some());
        let nested = fixture.roots["work"].join("nested");
        fs::rename(nested.join("old.md"), nested.join("new.md")).unwrap();
        let reopened = SearchIndex::new(fixture.index.clone());
        assert_eq!(
            fixture.query(&reopened, &request).hits[0].path,
            "nested/new.md"
        );
        let current = fs::File::options()
            .write(true)
            .open(nested.join("new.md"))
            .unwrap();
        current.set_modified(SystemTime::now()).unwrap();
        reopened.mark_dirty();
        let new = fixture.query(&reopened, &request);
        assert!(new.hits[0].modified_ms.unwrap() > 20_000);
        assert!(matches!(
            reopened.search(
                &fixture.roots,
                &[],
                &request,
                &AtomicBool::new(true),
                |_, _| true
            ),
            Err(SearchError::Cancelled)
        ));
    }

    #[test]
    fn repeated_refresh_requests_advance_the_same_bounded_scan() {
        let fixture = Fixture::new();
        for number in 0..(SCAN_BATCH + 9) {
            fixture.add(&format!("item-{number:04}.txt"), number as u64);
        }
        let search = SearchIndex::new(fixture.index.clone());
        let request = SearchRequest {
            refresh: true,
            limit: Some(2),
            ..SearchRequest::default()
        };
        let first = search
            .search(
                &fixture.roots,
                &[],
                &request,
                &AtomicBool::new(false),
                |_, _| true,
            )
            .unwrap();
        assert!(first.scanning && !first.complete && first.next_cursor.is_none());
        let final_result = fixture.query(&search, &request);
        assert!(final_result.complete);
        assert_eq!(
            final_result.hits[0].path,
            format!("item-{:04}.txt", SCAN_BATCH + 8)
        );
        assert!(final_result.next_cursor.is_some());
    }

    #[tokio::test]
    async fn pending_scan_advances_without_additional_queries() {
        let fixture = Fixture::new();
        for number in 0..(SCAN_BATCH + 1) {
            fixture.add(&format!("item-{number:04}.txt"), number as u64);
        }
        let profile = RuntimeProfile {
            kind: ProfileKind::Production,
            home: fixture.base.join("profile"),
            onboarding_qa: false,
        };
        let (access, error) = AccessRuntime::open(&profile);
        assert!(error.is_none());
        let policy = AccessPolicy {
            roots: fixture.roots.clone(),
            search: GrantScope::Folders,
            ..AccessPolicy::default()
        };
        access.validate(&policy).unwrap();
        access.save(policy, false).unwrap();
        let request = SearchRequest {
            limit: Some(1),
            ..SearchRequest::default()
        };
        let first = access.clone().search_local(request.clone()).await.unwrap();
        assert!(first.scanning && first.next_cursor.is_none());

        // Completion must occur before the next search request.
        let index = profile.home.join("file-name-index.json");
        tokio::time::timeout(Duration::from_secs(10), async {
            while !index.is_file() {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
        let result = access.search_local(request).await.unwrap();
        assert!(result.complete && !result.scanning);
        assert_eq!(result.hits[0].path, format!("item-{SCAN_BATCH:04}.txt"));
        assert!(result.next_cursor.is_some());
    }
}
