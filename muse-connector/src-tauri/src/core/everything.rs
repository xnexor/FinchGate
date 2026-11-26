//! The bundled Everything client talks to local IPC only.
mod ipc;
#[cfg(test)]
mod ntfs_tests;

use std::collections::VecDeque;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{Error, Read};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const MAX_EXPORT_BYTES: u64 = 8 * 1024 * 1024;
const QUERY_BUDGET: Duration = Duration::from_millis(900);
const MAX_MANAGED_INSTANCES: usize = 3;
const CANDIDATE_PAGE: usize = 256;
const MANAGED_CANDIDATE_LIMIT: usize = 2048;

pub(super) struct Everything {
    binaries: PathBuf,
    state: PathBuf,
    reuse_existing: bool,
    processes: Mutex<Processes>,
}

#[derive(Default)]
struct Processes {
    instances: VecDeque<Instance>,
    ntfs: Option<Instance>,
    retry_ntfs_at: Option<Instant>,
    retry_existing_at: Option<Instant>,
}

#[derive(Debug, Eq, PartialEq)]
struct NtfsVolume {
    root: PathBuf,
    name: String,
}

struct Instance {
    roots: Vec<PathBuf>,
    volumes: Vec<NtfsVolume>,
    name: String,
    cli: PathBuf,
    child: Child,
    _job: super::job::ChildJob,
    ready_deadline: Instant,
    verified_volumes: usize,
}

pub(super) struct Candidates {
    pub paths: Vec<PathBuf>,
    pub scanning: bool,
    pub covered: bool,
    pub ntfs_roots: Vec<PathBuf>,
}

#[derive(serde::Deserialize)]
struct ExportRow {
    filename: PathBuf,
}

enum QueryResult {
    Ready(Vec<PathBuf>),
    Loading,
    Unavailable,
}

impl Everything {
    pub(super) fn discover(app_home: &Path, reuse_existing: bool) -> Option<Self> {
        if std::env::var_os("MUSE_CONNECTOR_DISABLE_EVERYTHING").is_some() {
            return None;
        }
        let binaries = std::env::current_exe().ok()?.parent()?.join("everything");
        Self::new(binaries, app_home.join("everything"), reuse_existing)
    }

    pub(super) fn new(binaries: PathBuf, state: PathBuf, reuse_existing: bool) -> Option<Self> {
        if !binaries.join("Everything.exe").is_file() || !binaries.join("es.exe").is_file() {
            return None;
        }
        Some(Self {
            binaries,
            state,
            reuse_existing,
            processes: Mutex::new(Processes::default()),
        })
    }

    pub(super) fn query(
        &self,
        roots: &[PathBuf],
        authorized_roots: &[PathBuf],
        name: &str,
        cancel: &AtomicBool,
    ) -> Option<Candidates> {
        if roots.is_empty() || roots.len() > 32 || cancel.load(Ordering::Acquire) {
            return None;
        }
        std::fs::create_dir_all(&self.state).ok()?;
        let mut state = self.processes.lock().ok()?;
        let deadline = Instant::now() + QUERY_BUDGET;
        if let Some(result) =
            self.query_ntfs(&mut state, roots, authorized_roots, name, cancel, deadline)
        {
            return Some(result);
        }
        let mut existing_paths = Vec::new();
        // An external instance can have filters or excluded roots. Its positive hits are useful,
        // while the managed instance supplies coverage for the connector's current scope.
        if self.reuse_existing
            && state
                .retry_existing_at
                .is_none_or(|time| time <= Instant::now())
        {
            for root in roots {
                match self.run_query(None, Some(root), name, CANDIDATE_PAGE, cancel, deadline) {
                    QueryResult::Ready(paths) => existing_paths.extend(paths),
                    QueryResult::Loading | QueryResult::Unavailable => {
                        state.retry_existing_at = Some(Instant::now() + Duration::from_secs(30));
                        break;
                    }
                }
            }
        }

        let (managed, indexing) = self.run_managed(&mut state, roots, name, cancel, deadline)?;
        match managed {
            QueryResult::Ready(paths) => Some(Candidates {
                covered: paths.len() < MANAGED_CANDIDATE_LIMIT,
                paths,
                scanning: false,
                ntfs_roots: Vec::new(),
            }),
            QueryResult::Loading | QueryResult::Unavailable if indexing => {
                let priority = priority_folders(roots);
                if !priority.is_empty()
                    && priority.as_slice() != roots
                    && let Some((QueryResult::Ready(paths), _)) =
                        self.run_managed(&mut state, &priority, name, cancel, deadline)
                {
                    existing_paths.extend(paths);
                }
                Some(Candidates {
                    paths: existing_paths,
                    scanning: true,
                    covered: false,
                    ntfs_roots: Vec::new(),
                })
            }
            _ => None,
        }
    }

    pub(super) fn stop_managed(&self) {
        if let Ok(mut state) = self.processes.lock() {
            state.instances.clear();
            state.ntfs = None;
            state.retry_ntfs_at = None;
        }
    }

    fn instance(&self, state: &mut Processes, roots: &[PathBuf]) -> Option<String> {
        let found = state
            .instances
            .iter()
            .position(|instance| instance.roots == roots);
        let mut instance = found.and_then(|at| state.instances.remove(at));
        if instance
            .as_mut()
            .is_some_and(|entry| !matches!(entry.child.try_wait(), Ok(None)))
        {
            instance = None;
        }
        let instance = instance.or_else(|| self.start(roots, Vec::new()).ok())?;
        let name = instance.name.clone();
        state.instances.push_back(instance);
        if state.instances.len() > MAX_MANAGED_INSTANCES {
            state.instances.pop_front();
        }
        Some(name)
    }

    fn run_managed(
        &self,
        state: &mut Processes,
        roots: &[PathBuf],
        name: &str,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Option<(QueryResult, bool)> {
        let instance = self.instance(state, roots)?;
        let indexing = state
            .instances
            .back()
            .is_some_and(|entry| Instant::now() < entry.ready_deadline);
        Some((
            // The managed database already contains only these roots.
            self.run_query(
                Some(&instance),
                None,
                name,
                MANAGED_CANDIDATE_LIMIT,
                cancel,
                deadline,
            ),
            indexing,
        ))
    }

    fn prepare_ntfs<'a>(
        &self,
        state: &'a mut Processes,
        authorized_roots: &[PathBuf],
    ) -> Option<&'a mut Instance> {
        if !self.reuse_existing
            || authorized_roots.len() > 32
            || state
                .retry_ntfs_at
                .is_some_and(|retry| retry > Instant::now())
        {
            return None;
        }
        if !service_running() {
            state.ntfs = None;
            return None;
        }
        let volumes: Vec<_> = authorized_roots
            .iter()
            .filter_map(|root| ntfs_volume(root))
            .collect();
        if volumes.is_empty() {
            state.ntfs = None;
            return None;
        }
        if state.ntfs.as_mut().is_some_and(|instance| {
            instance.roots != authorized_roots
                || instance.volumes != volumes
                || !matches!(instance.child.try_wait(), Ok(None))
        }) {
            state.ntfs = None;
        }
        if state.ntfs.is_none() {
            match self.start(authorized_roots, volumes) {
                Ok(instance) => state.ntfs = Some(instance),
                Err(_) => state.retry_ntfs_at = Some(Instant::now() + Duration::from_secs(30)),
            }
        }
        state.ntfs.as_mut()
    }

    fn query_ntfs(
        &self,
        state: &mut Processes,
        roots: &[PathBuf],
        authorized_roots: &[PathBuf],
        name: &str,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> Option<Candidates> {
        let instance = self.prepare_ntfs(state, authorized_roots)?;
        while let Some(volume) = instance.volumes.get(instance.verified_volumes) {
            let probe = self.run_query(
                Some(&instance.name),
                Some(&volume.root),
                "",
                1,
                cancel,
                deadline,
            );
            match probe {
                QueryResult::Ready(paths) if !paths.is_empty() => instance.verified_volumes += 1,
                QueryResult::Loading
                    if Instant::now() < instance.ready_deadline
                        && matches!(instance.child.try_wait(), Ok(None)) =>
                {
                    return Some(Candidates {
                        paths: Vec::new(),
                        scanning: true,
                        covered: false,
                        ntfs_roots: instance
                            .volumes
                            .iter()
                            .map(|volume| volume.root.clone())
                            .collect(),
                    });
                }
                _ if cancel.load(Ordering::Acquire) => return None,
                _ => {
                    // A loaded database alone does not prove the service could index each volume.
                    state.ntfs = None;
                    state.retry_ntfs_at = Some(Instant::now() + Duration::from_secs(30));
                    return None;
                }
            }
        }
        let path = if roots == authorized_roots {
            None
        } else {
            roots.first().map(PathBuf::as_path)
        };
        let result = self.run_query(
            Some(&instance.name),
            path,
            name,
            MANAGED_CANDIDATE_LIMIT,
            cancel,
            deadline,
        );
        let (paths, scanning) = match result {
            QueryResult::Ready(paths) => (paths, false),
            QueryResult::Loading => (Vec::new(), true),
            QueryResult::Unavailable => return None,
        };
        Some(Candidates {
            covered: !scanning && paths.len() < MANAGED_CANDIDATE_LIMIT,
            paths,
            scanning,
            ntfs_roots: instance
                .volumes
                .iter()
                .map(|volume| volume.root.clone())
                .collect(),
        })
    }

    fn start(&self, roots: &[PathBuf], volumes: Vec<NtfsVolume>) -> std::io::Result<Instance> {
        let mut hash = DefaultHasher::new();
        self.state.hash(&mut hash);
        if volumes.is_empty() {
            roots.hash(&mut hash);
        }
        let id = hash.finish();
        let name = format!("MuseFiles-{id:016x}-{}", std::process::id());
        let data = if volumes.is_empty() {
            self.state.join(format!("scope-{id:016x}"))
        } else {
            self.state.join("ntfs-v1")
        };
        std::fs::create_dir_all(&data)?;
        let config = data.join("Everything.ini");
        let database = data.join("Everything.db");
        super::storage::atomic_write(&config, &settings(roots, &volumes)?)?;
        let mut child = command(&self.binaries.join("Everything.exe"))
            .current_dir(&data)
            .args(["-instance", &name, "-startup", "-config"])
            .arg(&config)
            .arg("-db")
            .arg(database)
            .spawn()?;
        let job = match super::job::ChildJob::attach_std(&child) {
            Ok(job) => job,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        };
        Ok(Instance {
            roots: roots.to_vec(),
            volumes,
            name,
            cli: self.binaries.join("es.exe"),
            child,
            _job: job,
            ready_deadline: Instant::now() + Duration::from_secs(180),
            verified_volumes: 0,
        })
    }

    fn run_query(
        &self,
        instance: Option<&str>,
        path: Option<&Path>,
        name: &str,
        limit: usize,
        cancel: &AtomicBool,
        deadline: Instant,
    ) -> QueryResult {
        if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
            return QueryResult::Loading;
        }
        if let Some(search) = scoped_expression(path, name) {
            let mut paths = Vec::new();
            while paths.len() < limit {
                let size = (limit - paths.len()).min(CANDIDATE_PAGE);
                let ipc_deadline = deadline.min(Instant::now() + Duration::from_millis(150));
                match ipc::query(
                    instance,
                    &search,
                    paths.len() as u32,
                    size as u32,
                    cancel,
                    ipc_deadline,
                ) {
                    ipc::Reply::Page(page) if page.len() <= size => {
                        let done = page.len() < size;
                        paths.extend(page);
                        if done || paths.len() == limit {
                            return QueryResult::Ready(paths);
                        }
                    }
                    ipc::Reply::Indexing => return QueryResult::Loading,
                    _ => break,
                }
            }
        }
        if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
            return QueryResult::Loading;
        }
        let export = ExportFile(
            self.state
                .join(format!("result-{}.json", super::token::generate())),
        );
        let mut query = command(&self.binaries.join("es.exe"));
        query.current_dir(&self.state);
        if let Some(instance) = instance {
            query.args(["-instance", instance]);
        }
        query.args([
            "-timeout",
            "100",
            "-n",
            &limit.to_string(),
            "-no-result-error",
        ]);
        if let Some(root) = path.and_then(Path::to_str) {
            query
                .arg("-path")
                .arg(root.strip_prefix(r"\\?\").unwrap_or(root));
        }
        query.arg("-export-json").arg(&export.0);
        if !name.is_empty() {
            if let Some(term) = simple_term(name) {
                query.arg(term);
            } else {
                query.arg("-regex").arg(literal_pattern(name));
            }
        }
        match run_until(&mut query, cancel, deadline)
            .ok()
            .and_then(|status| status.code())
        {
            Some(0) => match read_export(&export.0) {
                Ok(paths) => QueryResult::Ready(paths),
                Err(_) => QueryResult::Unavailable,
            },
            Some(9) => QueryResult::Ready(Vec::new()),
            Some(8) | None => QueryResult::Loading,
            _ => QueryResult::Unavailable,
        }
    }
}

fn priority_folders(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for path in [
        dirs::desktop_dir(),
        dirs::document_dir(),
        dirs::download_dir(),
    ]
    .into_iter()
    .flatten()
    {
        if path.is_dir()
            && super::access::protected_path(&path, roots)
            && super::access::reject_reparse_ancestors(&path).is_ok()
            && !paths.contains(&path)
        {
            paths.push(path);
        }
    }
    paths
}

impl Drop for Instance {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let deadline = Instant::now() + Duration::from_secs(4);
            let _ = run_until(
                command(&self.cli).args(["-instance", &self.name, "-exit"]),
                &AtomicBool::new(false),
                deadline,
            );
            // ES acknowledges receipt of the exit command before the engine finishes saving.
            while matches!(self.child.try_wait(), Ok(None)) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(15));
            }
            if matches!(self.child.try_wait(), Ok(None)) {
                let _ = self.child.kill();
            }
            let _ = self.child.wait();
        }
    }
}

struct ExportFile(PathBuf);
impl Drop for ExportFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn command(path: &Path) -> Command {
    let mut command = Command::new(path);
    command
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

fn run_until(
    command: &mut Command,
    cancel: &AtomicBool,
    deadline: Instant,
) -> std::io::Result<ExitStatus> {
    let mut child = command.spawn()?;
    let result = loop {
        if cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
            break Err(Error::other("Everything query interrupted"));
        }
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => std::thread::sleep(Duration::from_millis(8)),
            Err(error) => break Err(error),
        }
    };
    let _ = child.kill();
    let _ = child.wait();
    result
}

fn read_export(path: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut raw = Vec::new();
    std::fs::File::open(path)?
        .take(MAX_EXPORT_BYTES + 1)
        .read_to_end(&mut raw)?;
    if raw.len() as u64 > MAX_EXPORT_BYTES {
        return Err(Error::other("Everything export too large"));
    }
    let raw = raw.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&raw);
    let rows: Vec<ExportRow> = serde_json::from_slice(raw)?;
    Ok(rows.into_iter().map(|row| row.filename).collect())
}

fn literal_pattern(name: &str) -> String {
    let mut pattern = String::from("(?i)");
    for ch in name.trim().chars() {
        if r"\.^$|?*+()[]{}".contains(ch) {
            pattern.push('\\');
        }
        pattern.push(ch);
    }
    pattern
}

fn simple_term(name: &str) -> Option<&str> {
    let name = name.trim();
    (name.chars().next().is_some_and(char::is_alphanumeric)
        && name
            .chars()
            .all(|ch| ch.is_alphanumeric() || matches!(ch, '.' | '-' | '_')))
    .then_some(name)
}

fn scoped_expression(path: Option<&Path>, name: &str) -> Option<String> {
    let mut query = String::new();
    if let Some(path) = path {
        let path = path.to_str()?;
        let path = path.strip_prefix(r"\\?\").unwrap_or(path);
        if path.contains(['"', '\0', '\r', '\n']) {
            return None;
        }
        query.push('"');
        query.push_str(path);
        if !path.ends_with('\\') {
            query.push('\\');
        }
        query.push_str("\" ");
    }
    let name = name.trim();
    if name.is_empty() {
        return Some(query);
    }
    if let Some(term) = simple_term(name) {
        query.push_str(term);
        return Some(query);
    }
    query.push_str("regex:(?i)");
    for ch in name.chars() {
        if ch.is_ascii() && !ch.is_ascii_alphanumeric() {
            use std::fmt::Write;
            let _ = write!(query, "\\x{:02x}", u32::from(ch));
        } else {
            query.push(ch);
        }
    }
    Some(query)
}

pub(crate) fn service_running() -> bool {
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT,
        SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS,
    };

    let name: Vec<_> = "Everything".encode_utf16().chain([0]).collect();
    // SAFETY: The SCM and service handles are valid until closed, and status points to writable memory.
    unsafe {
        let manager = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if manager.is_null() {
            return false;
        }
        let service = OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_STATUS);
        CloseServiceHandle(manager);
        if service.is_null() {
            return false;
        }
        let mut status = SERVICE_STATUS::default();
        let running = QueryServiceStatus(service, &mut status) != 0
            && status.dwCurrentState == SERVICE_RUNNING;
        CloseServiceHandle(service);
        running
    }
}

fn ntfs_volume(root: &Path) -> Option<NtfsVolume> {
    use windows_sys::Win32::Storage::FileSystem::{
        GetDriveTypeW, GetVolumeInformationW, GetVolumeNameForVolumeMountPointW,
    };
    use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;

    let path = root.to_str()?;
    let path = path.strip_prefix(r"\\?\").unwrap_or(path);
    let [letter, b':', b'\\'] = path.as_bytes() else {
        return None;
    };
    if !letter.is_ascii_alphabetic() {
        return None;
    }
    let wide = [
        u16::from(letter.to_ascii_uppercase()),
        u16::from(b':'),
        u16::from(b'\\'),
        0,
    ];
    let mut file_system = [0u16; 32];
    let mut volume = [0u16; 64];
    // SAFETY: The root is null-terminated; the output buffers are correctly sized.
    unsafe {
        if GetDriveTypeW(wide.as_ptr()) != DRIVE_FIXED
            || GetVolumeInformationW(
                wide.as_ptr(),
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                file_system.as_mut_ptr(),
                file_system.len() as u32,
            ) == 0
            || GetVolumeNameForVolumeMountPointW(
                wide.as_ptr(),
                volume.as_mut_ptr(),
                volume.len() as u32,
            ) == 0
        {
            return None;
        }
    }
    let file_system =
        String::from_utf16(&file_system[..file_system.iter().position(|unit| *unit == 0)?]).ok()?;
    if !file_system.eq_ignore_ascii_case("NTFS") {
        return None;
    }
    let volume = String::from_utf16(&volume[..volume.iter().position(|unit| *unit == 0)?]).ok()?;
    Some(NtfsVolume {
        root: root.to_path_buf(),
        name: volume.trim_end_matches('\\').to_owned(),
    })
}

fn settings(roots: &[PathBuf], volumes: &[NtfsVolume]) -> std::io::Result<Vec<u8>> {
    let folders = roots
        .iter()
        .filter(|root| {
            !volumes
                .iter()
                .any(|volume| volume.root.as_path() == root.as_path())
        })
        .map(|root| {
            let root = root
                .to_str()
                .ok_or_else(|| Error::other("invalid Everything folder"))?;
            // Stable voidtools ini uses comma-separated paths. Unsupported names use the fallback.
            let root = root.strip_prefix(r"\\?\").unwrap_or(root);
            if root.contains([',', '"', '\r', '\n']) {
                return Err(Error::other("unsupported Everything folder"));
            }
            Ok(root)
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let list = |value| vec![value; folders.len()].join(",");
    let mut bytes = b"\xef\xbb\xbf".to_vec();
    bytes.extend_from_slice(format!(concat!(
        "[Everything]\r\napp_data=0\r\nrun_as_admin=0\r\nservice={}\r\n",
        "auto_include_fixed_volumes=0\r\nauto_include_removable_volumes=0\r\n",
        "auto_include_fixed_refs_volumes=0\r\nauto_include_removable_refs_volumes=0\r\n",
        "auto_include_cdrom_volumes=0\r\nshow_tray_icon=0\r\ncheck_for_updates_on_startup=0\r\n",
        "search_history_enabled=0\r\nrun_history_enabled=0\r\nhttp_server_enabled=0\r\netp_server_enabled=0\r\n",
        "folders={}\r\nfolder_monitor_changes={}\r\nfolder_rescan_if_full_list={}\r\nfolder_update_types={}\r\n"
    ), u8::from(!volumes.is_empty()), folders.join(","), list("1"), list("1"), list("0")).as_bytes());
    if !volumes.is_empty() {
        let flags = vec!["1"; volumes.len()].join(",");
        let paths = volumes
            .iter()
            .map(|volume| {
                let path = volume.root.to_str().expect("validated NTFS drive root");
                let path = path.strip_prefix(r"\\?\").unwrap_or(path);
                format!("\"{}\"", path.trim_end_matches('\\').to_ascii_uppercase())
            })
            .collect::<Vec<_>>()
            .join(",");
        let names = volumes
            .iter()
            // Everything's quoted list syntax escapes literal backslashes.
            .map(|volume| format!("\"{}\"", volume.name.replace('\\', "\\\\")))
            .collect::<Vec<_>>()
            .join(",");
        bytes.extend_from_slice(format!(
            "service_pipe_name=\\\\.\\PIPE\\Everything Service\r\nntfs_volume_guids={names}\r\nntfs_volume_paths={paths}\r\nntfs_volume_includes={flags}\r\nntfs_volume_monitors={flags}\r\n"
        ).as_bytes());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn names_are_literals_and_managed_ini_scopes_are_explicit() {
        assert_eq!(literal_pattern(" !foo.[例] "), r"(?i)!foo\.\[例\]");
        assert_eq!(
            simple_term("例会-26.11.16.xlsx"),
            Some("例会-26.11.16.xlsx")
        );
        assert_eq!(simple_term("-exit"), None);
        assert_eq!(simple_term("ext:exe"), None);
        let ini = settings(&[PathBuf::from(r"E:\测试资料")], &[]).unwrap();
        assert!(String::from_utf8_lossy(&ini).contains("folders=E:\\测试资料\r\n"));
        assert!(settings(&[PathBuf::from("E:\\a,b")], &[]).is_err());
    }

    #[test]
    fn managed_ntfs_uses_explicit_volumes_and_keeps_other_roots_as_folders() {
        let root = PathBuf::from(r"E:\");
        let volumes = [NtfsVolume {
            root: root.clone(),
            name: r"\\?\Volume{67f220d4-6608-4360-a8c4-54236e151b36}".into(),
        }];
        let ini = settings(&[root, PathBuf::from(r"R:\")], &volumes).unwrap();
        let ini = String::from_utf8(ini).unwrap();
        assert!(ini.contains("service=1\r\n"));
        assert!(ini.contains("auto_include_fixed_volumes=0\r\n"));
        assert!(ini.contains("ntfs_volume_paths=\"E:\"\r\n"));
        assert!(ini.contains(r#"ntfs_volume_guids="\\\\?\\Volume{"#));
        assert!(ini.contains("ntfs_volume_monitors=1\r\n"));
        assert!(ini.contains("folders=R:\\\r\n"));
    }

    #[test]
    #[ignore = "requires MUSE_CONNECTOR_EVERYTHING_QA pointing to the bundled official binaries"]
    fn official_named_ipc_scopes_unicode_results_and_accepts_offsets() {
        let binaries = PathBuf::from(std::env::var_os("MUSE_CONNECTOR_EVERYTHING_QA").unwrap());
        let fixture = std::env::temp_dir().join(format!(
            "muse-everything-qa-{}",
            super::super::token::generate()
        ));
        std::fs::create_dir(&fixture).unwrap();
        struct Fixture(PathBuf);
        impl Drop for Fixture {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let fixture = Fixture(fixture);
        let first = fixture.0.join("目录 一");
        let second = fixture.0.join("目录二");
        std::fs::create_dir(&first).unwrap();
        std::fs::create_dir(&second).unwrap();
        let needle = "中文 空格[1]";
        for path in [&first, &second] {
            std::fs::write(path.join(format!("{needle}.txt")), b"fixture").unwrap();
        }
        std::fs::write(first.join(format!("{needle}-2.txt")), b"fixture").unwrap();
        for index in 0..270 {
            std::fs::write(first.join(format!("分页样本-{index:03}.txt")), b"fixture").unwrap();
        }
        let everything = Everything::new(binaries, fixture.0.join("index"), false).unwrap();
        let instance = everything
            .start(&[first.clone(), second], Vec::new())
            .unwrap();
        let query = scoped_expression(Some(&first), needle).unwrap();
        let cancel = AtomicBool::new(false);
        let start = Instant::now();
        let results = loop {
            let deadline = Instant::now() + Duration::from_millis(800);
            if let ipc::Reply::Page(paths) =
                ipc::query(Some(&instance.name), &query, 0, 8, &cancel, deadline)
            {
                break paths;
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "official named IPC failed to respond"
            );
            std::thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|path| path.starts_with(&first)));
        let deadline = Instant::now() + Duration::from_millis(800);
        let ipc::Reply::Page(second_page) =
            ipc::query(Some(&instance.name), &query, 1, 1, &cancel, deadline)
        else {
            panic!("official named IPC did not return the next page");
        };
        assert_eq!(second_page, results[1..]);
        let deadline = Instant::now() + QUERY_BUDGET;
        let QueryResult::Ready(paged) = everything.run_query(
            Some(&instance.name),
            Some(&first),
            "分页样本",
            MANAGED_CANDIDATE_LIMIT,
            &cancel,
            deadline,
        ) else {
            panic!("failed to collect candidate pages");
        };
        assert_eq!(paged.len(), 270);
        let all_roots = everything.run_query(
            Some(&instance.name),
            None,
            needle,
            8,
            &cancel,
            Instant::now() + QUERY_BUDGET,
        );
        assert!(matches!(all_roots, QueryResult::Ready(paths) if paths.len() == 3));
        drop(instance);
        assert!(
            std::fs::read_dir(fixture.0.join("index"))
                .unwrap()
                .any(|entry| { entry.unwrap().path().join("Everything.db").is_file() })
        );
    }
}
