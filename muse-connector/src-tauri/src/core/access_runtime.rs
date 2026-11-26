use std::collections::{BTreeMap, VecDeque};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{
    Arc, Mutex, RwLock,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use super::access::{
    AccessPolicy, ERR_NOT_AUTHORIZED, GrantScope, Operation, ScopeMode, fixed_local_roots,
    protected_path, reject_reparse_ancestors,
};
use super::config::BridgeConfig;
use super::search::{SearchError, SearchIndex, SearchRequest, SearchResponse};
use super::token;
use crate::profile::RuntimeProfile;

const VERSION: u32 = 1;
const AGENT_TOKEN_FILE: &str = "agent-token";
const AGENT_TOKEN_PREFIX: &str = "mfa_";
const INDEX_MARKER: &str = "search-index-state";

#[derive(Clone, Copy, Serialize, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
enum IndexPhase {
    Waiting,
    Indexing,
    Ready,
    DirectorySearch,
    Unavailable,
    Clearing,
    Cleared,
    ClearFailed,
}

impl IndexPhase {
    fn suspended(self) -> bool {
        matches!(self, Self::Clearing | Self::Cleared | Self::ClearFailed)
    }
}

#[derive(Clone, Serialize)]
pub(crate) struct IndexStatus {
    state: IndexPhase,
    bytes: Option<u64>,
}

#[derive(Default)]
struct IndexLifecycle {
    prewarm_cancel: Arc<AtomicBool>,
    stopped: bool,
}

#[derive(Serialize, Deserialize)]
struct AccessSettings {
    version: u32,
    policy: AccessPolicy,
    #[serde(default)]
    preserve_legacy_read_only: bool,
}

struct ActiveAccess {
    policy: Option<AccessPolicy>,
    preserve_legacy_read_only: bool,
    agent_token: Option<String>,
    blocked: bool,
    cancel: Arc<AtomicBool>,
}

#[derive(Debug)]
pub(crate) enum AgentSearchError {
    Unauthorized,
    Forbidden,
    Search(SearchError),
    WorkerFailed,
}

#[derive(Serialize)]
pub(crate) struct AgentDesktopLocation {
    pub root: String,
    pub path: String,
    pub absolute_path: String,
}

pub(crate) struct AccessRuntime {
    settings_path: PathBuf,
    agent_token_path: PathBuf,
    protected: Vec<PathBuf>,
    write_protected: Vec<PathBuf>,
    development_home: Option<PathBuf>,
    active: RwLock<ActiveAccess>,
    index: Arc<SearchIndex>,
    scoped_indexes: Mutex<VecDeque<(PathBuf, Arc<SearchIndex>)>>,
    scoped_cache: PathBuf,
    index_home: PathBuf,
    index_phase: RwLock<IndexPhase>,
    index_lifecycle: Arc<Mutex<IndexLifecycle>>,
    #[cfg(windows)]
    everything: Option<super::everything::Everything>,
    search_slot: Arc<Semaphore>,
    pub(crate) legacy_requests: RwLock<()>,
}

impl AccessRuntime {
    pub(crate) fn index_home(&self) -> &Path {
        &self.index_home
    }

    #[cfg(all(test, windows))]
    pub(super) fn with_test_engine(
        profile: &RuntimeProfile,
        engine: super::everything::Everything,
    ) -> Arc<Self> {
        let (mut access, error) = Self::open(profile);
        assert!(error.is_none());
        Arc::get_mut(&mut access).unwrap().everything = Some(engine);
        access
    }

    pub(crate) fn open(profile: &RuntimeProfile) -> (Arc<Self>, Option<String>) {
        let settings_path = profile.home.join("file-access.json");
        let cache_path = profile.home.join("file-name-index.json");
        let agent_token_path = profile.home.join(AGENT_TOKEN_FILE);
        let agent_token = load_agent_token(&agent_token_path);
        let development_home = profile.is_development().then(|| profile.home.clone());
        let (protected, write_protected) = if development_home.is_some() {
            let protected: Vec<PathBuf> = [
                "config.json",
                "token",
                AGENT_TOKEN_FILE,
                "desktop-state.json",
                "file-access.json",
                "file-name-index.json",
                "search-indexes",
                INDEX_MARKER,
                "everything",
                "audit.log",
                "server.log",
            ]
            .into_iter()
            .map(|item| profile.home.join(item))
            .map(normalize_protected)
            .collect();
            (protected.clone(), protected)
        } else {
            production_protection(&SensitiveRoots::from_host(&profile.home))
        };
        let (policy, preserve_legacy_read_only, error) = match Self::load_settings(&settings_path) {
            Ok(settings) => match settings
                .policy
                .validate(&protected, development_home.as_deref())
            {
                Ok(()) => (
                    Some(settings.policy),
                    settings.preserve_legacy_read_only,
                    None,
                ),
                Err(error) => (None, false, Some(format!("文件授权配置需要修复：{error}"))),
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => (None, false, None),
            Err(_) => (None, false, Some("无法读取本机文件授权配置".into())),
        };
        (
            Arc::new(Self {
                settings_path,
                agent_token_path,
                protected,
                write_protected,
                development_home,
                active: RwLock::new(ActiveAccess {
                    policy,
                    preserve_legacy_read_only,
                    agent_token,
                    blocked: error.is_some(),
                    cancel: Arc::new(AtomicBool::new(false)),
                }),
                index: Arc::new(SearchIndex::new(cache_path)),
                scoped_indexes: Mutex::new(VecDeque::new()),
                scoped_cache: profile.home.join("search-indexes"),
                index_home: profile.home.clone(),
                index_phase: RwLock::new(match std::fs::read(profile.home.join(INDEX_MARKER)) {
                    Ok(value) if value == b"cleared" => IndexPhase::Cleared,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => IndexPhase::Waiting,
                    _ => IndexPhase::ClearFailed,
                }),
                index_lifecycle: Arc::new(Mutex::new(IndexLifecycle::default())),
                #[cfg(windows)]
                everything: super::everything::Everything::discover(
                    &profile.home,
                    !profile.is_development(),
                ),
                search_slot: Arc::new(Semaphore::new(1)),
                legacy_requests: RwLock::new(()),
            }),
            error,
        )
    }

    fn load_settings(path: &Path) -> io::Result<AccessSettings> {
        let raw = std::fs::read_to_string(path)?;
        let settings: AccessSettings =
            serde_json::from_str(raw.trim_start_matches('\u{feff}')).map_err(io::Error::other)?;
        if settings.version != VERSION {
            return Err(io::Error::other("不支持此文件授权配置版本"));
        }
        Ok(settings)
    }

    pub(crate) fn policy(&self) -> Option<AccessPolicy> {
        self.active.read().unwrap().policy.clone()
    }

    pub(crate) fn agent_enabled(&self) -> bool {
        self.active.read().unwrap().agent_token.is_some()
    }

    pub(crate) fn agent_ready(&self) -> bool {
        let active = self.active.read().unwrap();
        active.agent_token.is_some() && active.policy.as_ref().is_some_and(has_agent_grant)
    }

    pub(crate) fn agent_token(&self) -> Option<String> {
        self.active.read().unwrap().agent_token.clone()
    }

    pub(crate) fn agent_token_path(&self) -> &Path {
        &self.agent_token_path
    }

    pub(crate) fn agent_auth(&self, header: Option<&str>) -> bool {
        agent_auth(&self.active.read().unwrap(), header)
    }

    pub(crate) fn agent_search_generation(&self) -> Arc<AtomicBool> {
        self.active.read().unwrap().cancel.clone()
    }

    pub(crate) fn issue_agent_token(&self, protect: impl FnOnce(&str)) -> Result<(), String> {
        let _requests = self.legacy_requests.write().unwrap();
        let mut active = self.active.write().unwrap();
        if !active.policy.as_ref().is_some_and(has_agent_grant) {
            return Err("请先保存至少一项文件权限".into());
        }
        let new_token = format!("{AGENT_TOKEN_PREFIX}{}", token::generate());
        reject_reparse_ancestors(&self.agent_token_path)
            .map_err(|_| "Agent 令牌文件路径不可用".to_string())?;
        token::save(&self.agent_token_path, &new_token)
            .map_err(|_| "无法保存 Agent 令牌，原令牌仍有效".to_string())?;
        protect(&new_token);
        active.agent_token = Some(new_token);
        self.invalidate_search(&mut active);
        Ok(())
    }

    pub(crate) fn revoke_agent_token(&self) -> Result<(), String> {
        let _requests = self.legacy_requests.write().unwrap();
        let mut active = self.active.write().unwrap();
        match std::fs::remove_file(&self.agent_token_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err("无法撤销 Agent 令牌，原令牌仍有效".into()),
        }
        active.agent_token = None;
        self.invalidate_search(&mut active);
        Ok(())
    }

    pub(crate) fn agent_roots(&self, op: Operation) -> Option<BTreeMap<String, PathBuf>> {
        let active = self.active.read().unwrap();
        let policy = active.policy.as_ref()?;
        let local = self.operation_roots(policy, op);
        let mut roots = policy.roots_for(op, &local)?;
        roots.retain(|_, path| self.agent_listing_entry_allowed(path));
        Some(roots)
    }

    pub(crate) fn resolve_agent_target(
        &self,
        op: Operation,
        alias: &str,
        relative: &str,
    ) -> Result<PathBuf, &'static str> {
        self.resolve_agent_file(op, alias, relative)
            .map(|resolved| resolved.path)
    }

    fn protected_for(&self, op: Operation) -> &[PathBuf] {
        match op {
            Operation::Write => &self.write_protected,
            Operation::Search | Operation::Read => &self.protected,
        }
    }

    pub(crate) fn resolve_agent_file(
        &self,
        op: Operation,
        alias: &str,
        relative: &str,
    ) -> Result<super::path_guard::Resolved, &'static str> {
        let active = self.active.read().unwrap();
        let policy = active.policy.as_ref().ok_or(ERR_NOT_AUTHORIZED)?;
        policy.resolve_file(
            op,
            &self.operation_roots(policy, op),
            self.protected_for(op),
            alias,
            relative,
        )
    }

    pub(crate) fn is_protected_path(&self, path: &Path) -> bool {
        protected_path(path, &self.protected)
    }

    pub(crate) fn is_write_protected_path(&self, path: &Path) -> bool {
        protected_path(path, &self.write_protected)
    }

    pub(crate) fn agent_listing_entry_allowed(&self, path: &Path) -> bool {
        !protected_path(path, &self.protected)
            && super::access::canonicalize_direct(path)
                .is_some_and(|canonical| !protected_path(&canonical, &self.protected))
    }

    pub(crate) fn agent_desktop(&self) -> Option<AgentDesktopLocation> {
        let path = match &self.development_home {
            Some(home) => home.join("files"),
            None => dirs::desktop_dir()?,
        };
        reject_reparse_ancestors(&path).ok()?;
        let desktop = std::fs::canonicalize(&path)
            .ok()
            .filter(|path| path.is_dir())?;
        let absolute_path = path.to_str()?.to_owned();
        for op in [Operation::Read, Operation::Search] {
            let Some(roots) = self.agent_roots(op) else {
                continue;
            };
            for (root, base) in roots {
                let Ok(base) = std::fs::canonicalize(&base) else {
                    continue;
                };
                if !protected_path(&desktop, &[base.clone()]) {
                    continue;
                }
                let relative: PathBuf = desktop
                    .components()
                    .skip(base.components().count())
                    .collect();
                let Some(relative) = relative.to_str().map(|value| value.replace('\\', "/")) else {
                    continue;
                };
                if self
                    .resolve_agent_target(op, &root, &relative)
                    .is_ok_and(|resolved| same_path(&resolved, &desktop))
                {
                    return Some(AgentDesktopLocation {
                        root,
                        path: relative,
                        absolute_path,
                    });
                }
            }
        }
        None
    }

    pub(crate) fn validate(&self, policy: &AccessPolicy) -> Result<(), String> {
        policy
            .validate(&self.protected, self.development_home.as_deref())
            .map_err(str::to_owned)?;
        if policy.write == GrantScope::Folders {
            for (alias, path) in &policy.roots {
                if !policy.permits_folder(alias, Operation::Write) {
                    continue;
                }
                let canonical =
                    super::path_guard::canonical_non_strict(path).unwrap_or_else(|_| path.clone());
                if protected_path(path, &self.write_protected)
                    || protected_path(&canonical, &self.write_protected)
                {
                    return Err(super::access::ERR_PROTECTED.into());
                }
            }
        }
        if let Some(disks) = &policy.disks {
            let local = self.local_roots();
            if disks.iter().any(|alias| !local.contains_key(alias)) {
                return Err("所选磁盘当前不可用，请重新选择".into());
            }
        }
        Ok(())
    }

    pub(crate) fn save(&self, policy: AccessPolicy, legacy_read_only: bool) -> Result<(), String> {
        let lifecycle = self.index_lifecycle.lock().unwrap();
        let _requests = self.legacy_requests.write().unwrap();
        let mut access = self.active.write().unwrap();
        let preserve_legacy_read_only =
            access.preserve_legacy_read_only || access.policy.is_none() && legacy_read_only;
        let bytes = serde_json::to_vec_pretty(&AccessSettings {
            version: VERSION,
            policy: policy.clone(),
            preserve_legacy_read_only,
        })
        .map_err(|_| "无法编码文件授权配置".to_string())?;
        super::storage::atomic_write(&self.settings_path, &bytes)
            .map_err(|_| "保存文件授权失败，原授权仍有效".to_string())?;
        let search_changed = access.policy.as_ref().is_none_or(|previous| {
            let local = self.local_roots();
            previous.roots_for(Operation::Search, &local)
                != policy.roots_for(Operation::Search, &local)
        });
        self.invalidate_search(&mut access);
        access.policy = Some(policy);
        access.preserve_legacy_read_only = preserve_legacy_read_only;
        access.blocked = false;
        drop(access);
        drop(_requests);
        if search_changed {
            lifecycle.prewarm_cancel.store(true, Ordering::Release);
            self.stop_search_engine();
            let mut phase = self.index_phase.write().unwrap();
            if !phase.suspended() {
                *phase = IndexPhase::Waiting;
            }
        }
        Ok(())
    }

    pub(crate) fn prewarm_search(&self) {
        let (roots, cancel) = {
            let mut lifecycle = self.index_lifecycle.lock().unwrap();
            if lifecycle.stopped || self.index_phase.read().unwrap().suspended() {
                return;
            }
            let Some(policy) = self.policy() else { return };
            let local = self.operation_roots(&policy, Operation::Search);
            let Some(roots) = policy
                .roots_for(Operation::Search, &local)
                .filter(|roots| !roots.is_empty())
            else {
                return;
            };
            lifecycle.prewarm_cancel.store(true, Ordering::Release);
            lifecycle.prewarm_cancel = Arc::new(AtomicBool::new(false));
            (roots, lifecycle.prewarm_cancel.clone())
        };
        let authorized: Vec<_> = roots.values().cloned().collect();
        let request = SearchRequest {
            name: format!("MuseIndex-{}", token::generate()),
            limit: Some(1),
            ..Default::default()
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(600);
        loop {
            let result = {
                let _lifecycle = self.index_lifecycle.lock().unwrap();
                if cancel.load(Ordering::Acquire) {
                    return;
                }
                let result = self.run_index_search(
                    &self.index,
                    &roots,
                    &authorized,
                    &request,
                    &cancel,
                    &|_, _| false,
                );
                match &result {
                    Ok(response) => self.record_index_result(response),
                    Err(_) => *self.index_phase.write().unwrap() = IndexPhase::Unavailable,
                }
                result
            };
            if !result.is_ok_and(|response| response.scanning) {
                return;
            }
            if std::time::Instant::now() >= deadline {
                return;
            }
            std::thread::sleep(Duration::from_millis(150));
        }
    }

    pub(crate) fn index_status(&self) -> IndexStatus {
        IndexStatus {
            state: *self.index_phase.read().unwrap(),
            bytes: super::index_storage::bytes(&self.index_home),
        }
    }

    pub(crate) fn clear_index(&self) -> Result<(), String> {
        let lifecycle = self.index_lifecycle.lock().unwrap();
        super::storage::atomic_write(&self.index_home.join(INDEX_MARKER), b"clearing")
            .map_err(|error| format!("无法保存索引清除状态：{error}"))?;
        *self.index_phase.write().unwrap() = IndexPhase::Clearing;
        lifecycle.prewarm_cancel.store(true, Ordering::Release);
        self.cancel_search();
        self.stop_search_engine();
        self.index.reset();
        self.scoped_indexes.lock().unwrap().clear();
        let result = super::index_storage::clear(&self.index_home).and_then(|()| {
            super::storage::atomic_write(&self.index_home.join(INDEX_MARKER), b"cleared")
        });
        *self.index_phase.write().unwrap() = if result.is_ok() {
            IndexPhase::Cleared
        } else {
            IndexPhase::ClearFailed
        };
        result.map_err(|error| format!("清除本机索引失败，请重试：{error}"))
    }

    pub(crate) fn resume_index(&self) -> Result<(), String> {
        let _lifecycle = self.index_lifecycle.lock().unwrap();
        let mut phase = self.index_phase.write().unwrap();
        if *phase == IndexPhase::ClearFailed {
            return Err("请先重试清除本机索引".into());
        }
        if *phase == IndexPhase::Cleared {
            std::fs::remove_file(self.index_home.join(INDEX_MARKER))
                .map_err(|error| format!("无法恢复自动建库：{error}"))?;
            *phase = IndexPhase::Waiting;
        }
        Ok(())
    }

    fn record_index_result(&self, result: &SearchResponse) {
        *self.index_phase.write().unwrap() = if result.scanning {
            IndexPhase::Indexing
        } else if !result.complete {
            IndexPhase::Unavailable
        } else if matches!(result.backend, "everything_ntfs" | "everything_mixed") {
            IndexPhase::Ready
        } else {
            IndexPhase::DirectorySearch
        };
    }

    pub(crate) fn shutdown_index(&self) {
        let mut lifecycle = self.index_lifecycle.lock().unwrap();
        lifecycle.stopped = true;
        lifecycle.prewarm_cancel.store(true, Ordering::Release);
        self.stop_search_engine();
    }

    pub(crate) fn ntfs_search_service(&self) -> Option<bool> {
        #[cfg(windows)]
        if self.everything.is_some() {
            return Some(self.development_home.is_none() && super::everything::service_running());
        }
        None
    }

    pub(crate) fn stop_search_engine(&self) {
        #[cfg(windows)]
        if let Some(engine) = &self.everything {
            engine.stop_managed();
        }
    }

    pub(crate) fn cancel_search(&self) {
        let mut access = self.active.write().unwrap();
        self.invalidate_search(&mut access);
    }

    fn invalidate_search(&self, access: &mut ActiveAccess) {
        access.cancel.store(true, Ordering::Release);
        access.cancel = Arc::new(AtomicBool::new(false));
        self.changed_files();
    }

    pub(crate) fn changed_files(&self) {
        self.index.mark_dirty();
        for (_, index) in self.scoped_indexes.lock().unwrap().iter() {
            index.mark_dirty();
        }
    }

    fn scoped_index(
        &self,
        roots: &BTreeMap<String, PathBuf>,
        root: Option<&str>,
    ) -> Arc<SearchIndex> {
        let Some(root) = root else {
            return self.index.clone();
        };
        let mut hash = DefaultHasher::new();
        root.hash(&mut hash);
        roots.hash(&mut hash);
        let cache = self
            .scoped_cache
            .join(format!("{:016x}.json", hash.finish()));
        let mut indexes = self.scoped_indexes.lock().unwrap();
        let position = indexes.iter().position(|(path, _)| *path == cache);
        let index = position
            .and_then(|position| indexes.remove(position))
            .map(|(_, index)| index)
            .unwrap_or_else(|| Arc::new(SearchIndex::new(cache.clone())));
        indexes.push_back((cache, index.clone()));
        if indexes.len() > 6 {
            indexes.pop_front();
        }
        index
    }

    pub(crate) fn legacy_view(&self, mut config: BridgeConfig) -> BridgeConfig {
        let active = self.active.read().unwrap();
        if active.blocked {
            config.roots.clear();
            config.read_only = true;
            return config;
        }
        let Some(policy) = active.policy.as_ref() else {
            return config;
        };
        match policy.read {
            GrantScope::Off => config.roots.clear(),
            GrantScope::Folders if policy.mode == ScopeMode::Folders => {
                // This mode was explicitly selected for the existing file integration.
                config.roots.clone_from(&policy.roots);
                config
                    .roots
                    .retain(|name, _| policy.permits_folder(name, Operation::Read));
            }
            GrantScope::Folders => config.roots.retain(|name, path| {
                policy.permits_folder(name, Operation::Read)
                    && policy
                        .roots
                        .get(name)
                        .is_some_and(|granted| same_path(path, granted))
            }),
            GrantScope::AllLocal => {
                let fixed: Vec<_> = policy
                    .roots_for(Operation::Read, &self.local_roots())
                    .unwrap_or_default()
                    .into_values()
                    .collect();
                config.roots.retain(|_, path| {
                    protected_path(path, &fixed)
                        || super::access::canonicalize_direct(path)
                            .is_some_and(|canonical| protected_path(&canonical, &fixed))
                });
            }
        }
        config
            .roots
            .retain(|_, path| !protected_path(path, &self.protected));
        config.read_only = (active.preserve_legacy_read_only && config.read_only)
            || match policy.write {
                GrantScope::Off => true,
                GrantScope::Folders if policy.mode == ScopeMode::Folders => !config
                    .roots
                    .keys()
                    .any(|alias| policy.permits_folder(alias, Operation::Write)),
                GrantScope::Folders | GrantScope::AllLocal => config.read_only,
            };
        config
    }

    pub(crate) fn permits_legacy(&self, target: &Path, writing: bool) -> bool {
        let protected = if writing {
            &self.write_protected
        } else {
            &self.protected
        };
        if protected_path(target, protected) {
            return false;
        }
        let access = self.active.read().unwrap();
        if access.blocked {
            return false;
        }
        let Some(policy) = access.policy.as_ref() else {
            return true;
        };
        if policy.disks.is_some() {
            let operation = if writing {
                Operation::Write
            } else {
                Operation::Read
            };
            return policy
                .roots_for(operation, &self.local_roots())
                .is_some_and(|roots| roots.values().any(|root| inside(target, root)));
        }
        if !writing {
            return true;
        }
        match access.policy.as_ref().map(|policy| policy.write) {
            Some(GrantScope::Off) => false,
            Some(GrantScope::Folders) => access.policy.as_ref().is_some_and(|policy| {
                policy.roots.iter().any(|(alias, root)| {
                    policy.permits_folder(alias, Operation::Write) && inside(target, root)
                })
            }),
            Some(GrantScope::AllLocal) => {
                self.local_roots().values().any(|root| inside(target, root))
            }
            _ => true,
        }
    }

    pub(crate) fn verify_legacy_path(
        &self,
        root: &Path,
        relative: &str,
    ) -> Result<bool, &'static str> {
        if self.active.read().unwrap().policy.is_none() {
            return Ok(false);
        }
        let lexical = root.join(relative.replace('\\', "/"));
        super::access::reject_reparse_ancestors(&lexical)?;
        Ok(true)
    }

    fn local_roots(&self) -> BTreeMap<String, PathBuf> {
        if let Some(home) = &self.development_home {
            let fixture = home.join("files");
            return super::access::canonicalize_direct(&fixture)
                .into_iter()
                .map(|path| ("test-disk".into(), path))
                .collect();
        }
        fixed_local_roots()
    }

    pub(crate) fn local_disk_aliases(&self) -> Vec<String> {
        self.local_roots().into_keys().collect()
    }

    fn operation_roots(
        &self,
        policy: &AccessPolicy,
        operation: Operation,
    ) -> BTreeMap<String, PathBuf> {
        if policy.grant(operation) == GrantScope::AllLocal {
            self.local_roots()
        } else {
            BTreeMap::new()
        }
    }

    pub(crate) fn preserve_folder_access(
        &self,
        saved: &AccessPolicy,
        mut policy: AccessPolicy,
    ) -> Result<AccessPolicy, String> {
        use super::access::{FolderGrant, canonicalize_direct};

        let operations = [Operation::Search, Operation::Read, Operation::Write];
        let local_roots = self.local_roots();
        let authorized = operations.map(|operation| {
            saved
                .roots_for(operation, &local_roots)
                .into_iter()
                .flatten()
                .filter_map(|(_, root)| canonicalize_direct(&root))
                .collect::<Vec<_>>()
        });
        let grants = policy
            .roots
            .iter()
            .map(|(alias, path)| {
                let path = canonicalize_direct(path).ok_or("无法访问目录")?;
                let [search, read, write] = std::array::from_fn(|index| {
                    let operation = operations[index];
                    policy.grant(operation) == GrantScope::Folders
                        && policy.permits_folder(alias, operation)
                        && protected_path(&path, &authorized[index])
                        && (saved.grant(operation) != GrantScope::Folders
                            || !saved.roots.iter().any(|(alias, root)| {
                                !saved.permits_folder(alias, operation) && same_path(&path, root)
                            }))
                });
                Ok((
                    alias.clone(),
                    FolderGrant {
                        search,
                        read,
                        write,
                    },
                ))
            })
            .collect::<Result<BTreeMap<_, _>, &str>>()?;
        policy.folder_grants = Some(grants);
        if !has_agent_grant(&policy) {
            return Err(
                "所选文件夹没有可保留的权限。请选择已授权的文件夹，或确认启用全部操作。".into(),
            );
        }
        Ok(policy)
    }

    pub(crate) async fn search_local(
        self: Arc<Self>,
        request: SearchRequest,
    ) -> Result<SearchResponse, String> {
        self.search(request, None)
            .await
            .map_err(|error| match error {
                AgentSearchError::Unauthorized | AgentSearchError::Forbidden => {
                    "尚未允许搜索本机文件".into()
                }
                AgentSearchError::Search(error) => error.to_string(),
                AgentSearchError::WorkerFailed => "本机文件搜索未完成".into(),
            })
    }

    pub(crate) async fn search_agent(
        self: Arc<Self>,
        header: &str,
        request: SearchRequest,
    ) -> Result<SearchResponse, AgentSearchError> {
        if !self.agent_auth(Some(header)) {
            return Err(AgentSearchError::Unauthorized);
        }
        self.search(request, Some(header.to_owned())).await
    }

    async fn search(
        self: Arc<Self>,
        request: SearchRequest,
        agent_header: Option<String>,
    ) -> Result<SearchResponse, AgentSearchError> {
        let slot = self
            .search_slot
            .clone()
            .try_acquire_owned()
            .map_err(|_| AgentSearchError::Search(SearchError::Busy))?;
        tokio::task::spawn_blocking(move || {
            let _slot = slot;
            let lifecycle = self.index_lifecycle.lock().unwrap();
            let (policy, cancel) = {
                let active = self.active.read().unwrap();
                if let Some(header) = agent_header.as_deref()
                    && !agent_auth(&active, Some(header))
                {
                    return Err(AgentSearchError::Unauthorized);
                }
                let policy = active.policy.clone().ok_or(AgentSearchError::Forbidden)?;
                (policy, active.cancel.clone())
            };
            let local_roots = self.operation_roots(&policy, Operation::Search);
            let mut roots = policy
                .roots_for(Operation::Search, &local_roots)
                .filter(|roots| !roots.is_empty())
                .ok_or(AgentSearchError::Forbidden)?;
            let authorized_roots: Vec<_> = roots.values().cloned().collect();
            if let Some(root) = request.root.as_ref() {
                let path = roots
                    .remove(root)
                    .ok_or(AgentSearchError::Search(SearchError::Invalid))?;
                roots = BTreeMap::from([(root.clone(), path)]);
            }
            if self.index_phase.read().unwrap().suspended() {
                return Err(AgentSearchError::Search(SearchError::IndexCleared));
            }
            if lifecycle.stopped {
                return Err(AgentSearchError::Search(SearchError::Cancelled));
            }
            let index = self.scoped_index(&roots, request.root.as_deref());
            let allows = |alias: &str, relative: &str| {
                !cancel.load(Ordering::Acquire)
                    && policy
                        .resolve(
                            Operation::Search,
                            &local_roots,
                            &self.protected,
                            alias,
                            relative,
                        )
                        .ok()
                        .is_some_and(|path| path.exists())
            };
            let result = self.run_index_search(
                &index,
                &roots,
                &authorized_roots,
                &request,
                &cancel,
                &allows,
            );
            let _requests = self.legacy_requests.read().unwrap();
            if let Some(header) = agent_header.as_deref()
                && !self.agent_auth(Some(header))
            {
                return Err(AgentSearchError::Unauthorized);
            }
            if cancel.load(Ordering::Acquire) {
                return Err(AgentSearchError::Search(SearchError::Cancelled));
            }
            let result = result.map_err(AgentSearchError::Search)?;
            if request.root.is_none()
                && request.cursor.is_none()
                && (result.complete || result.scanning)
            {
                self.record_index_result(&result);
            }
            if result.backend == "built_in"
                && result.scanning
                && let Some(worker) = index.claim_pending_scan(&cancel)
            {
                drop(_requests);
                let lifecycle = self.index_lifecycle.clone();
                tokio::task::spawn_blocking(move || {
                    loop {
                        {
                            let lifecycle = lifecycle.lock().unwrap();
                            if lifecycle.stopped || !index.advance_pending_scan(&worker, &cancel) {
                                break;
                            }
                        }
                        // Leave the index lock available to queries while the scan progresses.
                        std::thread::sleep(Duration::from_millis(15));
                    }
                });
            }
            Ok(result)
        })
        .await
        .map_err(|_| AgentSearchError::WorkerFailed)?
    }

    fn run_index_search(
        &self,
        index: &SearchIndex,
        roots: &BTreeMap<String, PathBuf>,
        _authorized_roots: &[PathBuf],
        request: &SearchRequest,
        cancel: &AtomicBool,
        allows: &impl Fn(&str, &str) -> bool,
    ) -> Result<SearchResponse, SearchError> {
        #[cfg(windows)]
        if let Some(engine) = &self.everything
            && let Some(response) = index.search_everything(
                engine,
                roots,
                _authorized_roots,
                &self.protected,
                request,
                cancel,
                allows,
            )?
        {
            return Ok(response);
        }
        index.search(roots, &self.protected, request, cancel, allows)
    }
}

fn normalize_protected(path: PathBuf) -> PathBuf {
    super::path_guard::canonical_non_strict(&path).unwrap_or(path)
}

struct SensitiveRoots {
    profile_home: PathBuf,
    user_home: Option<PathBuf>,
    roaming_app_data: Option<PathBuf>,
    local_app_data: Option<PathBuf>,
    documents: Option<PathBuf>,
    desktop: Option<PathBuf>,
    downloads: Option<PathBuf>,
    program_data: Option<PathBuf>,
    system_root: Option<PathBuf>,
    program_files: Vec<PathBuf>,
    current_exe: Option<PathBuf>,
}

impl SensitiveRoots {
    fn from_host(profile_home: &Path) -> Self {
        let env_path = |key: &str| {
            std::env::var_os(key)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
        };
        let program_files = ["ProgramFiles", "ProgramFiles(x86)"]
            .into_iter()
            .filter_map(env_path)
            .collect();
        Self {
            profile_home: profile_home.to_path_buf(),
            user_home: dirs::home_dir(),
            roaming_app_data: dirs::config_dir(),
            local_app_data: dirs::data_local_dir(),
            documents: dirs::document_dir(),
            desktop: dirs::desktop_dir(),
            downloads: dirs::download_dir(),
            program_data: env_path("ProgramData"),
            system_root: env_path("SystemRoot"),
            program_files,
            current_exe: std::env::current_exe().ok(),
        }
    }
}

fn push_unique(list: &mut Vec<PathBuf>, path: PathBuf) {
    let normalized = normalize_protected(path);
    if !list.iter().any(|existing| existing == &normalized) {
        list.push(normalized);
    }
}

fn production_protection(env: &SensitiveRoots) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let mut protected = Vec::new();
    push_unique(&mut protected, env.profile_home.clone());
    if let Some(home) = &env.user_home {
        for dir in [".ssh", ".aws", ".gnupg"] {
            push_unique(&mut protected, home.join(dir));
        }
    }

    let mut write_protected = protected.clone();
    if let Some(roaming) = &env.roaming_app_data {
        push_unique(
            &mut write_protected,
            roaming.join(r"Microsoft\Windows\Start Menu\Programs\Startup"),
        );
    }
    if let Some(program_data) = &env.program_data {
        push_unique(
            &mut write_protected,
            program_data.join(r"Microsoft\Windows\Start Menu\Programs\StartUp"),
        );
    }
    if let Some(system_root) = &env.system_root {
        push_unique(&mut write_protected, system_root.clone());
    }
    for dir in &env.program_files {
        push_unique(&mut write_protected, dir.clone());
    }
    if let Some(local) = &env.local_app_data {
        push_unique(&mut write_protected, local.join("Programs"));
    }
    if let Some(documents) = &env.documents {
        for dir in ["PowerShell", "WindowsPowerShell"] {
            push_unique(&mut write_protected, documents.join(dir));
        }
    }
    if let Some(home) = &env.user_home {
        for file in [
            ".gitconfig",
            ".bashrc",
            ".zshrc",
            ".profile",
            ".npmrc",
            ".pypirc",
        ] {
            push_unique(&mut write_protected, home.join(file));
        }
    }
    if let Some(exe) = &env.current_exe
        && let Some(exe_dir) = exe.parent()
    {
        let shared_roots = [
            env.user_home.as_deref(),
            env.desktop.as_deref(),
            env.downloads.as_deref(),
            env.documents.as_deref(),
        ];
        let is_shared_dir = super::access::is_drive_root(exe_dir)
            || shared_roots
                .into_iter()
                .flatten()
                .any(|shared| same_path(exe_dir, shared));
        if is_shared_dir {
            push_unique(&mut write_protected, exe.clone());
            push_unique(&mut write_protected, exe_dir.join("everything"));
        } else {
            push_unique(&mut write_protected, exe_dir.to_path_buf());
        }
    }

    (protected, write_protected)
}

fn agent_auth(active: &ActiveAccess, header: Option<&str>) -> bool {
    active
        .agent_token
        .as_deref()
        .is_some_and(|secret| token::check_auth_header(header, secret))
}

fn has_agent_grant(policy: &AccessPolicy) -> bool {
    [Operation::Search, Operation::Read, Operation::Write]
        .into_iter()
        .any(|operation| match policy.grant(operation) {
            GrantScope::Off => false,
            GrantScope::Folders => policy
                .roots
                .keys()
                .any(|alias| policy.permits_folder(alias, operation)),
            GrantScope::AllLocal => policy.mode == ScopeMode::Full,
        })
}

fn load_agent_token(path: &Path) -> Option<String> {
    reject_reparse_ancestors(path).ok()?;
    if !std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file() && metadata.len() <= 64) {
        return None;
    }
    token::load(path).ok().filter(|secret| {
        secret
            .strip_prefix(AGENT_TOKEN_PREFIX)
            .is_some_and(|value| {
                value.len() == 43
                    && value
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            })
    })
}

fn same_path(a: &Path, b: &Path) -> bool {
    super::path_guard::canonical_non_strict(a)
        .ok()
        .is_some_and(|a| super::path_guard::canonical_non_strict(b).is_ok_and(|b| a == b))
}

fn inside(path: &Path, root: &Path) -> bool {
    super::path_guard::canonical_non_strict(root).is_ok_and(|root| path.starts_with(root))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::ProfileKind;

    struct Fixture(RuntimeProfile);

    impl Fixture {
        fn new() -> Self {
            let home =
                std::env::temp_dir().join(format!("muse-agent-access-test-{}", token::generate()));
            let profile = RuntimeProfile {
                kind: ProfileKind::Development,
                home,
                onboarding_qa: true,
            };
            profile.initialize_development().unwrap();
            Self(profile)
        }

        fn open(&self) -> Arc<AccessRuntime> {
            let (runtime, error) = AccessRuntime::open(&self.0);
            assert!(error.is_none());
            runtime
        }

        fn full_search() -> AccessPolicy {
            AccessPolicy {
                mode: ScopeMode::Full,
                search: GrantScope::AllLocal,
                ..AccessPolicy::default()
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0.home);
        }
    }

    #[tokio::test]
    async fn cleared_index_stays_cleared_on_restart_and_policy_change() {
        let fixture = Fixture::new();
        let mut access = fixture.open();
        #[cfg(windows)]
        {
            Arc::get_mut(&mut access).unwrap().everything = None;
        }
        access.save(Fixture::full_search(), false).unwrap();
        access.issue_agent_token(|_| {}).unwrap();
        let author = format!("Bearer {}", access.agent_token().unwrap());
        let path = fixture.0.home.join("file-name-index.json");
        access.prewarm_search();
        assert!(path.is_file());
        assert_eq!(access.index_status().state, IndexPhase::DirectorySearch);

        let scoped = fixture.0.home.join("search-indexes");
        std::fs::create_dir(&scoped).unwrap();
        let managed = scoped.join("1234567890abcdef.json");
        let owned = scoped.join("unrelated.json");
        std::fs::write(&managed, "managed").unwrap();
        std::fs::write(&owned, "sample to preserve").unwrap();
        access.clear_index().unwrap();
        assert!(!path.exists() && !managed.exists() && owned.is_file());
        assert_eq!(access.index_status().bytes, Some(0));
        drop(access);

        let mut access = fixture.open();
        #[cfg(windows)]
        {
            Arc::get_mut(&mut access).unwrap().everything = None;
        }
        assert_eq!(access.index_status().state, IndexPhase::Cleared);
        access.save(Fixture::full_search(), false).unwrap();
        access.prewarm_search();
        let request = SearchRequest {
            name: "hello.txt".into(),
            ..SearchRequest::default()
        };
        assert!(matches!(
            access.clone().search_agent(&author, request.clone()).await,
            Err(AgentSearchError::Search(SearchError::IndexCleared))
        ));
        assert!(!path.exists());

        access.resume_index().unwrap();
        access.prewarm_search();
        assert!(path.is_file());
        let answer = access.search_agent(&author, request).await.unwrap();
        assert_eq!(answer.hits[0].path, "hello.txt");
    }

    #[test]
    fn agent_credential_is_explicit_separate_persistent_and_revocable() {
        let fixture = Fixture::new();
        let runtime = fixture.open();
        assert!(runtime.issue_agent_token(|_| panic!("no grant")).is_err());
        runtime.save(Fixture::full_search(), false).unwrap();
        assert!(!runtime.agent_ready());
        assert!(!fixture.open().agent_enabled());
        let mut redaction = String::new();
        runtime
            .issue_agent_token(|secret| redaction = secret.into())
            .unwrap();
        let first = format!("Bearer {redaction}");
        assert!(runtime.agent_ready());
        assert!(runtime.agent_auth(Some(&first)));
        assert!(fixture.open().agent_auth(Some(&first)));
        assert!(!runtime.agent_auth(Some(&format!("Bearer {}", token::generate()))));
        let generation = runtime.agent_search_generation();
        runtime.issue_agent_token(|_| {}).unwrap();
        assert!(generation.load(Ordering::Acquire));
        assert!(!runtime.agent_auth(Some(&first)));
        let second = format!("Bearer {}", runtime.agent_token().unwrap());
        assert!(fixture.open().agent_auth(Some(&second)));
        runtime.revoke_agent_token().unwrap();
        assert!(!runtime.agent_enabled());
        assert!(!runtime.agent_auth(Some(&second)));
        assert!(!fixture.open().agent_enabled());
    }

    #[tokio::test]
    async fn search_cannot_grant_content_access_and_revoke_invalidates_it() {
        let fixture = Fixture::new();
        let runtime = fixture.open();
        runtime.save(Fixture::full_search(), false).unwrap();
        runtime.issue_agent_token(|_| {}).unwrap();
        let header = format!("Bearer {}", runtime.agent_token().unwrap());
        assert!(runtime.agent_roots(Operation::Read).is_none());
        assert!(runtime.agent_roots(Operation::Write).is_none());
        assert_eq!(
            runtime.resolve_agent_target(Operation::Read, "test-disk", "hello.txt"),
            Err(ERR_NOT_AUTHORIZED)
        );
        let desktop = runtime.agent_desktop().unwrap();
        assert_eq!(desktop.root, "test-disk");
        assert!(desktop.path.is_empty());
        assert!(same_path(
            Path::new(&desktop.absolute_path),
            &fixture.0.home.join("files")
        ));
        let request = SearchRequest {
            name: "hello.txt".into(),
            ..Default::default()
        };
        let result = runtime
            .clone()
            .search_agent(&header, request.clone())
            .await
            .unwrap();
        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].path, "hello.txt");
        runtime.save(AccessPolicy::default(), false).unwrap();
        assert!(runtime.agent_enabled());
        assert!(!runtime.agent_ready());
        assert!(runtime.agent_desktop().is_none());
        assert!(matches!(
            runtime.clone().search_agent(&header, request.clone()).await,
            Err(AgentSearchError::Forbidden)
        ));
        runtime.revoke_agent_token().unwrap();
        assert!(matches!(
            runtime.clone().search_agent(&header, request).await,
            Err(AgentSearchError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn selected_search_root_has_a_separate_index_and_coverage() {
        let fixture = Fixture::new();
        let work = fixture.0.home.join("files");
        let other = fixture.0.home.join("other");
        std::fs::create_dir(&other).unwrap();
        std::fs::write(other.join("hello.txt"), "other scope").unwrap();
        let runtime = fixture.open();
        runtime
            .save(
                AccessPolicy {
                    roots: BTreeMap::from([("work".into(), work), ("other".into(), other)]),
                    search: GrantScope::Folders,
                    ..Default::default()
                },
                false,
            )
            .unwrap();
        let response = runtime
            .clone()
            .search_local(SearchRequest {
                root: Some("work".into()),
                name: "hello.txt".into(),
                ..Default::default()
            })
            .await
            .unwrap();
        assert!(response.complete);
        assert_eq!(response.scopes.len(), 1);
        assert_eq!(response.scopes[0].root, "work");
        assert_eq!(response.hits.len(), 1);
        assert_eq!(response.hits[0].root, "work");
        assert!(!fixture.0.home.join("file-name-index.json").exists());
    }

    #[test]
    fn agent_credential_file_is_hidden_even_with_parent_grant() {
        let fixture = Fixture::new();
        let runtime = fixture.open();
        let policy = AccessPolicy {
            roots: [("profile".into(), fixture.0.home.clone())].into(),
            read: GrantScope::Folders,
            write: GrantScope::Folders,
            ..AccessPolicy::default()
        };
        runtime.validate(&policy).unwrap();
        runtime.save(policy, false).unwrap();
        runtime.issue_agent_token(|_| {}).unwrap();
        assert!(!runtime.agent_listing_entry_allowed(runtime.agent_token_path()));
        for operation in [Operation::Read, Operation::Write] {
            assert_eq!(
                runtime.resolve_agent_target(operation, "profile", AGENT_TOKEN_FILE),
                Err(super::super::access::ERR_PROTECTED)
            );
        }
    }

    #[test]
    fn production_protection_blocks_credentials_and_sensitive_writes_only() {
        let raw_root =
            std::env::temp_dir().join(format!("muse-sensitive-test-{}", token::generate()));
        std::fs::create_dir_all(&raw_root).unwrap();
        // GitHub Actions windows-latest 的 %TEMP% 含 8.3 短路径（RUNNER~1）；先规范化再构造预期路径。
        let root = std::fs::canonicalize(&raw_root).unwrap();
        let home = root.join("Users/Alice");
        let documents = home.join("Documents");
        let desktop = home.join("Desktop");
        let downloads = home.join("Downloads");
        let roaming = home.join("AppData/Roaming");
        let local = home.join("AppData/Local");
        let startup = roaming.join(r"Microsoft\Windows\Start Menu\Programs\Startup");
        let ps_profile = documents.join("PowerShell");
        let ssh = home.join(".ssh");
        let app_dir = root.join("Portable/MuseLink");
        let project = desktop.join("MyProject");
        for dir in [
            &home,
            &documents,
            &desktop,
            &downloads,
            &startup,
            &ps_profile,
            &ssh,
            &app_dir,
            &project,
            &local,
        ] {
            std::fs::create_dir_all(dir).unwrap();
        }
        let exe = app_dir.join("muse-connector.exe");
        std::fs::write(&exe, b"bin").unwrap();

        let env = SensitiveRoots {
            profile_home: home.join(".muse-bridge"),
            user_home: Some(home.clone()),
            roaming_app_data: Some(roaming.clone()),
            local_app_data: Some(local.clone()),
            documents: Some(documents.clone()),
            desktop: Some(desktop.clone()),
            downloads: Some(downloads.clone()),
            program_data: Some(root.join("ProgramData")),
            system_root: Some(root.join("Windows")),
            program_files: vec![root.join("Program Files")],
            current_exe: Some(exe.clone()),
        };
        let (protected, write_protected) = production_protection(&env);

        // 凭证私钥目录：读写搜全部保护
        assert!(protected_path(&ssh.join("id_ed25519"), &protected));
        assert!(protected_path(&ssh.join("id_ed25519"), &write_protected));

        // 启动项、PowerShell Profile、.gitconfig 与程序目录：允许读，但禁止写
        for target in [
            startup.join("evil.bat"),
            ps_profile.join("Microsoft.PowerShell_profile.ps1"),
            home.join(".gitconfig"),
            app_dir.join("version.dll"),
        ] {
            assert!(!protected_path(&target, &protected));
            assert!(protected_path(&target, &write_protected));
        }

        // 普通项目目录与文档根目录自身可正常读写
        assert!(!protected_path(&project.join("main.rs"), &write_protected));
        assert!(!protected_path(
            &documents.join("notes.txt"),
            &write_protected
        ));

        // 便携 exe 裸放在桌面时，不误把整个桌面标成只读，仍保护 exe 自身与 everything/
        let loose_exe = desktop.join("muse-connector.exe");
        std::fs::write(&loose_exe, b"bin").unwrap();
        let loose_env = SensitiveRoots {
            current_exe: Some(loose_exe.clone()),
            ..env
        };
        let (_, loose_write_protected) = production_protection(&loose_env);
        assert!(!protected_path(
            &project.join("main.rs"),
            &loose_write_protected
        ));
        assert!(protected_path(&loose_exe, &loose_write_protected));
        assert!(protected_path(
            &desktop.join("everything/Everything.exe"),
            &loose_write_protected
        ));

        std::fs::remove_dir_all(root).unwrap();
    }
}
