//! 一个监督层拥有 API 监听器和隧道；用户操作与恢复共享同一把异步锁。
use crate::core::{
    access::{AccessPolicy, GrantScope, ScopeMode},
    access_runtime::{AccessRuntime, IndexStatus},
    api::{self, ApiOptions, ApiState, BridgePaths},
    audit::{Audit, AuditEntry, now_iso},
    config::BridgeConfig,
    exec_runtime::{
        ApprovalDecision, ApprovalEvent, ApprovalView, AuditSink, ExecRuntime, SessionGrantView,
    },
    search::{SearchRequest, SearchResponse},
    token,
};
use crate::profile::{
    DesktopState, DeviceNameUpdate, Language, ProviderSettings, RuntimeProfile, valid_device_name,
};
use crate::tunnel::{Health, TunnelManager, TunnelObservation, TunnelStatus, observe_tailscale};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, watch};

struct Runtime {
    api_task: Option<tokio::task::JoinHandle<std::io::Result<()>>>,
    shutdown: Option<watch::Sender<bool>>,
    tunnel: TunnelManager,
    actual_port: u16,
    retries: u32,
    generation: u64,
}
impl Drop for Runtime {
    fn drop(&mut self) {
        if let Some(task) = self.api_task.take() {
            task.abort();
        }
    }
}
#[derive(Clone, Serialize)]
pub struct Snapshot {
    pub run_id: String,
    pub profile: crate::profile::ProfileKind,
    pub initialized: bool,
    pub connection_configured: bool,
    pub access_configured: bool,
    pub file_access: Option<AccessPolicy>,
    pub ntfs_search_service: Option<bool>,
    pub(crate) index_status: IndexStatus,
    pub agent_enabled: bool,
    pub agent_ready: bool,
    pub agent_token_version: Option<String>,
    pub exec_enabled: bool,
    pub pending_approvals: Vec<ApprovalView>,
    pub exec_sessions: Vec<SessionGrantView>,
    pub fresh_setup: bool,
    pub setup_error: Option<String>,
    pub file_token_version: Option<String>,
    pub home: String,
    pub config: BridgeConfig,
    pub desktop: DesktopState,
    pub suggested_device_name: Option<String>,
    pub status: TunnelStatus,
    pub stats: Value,
    pub dependencies: Value,
    pub capabilities: crate::capabilities::CapabilityBoundary,
    pub version: &'static str,
    pub log_bytes: u64,
    pub log_errors: Vec<String>,
}

#[derive(Clone, Copy, Deserialize)]
pub(crate) struct FileAccessEdit {
    pub(super) expected_mode: Option<ScopeMode>,
    pub(super) enable_all_operations: bool,
}

struct ApiAuditSink(ApiState);

impl AuditSink for ApiAuditSink {
    fn record_exec(&self, entry: AuditEntry) {
        self.0.audit().record(&entry);
    }
    fn redact(&self, text: &str) -> String {
        self.0.audit().redact_text(text)
    }
}

pub struct ServiceController {
    pub profile: RuntimeProfile,
    pub api: ApiState,
    pub logs: Arc<Audit>,
    access: Arc<AccessRuntime>,
    exec: Arc<ExecRuntime>,
    access_update: Mutex<()>,
    desktop: RwLock<DesktopState>,
    runtime: Mutex<Runtime>,
    status: watch::Sender<TunnelStatus>,
    initialized: AtomicBool,
    fresh_setup: bool,
    setup_error: RwLock<Option<String>>,
    tools: std::sync::Mutex<Option<(Instant, Value)>>,
    run_id: String,
    port_override: Option<u16>,
    pub exiting: AtomicBool,
    maintenance: AtomicBool,
    ntfs_service_observed: AtomicBool,
}
impl ServiceController {
    pub fn open(profile: RuntimeProfile) -> Arc<Self> {
        Self::open_inner(profile, None)
    }
    fn open_inner(profile: RuntimeProfile, port_override: Option<u16>) -> Arc<Self> {
        let initialization = profile.initialize_development().err();
        let loaded = BridgeConfig::load_from(&profile.config_path()).and_then(|mut config| {
            profile
                .validate_config_scope(&config)
                .map_err(std::io::Error::other)?;
            if profile.is_development() {
                config.port = 18795;
            }
            Ok(config)
        });
        let loaded_token = token::load(&profile.token_path());
        let initialized = loaded.is_ok() && loaded_token.is_ok();
        let desktop = profile.load_desktop();
        let is_missing = |error: &std::io::Error| error.kind() == std::io::ErrorKind::NotFound;
        let fresh_setup = initialization.is_none()
            && loaded.as_ref().is_err_and(is_missing)
            && loaded_token.as_ref().is_err_and(is_missing)
            && matches!(profile.state_path().try_exists(), Ok(false));
        let mut setup_error = initialization.or_else(|| match (&loaded, &loaded_token) {
            _ if fresh_setup => Some("请选择开放目录。".into()),
            (Err(_), Err(_)) => {
                Some("无法读取现有目录配置和本机令牌，请检查 config.json 与 token 文件。".into())
            }
            (Err(_), _) => Some("无法读取现有目录配置，请检查 config.json 和开放目录。".into()),
            (_, Err(_)) => Some("无法读取本机令牌，请检查 token 文件。".into()),
            _ => None,
        });
        let config = loaded.unwrap_or_else(|_| BridgeConfig {
            port: profile.default_port(),
            read_only: true,
            roots: Default::default(),
        });
        let desktop = desktop.unwrap_or_else(|e| {
            setup_error = Some(e);
            DesktopState::default()
        });
        let (access, access_error) = AccessRuntime::open(&profile);
        if let Some(error) = access_error {
            setup_error = Some(error);
        } else if access.policy().is_some() && !initialized && initialization_files_absent(&profile)
        {
            setup_error = None;
        }
        let paths = BridgePaths {
            config: profile.config_path(),
            token: profile.token_path(),
            audit: profile.home.join("audit.log"),
        };
        let (api, _) = ApiState::new(
            config,
            loaded_token.unwrap_or_else(|_| token::generate()),
            paths,
            ApiOptions::default(),
        );
        api.attach_access(access.clone());
        let exec = ExecRuntime::new(&profile.home, desktop.exec_enabled);
        exec.attach_audit(Arc::new(ApiAuditSink(api.clone())));
        api.attach_exec(exec.clone());
        let logs = Arc::new(Audit::runtime(profile.home.join("server.log")));
        logs.protect_secret(&api.token());
        if let Some(secret) = access.agent_token() {
            api.audit().protect_secret(&secret);
            logs.protect_secret(&secret);
        }
        let mut tunnel = TunnelManager::new(profile.clone());
        let port = api.config_snapshot().port;
        tunnel.adopt_pending_owner(&desktop.provider, port);
        let (status, _) = watch::channel(TunnelStatus {
            health: Health::Paused,
            enabled: desktop.desired_enabled,
            note: "连接已暂停".into(),
            ..Default::default()
        });
        let controller = Arc::new(Self {
            profile,
            api,
            logs,
            access,
            exec,
            access_update: Mutex::new(()),
            desktop: RwLock::new(desktop),
            runtime: Mutex::new(Runtime {
                api_task: None,
                shutdown: None,
                tunnel,
                actual_port: port,
                retries: 0,
                generation: 0,
            }),
            status,
            initialized: AtomicBool::new(initialized),
            fresh_setup,
            setup_error: RwLock::new(setup_error),
            tools: std::sync::Mutex::new(None),
            run_id: format!(
                "{}-{}",
                std::process::id(),
                chrono::Utc::now().timestamp_millis()
            ),
            port_override,
            exiting: AtomicBool::new(false),
            maintenance: AtomicBool::new(false),
            ntfs_service_observed: AtomicBool::new(false),
        });
        controller
            .api
            .attach_device_names(Arc::downgrade(&controller));
        controller
    }
    pub fn snapshot(&self) -> Snapshot {
        let initialized = self.initialized.load(Ordering::Relaxed);
        let file_access = self.access.policy();
        let agent_enabled = self.access.agent_enabled();
        let agent_ready = self.access.agent_ready();
        let ntfs_search_service = self.access.ntfs_search_service();
        let service_running = ntfs_search_service == Some(true);
        if service_running && !self.ntfs_service_observed.swap(true, Ordering::AcqRel) {
            self.prewarm_file_search();
        } else if !service_running {
            self.ntfs_service_observed.store(false, Ordering::Release);
        }
        Snapshot {
            run_id: self.run_id.clone(),
            profile: self.profile.kind,
            initialized,
            connection_configured: initialized || agent_enabled,
            access_configured: initialized || file_access.is_some(),
            fresh_setup: self.fresh_setup && !initialized && file_access.is_none(),
            file_access,
            ntfs_search_service,
            index_status: self.access.index_status(),
            agent_enabled,
            agent_ready,
            agent_token_version: agent_enabled
                .then(|| token::file_version(self.access.agent_token_path()))
                .flatten(),
            exec_enabled: self.exec.is_enabled(),
            pending_approvals: self.exec.pending_approvals(),
            exec_sessions: self.exec.active_sessions(),
            setup_error: self.setup_error.read().unwrap().clone(),
            file_token_version: if initialized {
                token::file_version(&self.api.paths().token)
            } else {
                None
            },
            home: self.profile.home.to_string_lossy().into(),
            config: self.api.file_view(),
            desktop: self.desktop_state(),
            suggested_device_name: std::env::var("COMPUTERNAME")
                .ok()
                .filter(|name| valid_device_name(name)),
            status: self.status(),
            stats: self.api.stats_snapshot(),
            dependencies: self.tool_status(),
            capabilities: crate::capabilities::file_tools_boundary(
                agent_ready,
                self.exec.is_enabled(),
            ),
            version: env!("CARGO_PKG_VERSION"),
            log_bytes: self
                .api
                .audit()
                .disk_bytes()
                .saturating_add(self.logs.disk_bytes()),
            log_errors: [self.api.audit().error(), self.logs.error()]
                .into_iter()
                .flatten()
                .collect(),
        }
    }
    fn connection_configured(&self) -> bool {
        self.initialized.load(Ordering::Relaxed) || self.access.agent_enabled()
    }

    pub async fn set_agent_access(&self, enabled: bool) -> Result<(), String> {
        let _update = self.access_update.lock().await;
        if enabled && let Some(error) = self.setup_error.read().unwrap().clone() {
            return Err(error);
        }
        let access = self.access.clone();
        let api = self.api.clone();
        let logs = self.logs.clone();
        tokio::task::spawn_blocking(move || {
            if enabled {
                access.issue_agent_token(|secret| {
                    api.audit().protect_secret(secret);
                    logs.protect_secret(secret);
                })?;
                logs.runtime_entry("info", "Muse 文件工具凭证已发放，请在安全卡片中填写");
            } else {
                access.revoke_agent_token()?;
                logs.runtime_entry("info", "Muse 文件工具凭证已撤销");
            }
            Ok::<(), String>(())
        })
        .await
        .map_err(|_| "Muse 文件工具凭证更新未完成".to_string())??;
        self.exec.abort_all("Muse 专用令牌已变更");
        self.reset_agent_public_result();
        if !enabled && !self.connection_configured() && self.desktop_state().desired_enabled {
            self.toggle(false)
                .await
                .map_err(|error| format!("Muse 文件工具凭证已撤销，暂停连接时遇到问题：{error}"))?;
        }
        Ok(())
    }

    pub fn agent_token_path(&self) -> Result<&std::path::Path, String> {
        if self.access.agent_enabled() {
            Ok(self.access.agent_token_path())
        } else {
            Err("请先启用 Muse 文件工具".into())
        }
    }

    pub(crate) fn current_agent_token(&self) -> Result<String, String> {
        self.access
            .agent_token()
            .ok_or_else(|| "请先生成 Muse 专用令牌".into())
    }

    pub async fn agent_probe_context(&self) -> Result<(String, AccessPolicy), String> {
        let _update = self.access_update.lock().await;
        let policy = self
            .access
            .policy()
            .filter(|_| self.access.agent_ready())
            .ok_or("请先保存文件授权并生成 Muse 专用令牌")?;
        Ok((self.current_agent_token()?, policy))
    }

    pub async fn save_file_access(&self, policy: AccessPolicy) -> Result<(), String> {
        self.save_file_access_edit(policy, None).await
    }

    pub(crate) async fn save_file_access_edit(
        &self,
        mut policy: AccessPolicy,
        edit: Option<FileAccessEdit>,
    ) -> Result<(), String> {
        let _update = self.access_update.lock().await;
        let saved = self.access.policy();
        if let Some(edit) = edit
            && edit.expected_mode != saved.as_ref().map(|saved| saved.mode)
        {
            return Err("文件权限已变更，请检查后重新保存。".into());
        }
        self.access.validate(&policy)?;
        if !edit.is_some_and(|edit| edit.enable_all_operations)
            && let Some(saved) = saved.as_ref().filter(|saved| saved.mode != policy.mode)
        {
            let scopes = [policy.search, policy.read, policy.write];
            if scopes.contains(&GrantScope::AllLocal) {
                return Err("切换到磁盘模式前，请确认对所选范围启用全部操作。".into());
            }
            if scopes.contains(&GrantScope::Folders) {
                let access = self.access.clone();
                let saved = saved.clone();
                policy = tokio::task::spawn_blocking(move || {
                    access.preserve_folder_access(&saved, policy)
                })
                .await
                .map_err(|_| "保存文件授权未完成".to_string())??;
            }
        }
        if saved.as_ref() == Some(&policy) {
            return Ok(());
        }
        let initialized = self.initialized.load(Ordering::Relaxed);
        let legacy_read_only = initialized && self.api.read_only();
        // Bootstrap a narrow v0.3 entry only when the user explicitly selects folders.
        if !initialized
            && initialization_files_absent(&self.profile)
            && policy.mode == ScopeMode::Folders
            && policy.read == GrantScope::Folders
        {
            self.configure(BridgeConfig {
                port: self.api.config_snapshot().port,
                roots: policy.roots.clone(),
                read_only: true,
            })
            .await?;
        }
        let access = self.access.clone();
        tokio::task::spawn_blocking(move || access.save(policy, legacy_read_only))
            .await
            .map_err(|_| "保存文件授权未完成".to_string())??;
        self.exec.revoke_sessions();
        self.reset_agent_public_result();
        if self.initialized.load(Ordering::Relaxed) || initialization_files_absent(&self.profile) {
            *self.setup_error.write().unwrap() = None;
        }
        self.prewarm_file_search();
        Ok(())
    }

    pub fn local_disk_aliases(&self) -> Vec<String> {
        self.access.local_disk_aliases()
    }

    pub async fn search_local_files(
        &self,
        request: SearchRequest,
    ) -> Result<SearchResponse, String> {
        self.access.clone().search_local(request).await
    }
    pub async fn clear_search_index(&self) -> Result<(), String> {
        let access = self.access.clone();
        tokio::task::spawn_blocking(move || access.clear_index())
            .await
            .map_err(|_| "清理索引任务中断".to_string())?
    }

    pub fn index_folder_path(&self) -> std::path::PathBuf {
        let dir = self.access.index_home();
        if dir.is_dir() {
            dir.to_path_buf()
        } else {
            self.profile.home.clone()
        }
    }

    pub async fn clear_logs(&self) -> Result<(), String> {
        let api = self.api.clone();
        let runtime = self.logs.clone();
        tokio::task::spawn_blocking(move || {
            api.audit().clear()?;
            runtime.clear()?;
            Ok::<(), String>(())
        })
        .await
        .map_err(|_| "清除日志任务中断".to_string())?
    }

    pub async fn rebuild_search_index(&self) -> Result<(), String> {
        let access = self.access.clone();
        tokio::task::spawn_blocking(move || access.resume_index())
            .await
            .map_err(|_| "重新建库任务中断".to_string())??;
        self.prewarm_file_search();
        Ok(())
    }
    pub fn cancel_local_file_search(&self) {
        self.access.cancel_search();
    }
    pub(crate) fn invalidate_tool_status(&self) {
        *self.tools.lock().unwrap() = None;
    }
    fn tool_status(&self) -> Value {
        let mut tools = self.tools.lock().unwrap();
        if let Some((checked, status)) = &*tools
            && checked.elapsed() < Duration::from_secs(60)
        {
            return status.clone();
        }
        let status = json!({
            "tailscale": crate::tunnel::discover_executable("tailscale.exe").is_some(),
            "cloudflared": crate::tunnel::discover_executable("cloudflared.exe").is_some(),
            "simulated": self.profile.is_development(),
        });
        *tools = Some((Instant::now(), status.clone()));
        status
    }
    pub(crate) fn desktop_state(&self) -> DesktopState {
        self.desktop.read().unwrap().clone()
    }
    pub fn status(&self) -> TunnelStatus {
        self.status.borrow().clone()
    }
    pub fn subscribe(&self) -> watch::Receiver<TunnelStatus> {
        self.status.subscribe()
    }
    fn publish(
        &self,
        health: Health,
        api_up: bool,
        observation: TunnelObservation,
        note: String,
        port: u16,
    ) {
        let mut next = TunnelStatus {
            health,
            api_up,
            funnel_up: observation.configured && observation.online,
            url: observation.url,
            enabled: self.desktop.read().unwrap().desired_enabled,
            last_check: now_iso(),
            note,
            api_port: port,
            public_verified: None,
            agent_public_verified: None,
        };
        let mut log_note = None;
        self.status.send_modify(|previous| {
            if previous.api_up
                && next.api_up
                && previous.funnel_up
                && next.funnel_up
                && previous.url == next.url
                && previous.api_port == next.api_port
                && previous.health == next.health
                && previous.enabled == next.enabled
            {
                next.public_verified = previous.public_verified;
                next.agent_public_verified = previous.agent_public_verified;
                if previous.public_verified.is_some() {
                    next.note = previous.note.clone();
                }
            }
            if previous.health != next.health || previous.note != next.note {
                log_note = Some(next.note.clone());
            }
            *previous = next;
        });
        if let Some(note) = log_note {
            self.logs.runtime_entry("info", &note);
        }
    }
    pub fn spawn_supervisor(self: &Arc<Self>) {
        let weak = Arc::downgrade(self);
        tauri::async_runtime::spawn(async move {
            loop {
                let Some(controller) = weak.upgrade() else {
                    break;
                };
                if controller.exiting.load(Ordering::Relaxed) {
                    break;
                }
                controller.supervise().await;
                let retry = controller.runtime.lock().await.retries;
                drop(controller);
                tokio::time::sleep(Duration::from_secs(
                    (15u64.saturating_mul(1 << retry.min(3))).min(120),
                ))
                .await;
            }
        });
    }
    async fn supervise(&self) {
        self.supervise_with(|port| async move {
            if !probe_owned_api(port, &self.api.token()).await {
                return None;
            }
            Some(if self.profile.is_development() {
                Ok(TunnelObservation::simulated(true))
            } else {
                observe_tailscale(port).await
            })
        })
        .await;
    }
    async fn supervise_with<Fut>(&self, probe: impl FnOnce(u16) -> Fut)
    where
        Fut: std::future::Future<Output = Option<Result<TunnelObservation, String>>>,
    {
        let (generation, port) = {
            let mut runtime = self.runtime.lock().await;
            if self.exiting.load(Ordering::Relaxed) || self.maintenance.load(Ordering::Relaxed) {
                return;
            }
            if !self.desktop_state().desired_enabled {
                // Only a matching ownership ledger permits interrupted-pause cleanup.
                if runtime.tunnel.is_owned()
                    && let Err(error) = self.stop_locked(&mut runtime).await
                {
                    self.logs.runtime_entry("error", &error);
                }
                return;
            }
            if !self.connection_configured()
                || self.setup_error.read().unwrap().is_some()
                || runtime.retries >= 5
            {
                return;
            }
            if !runtime.tunnel.is_live_tailscale(runtime.actual_port)
                || runtime
                    .api_task
                    .as_ref()
                    .is_none_or(|task| task.is_finished())
            {
                let result = self.start_locked(&mut runtime).await;
                self.record_retry(&mut runtime, result);
                return;
            }
            (runtime.generation, runtime.actual_port)
        };
        self.finish_observation(generation, probe(port).await).await;
    }
    async fn finish_observation(
        &self,
        generation: u64,
        observation: Option<Result<TunnelObservation, String>>,
    ) {
        let mut runtime = self.runtime.lock().await;
        if runtime.generation != generation
            || self.exiting.load(Ordering::Relaxed)
            || self.maintenance.load(Ordering::Relaxed)
            || !self.desktop_state().desired_enabled
        {
            return;
        }
        let result = match observation {
            Some(observed)
                if runtime
                    .api_task
                    .as_ref()
                    .is_some_and(|task| !task.is_finished()) =>
            {
                self.reconcile_tunnel(&mut runtime, observed).await
            }
            _ => self.start_locked(&mut runtime).await,
        };
        self.record_retry(&mut runtime, result);
    }
    fn record_retry(&self, runtime: &mut Runtime, result: Result<(), String>) {
        if let Err(error) = result {
            runtime.retries += 1;
            self.logs.runtime_entry("error", &error);
        }
    }
    async fn start_locked(&self, runtime: &mut Runtime) -> Result<(), String> {
        runtime.generation = runtime.generation.wrapping_add(1);
        if !self.connection_configured() {
            return Err("请先保存文件授权并启用 Muse 文件工具".into());
        }
        if runtime.api_task.as_ref().is_some_and(|t| t.is_finished()) {
            runtime.api_task.take();
            runtime.shutdown.take();
            self.logs
                .runtime_entry("warning", "内置 API 任务已退出，正在恢复");
        }
        if runtime.api_task.is_none() {
            let config = self.api.config_snapshot();
            let port = self.port_override.unwrap_or_else(|| {
                if self.profile.is_development() {
                    18795
                } else {
                    config.port
                }
            });
            self.publish(
                Health::Starting,
                false,
                Default::default(),
                "正在启动文件服务".into(),
                port,
            );
            let listener = match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
                Ok(listener) => listener,
                Err(e) => {
                    let message = if e.kind() == std::io::ErrorKind::AddrInUse {
                        format!("端口 {port} 被其他进程占用；本应用未取得服务归属")
                    } else {
                        format!("文件服务无法监听：{}", e.kind())
                    };
                    self.publish(
                        Health::Conflict,
                        false,
                        Default::default(),
                        message.clone(),
                        port,
                    );
                    return Err(message);
                }
            };
            runtime.actual_port = listener.local_addr().map_err(|e| e.to_string())?.port();
            let (tx, rx) = watch::channel(false);
            let api = self.api.clone();
            runtime.api_task = Some(tokio::spawn(async move {
                api::serve_listener(api, listener, rx).await
            }));
            runtime.shutdown = Some(tx);
        }
        if !probe_owned_api(runtime.actual_port, &self.api.token()).await {
            self.stop_api(runtime).await;
            self.publish(
                Health::Down,
                false,
                Default::default(),
                "内置 API 鉴权健康检查失败；已停止本应用监听".into(),
                runtime.actual_port,
            );
            return Err("内置 API 健康检查失败".into());
        }
        let observed = runtime.tunnel.observe().await;
        self.reconcile_tunnel(runtime, observed).await
    }
    async fn reconcile_tunnel(
        &self,
        runtime: &mut Runtime,
        observed: Result<TunnelObservation, String>,
    ) -> Result<(), String> {
        let provider = self.desktop_state().provider;
        let observed = match observed {
            Ok(o)
                if runtime.tunnel.is_owned()
                    && o.online
                    && (o.configured
                        || provider.kind != crate::profile::ProviderKind::Tailscale) =>
            {
                Ok(o)
            }
            _ => runtime.tunnel.start(&provider, runtime.actual_port).await,
        };
        match observed {
            Ok(observation) => {
                let health = if observation.configured && observation.online {
                    Health::Up
                } else {
                    Health::Degraded
                };
                let note = observation.note.clone();
                self.publish(health, true, observation, note, runtime.actual_port);
                runtime.retries = 0;
                Ok(())
            }
            Err(error) => {
                self.invalidate_tool_status();
                self.publish(
                    Health::Degraded,
                    true,
                    Default::default(),
                    format!("本地 API 正常，隧道不可用：{error}"),
                    runtime.actual_port,
                );
                Err(error)
            }
        }
    }
    async fn stop_api(&self, runtime: &mut Runtime) {
        if let Some(tx) = runtime.shutdown.take() {
            let _ = tx.send(true);
        }
        if let Some(mut task) = runtime.api_task.take() {
            if tokio::time::timeout(Duration::from_secs(2), &mut task)
                .await
                .is_err()
            {
                task.abort();
                let _ = task.await;
            }
        }
    }
    async fn stop_locked(&self, runtime: &mut Runtime) -> Result<(), String> {
        self.access.cancel_search();
        self.exec.abort_all("连接已暂停");
        runtime.generation = runtime.generation.wrapping_add(1);
        self.publish(
            Health::Stopping,
            self.status().api_up,
            Default::default(),
            "正在停止连接".into(),
            runtime.actual_port,
        );
        let result = runtime.tunnel.stop().await;
        self.stop_api(runtime).await;
        self.publish(
            if result.is_ok() {
                Health::Paused
            } else {
                Health::Degraded
            },
            false,
            Default::default(),
            result
                .as_ref()
                .err()
                .map(|e| format!("文件服务已停止，隧道清理失败：{e}"))
                .unwrap_or_else(|| "连接已暂停".into()),
            runtime.actual_port,
        );
        result
    }
    fn update_desktop(
        &self,
        update: impl FnOnce(&mut DesktopState) -> Result<bool, String>,
    ) -> Result<bool, String> {
        let mut current = self.desktop.write().unwrap();
        let mut next = current.clone();
        if !update(&mut next)? {
            return Ok(false);
        }
        self.profile.save_desktop(&next)?;
        *current = next;
        Ok(true)
    }
    pub async fn toggle(&self, enable: bool) -> Result<TunnelStatus, String> {
        let mut runtime = self.runtime.lock().await;
        runtime.retries = 0;
        if enable {
            if let Some(error) = self.setup_error.read().unwrap().clone() {
                return Err(error);
            }
            self.update_desktop(|state| {
                state.desired_enabled = true;
                Ok(true)
            })?;
            self.start_locked(&mut runtime).await?;
        } else {
            // 即便磁盘失败也先停止服务，界面明确提示暂停偏好未保存。
            let save = {
                let mut state = self.desktop.write().unwrap();
                state.desired_enabled = false;
                self.profile.save_desktop(&state)
            };
            let stopped = self.stop_locked(&mut runtime).await;
            save?;
            stopped?;
        }
        Ok(self.status())
    }
    pub async fn configure(&self, mut config: BridgeConfig) -> Result<(), String> {
        if self.profile.is_development() {
            config.port = 18795;
        }
        if config.port == 0 {
            return Err("端口必须在 1–65535 之间".into());
        }
        if config.roots.keys().any(|k| {
            k.is_empty()
                || k.len() > 64
                || k.contains(['/', '\\', ':'])
                || k.chars().any(char::is_control)
        }) {
            return Err("目录别名不能为空或包含路径分隔符".into());
        }
        if config.roots.is_empty() {
            return Err("至少保留一个开放目录".into());
        }
        config.ensure_roots().map_err(|e| e.to_string())?;
        self.profile.validate_config_scope(&config)?;
        let mut runtime = self.runtime.lock().await;
        let old = self.api.config_snapshot();
        let resume = self.desktop.read().unwrap().desired_enabled;
        if runtime.api_task.is_some() {
            self.stop_locked(&mut runtime).await?;
        }
        if let Err(e) = self.api.update_config(config) {
            if resume {
                let _ = self.start_locked(&mut runtime).await;
            }
            return Err(e);
        }
        if !self.initialized.load(Ordering::Relaxed) {
            if !self.profile.token_path().exists() {
                token::save(&self.profile.token_path(), &token::generate())
                    .map_err(|_| "初始化令牌失败，请重试")?;
            }
            self.api.set_token(
                token::load(&self.profile.token_path()).map_err(|_| "无法读取本机令牌")?,
            );
            self.initialized.store(true, Ordering::Relaxed);
            *self.setup_error.write().unwrap() = None;
        }
        if resume && let Err(e) = self.start_locked(&mut runtime).await {
            let _ = self.stop_locked(&mut runtime).await;
            if self.api.update_config(old).is_ok() {
                let _ = self.start_locked(&mut runtime).await;
            }
            return Err(format!("新配置未能启用，已尝试恢复旧配置：{e}"));
        }
        self.logs
            .runtime_entry("info", "文件配置已保存；开放目录未被删除");
        Ok(())
    }
    pub async fn set_provider(&self, provider: ProviderSettings) -> Result<(), String> {
        crate::tunnel::validate_provider(&provider)?;
        let mut runtime = self.runtime.lock().await;
        let previous = self.desktop.read().unwrap().clone();
        if previous.provider == provider {
            return Ok(());
        }
        if runtime.api_task.is_some() {
            self.stop_locked(&mut runtime).await?;
        }
        if let Err(e) = self.update_desktop(|state| {
            state.provider = provider;
            Ok(true)
        }) {
            if previous.desired_enabled {
                let _ = self.start_locked(&mut runtime).await;
            }
            return Err(e);
        }
        if previous.desired_enabled
            && let Err(e) = self.start_locked(&mut runtime).await
        {
            let _ = self.stop_locked(&mut runtime).await;
            self.update_desktop(|state| {
                state.provider = previous.provider;
                Ok(true)
            })?;
            let restored = self.start_locked(&mut runtime).await;
            return Err(format!(
                "切换失败：{e}；{}",
                if restored.is_ok() {
                    "原连接已恢复"
                } else {
                    "原连接恢复失败，请检查运行日志"
                }
            ));
        }
        Ok(())
    }
    pub async fn save_window_preferences(
        &self,
        close_to_tray: Option<bool>,
        start_minimized: Option<bool>,
    ) -> Result<(), String> {
        let _operation = self.runtime.lock().await;
        self.update_desktop(|state| {
            if let Some(value) = close_to_tray {
                state.close_to_tray = value;
            }
            if let Some(value) = start_minimized {
                state.start_minimized = value;
            }
            Ok(true)
        })?;
        Ok(())
    }
    pub async fn save_language(&self, language: Language) -> Result<(), String> {
        let _operation = self.runtime.lock().await;
        self.update_desktop(|state| {
            state.language = language;
            Ok(true)
        })?;
        Ok(())
    }
    pub async fn save_device_name(
        &self,
        name: String,
        update_muse: bool,
    ) -> Result<Option<DeviceNameUpdate>, String> {
        if !valid_device_name(&name) {
            return Err(
                "请输入 1–32 个字符，可用文字、0–9、空格、连字符和下划线，首尾不能有空格。".into(),
            );
        }
        let mut receipt = None;
        let changed = self.update_desktop(|state| {
            if state.device_name == name {
                receipt = state.device_name_update.clone();
                return Ok(false);
            }
            // 保留无法读取的状态文件，等待用户修复。
            self.profile.load_desktop()?;
            let pending = state
                .device_name_update
                .as_ref()
                .is_some_and(|item| item.pending);
            receipt = (update_muse || pending).then(|| DeviceNameUpdate {
                id: token::generate(),
                pending: true,
            });
            state.device_name = name;
            state.device_name_update = receipt.clone();
            Ok(true)
        })?;
        if changed {
            self.status.send_modify(|_| {});
        }
        Ok(receipt)
    }
    pub(crate) fn confirm_device_name(&self, id: &str) -> Result<bool, String> {
        let mut matched = false;
        let changed = self.update_desktop(|state| {
            let Some(receipt) = state
                .device_name_update
                .as_mut()
                .filter(|item| token::constant_time_eq(&item.id, id))
            else {
                return Ok(false);
            };
            matched = true;
            let pending = receipt.pending;
            receipt.pending = false;
            Ok(pending)
        })?;
        if changed {
            self.status.send_modify(|_| {});
        }
        Ok(matched)
    }
    pub(crate) fn attach_approval_notifier(
        &self,
        notifier: Arc<dyn Fn(ApprovalEvent) + Send + Sync>,
    ) {
        self.exec.attach_notifier(notifier);
    }

    pub async fn set_exec_enabled(&self, enabled: bool) -> Result<(), String> {
        let _operation = self.runtime.lock().await;
        self.update_desktop(|state| {
            state.exec_enabled = enabled;
            Ok(true)
        })?;
        self.exec.set_enabled(enabled);
        self.logs.runtime_entry(
            "info",
            if enabled {
                "命令执行能力已开启（默认运行于写受限沙箱）"
            } else {
                "命令执行能力已关闭，待审批项与运行中任务已中止"
            },
        );
        self.status.send_modify(|_| {});
        Ok(())
    }

    pub fn resolve_exec_approval(
        &self,
        id: &str,
        decision: ApprovalDecision,
    ) -> Result<bool, String> {
        let handled = self.exec.resolve_approval(id, decision)?;
        if handled {
            self.status.send_modify(|_| {});
        }
        Ok(handled)
    }

    pub fn revoke_exec_sessions(&self) {
        self.exec.revoke_sessions();
        self.logs
            .runtime_entry("info", "已收回所有项目会话执行授权");
        self.status.send_modify(|_| {});
    }

    pub async fn shutdown(&self) {
        {
            let mut runtime = self.runtime.lock().await;
            let _ = self.stop_locked(&mut runtime).await;
        }
        let access = self.access.clone();
        let _ = tokio::task::spawn_blocking(move || access.shutdown_index()).await;
    }

    pub fn prewarm_file_search(&self) {
        let access = self.access.clone();
        tauri::async_runtime::spawn_blocking(move || access.prewarm_search());
    }
    pub async fn suspend_for_update(&self) -> Result<(), String> {
        let mut runtime = self.runtime.lock().await;
        self.maintenance.store(true, Ordering::Relaxed);
        if let Err(error) = self.stop_locked(&mut runtime).await {
            self.maintenance.store(false, Ordering::Relaxed);
            return Err(error);
        }
        Ok(())
    }
    pub async fn resume_after_update_failure(&self) {
        let mut runtime = self.runtime.lock().await;
        self.maintenance.store(false, Ordering::Relaxed);
        if self.desktop.read().unwrap().desired_enabled {
            let _ = self.start_locked(&mut runtime).await;
        }
    }
    pub fn mark_public_result(
        &self,
        expected: &TunnelStatus,
        success: bool,
        note: &str,
    ) -> Result<(), String> {
        self.record_public_result(expected, |status| {
            status.public_verified = Some(success);
            status.note = note.into();
        })
    }

    fn reset_agent_public_result(&self) {
        self.status
            .send_if_modified(|status| status.agent_public_verified.take().is_some());
    }

    pub async fn mark_agent_public_result(
        &self,
        expected: &TunnelStatus,
        credential: &str,
        policy: &AccessPolicy,
        success: bool,
    ) -> Result<(), String> {
        let _update = self.access_update.lock().await;
        if self.access.policy().as_ref() != Some(policy)
            || !self.access.agent_ready()
            || !token::constant_time_eq(&self.current_agent_token()?, credential)
        {
            return Err("授权或令牌在测试期间已变化，请重新测试".into());
        }
        self.record_public_result(expected, |status| {
            status.agent_public_verified = Some(success)
        })
    }

    fn record_public_result(
        &self,
        expected: &TunnelStatus,
        record: impl FnOnce(&mut TunnelStatus),
    ) -> Result<(), String> {
        let saved = self.status.send_if_modified(|status| {
            if status.url != expected.url
                || status.api_port != expected.api_port
                || !status.api_up
                || !status.funnel_up
            {
                return false;
            }
            record(status);
            true
        });
        saved
            .then_some(())
            .ok_or_else(|| "连接在测试期间已变化，请重新测试当前入口".into())
    }
}
fn initialization_files_absent(profile: &RuntimeProfile) -> bool {
    [profile.config_path(), profile.token_path()]
        .into_iter()
        .all(|path| matches!(path.try_exists(), Ok(false)))
}

async fn probe_owned_api(port: u16, token: &str) -> bool {
    tokio::time::timeout(Duration::from_secs(3),async{
        let mut connection=tokio::net::TcpStream::connect(("127.0.0.1",port)).await?;
        connection.write_all(format!("GET /api/health HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n").as_bytes()).await?;
        let mut bytes=Vec::new();connection.take(16384).read_to_end(&mut bytes).await?;
        let response=String::from_utf8_lossy(&bytes);
        let body=response.split_once("\r\n\r\n").map(|(_,b)|b).unwrap_or("");
        let valid=serde_json::from_str::<Value>(body).ok().is_some_and(|v|v["ok"]==true&&v["version"]=="0.3");
        Ok::<bool,std::io::Error>(response.starts_with("HTTP/1.1 200")&&valid)
    }).await.ok().and_then(Result::ok).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile() -> RuntimeProfile {
        RuntimeProfile {
            kind: crate::profile::ProfileKind::Development,
            home: std::env::temp_dir().join(format!("muse-service-{}", token::generate())),
            onboarding_qa: false,
        }
    }
    #[tokio::test]
    async fn device_name_preserves_legacy_state_and_rejects_invalid_saves() {
        let profile = profile();
        profile.initialize_development().unwrap();
        std::fs::write(
            profile.state_path(),
            r#"{"start_minimized":true,"extra":"keep"}"#,
        )
        .unwrap();
        let controller = ServiceController::open_inner(profile.clone(), Some(0));
        assert!(controller.snapshot().desktop.device_name.is_empty());

        let name = "测试笔记本 2_A-𠀀";
        assert!(
            controller
                .save_device_name(name.into(), false)
                .await
                .unwrap()
                .is_none()
        );
        controller.save_language(Language::English).await.unwrap();
        let saved = std::fs::read_to_string(profile.state_path()).unwrap();
        for invalid in [
            "",
            " leading",
            "trailing ",
            "bad/name",
            "bad\nname",
            "bad😃",
            &"机".repeat(33),
        ] {
            assert!(
                controller
                    .save_device_name(invalid.into(), false)
                    .await
                    .is_err()
            );
        }
        assert!(valid_device_name(&"𠀀".repeat(32)));
        assert_eq!(controller.snapshot().desktop.device_name, name);
        assert_eq!(
            std::fs::read_to_string(profile.state_path()).unwrap(),
            saved
        );
        assert_eq!(
            serde_json::from_str::<Value>(&saved).unwrap()["extra"],
            "keep"
        );
        drop(controller);

        let reopened = ServiceController::open_inner(profile.clone(), Some(0));
        let state = reopened.snapshot().desktop;
        assert_eq!(state.device_name, name);
        assert_eq!(state.language, Language::English);
        assert!(state.start_minimized);
        assert!(state.close_to_tray);
        drop(reopened);
        std::fs::remove_dir_all(profile.home).unwrap();
    }
    #[tokio::test]
    async fn muse_can_confirm_only_the_current_rename_with_its_own_credential() {
        let profile = profile();
        profile.initialize_development().unwrap();
        let controller = ServiceController::open_inner(profile.clone(), Some(0));
        controller
            .save_file_access(AccessPolicy {
                mode: ScopeMode::Folders,
                roots: [("fixture".into(), profile.home.join("files"))].into(),
                read: GrantScope::Folders,
                ..AccessPolicy::default()
            })
            .await
            .unwrap();
        controller.set_agent_access(true).await.unwrap();
        let previous = controller
            .save_device_name("笔记本".into(), true)
            .await
            .unwrap()
            .unwrap();
        let current = controller
            .save_device_name("工作笔记本".into(), true)
            .await
            .unwrap()
            .unwrap();
        let agent = controller.access.agent_token().unwrap();
        let legacy = controller.api.token();
        let port = controller.toggle(true).await.unwrap().api_port;
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let confirm = |id: &str, credential: &str| {
            client
                .post(format!(
                    "http://127.0.0.1:{port}/agent/v1/device-name/confirm"
                ))
                .bearer_auth(credential)
                .header("Content-Type", "application/json")
                .body(json!({"update_id": id}).to_string())
                .send()
        };
        assert_eq!(confirm(&current.id, &legacy).await.unwrap().status(), 401);
        assert_eq!(confirm(&previous.id, &agent).await.unwrap().status(), 409);
        assert!(
            profile
                .load_desktop()
                .unwrap()
                .device_name_update
                .unwrap()
                .pending
        );
        assert_eq!(confirm(&current.id, &agent).await.unwrap().status(), 200);
        assert_eq!(confirm(&current.id, &agent).await.unwrap().status(), 200);
        let stored = profile.load_desktop().unwrap();
        assert_eq!(stored.device_name, "工作笔记本");
        assert!(!stored.device_name_update.unwrap().pending);
        controller.shutdown().await;
        drop(controller);
        let reopened = ServiceController::open_inner(profile.clone(), Some(0));
        assert!(
            !reopened
                .snapshot()
                .desktop
                .device_name_update
                .unwrap()
                .pending
        );
        drop(reopened);
        std::fs::remove_dir_all(profile.home).unwrap();
    }

    #[tokio::test]
    async fn fresh_setup_is_distinct_from_repair_and_token_version_survives_restart() {
        let mut profile = profile();
        profile.onboarding_qa = true;
        let controller = ServiceController::open_inner(profile.clone(), Some(0));
        let first = controller.snapshot();
        assert!(first.fresh_setup && !first.initialized);
        assert!(first.file_token_version.is_none());
        assert!(profile.home.join("files/hello.txt").is_file());

        let mut config = first.config;
        config.roots.insert("qa".into(), profile.home.join("files"));
        controller.configure(config).await.unwrap();
        let saved = controller.snapshot();
        assert!(saved.initialized && !saved.fresh_setup);
        assert!(saved.file_token_version.is_some());
        drop(controller);

        let reopened = ServiceController::open_inner(profile.clone(), Some(0));
        assert_eq!(
            reopened.snapshot().file_token_version,
            saved.file_token_version
        );
        reopened.api.rotate_token().unwrap();
        assert_ne!(
            reopened.snapshot().file_token_version,
            saved.file_token_version
        );
        drop(reopened);

        std::fs::write(profile.config_path(), "invalid config").unwrap();
        let broken = ServiceController::open_inner(profile.clone(), Some(0));
        let snapshot = broken.snapshot();
        assert!(!snapshot.fresh_setup && !snapshot.initialized);
        assert!(snapshot.setup_error.unwrap().contains("config.json"));
        drop(broken);
        std::fs::remove_dir_all(profile.home).unwrap();
    }
    #[tokio::test]
    async fn agent_only_setup_serves_authorized_files_and_revokes_without_a_legacy_token() {
        let mut profile = profile();
        profile.onboarding_qa = true;
        let controller = ServiceController::open_inner(profile.clone(), Some(0));
        controller
            .save_file_access(AccessPolicy {
                mode: ScopeMode::Full,
                search: GrantScope::AllLocal,
                read: GrantScope::AllLocal,
                write: GrantScope::AllLocal,
                ..AccessPolicy::default()
            })
            .await
            .unwrap();
        assert!(!controller.snapshot().connection_configured);
        controller.set_agent_access(true).await.unwrap();
        assert!(controller.snapshot().connection_configured && controller.snapshot().agent_ready);
        assert!(!profile.token_path().exists());
        let key = controller.access.agent_token().unwrap();
        let started = controller.toggle(true).await.unwrap();
        assert!(started.api_up);
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let origin = format!("http://127.0.0.1:{}", started.api_port);

        let desktop: Value = client
            .get(format!("{origin}/agent/v1/locations/desktop"))
            .bearer_auth(&key)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(desktop["root"], "test-disk");
        assert_eq!(desktop["path"], "");
        let search: Value = client
            .post(format!("{origin}/agent/v1/search"))
            .bearer_auth(&key)
            .json(&json!({"name": "hello.txt"}))
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(search["hits"][0]["root"], "test-disk");
        assert_eq!(search["hits"][0]["path"], "hello.txt");

        controller.set_agent_access(true).await.unwrap();
        let obsolete = client
            .get(format!("{origin}/agent/v1/roots"))
            .bearer_auth(&key)
            .send()
            .await
            .unwrap();
        assert_eq!(obsolete.status(), reqwest::StatusCode::UNAUTHORIZED);
        controller.set_agent_access(false).await.unwrap();
        assert!(!controller.snapshot().agent_enabled && !controller.status().api_up);
        drop(controller);

        let reopened = ServiceController::open_inner(profile.clone(), Some(0));
        assert!(!reopened.snapshot().agent_enabled && !reopened.desktop_state().desired_enabled);
        assert!(!profile.token_path().exists());
        drop(reopened);
        std::fs::remove_dir_all(profile.home).unwrap();
    }
    #[tokio::test]
    async fn full_access_can_initialize_and_search_without_a_legacy_token() {
        let mut profile = profile();
        profile.onboarding_qa = true;
        let controller = ServiceController::open_inner(profile.clone(), Some(0));
        let policy = AccessPolicy {
            mode: ScopeMode::Full,
            search: GrantScope::AllLocal,
            ..AccessPolicy::default()
        };
        controller.save_file_access(policy.clone()).await.unwrap();
        let snapshot = controller.snapshot();
        assert!(snapshot.access_configured && !snapshot.initialized && !snapshot.fresh_setup);
        assert!(snapshot.setup_error.is_none());
        assert!(!profile.token_path().exists());
        let result = controller
            .search_local_files(SearchRequest {
                name: "hello".into(),
                ..SearchRequest::default()
            })
            .await
            .unwrap();
        assert_eq!(result.hits.len(), 1);
        assert_eq!(result.hits[0].root, "test-disk");
        drop(controller);

        let reopened = ServiceController::open_inner(profile.clone(), Some(0));
        assert_eq!(reopened.snapshot().file_access, Some(policy));
        assert!(reopened.snapshot().setup_error.is_none());
        reopened
            .save_file_access(AccessPolicy::default())
            .await
            .unwrap();
        assert!(
            reopened
                .search_local_files(SearchRequest::default())
                .await
                .is_err()
        );
        drop(reopened);
        std::fs::remove_dir_all(profile.home).unwrap();
    }
    #[tokio::test]
    async fn folders_can_bootstrap_legacy_but_full_mode_does_not_expand_it() {
        let mut profile = profile();
        profile.onboarding_qa = true;
        let controller = ServiceController::open_inner(profile.clone(), Some(0));
        let folders = AccessPolicy {
            mode: ScopeMode::Folders,
            roots: [("files".into(), profile.home.join("files"))].into(),
            folder_grants: None,
            disks: None,
            search: GrantScope::Folders,
            read: GrantScope::Folders,
            write: GrantScope::Folders,
        };
        controller.save_file_access(folders.clone()).await.unwrap();
        assert!(controller.snapshot().initialized);
        assert!(!controller.api.file_view().read_only);
        let full = AccessPolicy {
            mode: ScopeMode::Full,
            search: GrantScope::AllLocal,
            read: GrantScope::AllLocal,
            ..AccessPolicy::default()
        };
        assert!(controller.save_file_access(full.clone()).await.is_err());
        assert_eq!(controller.snapshot().file_access.as_ref(), Some(&folders));
        controller
            .save_file_access_edit(
                full,
                Some(FileAccessEdit {
                    expected_mode: Some(ScopeMode::Folders),
                    enable_all_operations: true,
                }),
            )
            .await
            .unwrap();
        let narrowed = controller.api.file_view();
        assert_eq!(narrowed.roots, folders.roots);
        assert!(narrowed.read_only);
        controller
            .save_file_access(AccessPolicy::default())
            .await
            .unwrap();
        assert!(controller.api.file_view().roots.is_empty());
        drop(controller);
        std::fs::remove_dir_all(profile.home).unwrap();
    }
    #[tokio::test]
    async fn switching_to_folders_keeps_only_the_saved_file_permissions() {
        use crate::core::access::FolderGrant;

        let mut profile = profile();
        profile.onboarding_qa = true;
        let controller = ServiceController::open_inner(profile.clone(), Some(0));
        let inside = profile.home.join("files/inside");
        let restricted = inside.join("restricted");
        let outside = profile.home.join("outside");
        std::fs::create_dir_all(&restricted).unwrap();
        std::fs::create_dir(&outside).unwrap();

        let initial = AccessPolicy {
            mode: ScopeMode::Full,
            roots: [
                ("inside".into(), inside.clone()),
                ("restricted".into(), restricted.clone()),
                ("outside".into(), outside.clone()),
            ]
            .into(),
            disks: Some(["test-disk".into()].into()),
            folder_grants: Some(
                [
                    (
                        "inside".into(),
                        FolderGrant {
                            search: true,
                            ..Default::default()
                        },
                    ),
                    ("restricted".into(), FolderGrant::default()),
                    (
                        "outside".into(),
                        FolderGrant {
                            search: true,
                            ..Default::default()
                        },
                    ),
                ]
                .into(),
            ),
            search: GrantScope::Folders,
            read: GrantScope::Off,
            write: GrantScope::AllLocal,
        };
        controller.save_file_access(initial.clone()).await.unwrap();

        let mut folders = AccessPolicy {
            mode: ScopeMode::Folders,
            roots: initial.roots.clone(),
            search: GrantScope::Folders,
            read: GrantScope::Folders,
            write: GrantScope::Folders,
            ..Default::default()
        };
        let denied_change = AccessPolicy {
            roots: [("outside".into(), outside.clone())].into(),
            search: GrantScope::Off,
            ..folders.clone()
        };
        assert!(controller.save_file_access(denied_change).await.is_err());
        assert_eq!(controller.snapshot().file_access.as_ref(), Some(&initial));

        folders.roots.remove("restricted");
        folders.roots.insert("renamed".into(), restricted);
        let switch = Some(FileAccessEdit {
            expected_mode: Some(ScopeMode::Full),
            enable_all_operations: false,
        });
        controller
            .save_file_access_edit(folders.clone(), switch)
            .await
            .unwrap();
        assert_eq!(
            controller
                .save_file_access_edit(folders.clone(), switch)
                .await,
            Err("文件权限已变更，请检查后重新保存。".into())
        );
        controller.set_agent_access(true).await.unwrap();
        let port = controller.toggle(true).await.unwrap().api_port;
        let token = controller.current_agent_token().unwrap();
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let base = format!("http://127.0.0.1:{port}/agent/v1");
        let roots = || {
            client
                .get(format!("{base}/roots"))
                .bearer_auth(&token)
                .send()
        };
        let write = |root| {
            client
                .post(format!("{base}/write"))
                .bearer_auth(&token)
                .json(&json!({"root": root, "path": "sample.txt", "content": "fixture"}))
                .send()
        };
        let reply = roots().await.unwrap().error_for_status().unwrap();
        let reply = reply.json::<serde_json::Value>().await.unwrap();
        assert_eq!(
            reply["roots"],
            json!({"search": ["inside", "outside"], "read": [], "write": ["inside", "renamed"]})
        );
        assert_eq!(write("outside").await.unwrap().status(), 403);
        assert!(!outside.join("sample.txt").exists());
        assert_eq!(write("inside").await.unwrap().status(), 200);
        assert_eq!(
            std::fs::read_to_string(inside.join("sample.txt")).unwrap(),
            "fixture"
        );

        controller
            .save_file_access_edit(
                folders,
                Some(FileAccessEdit {
                    expected_mode: Some(ScopeMode::Folders),
                    enable_all_operations: true,
                }),
            )
            .await
            .unwrap();
        assert_eq!(write("outside").await.unwrap().status(), 200);
        assert_eq!(
            std::fs::read_to_string(outside.join("sample.txt")).unwrap(),
            "fixture"
        );
        controller.shutdown().await;
        drop(controller);
        std::fs::remove_dir_all(profile.home).unwrap();
    }
    #[tokio::test]
    async fn first_muse_grant_preserves_existing_legacy_read_only() {
        use crate::core::access::Operation;

        let profile = profile();
        let controller = ServiceController::open_inner(profile.clone(), Some(0));
        let config = controller.api.config_snapshot();
        assert!(controller.snapshot().initialized);
        assert!(config.read_only);
        assert!(controller.access.policy().is_none());

        let policy = AccessPolicy {
            mode: ScopeMode::Folders,
            roots: config.roots.clone(),
            search: GrantScope::Folders,
            read: GrantScope::Folders,
            write: GrantScope::Folders,
            ..AccessPolicy::default()
        };
        controller.save_file_access(policy.clone()).await.unwrap();
        controller.shutdown().await;
        drop(controller);

        let reopened = ServiceController::open_inner(profile.clone(), Some(0));
        assert_eq!(reopened.api.file_view().roots, config.roots);
        assert!(reopened.api.file_view().read_only);
        assert_eq!(reopened.access.policy().as_ref(), Some(&policy));
        assert!(
            reopened
                .access
                .resolve_agent_target(Operation::Write, "development", "sample.txt")
                .is_ok()
        );
        reopened.shutdown().await;
        drop(reopened);
        std::fs::remove_dir_all(profile.home).unwrap();
    }

    #[tokio::test]
    async fn legacy_http_checks_each_folders_write_permission_and_revocation() {
        use crate::core::access::FolderGrant;

        let mut profile = profile();
        profile.onboarding_qa = true;
        let controller = ServiceController::open_inner(profile.clone(), Some(0));
        let input = profile.home.join("files/input");
        let output = profile.home.join("files/output");
        std::fs::create_dir(&input).unwrap();
        std::fs::create_dir(&output).unwrap();
        let mut policy = AccessPolicy {
            mode: ScopeMode::Folders,
            disks: None,
            roots: [
                ("input".into(), input.clone()),
                ("output".into(), output.clone()),
            ]
            .into(),
            folder_grants: Some(
                [
                    (
                        "input".into(),
                        FolderGrant {
                            search: true,
                            read: true,
                            write: false,
                        },
                    ),
                    (
                        "output".into(),
                        FolderGrant {
                            search: true,
                            read: true,
                            write: true,
                        },
                    ),
                ]
                .into(),
            ),
            search: GrantScope::Folders,
            read: GrantScope::Folders,
            write: GrantScope::Folders,
        };
        controller.save_file_access(policy.clone()).await.unwrap();
        let status = controller.toggle(true).await.unwrap();
        let url = format!("http://127.0.0.1:{}/api/write", status.api_port);
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let token = controller.api.token();
        let write = |root| {
            client
                .post(&url)
                .bearer_auth(&token)
                .json(&json!({
                    "root": root, "path": "sample.txt", "content": "fixture"
                }))
                .send()
        };
        assert_eq!(write("input").await.unwrap().status(), 403);
        assert!(!input.join("sample.txt").exists());
        assert_eq!(write("output").await.unwrap().status(), 200);
        assert_eq!(
            std::fs::read_to_string(output.join("sample.txt")).unwrap(),
            "fixture"
        );
        policy
            .folder_grants
            .as_mut()
            .unwrap()
            .get_mut("output")
            .unwrap()
            .write = false;
        controller.save_file_access(policy).await.unwrap();
        assert_eq!(write("output").await.unwrap().status(), 403);
        controller.shutdown().await;
        drop(controller);
        std::fs::remove_dir_all(profile.home).unwrap();
    }
    #[tokio::test]
    async fn pause_and_shutdown_wait_for_a_request_already_receiving_its_body() {
        for exit in [false, true] {
            let profile = profile();
            let home = profile.home.clone();
            let controller = ServiceController::open_inner(profile, Some(0));
            let mut config = controller.api.config_snapshot();
            config.read_only = false;
            let (root, path) = config.roots.first_key_value().unwrap();
            let target = path.join("pending.txt");
            std::fs::write(&target, "old").unwrap();
            let body =
                json!({"root":root,"path":"pending.txt","content":"replacement"}).to_string();
            controller.configure(config).await.unwrap();
            let started = controller.toggle(true).await.unwrap();
            let before = controller.api.stats_snapshot()["total"].clone();
            let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", started.api_port))
                .await
                .unwrap();
            let headers = format!(
                "POST /api/write HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                controller.api.token(),
                body.len()
            );
            tcp.write_all(headers.as_bytes()).await.unwrap();
            let (partial, end) = body.as_bytes().split_at(body.len() - 1);
            tcp.write_all(partial).await.unwrap();
            let wait_for_file_request = async {
                while controller.api.stats_snapshot()["total"] == before {
                    tokio::task::yield_now().await;
                }
            };
            tokio::time::timeout(Duration::from_secs(1), wait_for_file_request)
                .await
                .unwrap();
            assert_eq!(controller.api.stats_snapshot()["file_activity"]["total"], 0);
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "old");

            let mut status = controller.subscribe();
            let stop = tokio::spawn({
                let controller = controller.clone();
                async move {
                    if exit {
                        controller.exiting.store(true, Ordering::SeqCst);
                        controller.shutdown().await;
                    } else {
                        controller.toggle(false).await.unwrap();
                    }
                }
            });
            tokio::time::timeout(
                Duration::from_secs(1),
                status.wait_for(|s| s.health == Health::Stopping),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(!stop.is_finished());
            tcp.write_all(end).await.unwrap();
            let mut response = Vec::new();
            tokio::time::timeout(Duration::from_secs(1), tcp.read_to_end(&mut response))
                .await
                .unwrap()
                .unwrap();
            assert!(response.starts_with(b"HTTP/1.1 200"));
            stop.await.unwrap();
            assert!(!probe_owned_api(started.api_port, &controller.api.token()).await);
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "replacement");
            assert_eq!(controller.desktop_state().desired_enabled, exit);
            drop(controller);
            std::fs::remove_dir_all(home).unwrap();
        }
    }

    #[tokio::test]
    async fn slow_observation_does_not_delay_controls_or_restore_old_state() {
        use crate::profile::ProviderKind;

        let profile = profile();
        let home = profile.home.clone();
        let controller = ServiceController::open_inner(profile, Some(0));

        for action in ["pause", "switch", "exit"] {
            controller
                .set_provider(ProviderSettings::default())
                .await
                .unwrap();
            controller.toggle(true).await.unwrap();
            let (started, wait_for_probe) = tokio::sync::oneshot::channel();
            let (complete, pending) = tokio::sync::oneshot::channel();
            let probe = tokio::spawn({
                let controller = controller.clone();
                async move {
                    controller
                        .supervise_with(|_| async {
                            started.send(()).unwrap();
                            pending.await.unwrap()
                        })
                        .await;
                }
            });

            tokio::time::timeout(Duration::from_secs(2), wait_for_probe)
                .await
                .expect("periodic probe should start")
                .unwrap();
            let start = Instant::now();
            tokio::time::timeout(Duration::from_secs(2), async {
                match action {
                    "pause" => {
                        controller.toggle(false).await.unwrap();
                    }
                    "switch" => {
                        controller
                            .set_provider(ProviderSettings {
                                kind: ProviderKind::CloudflareNamed,
                                tunnel_id: "test-tunnel".into(),
                                hostname: "muse.example.com".into(),
                            })
                            .await
                            .unwrap();
                    }
                    "exit" => {
                        controller.exiting.store(true, Ordering::SeqCst);
                        controller.shutdown().await;
                    }
                    _ => unreachable!(),
                }
            })
            .await
            .expect("control should finish while probe is pending");
            let current = controller.status();
            assert_eq!(current.api_up, action == "switch");
            eprintln!(
                "{action}: {:.2?} with the probe still pending",
                start.elapsed()
            );
            complete.send(Some(Err("stale probe".into()))).unwrap();
            probe.await.unwrap();
            assert_eq!(controller.status().health, current.health);
            assert_eq!(controller.status().note, current.note);
        }
        drop(controller);
        std::fs::remove_dir_all(home).unwrap();
    }

    #[tokio::test]
    async fn public_result_survives_polling_but_cannot_cross_a_restart() {
        let profile = profile();
        let home = profile.home.clone();
        let controller = ServiceController::open_inner(profile, Some(0));
        let observation = TunnelObservation {
            configured: true,
            online: true,
            url: Some("https://test.ts.net".into()),
            note: "configured".into(),
        };
        controller.publish(
            Health::Up,
            true,
            observation.clone(),
            "configured".into(),
            1234,
        );
        let expected = controller.status();
        controller
            .mark_public_result(&expected, true, "verified")
            .unwrap();
        controller.publish(
            Health::Up,
            true,
            observation.clone(),
            "configured".into(),
            1234,
        );
        assert_eq!(controller.status().public_verified, Some(true));
        assert_eq!(controller.status().note, "verified");
        controller.publish(
            Health::Paused,
            false,
            Default::default(),
            "paused".into(),
            1234,
        );
        assert!(
            controller
                .mark_public_result(&expected, true, "stale")
                .is_err()
        );
        controller.publish(Health::Up, true, observation, "configured".into(), 1234);
        assert_eq!(controller.status().public_verified, None);
        drop(controller);
        std::fs::remove_dir_all(home).unwrap();
    }

    #[tokio::test]
    async fn agent_public_result_is_separate_and_expires_on_credential_change() {
        let profile = profile();
        let home = profile.home.clone();
        let controller = ServiceController::open_inner(profile, Some(0));
        controller
            .save_file_access(AccessPolicy {
                mode: ScopeMode::Folders,
                roots: [("files".into(), home.join("files"))].into(),
                read: GrantScope::Folders,
                ..Default::default()
            })
            .await
            .unwrap();
        controller.set_agent_access(true).await.unwrap();
        let (credential, policy) = controller.agent_probe_context().await.unwrap();
        let observation = TunnelObservation {
            configured: true,
            online: true,
            url: Some("https://test.ts.net".into()),
            note: "configured".into(),
        };
        controller.publish(
            Health::Up,
            true,
            observation.clone(),
            "configured".into(),
            1234,
        );
        let expected = controller.status();
        controller
            .mark_public_result(&expected, false, "legacy failed")
            .unwrap();
        controller
            .mark_agent_public_result(&expected, &credential, &policy, true)
            .await
            .unwrap();
        controller.publish(Health::Up, true, observation, "configured".into(), 1234);
        let verified = controller.status();
        assert_eq!(verified.agent_public_verified, Some(true));
        assert_eq!(verified.public_verified, Some(false));

        controller.set_agent_access(true).await.unwrap();
        assert_eq!(controller.status().agent_public_verified, None);
        assert!(
            controller
                .mark_agent_public_result(&expected, &credential, &policy, true)
                .await
                .is_err()
        );
        drop(controller);
        std::fs::remove_dir_all(home).unwrap();
    }
    #[tokio::test]
    async fn failed_installer_can_restore_the_persisted_connection_intent() {
        let profile = profile();
        let home = profile.home.clone();
        let controller = ServiceController::open_inner(profile, Some(0));
        controller.toggle(true).await.unwrap();
        controller.suspend_for_update().await.unwrap();
        assert!(!controller.status().api_up);
        assert!(controller.snapshot().desktop.desired_enabled);
        assert!(controller.maintenance.load(Ordering::Relaxed));
        controller.resume_after_update_failure().await;
        assert!(controller.status().api_up);
        assert!(!controller.maintenance.load(Ordering::Relaxed));
        controller.toggle(false).await.unwrap();
        drop(controller);
        std::fs::remove_dir_all(home).unwrap();
    }
    #[tokio::test]
    async fn owned_listener_pause_and_restart_stay_isolated() {
        let profile = profile();
        let home = profile.home.clone();
        let controller = ServiceController::open_inner(profile.clone(), Some(0));
        controller.toggle(true).await.unwrap();
        let port = controller.status().api_port;
        assert!(port > 0);
        assert!(controller.status().api_up);
        assert!(probe_owned_api(port, &controller.api.token()).await);
        assert!(controller.status().url.is_none());
        controller.toggle(false).await.unwrap();
        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_err()
        );
        assert!(!profile.load_desktop().unwrap().desired_enabled);
        drop(controller);
        let reopened = ServiceController::open_inner(profile, Some(0));
        assert!(!reopened.snapshot().desktop.desired_enabled);
        assert!(!reopened.status().api_up);
        drop(reopened);
        std::fs::remove_dir_all(home).unwrap();
    }
    #[tokio::test]
    async fn saving_the_current_provider_does_not_restart_or_write_state() {
        let profile = profile();
        let home = profile.home.clone();
        let controller = ServiceController::open_inner(profile, Some(0));
        controller.toggle(true).await.unwrap();
        let port = controller.status().api_port;
        let status_before = controller.status().last_check;
        let logs_before = controller.logs.recent(None, 1000).last_seq;
        let state_before = std::fs::read(controller.profile.state_path()).unwrap();
        controller
            .set_provider(controller.snapshot().desktop.provider)
            .await
            .unwrap();
        assert_eq!(controller.status().api_port, port);
        assert_eq!(controller.status().last_check, status_before);
        assert_eq!(controller.logs.recent(None, 1000).last_seq, logs_before);
        assert_eq!(
            std::fs::read(controller.profile.state_path()).unwrap(),
            state_before
        );
        assert!(probe_owned_api(port, &controller.api.token()).await);
        controller.toggle(false).await.unwrap();
        drop(controller);
        std::fs::remove_dir_all(home).unwrap();
    }
    #[tokio::test]
    async fn unrelated_listener_is_never_reported_as_owned_api() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let profile = profile();
        let home = profile.home.clone();
        let controller = ServiceController::open_inner(profile, Some(port));
        assert!(controller.toggle(true).await.is_err());
        assert_eq!(controller.status().health, Health::Conflict);
        assert!(!controller.status().api_up);
        controller.toggle(false).await.unwrap();
        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_ok()
        );
        drop(controller);
        drop(listener);
        std::fs::remove_dir_all(home).unwrap();
    }
    #[tokio::test]
    async fn crashed_api_task_is_restarted_by_supervisor() {
        let profile = profile();
        let home = profile.home.clone();
        let controller = ServiceController::open_inner(profile, Some(0));
        controller.toggle(true).await.unwrap();
        {
            let mut runtime = controller.runtime.lock().await;
            runtime.api_task.as_ref().unwrap().abort();
            let _ = runtime.api_task.take().unwrap().await;
            controller.start_locked(&mut runtime).await.unwrap();
        }
        assert!(controller.status().api_up);
        controller.toggle(false).await.unwrap();
        drop(controller);
        std::fs::remove_dir_all(home).unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn agent_exec_enforces_toggle_approval_session_and_sandbox_boundary() {
        let profile = profile();
        let home = profile.home.clone();
        profile.initialize_development().unwrap();
        let project = home.join("files/demo-project");
        let outside = home.join("outside-sibling");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        let controller = ServiceController::open_inner(profile.clone(), Some(0));
        controller
            .save_file_access(AccessPolicy {
                mode: ScopeMode::Folders,
                roots: [("work".into(), home.join("files"))].into(),
                search: GrantScope::Folders,
                read: GrantScope::Folders,
                write: GrantScope::Folders,
                ..AccessPolicy::default()
            })
            .await
            .unwrap();
        controller.set_agent_access(true).await.unwrap();
        let agent_key = controller.access.agent_token().unwrap();
        let legacy_key = controller.api.token();
        let port = controller.toggle(true).await.unwrap().api_port;

        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap();
        let origin = format!("http://127.0.0.1:{port}");

        // 1) 默认关闭：返回 403
        let disabled_resp = client
            .post(format!("{origin}/agent/v1/exec"))
            .bearer_auth(&agent_key)
            .json(&json!({
                "root": "work",
                "cwd": "demo-project",
                "mode": "direct",
                "program": "where",
                "args": ["cmd.exe"]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(disabled_resp.status(), 403);

        // 2) 开启总开关，但旧版 file token 依然 401
        controller.set_exec_enabled(true).await.unwrap();
        assert!(controller.snapshot().exec_enabled);
        let legacy_resp = client
            .post(format!("{origin}/agent/v1/exec"))
            .bearer_auth(&legacy_key)
            .json(&json!({
                "root": "work",
                "cwd": "demo-project",
                "mode": "direct",
                "program": "where",
                "args": ["cmd.exe"]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(legacy_resp.status(), 401);

        // 3) Direct 常规只读工具：无感自动放行并短等待直返 200
        let direct_resp = client
            .post(format!("{origin}/agent/v1/exec"))
            .bearer_auth(&agent_key)
            .json(&json!({
                "root": "work",
                "cwd": "demo-project",
                "mode": "direct",
                "program": "where",
                "args": ["cmd.exe"],
                "wait_ms": 5000
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(direct_resp.status(), 200);
        let direct_body: Value = direct_resp.json().await.unwrap();
        assert_eq!(direct_body["status"], "completed");
        assert_eq!(direct_body["exit_code"], 0);
        assert_eq!(direct_body["sandboxed"], true);

        // 4) 首次在该项目使用 cmd：进入 202 awaiting_approval，并出现在 pending_approvals
        let first_cmd = client
            .post(format!("{origin}/agent/v1/exec"))
            .bearer_auth(&agent_key)
            .json(&json!({
                "root": "work",
                "cwd": "demo-project",
                "mode": "cmd",
                "command": "echo inside-ok> inside.txt",
                "reason": "write test marker"
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(first_cmd.status(), 202);
        let first_body: Value = first_cmd.json().await.unwrap();
        assert_eq!(first_body["status"], "awaiting_approval");
        let job_id = first_body["job_id"].as_str().unwrap().to_owned();
        let approvals = controller.snapshot().pending_approvals;
        assert_eq!(approvals.len(), 1);
        assert!(approvals[0].allow_session);

        // 5) 桌面端批准「本会话允许此项目」，等待作业完成
        assert!(
            controller
                .resolve_exec_approval(&approvals[0].id, ApprovalDecision::AllowSession)
                .unwrap()
        );
        assert!(controller.snapshot().pending_approvals.is_empty());
        assert_eq!(controller.snapshot().exec_sessions.len(), 1);
        let mut finished = Value::Null;
        for _ in 0..40 {
            let poll: Value = client
                .get(format!("{origin}/agent/v1/exec/{job_id}"))
                .bearer_auth(&agent_key)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            if poll["status"] != "running" {
                finished = poll;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(finished["status"], "completed");
        assert_eq!(finished["exit_code"], 0);
        assert!(project.join("inside.txt").is_file());

        // 6) 同一项目第二次 cmd：命中本会话豁免直接无感放行，但尝试写工作区外仍被写受限沙箱拦截
        let escaped_file = outside.join("nope.txt");
        let second_cmd = client
            .post(format!("{origin}/agent/v1/exec"))
            .bearer_auth(&agent_key)
            .json(&json!({
                "root": "work",
                "cwd": "demo-project",
                "mode": "cmd",
                "command": format!("echo nope> \"{}\"", escaped_file.display()),
                "wait_ms": 5000
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(second_cmd.status(), 200);
        let second_body: Value = second_cmd.json().await.unwrap();
        assert_eq!(second_body["status"], "completed");
        assert_ne!(second_body["exit_code"], 0);
        assert!(!escaped_file.exists());

        // 7) 关闭命令执行总开关：立即熔断并清空会话授权
        controller.set_exec_enabled(false).await.unwrap();
        assert!(controller.snapshot().exec_sessions.is_empty());
        let after_off = client
            .post(format!("{origin}/agent/v1/exec"))
            .bearer_auth(&agent_key)
            .json(&json!({
                "root": "work",
                "cwd": "demo-project",
                "mode": "direct",
                "program": "where",
                "args": ["cmd.exe"]
            }))
            .send()
            .await
            .unwrap();
        assert_eq!(after_off.status(), 403);

        controller.shutdown().await;
        drop(controller);
        std::fs::remove_dir_all(home).unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn agent_exec_long_poll_wakes_on_approval_denial_and_grandchild_exit() {
        let profile = profile();
        let home = profile.home.clone();
        profile.initialize_development().unwrap();
        let project = home.join("files/demo-longpoll");
        std::fs::create_dir_all(&project).unwrap();

        let controller = ServiceController::open_inner(profile.clone(), Some(0));
        controller
            .save_file_access(AccessPolicy {
                mode: ScopeMode::Folders,
                roots: [("work".into(), home.join("files"))].into(),
                search: GrantScope::Folders,
                read: GrantScope::Folders,
                write: GrantScope::Folders,
                ..AccessPolicy::default()
            })
            .await
            .unwrap();
        controller.set_agent_access(true).await.unwrap();
        controller.set_exec_enabled(true).await.unwrap();
        let agent_key = controller.access.agent_token().unwrap();
        let port = controller.toggle(true).await.unwrap().api_port;

        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(20))
            .build()
            .unwrap();
        let origin = format!("http://127.0.0.1:{port}");

        // 1) 提交需审批命令（含继承管道的后台孙进程，验证长轮询实时唤醒且不会因孙进程卡死在 running）
        let submit: Value = client
            .post(format!("{origin}/agent/v1/exec"))
            .bearer_auth(&agent_key)
            .json(&json!({
                "root": "work",
                "cwd": "demo-longpoll",
                "mode": "cmd",
                "command": "start /b cmd /c \"ping -n 30 127.0.0.1 >nul\" & echo longpoll-ok"
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(submit["status"], "awaiting_approval");
        let job_id = submit["job_id"].as_str().unwrap().to_owned();
        let approval_id = controller.snapshot().pending_approvals[0].id.clone();

        // 2) 短 wait_ms 未审批时应按时返回 awaiting_approval
        let t0 = std::time::Instant::now();
        let waiting: Value = client
            .get(format!("{origin}/agent/v1/exec/{job_id}?wait_ms=150"))
            .bearer_auth(&agent_key)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(waiting["status"], "awaiting_approval");
        assert!(t0.elapsed() >= Duration::from_millis(120));

        // 3) 发起长轮询（wait_ms=10000），150ms 后桌面端批准，应迅速一步返回 completed 且不被孙进程阻塞
        let approver = controller.clone();
        let aid = approval_id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            let _ = approver.resolve_exec_approval(&aid, ApprovalDecision::AllowOnce);
        });
        let t1 = std::time::Instant::now();
        let done: Value = client
            .get(format!("{origin}/agent/v1/exec/{job_id}?wait_ms=10000"))
            .bearer_auth(&agent_key)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(done["status"], "completed");
        assert_eq!(done["exit_code"], 0);
        assert!(
            done["stdout"]
                .as_str()
                .unwrap_or("")
                .contains("longpoll-ok")
        );
        assert!(
            t1.elapsed() < Duration::from_secs(6),
            "long poll or detached grandchild stalled: {:?}",
            t1.elapsed()
        );

        // 4) 再提交一条审批命令，长轮询期间点击拒绝，应毫秒级立刻返回 denied
        let submit2: Value = client
            .post(format!("{origin}/agent/v1/exec"))
            .bearer_auth(&agent_key)
            .json(&json!({
                "root": "work",
                "cwd": "demo-longpoll",
                "mode": "cmd",
                "command": "echo should-deny"
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(submit2["status"], "awaiting_approval");
        let job_id2 = submit2["job_id"].as_str().unwrap().to_owned();
        let approval_id2 = controller.snapshot().pending_approvals[0].id.clone();

        let denier = controller.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            let _ = denier.resolve_exec_approval(&approval_id2, ApprovalDecision::Deny);
        });
        let t2 = std::time::Instant::now();
        let denied: Value = client
            .get(format!("{origin}/agent/v1/exec/{job_id2}?wait_ms=10000"))
            .bearer_auth(&agent_key)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(denied["status"], "denied");
        assert!(
            t2.elapsed() < Duration::from_secs(3),
            "long poll did not wake promptly on denial: {:?}",
            t2.elapsed()
        );

        // 5) 并发长轮询（超过 control_jobs 4 槽位）不得阻塞其他接口，且令牌撤销后长轮询返回 401
        let submit3: Value = client
            .post(format!("{origin}/agent/v1/exec"))
            .bearer_auth(&agent_key)
            .json(&json!({
                "root": "work",
                "cwd": "demo-longpoll",
                "mode": "cmd",
                "command": "echo concurrent-and-revoke"
            }))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(submit3["status"], "awaiting_approval");
        let job_id3 = submit3["job_id"].as_str().unwrap().to_owned();

        let mut waiters = Vec::new();
        for _ in 0..5 {
            let c = client.clone();
            let url = format!("{origin}/agent/v1/exec/{job_id3}?wait_ms=10000");
            let key = agent_key.clone();
            waiters.push(tokio::spawn(async move {
                c.get(url).bearer_auth(&key).send().await.unwrap().status()
            }));
        }
        tokio::time::sleep(Duration::from_millis(120)).await;

        let roots_t0 = std::time::Instant::now();
        let roots_resp = client
            .get(format!("{origin}/agent/v1/roots"))
            .bearer_auth(&agent_key)
            .send()
            .await
            .unwrap();
        assert_eq!(roots_resp.status(), 200);
        assert!(
            roots_t0.elapsed() < Duration::from_secs(2),
            "long polling blocked /agent/v1/roots: {:?}",
            roots_t0.elapsed()
        );

        // 撤销 Muse 专用令牌：会清空待审批并唤醒长轮询，唤醒后凭证复核返回 401
        controller.set_agent_access(false).await.unwrap();
        for waiter in waiters {
            let code = tokio::time::timeout(Duration::from_secs(3), waiter)
                .await
                .expect("waiter should wake after token revoke")
                .unwrap();
            assert_eq!(code, 401);
        }

        controller.shutdown().await;
        drop(controller);
        std::fs::remove_dir_all(home).unwrap();
    }
}
