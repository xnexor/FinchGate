//! file-api —— Python 版 `muse-file-api.py` v0.3 的 Rust 移植。
//! 保留 v0.3 成功响应及常用错误契约，有意修复/收紧：
//!   1. 限流只对未鉴权请求生效（原版匿名可打满配额，构成 DoS 面）
//!   2. 保留设备名 / ADS / 尾部点空格 / 根内 `..` 一律 400（原版为连接重置或静默别名）
//!   3. 逃逸出根的 `..` 报 "path escapes root"（错误串与原版一致）
//!   4. 拒绝非字符串 content 与无效 base64；合法 ASCII 空白仍可解码
//!   5. 写入请求体按 Base64 编码后的长度放行，再以解码后 10 MiB 兜底；
//!      原版按解码前的接近 10 MiB 截断，使合法的满额二进制写入提前失败
//!
//! 与 Python 版的行为对齐说明（经 11-17 攻击矩阵实测比对）：
//! - 401/403/404/413/429 与各端点成功响应体逐字段一致；
//! - read_only 检查先于路径解析（对齐原版：只读模式下连非法路径也报 403）；
//! - 审计字段与顺序、ts 格式（RFC3339 秒级 +00:00）一致。

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{ConnectInfo, OriginalUri, Path as AxumPath, Request, State};
use axum::http::{StatusCode, header};
use axum::response::Response;
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::{Semaphore, broadcast};

use super::access::{ERR_NOT_AUTHORIZED, ERR_PROTECTED, ERR_REPARSE, Operation};
use super::access_runtime::{AccessRuntime, AgentSearchError};
use super::audit::{Audit, AuditEntry, now_iso};
use super::config::BridgeConfig;
use super::exec_policy::ExecRequest;
use super::exec_runtime::{ExecJobStatus, ExecRuntime, ExecSubmitError, MAX_STATUS_WAIT_MS};
use super::handle;
use super::path_guard;
use super::search::{SearchError, SearchRequest};
use super::token;

pub const VERSION: &str = "0.3"; // 协议版本，与 Python 版对齐
pub const MAX_READ_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_WRITE_BYTES: u64 = 10 * 1024 * 1024;
pub const LIST_MAX_ENTRIES: usize = 5000;
pub const RATE_LIMIT: u64 = 1000;
pub const RATE_WINDOW_SECS: u64 = 60;
const MAX_SEARCH_REQUEST_BYTES: usize = 8 * 1024;
/// 不携带内容的 POST（建目录、轮换令牌）只放行元数据。
const MAX_METADATA_REQUEST_BYTES: usize = 32 * 1024;

// ---------- 路径集合 ----------

#[derive(Clone, Debug)]
pub struct BridgePaths {
    pub config: PathBuf,
    pub token: PathBuf,
    pub audit: PathBuf,
}

impl Default for BridgePaths {
    fn default() -> Self {
        Self {
            config: super::config::config_path(),
            token: super::config::token_path(),
            audit: super::config::audit_path(),
        }
    }
}

// ---------- 可调参数（测试注入用） ----------

#[derive(Clone, Debug)]
pub struct ApiOptions {
    pub rate_limit: u64,
    pub rate_window_secs: u64,
    pub max_read: u64,
    pub max_write: u64,
    pub list_max: usize,
}

impl Default for ApiOptions {
    fn default() -> Self {
        Self {
            rate_limit: RATE_LIMIT,
            rate_window_secs: RATE_WINDOW_SECS,
            max_read: MAX_READ_BYTES,
            max_write: MAX_WRITE_BYTES,
            list_max: LIST_MAX_ENTRIES,
        }
    }
}

// ---------- 统计 ----------

#[derive(Default)]
pub struct Stats {
    pub total: AtomicU64,
    pub authed: AtomicU64,
    pub auth_failures: AtomicU64,
    pub last_request: Mutex<Option<String>>,
    pub completed: AtomicU64,
    pub errors: AtomicU64,
    pub read_bytes: AtomicU64,
    pub written_bytes: AtomicU64,
    trend: Mutex<VecDeque<Value>>,
}

impl Stats {
    fn hit(&self, authed: bool, record_time: bool) {
        self.total.fetch_add(1, Ordering::Relaxed);
        if authed {
            self.authed.fetch_add(1, Ordering::Relaxed);
        } else {
            self.auth_failures.fetch_add(1, Ordering::Relaxed);
        }
        if record_time {
            *self.last_request.lock().unwrap() = Some(now_iso());
        }
    }
    fn complete(&self, endpoint: &str, code: u16, bytes: Option<u64>) {
        self.completed.fetch_add(1, Ordering::Relaxed);
        if code >= 400 {
            self.errors.fetch_add(1, Ordering::Relaxed);
        }
        if code == 200 {
            if matches!(endpoint, "/api/read" | "/agent/v1/read") {
                self.read_bytes
                    .fetch_add(bytes.unwrap_or(0), Ordering::Relaxed);
            }
            if matches!(endpoint, "/api/write" | "/agent/v1/write") {
                self.written_bytes
                    .fetch_add(bytes.unwrap_or(0), Ordering::Relaxed);
            }
        }
        let minute = chrono::Utc::now().timestamp() / 60;
        let mut trend = self.trend.lock().unwrap();
        if trend.back().is_none_or(|v| v["minute"] != minute) {
            trend.push_back(json!({"minute":minute,"requests":0,"errors":0}));
            while trend.len() > 15 {
                trend.pop_front();
            }
        }
        if let Some(bucket) = trend.back_mut() {
            bucket["requests"] = json!(bucket["requests"].as_u64().unwrap_or(0) + 1);
            if code >= 400 {
                bucket["errors"] = json!(bucket["errors"].as_u64().unwrap_or(0) + 1);
            }
        }
    }
    pub fn snapshot(&self) -> Value {
        json!({
            "total": self.total.load(Ordering::Relaxed),
            "authed": self.authed.load(Ordering::Relaxed),
            "auth_failures": self.auth_failures.load(Ordering::Relaxed),
            "last_request": *self.last_request.lock().unwrap(),
            "completed": self.completed.load(Ordering::Relaxed),
            "errors": self.errors.load(Ordering::Relaxed),
            "read_bytes": self.read_bytes.load(Ordering::Relaxed),
            "written_bytes": self.written_bytes.load(Ordering::Relaxed),
            "trend": self.trend.lock().unwrap().iter().filter(|bucket| bucket["minute"].as_i64().unwrap_or(0) >= chrono::Utc::now().timestamp()/60 - 14).cloned().collect::<Vec<_>>(),
        })
    }
}

// ---------- 状态 ----------

struct Inner {
    paths: BridgePaths,
    token: RwLock<String>,
    config: RwLock<BridgeConfig>,
    token_update: RwLock<()>,
    audit: Audit,
    options: ApiOptions,
    rate: Mutex<HashMap<String, (Instant, u64)>>,
    stats: Stats,
    file_stats: Stats,
    file_jobs: Arc<Semaphore>,
    control_jobs: Arc<Semaphore>,
    access: std::sync::OnceLock<Arc<AccessRuntime>>,
    exec: std::sync::OnceLock<Arc<ExecRuntime>>,
    device_names: std::sync::OnceLock<std::sync::Weak<crate::service::ServiceController>>,
}

#[derive(Clone)]
pub struct ApiState {
    inner: Arc<Inner>,
    agent: bool,
}

impl ApiState {
    /// 生产构造：沿用 ~/.muse-bridge 现有配置与令牌。
    pub fn from_bridge_home() -> std::io::Result<(Self, broadcast::Receiver<String>)> {
        let cfg = BridgeConfig::load()?;
        let tok = token::load(&super::config::token_path())?;
        let (audit, rx) = Audit::new(super::config::audit_path(), 10 * 1024 * 1024, 3);
        audit.protect_secret(&tok);
        Ok((
            Self {
                agent: false,
                inner: Arc::new(Inner {
                    paths: BridgePaths::default(),
                    token: RwLock::new(tok),
                    config: RwLock::new(cfg),
                    token_update: RwLock::new(()),
                    audit,
                    options: ApiOptions::default(),
                    rate: Mutex::new(HashMap::new()),
                    stats: Stats::default(),
                    file_stats: Stats::default(),
                    file_jobs: Arc::new(Semaphore::new(4)),
                    control_jobs: Arc::new(Semaphore::new(4)),
                    access: std::sync::OnceLock::new(),
                    exec: std::sync::OnceLock::new(),
                    device_names: std::sync::OnceLock::new(),
                }),
            },
            rx,
        ))
    }

    /// 测试构造：指定配置、令牌与全部路径。
    pub fn new(
        cfg: BridgeConfig,
        tok: String,
        paths: BridgePaths,
        options: ApiOptions,
    ) -> (Self, broadcast::Receiver<String>) {
        let (audit, rx) = Audit::new(paths.audit.clone(), 10 * 1024 * 1024, 3);
        audit.protect_secret(&tok);
        (
            Self {
                agent: false,
                inner: Arc::new(Inner {
                    paths,
                    token: RwLock::new(tok),
                    config: RwLock::new(cfg),
                    token_update: RwLock::new(()),
                    audit,
                    options,
                    rate: Mutex::new(HashMap::new()),
                    stats: Stats::default(),
                    file_stats: Stats::default(),
                    file_jobs: Arc::new(Semaphore::new(4)),
                    control_jobs: Arc::new(Semaphore::new(4)),
                    access: std::sync::OnceLock::new(),
                    exec: std::sync::OnceLock::new(),
                    device_names: std::sync::OnceLock::new(),
                }),
            },
            rx,
        )
    }

    pub fn token(&self) -> String {
        self.inner.token.read().unwrap().clone()
    }
    pub(crate) fn set_token(&self, t: String) {
        let _guard = self.inner.token_update.write().unwrap();
        *self.inner.token.write().unwrap() = t;
    }
    pub fn read_only(&self) -> bool {
        self.inner.config.read().unwrap().read_only
    }
    pub fn set_read_only(&self, v: bool) {
        self.inner.config.write().unwrap().read_only = v;
    }
    pub fn roots(&self) -> BTreeMap<String, PathBuf> {
        self.inner.config.read().unwrap().roots.clone()
    }
    pub fn stats(&self) -> &Stats {
        &self.inner.stats
    }
    pub fn stats_snapshot(&self) -> Value {
        let mut value = self.stats().snapshot();
        value["file_activity"] = self.inner.file_stats.snapshot();
        value
    }
    pub fn config_snapshot(&self) -> BridgeConfig {
        self.inner.config.read().unwrap().clone()
    }
    pub(crate) fn attach_access(&self, access: Arc<AccessRuntime>) {
        let _ = self.inner.access.set(access);
    }
    pub(crate) fn attach_exec(&self, exec: Arc<ExecRuntime>) {
        let _ = self.inner.exec.set(exec);
    }
    pub(crate) fn attach_device_names(
        &self,
        controller: std::sync::Weak<crate::service::ServiceController>,
    ) {
        let _ = self.inner.device_names.set(controller);
    }
    fn as_agent(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            agent: true,
        }
    }
    fn check_auth(&self, header: Option<&str>) -> bool {
        if self.agent {
            self.inner
                .access
                .get()
                .is_some_and(|access| access.agent_auth(header))
        } else {
            token::check_auth_header(header, &self.token())
        }
    }
    pub(crate) fn file_view(&self) -> BridgeConfig {
        let config = self.config_snapshot();
        match self.inner.access.get() {
            Some(access) => access.legacy_view(config),
            None => config,
        }
    }
    fn access_guard(&self) -> Option<std::sync::RwLockReadGuard<'_, ()>> {
        self.inner
            .access
            .get()
            .map(|access| access.legacy_requests.read().unwrap())
    }
    fn legacy_mutation_guard(&self) -> Option<std::sync::RwLockReadGuard<'_, ()>> {
        (!self.agent).then(|| self.inner.token_update.read().unwrap())
    }
    fn permits_target(&self, target: &Path, writing: bool) -> bool {
        self.inner
            .access
            .get()
            .is_none_or(|access| access.permits_legacy(target, writing))
    }
    fn resolve_file_target(
        &self,
        roots: &BTreeMap<String, PathBuf>,
        alias: &str,
        relative: &str,
    ) -> Result<path_guard::Resolved, &'static str> {
        let mut path = path_guard::resolve(roots, alias, relative)?;
        if let Some(access) = self.inner.access.get()
            && let Some(root) = roots.get(alias)
            && access.verify_legacy_path(root, relative)?
        {
            path.reject_reparse = true;
        }
        Ok(path)
    }
    fn mark_index_dirty(&self) {
        if let Some(access) = self.inner.access.get() {
            access.changed_files();
        }
    }
    pub fn paths(&self) -> &BridgePaths {
        &self.inner.paths
    }

    pub fn audit(&self) -> &Audit {
        &self.inner.audit
    }
    pub fn update_config(&self, cfg: BridgeConfig) -> Result<(), String> {
        if cfg.roots.is_empty() {
            return Err("至少保留一个开放目录".into());
        }
        cfg.ensure_roots().map_err(|e| e.to_string())?;
        cfg.save_to(&self.inner.paths.config)
            .map_err(|_| "保存文件配置失败，原配置已保留".to_string())?;
        *self.inner.config.write().unwrap() = cfg;
        Ok(())
    }
    pub fn rotate_token(&self) -> Result<(), String> {
        self.rotate_token_if(|_| true).map(|_| ())
    }
    fn rotate_token_if(&self, authorized: impl FnOnce(&str) -> bool) -> Result<bool, String> {
        // Complete admitted legacy writes before publishing a new credential.
        let _guard = self
            .inner
            .token_update
            .write()
            .map_err(|_| "令牌更新锁不可用".to_string())?;
        if !authorized(&self.inner.token.read().unwrap()) {
            return Ok(false);
        }
        let new_token = token::generate();
        token::save(&self.inner.paths.token, &new_token)
            .map_err(|_| "保存令牌失败，原令牌仍有效".to_string())?;
        self.inner.audit.protect_secret(&new_token);
        *self.inner.token.write().unwrap() = new_token;
        Ok(true)
    }
    fn options(&self) -> &ApiOptions {
        &self.inner.options
    }

    fn hit(&self, authed: bool) {
        self.inner.stats.hit(authed, true);
    }
}

// ---------- 鉴权与限流 ----------

enum Gate {
    Ok,
    Unauth,
    RateLimited,
}

fn gate(state: &ApiState, parts: &axum::http::request::Parts) -> Gate {
    if state.check_auth(auth_header(parts)) {
        return Gate::Ok;
    }
    // 修复缺陷3：只有未鉴权请求才消耗限流配额
    if !allow_unauth(state, &client_of(parts)) {
        Gate::RateLimited
    } else {
        Gate::Unauth
    }
}

fn auth_header(parts: &axum::http::request::Parts) -> Option<&str> {
    parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
}

fn allow_unauth(state: &ApiState, ip: &str) -> bool {
    let mut map = state.inner.rate.lock().unwrap();
    let now = Instant::now();
    let opts = state.options();
    let (start, count) = map.get(ip).copied().unwrap_or((now, 0));
    let (start, count) = if now.duration_since(start).as_secs() >= opts.rate_window_secs {
        (now, 0)
    } else {
        (start, count)
    };
    let count = count + 1;
    map.insert(ip.to_string(), (start, count));
    count <= opts.rate_limit
}

fn client_of(parts: &axum::http::request::Parts) -> String {
    parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip().to_string())
        .unwrap_or_else(|| "127.0.0.1".to_string())
}

// ---------- 查询串解析（对齐 parse_qs 的取值行为：百分号解码、首个取值生效） ----------

fn query_map(q: Option<&str>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Some(q) = q else { return map };
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        if v.is_empty() {
            continue;
        }
        map.entry(percent_decode(k))
            .or_insert_with(|| percent_decode(v));
    }
    map
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hi = (b[i + 1] as char).to_digit(16);
            let lo = (b[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(if b[i] == b'+' { b' ' } else { b[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------- 响应与审计 ----------

async fn blocking_response(
    slots: Arc<Semaphore>,
    job: impl FnOnce() -> Response + Send + 'static,
) -> Response {
    let Ok(slot) = slots.acquire_owned().await else {
        return json_resp(500, &json!({"error":"file service unavailable"}));
    };
    tokio::task::spawn_blocking(move || {
        let _slot = slot;
        job()
    })
    .await
    .unwrap_or_else(|_| json_resp(500, &json!({"error":"file service unavailable"})))
}

#[allow(clippy::too_many_arguments)]
fn respond(
    state: &ApiState,
    parts: &axum::http::request::Parts,
    code: u16,
    body: impl Serialize,
    authed: bool,
    root: Option<&str>,
    path: Option<&str>,
    bytes: Option<u64>,
) -> Response {
    respond_with_search(state, parts, code, body, authed, root, path, bytes, None)
}

#[allow(clippy::too_many_arguments)]
fn respond_with_search(
    state: &ApiState,
    parts: &axum::http::request::Parts,
    code: u16,
    body: impl Serialize,
    authed: bool,
    root: Option<&str>,
    path: Option<&str>,
    bytes: Option<u64>,
    search: Option<(&'static str, u64)>,
) -> Response {
    let endpoint = parts
        .extensions
        .get::<OriginalUri>()
        .map_or(parts.uri.path(), |original| original.0.path());
    state.stats().complete(endpoint, code, bytes);
    if matches!(
        endpoint,
        "/api/list"
            | "/api/read"
            | "/api/write"
            | "/api/mkdir"
            | "/agent/v1/list"
            | "/agent/v1/read"
            | "/agent/v1/write"
            | "/agent/v1/mkdir"
            | "/agent/v1/search"
            | "/agent/v1/locations/desktop"
    ) {
        // Keep all requests in the audit and diagnostics. File activity has a
        // separate counter and only authenticated attempts update its time.
        state.inner.file_stats.hit(authed, authed);
        state.inner.file_stats.complete(endpoint, code, bytes);
    }
    state.audit().record(&AuditEntry {
        ts: now_iso(),
        client: client_of(parts),
        method: parts.method.as_str().to_string(),
        endpoint: Some(endpoint.to_string()),
        authed,
        root: root.map(|s| s.to_string()),
        path: path.map(|s| s.to_string()),
        code,
        bytes,
        search_backend: search.map(|(backend, _)| backend),
        search_ms: search.map(|(_, elapsed)| elapsed),
    });
    let mut response = json_resp(code, &body);
    if state.agent {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );
    }
    response
}

pub fn json_resp(code: u16, body: &impl Serialize) -> Response {
    let body = serde_json::to_string(body).unwrap_or_default();
    Response::builder()
        .status(StatusCode::from_u16(code).unwrap())
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .body(Body::from(body))
        .unwrap()
}

// ---------- 路由 ----------

pub fn router(state: ApiState) -> Router {
    let agent = Router::new()
        .route("/roots", get(agent_roots))
        .route("/locations/desktop", get(agent_desktop))
        .route("/search", post(agent_search))
        .route("/list", get(list))
        .route("/read", get(read))
        .route("/write", post(write_ep))
        .route("/mkdir", post(mkdir_ep))
        .route("/exec", post(agent_exec_submit))
        .route("/exec/{job_id}", get(agent_exec_status))
        .route("/exec/{job_id}/cancel", post(agent_exec_cancel))
        .route("/device-name/confirm", post(confirm_device_name))
        .fallback(not_found)
        .method_not_allowed_fallback(not_found)
        .with_state(state.as_agent());
    Router::new()
        .route("/api/health", get(health))
        .route("/api/list", get(list))
        .route("/api/read", get(read))
        .route("/api/write", post(write_ep))
        .route("/api/mkdir", post(mkdir_ep))
        .route("/api/rotate-token", post(rotate_token_ep))
        .fallback(not_found)
        .method_not_allowed_fallback(not_found)
        .with_state(state)
        .nest("/agent/v1", agent)
}

/// 在 127.0.0.1 上启动服务（与 Python 版一致的绑定面）。
pub async fn serve(
    state: ApiState,
    port: u16,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
    serve_listener(state, listener, shutdown).await
}

pub async fn serve_listener(
    state: ApiState,
    listener: tokio::net::TcpListener,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<()> {
    let app = router(state).into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let mut rx = shutdown;
            let _ = rx.changed().await;
        })
        .await
}

// ---------- GET ----------

async fn health(State(s): State<ApiState>, req: Request) -> Response {
    let (parts, _) = req.into_parts();
    // Reserve slots for health and inexpensive responses when the disk is busy.
    blocking_response(s.inner.control_jobs.clone(), move || health_sync(s, parts)).await
}

fn health_sync(s: ApiState, parts: axum::http::request::Parts) -> Response {
    match gate(&s, &parts) {
        Gate::Ok => {
            s.hit(true);
            let _guard = s.access_guard();
            let file = s.file_view();
            let roots: Vec<String> = file.roots.keys().cloned().collect();
            respond(
                &s,
                &parts,
                200,
                json!({"ok": true, "version": VERSION, "roots": roots, "read_only": file.read_only}),
                true,
                None,
                None,
                None,
            )
        }
        Gate::Unauth => {
            s.hit(false);
            respond(
                &s,
                &parts,
                401,
                json!({"error": "unauthorized"}),
                false,
                None,
                None,
                None,
            )
        }
        Gate::RateLimited => {
            s.hit(false);
            respond(
                &s,
                &parts,
                429,
                json!({"error": "rate limit exceeded"}),
                false,
                None,
                None,
                None,
            )
        }
    }
}

async fn list(State(s): State<ApiState>, req: Request) -> Response {
    let (parts, _) = req.into_parts();
    blocking_response(s.inner.file_jobs.clone(), move || list_sync(s, parts)).await
}

async fn agent_roots(State(state): State<ApiState>, request: Request) -> Response {
    agent_metadata(state, request, |access| {
        let aliases = |operation| {
            access
                .agent_roots(operation)
                .unwrap_or_default()
                .into_keys()
                .collect::<Vec<_>>()
        };
        Some(json!({
            "version": "1",
            "roots": {
                "search": aliases(Operation::Search),
                "read": aliases(Operation::Read),
                "write": aliases(Operation::Write),
            },
        }))
    })
    .await
}

async fn agent_desktop(State(state): State<ApiState>, request: Request) -> Response {
    agent_metadata(state, request, |access| {
        access.agent_desktop().map(|location| json!(location))
    })
    .await
}

async fn agent_metadata(
    state: ApiState,
    request: Request,
    data: impl FnOnce(&AccessRuntime) -> Option<Value> + Send + 'static,
) -> Response {
    let (parts, _) = request.into_parts();
    blocking_response(state.inner.control_jobs.clone(), move || {
        let _guard = state.access_guard();
        if let Some(response) = get_auth_failure(&state, &parts) {
            return response;
        }
        match state.inner.access.get().and_then(|access| data(access)) {
            Some(body) => respond(&state, &parts, 200, body, true, None, None, None),
            None => access_denied(&state, &parts),
        }
    })
    .await
}

fn get_auth_failure(state: &ApiState, parts: &axum::http::request::Parts) -> Option<Response> {
    let (code, message) = match gate(state, parts) {
        Gate::Ok => {
            state.hit(true);
            return None;
        }
        Gate::Unauth => (401, "unauthorized"),
        Gate::RateLimited => (429, "rate limit exceeded"),
    };
    state.hit(false);
    Some(respond(
        state,
        parts,
        code,
        json!({"error": message}),
        false,
        None,
        None,
        None,
    ))
}

#[derive(Serialize)]
struct DirectoryEntry {
    mtime: f64,
    name: String,
    size: u64,
    #[serde(rename = "type")]
    kind: &'static str,
}

#[derive(Serialize)]
struct DirectoryList {
    entries: Vec<DirectoryEntry>,
    truncated: bool,
}

fn list_sync(s: ApiState, parts: axum::http::request::Parts) -> Response {
    let _guard = s.access_guard();
    if let Some(response) = get_auth_failure(&s, &parts) {
        return response;
    }

    let q = query_map(parts.uri.query());
    let root_name = q.get("root").cloned().unwrap_or_default();
    let rel = q.get("path").cloned().unwrap_or_default();

    let resolved = match resolve_file_request(&s, &parts, &root_name, &rel, Operation::Read) {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };

    let mut entries = Vec::new();
    let listed = handle::list(&resolved, |entry| {
        let path = resolved.path.join(&entry.name);
        if s.agent {
            if entry.is_reparse
                || s.inner
                    .access
                    .get()
                    .is_none_or(|access| access.is_protected_path(&path))
            {
                return;
            }
        } else if !s.permits_target(&path, false) {
            return;
        }
        let name = entry.name.to_string_lossy().into_owned();
        entries.push((
            (!entry.is_directory, name.to_lowercase(), entries.len()),
            DirectoryEntry {
                name,
                mtime: entry.mtime,
                size: entry.size,
                kind: if entry.is_directory { "dir" } else { "file" },
            },
        ));
    });
    if let Err(error) = listed {
        return file_error(&s, &parts, &root_name, &rel, error, Some("not a directory"));
    }

    // The enumeration index preserves the previous stable order for equal keys.
    let list_max = s.options().list_max;
    let truncated = entries.len() > list_max;
    if truncated {
        entries.select_nth_unstable_by(list_max, |a, b| a.0.cmp(&b.0));
        entries.truncate(list_max);
    }
    entries.sort_unstable_by(|a, b| a.0.cmp(&b.0));
    let entries = entries.into_iter().map(|(_, entry)| entry).collect();
    respond(
        &s,
        &parts,
        200,
        DirectoryList { entries, truncated },
        true,
        Some(&root_name),
        Some(&rel),
        None,
    )
}

async fn read(State(s): State<ApiState>, req: Request) -> Response {
    let (parts, _) = req.into_parts();
    blocking_response(s.inner.file_jobs.clone(), move || read_sync(s, parts)).await
}

fn read_sync(s: ApiState, parts: axum::http::request::Parts) -> Response {
    let _guard = s.access_guard();
    if let Some(response) = get_auth_failure(&s, &parts) {
        return response;
    }
    let q = query_map(parts.uri.query());
    let root_name = q.get("root").cloned().unwrap_or_default();
    let rel = q.get("path").cloned().unwrap_or_default();

    let resolved = match resolve_file_request(&s, &parts, &root_name, &rel, Operation::Read) {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };

    let file = match handle::read(&resolved) {
        Ok(file) => file,
        Err(error) => return file_error(&s, &parts, &root_name, &rel, error, Some("not a file")),
    };
    let size = match file.metadata() {
        Ok(metadata) => metadata.len(),
        Err(error) => {
            return respond(
                &s,
                &parts,
                500,
                json!({"error": error.to_string()}),
                true,
                Some(&root_name),
                Some(&rel),
                None,
            );
        }
    };
    if size > s.options().max_read {
        let msg = format!("file too large ({size} bytes)");
        return respond(
            &s,
            &parts,
            413,
            json!({"error": msg}),
            true,
            Some(&root_name),
            Some(&rel),
            None,
        );
    }
    let data = match (|| -> std::io::Result<Vec<u8>> {
        use std::io::Read;
        let mut data = Vec::new();
        file.take(s.options().max_read.saturating_add(1))
            .read_to_end(&mut data)?;
        Ok(data)
    })() {
        Ok(d) => d,
        Err(e) => {
            return respond(
                &s,
                &parts,
                500,
                json!({"error": e.to_string()}),
                true,
                Some(&root_name),
                Some(&rel),
                None,
            );
        }
    };
    let n = data.len() as u64;
    if n > s.options().max_read {
        return respond(
            &s,
            &parts,
            413,
            json!({"error":"file too large"}),
            true,
            Some(&root_name),
            Some(&rel),
            None,
        );
    }
    let body = match String::from_utf8(data) {
        Ok(text) => json!({"encoding": "text", "content": text}),
        Err(e) => json!({"encoding": "base64", "content": B64.encode(e.into_bytes())}),
    };
    respond(
        &s,
        &parts,
        200,
        body,
        true,
        Some(&root_name),
        Some(&rel),
        Some(n),
    )
}

// ---------- POST ----------

async fn post_failure(
    state: &ApiState,
    parts: &axum::http::request::Parts,
    code: u16,
    message: &'static str,
    authed: bool,
) -> Response {
    let state = state.clone();
    let parts = parts.clone();
    blocking_response(state.inner.control_jobs.clone(), move || {
        respond(
            &state,
            &parts,
            code,
            json!({"error": message}),
            authed,
            None,
            None,
            None,
        )
    })
    .await
}

/// 不携带内容的 POST 前置：鉴权（仅失败时计入限流）→ 元数据体积检查 → JSON 解析。
async fn post_gate(
    s: &ApiState,
    parts: &axum::http::request::Parts,
    body: Body,
) -> Result<Value, Response> {
    post_gate_limited(s, parts, body, MAX_METADATA_REQUEST_BYTES).await
}

/// 写入路由的请求体上限：按解码后的上限反推 Base64 长度，再留出 JSON 元数据余量。
/// Base64 把 3 字节编码成 4 字节，所以 10 MiB 内容在请求体里约占 13.3 MiB。
fn encoded_write_limit(max_write: u64) -> usize {
    let encoded = max_write.saturating_add(2) / 3;
    usize::try_from(encoded.saturating_mul(4))
        .unwrap_or(usize::MAX)
        .saturating_add(MAX_METADATA_REQUEST_BYTES)
}

/// 写入专用前置：体积检查放行编码后的满额内容，解码后的 10 MiB 上限仍单独校验。
async fn write_gate(
    s: &ApiState,
    parts: &axum::http::request::Parts,
    body: Body,
) -> Result<Value, Response> {
    post_gate_limited(s, parts, body, encoded_write_limit(s.options().max_write)).await
}

async fn post_gate_limited(
    s: &ApiState,
    parts: &axum::http::request::Parts,
    body: Body,
    limit: usize,
) -> Result<Value, Response> {
    match gate(s, parts) {
        Gate::Ok => {}
        Gate::Unauth => {
            s.hit(false);
            return Err(post_failure(s, parts, 401, "unauthorized", false).await);
        }
        Gate::RateLimited => {
            s.hit(false);
            return Err(post_failure(s, parts, 429, "rate limit exceeded", false).await);
        }
    }
    s.hit(true);

    let bytes = match to_bytes(body, limit).await {
        Ok(b) => b,
        Err(_) => {
            return Err(post_failure(s, parts, 413, "payload too large", true).await);
        }
    };
    let body: Value = if bytes.is_empty() {
        json!({})
    } else {
        match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => {
                return Err(post_failure(s, parts, 400, "invalid json", true).await);
            }
        }
    };
    Ok(body)
}

async fn agent_exec_submit(State(state): State<ApiState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let body = match post_gate_limited(&state, &parts, body, MAX_METADATA_REQUEST_BYTES).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let Ok(exec_req) = serde_json::from_value::<ExecRequest>(body) else {
        return post_failure(&state, &parts, 400, "invalid exec request", true).await;
    };
    let Some(access) = state.inner.access.get().cloned() else {
        return post_failure(&state, &parts, 403, "command execution unavailable", true).await;
    };
    let Some(exec) = state.inner.exec.get().cloned() else {
        return post_failure(&state, &parts, 403, "exec_disabled", true).await;
    };
    let client = client_of(&parts);
    blocking_response(state.inner.file_jobs.clone(), move || {
        let _guard = state.access_guard();
        if let Some(response) = reject_changed_credential(&state, &parts) {
            return response;
        }
        match exec.submit(exec_req, &access, &client) {
            Ok((code, view)) => {
                let mut response = json_resp(code, &view);
                response.headers_mut().insert(
                    header::CACHE_CONTROL,
                    header::HeaderValue::from_static("no-store"),
                );
                response
            }
            Err(ExecSubmitError::Disabled) => respond(
                &state,
                &parts,
                403,
                json!({"error": "exec_disabled", "message": "command execution is disabled"}),
                true,
                None,
                None,
                None,
            ),
            Err(ExecSubmitError::Forbidden(message)) => respond(
                &state,
                &parts,
                403,
                json!({"error": message}),
                true,
                None,
                None,
                None,
            ),
            Err(ExecSubmitError::Invalid(message)) => respond(
                &state,
                &parts,
                400,
                json!({"error": message}),
                true,
                None,
                None,
                None,
            ),
            Err(ExecSubmitError::Busy) => respond(
                &state,
                &parts,
                429,
                json!({"error": "too many commands running; retry shortly"}),
                true,
                None,
                None,
                None,
            ),
        }
    })
    .await
}

fn exec_no_store_response(code: u16, view: &impl Serialize) -> Response {
    let mut response = json_resp(code, view);
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
}

async fn agent_exec_status(
    State(state): State<ApiState>,
    AxumPath(job_id): AxumPath<String>,
    request: Request,
) -> Response {
    let (parts, _) = request.into_parts();
    let wait_ms = query_map(parts.uri.query())
        .get("wait_ms")
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
        .min(MAX_STATUS_WAIT_MS);

    let Ok(slot) = state.inner.control_jobs.clone().acquire_owned().await else {
        return json_resp(500, &json!({"error": "file service unavailable"}));
    };
    let init_state = state.clone();
    let init_parts = parts.clone();
    let init_job_id = job_id.clone();
    let initial = tokio::task::spawn_blocking(move || {
        let _slot = slot;
        let _guard = init_state.access_guard();
        if let Some(response) = get_auth_failure(&init_state, &init_parts) {
            return Err(response);
        }
        let Some(exec) = init_state.inner.exec.get().cloned() else {
            return Err(respond(
                &init_state,
                &init_parts,
                403,
                json!({"error": "exec_disabled", "message": "command execution is disabled"}),
                true,
                None,
                None,
                None,
            ));
        };
        match exec.subscribe_job(&init_job_id) {
            Some((view, rx, approval_expires)) => Ok((exec, view, rx, approval_expires)),
            None => Err(respond(
                &init_state,
                &init_parts,
                404,
                json!({"error": "job not found"}),
                true,
                None,
                None,
                None,
            )),
        }
    })
    .await
    .unwrap_or_else(|_| {
        Err(json_resp(
            500,
            &json!({"error": "file service unavailable"}),
        ))
    });

    let (exec, mut current_view, mut rx, mut current_expires) = match initial {
        Ok(sub) => sub,
        Err(response) => return response,
    };

    if wait_ms == 0 || current_view.status.is_terminal() {
        return exec_no_store_response(200, &current_view);
    }

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_millis(wait_ms);
    loop {
        let now_tokio = tokio::time::Instant::now();
        if now_tokio >= deadline {
            break;
        }
        let step_deadline = if current_view.status == ExecJobStatus::AwaitingApproval {
            if let Some(exp) = current_expires {
                let remaining = exp.saturating_duration_since(Instant::now());
                deadline.min(now_tokio + remaining + std::time::Duration::from_millis(15))
            } else {
                deadline
            }
        } else {
            deadline
        };

        let waited = tokio::time::timeout_at(step_deadline, rx.changed()).await;

        if !state.check_auth(auth_header(&parts)) {
            let state = state.clone();
            return blocking_response(state.inner.control_jobs.clone(), move || {
                unauthorized_response(&state, &parts)
            })
            .await;
        }

        let Some((next_view, next_expires)) = exec.get_job_with_expiry(&job_id) else {
            let state = state.clone();
            return blocking_response(state.inner.control_jobs.clone(), move || {
                respond(
                    &state,
                    &parts,
                    404,
                    json!({"error": "job not found"}),
                    true,
                    None,
                    None,
                    None,
                )
            })
            .await;
        };
        current_view = next_view;
        current_expires = next_expires;

        if current_view.status.is_terminal() {
            break;
        }
        match waited {
            Ok(Ok(())) => continue,
            Ok(Err(_)) | Err(_) => break,
        }
    }

    exec_no_store_response(200, &current_view)
}

async fn agent_exec_cancel(
    State(state): State<ApiState>,
    AxumPath(job_id): AxumPath<String>,
    request: Request,
) -> Response {
    let (parts, body) = request.into_parts();
    if let Err(response) = post_gate_limited(&state, &parts, body, 512).await {
        return response;
    }
    blocking_response(state.inner.control_jobs.clone(), move || {
        let _guard = state.access_guard();
        if let Some(response) = reject_changed_credential(&state, &parts) {
            return response;
        }
        let Some(exec) = state.inner.exec.get() else {
            return respond(
                &state,
                &parts,
                403,
                json!({"error": "exec_disabled", "message": "command execution is disabled"}),
                true,
                None,
                None,
                None,
            );
        };
        match exec.cancel_job(&job_id) {
            Some(view) => respond(&state, &parts, 200, view, true, None, Some(&job_id), None),
            None => respond(
                &state,
                &parts,
                404,
                json!({"error": "job not found"}),
                true,
                None,
                Some(&job_id),
                None,
            ),
        }
    })
    .await
}

async fn confirm_device_name(State(state): State<ApiState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let body = match post_gate_limited(&state, &parts, body, 512).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let Some(id) = body
        .get("update_id")
        .and_then(Value::as_str)
        .filter(|id| id.len() == 43)
    else {
        return post_failure(&state, &parts, 400, "invalid device name update ID", true).await;
    };
    let id = id.to_owned();
    blocking_response(state.inner.control_jobs.clone(), move || {
        let _guard = state.access_guard();
        if let Some(response) = reject_changed_credential(&state, &parts) {
            return response;
        }
        let result = state
            .inner
            .device_names
            .get()
            .and_then(|controller| controller.upgrade())
            .map(|controller| controller.confirm_device_name(&id));
        let (code, body) = match result {
            Some(Ok(true)) => (200, json!({"confirmed": true})),
            Some(Ok(false)) => (409, json!({"error": "device_name_update_not_current"})),
            Some(Err(_)) | None => (
                503,
                json!({"error": "device_name_confirmation_unavailable"}),
            ),
        };
        respond(&state, &parts, code, body, true, None, None, None)
    })
    .await
}

async fn agent_search(State(state): State<ApiState>, request: Request) -> Response {
    let started = std::time::Instant::now();
    let (parts, body) = request.into_parts();
    let body = match post_gate_limited(&state, &parts, body, MAX_SEARCH_REQUEST_BYTES).await {
        Ok(body) => body,
        Err(response) => return response,
    };
    let Ok(request) = serde_json::from_value::<SearchRequest>(body) else {
        return post_failure(&state, &parts, 400, "invalid search request", true).await;
    };
    let Some(access) = state.inner.access.get().cloned() else {
        return post_failure(&state, &parts, 401, "unauthorized", false).await;
    };
    let generation = access.agent_search_generation();
    let result = access
        .clone()
        .search_agent(auth_header(&parts).unwrap_or_default(), request)
        .await;
    blocking_response(state.inner.control_jobs.clone(), move || {
        let _guard = state.access_guard();
        if let Some(response) = reject_changed_credential(&state, &parts) {
            return response;
        }
        if generation.load(Ordering::Acquire) {
            return respond(
                &state,
                &parts,
                409,
                json!({"error": "file access changed; retry search"}),
                true,
                None,
                None,
                None,
            );
        }
        let (code, message, authed) = match result {
            Ok(body) => {
                let search = Some((
                    body.backend,
                    started.elapsed().as_millis().min(u64::MAX as u128) as u64,
                ));
                return respond_with_search(
                    &state, &parts, 200, body, true, None, None, None, search,
                );
            }
            Err(AgentSearchError::Unauthorized) => (401, "unauthorized", false),
            Err(AgentSearchError::Forbidden) => (403, "file access denied", true),
            Err(AgentSearchError::Search(SearchError::Invalid)) => {
                (400, "invalid search request", true)
            }
            Err(AgentSearchError::Search(SearchError::Busy)) => {
                (429, "another search is running; retry shortly", true)
            }
            Err(AgentSearchError::Search(SearchError::CursorExpired)) => {
                (409, "search cursor expired; restart search", true)
            }
            Err(AgentSearchError::Search(SearchError::Cancelled)) => {
                (409, "file access changed; retry search", true)
            }
            Err(AgentSearchError::Search(SearchError::IndexCleared)) => {
                (409, "search_index_cleared", true)
            }
            Err(AgentSearchError::WorkerFailed) => (500, "file search unavailable", true),
        };
        respond(
            &state,
            &parts,
            code,
            json!({"error": message}),
            authed,
            None,
            None,
            None,
        )
    })
    .await
}

fn reject_changed_credential(
    state: &ApiState,
    parts: &axum::http::request::Parts,
) -> Option<Response> {
    (!state.check_auth(auth_header(parts))).then(|| unauthorized_response(state, parts))
}

fn unauthorized_response(state: &ApiState, parts: &axum::http::request::Parts) -> Response {
    respond(
        state,
        parts,
        401,
        json!({"error": "unauthorized"}),
        false,
        None,
        None,
        None,
    )
}

/// 只读拦截（对齐 Python：在路径解析之前，审计不记 root/path）。
fn access_denied(state: &ApiState, parts: &axum::http::request::Parts) -> Response {
    respond(
        state,
        parts,
        403,
        json!({"error": "file access denied"}),
        true,
        None,
        None,
        None,
    )
}

fn reject_read_only(
    state: &ApiState,
    parts: &axum::http::request::Parts,
    read_only: bool,
) -> Option<Response> {
    if read_only {
        Some(respond(
            state,
            parts,
            403,
            json!({"error": "read-only mode (set read_only=false in config.json)"}),
            true,
            None,
            None,
            None,
        ))
    } else {
        None
    }
}

fn resolve_file_request(
    state: &ApiState,
    parts: &axum::http::request::Parts,
    root: &str,
    relative: &str,
    operation: Operation,
) -> Result<path_guard::Resolved, Response> {
    let path = if state.agent {
        let result = state
            .inner
            .access
            .get()
            .ok_or(ERR_NOT_AUTHORIZED)
            .and_then(|access| access.resolve_agent_file(operation, root, relative));
        match result {
            Err(
                ERR_NOT_AUTHORIZED | ERR_PROTECTED | ERR_REPARSE | path_guard::ERR_UNKNOWN_ROOT,
            ) => {
                return Err(access_denied(state, parts));
            }
            result => result,
        }
    } else {
        let file = state.file_view();
        let writing = operation == Operation::Write;
        if writing && let Some(response) = reject_read_only(state, parts, file.read_only) {
            return Err(response);
        }
        let result = state.resolve_file_target(&file.roots, root, relative);
        if result
            .as_ref()
            .is_ok_and(|path| !state.permits_target(&path.path, writing))
        {
            return Err(access_denied(state, parts));
        }
        result
    };
    path.map_err(|error| {
        respond(
            state,
            parts,
            400,
            json!({"error": error}),
            true,
            None,
            None,
            None,
        )
    })
}

fn file_error(
    state: &ApiState,
    parts: &axum::http::request::Parts,
    root: &str,
    relative: &str,
    error: handle::Error,
    read_error: Option<&str>,
) -> Response {
    let (status, message) = match error {
        handle::Error::Escape => return escape_response(state, parts, root, relative),
        handle::Error::Changed | handle::Error::Exists => {
            return changed_response(state, parts, root, relative);
        }
        handle::Error::Missing | handle::Error::NotDirectory | handle::Error::IsDirectory
            if read_error.is_some() =>
        {
            (404, read_error.unwrap().to_owned())
        }
        handle::Error::Missing => return changed_response(state, parts, root, relative),
        handle::Error::IsDirectory => (400, "target is a directory".to_owned()),
        handle::Error::NotDirectory => (400, "not a directory".to_owned()),
        handle::Error::Io(error) => (500, error.to_string()),
    };
    respond(
        state,
        parts,
        status,
        json!({"error": message}),
        true,
        Some(root),
        Some(relative),
        None,
    )
}

/// 打开后的对象落在授权根外：与解析阶段的拒绝保持同一错误串。
fn escape_response(
    state: &ApiState,
    parts: &axum::http::request::Parts,
    root: &str,
    relative: &str,
) -> Response {
    respond(
        state,
        parts,
        400,
        json!({"error": "path escapes root"}),
        true,
        Some(root),
        Some(relative),
        None,
    )
}

/// 对象在操作期间被替换或改名：状态已不可信，调用方可以重试。
fn changed_response(
    state: &ApiState,
    parts: &axum::http::request::Parts,
    root: &str,
    relative: &str,
) -> Response {
    respond(
        state,
        parts,
        409,
        json!({"error": "path changed; retry"}),
        true,
        Some(root),
        Some(relative),
        None,
    )
}

async fn write_ep(State(s): State<ApiState>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let body_json = match write_gate(&s, &parts, body).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    blocking_response(s.inner.file_jobs.clone(), move || {
        write_sync(s, parts, body_json)
    })
    .await
}

fn write_sync(s: ApiState, parts: axum::http::request::Parts, body_json: Value) -> Response {
    let _guard = s.access_guard();
    let _legacy_credential = s.legacy_mutation_guard();
    if let Some(response) = reject_changed_credential(&s, &parts) {
        return response;
    }

    let root_name = body_json.get("root").and_then(|v| v.as_str()).unwrap_or("");
    let rel = body_json.get("path").and_then(|v| v.as_str()).unwrap_or("");

    let resolved = match resolve_file_request(&s, &parts, root_name, rel, Operation::Write) {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };

    let enc = body_json
        .get("encoding")
        .and_then(|v| v.as_str())
        .unwrap_or("text");
    if s.agent && !matches!(enc, "text" | "base64") {
        return respond(
            &s,
            &parts,
            400,
            json!({"error":"encoding must be text or base64"}),
            true,
            Some(root_name),
            Some(rel),
            None,
        );
    }
    let content = match body_json.get("content") {
        None if !s.agent => "",
        Some(Value::String(value)) => value,
        _ => {
            return respond(
                &s,
                &parts,
                400,
                json!({"error":"content must be a string"}),
                true,
                Some(root_name),
                Some(rel),
                None,
            );
        }
    };
    let data: Vec<u8> = if enc == "text" {
        content.as_bytes().to_vec()
    } else {
        // 对齐 Python：非 "text" 一律按 base64 解
        let encoded: Vec<u8> = content
            .bytes()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        match B64.decode(&encoded) {
            Ok(d) => d,
            Err(_) => {
                return respond(
                    &s,
                    &parts,
                    400,
                    json!({"error": "bad content encoding"}),
                    true,
                    Some(root_name),
                    Some(rel),
                    None,
                );
            }
        }
    };
    if data.len() as u64 > s.options().max_write {
        return respond(
            &s,
            &parts,
            413,
            json!({"error": "content too large"}),
            true,
            Some(root_name),
            Some(rel),
            None,
        );
    }
    if let Err(error) = handle::write(&resolved, &data) {
        return file_error(&s, &parts, root_name, rel, error, None);
    }
    s.mark_index_dirty();
    let written = data.len() as u64;
    respond(
        &s,
        &parts,
        200,
        json!({"ok": true, "bytes": written}),
        true,
        Some(root_name),
        Some(rel),
        Some(written),
    )
}

async fn mkdir_ep(State(s): State<ApiState>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let body_json = match post_gate(&s, &parts, body).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };
    blocking_response(s.inner.file_jobs.clone(), move || {
        mkdir_sync(s, parts, body_json)
    })
    .await
}

fn mkdir_sync(s: ApiState, parts: axum::http::request::Parts, body_json: Value) -> Response {
    let _guard = s.access_guard();
    let _legacy_credential = s.legacy_mutation_guard();
    if let Some(response) = reject_changed_credential(&s, &parts) {
        return response;
    }

    let root_name = body_json.get("root").and_then(|v| v.as_str()).unwrap_or("");
    let rel = body_json.get("path").and_then(|v| v.as_str()).unwrap_or("");

    let resolved = match resolve_file_request(&s, &parts, root_name, rel, Operation::Write) {
        Ok(resolved) => resolved,
        Err(response) => return response,
    };

    if let Err(error) = handle::mkdir(&resolved) {
        return file_error(&s, &parts, root_name, rel, error, None);
    }
    s.mark_index_dirty();
    respond(
        &s,
        &parts,
        200,
        json!({"ok": true}),
        true,
        Some(root_name),
        Some(rel),
        None,
    )
}

async fn rotate_token_ep(State(s): State<ApiState>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    if let Err(resp) = post_gate(&s, &parts, body).await {
        return resp;
    }
    blocking_response(s.inner.file_jobs.clone(), move || {
        rotate_token_sync(s, parts)
    })
    .await
}

fn rotate_token_sync(s: ApiState, parts: axum::http::request::Parts) -> Response {
    match s.rotate_token_if(|current| token::check_auth_header(auth_header(&parts), current)) {
        // The new credential stays in the local token file.
        Ok(true) => respond(&s, &parts, 200, json!({"ok": true}), true, None, None, None),
        Ok(false) => unauthorized_response(&s, &parts),
        Err(e) => respond(
            &s,
            &parts,
            500,
            json!({"error": e.to_string()}),
            true,
            None,
            None,
            None,
        ),
    }
}

async fn not_found(State(s): State<ApiState>, req: Request) -> Response {
    let (parts, _) = req.into_parts();
    blocking_response(s.inner.control_jobs.clone(), move || {
        not_found_sync(s, parts)
    })
    .await
}

fn not_found_sync(s: ApiState, parts: axum::http::request::Parts) -> Response {
    match gate(&s, &parts) {
        Gate::Ok => {
            s.hit(true);
            respond(
                &s,
                &parts,
                404,
                json!({"error": "not found"}),
                true,
                None,
                None,
                None,
            )
        }
        Gate::Unauth => {
            s.hit(false);
            respond(
                &s,
                &parts,
                401,
                json!({"error": "unauthorized"}),
                false,
                None,
                None,
                None,
            )
        }
        Gate::RateLimited => {
            s.hit(false);
            respond(
                &s,
                &parts,
                429,
                json!({"error": "rate limit exceeded"}),
                false,
                None,
                None,
                None,
            )
        }
    }
}

// ====================================================================
// 验收测试：攻击矩阵（以 11-17 对 Python 版的实测输出为基准）
// ====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;
    use tower::ServiceExt;

    static NONCE: AtomicU64 = AtomicU64::new(0);

    struct Env {
        dir: PathBuf,
        app: Router,
        state: ApiState,
        root: PathBuf,
        token: String,
        token_path: PathBuf,
    }

    impl Drop for Env {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn setup(read_only: bool, options: ApiOptions) -> Env {
        let n = NONCE.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "muse-test-{}-{n}-{}",
            std::process::id(),
            token::generate()
        ));
        let root = dir.join("root");
        std::fs::create_dir_all(&root).unwrap();
        let token_path = dir.join("token");
        let audit_path = dir.join("audit.log");
        let tok = format!("test-token-value-{n:04}");
        std::fs::write(&token_path, &tok).unwrap();
        let mut roots = BTreeMap::new();
        roots.insert("r".to_string(), root.clone());
        let cfg = BridgeConfig {
            port: 0,
            read_only,
            roots,
        };
        let paths = BridgePaths {
            config: dir.join("config.json"),
            token: token_path.clone(),
            audit: audit_path,
        };
        let (state, _rx) = ApiState::new(cfg, tok.clone(), paths, options);
        let app = router(state.clone());
        Env {
            dir,
            app,
            state,
            root,
            token: tok,
            token_path,
        }
    }

    async fn call(
        app: &Router,
        method: &str,
        uri: &str,
        auth: Option<&str>,
        body: &str,
    ) -> (u16, Value, Option<String>) {
        let mut b = Request::builder().method(method).uri(uri);
        if let Some(t) = auth {
            b = b.header("authorization", format!("Bearer {t}"));
        }
        let req = b.body(Body::from(body.to_string())).unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let status = resp.status().as_u16();
        let ctype = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let v: Value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        };
        (status, v, ctype)
    }

    fn default_opts() -> ApiOptions {
        ApiOptions {
            rate_limit: 1000,
            rate_window_secs: 60,
            max_read: MAX_READ_BYTES,
            max_write: MAX_WRITE_BYTES,
            list_max: LIST_MAX_ENTRIES,
        }
    }

    #[tokio::test]
    async fn agent_routes_use_independent_credentials_and_per_operation_roots() {
        use super::super::access::{AccessPolicy, GrantScope, ScopeMode};
        use crate::profile::{ProfileKind, RuntimeProfile};

        let e = setup(false, default_opts());
        let profile = RuntimeProfile {
            kind: ProfileKind::Development,
            home: e.root.parent().unwrap().join("agent"),
            onboarding_qa: false,
        };
        let fixture = profile.home.join("files");
        std::fs::create_dir_all(&fixture).unwrap();
        std::fs::write(fixture.join("sample.txt"), "example").unwrap();
        let (access, error) = AccessRuntime::open(&profile);
        assert!(error.is_none());
        e.state.attach_access(access.clone());
        let mut policy = AccessPolicy {
            mode: ScopeMode::Full,
            roots: [("fixture".into(), fixture.clone())].into(),
            search: GrantScope::AllLocal,
            read: GrantScope::Folders,
            ..Default::default()
        };
        access.validate(&policy).unwrap();
        access.save(policy.clone(), false).unwrap();

        let (code, _, _) = call(&e.app, "GET", "/agent/v1/roots", Some(&e.token), "").await;
        assert_eq!(code, 401);
        access
            .issue_agent_token(|key| e.state.audit().protect_secret(key))
            .unwrap();
        let agent_token = access.agent_token().unwrap();
        let auth = Some(agent_token.as_str());

        let (code, _, _) = call(&e.app, "GET", "/api/health", auth, "").await;
        assert_eq!(code, 401);
        let (code, roots, _) = call(&e.app, "GET", "/agent/v1/roots", auth, "").await;
        assert_eq!(code, 200);
        assert_eq!(
            roots["roots"],
            json!({"search":["test-disk"],"read":["fixture"],"write":[]})
        );
        let (code, desktop, _) = call(&e.app, "GET", "/agent/v1/locations/desktop", auth, "").await;
        assert_eq!(code, 200);
        assert_eq!(desktop["root"], "fixture");
        assert_eq!(desktop["path"], "");
        assert_eq!(desktop["absolute_path"], fixture.to_str().unwrap());
        let (code, search, _) = call(
            &e.app,
            "POST",
            "/agent/v1/search",
            auth,
            r#"{"name":"sample.txt"}"#,
        )
        .await;
        assert_eq!(code, 200);
        assert_eq!(search["hits"][0]["root"], "test-disk");
        assert_eq!(search["hits"][0]["path"], "sample.txt");
        access.clear_index().unwrap();
        let (code, search, _) = call(
            &e.app,
            "POST",
            "/agent/v1/search",
            auth,
            r#"{"name":"sample.txt"}"#,
        )
        .await;
        assert_eq!(code, 409);
        assert_eq!(search["error"], "search_index_cleared");
        let (code, _, _) = call(
            &e.app,
            "GET",
            "/agent/v1/read?root=test-disk&path=sample.txt",
            auth,
            "",
        )
        .await;
        assert_eq!(code, 403);
        let (code, file, _) = call(
            &e.app,
            "GET",
            "/agent/v1/read?root=fixture&path=sample.txt",
            auth,
            "",
        )
        .await;
        assert_eq!(code, 200);
        assert_eq!(file["content"], "example");
        let (code, _, _) = call(
            &e.app,
            "GET",
            "/agent/v1/read?root=fixture&path=../agent-token",
            auth,
            "",
        )
        .await;
        assert_eq!(code, 400);
        let write = r#"{"root":"test-disk","path":"sample.txt","content":"updated"}"#;
        let (code, _, _) = call(&e.app, "POST", "/agent/v1/write", auth, write).await;
        assert_eq!(code, 403);

        policy.read = GrantScope::Off;
        policy.write = GrantScope::AllLocal;
        access.save(policy, false).unwrap();
        let (code, _, _) = call(&e.app, "POST", "/agent/v1/write", auth, write).await;
        assert_eq!(code, 200);
        let (code, _, _) = call(
            &e.app,
            "POST",
            "/agent/v1/write",
            auth,
            r#"{"root":"test-disk","path":"sample.txt"}"#,
        )
        .await;
        assert_eq!(code, 400);
        assert_eq!(
            std::fs::read_to_string(fixture.join("sample.txt")).unwrap(),
            "updated"
        );
        let (code, _, _) = call(&e.app, "GET", "/agent/v1/list?root=test-disk", auth, "").await;
        assert_eq!(code, 403);
        let (code, _, _) = call(
            &e.app,
            "POST",
            "/agent/v1/mkdir",
            auth,
            r#"{"root":"test-disk","path":"new-dir"}"#,
        )
        .await;
        assert_eq!(code, 200);
        assert!(fixture.join("new-dir").is_dir());
        let (code, _, _) = call(&e.app, "POST", "/agent/v1/rotate-token", auth, "{}").await;
        assert_eq!(code, 404);
        let (code, _, _) = call(
            &e.app,
            "POST",
            "/agent/v1/rotate-token",
            Some(&e.token),
            "{}",
        )
        .await;
        assert_eq!(code, 401);

        access.revoke_agent_token().unwrap();
        let (code, _, _) = call(&e.app, "GET", "/agent/v1/roots", auth, "").await;
        assert_eq!(code, 401);
        let (code, _, _) = call(&e.app, "GET", "/api/health", Some(&e.token), "").await;
        assert_eq!(code, 200);
        let audit = std::fs::read_to_string(&e.state.paths().audit).unwrap();
        assert!(audit.contains(r#""endpoint":"/agent/v1/write""#));
        assert!(!audit.contains(&agent_token));
    }

    // ---- 鉴权与 health ----

    #[tokio::test]
    async fn health_flow() {
        let e = setup(false, default_opts());
        // 无令牌 → 401 {"error":"unauthorized"}（对齐 Python）
        let (c, v, ct) = call(&e.app, "GET", "/api/health", None, "").await;
        assert_eq!(c, 401);
        assert_eq!(v["error"], "unauthorized");
        assert_eq!(ct.as_deref(), Some("application/json; charset=utf-8"));
        // 带令牌 → 200 全字段
        let (c, v, _) = call(&e.app, "GET", "/api/health", Some(&e.token), "").await;
        assert_eq!(c, 200);
        assert_eq!(v["ok"], true);
        assert_eq!(v["version"], VERSION);
        assert_eq!(v["roots"], json!(["r"]));
        assert_eq!(v["read_only"], false);
    }

    #[tokio::test]
    async fn unknown_root_and_endpoint() {
        let e = setup(false, default_opts());
        let (c, v, _) = call(&e.app, "GET", "/api/list?root=&path=", Some(&e.token), "").await;
        assert_eq!(c, 400);
        assert_eq!(v["error"], "unknown root");
        let (c, v, _) = call(&e.app, "GET", "/api/nope", Some(&e.token), "").await;
        assert_eq!(c, 404);
        assert_eq!(v["error"], "not found");
        let (c, _, _) = call(&e.app, "POST", "/api/nope", Some(&e.token), "{}").await;
        assert_eq!(c, 404);
    }

    // ---- 攻击矩阵：路径穿越 ----

    #[tokio::test]
    async fn traversal_matrix() {
        let e = setup(false, default_opts());
        // 逃逸型：报错串与 Python 一致
        for uri in [
            "/api/read?root=r&path=../../escape.txt",
            "/api/read?root=r&path=..%2f..%2fescape.txt",
            "/api/read?root=r&path=..%5c..%5cescape.txt",
            "/api/read?root=r&path=%2e%2e%2f%2e%2e%2fescape.txt",
            "/api/read?root=r&path=..",
            "/api/write", // 见下：POST 用 body 测
        ] {
            if uri == "/api/write" {
                continue;
            }
            let (c, v, _) = call(&e.app, "GET", uri, Some(&e.token), "").await;
            assert_eq!(c, 400, "GET {uri}");
            assert_eq!(v["error"], "path escapes root", "GET {uri}");
        }
        // 根内 ".."（Python 允许 realpath 落回根内；有意收紧为 400）
        let (c, v, _) = call(
            &e.app,
            "GET",
            "/api/read?root=r&path=sub%2f..%2fok.txt",
            Some(&e.token),
            "",
        )
        .await;
        assert_eq!(c, 400);
        assert_eq!(v["error"], "invalid path");
        // 写入穿越
        for path in ["../escape_write.txt", "..\\..\\escape_w.txt"] {
            let body = json!({"root":"r","path":path,"content":"x"}).to_string();
            let (c, v, _) = call(&e.app, "POST", "/api/write", Some(&e.token), &body).await;
            assert_eq!(c, 400, "write {path}");
            assert_eq!(v["error"], "path escapes root", "write {path}");
        }
        // 磁盘上不存在逃逸产物
        assert!(!e.root.parent().unwrap().join("escape.txt").exists());
        assert!(!e.root.parent().unwrap().join("escape_w.txt").exists());
    }

    #[tokio::test]
    async fn absolute_unc_device_paths() {
        let e = setup(false, default_opts());
        for path in [
            "C:\\Windows\\win.ini",
            "C:/Windows/win.ini",
            "/etc/passwd",
            "\\\\127.0.0.1\\c$\\Windows\\win.ini",
            "\\\\.\\C:\\Windows\\win.ini",
            "\\\\?\\C:\\Windows\\win.ini",
        ] {
            let uri = format!("/api/read?root=r&path={}", urlencode(path));
            let (c, v, _) = call(&e.app, "GET", &uri, Some(&e.token), "").await;
            assert_eq!(c, 400, "{path}");
            assert_eq!(v["error"], "path must be relative", "{path}");
        }
    }

    #[tokio::test]
    async fn reserved_device_names() {
        let e = setup(false, default_opts());
        for path in [
            "CON", "CON.txt", "PRN", "AUX", "NUL", "NUL.txt", "COM1", "LPT1", "com2",
        ] {
            let uri = format!("/api/read?root=r&path={}", urlencode(path));
            let (c, v, _) = call(&e.app, "GET", &uri, Some(&e.token), "").await;
            assert_eq!(c, 400, "{path}");
            assert_eq!(v["error"], "invalid path", "{path}");
        }
    }

    #[tokio::test]
    async fn ads_and_trailing_dot_space() {
        let e = setup(false, default_opts());
        // ADS 数据流（Python 曾返回 200 —— 缺陷，修复后 400）
        let (c, v, _) = call(
            &e.app,
            "GET",
            "/api/read?root=r&path=a.txt%3a%3a%24DATA",
            Some(&e.token),
            "",
        )
        .await;
        assert_eq!(c, 400);
        assert_eq!(v["error"], "invalid path");
        // 先放一个正常文件
        let body = json!({"root":"r","path":"a.txt","content":"hello"}).to_string();
        let (c, _, _) = call(&e.app, "POST", "/api/write", Some(&e.token), &body).await;
        assert_eq!(c, 200);
        // 尾部点 / 尾部空格读取（Python 曾 200 别名 —— 缺陷，修复后 400）
        let (c, _, _) = call(
            &e.app,
            "GET",
            "/api/read?root=r&path=a.txt.",
            Some(&e.token),
            "",
        )
        .await;
        assert_eq!(c, 400);
        let (c, _, _) = call(
            &e.app,
            "GET",
            "/api/read?root=r&path=a.txt%20",
            Some(&e.token),
            "",
        )
        .await;
        assert_eq!(c, 400);
        // 尾部点写入不得碰原文件
        let body = json!({"root":"r","path":"a.txt.","content":"hijack"}).to_string();
        let (c, _, _) = call(&e.app, "POST", "/api/write", Some(&e.token), &body).await;
        assert_eq!(c, 400);
        let (c, v, _) = call(
            &e.app,
            "GET",
            "/api/read?root=r&path=a.txt",
            Some(&e.token),
            "",
        )
        .await;
        assert_eq!(c, 200);
        assert_eq!(v["content"], "hello");
        // 磁盘上没有产生 "a.txt." 变体
        assert_eq!(std::fs::read_dir(&e.root).unwrap().count(), 1);
    }

    #[cfg(windows)]
    fn link_fixture(e: &Env) -> PathBuf {
        let outside = e.root.parent().unwrap().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("sentinel.txt"), "outside").unwrap();
        outside
    }

    /// 重解析点必须被授权闸门挡住：读取与写入都不得触及根外文件。
    #[cfg(windows)]
    async fn assert_link_rejected(e: &Env, kind: &str, outside: &Path) {
        let uri = format!("/api/list?root=r&path={kind}");
        let (code, _, _) = call(&e.app, "GET", &uri, Some(&e.token), "").await;
        assert_eq!(code, 400, "{kind} 列目录未被拒绝");
        let uri = format!("/api/read?root=r&path={kind}%2fsentinel.txt");
        let (code, body, _) = call(&e.app, "GET", &uri, Some(&e.token), "").await;
        assert_eq!(code, 400, "{kind} 读取未被拒绝");
        assert_eq!(body["error"], "path escapes root", "{kind}");
        let body = json!({"root":"r","path":format!("{kind}/sentinel.txt"),"content":"changed"})
            .to_string();
        let (code, _, _) = call(&e.app, "POST", "/api/write", Some(&e.token), &body).await;
        assert_eq!(code, 400, "{kind} 写入未被拒绝");
        assert_eq!(
            std::fs::read_to_string(outside.join("sentinel.txt")).unwrap(),
            "outside",
            "{kind} 改写了根外文件"
        );
        // 建目录同样不得穿过重解析点。
        let body = json!({"root":"r","path":format!("{kind}/newdir")}).to_string();
        let (code, _, _) = call(&e.app, "POST", "/api/mkdir", Some(&e.token), &body).await;
        assert_eq!(code, 400, "{kind} 建目录未被拒绝");
        assert!(!outside.join("newdir").exists(), "{kind} 在根外建了目录");
    }

    /// 目录联接不要求管理员权限，创建失败即真实失败，不能算作通过。
    #[cfg(windows)]
    #[tokio::test]
    async fn junction_escape() {
        use std::os::windows::process::CommandExt;
        let e = setup(false, default_opts());
        let outside = link_fixture(&e);
        let link = e.root.join("junction");
        let status = std::process::Command::new("cmd.exe")
            .creation_flags(0x08000000)
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&link)
            .arg(&outside)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "目录联接未创建，不能将攻击矩阵判为通过");
        assert_link_rejected(&e, "junction", &outside).await;
        std::fs::remove_dir(&link).unwrap();
    }

    /// 符号链接需要 SeCreateSymbolicLinkPrivilege（管理员或开发者模式）。
    /// 缺权限时本机标为未覆盖；设置 `MUSE_CONNECTOR_REQUIRE_SYMLINK_TESTS=1` 时改为失败，
    /// 供 CI 断言该用例确实执行，避免把跳过当成通过。
    #[cfg(windows)]
    #[tokio::test]
    async fn symlink_escape() {
        let e = setup(false, default_opts());
        let outside = link_fixture(&e);
        let link = e.root.join("symlink");
        if let Err(error) = std::os::windows::fs::symlink_dir(&outside, &link) {
            assert!(
                matches!(error.raw_os_error(), Some(5 | 1314)),
                "符号链接创建失败且不是权限原因，不能将攻击矩阵判为通过: {error:?}"
            );
            assert!(
                std::env::var_os("MUSE_CONNECTOR_REQUIRE_SYMLINK_TESTS").is_none(),
                "当前环境缺少创建符号链接的权限，symlink_escape 未覆盖: {error:?}"
            );
            eprintln!("symlink_escape 未覆盖：环境不允许创建符号链接（{error:?}）");
            return;
        }
        assert_link_rejected(&e, "symlink", &outside).await;
        std::fs::remove_dir(&link).unwrap();
    }

    // ---- 读写功能矩阵 ----

    #[tokio::test]
    async fn write_read_roundtrip_text() {
        let e = setup(false, default_opts());
        let body = json!({"root":"r","path":"notes/todo.txt","content":"你好，MuseLink\nline 2"})
            .to_string();
        let (c, v, _) = call(&e.app, "POST", "/api/write", Some(&e.token), &body).await;
        assert_eq!(c, 200);
        assert_eq!(v["ok"], true);
        assert_eq!(v["bytes"], json!("你好，MuseLink\nline 2".len() as u64));
        // 磁盘真实存在且父目录自动创建
        assert!(e.root.join("notes").join("todo.txt").exists());
        // 读回
        let (c, v, _) = call(
            &e.app,
            "GET",
            "/api/read?root=r&path=notes%2ftodo.txt",
            Some(&e.token),
            "",
        )
        .await;
        assert_eq!(c, 200);
        assert_eq!(v["encoding"], "text");
        assert_eq!(v["content"], "你好，MuseLink\nline 2");
        // 覆盖写
        let body = json!({"root":"r","path":"notes/todo.txt","content":"replaced"}).to_string();
        let (c, _, _) = call(&e.app, "POST", "/api/write", Some(&e.token), &body).await;
        assert_eq!(c, 200);
        let (c, v, _) = call(
            &e.app,
            "GET",
            "/api/read?root=r&path=notes%2ftodo.txt",
            Some(&e.token),
            "",
        )
        .await;
        assert_eq!(c, 200);
        assert_eq!(v["content"], "replaced");
    }

    #[tokio::test]
    async fn write_read_base64_binary() {
        let e = setup(false, default_opts());
        let blob: Vec<u8> = (0..=255u8).collect();
        let body =
            json!({"root":"r","path":"bin.dat","content":B64.encode(&blob),"encoding":"base64"})
                .to_string();
        let (c, v, _) = call(&e.app, "POST", "/api/write", Some(&e.token), &body).await;
        assert_eq!(c, 200);
        assert_eq!(v["bytes"], 256);
        let (c, v, _) = call(
            &e.app,
            "GET",
            "/api/read?root=r&path=bin.dat",
            Some(&e.token),
            "",
        )
        .await;
        assert_eq!(c, 200);
        assert_eq!(v["encoding"], "base64");
        assert_eq!(B64.decode(v["content"].as_str().unwrap()).unwrap(), blob);
    }

    #[tokio::test]
    async fn error_shapes() {
        let e = setup(false, default_opts());
        // 读缺失
        let (c, v, _) = call(
            &e.app,
            "GET",
            "/api/read?root=r&path=nope.txt",
            Some(&e.token),
            "",
        )
        .await;
        assert_eq!(c, 404);
        assert_eq!(v["error"], "not a file");
        // list 非目录
        let body = json!({"root":"r","path":"a.txt","content":"x"}).to_string();
        call(&e.app, "POST", "/api/write", Some(&e.token), &body).await;
        let (c, v, _) = call(
            &e.app,
            "GET",
            "/api/list?root=r&path=a.txt",
            Some(&e.token),
            "",
        )
        .await;
        assert_eq!(c, 404);
        assert_eq!(v["error"], "not a directory");
        // 目标是目录：先 mkdir，再对同路径 write → 400
        let body = json!({"root":"r","path":"notes"}).to_string();
        let (c, _, _) = call(&e.app, "POST", "/api/mkdir", Some(&e.token), &body).await;
        assert_eq!(c, 200);
        let body = json!({"root":"r","path":"notes","content":"x"}).to_string();
        let (c, v, _) = call(&e.app, "POST", "/api/write", Some(&e.token), &body).await;
        assert_eq!(c, 400);
        assert_eq!(v["error"], "target is a directory");
        // 非法 JSON
        let (c, v, _) = call(&e.app, "POST", "/api/write", Some(&e.token), "not json").await;
        assert_eq!(c, 400);
        assert_eq!(v["error"], "invalid json");
        // 空 body → root 缺失 → unknown root（对齐 Python）
        let (c, v, _) = call(&e.app, "POST", "/api/write", Some(&e.token), "").await;
        assert_eq!(c, 400);
        assert_eq!(v["error"], "unknown root");
        // 坏 base64
        let body =
            json!({"root":"r","path":"x.bin","content":"@@@","encoding":"base64"}).to_string();
        let (c, v, _) = call(&e.app, "POST", "/api/write", Some(&e.token), &body).await;
        assert_eq!(c, 400);
        assert_eq!(v["error"], "bad content encoding");
    }

    #[tokio::test]
    async fn content_type_errors_never_truncate_and_base64_accepts_whitespace() {
        let e = setup(false, default_opts());
        std::fs::write(e.root.join("keep.txt"), "keep").unwrap();
        for content in [json!(null), json!(123), json!({"value":"wrong"})] {
            let body = json!({"root":"r","path":"keep.txt","content":content}).to_string();
            let (code, _, _) = call(&e.app, "POST", "/api/write", Some(&e.token), &body).await;
            assert_eq!(code, 400);
            assert_eq!(
                std::fs::read_to_string(e.root.join("keep.txt")).unwrap(),
                "keep"
            );
        }
        let body =
            json!({"root":"r","path":"base64.bin","encoding":"base64","content":"aG Vs\r\nbG8=\t"})
                .to_string();
        let (code, _, _) = call(&e.app, "POST", "/api/write", Some(&e.token), &body).await;
        assert_eq!(code, 200);
        assert_eq!(std::fs::read(e.root.join("base64.bin")).unwrap(), b"hello");
    }

    #[tokio::test]
    async fn health_probes_stay_audited_without_changing_file_activity() {
        let e = setup(false, default_opts());
        call(&e.app, "GET", "/api/health", Some(&e.token), "").await;
        assert_eq!(e.state.stats_snapshot()["file_activity"]["total"], 0);
        let body = json!({"root":"r","path":"activity.txt","content":"file"}).to_string();
        assert_eq!(
            call(&e.app, "POST", "/api/write", Some(&e.token), &body)
                .await
                .0,
            200
        );
        let activity = e.state.stats_snapshot()["file_activity"].clone();
        assert_eq!(activity["written_bytes"], 4);
        assert!(activity["last_request"].is_string());
        for _ in 0..3 {
            call(&e.app, "GET", "/api/health", Some(&e.token), "").await;
        }
        assert_eq!(e.state.stats_snapshot()["file_activity"], activity);
        call(
            &e.app,
            "GET",
            "/api/read?root=r&path=activity.txt",
            None,
            "",
        )
        .await;
        let snapshot = e.state.stats_snapshot();
        assert_eq!(snapshot["total"], 6);
        assert_eq!(snapshot["file_activity"]["total"], 2);
        assert_eq!(snapshot["file_activity"]["auth_failures"], 1);
        assert_eq!(
            snapshot["file_activity"]["last_request"],
            activity["last_request"]
        );
        assert_eq!(e.state.audit().recent(None, 1000).entries.len(), 6);
    }
    #[tokio::test]
    async fn list_format() {
        let e = setup(false, default_opts());
        for (p, c) in [("b.txt", "1"), ("z.txt", "2"), ("a.txt", "3")] {
            let body = json!({"root":"r","path":p,"content":c}).to_string();
            call(&e.app, "POST", "/api/write", Some(&e.token), &body).await;
        }
        // mkdir
        let body = json!({"root":"r","path":"dirA"}).to_string();
        let (c, v, _) = call(&e.app, "POST", "/api/mkdir", Some(&e.token), &body).await;
        assert_eq!(c, 200);
        assert_eq!(v["ok"], true);
        let (c, v, _) = call(&e.app, "GET", "/api/list?root=r&path=", Some(&e.token), "").await;
        assert_eq!(c, 200);
        let names: Vec<&str> = v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, vec!["dirA", "a.txt", "b.txt", "z.txt"]); // 目录在前，名称序
        assert_eq!(v["truncated"], false);
        let first = &v["entries"][0];
        assert_eq!(first["type"], "dir");
        assert!(first["mtime"].is_number());
        assert!(first["size"].is_number());
    }

    #[tokio::test]
    async fn list_truncates_after_directory_and_case_insensitive_ordering() {
        let e = setup(
            false,
            ApiOptions {
                list_max: 3,
                ..default_opts()
            },
        );
        for name in ["Z.txt", "a.txt", "B.txt"] {
            std::fs::write(e.root.join(name), b"sample").unwrap();
        }
        for name in ["z-dir", "A-dir"] {
            std::fs::create_dir(e.root.join(name)).unwrap();
        }
        let (code, list, _) =
            call(&e.app, "GET", "/api/list?root=r&path=", Some(&e.token), "").await;
        assert_eq!(code, 200);
        assert_eq!(list["truncated"], true);
        let names: Vec<_> = list["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["A-dir", "z-dir", "a.txt"]);
    }

    #[tokio::test]
    async fn read_only_mode_403() {
        let e = setup(true, default_opts());
        let body = json!({"root":"r","path":"x.txt","content":"x"}).to_string();
        let (c, v, _) = call(&e.app, "POST", "/api/write", Some(&e.token), &body).await;
        assert_eq!(c, 403);
        assert_eq!(
            v["error"],
            "read-only mode (set read_only=false in config.json)"
        );
        let body = json!({"root":"r","path":"d"}).to_string();
        let (c, _, _) = call(&e.app, "POST", "/api/mkdir", Some(&e.token), &body).await;
        assert_eq!(c, 403);
        // 只读不影响读
        let (c, _, _) = call(&e.app, "GET", "/api/health", Some(&e.token), "").await;
        assert_eq!(c, 200);
    }

    #[tokio::test]
    async fn rate_limit_only_counts_unauth() {
        let opts = ApiOptions {
            rate_limit: 3,
            ..default_opts()
        };
        let e = setup(false, opts);
        // 3 次未鉴权：401
        for _ in 0..3 {
            let (c, v, _) = call(&e.app, "GET", "/api/health", None, "").await;
            assert_eq!(c, 401);
            assert_eq!(v["error"], "unauthorized");
        }
        // 第 4 次：429（对齐 Python 文案）
        let (c, v, _) = call(&e.app, "GET", "/api/health", None, "").await;
        assert_eq!(c, 429);
        assert_eq!(v["error"], "rate limit exceeded");
        // 鉴权请求不受限流影响（缺陷修复点）
        for _ in 0..5 {
            let (c, _, _) = call(&e.app, "GET", "/api/health", Some(&e.token), "").await;
            assert_eq!(c, 200);
        }
    }

    #[tokio::test]
    async fn rotate_token_invalidates_old() {
        let e = setup(false, default_opts());
        let (c, v, _) = call(&e.app, "POST", "/api/rotate-token", Some(&e.token), "").await;
        assert_eq!(c, 200);
        assert_eq!(v["ok"], true);
        assert!(v.get("token").is_none(), "新令牌绝不回显");
        // 旧令牌失效
        let (c, _, _) = call(&e.app, "GET", "/api/health", Some(&e.token), "").await;
        assert_eq!(c, 401);
        // 文件里的新令牌可用
        let new_tok = std::fs::read_to_string(&e.token_path)
            .unwrap()
            .trim()
            .to_string();
        assert_eq!(new_tok.len(), 43);
        assert_ne!(new_tok, e.token);
        assert_eq!(e.state.token(), new_tok);
        let old_header = format!("Bearer {}", e.token);
        assert!(
            !e.state
                .rotate_token_if(|current| token::check_auth_header(Some(&old_header), current))
                .unwrap()
        );
        assert_eq!(token::load(&e.token_path).unwrap(), new_tok);
        let (c, _, _) = call(&e.app, "GET", "/api/health", Some(&new_tok), "").await;
        assert_eq!(c, 200);
    }

    #[test]
    fn legacy_mutations_hold_the_rotation_guard() {
        let e = setup(false, default_opts());
        let legacy = e.state.legacy_mutation_guard();
        assert!(e.state.inner.token_update.try_write().is_err());
        assert!(e.state.as_agent().legacy_mutation_guard().is_none());
        drop(legacy);
        assert!(e.state.inner.token_update.try_write().is_ok());
    }

    #[tokio::test]
    async fn size_limits() {
        let opts = ApiOptions {
            max_write: 1024,
            ..default_opts()
        };
        let e = setup(false, opts);
        // content 解码后超限；请求体本身仍在编码后上限内
        let big = "x".repeat(2000);
        let body = json!({"root":"r","path":"big.txt","content":big}).to_string();
        let (c, v, _) = call(&e.app, "POST", "/api/write", Some(&e.token), &body).await;
        assert_eq!(c, 413);
        assert_eq!(v["error"], "content too large");
        assert!(!e.root.join("big.txt").exists());
        // 原始 payload 超出编码后上限（max_write 的 Base64 长度 + 元数据余量）
        let limit = encoded_write_limit(1024);
        let huge = json!({"root":"r","path":"big.txt","content":"y".repeat(limit)}).to_string();
        assert!(huge.len() > limit);
        let (c, v, _) = call(&e.app, "POST", "/api/write", Some(&e.token), &huge).await;
        assert_eq!(c, 413);
        assert_eq!(v["error"], "payload too large");
        assert!(!e.root.join("big.txt").exists());

        // 读超限
        let opts = ApiOptions {
            max_read: 2048,
            max_write: 64 * 1024,
            ..default_opts()
        };
        let e2 = setup(false, opts);
        let blob = vec![0u8; 3000];
        let body =
            json!({"root":"r","path":"blob.bin","content":B64.encode(&blob),"encoding":"base64"})
                .to_string();
        let (c, _, _) = call(&e2.app, "POST", "/api/write", Some(&e2.token), &body).await;
        assert_eq!(c, 200);
        let (c, v, _) = call(
            &e2.app,
            "GET",
            "/api/read?root=r&path=blob.bin",
            Some(&e2.token),
            "",
        )
        .await;
        assert_eq!(c, 413);
        assert_eq!(v["error"], "file too large (3000 bytes)");
    }

    #[test]
    fn write_envelope_covers_base64_and_metadata() {
        // 10 MiB 恰好编码成 13,981,016 字节，再加 32 KiB 元数据余量
        assert_eq!(
            B64.encode(vec![0u8; MAX_WRITE_BYTES as usize]).len(),
            13_981_016
        );
        assert_eq!(encoded_write_limit(MAX_WRITE_BYTES), 14_013_784);
        assert_eq!(encoded_write_limit(0), MAX_METADATA_REQUEST_BYTES);
        // 3 字节 -> 4 个字符，向上取整
        assert_eq!(encoded_write_limit(1) - MAX_METADATA_REQUEST_BYTES, 4);
        assert_eq!(encoded_write_limit(3) - MAX_METADATA_REQUEST_BYTES, 4);
        assert_eq!(encoded_write_limit(4) - MAX_METADATA_REQUEST_BYTES, 8);
        // 极端值不溢出，且门限随 max_write 单调增长
        assert!(encoded_write_limit(u64::MAX) > encoded_write_limit(MAX_WRITE_BYTES));
    }

    /// 旧 `/api` 与 `/agent/v1` 共用同一写入限制：五个边界都必须一致。
    async fn assert_write_boundaries(
        app: &Router,
        auth: Option<&str>,
        route: &str,
        alias: &str,
        dir: &Path,
    ) {
        let payload = |path: &str, content: &str, encoding: &str| {
            json!({"root": alias, "path": path, "content": content, "encoding": encoding})
                .to_string()
        };

        // 文本写入
        let text = "第一行 hello\nsecond line";
        let body = payload("text.txt", text, "text");
        let (code, v, _) = call(app, "POST", route, auth, &body).await;
        assert_eq!(code, 200, "{route} text");
        assert_eq!(v["bytes"], text.len() as u64, "{route} text bytes");
        assert_eq!(
            std::fs::read_to_string(dir.join("text.txt")).unwrap(),
            text,
            "{route} text content"
        );

        // 上限以内
        let inside = vec![0x11u8; 1024 * 1024];
        let body = payload("inside.bin", &B64.encode(&inside), "base64");
        let (code, v, _) = call(app, "POST", route, auth, &body).await;
        assert_eq!(code, 200, "{route} inside limit");
        assert_eq!(v["bytes"], inside.len() as u64);

        // 恰好 10 MiB：编码后 13,981,016 字节必须穿过请求体检查
        let full = vec![0xA5u8; MAX_WRITE_BYTES as usize];
        let encoded = B64.encode(&full);
        let body = payload("full.bin", &encoded, "base64");
        assert!(body.len() < encoded_write_limit(MAX_WRITE_BYTES));
        let (code, v, _) = call(app, "POST", route, auth, &body).await;
        assert_eq!(code, 200, "{route} exact limit");
        assert_eq!(v["bytes"], MAX_WRITE_BYTES);
        let written = std::fs::read(dir.join("full.bin")).unwrap();
        assert_eq!(written.len() as u64, MAX_WRITE_BYTES, "{route} file length");
        assert!(
            written.iter().all(|byte| *byte == 0xA5),
            "{route} file content"
        );

        // 超出 1 字节：413，且原文件保持 10 MiB 内容不变
        let over = vec![0x5Au8; MAX_WRITE_BYTES as usize + 1];
        let body = payload("full.bin", &B64.encode(&over), "base64");
        let (code, v, _) = call(app, "POST", route, auth, &body).await;
        assert_eq!(code, 413, "{route} one byte over");
        assert_eq!(v["error"], "content too large");
        let kept = std::fs::read(dir.join("full.bin")).unwrap();
        assert_eq!(kept.len() as u64, MAX_WRITE_BYTES, "{route} kept length");
        assert!(
            kept.iter().all(|byte| *byte == 0xA5),
            "{route} kept content"
        );

        // 非法编码：400，原文件不被改写
        let body = payload("text.txt", "!!!not-base64!!!", "base64");
        let (code, v, _) = call(app, "POST", route, auth, &body).await;
        assert_eq!(code, 400, "{route} bad base64");
        assert_eq!(v["error"], "bad content encoding");
        assert_eq!(
            std::fs::read_to_string(dir.join("text.txt")).unwrap(),
            text,
            "{route} text preserved"
        );
    }

    fn setup_agent_file_grant(e: &Env) -> (PathBuf, String) {
        use super::super::access::{AccessPolicy, GrantScope, ScopeMode};
        use crate::profile::{ProfileKind, RuntimeProfile};

        let profile = RuntimeProfile {
            kind: ProfileKind::Development,
            home: e.root.parent().unwrap().join("agent-write"),
            onboarding_qa: false,
        };
        let fixture = profile.home.join("files");
        std::fs::create_dir_all(&fixture).unwrap();
        let (access, error) = AccessRuntime::open(&profile);
        assert!(error.is_none());
        e.state.attach_access(access.clone());
        let policy = AccessPolicy {
            mode: ScopeMode::Folders,
            roots: [("fixture".into(), fixture.clone())].into(),
            search: GrantScope::Off,
            read: GrantScope::Folders,
            write: GrantScope::Folders,
            ..Default::default()
        };
        access.validate(&policy).unwrap();
        access.save(policy, false).unwrap();
        access
            .issue_agent_token(|key| e.state.audit().protect_secret(key))
            .unwrap();
        (fixture, access.agent_token().unwrap())
    }

    #[tokio::test]
    async fn write_boundaries_accept_base64_up_to_the_decoded_limit() {
        let e = setup(false, default_opts());
        assert_write_boundaries(&e.app, Some(&e.token), "/api/write", "r", &e.root).await;

        let (fixture, agent_token) = setup_agent_file_grant(&e);
        assert_write_boundaries(
            &e.app,
            Some(&agent_token),
            "/agent/v1/write",
            "fixture",
            &fixture,
        )
        .await;

        // 两个凭证入口不能互换
        let (code, _, _) = call(&e.app, "POST", "/agent/v1/write", Some(&e.token), "{}").await;
        assert_eq!(code, 401);
        let (code, _, _) = call(&e.app, "POST", "/api/write", Some(&agent_token), "{}").await;
        assert_eq!(code, 401);
    }

    #[tokio::test]
    async fn both_file_apis_support_long_unicode_paths() {
        let e = setup(false, default_opts());
        let agent = setup(false, default_opts());
        let (fixture, agent_token) = setup_agent_file_grant(&agent);
        let parent = format!("{}/{}/{}", "a".repeat(96), "b".repeat(96), "c".repeat(96));
        let directory = format!("{parent}/notes");
        let name = "中文 测试.txt";
        let encoded_name = "%E4%B8%AD%E6%96%87%20%E6%B5%8B%E8%AF%95.txt";

        for (app, prefix, alias, token, root) in [
            (&e.app, "/api", "r", &e.token, &e.root),
            (&agent.app, "/agent/v1", "fixture", &agent_token, &fixture),
        ] {
            let auth = Some(token.as_str());
            let mkdir = json!({"root": alias, "path": parent}).to_string();
            let (code, body, _) = call(app, "POST", &format!("{prefix}/mkdir"), auth, &mkdir).await;
            assert_eq!(code, 200, "{prefix} mkdir returned {body}");

            let path = format!("{directory}/{name}");
            for content in ["first", "updated"] {
                let write = json!({"root": alias, "path": path, "content": content}).to_string();
                let (code, body, _) =
                    call(app, "POST", &format!("{prefix}/write"), auth, &write).await;
                assert_eq!(code, 200, "{prefix} write returned {body}");
            }

            let list = format!("{prefix}/list?root={alias}&path={directory}");
            let (code, body, _) = call(app, "GET", &list, auth, "").await;
            assert_eq!(code, 200, "{prefix} list returned {body}");
            assert_eq!(body["entries"].as_array().unwrap().len(), 1);
            assert_eq!(body["entries"][0]["name"], name);
            assert_eq!(body["entries"][0]["size"], 7);

            let read = format!("{prefix}/read?root={alias}&path={directory}/{encoded_name}");
            let (code, body, _) = call(app, "GET", &read, auth, "").await;
            assert_eq!(code, 200, "{prefix} read returned {body}");
            assert_eq!(body["content"], "updated");
            assert_eq!(
                std::fs::read_to_string(root.join(&path)).unwrap(),
                "updated"
            );
        }
    }

    #[tokio::test]
    async fn audit_line_shape() {
        let e = setup(false, default_opts());
        let audit_path = e.state.inner.paths.audit.clone();
        call(&e.app, "GET", "/api/health", Some(&e.token), "").await;
        let content = std::fs::read_to_string(&audit_path).unwrap();
        let line = content.lines().next().unwrap();
        // 字段顺序对齐 Python 版：struct 序列化保序；这里直接对原始行断言
        // （serde_json::Value 默认按字母序读回，不能用于验证顺序）
        assert!(line.starts_with(r#"{"ts":"#), "首字段应为 ts: {line}");
        let pos = |k: &str| line.find(&format!("\"{k}\":")).unwrap();
        assert!(
            pos("ts") < pos("client")
                && pos("client") < pos("method")
                && pos("method") < pos("endpoint")
                && pos("endpoint") < pos("authed")
                && pos("authed") < pos("root")
                && pos("root") < pos("path")
                && pos("path") < pos("code"),
            "字段顺序: {line}"
        );
        let v: Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["method"], "GET");
        assert_eq!(v["endpoint"], "/api/health");
        assert_eq!(v["authed"], true);
        assert_eq!(v["root"], Value::Null);
        assert_eq!(v["path"], Value::Null);
        assert_eq!(v["code"], 200);
        assert!(v["ts"].as_str().unwrap().ends_with("+00:00"));
        // 401 行：authed=false
        call(&e.app, "GET", "/api/health", None, "").await;
        let content = std::fs::read_to_string(&audit_path).unwrap();
        let line: Value = serde_json::from_str(content.lines().nth(1).unwrap()).unwrap();
        assert_eq!(line["authed"], false);
        assert_eq!(line["code"], 401);
    }

    #[tokio::test]
    async fn query_plus_is_form_encoded_space() {
        let e = setup(false, default_opts());
        std::fs::write(e.root.join("a b.txt"), "space-name").unwrap();
        let (code, body, _) = call(
            &e.app,
            "GET",
            "/api/read?root=r&path=a+b.txt",
            Some(&e.token),
            "",
        )
        .await;
        assert_eq!(code, 200);
        assert_eq!(body["content"], "space-name");
    }

    #[tokio::test]
    async fn query_ignores_empty_values_like_python() {
        let e = setup(false, default_opts());
        std::fs::write(e.root.join("x.txt"), "value").unwrap();
        let (code, body, _) = call(
            &e.app,
            "GET",
            "/api/read?root=&root=r&path=x.txt",
            Some(&e.token),
            "",
        )
        .await;
        assert_eq!(code, 200);
        assert_eq!(body["content"], "value");
    }

    #[tokio::test]
    async fn wrong_method_is_authenticated_and_audited() {
        let e = setup(false, default_opts());
        let (code, body, _) = call(&e.app, "POST", "/api/health", None, "").await;
        assert_eq!(code, 401);
        assert_eq!(body["error"], "unauthorized");
        let line = std::fs::read_to_string(&e.state.paths().audit).unwrap();
        assert!(line.contains("\"code\":401"));
        let (code, body, _) = call(&e.app, "POST", "/api/health", Some(&e.token), "").await;
        assert_eq!(code, 404);
        assert_eq!(body["error"], "not found");
    }

    #[test]
    fn config_accepts_legacy_utf8_bom() {
        let e = setup(false, default_opts());
        let path = e.root.parent().unwrap().join("bom-config.json");
        let cfg = serde_json::to_string(&e.state.config_snapshot()).unwrap();
        std::fs::write(&path, format!("\u{feff}{cfg}")).unwrap();
        assert!(BridgeConfig::load_from(&path).is_ok());
    }

    fn urlencode(s: &str) -> String {
        let mut out = String::new();
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    out.push(b as char)
                }
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }
}
