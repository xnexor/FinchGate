//! 受控命令执行运行时：异步作业、短等待直返、桌面通用审批队列、项目级会话授权与资源回收。

use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use super::access::{ERR_NOT_AUTHORIZED, ERR_PROTECTED, Operation};
use super::access_runtime::AccessRuntime;
use super::audit::{Audit, AuditEntry, now_iso};
use super::exec_policy::{
    ExecMode, ExecRequest, RiskTier, ValidatedExec, evaluate, validate_request,
};
use super::token;

const MAX_CONCURRENT_RUNNING: usize = 4;
const MAX_RETAINED_JOBS: usize = 64;
const JOB_RETENTION: Duration = Duration::from_secs(15 * 60);
const APPROVAL_TTL: Duration = Duration::from_secs(120);
const SESSION_TTL: Duration = Duration::from_secs(4 * 60 * 60);
const MAX_STREAM_BYTES: usize = 128 * 1024;
pub(crate) const MAX_STATUS_WAIT_MS: u64 = 25_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecJobStatus {
    AwaitingApproval,
    Running,
    Completed,
    Failed,
    TimedOut,
    Cancelled,
    Denied,
    Expired,
}

impl ExecJobStatus {
    pub(crate) fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed
                | Self::Failed
                | Self::TimedOut
                | Self::Cancelled
                | Self::Denied
                | Self::Expired
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalDecision {
    AllowOnce,
    AllowSession,
    Deny,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExecApprovalHint {
    pub id: String,
    pub tier: RiskTier,
    pub risk_tags: Vec<&'static str>,
    pub expires_in_sec: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExecJobView {
    pub job_id: String,
    pub status: ExecJobStatus,
    pub sandboxed: bool,
    pub tier: RiskTier,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub truncated: bool,
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval: Option<ExecApprovalHint>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApprovalView {
    pub id: String,
    pub job_id: String,
    pub kind: &'static str,
    pub tier: RiskTier,
    pub allow_session: bool,
    pub root: String,
    pub cwd: String,
    pub workspace_path: String,
    pub mode: ExecMode,
    pub command: String,
    pub sandboxed: bool,
    pub risk_tags: Vec<&'static str>,
    pub reason: Option<String>,
    pub created_at: String,
    pub expires_at_ms: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionGrantView {
    pub workspace_path: String,
    pub expires_at_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalEvent {
    Requested,
    Drained,
    Updated,
}

#[derive(Debug)]
pub(crate) enum ExecSubmitError {
    Disabled,
    Invalid(&'static str),
    Forbidden(&'static str),
    Busy,
}

struct PendingApproval {
    view: ApprovalView,
    workspace_key: PathBuf,
    expires_at: Instant,
    validated: ValidatedExec,
    workspace_dir: PathBuf,
}

struct JobRecord {
    id: String,
    status: ExecJobStatus,
    sandboxed: bool,
    tier: RiskTier,
    root: String,
    cwd_rel: String,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    truncated: bool,
    duration_ms: Option<u64>,
    error: Option<String>,
    approval_id: Option<String>,
    risk_tags: Vec<&'static str>,
    approval_expires: Option<Instant>,
    updated_at: Instant,
    cancel_flag: Arc<AtomicBool>,
    done_signal: Arc<(Mutex<bool>, Condvar)>,
    state_tx: tokio::sync::watch::Sender<u64>,
}

impl JobRecord {
    fn view(&self) -> ExecJobView {
        let approval = if self.status == ExecJobStatus::AwaitingApproval {
            self.approval_id.as_ref().map(|id| ExecApprovalHint {
                id: id.clone(),
                tier: self.tier,
                risk_tags: self.risk_tags.clone(),
                expires_in_sec: self
                    .approval_expires
                    .map(|exp| exp.saturating_duration_since(Instant::now()).as_secs())
                    .unwrap_or(0),
            })
        } else {
            None
        };
        let retry_after_ms = match self.status {
            ExecJobStatus::AwaitingApproval => Some(2_000),
            ExecJobStatus::Running => Some(1_500),
            _ => None,
        };
        ExecJobView {
            job_id: self.id.clone(),
            status: self.status,
            sandboxed: self.sandboxed,
            tier: self.tier,
            exit_code: self.exit_code,
            stdout: self.stdout.clone(),
            stderr: self.stderr.clone(),
            truncated: self.truncated,
            duration_ms: self.duration_ms,
            error: self.error.clone(),
            retry_after_ms,
            approval,
        }
    }
}

struct SessionEntry {
    display_path: String,
    expires_at: Instant,
    expires_at_ms: u64,
}

#[derive(Default)]
struct State {
    jobs: HashMap<String, JobRecord>,
    approvals: HashMap<String, PendingApproval>,
    sessions: HashMap<PathBuf, SessionEntry>,
}

impl State {
    fn running_count(&self) -> usize {
        self.jobs
            .values()
            .filter(|j| j.status == ExecJobStatus::Running)
            .count()
    }

    fn prune_locked(&mut self, now: Instant) -> bool {
        let mut drained = false;
        let had_approvals = !self.approvals.is_empty();
        let expired_ids: Vec<String> = self
            .approvals
            .iter()
            .filter(|(_, a)| a.expires_at <= now)
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired_ids {
            if let Some(pending) = self.approvals.remove(&id)
                && let Some(job) = self.jobs.get_mut(&pending.view.job_id)
                && job.status == ExecJobStatus::AwaitingApproval
            {
                job.status = ExecJobStatus::Expired;
                job.error = Some("approval timed out".into());
                job.updated_at = now;
                signal_done(&job.done_signal);
                bump_state(&job.state_tx);
            }
        }
        if had_approvals && self.approvals.is_empty() {
            drained = true;
        }
        self.sessions.retain(|_, entry| entry.expires_at > now);

        let expired_jobs: Vec<String> = self
            .jobs
            .iter()
            .filter(|(_, j)| {
                j.status.is_terminal() && now.duration_since(j.updated_at) > JOB_RETENTION
            })
            .map(|(id, _)| id.clone())
            .collect();
        for id in expired_jobs {
            self.jobs.remove(&id);
        }
        while self.jobs.len() > MAX_RETAINED_JOBS {
            let oldest = self
                .jobs
                .iter()
                .filter(|(_, j)| j.status.is_terminal())
                .min_by_key(|(_, j)| j.updated_at)
                .map(|(id, _)| id.clone());
            match oldest {
                Some(id) => {
                    self.jobs.remove(&id);
                }
                None => break,
            }
        }
        drained
    }
}

fn signal_done(signal: &Arc<(Mutex<bool>, Condvar)>) {
    let (lock, cv) = &**signal;
    if let Ok(mut done) = lock.lock() {
        *done = true;
        cv.notify_all();
    }
}

fn bump_state(tx: &tokio::sync::watch::Sender<u64>) {
    tx.send_modify(|seq| *seq = seq.wrapping_add(1));
}

pub(crate) struct ExecRuntime {
    temp_root: PathBuf,
    enabled: RwLock<bool>,
    state: Mutex<State>,
    audit: OnceLock<AuditHandle>,
    notifier: OnceLock<Arc<dyn Fn(ApprovalEvent) + Send + Sync>>,
}

#[derive(Clone)]
struct AuditHandle {
    audit: Arc<dyn AuditSink>,
}

pub(crate) trait AuditSink: Send + Sync {
    fn record_exec(&self, entry: AuditEntry);
    fn redact(&self, text: &str) -> String;
}

impl AuditSink for Audit {
    fn record_exec(&self, entry: AuditEntry) {
        self.record(&entry);
    }
    fn redact(&self, text: &str) -> String {
        self.redact_text(text)
    }
}

impl ExecRuntime {
    pub(crate) fn new(home: &Path, initial_enabled: bool) -> Arc<Self> {
        Arc::new(Self {
            temp_root: home.join("exec-tmp"),
            enabled: RwLock::new(initial_enabled),
            state: Mutex::new(State::default()),
            audit: OnceLock::new(),
            notifier: OnceLock::new(),
        })
    }

    pub(crate) fn attach_audit(&self, sink: Arc<dyn AuditSink>) {
        let _ = self.audit.set(AuditHandle { audit: sink });
    }

    pub(crate) fn attach_notifier(&self, notifier: Arc<dyn Fn(ApprovalEvent) + Send + Sync>) {
        let _ = self.notifier.set(notifier);
    }

    fn notify(&self, event: ApprovalEvent) {
        if let Some(notifier) = self.notifier.get() {
            notifier(event);
        }
    }

    fn redact(&self, text: &str) -> String {
        self.audit
            .get()
            .map(|h| h.audit.redact(text))
            .unwrap_or_else(|| text.to_owned())
    }

    fn audit_exec(
        &self,
        client: &str,
        endpoint: &str,
        root: &str,
        cwd_rel: &str,
        summary: &str,
        code: u16,
    ) {
        if let Some(handle) = self.audit.get() {
            let path = if cwd_rel.is_empty() {
                summary.to_owned()
            } else {
                format!("{cwd_rel} :: {summary}")
            };
            handle.audit.record_exec(AuditEntry {
                ts: now_iso(),
                client: client.to_owned(),
                method: "POST".into(),
                endpoint: Some(endpoint.to_owned()),
                authed: true,
                root: Some(root.to_owned()),
                path: Some(path),
                code,
                bytes: None,
                search_backend: None,
                search_ms: None,
            });
        }
    }

    pub(crate) fn is_enabled(&self) -> bool {
        *self.enabled.read().unwrap()
    }

    pub(crate) fn set_enabled(&self, enabled: bool) {
        *self.enabled.write().unwrap() = enabled;
        if !enabled {
            self.abort_all("command execution disabled");
        }
    }

    pub(crate) fn pending_approvals(&self) -> Vec<ApprovalView> {
        let mut state = self.state.lock().unwrap();
        let drained = state.prune_locked(Instant::now());
        let mut list: Vec<ApprovalView> =
            state.approvals.values().map(|a| a.view.clone()).collect();
        drop(state);
        if drained {
            self.notify(ApprovalEvent::Drained);
        }
        list.sort_by(|a, b| a.expires_at_ms.cmp(&b.expires_at_ms));
        list
    }

    pub(crate) fn active_sessions(&self) -> Vec<SessionGrantView> {
        let mut state = self.state.lock().unwrap();
        let drained = state.prune_locked(Instant::now());
        let mut list: Vec<SessionGrantView> = state
            .sessions
            .values()
            .map(|s| SessionGrantView {
                workspace_path: s.display_path.clone(),
                expires_at_ms: s.expires_at_ms,
            })
            .collect();
        drop(state);
        if drained {
            self.notify(ApprovalEvent::Drained);
        }
        list.sort_by(|a, b| a.workspace_path.cmp(&b.workspace_path));
        list
    }

    pub(crate) fn revoke_sessions(&self) {
        let mut state = self.state.lock().unwrap();
        state.sessions.clear();
        drop(state);
        self.notify(ApprovalEvent::Updated);
    }

    pub(crate) fn abort_all(&self, reason: &str) {
        let mut state = self.state.lock().unwrap();
        let had_approvals = !state.approvals.is_empty();
        state.approvals.clear();
        state.sessions.clear();
        let now = Instant::now();
        for job in state.jobs.values_mut() {
            if !job.status.is_terminal() {
                job.cancel_flag.store(true, Ordering::Release);
                job.status = if job.status == ExecJobStatus::AwaitingApproval {
                    ExecJobStatus::Denied
                } else {
                    ExecJobStatus::Cancelled
                };
                job.error = Some(reason.to_owned());
                job.updated_at = now;
                signal_done(&job.done_signal);
                bump_state(&job.state_tx);
            }
        }
        drop(state);
        if had_approvals {
            self.notify(ApprovalEvent::Drained);
        } else {
            self.notify(ApprovalEvent::Updated);
        }
        let _ = std::fs::remove_dir_all(&self.temp_root);
    }

    pub(crate) fn submit(
        self: &Arc<Self>,
        request: ExecRequest,
        access: &AccessRuntime,
        client: &str,
    ) -> Result<(u16, ExecJobView), ExecSubmitError> {
        if !self.is_enabled() {
            return Err(ExecSubmitError::Disabled);
        }
        let validated = validate_request(request).map_err(ExecSubmitError::Invalid)?;

        // 1) 校验工作目录归属已授权范围（至少具备 Read 权限且不能位于 protected 凭证目录内）
        let resolved = access
            .resolve_agent_file(Operation::Read, &validated.root, &validated.cwd_rel)
            .map_err(|err| match err {
                ERR_NOT_AUTHORIZED
                | ERR_PROTECTED
                | super::access::ERR_REPARSE
                | super::path_guard::ERR_UNKNOWN_ROOT => ExecSubmitError::Forbidden(err),
                _ => ExecSubmitError::Invalid(err),
            })?;
        if !resolved.path.is_dir() {
            return Err(ExecSubmitError::Invalid("cwd is not an existing directory"));
        }
        // 严禁将整块盘符根目录作为执行工作区（避免写受限沙箱扩到整块磁盘）
        if super::access::is_drive_root(&resolved.path) {
            return Err(ExecSubmitError::Forbidden(
                "cannot execute directly on a drive root; specify a project subfolder in cwd",
            ));
        }

        // 检查目标工作目录是否落在敏感写保护目录内（仍可触发 Tier 3 单次确认）
        let sensitive_workspace = access.is_write_protected_path(&resolved.path);
        // 若非敏感目录，还必须拥有该目录的写权限或显式授权（防止只读授权被执行绕过）
        if !sensitive_workspace
            && access
                .resolve_agent_file(Operation::Write, &validated.root, &validated.cwd_rel)
                .is_err()
        {
            return Err(ExecSubmitError::Forbidden(ERR_NOT_AUTHORIZED));
        }

        let verdict = evaluate(&validated, sensitive_workspace);
        let workspace_key = normalize_workspace_key(&resolved.path);
        let now = Instant::now();

        let job_id = format!("job_{}", &token::generate()[..20]);
        let done_signal = Arc::new((Mutex::new(false), Condvar::new()));
        let cancel_flag = Arc::new(AtomicBool::new(false));
        let (state_tx, _) = tokio::sync::watch::channel(0u64);

        let needs_approval = {
            let mut state = self.state.lock().unwrap();
            let drained = state.prune_locked(now);
            if drained {
                drop(state);
                self.notify(ApprovalEvent::Drained);
                state = self.state.lock().unwrap();
            }
            if state.running_count() >= MAX_CONCURRENT_RUNNING {
                return Err(ExecSubmitError::Busy);
            }
            match verdict.tier {
                RiskTier::Auto => false,
                RiskTier::Session => !state
                    .sessions
                    .get(&workspace_key)
                    .is_some_and(|s| s.expires_at > now),
                RiskTier::Always => true,
            }
        };

        if needs_approval {
            let approval_id = format!("apr_{}", &token::generate()[..20]);
            let expires_at = now + APPROVAL_TTL;
            let expires_at_ms = epoch_ms_after(APPROVAL_TTL);
            let workspace_display = display_clean_path(&resolved.path);
            let view = ApprovalView {
                id: approval_id.clone(),
                job_id: job_id.clone(),
                kind: "exec",
                tier: verdict.tier,
                allow_session: verdict.allow_session,
                root: validated.root.clone(),
                cwd: validated.cwd_rel.clone(),
                workspace_path: workspace_display,
                mode: validated.mode,
                command: verdict.display_command.clone(),
                sandboxed: !validated.unsandboxed,
                risk_tags: verdict.risk_tags.clone(),
                reason: validated.reason.clone(),
                created_at: now_iso(),
                expires_at_ms,
            };
            let record = JobRecord {
                id: job_id.clone(),
                status: ExecJobStatus::AwaitingApproval,
                sandboxed: !validated.unsandboxed,
                tier: verdict.tier,
                root: validated.root.clone(),
                cwd_rel: validated.cwd_rel.clone(),
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                truncated: false,
                duration_ms: None,
                error: None,
                approval_id: Some(approval_id.clone()),
                risk_tags: verdict.risk_tags.clone(),
                approval_expires: Some(expires_at),
                updated_at: now,
                cancel_flag,
                done_signal,
                state_tx,
            };
            let job_view = record.view();
            let audit_root = validated.root.clone();
            let audit_cwd = validated.cwd_rel.clone();
            {
                let mut state = self.state.lock().unwrap();
                state.jobs.insert(job_id.clone(), record);
                state.approvals.insert(
                    approval_id,
                    PendingApproval {
                        view,
                        workspace_key,
                        expires_at,
                        validated,
                        workspace_dir: resolved.path,
                    },
                );
            }
            self.audit_exec(
                client,
                "/agent/v1/exec",
                &audit_root,
                &audit_cwd,
                &format!(
                    "awaiting_approval ({}): {}",
                    job_view.job_id, verdict.display_command
                ),
                202,
            );
            self.notify(ApprovalEvent::Requested);
            return Ok((202, job_view));
        }

        // 自动放行（Tier 1 或命中本会话已允许项目）
        let record = JobRecord {
            id: job_id.clone(),
            status: ExecJobStatus::Running,
            sandboxed: !validated.unsandboxed,
            tier: verdict.tier,
            root: validated.root.clone(),
            cwd_rel: validated.cwd_rel.clone(),
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            truncated: false,
            duration_ms: None,
            error: None,
            approval_id: None,
            risk_tags: verdict.risk_tags.clone(),
            approval_expires: None,
            updated_at: now,
            cancel_flag: cancel_flag.clone(),
            done_signal: done_signal.clone(),
            state_tx,
        };
        {
            let mut state = self.state.lock().unwrap();
            state.jobs.insert(job_id.clone(), record);
        }
        let wait_ms = validated.wait_ms;
        self.spawn_worker(
            job_id.clone(),
            validated,
            resolved.path,
            cancel_flag,
            done_signal.clone(),
            client.to_owned(),
            if verdict.tier == RiskTier::Auto {
                "auto"
            } else {
                "session"
            },
        );

        // 短等待：快命令在 wait_ms 内完成可直接 200 返回结果，避免二次轮询
        if wait_ms > 0 {
            let (lock, cv) = &*done_signal;
            if let Ok(guard) = lock.lock() {
                let _ = cv.wait_timeout_while(guard, Duration::from_millis(wait_ms), |done| !*done);
            }
        }

        let view = self.get_job(&job_id).unwrap();
        let status_code = if view.status.is_terminal() { 200 } else { 202 };
        Ok((status_code, view))
    }

    pub(crate) fn resolve_approval(
        self: &Arc<Self>,
        approval_id: &str,
        decision: ApprovalDecision,
    ) -> Result<bool, String> {
        let now = Instant::now();
        let (pending, remaining_approvals) = {
            let mut state = self.state.lock().unwrap();
            state.prune_locked(now);
            let Some(pending) = state.approvals.remove(approval_id) else {
                return Ok(false);
            };
            let remaining = state.approvals.len();
            match decision {
                ApprovalDecision::Deny => {
                    if let Some(job) = state.jobs.get_mut(&pending.view.job_id) {
                        job.status = ExecJobStatus::Denied;
                        job.error = Some("denied by user".into());
                        job.updated_at = now;
                        signal_done(&job.done_signal);
                        bump_state(&job.state_tx);
                    }
                    (Some((pending, None)), remaining)
                }
                ApprovalDecision::AllowOnce | ApprovalDecision::AllowSession => {
                    if decision == ApprovalDecision::AllowSession && pending.view.allow_session {
                        state.sessions.insert(
                            pending.workspace_key.clone(),
                            SessionEntry {
                                display_path: pending.view.workspace_path.clone(),
                                expires_at: now + SESSION_TTL,
                                expires_at_ms: epoch_ms_after(SESSION_TTL),
                            },
                        );
                    }
                    if state.running_count() >= MAX_CONCURRENT_RUNNING {
                        if let Some(job) = state.jobs.get_mut(&pending.view.job_id) {
                            job.status = ExecJobStatus::Failed;
                            job.error = Some("too many running commands".into());
                            job.updated_at = now;
                            signal_done(&job.done_signal);
                            bump_state(&job.state_tx);
                        }
                        return Err("当前运行中的命令数量已达上限，请稍后重试".into());
                    }
                    let worker_ctx = state.jobs.get_mut(&pending.view.job_id).map(|job| {
                        job.status = ExecJobStatus::Running;
                        job.approval_id = None;
                        job.approval_expires = None;
                        job.updated_at = now;
                        bump_state(&job.state_tx);
                        (job.cancel_flag.clone(), job.done_signal.clone())
                    });
                    (Some((pending, worker_ctx)), remaining)
                }
            }
        };

        if let Some((pending, worker_ctx)) = pending {
            if let Some((cancel_flag, done_signal)) = worker_ctx {
                let how =
                    if decision == ApprovalDecision::AllowSession && pending.view.allow_session {
                        "approved_session"
                    } else {
                        "approved_once"
                    };
                self.spawn_worker(
                    pending.view.job_id.clone(),
                    pending.validated,
                    pending.workspace_dir,
                    cancel_flag,
                    done_signal,
                    "desktop".into(),
                    how,
                );
            } else {
                self.audit_exec(
                    "desktop",
                    "/agent/v1/exec",
                    &pending.view.root,
                    &pending.view.cwd,
                    &format!("denied: {}", pending.view.command),
                    403,
                );
            }
        }

        if remaining_approvals == 0 {
            self.notify(ApprovalEvent::Drained);
        } else {
            self.notify(ApprovalEvent::Updated);
        }
        Ok(true)
    }

    pub(crate) fn get_job(&self, job_id: &str) -> Option<ExecJobView> {
        self.get_job_with_expiry(job_id).map(|(view, _)| view)
    }

    pub(crate) fn get_job_with_expiry(
        &self,
        job_id: &str,
    ) -> Option<(ExecJobView, Option<Instant>)> {
        let mut state = self.state.lock().unwrap();
        let drained = state.prune_locked(Instant::now());
        let result = state
            .jobs
            .get(job_id)
            .map(|job| (job.view(), job.approval_expires));
        drop(state);
        if drained {
            self.notify(ApprovalEvent::Drained);
        }
        result
    }

    pub(crate) fn subscribe_job(
        &self,
        job_id: &str,
    ) -> Option<(
        ExecJobView,
        tokio::sync::watch::Receiver<u64>,
        Option<Instant>,
    )> {
        let mut state = self.state.lock().unwrap();
        let drained = state.prune_locked(Instant::now());
        let result = state.jobs.get(job_id).map(|job| {
            let mut rx = job.state_tx.subscribe();
            let _ = rx.borrow_and_update();
            (job.view(), rx, job.approval_expires)
        });
        drop(state);
        if drained {
            self.notify(ApprovalEvent::Drained);
        }
        result
    }

    pub(crate) fn cancel_job(&self, job_id: &str) -> Option<ExecJobView> {
        let mut guard = self.state.lock().unwrap();
        let now = Instant::now();
        let mut drained = guard.prune_locked(now);
        let state = &mut *guard;
        let job = state.jobs.get_mut(job_id)?;
        if job.status == ExecJobStatus::AwaitingApproval {
            if let Some(apr_id) = job.approval_id.take() {
                state.approvals.remove(&apr_id);
                if state.approvals.is_empty() {
                    drained = true;
                }
            }
            job.status = ExecJobStatus::Cancelled;
            job.error = Some("cancelled".into());
            job.updated_at = now;
            signal_done(&job.done_signal);
            bump_state(&job.state_tx);
        } else if job.status == ExecJobStatus::Running {
            job.cancel_flag.store(true, Ordering::Release);
            job.status = ExecJobStatus::Cancelled;
            job.error = Some("cancelled".into());
            job.updated_at = now;
            signal_done(&job.done_signal);
            bump_state(&job.state_tx);
        }
        let view = job.view();
        drop(guard);
        if drained {
            self.notify(ApprovalEvent::Drained);
        }
        Some(view)
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_worker(
        self: &Arc<Self>,
        job_id: String,
        validated: ValidatedExec,
        workspace_dir: PathBuf,
        cancel_flag: Arc<AtomicBool>,
        done_signal: Arc<(Mutex<bool>, Condvar)>,
        client: String,
        approval_source: &'static str,
    ) {
        let runtime = Arc::clone(self);
        std::thread::spawn(move || {
            let started = Instant::now();
            let job_temp = runtime.temp_root.join(&job_id);
            let outcome = run_process(
                &validated,
                &workspace_dir,
                &job_temp,
                &cancel_flag,
                Duration::from_secs(validated.timeout_sec),
            );
            let _ = std::fs::remove_dir_all(&job_temp);
            let elapsed_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;

            let (
                final_status,
                exit_code,
                stdout,
                stderr,
                truncated,
                error,
                audit_code,
                display_cmd,
            ) = match outcome {
                Ok(res) => {
                    let status = if res.cancelled {
                        ExecJobStatus::Cancelled
                    } else if res.timed_out {
                        ExecJobStatus::TimedOut
                    } else {
                        ExecJobStatus::Completed
                    };
                    let err = if res.timed_out {
                        Some("command timed out and was terminated".into())
                    } else if res.cancelled {
                        Some("cancelled".into())
                    } else {
                        None
                    };
                    (
                        status,
                        res.exit_code,
                        runtime.redact(&res.stdout),
                        runtime.redact(&res.stderr),
                        res.truncated,
                        err,
                        if status == ExecJobStatus::Completed {
                            200
                        } else {
                            408
                        },
                        res.display_cmd,
                    )
                }
                Err(msg) => (
                    ExecJobStatus::Failed,
                    None,
                    String::new(),
                    String::new(),
                    false,
                    Some(runtime.redact(&msg)),
                    500,
                    validated.program.clone(),
                ),
            };

            let (root, cwd_rel) = {
                let mut state = runtime.state.lock().unwrap();
                if let Some(job) = state.jobs.get_mut(&job_id) {
                    if job.status != ExecJobStatus::Cancelled {
                        job.status = final_status;
                    }
                    job.exit_code = exit_code;
                    job.stdout = stdout;
                    job.stderr = stderr;
                    job.truncated = truncated;
                    job.duration_ms = Some(elapsed_ms);
                    if job.error.is_none() {
                        job.error = error;
                    }
                    job.updated_at = Instant::now();
                    signal_done(&job.done_signal);
                    bump_state(&job.state_tx);
                    (job.root.clone(), job.cwd_rel.clone())
                } else {
                    signal_done(&done_signal);
                    (validated.root.clone(), validated.cwd_rel.clone())
                }
            };

            runtime.audit_exec(
                &client,
                "/agent/v1/exec",
                &root,
                &cwd_rel,
                &format!(
                    "[{approval_source}] {display_cmd} -> {:?} (code={:?}, {}ms)",
                    final_status, exit_code, elapsed_ms
                ),
                audit_code,
            );
        });
    }
}

struct ProcessOutcome {
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    truncated: bool,
    timed_out: bool,
    cancelled: bool,
    display_cmd: String,
}

#[cfg(windows)]
fn run_process(
    req: &ValidatedExec,
    workspace_dir: &Path,
    job_temp: &Path,
    cancel: &AtomicBool,
    timeout: Duration,
) -> Result<ProcessOutcome, String> {
    use super::job::JobLimits;
    use super::sandbox::{
        DEFAULT_EXEC_MAX_PROCESSES, DEFAULT_EXEC_MEMORY_BYTES, SpawnConfig, build_windows_cmdline,
        quote_windows_arg, resolve_program, spawn, strip_verbatim, system_executable,
    };

    let (application, command_line, display_cmd) = match req.mode {
        ExecMode::Direct => {
            let (resolved_exe, is_batch) = resolve_program(&req.program)
                .ok_or_else(|| format!("program not found in PATH: {}", req.program))?;
            if is_batch {
                // 对 .cmd/.bat（如 pnpm.cmd/npm.cmd）拒绝危险 cmd 元字符，防止参数逃逸为多条命令
                for arg in &req.args {
                    if arg
                        .chars()
                        .any(|c| matches!(c, '&' | '|' | '<' | '>' | '^' | '%' | '!'))
                    {
                        return Err(
                            "batch tool argument contains shell metacharacters; use powershell or cmd mode"
                                .into(),
                        );
                    }
                }
                let cmd_exe = system_executable(r"System32\cmd.exe")
                    .map_err(|e| format!("cmd.exe unavailable: {e}"))?;
                let inner = build_windows_cmdline(&strip_verbatim(&resolved_exe), &req.args);
                let line = format!(
                    "{} /d /s /c \"{}\"",
                    quote_windows_arg(&strip_verbatim(&cmd_exe)),
                    inner
                );
                (
                    cmd_exe,
                    line,
                    format!("{} {}", req.program, req.args.join(" ")),
                )
            } else {
                let line = build_windows_cmdline(&strip_verbatim(&resolved_exe), &req.args);
                (
                    resolved_exe,
                    line,
                    format!("{} {}", req.program, req.args.join(" ")),
                )
            }
        }
        ExecMode::Powershell => {
            let ps_exe = system_executable(r"System32\WindowsPowerShell\v1.0\powershell.exe")
                .map_err(|e| format!("powershell.exe unavailable: {e}"))?;
            let script = req.command.as_deref().unwrap_or_default();
            let line = build_windows_cmdline(
                &strip_verbatim(&ps_exe),
                &[
                    "-NoProfile".into(),
                    "-NonInteractive".into(),
                    "-ExecutionPolicy".into(),
                    "Bypass".into(),
                    "-Command".into(),
                    script.to_owned(),
                ],
            );
            (ps_exe, line, format!("powershell: {script}"))
        }
        ExecMode::Cmd => {
            let cmd_exe = system_executable(r"System32\cmd.exe")
                .map_err(|e| format!("cmd.exe unavailable: {e}"))?;
            let script = req.command.as_deref().unwrap_or_default();
            let line = format!(
                "{} /d /s /c \"{}\"",
                quote_windows_arg(&strip_verbatim(&cmd_exe)),
                script
            );
            (cmd_exe, line, format!("cmd: {script}"))
        }
    };

    if cancel.load(Ordering::Acquire) {
        return Ok(ProcessOutcome {
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            truncated: false,
            timed_out: false,
            cancelled: true,
            display_cmd,
        });
    }

    let write_workspace = !super::exec_policy::is_read_only_direct(req);
    let mut proc = match spawn(
        &SpawnConfig {
            application,
            command_line,
            cwd: workspace_dir.to_path_buf(),
            temp_dir: job_temp.to_path_buf(),
            sandboxed: !req.unsandboxed,
            write_workspace,
            limits: JobLimits {
                memory_bytes: Some(DEFAULT_EXEC_MEMORY_BYTES),
                max_processes: Some(DEFAULT_EXEC_MAX_PROCESSES),
            },
        },
        Some(cancel),
    ) {
        Ok(proc) => proc,
        Err(e) if e.kind() == std::io::ErrorKind::Interrupted || cancel.load(Ordering::Acquire) => {
            return Ok(ProcessOutcome {
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                truncated: false,
                timed_out: false,
                cancelled: true,
                display_cmd,
            });
        }
        Err(e) => return Err(format!("failed to launch sandboxed command: {e}")),
    };

    let (mut stdout_file, mut stderr_file) = proc
        .take_pipes()
        .ok_or_else(|| "failed to capture command output pipes".to_string())?;
    let out_reader = std::thread::spawn(move || read_bounded(&mut stdout_file, MAX_STREAM_BYTES));
    let err_reader = std::thread::spawn(move || read_bounded(&mut stderr_file, MAX_STREAM_BYTES));

    let deadline = Instant::now() + timeout;
    let mut exit_code = None;
    let mut timed_out = false;
    let mut cancelled = false;
    loop {
        if cancel.load(Ordering::Acquire) {
            cancelled = true;
            proc.terminate();
            break;
        }
        if Instant::now() >= deadline {
            timed_out = true;
            proc.terminate();
            break;
        }
        match proc.wait_timeout(50) {
            Ok(Some(code)) => {
                exit_code = Some(code);
                break;
            }
            Ok(None) => {}
            Err(_) => {
                proc.terminate();
                break;
            }
        }
    }

    // 主进程已退出或超时/取消：立即清理 Job Object 中的残留子进程树，
    // 防止被后台孙进程继承的 stdout/stderr 管道写端保持打开导致读线程永久阻塞在 running。
    proc.terminate();
    drop(proc);

    let (stdout_bytes, out_trunc) = out_reader.join().unwrap_or_default();
    let (stderr_bytes, err_trunc) = err_reader.join().unwrap_or_default();

    Ok(ProcessOutcome {
        exit_code,
        stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
        stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
        truncated: out_trunc || err_trunc,
        timed_out,
        cancelled,
        display_cmd,
    })
}

#[cfg(not(windows))]
fn run_process(
    _req: &ValidatedExec,
    _workspace_dir: &Path,
    _job_temp: &Path,
    _cancel: &AtomicBool,
    _timeout: Duration,
) -> Result<ProcessOutcome, String> {
    Err("sandboxed execution is only supported on Windows".into())
}

fn read_bounded(reader: &mut impl Read, max_bytes: usize) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut truncated = false;
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if out.len() < max_bytes {
                    let keep = n.min(max_bytes - out.len());
                    out.extend_from_slice(&buf[..keep]);
                    if keep < n {
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(_) => break,
        }
    }
    (out, truncated)
}

fn normalize_workspace_key(path: &Path) -> PathBuf {
    PathBuf::from(display_clean_path(path).to_ascii_lowercase())
}

fn display_clean_path(path: &Path) -> String {
    let s = path.to_string_lossy();
    s.strip_prefix(r"\\?\").unwrap_or(&s).to_owned()
}

fn epoch_ms_after(delta: Duration) -> u64 {
    SystemTime::now()
        .checked_add(delta)
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis().min(u64::MAX as u128) as u64)
        .unwrap_or(0)
}
