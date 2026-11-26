//! 隧道适配器。开发 profile 不调用真实工具；只撤销本应用拥有的入口。
use crate::profile::{ProviderKind, ProviderSettings, RuntimeProfile};
use serde::{Deserialize, Serialize};
use serde_json::Value;
#[cfg(test)]
use serde_json::json;
use std::path::PathBuf;
use std::time::Duration;
use tokio::process::{Child, Command};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum Health {
    Up,
    Degraded,
    Down,
    Paused,
    Unknown,
    Starting,
    Stopping,
    Conflict,
}
#[derive(Debug, Clone, Serialize)]
pub struct TunnelStatus {
    pub health: Health,
    pub api_up: bool,
    pub funnel_up: bool,
    pub url: Option<String>,
    pub enabled: bool,
    pub last_check: String,
    pub note: String,
    pub api_port: u16,
    pub public_verified: Option<bool>,
    pub agent_public_verified: Option<bool>,
}
impl Default for TunnelStatus {
    fn default() -> Self {
        Self {
            health: Health::Unknown,
            api_up: false,
            funnel_up: false,
            url: None,
            enabled: false,
            last_check: String::new(),
            note: "尚未探测".into(),
            api_port: 0,
            public_verified: None,
            agent_public_verified: None,
        }
    }
}
#[derive(Debug, Clone, Serialize, Default)]
pub struct TunnelObservation {
    pub configured: bool,
    pub online: bool,
    pub url: Option<String>,
    pub note: String,
}

impl TunnelObservation {
    pub(crate) fn simulated(owned: bool) -> Self {
        Self {
            configured: owned,
            online: owned,
            url: None,
            note: "开发模拟连接，不创建公网入口".into(),
        }
    }
}

pub fn discover_executable(name: &str) -> Option<PathBuf> {
    if let Some(found) = std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join(name))
            .find(|p| p.is_file())
    }) {
        return Some(found);
    }
    let mut candidates = vec![];
    if name == "tailscale.exe" {
        candidates.push(PathBuf::from(r"C:\Program Files\Tailscale\tailscale.exe"));
    }
    if let Some(local) = dirs::data_local_dir() {
        candidates.push(local.join("Microsoft/WinGet/Links").join(name));
    }
    if let Some(program) = std::env::var_os("ProgramFiles") {
        let program = PathBuf::from(program);
        candidates.push(program.join("cloudflared").join(name));
        candidates.push(program.join("WinGet/Links").join(name));
        if name == "cloudflared.exe" {
            for base in [
                program.join("WinGet/Packages"),
                dirs::data_local_dir()
                    .unwrap_or_default()
                    .join("Microsoft/WinGet/Packages"),
            ] {
                if let Ok(entries) = std::fs::read_dir(base) {
                    for entry in entries.flatten().filter(|e| {
                        e.file_name()
                            .to_string_lossy()
                            .starts_with("Cloudflare.cloudflared_")
                    }) {
                        candidates.push(entry.path().join(name));
                    }
                }
            }
        }
    }
    candidates.into_iter().find(|p| p.is_file())
}
pub fn command(exe: &std::path::Path) -> Command {
    let mut native = std::process::Command::new(exe);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        native.creation_flags(0x08000000);
    }
    let mut cmd = Command::from(native);
    cmd.kill_on_drop(true);
    cmd
}
pub async fn run_cli(exe: &std::path::Path, args: &[&str]) -> Result<String, String> {
    let mut cmd = command(exe);
    cmd.args(args);
    let out = tokio::time::timeout(Duration::from_secs(12), cmd.output())
        .await
        .map_err(|_| "命令超时，子进程已取消".to_string())?
        .map_err(|e| format!("工具启动失败：{}", e.kind()))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let first = stderr
            .lines()
            .find(|l| !l.trim().is_empty())
            .unwrap_or("请检查工具登录与权限");
        return Err(format!(
            "工具退出码 {:?}：{}",
            out.status.code(),
            first.chars().take(300).collect::<String>()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Owner {
    port: u16,
    provider: ProviderKind,
}

pub struct TunnelManager {
    profile: RuntimeProfile,
    child: Option<Child>,
    #[cfg(windows)]
    child_job: Option<crate::core::job::ChildJob>,
    owned: bool,
    port: u16,
    current: ProviderSettings,
}
impl TunnelManager {
    pub fn new(profile: RuntimeProfile) -> Self {
        Self {
            profile,
            child: None,
            #[cfg(windows)]
            child_job: None,
            owned: false,
            port: 0,
            current: ProviderSettings::default(),
        }
    }
    fn owner_path(&self) -> PathBuf {
        self.profile.home.join("tunnel-owner.json")
    }
    fn remember(&self, settings: &ProviderSettings, port: u16) -> Result<(), String> {
        crate::core::storage::atomic_write(
            &self.owner_path(),
            &serde_json::to_vec(&Owner {
                port,
                provider: settings.kind.clone(),
            })
            .map_err(|e| e.to_string())?,
        )
        .map_err(|_| "不能保存隧道归属，已拒绝修改入口".into())
    }
    pub async fn start(
        &mut self,
        settings: &ProviderSettings,
        port: u16,
    ) -> Result<TunnelObservation, String> {
        if self.profile.is_development() {
            self.current = settings.clone();
            self.port = port;
            self.owned = true;
            return self.observe().await;
        }
        match settings.kind {
            ProviderKind::Tailscale => {
                let exe = discover_executable("tailscale.exe")
                    .ok_or("未检测到 Tailscale，请先安装并登录")?;
                let raw = run_cli(&exe, &["funnel", "status", "--json"]).await?;
                let cfg: Value = serde_json::from_str(&raw)
                    .map_err(|_| "无法解析 Tailscale 配置，未改变入口")?;
                ensure_exclusive_mapping(&cfg, port)?;
                self.remember(settings, port)?;
                // 先记归属再执行：超时/崩溃后可以识别本次未完成操作。
                self.current = settings.clone();
                self.port = port;
                self.owned = true;
                run_cli(&exe, &["funnel", "--bg", "--https=443", &port.to_string()]).await?;
            }
            ProviderKind::CloudflareNamed => {
                let exe = discover_executable("cloudflared.exe")
                    .ok_or("未检测到 cloudflared，请先安装")?;
                validate_provider(settings)?;
                let mut cmd = command(&exe);
                cmd.arg("tunnel").arg("--no-autoupdate").args([
                    "--url",
                    &format!("http://127.0.0.1:{port}"),
                    "run",
                    &settings.tunnel_id,
                ]);
                cmd.stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
                let child = cmd
                    .spawn()
                    .map_err(|e| format!("cloudflared 启动失败：{}", e.kind()))?;
                #[cfg(windows)]
                {
                    self.child_job = Some(
                        crate::core::job::ChildJob::attach_tokio(&child)
                            .map_err(|_| "无法建立隧道子进程退出保护，已取消启动")?,
                    );
                }
                self.child = Some(child);
                self.current = settings.clone();
                self.port = port;
                self.owned = true;
            }
        }
        self.observe().await
    }
    pub async fn stop(&mut self) -> Result<(), String> {
        if self.profile.is_development() {
            self.owned = false;
            return Ok(());
        }
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
            if tokio::time::timeout(Duration::from_secs(3), child.wait())
                .await
                .is_err()
            {
                self.child = Some(child);
                return Err("隧道子进程停止超时，文件服务将单独停止".into());
            }
        }
        #[cfg(windows)]
        {
            self.child_job.take();
        }
        if self.owned && self.current.kind == ProviderKind::Tailscale {
            let exe =
                discover_executable("tailscale.exe").ok_or("Tailscale 工具不可用，无法清理入口")?;
            let raw = run_cli(&exe, &["funnel", "status", "--json"]).await?;
            let cfg: Value =
                serde_json::from_str(&raw).map_err(|_| "无法确认隧道归属，未撤销入口")?;
            ensure_exclusive_mapping(&cfg, self.port)?;
            if has_mapping(&cfg, self.port) {
                run_cli(&exe, &["funnel", "--https=443", "off"]).await?;
            }
        }
        let was_owned = self.owned;
        self.owned = false;
        if was_owned && self.owner_path().exists() {
            std::fs::remove_file(self.owner_path())
                .map_err(|_| "入口已停止，但归属记录清理失败")?;
        }
        Ok(())
    }
    pub async fn observe(&mut self) -> Result<TunnelObservation, String> {
        if self.profile.is_development() {
            return Ok(TunnelObservation::simulated(self.owned));
        }
        match self.current.kind {
            ProviderKind::Tailscale => observe_tailscale(self.port).await,
            ProviderKind::CloudflareNamed => {
                let running = match self.child.as_mut() {
                    Some(child) => child
                        .try_wait()
                        .map_err(|_| "无法检查 cloudflared 进程")?
                        .is_none(),
                    None => false,
                };
                let url = Some(format!("https://{}", self.current.hostname));
                Ok(TunnelObservation {
                    configured: running,
                    online: running,
                    url,
                    note: if running {
                        "隧道进程运行中；公网来源尚未验证".into()
                    } else {
                        "隧道进程已退出".into()
                    },
                })
            }
        }
    }
    pub fn adopt_pending_owner(&mut self, settings: &ProviderSettings, port: u16) {
        self.port = port;
        self.current = settings.clone();
        if let Ok(raw) = std::fs::read(self.owner_path())
            && let Ok(owner) = serde_json::from_slice::<Owner>(&raw)
            && owner.provider == settings.kind
            && owner.port == port
        {
            self.owned = true;
            self.port = port;
            self.current = settings.clone();
        }
    }
    pub fn is_owned(&self) -> bool {
        self.owned
    }
    pub(crate) fn is_live_tailscale(&self, port: u16) -> bool {
        self.owned && self.current.kind == ProviderKind::Tailscale && self.port == port
    }
}

pub(crate) async fn observe_tailscale(port: u16) -> Result<TunnelObservation, String> {
    let exe = discover_executable("tailscale.exe").ok_or("未安装 Tailscale")?;
    let raw = run_cli(&exe, &["funnel", "status", "--json"]).await?;
    let cfg: Value = serde_json::from_str(&raw).map_err(|_| "Tailscale 状态未知：配置解析失败")?;
    let configured = has_mapping(&cfg, port);
    let node: Value = serde_json::from_str(&run_cli(&exe, &["status", "--json"]).await?)
        .map_err(|_| "节点状态解析失败")?;
    let online = node["BackendState"] == "Running" && node["Self"]["Online"] == true;
    let url = cfg["Web"].as_object().and_then(|web| {
        web.iter()
            .find(|(host, v)| {
                host.ends_with(":443")
                    && v["Handlers"]["/"]["Proxy"] == format!("http://127.0.0.1:{}", port)
            })
            .map(|(host, _)| format!("https://{}", host.trim_end_matches(":443")))
    });
    Ok(TunnelObservation {
        configured,
        online,
        url,
        note: if !online {
            "Tailscale 节点未在线".into()
        } else if !configured {
            "隧道映射与当前 API 不一致".into()
        } else {
            "隧道已配置；公网来源尚未验证".into()
        },
    })
}

pub fn validate_provider(settings: &ProviderSettings) -> Result<(), String> {
    if settings.kind == ProviderKind::CloudflareNamed {
        if settings.tunnel_id.is_empty()
            || settings.tunnel_id.len() > 100
            || !settings
                .tunnel_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err("请输入有效的隧道 ID 或名称".into());
        }
        let hostname = &settings.hostname;
        if hostname.len() > 253
            || !hostname.contains('.')
            || !hostname.split('.').all(|s| {
                !s.is_empty()
                    && s.len() <= 63
                    && !s.starts_with('-')
                    && !s.ends_with('-')
                    && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            })
        {
            return Err("请输入不含协议、端口或路径的域名".into());
        }
    }
    Ok(())
}
fn has_mapping(cfg: &Value, port: u16) -> bool {
    cfg["TCP"]["443"]["HTTPS"] == true
        && cfg["Web"].as_object().is_some_and(|web| {
            web.iter().any(|(host, v)| {
                host.ends_with(":443")
                    && v["Handlers"]["/"]["Proxy"] == format!("http://127.0.0.1:{port}")
                    && cfg["AllowFunnel"][host] == true
            })
        })
}
pub(crate) fn ensure_exclusive_mapping(cfg: &Value, port: u16) -> Result<(), String> {
    let object = cfg
        .as_object()
        .ok_or("Tailscale 返回了未知结构，未改变转发")?;
    if !object.is_empty()
        && !["Web", "TCP", "AllowFunnel"]
            .iter()
            .any(|key| object.contains_key(*key))
    {
        return Err("Tailscale 配置结构未知，未改变转发".into());
    }
    if object.get("Web").is_some_and(|v| !v.is_object()) {
        return Err("Tailscale 路由结构无效".into());
    }
    if let Some(web) = cfg["Web"].as_object() {
        for (host, entry) in web {
            if !host.ends_with(":443") {
                continue;
            }
            if let Some(handlers) = entry["Handlers"].as_object() {
                for (path, handler) in handlers {
                    if path != "/" || handler["Proxy"] != format!("http://127.0.0.1:{port}") {
                        return Err("443 入口含其他应用的转发，已拒绝覆盖或撤销".into());
                    }
                }
            } else {
                return Err("443 路由结构未知，未改变转发".into());
            }
        }
    }
    if cfg["TCP"]["443"].get("TCPForward").is_some() {
        return Err("443 正被其他 TCP 转发使用".into());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mapping_checks_target_and_rejects_foreign_handlers() {
        assert!(ensure_exclusive_mapping(&json!(null), 18790).is_err());
        assert!(ensure_exclusive_mapping(&json!({"unexpected":true}), 18790).is_err());
        assert!(ensure_exclusive_mapping(&json!({"Web":[]}), 18790).is_err());
        let cfg = json!({"TCP":{"443":{"HTTPS":true}},"Web":{"example.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:18790"}}}},"AllowFunnel":{"example.ts.net:443":true}});
        assert!(has_mapping(&cfg, 18790));
        assert!(!has_mapping(&cfg, 18795));
        assert!(ensure_exclusive_mapping(&cfg, 18795).is_err());
        let foreign = json!({"Web":{"example.ts.net:443":{"Handlers":{"/other":{"Proxy":"http://127.0.0.1:1234"}}}}});
        assert!(ensure_exclusive_mapping(&foreign, 18790).is_err());
    }
    #[cfg(windows)]
    #[tokio::test]
    async fn closing_our_job_terminates_our_child() {
        let system =
            PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32/ping.exe");
        let mut child = command(&system)
            .args(["-n", "120", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let job = crate::core::job::ChildJob::attach_tokio(&child).unwrap();
        assert!(child.try_wait().unwrap().is_none());
        drop(job);
        // Windows may use exit code 0 when closing a kill-on-close job.
        // A 120-second child finishing within this bound proves containment.
        let _result = tokio::time::timeout(Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap();
    }
}
