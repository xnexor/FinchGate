//! 旧系统迁移事务：先停看门狗，按原 Enabled/Running 快照恢复。
use crate::profile::RuntimeProfile;
use serde::{Deserialize, Serialize};
use serde_json::Value;
const API: &str = "MuseFileBridge API";
const TUNNEL: &str = "MuseFileBridge Tunnel";
const WATCHDOG: &str = "MuseFileBridge Watchdog";
const TASKS: [&str; 3] = [WATCHDOG, API, TUNNEL];
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRecord {
    pub name: String,
    pub exists: bool,
    pub enabled: bool,
    pub running: bool,
    #[serde(default)]
    pub xml: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct TaskInfo {
    pub name: String,
    pub exists: bool,
    pub enabled: bool,
    pub running: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct LegacyState {
    pub tasks: Vec<TaskInfo>,
    pub port_occupied: bool,
    pub needs_takeover: bool,
    pub can_restore: bool,
    pub migration_phase: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationRecord {
    pub schema_version: u32,
    pub phase: String,
    pub created_at: String,
    pub tasks: Vec<TaskRecord>,
    pub prior_funnel: Option<Value>,
}
trait TaskOps {
    fn read(&self) -> Result<Vec<TaskRecord>, String>;
    fn change(&self, name: &str, action: &str) -> Result<(), String>;
}
struct WindowsTasks;
impl TaskOps for WindowsTasks {
    fn read(&self) -> Result<Vec<TaskRecord>, String> {
        let script = r#"[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$ErrorActionPreference='Stop';$items=@();foreach($name in @('MuseFileBridge Watchdog','MuseFileBridge API','MuseFileBridge Tunnel')){$t=Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue;if($null -eq $t){$items+=@{name=$name;exists=$false;enabled=$false;running=$false;xml=''}}else{$items+=@{name=$name;exists=$true;enabled=[bool]$t.Settings.Enabled;running=($t.State.ToString() -eq 'Running');xml=(Export-ScheduledTask -TaskName $name)}}};ConvertTo-Json -InputObject $items -Depth 8 -Compress"#;
        let mut cmd = std::process::Command::new("powershell.exe");
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000);
        }
        let output = cmd
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .output()
            .map_err(|_| "无法读取旧计划任务")?;
        if !output.status.success() {
            return Err("旧任务读取失败，请检查任务计划程序权限".into());
        }
        serde_json::from_slice(&output.stdout).map_err(|_| "旧任务状态解析失败".into())
    }
    fn change(&self, name: &str, action: &str) -> Result<(), String> {
        if !TASKS.contains(&name) {
            return Err("迁移记录包含未知任务，已拒绝操作".into());
        }
        let mut cmd = std::process::Command::new("schtasks.exe");
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000);
        }
        match action {
            "disable" => {
                cmd.args(["/Change", "/TN", name, "/DISABLE"]);
            }
            "enable" => {
                cmd.args(["/Change", "/TN", name, "/ENABLE"]);
            }
            "end" => {
                cmd.args(["/End", "/TN", name]);
            }
            "run" => {
                cmd.args(["/Run", "/TN", name]);
            }
            _ => return Err("未知任务操作".into()),
        };
        let output = cmd.output().map_err(|_| "无法调用任务计划程序")?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!("{name}：{action} 失败，请检查是否需要管理员权限"))
        }
    }
}
fn public_tasks(tasks: Vec<TaskRecord>) -> Vec<TaskInfo> {
    tasks
        .into_iter()
        .map(|t| TaskInfo {
            name: t.name,
            exists: t.exists,
            enabled: t.enabled,
            running: t.running,
        })
        .collect()
}
pub fn check_legacy(profile: &RuntimeProfile) -> Result<LegacyState, String> {
    let tasks = WindowsTasks.read()?;
    let port_occupied = std::net::TcpStream::connect_timeout(
        &"127.0.0.1:18790".parse().unwrap(),
        std::time::Duration::from_millis(250),
    )
    .is_ok();
    let record = read_record(profile).ok();
    Ok(LegacyState {
        needs_takeover: tasks.iter().any(|t| t.exists),
        tasks: public_tasks(tasks),
        port_occupied,
        can_restore: record.as_ref().is_some_and(|r| r.phase != "restored"),
        migration_phase: record.map(|r| r.phase),
    })
}
fn record_path(profile: &RuntimeProfile) -> std::path::PathBuf {
    profile.home.join("migration-state.json")
}
fn save_record(profile: &RuntimeProfile, record: &MigrationRecord) -> Result<(), String> {
    crate::core::storage::atomic_write(
        &record_path(profile),
        &serde_json::to_vec_pretty(record).map_err(|e| e.to_string())?,
    )
    .map_err(|_| "无法保存迁移事务，已停止后续操作".into())
}
fn read_record(profile: &RuntimeProfile) -> Result<MigrationRecord, String> {
    let record: MigrationRecord = serde_json::from_slice(
        &std::fs::read(record_path(profile)).map_err(|_| "没有可恢复的迁移快照")?,
    )
    .map_err(|_| "迁移快照损坏")?;
    if record.schema_version != 1
        || record.tasks.len() != 3
        || TASKS
            .iter()
            .any(|name| record.tasks.iter().filter(|t| t.name == *name).count() != 1)
    {
        return Err("迁移快照格式无效".into());
    }
    Ok(record)
}
fn stop_tasks(ops: &impl TaskOps, tasks: &[TaskRecord]) -> Result<(), String> {
    for name in TASKS {
        if !tasks.iter().any(|t| t.name == name && t.exists) {
            continue;
        }
        let before = ops.read()?;
        if before.iter().any(|t| t.name == name && t.enabled) {
            ops.change(name, "disable")?;
        }
        let current = ops.read()?;
        let state = current
            .iter()
            .find(|t| t.name == name)
            .ok_or("旧任务消失，迁移已停止")?;
        if state.enabled {
            return Err(format!("{name} 未实际禁用"));
        }
        if state.running {
            ops.change(name, "end")?;
        }
        let verified = ops.read()?;
        if verified
            .iter()
            .any(|t| t.name == name && (t.enabled || t.running))
        {
            return Err(format!("{name} 仍在运行或未禁用"));
        }
    }
    Ok(())
}
fn restore_tasks(ops: &impl TaskOps, tasks: &[TaskRecord]) -> Result<(), String> {
    for name in [API, TUNNEL, WATCHDOG] {
        let Some(original) = tasks.iter().find(|t| t.name == name && t.exists) else {
            continue;
        };
        let current = ops.read()?;
        let state = current
            .iter()
            .find(|t| t.name == name && t.exists)
            .ok_or("旧任务已不存在，不能按快照恢复")?;
        if !original.running && state.running {
            ops.change(name, "end")?;
        }
        let must_enable = original.enabled || (original.running && !state.running);
        if state.enabled != must_enable {
            ops.change(name, if must_enable { "enable" } else { "disable" })?;
        }
        if original.running && !state.running {
            ops.change(name, "run")?;
        }
        if !original.enabled && must_enable {
            ops.change(name, "disable")?;
        }
        let verified = ops.read()?;
        let restored = verified
            .iter()
            .find(|t| t.name == name)
            .ok_or("恢复验证时任务消失")?;
        if restored.enabled != original.enabled || restored.running != original.running {
            return Err(format!("{name} 未恢复到原状态"));
        }
    }
    Ok(())
}
pub fn takeover(profile: &RuntimeProfile, prior_funnel: Option<Value>) -> Result<(), String> {
    profile.require_production()?;
    if let Ok(existing) = read_record(profile)
        && existing.phase != "restored"
        && existing.phase != "rolled_back"
    {
        return Err("已有未结束的迁移事务，请先恢复旧版".into());
    }
    let tasks = WindowsTasks.read()?;
    if !tasks.iter().any(|t| t.exists) {
        return Err("没有发现旧计划任务，无需接管".into());
    }
    let mut record = MigrationRecord {
        schema_version: 1,
        phase: "stopping_legacy".into(),
        created_at: crate::core::audit::now_iso(),
        tasks,
        prior_funnel,
    };
    save_record(profile, &record)?;
    if let Err(error) = stop_tasks(&WindowsTasks, &record.tasks) {
        let restored = restore_tasks(&WindowsTasks, &record.tasks);
        record.phase = if restored.is_ok() {
            "rolled_back"
        } else {
            "recovery_required"
        }
        .into();
        save_record(profile, &record)?;
        return Err(format!(
            "接管失败：{error}；{}",
            if restored.is_ok() {
                "旧任务状态已恢复"
            } else {
                "恢复不完整，请查看旧任务状态"
            }
        ));
    }
    record.phase = "legacy_stopped".into();
    save_record(profile, &record)
}
pub fn mark_active(profile: &RuntimeProfile) -> Result<(), String> {
    let mut record = read_record(profile)?;
    record.phase = "active".into();
    save_record(profile, &record)
}
pub fn restore(profile: &RuntimeProfile) -> Result<MigrationRecord, String> {
    profile.require_production()?;
    let mut record = read_record(profile)?;
    record.phase = "restoring".into();
    save_record(profile, &record)?;
    if let Err(e) = restore_tasks(&WindowsTasks, &record.tasks) {
        record.phase = "recovery_required".into();
        save_record(profile, &record)?;
        return Err(e);
    }
    Ok(record)
}
pub fn mark_restored(profile: &RuntimeProfile) -> Result<(), String> {
    let mut record = read_record(profile)?;
    record.phase = "restored".into();
    save_record(profile, &record)
}
pub async fn restore_funnel(record: &MigrationRecord) -> Result<(), String> {
    let Some(cfg) = &record.prior_funnel else {
        return Ok(());
    };
    let Some(web) = cfg["Web"].as_object() else {
        return Ok(());
    };
    for (host, entry) in web {
        if cfg["AllowFunnel"][host] != true {
            continue;
        }
        let handlers = entry["Handlers"].as_object().ok_or("原隧道快照无效")?;
        if handlers.len() != 1 || !handlers.contains_key("/") {
            return Err("原转发包含复杂路径，请按快照人工恢复".into());
        }
        let target = handlers["/"]["Proxy"]
            .as_str()
            .and_then(|s| s.strip_prefix("http://127.0.0.1:"))
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or("原转发不是本机文件服务，已拒绝自动覆盖")?;
        if !host.ends_with(":443") {
            return Err("原转发端口不是 443，请人工恢复".into());
        }
        let exe = crate::tunnel::discover_executable("tailscale.exe")
            .ok_or("无法找到 Tailscale 恢复原入口")?;
        let current: Value = serde_json::from_str(
            &crate::tunnel::run_cli(&exe, &["funnel", "status", "--json"]).await?,
        )
        .map_err(|_| "无法确认当前入口")?;
        crate::tunnel::ensure_exclusive_mapping(&current, target)?;
        crate::tunnel::run_cli(
            &exe,
            &["funnel", "--bg", "--https=443", &target.to_string()],
        )
        .await?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    struct Mock {
        tasks: Mutex<Vec<TaskRecord>>,
        actions: Mutex<Vec<String>>,
        fail: Option<String>,
    }
    impl TaskOps for Mock {
        fn read(&self) -> Result<Vec<TaskRecord>, String> {
            Ok(self.tasks.lock().unwrap().clone())
        }
        fn change(&self, name: &str, action: &str) -> Result<(), String> {
            self.actions
                .lock()
                .unwrap()
                .push(format!("{name}:{action}"));
            if self.fail.as_deref() == Some(&format!("{name}:{action}")) {
                return Err("模拟失败".into());
            }
            let mut tasks = self.tasks.lock().unwrap();
            let t = tasks.iter_mut().find(|t| t.name == name).unwrap();
            match action {
                "disable" => t.enabled = false,
                "enable" => t.enabled = true,
                "run" => t.running = true,
                "end" => t.running = false,
                _ => {}
            };
            Ok(())
        }
    }
    fn original() -> Vec<TaskRecord> {
        TASKS
            .iter()
            .map(|name| TaskRecord {
                name: (*name).into(),
                exists: true,
                enabled: *name != TUNNEL,
                running: *name == API,
                xml: String::new(),
            })
            .collect()
    }
    #[test]
    fn takeover_stops_watchdog_first_and_restore_preserves_disabled_tunnel() {
        let original = original();
        let mock = Mock {
            tasks: Mutex::new(original.clone()),
            actions: Mutex::new(vec![]),
            fail: None,
        };
        stop_tasks(&mock, &original).unwrap();
        let actions = mock.actions.lock().unwrap().clone();
        assert_eq!(actions[0], format!("{WATCHDOG}:disable"));
        restore_tasks(&mock, &original).unwrap();
        let tasks = mock.read().unwrap();
        assert!(!tasks.iter().find(|t| t.name == TUNNEL).unwrap().enabled);
        assert!(tasks.iter().find(|t| t.name == API).unwrap().running);
    }
    #[test]
    fn failed_disable_does_not_continue_to_stop_api() {
        let original = original();
        let mock = Mock {
            tasks: Mutex::new(original.clone()),
            actions: Mutex::new(vec![]),
            fail: Some(format!("{WATCHDOG}:disable")),
        };
        assert!(stop_tasks(&mock, &original).is_err());
        assert!(
            mock.actions
                .lock()
                .unwrap()
                .iter()
                .all(|s| !s.starts_with(API))
        );
    }
    #[test]
    fn already_disabled_tasks_need_no_write_permission_to_take_over_or_restore() {
        let original: Vec<_> = original()
            .into_iter()
            .map(|mut t| {
                t.enabled = false;
                t.running = false;
                t
            })
            .collect();
        let mock = Mock {
            tasks: Mutex::new(original.clone()),
            actions: Mutex::new(vec![]),
            fail: None,
        };
        stop_tasks(&mock, &original).unwrap();
        restore_tasks(&mock, &original).unwrap();
        assert!(mock.actions.lock().unwrap().is_empty());
    }
}
