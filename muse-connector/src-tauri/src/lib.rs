//! Muse 连接器桌面壳：所有生命周期操作委托给同一服务监督层。
pub mod capabilities;
#[cfg(windows)]
mod clipboard;
pub mod core;
mod legacy;
pub mod profile;
pub mod service;
mod tray;
mod tunnel;
use profile::{Language, ProviderSettings, RuntimeProfile};
use serde_json::{Value, json};
use service::ServiceController;
use std::sync::{Arc, atomic::Ordering};
use std::time::Duration;
use tauri::{Emitter, Manager};
use tauri_plugin_autostart::ManagerExt as AutostartExt;
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_opener::OpenerExt;
use tauri_plugin_updater::UpdaterExt;
type Services = Arc<ServiceController>;

#[tauri::command]
fn get_snapshot(
    app: tauri::AppHandle,
    state: tauri::State<'_, Services>,
    refresh_dependencies: Option<bool>,
) -> Value {
    if refresh_dependencies == Some(true) {
        state.invalidate_tool_status();
    }
    let mut result = serde_json::to_value(state.snapshot()).unwrap();
    result["autostart"] = if state.profile.is_development() {
        Value::Null
    } else {
        app.autolaunch()
            .is_enabled()
            .map(Value::Bool)
            .unwrap_or(Value::Null)
    };
    result["update_configured"] = json!(update_configuration().is_some());
    result
}
#[tauri::command]
fn get_status(state: tauri::State<'_, Services>) -> tunnel::TunnelStatus {
    state.status()
}
#[tauri::command]
fn get_stats(state: tauri::State<'_, Services>) -> Value {
    state.api.stats_snapshot()
}
#[tauri::command]
fn get_config(state: tauri::State<'_, Services>) -> core::config::BridgeConfig {
    state.api.file_view()
}
#[tauri::command]
fn get_logs(
    kind: String,
    after: Option<u64>,
    state: tauri::State<'_, Services>,
) -> Result<core::audit::LogBatch, String> {
    match kind.as_str() {
        "audit" => Ok(state.api.audit().recent(after, 1000)),
        "runtime" => Ok(state.logs.recent(after, 1000)),
        _ => Err("未知日志类型".into()),
    }
}
#[tauri::command]
async fn toggle_connection(
    enable: bool,
    state: tauri::State<'_, Services>,
) -> Result<tunnel::TunnelStatus, String> {
    state.toggle(enable).await
}
#[tauri::command]
async fn save_config(
    config: core::config::BridgeConfig,
    state: tauri::State<'_, Services>,
) -> Result<(), String> {
    state.configure(config).await
}
#[tauri::command]
async fn save_file_access(
    policy: core::access::AccessPolicy,
    edit: service::FileAccessEdit,
    state: tauri::State<'_, Services>,
) -> Result<(), String> {
    state.save_file_access_edit(policy, Some(edit)).await
}

#[tauri::command]
async fn list_local_disks(state: tauri::State<'_, Services>) -> Result<Vec<String>, String> {
    let controller = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || controller.local_disk_aliases())
        .await
        .map_err(|_| "无法读取本机磁盘列表".into())
}
#[tauri::command]
async fn clear_search_index(state: tauri::State<'_, Services>) -> Result<(), String> {
    state.clear_search_index().await
}
#[tauri::command]
async fn rebuild_search_index(state: tauri::State<'_, Services>) -> Result<(), String> {
    state.rebuild_search_index().await
}
#[tauri::command]
async fn set_agent_access(enabled: bool, state: tauri::State<'_, Services>) -> Result<(), String> {
    state.set_agent_access(enabled).await
}
#[tauri::command]
async fn set_exec_enabled(enabled: bool, state: tauri::State<'_, Services>) -> Result<(), String> {
    state.set_exec_enabled(enabled).await
}
#[tauri::command]
fn resolve_exec_approval(
    id: String,
    decision: core::exec_runtime::ApprovalDecision,
    state: tauri::State<'_, Services>,
) -> Result<bool, String> {
    state.resolve_exec_approval(&id, decision)
}
#[tauri::command]
fn revoke_exec_sessions(state: tauri::State<'_, Services>) {
    state.revoke_exec_sessions();
}
#[tauri::command]
fn open_agent_token(
    app: tauri::AppHandle,
    state: tauri::State<'_, Services>,
) -> Result<(), String> {
    app.opener()
        .reveal_item_in_dir(state.agent_token_path()?)
        .map_err(|_| "无法找到本机 Muse 文件工具令牌".into())
}
#[tauri::command]
fn copy_agent_token(
    window: tauri::WebviewWindow,
    state: tauri::State<'_, Services>,
) -> Result<(), String> {
    #[cfg(windows)]
    {
        let owner = window.hwnd().map_err(|_| "无法读取连接器窗口")?;
        clipboard::copy_secret(owner.0, &state.current_agent_token()?).map_err(str::to_owned)
    }
    #[cfg(not(windows))]
    {
        let _ = (window, state);
        Err("请从令牌文件手动复制".into())
    }
}
#[tauri::command]
async fn search_local_files(
    request: core::search::SearchRequest,
    state: tauri::State<'_, Services>,
) -> Result<core::search::SearchResponse, String> {
    state.search_local_files(request).await
}
#[tauri::command]
fn cancel_local_file_search(state: tauri::State<'_, Services>) {
    state.cancel_local_file_search();
}
#[tauri::command]
async fn save_provider(
    provider: ProviderSettings,
    state: tauri::State<'_, Services>,
) -> Result<(), String> {
    state.set_provider(provider).await
}
#[tauri::command]
async fn rotate_file_token(state: tauri::State<'_, Services>) -> Result<(), String> {
    let api = state.api.clone();
    tokio::task::spawn_blocking(move || api.rotate_token())
        .await
        .map_err(|_| "文件令牌轮换未完成".to_string())??;
    state
        .logs
        .runtime_entry("info", "文件令牌已轮换，请在本机更新安全卡片");
    Ok(())
}
#[tauri::command]
async fn save_preferences(
    close_to_tray: Option<bool>,
    start_minimized: Option<bool>,
    state: tauri::State<'_, Services>,
) -> Result<(), String> {
    state
        .save_window_preferences(close_to_tray, start_minimized)
        .await
}
#[tauri::command]
async fn save_device_name(
    name: String,
    update_muse: bool,
    state: tauri::State<'_, Services>,
) -> Result<Option<profile::DeviceNameUpdate>, String> {
    state.save_device_name(name, update_muse).await
}
#[tauri::command]
fn confirm_device_name(id: String, state: tauri::State<'_, Services>) -> Result<(), String> {
    if state.confirm_device_name(&id)? {
        Ok(())
    } else {
        Err("这次改名已被更新，请查看当前设备名称。".into())
    }
}
#[tauri::command]
async fn set_language(
    language: Language,
    app: tauri::AppHandle,
    state: tauri::State<'_, Services>,
) -> Result<(), String> {
    state.save_language(language).await?;
    tray::refresh(&app);
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.set_title(&state.profile.window_title(state.desktop_state().language));
    }
    Ok(())
}
#[tauri::command]
fn set_autostart(
    enable: bool,
    app: tauri::AppHandle,
    state: tauri::State<'_, Services>,
) -> Result<bool, String> {
    state.profile.require_production()?;
    if enable {
        app.autolaunch().enable()
    } else {
        app.autolaunch().disable()
    }
    .map_err(|_| "登录自启设置失败".to_string())?;
    let actual = app
        .autolaunch()
        .is_enabled()
        .map_err(|_| "无法核实自启状态")?;
    if actual != enable {
        return Err("系统自启状态与请求不一致".into());
    }
    Ok(actual)
}
#[tauri::command]
async fn pick_directory(
    app: tauri::AppHandle,
    state: tauri::State<'_, Services>,
) -> Result<Option<String>, String> {
    let profile = state.profile.clone();
    let language = state.desktop_state().language;
    tauri::async_runtime::spawn_blocking(move || {
        let mut dialog = app.dialog().file().set_title(language.text(
            "选择允许 Muse 访问的目录",
            "Choose a folder Muse can access",
        ));
        if profile.onboarding_qa {
            dialog = dialog.set_directory(profile.home.join("files"));
        }
        dialog
            .blocking_pick_folder()
            .map(|p| {
                p.into_path()
                    .map(|p| p.to_string_lossy().into_owned())
                    .map_err(|_| "无法转换选择的目录".to_string())
            })
            .transpose()
    })
    .await
    .map_err(|_| "目录选择器未能完成".to_string())?
}
#[tauri::command]
fn open_local_folder(
    app: tauri::AppHandle,
    state: tauri::State<'_, Services>,
) -> Result<(), String> {
    app.opener()
        .open_path(state.profile.home.to_string_lossy(), None::<&str>)
        .map_err(|_| "无法打开本机配置文件夹".into())
}
#[tauri::command]
fn open_index_folder(
    app: tauri::AppHandle,
    state: tauri::State<'_, Services>,
) -> Result<(), String> {
    let path = state.index_folder_path();
    app.opener()
        .open_path(path.to_string_lossy(), None::<&str>)
        .map_err(|_| "无法打开索引目录".into())
}
#[tauri::command]
async fn clear_logs(
    app: tauri::AppHandle,
    state: tauri::State<'_, Services>,
) -> Result<(), String> {
    state.clear_logs().await?;
    let _ = app.emit("bridge-log-gap", ());
    Ok(())
}
#[tauri::command]
fn open_logs_folder(
    kind: Option<String>,
    app: tauri::AppHandle,
    state: tauri::State<'_, Services>,
) -> Result<(), String> {
    let preferred = if kind.as_deref() == Some("runtime") {
        state.profile.home.join("server.log")
    } else {
        state.profile.home.join("audit.log")
    };
    if preferred.is_file() {
        app.opener()
            .reveal_item_in_dir(&preferred)
            .map_err(|_| "无法定位日志文件".into())
    } else {
        app.opener()
            .open_path(state.profile.home.to_string_lossy(), None::<&str>)
            .map_err(|_| "无法打开日志目录".into())
    }
}
#[tauri::command]
async fn export_logs(
    default_name: String,
    format: String,
    content: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, Services>,
) -> Result<Option<String>, String> {
    const MAX_EXPORT_BYTES: usize = 16 * 1024 * 1024;
    if content.len() > MAX_EXPORT_BYTES {
        return Err("导出内容过大，请缩小筛选范围后重试".into());
    }
    let (ext, filter_name) = match format.as_str() {
        "jsonl" => ("jsonl", "JSON Lines (*.jsonl)"),
        "csv" => ("csv", "CSV (*.csv)"),
        _ => return Err("不支持的导出格式".into()),
    };
    let clean_name: String = default_name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(96)
        .collect();
    let file_name = if clean_name.is_empty() {
        format!("muselink-logs.{ext}")
    } else if clean_name
        .to_ascii_lowercase()
        .ends_with(&format!(".{ext}"))
    {
        clean_name
    } else {
        format!("{clean_name}.{ext}")
    };
    let language = state.desktop_state().language;
    let redacted = state
        .logs
        .redact_text(&state.api.audit().redact_text(&content));
    tauri::async_runtime::spawn_blocking(move || {
        let picked = app
            .dialog()
            .file()
            .set_title(language.text("导出日志", "Export logs"))
            .set_file_name(&file_name)
            .add_filter(filter_name, &[ext])
            .blocking_save_file();
        let Some(target) = picked else {
            return Ok(None);
        };
        let mut path = target
            .into_path()
            .map_err(|_| "无法解析导出文件路径".to_string())?;
        if path.extension().is_none() {
            path.set_extension(ext);
        }
        std::fs::write(&path, redacted.as_bytes())
            .map_err(|_| "写入导出文件失败，请检查目标目录权限".to_string())?;
        Ok(Some(path.to_string_lossy().into_owned()))
    })
    .await
    .map_err(|_| "导出日志任务未完成".to_string())?
}
#[tauri::command]
async fn check_legacy(state: tauri::State<'_, Services>) -> Result<legacy::LegacyState, String> {
    let profile = state.profile.clone();
    tauri::async_runtime::spawn_blocking(move || legacy::check_legacy(&profile))
        .await
        .map_err(|_| "旧系统检测未完成".to_string())?
}
async fn prior_funnel() -> Option<Value> {
    let exe = tunnel::discover_executable("tailscale.exe")?;
    serde_json::from_str(
        &tunnel::run_cli(&exe, &["funnel", "status", "--json"])
            .await
            .ok()?,
    )
    .ok()
}
#[tauri::command]
async fn takeover_legacy(state: tauri::State<'_, Services>) -> Result<(), String> {
    state.profile.require_production()?;
    state.toggle(false).await?;
    let profile = state.profile.clone();
    let old = prior_funnel().await;
    tauri::async_runtime::spawn_blocking(move || legacy::takeover(&profile, old))
        .await
        .map_err(|_| "旧系统接管任务中断".to_string())??;
    for _ in 0..20 {
        if tokio::net::TcpStream::connect(("127.0.0.1", state.api.config_snapshot().port))
            .await
            .is_err()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    if let Err(error) = state.toggle(true).await {
        let _ = state.toggle(false).await;
        let profile = state.profile.clone();
        let restored =
            tauri::async_runtime::spawn_blocking(move || legacy::restore(&profile)).await;
        if let Ok(Ok(record)) = restored {
            if legacy::restore_funnel(&record).await.is_ok() {
                let _ = legacy::mark_restored(&state.profile);
            }
        }
        return Err(format!(
            "内置服务接管失败：{error}；已尝试按快照恢复，请核对旧系统状态"
        ));
    }
    legacy::mark_active(&state.profile)?;
    state
        .logs
        .runtime_entry("info", "旧系统已接管，等待 Muse 实际读写验收");
    Ok(())
}
#[tauri::command]
async fn restore_legacy(state: tauri::State<'_, Services>) -> Result<(), String> {
    state.profile.require_production()?;
    state.toggle(false).await?;
    let profile = state.profile.clone();
    let record = tauri::async_runtime::spawn_blocking(move || legacy::restore(&profile))
        .await
        .map_err(|_| "旧系统恢复任务中断".to_string())??;
    legacy::restore_funnel(&record).await?;
    legacy::mark_restored(&state.profile)?;
    state.logs.runtime_entry(
        "info",
        "旧系统已按原 Enabled/Running 状态恢复，桌面服务保持暂停",
    );
    Ok(())
}
#[tauri::command]
fn open_tool_setup(tool: String, app: tauri::AppHandle) -> Result<(), String> {
    let url = match tool.as_str() {
        "tailscale" => "https://tailscale.com/download/windows",
        "tailscale_login" => "https://tailscale.com/docs/install/windows",
        "tailscale_funnel" => "https://tailscale.com/docs/features/tailscale-funnel#enable-funnel",
        "cloudflared" => {
            "https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
        }
        "domains" => "https://dash.cloudflare.com/",
        "everything" => "https://www.voidtools.com/support/everything/installing_everything/",
        _ => return Err("未知帮助入口".into()),
    };
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|_| "无法打开帮助页面".into())
}
#[tauri::command]
async fn cloudflare_action(
    action: String,
    name: Option<String>,
    hostname: Option<String>,
    state: tauri::State<'_, Services>,
) -> Result<Value, String> {
    state.profile.require_production()?;
    let exe = tunnel::discover_executable("cloudflared.exe").ok_or("请先安装 cloudflared")?;
    match action.as_str() {
        "login" => {
            let mut cmd = tunnel::command(&exe);
            cmd.args(["tunnel", "login"])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            let result = tokio::time::timeout(Duration::from_secs(180), cmd.status())
                .await
                .map_err(|_| "授权等待超时，请在浏览器完成后重试")?
                .map_err(|_| "无法启动浏览器授权")?;
            if !result.success() {
                return Err("Cloudflare 登录未完成，请检查浏览器授权和域名账户".into());
            }
            Ok(json!({"message":"授权已完成，请刷新隧道列表"}))
        }
        "list" => {
            let raw = tunnel::run_cli(&exe, &["tunnel", "list", "--output", "json"]).await?;
            let tunnels: Vec<Value> = serde_json::from_str(&raw).map_err(|_| "隧道列表解析失败")?;
            Ok(
                json!({"tunnels":tunnels.iter().map(|v|json!({"id":v["id"],"name":v["name"]})).collect::<Vec<_>>() }),
            )
        }
        "create" => {
            let name = name.ok_or("请输入新隧道名称")?;
            if name.is_empty()
                || name.len() > 64
                || !name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return Err("隧道名称仅使用英文字母、数字、短横线和下划线".into());
            }
            tunnel::run_cli(&exe, &["tunnel", "create", &name]).await?;
            Ok(json!({"message":"隧道已创建，请刷新列表选择；凭证仅由 cloudflared 保存于本机"}))
        }
        "route" => {
            let settings = ProviderSettings {
                kind: profile::ProviderKind::CloudflareNamed,
                tunnel_id: name.ok_or("请选择隧道")?,
                hostname: hostname.ok_or("请输入主机名")?,
            };
            tunnel::validate_provider(&settings)?;
            tunnel::run_cli(
                &exe,
                &[
                    "tunnel",
                    "route",
                    "dns",
                    &settings.tunnel_id,
                    &settings.hostname,
                ],
            )
            .await?;
            Ok(json!({"message":"主机名绑定完成，可以保存并测试连接"}))
        }
        _ => Err("未知连接向导操作".into()),
    }
}
#[tauri::command]
async fn test_public_connection(
    agent: Option<bool>,
    state: tauri::State<'_, Services>,
) -> Result<Value, String> {
    state.profile.require_production()?;
    let status = state.status();
    if !status.api_up || !status.funnel_up {
        return Err("请先开启并配置连接".into());
    }
    let url = status.url.as_ref().ok_or("尚未取得公网地址")?;
    let parsed = reqwest::Url::parse(&url).map_err(|_| "公网地址无效")?;
    if parsed.scheme() != "https"
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err("公网测试只允许经过 TLS 的已配置入口".into());
    }
    let client = public_http_client()?;
    let agent_context = if agent.unwrap_or(false) {
        Some(state.agent_probe_context().await?)
    } else {
        None
    };
    let (route, credential) = match &agent_context {
        Some((token, _)) => ("/agent/v1/roots", token.clone()),
        None => ("/api/health", state.api.token()),
    };
    let endpoint = parsed.join(route).map_err(|_| "公网地址无效")?;
    let result = async {
        let mut response = client
            .get(endpoint)
            .bearer_auth(&credential)
            .send()
            .await
            .map_err(|_| "公网请求失败，请检查网络、DNS 和证书")?;
        if response.status() != reqwest::StatusCode::OK {
            return Err("公网入口没有返回成功健康响应");
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| "公网响应读取失败")? {
            if bytes.len() + chunk.len() > 65536 {
                return Err("公网响应超出健康接口限制");
            }
            bytes.extend_from_slice(&chunk);
        }
        let body: Value =
            serde_json::from_slice(&bytes).map_err(|_| "公网响应不是文件服务 JSON")?;
        let matches_protocol = if agent_context.is_some() {
            body["version"] == "1"
                && ["search", "read", "write"]
                    .iter()
                    .all(|operation| body["roots"][*operation].is_array())
        } else {
            body["ok"] == true && body["version"] == "0.3"
        };
        if !matches_protocol {
            return Err("公网响应与文件协议不匹配");
        }
        Ok(())
    }
    .await;
    if let Some((token, policy)) = agent_context {
        state
            .mark_agent_public_result(&status, &token, &policy, result.is_ok())
            .await?;
        return result
            .map(|()| json!({"message":"Muse 专用令牌的公网验证通过"}))
            .map_err(str::to_owned);
    }
    match result {
        Ok(()) => {
            state.mark_public_result(
                &status,
                true,
                "公网健康接口已验证；仍需 Muse 来源端读写验收",
            )?;
            Ok(json!({"message":"公网健康接口验证通过，尚未代替 Muse 读写验收"}))
        }
        Err(e) => {
            state.mark_public_result(&status, false, e)?;
            Err(e.into())
        }
    }
}
fn public_http_client() -> Result<reqwest::Client, String> {
    // reqwest's rustls-no-provider requires an explicit process provider even
    // when ring was already enabled transitively by the updater dependency.
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| "无法初始化 TLS 客户端".into())
}
fn update_configuration() -> Option<(String, String)> {
    let endpoint = std::env::var("MUSE_CONNECTOR_UPDATE_ENDPOINT").ok()?;
    let key = std::env::var("MUSE_CONNECTOR_UPDATE_PUBLIC_KEY").ok()?;
    parse_update_configuration(endpoint, key)
}
fn parse_update_configuration(endpoint: String, key: String) -> Option<(String, String)> {
    if key.trim().is_empty() {
        return None;
    }
    let parsed = reqwest::Url::parse(&endpoint).ok()?;
    if parsed.scheme() != "https" || !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }
    Some((endpoint, key))
}
#[tauri::command]
async fn check_updates(app: tauri::AppHandle) -> Result<Value, String> {
    let Some((endpoint, key)) = update_configuration() else {
        return Ok(
            json!({"configured":false,"available":false,"message":"自动更新尚未配置，请使用新版安装包更新"}),
        );
    };
    let updater = app
        .updater_builder()
        .pubkey(key)
        .endpoints(vec![endpoint.parse().map_err(|_| "更新源地址无效")?])
        .map_err(|_| "更新源必须使用 HTTPS")?
        .timeout(Duration::from_secs(15))
        .build()
        .map_err(|_| "更新配置无效")?;
    match updater
        .check()
        .await
        .map_err(|_| "更新检查失败，请检查来源和网络")?
    {
        Some(update) => Ok(
            json!({"configured":true,"available":true,"version":update.version,"notes":update.body}),
        ),
        None => Ok(json!({"configured":true,"available":false,"message":"当前已是最新版本"})),
    }
}
#[tauri::command]
async fn install_update(
    app: tauri::AppHandle,
    state: tauri::State<'_, Services>,
) -> Result<(), String> {
    state.profile.require_production()?;
    let (endpoint, key) = update_configuration().ok_or("更新源尚未配置")?;
    let updater = app
        .updater_builder()
        .pubkey(key)
        .endpoints(vec![endpoint.parse().map_err(|_| "更新源地址无效")?])
        .map_err(|_| "更新源配置无效")?
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| "更新配置无效")?;
    let update = updater
        .check()
        .await
        .map_err(|_| "重新检查更新失败")?
        .ok_or("没有可安装更新")?;
    let bytes = update
        .download(
            move |_, _| {
                let _ = app.emit("update-progress", "正在下载并校验更新");
            },
            || {},
        )
        .await
        .map_err(|_| "更新下载或签名校验失败，当前连接保持原状态".to_string())?;
    state.suspend_for_update().await?;
    match update.install(bytes) {
        Ok(()) => Ok(()),
        Err(_) => {
            state.resume_after_update_failure().await;
            Err("更新安装失败，已尝试恢复原连接；也可使用安装包更新".into())
        }
    }
}
#[cfg(test)]
mod updater_tests {
    use super::*;
    #[test]
    fn public_tls_client_constructs_without_first_checking_updates() {
        assert!(public_http_client().is_ok());
        assert!(rustls::crypto::CryptoProvider::get_default().is_some());
    }
    #[test]
    fn update_config_and_release_metadata_fail_closed() {
        assert!(
            parse_update_configuration("http://example.com/update".into(), "key".into()).is_none()
        );
        assert!(
            parse_update_configuration(
                "https://user:secret@example.com/update".into(),
                "key".into()
            )
            .is_none()
        );
        assert!(
            parse_update_configuration("https://example.com/update".into(), " ".into()).is_none()
        );
        assert!(
            parse_update_configuration("https://example.com/update".into(), "key".into()).is_some()
        );
        let valid = json!({"version":"v0.2.0","platforms":{"windows-x86_64":{"url":"https://example.com/installer.exe","signature":"disposable-invalid-signature"}}});
        let parsed: tauri_plugin_updater::RemoteRelease = serde_json::from_value(valid).unwrap();
        assert_eq!(parsed.version.to_string(), "0.2.0");
        assert!(parsed.download_url("windows-aarch64").is_err());
        assert!(
            serde_json::from_value::<tauri_plugin_updater::RemoteRelease>(
                json!({"version":"invalid"})
            )
            .is_err()
        );
        assert!(
            serde_json::from_value::<tauri_plugin_updater::RemoteRelease>(
                json!({"version":"0.2.0","url":"https://example.com/update.exe"})
            )
            .is_err()
        );
    }
}
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let profile = match RuntimeProfile::discover() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return;
        }
    };
    let mut context = tauri::generate_context!();
    if profile.is_development() {
        let suffix = if profile.onboarding_qa {
            ".onboarding-qa"
        } else {
            ".development"
        };
        context.config_mut().identifier.push_str(suffix);
        if profile.onboarding_qa && std::env::var_os("MUSE_CONNECTOR_DEV_HOME").is_some() {
            context
                .config_mut()
                .identifier
                .push_str(&format!(".isolated-{}", std::process::id()));
        }
    }
    let controller = ServiceController::open(profile);
    let desktop = controller.desktop_state();
    let fresh_setup = controller.snapshot().fresh_setup;
    let launched_by_autostart = std::env::args().any(|arg| arg == "--autostart");
    if let Some(window) = context
        .config_mut()
        .app
        .windows
        .iter_mut()
        .find(|w| w.label == "main")
    {
        window.title = controller.profile.window_title(desktop.language);
        if launched_by_autostart && !fresh_setup && !controller.profile.onboarding_qa {
            window.create = false;
        }
    }
    let startup = controller.clone();
    let application = tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            tray::show_main(app)
        }))
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--autostart"]),
        ))
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.set_always_on_top(false);
                let close_to_tray = window
                    .try_state::<Services>()
                    .is_none_or(|state| state.desktop_state().close_to_tray);
                if close_to_tray {
                    if window.hide().is_ok() {
                        let _ = window.emit("desktop-visibility", false);
                    }
                    api.prevent_close();
                } else {
                    api.prevent_close();
                    window.app_handle().exit(0);
                }
            }
        })
        .setup(move |app| {
            app.manage(startup.clone());
            tray::build_tray(app.handle())?;
            tray::spawn_status_watcher(app.handle().clone(), startup.subscribe());
            let mut status = startup.subscribe();
            let handle = app.handle().clone();
            let events = startup.clone();
            tauri::async_runtime::spawn(async move {
                while status.changed().await.is_ok() {
                    if let Some(window) = handle.get_webview_window("main")
                        && window.is_visible().unwrap_or(false)
                    {
                        let _ = window.emit("bridge-snapshot", events.snapshot());
                    }
                }
            });
            for mut receiver in [startup.api.audit().subscribe(), startup.logs.subscribe()] {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    loop {
                        match receiver.recv().await {
                            Ok(record) => {
                                let _ = handle.emit("bridge-log", record);
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                                let _ = handle.emit("bridge-log-gap", ());
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
            startup.spawn_supervisor();
            startup.prewarm_file_search();
            {
                use crate::core::exec_runtime::ApprovalEvent;
                let handle = app.handle().clone();
                let events = startup.clone();
                let auto_shown = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let approval_topmost = Arc::new(std::sync::atomic::AtomicBool::new(false));
                startup.attach_approval_notifier(Arc::new(move |event| {
                    let main_handle = handle.clone();
                    let events = events.clone();
                    let auto_shown = auto_shown.clone();
                    let approval_topmost = approval_topmost.clone();
                    let _ = handle.run_on_main_thread(move || {
                        let visible = main_handle
                            .get_webview_window("main")
                            .and_then(|w| w.is_visible().ok())
                            .unwrap_or(false);
                        match event {
                            ApprovalEvent::Requested => {
                                if !visible {
                                    auto_shown.store(true, Ordering::Release);
                                }
                                if let Ok(window) = tray::open_main(&main_handle) {
                                    // Windows 后台窗口调用 SetForegroundWindow 会被系统拦截，临时置顶才能立即弹出到当前视口上方
                                    let _ = window.set_always_on_top(true);
                                    approval_topmost.store(true, Ordering::Release);
                                    let _ = window.request_user_attention(Some(
                                        tauri::UserAttentionType::Critical,
                                    ));
                                    let _ = window.set_focus();
                                    let _ = window.emit("bridge-snapshot", events.snapshot());
                                }
                            }
                            ApprovalEvent::Drained => {
                                if let Some(window) = main_handle.get_webview_window("main") {
                                    let _ = window.emit("bridge-snapshot", events.snapshot());
                                    if approval_topmost.swap(false, Ordering::AcqRel) {
                                        let _ = window.set_always_on_top(false);
                                        let _ = window.request_user_attention(None);
                                    }
                                    if auto_shown.swap(false, Ordering::AcqRel)
                                        && window.hide().is_ok()
                                    {
                                        let _ = window.emit("desktop-visibility", false);
                                    }
                                }
                            }
                            ApprovalEvent::Updated => {
                                if let Some(window) = main_handle.get_webview_window("main")
                                    && visible
                                {
                                    let _ = window.emit("bridge-snapshot", events.snapshot());
                                }
                            }
                        }
                    });
                }));
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_snapshot,
            get_status,
            get_stats,
            get_config,
            get_logs,
            toggle_connection,
            save_config,
            save_file_access,
            list_local_disks,
            clear_search_index,
            rebuild_search_index,
            set_agent_access,
            set_exec_enabled,
            resolve_exec_approval,
            revoke_exec_sessions,
            open_agent_token,
            copy_agent_token,
            search_local_files,
            cancel_local_file_search,
            save_provider,
            rotate_file_token,
            save_preferences,
            save_device_name,
            confirm_device_name,
            set_language,
            set_autostart,
            pick_directory,
            open_local_folder,
            open_index_folder,
            open_logs_folder,
            clear_logs,
            export_logs,
            check_legacy,
            takeover_legacy,
            restore_legacy,
            open_tool_setup,
            cloudflare_action,
            test_public_connection,
            check_updates,
            install_update
        ])
        .build(context)
        .expect("桌面应用初始化失败");
    application.run(move |app, event| {
        if let tauri::RunEvent::ExitRequested { api, .. } = event {
            if !controller.exiting.swap(true, Ordering::SeqCst) {
                api.prevent_exit();
                let service = controller.clone();
                let handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    let _ = tokio::time::timeout(Duration::from_secs(20), service.shutdown()).await;
                    handle.exit(0);
                });
            }
        }
    });
}
