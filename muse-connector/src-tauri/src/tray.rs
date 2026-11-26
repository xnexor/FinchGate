//! 托盘使用统一的应用图标；连接状态显示在提示和菜单中。
use crate::{
    Services,
    profile::Language,
    tunnel::{Health, TunnelStatus},
};
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager};
struct TrayItems {
    toggle: MenuItem<tauri::Wry>,
    status: MenuItem<tauri::Wry>,
    show: MenuItem<tauri::Wry>,
    quit: MenuItem<tauri::Wry>,
}
pub fn build_tray(app: &AppHandle) -> tauri::Result<()> {
    let status = MenuItem::with_id(app, "status", "", false, None::<&str>)?;
    let toggle = MenuItem::with_id(app, "toggle", "", true, None::<&str>)?;
    let show = MenuItem::with_id(app, "show", "", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, "quit", "", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&status, &toggle, &show, &sep, &quit])?;
    app.manage(TrayItems {
        toggle,
        status,
        show,
        quit,
    });
    TrayIconBuilder::with_id("main")
        .icon(tauri::include_image!("icons/32x32.png"))
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "show" => show_main(app),
            "quit" => app.exit(0),
            "toggle" => {
                let state = app.state::<Services>().inner().clone();
                tauri::async_runtime::spawn(async move {
                    let enable = !state.desktop_state().desired_enabled;
                    if let Err(e) = state.toggle(enable).await {
                        state.logs.runtime_entry("error", &e);
                    }
                });
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        })
        .build(app)?;
    refresh(app);
    Ok(())
}
pub fn spawn_status_watcher(app: AppHandle, mut rx: tokio::sync::watch::Receiver<TunnelStatus>) {
    tauri::async_runtime::spawn(async move {
        while rx.changed().await.is_ok() {
            refresh(&app);
        }
    });
}
pub fn refresh(app: &AppHandle) {
    let state = app.state::<Services>();
    let language = state.desktop_state().language;
    let status = state.status();
    let health = health_label(&status.health, language);
    if let Some(tray) = app.tray_by_id("main") {
        let mut tooltip = format!("{} · {health}", language.product_name());
        if language == Language::Chinese {
            tooltip.push('\n');
            tooltip.push_str(&status.note);
        }
        let _ = tray.set_tooltip(Some(tooltip));
    }
    let items = app.state::<TrayItems>();
    let _ = items.status.set_text(if language == Language::English {
        format!("Status: {health}")
    } else {
        format!("状态：{health}")
    });
    let _ = items.toggle.set_text(if status.enabled {
        language.text("暂停连接", "Pause connection")
    } else {
        language.text("开启连接", "Start connection")
    });
    let _ = items.toggle.set_enabled(!matches!(
        status.health,
        Health::Starting | Health::Stopping
    ));
    let _ = items
        .show
        .set_text(language.text("打开主窗口", "Open main window"));
    let _ = items.quit.set_text(language.text("退出", "Quit"));
}

fn health_label(health: &Health, language: Language) -> &'static str {
    match health {
        Health::Up => language.text("连接已配置", "Connection configured"),
        Health::Degraded => language.text("需要检查", "Needs attention"),
        Health::Down => language.text("文件服务异常", "File service error"),
        Health::Paused => language.text("本应用已暂停", "Paused"),
        Health::Unknown => language.text("尚未探测", "Unchecked"),
        Health::Starting => language.text("正在开启", "Starting"),
        Health::Stopping => language.text("正在暂停", "Pausing"),
        Health::Conflict => language.text("端口冲突", "Port conflict"),
    }
}
pub fn show_main(app: &AppHandle) {
    let handle = app.clone();
    if let Err(error) = app.run_on_main_thread(move || {
        let Some(state) = handle.try_state::<Services>() else {
            return;
        };
        if state.exiting.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        if let Err(error) = open_main(&handle) {
            state
                .logs
                .runtime_entry("error", &format!("无法打开主窗口：{error}"));
        }
    }) && let Some(state) = app.try_state::<Services>()
    {
        state
            .logs
            .runtime_entry("error", &format!("无法调度主窗口：{error}"));
    }
}

pub(crate) fn open_main(app: &AppHandle) -> tauri::Result<tauri::WebviewWindow> {
    let window = if let Some(window) = app.get_webview_window("main") {
        window
    } else {
        let config = app
            .config()
            .app
            .windows
            .iter()
            .find(|window| window.label == "main")
            .expect("main window is configured");
        tauri::WebviewWindowBuilder::from_config(app, config)?.build()?
    };
    let state = app.state::<Services>();
    let _ = window.set_title(&state.profile.window_title(state.desktop_state().language));
    window.unminimize()?;
    window.show()?;
    let _ = window.emit("desktop-visibility", true);
    let _ = window.set_focus();
    Ok(window)
}
