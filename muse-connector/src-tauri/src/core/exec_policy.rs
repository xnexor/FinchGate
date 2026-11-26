//! 受控命令执行策略：请求校验 + 智能三档风险分流（直通 / 项目会话免打扰 / 强制单次确认）。

use serde::{Deserialize, Serialize};

pub const DEFAULT_TIMEOUT_SEC: u64 = 60;
pub const MAX_TIMEOUT_SEC: u64 = 300;
pub const DEFAULT_WAIT_MS: u64 = 3_000;
pub const MAX_WAIT_MS: u64 = 10_000;
const MAX_ARGS: usize = 128;
const MAX_ARGS_BYTES: usize = 16 * 1024;
const MAX_COMMAND_BYTES: usize = 8 * 1024;
const MAX_REASON_CHARS: usize = 300;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecMode {
    #[default]
    Direct,
    Powershell,
    Cmd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    Auto,
    Session,
    Always,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExecRequest {
    pub root: String,
    pub cwd: Option<String>,
    pub mode: ExecMode,
    pub program: Option<String>,
    pub args: Vec<String>,
    pub command: Option<String>,
    pub reason: Option<String>,
    pub unsandboxed: bool,
    pub timeout_sec: Option<u64>,
    pub wait_ms: Option<u64>,
}

#[derive(Clone, Debug)]
pub(crate) struct ValidatedExec {
    pub(crate) root: String,
    pub(crate) cwd_rel: String,
    pub(crate) mode: ExecMode,
    pub(crate) program: String,
    pub(crate) args: Vec<String>,
    pub(crate) command: Option<String>,
    pub(crate) reason: Option<String>,
    pub(crate) unsandboxed: bool,
    pub(crate) timeout_sec: u64,
    pub(crate) wait_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PolicyVerdict {
    pub(crate) tier: RiskTier,
    pub(crate) allow_session: bool,
    pub(crate) risk_tags: Vec<&'static str>,
    pub(crate) display_command: String,
}

pub(crate) fn validate_request(req: ExecRequest) -> Result<ValidatedExec, &'static str> {
    let root = req.root.trim().to_owned();
    if root.is_empty() {
        return Err("missing root");
    }
    let cwd_rel = req.cwd.unwrap_or_default().trim().to_owned();
    let timeout_sec = req
        .timeout_sec
        .unwrap_or(DEFAULT_TIMEOUT_SEC)
        .clamp(1, MAX_TIMEOUT_SEC);
    let wait_ms = req.wait_ms.unwrap_or(DEFAULT_WAIT_MS).min(MAX_WAIT_MS);
    let reason = req.reason.and_then(|raw| {
        let cleaned: String = raw
            .chars()
            .filter(|c| !c.is_control() || *c == ' ')
            .take(MAX_REASON_CHARS)
            .collect();
        let trimmed = cleaned.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_owned())
    });

    match req.mode {
        ExecMode::Direct => {
            if req.command.as_ref().is_some_and(|c| !c.trim().is_empty()) {
                return Err("direct mode uses program and args, not command");
            }
            let program = req.program.unwrap_or_default().trim().to_owned();
            if program.is_empty()
                || program.len() > 64
                || program.contains(['/', '\\', ':', '\0'])
                || program.chars().any(char::is_control)
                || !program
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
            {
                return Err("invalid program name");
            }
            if req.args.len() > MAX_ARGS {
                return Err("too many arguments");
            }
            let mut total = 0usize;
            for arg in &req.args {
                if arg.contains('\0') || arg.contains('\r') || arg.contains('\n') {
                    return Err("invalid argument");
                }
                total = total.saturating_add(arg.len());
                if total > MAX_ARGS_BYTES {
                    return Err("arguments too large");
                }
            }
            Ok(ValidatedExec {
                root,
                cwd_rel,
                mode: ExecMode::Direct,
                program,
                args: req.args,
                command: None,
                reason,
                unsandboxed: req.unsandboxed,
                timeout_sec,
                wait_ms,
            })
        }
        ExecMode::Powershell | ExecMode::Cmd => {
            let command = req.command.unwrap_or_default();
            let trimmed = command.trim();
            if trimmed.is_empty() || trimmed.len() > MAX_COMMAND_BYTES || trimmed.contains('\0') {
                return Err("invalid shell command");
            }
            let program = match req.mode {
                ExecMode::Powershell => "powershell.exe".to_owned(),
                ExecMode::Cmd => "cmd.exe".to_owned(),
                ExecMode::Direct => unreachable!(),
            };
            Ok(ValidatedExec {
                root,
                cwd_rel,
                mode: req.mode,
                program,
                args: Vec::new(),
                command: Some(trimmed.to_owned()),
                reason,
                unsandboxed: req.unsandboxed,
                timeout_sec,
                wait_ms,
            })
        }
    }
}

pub(crate) fn evaluate(req: &ValidatedExec, sensitive_workspace: bool) -> PolicyVerdict {
    let mut tags: Vec<&'static str> = Vec::new();
    let mut tier = RiskTier::Auto;

    let display_command = match req.mode {
        ExecMode::Direct => {
            if req.args.is_empty() {
                req.program.clone()
            } else {
                format!("{} {}", req.program, format_args_preview(&req.args))
            }
        }
        ExecMode::Powershell => format!(
            "powershell -NoProfile -Command {}",
            req.command.as_deref().unwrap_or_default()
        ),
        ExecMode::Cmd => format!(
            "cmd /d /s /c {}",
            req.command.as_deref().unwrap_or_default()
        ),
    };

    if sensitive_workspace {
        tags.push("sensitive_path");
        tier = RiskTier::Always;
    }
    if req.unsandboxed {
        tags.push("unsandboxed");
        tier = RiskTier::Always;
    }

    match req.mode {
        ExecMode::Direct => {
            let (prog_tier, prog_tags) = classify_direct(&req.program, &req.args);
            for t in prog_tags {
                if !tags.contains(&t) {
                    tags.push(t);
                }
            }
            tier = max_tier(tier, prog_tier);
        }
        ExecMode::Powershell | ExecMode::Cmd => {
            let shell_tag = if req.mode == ExecMode::Powershell {
                "shell_powershell"
            } else {
                "shell_cmd"
            };
            tags.push(shell_tag);
            tier = max_tier(tier, RiskTier::Session);
            let cmd = req.command.as_deref().unwrap_or_default();
            for high_tag in inspect_shell_high_risk(cmd) {
                if !tags.contains(&high_tag) {
                    tags.push(high_tag);
                }
                tier = RiskTier::Always;
            }
        }
    }

    PolicyVerdict {
        allow_session: tier == RiskTier::Session && !sensitive_workspace && !req.unsandboxed,
        tier,
        risk_tags: tags,
        display_command,
    }
}

/// 纯只读直调命令无需向工作目录写 ACL，仅授予隔离临时目录写权限即可秒级启动。
pub(crate) fn is_read_only_direct(req: &ValidatedExec) -> bool {
    if req.mode != ExecMode::Direct {
        return false;
    }
    let name = normalized_program(&req.program);
    let args_lower: Vec<String> = req.args.iter().map(|a| a.to_ascii_lowercase()).collect();
    if args_lower.len() == 1
        && matches!(
            args_lower[0].as_str(),
            "--version" | "-v" | "-V" | "version"
        )
    {
        return true;
    }
    match name.as_str() {
        "where" | "whoami" | "rg" | "fd" => true,
        "git" => {
            let sub = args_lower
                .iter()
                .find(|a| !a.starts_with('-'))
                .map(String::as_str)
                .unwrap_or("");
            match sub {
                "status" | "diff" | "log" | "show" | "rev-parse" | "ls-files" | "describe"
                | "blame" | "grep" | "shortlog" | "reflog" | "merge-base" => true,
                "branch" => !args_lower.iter().any(|a| {
                    matches!(
                        a.as_str(),
                        "-d" | "-D" | "--delete" | "-m" | "-M" | "-c" | "-C"
                    )
                }),
                "remote" => !args_lower
                    .iter()
                    .any(|a| matches!(a.as_str(), "add" | "remove" | "rm" | "set-url")),
                _ => false,
            }
        }
        _ => false,
    }
}

fn max_tier(a: RiskTier, b: RiskTier) -> RiskTier {
    match (a, b) {
        (RiskTier::Always, _) | (_, RiskTier::Always) => RiskTier::Always,
        (RiskTier::Session, _) | (_, RiskTier::Session) => RiskTier::Session,
        _ => RiskTier::Auto,
    }
}

fn normalized_program(program: &str) -> String {
    let lower = program.to_ascii_lowercase();
    for ext in [".exe", ".cmd", ".bat", ".com"] {
        if let Some(stem) = lower.strip_suffix(ext) {
            return stem.to_owned();
        }
    }
    lower
}

fn classify_direct(program: &str, args: &[String]) -> (RiskTier, Vec<&'static str>) {
    let name = normalized_program(program);
    let args_lower: Vec<String> = args.iter().map(|a| a.to_ascii_lowercase()).collect();

    // 禁止把系统高危工具伪装为常规直调程序
    if matches!(
        name.as_str(),
        "reg"
            | "regedit"
            | "sc"
            | "schtasks"
            | "bcdedit"
            | "diskpart"
            | "format"
            | "shutdown"
            | "net"
            | "netsh"
            | "icacls"
            | "takeown"
            | "runas"
            | "mshta"
            | "rundll32"
            | "regsvr32"
            | "certutil"
            | "bitsadmin"
            | "wmic"
            | "msiexec"
            | "wsl"
            | "wscript"
            | "cscript"
    ) {
        return (RiskTier::Always, vec!["system_admin_tool"]);
    }

    // 把 shell 程序伪装成 direct 调用时，按 shell 规则升级
    if matches!(name.as_str(), "powershell" | "pwsh" | "cmd") {
        let joined = args.join(" ");
        let mut tags = vec![if name == "cmd" {
            "shell_cmd"
        } else {
            "shell_powershell"
        }];
        let mut tier = RiskTier::Session;
        for high in inspect_shell_high_risk(&joined) {
            tags.push(high);
            tier = RiskTier::Always;
        }
        return (tier, tags);
    }

    // 任意工具仅查版本号：纯只读直通
    if args_lower.len() == 1
        && matches!(
            args_lower[0].as_str(),
            "--version" | "-v" | "-V" | "version"
        )
    {
        return (RiskTier::Auto, Vec::new());
    }

    match name.as_str() {
        "git" => classify_git(&args_lower),
        "cargo" => classify_cargo(&args_lower),
        "rustc" | "rustfmt" | "rg" | "fd" | "where" | "whoami" | "tsc" | "vite" | "vitest"
        | "jest" | "pytest" => (RiskTier::Auto, Vec::new()),
        "pnpm" | "npm" | "yarn" | "npx" => classify_node_pm(&args_lower),
        "go" => match args_lower.first().map(String::as_str) {
            Some("test" | "build" | "vet" | "fmt" | "version" | "list" | "env") => {
                (RiskTier::Auto, Vec::new())
            }
            Some("get" | "install") => (RiskTier::Session, vec!["package_mutation"]),
            _ => (RiskTier::Session, vec!["custom_command"]),
        },
        "dotnet" => match args_lower.first().map(String::as_str) {
            Some("build" | "test" | "format" | "--info" | "--list-sdks") => {
                (RiskTier::Auto, Vec::new())
            }
            Some("add" | "remove" | "restore" | "publish" | "nuget") => {
                (RiskTier::Session, vec!["package_mutation"])
            }
            _ => (RiskTier::Session, vec!["custom_command"]),
        },
        "python" | "python3" | "py" => classify_python(&args_lower),
        "node" => {
            if args_lower.iter().any(|a| a == "-e" || a == "--eval") {
                (RiskTier::Session, vec!["inline_script"])
            } else {
                (RiskTier::Session, vec!["custom_command"])
            }
        }
        "pip" | "pip3" | "uv" | "winget" | "choco" | "scoop" => {
            (RiskTier::Session, vec!["package_mutation"])
        }
        _ => (RiskTier::Session, vec!["custom_command"]),
    }
}

fn classify_git(args: &[String]) -> (RiskTier, Vec<&'static str>) {
    // 禁止通过 -c / --exec-path / --upload-pack 等全局参数注入任意命令
    if args.iter().any(|a| {
        a == "-c"
            || a.starts_with("-c=")
            || a.starts_with("--exec-path")
            || a.starts_with("--git-dir")
            || a.starts_with("--work-tree")
            || a.contains("core.fsmonitor")
            || a.contains("core.sshcommand")
    }) {
        return (RiskTier::Always, vec!["git_config_override"]);
    }

    // 跳过如 `-C <dir>`（仍禁止 `-C` 跳出目录，直接升级）
    if args
        .iter()
        .any(|a| a == "-c" || a == "--global" || a == "--system")
    {
        return (RiskTier::Always, vec!["git_config_override"]);
    }

    let sub = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(String::as_str)
        .unwrap_or("");
    match sub {
        "status" | "diff" | "log" | "show" | "rev-parse" | "ls-files" | "describe" | "blame"
        | "grep" | "shortlog" | "reflog" | "merge-base" => (RiskTier::Auto, Vec::new()),
        "branch" => {
            if args
                .iter()
                .any(|a| a == "-d" || a == "-D" || a == "--delete")
            {
                (RiskTier::Session, vec!["destructive_git"])
            } else {
                (RiskTier::Auto, Vec::new())
            }
        }
        "remote" => {
            if args
                .iter()
                .any(|a| matches!(a.as_str(), "add" | "remove" | "rm" | "set-url"))
            {
                (RiskTier::Session, vec!["remote_mutation"])
            } else {
                (RiskTier::Auto, Vec::new())
            }
        }
        "add" | "commit" | "switch" | "checkout" | "restore" | "stash" | "merge"
        | "cherry-pick" | "fetch" | "pull" => (RiskTier::Auto, Vec::new()),
        "push" => {
            if args.iter().any(|a| {
                a == "--force" || a == "-f" || a == "--force-with-lease" || a == "--delete"
            }) {
                (RiskTier::Always, vec!["remote_force_push"])
            } else {
                (RiskTier::Session, vec!["remote_push"])
            }
        }
        "reset" => {
            if args.iter().any(|a| a == "--hard") {
                (RiskTier::Always, vec!["destructive_git"])
            } else {
                (RiskTier::Session, vec!["destructive_git"])
            }
        }
        "clean" => (RiskTier::Always, vec!["destructive_delete"]),
        "config" => (RiskTier::Always, vec!["git_config_override"]),
        _ => (RiskTier::Session, vec!["custom_command"]),
    }
}

fn classify_cargo(args: &[String]) -> (RiskTier, Vec<&'static str>) {
    let sub = args
        .iter()
        .find(|a| !a.starts_with('-'))
        .map(String::as_str)
        .unwrap_or("");
    match sub {
        "check" | "test" | "build" | "clippy" | "fmt" | "metadata" | "doc" | "bench" | "run"
        | "tree" => (RiskTier::Auto, Vec::new()),
        "clean" | "update" | "add" | "remove" | "install" => {
            (RiskTier::Session, vec!["package_mutation"])
        }
        "publish" | "login" => (RiskTier::Always, vec!["remote_push"]),
        _ => (RiskTier::Session, vec!["custom_command"]),
    }
}

fn classify_node_pm(args: &[String]) -> (RiskTier, Vec<&'static str>) {
    // 允许 pnpm -C <subdir> build 这类子目录写法（但不允许含 .. 或绝对路径）
    let mut iter = args.iter().peekable();
    let mut sub = "";
    while let Some(arg) = iter.next() {
        if arg == "-c" || arg == "--dir" {
            if let Some(target) = iter.next() {
                if target.contains("..") || target.contains(':') || target.starts_with(['/', '\\'])
                {
                    return (RiskTier::Always, vec!["path_escape_attempt"]);
                }
            }
            continue;
        }
        if !arg.starts_with('-') {
            sub = arg.as_str();
            break;
        }
    }
    match sub {
        "build" | "test" | "lint" | "typecheck" | "check" | "format" | "fmt" | "run" | "exec"
        | "tsc" | "vite" | "vitest" | "jest" => (RiskTier::Auto, Vec::new()),
        "install" | "i" | "add" | "remove" | "rm" | "uninstall" | "update" | "up" | "dlx" => {
            (RiskTier::Session, vec!["package_mutation"])
        }
        "publish" | "login" | "adduser" => (RiskTier::Always, vec!["remote_push"]),
        _ => (RiskTier::Session, vec!["custom_command"]),
    }
}

fn classify_python(args: &[String]) -> (RiskTier, Vec<&'static str>) {
    if args.len() >= 2 && args[0] == "-m" {
        return match args[1].as_str() {
            "pytest" | "unittest" | "py_compile" | "compileall" | "ruff" | "mypy" | "black"
            | "flake8" => (RiskTier::Auto, Vec::new()),
            "pip" => (RiskTier::Session, vec!["package_mutation"]),
            _ => (RiskTier::Session, vec!["custom_command"]),
        };
    }
    if args.iter().any(|a| a == "-c") {
        return (RiskTier::Session, vec!["inline_script"]);
    }
    (RiskTier::Session, vec!["custom_command"])
}

fn inspect_shell_high_risk(command: &str) -> Vec<&'static str> {
    let lower = command.to_ascii_lowercase();
    let mut tags = Vec::new();
    let mut push = |tag: &'static str| {
        if !tags.contains(&tag) {
            tags.push(tag);
        }
    };

    if has_token_any(
        &lower,
        &[
            "-encodedcommand",
            "-enc",
            "-ec",
            "frombase64string",
            "invoke-expression",
            "iex",
        ],
    ) {
        push("obfuscated_command");
    }
    if has_token_any(
        &lower,
        &[
            "format",
            "diskpart",
            "bcdedit",
            "shutdown",
            "restart-computer",
            "stop-computer",
            "schtasks",
            "register-scheduledtask",
            "reg",
            "set-itemproperty",
            "new-itemproperty",
            "remove-itemproperty",
            "sc.exe",
            "set-service",
            "stop-service",
            "netsh",
            "icacls",
            "takeown",
            "runas",
            "start-process",
        ],
    ) || lower.contains("hkcu:")
        || lower.contains("hklm:")
        || lower.contains("registry::")
        || lower.contains("-verb runas")
    {
        push("system_admin_tool");
    }
    if lower.contains("git push") && (lower.contains("--force") || has_token_any(&lower, &["-f"])) {
        push("remote_force_push");
    }
    if lower.contains("git reset --hard") || lower.contains("git clean") {
        push("destructive_git");
    }
    if (lower.contains("remove-item") && (lower.contains("-recurse") || lower.contains("-force")))
        || (has_token_any(&lower, &["rmdir", "rd"]) && lower.contains("/s"))
        || (has_token_any(&lower, &["del", "erase"]) && lower.contains("/s"))
        || lower.contains("rm -rf")
    {
        push("destructive_delete");
    }
    if lower.contains("..\\") || lower.contains("../") || has_token_any(&lower, &[".."]) {
        push("path_escape_attempt");
    }
    if lower.contains(".muse-bridge")
        || lower.contains("\\.ssh")
        || lower.contains("/.ssh")
        || lower.contains("\\.aws")
        || lower.contains("\\.gnupg")
        || lower.contains("\\startup")
    {
        push("sensitive_path");
    }
    tags
}

fn has_token_any(haystack: &str, needles: &[&str]) -> bool {
    let tokens: Vec<&str> = haystack
        .split(|c: char| {
            c.is_whitespace() || matches!(c, ';' | '|' | '&' | '(' | ')' | '"' | '\'' | '`')
        })
        .filter(|t| !t.is_empty())
        .collect();
    needles.iter().any(|needle| tokens.contains(needle))
}

fn format_args_preview(args: &[String]) -> String {
    args.iter()
        .map(|arg| {
            if arg.is_empty() || arg.chars().any(|c| c.is_whitespace() || c == '"') {
                format!("{arg:?}")
            } else {
                arg.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req_direct(program: &str, args: &[&str]) -> ValidatedExec {
        validate_request(ExecRequest {
            root: "project".into(),
            cwd: Some("app".into()),
            mode: ExecMode::Direct,
            program: Some(program.into()),
            args: args.iter().map(|s| (*s).into()).collect(),
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn direct_dev_tools_are_auto_allowed_while_high_risk_require_approval() {
        let auto = evaluate(&req_direct("cargo", &["test", "--locked"]), false);
        assert_eq!(auto.tier, RiskTier::Auto);
        assert!(!auto.allow_session);

        let git_ok = evaluate(&req_direct("git", &["status", "--short"]), false);
        assert_eq!(git_ok.tier, RiskTier::Auto);

        let pnpm_build = evaluate(&req_direct("pnpm", &["-C", "web", "build"]), false);
        assert_eq!(pnpm_build.tier, RiskTier::Auto);

        let pnpm_install = evaluate(&req_direct("pnpm", &["install"]), false);
        assert_eq!(pnpm_install.tier, RiskTier::Session);
        assert!(pnpm_install.allow_session);

        let git_push = evaluate(&req_direct("git", &["push", "origin", "feat"]), false);
        assert_eq!(git_push.tier, RiskTier::Session);
        assert!(git_push.allow_session);

        let force_push = evaluate(&req_direct("git", &["push", "--force"]), false);
        assert_eq!(force_push.tier, RiskTier::Always);
        assert!(!force_push.allow_session);
        assert!(force_push.risk_tags.contains(&"remote_force_push"));

        let git_inject = evaluate(
            &req_direct("git", &["-c", "core.fsmonitor=calc.exe", "status"]),
            false,
        );
        assert_eq!(git_inject.tier, RiskTier::Always);
    }

    #[test]
    fn powershell_and_cmd_require_session_or_always_approval() {
        let normal_ps = validate_request(ExecRequest {
            root: "project".into(),
            cwd: Some("app".into()),
            mode: ExecMode::Powershell,
            command: Some("Get-ChildItem | Select-Object -First 5".into()),
            ..Default::default()
        })
        .unwrap();
        let verdict = evaluate(&normal_ps, false);
        assert_eq!(verdict.tier, RiskTier::Session);
        assert!(verdict.allow_session);
        assert!(verdict.risk_tags.contains(&"shell_powershell"));

        let encoded_ps = validate_request(ExecRequest {
            root: "project".into(),
            cwd: Some("app".into()),
            mode: ExecMode::Powershell,
            command: Some("powershell -EncodedCommand AAA".into()),
            ..Default::default()
        })
        .unwrap();
        let high = evaluate(&encoded_ps, false);
        assert_eq!(high.tier, RiskTier::Always);
        assert!(!high.allow_session);
        assert!(high.risk_tags.contains(&"obfuscated_command"));

        let sensitive = evaluate(&req_direct("cargo", &["check"]), true);
        assert_eq!(sensitive.tier, RiskTier::Always);
        assert!(!sensitive.allow_session);
        assert!(sensitive.risk_tags.contains(&"sensitive_path"));

        let escape_ps = validate_request(ExecRequest {
            root: "project".into(),
            cwd: Some("app".into()),
            mode: ExecMode::Powershell,
            command: Some(r#"Set-Content ..\escape.txt "test""#.into()),
            ..Default::default()
        })
        .unwrap();
        let escape_verdict = evaluate(&escape_ps, false);
        assert_eq!(escape_verdict.tier, RiskTier::Always);
        assert!(!escape_verdict.allow_session);
        assert!(escape_verdict.risk_tags.contains(&"path_escape_attempt"));
    }

    #[test]
    fn unsandboxed_always_forces_single_approval() {
        let req = validate_request(ExecRequest {
            root: "project".into(),
            cwd: Some("app".into()),
            mode: ExecMode::Direct,
            program: Some("cargo".into()),
            args: vec!["test".into()],
            unsandboxed: true,
            ..Default::default()
        })
        .unwrap();
        let verdict = evaluate(&req, false);
        assert_eq!(verdict.tier, RiskTier::Always);
        assert!(!verdict.allow_session);
        assert!(verdict.risk_tags.contains(&"unsandboxed"));
    }
}
