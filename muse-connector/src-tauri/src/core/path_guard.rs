//! 路径安全闸门 —— 移植自 Python 版 `_resolve`，并修复三个已知缺陷：
//! 1. 保留设备名（CON 等）导致的解析异常 → 预检直接拒绝
//! 2. 尾部点/空格被 Windows 归一化（`a.txt.` 覆盖 `a.txt`）→ 预检拒绝
//! 3. ADS 数据流（`file::$DATA`）与 `..` 组件 → 预检拒绝（比 Python 更严，属有意收紧）
//!
//! 判定基准（与实测的 Python 行为逐例对照）：
//! - "unknown root" / "path must be relative" / "path escapes root" 三个错误串保持兼容；
//! - 新增拒绝使用 "invalid path"（Python 对应场景是连接重置或悄悄别名，均属缺陷行为）。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const ERR_UNKNOWN_ROOT: &str = "unknown root";
pub const ERR_ABSOLUTE: &str = "path must be relative";
pub const ERR_INVALID: &str = "invalid path";
pub const ERR_ESCAPE: &str = "path escapes root";

const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

pub(crate) struct Resolved {
    pub(crate) root: PathBuf,
    pub(crate) path: PathBuf,
    pub(crate) requested_root: PathBuf,
    pub(crate) requested_relative: PathBuf,
    pub(crate) reject_reparse: bool,
}

pub(crate) fn resolve(
    roots: &BTreeMap<String, PathBuf>,
    root_name: &str,
    rel: &str,
) -> Result<Resolved, &'static str> {
    let base = roots.get(root_name).ok_or(ERR_UNKNOWN_ROOT)?;

    // 绝对路径检测（对齐 Windows ntpath.isabs 的判定面）
    let b = rel.as_bytes();
    if b.first() == Some(&b'/') || b.first() == Some(&b'\\') {
        return Err(ERR_ABSOLUTE);
    }
    if b.len() >= 2 && b[1] == b':' {
        return Err(ERR_ABSOLUTE); // 盘符（含 UNC 的 \\.\ 与 \\server\ 形式由首字符反斜杠覆盖）
    }
    if rel.contains('\0') {
        return Err(ERR_INVALID);
    }

    // 预扫描一：`..` 深度。逃出根 → "path escapes root"（错误串与 Python 实测一致）；
    // 落回根内的 `..` 在组件检查中拒绝（Python 经 realpath 允许 —— 有意收紧为 invalid path）。
    let mut depth: i64 = 0;
    for comp in rel.split(['/', '\\']) {
        if comp == ".." {
            depth -= 1;
            if depth < 0 {
                return Err(ERR_ESCAPE);
            }
        } else if !comp.is_empty() && comp != "." {
            depth += 1;
        }
    }

    // 组件级预检（修复三缺陷的核心）
    let mut clean: Vec<&str> = Vec::new();
    for comp in rel.split(['/', '\\']) {
        if comp.is_empty() || comp == "." {
            continue;
        }
        if comp == ".." {
            // Python 允许"落回根内"的 ..；此处一律拒绝 —— 消灭整类穿越，属有意收紧
            return Err(ERR_INVALID);
        }
        if comp.contains(':') {
            // ADS 数据流 / 设备命名空间 / 残余盘符
            return Err(ERR_INVALID);
        }
        if comp.ends_with('.') || comp.ends_with(' ') {
            // Win32 剥离尾部点与空格：既造成别名（a.txt. == a.txt），也包含 "..." 穿越
            return Err(ERR_INVALID);
        }
        // 保留设备名（CON、CON.txt 等同形变体）
        let stem = comp.split('.').next().unwrap_or(comp).to_ascii_uppercase();
        if RESERVED.contains(&stem.as_str()) {
            return Err(ERR_INVALID);
        }
        clean.push(comp);
    }

    let requested_relative: PathBuf = clean.into_iter().collect();
    let target = base.join(&requested_relative);

    // 白名单判定：canonicalize 消解 junction/符号链接/剩余 .. 后必须仍在根内。
    // base 在 config 加载时已 ensure_roots，此处仍容忍竞态导致的失败。
    let base_canon = std::fs::canonicalize(base).map_err(|_| ERR_INVALID)?;
    let target_canon = canonical_non_strict(&target).map_err(|_| ERR_INVALID)?;

    if target_canon == base_canon || target_canon.starts_with(&base_canon) {
        Ok(Resolved {
            root: base_canon,
            path: target_canon,
            requested_root: base.clone(),
            requested_relative,
            reject_reparse: false,
        })
    } else {
        Err(ERR_ESCAPE)
    }
}

/// 非严格 canonicalize：路径不存在（写目标）时，解析到最深的存在祖先，
/// 再拼回剩余组件 —— 等价于 Python os.path.realpath 在 Windows 上的非严格行为。
pub(crate) fn canonical_non_strict(p: &Path) -> std::io::Result<PathBuf> {
    if let Ok(c) = std::fs::canonicalize(p) {
        return Ok(c);
    }
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = p.to_path_buf();
    loop {
        let name = cur.file_name().map(|n| n.to_os_string());
        let Some(parent) = cur.parent() else { break };
        if let Some(n) = name {
            tail.push(n);
        }
        cur = parent.to_path_buf();
        if cur.as_os_str().is_empty() || std::fs::canonicalize(&cur).is_ok() {
            break;
        }
    }
    let mut c = std::fs::canonicalize(&cur)?;
    for name in tail.into_iter().rev() {
        c.push(name);
    }
    Ok(c)
}
