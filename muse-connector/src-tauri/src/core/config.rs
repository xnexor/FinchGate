//! 沿用 Python 版 `~/.muse-bridge/config.json` 的路径、字段和默认值。
//! 写回 UTF-8 无 BOM；严格字段类型与现存绝对目录校验属于有意收紧。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const DEFAULT_PORT: u16 = 18790;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeConfig {
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub read_only: bool,
    #[serde(default)]
    pub roots: BTreeMap<String, PathBuf>,
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

impl Default for BridgeConfig {
    fn default() -> Self {
        // 与 Python load_config 的兜底一致：默认只暴露 Documents\MuseBridge，只读
        let mut roots = BTreeMap::new();
        if let Some(doc) = dirs::document_dir() {
            roots.insert("bridge".to_string(), doc.join("MuseBridge"));
        }
        Self {
            port: DEFAULT_PORT,
            read_only: true,
            roots,
        }
    }
}

/// `~/.muse-bridge`
pub fn bridge_home() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".muse-bridge")
}

pub fn config_path() -> PathBuf {
    bridge_home().join("config.json")
}

pub fn token_path() -> PathBuf {
    bridge_home().join("token")
}

pub fn audit_path() -> PathBuf {
    bridge_home().join("audit.log")
}

impl BridgeConfig {
    pub fn load() -> std::io::Result<Self> {
        Self::load_from(&config_path())
    }

    pub fn load_from(path: &Path) -> std::io::Result<Self> {
        let raw = std::fs::read_to_string(path)?;
        let mut cfg: BridgeConfig = serde_json::from_str(raw.trim_start_matches('\u{feff}'))?;
        cfg.roots = cfg
            .roots
            .into_iter()
            .filter_map(|(name, path)| {
                let expanded = expand_path(&path);
                if expanded.is_dir() {
                    Some((name, expanded))
                } else {
                    None
                }
            })
            .collect();
        if cfg.roots.is_empty() {
            return Err(std::io::Error::other("没有可用的目录白名单"));
        }
        Ok(cfg)
    }

    pub fn save(&self) -> std::io::Result<()> {
        Self::save_to(self, &config_path())
    }

    pub fn save_to(&self, path: &Path) -> std::io::Result<()> {
        // 保留 Python/未来版本的未知字段，不用反序列化后的结构覆盖整份配置。
        let mut value = std::fs::read_to_string(path)
            .ok()
            .and_then(|s| {
                serde_json::from_str::<serde_json::Value>(s.trim_start_matches('\u{feff}')).ok()
            })
            .filter(|v| v.is_object())
            .unwrap_or_else(|| serde_json::json!({}));
        let known = serde_json::to_value(self)?;
        for (key, val) in known.as_object().unwrap() {
            value[key] = val.clone();
        }
        super::storage::atomic_write(path, &serde_json::to_vec_pretty(&value)?)
    }

    /// 只验证用户选定目录，不因配置拼写错误创建新目录。
    pub fn ensure_roots(&self) -> std::io::Result<()> {
        for p in self.roots.values() {
            if !p.is_absolute() || !p.is_dir() {
                return Err(std::io::Error::other("根目录必须是已存在的绝对目录"));
            }
        }
        Ok(())
    }
}

fn expand_path(path: &Path) -> PathBuf {
    let mut s = path.to_string_lossy().to_string();
    if (s == "~" || s.starts_with("~/") || s.starts_with("~\\"))
        && let Some(home) = dirs::home_dir()
    {
        s = format!("{}{}", home.display(), &s[1..]);
    }
    // 与 Windows Python expandvars 的 %NAME% 兼容；未知变量保持原样。
    let mut out = String::new();
    let mut rest = s.as_str();
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let tail = &rest[start + 1..];
        if let Some(end) = tail.find('%') {
            let name = &tail[..end];
            out.push_str(&std::env::var(name).unwrap_or_else(|_| format!("%{name}%")));
            rest = &tail[end + 1..];
        } else {
            out.push_str(&rest[start..]);
            rest = "";
            break;
        }
    }
    out.push_str(rest);
    PathBuf::from(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_defaults_and_unknown_fields_survive_atomic_save() {
        let dir =
            std::env::temp_dir().join(format!("muse-config-{}", crate::core::token::generate()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        let input = serde_json::json!({"roots":{"r":dir},"future_option":{"enabled":true}});
        std::fs::write(&path, format!("\u{feff}{input}")).unwrap();
        let mut cfg = BridgeConfig::load_from(&path).unwrap();
        assert_eq!(cfg.port, 18790);
        assert!(!cfg.read_only);
        cfg.read_only = true;
        cfg.save_to(&path).unwrap();
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(value["future_option"]["enabled"], true);
        assert_eq!(value["read_only"], true);
        assert!(!std::fs::read(&path).unwrap().starts_with(&[239, 187, 191]));
        std::fs::remove_dir_all(dir).unwrap();
    }
}
