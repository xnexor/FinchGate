//! 令牌：43 字符 base64url（32 随机字节），首字符避开 '-'。
//! 与 Python 版同一文件（~/.muse-bridge/token），格式与轮换行为兼容。

use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use subtle::ConstantTimeEq;

pub fn generate() -> String {
    loop {
        let mut buf = [0u8; 32];
        getrandom::getrandom(&mut buf).expect("系统随机源不可用");
        let tok = URL_SAFE_NO_PAD.encode(buf);
        if !tok.starts_with('-') {
            return tok; // 恒为 43 字符
        }
    }
}

pub fn load(path: &Path) -> std::io::Result<String> {
    let value = std::fs::read_to_string(path)?.trim().to_string();
    if value.is_empty() {
        return Err(std::io::Error::other("令牌文件为空"));
    }
    Ok(value)
}

/// 轮换：新令牌只写本机文件，绝不通过任何响应返回。
pub fn save(path: &Path, token: &str) -> std::io::Result<()> {
    super::storage::atomic_write(path, token.as_bytes())
}

/// 界面只用文件时间判断试读确认是否过期，无需读取或派生令牌内容。
pub fn file_version(path: &Path) -> Option<String> {
    let metadata = std::fs::metadata(path).ok()?;
    let stamp = |time: std::time::SystemTime| {
        time.duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|value| value.as_nanos())
    };
    let modified = stamp(metadata.modified().ok()?)?;
    let created = metadata.created().ok().and_then(stamp).unwrap_or_default();
    Some(format!("{modified}:{created}:{}", metadata.len()))
}

/// 常数时间比较（对应 Python hmac.compare_digest）。
/// 长度不同时直接返回 false（与 compare_digest 对字符串的行为一致）。
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.as_bytes().ct_eq(b.as_bytes()).unwrap_u8() == 1
}

/// 校验 Authorization 头。规则与 Python 版一致：必须 "Bearer " 前缀，值 trim 后比较。
pub fn check_auth_header(header_value: Option<&str>, token: &str) -> bool {
    let Some(v) = header_value else { return false };
    let Some(rest) = v.strip_prefix("Bearer ") else {
        return false;
    };
    constant_time_eq(rest.trim(), token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_shape() {
        let t = generate();
        assert_eq!(t.len(), 43);
        assert!(!t.starts_with('-'));
        assert!(
            t.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
    }

    #[test]
    fn auth_header_rules() {
        assert!(check_auth_header(Some("Bearer abc"), "abc"));
        assert!(
            !check_auth_header(Some("bearer abc"), "abc"),
            "前缀大小写敏感"
        );
        assert!(check_auth_header(Some("Bearer abc "), "abc"), "值会 trim");
        assert!(!check_auth_header(Some("Bearer xyz"), "abc"));
        assert!(!check_auth_header(None, "abc"));
        assert!(!check_auth_header(Some(""), "abc"));
    }
}
