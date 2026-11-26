//! 文件工具的能力说明，以及预留的 MCP 默认拒绝边界。
use serde::Serialize;
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub enum CredentialClass {
    File,
    Agent,
}
#[derive(Debug, Clone, Serialize)]
pub struct CapabilityBoundary {
    pub protocol: &'static str,
    pub enabled: bool,
    pub tools: Vec<&'static str>,
}
pub fn boundary() -> CapabilityBoundary {
    CapabilityBoundary {
        protocol: "reserved",
        enabled: false,
        tools: vec![],
    }
}
pub fn file_tools_boundary(enabled: bool, exec_enabled: bool) -> CapabilityBoundary {
    if enabled {
        let mut tools = vec![
            "roots", "desktop", "search", "list", "read", "write", "mkdir",
        ];
        if exec_enabled {
            tools.push("exec");
        }
        CapabilityBoundary {
            protocol: "agent-file-v1",
            enabled: true,
            tools,
        }
    } else {
        boundary()
    }
}
pub fn authorize(_credential: CredentialClass, _tool: &str) -> Result<(), &'static str> {
    Err("Agent/MCP 能力尚未启用")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_token_can_invoke_unimplemented_tools() {
        for class in [CredentialClass::File, CredentialClass::Agent] {
            assert!(authorize(class, "shell").is_err());
        }
        assert!(boundary().tools.is_empty());
    }
}
