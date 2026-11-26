# 安全策略 / Security Policy

## 支持的版本 / Supported Versions

安全修复仅针对最新发布的稳定版本提供。

Security updates are provided for the latest released version.

| 版本 / Version | 是否支持 / Supported |
| --- | --- |
| `0.2.x`（最新 / Latest） | ✅ |
| `< 0.2.0` | ❌ |

## 报告安全漏洞 / Reporting a Vulnerability

**请勿通过公开 GitHub Issue 披露安全漏洞**，尤其是涉及权限边界绕过、路径逃逸、写受限沙箱绕过、令牌泄露或本地提权的问题。

请通过以下方式私下提交：

- 使用本仓库的 [GitHub Security Advisories](https://github.com/Aenvo/MuseLink/security/advisories/new)（推荐）提交私密漏洞报告。

提交报告时，请尽量提供：

1. 受影响的 MuseLink 版本与 Windows 系统版本。
2. 最小复现步骤、触发条件与预期/实际行为。
3. 请先脱敏真实令牌（`mfa_*`）、公网隧道域名与个人文件路径。

收到报告后会尽快确认并在修复发布后协调公开说明。

---

**Please do not disclose security vulnerabilities in public GitHub Issues**, especially issues involving file access scope bypasses, symlink/junction escapes, write-restricted sandbox escapes, token exposure, or local privilege escalation.

Please report vulnerabilities privately via:

- [GitHub Security Advisories](https://github.com/Aenvo/MuseLink/security/advisories/new) (preferred)

When submitting a report, please include:

1. Affected MuseLink version and Windows OS version.
2. Minimal reproduction steps, prerequisites, and expected vs. actual behavior.
3. Redacted logs only — never include real `mfa_*` tokens, private tunnel hostnames, or sensitive personal paths.

We will acknowledge your report as soon as possible and coordinate disclosure once a fix is released.
