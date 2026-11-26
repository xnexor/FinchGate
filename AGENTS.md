# MuseLink 协作指南

- `muse-connector/src/` 是 React 界面，`muse-connector/src-tauri/` 是 Tauri 和 Rust 后端。优先复用现有组件、状态模型和命令。
- 界面文案通过 `muse-connector/src/lib/i18n.tsx` 和 `muse-connector/src/lib/messages.ts` 管理。更新页面、引导或反馈文案时同步中英文。对外使用英文名 MuseLink 和中文名 Muse连接器。
- 维护文件授权与令牌边界。新版 `/agent/v1` 使用独立令牌，文件访问受已保存的授权范围和 Windows 账户权限约束。变更权限、路径解析或令牌处理时，用隔离测试目录和测试凭证验证。
- 文件操作经 `muse-connector/src-tauri/src/core/handle.rs`：打开句柄后核对对象实际路径与属性，读取只通过该句柄完成，写入以已验证目录中的临时文件替换并在重命名前后复核。校验后对象发生变化时返回 409 `path changed; retry`，不要退回只按路径字符串操作。
- 本地开发使用 `pnpm -C muse-connector tauri dev` 的隔离配置。界面变更运行 `pnpm -C muse-connector build`。Rust 变更运行 `cargo test --manifest-path muse-connector/src-tauri/Cargo.toml --locked`。原生窗口、隧道或文件操作的验收需要在对应入口验证。
- 更改用户流程、安装或构建命令时，同步更新 `README.md` 和 `README.en.md`。文档使用仓库相对路径，提交前排除本机配置、凭证、日志、内部笔记和构建产物。
- 每次功能更新、问题修复或推送发布时，必须同步更新仓库根目录的 `CHANGELOG.md` 和 `CHANGELOG.en.md`（按版本与日期记录用户可见的新增、优化、修复与安全变更），确保 GitHub 首页的「更新日志」入口与程序内「关于 → 更新日志」按钮指向的内容始终与推送保持同步。

## 验证与覆盖

CI 工作流 `.github/workflows/windows.yml` 使用 runner 预装的 Node 22、pnpm 11.7.0 与 stable MSVC 工具链，不额外安装 Rust。

| 项目 | 命令 | CI | 本机（无管理员） | 专用 Windows 环境 |
| --- | --- | --- | --- | --- |
| 前端构建 | `pnpm -C muse-connector build` | 执行 | 执行 | — |
| 格式门禁 | `cargo fmt --manifest-path muse-connector/src-tauri/Cargo.toml --all -- --check` | 执行 | 执行 | — |
| Rust 测试 | `cargo test --manifest-path muse-connector/src-tauri/Cargo.toml --locked` | 执行 | 执行 | — |
| TCP 契约 `tcp_contract` | 含在上面的 Rust 测试内 | 执行 | 执行 | — |
| `junction_escape` | 含在上面的 Rust 测试内 | 执行 | 执行（`mklink /J` 不需提权） | — |
| `symlink_escape` | 含在上面的 Rust 测试内 | 执行（工作流启用开发者模式并设置 `MUSE_CONNECTOR_REQUIRE_SYMLINK_TESTS=1`） | 开发者模式开启时执行；否则标记未覆盖 | 执行 |
| Everything 文件名 IPC `official_named_ipc_…` | `MUSE_CONNECTOR_EVERYTHING_QA=<官方二进制目录> cargo test --manifest-path muse-connector/src-tauri/Cargo.toml --locked -- --ignored` | 不执行 | 执行（2026-11-24 已通过） | — |
| Everything NTFS 全卷 `official_ntfs_…` | 同上，另需 `MUSE_CONNECTOR_NTFS_QA_DIRS=<每块固定盘一个可写目录>` 且 Everything Service 运行中 | 不执行 | 不执行 | 执行 |
| 真实隧道与 Muse 端到端 | 人工验收 | 不执行 | 不执行 | 人工 |

- `symlink_escape` 在缺少 `SeCreateSymbolicLinkPrivilege`（错误码 5 或 1314）时只标记未覆盖；开启 Windows 开发者模式后，非管理员账户也能真实执行。CI 通过环境变量把跳过转为失败，避免把「没跑」当成「通过」。
- 两个 Everything 用例都标记为 `#[ignore]`，需要官方 `Everything.exe` 与 `es.exe`（版本与 SHA256 见 `muse-connector/scripts/package-portable.ps1`）。NTFS 用例还会启动命名实例对每块固定盘做全卷索引，在开发者工作机上 I/O 开销过大，因此只在专用环境执行。
