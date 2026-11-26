use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::{config::BridgeConfig, path_guard};

pub const ERR_NOT_AUTHORIZED: &str = "operation is not authorized";
pub const ERR_PROTECTED: &str = "protected path";
pub(super) const ERR_REPARSE: &str = "reparse points are not authorized";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeMode {
    #[default]
    Folders,
    Full,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantScope {
    #[default]
    Off,
    Folders,
    AllLocal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Search,
    Read,
    Write,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FolderGrant {
    pub search: bool,
    pub read: bool,
    pub write: bool,
}

impl FolderGrant {
    fn permits(self, operation: Operation) -> bool {
        match operation {
            Operation::Search => self.search,
            Operation::Read => self.read,
            Operation::Write => self.write,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessPolicy {
    pub mode: ScopeMode,
    pub roots: BTreeMap<String, PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder_grants: Option<BTreeMap<String, FolderGrant>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disks: Option<BTreeSet<String>>,
    pub search: GrantScope,
    pub read: GrantScope,
    pub write: GrantScope,
}

impl AccessPolicy {
    /// Legacy grants supply an editable baseline; search is granted explicitly.
    pub fn from_legacy(config: &BridgeConfig) -> Self {
        if config.roots.is_empty() {
            return Self::default();
        }
        Self {
            mode: ScopeMode::Folders,
            roots: config.roots.clone(),
            folder_grants: None,
            disks: None,
            search: GrantScope::Off,
            read: GrantScope::Folders,
            write: if config.read_only {
                GrantScope::Off
            } else {
                GrantScope::Folders
            },
        }
    }

    pub fn grant(&self, operation: Operation) -> GrantScope {
        match operation {
            Operation::Search => self.search,
            Operation::Read => self.read,
            Operation::Write => self.write,
        }
    }

    /// The operation's chosen realm is checked separately by `roots_for` and `resolve`.
    pub fn permits_folder(&self, alias: &str, operation: Operation) -> bool {
        self.roots.contains_key(alias)
            && self.folder_grants.as_ref().is_none_or(|grants| {
                grants
                    .get(alias)
                    .is_some_and(|grant| grant.permits(operation))
            })
    }

    pub fn validate(
        &self,
        protected: &[PathBuf],
        development_home: Option<&Path>,
    ) -> Result<(), &'static str> {
        let grants = [self.search, self.read, self.write];
        if self.mode == ScopeMode::Folders && grants.contains(&GrantScope::AllLocal) {
            return Err("全盘访问需要选择管理本机磁盘");
        }
        if let Some(disks) = &self.disks {
            if self.mode != ScopeMode::Full || !grants.contains(&GrantScope::AllLocal) {
                return Err("选择指定磁盘需要至少一项操作使用磁盘授权");
            }
            if disks.is_empty()
                || disks.iter().any(|alias| {
                    if development_home.is_some() {
                        return alias != "test-disk";
                    }
                    !alias.strip_prefix("drive-").is_some_and(|letter| {
                        letter.len() == 1 && letter.as_bytes()[0].is_ascii_lowercase()
                    })
                })
            {
                return Err("请至少选择一个有效的本机磁盘");
            }
        }
        if grants.contains(&GrantScope::Folders) && self.roots.is_empty() {
            return Err("请至少选择一个文件夹");
        }
        if self
            .folder_grants
            .as_ref()
            .is_some_and(|grants| grants.keys().ne(self.roots.keys()))
        {
            return Err("文件夹权限必须与已选目录一一对应");
        }
        let development_home = development_home
            .map(std::fs::canonicalize)
            .transpose()
            .map_err(|_| "开发数据目录不可用")?;

        for (alias, path) in &self.roots {
            if alias.is_empty()
                || alias.trim() != alias
                || alias.len() > 64
                || alias.contains(['/', '\\', ':'])
                || alias.chars().any(char::is_control)
            {
                return Err("目录别名无效");
            }
            if !is_directory_path(path) || !path.is_dir() {
                return Err("根目录必须是已存在的绝对目录");
            }
            reject_reparse_ancestors(path)?;
            let real = std::fs::canonicalize(path).map_err(|_| "无法访问目录")?;
            if is_drive_root(&real) {
                return Err("盘符根目录需要通过管理本机磁盘授权");
            }
            if protected_path(path, protected) || protected_path(&real, protected) {
                return Err(ERR_PROTECTED);
            }
            if development_home
                .as_ref()
                .is_some_and(|home| !within(&real, home))
            {
                return Err("开发模式只允许开放独立开发数据目录内的测试文件夹");
            }
        }
        Ok(())
    }

    fn scope_roots<'a>(
        &'a self,
        operation: Operation,
        local_roots: &'a BTreeMap<String, PathBuf>,
    ) -> Option<&'a BTreeMap<String, PathBuf>> {
        match self.grant(operation) {
            GrantScope::Folders => Some(&self.roots),
            GrantScope::AllLocal if self.mode == ScopeMode::Full => Some(local_roots),
            _ => None,
        }
    }

    /// `local_roots` are discovered by the host rather than supplied by a caller.
    pub fn roots_for(
        &self,
        operation: Operation,
        local_roots: &BTreeMap<String, PathBuf>,
    ) -> Option<BTreeMap<String, PathBuf>> {
        let roots = self.scope_roots(operation, local_roots)?;
        Some(
            roots
                .iter()
                .filter(|(alias, _)| self.permits_root(alias, operation))
                .map(|(alias, path)| (alias.clone(), path.clone()))
                .collect(),
        )
    }

    fn permits_root(&self, alias: &str, operation: Operation) -> bool {
        match self.grant(operation) {
            GrantScope::AllLocal => self
                .disks
                .as_ref()
                .is_none_or(|disks| disks.contains(alias)),
            GrantScope::Folders => self.permits_folder(alias, operation),
            GrantScope::Off => false,
        }
    }

    pub fn resolve(
        &self,
        operation: Operation,
        local_roots: &BTreeMap<String, PathBuf>,
        protected: &[PathBuf],
        alias: &str,
        relative: &str,
    ) -> Result<PathBuf, &'static str> {
        self.resolve_file(operation, local_roots, protected, alias, relative)
            .map(|resolved| resolved.path)
    }

    pub(crate) fn resolve_file(
        &self,
        operation: Operation,
        local_roots: &BTreeMap<String, PathBuf>,
        protected: &[PathBuf],
        alias: &str,
        relative: &str,
    ) -> Result<path_guard::Resolved, &'static str> {
        let roots = self
            .scope_roots(operation, local_roots)
            .ok_or(ERR_NOT_AUTHORIZED)?;
        let root = roots.get(alias).ok_or(path_guard::ERR_UNKNOWN_ROOT)?;
        if !self.permits_root(alias, operation) {
            return Err(ERR_NOT_AUTHORIZED);
        }
        check_target(roots, root, protected, alias, relative)
    }
}

fn check_target(
    roots: &BTreeMap<String, PathBuf>,
    root: &Path,
    protected: &[PathBuf],
    alias: &str,
    relative: &str,
) -> Result<path_guard::Resolved, &'static str> {
    let mut resolved = path_guard::resolve(roots, alias, relative)?;
    let lexical = relative
        .split(['/', '\\'])
        .filter(|component| !component.is_empty() && *component != ".")
        .fold(root.to_path_buf(), |mut path, component| {
            path.push(component);
            path
        });
    if protected_path(&lexical, protected) || protected_path(&resolved.path, protected) {
        return Err(ERR_PROTECTED);
    }
    reject_reparse_ancestors(&lexical)?;
    resolved.reject_reparse = true;
    Ok(resolved)
}

/// A lexical, component-aware containment test for both absolute and canonical Windows paths.
/// Protected entries should also be canonicalized by the caller when they exist.
pub fn protected_path(candidate: &Path, protected: &[PathBuf]) -> bool {
    protected.iter().any(|path| within(candidate, path))
}

/// Canonicalize an existing path only if it has the same spelling after expanding DOS aliases.
pub(crate) fn canonicalize_direct(path: &Path) -> Option<PathBuf> {
    let canonical = std::fs::canonicalize(path).ok()?;
    let same = |spelling: &Path| within(spelling, &canonical) && within(&canonical, spelling);
    if same(path) {
        return Some(canonical);
    }
    #[cfg(windows)]
    if reject_reparse_ancestors(path).is_ok()
        && long_path_spelling(path).is_some_and(|spelling| same(&spelling))
    {
        return Some(canonical);
    }
    None
}

#[cfg(windows)]
fn long_path_spelling(path: &Path) -> Option<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use windows_sys::Win32::Storage::FileSystem::GetLongPathNameW;

    // This expands DOS short names without substituting the target of a junction or symlink.
    let path: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut output = vec![0u16; 512];
    loop {
        // Both buffers are valid UTF-16 storage, with a NUL terminator on the input.
        let len =
            unsafe { GetLongPathNameW(path.as_ptr(), output.as_mut_ptr(), output.len() as u32) }
                as usize;
        if len == 0 {
            return None;
        }
        if len < output.len() {
            return Some(OsString::from_wide(&output[..len]).into());
        }
        output.resize(len + 1, 0);
    }
}

#[cfg(not(windows))]
fn within(candidate: &Path, root: &Path) -> bool {
    candidate.starts_with(root)
}

#[cfg(windows)]
fn within(candidate: &Path, root: &Path) -> bool {
    use std::ffi::OsStr;
    use std::path::{Component, Prefix};

    fn eq_name(lhs: &OsStr, rhs: &OsStr) -> bool {
        lhs == rhs || lhs.to_string_lossy().to_uppercase() == rhs.to_string_lossy().to_uppercase()
    }

    let mut candidate = candidate.components();
    root.components()
        .all(|part| match (candidate.next(), part) {
            (Some(Component::Prefix(lhs)), Component::Prefix(rhs)) => {
                match (lhs.kind(), rhs.kind()) {
                    (
                        Prefix::Disk(lhs) | Prefix::VerbatimDisk(lhs),
                        Prefix::Disk(rhs) | Prefix::VerbatimDisk(rhs),
                    ) => lhs.eq_ignore_ascii_case(&rhs),
                    (
                        Prefix::UNC(lhs_host, lhs_share) | Prefix::VerbatimUNC(lhs_host, lhs_share),
                        Prefix::UNC(rhs_host, rhs_share) | Prefix::VerbatimUNC(rhs_host, rhs_share),
                    ) => eq_name(lhs_host, rhs_host) && eq_name(lhs_share, rhs_share),
                    _ => lhs == rhs,
                }
            }
            (Some(Component::Normal(lhs)), Component::Normal(rhs)) => eq_name(lhs, rhs),
            (Some(lhs), rhs) => lhs == rhs,
            (None, _) => false,
        })
}

fn is_directory_path(path: &Path) -> bool {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == std::path::Component::ParentDir)
    {
        return false;
    }
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        match path.components().next() {
            Some(Component::Prefix(value)) => matches!(
                value.kind(),
                Prefix::Disk(_)
                    | Prefix::VerbatimDisk(_)
                    | Prefix::UNC(..)
                    | Prefix::VerbatimUNC(..)
            ),
            _ => false,
        }
    }
    #[cfg(not(windows))]
    {
        true
    }
}

pub(crate) fn is_drive_root(path: &Path) -> bool {
    #[cfg(windows)]
    {
        use std::path::{Component, Prefix};
        let mut parts = path.components();
        matches!(parts.next(), Some(Component::Prefix(value))
            if matches!(value.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)))
            && parts.next() == Some(Component::RootDir)
            && parts.next().is_none()
    }
    #[cfg(not(windows))]
    {
        path == Path::new("/")
    }
}

pub(crate) fn reject_reparse_ancestors(path: &Path) -> Result<(), &'static str> {
    for ancestor in path.ancestors().take_while(|path| path.is_absolute()) {
        match ancestor.symlink_metadata() {
            Ok(metadata) if is_reparse(&metadata) => return Err(ERR_REPARSE),
            Ok(_) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(path_guard::ERR_INVALID),
        }
    }
    Ok(())
}

pub fn is_reparse(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

#[cfg(windows)]
pub fn fixed_local_roots() -> BTreeMap<String, PathBuf> {
    use windows_sys::Win32::Storage::FileSystem::{GetDriveTypeW, GetLogicalDrives};
    use windows_sys::Win32::System::WindowsProgramming::DRIVE_FIXED;

    // SAFETY: GetLogicalDrives accepts no arguments and returns a volume bitmask.
    let drives = unsafe { GetLogicalDrives() };
    let mut roots = BTreeMap::new();
    for (slot, letter) in (b'A'..=b'Z').enumerate() {
        if drives & (1 << slot) == 0 {
            continue;
        }
        let wide = [u16::from(letter), u16::from(b':'), u16::from(b'\\'), 0];
        // SAFETY: wide is a live, null-terminated UTF-16 root path.
        if unsafe { GetDriveTypeW(wide.as_ptr()) } == DRIVE_FIXED {
            let path = PathBuf::from(format!("{}:\\", char::from(letter)));
            // A drive letter mapped to a subdirectory is not a separate fixed volume.
            if std::fs::canonicalize(&path)
                .is_ok_and(|real| is_drive_root(&real) && within(&real, &path))
            {
                roots.insert(
                    format!("drive-{}", char::from(letter.to_ascii_lowercase())),
                    path,
                );
            }
        }
    }
    roots
}

#[cfg(not(windows))]
pub fn fixed_local_roots() -> BTreeMap<String, PathBuf> {
    BTreeMap::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_disks_limit_search_read_and_write() {
        let home =
            std::env::temp_dir().join(format!("muse-disks-{}", super::super::token::generate()));
        let first = home.join("first");
        let second = home.join("second");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        let roots = BTreeMap::from([("drive-c".into(), first), ("drive-e".into(), second)]);
        let mut policy = AccessPolicy {
            mode: ScopeMode::Full,
            search: GrantScope::AllLocal,
            read: GrantScope::AllLocal,
            write: GrantScope::AllLocal,
            ..Default::default()
        };
        assert!(
            !serde_json::to_value(&policy)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("disks")
        );
        assert_eq!(
            policy.roots_for(Operation::Search, &roots).unwrap().len(),
            2
        );
        policy.disks = Some(["drive-e".into()].into());
        assert!(policy.validate(&[], None).is_ok());
        let mut policy: AccessPolicy =
            serde_json::from_value(serde_json::to_value(policy).unwrap()).unwrap();
        for operation in [Operation::Search, Operation::Read, Operation::Write] {
            let granted = policy.roots_for(operation, &roots).unwrap();
            assert_eq!(
                granted.keys().map(String::as_str).collect::<Vec<_>>(),
                ["drive-e"]
            );
            assert!(
                policy
                    .resolve(operation, &roots, &[], "drive-e", "")
                    .is_ok()
            );
            assert_eq!(
                policy.resolve(operation, &roots, &[], "drive-c", ""),
                Err(ERR_NOT_AUTHORIZED)
            );
        }
        policy.write = GrantScope::Off;
        assert!(policy.validate(&[], None).is_ok());
        assert!(policy.roots_for(Operation::Write, &roots).is_none());
        assert_eq!(
            policy.resolve(Operation::Read, &roots, &[], "drive-c", ""),
            Err(ERR_NOT_AUTHORIZED)
        );
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn full_search_does_not_grant_full_read_or_write() {
        let home =
            std::env::temp_dir().join(format!("muse-access-{}", super::super::token::generate()));
        let shared = home.join("shared");
        let protected = home.join("protected");
        std::fs::create_dir_all(&shared).unwrap();
        std::fs::create_dir_all(&protected).unwrap();
        let policy = AccessPolicy {
            mode: ScopeMode::Full,
            roots: BTreeMap::from([("shared".into(), shared.clone())]),
            folder_grants: None,
            disks: None,
            search: GrantScope::AllLocal,
            read: GrantScope::Folders,
            write: GrantScope::Off,
        };
        let full = BTreeMap::from([("drive-q".into(), home.clone())]);
        let denied = [protected];
        assert!(policy.validate(&denied, Some(&home)).is_ok());
        assert!(
            policy
                .resolve(Operation::Search, &full, &denied, "drive-q", "shared")
                .is_ok()
        );
        assert_eq!(
            policy.resolve(
                Operation::Search,
                &full,
                &denied,
                "drive-q",
                "protected/missing"
            ),
            Err(ERR_PROTECTED)
        );
        assert_eq!(
            policy.resolve(Operation::Read, &full, &denied, "drive-q", "shared"),
            Err(path_guard::ERR_UNKNOWN_ROOT)
        );
        assert!(
            policy
                .resolve(Operation::Read, &full, &denied, "shared", "")
                .is_ok()
        );
        assert_eq!(
            policy.resolve(Operation::Write, &full, &denied, "shared", "new.txt"),
            Err(ERR_NOT_AUTHORIZED)
        );
        assert_eq!(
            policy.resolve(Operation::Search, &full, &denied, "drive-q", "../outside"),
            Err(path_guard::ERR_ESCAPE)
        );
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn folder_grants_filter_each_operation_independently() {
        let home =
            std::env::temp_dir().join(format!("muse-access-{}", super::super::token::generate()));
        let input = home.join("input");
        let output = home.join("output");
        std::fs::create_dir_all(&input).unwrap();
        std::fs::create_dir_all(&output).unwrap();
        let mut policy = AccessPolicy {
            mode: ScopeMode::Folders,
            disks: None,
            roots: BTreeMap::from([
                ("input".into(), input.clone()),
                ("output".into(), output.clone()),
            ]),
            folder_grants: Some(BTreeMap::from([
                (
                    "input".into(),
                    FolderGrant {
                        search: true,
                        read: true,
                        write: false,
                    },
                ),
                (
                    "output".into(),
                    FolderGrant {
                        search: false,
                        read: false,
                        write: true,
                    },
                ),
            ])),
            search: GrantScope::Folders,
            read: GrantScope::Folders,
            write: GrantScope::Folders,
        };
        let volumes = BTreeMap::new();
        assert!(policy.validate(&[], Some(&home)).is_ok());
        assert_eq!(
            policy.roots_for(Operation::Search, &volumes),
            Some(BTreeMap::from([("input".into(), input.clone())]))
        );
        assert_eq!(
            policy.roots_for(Operation::Write, &volumes),
            Some(BTreeMap::from([("output".into(), output.clone())]))
        );
        assert_eq!(
            policy.resolve(Operation::Write, &volumes, &[], "input", "denied.txt"),
            Err(ERR_NOT_AUTHORIZED)
        );
        assert!(
            policy
                .resolve(Operation::Write, &volumes, &[], "output", "allowed.txt")
                .is_ok()
        );
        assert_eq!(
            policy.resolve(Operation::Read, &volumes, &[], "output", "allowed.txt"),
            Err(ERR_NOT_AUTHORIZED)
        );
        policy.folder_grants.as_mut().unwrap().remove("output");
        assert!(policy.validate(&[], Some(&home)).is_err());
        assert!(!policy.permits_folder("output", Operation::Write));
        std::fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn legacy_access_does_not_grant_search_implicitly() {
        let config = BridgeConfig {
            port: 18790,
            read_only: true,
            roots: BTreeMap::from([("selected".into(), PathBuf::from("selected"))]),
        };
        let policy = AccessPolicy::from_legacy(&config);
        assert_eq!(policy.mode, ScopeMode::Folders);
        assert_eq!(policy.search, GrantScope::Off);
        assert_eq!(policy.read, GrantScope::Folders);
        assert_eq!(policy.write, GrantScope::Off);
        let old_shape = serde_json::to_value(&policy).unwrap();
        assert!(old_shape.get("folder_grants").is_none());
        assert_eq!(
            serde_json::from_value::<AccessPolicy>(old_shape).unwrap(),
            policy
        );
    }

    #[cfg(windows)]
    #[test]
    fn protects_drive_paths_across_prefix_and_case_variants() {
        let protected = [PathBuf::from(r"C:\Users\Agent\.muse-bridge")];
        assert!(protected_path(
            Path::new(r"\\?\c:\USERS\agent\.MUSE-BRIDGE\token"),
            &protected
        ));
        assert!(!protected_path(
            Path::new(r"C:\Users\Agent\.muse-bridge-copy\token"),
            &protected
        ));
    }
}
