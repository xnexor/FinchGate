//! Windows 写受限执行沙箱：Restricted Token (WRITE_RESTRICTED) + 目录 ACL + Job Object。
//! 沙箱初始化失败直接返回错误，绝不静默降级为无隔离裸跑。
#![cfg(windows)]

use std::collections::{BTreeMap, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, GENERIC_ALL, GetLastError, HANDLE,
    HANDLE_FLAG_INHERIT, HLOCAL, INVALID_HANDLE_VALUE, LocalFree, STILL_ACTIVE,
    SetHandleInformation, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, SetEntriesInAclW, TRUSTEE_IS_SID,
    TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows_sys::Win32::Security::{
    ACCESS_ALLOWED_ACE, ACL, ACL_SIZE_INFORMATION, AclSizeInformation, CreateRestrictedToken,
    DACL_SECURITY_INFORMATION, DISABLE_MAX_PRIVILEGE, EqualSid, GetAce, GetAclInformation,
    GetKernelObjectSecurity, GetSecurityDescriptorDacl, GetTokenInformation,
    InitializeSecurityDescriptor, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    SECURITY_DESCRIPTOR, SID_AND_ATTRIBUTES, SetKernelObjectSecurity, SetSecurityDescriptorDacl,
    SetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_ASSIGN_PRIMARY, TOKEN_DEFAULT_DACL,
    TOKEN_DUPLICATE, TOKEN_GROUPS, TOKEN_QUERY, TokenDefaultDacl, TokenGroups, TokenLogonSid,
    WRITE_RESTRICTED,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, DELETE, FILE_ALL_ACCESS, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_DELETE_CHILD, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL, WRITE_DAC,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW,
    CreateProcessW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, PROCESS_INFORMATION,
    ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOW, TerminateProcess, WaitForSingleObject,
};

use super::job::{ChildJob, JobLimits};

/// MuseLink 专用合成限制 SID 域前缀：每个工作目录通过 SHA-256 派生唯一 SID，
/// 彻底隔离不同项目与父子目录之间的写权限（即便父目录或兄弟项目曾运行过沙箱命令也互不可写）。
const SANDBOX_DOMAIN_PREFIX: u32 = 3_892_149_017;
/// Windows 内置 RESTRICTED SID 与 World/Everyone SID：用于通过系统 DLL、控制台与运行时早期初始化，
/// 普通用户目录、桌面、启动项、.ssh 及注册表均不授予二者写权限。
const RESTRICTED_SID_STR: &str = "S-1-5-12";
const WORLD_SID_STR: &str = "S-1-1-0";

const OBJECT_INHERIT_ACE_FLAG: u32 = 0x1;
const CONTAINER_INHERIT_ACE_FLAG: u32 = 0x2;
const SUB_CONTAINERS_AND_OBJECTS_INHERIT_FLAG: u32 =
    OBJECT_INHERIT_ACE_FLAG | CONTAINER_INHERIT_ACE_FLAG;
const SANDBOX_WRITE_MASK: u32 =
    FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE | DELETE | FILE_DELETE_CHILD;

pub(crate) const DEFAULT_EXEC_MEMORY_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub(crate) const DEFAULT_EXEC_MAX_PROCESSES: u32 = 64;
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const MAX_ACL_PREP_TIME: Duration = Duration::from_millis(800);
const MAX_ACL_PREP_ENTRIES: usize = 1_500;

static ACL_PREP_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

pub(crate) struct SpawnConfig {
    pub(crate) application: PathBuf,
    pub(crate) command_line: String,
    pub(crate) cwd: PathBuf,
    pub(crate) temp_dir: PathBuf,
    pub(crate) sandboxed: bool,
    pub(crate) write_workspace: bool,
    pub(crate) limits: JobLimits,
}

pub(crate) struct SpawnedProcess {
    process: OwnedHandle,
    job: ChildJob,
    pub(crate) stdout: Option<File>,
    pub(crate) stderr: Option<File>,
}

impl SpawnedProcess {
    pub(crate) fn take_pipes(&mut self) -> Option<(File, File)> {
        Some((self.stdout.take()?, self.stderr.take()?))
    }

    pub(crate) fn try_wait(&self) -> io::Result<Option<i32>> {
        // SAFETY: `self.process` is a valid live process handle.
        let waited = unsafe { WaitForSingleObject(self.process.as_raw_handle(), 0) };
        if waited != WAIT_OBJECT_0 {
            return Ok(None);
        }
        let mut code: u32 = 0;
        if unsafe { GetExitCodeProcess(self.process.as_raw_handle(), &mut code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if code == STILL_ACTIVE as u32 {
            return Ok(None);
        }
        Ok(Some(code as i32))
    }

    pub(crate) fn wait_timeout(&self, timeout_ms: u32) -> io::Result<Option<i32>> {
        // SAFETY: `self.process` is a valid live process handle.
        let waited = unsafe { WaitForSingleObject(self.process.as_raw_handle(), timeout_ms) };
        if waited != WAIT_OBJECT_0 {
            return Ok(None);
        }
        self.try_wait()
    }

    pub(crate) fn terminate(&self) {
        self.job.terminate();
    }
}

struct LocalSid(PSID);

impl LocalSid {
    fn from_str(sid_str: &str) -> io::Result<Self> {
        let wide = to_wide(sid_str);
        let mut sid: PSID = null_mut();
        // SAFETY: `wide` is null-terminated; Windows allocates the SID via LocalAlloc.
        if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) } == 0 || sid.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(sid))
    }

    fn for_workspace(path: &Path) -> io::Result<Self> {
        let sid_str = workspace_sid_string(path);
        Self::from_str(&sid_str)
    }

    fn restricted() -> io::Result<Self> {
        Self::from_str(RESTRICTED_SID_STR)
    }

    fn world() -> io::Result<Self> {
        Self::from_str(WORLD_SID_STR)
    }
}

fn workspace_sid_string(path: &Path) -> String {
    let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let normalized = strip_verbatim(&canonical)
        .trim_end_matches(['\\', '/'])
        .to_ascii_lowercase();
    let mut input = Vec::with_capacity(32 + normalized.len());
    input.extend_from_slice(b"muselink-sandbox-ws-v2:");
    input.extend_from_slice(normalized.as_bytes());
    let digest = sha256(&input);
    let a = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    let b = u32::from_be_bytes([digest[4], digest[5], digest[6], digest[7]]);
    let mut c = u32::from_be_bytes([digest[8], digest[9], digest[10], digest[11]]);
    if c == 9001 {
        c = 9002;
    }
    format!("S-1-5-21-{SANDBOX_DOMAIN_PREFIX}-{a}-{b}-{c}")
}

fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (slot, delta) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *slot = slot.wrapping_add(delta);
        }
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

impl Drop for LocalSid {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was allocated by ConvertStringSidToSidW.
            unsafe { LocalFree(self.0 as HLOCAL) };
        }
    }
}

pub(crate) fn spawn(
    config: &SpawnConfig,
    cancel: Option<&AtomicBool>,
) -> io::Result<SpawnedProcess> {
    std::fs::create_dir_all(&config.temp_dir)?;
    let sandbox_sid = if config.sandboxed {
        let sid = if config.write_workspace {
            let sid = LocalSid::for_workspace(&config.cwd)?;
            ensure_sandbox_write_access(&config.cwd, sid.0, cancel)?;
            sid
        } else {
            // 纯只读命令使用单任务临时目录派生 SID，连工作区本身也保持只读
            LocalSid::for_workspace(&config.temp_dir)?
        };
        apply_sandbox_ace_single(&config.temp_dir, sid.0, true)?;
        Some(sid)
    } else {
        None
    };
    if cancel.is_some_and(|c| c.load(Ordering::Acquire)) {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
    }

    let (stdout_read, stdout_write) = create_pipe_pair()?;
    let (stderr_read, stderr_write) = create_pipe_pair()?;
    let nul_in = open_nul_stdin()?;
    let env_block = build_clean_env(&config.temp_dir);

    let mut startup: STARTUPINFOW = unsafe { std::mem::zeroed() };
    startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdInput = nul_in.as_raw_handle();
    startup.hStdOutput = stdout_write.as_raw_handle();
    startup.hStdError = stderr_write.as_raw_handle();

    let app_wide = to_wide(&strip_verbatim(&config.application));
    let mut cmd_wide = to_wide(&config.command_line);
    let cwd_wide = to_wide(&strip_verbatim(&config.cwd));
    let flags = CREATE_NO_WINDOW | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let created = if let Some(sid) = &sandbox_sid {
        let restricted = create_write_restricted_token(sid.0)?;
        // SAFETY: all wide strings, env_block, and handles remain alive across the call.
        unsafe {
            CreateProcessAsUserW(
                restricted.as_raw_handle(),
                app_wide.as_ptr(),
                cmd_wide.as_mut_ptr(),
                null(),
                null(),
                1,
                flags,
                env_block.as_ptr().cast(),
                cwd_wide.as_ptr(),
                &startup,
                &mut pi,
            )
        }
    } else {
        // SAFETY: all wide strings, env_block, and handles remain alive across the call.
        unsafe {
            CreateProcessW(
                app_wide.as_ptr(),
                cmd_wide.as_mut_ptr(),
                null(),
                null(),
                1,
                flags,
                env_block.as_ptr().cast(),
                cwd_wide.as_ptr(),
                &startup,
                &mut pi,
            )
        }
    };

    // 父进程立即关闭已传递给子进程的管道写端与 NUL 输入端，确保子进程退出时读端能收到 EOF。
    drop(stdout_write);
    drop(stderr_write);
    drop(nul_in);

    if created == 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: CreateProcess* returned valid owned process and thread handles.
    let process = unsafe { OwnedHandle::from_raw_handle(pi.hProcess) };
    let thread = unsafe { OwnedHandle::from_raw_handle(pi.hThread) };

    let job = match ChildJob::attach_raw_with_limits(process.as_raw_handle(), config.limits) {
        Ok(job) => job,
        Err(error) => {
            unsafe {
                let _ = TerminateProcess(process.as_raw_handle(), 1);
            }
            return Err(error);
        }
    };

    if unsafe { ResumeThread(thread.as_raw_handle()) } == u32::MAX {
        let error = io::Error::last_os_error();
        job.terminate();
        return Err(error);
    }

    Ok(SpawnedProcess {
        process,
        job,
        stdout: Some(File::from(stdout_read)),
        stderr: Some(File::from(stderr_read)),
    })
}

fn create_write_restricted_token(sid: PSID) -> io::Result<OwnedHandle> {
    let mut current: HANDLE = null_mut();
    let access = TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT;
    // SAFETY: GetCurrentProcess returns the current pseudo-handle.
    if unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut current) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let current = unsafe { OwnedHandle::from_raw_handle(current) };

    // 参考 OpenAI Codex Windows 写受限沙箱配方：
    // 保留 RESTRICTED (S-1-5-12)、Everyone (S-1-1-0) 与当前会话 Logon SID 以通过 Windows
    // DLL/控制台/运行时初始化，并叠加 MuseLink 专用合成 SID（仅授予目标工作区与隔离临时目录写权限）。
    let restricted_code_sid = LocalSid::restricted()?;
    let world_sid = LocalSid::world()?;
    let (logon_buf, logon_sid) = read_logon_sid(current.as_raw_handle());
    let _keep_alive = &logon_buf;
    let mut restrict = vec![
        SID_AND_ATTRIBUTES {
            Sid: sid,
            Attributes: 0,
        },
        SID_AND_ATTRIBUTES {
            Sid: restricted_code_sid.0,
            Attributes: 0,
        },
        SID_AND_ATTRIBUTES {
            Sid: world_sid.0,
            Attributes: 0,
        },
    ];
    if let Some(lsid) = logon_sid {
        restrict.push(SID_AND_ATTRIBUTES {
            Sid: lsid,
            Attributes: 0,
        });
    }

    let mut restricted: HANDLE = null_mut();
    // SAFETY: `restrict` and `logon_buf` stay alive for the synchronous call.
    if unsafe {
        CreateRestrictedToken(
            current.as_raw_handle(),
            DISABLE_MAX_PRIVILEGE | WRITE_RESTRICTED,
            0,
            null(),
            0,
            null(),
            restrict.len() as u32,
            restrict.as_ptr(),
            &mut restricted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let restricted = unsafe { OwnedHandle::from_raw_handle(restricted) };
    apply_sandbox_default_dacl(
        restricted.as_raw_handle(),
        sid,
        restricted_code_sid.0,
        logon_sid,
    )?;
    Ok(restricted)
}

fn apply_sandbox_default_dacl(
    token: HANDLE,
    sandbox_sid: PSID,
    restricted_sid: PSID,
    logon_sid: Option<PSID>,
) -> io::Result<()> {
    let mut needed: u32 = 0;
    unsafe {
        GetTokenInformation(token, TokenDefaultDacl, null_mut(), 0, &mut needed);
    }
    let mut dacl_buf = vec![0u8; needed as usize];
    let existing_dacl = if needed > 0
        && unsafe {
            GetTokenInformation(
                token,
                TokenDefaultDacl,
                dacl_buf.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } != 0
    {
        let info = unsafe { &*(dacl_buf.as_ptr() as *const TOKEN_DEFAULT_DACL) };
        info.DefaultDacl
    } else {
        null_mut()
    };

    let make_ea = |target_sid: PSID| EXPLICIT_ACCESS_W {
        grfAccessPermissions: GENERIC_ALL,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: 0,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: target_sid.cast(),
        },
    };
    let mut entries = vec![make_ea(sandbox_sid), make_ea(restricted_sid)];
    if let Some(lsid) = logon_sid {
        entries.push(make_ea(lsid));
    }

    let mut new_dacl: *mut ACL = null_mut();
    let status = unsafe {
        SetEntriesInAclW(
            entries.len() as u32,
            entries.as_ptr(),
            existing_dacl,
            &mut new_dacl,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let td = TOKEN_DEFAULT_DACL {
        DefaultDacl: new_dacl,
    };
    let ok = unsafe {
        SetTokenInformation(
            token,
            TokenDefaultDacl,
            (&td as *const TOKEN_DEFAULT_DACL).cast(),
            std::mem::size_of::<TOKEN_DEFAULT_DACL>() as u32,
        )
    };
    let err = if ok == 0 {
        Some(io::Error::last_os_error())
    } else {
        None
    };
    if !new_dacl.is_null() {
        unsafe { LocalFree(new_dacl as HLOCAL) };
    }
    if let Some(e) = err {
        return Err(e);
    }
    Ok(())
}

fn read_logon_sid(token: HANDLE) -> (Vec<u8>, Option<PSID>) {
    // 先查 TokenLogonSid
    let mut needed: u32 = 0;
    unsafe {
        GetTokenInformation(token, TokenLogonSid, null_mut(), 0, &mut needed);
    }
    if needed > 0 {
        let mut buf = vec![0u8; needed as usize];
        if unsafe {
            GetTokenInformation(
                token,
                TokenLogonSid,
                buf.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } != 0
        {
            let groups = unsafe { &*(buf.as_ptr() as *const TOKEN_GROUPS) };
            if groups.GroupCount > 0 && !groups.Groups[0].Sid.is_null() {
                let sid = groups.Groups[0].Sid;
                return (buf, Some(sid));
            }
        }
    }
    // 兜底从 TokenGroups 查找带 SE_GROUP_LOGON_ID (0xC0000000) 标志的 SID
    const SE_GROUP_LOGON_ID: u32 = 0xC000_0000;
    needed = 0;
    unsafe {
        GetTokenInformation(token, TokenGroups, null_mut(), 0, &mut needed);
    }
    if needed > 0 {
        let mut buf = vec![0u8; needed as usize];
        if unsafe {
            GetTokenInformation(
                token,
                TokenGroups,
                buf.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } != 0
        {
            let groups = unsafe { &*(buf.as_ptr() as *const TOKEN_GROUPS) };
            let slice = unsafe {
                std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize)
            };
            for g in slice {
                if (g.Attributes & SE_GROUP_LOGON_ID) == SE_GROUP_LOGON_ID && !g.Sid.is_null() {
                    return (buf, Some(g.Sid));
                }
            }
        }
    }
    (Vec::new(), None)
}

/// 非递归授予目录及（有界/可取消的）浅层项目文件沙箱写权限。
/// 使用 SetKernelObjectSecurity 避免 SetNamedSecurityInfoW 在含 node_modules/桌面等大目录上同步递归阻塞数分钟。
fn ensure_sandbox_write_access(
    dir: &Path,
    sid: PSID,
    cancel: Option<&AtomicBool>,
) -> io::Result<()> {
    if check_sandbox_ace_single(dir, sid, true)? {
        return Ok(());
    }
    let _guard = ACL_PREP_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();
    if cancel.is_some_and(|c| c.load(Ordering::Acquire)) {
        return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
    }
    if check_sandbox_ace_single(dir, sid, true)? {
        return Ok(());
    }

    // 1) 先以非递归方式给目标目录本身加上可继承 (OI)(CI) ACE（<1ms），新建文件与子目录即刻生效。
    apply_sandbox_ace_single(dir, sid, true)?;

    // 2) 在时间与条目预算内按层补齐现有项目子项的 ACE（跳过重解析点与巨型依赖/缓存目录），随时响应取消。
    let deadline = Instant::now() + MAX_ACL_PREP_TIME;
    let mut visited = 0usize;
    let mut queue = VecDeque::new();
    queue.push_back(dir.to_path_buf());

    while let Some(current) = queue.pop_front() {
        if cancel.is_some_and(|c| c.load(Ordering::Acquire)) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
        }
        if visited >= MAX_ACL_PREP_ENTRIES || Instant::now() >= deadline {
            break;
        }
        let Ok(entries) = std::fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            if cancel.is_some_and(|c| c.load(Ordering::Acquire)) {
                return Err(io::Error::new(io::ErrorKind::Interrupted, "cancelled"));
            }
            if visited >= MAX_ACL_PREP_ENTRIES || Instant::now() >= deadline {
                break;
            }
            let path = entry.path();
            let Ok(meta) = std::fs::symlink_metadata(&path) else {
                continue;
            };
            // 绝不跟随符号链接/联接点/重解析点
            if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
                continue;
            }
            let is_dir = meta.is_dir();
            if is_dir && is_heavy_skip_dir(&entry.file_name()) {
                continue;
            }
            visited += 1;
            let _ = apply_sandbox_ace_single(&path, sid, is_dir);
            if is_dir {
                queue.push_back(path);
            }
        }
    }
    Ok(())
}

fn is_heavy_skip_dir(name: &OsStr) -> bool {
    let Some(s) = name.to_str() else {
        return false;
    };
    matches!(
        s.to_ascii_lowercase().as_str(),
        "node_modules"
            | ".pnpm-store"
            | ".venv"
            | "venv"
            | "__pycache__"
            | ".cache"
            | "appdata"
            | "$recycle.bin"
            | "system volume information"
    )
}

fn open_for_acl(path: &Path, write: bool) -> io::Result<OwnedHandle> {
    let wide = to_wide(&strip_verbatim(path));
    let access = if write {
        READ_CONTROL | WRITE_DAC
    } else {
        READ_CONTROL
    };
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn read_handle_dacl(handle: HANDLE) -> io::Result<(Vec<u8>, *mut ACL)> {
    let mut needed: u32 = 0;
    let ok = unsafe {
        GetKernelObjectSecurity(
            handle,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            0,
            &mut needed,
        )
    };
    if ok == 0 {
        let err = unsafe { GetLastError() };
        if err != ERROR_INSUFFICIENT_BUFFER {
            return Err(io::Error::from_raw_os_error(err as i32));
        }
    }
    let mut sd_buf = vec![0u8; needed.max(1) as usize];
    if unsafe {
        GetKernelObjectSecurity(
            handle,
            DACL_SECURITY_INFORMATION,
            sd_buf.as_mut_ptr().cast(),
            sd_buf.len() as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut dacl_present: i32 = 0;
    let mut dacl_defaulted: i32 = 0;
    let mut dacl: *mut ACL = null_mut();
    if unsafe {
        GetSecurityDescriptorDacl(
            sd_buf.as_mut_ptr().cast(),
            &mut dacl_present,
            &mut dacl,
            &mut dacl_defaulted,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok((sd_buf, if dacl_present != 0 { dacl } else { null_mut() }))
}

fn check_sandbox_ace_single(path: &Path, sid: PSID, require_inherit: bool) -> io::Result<bool> {
    let handle = open_for_acl(path, false)?;
    let (_buf, dacl) = read_handle_dacl(handle.as_raw_handle())?;
    Ok(unsafe { dacl_grants_sandbox_sid(dacl, sid, require_inherit) })
}

fn apply_sandbox_ace_single(path: &Path, sid: PSID, is_dir: bool) -> io::Result<()> {
    let handle = open_for_acl(path, true)?;
    let (_sd_buf, old_dacl) = read_handle_dacl(handle.as_raw_handle())?;
    if unsafe { dacl_grants_sandbox_sid(old_dacl, sid, is_dir) } {
        return Ok(());
    }

    let ea = EXPLICIT_ACCESS_W {
        grfAccessPermissions: SANDBOX_WRITE_MASK,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: if is_dir {
            SUB_CONTAINERS_AND_OBJECTS_INHERIT_FLAG
        } else {
            0
        },
        Trustee: TRUSTEE_W {
            pMultipleTrustee: null_mut(),
            MultipleTrusteeOperation: 0,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: sid.cast(),
        },
    };
    let mut new_dacl: *mut ACL = null_mut();
    let set_acl_status = unsafe { SetEntriesInAclW(1, &ea, old_dacl, &mut new_dacl) };
    if set_acl_status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(set_acl_status as i32));
    }

    let mut sd: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
    let sd_ptr: PSECURITY_DESCRIPTOR = (&mut sd as *mut SECURITY_DESCRIPTOR).cast();
    let apply_res = unsafe {
        if InitializeSecurityDescriptor(sd_ptr, SECURITY_DESCRIPTOR_REVISION) == 0 {
            Err(io::Error::last_os_error())
        } else if SetSecurityDescriptorDacl(sd_ptr, 1, new_dacl, 0) == 0 {
            Err(io::Error::last_os_error())
        } else if SetKernelObjectSecurity(handle.as_raw_handle(), DACL_SECURITY_INFORMATION, sd_ptr)
            == 0
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    };
    if !new_dacl.is_null() {
        unsafe { LocalFree(new_dacl as HLOCAL) };
    }
    apply_res
}

unsafe fn dacl_grants_sandbox_sid(dacl: *const ACL, sid: PSID, require_inherit: bool) -> bool {
    if dacl.is_null() {
        return false;
    }
    let mut info: ACL_SIZE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return false;
    }
    for index in 0..info.AceCount {
        let mut ace_ptr: *mut std::ffi::c_void = null_mut();
        if unsafe { GetAce(dacl, index, &mut ace_ptr) } == 0 || ace_ptr.is_null() {
            continue;
        }
        let ace = unsafe { &*(ace_ptr as *const ACCESS_ALLOWED_ACE) };
        // ACCESS_ALLOWED_ACE_TYPE == 0
        if ace.Header.AceType != 0 {
            continue;
        }
        if require_inherit {
            let inherit = u32::from(ace.Header.AceFlags);
            if inherit & SUB_CONTAINERS_AND_OBJECTS_INHERIT_FLAG
                != SUB_CONTAINERS_AND_OBJECTS_INHERIT_FLAG
            {
                continue;
            }
        }
        let mask = ace.Mask;
        let has_write = (mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS
            || (mask & SANDBOX_WRITE_MASK) == SANDBOX_WRITE_MASK;
        if !has_write {
            continue;
        }
        let ace_sid = std::ptr::addr_of!(ace.SidStart) as PSID;
        if unsafe { EqualSid(ace_sid, sid) } != 0 {
            return true;
        }
    }
    false
}

fn create_pipe_pair() -> io::Result<(OwnedHandle, OwnedHandle)> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let mut read: HANDLE = null_mut();
    let mut write: HANDLE = null_mut();
    if unsafe { CreatePipe(&mut read, &mut write, &sa, 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // 仅允许写端被子进程继承，父进程读端绝不继承。
    if unsafe { SetHandleInformation(read, HANDLE_FLAG_INHERIT, 0) } == 0 {
        let error = io::Error::last_os_error();
        unsafe {
            CloseHandle(read);
            CloseHandle(write);
        }
        return Err(error);
    }
    Ok(unsafe {
        (
            OwnedHandle::from_raw_handle(read),
            OwnedHandle::from_raw_handle(write),
        )
    })
}

fn open_nul_stdin() -> io::Result<OwnedHandle> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let nul = to_wide("NUL");
    let handle = unsafe {
        CreateFileW(
            nul.as_ptr(),
            FILE_GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &sa,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE || handle.is_null() {
        return Err(io::Error::from_raw_os_error(unsafe {
            GetLastError() as i32
        }));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

fn build_clean_env(temp_dir: &Path) -> Vec<u16> {
    let mut vars: BTreeMap<String, (OsString, OsString)> = BTreeMap::new();
    for (k, v) in std::env::vars_os() {
        let upper = k.to_string_lossy().to_ascii_uppercase();
        if upper.starts_with("MUSE_CONNECTOR_")
            || upper.starts_with("MUSE_LINK_")
            || upper.contains("AGENT_TOKEN")
        {
            continue;
        }
        vars.insert(upper, (k, v));
    }
    let clean_tmp = OsString::from(strip_verbatim(temp_dir));
    vars.insert("TEMP".into(), (OsString::from("TEMP"), clean_tmp.clone()));
    vars.insert("TMP".into(), (OsString::from("TMP"), clean_tmp));

    let mut block = Vec::new();
    for (_, (k, v)) in vars {
        block.extend(k.encode_wide());
        block.push(b'=' as u16);
        block.extend(v.encode_wide());
        block.push(0);
    }
    block.push(0);
    block
}

pub(crate) fn strip_verbatim(path: &Path) -> String {
    let s = path.to_string_lossy();
    s.strip_prefix(r"\\?\").unwrap_or(&s).to_owned()
}

fn to_wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain([0]).collect()
}

/// 按 Windows CreateProcess / CommandLineToArgvW 规则构造命令行字符串。
pub(crate) fn build_windows_cmdline(program: &str, args: &[String]) -> String {
    let mut out = quote_windows_arg(program);
    for arg in args {
        out.push(' ');
        out.push_str(&quote_windows_arg(arg));
    }
    out
}

pub(crate) fn quote_windows_arg(arg: &str) -> String {
    if !arg.is_empty()
        && !arg
            .bytes()
            .any(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\x0b' | b'"'))
    {
        return arg.to_owned();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
        } else if ch == '"' {
            for _ in 0..backslashes * 2 + 1 {
                out.push('\\');
            }
            out.push('"');
            backslashes = 0;
        } else {
            for _ in 0..backslashes {
                out.push('\\');
            }
            backslashes = 0;
            out.push(ch);
        }
    }
    for _ in 0..backslashes * 2 {
        out.push('\\');
    }
    out.push('"');
    out
}

pub(crate) fn system_executable(relative: &str) -> io::Result<PathBuf> {
    let root = std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let exe = root.join(relative);
    if exe.is_file() {
        Ok(exe)
    } else {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("system tool not found: {relative}"),
        ))
    }
}

/// 解析直接调用的可执行文件（优先 .exe/.com，其次 .cmd/.bat）。
pub(crate) fn resolve_program(name: &str) -> Option<(PathBuf, bool)> {
    let path_var = std::env::var_os("PATH")?;
    let lower = name.to_ascii_lowercase();
    let has_ext = lower.ends_with(".exe")
        || lower.ends_with(".com")
        || lower.ends_with(".cmd")
        || lower.ends_with(".bat");
    let exts: &[&str] = if has_ext {
        &[""]
    } else {
        &[".exe", ".com", ".cmd", ".bat"]
    };
    for ext in exts {
        let candidate_name = format!("{name}{ext}");
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(&candidate_name);
            if candidate.is_file() {
                let is_batch = candidate
                    .extension()
                    .and_then(OsStr::to_str)
                    .is_some_and(|e| {
                        e.eq_ignore_ascii_case("cmd") || e.eq_ignore_ascii_case("bat")
                    });
                return Some((candidate, is_batch));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn write_restricted_sandbox_allows_workspace_and_blocks_outside_writes() {
        let base = std::env::temp_dir().join(format!(
            "muse-sandbox-test-{}",
            super::super::token::generate()
        ));
        let _cleanup = Cleanup(base.clone());
        let workspace = base.join("workspace");
        let nested = workspace.join("sub");
        let outside = base.join("outside");
        let temp_dir = base.join("job-tmp");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let existing_file = nested.join("existing.txt");
        std::fs::write(&existing_file, "before\n").unwrap();

        let cmd_exe = system_executable(r"System32\cmd.exe").unwrap();
        let outside_file = outside.join("escape.txt");
        let inside_file = workspace.join("ok.txt");

        // 0) 只读快路径：无需触碰工作区 ACL 即可直接运行
        let ro_proc = spawn(
            &SpawnConfig {
                application: cmd_exe.clone(),
                command_line: format!(
                    "{} /d /s /c \"echo fast-ro\"",
                    quote_windows_arg(&strip_verbatim(&cmd_exe)),
                ),
                cwd: workspace.clone(),
                temp_dir: temp_dir.clone(),
                sandboxed: true,
                write_workspace: false,
                limits: JobLimits {
                    memory_bytes: Some(DEFAULT_EXEC_MEMORY_BYTES),
                    max_processes: Some(DEFAULT_EXEC_MAX_PROCESSES),
                },
            },
            None,
        )
        .unwrap();
        assert_eq!(ro_proc.wait_timeout(10_000).unwrap().unwrap(), 0);

        // 1) 在写受限沙箱内新建与修改工作区已有文件：必须成功
        let inside_proc = spawn(
            &SpawnConfig {
                application: cmd_exe.clone(),
                command_line: format!(
                    "{} /d /s /c \"echo hello-sandbox> {} && echo after>> {}\"",
                    quote_windows_arg(&strip_verbatim(&cmd_exe)),
                    quote_windows_arg(&strip_verbatim(&inside_file)),
                    quote_windows_arg(&strip_verbatim(&existing_file)),
                ),
                cwd: workspace.clone(),
                temp_dir: temp_dir.clone(),
                sandboxed: true,
                write_workspace: true,
                limits: JobLimits {
                    memory_bytes: Some(DEFAULT_EXEC_MEMORY_BYTES),
                    max_processes: Some(DEFAULT_EXEC_MAX_PROCESSES),
                },
            },
            None,
        )
        .unwrap();
        let code = inside_proc.wait_timeout(10_000).unwrap().unwrap();
        assert_eq!(code, 0);
        assert!(
            std::fs::read_to_string(&inside_file)
                .unwrap()
                .contains("hello-sandbox")
        );
        assert!(
            std::fs::read_to_string(&existing_file)
                .unwrap()
                .contains("after")
        );

        // 2) 在写受限沙箱内尝试通过 cmd.exe 写入工作区外部：必须被 Windows 内核拒绝
        let mut outside_proc = spawn(
            &SpawnConfig {
                application: cmd_exe.clone(),
                command_line: format!(
                    "{} /d /s /c \"echo pwn> {}\"",
                    quote_windows_arg(&strip_verbatim(&cmd_exe)),
                    quote_windows_arg(&strip_verbatim(&outside_file))
                ),
                cwd: workspace.clone(),
                temp_dir: temp_dir.clone(),
                sandboxed: true,
                write_workspace: true,
                limits: JobLimits {
                    memory_bytes: Some(DEFAULT_EXEC_MEMORY_BYTES),
                    max_processes: Some(DEFAULT_EXEC_MAX_PROCESSES),
                },
            },
            None,
        )
        .unwrap();
        let code = outside_proc.wait_timeout(10_000).unwrap().unwrap();
        let mut err_buf = String::new();
        if let Some(mut stderr) = outside_proc.stderr.take() {
            let _ = stderr.read_to_string(&mut err_buf);
        }
        assert_ne!(code, 0, "expected outside write to fail, stderr={err_buf}");
        assert!(
            !outside_file.exists(),
            "sandboxed cmd.exe escaped workspace write boundary!"
        );

        // 3) 在写受限沙箱内尝试通过 powershell.exe 写入工作区外部：同样必须被内核拒绝
        if let Ok(ps_exe) = system_executable(r"System32\WindowsPowerShell\v1.0\powershell.exe") {
            let ps_outside = outside.join("ps-escape.txt");
            let ps_cmd = format!(
                "Set-Content -LiteralPath '{}' -Value 'pwn' -ErrorAction Stop",
                strip_verbatim(&ps_outside).replace('\'', "''")
            );
            let ps_proc = spawn(
                &SpawnConfig {
                    application: ps_exe.clone(),
                    command_line: build_windows_cmdline(
                        &strip_verbatim(&ps_exe),
                        &[
                            "-NoProfile".into(),
                            "-NonInteractive".into(),
                            "-Command".into(),
                            ps_cmd,
                        ],
                    ),
                    cwd: workspace.clone(),
                    temp_dir: temp_dir.clone(),
                    sandboxed: true,
                    write_workspace: true,
                    limits: JobLimits {
                        memory_bytes: Some(DEFAULT_EXEC_MEMORY_BYTES),
                        max_processes: Some(DEFAULT_EXEC_MAX_PROCESSES),
                    },
                },
                None,
            )
            .unwrap();
            let ps_code = ps_proc.wait_timeout(15_000).unwrap().unwrap();
            assert_ne!(ps_code, 0, "expected powershell outside write to fail");
            assert!(
                !ps_outside.exists(),
                "sandboxed powershell.exe escaped workspace write boundary!"
            );
        }

        // 4) 跨工作区与父子目录严格隔离：即便父目录 base 与另一个项目 sibling 都运行过沙箱命令，
        //    子工作区 workspace 内运行的命令仍不能向父目录或 sibling 写入。
        let parent_sid = LocalSid::for_workspace(&base).unwrap();
        ensure_sandbox_write_access(&base, parent_sid.0, None).unwrap();
        let parent_escape = base.join("parent-escape.txt");
        let parent_proc = spawn(
            &SpawnConfig {
                application: cmd_exe.clone(),
                command_line: format!(
                    "{} /d /s /c \"echo escape-parent> {}\"",
                    quote_windows_arg(&strip_verbatim(&cmd_exe)),
                    quote_windows_arg(&strip_verbatim(&parent_escape))
                ),
                cwd: workspace.clone(),
                temp_dir: temp_dir.clone(),
                sandboxed: true,
                write_workspace: true,
                limits: JobLimits {
                    memory_bytes: Some(DEFAULT_EXEC_MEMORY_BYTES),
                    max_processes: Some(DEFAULT_EXEC_MAX_PROCESSES),
                },
            },
            None,
        )
        .unwrap();
        let parent_code = parent_proc.wait_timeout(10_000).unwrap().unwrap();
        assert_ne!(
            parent_code, 0,
            "child workspace must NOT inherit write access to previously-sandboxed parent!"
        );
        assert!(
            !parent_escape.exists(),
            "child workspace escaped into previously-sandboxed parent directory!"
        );
    }
}
