//! Windows Job Object 包装：主进程退出或关闭句柄时自动终止整棵子进程树，支持内存与进程数硬上限。
#![cfg(windows)]

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject,
};

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct JobLimits {
    pub(crate) memory_bytes: Option<u64>,
    pub(crate) max_processes: Option<u32>,
}

pub(crate) struct ChildJob {
    handle: OwnedHandle,
}

impl ChildJob {
    pub(crate) fn attach_tokio(child: &tokio::process::Child) -> io::Result<Self> {
        let process = child
            .raw_handle()
            .ok_or_else(|| io::Error::other("child already exited"))?;
        Self::attach_raw_with_limits(process as HANDLE, JobLimits::default())
    }

    pub(crate) fn attach_std(child: &std::process::Child) -> io::Result<Self> {
        Self::attach_raw_with_limits(child.as_raw_handle() as HANDLE, JobLimits::default())
    }

    pub(crate) fn attach_raw_with_limits(process: HANDLE, limits: JobLimits) -> io::Result<Self> {
        // SAFETY: null attributes/name create an unnamed, non-inheritable job. OwnedHandle
        // owns that valid handle; the limit structure lives through the synchronous call.
        unsafe {
            let raw = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if raw.is_null() {
                return Err(io::Error::last_os_error());
            }
            let handle = OwnedHandle::from_raw_handle(raw);
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            let mut flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if let Some(bytes) = limits.memory_bytes {
                flags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
                info.JobMemoryLimit = usize::try_from(bytes).unwrap_or(usize::MAX);
            }
            if let Some(max_processes) = limits.max_processes {
                flags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
                info.BasicLimitInformation.ActiveProcessLimit = max_processes.max(1);
            }
            info.BasicLimitInformation.LimitFlags = flags;
            if SetInformationJobObject(
                handle.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of_val(&info) as u32,
            ) == 0
                || AssignProcessToJobObject(handle.as_raw_handle(), process) == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(Self { handle })
        }
    }

    pub(crate) fn terminate(&self) {
        // SAFETY: `self.handle` is a live job handle owned by `self`.
        unsafe {
            let _ = TerminateJobObject(self.handle.as_raw_handle(), 1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::process::CommandExt;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    #[test]
    fn closing_job_terminates_std_child() {
        let system =
            PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32/ping.exe");
        let mut child = Command::new(system)
            .creation_flags(CREATE_NO_WINDOW)
            .args(["-n", "120", "127.0.0.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let job = ChildJob::attach_std(&child).unwrap();
        assert!(child.try_wait().unwrap().is_none());
        drop(job);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            assert!(Instant::now() < deadline, "child survived job close");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}
