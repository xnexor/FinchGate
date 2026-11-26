//! Everything 1.4 QUERY2 Unicode IPC, using the layout in voidtools' Everything_IPC.h.
use std::cell::{Cell, OnceCell};
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::ptr::{null, null_mut};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
use windows_sys::Win32::System::DataExchange::COPYDATASTRUCT;
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const QUERY2_UNICODE: usize = 18;
const IS_DB_LOADED: usize = 401;
const FULL_PATH: u32 = 4;
const SORT_NAME_ASCENDING: u32 = 1;
const MAX_REPLY: usize = 8 * 1024 * 1024;
const CLASS: &str = "MuseEverythingIpc";

static CLASS_REGISTERED: OnceLock<bool> = OnceLock::new();
static NEXT_REPLY_ID: AtomicU32 = AtomicU32::new(1);
thread_local! {
    static WINDOW: OnceCell<Option<Window>> = const { OnceCell::new() };
    static RESPONSE: Cell<Option<Response>> = const { Cell::new(None) };
}

pub(super) enum Reply {
    Page(Vec<PathBuf>),
    Indexing,
    Unavailable,
}

struct Response {
    id: u32,
    paths: Option<Vec<PathBuf>>,
}

pub(super) fn query(
    instance: Option<&str>,
    search: &str,
    offset: u32,
    limit: u32,
    cancel: &AtomicBool,
    deadline: Instant,
) -> Reply {
    let mut class = "EVERYTHING_TASKBAR_NOTIFICATION".to_string();
    if let Some(instance) = instance {
        class.push_str(&format!("_({instance})"));
    }
    let class: Vec<_> = class.encode_utf16().chain([0]).collect();
    // SAFETY: Window class is a terminated UTF-16 name. We verify the handle by sending the
    // documented status message before attempting a query.
    let target = unsafe { FindWindowW(class.as_ptr(), null()) };
    if target.is_null() {
        return Reply::Unavailable;
    }
    match send(target, WM_USER, IS_DB_LOADED, 0, deadline) {
        Some(0) => return Reply::Indexing,
        Some(_) => {}
        None => return Reply::Unavailable,
    }
    WINDOW.with(|slot| {
        let Some(window) = slot.get_or_init(Window::create) else {
            return Reply::Unavailable;
        };
        let id = NEXT_REPLY_ID.fetch_add(1, Ordering::Relaxed);
        let mut data: Vec<u8> = [
            window.0 as usize as u32,
            id,
            0,
            offset,
            limit,
            FULL_PATH,
            SORT_NAME_ASCENDING,
        ]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
        data.extend(search.encode_utf16().chain([0]).flat_map(u16::to_le_bytes));
        let message = COPYDATASTRUCT {
            dwData: QUERY2_UNICODE,
            cbData: data.len() as u32,
            lpData: data.as_mut_ptr().cast(),
        };
        RESPONSE.set(Some(Response { id, paths: None }));
        let accepted = send(
            target,
            WM_COPYDATA,
            window.0 as usize,
            &message as *const COPYDATASTRUCT as LPARAM,
            deadline,
        );
        if accepted != Some(1) {
            RESPONSE.set(None);
            return Reply::Unavailable;
        }

        let mut message = MSG::default();
        while !cancel.load(Ordering::Acquire) && Instant::now() < deadline {
            // SAFETY: This window belongs to the current thread. PeekMessage also dispatches
            // pending synchronous IPC replies to its window procedure.
            unsafe {
                while PeekMessageW(&mut message, window.0, 0, 0, PM_REMOVE) != 0 {
                    DispatchMessageW(&message);
                }
            }
            let response = RESPONSE.take();
            match response {
                Some(Response {
                    paths: Some(paths), ..
                }) => return Reply::Page(paths),
                pending => RESPONSE.set(pending),
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let wait = remaining.min(Duration::from_millis(10)).as_millis() as u32;
            // SAFETY: No kernel handles are supplied. Wait only for sent window messages.
            unsafe {
                MsgWaitForMultipleObjectsEx(0, null(), wait, QS_SENDMESSAGE, MWMO_INPUTAVAILABLE)
            };
        }
        RESPONSE.set(None);
        Reply::Unavailable
    })
}

fn send(
    target: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    deadline: Instant,
) -> Option<usize> {
    let timeout = deadline.saturating_duration_since(Instant::now());
    if timeout.is_zero() {
        return None;
    }
    let mut result = 0;
    // SAFETY: The optional WM_COPYDATA payload stays valid until the call returns.
    let delivered = unsafe {
        SendMessageTimeoutW(
            target,
            message,
            wparam,
            lparam,
            SMTO_ABORTIFHUNG | SMTO_ERRORONEXIT,
            timeout.as_millis().max(1) as u32,
            &mut result,
        )
    };
    (delivered != 0).then_some(result)
}

struct Window(HWND);

impl Window {
    fn create() -> Option<Self> {
        let class: Vec<_> = CLASS.encode_utf16().chain([0]).collect();
        // SAFETY: The module is the current executable. The class name and window procedure are
        // valid for the process lifetime. The returned window is owned by this worker thread.
        unsafe {
            let module = GetModuleHandleW(null());
            if module.is_null() {
                return None;
            }
            if !CLASS_REGISTERED.get_or_init(|| {
                RegisterClassW(&WNDCLASSW {
                    lpfnWndProc: Some(window_proc),
                    hInstance: module,
                    lpszClassName: class.as_ptr(),
                    ..Default::default()
                }) != 0
            }) {
                return None;
            }
            let window = CreateWindowExW(
                0,
                class.as_ptr(),
                null(),
                0,
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                null_mut(),
                module,
                null(),
            );
            (!window.is_null()).then_some(Self(window))
        }
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        // SAFETY: This thread-local window is destroyed on its owning thread.
        unsafe { DestroyWindow(self.0) };
    }
}

unsafe extern "system" fn window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message != WM_COPYDATA || lparam == 0 {
        // SAFETY: Forward the unchanged system-provided message.
        return unsafe { DefWindowProcW(window, message, wparam, lparam) };
    }
    // SAFETY: Windows supplies the marshalled COPYDATASTRUCT and a payload valid during this callback.
    let message = unsafe { &*(lparam as *const COPYDATASTRUCT) };
    let size = message.cbData as usize;
    if message.lpData.is_null() || !(20..=MAX_REPLY).contains(&size) {
        return 0;
    }
    RESPONSE
        .try_with(|slot| {
            let Some(mut response) = slot.take() else {
                return 0;
            };
            if message.dwData == response.id as usize {
                let data = unsafe { std::slice::from_raw_parts(message.lpData.cast::<u8>(), size) };
                response.paths = decode(data);
            }
            let accepted = response.paths.is_some();
            slot.set(Some(response));
            isize::from(accepted)
        })
        .unwrap_or(0)
}

fn decode(data: &[u8]) -> Option<Vec<PathBuf>> {
    fn dword(data: &[u8], at: usize) -> Option<u32> {
        Some(u32::from_le_bytes(
            data.get(at..at.checked_add(4)?)?.try_into().ok()?,
        ))
    }

    let count = dword(data, 4)? as usize;
    if dword(data, 12)? != FULL_PATH || count > (data.len().checked_sub(20)? / 8) {
        return None;
    }
    let data_start = 20 + count * 8;
    let mut paths = Vec::with_capacity(count);
    for index in 0..count {
        let offset = dword(data, 24 + index * 8)? as usize;
        if offset < data_start {
            return None;
        }
        let length = dword(data, offset)? as usize;
        let start = offset.checked_add(4)?;
        let end = start.checked_add(length.checked_mul(2)?)?;
        let text = data.get(start..end)?;
        if data.get(end..end.checked_add(2)?)? != [0, 0] {
            return None;
        }
        let units: Vec<_> = text
            .chunks_exact(2)
            .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
            .collect();
        paths.push(PathBuf::from(std::ffi::OsString::from_wide(&units)));
    }
    Some(paths)
}
