use std::{mem, ptr};
use windows_sys::Win32::Foundation::{GlobalFree, HGLOBAL, HWND};
use windows_sys::Win32::System::{
    DataExchange::{
        CloseClipboard, EmptyClipboard, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
    },
    Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock},
};

const CF_UNICODETEXT: u32 = 13;
const COPY_FAILED: &str = "复制令牌失败，可从令牌文件手动复制";

pub(crate) fn copy_secret(owner: HWND, secret: &str) -> Result<(), &'static str> {
    let exclude_format = windows_sys::core::w!("ExcludeClipboardContentFromMonitorProcessing");
    // Windows uses this registered format to suppress clipboard history and roaming.
    let exclude_format = unsafe { RegisterClipboardFormatW(exclude_format) };
    if exclude_format == 0 {
        return Err(COPY_FAILED);
    }
    let text: Vec<u16> = secret.encode_utf16().chain([0]).collect();
    let private = ClipboardMemory::new(&[0_u16])?;
    let text = ClipboardMemory::new(&text)?;

    // The main window owns the clipboard until the guard closes it.
    if unsafe { OpenClipboard(owner) } == 0 {
        return Err("剪贴板正被占用，请稍后再试");
    }
    let _clipboard = ClipboardGuard;
    if unsafe { EmptyClipboard() } == 0 {
        return Err(COPY_FAILED);
    }
    // Publish the privacy marker before publishing the secret.
    private.publish(exclude_format)?;
    text.publish(CF_UNICODETEXT)
}

struct ClipboardGuard;

impl Drop for ClipboardGuard {
    fn drop(&mut self) {
        unsafe { CloseClipboard() };
    }
}

struct ClipboardMemory(HGLOBAL);

impl ClipboardMemory {
    fn new(text: &[u16]) -> Result<Self, &'static str> {
        // SetClipboardData requires movable memory for these formats.
        let data = Self(unsafe { GlobalAlloc(GMEM_MOVEABLE, mem::size_of_val(text)) });
        if data.0.is_null() {
            return Err(COPY_FAILED);
        }
        let target = unsafe { GlobalLock(data.0) }.cast::<u16>();
        if target.is_null() {
            return Err(COPY_FAILED);
        }
        // The locked block holds exactly the input's UTF-16 code units.
        unsafe {
            ptr::copy_nonoverlapping(text.as_ptr(), target, text.len());
            GlobalUnlock(data.0);
        }
        Ok(data)
    }

    fn publish(mut self, format: u32) -> Result<(), &'static str> {
        if unsafe { SetClipboardData(format, self.0) }.is_null() {
            return Err(COPY_FAILED);
        }
        // Ownership transfers to Windows only after a successful call.
        self.0 = ptr::null_mut();
        Ok(())
    }
}

impl Drop for ClipboardMemory {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { GlobalFree(self.0) };
        }
    }
}
