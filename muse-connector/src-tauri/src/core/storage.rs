//! 同目录临时文件替换；失败保留原文件，不覆盖既有临时文件。
use std::io::{self, Write};
use std::path::Path;

pub fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    atomic_write_with(path, |file| file.write_all(bytes))
}

pub(crate) fn atomic_write_with(
    path: &Path,
    write: impl FnOnce(&mut std::fs::File) -> io::Result<()>,
) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("文件缺少父目录"))?;
    std::fs::create_dir_all(parent)?;
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|e| io::Error::other(e.to_string()))?;
    let name: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
    let temporary = parent.join(format!(".muse-{name}.tmp"));
    let mut created = false;
    let result = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        created = true;
        write(&mut f)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&temporary, path)
    })();
    if result.is_err() && created {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}
