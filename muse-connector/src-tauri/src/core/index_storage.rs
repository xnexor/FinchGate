use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::access::reject_reparse_ancestors;

pub(super) fn clear(home: &Path) -> io::Result<()> {
    for path in files(home)? {
        reject_links(&path)?;
        if let Err(error) = fs::remove_file(path)
            && error.kind() != io::ErrorKind::NotFound
        {
            return Err(error);
        }
    }
    Ok(())
}

pub(super) fn bytes(home: &Path) -> Option<u64> {
    files(home).ok()?.into_iter().try_fold(0u64, |total, path| {
        Some(total.saturating_add(path.symlink_metadata().ok()?.len()))
    })
}

fn files(home: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    add_file(&mut files, home.join("file-name-index.json"))?;

    if let Some(entries) = directory(&home.join("search-indexes"))? {
        for entry in entries {
            let entry = entry?;
            if entry
                .file_name()
                .to_str()
                .and_then(|name| name.strip_suffix(".json"))
                .is_some_and(cache_id)
            {
                add_file(&mut files, entry.path())?;
            }
        }
    }
    if let Some(entries) = directory(&home.join("everything"))? {
        for entry in entries {
            let entry = entry?;
            if entry.file_name().to_str().is_some_and(|name| {
                name == "ntfs-v1" || name.strip_prefix("scope-").is_some_and(cache_id)
            }) {
                let path = entry.path();
                reject_links(&path)?;
                add_file(&mut files, path.join("Everything.db"))?;
            }
        }
    }
    Ok(files)
}

fn add_file(files: &mut Vec<PathBuf>, path: PathBuf) -> io::Result<()> {
    match path.symlink_metadata() {
        Ok(metadata) => {
            reject_links(&path)?;
            if !metadata.is_file() {
                return Err(io::Error::other("索引缓存路径不是文件"));
            }
            files.push(path);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

fn directory(path: &Path) -> io::Result<Option<fs::ReadDir>> {
    reject_links(path)?;
    match fs::read_dir(path) {
        Ok(entries) => Ok(Some(entries)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn reject_links(path: &Path) -> io::Result<()> {
    reject_reparse_ancestors(path).map_err(io::Error::other)
}

fn cache_id(name: &str) -> bool {
    name.len() == 16 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
}
