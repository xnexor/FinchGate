//! 文件系统操作从已验证的授权根句柄开始，后续操作只使用相对句柄或已打开文件。

use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::mem::{offset_of, size_of, size_of_val};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, PathBuf};

use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    FILE_CREATE, FILE_DIRECTORY_FILE, FILE_DISPOSITION_INFORMATION, FILE_FULL_DIR_INFORMATION,
    FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION,
    FILE_SYNCHRONOUS_IO_NONALERT, FileDispositionInformation, FileFullDirectoryInformation,
    FileRenameInformation, NtCreateFile, NtQueryDirectoryFile, NtSetInformationFile,
};
use windows_sys::Win32::Foundation::{
    GENERIC_READ, GENERIC_WRITE, HANDLE, NTSTATUS, OBJ_CASE_INSENSITIVE, OBJ_DONT_REPARSE,
    RtlNtStatusToDosError, STATUS_FILE_IS_A_DIRECTORY, STATUS_LOCK_NOT_GRANTED,
    STATUS_NO_MORE_FILES, STATUS_NO_SUCH_FILE, STATUS_NOT_A_DIRECTORY,
    STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND,
    STATUS_REPARSE_POINT_ENCOUNTERED, STATUS_SHARING_VIOLATION, UNICODE_STRING,
};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_LIST_DIRECTORY, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, GetFileInformationByHandle, GetFinalPathNameByHandleW,
    SYNCHRONIZE, VOLUME_NAME_DOS,
};
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

use super::path_guard::Resolved;

const SHARE_DIRECTORY: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE;
const SHARE_FILE: u32 = SHARE_DIRECTORY | FILE_SHARE_DELETE;
const FILETIME_UNIX_EPOCH: i64 = 116_444_736_000_000_000;

#[derive(Debug)]
pub(crate) enum Error {
    Missing,
    NotDirectory,
    IsDirectory,
    Escape,
    Changed,
    Exists,
    Io(io::Error),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        match error.kind() {
            io::ErrorKind::NotFound => Self::Missing,
            io::ErrorKind::NotADirectory => Self::NotDirectory,
            io::ErrorKind::IsADirectory => Self::IsDirectory,
            io::ErrorKind::AlreadyExists => Self::Exists,
            _ if matches!(error.raw_os_error(), Some(32 | 33)) => Self::Changed,
            _ => Self::Io(error),
        }
    }
}

fn status_result(status: NTSTATUS) -> Result<(), Error> {
    match status {
        STATUS_OBJECT_NAME_NOT_FOUND | STATUS_OBJECT_PATH_NOT_FOUND | STATUS_NO_SUCH_FILE => {
            Err(Error::Missing)
        }
        STATUS_NOT_A_DIRECTORY => Err(Error::NotDirectory),
        STATUS_FILE_IS_A_DIRECTORY => Err(Error::IsDirectory),
        STATUS_OBJECT_NAME_COLLISION => Err(Error::Exists),
        STATUS_REPARSE_POINT_ENCOUNTERED => Err(Error::Escape),
        STATUS_SHARING_VIOLATION | STATUS_LOCK_NOT_GRANTED => Err(Error::Changed),
        status if status >= 0 => Ok(()),
        status => Err(Error::from(io::Error::from_raw_os_error(unsafe {
            RtlNtStatusToDosError(status) as i32
        }))),
    }
}

fn relative(target: &Resolved) -> Result<&Path, Error> {
    let canonical = target
        .path
        .strip_prefix(&target.root)
        .map_err(|_| Error::Escape)?;
    Ok(if target.reject_reparse {
        &target.requested_relative
    } else {
        canonical
    })
}

fn open_absolute(path: &Path, access: u32, share: u32) -> Result<File, Error> {
    Ok(OpenOptions::new()
        .access_mode(access)
        .share_mode(share)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?)
}

fn open_root(target: &Resolved, access: u32) -> Result<File, Error> {
    let access = access | FILE_READ_ATTRIBUTES;
    let file = if target.reject_reparse {
        let volume: PathBuf = target.requested_root.components().take(2).collect();
        if !volume.is_absolute() {
            return Err(Error::Escape);
        }
        let relative: PathBuf = target
            .requested_root
            .strip_prefix(&volume)
            .map_err(|_| Error::Escape)?
            .components()
            .collect();
        if relative.as_os_str().is_empty() {
            open_absolute(&volume, access, SHARE_DIRECTORY)?
        } else {
            let device = open_absolute(&volume, 0, SHARE_FILE)?;
            open_relative(
                &device,
                relative.as_os_str(),
                access,
                FILE_OPEN,
                FILE_DIRECTORY_FILE,
                SHARE_DIRECTORY,
            )?
        }
    } else {
        open_absolute(&target.root, access, SHARE_DIRECTORY)?
    };
    if attributes(&file)? & FILE_ATTRIBUTE_DIRECTORY == 0 {
        return Err(Error::NotDirectory);
    }
    // Keep the exact canonical root from authorization, including the extended path prefix.
    let mut name = vec![0u16; 512];
    loop {
        let length = unsafe {
            GetFinalPathNameByHandleW(
                raw(&file),
                name.as_mut_ptr(),
                name.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        } as usize;
        if length == 0 {
            return Err(io::Error::last_os_error().into());
        }
        if length < name.len() {
            let actual = OsString::from_wide(&name[..length]);
            return if Path::new(&actual) == target.root {
                Ok(file)
            } else {
                Err(Error::Changed)
            };
        }
        name.resize(length + 1, 0);
    }
}

fn raw(file: &File) -> HANDLE {
    file.as_raw_handle().cast()
}

fn attributes(file: &File) -> Result<u32, Error> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(raw(file), &mut info) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(Error::Escape);
    }
    Ok(info.dwFileAttributes)
}

fn open_relative(
    parent: &File,
    name: &OsStr,
    access: u32,
    disposition: u32,
    kind: u32,
    share: u32,
) -> Result<File, Error> {
    let mut wide: Vec<u16> = name.encode_wide().collect();
    let length = u16::try_from(size_of_val(wide.as_slice())).map_err(|_| Error::Escape)?;
    let mut name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: wide.as_mut_ptr(),
    };
    let object = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: raw(parent),
        ObjectName: &mut name,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        ..Default::default()
    };
    let mut result = std::ptr::null_mut();
    let mut io_status = IO_STATUS_BLOCK::default();
    // All buffers and the parent handle are live for this synchronous call.
    let status = unsafe {
        NtCreateFile(
            &mut result,
            access | SYNCHRONIZE,
            &object,
            &mut io_status,
            std::ptr::null(),
            FILE_ATTRIBUTE_NORMAL,
            share,
            disposition,
            kind | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            std::ptr::null(),
            0,
        )
    };
    status_result(status)?;
    // A successful NtCreateFile gives ownership of the new handle to the caller.
    let file = unsafe { File::from_raw_handle(result.cast()) };
    if disposition != FILE_CREATE {
        attributes(&file)?;
    }
    Ok(file)
}

pub(crate) fn read(target: &Resolved) -> Result<File, Error> {
    let path = relative(target)?;
    if path.as_os_str().is_empty() {
        return Err(Error::IsDirectory);
    }
    let root = open_root(target, 0)?;
    open_relative(
        &root,
        path.as_os_str(),
        GENERIC_READ,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
        SHARE_FILE,
    )
}

pub(crate) struct Entry {
    pub(crate) name: OsString,
    pub(crate) size: u64,
    pub(crate) mtime: f64,
    pub(crate) is_directory: bool,
    pub(crate) is_reparse: bool,
}

pub(crate) fn list(target: &Resolved, mut visit: impl FnMut(Entry)) -> Result<(), Error> {
    let path = relative(target)?;
    let is_root = path.as_os_str().is_empty();
    let root = open_root(target, if is_root { FILE_LIST_DIRECTORY } else { 0 })?;
    let child;
    let directory = if is_root {
        &root
    } else {
        child = open_relative(
            &root,
            path.as_os_str(),
            FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            FILE_OPEN,
            FILE_DIRECTORY_FILE,
            SHARE_DIRECTORY,
        )?;
        &child
    };

    // The kernel packs records with UTF-16 names into this eight-byte aligned buffer.
    let mut buffer = vec![0u64; 4096];
    loop {
        let mut io_status = IO_STATUS_BLOCK::default();
        // The call is synchronous, with no event or completion callback.
        let status = unsafe {
            NtQueryDirectoryFile(
                raw(directory),
                std::ptr::null_mut(),
                None,
                std::ptr::null(),
                &mut io_status,
                buffer.as_mut_ptr().cast(),
                size_of_val(buffer.as_slice()) as u32,
                FileFullDirectoryInformation,
                false,
                std::ptr::null(),
                false,
            )
        };
        if matches!(status, STATUS_NO_MORE_FILES | STATUS_NO_SUCH_FILE) {
            return Ok(());
        }
        status_result(status)?;
        if io_status.Information == 0 {
            return Ok(());
        }
        visit_entries(&buffer, io_status.Information, &mut visit)?;
    }
}

fn visit_entries(buffer: &[u64], used: usize, visit: &mut impl FnMut(Entry)) -> Result<(), Error> {
    // The backing buffer is initialized, and the byte slice cannot outlive it.
    let bytes =
        unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), size_of_val(buffer)) };
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid directory information");
    let mut entries = bytes.get(..used).ok_or_else(invalid)?;
    let name_offset = offset_of!(FILE_FULL_DIR_INFORMATION, FileName);
    loop {
        if entries.len() < name_offset {
            return Err(invalid().into());
        }
        // Only copy the fixed header. The trailing FileName field is variable length.
        let mut record = FILE_FULL_DIR_INFORMATION::default();
        unsafe {
            std::ptr::copy_nonoverlapping(
                entries.as_ptr(),
                std::ptr::from_mut(&mut record).cast(),
                name_offset,
            )
        };
        let next = record.NextEntryOffset as usize;
        let end = if next == 0 { entries.len() } else { next };
        let name_end = name_offset
            .checked_add(record.FileNameLength as usize)
            .ok_or_else(invalid)?;
        if name_end > end || end > entries.len() || !record.FileNameLength.is_multiple_of(2) {
            return Err(invalid().into());
        }
        let (units, _) = entries[name_offset..name_end].as_chunks::<2>();
        let wide: Vec<u16> = units
            .iter()
            .map(|&chunk| u16::from_le_bytes(chunk))
            .collect();
        let name = OsString::from_wide(&wide);
        if name != "." && name != ".." {
            visit(Entry {
                name,
                size: record.EndOfFile.max(0) as u64,
                mtime: record
                    .LastWriteTime
                    .saturating_sub(FILETIME_UNIX_EPOCH)
                    .max(0) as f64
                    / 10_000_000.0,
                is_directory: record.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
                is_reparse: record.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0,
            });
        }
        if next == 0 {
            return Ok(());
        }
        entries = &entries[next..];
    }
}

fn open_or_create_directory(parent: &File, name: &OsStr) -> Result<File, Error> {
    let open = || {
        open_relative(
            parent,
            name,
            FILE_READ_ATTRIBUTES,
            FILE_OPEN,
            FILE_DIRECTORY_FILE,
            SHARE_DIRECTORY,
        )
    };
    match open() {
        Err(Error::Missing) => match open_relative(
            parent,
            name,
            FILE_READ_ATTRIBUTES,
            FILE_CREATE,
            FILE_DIRECTORY_FILE,
            SHARE_DIRECTORY,
        ) {
            Err(Error::Exists) => open(),
            result => result,
        },
        result => result,
    }
}

fn ensure_directory(target: &Resolved, path: &Path) -> Result<Vec<File>, Error> {
    let mut handles = vec![open_root(target, 0)?];
    for component in path.components() {
        let Component::Normal(name) = component else {
            return Err(Error::Escape);
        };
        let directory = open_or_create_directory(handles.last().unwrap(), name)?;
        handles.push(directory);
    }
    Ok(handles)
}

pub(crate) fn mkdir(target: &Resolved) -> Result<(), Error> {
    ensure_directory(target, relative(target)?)?;
    Ok(())
}

pub(crate) fn write(target: &Resolved, bytes: &[u8]) -> Result<(), Error> {
    let path = relative(target)?;
    let name = path.file_name().ok_or(Error::IsDirectory)?;
    let directories = ensure_directory(target, path.parent().ok_or(Error::Escape)?)?;
    let directory = directories.last().unwrap();
    match open_relative(
        directory,
        name,
        FILE_READ_ATTRIBUTES,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
        SHARE_FILE,
    ) {
        Ok(_) | Err(Error::Missing) => (),
        Err(error) => return Err(error),
    }

    let temp = (0..4)
        .find_map(|_| {
            let name = format!(".muse-{}.tmp", super::token::generate());
            match open_relative(
                directory,
                OsStr::new(&name),
                GENERIC_WRITE | DELETE,
                FILE_CREATE,
                FILE_NON_DIRECTORY_FILE,
                0,
            ) {
                Err(Error::Exists) => None,
                result => Some(result),
            }
        })
        .ok_or(Error::Changed)??;
    let mut temp = temp;
    let result = (|| {
        temp.write_all(bytes)?;
        temp.sync_all()?;
        rename(&temp, directory, name)
    })();
    if result.is_err() {
        delete_on_close(&temp)?;
    }
    result
}

fn rename(file: &File, directory: &File, name: &OsStr) -> Result<(), Error> {
    let wide: Vec<u16> = name.encode_wide().collect();
    let name_size = size_of_val(wide.as_slice());
    let size = (offset_of!(FILE_RENAME_INFORMATION, FileName) + name_size)
        .max(size_of::<FILE_RENAME_INFORMATION>());
    let mut buffer = vec![0usize; size.div_ceil(size_of::<usize>())];
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
    let mut io_status = IO_STATUS_BLOCK::default();
    // The storage is aligned and large enough for both the fixed header and the complete name.
    let status = unsafe {
        (*info).Anonymous.ReplaceIfExists = true;
        (*info).RootDirectory = raw(directory);
        (*info).FileNameLength = name_size as u32;
        let name_buffer = info
            .cast::<u8>()
            .add(offset_of!(FILE_RENAME_INFORMATION, FileName))
            .cast::<u16>();
        std::ptr::copy_nonoverlapping(wide.as_ptr(), name_buffer, wide.len());
        NtSetInformationFile(
            raw(file),
            &mut io_status,
            info.cast(),
            size as u32,
            FileRenameInformation,
        )
    };
    status_result(status)
}

fn delete_on_close(file: &File) -> Result<(), Error> {
    let mut io_status = IO_STATUS_BLOCK::default();
    let info = FILE_DISPOSITION_INFORMATION { DeleteFile: true };
    let status = unsafe {
        NtSetInformationFile(
            raw(file),
            &mut io_status,
            std::ptr::from_ref(&info).cast(),
            size_of::<FILE_DISPOSITION_INFORMATION>() as u32,
            FileDispositionInformation,
        )
    };
    status_result(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    struct Fixture(PathBuf);

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .join(format!("muse-handle-{}", super::super::token::generate()));
            std::fs::create_dir(&root).unwrap();
            Self(root)
        }

        fn target(&self, path: &str) -> Resolved {
            let roots = [("root".to_owned(), self.0.clone())].into();
            let mut target = super::super::path_guard::resolve(&roots, "root", path).unwrap();
            target.reject_reparse = true;
            target
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn reading_keeps_the_open_file_when_its_name_changes() {
        let fixture = Fixture::new();
        let target = fixture.target("note.txt");
        std::fs::write(&target.path, b"original").unwrap();
        let mut file = read(&target).unwrap();
        std::fs::rename(&target.path, fixture.0.join("moved.txt")).unwrap();
        std::fs::write(&target.path, b"replacement").unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original");
    }

    #[test]
    fn failed_replacement_keeps_the_previous_file_and_removes_the_temp_file() {
        let fixture = Fixture::new();
        let target = fixture.target("note.txt");
        write(&target, b"original").unwrap();
        let locked = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&target.path)
            .unwrap();
        assert!(write(&target, b"replacement").is_err());
        assert_eq!(std::fs::read(&target.path).unwrap(), b"original");
        assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
        drop(locked);
        write(&target, b"replacement").unwrap();
        assert_eq!(std::fs::read(&target.path).unwrap(), b"replacement");
        assert_eq!(std::fs::read_dir(&fixture.0).unwrap().count(), 1);
    }

    #[test]
    fn verified_directories_stay_in_place_until_the_operation_releases_them() {
        let fixture = Fixture::new();
        let target = fixture.target("parent/child");
        let handles = ensure_directory(&target, relative(&target).unwrap()).unwrap();
        let parent = fixture.0.join("parent");
        let renamed = fixture.0.join("renamed");
        assert!(std::fs::rename(&parent, &renamed).is_err());
        drop(handles);
        std::fs::rename(parent, &renamed).unwrap();
        assert!(renamed.join("child").is_dir());
    }

    #[test]
    fn write_keeps_existing_directories_intact() {
        let fixture = Fixture::new();
        let target = fixture.target("folder");
        mkdir(&target).unwrap();
        std::fs::write(target.path.join("note.txt"), b"original").unwrap();
        assert!(matches!(
            write(&target, b"replacement"),
            Err(Error::IsDirectory)
        ));
        assert_eq!(
            std::fs::read(target.path.join("note.txt")).unwrap(),
            b"original"
        );
    }
}
