use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::hash::{BuildHasher, Hasher};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{OnceLock, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::WasiPolicy;

pub const ERRNO_SUCCESS: i32 = 0;
pub const ERRNO_BADF: i32 = 8;
pub const ERRNO_FAULT: i32 = 21;
pub const ERRNO_INVAL: i32 = 28;
pub const ERRNO_IO: i32 = 29;
pub const ERRNO_NOENT: i32 = 44;
pub const ERRNO_NOTDIR: i32 = 54;
pub const ERRNO_NOSYS: i32 = 52;
pub const ERRNO_PERM: i32 = 63;

const FILETYPE_CHARACTER_DEVICE: u8 = 2;
const FILETYPE_DIRECTORY: u8 = 3;
const FILETYPE_REGULAR_FILE: u8 = 4;
const FILETYPE_SYMBOLIC_LINK: u8 = 7;
const FILETYPE_UNKNOWN: u8 = 0;

const PREOPENS_ENV: &str = "RUSTC_WATT_PREOPENS";
const DETERMINISTIC_RANDOM_ENV: &str = "RUSTC_WATT_DETERMINISTIC_RANDOM";
const RIGHTS_FD_WRITE: u64 = 1u64 << 6;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Filestat {
    pub dev: u64,
    pub ino: u64,
    pub filetype: u8,
    pub nlink: u64,
    pub size: u64,
    pub atim: u64,
    pub mtim: u64,
    pub ctim: u64,
}

#[derive(Clone, Debug)]
struct PreopenDir {
    root: PathBuf,
    guest_path: String,
    writable: bool,
}

#[derive(Debug)]
enum FdEntry {
    Stdin,
    Stdout,
    Stderr,
    PreopenDir(PreopenDir),
    OpenDir { root: PathBuf, writable: bool },
    OpenFile { file: File, writable: bool },
}

#[derive(Debug)]
struct WasiProcMacroCtx {
    args_entries: Vec<Vec<u8>>,
    env_entries: Vec<Vec<u8>>,
    stdout_capture: Vec<u8>,
    stderr_capture: Vec<u8>,
    mirror_stdio: bool,
    deterministic_random: bool,
    random_state: std::collections::hash_map::RandomState,
    random_counter: u64,
    fds: Vec<Option<FdEntry>>,
}

fn collect_args_entries() -> Vec<Vec<u8>> {
    let mut args_entries = Vec::new();
    for arg in std::env::args_os() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(arg.to_string_lossy().as_bytes());
        bytes.push(0);
        args_entries.push(bytes);
    }
    args_entries
}

fn collect_env_entries(allowlist: Option<&[String]>) -> Vec<Vec<u8>> {
    let mut env_entries = Vec::new();
    let allow_all = allowlist.is_none_or(|v| v.is_empty());
    for (k, v) in std::env::vars_os() {
        if !allow_all {
            let key = k.to_string_lossy();
            let allowed = allowlist
                .expect("allowlist must exist when allow_all is false")
                .iter()
                .any(|name| name == &*key);
            if !allowed {
                continue;
            }
        }

        let mut bytes = Vec::new();
        bytes.extend_from_slice(k.to_string_lossy().as_bytes());
        bytes.push(b'=');
        bytes.extend_from_slice(v.to_string_lossy().as_bytes());
        bytes.push(0);
        env_entries.push(bytes);
    }
    env_entries
}

fn parse_preopen_spec(spec: &str) -> Option<(String, bool)> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(path) = trimmed.strip_suffix(":rw") {
        return Some((path.trim().to_string(), true));
    }
    if let Some(path) = trimmed.strip_suffix(":ro") {
        return Some((path.trim().to_string(), false));
    }
    Some((trimmed.to_string(), false))
}

fn canonicalize_dir(path: &Path) -> Option<PathBuf> {
    let canon = path.canonicalize().ok()?;
    if canon.is_dir() { Some(canon) } else { None }
}

fn preopens_from_host() -> Vec<PreopenDir> {
    let mut out = Vec::new();
    if let Ok(raw) = std::env::var(PREOPENS_ENV) {
        for entry in raw.split(';') {
            let Some((path, writable)) = parse_preopen_spec(entry) else {
                continue;
            };
            let root = PathBuf::from(path.clone());
            if let Some(canon) = canonicalize_dir(&root) {
                out.push(PreopenDir {
                    root: canon,
                    guest_path: path,
                    writable,
                });
            }
        }
    }

    if out.is_empty() {
        if let Ok(cwd) = std::env::current_dir() {
            if let Some(canon) = canonicalize_dir(&cwd) {
                // Match native-like proc-macro behavior as closely as possible:
                // default cwd preopen is writable unless caller narrows policy.
                out.push(PreopenDir {
                    root: canon,
                    guest_path: cwd.to_string_lossy().to_string(),
                    writable: true,
                });
            }
        }
    }
    out
}

fn preopens_from_policy(policy: &WasiPolicy) -> Vec<PreopenDir> {
    let mut out = Vec::new();
    for entry in &policy.preopens {
        let guest_path = entry
            .guest_path
            .as_ref()
            .unwrap_or(&entry.path)
            .to_string_lossy()
            .to_string();
        if let Some(canon) = canonicalize_dir(&entry.path) {
            out.push(PreopenDir {
                root: canon,
                guest_path,
                writable: entry.writable,
            });
            continue;
        }

        // Proc-macro WASI policy is constructed by rustc itself. Inside the outer
        // rustc.wasm environment, canonicalize() can fail even for guest-visible
        // absolute paths like `/` or `/.`, but those paths are still the right
        // roots to hand to the nested proc-macro runtime.
        if entry.path.is_absolute() {
            out.push(PreopenDir {
                root: entry.path.clone(),
                guest_path,
                writable: entry.writable,
            });
        }
    }
    out
}

fn policy_cell() -> &'static RwLock<Option<WasiPolicy>> {
    static CELL: OnceLock<RwLock<Option<WasiPolicy>>> = OnceLock::new();
    CELL.get_or_init(|| RwLock::new(None))
}

fn active_policy() -> Option<WasiPolicy> {
    policy_cell()
        .read()
        .ok()
        .and_then(|guard| guard.clone())
}

impl WasiProcMacroCtx {
    fn from_host() -> Self {
        let policy = active_policy();
        let mut fds = vec![Some(FdEntry::Stdin), Some(FdEntry::Stdout), Some(FdEntry::Stderr)];
        let preopens = if let Some(policy) = &policy {
            preopens_from_policy(policy)
        } else {
            preopens_from_host()
        };
        for dir in preopens {
            fds.push(Some(FdEntry::PreopenDir(dir)));
        }

        Self {
            args_entries: if policy.as_ref().is_none_or(|p| p.inherit_args) {
                collect_args_entries()
            } else {
                Vec::new()
            },
            env_entries: if policy.as_ref().is_none_or(|p| p.inherit_env) {
                collect_env_entries(policy.as_ref().map(|p| p.env_allowlist.as_slice()))
            } else {
                Vec::new()
            },
            stdout_capture: Vec::new(),
            stderr_capture: Vec::new(),
            mirror_stdio: policy.as_ref().map_or(true, |p| p.mirror_stdio),
            deterministic_random: policy.as_ref().map_or_else(
                || {
                    std::env::var(DETERMINISTIC_RANDOM_ENV)
                        .ok()
                        .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                },
                |p| p.deterministic_random,
            ),
            random_state: std::collections::hash_map::RandomState::new(),
            random_counter: 0,
            fds,
        }
    }

    fn fd_entry(&self, fd: u32) -> Option<&FdEntry> {
        self.fds.get(fd as usize)?.as_ref()
    }

    fn fd_entry_mut(&mut self, fd: u32) -> Option<&mut FdEntry> {
        self.fds.get_mut(fd as usize)?.as_mut()
    }

    fn alloc_fd(&mut self, entry: FdEntry) -> u32 {
        for (idx, slot) in self.fds.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(entry);
                return idx as u32;
            }
        }
        self.fds.push(Some(entry));
        (self.fds.len() - 1) as u32
    }
}

fn is_rel_path_safe(path: &Path) -> bool {
    if path.is_absolute() {
        return false;
    }
    !path
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::RootDir | Component::Prefix(_)))
}

fn normalize_rel_path(path: &Path) -> Result<PathBuf, i32> {
    if !is_rel_path_safe(path) {
        return Err(ERRNO_PERM);
    }

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ERRNO_PERM);
            }
        }
    }

    Ok(normalized)
}

fn should_fallback_to_guest_path(root: &Path) -> bool {
    if !root.is_absolute() {
        return false;
    }
    if canonicalize_dir(root).is_some() {
        return false;
    }
    std::fs::metadata(root).is_ok_and(|meta| meta.is_dir())
}

fn resolve_in_preopen(root: &Path, rel_path: &Path) -> Result<PathBuf, i32> {
    let rel_path = normalize_rel_path(rel_path)?;
    let allow_guest_fallback = should_fallback_to_guest_path(root);

    let joined = root.join(rel_path);
    if joined.exists() {
        let canon = match joined.canonicalize() {
            Ok(canon) => canon,
            Err(_) if allow_guest_fallback => return Ok(joined),
            Err(_) => return Err(ERRNO_IO),
        };
        if !canon.starts_with(root) {
            return Err(ERRNO_PERM);
        }
        return Ok(canon);
    }

    let parent = joined.parent().ok_or(ERRNO_PERM)?;
    let parent_canon = match parent.canonicalize() {
        Ok(parent_canon) => parent_canon,
        Err(_) if allow_guest_fallback => return Ok(joined),
        Err(_) => return Err(ERRNO_NOENT),
    };
    if !parent_canon.starts_with(root) {
        return Err(ERRNO_PERM);
    }
    Ok(parent_canon.join(
        joined
            .file_name()
            .ok_or(ERRNO_INVAL)?
            .to_string_lossy()
            .to_string(),
    ))
}

fn wants_write_access(oflags: u32, fdflags: u32, rights_base: u64) -> bool {
    // WASI preview1 oflags bits: CREAT=1, DIRECTORY=2, EXCL=4, TRUNC=8.
    let create_or_trunc = (oflags & 0x1) != 0 || (oflags & 0x8) != 0;
    let fd_writeish = fdflags != 0;
    let rights_write = (rights_base & RIGHTS_FD_WRITE) != 0;
    create_or_trunc || fd_writeish || rights_write
}

fn io_error_to_errno(err: &io::Error) -> i32 {
    match err.kind() {
        io::ErrorKind::NotFound => ERRNO_NOENT,
        io::ErrorKind::PermissionDenied => ERRNO_PERM,
        io::ErrorKind::InvalidInput => ERRNO_INVAL,
        io::ErrorKind::NotADirectory => ERRNO_NOTDIR,
        _ => ERRNO_IO,
    }
}

fn metadata_to_filestat(meta: &std::fs::Metadata) -> Filestat {
    let filetype = if meta.file_type().is_symlink() {
        FILETYPE_SYMBOLIC_LINK
    } else if meta.is_dir() {
        FILETYPE_DIRECTORY
    } else {
        FILETYPE_REGULAR_FILE
    };

    Filestat {
        dev: 0,
        ino: 0,
        filetype,
        nlink: 1,
        size: meta.len(),
        atim: system_time_to_wasi_nanos(meta.accessed()),
        mtim: system_time_to_wasi_nanos(meta.modified()),
        ctim: system_time_to_wasi_nanos(meta.created()),
    }
}

fn std_filetype_to_wasi(file_type: &std::fs::FileType) -> u8 {
    if file_type.is_symlink() {
        FILETYPE_SYMBOLIC_LINK
    } else if file_type.is_dir() {
        FILETYPE_DIRECTORY
    } else if file_type.is_file() {
        FILETYPE_REGULAR_FILE
    } else {
        FILETYPE_UNKNOWN
    }
}

fn dir_root_from_entry(entry: &FdEntry) -> Result<(PathBuf, bool), i32> {
    match entry {
        FdEntry::PreopenDir(dir) => Ok((dir.root.clone(), dir.writable)),
        FdEntry::OpenDir { root, writable } => Ok((root.clone(), *writable)),
        _ => Err(ERRNO_NOTDIR),
    }
}

fn resolve_existing_in_preopen(
    root: &Path,
    rel_path: &Path,
    follow_symlink: bool,
) -> Result<PathBuf, i32> {
    let rel_path = normalize_rel_path(rel_path)?;
    let allow_guest_fallback = should_fallback_to_guest_path(root);

    if rel_path.as_os_str().is_empty() {
        if follow_symlink {
            let canon = match root.canonicalize() {
                Ok(canon) => canon,
                Err(_) if allow_guest_fallback => return Ok(root.to_path_buf()),
                Err(err) => return Err(io_error_to_errno(&err)),
            };
            if !canon.starts_with(root) {
                return Err(ERRNO_PERM);
            }
            return Ok(canon);
        }
        return Ok(root.to_path_buf());
    }

    let joined = root.join(rel_path);
    if follow_symlink {
        let canon = match joined.canonicalize() {
            Ok(canon) => canon,
            Err(_) if allow_guest_fallback => return Ok(joined),
            Err(err) => return Err(io_error_to_errno(&err)),
        };
        if !canon.starts_with(root) {
            return Err(ERRNO_PERM);
        }
        return Ok(canon);
    }

    let parent = joined.parent().ok_or(ERRNO_PERM)?;
    let parent_canon = match parent.canonicalize() {
        Ok(parent_canon) => parent_canon,
        Err(_) if allow_guest_fallback => return Ok(joined),
        Err(err) => return Err(io_error_to_errno(&err)),
    };
    if !parent_canon.starts_with(root) {
        return Err(ERRNO_PERM);
    }
    Ok(parent_canon.join(
        joined
            .file_name()
            .ok_or(ERRNO_INVAL)?
            .to_string_lossy()
            .to_string(),
    ))
}

fn system_time_to_wasi_nanos(time: Result<SystemTime, io::Error>) -> u64 {
    time.ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |duration| duration.as_nanos().min(u64::MAX as u128) as u64)
}

std::thread_local! {
    static CTX: RefCell<WasiProcMacroCtx> = RefCell::new(WasiProcMacroCtx::from_host());
}

pub(crate) fn reset_from_host() {
    CTX.with(|ctx| *ctx.borrow_mut() = WasiProcMacroCtx::from_host());
}

pub(crate) fn set_policy(policy: WasiPolicy) {
    if let Ok(mut guard) = policy_cell().write() {
        *guard = Some(policy);
    }
    reset_from_host();
}

pub(crate) fn clear_policy() {
    if let Ok(mut guard) = policy_cell().write() {
        *guard = None;
    }
    reset_from_host();
}

pub(crate) fn environ_entries() -> Vec<Vec<u8>> {
    CTX.with(|ctx| ctx.borrow().env_entries.clone())
}

pub(crate) fn args_entries() -> Vec<Vec<u8>> {
    CTX.with(|ctx| ctx.borrow().args_entries.clone())
}

pub(crate) fn random_fill(out: &mut [u8]) {
    CTX.with(|ctx| {
        let mut ctx = ctx.borrow_mut();
        if ctx.deterministic_random {
            out.fill(0);
            return;
        }

        let mut i = 0usize;
        while i < out.len() {
            let mut hasher = ctx.random_state.build_hasher();
            hasher.write_u64(ctx.random_counter);
            ctx.random_counter = ctx.random_counter.wrapping_add(1);
            let block = hasher.finish().to_le_bytes();
            let n = std::cmp::min(block.len(), out.len() - i);
            out[i..i + n].copy_from_slice(&block[..n]);
            i += n;
        }
    });
}

pub(crate) fn write_stdout(bytes: &[u8]) -> io::Result<()> {
    CTX.with(|ctx| {
        let mut ctx = ctx.borrow_mut();
        ctx.stdout_capture.extend_from_slice(bytes);
        if ctx.mirror_stdio {
            io::stdout().write_all(bytes)?;
            io::stdout().flush()?;
        }
        Ok(())
    })
}

pub(crate) fn write_stderr(bytes: &[u8]) -> io::Result<()> {
    CTX.with(|ctx| {
        let mut ctx = ctx.borrow_mut();
        ctx.stderr_capture.extend_from_slice(bytes);
        if ctx.mirror_stdio {
            io::stderr().write_all(bytes)?;
            io::stderr().flush()?;
        }
        Ok(())
    })
}

pub(crate) fn fd_read_one(fd: u32, slice: &mut [u8]) -> Result<usize, i32> {
    CTX.with(|ctx| {
        let mut ctx = ctx.borrow_mut();
        let entry = ctx.fd_entry_mut(fd).ok_or(ERRNO_BADF)?;
        let file = match entry {
            FdEntry::OpenFile { file, .. } => file,
            _ => return Err(ERRNO_BADF),
        };
        file.read(slice).map_err(|_| ERRNO_IO)
    })
}

pub(crate) fn fd_write(fd: u32, chunks: &[Vec<u8>]) -> Result<u32, i32> {
    if fd == 1 {
        let mut total = 0u32;
        for chunk in chunks {
            write_stdout(chunk).map_err(|_| ERRNO_IO)?;
            total = total.saturating_add(chunk.len() as u32);
        }
        return Ok(total);
    }
    if fd == 2 {
        let mut total = 0u32;
        for chunk in chunks {
            write_stderr(chunk).map_err(|_| ERRNO_IO)?;
            total = total.saturating_add(chunk.len() as u32);
        }
        return Ok(total);
    }

    CTX.with(|ctx| {
        let mut ctx = ctx.borrow_mut();
        let entry = ctx.fd_entry_mut(fd).ok_or(ERRNO_BADF)?;
        let (file, writable) = match entry {
            FdEntry::OpenFile { file, writable } => (file, *writable),
            _ => return Err(ERRNO_BADF),
        };
        if !writable {
            return Err(ERRNO_PERM);
        }

        let mut total = 0u32;
        for chunk in chunks {
            file.write_all(chunk).map_err(|_| ERRNO_IO)?;
            total = total.saturating_add(chunk.len() as u32);
        }
        Ok(total)
    })
}

pub(crate) fn fd_close(fd: u32) -> Result<(), i32> {
    CTX.with(|ctx| {
        let mut ctx = ctx.borrow_mut();
        let slot = ctx.fds.get_mut(fd as usize).ok_or(ERRNO_BADF)?;
        match slot {
            Some(FdEntry::Stdin | FdEntry::Stdout | FdEntry::Stderr | FdEntry::PreopenDir(_)) => {
                Err(ERRNO_BADF)
            }
            Some(FdEntry::OpenDir { .. } | FdEntry::OpenFile { .. }) => {
                *slot = None;
                Ok(())
            }
            None => Err(ERRNO_BADF),
        }
    })
}

pub(crate) fn fd_seek(fd: u32, offset: i64, whence: u8) -> Result<u64, i32> {
    CTX.with(|ctx| {
        let mut ctx = ctx.borrow_mut();
        let entry = ctx.fd_entry_mut(fd).ok_or(ERRNO_BADF)?;
        let file = match entry {
            FdEntry::OpenFile { file, .. } => file,
            _ => return Err(ERRNO_BADF),
        };
        let target = match whence {
            0 => SeekFrom::Start(offset as u64),
            1 => SeekFrom::Current(offset),
            2 => SeekFrom::End(offset),
            _ => return Err(ERRNO_INVAL),
        };
        file.seek(target).map_err(|_| ERRNO_IO)
    })
}

pub(crate) fn fd_tell(fd: u32) -> Result<u64, i32> {
    fd_seek(fd, 0, 1)
}

pub(crate) fn fd_filetype(fd: u32) -> Result<u8, i32> {
    CTX.with(|ctx| {
        let ctx = ctx.borrow();
        let entry = ctx.fd_entry(fd).ok_or(ERRNO_BADF)?;
        let ty = match entry {
            FdEntry::Stdin | FdEntry::Stdout | FdEntry::Stderr => FILETYPE_CHARACTER_DEVICE,
            FdEntry::PreopenDir(_) | FdEntry::OpenDir { .. } => FILETYPE_DIRECTORY,
            FdEntry::OpenFile { .. } => FILETYPE_REGULAR_FILE,
        };
        Ok(ty)
    })
}

pub(crate) fn fd_filestat(fd: u32) -> Result<Filestat, i32> {
    CTX.with(|ctx| {
        let ctx = ctx.borrow();
        let entry = ctx.fd_entry(fd).ok_or(ERRNO_BADF)?;

        let stat = match entry {
            FdEntry::Stdin | FdEntry::Stdout | FdEntry::Stderr => Filestat {
                dev: 0,
                ino: 0,
                filetype: FILETYPE_CHARACTER_DEVICE,
                nlink: 1,
                size: 0,
                atim: 0,
                mtim: 0,
                ctim: 0,
            },
            FdEntry::PreopenDir(dir) => {
                let meta = std::fs::metadata(&dir.root).map_err(|_| ERRNO_IO)?;
                let mut stat = metadata_to_filestat(&meta);
                stat.filetype = FILETYPE_DIRECTORY;
                stat
            }
            FdEntry::OpenDir { root, .. } => {
                let meta = std::fs::metadata(root).map_err(|_| ERRNO_IO)?;
                let mut stat = metadata_to_filestat(&meta);
                stat.filetype = FILETYPE_DIRECTORY;
                stat
            }
            FdEntry::OpenFile { file, .. } => {
                let meta = file.metadata().map_err(|_| ERRNO_IO)?;
                metadata_to_filestat(&meta)
            }
        };

        Ok(stat)
    })
}

pub(crate) fn path_filestat(dirfd: u32, lookupflags: u32, rel_path: &[u8]) -> Result<Filestat, i32> {
    let rel = std::str::from_utf8(rel_path).map_err(|_| ERRNO_INVAL)?;
    let rel_path = Path::new(rel);
    let follow_symlink = (lookupflags & 1) != 0;

    CTX.with(|ctx| {
        let ctx = ctx.borrow();
        let entry = ctx.fd_entry(dirfd).ok_or(ERRNO_BADF)?;
        let (root, _) = dir_root_from_entry(entry)?;
        let full = resolve_existing_in_preopen(&root, rel_path, follow_symlink)?;
        let meta = if follow_symlink {
            std::fs::metadata(&full)
        } else {
            std::fs::symlink_metadata(&full)
        }
        .map_err(|err| io_error_to_errno(&err))?;

        Ok(metadata_to_filestat(&meta))
    })
}

pub(crate) fn path_open(
    dirfd: u32,
    rel_path: &[u8],
    oflags: u32,
    fdflags: u32,
    rights_base: u64,
) -> Result<u32, i32> {
    let rel = std::str::from_utf8(rel_path).map_err(|_| ERRNO_INVAL)?;
    let rel_path = Path::new(rel);
    let write_requested = wants_write_access(oflags, fdflags, rights_base);

    CTX.with(|ctx| {
        let mut ctx = ctx.borrow_mut();
        let entry = ctx.fd_entry(dirfd).ok_or(ERRNO_BADF)?;
        let (root, writable) = dir_root_from_entry(entry)?;

        if write_requested && !writable {
            return Err(ERRNO_PERM);
        }
        let want_directory = (oflags & 0x2) != 0;
        let full = if want_directory {
            let follow_symlink = false;
            resolve_existing_in_preopen(&root, rel_path, follow_symlink)?
        } else {
            resolve_in_preopen(&root, rel_path)?
        };

        if want_directory {
            let meta = std::fs::metadata(&full).map_err(|err| io_error_to_errno(&err))?;
            if !meta.is_dir() {
                return Err(ERRNO_NOTDIR);
            }
            return Ok(ctx.alloc_fd(FdEntry::OpenDir { root: full, writable }));
        }

        let mut opts = OpenOptions::new();
        opts.read(true);
        if write_requested {
            opts.write(true);
            if (oflags & 0x1) != 0 {
                opts.create(true);
            }
            if (oflags & 0x8) != 0 {
                opts.truncate(true);
            }
        }

        let file = opts.open(&full).map_err(|_| ERRNO_IO)?;
        Ok(ctx.alloc_fd(FdEntry::OpenFile { file, writable: write_requested }))
    })
}

pub(crate) fn fd_readdir(fd: u32, cookie: u64, buf: &mut [u8]) -> Result<u32, i32> {
    CTX.with(|ctx| {
        let ctx = ctx.borrow();
        let (root, _) = dir_root_from_entry(ctx.fd_entry(fd).ok_or(ERRNO_BADF)?)?;
        let mut host_entries = Vec::new();
        for entry in std::fs::read_dir(&root).map_err(|err| io_error_to_errno(&err))? {
            let entry = entry.map_err(|err| io_error_to_errno(&err))?;
            let file_type = entry.file_type().map_err(|err| io_error_to_errno(&err))?;
            host_entries.push((entry.file_name().to_string_lossy().as_bytes().to_vec(), std_filetype_to_wasi(&file_type)));
        }
        host_entries.sort_by(|a, b| a.0.cmp(&b.0));

        let mut written = 0usize;
        for (idx, (name, filetype)) in host_entries.iter().enumerate().skip(cookie as usize) {
            let header_len = 24usize;
            let available = buf.len().saturating_sub(written);
            if available < header_len {
                // std's WASI ReadDir treats a short final chunk as EOF. If more
                // entries remain but there is not enough space for another dirent
                // header, pad the buffer to signal the caller to reissue with the
                // last completed cookie.
                written = buf.len();
                break;
            }

            let next_cookie = (idx + 1) as u64;
            let header = &mut buf[written..written + header_len];
            header.fill(0);
            header[0..8].copy_from_slice(&next_cookie.to_le_bytes());
            header[8..16].copy_from_slice(&0u64.to_le_bytes());
            header[16..20].copy_from_slice(&(name.len() as u32).to_le_bytes());
            header[20] = *filetype;
            written += header_len;

            let writable_name = name.len().min(buf.len().saturating_sub(written));
            buf[written..written + writable_name].copy_from_slice(&name[..writable_name]);
            written += writable_name;

            if writable_name < name.len() {
                break;
            }
        }

        Ok(written as u32)
    })
}

pub(crate) fn fd_prestat_dir(fd: u32) -> Result<u32, i32> {
    CTX.with(|ctx| {
        let ctx = ctx.borrow();
        let Some(entry) = ctx.fd_entry(fd) else {
            return Err(ERRNO_BADF);
        };
        match entry {
            FdEntry::PreopenDir(dir) => Ok(dir.guest_path.len() as u32),
            _ => Err(ERRNO_BADF),
        }
    })
}

pub(crate) fn fd_prestat_dir_name(fd: u32) -> Result<Vec<u8>, i32> {
    CTX.with(|ctx| {
        let ctx = ctx.borrow();
        match ctx.fd_entry(fd).ok_or(ERRNO_BADF)? {
            FdEntry::PreopenDir(dir) => Ok(dir.guest_path.as_bytes().to_vec()),
            _ => Err(ERRNO_BADF),
        }
    })
}

pub(crate) fn clock_res_get(clock_id: u32) -> Result<u64, i32> {
    match clock_id {
        0 | 1 => Ok(1),
        _ => Err(ERRNO_NOSYS),
    }
}

pub(crate) fn clock_time_get(clock_id: u32) -> Result<u64, i32> {
    CTX.with(|ctx| {
        let ctx = ctx.borrow();
        match clock_id {
            0 => {
                if ctx.deterministic_random {
                    Ok(0)
                } else {
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|duration| duration.as_nanos() as u64)
                        .map_err(|_| ERRNO_IO)
                }
            }
            1 => {
                if ctx.deterministic_random {
                    Ok(0)
                } else {
                    static START: OnceLock<Instant> = OnceLock::new();
                    let start = START.get_or_init(Instant::now);
                    Ok(start.elapsed().as_nanos() as u64)
                }
            }
            _ => Err(ERRNO_NOSYS),
        }
    })
}

#[cfg(test)]
pub(crate) fn set_for_test(env_entries: Vec<Vec<u8>>, mirror_stdio: bool) {
    CTX.with(|ctx| {
        let mut fds = vec![Some(FdEntry::Stdin), Some(FdEntry::Stdout), Some(FdEntry::Stderr)];
        if let Ok(cwd) = std::env::current_dir() {
            if let Some(canon) = canonicalize_dir(&cwd) {
                fds.push(Some(FdEntry::PreopenDir(PreopenDir {
                    root: canon.clone(),
                    guest_path: canon.to_string_lossy().to_string(),
                    writable: false,
                })));
            }
        }
        *ctx.borrow_mut() = WasiProcMacroCtx {
            args_entries: Vec::new(),
            env_entries,
            stdout_capture: Vec::new(),
            stderr_capture: Vec::new(),
            mirror_stdio,
            deterministic_random: false,
            random_state: std::collections::hash_map::RandomState::new(),
            random_counter: 0,
            fds,
        };
    });
}

#[cfg(test)]
pub(crate) fn set_for_test_with_preopens(
    env_entries: Vec<Vec<u8>>,
    mirror_stdio: bool,
    preopens: Vec<(PathBuf, bool)>,
) {
    CTX.with(|ctx| {
        let mut fds = vec![Some(FdEntry::Stdin), Some(FdEntry::Stdout), Some(FdEntry::Stderr)];
        for (root, writable) in preopens {
            if let Some(canon) = canonicalize_dir(&root) {
                fds.push(Some(FdEntry::PreopenDir(PreopenDir {
                    root: canon.clone(),
                    guest_path: canon.to_string_lossy().to_string(),
                    writable,
                })));
            }
        }
        *ctx.borrow_mut() = WasiProcMacroCtx {
            args_entries: Vec::new(),
            env_entries,
            stdout_capture: Vec::new(),
            stderr_capture: Vec::new(),
            mirror_stdio,
            deterministic_random: false,
            random_state: std::collections::hash_map::RandomState::new(),
            random_counter: 0,
            fds,
        };
    });
}

#[cfg(test)]
pub(crate) fn set_for_test_full(
    args_entries: Vec<Vec<u8>>,
    env_entries: Vec<Vec<u8>>,
    mirror_stdio: bool,
    deterministic_random: bool,
) {
    CTX.with(|ctx| {
        let mut fds = vec![Some(FdEntry::Stdin), Some(FdEntry::Stdout), Some(FdEntry::Stderr)];
        if let Ok(cwd) = std::env::current_dir() {
            if let Some(canon) = canonicalize_dir(&cwd) {
                fds.push(Some(FdEntry::PreopenDir(PreopenDir {
                    root: canon.clone(),
                    guest_path: canon.to_string_lossy().to_string(),
                    writable: true,
                })));
            }
        }
        *ctx.borrow_mut() = WasiProcMacroCtx {
            args_entries,
            env_entries,
            stdout_capture: Vec::new(),
            stderr_capture: Vec::new(),
            mirror_stdio,
            deterministic_random,
            random_state: std::collections::hash_map::RandomState::new(),
            random_counter: 0,
            fds,
        };
    });
}

#[cfg(test)]
pub(crate) fn captured_stdout() -> Vec<u8> {
    CTX.with(|ctx| ctx.borrow().stdout_capture.clone())
}

#[cfg(test)]
pub(crate) fn captured_stderr() -> Vec<u8> {
    CTX.with(|ctx| ctx.borrow().stderr_capture.clone())
}

#[cfg(test)]
pub(crate) fn mirror_stdio_enabled() -> bool {
    CTX.with(|ctx| ctx.borrow().mirror_stdio)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{WasiPolicy, WasiPreopenDir};
    #[cfg(unix)]
    use std::os::unix::fs::symlink;
    use std::sync::{Mutex, MutexGuard, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn policy_lock<'a>() -> MutexGuard<'a, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    fn mk_tmp_dir() -> PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("rustc-watt-test-{nanos}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn parse_preopen_spec_modes() {
        assert_eq!(parse_preopen_spec("/tmp:rw"), Some(("/tmp".to_string(), true)));
        assert_eq!(parse_preopen_spec("/tmp:ro"), Some(("/tmp".to_string(), false)));
        assert_eq!(parse_preopen_spec("/tmp"), Some(("/tmp".to_string(), false)));
    }

    #[test]
    fn path_open_respects_read_only_preopen() {
        let dir = mk_tmp_dir().canonicalize().unwrap();
        let file = dir.join("a.txt");
        std::fs::write(&file, b"abc").unwrap();

        let mut ctx = WasiProcMacroCtx {
            args_entries: Vec::new(),
            env_entries: Vec::new(),
            stdout_capture: Vec::new(),
            stderr_capture: Vec::new(),
            mirror_stdio: false,
            deterministic_random: false,
            random_state: std::collections::hash_map::RandomState::new(),
            random_counter: 0,
            fds: vec![
                Some(FdEntry::Stdin),
                Some(FdEntry::Stdout),
                Some(FdEntry::Stderr),
                Some(FdEntry::PreopenDir(PreopenDir {
                    root: dir.clone(),
                    guest_path: dir.to_string_lossy().to_string(),
                    writable: false,
                })),
            ],
        };

        let rel = b"a.txt";
        let read_fd = {
            let preopen = match ctx.fd_entry(3).unwrap() {
                FdEntry::PreopenDir(p) => p.clone(),
                _ => panic!("expected preopen"),
            };
            let full = resolve_in_preopen(&preopen.root, Path::new(std::str::from_utf8(rel).unwrap()))
                .unwrap();
            let mut opts = OpenOptions::new();
            opts.read(true);
            let file = opts.open(full).unwrap();
            ctx.alloc_fd(FdEntry::OpenFile { file, writable: false })
        };
        assert!(read_fd >= 4);
        assert!(matches!(ctx.fd_entry(read_fd).unwrap(), FdEntry::OpenFile { writable: false, .. }));
    }

    #[test]
    fn path_open_denies_parent_traversal() {
        let dir = mk_tmp_dir();
        set_for_test_with_preopens(Vec::new(), false, vec![(dir.clone(), false)]);
        let err = path_open(3, b"../escape.txt", 0, 0, 0).unwrap_err();
        assert_eq!(err, ERRNO_PERM);
    }

    #[test]
    fn read_only_preopen_denies_write_open() {
        let dir = mk_tmp_dir();
        set_for_test_with_preopens(Vec::new(), false, vec![(dir.clone(), false)]);
        let err = path_open(3, b"new.txt", 0x1, 0, RIGHTS_FD_WRITE).unwrap_err();
        assert_eq!(err, ERRNO_PERM);
    }

    #[test]
    fn writable_preopen_allows_write_open_and_write() {
        let dir = mk_tmp_dir();
        let out = dir.join("out.txt");
        set_for_test_with_preopens(Vec::new(), false, vec![(dir.clone(), true)]);

        let fd = path_open(3, b"out.txt", 0x1, 0, RIGHTS_FD_WRITE).unwrap();
        let wrote = fd_write(fd, &[b"hello".to_vec(), b" wasm".to_vec()]).unwrap();
        assert_eq!(wrote, 10);
        fd_close(fd).unwrap();

        let data = std::fs::read(out).unwrap();
        assert_eq!(data, b"hello wasm");
    }

    #[test]
    fn fd_seek_and_tell_round_trip() {
        let dir = mk_tmp_dir();
        std::fs::write(dir.join("seek.txt"), b"abcdef").unwrap();
        set_for_test_with_preopens(Vec::new(), false, vec![(dir.clone(), true)]);

        let fd = path_open(3, b"seek.txt", 0, 0, 0).unwrap();
        assert_eq!(fd_tell(fd).unwrap(), 0);
        assert_eq!(fd_seek(fd, 2, 0).unwrap(), 2);
        assert_eq!(fd_tell(fd).unwrap(), 2);
        fd_close(fd).unwrap();
    }

    #[test]
    fn fd_prestat_reports_preopen_name() {
        let dir = mk_tmp_dir().canonicalize().unwrap();
        set_for_test_with_preopens(Vec::new(), false, vec![(dir.clone(), false)]);

        let len = fd_prestat_dir(3).unwrap();
        let name = fd_prestat_dir_name(3).unwrap();
        assert_eq!(len as usize, dir.to_string_lossy().len());
        assert_eq!(name, dir.to_string_lossy().as_bytes());
    }

    #[test]
    fn fd_prestat_can_report_guest_visible_name() {
        let dir = mk_tmp_dir().canonicalize().unwrap();

        CTX.with(|ctx| {
            *ctx.borrow_mut() = WasiProcMacroCtx {
                args_entries: Vec::new(),
                env_entries: Vec::new(),
                stdout_capture: Vec::new(),
                stderr_capture: Vec::new(),
                mirror_stdio: false,
                deterministic_random: false,
                random_state: std::collections::hash_map::RandomState::new(),
                random_counter: 0,
                fds: vec![
                    Some(FdEntry::Stdin),
                    Some(FdEntry::Stdout),
                    Some(FdEntry::Stderr),
                    Some(FdEntry::PreopenDir(PreopenDir {
                        root: dir,
                        guest_path: "/./".to_string(),
                        writable: false,
                    })),
                ],
            };
        });

        let len = fd_prestat_dir(3).unwrap();
        let name = fd_prestat_dir_name(3).unwrap();
        assert_eq!(len as usize, "/./".len());
        assert_eq!(name, b"/./");
    }

    #[test]
    fn path_filestat_reads_relative_metadata() {
        let dir = mk_tmp_dir();
        let file = dir.join("meta.txt");
        std::fs::write(&file, b"hello").unwrap();
        set_for_test_with_preopens(Vec::new(), false, vec![(dir.clone(), false)]);

        let stat = path_filestat(3, 1, b"meta.txt").unwrap();
        assert_eq!(stat.filetype, FILETYPE_REGULAR_FILE);
        assert_eq!(stat.size, 5);
    }

    #[test]
    fn directory_open_and_readdir_work() {
        let dir = mk_tmp_dir();
        let child = dir.join("wit");
        std::fs::create_dir(&child).unwrap();
        std::fs::write(child.join("a.wit"), b"package a:b;").unwrap();
        std::fs::write(child.join("b.wit"), b"package a:c;").unwrap();
        set_for_test_with_preopens(Vec::new(), false, vec![(dir.clone(), false)]);

        let fd = path_open(3, b"wit", 0x2, 0, 0).unwrap();
        assert_eq!(fd_filetype(fd).unwrap(), FILETYPE_DIRECTORY);

        let mut buf = vec![0u8; 256];
        let used = fd_readdir(fd, 0, &mut buf).unwrap() as usize;
        assert!(used > 0);
        let bytes = &buf[..used];
        assert!(bytes.windows(5).any(|w| w == b"a.wit"));
        assert!(bytes.windows(5).any(|w| w == b"b.wit"));
        fd_close(fd).unwrap();
    }

    #[test]
    fn directory_readdir_paginates_small_std_style_buffers() {
        let dir = mk_tmp_dir();
        let deps = dir.join("wit").join("deps");
        std::fs::create_dir_all(&deps).unwrap();
        for name in [
            "wasi-cli-0.2.0",
            "wasi-clocks-0.2.0",
            "wasi-http-0.2.0",
            "wasi-io-0.2.0",
            "wasi-random-0.2.0",
        ] {
            std::fs::create_dir(deps.join(name)).unwrap();
        }
        set_for_test_with_preopens(Vec::new(), false, vec![(dir.clone(), false)]);

        let fd = path_open(3, b"wit/deps", 0x2, 0, 0).unwrap();
        let mut buf = vec![0u8; 128];
        let used = fd_readdir(fd, 0, &mut buf).unwrap() as usize;
        assert_eq!(used, buf.len());
        let bytes = &buf[..used];
        assert!(bytes.windows(b"wasi-http-0.2.0".len()).any(|w| w == b"wasi-http-0.2.0"));

        // `3` is the cookie of the last complete entry from the first page:
        // wasi-cli, wasi-clocks, wasi-http.
        let used2 = fd_readdir(fd, 3, &mut buf).unwrap() as usize;
        assert!(used2 > 0);
        let bytes2 = &buf[..used2];
        assert!(bytes2.windows(b"wasi-io-0.2.0".len()).any(|w| w == b"wasi-io-0.2.0"));
        assert!(
            bytes2
                .windows(b"wasi-random-0.2.0".len())
                .any(|w| w == b"wasi-random-0.2.0")
        );
        fd_close(fd).unwrap();
    }

    #[test]
    fn relative_paths_ignore_current_dir_segments() {
        let dir = mk_tmp_dir();
        let child = dir.join("wit");
        std::fs::create_dir(&child).unwrap();
        std::fs::write(child.join("world.wit"), b"package test:component;").unwrap();
        set_for_test_with_preopens(Vec::new(), false, vec![(dir.clone(), false)]);

        let stat = path_filestat(3, 1, b"./wit").unwrap();
        assert_eq!(stat.filetype, FILETYPE_DIRECTORY);

        let fd = path_open(3, b"./wit/world.wit", 0, 0, 0).unwrap();
        assert!(fd >= 4);
        CTX.with(|ctx| {
            assert!(matches!(
                ctx.borrow().fd_entry(fd).unwrap(),
                FdEntry::OpenFile { .. }
            ));
        });
        fd_close(fd).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn path_open_denies_symlink_breakout() {
        let dir = mk_tmp_dir();
        let outside = mk_tmp_dir();
        std::fs::write(outside.join("secret.txt"), b"top-secret").unwrap();
        symlink(&outside, dir.join("escape")).unwrap();

        set_for_test_with_preopens(Vec::new(), false, vec![(dir.clone(), false)]);
        let err = path_open(3, b"escape/secret.txt", 0, 0, 0).unwrap_err();
        assert_eq!(err, ERRNO_PERM);
    }

    #[test]
    fn default_fallback_preopen_is_writable() {
        let preopens = preopens_from_host();
        assert!(!preopens.is_empty());
        assert!(preopens[0].writable);
    }

    #[test]
    fn random_fill_deterministic_override() {
        set_for_test_full(Vec::new(), Vec::new(), false, true);
        let mut out = [1u8; 16];
        random_fill(&mut out);
        assert_eq!(&out, &[0u8; 16]);
    }

    #[test]
    fn deterministic_mode_zeroes_supported_clocks() {
        set_for_test_full(Vec::new(), Vec::new(), false, true);
        assert_eq!(clock_res_get(0).unwrap(), 1);
        assert_eq!(clock_res_get(1).unwrap(), 1);
        assert_eq!(clock_time_get(0).unwrap(), 0);
        assert_eq!(clock_time_get(1).unwrap(), 0);
        assert_eq!(clock_time_get(999).unwrap_err(), ERRNO_NOSYS);
    }

    #[test]
    fn env_allowlist_filters_entries() {
        let Some((first_key, _)) = std::env::vars_os().next() else {
            return;
        };
        let key = first_key.to_string_lossy().to_string();
        let allow = vec![key.clone()];
        let env = collect_env_entries(Some(&allow));
        assert!(!env.is_empty());
        for entry in env {
            let s = String::from_utf8_lossy(&entry);
            assert!(s.starts_with(&(key.clone() + "=")));
        }
    }

    #[test]
    fn env_allowlist_empty_allows_all() {
        let all = collect_env_entries(None);
        let allow_all = collect_env_entries(Some(&[]));
        assert_eq!(all, allow_all);
    }

    #[test]
    fn policy_can_disable_args_and_env_inheritance() {
        let _lock = policy_lock();
        let mut policy = WasiPolicy::native_like();
        policy.inherit_args = false;
        policy.inherit_env = false;
        policy.preopens = vec![WasiPreopenDir {
            path: std::env::current_dir().unwrap(),
            guest_path: None,
            writable: false,
        }];
        set_policy(policy);

        assert!(args_entries().is_empty());
        assert!(environ_entries().is_empty());

        clear_policy();
    }

    #[test]
    fn policy_preopen_can_override_guest_visible_name() {
        let _lock = policy_lock();
        let dir = mk_tmp_dir().canonicalize().unwrap();

        let mut policy = WasiPolicy::native_like();
        policy.preopens = vec![WasiPreopenDir {
            path: dir,
            guest_path: Some(PathBuf::from("/.")),
            writable: false,
        }];
        set_policy(policy);

        let len = fd_prestat_dir(3).unwrap();
        let name = fd_prestat_dir_name(3).unwrap();
        assert_eq!(len as usize, "/.".len());
        assert_eq!(name, b"/.");

        clear_policy();
    }

    #[test]
    fn policy_controls_mirror_stdio_toggle() {
        let _lock = policy_lock();
        let mut policy = WasiPolicy::native_like();
        policy.mirror_stdio = false;
        set_policy(policy);
        assert!(!mirror_stdio_enabled());

        clear_policy();
        assert!(mirror_stdio_enabled());
    }
}
