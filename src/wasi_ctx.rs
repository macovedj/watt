use std::cell::RefCell;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

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

const PREOPENS_ENV: &str = "RUSTC_WATT_PREOPENS";
const RIGHTS_FD_WRITE: u64 = 1u64 << 6;

#[derive(Clone, Debug)]
struct PreopenDir {
    root: PathBuf,
    writable: bool,
}

#[derive(Debug)]
enum FdEntry {
    Stdin,
    Stdout,
    Stderr,
    PreopenDir(PreopenDir),
    OpenFile { file: File, writable: bool },
}

#[derive(Debug)]
struct WasiProcMacroCtx {
    env_entries: Vec<Vec<u8>>,
    stdout_capture: Vec<u8>,
    stderr_capture: Vec<u8>,
    mirror_stdio: bool,
    fds: Vec<Option<FdEntry>>,
}

fn collect_env_entries() -> Vec<Vec<u8>> {
    let mut env_entries = Vec::new();
    for (k, v) in std::env::vars_os() {
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
            let root = PathBuf::from(path);
            if let Some(canon) = canonicalize_dir(&root) {
                out.push(PreopenDir { root: canon, writable });
            }
        }
    }

    if out.is_empty() {
        if let Ok(cwd) = std::env::current_dir() {
            if let Some(canon) = canonicalize_dir(&cwd) {
                out.push(PreopenDir { root: canon, writable: false });
            }
        }
    }
    out
}

impl WasiProcMacroCtx {
    fn from_host() -> Self {
        let mut fds = vec![Some(FdEntry::Stdin), Some(FdEntry::Stdout), Some(FdEntry::Stderr)];
        for dir in preopens_from_host() {
            fds.push(Some(FdEntry::PreopenDir(dir)));
        }

        Self {
            env_entries: collect_env_entries(),
            stdout_capture: Vec::new(),
            stderr_capture: Vec::new(),
            mirror_stdio: true,
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

fn resolve_in_preopen(root: &Path, rel_path: &Path) -> Result<PathBuf, i32> {
    if !is_rel_path_safe(rel_path) {
        return Err(ERRNO_PERM);
    }

    let joined = root.join(rel_path);
    if joined.exists() {
        let canon = joined.canonicalize().map_err(|_| ERRNO_IO)?;
        if !canon.starts_with(root) {
            return Err(ERRNO_PERM);
        }
        return Ok(canon);
    }

    let parent = joined.parent().ok_or(ERRNO_PERM)?;
    let parent_canon = parent.canonicalize().map_err(|_| ERRNO_NOENT)?;
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

std::thread_local! {
    static CTX: RefCell<WasiProcMacroCtx> = RefCell::new(WasiProcMacroCtx::from_host());
}

pub(crate) fn reset_from_host() {
    CTX.with(|ctx| *ctx.borrow_mut() = WasiProcMacroCtx::from_host());
}

pub(crate) fn environ_entries() -> Vec<Vec<u8>> {
    CTX.with(|ctx| ctx.borrow().env_entries.clone())
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
            Some(FdEntry::OpenFile { .. }) => {
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
            FdEntry::PreopenDir(_) => FILETYPE_DIRECTORY,
            FdEntry::OpenFile { .. } => FILETYPE_REGULAR_FILE,
        };
        Ok(ty)
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
        let preopen = match ctx.fd_entry(dirfd).ok_or(ERRNO_BADF)? {
            FdEntry::PreopenDir(dir) => dir.clone(),
            _ => return Err(ERRNO_NOTDIR),
        };

        if write_requested && !preopen.writable {
            return Err(ERRNO_PERM);
        }

        // Disallow directory-only opens for now.
        if (oflags & 0x2) != 0 {
            return Err(ERRNO_NOSYS);
        }

        let full = resolve_in_preopen(&preopen.root, rel_path)?;

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

        let file = opts.open(full).map_err(|_| ERRNO_IO)?;
        let fd = ctx.alloc_fd(FdEntry::OpenFile { file, writable: write_requested });
        Ok(fd)
    })
}

pub(crate) fn fd_prestat_dir(fd: u32) -> Result<u32, i32> {
    CTX.with(|ctx| {
        let ctx = ctx.borrow();
        match ctx.fd_entry(fd).ok_or(ERRNO_BADF)? {
            FdEntry::PreopenDir(dir) => Ok(dir.root.to_string_lossy().len() as u32),
            _ => Err(ERRNO_BADF),
        }
    })
}

pub(crate) fn fd_prestat_dir_name(fd: u32) -> Result<Vec<u8>, i32> {
    CTX.with(|ctx| {
        let ctx = ctx.borrow();
        match ctx.fd_entry(fd).ok_or(ERRNO_BADF)? {
            FdEntry::PreopenDir(dir) => Ok(dir.root.to_string_lossy().as_bytes().to_vec()),
            _ => Err(ERRNO_BADF),
        }
    })
}

#[cfg(test)]
pub(crate) fn set_for_test(env_entries: Vec<Vec<u8>>, mirror_stdio: bool) {
    CTX.with(|ctx| {
        let mut fds = vec![Some(FdEntry::Stdin), Some(FdEntry::Stdout), Some(FdEntry::Stderr)];
        if let Ok(cwd) = std::env::current_dir() {
            if let Some(canon) = canonicalize_dir(&cwd) {
                fds.push(Some(FdEntry::PreopenDir(PreopenDir { root: canon, writable: false })));
            }
        }
        *ctx.borrow_mut() = WasiProcMacroCtx {
            env_entries,
            stdout_capture: Vec::new(),
            stderr_capture: Vec::new(),
            mirror_stdio,
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
                fds.push(Some(FdEntry::PreopenDir(PreopenDir { root: canon, writable })));
            }
        }
        *ctx.borrow_mut() = WasiProcMacroCtx {
            env_entries,
            stdout_capture: Vec::new(),
            stderr_capture: Vec::new(),
            mirror_stdio,
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
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

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
            env_entries: Vec::new(),
            stdout_capture: Vec::new(),
            stderr_capture: Vec::new(),
            mirror_stdio: false,
            fds: vec![
                Some(FdEntry::Stdin),
                Some(FdEntry::Stdout),
                Some(FdEntry::Stderr),
                Some(FdEntry::PreopenDir(PreopenDir { root: dir.clone(), writable: false })),
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
}
