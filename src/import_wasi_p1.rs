use crate::runtime::types::{Func, Int, Value as ValueType};
use crate::runtime::{HostFunc, Value};
use crate::wasi_ctx;

pub const WASI_P1_MODULE: &str = "wasi_snapshot_preview1";

fn i32() -> ValueType {
    ValueType::Int(Int::I32)
}

fn i64() -> ValueType {
    ValueType::Int(Int::I64)
}

fn signature_matches(sig: &Func, params: &[ValueType], results: &[ValueType]) -> bool {
    sig.args == params && sig.result == results
}

fn pop_u32(interp: &mut crate::runtime::Interpreter<'_>) -> Option<u32> {
    match interp.pop() {
        Some(Value::I32(v)) => Some(v),
        _ => None,
    }
}

fn pop_i64(interp: &mut crate::runtime::Interpreter<'_>) -> Option<i64> {
    match interp.pop() {
        Some(Value::I64(v)) => Some(v as i64),
        _ => None,
    }
}

fn write_u32(memory: &mut [u8], ptr: usize, value: u32) -> bool {
    let end = ptr.saturating_add(4);
    if end > memory.len() {
        return false;
    }
    memory[ptr..end].copy_from_slice(&value.to_le_bytes());
    true
}

fn write_u64(memory: &mut [u8], ptr: usize, value: u64) -> bool {
    let end = ptr.saturating_add(8);
    if end > memory.len() {
        return false;
    }
    memory[ptr..end].copy_from_slice(&value.to_le_bytes());
    true
}

fn wasi_args_sizes_get(interp: &mut crate::runtime::Interpreter<'_>) -> Option<String> {
    let buf_size_ptr = pop_u32(interp)? as usize;
    let count_ptr = pop_u32(interp)? as usize;
    let args = wasi_ctx::args_entries();
    let args_count = args.len() as u32;
    let args_buf_size = args.iter().map(|entry| entry.len() as u32).sum::<u32>();
    let memory = interp.get_memory_mut();
    if !write_u32(memory, count_ptr, args_count) || !write_u32(memory, buf_size_ptr, args_buf_size) {
        interp.push(Value::I32(wasi_ctx::ERRNO_FAULT as u32));
        return None;
    }
    interp.push(Value::I32(wasi_ctx::ERRNO_SUCCESS as u32));
    None
}

fn wasi_args_get(interp: &mut crate::runtime::Interpreter<'_>) -> Option<String> {
    let argv_buf_ptr = pop_u32(interp)? as usize;
    let argv_ptrs_ptr = pop_u32(interp)? as usize;
    let args = wasi_ctx::args_entries();
    let memory = interp.get_memory_mut();
    let mut write_ptr = argv_buf_ptr;
    for (idx, entry) in args.iter().enumerate() {
        let ptr_slot = argv_ptrs_ptr.saturating_add(idx * 4);
        if !write_u32(memory, ptr_slot, write_ptr as u32) {
            interp.push(Value::I32(wasi_ctx::ERRNO_FAULT as u32));
            return None;
        }
        let end = write_ptr.saturating_add(entry.len());
        if end > memory.len() {
            interp.push(Value::I32(wasi_ctx::ERRNO_FAULT as u32));
            return None;
        }
        memory[write_ptr..end].copy_from_slice(entry);
        write_ptr = end;
    }
    interp.push(Value::I32(wasi_ctx::ERRNO_SUCCESS as u32));
    None
}

fn wasi_environ_sizes_get(interp: &mut crate::runtime::Interpreter<'_>) -> Option<String> {
    let buf_size_ptr = pop_u32(interp)? as usize;
    let count_ptr = pop_u32(interp)? as usize;
    let env = wasi_ctx::environ_entries();
    let env_count = env.len() as u32;
    let env_buf_size = env.iter().map(|entry| entry.len() as u32).sum::<u32>();

    let memory = interp.get_memory_mut();
    if !write_u32(memory, count_ptr, env_count) || !write_u32(memory, buf_size_ptr, env_buf_size) {
        interp.push(Value::I32(wasi_ctx::ERRNO_FAULT as u32));
        return None;
    }

    interp.push(Value::I32(wasi_ctx::ERRNO_SUCCESS as u32));
    None
}

fn wasi_environ_get(interp: &mut crate::runtime::Interpreter<'_>) -> Option<String> {
    let env_buf_ptr = pop_u32(interp)? as usize;
    let env_ptrs_ptr = pop_u32(interp)? as usize;
    let env = wasi_ctx::environ_entries();

    let memory = interp.get_memory_mut();
    let mut write_ptr = env_buf_ptr;

    for (idx, entry) in env.iter().enumerate() {
        let ptr_slot = env_ptrs_ptr.saturating_add(idx * 4);
        if !write_u32(memory, ptr_slot, write_ptr as u32) {
            interp.push(Value::I32(wasi_ctx::ERRNO_FAULT as u32));
            return None;
        }

        let end = write_ptr.saturating_add(entry.len());
        if end > memory.len() {
            interp.push(Value::I32(wasi_ctx::ERRNO_FAULT as u32));
            return None;
        }
        memory[write_ptr..end].copy_from_slice(entry);
        write_ptr = end;
    }

    interp.push(Value::I32(wasi_ctx::ERRNO_SUCCESS as u32));
    None
}

fn wasi_fd_write(interp: &mut crate::runtime::Interpreter<'_>) -> Option<String> {
    let nwritten_ptr = pop_u32(interp)? as usize;
    let iovs_len = pop_u32(interp)? as usize;
    let iovs_ptr = pop_u32(interp)? as usize;
    let fd = pop_u32(interp)?;

    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut total_requested = 0u32;
    {
        let memory = interp.get_memory_mut();
        for i in 0..iovs_len {
            let iov = iovs_ptr.saturating_add(i * 8);
            let iov_end = iov.saturating_add(8);
            if iov_end > memory.len() {
                interp.push(Value::I32(wasi_ctx::ERRNO_FAULT as u32));
                return None;
            }

            let base = u32::from_le_bytes([
                memory[iov],
                memory[iov + 1],
                memory[iov + 2],
                memory[iov + 3],
            ]) as usize;
            let len = u32::from_le_bytes([
                memory[iov + 4],
                memory[iov + 5],
                memory[iov + 6],
                memory[iov + 7],
            ]) as usize;

            let data_end = base.saturating_add(len);
            if data_end > memory.len() {
                interp.push(Value::I32(wasi_ctx::ERRNO_FAULT as u32));
                return None;
            }
            chunks.push(memory[base..data_end].to_vec());
            total_requested = total_requested.saturating_add(len as u32);
        }
    }

    let (errno, written) = match wasi_ctx::fd_write(fd, &chunks) {
        Ok(written) => (wasi_ctx::ERRNO_SUCCESS, written),
        Err(errno) => (errno, 0),
    };
    let written = if errno == wasi_ctx::ERRNO_SUCCESS { written } else { 0 };

    let memory = interp.get_memory_mut();
    let write_count = if written > total_requested { total_requested } else { written };
    if !write_u32(memory, nwritten_ptr, write_count) {
        interp.push(Value::I32(wasi_ctx::ERRNO_FAULT as u32));
        return None;
    };
    interp.push(Value::I32(errno as u32));
    None
}

fn wasi_random_get(interp: &mut crate::runtime::Interpreter<'_>) -> Option<String> {
    let buf_len = pop_u32(interp)? as usize;
    let buf_ptr = pop_u32(interp)? as usize;
    let memory = interp.get_memory_mut();
    let end = buf_ptr.saturating_add(buf_len);
    if end > memory.len() {
        interp.push(Value::I32(wasi_ctx::ERRNO_FAULT as u32));
        return None;
    }
    wasi_ctx::random_fill(&mut memory[buf_ptr..end]);
    interp.push(Value::I32(wasi_ctx::ERRNO_SUCCESS as u32));
    None
}

fn wasi_clock_res_get(interp: &mut crate::runtime::Interpreter<'_>) -> Option<String> {
    let resolution_ptr = pop_u32(interp)? as usize;
    let clock_id = pop_u32(interp)?;
    let resolution = match wasi_ctx::clock_res_get(clock_id) {
        Ok(value) => value,
        Err(errno) => {
            interp.push(Value::I32(errno as u32));
            return None;
        }
    };
    let memory = interp.get_memory_mut();
    if !write_u64(memory, resolution_ptr, resolution) {
        interp.push(Value::I32(wasi_ctx::ERRNO_FAULT as u32));
        return None;
    }
    interp.push(Value::I32(wasi_ctx::ERRNO_SUCCESS as u32));
    None
}

fn wasi_clock_time_get(interp: &mut crate::runtime::Interpreter<'_>) -> Option<String> {
    let time_ptr = pop_u32(interp)? as usize;
    let _precision = pop_i64(interp)? as u64;
    let clock_id = pop_u32(interp)?;
    let now = match wasi_ctx::clock_time_get(clock_id) {
        Ok(value) => value,
        Err(errno) => {
            interp.push(Value::I32(errno as u32));
            return None;
        }
    };
    let memory = interp.get_memory_mut();
    if !write_u64(memory, time_ptr, now) {
        interp.push(Value::I32(wasi_ctx::ERRNO_FAULT as u32));
        return None;
    }
    interp.push(Value::I32(wasi_ctx::ERRNO_SUCCESS as u32));
    None
}

fn wasi_fd_read(interp: &mut crate::runtime::Interpreter<'_>) -> Option<String> {
    let nread_ptr = pop_u32(interp)? as usize;
    let iovs_len = pop_u32(interp)? as usize;
    let iovs_ptr = pop_u32(interp)? as usize;
    let fd = pop_u32(interp)?;

    let mut iov_desc = Vec::with_capacity(iovs_len);
    {
        let memory = interp.get_memory_mut();
        for i in 0..iovs_len {
            let iov = iovs_ptr.saturating_add(i * 8);
            let end = iov.saturating_add(8);
            if end > memory.len() {
                interp.push(Value::I32(wasi_ctx::ERRNO_FAULT as u32));
                return None;
            }

            let base = u32::from_le_bytes([
                memory[iov],
                memory[iov + 1],
                memory[iov + 2],
                memory[iov + 3],
            ]) as usize;
            let len = u32::from_le_bytes([
                memory[iov + 4],
                memory[iov + 5],
                memory[iov + 6],
                memory[iov + 7],
            ]) as usize;
            if base.saturating_add(len) > memory.len() {
                interp.push(Value::I32(wasi_ctx::ERRNO_FAULT as u32));
                return None;
            }
            iov_desc.push((base, len));
        }
    }

    let mut total_read = 0u32;
    for (base, len) in iov_desc {
        let n = {
            let memory = interp.get_memory_mut();
            let slice = &mut memory[base..base + len];
            match wasi_ctx::fd_read_one(fd, slice) {
                Ok(n) => n,
                Err(errno) => {
                    interp.push(Value::I32(errno as u32));
                    return None;
                }
            }
        };
        total_read = total_read.saturating_add(n as u32);
        if n < len {
            break;
        }
    }

    let memory = interp.get_memory_mut();
    if !write_u32(memory, nread_ptr, total_read) {
        interp.push(Value::I32(wasi_ctx::ERRNO_FAULT as u32));
        return None;
    }
    interp.push(Value::I32(wasi_ctx::ERRNO_SUCCESS as u32));
    None
}

fn wasi_fd_close(interp: &mut crate::runtime::Interpreter<'_>) -> Option<String> {
    let fd = pop_u32(interp)?;
    let errno = match wasi_ctx::fd_close(fd) {
        Ok(()) => wasi_ctx::ERRNO_SUCCESS,
        Err(errno) => errno,
    };
    interp.push(Value::I32(errno as u32));
    None
}

fn wasi_fd_seek(interp: &mut crate::runtime::Interpreter<'_>) -> Option<String> {
    let newoffset_ptr = pop_u32(interp)? as usize;
    let whence = pop_u32(interp)? as u8;
    let offset = pop_i64(interp)?;
    let fd = pop_u32(interp)?;

    let new_off = match wasi_ctx::fd_seek(fd, offset, whence) {
        Ok(v) => v,
        Err(errno) => {
            interp.push(Value::I32(errno as u32));
            return None;
        }
    };

    let memory = interp.get_memory_mut();
    let end = newoffset_ptr.saturating_add(8);
    if end > memory.len() {
        interp.push(Value::I32(wasi_ctx::ERRNO_FAULT as u32));
        return None;
    }
    memory[newoffset_ptr..end].copy_from_slice(&new_off.to_le_bytes());
    interp.push(Value::I32(wasi_ctx::ERRNO_SUCCESS as u32));
    None
}

fn wasi_fd_tell(interp: &mut crate::runtime::Interpreter<'_>) -> Option<String> {
    let offset_ptr = pop_u32(interp)? as usize;
    let fd = pop_u32(interp)?;
    let off = match wasi_ctx::fd_tell(fd) {
        Ok(v) => v,
        Err(errno) => {
            interp.push(Value::I32(errno as u32));
            return None;
        }
    };
    let memory = interp.get_memory_mut();
    let end = offset_ptr.saturating_add(8);
    if end > memory.len() {
        interp.push(Value::I32(wasi_ctx::ERRNO_FAULT as u32));
        return None;
    }
    memory[offset_ptr..end].copy_from_slice(&off.to_le_bytes());
    interp.push(Value::I32(wasi_ctx::ERRNO_SUCCESS as u32));
    None
}

fn wasi_fd_fdstat_get(interp: &mut crate::runtime::Interpreter<'_>) -> Option<String> {
    let stat_ptr = pop_u32(interp)? as usize;
    let fd = pop_u32(interp)?;
    let filetype = match wasi_ctx::fd_filetype(fd) {
        Ok(v) => v,
        Err(errno) => {
            interp.push(Value::I32(errno as u32));
            return None;
        }
    };

    let memory = interp.get_memory_mut();
    let end = stat_ptr.saturating_add(24);
    if end > memory.len() {
        interp.push(Value::I32(wasi_ctx::ERRNO_FAULT as u32));
        return None;
    }

    memory[stat_ptr..end].fill(0);
    memory[stat_ptr] = filetype;
    // flags @ [2..4], rights_base @ [8..16], rights_inheriting @ [16..24]
    // Keep rights 0 in strict proc-macro subset.
    interp.push(Value::I32(wasi_ctx::ERRNO_SUCCESS as u32));
    None
}

fn wasi_path_open(interp: &mut crate::runtime::Interpreter<'_>) -> Option<String> {
    let opened_fd_ptr = pop_u32(interp)? as usize;
    let fdflags = pop_u32(interp)?;
    let _rights_inheriting = pop_i64(interp)?;
    let _rights_base = pop_i64(interp)?;
    let oflags = pop_u32(interp)?;
    let path_len = pop_u32(interp)? as usize;
    let path_ptr = pop_u32(interp)? as usize;
    let dirflags = pop_u32(interp)?;
    let dirfd = pop_u32(interp)?;

    let _ = dirflags;
    // Strict read-only mode: reject open flags that imply create/truncate,
    // and reject fdflags that request append/sync semantics.
    if (oflags & 0x1) != 0 || (oflags & 0x8) != 0 || (fdflags & 0x1f) != 0 {
        interp.push(Value::I32(wasi_ctx::ERRNO_PERM as u32));
        return None;
    }

    let path_bytes = {
        let memory = interp.get_memory_mut();
        let end = path_ptr.saturating_add(path_len);
        if end > memory.len() {
            interp.push(Value::I32(wasi_ctx::ERRNO_FAULT as u32));
            return None;
        }
        memory[path_ptr..end].to_vec()
    };

    let rights_base = _rights_base as u64;
    let opened_fd = match wasi_ctx::path_open(dirfd, &path_bytes, oflags, fdflags, rights_base) {
        Ok(fd) => fd,
        Err(errno) => {
            interp.push(Value::I32(errno as u32));
            return None;
        }
    };

    let memory = interp.get_memory_mut();
    if !write_u32(memory, opened_fd_ptr, opened_fd) {
        interp.push(Value::I32(wasi_ctx::ERRNO_FAULT as u32));
        return None;
    }
    interp.push(Value::I32(wasi_ctx::ERRNO_SUCCESS as u32));
    None
}

fn wasi_fd_prestat_get(interp: &mut crate::runtime::Interpreter<'_>) -> Option<String> {
    let prestat_ptr = pop_u32(interp)? as usize;
    let fd = pop_u32(interp)?;
    let name_len = match wasi_ctx::fd_prestat_dir(fd) {
        Ok(v) => v,
        Err(errno) => {
            interp.push(Value::I32(errno as u32));
            return None;
        }
    };
    let memory = interp.get_memory_mut();
    let end = prestat_ptr.saturating_add(8);
    if end > memory.len() {
        interp.push(Value::I32(wasi_ctx::ERRNO_FAULT as u32));
        return None;
    }
    memory[prestat_ptr..end].fill(0);
    // tag for dir prestat
    memory[prestat_ptr] = 0;
    memory[prestat_ptr + 4..prestat_ptr + 8].copy_from_slice(&name_len.to_le_bytes());
    interp.push(Value::I32(wasi_ctx::ERRNO_SUCCESS as u32));
    None
}

fn wasi_fd_prestat_dir_name(interp: &mut crate::runtime::Interpreter<'_>) -> Option<String> {
    let path_len = pop_u32(interp)? as usize;
    let path_ptr = pop_u32(interp)? as usize;
    let fd = pop_u32(interp)?;
    let name = match wasi_ctx::fd_prestat_dir_name(fd) {
        Ok(v) => v,
        Err(errno) => {
            interp.push(Value::I32(errno as u32));
            return None;
        }
    };
    if name.len() > path_len {
        interp.push(Value::I32(wasi_ctx::ERRNO_INVAL as u32));
        return None;
    }
    let memory = interp.get_memory_mut();
    let end = path_ptr.saturating_add(name.len());
    if end > memory.len() {
        interp.push(Value::I32(wasi_ctx::ERRNO_FAULT as u32));
        return None;
    }
    memory[path_ptr..end].copy_from_slice(&name);
    interp.push(Value::I32(wasi_ctx::ERRNO_SUCCESS as u32));
    None
}

pub fn host_func(name: &str, sig: &Func) -> Result<Option<HostFunc>, &'static str> {
    match name {
        "args_sizes_get" => {
            if signature_matches(sig, &[i32(), i32()], &[i32()]) {
                Ok(Some(Box::new(wasi_args_sizes_get)))
            } else {
                Err("(i32, i32) -> (i32)")
            }
        }
        "args_get" => {
            if signature_matches(sig, &[i32(), i32()], &[i32()]) {
                Ok(Some(Box::new(wasi_args_get)))
            } else {
                Err("(i32, i32) -> (i32)")
            }
        }
        "environ_sizes_get" => {
            if signature_matches(sig, &[i32(), i32()], &[i32()]) {
                Ok(Some(Box::new(wasi_environ_sizes_get)))
            } else {
                Err("(i32, i32) -> (i32)")
            }
        }
        "environ_get" => {
            if signature_matches(sig, &[i32(), i32()], &[i32()]) {
                Ok(Some(Box::new(wasi_environ_get)))
            } else {
                Err("(i32, i32) -> (i32)")
            }
        }
        "fd_write" => {
            if signature_matches(sig, &[i32(), i32(), i32(), i32()], &[i32()]) {
                Ok(Some(Box::new(wasi_fd_write)))
            } else {
                Err("(i32, i32, i32, i32) -> (i32)")
            }
        }
        "fd_read" => {
            if signature_matches(sig, &[i32(), i32(), i32(), i32()], &[i32()]) {
                Ok(Some(Box::new(wasi_fd_read)))
            } else {
                Err("(i32, i32, i32, i32) -> (i32)")
            }
        }
        "fd_close" => {
            if signature_matches(sig, &[i32()], &[i32()]) {
                Ok(Some(Box::new(wasi_fd_close)))
            } else {
                Err("(i32) -> (i32)")
            }
        }
        "fd_seek" => {
            if signature_matches(sig, &[i32(), i64(), i32(), i32()], &[i32()]) {
                Ok(Some(Box::new(wasi_fd_seek)))
            } else {
                Err("(i32, i64, i32, i32) -> (i32)")
            }
        }
        "fd_tell" => {
            if signature_matches(sig, &[i32(), i32()], &[i32()]) {
                Ok(Some(Box::new(wasi_fd_tell)))
            } else {
                Err("(i32, i32) -> (i32)")
            }
        }
        "fd_fdstat_get" => {
            if signature_matches(sig, &[i32(), i32()], &[i32()]) {
                Ok(Some(Box::new(wasi_fd_fdstat_get)))
            } else {
                Err("(i32, i32) -> (i32)")
            }
        }
        "path_open" => {
            if signature_matches(
                sig,
                &[
                    i32(),
                    i32(),
                    i32(),
                    i32(),
                    i32(),
                    i64(),
                    i64(),
                    i32(),
                    i32(),
                ],
                &[i32()],
            ) {
                Ok(Some(Box::new(wasi_path_open)))
            } else {
                Err("(i32, i32, i32, i32, i32, i64, i64, i32, i32) -> (i32)")
            }
        }
        "fd_prestat_get" => {
            if signature_matches(sig, &[i32(), i32()], &[i32()]) {
                Ok(Some(Box::new(wasi_fd_prestat_get)))
            } else {
                Err("(i32, i32) -> (i32)")
            }
        }
        "fd_prestat_dir_name" => {
            if signature_matches(sig, &[i32(), i32(), i32()], &[i32()]) {
                Ok(Some(Box::new(wasi_fd_prestat_dir_name)))
            } else {
                Err("(i32, i32, i32) -> (i32)")
            }
        }
        "random_get" => {
            if signature_matches(sig, &[i32(), i32()], &[i32()]) {
                Ok(Some(Box::new(wasi_random_get)))
            } else {
                Err("(i32, i32) -> (i32)")
            }
        }
        "clock_res_get" => {
            if signature_matches(sig, &[i32(), i32()], &[i32()]) {
                Ok(Some(Box::new(wasi_clock_res_get)))
            } else {
                Err("(i32, i32) -> (i32)")
            }
        }
        "clock_time_get" => {
            if signature_matches(sig, &[i32(), i64(), i32()], &[i32()]) {
                Ok(Some(Box::new(wasi_clock_time_get)))
            } else {
                Err("(i32, i64, i32) -> (i32)")
            }
        }
        "fd_readdir" => {
            if signature_matches(sig, &[i32(), i32(), i32(), i64(), i32()], &[i32()]) {
                Ok(Some(Box::new(|interp| {
                    let _ = pop_u32(interp);
                    let _ = pop_i64(interp);
                    let _ = pop_u32(interp);
                    let _ = pop_u32(interp);
                    let _ = pop_u32(interp);
                    interp.push(Value::I32(wasi_ctx::ERRNO_NOSYS as u32));
                    None
                })))
            } else {
                Err("(i32, i32, i32, i64, i32) -> (i32)")
            }
        }
        "proc_exit" => {
            if signature_matches(sig, &[i32()], &[]) {
                Ok(Some(Box::new(|interp| {
                    let code = match pop_u32(interp) {
                        Some(v) => v,
                        None => return Some("WasiProcExit(255)".to_string()),
                    };
                    Some(format!("WasiProcExit({code})"))
                })))
            } else {
                Err("(i32) -> ()")
            }
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::host_func;
    use crate::runtime::types::{Func, Int, Value};
    use crate::wasi_ctx;

    fn i32() -> Value {
        Value::Int(Int::I32)
    }

    #[test]
    fn exposes_expected_proc_macro_subset() {
        let sig = Func { args: vec![i32(), i32()], result: vec![i32()] };
        assert!(host_func("environ_sizes_get", &sig).unwrap().is_some());
        assert!(host_func("environ_get", &sig).unwrap().is_some());
        assert!(host_func("args_get", &sig).unwrap().is_some());
        assert!(host_func("not_supported", &sig).unwrap().is_none());
    }

    #[test]
    fn validates_signatures() {
        let wrong = Func { args: vec![i32()], result: vec![i32()] };
        assert!(host_func("environ_sizes_get", &wrong).is_err());
        assert!(host_func("proc_exit", &wrong).is_err());
    }

    #[test]
    fn stdout_capture_works() {
        wasi_ctx::set_for_test(Vec::new(), false);
        assert!(wasi_ctx::captured_stdout().is_empty());
        assert!(wasi_ctx::write_stdout(b"hello").is_ok());
        assert_eq!(wasi_ctx::captured_stdout(), b"hello");
        assert!(wasi_ctx::captured_stderr().is_empty());
    }

    #[test]
    fn args_sizes_and_get_use_runtime_context() {
        let args = vec![b"rustc\0".to_vec(), b"--crate-name\0".to_vec()];
        wasi_ctx::set_for_test_full(args.clone(), Vec::new(), false, false);
        let got = wasi_ctx::args_entries();
        assert_eq!(got, args);
    }
}
