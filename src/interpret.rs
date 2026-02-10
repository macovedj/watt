use crate::data::Data;
use crate::runtime::HostFunc;
use crate::import;
use crate::runtime::{
    alloc_func, decode_module, get_export, init_store, instantiate_module, invoke_func,
    module_imports, Extern, ExternVal, FuncAddr, Module, ModuleInst, Store, Value,
};
use crate::WasmMacro;
use proc_macro::TokenStream;
use std::cell::RefCell;
use std::collections::hash_map::{Entry, HashMap};
use std::io::Cursor;
use std::rc::Rc;

struct ThreadState {
    store: Store,
    instances: HashMap<usize, Rc<ModuleInst>>,
}

std::thread_local! {
    static STATE: RefCell<ThreadState> = {
        RefCell::new(ThreadState {
            store: init_store(),
            instances: HashMap::new(),
        })
    };
}

impl ThreadState {
    pub fn instance(&mut self, instance: &WasmMacro) -> &ModuleInst {
        let id = instance.id();
        let entry = match self.instances.entry(id) {
            Entry::Occupied(e) => return e.into_mut(),
            Entry::Vacant(v) => v,
        };

        let cursor = Cursor::new(instance.wasm_bytes());
        let module = match decode_module(cursor) {
            Ok(m) => {
                m
            }
            Err(e) => {
                panic!("Failed to decode WASM module: {:?}", e);
            }
        };
        #[cfg(watt_debug)]
        print_module(&module);
        let extern_vals = extern_vals(&module, &mut self.store);
        let module_instance = instantiate_module(&mut self.store, module, &extern_vals).unwrap();
        entry.insert(module_instance)
    }
}

pub fn proc_macro(fun: &str, inputs: Vec<TokenStream>, instance: &WasmMacro) -> TokenStream {
    STATE.with(|state| {
        let state = &mut state.borrow_mut();
        let instance = state.instance(instance);
        let exports = Exports::collect(instance, fun);

        let _guard = Data::guard();
        let raws: Vec<Value> = Data::with(|d| {
            inputs
                .into_iter()
                .map(|input| Value::I32(d.tokenstream.push(input)))
                .collect()
        });

        let args: Vec<Value> = raws
            .into_iter()
            .map(|raw| call(state, exports.raw_to_token_stream, vec![raw]))
            .collect();
        let output = call(state, exports.main, args);
        let raw = call(state, exports.token_stream_into_raw, vec![output]);
        let handle = match raw {
            Value::I32(handle) => handle,
            _ => unimplemented!("unexpected macro return type"),
        };
        Data::with(|d| d.tokenstream[handle].clone())
    })
}

struct Exports {
    main: FuncAddr,
    raw_to_token_stream: FuncAddr,
    token_stream_into_raw: FuncAddr,
}

impl Exports {
    fn collect(instance: &ModuleInst, entry_point: &str) -> Self {
        let main = match get_export(instance, entry_point) {
            Ok(ExternVal::Func(main)) => {
                main
            }
            _ => {
                unimplemented!("unresolved macro: {:?}", entry_point)
            }
        };
        let raw_to_token_stream = match get_export(instance, "raw_to_token_stream") {
            Ok(ExternVal::Func(func)) => {
                func
            }
            _ => {
                unimplemented!("raw_to_token_stream not found")
            }
        };
        let token_stream_into_raw = match get_export(instance, "token_stream_into_raw") {
            Ok(ExternVal::Func(func)) => {
                func
            }
            _ => {
                unimplemented!("token_stream_into_raw not found")
            }
        };
        Exports {
            main,
            raw_to_token_stream,
            token_stream_into_raw,
        }
    }
}

fn call(state: &mut ThreadState, func: FuncAddr, args: Vec<Value>) -> Value {
    match invoke_func(&mut state.store, func, args) {
        Ok(ret) => {
            assert_eq!(ret.len(), 1);
            ret.into_iter().next().unwrap()
        }
        Err(err) => panic!("{:?}", err),
    }
}

type Import<'a> = (&'a str, &'a str, Extern);

fn extern_vals(module: &Module, store: &mut Store) -> Vec<ExternVal> {
    module_imports(module)
        .map(|import| mk_host_func(import, store))
        .collect()
}

fn mk_host_func(import: Import, store: &mut Store) -> ExternVal {
    let (module, name, ref sig) = import;
    let func = match sig {
        Extern::Func(func) => func,
        Extern::Table(_) | Extern::Memory(_) | Extern::Global(_) => {
            unimplemented!("unsupported import")
        }
    };
    
    if module == "watt-0.5" || module == "watt-0.4" {
        let hostfunc = import::host_func(name, store);
        ExternVal::Func(alloc_func(store, func, hostfunc))
    } else if module == "wasi_snapshot_preview1" {
        // WASI stubs for wasm32-wasip1 compiled proc-macros
        let name_owned = name.to_string();
        let hostfunc: HostFunc = Box::new(move |interp| {
            eprintln!("[WATT WASI STUB] wasi_snapshot_preview1::{} (stack depth: {})", name_owned, interp.stack.len());
            match name_owned.as_str() {
                "proc_exit" => {
                    // proc_exit should halt execution - return a trap
                    let exit_code = interp.pop().map(|v| match v {
                        Value::I32(code) => code as i32,
                        _ => 0,
                    }).unwrap_or(0);
                    return Some(format!("proc_exit called with code {}", exit_code));
                }
                "random_get" => {
                    // random_get(buf: i32, buf_len: i32) -> errno
                    // Pop arguments in reverse order
                    let buf_len = match interp.pop() {
                        Some(Value::I32(v)) => v as usize,
                        _ => 0,
                    };
                    let buf_ptr = match interp.pop() {
                        Some(Value::I32(v)) => v as usize,
                        _ => 0,
                    };
                    // Write pseudo-random bytes to buffer
                    let mem = interp.get_memory_mut();
                    if buf_ptr + buf_len <= mem.len() {
                        // Use a simple deterministic pattern for "randomness"
                        // This is fine for proc macros that just need some entropy
                        for i in 0..buf_len {
                            mem[buf_ptr + i] = ((buf_ptr + i) * 31 + 17) as u8;
                        }
                    }
                    interp.push(Value::I32(0)); eprintln!("[WATT WASI DEBUG] After push, stack depth: {}", interp.stack.len()); // Success
                }
                "environ_sizes_get" => {
                    // environ_sizes_get(environ_count: *mut size, environ_buf_size: *mut size) -> errno
                    // Pop pointers and write 0 to both (no environment variables)
                    let buf_size_ptr = match interp.pop() {
                        Some(Value::I32(v)) => v as usize,
                        _ => 0,
                    };
                    let count_ptr = match interp.pop() {
                        Some(Value::I32(v)) => v as usize,
                        _ => 0,
                    };
                    let mem = interp.get_memory_mut();
                    // Write 0 as u32 (little-endian) for count
                    if count_ptr + 4 <= mem.len() {
                        mem[count_ptr..count_ptr + 4].copy_from_slice(&0u32.to_le_bytes());
                    }
                    // Write 0 as u32 (little-endian) for buf_size
                    if buf_size_ptr + 4 <= mem.len() {
                        mem[buf_size_ptr..buf_size_ptr + 4].copy_from_slice(&0u32.to_le_bytes());
                    }
                    interp.push(Value::I32(0)); eprintln!("[WATT WASI DEBUG] After push, stack depth: {}", interp.stack.len()); // Success
                }
                "environ_get" => {
                    // environ_get(environ: *mut *mut u8, environ_buf: *mut u8) -> errno
                    // We have 0 env vars, so just return success without writing
                    let _environ_buf = interp.pop();
                    let _environ = interp.pop();
                    interp.push(Value::I32(0)); eprintln!("[WATT WASI DEBUG] After push, stack depth: {}", interp.stack.len()); // Success
                }
                "fd_write" => {
                    // fd_write(fd: fd, iovs: *const ciovec, iovs_len: size, nwritten: *mut size) -> errno
                    let nwritten_ptr = match interp.pop() {
                        Some(Value::I32(v)) => v as usize,
                        _ => 0,
                    };
                    let _iovs_len = interp.pop();
                    let _iovs = interp.pop();
                    let _fd = interp.pop();
                    // Write 0 bytes written
                    let mem = interp.get_memory_mut();
                    if nwritten_ptr + 4 <= mem.len() {
                        mem[nwritten_ptr..nwritten_ptr + 4].copy_from_slice(&0u32.to_le_bytes());
                    }
                    interp.push(Value::I32(0)); eprintln!("[WATT WASI DEBUG] After push, stack depth: {}", interp.stack.len()); // Success
                }
                _ => {
                    // Default: return 0 (success)
                    interp.push(Value::I32(0));
                }
            }
            None
        });
        ExternVal::Func(alloc_func(store, func, hostfunc))
    } else {
        panic!("Wasm import from unknown module: {}", module);
    }
}

#[cfg(watt_debug)]
fn print_module(module: &Module) {
    use crate::runtime::module_exports;

    let mut imports: Vec<_> = module_imports(module).collect();
    imports.sort_by_key(|entry| entry.1);
    for (_env, name, sig) in imports {
    }

    let mut exports: Vec<_> = module_exports(module).collect();
    exports.sort_by_key(|entry| entry.0);
}
