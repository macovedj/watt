use crate::data::Data;
use crate::import;
use crate::import_wasi_p1;
use crate::module_support;
use crate::runtime::{
    alloc_func, decode_module, get_export, init_store, instantiate_module, invoke_func,
    module_imports, types, Extern, ExternVal, FuncAddr, Module, ModuleInst, Store, Value,
};
use crate::WasmMacro;
use proc_macro::TokenStream;
use std::io::Cursor;
use std::rc::Rc;

struct RuntimeState {
    store: Store,
}

impl RuntimeState {
    fn new() -> Self {
        Self { store: init_store() }
    }

    pub fn instantiate(&mut self, instance: &WasmMacro) -> Rc<ModuleInst> {
        let cursor = Cursor::new(instance.wasm_bytes());
        let module = decode_module(cursor).unwrap_or_else(|e| {
            panic!("Failed to decode WASM module: {:?}", e);
        });
        module_support::ensure_wasm32_wasip1_proc_macro_module(&module).unwrap_or_else(|e| {
            panic!("Unsupported wasm32-wasip1 proc-macro module: {:?}", e);
        });
        #[cfg(watt_debug)]
        print_module(&module);

        let extern_vals = extern_vals(&module, &mut self.store).unwrap_or_else(|e| {
            panic!("Failed to resolve WASM imports: {:?}", e);
        });

        instantiate_module(&mut self.store, module, &extern_vals)
            .unwrap_or_else(|e| panic!("Failed to instantiate WASM module: {:?}", e))
    }
}

pub fn proc_macro(fun: &str, inputs: Vec<TokenStream>, instance: &WasmMacro) -> TokenStream {
    let state = &mut RuntimeState::new();
    let instance = state.instantiate(instance);
    let exports = Exports::collect(&instance, fun);

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
        _ => panic!("unexpected macro return type: {:?}", raw),
    };
    Data::with(|d| d.tokenstream[handle].clone())
}

struct Exports {
    main: FuncAddr,
    raw_to_token_stream: FuncAddr,
    token_stream_into_raw: FuncAddr,
}

impl Exports {
    fn collect(instance: &ModuleInst, entry_point: &str) -> Self {
        let main = match get_export(instance, entry_point) {
            Ok(ExternVal::Func(main)) => main,
            _ => panic!("unresolved macro entry point: {:?}", entry_point),
        };
        let raw_to_token_stream = match get_export(instance, "raw_to_token_stream") {
            Ok(ExternVal::Func(func)) => func,
            _ => panic!("raw_to_token_stream not found"),
        };
        let token_stream_into_raw = match get_export(instance, "token_stream_into_raw") {
            Ok(ExternVal::Func(func)) => func,
            _ => panic!("token_stream_into_raw not found"),
        };
        Exports {
            main,
            raw_to_token_stream,
            token_stream_into_raw,
        }
    }
}

fn call(state: &mut RuntimeState, func: FuncAddr, args: Vec<Value>) -> Value {
    match invoke_func(&mut state.store, func, args) {
        Ok(ret) => {
            assert_eq!(ret.len(), 1);
            ret.into_iter().next().unwrap()
        }
        Err(err) => panic!("{:?}", err),
    }
}

type Import<'a> = (&'a str, &'a str, Extern);

fn extern_vals(module: &Module, store: &mut Store) -> Result<Vec<ExternVal>, crate::runtime::Error> {
    module_imports(module)
        .map(|import| mk_host_func(import, store))
        .collect()
}

fn mk_host_func(import: Import, store: &mut Store) -> Result<ExternVal, crate::runtime::Error> {
    let (module, name, ref sig) = import;
    let func = match sig {
        Extern::Func(func) => func,
        Extern::Table(_) | Extern::Memory(_) | Extern::Global(_) => {
            return Err(crate::runtime::Error::UnsupportedImportSignature {
                module: module.to_string(),
                name: name.to_string(),
                expected: "func".to_string(),
                found: "non-func import".to_string(),
            });
        }
    };

    let hostfunc = if module == "watt-0.5" || module == "watt-0.4" {
        import::host_func(name, store, func)
    } else if module == import_wasi_p1::WASI_P1_MODULE {
        import_wasi_p1::host_func(name, func)
    } else {
        Ok(None)
    };

    match hostfunc {
        Ok(Some(hostfunc)) => Ok(ExternVal::Func(alloc_func(store, func, hostfunc))),
        Ok(None) => Err(crate::runtime::Error::UnsupportedImport {
            module: module.to_string(),
            name: name.to_string(),
        }),
        Err(expected) => Err(crate::runtime::Error::UnsupportedImportSignature {
            module: module.to_string(),
            name: name.to_string(),
            expected: expected.to_string(),
            found: format_func_sig(func),
        }),
    }
}

fn format_func_sig(func: &types::Func) -> String {
    fn ty(value: types::Value) -> &'static str {
        match value {
            types::Value::Int(types::Int::I32) => "i32",
            types::Value::Int(types::Int::I64) => "i64",
            types::Value::Float(types::Float::F32) => "f32",
            types::Value::Float(types::Float::F64) => "f64",
        }
    }

    let args = if func.args.is_empty() {
        String::new()
    } else {
        func.args.iter().map(|v| ty(*v)).collect::<Vec<_>>().join(", ")
    };
    let results = if func.result.is_empty() {
        String::new()
    } else {
        func.result.iter().map(|v| ty(*v)).collect::<Vec<_>>().join(", ")
    };
    format!("({args}) -> ({results})")
}

#[cfg(test)]
mod tests {
    use super::{extern_vals, mk_host_func};
    use crate::module_support;
    use crate::runtime::{
        decode_module, get_export, init_store, instantiate_module, invoke_func, types, Error,
        Extern, ExternVal, Module, ModuleInst, Store, Value,
    };
    use crate::wasi_ctx;
    use std::io::Cursor;
    use std::path::PathBuf;
    use std::rc::Rc;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn i32() -> types::Value {
        types::Value::Int(types::Int::I32)
    }

    fn mk_tmp_dir() -> PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("rustc-watt-interpret-test-{nanos}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn instantiate_wat(wat_src: &str) -> (Store, Rc<ModuleInst>) {
        let wasm = wat::parse_str(wat_src).unwrap();
        let module = decode_module(Cursor::new(wasm)).unwrap();
        module_support::ensure_wasm32_wasip1_proc_macro_module(&module).unwrap();
        instantiate_validated_module(module)
    }

    fn instantiate_validated_module(module: Module) -> (Store, Rc<ModuleInst>) {
        let mut store = init_store();
        let externs = extern_vals(&module, &mut store).unwrap();
        let inst = instantiate_module(&mut store, module, &externs).unwrap();
        (store, inst)
    }

    fn invoke_export(
        store: &mut Store,
        inst: &ModuleInst,
        name: &str,
        args: Vec<Value>,
    ) -> Result<Vec<Value>, Error> {
        let ExternVal::Func(func) = get_export(inst, name).unwrap() else {
            panic!("export `{name}` must be a function");
        };
        invoke_func(store, func, args)
    }

    #[test]
    fn rejects_unknown_imports() {
        let mut store = init_store();
        let sig = Extern::Func(types::Func { args: vec![i32()], result: vec![] });
        let err = mk_host_func(("unknown.module", "some_func", sig), &mut store).unwrap_err();

        assert!(matches!(
            err,
            Error::UnsupportedImport { module, name }
            if module == "unknown.module" && name == "some_func"
        ));
    }

    #[test]
    fn rejects_signature_mismatch() {
        let mut store = init_store();
        let bad_sig = Extern::Func(types::Func { args: vec![i32()], result: vec![i32()] });
        let err =
            mk_host_func(("wasi_snapshot_preview1", "proc_exit", bad_sig), &mut store).unwrap_err();

        assert!(matches!(
            err,
            Error::UnsupportedImportSignature { module, name, .. }
            if module == "wasi_snapshot_preview1" && name == "proc_exit"
        ));
    }

    #[test]
    fn executes_fd_write_to_stdout_capture() {
        wasi_ctx::set_for_test(Vec::new(), false);
        let (mut store, inst) = instantiate_wat(
            r#"(module
                (type $fd_write (func (param i32 i32 i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (type $fd_write)))
                (memory 1)
                (data (i32.const 16) "hello")
                (func (export "run") (result i32)
                    i32.const 0
                    i32.const 16
                    i32.store
                    i32.const 4
                    i32.const 5
                    i32.store
                    i32.const 1
                    i32.const 0
                    i32.const 1
                    i32.const 8
                    call $fd_write
                )
            )"#,
        );

        let ret = invoke_export(&mut store, &inst, "run", Vec::new()).unwrap();
        assert_eq!(ret, vec![Value::I32(0)]);
        assert_eq!(wasi_ctx::captured_stdout(), b"hello");
    }

    #[test]
    fn executes_random_get_deterministically() {
        wasi_ctx::set_for_test_full(Vec::new(), Vec::new(), false, true);
        let (mut store, inst) = instantiate_wat(
            r#"(module
                (type $random_get (func (param i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "random_get" (func $random_get (type $random_get)))
                (memory 1)
                (func (export "run") (result i32)
                    i32.const 0
                    i32.const 4
                    call $random_get
                    drop
                    i32.const 0
                    i32.load
                )
            )"#,
        );

        let ret = invoke_export(&mut store, &inst, "run", Vec::new()).unwrap();
        assert_eq!(ret, vec![Value::I32(0)]);
    }

    #[test]
    fn executes_clock_time_get_in_deterministic_mode() {
        wasi_ctx::set_for_test_full(Vec::new(), Vec::new(), false, true);
        let (mut store, inst) = instantiate_wat(
            r#"(module
                (type $clock_res_get (func (param i32 i32) (result i32)))
                (type $clock_time_get (func (param i32 i64 i32) (result i32)))
                (import "wasi_snapshot_preview1" "clock_res_get" (func $clock_res_get (type $clock_res_get)))
                (import "wasi_snapshot_preview1" "clock_time_get" (func $clock_time_get (type $clock_time_get)))
                (memory 1)
                (func (export "run") (result i64)
                    i32.const 0
                    i32.const 16
                    call $clock_res_get
                    drop
                    i32.const 0
                    i64.const 0
                    i32.const 8
                    call $clock_time_get
                    drop
                    i32.const 16
                    i64.load
                    i32.wrap_i64
                    if (result i64)
                        i32.const 8
                        i64.load
                    else
                        i64.const -1
                    end
                )
            )"#,
        );

        let ret = invoke_export(&mut store, &inst, "run", Vec::new()).unwrap();
        assert_eq!(ret, vec![Value::I64(0)]);
    }

    #[test]
    fn executes_args_and_environ_queries() {
        let args = vec![b"rustc\0".to_vec()];
        let env = vec![b"K=V\0".to_vec()];
        wasi_ctx::set_for_test_full(args, env, false, false);
        let (mut store, inst) = instantiate_wat(
            r#"(module
                (type $sizes (func (param i32 i32) (result i32)))
                (type $get (func (param i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "args_sizes_get" (func $args_sizes_get (type $sizes)))
                (import "wasi_snapshot_preview1" "args_get" (func $args_get (type $get)))
                (import "wasi_snapshot_preview1" "environ_sizes_get" (func $env_sizes_get (type $sizes)))
                (import "wasi_snapshot_preview1" "environ_get" (func $env_get (type $get)))
                (memory 1)
                (func (export "run") (result i32)
                    i32.const 0
                    i32.const 4
                    call $args_sizes_get
                    drop
                    i32.const 8
                    i32.const 16
                    call $args_get
                    drop
                    i32.const 24
                    i32.const 28
                    call $env_sizes_get
                    drop
                    i32.const 32
                    i32.const 40
                    call $env_get
                    drop
                    i32.const 16
                    i32.load8_u
                    i32.const 114
                    i32.sub
                    i32.const 40
                    i32.load8_u
                    i32.const 75
                    i32.sub
                    i32.add
                )
            )"#,
        );

        let ret = invoke_export(&mut store, &inst, "run", Vec::new()).unwrap();
        assert_eq!(ret, vec![Value::I32(0)]);
    }

    #[test]
    fn executes_path_open_fd_write_and_close() {
        let dir = mk_tmp_dir();
        let out = dir.join("out.txt");
        std::fs::write(&out, b"").unwrap();
        wasi_ctx::set_for_test_with_preopens(Vec::new(), false, vec![(dir.clone(), true)]);
        let (mut store, inst) = instantiate_wat(
            r#"(module
                (type $path_open (func (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
                (type $fd_write (func (param i32 i32 i32 i32) (result i32)))
                (type $fd_close (func (param i32) (result i32)))
                (import "wasi_snapshot_preview1" "path_open" (func $path_open (type $path_open)))
                (import "wasi_snapshot_preview1" "fd_write" (func $fd_write (type $fd_write)))
                (import "wasi_snapshot_preview1" "fd_close" (func $fd_close (type $fd_close)))
                (memory 1)
                (data (i32.const 32) "out.txt")
                (data (i32.const 64) "hello")
                (func (export "run") (result i32)
                    i32.const 3
                    i32.const 0
                    i32.const 32
                    i32.const 7
                    i32.const 0
                    i64.const 64
                    i64.const 0
                    i32.const 0
                    i32.const 24
                    call $path_open
                    if (result i32)
                        i32.const 1
                    else
                        i32.const 0
                        i32.const 64
                        i32.store
                        i32.const 4
                        i32.const 5
                        i32.store
                        i32.const 24
                        i32.load
                        i32.const 0
                        i32.const 1
                        i32.const 28
                        call $fd_write
                        drop
                        i32.const 24
                        i32.load
                        call $fd_close
                    end
                )
            )"#,
        );

        let ret = invoke_export(&mut store, &inst, "run", Vec::new()).unwrap();
        assert_eq!(ret, vec![Value::I32(0)]);
        assert_eq!(std::fs::read(out).unwrap(), b"hello");
    }

    #[test]
    fn executes_path_open_fd_read_and_close() {
        let dir = mk_tmp_dir();
        std::fs::write(dir.join("in.txt"), b"ABC").unwrap();
        wasi_ctx::set_for_test_with_preopens(Vec::new(), false, vec![(dir.clone(), false)]);
        let (mut store, inst) = instantiate_wat(
            r#"(module
                (type $path_open (func (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
                (type $fd_read (func (param i32 i32 i32 i32) (result i32)))
                (type $fd_close (func (param i32) (result i32)))
                (import "wasi_snapshot_preview1" "path_open" (func $path_open (type $path_open)))
                (import "wasi_snapshot_preview1" "fd_read" (func $fd_read (type $fd_read)))
                (import "wasi_snapshot_preview1" "fd_close" (func $fd_close (type $fd_close)))
                (memory 1)
                (data (i32.const 32) "in.txt")
                (func (export "run") (result i32)
                    i32.const 3
                    i32.const 0
                    i32.const 32
                    i32.const 6
                    i32.const 0
                    i64.const 0
                    i64.const 0
                    i32.const 0
                    i32.const 24
                    call $path_open
                    drop
                    i32.const 0
                    i32.const 64
                    i32.store
                    i32.const 4
                    i32.const 3
                    i32.store
                    i32.const 24
                    i32.load
                    i32.const 0
                    i32.const 1
                    i32.const 28
                    call $fd_read
                    drop
                    i32.const 24
                    i32.load
                    call $fd_close
                    drop
                    i32.const 64
                    i32.load8_u
                    i32.const 65
                    i32.sub
                )
            )"#,
        );

        let ret = invoke_export(&mut store, &inst, "run", Vec::new()).unwrap();
        assert_eq!(ret, vec![Value::I32(0)]);
    }

    #[test]
    fn executes_fd_prestat_queries_and_readdir_nosys() {
        let dir = mk_tmp_dir().canonicalize().unwrap();
        let first_byte = dir.to_string_lossy().as_bytes()[0] as u32;
        wasi_ctx::set_for_test_with_preopens(Vec::new(), false, vec![(dir.clone(), false)]);
        let (mut store, inst) = instantiate_wat(
            r#"(module
                (type $fd_prestat_get (func (param i32 i32) (result i32)))
                (type $fd_prestat_dir_name (func (param i32 i32 i32) (result i32)))
                (type $fd_readdir (func (param i32 i32 i32 i64 i32) (result i32)))
                (import "wasi_snapshot_preview1" "fd_prestat_get" (func $fd_prestat_get (type $fd_prestat_get)))
                (import "wasi_snapshot_preview1" "fd_prestat_dir_name" (func $fd_prestat_dir_name (type $fd_prestat_dir_name)))
                (import "wasi_snapshot_preview1" "fd_readdir" (func $fd_readdir (type $fd_readdir)))
                (memory 1)
                (func (export "prestat_first_byte") (result i32)
                    i32.const 3
                    i32.const 0
                    call $fd_prestat_get
                    drop
                    i32.const 3
                    i32.const 8
                    i32.const 4
                    i32.load
                    call $fd_prestat_dir_name
                    drop
                    i32.const 8
                    i32.load8_u
                )
                (func (export "readdir_errno") (result i32)
                    i32.const 3
                    i32.const 16
                    i32.const 8
                    i64.const 0
                    i32.const 24
                    call $fd_readdir
                )
            )"#,
        );

        let first = invoke_export(&mut store, &inst, "prestat_first_byte", Vec::new()).unwrap();
        assert_eq!(first, vec![Value::I32(first_byte)]);

        let errno = invoke_export(&mut store, &inst, "readdir_errno", Vec::new()).unwrap();
        assert_eq!(errno, vec![Value::I32(wasi_ctx::ERRNO_NOSYS as u32)]);
    }

    #[test]
    fn executes_proc_exit_as_typed_runtime_error() {
        let (mut store, inst) = instantiate_wat(
            r#"(module
                (type $proc_exit (func (param i32)))
                (import "wasi_snapshot_preview1" "proc_exit" (func $proc_exit (type $proc_exit)))
                (func (export "run")
                    i32.const 7
                    call $proc_exit
                )
            )"#,
        );

        let err = invoke_export(&mut store, &inst, "run", Vec::new()).unwrap_err();
        assert_eq!(err, Error::WasiProcExit(7));
    }
}

#[cfg(watt_debug)]
fn print_module(module: &Module) {
    use crate::runtime::module_exports;

    let mut imports: Vec<_> = module_imports(module).collect();
    imports.sort_by_key(|entry| entry.1);
    for _ in imports {}

    let mut exports: Vec<_> = module_exports(module).collect();
    exports.sort_by_key(|entry| entry.0);
    for _ in exports {}
}
