use crate::data::Data;
use crate::import;
use crate::import_wasi_p1;
use crate::import_wasi_p2_core;
use crate::runtime::{
    alloc_func, decode_module, get_export, init_store, instantiate_module, invoke_func,
    module_imports, types, Extern, ExternVal, FuncAddr, Module, ModuleInst, Store, Value,
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
        let module = decode_module(cursor).unwrap_or_else(|e| {
            panic!("Failed to decode WASM module: {:?}", e);
        });
        #[cfg(watt_debug)]
        print_module(&module);

        let extern_vals = extern_vals(&module, &mut self.store).unwrap_or_else(|e| {
            panic!("Failed to resolve WASM imports: {:?}", e);
        });

        let module_instance = instantiate_module(&mut self.store, module, &extern_vals)
            .unwrap_or_else(|e| panic!("Failed to instantiate WASM module: {:?}", e));

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
            _ => panic!("unexpected macro return type: {:?}", raw),
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
    } else if import_wasi_p2_core::is_supported_module(module) {
        import_wasi_p2_core::host_func(name, func)
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
    use super::mk_host_func;
    use crate::runtime::{init_store, types, Error, Extern};

    fn i32() -> types::Value {
        types::Value::Int(types::Int::I32)
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
