use std::collections::BTreeSet;
use std::io::Cursor;

use crate::import;
use crate::import_wasi_p1;
use crate::runtime::ast::{Expr, ImportDesc, Instr};
use crate::runtime::{self, Error, Extern, Module};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleCapabilityCensus {
    pub imports: Vec<String>,
    pub wasm_features: Vec<String>,
    pub special_instructions: Vec<String>,
}

impl ModuleCapabilityCensus {
    fn new() -> Self {
        Self { imports: Vec::new(), wasm_features: Vec::new(), special_instructions: Vec::new() }
    }
}

pub fn validate_wasm32_wasip1_proc_macro_module(
    wasm_bytes: &[u8],
) -> Result<ModuleCapabilityCensus, Error> {
    let module = runtime::decode_module(Cursor::new(wasm_bytes))?;
    ensure_wasm32_wasip1_proc_macro_module(&module)
}

pub(crate) fn ensure_wasm32_wasip1_proc_macro_module(
    module: &Module,
) -> Result<ModuleCapabilityCensus, Error> {
    let mut census = ModuleCapabilityCensus::new();
    let mut imports = BTreeSet::new();
    let mut features = BTreeSet::new();
    let mut instructions = BTreeSet::new();
    let mut store = runtime::init_store();

    for import in &module.imports {
        let sig = match &import.desc {
            ImportDesc::Func(idx) => Extern::Func(module.types[*idx as usize].clone()),
            ImportDesc::Table(_) | ImportDesc::Memory(_) | ImportDesc::Global(_) => {
                return Err(Error::UnsupportedImportSignature {
                    module: import.module.clone(),
                    name: import.name.clone(),
                    expected: "func".to_string(),
                    found: "non-func import".to_string(),
                });
            }
        };

        imports.insert(format!("{}::{}", import.module, import.name));
        match (&*import.module, &*import.name, &sig) {
            ("watt-0.5" | "watt-0.4", name, Extern::Func(func)) => {
                import::host_func(name, &mut store, func).map_err(|expected| {
                    Error::UnsupportedImportSignature {
                        module: import.module.clone(),
                        name: import.name.clone(),
                        expected: expected.to_string(),
                        found: format_func_sig(func),
                    }
                })?;
            }
            (import_wasi_p1::WASI_P1_MODULE, name, Extern::Func(func)) => {
                features.insert("wasi-preview1".to_string());
                match import_wasi_p1::host_func(name, func) {
                    Ok(Some(_)) => {}
                    Ok(None) => {
                        return Err(Error::UnsupportedImport {
                            module: import.module.clone(),
                            name: import.name.clone(),
                        });
                    }
                    Err(expected) => {
                        return Err(Error::UnsupportedImportSignature {
                            module: import.module.clone(),
                            name: import.name.clone(),
                            expected: expected.to_string(),
                            found: format_func_sig(func),
                        });
                    }
                }
            }
            _ => {
                return Err(Error::UnsupportedImport {
                    module: import.module.clone(),
                    name: import.name.clone(),
                });
            }
        }
    }

    for func in &module.funcs {
        collect_expr_capabilities(&func.body, &mut features, &mut instructions)?;
    }
    for global in &module.globals {
        collect_expr_capabilities(&global.value, &mut features, &mut instructions)?;
    }
    for elem in &module.elems {
        collect_expr_capabilities(&elem.offset, &mut features, &mut instructions)?;
    }
    for data in &module.data {
        collect_expr_capabilities(&data.offset, &mut features, &mut instructions)?;
    }

    census.imports = imports.into_iter().collect();
    census.wasm_features = features.into_iter().collect();
    census.special_instructions = instructions.into_iter().collect();
    Ok(census)
}

fn collect_expr_capabilities(
    expr: &Expr,
    features: &mut BTreeSet<String>,
    instructions: &mut BTreeSet<String>,
) -> Result<(), Error> {
    let mut pending = vec![expr];
    while let Some(expr) = pending.pop() {
        for instr in expr {
            match instr {
                Instr::Block(_, body) | Instr::Loop(_, body) => {
                    pending.push(body);
                }
                Instr::If(_, then_body, else_body) => {
                    pending.push(else_body);
                    pending.push(then_body);
                }
                Instr::RefNull | Instr::RefIsNull | Instr::RefFunc(_) => {
                    features.insert("reference-types".to_string());
                    let opname = match instr {
                        Instr::RefNull => "ref.null",
                        Instr::RefIsNull => "ref.is_null",
                        Instr::RefFunc(_) => "ref.func",
                        _ => unreachable!(),
                    };
                    instructions.insert(opname.to_string());
                }
                Instr::MemoryCopy | Instr::MemoryFill => {
                    features.insert("bulk-memory".to_string());
                    let opname = match instr {
                        Instr::MemoryCopy => "memory.copy",
                        Instr::MemoryFill => "memory.fill",
                        _ => unreachable!(),
                    };
                    instructions.insert(opname.to_string());
                }
                Instr::MemoryInit(_) => return Err(Error::UnsupportedInstruction("memory.init")),
                Instr::DataDrop(_) => return Err(Error::UnsupportedInstruction("data.drop")),
                Instr::TableInit(_, _) => return Err(Error::UnsupportedInstruction("table.init")),
                Instr::ElemDrop(_) => return Err(Error::UnsupportedInstruction("elem.drop")),
                Instr::TableCopy(_, _) => return Err(Error::UnsupportedInstruction("table.copy")),
                Instr::TableGrow(_) => return Err(Error::UnsupportedInstruction("table.grow")),
                Instr::TableSize(_) => return Err(Error::UnsupportedInstruction("table.size")),
                Instr::TableFill(_) => return Err(Error::UnsupportedInstruction("table.fill")),
                Instr::IUnary(_, op) => {
                    let opname = match op {
                        crate::runtime::ast::IUnOp::Extend8S => Some("i.extend8_s"),
                        crate::runtime::ast::IUnOp::Extend16S => Some("i.extend16_s"),
                        crate::runtime::ast::IUnOp::Extend32S => Some("i64.extend32_s"),
                        _ => None,
                    };
                    if let Some(opname) = opname {
                        features.insert("sign-ext".to_string());
                        instructions.insert(opname.to_string());
                    }
                }
                Instr::Convert(crate::runtime::ast::ConvertOp::TruncSat { .. }) => {
                    features.insert("nontrapping-fptoint".to_string());
                    instructions.insert("trunc_sat".to_string());
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn format_func_sig(func: &crate::runtime::types::Func) -> String {
    fn ty(value: crate::runtime::types::Value) -> &'static str {
        match value {
            crate::runtime::types::Value::Int(crate::runtime::types::Int::I32) => "i32",
            crate::runtime::types::Value::Int(crate::runtime::types::Int::I64) => "i64",
            crate::runtime::types::Value::Float(crate::runtime::types::Float::F32) => "f32",
            crate::runtime::types::Value::Float(crate::runtime::types::Float::F64) => "f64",
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
fn render_census_snapshot(fixtures: &[(&str, &[u8])]) -> String {
    let mut out = String::new();
    for (idx, (name, wasm)) in fixtures.iter().enumerate() {
        let census = validate_wasm32_wasip1_proc_macro_module(wasm)
            .unwrap_or_else(|err| panic!("fixture `{name}` must validate: {err:?}"));
        if idx > 0 {
            out.push('\n');
        }
        out.push_str(&format!("[{name}]\n"));
        out.push_str("imports=");
        out.push_str(&census.imports.join(","));
        out.push('\n');
        out.push_str("features=");
        out.push_str(&census.wasm_features.join(","));
        out.push('\n');
        out.push_str("instructions=");
        out.push_str(&census.special_instructions.join(","));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{render_census_snapshot, validate_wasm32_wasip1_proc_macro_module};

    fn fixture_corpus() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            (
                "pass-through",
                wat::parse_str(
                    r#"(module
                        (func (export "expand") (result i32)
                            i32.const 0
                        )
                    )"#,
                )
                .unwrap(),
            ),
            (
                "args-env-stdio",
                wat::parse_str(
                    r#"(module
                        (type $args_sizes_get (func (param i32 i32) (result i32)))
                        (type $args_get (func (param i32 i32) (result i32)))
                        (type $env_sizes_get (func (param i32 i32) (result i32)))
                        (type $env_get (func (param i32 i32) (result i32)))
                        (type $fd_write (func (param i32 i32 i32 i32) (result i32)))
                        (import "wasi_snapshot_preview1" "args_sizes_get" (func (type $args_sizes_get)))
                        (import "wasi_snapshot_preview1" "args_get" (func (type $args_get)))
                        (import "wasi_snapshot_preview1" "environ_sizes_get" (func (type $env_sizes_get)))
                        (import "wasi_snapshot_preview1" "environ_get" (func (type $env_get)))
                        (import "wasi_snapshot_preview1" "fd_write" (func (type $fd_write)))
                        (memory 1)
                    )"#,
                )
                .unwrap(),
            ),
            (
                "filesystem",
                wat::parse_str(
                    r#"(module
                        (type $fd_read_write (func (param i32 i32 i32 i32) (result i32)))
                        (type $fd_close (func (param i32) (result i32)))
                        (type $fd_seek (func (param i32 i64 i32 i32) (result i32)))
                        (type $fd_tell (func (param i32 i32) (result i32)))
                        (type $fd_fdstat_get (func (param i32 i32) (result i32)))
                        (type $path_open (func (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
                        (type $fd_prestat_get (func (param i32 i32) (result i32)))
                        (type $fd_prestat_dir_name (func (param i32 i32 i32) (result i32)))
                        (type $fd_readdir (func (param i32 i32 i32 i64 i32) (result i32)))
                        (import "wasi_snapshot_preview1" "fd_read" (func (type $fd_read_write)))
                        (import "wasi_snapshot_preview1" "fd_write" (func (type $fd_read_write)))
                        (import "wasi_snapshot_preview1" "fd_close" (func (type $fd_close)))
                        (import "wasi_snapshot_preview1" "fd_seek" (func (type $fd_seek)))
                        (import "wasi_snapshot_preview1" "fd_tell" (func (type $fd_tell)))
                        (import "wasi_snapshot_preview1" "fd_fdstat_get" (func (type $fd_fdstat_get)))
                        (import "wasi_snapshot_preview1" "path_open" (func (type $path_open)))
                        (import "wasi_snapshot_preview1" "fd_prestat_get" (func (type $fd_prestat_get)))
                        (import "wasi_snapshot_preview1" "fd_prestat_dir_name" (func (type $fd_prestat_dir_name)))
                        (import "wasi_snapshot_preview1" "fd_readdir" (func (type $fd_readdir)))
                        (memory 1)
                    )"#,
                )
                .unwrap(),
            ),
            (
                "random-clock-proc-exit",
                wat::parse_str(
                    r#"(module
                        (type $random_get (func (param i32 i32) (result i32)))
                        (type $clock_res_get (func (param i32 i32) (result i32)))
                        (type $clock_time_get (func (param i32 i64 i32) (result i32)))
                        (type $proc_exit (func (param i32)))
                        (import "wasi_snapshot_preview1" "random_get" (func (type $random_get)))
                        (import "wasi_snapshot_preview1" "clock_res_get" (func (type $clock_res_get)))
                        (import "wasi_snapshot_preview1" "clock_time_get" (func (type $clock_time_get)))
                        (import "wasi_snapshot_preview1" "proc_exit" (func (type $proc_exit)))
                        (memory 1)
                    )"#,
                )
                .unwrap(),
            ),
            (
                "wasm-features",
                wat::parse_str(
                    r#"(module
                        (memory 1)
                        (func (export "features") (param f32) (result i32)
                            i32.const 0
                            i32.const 4
                            i32.const 2
                            memory.copy
                            i32.const 8
                            i32.const 0
                            i32.const 4
                            memory.fill
                            i32.const 255
                            i32.extend8_s
                            drop
                            local.get 0
                            i32.trunc_sat_f32_s
                            drop
                            ref.null func
                            ref.is_null
                        )
                    )"#,
                )
                .unwrap(),
            ),
        ]
    }

    #[test]
    fn rejects_threads_prefixed_module() {
        let wasm = wat::parse_str(
            r#"(module
                (memory 1 1 shared)
            )"#,
        )
        .unwrap();
        let err = validate_wasm32_wasip1_proc_macro_module(&wasm).unwrap_err();
        assert!(matches!(err, crate::runtime::Error::UnsupportedWasmFeature("threads")));
    }

    #[test]
    fn rejects_unsupported_bulk_memory_ops_before_execution() {
        let wasm = wat::parse_str(
            r#"(module
                (table 1 funcref)
                (func (export "bad") (result i32)
                    ref.null func
                    i32.const 0
                    i32.const 1
                    table.grow 0
                )
            )"#,
        )
        .unwrap();
        let err = validate_wasm32_wasip1_proc_macro_module(&wasm).unwrap_err();
        assert!(
            matches!(err, crate::runtime::Error::UnsupportedInstruction("table.grow")),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn records_supported_feature_census() {
        let wasm = wat::parse_str(
            r#"(module
                (type (func (param i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "random_get" (func (type 0)))
                (memory 1)
                (func (export "f") (param f32) (result i32)
                    local.get 0
                    i32.trunc_sat_f32_s
                )
            )"#,
        )
        .unwrap();
        let census = validate_wasm32_wasip1_proc_macro_module(&wasm).unwrap();
        assert!(census.imports.iter().any(|entry| entry == "wasi_snapshot_preview1::random_get"));
        assert!(census.wasm_features.iter().any(|entry| entry == "nontrapping-fptoint"));
        assert!(census.special_instructions.iter().any(|entry| entry == "trunc_sat"));
    }

    #[test]
    fn capability_corpus_matches_snapshot() {
        let fixtures = fixture_corpus();
        let borrowed = fixtures
            .iter()
            .map(|(name, wasm)| (*name, wasm.as_slice()))
            .collect::<Vec<_>>();
        let actual = render_census_snapshot(&borrowed);
        let expected = include_str!("testdata/wasm32_wasip1_capability_corpus.txt");
        assert_eq!(actual, expected);
    }
}
