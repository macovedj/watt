use crate::runtime::types::Func;
use crate::runtime::HostFunc;

use crate::import_wasi_p1;

const P2_MODULE_ALLOWLIST: &[&str] = &[
    // Common aliases observed in preview2-core lowering pipelines.
    "wasi_snapshot_preview2",
    "wasi:cli/environment@",
    "wasi:io/streams@",
    "wasi:random/random@",
];

pub fn is_supported_module(module: &str) -> bool {
    P2_MODULE_ALLOWLIST.iter().any(|prefix| module.starts_with(prefix))
}

pub fn host_func(name: &str, sig: &Func) -> Result<Option<HostFunc>, &'static str> {
    // We currently support only the proc-macro required compatibility subset.
    // Map to deterministic WASI p1-compatible behavior.
    import_wasi_p1::host_func(name, sig)
}

#[cfg(test)]
mod tests {
    use crate::runtime::types::{Func, Int, Value};

    use super::{host_func, is_supported_module};

    fn i32() -> Value {
        Value::Int(Int::I32)
    }

    #[test]
    fn accepts_known_p2_prefixes() {
        assert!(is_supported_module("wasi:cli/environment@0.2.0"));
        assert!(is_supported_module("wasi:io/streams@0.2.0"));
        assert!(is_supported_module("wasi_snapshot_preview2"));
        assert!(!is_supported_module("env"));
    }

    #[test]
    fn maps_supported_names_to_handlers() {
        let sig = Func { args: vec![i32(), i32()], result: vec![i32()] };
        assert!(host_func("environ_sizes_get", &sig).unwrap().is_some());
        assert!(host_func("not_supported", &sig).unwrap().is_none());
    }
}
