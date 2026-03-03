use crate::runtime::types::{Func, Int, Value};
use crate::runtime::{func1, mem_func2, HostFunc, Store};
use crate::sym;

fn i32() -> Value {
    Value::Int(Int::I32)
}

fn signature_matches(sig: &Func, params: &[Value], results: &[Value]) -> bool {
    sig.args == params && sig.result == results
}

pub fn host_func(name: &str, store: &Store, sig: &Func) -> Result<Option<HostFunc>, &'static str> {
    match name {
        "token_stream_serialize" => {
            if signature_matches(sig, &[i32()], &[i32()]) {
                Ok(Some(func1(sym::token_stream_serialize, store)))
            } else {
                Err("(i32) -> (i32)")
            }
        }
        "token_stream_deserialize" | "token_stream_parse" | "string_new" => {
            if signature_matches(sig, &[i32(), i32()], &[i32()]) {
                let host = match name {
                    "token_stream_deserialize" => mem_func2(sym::token_stream_deserialize, store),
                    "token_stream_parse" => mem_func2(sym::token_stream_parse, store),
                    "string_new" => mem_func2(sym::string_new, store),
                    _ => unreachable!(),
                };
                Ok(Some(host))
            } else {
                Err("(i32, i32) -> (i32)")
            }
        }
        "literal_to_string" | "string_len" | "bytes_len" => {
            if signature_matches(sig, &[i32()], &[i32()]) {
                let host = match name {
                    "literal_to_string" => func1(sym::literal_to_string, store),
                    "string_len" => func1(sym::string_len, store),
                    "bytes_len" => func1(sym::bytes_len, store),
                    _ => unreachable!(),
                };
                Ok(Some(host))
            } else {
                Err("(i32) -> (i32)")
            }
        }
        "string_read" | "bytes_read" => {
            if signature_matches(sig, &[i32(), i32()], &[]) {
                let host = match name {
                    "string_read" => mem_func2(sym::string_read, store),
                    "bytes_read" => mem_func2(sym::bytes_read, store),
                    _ => unreachable!(),
                };
                Ok(Some(host))
            } else {
                Err("(i32, i32) -> ()")
            }
        }
        "print_panic" => {
            if signature_matches(sig, &[i32()], &[]) {
                Ok(Some(func1(sym::print_panic, store)))
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
    use crate::runtime::init_store;

    fn i32() -> Value {
        Value::Int(Int::I32)
    }

    #[test]
    fn watt_imports_enforce_signatures() {
        let store = init_store();
        let ok = Func { args: vec![i32()], result: vec![i32()] };
        let bad = Func { args: vec![i32()], result: vec![] };

        assert!(host_func("string_len", &store, &ok).unwrap().is_some());
        assert!(host_func("string_len", &store, &bad).is_err());
    }
}
