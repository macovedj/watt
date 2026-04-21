//! Watt runtime for executing Rust procedural macros compiled as WebAssembly.
//!
//! This is a vendored and modified version of the watt crate for use in rustc.
//! Original: https://github.com/dtolnay/watt
//!
//! Key modifications:
//! - WasmMacro accepts owned Vec<u8> instead of &'static [u8]
//! - Removed JIT support (interpreter only)
//! - Adapted for rustc integration

#![deny(unsafe_op_in_unsafe_fn)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::manual_let_else,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::cast_lossless,
    clippy::cloned_instead_of_copied,
    clippy::cognitive_complexity,
    clippy::enum_glob_use,
    clippy::float_cmp,
    clippy::if_not_else,
    clippy::len_without_is_empty,
    clippy::let_unit_value,
    clippy::match_on_vec_items,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_inception,
    clippy::module_name_repetitions,
    clippy::needless_lifetimes,
    clippy::new_without_default,
    clippy::ptr_arg,
    clippy::redundant_else,
    clippy::redundant_slicing,
    clippy::return_self_not_must_use,
    clippy::semicolon_if_nothing_returned,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_cast,
    clippy::unnecessary_wraps,
    clippy::unreadable_literal,
    clippy::unused_self,
    clippy::wildcard_imports,
    clippy::wrong_self_convention
)]

extern crate rustc_proc_macro as proc_macro;

// Use the interpreter-based execution
#[path = "interpret.rs"]
mod exec;

// Import the runtime (formerly ../runtime/src/lib.rs)
#[path = "runtime_lib.rs"]
mod runtime;

mod data;
mod decode;
mod encode;
mod import;
mod sym;

pub mod metadata;

use proc_macro::TokenStream;
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::Arc;

/// Wrapper for WASM bytecode that can be either static or owned.
#[derive(Clone)]
enum WasmBytes {
    Static(&'static [u8]),
    Owned(Arc<Vec<u8>>),
}

impl WasmBytes {
    fn as_slice(&self) -> &[u8] {
        match self {
            WasmBytes::Static(bytes) => bytes,
            WasmBytes::Owned(vec) => vec.as_slice(),
        }
    }
}

/// An instantiation of a WebAssembly module used to invoke procedural macro
/// methods on the wasm module.
pub struct WasmMacro {
    wasm: WasmBytes,
    id: AtomicUsize,
}

impl WasmMacro {
    /// Creates a new `WasmMacro` from the statically included blob of wasm bytes.
    ///
    /// This is the original watt API for compatibility.
    pub const fn new(wasm: &'static [u8]) -> WasmMacro {
        WasmMacro {
            wasm: WasmBytes::Static(wasm),
            id: AtomicUsize::new(0),
        }
    }

    /// Creates a new `WasmMacro` from an owned Vec of wasm bytes.
    ///
    /// This is added for rustc integration where WASM bytecode is loaded
    /// from disk rather than being statically included.
    pub fn new_owned(wasm: Vec<u8>) -> WasmMacro {
        WasmMacro {
            wasm: WasmBytes::Owned(Arc::new(wasm)),
            id: AtomicUsize::new(0),
        }
    }

    /// Get the wasm bytes as a slice.
    ///
    /// This is useful for extracting metadata from the WASM module.
    pub fn wasm_bytes(&self) -> &[u8] {
        self.wasm.as_slice()
    }

    /// A #\[proc_macro\] implemented in wasm!
    pub fn proc_macro(&self, fun: &str, input: TokenStream) -> TokenStream {
        exec::proc_macro(fun, vec![input], self)
    }

    /// A #\[proc_macro_derive\] implemented in wasm!
    pub fn proc_macro_derive(&self, fun: &str, input: TokenStream) -> TokenStream {
        exec::proc_macro(fun, vec![input], self)
    }

    /// A #\[proc_macro_attribute\] implemented in wasm!
    pub fn proc_macro_attribute(
        &self,
        fun: &str,
        args: TokenStream,
        input: TokenStream,
    ) -> TokenStream {
        exec::proc_macro(fun, vec![args, input], self)
    }

    pub(crate) fn id(&self) -> usize {
        static NEXT_ID: AtomicUsize = AtomicUsize::new(1);
        match self.id.load(SeqCst) {
            0 => {}
            n => return n,
        }
        let id = NEXT_ID.fetch_add(1, SeqCst);
        self.id
            .compare_exchange(0, id, SeqCst, SeqCst)
            .unwrap_or_else(|id| id)
    }
}
