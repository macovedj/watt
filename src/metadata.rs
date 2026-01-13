//! Proc macro metadata extraction from WASM modules
//!
//! This module provides functionality to extract proc macro declarations
//! from WASM modules. The metadata is stored in a custom WASM section
//! named `.rustc_proc_macro_decls`.

/// Metadata for a single proc macro
#[derive(Debug, Clone)]
pub enum ProcMacroMetadata {
    /// A derive macro (#[proc_macro_derive])
    CustomDerive {
        trait_name: String,
        /// Helper attributes for this derive
        attributes: Vec<String>,
        /// The name of the exported WASM function
        function_name: String,
    },
    /// An attribute macro (#[proc_macro_attribute])
    Attr {
        name: String,
        /// The name of the exported WASM function
        function_name: String,
    },
    /// A function-like macro (#[proc_macro])
    Bang {
        name: String,
        /// The name of the exported WASM function
        function_name: String,
    },
}

impl ProcMacroMetadata {
    /// Get the function name that should be called in the WASM module
    pub fn function_name(&self) -> &str {
        match self {
            ProcMacroMetadata::CustomDerive { function_name, .. }
            | ProcMacroMetadata::Attr { function_name, .. }
            | ProcMacroMetadata::Bang { function_name, .. } => function_name,
        }
    }

    /// Get the display name for this proc macro
    pub fn name(&self) -> &str {
        match self {
            ProcMacroMetadata::CustomDerive { trait_name, .. } => trait_name,
            ProcMacroMetadata::Attr { name, .. } | ProcMacroMetadata::Bang { name, .. } => name,
        }
    }
}

/// Extract proc macro metadata from WASM bytes
///
/// This looks for a custom section named `.rustc_proc_macro_decls` containing
/// the metadata in a simple text format.
///
/// Format (one per line):
/// - `derive:TraitName:function_name` (no attributes)
/// - `derive:TraitName:function_name:attr1,attr2` (with attributes)
/// - `attr:name:function_name`
/// - `bang:name:function_name`
pub fn extract_proc_macro_metadata(wasm_bytes: &[u8]) -> Vec<ProcMacroMetadata> {
    // Look for custom section
    if let Some(metadata_bytes) = find_custom_section(wasm_bytes, ".rustc_proc_macro_decls") {
        parse_metadata(&metadata_bytes)
    } else {
        // No metadata found - return empty vec
        // In the future, we could try to infer from exports
        Vec::new()
    }
}

/// Find a custom section in WASM bytecode
fn find_custom_section(wasm_bytes: &[u8], section_name: &str) -> Option<Vec<u8>> {
    // Simple WASM parser to find custom sections
    // This is a basic implementation - a full parser would use wasmparser crate

    let mut pos = 0;

    // Check WASM magic number
    if wasm_bytes.len() < 8 {
        return None;
    }

    if &wasm_bytes[0..4] != b"\0asm" {
        return None;
    }

    // Skip magic and version
    pos += 8;

    // Parse sections
    while pos < wasm_bytes.len() {
        if pos + 1 > wasm_bytes.len() {
            break;
        }

        let section_id = wasm_bytes[pos];
        pos += 1;

        // Read section size (LEB128)
        let (size, size_len) = read_leb128_u32(&wasm_bytes[pos..])?;
        pos += size_len;

        // Section 0 is custom section
        if section_id == 0 {
            let section_start = pos;
            let section_end = pos + size as usize;

            if section_end > wasm_bytes.len() {
                break;
            }

            // Read name length and name
            let (name_len, name_len_size) = read_leb128_u32(&wasm_bytes[pos..])?;
            pos += name_len_size;

            if pos + name_len as usize > section_end {
                pos = section_end;
                continue;
            }

            let name = &wasm_bytes[pos..pos + name_len as usize];
            pos += name_len as usize;

            if name == section_name.as_bytes() {
                // Found the section - return its contents
                return Some(wasm_bytes[pos..section_end].to_vec());
            }

            pos = section_end;
        } else {
            // Skip other sections
            pos += size as usize;
        }
    }

    None
}

/// Read a LEB128 encoded u32
fn read_leb128_u32(bytes: &[u8]) -> Option<(u32, usize)> {
    let mut result = 0u32;
    let mut shift = 0;
    let mut pos = 0;

    loop {
        if pos >= bytes.len() {
            return None;
        }

        let byte = bytes[pos];
        pos += 1;

        result |= ((byte & 0x7F) as u32) << shift;

        if byte & 0x80 == 0 {
            return Some((result, pos));
        }

        shift += 7;

        if shift > 28 {
            return None; // Overflow
        }
    }
}

/// Parse metadata from the custom section bytes
fn parse_metadata(bytes: &[u8]) -> Vec<ProcMacroMetadata> {
    let text = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let mut result = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split(':').collect();

        match parts.as_slice() {
            ["derive", trait_name, function_name] => {
                result.push(ProcMacroMetadata::CustomDerive {
                    trait_name: trait_name.to_string(),
                    attributes: Vec::new(),
                    function_name: function_name.to_string(),
                });
            }
            ["derive", trait_name, function_name, attrs] => {
                let attributes = attrs
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();

                result.push(ProcMacroMetadata::CustomDerive {
                    trait_name: trait_name.to_string(),
                    attributes,
                    function_name: function_name.to_string(),
                });
            }
            ["attr", name, function_name] => {
                result.push(ProcMacroMetadata::Attr {
                    name: name.to_string(),
                    function_name: function_name.to_string(),
                });
            }
            ["bang", name, function_name] => {
                result.push(ProcMacroMetadata::Bang {
                    name: name.to_string(),
                    function_name: function_name.to_string(),
                });
            }
            _ => {
                // Unknown format, skip
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_metadata() {
        let input = b"derive:Debug:derive_debug\nattr:my_attr:my_attr_impl\nbang:my_macro:my_macro_impl";
        let result = parse_metadata(input);

        assert_eq!(result.len(), 3);
        assert!(matches!(result[0], ProcMacroMetadata::CustomDerive { .. }));
        assert!(matches!(result[1], ProcMacroMetadata::Attr { .. }));
        assert!(matches!(result[2], ProcMacroMetadata::Bang { .. }));
    }
}
