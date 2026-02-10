use crate::data::Data;
use std::str;

pub fn literal_to_string(literal: u32) -> u32 { eprintln!("[WATT SYM] literal_to_string({})", literal); { use std::io::Write; let _ = std::io::stderr().flush(); }
    Data::with(|d| {
        let string = d.literal[literal].to_string();
        d.string.push(string)
    })
}

pub fn string_new(memory: &mut [u8], ptr: u32, len: u32) -> u32 {
    eprintln!("[WATT SYM] string_new(ptr={}, len={}, memory_len={})", ptr, len, memory.len());
    { use std::io::Write; let _ = std::io::stderr().flush(); }
    
    let len_usize = len as usize;
    let ptr_usize = ptr as usize;
    
    eprintln!("[WATT SYM] string_new: checking bounds ptr_usize={} + len_usize={} = {}, memory.len()={}", 
              ptr_usize, len_usize, ptr_usize + len_usize, memory.len());
    { use std::io::Write; let _ = std::io::stderr().flush(); }
    
    if ptr_usize + len_usize > memory.len() {
        eprintln!("[WATT SYM] string_new: OUT OF BOUNDS!");
        { use std::io::Write; let _ = std::io::stderr().flush(); }
        panic!("string_new: memory access out of bounds");
    }
    
    let bytes = memory[ptr_usize..ptr_usize + len_usize].to_owned();
    eprintln!("[WATT SYM] string_new: got {} bytes", bytes.len());
    { use std::io::Write; let _ = std::io::stderr().flush(); }
    
    Data::with(|d| {
        match String::from_utf8(bytes) {
            Ok(string) => {
                eprintln!("[WATT SYM] string_new: valid UTF-8, pushing string");
                { use std::io::Write; let _ = std::io::stderr().flush(); }
                d.string.push(string)
            }
            Err(e) => {
                eprintln!("[WATT SYM] string_new: UTF-8 error: {:?}", e);
                { use std::io::Write; let _ = std::io::stderr().flush(); }
                panic!("non-utf8")
            }
        }
    })
}
pub fn string_len(string: u32) -> u32 { eprintln!("[WATT SYM] string_len({})", string); { use std::io::Write; let _ = std::io::stderr().flush(); }
    Data::with(|d| {
        let string = &d.string[string];
        string.len() as u32
    })
}

pub fn string_read(memory: &mut [u8], string: u32, ptr: u32) { eprintln!("[WATT SYM] string_read(string={}, ptr={})", string, ptr); { use std::io::Write; let _ = std::io::stderr().flush(); }
    Data::with(|d| {
        let ptr = ptr as usize;
        let string = &d.string[string];
        memory[ptr..ptr + string.len()].copy_from_slice(string.as_bytes());
    });
}

pub fn print_panic(string: u32) { eprintln!("[WATT SYM] print_panic({})", string); { use std::io::Write; let _ = std::io::stderr().flush(); }
    Data::with(|d| panic!("{}", d.string[string]));
}

pub fn bytes_len(bytes: u32) -> u32 { eprintln!("[WATT SYM] bytes_len({})", bytes); { use std::io::Write; let _ = std::io::stderr().flush(); }
    Data::with(|d| d.bytes[bytes].len() as u32)
}

pub fn bytes_read(memory: &mut [u8], bytes: u32, ptr: u32) { eprintln!("[WATT SYM] bytes_read(bytes={}, ptr={})", bytes, ptr); { use std::io::Write; let _ = std::io::stderr().flush(); }
    Data::with(|d| {
        let ptr = ptr as usize;
        let bytes = &d.bytes[bytes];
        memory[ptr..ptr + bytes.len()].copy_from_slice(bytes);
    });
}

pub fn token_stream_serialize(stream: u32) -> u32 { eprintln!("[WATT SYM] token_stream_serialize({})", stream); { use std::io::Write; let _ = std::io::stderr().flush(); }
    Data::with(|d| {
        let stream = d.tokenstream[stream].clone();
        let bytes = crate::encode::encode(stream, d);
        d.bytes.push(bytes)
    })
}

pub fn token_stream_deserialize(memory: &mut [u8], ptr: u32, len: u32) -> u32 { eprintln!("[WATT SYM] token_stream_deserialize(ptr={}, len={})", ptr, len); { use std::io::Write; let _ = std::io::stderr().flush(); }
    Data::with(|d| {
        let ptr = ptr as usize;
        let len = len as usize;
        let memory = &memory[ptr..ptr + len];
        let stream = crate::decode::decode(memory, d);
        d.tokenstream.push(stream)
    })
}

pub fn token_stream_parse(memory: &mut [u8], ptr: u32, len: u32) -> u32 { eprintln!("[WATT SYM] token_stream_parse(ptr={}, len={})", ptr, len); { use std::io::Write; let _ = std::io::stderr().flush(); }
    Data::with(|d| {
        let ptr = ptr as usize;
        let len = len as usize;
        let memory = &memory[ptr..ptr + len];
        let string = match str::from_utf8(memory) {
            Ok(s) => s,
            Err(_) => return u32::max_value(),
        };
        let stream = match string.parse() {
            Ok(s) => s,
            Err(_) => return u32::max_value(),
        };
        d.tokenstream.push(stream)
    })
}
