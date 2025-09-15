use std::ffi::c_char;

/// Returns true if the C return code indicates success (0).
#[inline]
pub fn success(code: i32) -> bool {
    code == 0
}

/// Returns true if the C return code indicates a present/found state (non-zero).
#[inline]
pub fn present(code: i32) -> bool {
    code != 0
}

/// Returns true if the C return code indicates an enabled state (non-zero).
#[inline]
pub fn enabled(code: i32) -> bool {
    code != 0
}

/// Returns true if the C return code indicates verification passed (1).
#[inline]
pub fn verification_passed(code: i32) -> bool {
    code == 1
}

/// Converts a Rust bool to C bool representation (1 for true, 0 for false).
#[inline]
pub fn to_c_bool(value: bool) -> i32 {
    if value {
        1
    } else {
        0
    }
}

/// Converts success status to C result code (0 for success, 1 for failure).
#[inline]
pub fn to_c_result(success: bool) -> i32 {
    if success {
        0
    } else {
        1
    }
}

pub unsafe fn to_string(c_str: *const c_char, len: usize) -> String {
    if !c_str.is_null() {
        let slice = std::slice::from_raw_parts(c_str as *const u8, len);
        String::from_utf8_lossy(slice).into_owned()
    } else {
        "".to_string()
    }
}
