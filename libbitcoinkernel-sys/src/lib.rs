#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi::{CString, NulError, CStr};
use std::os::raw::{c_void, c_char};
use std::default::Default;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

extern "C" fn rust_log_callback(message: *const c_char) {
    let message_str = unsafe { CStr::from_ptr(message).to_str().unwrap()};
    println!("rust-bitcoinkernel: {}", message_str);
}

pub struct Scheduler {
    inner: *mut c_void,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ChainstateManager {
    inner: *mut c_void,
}

impl Scheduler {
    pub fn new() -> Scheduler {
        let inner = unsafe { c_scheduler_new() };
        Self { inner }
    }
}

impl ChainstateManager {
    pub fn new(data_dir: &str, scheduler: &Scheduler) -> Result<Self, NulError> {
        let c_data_dir = CString::new(data_dir)?;
        let inner = unsafe {
            c_chainstate_manager_create(c_data_dir.as_ptr().cast::<i8>(), scheduler.inner)
        };
        Ok(Self { inner })
    }

    pub fn validate_block(&self, raw_block: &str) -> Result<(), NulError> {
        let c_raw_block = CString::new(raw_block)?;
        unsafe {
            c_chainstate_manager_validate_block(self.inner, c_raw_block.as_ptr().cast::<i8>());
        };
        Ok(())
    }
}

pub fn c_chainstate_manager_delete_wrapper(chainman: ChainstateManager, scheduler: Scheduler) {
    unsafe {
        c_chainstate_manager_delete(chainman.inner, scheduler.inner);
    }
}

pub fn set_logging_callback_and_start_logging_wrapper() {
    unsafe {
        set_logging_callback_and_start_logging(Some(rust_log_callback))
    }
}
