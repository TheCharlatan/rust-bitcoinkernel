#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::default::Default;
use std::ffi::{CStr, CString, NulError};
use std::os::raw::{c_char, c_void};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

extern "C" fn rust_log_callback(message: *const c_char) {
    let message_str = unsafe { CStr::from_ptr(message).to_str().unwrap() };
    println!("rust-bitcoinkernel: {}", message_str);
}

pub struct Scheduler {
    inner: *mut c_void,
}

#[derive(Debug, Clone)]
pub struct ChainstateInfoWrapper {
    pub path: String,
    pub reindexing: bool,
    pub snapshot_active: bool,
    pub active_height: i32,
    pub active_ibd: bool,
}

impl From<ChainstateInfo> for ChainstateInfoWrapper {
    fn from(c: ChainstateInfo) -> ChainstateInfoWrapper {
        ChainstateInfoWrapper {
            path: unsafe { CStr::from_ptr(c.path).to_string_lossy().into_owned() },
            reindexing: c.reindexing != 0,
            snapshot_active: c.snapshot_active != 0,
            active_height: c.active_height,
            active_ibd: c.active_ibd != 0,
        }
    }
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

    pub fn get_chainstate_info_wrapper(&self) -> ChainstateInfoWrapper {
        unsafe {
            get_chainstate_info(self.inner).into()
        }
    }
}

pub fn c_chainstate_manager_delete_wrapper(chainman: ChainstateManager, scheduler: Scheduler) {
    unsafe {
        c_chainstate_manager_delete(chainman.inner, scheduler.inner);
    }
}

pub fn set_logging_callback_and_start_logging_wrapper() {
    unsafe { set_logging_callback_and_start_logging(Some(rust_log_callback)) }
}

pub trait LogFn: Fn(&str) {}
impl<F: Fn(&str)> LogFn for F {}

struct CallbackHolder {
    callback: Box<dyn LogFn>,
}

static mut GLOBAL_CALLBACK_HOLDER: Option<CallbackHolder> = None;

pub fn set_logging_callback<F>(callback: F)
where
    F: LogFn + 'static,
{
    extern "C" fn log_callback(message: *const c_char) {
        let message = unsafe { CStr::from_ptr(message).to_string_lossy().into_owned() };
        let callback = unsafe { GLOBAL_CALLBACK_HOLDER.as_ref().unwrap().callback.as_ref() };
        callback(&message);
    }

    let callback_box = Box::new(callback);
    let callback_holder = CallbackHolder {
        callback: callback_box,
    };
    unsafe { GLOBAL_CALLBACK_HOLDER = Some(callback_holder) };

    unsafe { set_logging_callback_and_start_logging(Some(log_callback)) };
}
