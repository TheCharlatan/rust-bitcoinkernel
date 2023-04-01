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
pub struct ChainstateInfo {
    pub path: String,
    pub reindexing: bool,
    pub snapshot_active: bool,
    pub active_height: i32,
    pub active_ibd: bool,
}

impl From<C_ChainstateInfo> for ChainstateInfo {
    fn from(c: C_ChainstateInfo) -> ChainstateInfo {
        ChainstateInfo {
            path: unsafe { CStr::from_ptr(c.path).to_string_lossy().into_owned() },
            reindexing: c.reindexing != 0,
            snapshot_active: c.snapshot_active != 0,
            active_height: c.active_height,
            active_ibd: c.active_ibd != 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OutPoint {
    pub hash: String,
    pub n: u32,
}

impl From<C_OutPoint> for OutPoint {
    fn from(c: C_OutPoint) -> OutPoint {
        OutPoint {
            hash: unsafe { CStr::from_ptr(c.hash).to_string_lossy().into_owned() },
            n: c.n,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TxOut {
    pub value: i64,
    pub script_pubkey: String,
}

impl From<C_TxOut> for TxOut {
    fn from(c: C_TxOut) -> TxOut {
        TxOut {
            value: c.value,
            script_pubkey: unsafe { CStr::from_ptr(c.script_pubkey).to_string_lossy().into_owned() },
        }
    }
}

#[derive(Debug, Clone)]
pub struct Coin {
    pub out: TxOut,
    pub is_coinbase: bool,
    pub confirmation_height: u32,
}

impl From<C_Coin> for Coin {
    fn from(c: C_Coin) -> Coin {
        Coin {
            out: c.out.into(),
            is_coinbase: c.is_coinbase != 0,
            confirmation_height: c.confirmation_height,
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

pub struct CoinsCursor {
    inner: *mut c_void,
}

impl CoinsCursor {
    pub fn coins_cursor_next(&self) {
        unsafe {c_coins_cursor_next(self.inner)};
    }

    pub fn coins_cursor_get_key(&self) -> OutPoint {
        unsafe {c_coins_cursor_get_key(self.inner).into()}
    }

    pub fn coins_cursor_get_value(&self) -> Coin {
        unsafe {c_coins_cursor_get_value(self.inner).into()}
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

    pub fn get_chainstate_info(&self) -> ChainstateInfo {
        unsafe {
            c_get_chainstate_info(self.inner).into()
        }
    }

    pub fn chainstate_coins_cursor(&self) -> CoinsCursor {
        unsafe {
            CoinsCursor{inner: c_chainstate_coins_cursor(self.inner)}
        }
    }
}

pub fn c_chainstate_manager_delete_wrapper(chainman: ChainstateManager, scheduler: Scheduler) {
    unsafe {
        c_chainstate_manager_delete(chainman.inner, scheduler.inner);
    }
}

pub fn set_logging_callback_and_start_logging() {
    unsafe { c_set_logging_callback_and_start_logging(Some(rust_log_callback)) }
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

    unsafe { c_set_logging_callback_and_start_logging(Some(log_callback)) };
}
