#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi::{CStr, CString, NulError};
use std::os::raw::{c_char, c_ulong, c_void};
use std::sync::atomic::{AtomicPtr, Ordering};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

unsafe fn cast_string(c_str: *const i8) -> String {
    if !c_str.is_null() {
        std::ffi::CStr::from_ptr(c_str)
            .to_string_lossy()
            .into_owned()
    } else {
        "".to_string()
    }
}

pub enum SynchronizationState {
    INIT_REINDEX,
    INIT_DOWNLOAD,
    POST_INIT,
}

impl From<C_SynchronizationState> for SynchronizationState {
    fn from(state: C_SynchronizationState) -> SynchronizationState {
        match state {
            C_SynchronizationState_INIT_DOWNLOAD => SynchronizationState::INIT_DOWNLOAD,
            C_SynchronizationState_INIT_REINDEX => SynchronizationState::INIT_REINDEX,
            C_SynchronizationState_POST_INIT => SynchronizationState::POST_INIT,
            _ => panic!("Unexpected Synchronization state"),
        }
    }
}

pub trait KNBlockTipFn: Fn(SynchronizationState) {}
impl<F: Fn(SynchronizationState)> KNBlockTipFn for F {}

pub trait KNHeaderTipFn: Fn(SynchronizationState, i64, i64, bool) {}
impl<F: Fn(SynchronizationState, i64, i64, bool)> KNHeaderTipFn for F {}

pub trait KNProgressFn: Fn(String, i32, bool) {}
impl<F: Fn(String, i32, bool)> KNProgressFn for F {}

pub trait KNWarningFn: Fn(String) {}
impl<F: Fn(String)> KNWarningFn for F {}

pub trait KNFlushErrorFn: Fn(String) {}
impl<F: Fn(String)> KNFlushErrorFn for F {}

pub trait KNFatalErrorFn: Fn(String) {}
impl<F: Fn(String)> KNFatalErrorFn for F {}

pub struct KernelNotificationInterfaceCallbackHolder {
    pub kn_block_tip: Box<dyn KNBlockTipFn>,
    pub kn_header_tip: Box<dyn KNHeaderTipFn>,
    pub kn_progress: Box<dyn KNProgressFn>,
    pub kn_warning: Box<dyn KNWarningFn>,
    pub kn_flush_error: Box<dyn KNFlushErrorFn>,
    pub kn_fatal_error: Box<dyn KNFatalErrorFn>,
}

unsafe extern "C" fn kn_block_tip_wrapper(
    user_data: *mut c_void,
    state: C_SynchronizationState,
    _index: *mut c_void,
) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbackHolder);
    (holder.kn_block_tip)(state.into());
}

unsafe extern "C" fn kn_header_tip_wrapper(
    user_data: *mut c_void,
    state: C_SynchronizationState,
    height: i64,
    timestamp: i64,
    presync: bool,
) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbackHolder);
    (holder.kn_header_tip)(state.into(), height, timestamp, presync);
}

unsafe extern "C" fn kn_progress_wrapper(
    user_data: *mut c_void,
    title: *const i8,
    progress_percent: i32,
    resume_possible: bool,
) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbackHolder);
    (holder.kn_progress)(cast_string(title), progress_percent, resume_possible);
}

unsafe extern "C" fn kn_warning_wrapper(user_data: *mut c_void, warning: *const i8) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbackHolder);
    (holder.kn_warning)(cast_string(warning));
}

unsafe extern "C" fn kn_flush_error_wrapper(user_data: *mut c_void, message: *const i8) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbackHolder);
    (holder.kn_flush_error)(cast_string(message));
}

unsafe extern "C" fn kn_fatal_error_wrapper(
    user_data: *mut c_void,
    message: *const i8,
) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbackHolder);
    (holder.kn_fatal_error)(cast_string(message));
}

pub trait TRInsertFn: Fn(Event) {}
impl<F: Fn(Event)> TRInsertFn for F {}

pub trait TRFlushFn: Fn() {}
impl<F: Fn()> TRFlushFn for F {}

pub trait TRSizeFn: Fn() -> size_t {}
impl<F: Fn() -> size_t> TRSizeFn for F {}

pub struct TaskRunnerCallbackHolder {
    pub tr_insert: Box<dyn TRInsertFn>,
    pub tr_flush: Box<dyn TRFlushFn>,
    pub tr_size: Box<dyn TRSizeFn>,
}

unsafe extern "C" fn tr_insert_wrapper(user_data: *mut c_void, event: *mut c_void) {
    let holder = &*(user_data as *mut TaskRunnerCallbackHolder);
    (holder.tr_insert)(Event {
        inner: AtomicPtr::new(event),
    });
}

unsafe extern "C" fn tr_flush_wrapper(user_data: *mut c_void) {
    let holder = &*(user_data as *mut TaskRunnerCallbackHolder);
    (holder.tr_flush)();
}

unsafe extern "C" fn tr_size_wrapper(user_data: *mut c_void) -> c_ulong {
    let holder = &*(user_data as *mut TaskRunnerCallbackHolder);
    let res = (holder.tr_size)();
    res
}

pub struct ContextWrapper {
    inner: *mut c_void,
    pub tr_callbacks: Box<TaskRunnerCallbackHolder>,
    pub kn_callbacks: Box<KernelNotificationInterfaceCallbackHolder>,
}

#[derive(Debug)]
pub enum KernelError {
    InvalidPointer,
    LoggingFailed,
    UnknownOption,
    InvalidContext,
    SignatureCacheInit,
    ScriptExecutionCacheInit,
}

fn handle_kernel_error(error: kernel_error_t) -> Result<(), KernelError> {
    match error {
        kernel_error_t_kernel_ERR_INVALID_CONTEXT => Err(KernelError::InvalidContext),
        kernel_error_t_kernel_ERR_INVALID_POINTER => Err(KernelError::InvalidPointer),
        kernel_error_t_kernel_ERR_LOGGING_FAILED => Err(KernelError::LoggingFailed),
        kernel_error_t_kernel_ERR_UNKNOWN_OPTION => Err(KernelError::UnknownOption),
        kernel_error_t_kernel_ERR_SIGNATURE_CACHE_INIT => Err(KernelError::SignatureCacheInit),
        kernel_error_t_kernel_ERR_SCRIPT_EXECUTION_CACHE_INIT => Err(KernelError::ScriptExecutionCacheInit),
        _ => Ok(())
    }
}

impl ContextWrapper {
    pub fn new(
        kn_callbacks: Box<KernelNotificationInterfaceCallbackHolder>,
        tr_callbacks: Box<TaskRunnerCallbackHolder>,
    ) -> Result<ContextWrapper, KernelError> {
        let kn_pointer = Box::into_raw(kn_callbacks);
        let viq_pointer = Box::into_raw(tr_callbacks);

        let mut err = kernel_error_t_kernel_ERR_OK;
        let inner = unsafe { c_context_new(&mut err) };
        handle_kernel_error(err)?;

        unsafe {
            c_context_set_opt(
                inner,
                C_ContextOptions_KernelNotificationInterfaceCallbacksOption,
                Box::into_raw(Box::new(KernelNotificationInterfaceCallbacks {
                    user_data: kn_pointer as *mut c_void,
                    block_tip: Some(kn_block_tip_wrapper),
                    header_tip: Some(kn_header_tip_wrapper),
                    progress: Some(kn_progress_wrapper),
                    warning: Some(kn_warning_wrapper),
                    flush_error: Some(kn_flush_error_wrapper),
                    fatal_error: Some(kn_fatal_error_wrapper),
                }))as *mut c_void,
                &mut err,
            );
        }
        handle_kernel_error(err)?;

        unsafe {
            c_context_set_opt(
                inner,
                C_ContextOptions_TaskRunnerCallbacksOption,
                Box::into_raw(Box::new(TaskRunnerCallbacks {
                    user_data: viq_pointer as *mut c_void,
                    insert: Some(tr_insert_wrapper),
                    flush: Some(tr_flush_wrapper),
                    size: Some(tr_size_wrapper),
                })) as *mut c_void,
                &mut err,
            );
        }
        handle_kernel_error(err)?;

        // We have to do this ugly trick here in order to safely extend the
        // lifetime of the pointers
        let tr_callbacks = unsafe { Box::from_raw(viq_pointer) };
        let kn_callbacks = unsafe { Box::from_raw(kn_pointer) };

        Ok(Self {
            inner,
            tr_callbacks,
            kn_callbacks,
        })
    }
}

impl Drop for ContextWrapper {
    fn drop(&mut self) {
        let mut err = kernel_error_t_kernel_ERR_OK;
        unsafe { c_context_delete(self.inner, &mut err); }
        handle_kernel_error(err).unwrap();
    }
}

pub trait VIBlockCheckedFn: Fn() {}
impl<F: Fn()> VIBlockCheckedFn for F {}

pub struct ValidationInterfaceCallbackHolder {
    pub block_checked: Box<dyn VIBlockCheckedFn>,
}

unsafe extern "C" fn vi_block_checked_wrapper(
    user_data: *mut c_void,
    _block: *mut c_void,
    _stateIn: C_BlockValidationState,
) {
    let holder = &*(user_data as *mut ValidationInterfaceCallbackHolder);
    (holder.block_checked)();
}

pub struct ValidationInterfaceWrapper {
    inner: *mut c_void,
    pub vi_callbacks: Box<ValidationInterfaceCallbackHolder>,
}

impl ValidationInterfaceWrapper {
    pub fn new(vi_callbacks: Box<ValidationInterfaceCallbackHolder>) -> ValidationInterfaceWrapper {
        let vi_pointer = Box::into_raw(vi_callbacks);
        let inner = unsafe {
            c_create_validation_interface(ValidationInterfaceCallbacks {
                user_data: vi_pointer as *mut c_void,
                block_checked: Some(vi_block_checked_wrapper),
            })
        };

        let vi_callbacks = unsafe { Box::from_raw(vi_pointer) };
        Self {
            inner,
            vi_callbacks,
        }
    }
}

pub fn register_validation_interface(vi: &ValidationInterfaceWrapper, context: &ContextWrapper) -> Result<(), KernelError> {
    let mut err = kernel_error_t_kernel_ERR_OK;
    unsafe { c_register_validation_interface(context.inner, vi.inner, &mut err); }
    handle_kernel_error(err)?;
    Ok(())
}

pub fn unregister_validation_interface(vi: &ValidationInterfaceWrapper, context: &ContextWrapper) -> Result<(), KernelError> {
    let mut err = kernel_error_t_kernel_ERR_OK;
    unsafe { c_unregister_validation_interface(context.inner, vi.inner, &mut err); }
    handle_kernel_error(err)?;
    Ok(())
} 

impl Drop for ValidationInterfaceWrapper {
    fn drop(&mut self) {
        let mut err = kernel_error_t_kernel_ERR_OK;
        unsafe { c_destroy_validation_interface(self.inner, &mut err); }
        handle_kernel_error(err).unwrap();
    }
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
    pub hash: [u8; 32],
    pub n: u32,
}

impl From<C_OutPoint> for OutPoint {
    fn from(c: C_OutPoint) -> OutPoint {
        OutPoint {
            hash: c.hash,
            n: c.n,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TxOut {
    pub value: i64,
    pub script_pubkey: Vec<u8>,
}

impl From<C_TxOut> for TxOut {
    fn from(c: C_TxOut) -> TxOut {
        TxOut {
            value: c.value,
            script_pubkey: unsafe {
                std::slice::from_raw_parts(
                    c.script_pubkey.data,
                    c.script_pubkey.len.try_into().unwrap(),
                )
            }
            .to_vec(),
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

pub struct Event {
    pub inner: AtomicPtr<c_void>,
}

pub fn execute_event(event: Event) {
    unsafe { c_execute_event(event.inner.load(Ordering::SeqCst)) };
}

pub struct ChainstateManager<'a> {
    inner: *mut c_void,
    context: &'a ContextWrapper,
}

pub struct CoinsCursor {
    inner: *mut c_void,
}

impl CoinsCursor {
    pub fn cursor_next(&self) {
        let mut err = kernel_error_t_kernel_ERR_OK;
        unsafe { c_coins_cursor_next(self.inner, &mut err) };
        handle_kernel_error(err).unwrap();
    }

    pub fn get_key(&self) -> Result<OutPoint, KernelError> {
        let mut err = kernel_error_t_kernel_ERR_OK;
        let outpoint = unsafe { c_coins_cursor_get_key(self.inner, &mut err).into() };
        handle_kernel_error(err)?;
        Ok(outpoint)
    }

    pub fn get_value(&self) -> Result<Coin, KernelError> {
        let mut err = kernel_error_t_kernel_ERR_OK;
        let coin = unsafe { c_coins_cursor_get_value(self.inner, &mut err).into() };
        handle_kernel_error(err)?;
        Ok(coin)
    }

    pub fn valid(&self) -> Result<bool, KernelError> {
        let mut err = kernel_error_t_kernel_ERR_OK;
        let valid = unsafe { c_coins_cursor_valid(self.inner, &mut err) != 0 };
        handle_kernel_error(err)?;
        Ok(valid)
    }
}

impl Iterator for CoinsCursor {
    type Item = (OutPoint, Coin);

    fn next(&mut self) -> Option<Self::Item> {
        let key = self.get_key().unwrap();
        let value = self.get_value().unwrap();
        self.cursor_next();

        if !self.valid().unwrap() {
            None
        } else {
            Some((key, value))
        }
    }
}

impl Drop for CoinsCursor {
    fn drop(&mut self) {
        let mut err = kernel_error_t_kernel_ERR_OK;
        unsafe { c_coins_cursor_delete(self.inner, &mut err) };
        handle_kernel_error(err).unwrap();
    }
}

impl<'a> ChainstateManager<'a> {
    pub fn new(data_dir: &str, reindex: bool, context: &'a ContextWrapper) -> Result<Self, NulError> {
        let c_data_dir = CString::new(data_dir)?;
        let mut err = kernel_error_t_kernel_ERR_OK;
        let inner =
            unsafe { c_chainstate_manager_create(c_data_dir.as_ptr().cast::<i8>(), reindex, context.inner, &mut err) };
        handle_kernel_error(err).unwrap();
        Ok(Self { inner, context })
    }

    pub fn validate_block(
        &self,
        raw_block: &str,
    ) -> Result<(), NulError> {
        let c_raw_block = CString::new(raw_block)?;
        let mut err = kernel_error_t_kernel_ERR_OK;
        unsafe {
            c_chainstate_manager_validate_block(
                self.inner,
                c_raw_block.as_ptr().cast::<i8>(),
                &mut err,
            );
        };
        handle_kernel_error(err).unwrap();
        Ok(())
    }

    pub fn get_chainstate_info(&self) -> Result<ChainstateInfo, KernelError> {
        let mut err = kernel_error_t_kernel_ERR_OK;
        let chainstate_info = unsafe { c_get_chainstate_info(self.inner, &mut err).into() };
        handle_kernel_error(err)?;
        Ok(chainstate_info)
    }

    pub fn chainstate_coins_cursor(&self) -> Result<CoinsCursor, KernelError> {
        let mut err = kernel_error_t_kernel_ERR_OK;
        let coins_cursor = unsafe {
            CoinsCursor {
                inner: c_chainstate_coins_cursor(self.inner, &mut err),
            }
        };
        handle_kernel_error(err)?;
        Ok(coins_cursor)
    }
}

impl<'a> Drop for ChainstateManager<'a> {
    fn drop(&mut self) {
        let mut err = kernel_error_t_kernel_ERR_OK;
        unsafe {
            c_chainstate_manager_delete(self.inner, self.context.inner, &mut err);
        }
        handle_kernel_error(err).unwrap();
    }
}

pub trait LogFn: Fn(&str) {}
impl<F: Fn(&str)> LogFn for F {}

pub struct CallbackHolder {
    callback: Box<dyn LogFn>,
}

static mut GLOBAL_LOG_CALLBACK_HOLDER: Option<CallbackHolder> = None;

pub fn set_logging_callback<F>(callback: F)
-> Result<(), KernelError>
where
    F: LogFn + 'static,
{
    extern "C" fn log_callback(message: *const c_char) {
        let message = unsafe { CStr::from_ptr(message).to_string_lossy().into_owned() };
        let callback = unsafe {
            GLOBAL_LOG_CALLBACK_HOLDER
                .as_ref()
                .unwrap()
                .callback
                .as_ref()
        };
        callback(&message);
    }

    let callback_box = Box::new(callback);
    let callback_holder = CallbackHolder {
        callback: callback_box,
    };
    unsafe { GLOBAL_LOG_CALLBACK_HOLDER = Some(callback_holder) };

    let mut err = kernel_error_t_kernel_ERR_OK;
    unsafe { c_set_logging_callback_and_start_logging(Some(log_callback), &mut err) };
    handle_kernel_error(err)?;
    Ok(())
}
