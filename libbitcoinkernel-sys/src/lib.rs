#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi::{CStr, CString, NulError};
use std::os::raw::{c_char, c_void};
use std::sync::atomic::{AtomicPtr, Ordering};
use std::fmt;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

unsafe fn cast_string(c_str: *const c_char) -> String {
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

pub enum ChainType {
    MAINNET,
    TESTNET,
    SIGNET,
    REGTEST,
}

impl From<ChainType> for C_Chain {
    fn from(chain: ChainType) -> C_Chain {
        match chain {
            ChainType::MAINNET => C_Chain_kernel_MAINNET,
            ChainType::TESTNET => C_Chain_kernel_TESTNET,
            ChainType::SIGNET => C_Chain_kernel_SIGNET,
            ChainType::REGTEST => C_Chain_kernel_REGTEST,
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
    title: *const c_char,
    progress_percent: i32,
    resume_possible: bool,
) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbackHolder);
    (holder.kn_progress)(cast_string(title), progress_percent, resume_possible);
}

unsafe extern "C" fn kn_warning_wrapper(user_data: *mut c_void, warning: *const c_char) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbackHolder);
    (holder.kn_warning)(cast_string(warning));
}

unsafe extern "C" fn kn_flush_error_wrapper(user_data: *mut c_void, message: *const c_char) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbackHolder);
    (holder.kn_flush_error)(cast_string(message));
}

unsafe extern "C" fn kn_fatal_error_wrapper(
    user_data: *mut c_void,
    message: *const c_char,
) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbackHolder);
    (holder.kn_fatal_error)(cast_string(message));
}

pub trait TRInsertFn: Fn(Event) {}
impl<F: Fn(Event)> TRInsertFn for F {}

pub trait TRFlushFn: Fn() {}
impl<F: Fn()> TRFlushFn for F {}

pub trait TRSizeFn: Fn() -> usize {}
impl<F: Fn() -> usize> TRSizeFn for F {}

pub struct TaskRunnerCallbackHolder {
    pub tr_insert: Box<dyn TRInsertFn>,
    pub tr_flush: Box<dyn TRFlushFn>,
    pub tr_size: Box<dyn TRSizeFn>,
}

unsafe extern "C" fn tr_insert_wrapper(user_data: *mut c_void, event: *mut C_ValidationEvent) {
    let holder = &*(user_data as *mut TaskRunnerCallbackHolder);
    (holder.tr_insert)(Event {
        inner: AtomicPtr::new(event),
    });
}

unsafe extern "C" fn tr_flush_wrapper(user_data: *mut c_void) {
    let holder = &*(user_data as *mut TaskRunnerCallbackHolder);
    (holder.tr_flush)();
}

unsafe extern "C" fn tr_size_wrapper(user_data: *mut c_void) -> usize {
    let holder = &*(user_data as *mut TaskRunnerCallbackHolder);
    let res = (holder.tr_size)();
    res
}

pub struct Context {
    inner: *mut C_Context,
    pub tr_callbacks: Box<TaskRunnerCallbackHolder>,
    pub kn_callbacks: Box<KernelNotificationInterfaceCallbackHolder>,
}

pub struct ContextBuilder {
    inner: *mut C_ContextOptions,
    pub tr_callbacks: Option<Box<TaskRunnerCallbackHolder>>,
    pub kn_callbacks: Option<Box<KernelNotificationInterfaceCallbackHolder>>,
}

pub fn make_kernel_error() -> kernel_error {
    kernel_error {
        code: kernel_error_code_kernel_ERR_OK,
        message: std::ptr::null_mut(),
    }
}

impl ContextBuilder {
    pub fn new() -> ContextBuilder {
        ContextBuilder {
            inner: unsafe { c_context_opt_create() },
            tr_callbacks: None,
            kn_callbacks: None,
        }
    }

    pub fn build(self) -> Result<Context, KernelError> {
        let mut err = make_kernel_error();
        let mut inner = std::ptr::null_mut();
        unsafe { c_context_create(self.inner, &mut inner, &mut err) };
        handle_kernel_error(err)?;
        if self.tr_callbacks.is_none() {
            return Err(KernelError::MissingCallbacks("Missing TaskRunner callbacks.".to_string()));
        }
        if self.kn_callbacks.is_none() {
            return Err(KernelError::MissingCallbacks("Missing KernelNotificationInterface callbacks.".to_string()));
        }
        Ok(Context {
            inner,
            tr_callbacks: self.tr_callbacks.unwrap(),
            kn_callbacks: self.kn_callbacks.unwrap(),
        })
    }

    pub fn tr_callbacks(mut self, tr_callbacks: Box<TaskRunnerCallbackHolder>) -> Result<ContextBuilder, KernelError> {
        let tr_pointer= Box::into_raw(tr_callbacks);
        let mut err = make_kernel_error();

        unsafe { c_context_set_opt(
            self.inner,
            C_ContextOptionType_TaskRunnerCallbacksOption,
            Box::into_raw(Box::new(TaskRunnerCallbacks {
                user_data: tr_pointer as *mut c_void,
                insert: Some(tr_insert_wrapper),
                flush: Some(tr_flush_wrapper),
                size: Some(tr_size_wrapper),
            })) as *mut c_void,
            &mut err,
        )};
        handle_kernel_error(err)?;
        self.tr_callbacks = unsafe { Some(Box::from_raw(tr_pointer)) };
        Ok(self)
    }

    pub fn kn_callbacks(mut self, kn_callbacks: Box<KernelNotificationInterfaceCallbackHolder>) -> Result<ContextBuilder, KernelError> {
        let kn_pointer = Box::into_raw(kn_callbacks);
        let mut err = make_kernel_error();
        unsafe { c_context_set_opt(
            self.inner,
            C_ContextOptionType_KernelNotificationInterfaceCallbacksOption,
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
        )};
        handle_kernel_error(err)?;
        self.kn_callbacks = unsafe { Some(Box::from_raw(kn_pointer))};
        Ok(self)
    }

    pub fn chain_type(self, chain_type: ChainType) -> Result<ContextBuilder, KernelError> {
        let mut err = make_kernel_error();
        unsafe { c_context_set_opt(
            self.inner,
            C_ContextOptionType_ChainTypeOption,
            Box::into_raw(Box::new(C_Chain::from(chain_type))) as *mut c_void,
            &mut err,
        )};
        handle_kernel_error(err)?;
        Ok(self)
    }
}

#[derive(Debug)]
pub enum KernelError {
    InvalidPointer(String),
    LoggingFailed(String),
    UnknownOption(String),
    InvalidContext(String),
    SignatureCacheInit(String),
    ScriptExecutionCacheInit(String),
    MissingCallbacks(String),
    Internal(String),
    CStringCreationFailed(String),
}

impl From<NulError> for KernelError {
    fn from(err: NulError) -> Self {
        KernelError::CStringCreationFailed(err.to_string())
    }
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KernelError::InvalidPointer(msg) => write!(f, "{}", msg),
            KernelError::LoggingFailed(msg) => write!(f, "{}", msg),
            KernelError::UnknownOption(msg) => write!(f, "{}", msg),
            KernelError::InvalidContext(msg) => write!(f, "{}", msg),
            KernelError::SignatureCacheInit(msg) => write!(f, "{}", msg),
            KernelError::ScriptExecutionCacheInit(msg) => write!(f, "{}", msg),
            KernelError::MissingCallbacks(msg) => write!(f, "{}", msg),
            KernelError::Internal(msg) => write!(f, "{}", msg),
            KernelError::CStringCreationFailed(msg) => write!(f, "{}", msg),
        }
    }
}

fn handle_kernel_error(error: kernel_error) -> Result<(), KernelError> {
    unsafe {
    match error.code {
        kernel_error_code_kernel_ERR_INVALID_POINTER => Err(KernelError::InvalidPointer(CStr::from_ptr(error.message).to_string_lossy().into_owned())),
        kernel_error_code_kernel_ERR_LOGGING_FAILED => Err(KernelError::LoggingFailed(CStr::from_ptr(error.message).to_string_lossy().into_owned())),
        kernel_error_code_kernel_ERR_UNKNOWN_OPTION => Err(KernelError::UnknownOption(CStr::from_ptr(error.message).to_string_lossy().into_owned())),
        kernel_error_code_kernel_ERR_INVALID_CONTEXT => Err(KernelError::InvalidContext(CStr::from_ptr(error.message).to_string_lossy().into_owned())),
        kernel_error_code_kernel_ERR_SIGNATURE_CACHE_INIT => Err(KernelError::SignatureCacheInit(CStr::from_ptr(error.message).to_string_lossy().into_owned())),
        kernel_error_code_kernel_ERR_SCRIPT_EXECUTION_CACHE_INIT => Err(KernelError::ScriptExecutionCacheInit(CStr::from_ptr(error.message).to_string_lossy().into_owned())),
        kernel_error_code_kernel_ERR_INTERNAL => Err(KernelError::Internal(CStr::from_ptr(error.message).to_string_lossy().into_owned())),
        _ => Ok(())
    }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        let mut err = make_kernel_error();
        unsafe { c_context_destroy(self.inner, &mut err); }
        handle_kernel_error(err).unwrap();
        println!("dropped context.");
    }
}

pub trait VIBlockCheckedFn: Fn() {}
impl<F: Fn()> VIBlockCheckedFn for F {}

pub struct ValidationInterfaceCallbackHolder {
    pub block_checked: Box<dyn VIBlockCheckedFn>,
}

unsafe extern "C" fn vi_block_checked_wrapper(
    user_data: *mut c_void,
    _block: *const C_BlockPointer,
    _stateIn: C_BlockValidationState,
) {
    let holder = &*(user_data as *mut ValidationInterfaceCallbackHolder);
    (holder.block_checked)();
}

pub struct ValidationInterfaceWrapper {
    inner: *mut C_ValidationInterface,
    pub vi_callbacks: Box<ValidationInterfaceCallbackHolder>,
}

impl ValidationInterfaceWrapper {
    pub fn new(vi_callbacks: Box<ValidationInterfaceCallbackHolder>) -> ValidationInterfaceWrapper {
        let vi_pointer = Box::into_raw(vi_callbacks);
        let mut inner = std::ptr::null_mut();
        unsafe {
            c_validation_interface_create(ValidationInterfaceCallbacks {
                user_data: vi_pointer as *mut c_void,
                block_checked: Some(vi_block_checked_wrapper),
            }, &mut inner)
        };

        let vi_callbacks = unsafe { Box::from_raw(vi_pointer) };
        Self {
            inner,
            vi_callbacks,
        }
    }
}

pub fn register_validation_interface(vi: &ValidationInterfaceWrapper, context: &Context) -> Result<(), KernelError> {
    let mut err = make_kernel_error();
    unsafe { c_validation_interface_register(context.inner, vi.inner, &mut err); }
    handle_kernel_error(err)?;
    Ok(())
}

pub fn unregister_validation_interface(vi: &ValidationInterfaceWrapper, context: &Context) -> Result<(), KernelError> {
    let mut err = make_kernel_error();
    unsafe { c_validation_interface_unregister(context.inner, vi.inner, &mut err); }
    handle_kernel_error(err)?;
    Ok(())
} 

impl Drop for ValidationInterfaceWrapper {
    fn drop(&mut self) {
        let mut err = make_kernel_error();
        unsafe { c_validation_interface_destroy(self.inner, &mut err); }
        handle_kernel_error(err).unwrap();
        println!("dropped validation interface wrapper.");
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
    pub inner: AtomicPtr<C_ValidationEvent>,
}

pub fn execute_event(event: Event) {
    unsafe { c_execute_event(event.inner.load(Ordering::SeqCst)) };
}

pub struct ChainstateManager<'a> {
    inner: *mut C_ChainstateManager,
    context: &'a Context,
}

pub struct Block {
    inner: *mut C_Block,
}

impl TryFrom<&str> for Block {
    type Error = KernelError;

    fn try_from(block_str: &str) -> Result<Self, Self::Error> {
        let mut err = make_kernel_error();
        let string = CString::new(block_str).unwrap();
        let mut block = Block {
            inner: std::ptr::null_mut(),
        };
        unsafe {
        c_block_from_str(string.as_ptr().cast::<i8>(), &mut block.inner, &mut err);
        handle_kernel_error(err)?;
        Ok(block)
        }
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        unsafe { c_block_destroy(self.inner)};
        println!("dropped block.");
    }
}

pub struct CoinsCursor {
    inner: *mut C_CoinsViewCursor,
}

impl CoinsCursor {
    pub fn cursor_next(&self) {
        let mut err = make_kernel_error();
        unsafe { c_coins_cursor_next(self.inner, &mut err) };
        handle_kernel_error(err).unwrap();
    }

    pub fn get_key(&self) -> Result<OutPoint, KernelError> {
        let mut err = make_kernel_error();
        if self.inner.is_null() {
            return Err(KernelError::InvalidPointer("Invalid CoinsCursor inner pointer.".to_string()));
        }
        self.valid()?;
        let outpoint = unsafe { c_coins_cursor_get_key(self.inner, &mut err).into() };
        handle_kernel_error(err)?;
        Ok(outpoint)
    }

    pub fn get_value(&self) -> Result<Coin, KernelError> {
        let mut err = make_kernel_error();
        let coin = unsafe { c_coins_cursor_get_value(self.inner, &mut err).into() };
        handle_kernel_error(err)?;
        Ok(coin)
    }

    pub fn valid(&self) -> Result<bool, KernelError> {
        let mut err = make_kernel_error();
        let valid = unsafe { c_coins_cursor_valid(self.inner, &mut err) };
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
        let valid = self.valid();
        if valid.is_err() || !valid.unwrap() {
            None
        } else {
            Some((key, value))
        }
    }
}

impl Drop for CoinsCursor {
    fn drop(&mut self) {
        let mut err = make_kernel_error();
        unsafe { c_coins_cursor_destroy(self.inner, &mut err) };
        handle_kernel_error(err).unwrap();
        println!("dropped coins cursor.");
    }
}

pub struct BlockIndex {
    inner: *mut C_BlockIndex,
}

impl BlockIndex {
    pub fn block_height(&self) -> Result<i32, KernelError> {
        let mut err = make_kernel_error();
        let height = unsafe { c_get_block_height(self.inner, &mut err)};
        handle_kernel_error(err)?;
        Ok(height)
    }
}

pub struct CTransactionRef {
    inner: *const C_TransactionRef,
    pub n_ins: usize,
    pub n_outs: usize,
    is_owned: bool,
}

impl TryFrom<&str> for CTransactionRef {
    type Error = KernelError;

    fn try_from(tx_str: &str) -> Result<Self, Self::Error> {
        let mut err = make_kernel_error();
        let string = CString::new(tx_str).unwrap();
        let mut inner = std::ptr::null_mut();
        unsafe {
        c_transaction_ref_from_str(string.as_ptr().cast::<i8>(), &mut inner, &mut err);
        handle_kernel_error(err)?;
        let n_ins = c_get_transaction_input_size(inner, &mut err);
        handle_kernel_error(err)?;
        let n_outs = c_get_transaction_output_size(inner, &mut err);
        handle_kernel_error(err)?;
        Ok(CTransactionRef {
            inner,
            n_ins,
            n_outs,
            is_owned: true,
        })
        }
    }
}

impl Drop for CTransactionRef {
    fn drop(&mut self) {
        if self.is_owned {
            let mut err = make_kernel_error();
            unsafe { c_transaction_ref_destroy(self.inner, &mut err)}
        }
    }
}

impl CTransactionRef {
    pub fn is_coinbase(&self) -> Result<bool, KernelError> {
        let mut err = make_kernel_error();
        let is_coinbase = unsafe { c_transaction_ref_is_coinbase(self.inner, &mut err)};
        handle_kernel_error(err)?;
        Ok(is_coinbase)
    }

    pub fn get_output_script_pubkey_by_index(&self, index: u64) -> Result<Vec<u8>, KernelError> {
        let mut err = make_kernel_error();
        let output = unsafe { c_get_output_by_index(self.inner, &mut err, index)};
        handle_kernel_error(err)?;
        let mut script_pubkey: *mut ByteArray = std::ptr::null_mut();
        unsafe { c_get_script_pubkey(output, &mut script_pubkey, &mut err)};
        handle_kernel_error(err)?;
        let res = unsafe {std::slice::from_raw_parts(
            (*script_pubkey).data,
            (*script_pubkey).len.try_into().unwrap(),
        ).to_vec()};
        unsafe { c_byte_array_destroy(script_pubkey)};
        Ok(res)
    }

    pub fn get_input_script_sig_by_index(&self, index: u64) -> Result<Vec<u8>, KernelError> {
        let mut err = make_kernel_error();
        let input = unsafe { c_get_input_by_index(self.inner, &mut err, index)};
        handle_kernel_error(err)?;
        let mut script_sig: *mut ByteArray = std::ptr::null_mut();
        unsafe { c_get_script_sig(input, &mut script_sig, &mut err)};
        handle_kernel_error(err)?;
        let res = unsafe {std::slice::from_raw_parts(
            (*script_sig).data,
            (*script_sig).len.try_into().unwrap(),
        ).to_vec()};
        unsafe { c_byte_array_destroy(script_sig)};
        Ok(res)
    }

    pub fn get_input_witness_by_index(&self, index: u64) -> Result<Vec<u8>, KernelError> {
        let mut err = make_kernel_error();
        let input= unsafe { c_get_input_by_index(self.inner, &mut err, index)};
        handle_kernel_error(err)?;
        let mut tx_in_witness: *mut C_TxInWitness = std::ptr::null_mut();
        unsafe {c_get_tx_in_witness(input, &mut tx_in_witness, &mut err)};
        handle_kernel_error(err)?;
        let mut witness: *mut ByteArray = std::ptr::null_mut();
        unsafe {c_get_witness(tx_in_witness, &mut witness, &mut err)};
        let res = unsafe {std::slice::from_raw_parts(
            (*witness).data,
            (*witness).len.try_into().unwrap(),
        ).to_vec()};
        unsafe { c_byte_array_destroy(witness)};
        unsafe { c_tx_in_witness_destroy(tx_in_witness, &mut err)};
        handle_kernel_error(err)?;
        Ok(res)
    }
}

pub struct CBlock {
    inner: *mut C_BlockPointer,
    pub n_txs: usize,
}

impl CBlock {
    pub fn get_transaction_by_index(&self, index: u64) -> Result<CTransactionRef, KernelError> {
        let mut err = make_kernel_error();
        let transaction_ref = unsafe { c_get_transaction_by_index(self.inner, &mut err, index)};
        handle_kernel_error(err)?;
        let n_ins = unsafe { c_get_transaction_input_size(transaction_ref, &mut err)};
        handle_kernel_error(err)?;
        let n_outs = unsafe { c_get_transaction_output_size(transaction_ref, &mut err)};
        handle_kernel_error(err)?;
        Ok(CTransactionRef {
            inner: transaction_ref,
            n_ins,
            n_outs,
            is_owned: false,
        })
    }
}

pub struct CBlockUndo {
    inner: *mut C_BlockUndo,
    pub n_txundo: usize,
}

impl CBlockUndo {
    pub fn get_txundo_by_index(&self, index: u64) -> Result<CTxUndo, KernelError> {
        let mut err = make_kernel_error();
        let tx_undo = unsafe { c_get_tx_undo_by_index(self.inner, &mut err, index)};
        handle_kernel_error(err)?;
        let n_out = unsafe { c_number_of_coins_in_tx_undo(tx_undo, &mut err)};
        handle_kernel_error(err)?;
        Ok(CTxUndo {
            inner: tx_undo,
            n_out,
        })
    }
}

pub struct CTxUndo {
    inner: *mut C_TxUndo,
    pub n_out: usize,
}

impl CTxUndo {
    pub fn get_output_script_pubkey_by_index(&self, index: u64) -> Result<Vec<u8>, KernelError> {
        let mut err = make_kernel_error();
        let coin = unsafe { c_get_coin_by_index(self.inner, &mut err, index)};
        handle_kernel_error(err)?;
        let prev_out = unsafe { c_get_prevout(coin, &mut err)};
        handle_kernel_error(err)?;
        let mut script_pubkey: *mut ByteArray = std::ptr::null_mut();
        unsafe { c_get_script_pubkey(prev_out, &mut script_pubkey, &mut err)};
        handle_kernel_error(err)?;
        let res = unsafe { std::slice::from_raw_parts(
            (*script_pubkey).data,
            (*script_pubkey).len.try_into().unwrap(),
        )}.to_vec();
        unsafe {c_byte_array_destroy(script_pubkey)};
        Ok(res)
    }
}

impl<'a> ChainstateManager<'a> {
    pub fn new(data_dir: &str, reindex: bool, context: &'a Context) -> Result<Self, KernelError> {
        let c_data_dir = CString::new(data_dir)?;
        let mut err = make_kernel_error();
        let mut inner: *mut C_ChainstateManager = std::ptr::null_mut();
        unsafe { c_chainstate_manager_create(c_data_dir.as_ptr().cast::<i8>(), reindex, context.inner, &mut inner, &mut err) };
        handle_kernel_error(err)?;
        Ok(Self { inner, context })
    }

    pub fn validate_block(
        &self,
        block: &Block,
    ) -> Result<(), KernelError> {
        let mut err = make_kernel_error();
        unsafe {
            c_chainstate_manager_validate_block(
                self.inner,
                block.inner,
                &mut err,
            );
        };
        handle_kernel_error(err)?;
        Ok(())
    }

    pub fn validate_transaction(
        &self,
        transaction: &CTransactionRef,
        test_accept: bool,
    ) -> Result<(), KernelError> {
        let mut err = make_kernel_error();
        let mut result: *mut C_MempoolAcceptResult = std::ptr::null_mut();
        unsafe { c_process_transaction(self.inner, transaction.inner, test_accept, &mut result, &mut err)};
        handle_kernel_error(err)?;
        Ok(())
    }

    pub fn import_blocks(&self) -> Result<(), KernelError> {
        let mut err = make_kernel_error();
        unsafe { c_import_blocks(self.inner, &mut err)}
        handle_kernel_error(err)?;
        Ok(())
    }

    pub fn chainstate_coins_cursor(&self) -> Result<CoinsCursor, KernelError> {
        let mut err = make_kernel_error();
        let mut coins_cursor = CoinsCursor {
            inner: std::ptr::null_mut(),
        };
        unsafe { c_chainstate_coins_cursor_create(self.inner, &mut coins_cursor.inner, &mut err)};
        handle_kernel_error(err)?;
        Ok(coins_cursor)
    }

    pub fn get_genesis_block_index(&self) -> Result<BlockIndex, KernelError> {
        let mut err = make_kernel_error();
        let block_index = unsafe { BlockIndex {
                inner: c_get_genesis_block_index(self.inner, &mut err),
            }
        };
        handle_kernel_error(err)?;
        Ok(block_index)
    }

    pub fn get_next_block_index(&self, mut block_index: BlockIndex) -> Result<BlockIndex, KernelError> {
        let mut err = make_kernel_error();
        block_index.inner = unsafe {c_get_next_block_index(self.inner, &mut err, block_index.inner)};
        handle_kernel_error(err)?;
        if block_index.inner == std::ptr::null_mut() {
            return Err(KernelError::InvalidPointer("Block index is null, indicating we are at the end of the chain".to_string()));
        }
        Ok(block_index)
    }

    pub fn flush(&self) -> Result<(), KernelError> {
        let mut err = make_kernel_error();
        unsafe {c_chainstate_manager_flush(self.inner, &mut err)};
        handle_kernel_error(err)?;
        Ok(())
    }

    pub fn read_block_data(&self, block_index: &BlockIndex) -> Result<(CBlock, CBlockUndo), KernelError> {
        let mut err = make_kernel_error();
        let mut block_data = CBlock {
            inner: std::ptr::null_mut(),
            n_txs: 0,
        };
        let mut undo_data = CBlockUndo {
            inner: std::ptr::null_mut(),
            n_txundo: 0,
        };
        unsafe { c_read_block_data(self.inner, block_index.inner, &mut err, &mut block_data.inner, true, &mut undo_data.inner, true)};
        handle_kernel_error(err)?;
        unsafe {block_data.n_txs = c_number_of_transactions_in_block(block_data.inner, &mut err)};
        handle_kernel_error(err)?;
        unsafe {undo_data.n_txundo = c_number_of_txundo_in_block_undo(undo_data.inner, &mut err)};
        handle_kernel_error(err)?;
        Ok((block_data, undo_data))
    }
}

impl<'a> Drop for ChainstateManager<'a> {
    fn drop(&mut self) {
        let mut err = make_kernel_error();
        unsafe {
            c_chainstate_manager_destroy(self.inner, self.context.inner, &mut err);
        }
        handle_kernel_error(err).unwrap();
        println!("dropped chainman.");
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

    let mut err = make_kernel_error();
    unsafe { c_set_logging_callback_and_start_logging(Some(log_callback), &mut err) };
    handle_kernel_error(err)?;
    Ok(())
}
