#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi::{CStr, CString, NulError};
use std::fmt;
use std::marker::PhantomData;
use std::os::raw::{c_char, c_void};
use std::sync::atomic::{AtomicPtr, Ordering};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub const VERIFY_NONE: u32 = kernel_ScriptFlags_kernel_SCRIPT_FLAGS_VERIFY_NONE;
pub const VERIFY_P2SH: u32 = kernel_ScriptFlags_kernel_SCRIPT_FLAGS_VERIFY_P2SH;
pub const VERIFY_DERSIG: u32 = kernel_ScriptFlags_kernel_SCRIPT_FLAGS_VERIFY_DERSIG;
pub const VERIFY_NULLDUMMY: u32 = kernel_ScriptFlags_kernel_SCRIPT_FLAGS_VERIFY_NULLDUMMY;
pub const VERIFY_CHECKLOCKTIMEVERIFY: u32 =
    kernel_ScriptFlags_kernel_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY;
pub const VERIFY_CHECKSEQUENCEVERIFY: u32 =
    kernel_ScriptFlags_kernel_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY;
pub const VERIFY_WITNESS: u32 = kernel_ScriptFlags_kernel_SCRIPT_FLAGS_VERIFY_WITNESS;
pub const VERIFY_TAPROOT: u32 = kernel_ScriptFlags_kernel_SCRIPT_FLAGS_VERIFY_TAPROOT;

pub const VERIFY_ALL_PRE_TAPROOT: u32 = VERIFY_P2SH
    | VERIFY_DERSIG
    | VERIFY_NULLDUMMY
    | VERIFY_CHECKLOCKTIMEVERIFY
    | VERIFY_CHECKSEQUENCEVERIFY
    | VERIFY_WITNESS;

pub struct Utxo<'a> {
    pub value: i64,
    pub script_pubkey: &'a [u8],
}

pub fn verify(
    script_pubkey: &[u8],
    amount: Option<i64>,
    tx_to: &[u8],
    input_index: u32,
    flags: Option<u32>,
    spent_outputs: &[Utxo],
) -> Result<(), KernelError> {
    let kernel_flags = if let Some(flag) = flags {
        flag
    } else {
        kernel_ScriptFlags_kernel_SCRIPT_FLAGS_VERIFY_ALL
    };
    let mut status = kernel_ScriptVerifyStatus_kernel_SCRIPT_VERIFY_OK;
    let kernel_amount = if let Some(a) = amount { a } else { 0 };
    let kernel_spent_outputs: Vec<kernel_TransactionOutput> = spent_outputs
        .iter()
        .map(|utxo| kernel_TransactionOutput {
            value: utxo.value,
            script_pubkey: utxo.script_pubkey.as_ptr(),
            script_pubkey_len: utxo.script_pubkey.len(),
        })
        .collect();

    let spent_outputs_ptr = if kernel_spent_outputs.is_empty() {
        std::ptr::null()
    } else {
        kernel_spent_outputs.as_ptr()
    };

    let ret = unsafe {
        kernel_verify_script(
            script_pubkey.as_ptr(),
            script_pubkey.len(),
            kernel_amount,
            tx_to.as_ptr(),
            tx_to.len(),
            spent_outputs_ptr,
            spent_outputs.len(),
            input_index,
            kernel_flags,
            &mut status,
        )
    };

    if !ret {
        let err = match status {
            kernel_ScriptVerifyStatus_kernel_SCRIPT_VERIFY_ERROR_TX_INPUT_INDEX => {
                ScriptVerifyError::TxInputIndex
            }
            kernel_ScriptVerifyStatus_kernel_SCRIPT_VERIFY_ERROR_TX_SIZE_MISMATCH => {
                ScriptVerifyError::TxSizeMismatch
            }
            kernel_ScriptVerifyStatus_kernel_SCRIPT_VERIFY_ERROR_TX_DESERIALIZE => {
                ScriptVerifyError::TxDeserialize
            }
            kernel_ScriptVerifyStatus_kernel_SCRIPT_VERIFY_ERROR_INVALID_FLAGS => {
                ScriptVerifyError::InvalidFlags
            }
            kernel_ScriptVerifyStatus_kernel_SCRIPT_VERIFY_ERROR_INVALID_FLAGS_COMBINATION => {
                ScriptVerifyError::InvalidFlagsCombination
            }
            kernel_ScriptVerifyStatus_kernel_SCRIPT_VERIFY_ERROR_SPENT_OUTPUTS_REQUIRED => {
                ScriptVerifyError::SpentOutputsRequired
            }
            kernel_ScriptVerifyStatus_kernel_SCRIPT_VERIFY_ERROR_SPENT_OUTPUTS_MISMATCH => {
                ScriptVerifyError::SpentOutputsMismatch
            }
            _ => ScriptVerifyError::Invalid,
        };
        Err(KernelError::ScriptVerify(err))
    } else {
        Ok(())
    }
}

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

impl From<kernel_SynchronizationState> for SynchronizationState {
    fn from(state: kernel_SynchronizationState) -> SynchronizationState {
        match state {
            kernel_SynchronizationState_kernel_INIT_DOWNLOAD => SynchronizationState::INIT_DOWNLOAD,
            kernel_SynchronizationState_kernel_INIT_REINDEX => SynchronizationState::INIT_REINDEX,
            kernel_SynchronizationState_kernel_POST_INIT => SynchronizationState::POST_INIT,
            _ => panic!("Unexpected Synchronization state"),
        }
    }
}

pub enum KernelWarning {
    UNKNOWN_NEW_RULES_ACTIVATED,
    LARGE_WORK_INVALID_CHAIN,
}

impl From<kernel_Warning> for KernelWarning {
    fn from(warning: kernel_Warning) -> KernelWarning {
        match warning {
            kernel_Warning_kernel_UNKNOWN_NEW_RULES_ACTIVATED => {
                KernelWarning::UNKNOWN_NEW_RULES_ACTIVATED
            }
            kernel_Warning_kernel_LARGE_WORK_INVALID_CHAIN => {
                KernelWarning::LARGE_WORK_INVALID_CHAIN
            }
            _ => panic!("Unexpected kernel warning"),
        }
    }
}

pub enum ChainType {
    MAINNET,
    TESTNET,
    SIGNET,
    REGTEST,
}

impl From<ChainType> for kernel_ChainType {
    fn from(chain: ChainType) -> kernel_ChainType {
        match chain {
            ChainType::MAINNET => kernel_ChainType_kernel_CHAIN_TYPE_MAINNET,
            ChainType::TESTNET => kernel_ChainType_kernel_CHAIN_TYPE_TESTNET,
            ChainType::SIGNET => kernel_ChainType_kernel_CHAIN_TYPE_SIGNET,
            ChainType::REGTEST => kernel_ChainType_kernel_CHAIN_TYPE_REGTEST,
        }
    }
}

pub trait KNBlockTipFn: Fn(SynchronizationState, *mut kernel_BlockIndex) {}
impl<F: Fn(SynchronizationState, *mut kernel_BlockIndex)> KNBlockTipFn for F {}

pub trait KNHeaderTipFn: Fn(SynchronizationState, i64, i64, bool) {}
impl<F: Fn(SynchronizationState, i64, i64, bool)> KNHeaderTipFn for F {}

pub trait KNProgressFn: Fn(String, i32, bool) {}
impl<F: Fn(String, i32, bool)> KNProgressFn for F {}

pub trait KNWarningSetFn: Fn(KernelWarning, String) {}
impl<F: Fn(KernelWarning, String)> KNWarningSetFn for F {}

pub trait KNWarningUnsetFn: Fn(KernelWarning) {}
impl<F: Fn(KernelWarning)> KNWarningUnsetFn for F {}

pub trait KNFlushErrorFn: Fn(String) {}
impl<F: Fn(String)> KNFlushErrorFn for F {}

pub trait KNFatalErrorFn: Fn(String) {}
impl<F: Fn(String)> KNFatalErrorFn for F {}

pub struct KernelNotificationInterfaceCallbackHolder {
    pub kn_block_tip: Box<dyn KNBlockTipFn>,
    pub kn_header_tip: Box<dyn KNHeaderTipFn>,
    pub kn_progress: Box<dyn KNProgressFn>,
    pub kn_warning_set: Box<dyn KNWarningSetFn>,
    pub kn_warning_unset: Box<dyn KNWarningUnsetFn>,
    pub kn_flush_error: Box<dyn KNFlushErrorFn>,
    pub kn_fatal_error: Box<dyn KNFatalErrorFn>,
}

unsafe extern "C" fn kn_block_tip_wrapper(
    user_data: *mut c_void,
    state: kernel_SynchronizationState,
    block_index: *mut kernel_BlockIndex,
) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbackHolder);
    (holder.kn_block_tip)(state.into(), block_index);
}

unsafe extern "C" fn kn_header_tip_wrapper(
    user_data: *mut c_void,
    state: kernel_SynchronizationState,
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

unsafe extern "C" fn kn_warning_set_wrapper(
    user_data: *mut c_void,
    warning: kernel_Warning,
    message: *const c_char,
) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbackHolder);
    (holder.kn_warning_set)(warning.into(), cast_string(message));
}

unsafe extern "C" fn kn_warning_unset_wrapper(user_data: *mut c_void, warning: kernel_Warning) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbackHolder);
    (holder.kn_warning_unset)(warning.into());
}

unsafe extern "C" fn kn_flush_error_wrapper(user_data: *mut c_void, message: *const c_char) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbackHolder);
    (holder.kn_flush_error)(cast_string(message));
}

unsafe extern "C" fn kn_fatal_error_wrapper(user_data: *mut c_void, message: *const c_char) {
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

unsafe extern "C" fn tr_insert_wrapper(user_data: *mut c_void, event: *mut kernel_ValidationEvent) {
    let holder = &*(user_data as *mut TaskRunnerCallbackHolder);
    (holder.tr_insert)(Event {
        inner: AtomicPtr::new(event),
    });
}

unsafe extern "C" fn tr_flush_wrapper(user_data: *mut c_void) {
    let holder = &*(user_data as *mut TaskRunnerCallbackHolder);
    (holder.tr_flush)();
}

unsafe extern "C" fn tr_size_wrapper(user_data: *mut c_void) -> u32 {
    let holder = &*(user_data as *mut TaskRunnerCallbackHolder);
    let res = (holder.tr_size)();
    res.try_into().unwrap()
}

pub struct ChainParams {
    inner: *const kernel_ChainParameters,
}

unsafe impl Send for ChainParams {}
unsafe impl Sync for ChainParams {}

impl ChainParams {
    pub fn new(chain_type: ChainType) -> ChainParams {
        let kernel_chain_type = chain_type.into();
        ChainParams {
            inner: unsafe { kernel_chain_parameters_create(kernel_chain_type) },
        }
    }
}

impl Drop for ChainParams {
    fn drop(&mut self) {
        unsafe {
            kernel_chain_parameters_destroy(self.inner);
        }
    }
}

pub struct Context {
    inner: *mut kernel_Context,
    pub tr_callbacks: Option<Box<TaskRunnerCallbackHolder>>,
    pub kn_callbacks: Box<KernelNotificationInterfaceCallbackHolder>,
}

unsafe impl Send for Context {}
unsafe impl Sync for Context {}

impl Context {
    pub fn interrupt(&self) -> bool {
        unsafe { kernel_context_interrupt(self.inner) }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            kernel_context_destroy(self.inner);
        }
    }
}

pub struct ContextBuilder {
    inner: *mut kernel_ContextOptions,
    pub tr_callbacks: Option<Box<TaskRunnerCallbackHolder>>,
    pub kn_callbacks: Option<Box<KernelNotificationInterfaceCallbackHolder>>,
}

impl ContextBuilder {
    pub fn new() -> ContextBuilder {
        let context = ContextBuilder {
            inner: unsafe { kernel_context_options_create() },
            tr_callbacks: None,
            kn_callbacks: None,
        };
        context
    }

    pub fn build(self) -> Result<Context, KernelError> {
        let inner = unsafe { kernel_context_create(self.inner) };
        if inner.is_null() {
            return Err(KernelError::Internal("Invalid context.".to_string()));
        }
        if self.kn_callbacks.is_none() {
            return Err(KernelError::MissingCallbacks(
                "Missing KernelNotificationInterface callbacks.".to_string(),
            ));
        }
        unsafe { kernel_context_options_destroy(self.inner) };
        Ok(Context {
            inner,
            tr_callbacks: self.tr_callbacks,
            kn_callbacks: self.kn_callbacks.unwrap(),
        })
    }

    pub fn tr_callbacks(
        mut self,
        tr_callbacks: Box<TaskRunnerCallbackHolder>,
    ) -> Result<ContextBuilder, KernelError> {
        let tr_pointer = Box::into_raw(tr_callbacks);

        unsafe {
            let holder = kernel_TaskRunnerCallbacks {
                user_data: tr_pointer as *mut c_void,
                insert: Some(tr_insert_wrapper),
                flush: Some(tr_flush_wrapper),
                size: Some(tr_size_wrapper),
            };
            let kernel_task_runner = kernel_task_runner_create(holder);
            let success = kernel_context_options_set(
                self.inner,
                kernel_ContextOptionType_kernel_TASK_RUNNER_OPTION,
                kernel_task_runner as *mut c_void,
            );
            kernel_task_runner_destroy(kernel_task_runner);
            if !success {
                return Err(KernelError::InvalidOptions(
                    "Failed to set task runner context option.".to_string(),
                ));
            }
        };
        self.tr_callbacks = unsafe { Some(Box::from_raw(tr_pointer)) };
        Ok(self)
    }

    pub fn kn_callbacks(
        mut self,
        kn_callbacks: Box<KernelNotificationInterfaceCallbackHolder>,
    ) -> Result<ContextBuilder, KernelError> {
        let kn_pointer = Box::into_raw(kn_callbacks);
        unsafe {
            let holder = kernel_NotificationInterfaceCallbacks {
                user_data: kn_pointer as *mut c_void,
                block_tip: Some(kn_block_tip_wrapper),
                header_tip: Some(kn_header_tip_wrapper),
                progress: Some(kn_progress_wrapper),
                warning_set: Some(kn_warning_set_wrapper),
                warning_unset: Some(kn_warning_unset_wrapper),
                flush_error: Some(kn_flush_error_wrapper),
                fatal_error: Some(kn_fatal_error_wrapper),
            };
            let kernel_notifications = kernel_notifications_create(holder);
            let success = kernel_context_options_set(
                self.inner,
                kernel_ContextOptionType_kernel_NOTIFICATIONS_OPTION,
                kernel_notifications as *mut c_void,
            );
            kernel_notifications_destroy(kernel_notifications);
            if !success {
                return Err(KernelError::InvalidOptions(
                    "Failed to set notifications context option.".to_string(),
                ));
            }
        };
        self.kn_callbacks = unsafe { Some(Box::from_raw(kn_pointer)) };
        Ok(self)
    }

    pub fn chain_type(self, chain_type: ChainType) -> Result<ContextBuilder, KernelError> {
        let chain_params = ChainParams::new(chain_type);
        unsafe {
            if !kernel_context_options_set(
                self.inner,
                kernel_ContextOptionType_kernel_CHAIN_PARAMETERS_OPTION,
                chain_params.inner as *mut c_void,
            ) {
                return Err(KernelError::InvalidOptions(
                    "Failed to set chainparams context option.".to_string(),
                ));
            }
        };
        Ok(self)
    }
}

#[derive(Debug)]
pub enum KernelError {
    Internal(String),
    MissingCallbacks(String),
    CStringCreationFailed(String),
    InvalidOptions(String),
    OutOfBounds,
    ScriptVerify(ScriptVerifyError),
    ProcessBlock(ProcessBlockError),
}

#[derive(Debug)]
pub enum ScriptVerifyError {
    TxInputIndex,
    TxSizeMismatch,
    TxDeserialize,
    InvalidFlags,
    InvalidFlagsCombination,
    SpentOutputsMismatch,
    SpentOutputsRequired,
    Invalid,
}

#[derive(Debug)]
pub enum ProcessBlockError {
    NoCoinbase,
    Duplicate,
    InvalidDuplicate,
    Invalid,
}

impl From<NulError> for KernelError {
    fn from(err: NulError) -> Self {
        KernelError::CStringCreationFailed(err.to_string())
    }
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KernelError::Internal(msg)
            | KernelError::MissingCallbacks(msg)
            | KernelError::CStringCreationFailed(msg)
            | KernelError::InvalidOptions(msg) => write!(f, "{}", msg),
            _ => write!(f, "Error!"),
        }
    }
}

pub trait VIBlockCheckedFn: Fn() {}
impl<F: Fn()> VIBlockCheckedFn for F {}

pub struct ValidationInterfaceCallbackHolder {
    pub block_checked: Box<dyn VIBlockCheckedFn>,
}

unsafe extern "C" fn vi_block_checked_wrapper(
    user_data: *mut c_void,
    _block: *const kernel_BlockPointer,
    _stateIn: *const kernel_BlockValidationState,
) {
    let holder = &*(user_data as *mut ValidationInterfaceCallbackHolder);
    (holder.block_checked)();
}

pub struct ValidationInterfaceWrapper {
    inner: *mut kernel_ValidationInterface,
    pub vi_callbacks: Box<ValidationInterfaceCallbackHolder>,
}

impl ValidationInterfaceWrapper {
    pub fn new(vi_callbacks: Box<ValidationInterfaceCallbackHolder>) -> ValidationInterfaceWrapper {
        let vi_pointer = Box::into_raw(vi_callbacks);
        let inner = unsafe {
            kernel_validation_interface_create(kernel_ValidationInterfaceCallbacks {
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

pub fn register_validation_interface(
    vi: &ValidationInterfaceWrapper,
    context: &Context,
) -> Result<(), KernelError> {
    unsafe {
        if !kernel_validation_interface_register(context.inner, vi.inner) {
            return Err(KernelError::Internal(
                "Failed to register validation interface.".to_string(),
            ));
        }
    }
    Ok(())
}

pub fn unregister_validation_interface(
    vi: &ValidationInterfaceWrapper,
    context: &Context,
) -> Result<(), KernelError> {
    unsafe {
        if !kernel_validation_interface_unregister(context.inner, vi.inner) {
            return Err(KernelError::Internal(
                "Failed to unregister validation interface.".to_string(),
            ));
        }
    }
    Ok(())
}

impl Drop for ValidationInterfaceWrapper {
    fn drop(&mut self) {
        unsafe {
            kernel_validation_interface_destroy(self.inner);
        }
    }
}

#[derive(Debug, Clone)]
pub struct TxOut {
    pub value: i64,
    pub script_pubkey: Vec<u8>,
}

impl From<kernel_TransactionOutput> for TxOut {
    fn from(c: kernel_TransactionOutput) -> TxOut {
        TxOut {
            value: c.value,
            script_pubkey: unsafe {
                std::slice::from_raw_parts(c.script_pubkey, c.script_pubkey_len.try_into().unwrap())
            }
            .to_vec(),
        }
    }
}

pub struct Event {
    pub inner: AtomicPtr<kernel_ValidationEvent>,
}

pub fn execute_event(event: Event) -> Result<(), KernelError> {
    unsafe { kernel_execute_event_and_destroy(event.inner.load(Ordering::SeqCst)) };
    Ok(())
}

pub struct Block {
    inner: *mut kernel_Block,
}

unsafe impl Send for Block {}
unsafe impl Sync for Block {}

impl Into<Vec<u8>> for Block {
    fn into(self) -> Vec<u8> {
        let raw_block = unsafe { kernel_copy_block_data(self.inner) };
        let vec = unsafe {
            std::slice::from_raw_parts((*raw_block).data, (*raw_block).size.try_into().unwrap())
        }
        .to_vec();
        unsafe { kernel_byte_array_destroy(raw_block) };
        vec
    }
}

impl TryFrom<&[u8]> for Block {
    type Error = KernelError;

    fn try_from(raw_block: &[u8]) -> Result<Self, Self::Error> {
        let inner = unsafe { kernel_block_create(raw_block.as_ptr(), raw_block.len()) };
        if inner.is_null() {
            return Err(KernelError::Internal(
                "Failed to de-serialize Block.".to_string(),
            ));
        }
        Ok(Block { inner })
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        unsafe { kernel_block_destroy(self.inner) };
    }
}

pub struct BlockIndex<'a> {
    inner: *mut kernel_BlockIndex,
    marker: PhantomData<ChainstateManager<'a>>,
}

unsafe impl Send for BlockIndex<'_> {}
unsafe impl Sync for BlockIndex<'_> {}

#[derive(Debug, Clone)]
pub struct BlockIndexInfo {
    pub height: i32,
}

impl<'a> BlockIndex<'a> {
    pub fn prev(self) -> Result<BlockIndex<'a>, KernelError> {
        let inner = unsafe { kernel_get_previous_block_index(self.inner) };
        if inner.is_null() {
            return Err(KernelError::OutOfBounds);
        }
        unsafe { kernel_block_index_destroy(self.inner) };
        Ok(BlockIndex {
            inner,
            marker: self.marker,
        })
    }

    pub fn info(&self) -> BlockIndexInfo {
        let info = unsafe { kernel_get_block_index_info(self.inner) };
        let res = BlockIndexInfo {
            height: unsafe { (*info).height },
        };
        unsafe { kernel_block_index_info_destroy(info) };
        return res;
    }
}

impl<'a> Drop for BlockIndex<'a> {
    fn drop(&mut self) {
        unsafe { kernel_block_index_destroy(self.inner) };
    }
}

pub struct BlockUndo {
    inner: *mut kernel_BlockUndo,
    pub n_tx_undo: usize,
}
unsafe impl Send for BlockUndo {}
unsafe impl Sync for BlockUndo {}

impl BlockUndo {
    pub fn get_get_transaction_undo_size(&self, transaction_index: u64) -> u64 {
        unsafe { kernel_get_transaction_undo_size(self.inner, transaction_index) }
    }

    pub fn get_prevout_by_index(
        &self,
        transaction_index: u64,
        prevout_index: u64,
    ) -> Result<TxOut, KernelError> {
        let prev_out = unsafe {
            kernel_get_undo_output_by_index(self.inner, transaction_index, prevout_index)
        };
        if prev_out.is_null() {
            return Err(KernelError::OutOfBounds);
        }
        let res = TxOut {
            value: unsafe { (*prev_out).value },
            script_pubkey: unsafe {
                std::slice::from_raw_parts(
                    (*prev_out).script_pubkey,
                    (*prev_out).script_pubkey_len.try_into().unwrap(),
                )
                .to_vec()
            },
        };
        unsafe { kernel_transaction_output_destroy(prev_out) };
        Ok(res)
    }
}

impl Drop for BlockUndo {
    fn drop(&mut self) {
        unsafe { kernel_block_undo_destroy(self.inner) };
    }
}

pub struct ChainstateManagerOptions {
    inner: *mut kernel_ChainstateManagerOptions,
}

impl ChainstateManagerOptions {
    pub fn new(context: &Context, data_dir: &str) -> Result<Self, KernelError> {
        let c_data_dir = CString::new(data_dir)?;
        let inner = unsafe {
            kernel_chainstate_manager_options_create(
                context.inner,
                c_data_dir.as_ptr().cast::<i8>(),
            )
        };
        if inner.is_null() {
            return Err(KernelError::Internal(
                "Failed to create chainstate manager options.".to_string(),
            ));
        }
        Ok(Self { inner })
    }
}

impl Drop for ChainstateManagerOptions {
    fn drop(&mut self) {
        unsafe {
            kernel_chainstate_manager_options_destroy(self.inner);
        }
    }
}

pub struct BlockManagerOptions {
    inner: *mut kernel_BlockManagerOptions,
}

impl BlockManagerOptions {
    pub fn new(context: &Context, blocks_dir: &str) -> Result<Self, KernelError> {
        let c_blocks_dir = CString::new(blocks_dir)?;
        let inner = unsafe {
            kernel_block_manager_options_create(context.inner, c_blocks_dir.as_ptr().cast::<i8>())
        };
        if inner.is_null() {
            return Err(KernelError::Internal(
                "Failed to create block manager options.".to_string(),
            ));
        }
        Ok(Self { inner })
    }
}

impl Drop for BlockManagerOptions {
    fn drop(&mut self) {
        unsafe {
            kernel_block_manager_options_destroy(self.inner);
        }
    }
}

pub struct ChainstateLoadOptions {
    inner: *mut kernel_ChainstateLoadOptions,
}

impl ChainstateLoadOptions {
    pub fn new() -> ChainstateLoadOptions {
        ChainstateLoadOptions {
            inner: unsafe { kernel_chainstate_load_options_create() },
        }
    }

    pub fn set_reindex(self, reindex: bool) -> Result<Self, KernelError> {
        unsafe {
            kernel_chainstate_load_options_set(
                self.inner,
                kernel_ChainstateLoadOptionType_kernel_WIPE_BLOCK_TREE_DB_CHAINSTATE_LOAD_OPTION,
                reindex,
            );
            kernel_chainstate_load_options_set(
                self.inner,
                kernel_ChainstateLoadOptionType_kernel_WIPE_CHAINSTATE_DB_CHAINSTATE_LOAD_OPTION,
                reindex,
            );
        }
        Ok(self)
    }

    pub fn set_wipe_chainstate_db(self, wipe_chainstate: bool) -> Result<Self, KernelError> {
        unsafe {
            kernel_chainstate_load_options_set(
                self.inner,
                kernel_ChainstateLoadOptionType_kernel_WIPE_CHAINSTATE_DB_CHAINSTATE_LOAD_OPTION,
                wipe_chainstate,
            );
        }
        Ok(self)
    }

    pub fn set_chainstate_db_in_memory(
        self,
        chainstate_db_in_memory: bool,
    ) -> Result<Self, KernelError> {
        unsafe {
            kernel_chainstate_load_options_set(
                self.inner,
                kernel_ChainstateLoadOptionType_kernel_CHAINSTATE_DB_IN_MEMORY_CHAINSTATE_LOAD_OPTION,
                chainstate_db_in_memory,
            );
        }
        Ok(self)
    }

    pub fn set_block_tree_db_in_memory(
        self,
        block_tree_db_in_memory: bool,
    ) -> Result<Self, KernelError> {
        unsafe {
            kernel_chainstate_load_options_set(
                self.inner,
                kernel_ChainstateLoadOptionType_kernel_CHAINSTATE_DB_IN_MEMORY_CHAINSTATE_LOAD_OPTION,
                block_tree_db_in_memory,
            );
        }
        Ok(self)
    }
}

impl Drop for ChainstateLoadOptions {
    fn drop(&mut self) {
        unsafe { kernel_chainstate_load_options_destroy(self.inner) };
    }
}

pub struct ChainstateManager<'a> {
    inner: *mut kernel_ChainstateManager,
    context: &'a Context,
}

unsafe impl Send for ChainstateManager<'_> {}
unsafe impl Sync for ChainstateManager<'_> {}

impl<'a> ChainstateManager<'a> {
    pub fn new(
        chainman_opts: ChainstateManagerOptions,
        blockman_opts: BlockManagerOptions,
        context: &'a Context,
    ) -> Result<Self, KernelError> {
        let inner = unsafe {
            kernel_chainstate_manager_create(
                chainman_opts.inner,
                blockman_opts.inner,
                context.inner,
            )
        };
        if inner.is_null() {
            return Err(KernelError::Internal(
                "Failed to create chainstate manager.".to_string(),
            ));
        }
        Ok(Self { inner, context })
    }

    pub fn load_chainstate(&self, opts: ChainstateLoadOptions) -> Result<(), KernelError> {
        if !unsafe {
            kernel_chainstate_manager_load_chainstate(self.context.inner, opts.inner, self.inner)
        } {
            return Err(KernelError::Internal(
                "Failed to load chainstate.".to_string(),
            ));
        }
        Ok(())
    }

    pub fn process_block(&self, block: &Block) -> Result<(), KernelError> {
        let mut status = kernel_ProcessBlockStatus_kernel_PROCESS_BLOCK_OK;
        let accepted = unsafe {
            kernel_chainstate_manager_process_block(
                self.context.inner,
                self.inner,
                block.inner,
                &mut status,
            )
        };

        if !accepted {
            let err = match status {
                kernel_ProcessBlockStatus_kernel_PROCESS_BLOCK_ERROR_NO_COINBASE => {
                    ProcessBlockError::NoCoinbase
                }
                kernel_ProcessBlockStatus_kernel_PROCESS_BLOCK_DUPLICATE => {
                    ProcessBlockError::Duplicate
                }
                kernel_ProcessBlockStatus_kernel_PROCESS_BLOCK_INVALID_DUPLICATE => {
                    ProcessBlockError::Duplicate
                }
                _ => ProcessBlockError::Invalid,
            };
            Err(KernelError::ProcessBlock(err))
        } else {
            Ok(())
        }
    }

    pub fn import_blocks(&self) -> Result<(), KernelError> {
        if !unsafe { kernel_import_blocks(self.context.inner, self.inner, std::ptr::null_mut(), 0) }
        {
            return Err(KernelError::Internal(
                "Failed to import blocks.".to_string(),
            ));
        }
        Ok(())
    }

    pub fn get_block_index_tip(&self) -> BlockIndex {
        BlockIndex {
            inner: unsafe { kernel_get_block_index_from_tip(self.context.inner, self.inner) },
            marker: PhantomData,
        }
    }

    pub fn get_block_index_genesis(&self) -> BlockIndex {
        BlockIndex {
            inner: unsafe { kernel_get_block_index_from_genesis(self.context.inner, self.inner) },
            marker: PhantomData,
        }
    }

    pub fn get_block_index_by_height(&self, block_height: i32) -> Result<BlockIndex, KernelError> {
        let inner = unsafe {
            kernel_get_block_index_by_height(self.context.inner, self.inner, block_height)
        };
        if inner.is_null() {
            return Err(KernelError::OutOfBounds);
        }
        Ok(BlockIndex {
            inner,
            marker: PhantomData,
        })
    }

    pub fn get_block_index_by_hash(&self, hash: [u8; 32]) -> Result<BlockIndex, KernelError> {
        let mut block_hash = kernel_BlockHash { hash };
        let inner = unsafe {
            kernel_get_block_index_by_hash(self.context.inner, self.inner, &mut block_hash)
        };
        if inner.is_null() {
            return Err(KernelError::Internal(
                "Block index for the given block hash not found.".to_string(),
            ));
        }
        Ok(BlockIndex {
            inner,
            marker: PhantomData,
        })
    }

    pub fn get_next_block_index(&self, block_index: BlockIndex) -> Result<BlockIndex, KernelError> {
        let inner = unsafe {
            kernel_get_next_block_index(self.context.inner, block_index.inner, self.inner)
        };
        if inner.is_null() {
            return Err(KernelError::OutOfBounds);
        }
        Ok(BlockIndex {
            inner,
            marker: PhantomData,
        })
    }

    pub fn read_block_data(&self, block_index: &BlockIndex) -> Result<Block, KernelError> {
        let inner = unsafe {
            kernel_read_block_from_disk(self.context.inner, self.inner, block_index.inner)
        };
        if inner.is_null() {
            return Err(KernelError::Internal("Failed to read block.".to_string()));
        }
        Ok(Block { inner })
    }

    pub fn read_undo_data(&self, block_index: &BlockIndex) -> Result<BlockUndo, KernelError> {
        let inner = unsafe {
            kernel_read_block_undo_from_disk(self.context.inner, self.inner, block_index.inner)
        };
        if inner.is_null() {
            return Err(KernelError::Internal(
                "Failed to read undo data.".to_string(),
            ));
        }
        let n_tx_undo = unsafe { kernel_block_undo_size(inner) }.try_into().unwrap();
        Ok(BlockUndo { inner, n_tx_undo })
    }
}

impl<'a> Drop for ChainstateManager<'a> {
    fn drop(&mut self) {
        unsafe {
            kernel_chainstate_manager_destroy(self.inner, self.context.inner);
        }
    }
}

pub trait Log {
    fn log(&self, message: &str);
}

unsafe extern "C" fn log_callback<T: Log + 'static>(
    user_data: *mut c_void,
    message: *const c_char,
) {
    let message = unsafe { CStr::from_ptr(message).to_string_lossy().into_owned() };
    let log = user_data as *mut T;
    (*log).log(&message);
}

pub struct Logger<T> {
    log: T,
    inner: *mut kernel_LoggingConnection,
}

impl<T> Drop for Logger<T> {
    fn drop(&mut self) {
        unsafe {
            kernel_logging_connection_destroy(self.inner);
        }
    }
}

pub fn disable_logging() {
    unsafe {
        kernel_disable_logging();
    }
}

impl<T: Log + 'static> Logger<T> {
    pub fn new(mut log: T) -> Result<Logger<T>, KernelError> {
        let options = kernel_LoggingOptions {
            log_timestamps: true,
            log_time_micros: false,
            log_threadnames: false,
            log_sourcelocations: false,
            always_print_category_levels: false,
        };

        let inner = unsafe {
            kernel_logging_connection_create(
                Some(log_callback::<T>),
                &mut log as *mut T as *mut c_void,
                options,
            )
        };

        if inner.is_null() {
            return Err(KernelError::Internal(
                "Failed to create new logging connection.".to_string(),
            ));
        }

        Ok(Logger { log, inner })
    }

    pub fn log(&self, message: &str) {
        self.log.log(message);
    }
}
