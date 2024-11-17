#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi::{CStr, CString, NulError};
use std::fmt;
use std::marker::PhantomData;
use std::os::raw::{c_char, c_void};
use std::sync::Arc;

use libbitcoinkernel_sys::*;

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

/// Verifies a transaction input against its corresponding output script.
///
/// # Arguments
/// * `script_pubkey` - The output script to verify against
/// * `amount` - Needs to be set if the segwit flag is set
/// * `tx_to` - The transaction containing the input to verify
/// * `input_index` - The index of the input within `tx_to` to verify
/// * `flags` - Defaults to all if none
/// * `spent_output` - The outputs being spent by this transaction
///
/// # Returns
/// * `Ok(())` if verification succeeds
/// * [`KernelError::ScriptVerify`] an error describing the failure
pub fn verify(
    script_pubkey: &ScriptPubkey,
    amount: Option<i64>,
    tx_to: &Transaction,
    input_index: u32,
    flags: Option<u32>,
    spent_outputs: &[TxOut],
) -> Result<(), KernelError> {
    let kernel_flags = if let Some(flag) = flags {
        flag
    } else {
        kernel_ScriptFlags_kernel_SCRIPT_FLAGS_VERIFY_ALL
    };
    let mut status = kernel_ScriptVerifyStatus_kernel_SCRIPT_VERIFY_OK;
    let kernel_amount = if let Some(a) = amount { a } else { 0 };
    let kernel_spent_outputs: Vec<*const kernel_TransactionOutput> = spent_outputs
        .iter()
        .map(|utxo| utxo.inner as *const kernel_TransactionOutput)
        .collect();

    let spent_outputs_ptr = if kernel_spent_outputs.is_empty() {
        std::ptr::null_mut()
    } else {
        kernel_spent_outputs.as_ptr() as *mut *const kernel_TransactionOutput
    };

    let ret = unsafe {
        kernel_verify_script(
            script_pubkey.inner,
            kernel_amount,
            tx_to.inner,
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

/// The current synch state, i.e. whether in reindex, ibd, or complete.
/// Emitted by the block tip notification.
#[derive(Debug)]
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

/// Warning state emitted by the kernel warning notification.
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

/// The ChainType used to configure the kernel [`Context`].
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

/// The chain's tip was updated to the provided block hash.
pub trait KNBlockTipFn: Fn(SynchronizationState, BlockHash) {}
impl<F: Fn(SynchronizationState, BlockHash)> KNBlockTipFn for F {}

/// A new best block header was added.
pub trait KNHeaderTipFn: Fn(SynchronizationState, i64, i64, bool) {}
impl<F: Fn(SynchronizationState, i64, i64, bool)> KNHeaderTipFn for F {}

/// Reports on the current synchronization progress.
pub trait KNProgressFn: Fn(String, i32, bool) {}
impl<F: Fn(String, i32, bool)> KNProgressFn for F {}

/// A warning state issued by the kernel during validation.
pub trait KNWarningSetFn: Fn(KernelWarning, String) {}
impl<F: Fn(KernelWarning, String)> KNWarningSetFn for F {}

/// A previous condition leading to the issuance of a warning is no longer given.
pub trait KNWarningUnsetFn: Fn(KernelWarning) {}
impl<F: Fn(KernelWarning)> KNWarningUnsetFn for F {}

/// An error was encountered when flushing data to disk.
pub trait KNFlushErrorFn: Fn(String) {}
impl<F: Fn(String)> KNFlushErrorFn for F {}

/// An un-recoverable system error was encountered by the library.
pub trait KNFatalErrorFn: Fn(String) {}
impl<F: Fn(String)> KNFatalErrorFn for F {}

/// A callback holder struct for the notification interface calls.
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
    let hash = kernel_block_index_get_block_hash(block_index);
    let res = BlockHash {
        hash: (&*hash).hash,
    };
    (holder.kn_block_tip)(state.into(), res);
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

/// The chain parameters with which to configure a [`Context`].
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

/// The main context struct. This should be setup through the [`ContextBuilder`] and
/// has to be kept in memory for the duration of context-dependent library
/// operations.
///
pub struct Context {
    inner: *mut kernel_Context,
    // We need something to hold this in memory.
    #[allow(dead_code)]
    kn_callbacks: Option<Box<KernelNotificationInterfaceCallbackHolder>>,
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

/// Builder struct for the kernel [`Context`].
///
/// The builder by default configures for mainnet and swallows any kernel
/// notifications.
pub struct ContextBuilder {
    inner: *mut kernel_ContextOptions,
    kn_callbacks: Option<Box<KernelNotificationInterfaceCallbackHolder>>,
}

impl ContextBuilder {
    pub fn new() -> ContextBuilder {
        let context = ContextBuilder {
            inner: unsafe { kernel_context_options_create() },
            kn_callbacks: None,
        };
        context
    }

    /// Consumes the builder and creates a [`Context`].
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::Internal`] if [`Context`] creation fails.
    pub fn build(self) -> Result<Context, KernelError> {
        let inner = unsafe { kernel_context_create(self.inner) };
        if inner.is_null() {
            return Err(KernelError::Internal("Invalid context.".to_string()));
        }
        unsafe { kernel_context_options_destroy(self.inner) };
        Ok(Context {
            inner,
            kn_callbacks: self.kn_callbacks,
        })
    }

    /// Sets the notifications callbacks to the passed in holder struct
    pub fn kn_callbacks(
        mut self,
        kn_callbacks: Box<KernelNotificationInterfaceCallbackHolder>,
    ) -> ContextBuilder {
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
            kernel_context_options_set_notifications(self.inner, kernel_notifications);
            kernel_notifications_destroy(kernel_notifications);
        };
        self.kn_callbacks = unsafe { Some(Box::from_raw(kn_pointer)) };
        self
    }

    /// Sets the chain type
    pub fn chain_type(self, chain_type: ChainType) -> ContextBuilder {
        let chain_params = ChainParams::new(chain_type);
        unsafe { kernel_context_options_set_chainparams(self.inner, chain_params.inner) };
        self
    }
}

/// A collection of errors emitted by this library
#[derive(Debug)]
pub enum KernelError {
    Internal(String),
    CStringCreationFailed(String),
    InvalidOptions(String),
    OutOfBounds,
    ScriptVerify(ScriptVerifyError),
}

/// A collection of errors that may occur during script verification
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

impl From<NulError> for KernelError {
    fn from(err: NulError) -> Self {
        KernelError::CStringCreationFailed(err.to_string())
    }
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KernelError::Internal(msg)
            | KernelError::CStringCreationFailed(msg)
            | KernelError::InvalidOptions(msg) => write!(f, "{}", msg),
            _ => write!(f, "Error!"),
        }
    }
}

/// Whether a validated data structure is valid, invalid, or an error was
/// encountered during processing.
pub enum ValidationMode {
    VALID,
    INVALID,
    ERROR,
}

impl From<kernel_ValidationMode> for ValidationMode {
    fn from(mode: kernel_ValidationMode) -> Self {
        match mode {
            kernel_ValidationMode_kernel_VALIDATION_STATE_VALID => Self::VALID,
            kernel_ValidationMode_kernel_VALIDATION_STATE_INVALID => Self::INVALID,
            kernel_ValidationMode_kernel_VALIDATION_STATE_ERROR => Self::ERROR,
            _ => ValidationMode::ERROR, // This should never happen
        }
    }
}

/// A granular reason why a block was invalid.
pub enum BlockValidationResult {
    /// initial value. Block has not yet been rejected
    RESULT_UNSET = 0,
    /// invalid by consensus rules (excluding any below reasons)
    CONSENSUS,
    /// this block was cached as being invalid and we didn't store the reason why
    CACHED_INVALID,
    /// invalid proof of work or time too old
    INVALID_HEADER,
    /// the block's data didn't match the data committed to by the PoW
    MUTATED,
    /// We don't have the previous block the checked one is built on
    MISSING_PREV,
    /// A block this one builds on is invalid
    INVALID_PREV,
    /// block timestamp was > 2 hours in the future (or our clock is bad)
    TIME_FUTURE,
    /// the block failed to meet one of our checkpoints
    CHECKPOINT,
    /// the block header may be on a too-little-work chain
    HEADER_LOW_WORK,
}

impl From<kernel_BlockValidationResult> for BlockValidationResult {
    fn from(res: kernel_BlockValidationResult) -> Self {
        match res {
            kernel_BlockValidationResult_kernel_BLOCK_RESULT_UNSET => Self::RESULT_UNSET,
            kernel_BlockValidationResult_kernel_BLOCK_CONSENSUS => Self::CONSENSUS,
            kernel_BlockValidationResult_kernel_BLOCK_CACHED_INVALID => Self::CACHED_INVALID,
            kernel_BlockValidationResult_kernel_BLOCK_INVALID_HEADER => Self::INVALID_HEADER,
            kernel_BlockValidationResult_kernel_BLOCK_MUTATED => Self::MUTATED,
            kernel_BlockValidationResult_kernel_BLOCK_MISSING_PREV => Self::MISSING_PREV,
            kernel_BlockValidationResult_kernel_BLOCK_INVALID_PREV => Self::INVALID_PREV,
            kernel_BlockValidationResult_kernel_BLOCK_TIME_FUTURE => Self::TIME_FUTURE,
            kernel_BlockValidationResult_kernel_BLOCK_CHECKPOINT => Self::CHECKPOINT,
            kernel_BlockValidationResult_kernel_BLOCK_HEADER_LOW_WORK => Self::HEADER_LOW_WORK,
            _ => Self::CONSENSUS,
        }
    }
}

/// Exposes the result after validating a block.
pub trait VIBlockCheckedFn: Fn(UnownedBlock, ValidationMode, BlockValidationResult) {}
impl<F: Fn(UnownedBlock, ValidationMode, BlockValidationResult)> VIBlockCheckedFn for F {}

/// A holder struct for validation interface callbacks
pub struct ValidationInterfaceCallbackHolder {
    /// Called after a block has completed validation and communicates its validation state.
    pub block_checked: Box<dyn VIBlockCheckedFn>,
}

unsafe extern "C" fn vi_block_checked_wrapper(
    user_data: *mut c_void,
    block: *const kernel_BlockPointer,
    stateIn: *const kernel_BlockValidationState,
) {
    let holder = &*(user_data as *mut ValidationInterfaceCallbackHolder);
    let result = kernel_get_block_validation_result_from_block_validation_state(stateIn);
    let mode = kernel_get_validation_mode_from_block_validation_state(stateIn);
    (holder.block_checked)(UnownedBlock::new(block), mode.into(), result.into());
}

/// A wrapper for the validation interface. This is the struct that has to be
/// registered with a [`Context`] in order to receive validation interface events.
pub struct ValidationInterfaceWrapper {
    inner: *mut kernel_ValidationInterface,
    pub vi_callbacks: Box<ValidationInterfaceCallbackHolder>,
}

impl ValidationInterfaceWrapper {
    /// Create a new ValidationInterface wrapper configured with the passed in callbacks.
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

/// Register a validation interface with a [`Context`].
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

/// De-register a validation interface with a previously registered [`Context`].
/// This should be done before destroying the [`Context`].
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

/// A single script pubkey
#[derive(Debug, Clone)]
pub struct ScriptPubkey {
    inner: *mut kernel_ScriptPubkey,
}

unsafe impl Send for ScriptPubkey {}
unsafe impl Sync for ScriptPubkey {}

impl ScriptPubkey {
    pub fn get(&self) -> Vec<u8> {
        let script_pubkey = unsafe { kernel_copy_script_pubkey_data(self.inner) };
        unsafe {
            std::slice::from_raw_parts(
                (*script_pubkey).data,
                (*script_pubkey).size.try_into().unwrap(),
            )
        }
        .to_vec()
    }
}

impl TryFrom<&[u8]> for ScriptPubkey {
    type Error = KernelError;

    fn try_from(raw_script_pubkey: &[u8]) -> Result<Self, Self::Error> {
        let inner = unsafe {
            kernel_script_pubkey_create(raw_script_pubkey.as_ptr(), raw_script_pubkey.len())
        };
        if inner.is_null() {
            return Err(KernelError::Internal(
                "Failed to decode raw transaction".to_string(),
            ));
        }
        Ok(ScriptPubkey { inner })
    }
}

impl Drop for ScriptPubkey {
    fn drop(&mut self) {
        unsafe { kernel_script_pubkey_destroy(self.inner) }
    }
}

/// A single transaction output.
///
/// It can be initialized with a script pubkey and amount, and the user may
/// retrieve a copy of a script pubkey and its amount.
#[derive(Debug, Clone)]
pub struct TxOut {
    inner: *mut kernel_TransactionOutput,
}

unsafe impl Send for TxOut {}
unsafe impl Sync for TxOut {}

impl TxOut {
    pub fn new(script_pubkey: &ScriptPubkey, amount: i64) -> TxOut {
        TxOut {
            inner: unsafe { kernel_transaction_output_create(script_pubkey.inner, amount) },
        }
    }

    /// Get the amount associated with this transaction output
    pub fn get_value(&self) -> i64 {
        unsafe { kernel_get_transaction_output_amount(self.inner) }
    }

    /// Get the script pubkey of this output
    pub fn get_script_pubkey(&self) -> ScriptPubkey {
        ScriptPubkey {
            inner: unsafe { kernel_copy_script_pubkey_from_output(self.inner) },
        }
    }
}

impl Drop for TxOut {
    fn drop(&mut self) {
        unsafe { kernel_transaction_output_destroy(self.inner) }
    }
}

/// A single transaction.
pub struct Transaction {
    inner: *mut kernel_Transaction,
}

unsafe impl Send for Transaction {}
unsafe impl Sync for Transaction {}

impl TryFrom<&[u8]> for Transaction {
    type Error = KernelError;

    fn try_from(raw_transaction: &[u8]) -> Result<Self, Self::Error> {
        let inner =
            unsafe { kernel_transaction_create(raw_transaction.as_ptr(), raw_transaction.len()) };
        if inner.is_null() {
            return Err(KernelError::Internal(
                "Failed to decode raw transaction.".to_string(),
            ));
        }
        Ok(Transaction { inner })
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        unsafe { kernel_transaction_destroy(self.inner) }
    }
}

/// A single unowned block. Can only be used for copying data from it.
pub struct UnownedBlock {
    inner: *const kernel_BlockPointer,
}

impl UnownedBlock {
    fn new(block: *const kernel_BlockPointer) -> UnownedBlock {
        UnownedBlock { inner: block }
    }

    pub fn get_hash(&self) -> BlockHash {
        let hash = unsafe {kernel_block_pointer_get_hash(self.inner)};
        let res = BlockHash {
            hash: unsafe { (&*hash).hash },
        };
        unsafe { kernel_block_hash_destroy(hash) };
        return res;
    }
}

impl Into<Vec<u8>> for UnownedBlock {
    fn into(self) -> Vec<u8> {
        let raw_block = unsafe { kernel_copy_block_pointer_data(self.inner) };
        let vec = unsafe {
            std::slice::from_raw_parts((*raw_block).data, (*raw_block).size.try_into().unwrap())
        }
        .to_vec();
        unsafe { kernel_byte_array_destroy(raw_block) };
        vec
    }
}

/// A single Block
pub struct Block {
    inner: *mut kernel_Block,
}

unsafe impl Send for Block {}
unsafe impl Sync for Block {}

impl Block {
    pub fn get_hash(&self) -> BlockHash {
        let hash = unsafe {kernel_block_get_hash(self.inner)};
        let res = BlockHash {
            hash: unsafe { (&*hash).hash },
        };
        unsafe { kernel_block_hash_destroy(hash) };
        return res;
    }
}

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

/// A block index that is tied to a specific [`ChainstateManager`].
///
/// Internally the [`ChainstateManager`] keeps an in-memory of the current block
/// tree once it is loaded. The [`BlockIndex`] points to an entry in this tree.
/// It is only valid as long as the [`ChainstateManager`] it was retrieved from
/// remains in scope.
pub struct BlockIndex {
    inner: *mut kernel_BlockIndex,
    marker: PhantomData<ChainstateManager>,
}

unsafe impl Send for BlockIndex {}
unsafe impl Sync for BlockIndex {}

/// A type for a Block hash.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct BlockHash {
    pub hash: [u8; 32],
}

impl BlockIndex {
    /// Move to the previous entry in the block tree. E.g. from height n to
    /// height n-1.
    pub fn prev(self) -> Result<BlockIndex, KernelError> {
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

    /// Get the current height associated with this BlockIndex.
    pub fn height(&self) -> i32 {
        unsafe { kernel_block_index_get_height(self.inner) }
    }

    /// Get the current block hash associated with this BlockIndex.
    pub fn block_hash(&self) -> BlockHash {
        let hash = unsafe { kernel_block_index_get_block_hash(self.inner) };
        let res = BlockHash {
            hash: unsafe { (&*hash).hash },
        };
        unsafe { kernel_block_hash_destroy(hash) };
        return res;
    }
}

impl<'a> Drop for BlockIndex {
    fn drop(&mut self) {
        unsafe { kernel_block_index_destroy(self.inner) };
    }
}

/// The undo data of a block is used internally during re-orgs. It holds the
/// previous transaction outputs of a block's transactions. This data may be
/// useful for building indexes.
pub struct BlockUndo {
    inner: *mut kernel_BlockUndo,
    pub n_tx_undo: usize,
}
unsafe impl Send for BlockUndo {}
unsafe impl Sync for BlockUndo {}

impl BlockUndo {
    /// Gets the number of previous outputs associated with a transaction in a
    /// [`Block`] by its index.
    pub fn get_transaction_undo_size(&self, transaction_index: u64) -> u64 {
        unsafe { kernel_get_transaction_undo_size(self.inner, transaction_index) }
    }

    /// Gets the previous output of a transaction by its index.
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
        let res = TxOut { inner: prev_out };
        Ok(res)
    }
}

impl Drop for BlockUndo {
    fn drop(&mut self) {
        unsafe { kernel_block_undo_destroy(self.inner) };
    }
}

/// Holds the configuration options for creating a new [`ChainstateManager`]
pub struct ChainstateManagerOptions {
    inner: *mut kernel_ChainstateManagerOptions,
}

impl ChainstateManagerOptions {
    /// Create a new option
    ///
    /// # Arguments
    /// * `context` -  The [`ChainstateManager`] for which these options are created has to use the same [`Context`].
    /// * `data_dir` - The directory into which the [`ChainstateManager`] will write its data.
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

    pub fn set_worker_threads(&self, worker_threads: i32) {
        unsafe {
            kernel_chainstate_manager_options_set_worker_threads_num(self.inner, worker_threads);
        }
    }
}

impl Drop for ChainstateManagerOptions {
    fn drop(&mut self) {
        unsafe {
            kernel_chainstate_manager_options_destroy(self.inner);
        }
    }
}

/// Holds the configuration options for a BlockManager, which is used internally
/// by the [`ChainstateManager`]
pub struct BlockManagerOptions {
    inner: *mut kernel_BlockManagerOptions,
}

impl BlockManagerOptions {
    /// Create a new option
    ///
    /// # Arguments
    /// * `context` -  The [`ChainstateManager`] for which these options are created has to use the same [`Context`].
    /// * `blocks_dir` - The directory into which the [`ChainstateManager`] will write its block data.
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

/// Holds the configuration options for when loading the on disk state of the [`ChainstateManager`].
pub struct ChainstateLoadOptions {
    inner: *mut kernel_ChainstateLoadOptions,
}

impl ChainstateLoadOptions {
    pub fn new() -> ChainstateLoadOptions {
        ChainstateLoadOptions {
            inner: unsafe { kernel_chainstate_load_options_create() },
        }
    }

    pub fn set_reindex(self, reindex: bool) -> Self {
        unsafe {
            kernel_chainstate_load_options_set_wipe_block_tree_db(self.inner, reindex);
            kernel_chainstate_load_options_set_wipe_chainstate_db(self.inner, reindex);
        }
        self
    }

    pub fn set_wipe_chainstate_db(self, wipe_chainstate: bool) -> Self {
        unsafe {
            kernel_chainstate_load_options_set_wipe_chainstate_db(self.inner, wipe_chainstate);
        }
        self
    }

    pub fn set_chainstate_db_in_memory(self, chainstate_db_in_memory: bool) -> Self {
        unsafe {
            kernel_chainstate_load_options_set_chainstate_db_in_memory(
                self.inner,
                chainstate_db_in_memory,
            );
        }
        self
    }

    pub fn set_block_tree_db_in_memory(self, block_tree_db_in_memory: bool) -> Self {
        unsafe {
            kernel_chainstate_load_options_set_block_tree_db_in_memory(
                self.inner,
                block_tree_db_in_memory,
            );
        }
        self
    }
}

impl Drop for ChainstateLoadOptions {
    fn drop(&mut self) {
        unsafe { kernel_chainstate_load_options_destroy(self.inner) };
    }
}

/// The chainstate manager is the central object for doing validation tasks as
/// well as retrieving data from the chain. Internally it is a complex data
/// structure with diverse functionality.
///
/// The chainstate manager is only valid for as long as the [`Context`] with which it
/// was created remains in memory.
///
/// Its functionality will be more and more exposed in the future.
pub struct ChainstateManager {
    inner: *mut kernel_ChainstateManager,
    context: Arc<Context>,
}

unsafe impl Send for ChainstateManager {}
unsafe impl Sync for ChainstateManager {}

impl<'a> ChainstateManager {
    pub fn new(
        chainman_opts: ChainstateManagerOptions,
        blockman_opts: BlockManagerOptions,
        context: Arc<Context>,
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

    /// This function must be called to initialize the chainstate manager before
    /// doing validation tasks or interacting with its indexes.
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

    /// Process and validate the passed in block with the [`ChainstateManager`]
    /// If processing failed, some information can be retrieved through the status
    /// enumeration. More detailed validation information in case of a failure can
    /// also be retrieved through a registered validation interface. If the block
    /// fails to validate the `block_checked` callback's ['BlockValidationState'] will
    /// contain details.
    pub fn process_block(&self, block: &Block) -> (bool /* accepted */, bool /* duplicate */) {
        let mut new_block = true.into();
        let accepted = unsafe {
            kernel_chainstate_manager_process_block(
                self.context.inner,
                self.inner,
                block.inner,
                &mut new_block,
            )
        };
        (accepted, new_block)
    }

    /// May be called after load_chainstate to initialize the
    /// [`ChainstateManager`]. Triggers the start of a reindex if the option was
    /// previously set for the chainstate and block manager. Can also import an
    /// array of existing block files selected by the user.
    pub fn import_blocks(&self) -> Result<(), KernelError> {
        if !unsafe { kernel_import_blocks(self.context.inner, self.inner, std::ptr::null_mut(), 0) }
        {
            return Err(KernelError::Internal(
                "Failed to import blocks.".to_string(),
            ));
        }
        Ok(())
    }

    /// Get the block index entry of the current chain tip. Once returned,
    /// there is no guarantee that it remains in the active chain.
    pub fn get_block_index_tip(&self) -> BlockIndex {
        BlockIndex {
            inner: unsafe { kernel_get_block_index_from_tip(self.context.inner, self.inner) },
            marker: PhantomData,
        }
    }

    /// Get the block index entry of the genesis block.
    pub fn get_block_index_genesis(&self) -> BlockIndex {
        BlockIndex {
            inner: unsafe { kernel_get_block_index_from_genesis(self.context.inner, self.inner) },
            marker: PhantomData,
        }
    }

    /// Retrieve a block index by its height in the currently active chain.
    /// Once retrieved there is no guarantee that it remains in the active chain.
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

    /// Get a block index entry by its hash.
    pub fn get_block_index_by_hash(&self, hash: BlockHash) -> Result<BlockIndex, KernelError> {
        let mut block_hash = kernel_BlockHash { hash: hash.hash };
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

    /// Get the next block index entry in the chain. If this is the tip, or
    /// otherwise a leaf in the block tree, return an error.
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

    /// Read a block from disk by its block index.
    pub fn read_block_data(&self, block_index: &BlockIndex) -> Result<Block, KernelError> {
        let inner = unsafe {
            kernel_read_block_from_disk(self.context.inner, self.inner, block_index.inner)
        };
        if inner.is_null() {
            return Err(KernelError::Internal("Failed to read block.".to_string()));
        }
        Ok(Block { inner })
    }

    /// Read a block's undo data from disk by its block index.
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

impl Drop for ChainstateManager {
    fn drop(&mut self) {
        unsafe {
            kernel_chainstate_manager_destroy(self.inner, self.context.inner);
        }
    }
}

/// A function for handling log messages produced by the kernel library.
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

/// The logger object logs kernel log messages into a user-defined log function.
/// Messages logged by the kernel before this object is created are buffered in
/// a 1MB buffer. The kernel library internally uses a global logging instance.
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

/// Permanently disable logging and stop buffering.
pub fn disable_logging() {
    unsafe {
        kernel_disable_logging();
    }
}

impl<T: Log + 'static> Logger<T> {
    /// Create a new Logger with the specified callback.
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

    /// Manually log something through the user-specified callback.
    pub fn log(&self, message: &str) {
        self.log.log(message);
    }
}