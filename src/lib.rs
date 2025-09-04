#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::borrow::Borrow;
use std::ffi::{c_char, c_void, CString, NulError};
use std::marker::PhantomData;
use std::{fmt, panic};
pub mod constants;

use crate::constants::*;
use libbitcoinkernel_sys::*;

pub const VERIFY_NONE: btck_ScriptVerificationFlags = BTCK_SCRIPT_VERIFICATION_FLAGS_NONE;

pub const VERIFY_P2SH: btck_ScriptVerificationFlags = BTCK_SCRIPT_VERIFICATION_FLAGS_P2SH;

pub const VERIFY_DERSIG: btck_ScriptVerificationFlags = BTCK_SCRIPT_VERIFICATION_FLAGS_DERSIG;

pub const VERIFY_NULLDUMMY: btck_ScriptVerificationFlags = BTCK_SCRIPT_VERIFICATION_FLAGS_NULLDUMMY;

pub const VERIFY_CHECKLOCKTIMEVERIFY: btck_ScriptVerificationFlags =
    BTCK_SCRIPT_VERIFICATION_FLAGS_CHECKLOCKTIMEVERIFY;

pub const VERIFY_CHECKSEQUENCEVERIFY: btck_ScriptVerificationFlags =
    BTCK_SCRIPT_VERIFICATION_FLAGS_CHECKSEQUENCEVERIFY;

pub const VERIFY_WITNESS: btck_ScriptVerificationFlags = BTCK_SCRIPT_VERIFICATION_FLAGS_WITNESS;

pub const VERIFY_TAPROOT: btck_ScriptVerificationFlags = BTCK_SCRIPT_VERIFICATION_FLAGS_TAPROOT;

pub const VERIFY_ALL: btck_ScriptVerificationFlags = BTCK_SCRIPT_VERIFICATION_FLAGS_ALL;

pub const VERIFY_ALL_PRE_TAPROOT: btck_ScriptVerificationFlags = VERIFY_P2SH
    | VERIFY_DERSIG
    | VERIFY_NULLDUMMY
    | VERIFY_CHECKLOCKTIMEVERIFY
    | VERIFY_CHECKSEQUENCEVERIFY
    | VERIFY_WITNESS;

/// Helper functions for converting between Rust and C types.
mod c_helpers {
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
}

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
    input_index: usize,
    flags: Option<u32>,
    spent_outputs: &[TxOut],
) -> Result<(), KernelError> {
    let input_count = tx_to.input_count();

    if input_index >= input_count {
        return Err(KernelError::ScriptVerify(ScriptVerifyError::TxInputIndex));
    }

    if !spent_outputs.is_empty() && spent_outputs.len() != input_count {
        return Err(KernelError::ScriptVerify(
            ScriptVerifyError::SpentOutputsMismatch,
        ));
    }

    let kernel_flags = if let Some(flag) = flags {
        if (flag & !VERIFY_ALL) != 0 {
            return Err(KernelError::ScriptVerify(ScriptVerifyError::InvalidFlags));
        }
        flag
    } else {
        VERIFY_ALL
    };

    let status = ScriptVerifyStatus::Ok;
    let kernel_amount = amount.unwrap_or_default();
    let kernel_spent_outputs: Vec<*const btck_TransactionOutput> = spent_outputs
        .iter()
        .map(|utxo| utxo.inner as *const btck_TransactionOutput)
        .collect();

    let spent_outputs_ptr = if kernel_spent_outputs.is_empty() {
        std::ptr::null_mut()
    } else {
        kernel_spent_outputs.as_ptr() as *mut *const btck_TransactionOutput
    };

    let ret = unsafe {
        btck_script_pubkey_verify(
            script_pubkey.inner,
            kernel_amount,
            tx_to.inner,
            spent_outputs_ptr,
            spent_outputs.len(),
            input_index as u32,
            kernel_flags,
            &mut status.into(),
        )
    };

    let script_status = ScriptVerifyStatus::try_from(status).map_err(|_| {
        KernelError::Internal(format!("Invalid script verify status: {:?}", status))
    })?;

    if !c_helpers::verification_passed(ret) {
        let err = match script_status {
            ScriptVerifyStatus::ErrorInvalidFlagsCombination => {
                ScriptVerifyError::InvalidFlagsCombination
            }
            ScriptVerifyStatus::ErrorSpentOutputsRequired => {
                ScriptVerifyError::SpentOutputsRequired
            }
            _ => ScriptVerifyError::Invalid,
        };
        Err(KernelError::ScriptVerify(err))
    } else {
        Ok(())
    }
}

/// Status of script verification operations.
///
/// Indicates the result of verifying a transaction script, including any
/// configuration errors that prevented verification from proceeding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ScriptVerifyStatus {
    /// Script verification completed successfully
    Ok = BTCK_SCRIPT_VERIFY_STATUS_OK,
    /// Invalid combination of verification flags was provided
    ErrorInvalidFlagsCombination = BTCK_SCRIPT_VERIFY_STATUS_ERROR_INVALID_FLAGS_COMBINATION,
    /// Spent outputs are required for this type of verification but were not provided
    ErrorSpentOutputsRequired = BTCK_SCRIPT_VERIFY_STATUS_ERROR_SPENT_OUTPUTS_REQUIRED,
}

impl From<ScriptVerifyStatus> for btck_ScriptVerifyStatus {
    fn from(status: ScriptVerifyStatus) -> Self {
        status as btck_ScriptVerifyStatus
    }
}

impl From<btck_ScriptVerifyStatus> for ScriptVerifyStatus {
    fn from(value: btck_ScriptVerifyStatus) -> Self {
        match value {
            BTCK_SCRIPT_VERIFY_STATUS_OK => ScriptVerifyStatus::Ok,
            BTCK_SCRIPT_VERIFY_STATUS_ERROR_INVALID_FLAGS_COMBINATION => {
                ScriptVerifyStatus::ErrorInvalidFlagsCombination
            }
            BTCK_SCRIPT_VERIFY_STATUS_ERROR_SPENT_OUTPUTS_REQUIRED => {
                ScriptVerifyStatus::ErrorSpentOutputsRequired
            }
            _ => panic!("Unknown script verify status: {}", value),
        }
    }
}

/// Serializes data using a C callback function pattern.
///
/// Takes a C function that writes data via a callback and returns the
/// serialized bytes as a Vec<u8>.
fn c_serialize<F>(c_function: F) -> Result<Vec<u8>, KernelError>
where
    F: FnOnce(
        unsafe extern "C" fn(*const std::ffi::c_void, usize, *mut std::ffi::c_void) -> i32,
        *mut std::ffi::c_void,
    ) -> i32,
{
    let mut buffer = Vec::new();

    unsafe extern "C" fn write_callback(
        data: *const std::ffi::c_void,
        len: usize,
        user_data: *mut std::ffi::c_void,
    ) -> i32 {
        panic::catch_unwind(|| {
            let buffer = &mut *(user_data as *mut Vec<u8>);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            buffer.extend_from_slice(slice);
            c_helpers::to_c_result(true)
        })
        .unwrap_or_else(|_| c_helpers::to_c_result(false))
    }

    let result = c_function(
        write_callback,
        &mut buffer as *mut Vec<u8> as *mut std::ffi::c_void,
    );

    if c_helpers::success(result) {
        Ok(buffer)
    } else {
        Err(KernelError::SerializationFailed)
    }
}

unsafe fn cast_string(c_str: *const c_char, len: usize) -> String {
    if !c_str.is_null() {
        let slice = std::slice::from_raw_parts(c_str as *const u8, len);
        String::from_utf8_lossy(slice).into_owned()
    } else {
        "".to_string()
    }
}

/// Current synchronization state of the blockchain.
///
/// Indicates what phase of blockchain synchronization is currently active.
/// Emitted by block tip notifications to track sync progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SynchronizationState {
    /// Currently reindexing the blockchain from disk
    InitReindex = BTCK_SYNCHRONIZATION_STATE_INIT_REINDEX,
    /// Initial block download - syncing from network peers
    InitDownload = BTCK_SYNCHRONIZATION_STATE_INIT_DOWNLOAD,
    /// Synchronization complete - processing new blocks
    PostInit = BTCK_SYNCHRONIZATION_STATE_POST_INIT,
}

impl From<SynchronizationState> for btck_SynchronizationState {
    fn from(state: SynchronizationState) -> Self {
        state as btck_SynchronizationState
    }
}

impl From<btck_SynchronizationState> for SynchronizationState {
    fn from(value: btck_SynchronizationState) -> Self {
        match value {
            BTCK_SYNCHRONIZATION_STATE_INIT_REINDEX => SynchronizationState::InitReindex,
            BTCK_SYNCHRONIZATION_STATE_INIT_DOWNLOAD => SynchronizationState::InitDownload,
            BTCK_SYNCHRONIZATION_STATE_POST_INIT => SynchronizationState::PostInit,
            _ => panic!("Unknown synchronization state: {}", value),
        }
    }
}

/// Warning conditions detected by the kernel during validation.
///
/// These warnings indicate potentially problematic conditions that may
/// require user attention or represent network-wide issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Warning {
    /// Unknown new consensus rules have been activated
    ///
    /// This typically means the software is out of date and doesn't
    /// recognize new consensus rules that have activated on the network.
    UnknownNewRulesActivated = BTCK_WARNING_UNKNOWN_NEW_RULES_ACTIVATED,

    /// A chain with significant work contains invalid blocks
    ///
    /// This warning indicates that a substantial amount of computational
    /// work has been expended on a chain that contains invalid blocks.
    LargeWorkInvalidChain = BTCK_WARNING_LARGE_WORK_INVALID_CHAIN,
}

impl From<Warning> for btck_Warning {
    fn from(warning: Warning) -> Self {
        warning as btck_Warning
    }
}

impl From<btck_Warning> for Warning {
    fn from(value: btck_Warning) -> Self {
        match value {
            BTCK_WARNING_UNKNOWN_NEW_RULES_ACTIVATED => Warning::UnknownNewRulesActivated,
            BTCK_WARNING_LARGE_WORK_INVALID_CHAIN => Warning::LargeWorkInvalidChain,
            _ => panic!("Unknown warning: {}", value),
        }
    }
}

/// Bitcoin network chain types.
///
/// Specifies which Bitcoin network the kernel should operate on.
/// Each chain type has different consensus rules and network parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ChainType {
    /// Bitcoin mainnet - the production network
    Mainnet = BTCK_CHAIN_TYPE_MAINNET,
    /// Bitcoin testnet - the original test network
    Testnet = BTCK_CHAIN_TYPE_TESTNET,
    /// Bitcoin testnet4 - the newer test network
    Testnet4 = BTCK_CHAIN_TYPE_TESTNET_4,
    /// Bitcoin signet - signed test network
    Signet = BTCK_CHAIN_TYPE_SIGNET,
    /// Regression test network for local development
    Regtest = BTCK_CHAIN_TYPE_REGTEST,
}

impl From<ChainType> for btck_ChainType {
    fn from(chain_type: ChainType) -> Self {
        chain_type as btck_ChainType
    }
}

impl From<btck_ChainType> for ChainType {
    fn from(value: btck_ChainType) -> Self {
        match value {
            BTCK_CHAIN_TYPE_MAINNET => ChainType::Mainnet,
            BTCK_CHAIN_TYPE_TESTNET => ChainType::Testnet,
            BTCK_CHAIN_TYPE_TESTNET_4 => ChainType::Testnet4,
            BTCK_CHAIN_TYPE_SIGNET => ChainType::Signet,
            BTCK_CHAIN_TYPE_REGTEST => ChainType::Regtest,
            _ => panic!("Unknown chain type: {}", value),
        }
    }
}

/// The chain's tip was updated to the provided block hash.
pub trait BlockTip: Fn(SynchronizationState, BlockHash, f64) {}
impl<F: Fn(SynchronizationState, BlockHash, f64)> BlockTip for F {}

/// A new best block header was added.
pub trait HeaderTip: Fn(SynchronizationState, i64, i64, bool) {}
impl<F: Fn(SynchronizationState, i64, i64, bool)> HeaderTip for F {}

/// Reports on the current synchronization progress.
pub trait Progress: Fn(String, i32, bool) {}
impl<F: Fn(String, i32, bool)> Progress for F {}

/// A warning state issued by the kernel during validation.
pub trait WarningSet: Fn(Warning, String) {}
impl<F: Fn(Warning, String)> WarningSet for F {}

/// A previous condition leading to the issuance of a warning is no longer given.
pub trait WarningUnset: Fn(Warning) {}
impl<F: Fn(Warning)> WarningUnset for F {}

/// An error was encountered when flushing data to disk.
pub trait FlushError: Fn(String) {}
impl<F: Fn(String)> FlushError for F {}

/// An un-recoverable system error was encountered by the library.
pub trait FatalError: Fn(String) {}
impl<F: Fn(String)> FatalError for F {}

/// A callback holder struct for the notification interface calls.
pub struct KernelNotificationInterfaceCallbacks {
    pub kn_block_tip: Box<dyn BlockTip>,
    pub kn_header_tip: Box<dyn HeaderTip>,
    pub kn_progress: Box<dyn Progress>,
    pub kn_warning_set: Box<dyn WarningSet>,
    pub kn_warning_unset: Box<dyn WarningUnset>,
    pub kn_flush_error: Box<dyn FlushError>,
    pub kn_fatal_error: Box<dyn FatalError>,
}

unsafe extern "C" fn kn_user_data_destroy_wrapper(user_data: *mut c_void) {
    if !user_data.is_null() {
        let _ = Box::from_raw(user_data as *mut KernelNotificationInterfaceCallbacks);
    }
}

unsafe extern "C" fn kn_block_tip_wrapper(
    user_data: *mut c_void,
    state: btck_SynchronizationState,
    entry: *mut btck_BlockTreeEntry,
    verification_progress: f64,
) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbacks);
    let hash = btck_block_tree_entry_get_block_hash(entry);
    let res = BlockHash { hash: (*hash).hash };
    btck_block_hash_destroy(hash);
    btck_block_tree_entry_destroy(entry);
    (holder.kn_block_tip)(state.into(), res, verification_progress);
}

unsafe extern "C" fn kn_header_tip_wrapper(
    user_data: *mut c_void,
    state: btck_SynchronizationState,
    height: i64,
    timestamp: i64,
    presync: i32,
) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbacks);
    (holder.kn_header_tip)(state.into(), height, timestamp, c_helpers::enabled(presync));
}

unsafe extern "C" fn kn_progress_wrapper(
    user_data: *mut c_void,
    title: *const c_char,
    title_len: usize,
    progress_percent: i32,
    resume_possible: i32,
) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbacks);
    (holder.kn_progress)(
        cast_string(title, title_len),
        progress_percent,
        c_helpers::enabled(resume_possible),
    );
}

unsafe extern "C" fn kn_warning_set_wrapper(
    user_data: *mut c_void,
    warning: btck_Warning,
    message: *const c_char,
    message_len: usize,
) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbacks);
    (holder.kn_warning_set)(warning.into(), cast_string(message, message_len));
}

unsafe extern "C" fn kn_warning_unset_wrapper(user_data: *mut c_void, warning: btck_Warning) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbacks);
    (holder.kn_warning_unset)(warning.into());
}

unsafe extern "C" fn kn_flush_error_wrapper(
    user_data: *mut c_void,
    message: *const c_char,
    message_len: usize,
) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbacks);
    (holder.kn_flush_error)(cast_string(message, message_len));
}

unsafe extern "C" fn kn_fatal_error_wrapper(
    user_data: *mut c_void,
    message: *const c_char,
    message_len: usize,
) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbacks);
    (holder.kn_fatal_error)(cast_string(message, message_len));
}

/// The chain parameters with which to configure a [`Context`].
pub struct ChainParams {
    inner: *mut btck_ChainParameters,
}

unsafe impl Send for ChainParams {}
unsafe impl Sync for ChainParams {}

impl ChainParams {
    pub fn new(chain_type: ChainType) -> ChainParams {
        let btck_chain_type = chain_type.into();
        ChainParams {
            inner: unsafe { btck_chain_parameters_create(btck_chain_type) },
        }
    }
}

impl Drop for ChainParams {
    fn drop(&mut self) {
        unsafe {
            btck_chain_parameters_destroy(self.inner);
        }
    }
}

/// Exposes the result after validating a block.
pub trait BlockChecked: Fn(Block, ValidationMode, BlockValidationResult) {}
impl<F: Fn(Block, ValidationMode, BlockValidationResult)> BlockChecked for F {}

/// A holder struct for validation interface callbacks
pub struct ValidationInterfaceCallbacks {
    /// Called after a block has completed validation and communicates its validation state.
    pub block_checked: Box<dyn BlockChecked>,
}

unsafe extern "C" fn vi_user_data_destroy_wrapper(user_data: *mut c_void) {
    if !user_data.is_null() {
        let _ = Box::from_raw(user_data as *mut ValidationInterfaceCallbacks);
    }
}

unsafe extern "C" fn vi_block_checked_wrapper(
    user_data: *mut c_void,
    block: *mut btck_Block,
    stateIn: *const btck_BlockValidationState,
) {
    let holder = &*(user_data as *mut ValidationInterfaceCallbacks);
    let result = btck_block_validation_state_get_block_validation_result(stateIn);
    let mode = btck_block_validation_state_get_validation_mode(stateIn);
    (holder.block_checked)(Block { inner: block }, mode.into(), result.into());
}

/// The main context struct. This should be setup through the [`ContextBuilder`] and
/// has to be kept in memory for the duration of context-dependent library
/// operations.
///
pub struct Context {
    inner: *mut btck_Context,
}

unsafe impl Send for Context {}
unsafe impl Sync for Context {}

impl Context {
    pub fn interrupt(&self) -> Result<(), KernelError> {
        let result = unsafe { btck_context_interrupt(self.inner) };
        if c_helpers::success(result) {
            return Ok(());
        } else {
            return Err(KernelError::Internal(
                "Context interrupt failed.".to_string(),
            ));
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            btck_context_destroy(self.inner);
        }
    }
}

/// Builder struct for the kernel [`Context`].
///
/// The builder by default configures for mainnet and swallows any kernel
/// notifications.
pub struct ContextBuilder {
    inner: *mut btck_ContextOptions,
}

impl Default for ContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ContextBuilder {
    pub fn new() -> ContextBuilder {
        ContextBuilder {
            inner: unsafe { btck_context_options_create() },
        }
    }

    /// Consumes the builder and creates a [`Context`].
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::Internal`] if [`Context`] creation fails.
    pub fn build(self) -> Result<Context, KernelError> {
        let inner = unsafe { btck_context_create(self.inner) };
        if inner.is_null() {
            return Err(KernelError::Internal("Invalid context.".to_string()));
        }
        unsafe { btck_context_options_destroy(self.inner) };
        Ok(Context { inner })
    }

    /// Sets the notifications callbacks to the passed in holder struct
    pub fn kn_callbacks(
        self,
        kn_callbacks: Box<KernelNotificationInterfaceCallbacks>,
    ) -> ContextBuilder {
        let kn_pointer = Box::into_raw(kn_callbacks);
        unsafe {
            let holder = btck_NotificationInterfaceCallbacks {
                user_data: kn_pointer as *mut c_void,
                user_data_destroy: Some(kn_user_data_destroy_wrapper),
                block_tip: Some(kn_block_tip_wrapper),
                header_tip: Some(kn_header_tip_wrapper),
                progress: Some(kn_progress_wrapper),
                warning_set: Some(kn_warning_set_wrapper),
                warning_unset: Some(kn_warning_unset_wrapper),
                flush_error: Some(kn_flush_error_wrapper),
                fatal_error: Some(kn_fatal_error_wrapper),
            };
            btck_context_options_set_notifications(self.inner, holder);
        };
        self
    }

    /// Sets the chain type
    pub fn chain_type(self, chain_type: ChainType) -> ContextBuilder {
        let chain_params = ChainParams::new(chain_type);
        unsafe { btck_context_options_set_chainparams(self.inner, chain_params.inner) };
        self
    }

    /// Sets the validation interface callbacks
    pub fn validation_interface(
        self,
        vi_callbacks: Box<ValidationInterfaceCallbacks>,
    ) -> ContextBuilder {
        let vi_pointer = Box::into_raw(vi_callbacks);
        unsafe {
            let holder = btck_ValidationInterfaceCallbacks {
                user_data: vi_pointer as *mut c_void,
                user_data_destroy: Some(vi_user_data_destroy_wrapper),
                block_checked: Some(vi_block_checked_wrapper),
            };
            btck_context_options_set_validation_interface(self.inner, holder);
        }
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
    SerializationFailed,
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
            | KernelError::InvalidOptions(msg) => write!(f, "{msg}"),
            _ => write!(f, "Error!"),
        }
    }
}

/// Result of data structure validation.
///
/// Indicates whether a validated data structure (block, transaction, etc.)
/// is valid, invalid, or encountered an error during processing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ValidationMode {
    /// The data structure is valid according to consensus rules
    Valid = BTCK_VALIDATION_MODE_VALID,
    /// The data structure is invalid according to consensus rules
    Invalid = BTCK_VALIDATION_MODE_INVALID,
    /// An internal error occurred during validation
    InternalError = BTCK_VALIDATION_MODE_INTERNAL_ERROR,
}

impl From<ValidationMode> for btck_ValidationMode {
    fn from(mode: ValidationMode) -> Self {
        mode as btck_ValidationMode
    }
}

impl From<btck_ValidationMode> for ValidationMode {
    fn from(value: btck_ValidationMode) -> Self {
        match value {
            BTCK_VALIDATION_MODE_VALID => ValidationMode::Valid,
            BTCK_VALIDATION_MODE_INVALID => ValidationMode::Invalid,
            BTCK_VALIDATION_MODE_INTERNAL_ERROR => ValidationMode::InternalError,
            _ => panic!("Unknown validation mode: {}", value),
        }
    }
}

/// Result of block validation.
///
/// Provides information about why a block was accepted or rejected
/// during validation. This gives more specific reasons than just valid/invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u32)]
pub enum BlockValidationResult {
    /// Initial value - block has not yet been validated
    Unset = BTCK_BLOCK_VALIDATION_RESULT_UNSET,
    /// Block is valid according to consensus rules
    Consensus = BTCK_BLOCK_VALIDATION_RESULT_CONSENSUS,
    /// Block was cached as invalid (reason not stored)
    CachedInvalid = BTCK_BLOCK_VALIDATION_RESULT_CACHED_INVALID,
    /// Block header is invalid (proof of work or timestamp)
    InvalidHeader = BTCK_BLOCK_VALIDATION_RESULT_INVALID_HEADER,
    /// Block data doesn't match the proof of work commitment
    Mutated = BTCK_BLOCK_VALIDATION_RESULT_MUTATED,
    /// Previous block is not available
    MissingPrev = BTCK_BLOCK_VALIDATION_RESULT_MISSING_PREV,
    /// Previous block is invalid
    InvalidPrev = BTCK_BLOCK_VALIDATION_RESULT_INVALID_PREV,
    /// Block timestamp is too far in the future
    TimeFuture = BTCK_BLOCK_VALIDATION_RESULT_TIME_FUTURE,
    /// Block header indicates insufficient work
    HeaderLowWork = BTCK_BLOCK_VALIDATION_RESULT_HEADER_LOW_WORK,
}

impl From<BlockValidationResult> for btck_BlockValidationResult {
    fn from(result: BlockValidationResult) -> Self {
        result as btck_BlockValidationResult
    }
}

impl From<btck_BlockValidationResult> for BlockValidationResult {
    fn from(value: btck_BlockValidationResult) -> Self {
        match value {
            BTCK_BLOCK_VALIDATION_RESULT_UNSET => BlockValidationResult::Unset,
            BTCK_BLOCK_VALIDATION_RESULT_CONSENSUS => BlockValidationResult::Consensus,
            BTCK_BLOCK_VALIDATION_RESULT_CACHED_INVALID => BlockValidationResult::CachedInvalid,
            BTCK_BLOCK_VALIDATION_RESULT_INVALID_HEADER => BlockValidationResult::InvalidHeader,
            BTCK_BLOCK_VALIDATION_RESULT_MUTATED => BlockValidationResult::Mutated,
            BTCK_BLOCK_VALIDATION_RESULT_MISSING_PREV => BlockValidationResult::MissingPrev,
            BTCK_BLOCK_VALIDATION_RESULT_INVALID_PREV => BlockValidationResult::InvalidPrev,
            BTCK_BLOCK_VALIDATION_RESULT_TIME_FUTURE => BlockValidationResult::TimeFuture,
            BTCK_BLOCK_VALIDATION_RESULT_HEADER_LOW_WORK => BlockValidationResult::HeaderLowWork,
            _ => panic!("Unknown block validation result: {}", value),
        }
    }
}

/// A single script pubkey containing spending conditions for a transaction output.
///
/// Script pubkeys can be created from raw script bytes or retrieved from existing
/// transaction outputs.
#[derive(Debug)]
pub struct ScriptPubkey {
    inner: *mut btck_ScriptPubkey,
}

unsafe impl Send for ScriptPubkey {}
unsafe impl Sync for ScriptPubkey {}

impl ScriptPubkey {
    /// Serializes the script to raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        c_serialize(|callback, user_data| unsafe {
            btck_script_pubkey_to_bytes(self.inner, Some(callback), user_data)
        })
        .expect("Script pubkey to_bytes should never fail")
    }
}

impl From<ScriptPubkey> for Vec<u8> {
    fn from(pubkey: ScriptPubkey) -> Self {
        pubkey.to_bytes()
    }
}

impl TryFrom<&[u8]> for ScriptPubkey {
    type Error = KernelError;

    fn try_from(raw_script_pubkey: &[u8]) -> Result<Self, Self::Error> {
        let inner = unsafe {
            btck_script_pubkey_create(
                raw_script_pubkey.as_ptr() as *const c_void,
                raw_script_pubkey.len(),
            )
        };
        if inner.is_null() {
            return Err(KernelError::Internal(
                "Failed to decode raw script pubkey".to_string(),
            ));
        }
        Ok(ScriptPubkey { inner })
    }
}

impl Clone for ScriptPubkey {
    fn clone(&self) -> Self {
        ScriptPubkey {
            inner: unsafe { btck_script_pubkey_copy(self.inner) },
        }
    }
}

impl Drop for ScriptPubkey {
    fn drop(&mut self) {
        unsafe { btck_script_pubkey_destroy(self.inner) }
    }
}

/// A reference type that enforces lifetime relationships.
///
/// `RefType<'a, T, L>` represents a borrowed `T` that cannot outlive the owner `L`.
///
/// # Type Parameters
/// - `'a` - The lifetime of the borrow, tied to the owner's lifetime
/// - `T` - The borrowed type (e.g., `TxOut`, `ScriptPubkey`)
/// - `L` - The owner type (e.g., `Transaction`, `TxOut`)
pub struct RefType<'a, T, L> {
    inner: T,
    marker: PhantomData<&'a L>,
}

impl<'a, T, L> RefType<'a, T, L> {
    /// Creates a new RefType wrapping referenced data.
    pub(crate) fn new(inner: T) -> Self {
        RefType {
            inner,
            marker: PhantomData,
        }
    }

    /// Creates an owned copy of the borrowed data.
    ///
    /// This calls the underlying type's `Clone` implementation to create
    /// an independent copy that can outlive the original reference.
    pub fn to_owned(&self) -> T
    where
        T: Clone,
    {
        self.inner.clone()
    }
}

impl<'a, T, L> std::ops::Deref for RefType<'a, T, L> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a, T, L> AsRef<T> for RefType<'a, T, L> {
    fn as_ref(&self) -> &T {
        &self.inner
    }
}

impl<'a, T, L> Borrow<T> for RefType<'a, T, L> {
    fn borrow(&self) -> &T {
        &self.inner
    }
}

/// A single transaction output containing a value and spending conditions.
///
/// Transaction outputs can be created from a script pubkey and amount, or retrieved
/// from existing transactions. They represent spendable coins in the UTXO set.
#[derive(Debug)]
pub struct TxOut {
    inner: *mut btck_TransactionOutput,
}

unsafe impl Send for TxOut {}
unsafe impl Sync for TxOut {}

impl TxOut {
    /// Creates a new transaction output with the specified script and amount.
    ///
    /// # Arguments
    /// * `script_pubkey` - The script defining how this output can be spent
    /// * `amount` - The amount in satoshis
    pub fn new(script_pubkey: &ScriptPubkey, amount: i64) -> TxOut {
        TxOut {
            inner: unsafe { btck_transaction_output_create(script_pubkey.inner, amount) },
        }
    }

    /// Returns the amount of this output in satoshis.
    pub fn value(&self) -> i64 {
        unsafe { btck_transaction_output_get_amount(self.inner) }
    }

    /// Returns a reference to the script pubkey that defines how this output can be spent.
    ///
    /// # Returns
    /// * `RefType<ScriptPubkey, TxOut>` - A reference to the script pubkey
    pub fn script_pubkey(&self) -> RefType<'_, ScriptPubkey, TxOut> {
        RefType::new(ScriptPubkey {
            inner: unsafe { btck_transaction_output_get_script_pubkey(self.inner) },
        })
    }
}

impl Clone for TxOut {
    fn clone(&self) -> Self {
        TxOut {
            inner: unsafe { btck_transaction_output_copy(self.inner) },
        }
    }
}

impl Drop for TxOut {
    fn drop(&mut self) {
        unsafe { btck_transaction_output_destroy(self.inner) }
    }
}

/// A Bitcoin transaction.
pub struct Transaction {
    inner: *mut btck_Transaction,
}

unsafe impl Send for Transaction {}
unsafe impl Sync for Transaction {}

impl Transaction {
    /// Returns the number of outputs in this transaction.
    pub fn output_count(&self) -> usize {
        unsafe { btck_transaction_count_outputs(self.inner) as usize }
    }

    /// Returns a reference to the output at the specified index.
    ///
    /// # Arguments
    /// * `index` - The zero-based index of the output to retrieve
    ///
    /// # Returns
    /// * `Ok(RefType<TxOut, Transaction>)` - A reference to the output
    /// * `Err(KernelError::OutOfBounds)` - If the index is invalid
    pub fn output(&self, index: usize) -> Result<RefType<'_, TxOut, Transaction>, KernelError> {
        if index >= self.output_count() {
            return Err(KernelError::OutOfBounds);
        }
        let output_ptr = unsafe { btck_transaction_get_output_at(self.inner, index) };
        Ok(RefType::new(TxOut { inner: output_ptr }))
    }

    pub fn input_count(&self) -> usize {
        unsafe { btck_transaction_count_inputs(self.inner) as usize }
    }

    /// Consensus encodes the transaction to Bitcoin wire format.
    pub fn consensus_encode(&self) -> Result<Vec<u8>, KernelError> {
        c_serialize(|callback, user_data| unsafe {
            btck_transaction_to_bytes(self.inner, Some(callback), user_data)
        })
    }
}

impl TryFrom<Transaction> for Vec<u8> {
    type Error = KernelError;

    fn try_from(tx: Transaction) -> Result<Self, Self::Error> {
        tx.consensus_encode()
    }
}

impl TryFrom<&[u8]> for Transaction {
    type Error = KernelError;

    fn try_from(raw_transaction: &[u8]) -> Result<Self, Self::Error> {
        let inner = unsafe {
            btck_transaction_create(
                raw_transaction.as_ptr() as *const c_void,
                raw_transaction.len(),
            )
        };
        if inner.is_null() {
            return Err(KernelError::Internal(
                "Failed to decode raw transaction.".to_string(),
            ));
        }
        Ok(Transaction { inner })
    }
}

impl Clone for Transaction {
    fn clone(&self) -> Self {
        Transaction {
            inner: unsafe { btck_transaction_copy(self.inner) },
        }
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        unsafe { btck_transaction_destroy(self.inner) }
    }
}

/// A Bitcoin block containing a header and transactions.
///
/// Blocks can be created from raw serialized data or retrieved from the blockchain.
/// They represent the fundamental units of the Bitcoin blockchain structure.
pub struct Block {
    inner: *mut btck_Block,
}

unsafe impl Send for Block {}
unsafe impl Sync for Block {}

impl Block {
    /// Returns the hash of this block.
    ///
    /// This is the double SHA256 hash of the block header, which serves as
    /// the block's unique identifier.
    pub fn hash(&self) -> BlockHash {
        let hash = unsafe { btck_block_get_hash(self.inner) };
        let res = BlockHash {
            hash: unsafe { (&*hash).hash },
        };
        unsafe { btck_block_hash_destroy(hash) };
        res
    }

    /// Returns the number of transactions in this block.
    pub fn transaction_count(&self) -> usize {
        unsafe { btck_block_count_transactions(self.inner) as usize }
    }

    /// Returns the transaction at the specified index.
    ///
    /// # Arguments
    /// * `index` - The zero-based index of the transaction (0 is the coinbase)
    ///
    /// # Errors
    /// Returns [`KernelError::OutOfBounds`] if the index is invalid.
    pub fn transaction(&self, index: usize) -> Result<Transaction, KernelError> {
        if index >= self.transaction_count() {
            return Err(KernelError::OutOfBounds);
        }
        let tx = unsafe { btck_block_get_transaction_at(self.inner, index) };
        Ok(Transaction { inner: tx })
    }

    /// Consensus encodes the block to Bitcoin wire format.
    pub fn consensus_encode(&self) -> Result<Vec<u8>, KernelError> {
        c_serialize(|callback, user_data| unsafe {
            btck_block_to_bytes(self.inner, Some(callback), user_data)
        })
    }
}

impl TryFrom<Block> for Vec<u8> {
    type Error = KernelError;

    fn try_from(block: Block) -> Result<Self, KernelError> {
        block.consensus_encode()
    }
}

impl TryFrom<&[u8]> for Block {
    type Error = KernelError;

    fn try_from(raw_block: &[u8]) -> Result<Self, Self::Error> {
        let inner =
            unsafe { btck_block_create(raw_block.as_ptr() as *const c_void, raw_block.len()) };
        if inner.is_null() {
            return Err(KernelError::Internal(
                "Failed to de-serialize Block.".to_string(),
            ));
        }
        Ok(Block { inner })
    }
}

impl Clone for Block {
    fn clone(&self) -> Self {
        Block {
            inner: unsafe { btck_block_copy(self.inner) },
        }
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        unsafe { btck_block_destroy(self.inner) };
    }
}

/// A block tree entry that is tied to a specific [`ChainstateManager`].
///
/// Internally the [`ChainstateManager`] keeps an in-memory of the current block
/// tree once it is loaded. The [`BlockTreeEntry`] points to an entry in this tree.
/// It is only valid as long as the [`ChainstateManager`] it was retrieved from
/// remains in scope.
#[derive(Debug)]
pub struct BlockTreeEntry {
    inner: *mut btck_BlockTreeEntry,
    marker: PhantomData<ChainstateManager>,
}

unsafe impl Send for BlockTreeEntry {}
unsafe impl Sync for BlockTreeEntry {}

/// A type for a Block hash.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct BlockHash {
    pub hash: [u8; 32],
}

impl BlockTreeEntry {
    /// Move to the previous entry in the block tree. E.g. from height n to
    /// height n-1.
    pub fn prev(self) -> Result<BlockTreeEntry, KernelError> {
        let inner = unsafe { btck_block_tree_entry_get_previous(self.inner) };

        if inner.is_null() {
            return Err(KernelError::OutOfBounds);
        }

        Ok(BlockTreeEntry {
            inner,
            marker: self.marker,
        })
    }

    /// Returns the current height associated with this BlockTreeEntry.
    pub fn height(&self) -> i32 {
        unsafe { btck_block_tree_entry_get_height(self.inner) }
    }

    /// Returns the current block hash associated with this BlockTreeEntry.
    pub fn block_hash(&self) -> BlockHash {
        let hash = unsafe { btck_block_tree_entry_get_block_hash(self.inner) };
        let res = BlockHash {
            hash: unsafe { (&*hash).hash },
        };
        unsafe { btck_block_hash_destroy(hash) };
        res
    }
}

impl Drop for BlockTreeEntry {
    fn drop(&mut self) {
        unsafe { btck_block_tree_entry_destroy(self.inner) };
    }
}

/// Spent output data for all transactions in a block.
///
/// This contains the previous outputs that were consumed by all transactions
/// in a specific block.
pub struct BlockSpentOutputs {
    inner: *mut btck_BlockSpentOutputs,
}

unsafe impl Send for BlockSpentOutputs {}
unsafe impl Sync for BlockSpentOutputs {}

impl BlockSpentOutputs {
    /// Returns the number of transactions that have spent output data.
    ///
    /// Note: This excludes the coinbase transaction, which has no inputs.
    pub fn count(&self) -> usize {
        unsafe { btck_block_spent_outputs_count(self.inner) }
    }

    /// Returns a reference to the spent outputs for a specific transaction in the block.
    ///
    /// # Arguments
    /// * `transaction_index` - The index of the transaction (0-based, excluding coinbase)
    ///
    /// # Returns
    /// * `Ok(RefType<TransactionSpentOutputs, BlockSpentOutputs>)` - A reference to the transaction's spent outputs
    /// * `Err(KernelError::OutOfBounds)` - If the index is invalid
    pub fn transaction_spent_outputs(
        &self,
        transaction_index: usize,
    ) -> Result<RefType<'_, TransactionSpentOutputs, BlockSpentOutputs>, KernelError> {
        let tx_out_ptr = unsafe {
            btck_block_spent_outputs_get_transaction_spent_outputs_at(self.inner, transaction_index)
        };
        if tx_out_ptr.is_null() {
            return Err(KernelError::OutOfBounds);
        }
        Ok(RefType::new(TransactionSpentOutputs { inner: tx_out_ptr }))
    }
}

impl Clone for BlockSpentOutputs {
    fn clone(&self) -> Self {
        BlockSpentOutputs {
            inner: unsafe { btck_block_spent_outputs_copy(self.inner) },
        }
    }
}

impl Drop for BlockSpentOutputs {
    fn drop(&mut self) {
        unsafe { btck_block_spent_outputs_destroy(self.inner) };
    }
}

/// Spent output data for a single transaction.
///
/// Contains all the coins (UTXOs) that were consumed by a specific transaction's
/// inputs, in the same order as the transaction's inputs.
pub struct TransactionSpentOutputs {
    inner: *mut btck_TransactionSpentOutputs,
}

unsafe impl Send for TransactionSpentOutputs {}
unsafe impl Sync for TransactionSpentOutputs {}

impl TransactionSpentOutputs {
    /// Returns the number of coins spent by this transaction.
    pub fn count(&self) -> usize {
        unsafe { btck_transaction_spent_outputs_count(self.inner) }
    }

    /// Returns a reference to the coin at the specified input index.
    ///
    /// # Arguments
    /// * `coin_index` - The index corresponding to the transaction input
    ///
    /// # Returns
    /// * `Ok(RefType<Coin, TransactionSpentOutputs>)` - A reference to the coin
    /// * `Err(KernelError::OutOfBounds)` - If the index is invalid
    pub fn coin(
        &self,
        coin_index: usize,
    ) -> Result<RefType<'_, Coin, TransactionSpentOutputs>, KernelError> {
        let coin_ptr = unsafe {
            btck_transaction_spent_outputs_get_coin_at(self.inner as *const _, coin_index)
        };
        if coin_ptr.is_null() {
            return Err(KernelError::OutOfBounds);
        }

        Ok(RefType::new(Coin { inner: coin_ptr }))
    }
}

impl Clone for TransactionSpentOutputs {
    fn clone(&self) -> Self {
        TransactionSpentOutputs {
            inner: unsafe { btck_transaction_spent_outputs_copy(self.inner) },
        }
    }
}

impl Drop for TransactionSpentOutputs {
    fn drop(&mut self) {
        unsafe { btck_transaction_spent_outputs_destroy(self.inner) };
    }
}

/// A coin (UTXO) representing a transaction output.
///
/// Contains the transaction output data along with metadata about when
/// it was created and whether it came from a coinbase transaction.
pub struct Coin {
    inner: *mut btck_Coin,
}

unsafe impl Send for Coin {}
unsafe impl Sync for Coin {}

impl Coin {
    /// Returns the height of the block where this coin was created.
    pub fn confirmation_height(&self) -> u32 {
        unsafe { btck_coin_confirmation_height(self.inner) }
    }

    /// Returns true if this coin came from a coinbase transaction.
    pub fn is_coinbase(&self) -> bool {
        let result = unsafe { btck_coin_is_coinbase(self.inner) };
        c_helpers::present(result)
    }

    /// Returns a reference to the transaction output data for this coin.
    ///
    /// # Returns
    /// * `Ok(RefType<TxOut, Coin>)` - A reference to the transaction output
    /// * `Err(KernelError::Internal)` - If the coin data is corrupted
    pub fn output(&self) -> Result<RefType<'_, TxOut, Coin>, KernelError> {
        let output_ptr = unsafe { btck_coin_get_output(self.inner) };
        if output_ptr.is_null() {
            return Err(KernelError::Internal(
                "Unexpected null pointer from btck_coin_get_output".to_string(),
            ));
        }
        Ok(RefType::new(TxOut { inner: output_ptr }))
    }
}

impl Clone for Coin {
    fn clone(&self) -> Self {
        Coin {
            inner: unsafe { btck_coin_copy(self.inner) },
        }
    }
}

impl Drop for Coin {
    fn drop(&mut self) {
        unsafe { btck_coin_destroy(self.inner) };
    }
}

/// Holds the configuration options for creating a new [`ChainstateManager`]
pub struct ChainstateManagerOptions {
    inner: *mut btck_ChainstateManagerOptions,
}

impl ChainstateManagerOptions {
    /// Create a new option
    ///
    /// # Arguments
    /// * `context` -  The [`ChainstateManager`] for which these options are created has to use the same [`Context`].
    /// * `data_dir` - The directory into which the [`ChainstateManager`] will write its data.
    pub fn new(context: &Context, data_dir: &str, blocks_dir: &str) -> Result<Self, KernelError> {
        let c_data_dir = CString::new(data_dir)?;
        let c_blocks_dir = CString::new(blocks_dir)?;
        let inner = unsafe {
            btck_chainstate_manager_options_create(
                context.inner,
                c_data_dir.as_ptr(),
                c_data_dir.as_bytes().len(),
                c_blocks_dir.as_ptr(),
                c_blocks_dir.as_bytes().len(),
            )
        };
        if inner.is_null() {
            return Err(KernelError::Internal(
                "Failed to create chainstate manager options.".to_string(),
            ));
        }
        Ok(Self { inner })
    }

    /// Set the number of worker threads used by script validation
    pub fn set_worker_threads(&self, worker_threads: i32) {
        unsafe {
            btck_chainstate_manager_options_set_worker_threads_num(self.inner, worker_threads);
        }
    }

    /// Wipe the block tree or chainstate dbs. When wiping the block tree db the
    /// chainstate db has to be wiped too. Wiping the databases will triggere a
    /// rebase once import blocks is called.
    pub fn set_wipe_db(self, wipe_block_tree: bool, wipe_chainstate: bool) -> Self {
        unsafe {
            btck_chainstate_manager_options_set_wipe_dbs(
                self.inner,
                c_helpers::to_c_bool(wipe_block_tree),
                c_helpers::to_c_bool(wipe_chainstate),
            );
        }
        self
    }

    /// Run the block tree db in-memory only. No database files will be written to disk.
    pub fn set_block_tree_db_in_memory(self, block_tree_db_in_memory: bool) -> Self {
        unsafe {
            btck_chainstate_manager_options_set_block_tree_db_in_memory(
                self.inner,
                c_helpers::to_c_bool(block_tree_db_in_memory),
            );
        }
        self
    }

    /// Run the chainstate db in-memory only. No database files will be written to disk.
    pub fn set_chainstate_db_in_memory(self, chainstate_db_in_memory: bool) -> Self {
        unsafe {
            btck_chainstate_manager_options_set_chainstate_db_in_memory(
                self.inner,
                c_helpers::to_c_bool(chainstate_db_in_memory),
            );
        }
        self
    }
}

impl Drop for ChainstateManagerOptions {
    fn drop(&mut self) {
        unsafe {
            btck_chainstate_manager_options_destroy(self.inner);
        }
    }
}

/// Iterator for traversing blocks sequentially from genesis to tip.
pub struct ChainIterator<'a> {
    chain: &'a Chain,
    current: Option<BlockTreeEntry>,
}

impl<'a> ChainIterator<'a> {
    fn new(chain: &'a Chain, start: Option<BlockTreeEntry>) -> Self {
        Self {
            chain,
            current: start,
        }
    }
}

impl<'a> Iterator for ChainIterator<'a> {
    type Item = BlockTreeEntry;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(current_entry) = self.current.take() {
            self.current = self.chain.next(&current_entry);

            Some(current_entry)
        } else {
            None
        }
    }
}

/// Represents a chain instance for querying and traversal.
pub struct Chain {
    inner: *mut btck_Chain,
    marker: PhantomData<ChainstateManager>,
}

impl Chain {
    /// Returns the tip (highest block) of the active chain.
    pub fn tip(&self) -> BlockTreeEntry {
        BlockTreeEntry {
            inner: unsafe { btck_chain_get_tip(self.inner) },
            marker: PhantomData,
        }
    }

    /// Returns the genesis block (height 0) of the chain.
    pub fn genesis(&self) -> BlockTreeEntry {
        BlockTreeEntry {
            inner: unsafe { btck_chain_get_genesis(self.inner) },
            marker: PhantomData,
        }
    }

    /// Returns the block at the specified height, if it exists.
    pub fn at_height(&self, height: usize) -> Option<BlockTreeEntry> {
        let tip_height = self.tip().height();
        if height > tip_height as usize {
            return None;
        }

        let entry = unsafe { btck_chain_get_by_height(self.inner, height as i32) };
        if entry.is_null() {
            return None;
        }

        Some(BlockTreeEntry {
            inner: entry,
            marker: PhantomData,
        })
    }

    /// Returns the next block after the given entry.
    pub fn next(&self, entry: &BlockTreeEntry) -> Option<BlockTreeEntry> {
        self.at_height((entry.height() + 1) as usize)
    }

    /// Checks if the given block entry is part of the active chain.
    pub fn contains(&self, entry: &BlockTreeEntry) -> bool {
        let result = unsafe { btck_chain_contains(self.inner, entry.inner) };
        c_helpers::present(result)
    }

    /// Returns an iterator over all blocks from genesis to tip.
    pub fn iter(&self) -> ChainIterator<'_> {
        let genesis = self.genesis();
        ChainIterator::new(self, Some(genesis))
    }
}

impl Drop for Chain {
    fn drop(&mut self) {
        unsafe { btck_chain_destroy(self.inner) }
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
    inner: *mut btck_ChainstateManager,
}

unsafe impl Send for ChainstateManager {}
unsafe impl Sync for ChainstateManager {}

impl ChainstateManager {
    pub fn new(chainman_opts: ChainstateManagerOptions) -> Result<Self, KernelError> {
        let inner = unsafe { btck_chainstate_manager_create(chainman_opts.inner) };
        if inner.is_null() {
            return Err(KernelError::Internal(
                "Failed to create chainstate manager.".to_string(),
            ));
        }
        Ok(Self { inner })
    }

    /// Process and validate the passed in block with the [`ChainstateManager`]
    /// If processing failed, some information can be retrieved through the status
    /// enumeration. More detailed validation information in case of a failure can
    /// also be retrieved through a registered validation interface. If the block
    /// fails to validate the `block_checked` callback's ['BlockValidationState'] will
    /// contain details.
    pub fn process_block(&self, block: &Block) -> (bool /* accepted */, bool /* duplicate */) {
        let mut new_block: i32 = 0;
        let accepted = unsafe {
            btck_chainstate_manager_process_block(self.inner, block.inner, &mut new_block)
        };
        (c_helpers::success(accepted), c_helpers::enabled(new_block))
    }

    /// May be called after load_chainstate to initialize the
    /// [`ChainstateManager`]. Triggers the start of a reindex if the option was
    /// previously set for the chainstate and block manager. Can also import an
    /// array of existing block files selected by the user.
    pub fn import_blocks(&self) -> Result<(), KernelError> {
        let result = unsafe {
            btck_chainstate_manager_import_blocks(
                self.inner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            )
        };
        match c_helpers::success(result) {
            true => Ok(()),
            false => Err(KernelError::Internal(
                "Failed to import blocks.".to_string(),
            )),
        }
    }

    /// Read a block from disk by its block tree entry.
    pub fn read_block_data(&self, entry: &BlockTreeEntry) -> Result<Block, KernelError> {
        let inner = unsafe { btck_block_read(self.inner, entry.inner) };
        if inner.is_null() {
            return Err(KernelError::Internal("Failed to read block.".to_string()));
        }
        Ok(Block { inner })
    }

    /// Read a block's spent outputs data from disk by its block tree entry.
    pub fn read_spent_outputs(
        &self,
        entry: &BlockTreeEntry,
    ) -> Result<BlockSpentOutputs, KernelError> {
        let inner = unsafe { btck_block_spent_outputs_read(self.inner, entry.inner) };
        if inner.is_null() {
            return Err(KernelError::Internal(
                "Failed to read undo data.".to_string(),
            ));
        }
        Ok(BlockSpentOutputs { inner })
    }

    pub fn active_chain(&self) -> Chain {
        Chain {
            inner: unsafe { btck_chainstate_manager_get_active_chain(self.inner) },
            marker: PhantomData,
        }
    }
}

impl Drop for ChainstateManager {
    fn drop(&mut self) {
        unsafe {
            btck_chainstate_manager_destroy(self.inner);
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
    message_len: usize,
) {
    let message = unsafe { cast_string(message, message_len) };
    let log = user_data as *mut T;
    (*log).log(&message);
}

unsafe extern "C" fn destroy_log_callback<T>(user_data: *mut c_void) {
    if !user_data.is_null() {
        let _ = Box::from_raw(user_data as *mut T);
    }
}

/// The logger object logs kernel log messages into a user-defined log function.
/// Messages logged by the kernel before this object is created are buffered in
/// a 1MB buffer. The kernel library internally uses a global logging instance.
pub struct Logger {
    inner: *mut btck_LoggingConnection,
}

impl Drop for Logger {
    fn drop(&mut self) {
        unsafe {
            btck_logging_connection_destroy(self.inner);
        }
    }
}

/// Permanently disable logging and stop buffering.
pub fn disable_logging() {
    unsafe {
        btck_logging_disable();
    }
}

impl Logger {
    /// Create a new Logger with the specified callback.
    pub fn new<T: Log + 'static>(log: T) -> Result<Logger, KernelError> {
        let options = btck_LoggingOptions {
            log_timestamps: c_helpers::to_c_bool(true),
            log_time_micros: c_helpers::to_c_bool(false),
            log_threadnames: c_helpers::to_c_bool(false),
            log_sourcelocations: c_helpers::to_c_bool(false),
            always_print_category_levels: c_helpers::to_c_bool(false),
        };

        let log_ptr = Box::into_raw(Box::new(log));

        let inner = unsafe {
            btck_logging_connection_create(
                Some(log_callback::<T>),
                log_ptr as *mut c_void,
                Some(destroy_log_callback::<T>),
                options,
            )
        };

        if inner.is_null() {
            unsafe {
                let _ = Box::from_raw(log_ptr);
            }
            return Err(KernelError::Internal(
                "Failed to create new logging connection.".to_string(),
            ));
        }

        Ok(Logger { inner })
    }

    /// Sets the logging level for a specific category.
    pub fn set_level_category(&self, category: LogCategory, level: LogLevel) {
        unsafe {
            btck_logging_set_level_category(category.into(), level.into());
        }
    }

    /// Enables logging for a specific category.
    pub fn enable_category(&self, category: LogCategory) {
        unsafe {
            btck_logging_enable_category(category.into());
        }
    }

    /// Disables logging for a specific category.
    pub fn disable_category(&self, category: LogCategory) {
        unsafe {
            btck_logging_disable_category(category.into());
        }
    }
}

/// Logging categories for Bitcoin Kernel messages.
///
/// Controls which types of log messages are emitted by the kernel library.
/// Categories can be combined to enable multiple types of logging simultaneously.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LogCategory {
    /// All logging categories enabled
    All = BTCK_LOG_CATEGORY_ALL,
    /// Benchmark and performance logging
    Bench = BTCK_LOG_CATEGORY_BENCH,
    /// Block storage operations
    BlockStorage = BTCK_LOG_CATEGORY_BLOCKSTORAGE,
    /// Coin database operations
    CoinDb = BTCK_LOG_CATEGORY_COINDB,
    /// LevelDB operations
    LevelDb = BTCK_LOG_CATEGORY_LEVELDB,
    /// Memory pool operations
    Mempool = BTCK_LOG_CATEGORY_MEMPOOL,
    /// Block pruning operations
    Prune = BTCK_LOG_CATEGORY_PRUNE,
    /// Random number generation
    Rand = BTCK_LOG_CATEGORY_RAND,
    /// Block reindexing operations
    Reindex = BTCK_LOG_CATEGORY_REINDEX,
    /// Block and transaction validation
    Validation = BTCK_LOG_CATEGORY_VALIDATION,
    /// Kernel-specific operations
    Kernel = BTCK_LOG_CATEGORY_KERNEL,
}

impl From<LogCategory> for btck_LogCategory {
    fn from(category: LogCategory) -> Self {
        category as btck_LogCategory
    }
}

impl From<btck_LogCategory> for LogCategory {
    fn from(value: btck_LogCategory) -> Self {
        match value {
            BTCK_LOG_CATEGORY_ALL => LogCategory::All,
            BTCK_LOG_CATEGORY_BENCH => LogCategory::Bench,
            BTCK_LOG_CATEGORY_BLOCKSTORAGE => LogCategory::BlockStorage,
            BTCK_LOG_CATEGORY_COINDB => LogCategory::CoinDb,
            BTCK_LOG_CATEGORY_LEVELDB => LogCategory::LevelDb,
            BTCK_LOG_CATEGORY_MEMPOOL => LogCategory::Mempool,
            BTCK_LOG_CATEGORY_PRUNE => LogCategory::Prune,
            BTCK_LOG_CATEGORY_RAND => LogCategory::Rand,
            BTCK_LOG_CATEGORY_REINDEX => LogCategory::Reindex,
            BTCK_LOG_CATEGORY_VALIDATION => LogCategory::Validation,
            BTCK_LOG_CATEGORY_KERNEL => LogCategory::Kernel,
            _ => panic!("Unknown log category: {}", value),
        }
    }
}

/// Logging levels for controlling message verbosity.
///
/// Determines the minimum severity level of messages that will be logged.
/// Higher levels include all messages from lower levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LogLevel {
    /// Detailed trace information for debugging
    Trace = BTCK_LOG_LEVEL_TRACE,
    /// Debug information for development
    Debug = BTCK_LOG_LEVEL_DEBUG,
    /// General informational messages
    Info = BTCK_LOG_LEVEL_INFO,
}

impl From<LogLevel> for btck_LogLevel {
    fn from(level: LogLevel) -> Self {
        level as btck_LogLevel
    }
}

impl From<btck_LogLevel> for LogLevel {
    fn from(value: btck_LogLevel) -> Self {
        match value {
            BTCK_LOG_LEVEL_TRACE => LogLevel::Trace,
            BTCK_LOG_LEVEL_DEBUG => LogLevel::Debug,
            BTCK_LOG_LEVEL_INFO => LogLevel::Info,
            _ => panic!("Unknown log level: {}", value),
        }
    }
}
