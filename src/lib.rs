#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::borrow::Borrow;
use std::ffi::{CString, NulError};
use std::fmt;
use std::marker::PhantomData;
use std::os::raw::{c_char, c_void};

use libbitcoinkernel_sys::*;

#[allow(clippy::unnecessary_cast)]
pub const VERIFY_NONE: u32 = btck_ScriptFlags_btck_SCRIPT_FLAGS_VERIFY_NONE as u32;
#[allow(clippy::unnecessary_cast)]
pub const VERIFY_P2SH: u32 = btck_ScriptFlags_btck_SCRIPT_FLAGS_VERIFY_P2SH as u32;
#[allow(clippy::unnecessary_cast)]
pub const VERIFY_DERSIG: u32 = btck_ScriptFlags_btck_SCRIPT_FLAGS_VERIFY_DERSIG as u32;
#[allow(clippy::unnecessary_cast)]
pub const VERIFY_NULLDUMMY: u32 = btck_ScriptFlags_btck_SCRIPT_FLAGS_VERIFY_NULLDUMMY as u32;
#[allow(clippy::unnecessary_cast)]
pub const VERIFY_CHECKLOCKTIMEVERIFY: u32 =
    btck_ScriptFlags_btck_SCRIPT_FLAGS_VERIFY_CHECKLOCKTIMEVERIFY as u32;
#[allow(clippy::unnecessary_cast)]
pub const VERIFY_CHECKSEQUENCEVERIFY: u32 =
    btck_ScriptFlags_btck_SCRIPT_FLAGS_VERIFY_CHECKSEQUENCEVERIFY as u32;
#[allow(clippy::unnecessary_cast)]
pub const VERIFY_WITNESS: u32 = btck_ScriptFlags_btck_SCRIPT_FLAGS_VERIFY_WITNESS as u32;
#[allow(clippy::unnecessary_cast)]
pub const VERIFY_TAPROOT: u32 = btck_ScriptFlags_btck_SCRIPT_FLAGS_VERIFY_TAPROOT as u32;
#[allow(clippy::unnecessary_cast)]
pub const VERIFY_ALL: u32 = btck_ScriptFlags_btck_SCRIPT_FLAGS_VERIFY_ALL as u32;
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
    input_index: usize,
    flags: Option<u32>,
    spent_outputs: &[TxOut],
) -> Result<(), KernelError> {
    let input_count = tx_to.input_count();

    if input_index >= input_count {
        return Err(KernelError::OutOfBounds);
    }

    if !spent_outputs.is_empty() && spent_outputs.len() != input_count {
        return Err(KernelError::OutOfBounds);
    }

    let kernel_flags = if let Some(flag) = flags {
        flag
    } else {
        VERIFY_ALL
    };
    let mut status = btck_ScriptVerifyStatus_btck_SCRIPT_VERIFY_OK;
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
            &mut status,
        )
    };

    if !ret {
        let err = match status {
            btck_ScriptVerifyStatus_btck_SCRIPT_VERIFY_ERROR_INVALID_FLAGS => {
                ScriptVerifyError::InvalidFlags
            }
            btck_ScriptVerifyStatus_btck_SCRIPT_VERIFY_ERROR_INVALID_FLAGS_COMBINATION => {
                ScriptVerifyError::InvalidFlagsCombination
            }
            btck_ScriptVerifyStatus_btck_SCRIPT_VERIFY_ERROR_SPENT_OUTPUTS_REQUIRED => {
                ScriptVerifyError::SpentOutputsRequired
            }
            _ => ScriptVerifyError::Invalid,
        };
        Err(KernelError::ScriptVerify(err))
    } else {
        Ok(())
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

/// The current synch state, i.e. whether in reindex, ibd, or complete.
/// Emitted by the block tip notification.
#[derive(Debug)]
pub enum SynchronizationState {
    INIT_REINDEX,
    INIT_DOWNLOAD,
    POST_INIT,
}

impl From<btck_SynchronizationState> for SynchronizationState {
    fn from(state: btck_SynchronizationState) -> SynchronizationState {
        match state {
            btck_SynchronizationState_btck_INIT_DOWNLOAD => SynchronizationState::INIT_DOWNLOAD,
            btck_SynchronizationState_btck_INIT_REINDEX => SynchronizationState::INIT_REINDEX,
            btck_SynchronizationState_btck_POST_INIT => SynchronizationState::POST_INIT,
            _ => panic!("Unexpected Synchronization state"),
        }
    }
}

/// Warning state emitted by the kernel warning notification.
pub enum KernelWarning {
    UNKNOWN_NEW_RULES_ACTIVATED,
    LARGE_WORK_INVALID_CHAIN,
}

impl From<btck_Warning> for KernelWarning {
    fn from(warning: btck_Warning) -> KernelWarning {
        match warning {
            btck_Warning_btck_UNKNOWN_NEW_RULES_ACTIVATED => {
                KernelWarning::UNKNOWN_NEW_RULES_ACTIVATED
            }
            btck_Warning_btck_LARGE_WORK_INVALID_CHAIN => KernelWarning::LARGE_WORK_INVALID_CHAIN,
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

impl From<ChainType> for btck_ChainType {
    fn from(chain: ChainType) -> btck_ChainType {
        match chain {
            ChainType::MAINNET => btck_ChainType_btck_CHAIN_TYPE_MAINNET,
            ChainType::TESTNET => btck_ChainType_btck_CHAIN_TYPE_TESTNET,
            ChainType::SIGNET => btck_ChainType_btck_CHAIN_TYPE_SIGNET,
            ChainType::REGTEST => btck_ChainType_btck_CHAIN_TYPE_REGTEST,
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
pub trait WarningSet: Fn(KernelWarning, String) {}
impl<F: Fn(KernelWarning, String)> WarningSet for F {}

/// A previous condition leading to the issuance of a warning is no longer given.
pub trait WarningUnset: Fn(KernelWarning) {}
impl<F: Fn(KernelWarning)> WarningUnset for F {}

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

unsafe extern "C" fn kn_block_tip_wrapper(
    user_data: *mut c_void,
    state: btck_SynchronizationState,
    block_index: *const btck_BlockIndex,
    verification_progress: f64,
) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbacks);
    let hash = btck_block_index_get_block_hash(block_index);
    let res = BlockHash { hash: (*hash).hash };
    btck_block_hash_destroy(hash);
    (holder.kn_block_tip)(state.into(), res, verification_progress);
}

unsafe extern "C" fn kn_header_tip_wrapper(
    user_data: *mut c_void,
    state: btck_SynchronizationState,
    height: i64,
    timestamp: i64,
    presync: bool,
) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbacks);
    (holder.kn_header_tip)(state.into(), height, timestamp, presync);
}

unsafe extern "C" fn kn_progress_wrapper(
    user_data: *mut c_void,
    title: *const c_char,
    title_len: usize,
    progress_percent: i32,
    resume_possible: bool,
) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbacks);
    (holder.kn_progress)(
        cast_string(title, title_len),
        progress_percent,
        resume_possible,
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
pub trait BlockChecked: Fn(UnownedBlock, ValidationMode, BlockValidationResult) {}
impl<F: Fn(UnownedBlock, ValidationMode, BlockValidationResult)> BlockChecked for F {}

/// A holder struct for validation interface callbacks
pub struct ValidationInterfaceCallbacks {
    /// Called after a block has completed validation and communicates its validation state.
    pub block_checked: Box<dyn BlockChecked>,
}

unsafe extern "C" fn vi_block_checked_wrapper(
    user_data: *mut c_void,
    block: *const btck_BlockPointer,
    stateIn: *const btck_BlockValidationState,
) {
    let holder = &*(user_data as *mut ValidationInterfaceCallbacks);
    let result = btck_block_validation_state_get_block_validation_result(stateIn);
    let mode = btck_block_validation_state_get_validation_mode(stateIn);
    (holder.block_checked)(UnownedBlock::new(block), mode.into(), result.into());
}

/// The main context struct. This should be setup through the [`ContextBuilder`] and
/// has to be kept in memory for the duration of context-dependent library
/// operations.
///
pub struct Context {
    inner: *mut btck_Context,
    // We need something to hold this in memory.
    #[allow(dead_code)]
    kn_callbacks: Option<Box<KernelNotificationInterfaceCallbacks>>,
    #[allow(dead_code)]
    vi_callbacks: Option<Box<ValidationInterfaceCallbacks>>,
}

unsafe impl Send for Context {}
unsafe impl Sync for Context {}

impl Context {
    pub fn interrupt(&self) -> bool {
        unsafe { btck_context_interrupt(self.inner) }
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
    kn_callbacks: Option<Box<KernelNotificationInterfaceCallbacks>>,
    vi_callbacks: Option<Box<ValidationInterfaceCallbacks>>,
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
            kn_callbacks: None,
            vi_callbacks: None,
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
        Ok(Context {
            inner,
            kn_callbacks: self.kn_callbacks,
            vi_callbacks: self.vi_callbacks,
        })
    }

    /// Sets the notifications callbacks to the passed in holder struct
    pub fn kn_callbacks(
        mut self,
        kn_callbacks: Box<KernelNotificationInterfaceCallbacks>,
    ) -> ContextBuilder {
        let kn_pointer = Box::into_raw(kn_callbacks);
        unsafe {
            let holder = btck_NotificationInterfaceCallbacks {
                user_data: kn_pointer as *mut c_void,
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
        self.kn_callbacks = unsafe { Some(Box::from_raw(kn_pointer)) };
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
        mut self,
        vi_callbacks: Box<ValidationInterfaceCallbacks>,
    ) -> ContextBuilder {
        let vi_pointer = Box::into_raw(vi_callbacks);
        unsafe {
            let holder = btck_ValidationInterfaceCallbacks {
                user_data: vi_pointer as *mut c_void,
                block_checked: Some(vi_block_checked_wrapper),
            };
            btck_context_options_set_validation_interface(self.inner, holder);
        }
        self.vi_callbacks = unsafe { Some(Box::from_raw(vi_pointer)) };
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
            | KernelError::InvalidOptions(msg) => write!(f, "{msg}"),
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

impl From<btck_ValidationMode> for ValidationMode {
    fn from(mode: btck_ValidationMode) -> Self {
        match mode {
            btck_ValidationMode_btck_VALIDATION_STATE_VALID => Self::VALID,
            btck_ValidationMode_btck_VALIDATION_STATE_INVALID => Self::INVALID,
            btck_ValidationMode_btck_VALIDATION_STATE_ERROR => Self::ERROR,
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
    /// the block header may be on a too-little-work chain
    HEADER_LOW_WORK,
}

impl From<btck_BlockValidationResult> for BlockValidationResult {
    fn from(res: btck_BlockValidationResult) -> Self {
        match res {
            btck_BlockValidationResult_btck_BLOCK_RESULT_UNSET => Self::RESULT_UNSET,
            btck_BlockValidationResult_btck_BLOCK_CONSENSUS => Self::CONSENSUS,
            btck_BlockValidationResult_btck_BLOCK_CACHED_INVALID => Self::CACHED_INVALID,
            btck_BlockValidationResult_btck_BLOCK_INVALID_HEADER => Self::INVALID_HEADER,
            btck_BlockValidationResult_btck_BLOCK_MUTATED => Self::MUTATED,
            btck_BlockValidationResult_btck_BLOCK_MISSING_PREV => Self::MISSING_PREV,
            btck_BlockValidationResult_btck_BLOCK_INVALID_PREV => Self::INVALID_PREV,
            btck_BlockValidationResult_btck_BLOCK_TIME_FUTURE => Self::TIME_FUTURE,
            btck_BlockValidationResult_btck_BLOCK_HEADER_LOW_WORK => Self::HEADER_LOW_WORK,
            _ => Self::CONSENSUS,
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
    /// Returns the raw script bytes.
    ///
    /// This creates a copy of the underlying script data in the format
    /// used for script execution and storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        let script_pubkey = unsafe { btck_script_pubkey_copy_data(self.inner) };
        let res =
            unsafe { std::slice::from_raw_parts((*script_pubkey).data, (*script_pubkey).size) }
                .to_vec();
        unsafe { btck_byte_array_destroy(script_pubkey) };
        res
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
            btck_script_pubkey_create(raw_script_pubkey.as_ptr(), raw_script_pubkey.len())
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
        let output_ptr = unsafe { btck_transaction_get_output_at(self.inner, index as u64) };
        Ok(RefType::new(TxOut { inner: output_ptr }))
    }

    pub fn input_count(&self) -> usize {
        unsafe { btck_transaction_count_inputs(self.inner) as usize }
    }
}

unsafe impl Send for Transaction {}
unsafe impl Sync for Transaction {}

impl TryFrom<&[u8]> for Transaction {
    type Error = KernelError;

    fn try_from(raw_transaction: &[u8]) -> Result<Self, Self::Error> {
        let inner =
            unsafe { btck_transaction_create(raw_transaction.as_ptr(), raw_transaction.len()) };
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

/// A reference to block data owned by the Bitcoin Kernel infrastructure.
///
/// UnownedBlocks provide read-only access without taking ownership of the underlying memory.
/// They are typically received through validation callbacks and should be used immediately.
pub struct UnownedBlock {
    inner: *const btck_BlockPointer,
}

impl UnownedBlock {
    fn new(block: *const btck_BlockPointer) -> UnownedBlock {
        UnownedBlock { inner: block }
    }

    /// Returns the hash of this block.
    ///
    /// This is the double SHA256 hash of the block header.
    pub fn hash(&self) -> BlockHash {
        let hash = unsafe { btck_block_pointer_get_hash(self.inner) };
        let res = BlockHash {
            hash: unsafe { (&*hash).hash },
        };
        unsafe { btck_block_hash_destroy(hash) };
        res
    }

    /// Returns the raw block data as bytes.
    ///
    /// This creates a copy of the entire block (header + transactions) in the format
    /// used for network transmission and storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        let raw_block = unsafe { btck_block_pointer_copy_data(self.inner) };
        let vec =
            unsafe { std::slice::from_raw_parts((*raw_block).data, (*raw_block).size) }.to_vec();
        unsafe { btck_byte_array_destroy(raw_block) }
        vec
    }
}

impl From<UnownedBlock> for Vec<u8> {
    fn from(block: UnownedBlock) -> Self {
        block.to_bytes()
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
        let tx = unsafe { btck_block_get_transaction_at(self.inner, index as u64) };
        Ok(Transaction { inner: tx })
    }

    /// Returns the raw block data as bytes.
    ///
    /// This creates a copy of the entire block (header + transactions) in the format
    /// used for network transmission and storage.
    pub fn to_bytes(&self) -> Vec<u8> {
        let raw_block = unsafe { btck_block_copy_data(self.inner) };
        let vec =
            unsafe { std::slice::from_raw_parts((*raw_block).data, (*raw_block).size) }.to_vec();
        unsafe { btck_byte_array_destroy(raw_block) };
        vec
    }
}

impl From<Block> for Vec<u8> {
    fn from(block: Block) -> Vec<u8> {
        block.to_bytes()
    }
}

impl TryFrom<&[u8]> for Block {
    type Error = KernelError;

    fn try_from(raw_block: &[u8]) -> Result<Self, Self::Error> {
        let inner = unsafe { btck_block_create(raw_block.as_ptr(), raw_block.len()) };
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

/// A block index that is tied to a specific [`ChainstateManager`].
///
/// Internally the [`ChainstateManager`] keeps an in-memory of the current block
/// tree once it is loaded. The [`BlockIndex`] points to an entry in this tree.
/// It is only valid as long as the [`ChainstateManager`] it was retrieved from
/// remains in scope.
pub struct BlockIndex {
    inner: *mut btck_BlockIndex,
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
        let inner = unsafe { btck_block_index_get_previous(self.inner) };
        if inner.is_null() {
            return Err(KernelError::OutOfBounds);
        }
        unsafe { btck_block_index_destroy(self.inner) };
        Ok(BlockIndex {
            inner,
            marker: self.marker,
        })
    }

    /// Returns the current height associated with this BlockIndex.
    pub fn height(&self) -> i32 {
        unsafe { btck_block_index_get_height(self.inner) }
    }

    /// Returns the current block hash associated with this BlockIndex.
    pub fn block_hash(&self) -> BlockHash {
        let hash = unsafe { btck_block_index_get_block_hash(self.inner) };
        let res = BlockHash {
            hash: unsafe { (&*hash).hash },
        };
        unsafe { btck_block_hash_destroy(hash) };
        res
    }
}

impl Drop for BlockIndex {
    fn drop(&mut self) {
        unsafe { btck_block_index_destroy(self.inner) };
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
        unsafe { btck_block_spent_outputs_size(self.inner) as usize }
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
            btck_block_spent_outputs_get_transaction_spent_outputs_at(
                self.inner,
                transaction_index as u64,
            )
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
        unsafe { btck_transaction_spent_outputs_size(self.inner) as usize }
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
            btck_transaction_spent_outputs_get_coin_at(self.inner as *const _, coin_index as u64)
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
        unsafe { btck_coin_is_coinbase(self.inner) }
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
                wipe_block_tree,
                wipe_chainstate,
            );
        }
        self
    }

    /// Run the block tree db in-memory only. No database files will be written to disk.
    pub fn set_block_tree_db_in_memory(self, block_tree_db_in_memory: bool) -> Self {
        unsafe {
            btck_chainstate_manager_options_set_block_tree_db_in_memory(
                self.inner,
                block_tree_db_in_memory,
            );
        }
        self
    }

    /// Run the chainstate db in-memory only. No database files will be written to disk.
    pub fn set_chainstate_db_in_memory(self, chainstate_db_in_memory: bool) -> Self {
        unsafe {
            btck_chainstate_manager_options_set_chainstate_db_in_memory(
                self.inner,
                chainstate_db_in_memory,
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
        let mut new_block = true;
        let accepted = unsafe {
            btck_chainstate_manager_process_block(self.inner, block.inner, &mut new_block)
        };
        (accepted, new_block)
    }

    /// May be called after load_chainstate to initialize the
    /// [`ChainstateManager`]. Triggers the start of a reindex if the option was
    /// previously set for the chainstate and block manager. Can also import an
    /// array of existing block files selected by the user.
    pub fn import_blocks(&self) -> Result<(), KernelError> {
        if !unsafe {
            btck_chainstate_manager_import_blocks(
                self.inner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            )
        } {
            return Err(KernelError::Internal(
                "Failed to import blocks.".to_string(),
            ));
        }
        Ok(())
    }

    /// Returns the block index entry of the current chain tip.
    ///
    /// Once returned, there is no guarantee that it remains in the active chain.
    pub fn block_index_tip(&self) -> BlockIndex {
        BlockIndex {
            inner: unsafe { btck_block_index_get_tip(self.inner) },
            marker: PhantomData,
        }
    }

    /// Returns the block index entry of the genesis block.
    pub fn block_index_genesis(&self) -> BlockIndex {
        BlockIndex {
            inner: unsafe { btck_block_index_get_genesis(self.inner) },
            marker: PhantomData,
        }
    }

    /// Retrieve a block index by its height in the currently active chain.
    ///
    /// Once retrieved there is no guarantee that it remains in the active chain.
    pub fn block_index_by_height(&self, block_height: i32) -> Result<BlockIndex, KernelError> {
        let inner = unsafe { btck_block_index_get_by_height(self.inner, block_height) };
        if inner.is_null() {
            return Err(KernelError::OutOfBounds);
        }
        Ok(BlockIndex {
            inner,
            marker: PhantomData,
        })
    }

    /// Returns a block index entry by its hash.
    pub fn block_index_by_hash(&self, hash: BlockHash) -> Result<BlockIndex, KernelError> {
        let mut block_hash = btck_BlockHash { hash: hash.hash };
        let inner = unsafe { btck_block_index_get_by_hash(self.inner, &mut block_hash) };
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

    /// Returns the next block index entry in the chain.
    ///
    /// If this is the tip or otherwise a leaf in the block tree, returns an error.
    pub fn next_block_index(&self, block_index: BlockIndex) -> Result<BlockIndex, KernelError> {
        let inner = unsafe { btck_block_index_get_next(self.inner, block_index.inner) };
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
        let inner = unsafe { btck_block_read(self.inner, block_index.inner) };
        if inner.is_null() {
            return Err(KernelError::Internal("Failed to read block.".to_string()));
        }
        Ok(Block { inner })
    }

    /// Read a block's spent outputs data from disk by its block index.
    pub fn read_spent_outputs(
        &self,
        block_index: &BlockIndex,
    ) -> Result<BlockSpentOutputs, KernelError> {
        let inner = unsafe { btck_block_spent_outputs_read(self.inner, block_index.inner) };
        if inner.is_null() {
            return Err(KernelError::Internal(
                "Failed to read undo data.".to_string(),
            ));
        }
        Ok(BlockSpentOutputs { inner })
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

/// The logger object logs kernel log messages into a user-defined log function.
/// Messages logged by the kernel before this object is created are buffered in
/// a 1MB buffer. The kernel library internally uses a global logging instance.
pub struct Logger<T> {
    log: T,
    inner: *mut btck_LoggingConnection,
}

impl<T> Drop for Logger<T> {
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

impl<T: Log + 'static> Logger<T> {
    /// Create a new Logger with the specified callback.
    pub fn new(mut log: T) -> Result<Logger<T>, KernelError> {
        let options = btck_LoggingOptions {
            log_timestamps: true,
            log_time_micros: false,
            log_threadnames: false,
            log_sourcelocations: false,
            always_print_category_levels: false,
        };

        let inner = unsafe {
            btck_logging_connection_create(
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
