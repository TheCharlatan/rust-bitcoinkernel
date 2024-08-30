#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi::{CStr, CString, NulError};
use std::fmt;
use std::marker::PhantomData;
use std::os::raw::{c_char, c_void};

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
    pub kn_callbacks: Option<Box<KernelNotificationInterfaceCallbackHolder>>,
}

impl ContextBuilder {
    pub fn new() -> ContextBuilder {
        let context = ContextBuilder {
            inner: unsafe { kernel_context_options_create() },
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
            kn_callbacks: self.kn_callbacks.unwrap(),
        })
    }

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

    pub fn chain_type(self, chain_type: ChainType) -> ContextBuilder {
        let chain_params = ChainParams::new(chain_type);
        unsafe { kernel_context_options_set_chainparams(self.inner, chain_params.inner) };
        self
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

    pub fn get_value(&self) -> i64 {
        unsafe { kernel_get_transaction_output_amount(self.inner) }
    }

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

pub struct BlockHeader {
    inner: *mut kernel_BlockHeader,
}

unsafe impl Send for BlockHeader {}
unsafe impl Sync for BlockHeader {}

impl Into<Vec<u8>> for BlockHeader {
    fn into(self) -> Vec<u8> {
        let raw_header = unsafe { kernel_copy_block_header_data(self.inner) };
        let vec = unsafe {
            std::slice::from_raw_parts((*raw_header).data, (*raw_header).size.try_into().unwrap())
        }
        .to_vec();
        unsafe { kernel_byte_array_destroy(raw_header) };
        vec
    }
}

impl TryFrom<&[u8]> for BlockHeader {
    type Error = KernelError;

    fn try_from(raw_block: &[u8]) -> Result<Self, Self::Error> {
        let inner = unsafe { kernel_block_header_create(raw_block.as_ptr(), raw_block.len()) };
        if inner.is_null() {
            return Err(KernelError::Internal("Failed to decode block.".to_string()));
        }
        Ok(BlockHeader { inner })
    }
}

impl Drop for BlockHeader {
    fn drop(&mut self) {
        unsafe { kernel_block_header_destroy(self.inner) };
    }
}

pub struct Block {
    inner: *mut kernel_Block,
}

unsafe impl Send for Block {}
unsafe impl Sync for Block {}

impl Block {
    pub fn get_header(&self) -> BlockHeader {
        BlockHeader {
            inner: unsafe { kernel_get_block_header(self.inner) },
        }
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

pub struct BlockIndex<'a> {
    inner: *mut kernel_BlockIndex,
    marker: PhantomData<ChainstateManager<'a>>,
}

unsafe impl Send for BlockIndex<'_> {}
unsafe impl Sync for BlockIndex<'_> {}

#[derive(Debug, Clone)]
pub struct BlockHash {
    pub hash: [u8; 32],
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

    pub fn height(&self) -> i32 {
        unsafe { kernel_block_index_get_height(self.inner) }
    }

    pub fn info(&self) -> BlockHash {
        let hash = unsafe { kernel_block_index_get_block_hash(self.inner) };
        let res = BlockHash {
            hash: unsafe { (&*hash).hash },
        };
        unsafe { kernel_block_hash_destroy(hash) };
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
    pub fn get_transaction_undo_size(&self, transaction_index: u64) -> u64 {
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
        let res = TxOut { inner: prev_out };
        Ok(res)
    }
}

impl Drop for BlockUndo {
    fn drop(&mut self) {
        unsafe { kernel_block_undo_destroy(self.inner) };
    }
}

#[derive(Debug, Clone)]
pub struct OutPoint {
    pub hash: [u8; 32],
    pub n: u32,
}

impl From<kernel_OutPoint> for OutPoint {
    fn from(c: kernel_OutPoint) -> OutPoint {
        OutPoint {
            hash: c.hash,
            n: c.n,
        }
    }
}

pub struct CoinsCursor {
    inner: *mut kernel_CoinsViewCursor,
    iterating: bool,
}

impl CoinsCursor {
    pub fn next_entry(&self) -> bool {
        return unsafe { kernel_coins_cursor_next(self.inner) };
    }

    pub fn get_key(&self) -> Result<OutPoint, KernelError> {
        let outpoint_ptr = unsafe { kernel_coins_cursor_get_key(self.inner) };
        if outpoint_ptr.is_null() {
            return Err(KernelError::Internal("Failed to get outpoint.".to_string()));
        }
        let outpoint = unsafe { *outpoint_ptr }.into();
        unsafe { kernel_out_point_destroy(outpoint_ptr) };
        Ok(outpoint)
    }

    pub fn get_value(&self) -> Result<TxOut, KernelError> {
        let tx_out = unsafe { kernel_coins_cursor_get_value(self.inner) };
        if tx_out.is_null() {
            return Err(KernelError::Internal("Failed to get coin.".to_string()));
        }
        Ok(TxOut { inner: tx_out })
    }
}

impl Iterator for CoinsCursor {
    type Item = (OutPoint, TxOut);

    fn next(&mut self) -> Option<Self::Item> {
        if !self.iterating {
            let val = if let (Some(key), Some(value)) = (self.get_key().ok(), self.get_value().ok())
            {
                Some((key, value))
            } else {
                None
            };
            self.iterating = true;
            return val;
        }
        if !self.next_entry() {
            None
        } else {
            if let (Some(key), Some(value)) = (self.get_key().ok(), self.get_value().ok()) {
                Some((key, value))
            } else {
                None
            }
        }
    }
}

impl Drop for CoinsCursor {
    fn drop(&mut self) {
        unsafe { kernel_coins_cursor_destroy(self.inner) };
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

    pub fn process_block_header(&self, header: &BlockHeader) -> bool {
        return unsafe {
            kernel_chainstate_manager_process_block_header(
                self.context.inner,
                self.inner,
                header.inner,
            )
        };
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

    pub fn get_coins_cursor(&self) -> Result<CoinsCursor, KernelError> {
        let inner = unsafe { kernel_chainstate_coins_cursor_create(self.inner) };
        if inner.is_null() {
            return Err(KernelError::Internal(
                "Failed to get coins cursor.".to_string(),
            ));
        }
        Ok(CoinsCursor {
            inner,
            iterating: false,
        })
    }

    pub fn get_output(&self, point: OutPoint) -> Result<TxOut, KernelError> {
        let out_point = kernel_OutPoint {
            hash: point.hash,
            n: point.n,
        };
        let tx_out = unsafe { kernel_get_output_by_out_point(self.inner, &out_point) };
        if tx_out.is_null() {
            return Err(KernelError::Internal(
                "Failed to get coin by its outpoint.".to_string(),
            ));
        }
        Ok(TxOut { inner: tx_out })
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
