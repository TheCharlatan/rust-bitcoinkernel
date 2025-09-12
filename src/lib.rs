#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi::{c_char, c_void, CString, NulError};
use std::marker::PhantomData;
use std::{fmt, panic};

use crate::core::{ScriptPubkeyExt, TransactionExt, TxOutExt};
use ffi::{
    c_helpers, BTCK_BLOCK_VALIDATION_RESULT_CACHED_INVALID, BTCK_BLOCK_VALIDATION_RESULT_CONSENSUS,
    BTCK_BLOCK_VALIDATION_RESULT_HEADER_LOW_WORK, BTCK_BLOCK_VALIDATION_RESULT_INVALID_HEADER,
    BTCK_BLOCK_VALIDATION_RESULT_INVALID_PREV, BTCK_BLOCK_VALIDATION_RESULT_MISSING_PREV,
    BTCK_BLOCK_VALIDATION_RESULT_MUTATED, BTCK_BLOCK_VALIDATION_RESULT_TIME_FUTURE,
    BTCK_BLOCK_VALIDATION_RESULT_UNSET, BTCK_CHAIN_TYPE_MAINNET, BTCK_CHAIN_TYPE_REGTEST,
    BTCK_CHAIN_TYPE_SIGNET, BTCK_CHAIN_TYPE_TESTNET, BTCK_CHAIN_TYPE_TESTNET_4,
    BTCK_LOG_CATEGORY_ALL, BTCK_LOG_CATEGORY_BENCH, BTCK_LOG_CATEGORY_BLOCKSTORAGE,
    BTCK_LOG_CATEGORY_COINDB, BTCK_LOG_CATEGORY_KERNEL, BTCK_LOG_CATEGORY_LEVELDB,
    BTCK_LOG_CATEGORY_MEMPOOL, BTCK_LOG_CATEGORY_PRUNE, BTCK_LOG_CATEGORY_RAND,
    BTCK_LOG_CATEGORY_REINDEX, BTCK_LOG_CATEGORY_VALIDATION, BTCK_LOG_LEVEL_DEBUG,
    BTCK_LOG_LEVEL_INFO, BTCK_LOG_LEVEL_TRACE, BTCK_SYNCHRONIZATION_STATE_INIT_DOWNLOAD,
    BTCK_SYNCHRONIZATION_STATE_INIT_REINDEX, BTCK_SYNCHRONIZATION_STATE_POST_INIT,
    BTCK_VALIDATION_MODE_INTERNAL_ERROR, BTCK_VALIDATION_MODE_INVALID, BTCK_VALIDATION_MODE_VALID,
    BTCK_WARNING_LARGE_WORK_INVALID_CHAIN, BTCK_WARNING_UNKNOWN_NEW_RULES_ACTIVATED,
};
use libbitcoinkernel_sys::*;
use notifications::notification::{
    kn_block_tip_wrapper, kn_fatal_error_wrapper, kn_flush_error_wrapper, kn_header_tip_wrapper,
    kn_progress_wrapper, kn_user_data_destroy_wrapper, kn_warning_set_wrapper,
    kn_warning_unset_wrapper,
};
use notifications::validation::{vi_block_checked_wrapper, vi_user_data_destroy_wrapper};

pub mod core;
pub mod ffi;
pub mod notifications;

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
    chain: Chain<'a>,
    current_height: usize,
}

impl<'a> ChainIterator<'a> {
    fn new(chain: Chain<'a>) -> Self {
        Self {
            chain,
            current_height: 0,
        }
    }
}

impl<'a> Iterator for ChainIterator<'a> {
    type Item = BlockTreeEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let height = self.current_height;
        self.current_height += 1;
        self.chain.at_height(height)
    }
}

/// Represents a chain instance for querying and traversal.
pub struct Chain<'a> {
    inner: *const btck_Chain,
    marker: PhantomData<&'a ChainstateManager>,
}

impl<'a> Chain<'a> {
    pub unsafe fn from_ptr(ptr: *const btck_Chain) -> Self {
        Chain {
            inner: ptr,
            marker: PhantomData,
        }
    }

    /// Returns the tip (highest block) of the active chain.
    pub fn tip(&self) -> BlockTreeEntry<'a> {
        let ptr = unsafe { btck_chain_get_tip(self.inner) };
        unsafe { BlockTreeEntry::from_ptr(ptr) }
    }

    /// Returns the genesis block (height 0) of the chain.
    pub fn genesis(&self) -> BlockTreeEntry<'a> {
        let ptr = unsafe { btck_chain_get_genesis(self.inner) };
        unsafe { BlockTreeEntry::from_ptr(ptr) }
    }

    /// Returns the block at the specified height, if it exists.
    pub fn at_height(&self, height: usize) -> Option<BlockTreeEntry<'a>> {
        let tip_height = self.height();
        if height > tip_height as usize {
            return None;
        }

        let ptr = unsafe { btck_chain_get_by_height(self.inner, height as i32) };
        if ptr.is_null() {
            return None;
        }

        Some(unsafe { BlockTreeEntry::from_ptr(ptr) })
    }

    /// Checks if the given block entry is part of the active chain.
    pub fn contains(&self, entry: &BlockTreeEntry<'a>) -> bool {
        let result = unsafe { btck_chain_contains(self.inner, entry.as_ptr()) };
        c_helpers::present(result)
    }

    /// Returns an iterator over all blocks from genesis to tip.
    pub fn iter(&self) -> ChainIterator<'a> {
        ChainIterator::new(*self)
    }

    pub fn height(&self) -> i32 {
        self.tip().height()
    }
}

impl<'a> Clone for Chain<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a> Copy for Chain<'a> {}

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
            btck_chainstate_manager_process_block(self.inner, block.as_ptr(), &mut new_block)
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
        let inner = unsafe { btck_block_read(self.inner, entry.as_ptr()) };
        if inner.is_null() {
            return Err(KernelError::Internal("Failed to read block.".to_string()));
        }
        Ok(unsafe { Block::from_ptr(inner) })
    }

    /// Read a block's spent outputs data from disk by its block tree entry.
    pub fn read_spent_outputs(
        &self,
        entry: &BlockTreeEntry,
    ) -> Result<BlockSpentOutputs, KernelError> {
        let inner = unsafe { btck_block_spent_outputs_read(self.inner, entry.as_ptr()) };
        if inner.is_null() {
            return Err(KernelError::Internal(
                "Failed to read undo data.".to_string(),
            ));
        }
        Ok(unsafe { BlockSpentOutputs::from_ptr(inner) })
    }

    pub fn active_chain(&self) -> Chain<'_> {
        let ptr = unsafe { btck_chainstate_manager_get_active_chain(self.inner) };
        unsafe { Chain::from_ptr(ptr) }
    }

    pub fn get_block_tree_entry(&self, block_hash: &BlockHash) -> Option<BlockTreeEntry<'_>> {
        let ptr = unsafe {
            btck_chainstate_manager_get_block_tree_entry_by_hash(
                self.inner,
                block_hash as *const _ as *const btck_BlockHash,
            )
        };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { BlockTreeEntry::from_ptr(ptr) })
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
    let message = unsafe { c_helpers::to_string(message, message_len) };
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

pub use crate::core::{
    verify, Block, BlockHash, BlockSpentOutputs, BlockSpentOutputsRef, BlockTreeEntry, Coin,
    CoinRef, ScriptPubkey, ScriptPubkeyRef, ScriptVerifyError, ScriptVerifyStatus, Transaction,
    TransactionRef, TransactionSpentOutputs, TransactionSpentOutputsRef, TxOut, TxOutRef,
};

pub use crate::notifications::{
    BlockChecked, BlockTip, BlockValidationResult, FatalError, FlushError, HeaderTip,
    KernelNotificationInterfaceCallbacks, Progress, SynchronizationState,
    ValidationInterfaceCallbacks, ValidationMode, Warning, WarningSet, WarningUnset,
};

pub use crate::core::verify_flags::{
    VERIFY_ALL, VERIFY_ALL_PRE_TAPROOT, VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY,
    VERIFY_DERSIG, VERIFY_NONE, VERIFY_NULLDUMMY, VERIFY_P2SH, VERIFY_TAPROOT, VERIFY_WITNESS,
};

pub mod prelude {
    pub use crate::core::{
        BlockSpentOutputsExt, CoinExt, ScriptPubkeyExt, TransactionExt, TransactionSpentOutputsExt,
        TxOutExt,
    };
}
