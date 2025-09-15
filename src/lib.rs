#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi::{CString, NulError};
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
    BTCK_SYNCHRONIZATION_STATE_INIT_DOWNLOAD, BTCK_SYNCHRONIZATION_STATE_INIT_REINDEX,
    BTCK_SYNCHRONIZATION_STATE_POST_INIT, BTCK_VALIDATION_MODE_INTERNAL_ERROR,
    BTCK_VALIDATION_MODE_INVALID, BTCK_VALIDATION_MODE_VALID,
    BTCK_WARNING_LARGE_WORK_INVALID_CHAIN, BTCK_WARNING_UNKNOWN_NEW_RULES_ACTIVATED,
};
use libbitcoinkernel_sys::*;

pub mod core;
pub mod ffi;
pub mod log;
pub mod notifications;
pub mod state;

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
                context.as_ptr(),
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

pub use crate::core::{
    verify, Block, BlockHash, BlockSpentOutputs, BlockSpentOutputsRef, BlockTreeEntry, Coin,
    CoinRef, ScriptPubkey, ScriptPubkeyRef, ScriptVerifyError, ScriptVerifyStatus, Transaction,
    TransactionRef, TransactionSpentOutputs, TransactionSpentOutputsRef, TxOut, TxOutRef,
};

pub use crate::log::{disable_logging, Log, LogCategory, LogLevel, Logger};

pub use crate::notifications::{
    BlockChecked, BlockTip, BlockValidationResult, FatalError, FlushError, HeaderTip,
    KernelNotificationInterfaceCallbacks, Progress, SynchronizationState,
    ValidationInterfaceCallbacks, ValidationMode, Warning, WarningSet, WarningUnset,
};

pub use crate::state::{ChainParams, ChainType, Context, ContextBuilder};

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
