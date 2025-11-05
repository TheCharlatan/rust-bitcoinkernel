//! Chainstate manager for Bitcoin Core validation and chain state management.
//!
//! The [`ChainstateManager`] is the central component for:
//! - Processing and validating blocks
//! - Reading block data from disk
//! - Querying the active chain and block tree
//! - Managing chainstate databases
//!
//! # Example
//! ```no_run
//! use bitcoinkernel::*;
//!
//! let context = ContextBuilder::new()
//!     .chain_type(ChainType::Regtest)
//!     .build()?;
//!
//! let opts = ChainstateManagerOptions::new(&context, "/data", "/blocks")?
//!     .worker_threads(4)
//!     .chainstate_db_in_memory(true);
//!
//! let chainman = ChainstateManager::new(opts)?;
//! # Ok::<(), KernelError>(())
//! ```

use std::ffi::CString;

use libbitcoinkernel_sys::{
    btck_BlockHash, btck_ChainstateManager, btck_ChainstateManagerOptions, btck_block_read,
    btck_block_spent_outputs_read, btck_chainstate_manager_create, btck_chainstate_manager_destroy,
    btck_chainstate_manager_get_active_chain, btck_chainstate_manager_get_block_tree_entry_by_hash,
    btck_chainstate_manager_import_blocks, btck_chainstate_manager_options_create,
    btck_chainstate_manager_options_destroy, btck_chainstate_manager_options_set_wipe_dbs,
    btck_chainstate_manager_options_set_worker_threads_num,
    btck_chainstate_manager_options_update_block_tree_db_in_memory,
    btck_chainstate_manager_options_update_chainstate_db_in_memory,
    btck_chainstate_manager_process_block,
};

use crate::{
    ffi::{
        c_helpers,
        sealed::{AsPtr, FromMutPtr, FromPtr},
    },
    Block, BlockHash, BlockSpentOutputs, BlockTreeEntry, KernelError,
};

use super::{Chain, Context};

/// Result of processing a block with the chainstate manager.
///
/// Indicates whether a block was accepted, rejected, or was already known
/// to the chainstate manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessBlockResult {
    /// Block passed validation and was added to the chain.
    ///
    /// This indicates the block is new and has been successfully validated
    /// against all consensus rules.
    NewBlock,
    /// Block was already present in the block tree.
    ///
    /// The block is valid but was previously processed. No action was taken.
    Duplicate,
    /// Block failed validation.
    ///
    /// The block violated one or more consensus rules. Use a validation
    /// interface callback to retrieve detailed error information.
    Rejected,
}

impl ProcessBlockResult {
    /// Returns true if the block was accepted and is new
    pub fn is_new_block(&self) -> bool {
        matches!(self, Self::NewBlock)
    }

    /// Returns true if the block was accepted but was already known
    pub fn is_duplicate(&self) -> bool {
        matches!(self, Self::Duplicate)
    }

    /// Returns true if the block was rejected
    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected)
    }
}

/// The chainstate manager handles Bitcoin block validation and chain state.
///
/// This is the primary interface for interacting with the Bitcoin blockchain,
/// providing functionality to process and validate blocks, read block data from
/// disk, and query chain state.
///
/// # Lifetime
/// The chainstate manager is only valid while the [`Context`] used to create
/// it remains in scope. Dropping the context before the manager will result
/// in undefined behavior.
///
/// # Thread Safety
/// The chainstate manager is `Send` and `Sync`, allowing it to be shared
/// across threads safely.
///
/// # Examples
/// See module-level documentation for usage examples.
pub struct ChainstateManager {
    inner: *mut btck_ChainstateManager,
}

unsafe impl Send for ChainstateManager {}
unsafe impl Sync for ChainstateManager {}

impl ChainstateManager {
    /// Creates a new chainstate manager.
    ///
    /// # Arguments
    /// * `chainman_opts` - Configuration options created via
    ///   [`ChainstateManagerOptions::new`]. Note that the options are
    ///   consumed and cannot be reused.
    ///
    /// # Errors
    /// Returns [`KernelError::Internal`] if the underlying C++ library fails
    /// to create the chainstate manager. Common causes include:
    /// - Invalid data directory paths
    /// - Insufficient permissions
    /// - Corrupted database files (if not wiping)
    pub fn new(chainman_opts: ChainstateManagerOptions) -> Result<Self, KernelError> {
        let inner = unsafe { btck_chainstate_manager_create(chainman_opts.inner) };
        if inner.is_null() {
            return Err(KernelError::Internal(
                "Failed to create chainstate manager.".to_string(),
            ));
        }
        Ok(Self { inner })
    }

    /// Process and validate a block.
    ///
    /// Attempts to validate and add the block to the chain. The block goes
    /// through full consensus validation including proof-of-work, transaction
    /// validity, and script verification.
    ///
    /// # Arguments
    /// * `block` - The block to process
    ///
    /// # Returns
    /// A [`ProcessBlockResult`] indicating whether the block was:
    /// - Newly accepted and added to the chain ([`ProcessBlockResult::NewBlock`])
    /// - Valid but already present in the chain ([`ProcessBlockResult::Duplicate`])
    /// - Rejected due to validation failure ([`ProcessBlockResult::Rejected`])
    ///
    /// # Validation Details
    /// For detailed validation failure information, register a validation interface
    /// callback using [`crate::ContextBuilder::with_block_checked_validation`] or
    /// [`crate::ContextBuilder::validation`]. The block checked callback will receive a
    /// [`crate::notifications::types::BlockValidationStateRef`] containing specific
    /// error details when validation fails.
    ///
    /// # Example
    /// ```no_run
    /// # use bitcoinkernel::*;
    /// # let chainman: ChainstateManager = unimplemented!();
    /// # let block: Block = unimplemented!();
    /// match chainman.process_block(&block) {
    ///     ProcessBlockResult::NewBlock => println!("Block accepted and added!"),
    ///     ProcessBlockResult::Duplicate => println!("Block already known (valid)"),
    ///     ProcessBlockResult::Rejected => println!("Block validation failed"),
    /// }
    /// ```
    pub fn process_block(&self, block: &Block) -> ProcessBlockResult {
        let mut new_block: i32 = 0;
        let accepted = unsafe {
            btck_chainstate_manager_process_block(self.inner, block.as_ptr(), &mut new_block)
        };

        let is_accepted = c_helpers::success(accepted);
        let is_new = c_helpers::enabled(new_block);

        match (is_accepted, is_new) {
            (true, true) => ProcessBlockResult::NewBlock,
            (true, false) => ProcessBlockResult::Duplicate,
            (false, _) => ProcessBlockResult::Rejected,
        }
    }

    /// Initialize the chainstate manager and optionally trigger a reindex.
    ///
    /// This should be called after creating the chainstate manager to complete
    /// initialization. If the `wipe_db` option was set, this will trigger a
    /// blockchain reindex.
    ///
    /// # Errors
    /// Returns [`KernelError::Internal`] if initialization fails.
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

    /// Read a block's full data from disk.
    ///
    /// # Arguments
    /// * `entry` - The [`BlockTreeEntry`] identifying which block to read
    ///
    /// # Returns
    /// The complete [`Block`] including all transactions.
    ///
    /// # Errors
    /// Returns [`KernelError::Internal`] if:
    /// - The block file cannot be read
    /// - The block data is corrupted
    /// - The block has been pruned
    pub fn read_block_data(&self, entry: &BlockTreeEntry) -> Result<Block, KernelError> {
        let inner = unsafe { btck_block_read(self.inner, entry.as_ptr()) };
        if inner.is_null() {
            return Err(KernelError::Internal("Failed to read block.".to_string()));
        }
        Ok(unsafe { Block::from_ptr(inner) })
    }

    /// Read a block's spent outputs (undo data) from disk.
    ///
    /// Retrieves the spent outputs associated with a specific block. Spent outputs
    /// contain information about the transaction outputs that were consumed when the
    /// block's transactions were applied to the UTXO set. This data is essential for
    /// rolling back blocks during chain reorganizations.
    ///
    /// # Arguments
    /// * `entry` - The [`BlockTreeEntry`] identifying which block's spent outputs to read
    ///
    /// # Returns
    /// The [`BlockSpentOutputs`] containing the undo data for the specified block.
    ///
    /// # Errors
    /// Returns [`KernelError::Internal`] if:
    /// - The undo data file cannot be read
    /// - The undo data is corrupted
    /// - The block has been pruned
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

    /// Get a reference to the currently active blockchain.
    ///
    /// Returns the active chain, which represents the chain with the most
    /// accumulated proof-of-work. This is the canonical chain used for validation
    /// and represents the current consensus state of the network.
    ///
    /// The active chain changes over time as new blocks are processed or during
    /// chain reorganizations when a competing chain overtakes the current one. The
    /// returned [`Chain`] reference will reflect these updates.
    ///
    /// # Returns
    /// A [`Chain`] reference representing the active chain.
    ///
    /// # Lifetime
    /// The returned [`Chain`] reference is tied to the lifetime of the
    /// [`ChainstateManager`] and becomes invalid when the manager is dropped.
    pub fn active_chain(&self) -> Chain<'_> {
        let ptr = unsafe { btck_chainstate_manager_get_active_chain(self.inner) };
        unsafe { Chain::from_ptr(ptr) }
    }

    /// Get a block tree entry by its block hash.
    ///
    /// Looks up a block in the block tree using its hash. The block tree contains
    /// metadata about all known blocks, including those not on the active chain.
    ///
    /// # Arguments
    /// * `block_hash` - The [`BlockHash`] of the block to look up
    ///
    /// # Returns
    /// * `Some(BlockTreeEntry)` - If a block with the given hash exists in the block tree
    /// * `None` - If no block with the given hash is found
    ///
    /// # Lifetime
    /// The returned [`BlockTreeEntry`] reference is tied to the lifetime of the
    /// [`ChainstateManager`] and becomes invalid when the manager is dropped.
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

/// Configuration options for creating a [`ChainstateManager`].
///
/// Provides a fluent interface for configuring how the chainstate manager
/// will initialize and operate. Options control database locations, in-memory
/// operation, worker thread allocation, and database initialization behavior.
///
/// # Usage
/// Configure options by chaining method calls, then pass to
/// [`ChainstateManager::new`]. Note that options are consumed and cannot
/// be reused.
///
/// # Example
/// ```no_run
/// use bitcoinkernel::*;
///
/// let context = ContextBuilder::new()
///     .chain_type(ChainType::Regtest)
///     .build()?;
///
/// let opts = ChainstateManagerOptions::new(&context, "/data", "/blocks")?
///     .worker_threads(4)
///     .chainstate_db_in_memory(true)
///     .block_tree_db_in_memory(true);
///
/// let chainman = ChainstateManager::new(opts)?;
/// # Ok::<(), KernelError>(())
/// ```
pub struct ChainstateManagerOptions {
    inner: *mut btck_ChainstateManagerOptions,
}

impl ChainstateManagerOptions {
    /// Creates a new chainstate manager configuration.
    ///
    /// # Arguments
    /// * `context` - The [`Context`] that configures chain parameters. Must remain
    ///   valid for the lifetime of any [`ChainstateManager`] created from these options.
    /// * `data_dir` - Path to the directory where chainstate data will be stored.
    ///   This includes the UTXO set database and other chain state information.
    /// * `blocks_dir` - Path to the directory where block data will be stored.
    ///   This includes the raw block files and the block index database.
    ///
    /// # Errors
    /// Returns [`KernelError`] if:
    /// - The paths contain null bytes (invalid C strings)
    /// - The underlying C++ library fails to create the options object
    ///
    /// # Example
    /// ```no_run
    /// # use bitcoinkernel::*;
    /// let context = ContextBuilder::new()
    ///     .chain_type(ChainType::Regtest)
    ///     .build()?;
    ///
    /// let opts = ChainstateManagerOptions::new(
    ///     &context,
    ///     "/var/bitcoin",
    ///     "/var/bitcoin/blocks"
    /// )?;
    /// # Ok::<(), KernelError>(())
    /// ```
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

    /// Sets the number of worker threads for validation.
    ///
    /// Block validation can be parallelized across multiple threads to improve
    /// performance. More threads generally result in faster validation, but with
    /// diminishing returns beyond the number of available CPU cores.
    ///
    /// # Arguments
    /// * `worker_threads` - Number of worker threads to use for validation.
    ///   Valid range is 0-15 (values outside this range are clamped). When set to 0,
    ///   no parallel verification is performed.
    ///
    /// # Example
    /// ```no_run
    /// # use bitcoinkernel::*;
    /// # let context = ContextBuilder::new()
    /// #     .chain_type(ChainType::Regtest)
    /// #     .build()?;
    /// # let opts = ChainstateManagerOptions::new(&context, "/data", "/blocks")?;
    /// let opts = opts.worker_threads(8);
    /// # Ok::<(), KernelError>(())
    /// ```
    pub fn worker_threads(self, worker_threads: i32) -> Self {
        unsafe {
            btck_chainstate_manager_options_set_worker_threads_num(self.inner, worker_threads);
        }
        self
    }

    /// Configures database wiping behavior.
    ///
    /// When enabled, this will delete and recreate the specified databases on
    /// initialization. After wiping, [`ChainstateManager::import_blocks`] will
    /// trigger a reindex to rebuild the databases from the block files.
    ///
    /// # Arguments
    /// * `wipe_block_tree` - If true, wipe the block tree database (block index).
    ///   Should only be true if `wipe_chainstate` is also true.
    /// * `wipe_chainstate` - If true, wipe the chainstate database (UTXO set)
    ///
    /// # Reindex Behavior
    /// - Wiping both databases triggers a full reindex
    /// - Wiping only the chainstate triggers a chainstate-only reindex
    ///
    /// # Important
    /// Wiping the block tree without also wiping the chainstate is currently
    /// unsupported. If `wipe_block_tree` is true, `wipe_chainstate` must also
    /// be true.
    ///
    /// # Example
    /// ```no_run
    /// # use bitcoinkernel::*;
    /// # let context = ContextBuilder::new()
    /// #     .chain_type(ChainType::Regtest)
    /// #     .build()?;
    /// # let opts = ChainstateManagerOptions::new(&context, "/data", "/blocks")?;
    /// // Wipe both databases for a full reindex
    /// let opts = opts.wipe_db(true, true);
    ///
    /// // Only wipe chainstate (e.g., to rebuild UTXO set)
    /// let opts = opts.wipe_db(false, true);
    /// # Ok::<(), KernelError>(())
    /// ```
    pub fn wipe_db(self, wipe_block_tree: bool, wipe_chainstate: bool) -> Self {
        unsafe {
            btck_chainstate_manager_options_set_wipe_dbs(
                self.inner,
                c_helpers::to_c_bool(wipe_block_tree),
                c_helpers::to_c_bool(wipe_chainstate),
            );
        }
        self
    }

    /// Configures the block tree database to run entirely in memory.
    ///
    /// When enabled, the block tree database (which stores the block index and
    /// metadata about all known blocks) will be stored in RAM rather than on disk.
    /// This can improve performance but requires sufficient memory and means the
    /// database will be lost when the process exits.
    ///
    /// # Arguments
    /// * `block_tree_db_in_memory` - If true, run the block tree database in memory
    ///
    /// # Use Cases
    /// - Testing environments where persistence is not needed
    /// - Temporary validation tasks
    /// - Systems with fast RAM but slow disk I/O
    ///
    /// # Example
    /// ```no_run
    /// # use bitcoinkernel::*;
    /// # let context = ContextBuilder::new()
    /// #     .chain_type(ChainType::Regtest)
    /// #     .build()?;
    /// # let opts = ChainstateManagerOptions::new(&context, "/data", "/blocks")?;
    /// // Use in-memory block tree for testing
    /// let opts = opts.block_tree_db_in_memory(true);
    /// # Ok::<(), KernelError>(())
    /// ```
    pub fn block_tree_db_in_memory(self, block_tree_db_in_memory: bool) -> Self {
        unsafe {
            btck_chainstate_manager_options_update_block_tree_db_in_memory(
                self.inner,
                c_helpers::to_c_bool(block_tree_db_in_memory),
            );
        }
        self
    }

    /// Configures the chainstate database to run entirely in memory.
    ///
    /// When enabled, the chainstate database (which stores the current UTXO set)
    /// will be stored in RAM rather than on disk. This can significantly improve
    /// performance but requires substantial memory (several gigabytes for mainnet)
    /// and means the database will be lost when the process exits.
    ///
    /// # Arguments
    /// * `chainstate_db_in_memory` - If true, run the chainstate database in memory
    ///
    /// # Memory Requirements
    /// The chainstate database size varies by network:
    /// - Mainnet: ~5-10 GB
    /// - Testnet: ~1-2 GB
    /// - Regtest: Typically very small
    ///
    /// # Use Cases
    /// - Testing and development
    /// - Temporary validation or analysis tasks
    /// - High-performance applications with sufficient RAM
    ///
    /// # Example
    /// ```no_run
    /// # use bitcoinkernel::*;
    /// # let context = ContextBuilder::new()
    /// #     .chain_type(ChainType::Regtest)
    /// #     .build()?;
    /// # let opts = ChainstateManagerOptions::new(&context, "/data", "/blocks")?;
    /// // Use in-memory chainstate for fast testing
    /// let opts = opts.chainstate_db_in_memory(true);
    /// # Ok::<(), KernelError>(())
    /// ```
    pub fn chainstate_db_in_memory(self, chainstate_db_in_memory: bool) -> Self {
        unsafe {
            btck_chainstate_manager_options_update_chainstate_db_in_memory(
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChainType, ContextBuilder};
    use tempdir::TempDir;

    fn create_test_context() -> Context {
        ContextBuilder::new()
            .chain_type(ChainType::Regtest)
            .build()
            .unwrap()
    }

    fn create_test_dirs() -> (TempDir, String, String) {
        let temp_dir = TempDir::new("test_chainman").unwrap();
        let data_dir = temp_dir.path().to_str().unwrap().to_string();
        let blocks_dir = format!("{}/blocks", data_dir);
        (temp_dir, data_dir, blocks_dir)
    }

    #[test]
    fn test_chainstate_manager_options_new() {
        let context = create_test_context();
        let (_temp_dir, data_dir, blocks_dir) = create_test_dirs();

        let opts = ChainstateManagerOptions::new(&context, &data_dir, &blocks_dir);
        assert!(opts.is_ok());
    }

    #[test]
    fn test_chainstate_manager_options_invalid_path() {
        let context = create_test_context();

        let invalid_path = "test\0path";
        let blocks_dir = "blocks";

        let opts = ChainstateManagerOptions::new(&context, invalid_path, blocks_dir);
        assert!(opts.is_err());
    }

    #[test]
    fn test_chainstate_manager_creation() {
        let context = create_test_context();
        let (_temp_dir, data_dir, blocks_dir) = create_test_dirs();

        let opts = ChainstateManagerOptions::new(&context, &data_dir, &blocks_dir)
            .unwrap()
            .block_tree_db_in_memory(true)
            .chainstate_db_in_memory(true)
            .wipe_db(false, true)
            .worker_threads(4);

        let chainman = ChainstateManager::new(opts);
        assert!(chainman.is_ok());
    }

    #[test]
    fn test_process_block_result_new_block() {
        let result = ProcessBlockResult::NewBlock;

        assert_eq!(result, ProcessBlockResult::NewBlock);
        assert!(result.is_new_block());
        assert!(!result.is_duplicate());
        assert!(!result.is_rejected());
    }

    #[test]
    fn test_process_block_result_duplicate() {
        let result = ProcessBlockResult::Duplicate;

        assert_eq!(result, ProcessBlockResult::Duplicate);
        assert!(!result.is_new_block());
        assert!(result.is_duplicate());
        assert!(!result.is_rejected());
    }

    #[test]
    fn test_process_block_result_rejected() {
        let result = ProcessBlockResult::Rejected;

        assert_eq!(result, ProcessBlockResult::Rejected);
        assert!(!result.is_new_block());
        assert!(!result.is_duplicate());
        assert!(result.is_rejected());
    }

    #[test]
    fn test_process_block_result_match() {
        let result = ProcessBlockResult::NewBlock;

        let message = match result {
            ProcessBlockResult::NewBlock => "new",
            ProcessBlockResult::Duplicate => "duplicate",
            ProcessBlockResult::Rejected => "rejected",
        };

        assert_eq!(message, "new");
    }

    #[test]
    fn test_process_block_result_equality() {
        assert_eq!(ProcessBlockResult::NewBlock, ProcessBlockResult::NewBlock);
        assert_ne!(ProcessBlockResult::NewBlock, ProcessBlockResult::Rejected);
        assert_ne!(ProcessBlockResult::Duplicate, ProcessBlockResult::Rejected);
    }

    #[test]
    fn test_process_block_result_debug() {
        let result = ProcessBlockResult::NewBlock;
        let debug_str = format!("{:?}", result);
        assert_eq!(debug_str, "NewBlock");
    }
}
