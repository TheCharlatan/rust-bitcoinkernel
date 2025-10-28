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

/// Result of processing a block with the chainstate manager
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessBlockResult {
    /// Block was accepted and is new
    NewBlock,
    /// Block was accepted but was already known
    Duplicate,
    /// Block was rejected during validation
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
    pub fn worker_threads(self, worker_threads: i32) -> Self {
        unsafe {
            btck_chainstate_manager_options_set_worker_threads_num(self.inner, worker_threads);
        }
        self
    }

    /// Wipe the block tree or chainstate dbs. When wiping the block tree db the
    /// chainstate db has to be wiped too. Wiping the databases will triggere a
    /// rebase once import blocks is called.
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

    /// Run the block tree db in-memory only. No database files will be written to disk.
    pub fn block_tree_db_in_memory(self, block_tree_db_in_memory: bool) -> Self {
        unsafe {
            btck_chainstate_manager_options_update_block_tree_db_in_memory(
                self.inner,
                c_helpers::to_c_bool(block_tree_db_in_memory),
            );
        }
        self
    }

    /// Run the chainstate db in-memory only. No database files will be written to disk.
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
