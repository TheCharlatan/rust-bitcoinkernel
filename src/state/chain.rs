//! Chain traversal and querying interface for a specific chain.
//!
//! The [`Chain`] represents a specific chain, providing methods to query
//! [`BlockTreeEntry`] by height, check block membership, and iterate
//! through the chain from genesis to tip.

use std::marker::PhantomData;

use libbitcoinkernel_sys::{
    btck_Chain, btck_chain_contains, btck_chain_get_by_height, btck_chain_get_height,
};

use crate::{
    ffi::{
        c_helpers,
        sealed::{AsPtr, FromPtr},
    },
    BlockTreeEntry,
};

use super::ChainstateManager;

/// Iterator for traversing blocks sequentially from genesis to tip.
///
/// This iterator yields [`BlockTreeEntry`] items for each block in the
/// chain, starting from the genesis block (height 0) and continuing
/// through to the chain tip.
///
/// # Performance Note
/// This iterator traverses blocks sequentially from genesis. Common operations
/// have the following complexity:
/// - `.next()`: O(1) - retrieves next block by height
/// - `.last()`: O(N) - iterates through entire chain
/// - `.nth(n)`: O(N) - skips N blocks
///
/// For direct access, prefer using [`Chain`] methods:
/// - [`Chain::tip()`] - O(1) access to chain tip (instead of `.last()`)
/// - [`Chain::at_height()`] - O(1) access to specific height (instead of `.nth()`)
///
/// # Lifetime
/// The iterator is tied to the lifetime of the [`Chain`] it was created from,
/// which in turn is tied to the [`ChainstateManager`]. The iterator becomes
/// invalid when either is dropped.
///
/// # Example
/// ```no_run
/// # use bitcoinkernel::{ContextBuilder, ChainstateManager, ChainType, KernelError};
/// # let context = ContextBuilder::new().chain_type(ChainType::Regtest).build()?;
/// # let chainman = ChainstateManager::builder(&context, "/data", "/blocks")?.build()?;
/// let chain = chainman.active_chain();
///
/// // Iterate through all blocks
/// for entry in chain.iter() {
///     println!("Block {} at height {}", entry.block_hash(), entry.height());
/// }
/// # Ok::<(), KernelError>(())
/// ```
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

    /// Returns the next block in the chain.
    ///
    /// Yields blocks sequentially from genesis (height 0) to the current tip.
    /// Returns `None` when all blocks have been iterated.
    fn next(&mut self) -> Option<Self::Item> {
        let height = self.current_height;
        self.current_height += 1;
        self.chain.at_height(height)
    }
}

/// Represents a specific chain for querying and traversal.
///
/// The [`Chain`] allows retrieving block tree entries by height, checking if
/// blocks are part of the chain, and iterating through all blocks from
/// genesis to tip.
///
/// # Lifetime
/// The [`Chain`] is tied to the lifetime of the [`ChainstateManager`] that created
/// it. It becomes invalid when the manager is dropped.
///
/// # Thread Safety
/// [`Chain`] is `Copy` and can be safely shared across threads.
///
/// # Examples
/// ```no_run
/// use bitcoinkernel::{ChainstateManager, ChainType, ContextBuilder, KernelError};
///
/// # let context = ContextBuilder::new()
/// #     .chain_type(ChainType::Regtest)
/// #     .build()?;
/// #
/// # let chainman = ChainstateManager::builder(&context, "/data", "/blocks")?.build()?;
/// let chain = chainman.active_chain();
///
/// // Get the current tip
/// let tip = chain.tip();
/// println!("Chain height: {}", chain.height());
/// println!("Tip hash: {}", tip.block_hash());
///
/// // Get the genesis block
/// let genesis = chain.at_height(0).unwrap();
/// println!("Genesis hash: {}", genesis.block_hash());
///
/// // Query a specific height
/// if let Some(block_index_100) = chain.at_height(100) {
///     println!("Block 100: {}", block_index_100.block_hash());
/// }
/// # Ok::<(), KernelError>(())
/// ```
pub struct Chain<'a> {
    inner: *const btck_Chain,
    marker: PhantomData<&'a ChainstateManager>,
}

impl<'a> Chain<'a> {
    /// Returns the tip (highest block) of the chain.
    ///
    /// The tip represents the most recent block in the chain.
    ///
    /// # Returns
    /// A [`BlockTreeEntry`] for the chain's tip block.
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::{ChainstateManager, ChainType, ContextBuilder, KernelError};
    ///
    /// # let context = ContextBuilder::new().chain_type(ChainType::Regtest).build()?;
    /// # let chainman = ChainstateManager::builder(&context, "/data", "/blocks")?.build()?;
    /// let chain = chainman.active_chain();
    /// let tip = chain.tip();
    ///
    /// println!("Current chain height: {}", chain.height());
    /// println!("Tip block hash: {}", tip.block_hash());
    /// # Ok::<(), KernelError>(())
    /// ```
    pub fn tip(&self) -> BlockTreeEntry<'a> {
        let ptr = unsafe { btck_chain_get_by_height(self.inner, self.height()) };
        unsafe { BlockTreeEntry::from_ptr(ptr) }
    }

    /// Returns the block tree entry at the specified height, if it exists.
    ///
    /// Retrieves the block entry for a specific height in the chain.
    /// Height is zero-indexed, with the genesis block at height 0.
    ///
    /// # Arguments
    /// * `height` - The block height to query (0 = genesis block)
    ///
    /// # Returns
    /// * `Some(`[`BlockTreeEntry`]`)` - If a block exists at the specified height
    /// * `None` - If the height exceeds the current chain tip
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::{ChainstateManager, ChainType, ContextBuilder, KernelError};
    ///
    /// # let context = ContextBuilder::new().chain_type(ChainType::Regtest).build()?;
    /// # let chainman = ChainstateManager::builder(&context, "/data", "/blocks")?.build()?;
    /// let chain = chainman.active_chain();
    ///
    /// // Get block at height 1000
    /// if let Some(block_index) = chain.at_height(1000) {
    ///     println!("Block 1000: {}", block_index.block_hash());
    /// } else {
    ///     println!("Chain height is less than 1000");
    /// }
    ///
    /// // Genesis block is always present
    /// let genesis = chain.at_height(0).expect("Genesis must exist");
    /// # Ok::<(), KernelError>(())
    /// ```
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

    /// Checks if the given block entry is part of the chain.
    ///
    /// Determines whether a block is in the chain.
    ///
    /// # Arguments
    /// * `entry` - The [`BlockTreeEntry`] to check for membership
    ///
    /// # Returns
    /// * `true` - If the block is part of the chain
    /// * `false` - If the block is not in the chain (e.g., a stale block)
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::{BlockHash, ChainstateManager, ChainType, ContextBuilder, KernelError};
    ///
    /// # let context = ContextBuilder::new().chain_type(ChainType::Regtest).build()?;
    /// # let chainman = ChainstateManager::builder(&context, "/data", "/blocks")?.build()?;
    /// # let block_hash = BlockHash::from([0u8; 32]);
    /// let chain = chainman.active_chain();
    ///
    /// if let Some(entry) = chainman.get_block_tree_entry(&block_hash) {
    ///     if chain.contains(&entry) {
    ///         println!("Block is in the active chain");
    ///     } else {
    ///         println!("Block is stale");
    ///     }
    /// }
    /// # Ok::<(), KernelError>(())
    /// ```
    pub fn contains(&self, entry: &BlockTreeEntry<'a>) -> bool {
        let result = unsafe { btck_chain_contains(self.inner, entry.as_ptr()) };
        c_helpers::present(result)
    }

    /// Returns an iterator over all block tree entries from genesis to tip.
    ///
    /// Creates a [`ChainIterator`] that yields [`BlockTreeEntry`] items
    /// for each block in the chain, starting from the genesis block (height 0) and
    /// continuing sequentially to the current tip.
    ///
    /// # Performance
    /// **Warning:** Avoid calling `.last()` on this iterator, as it requires O(N)
    /// iteration through all blocks. Use [`chain.tip()`](Chain::tip) instead,
    /// which is O(1).
    ///
    /// # Returns
    /// A [`ChainIterator`] that traverses the entire chain.
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::{ChainstateManager, ChainType, ContextBuilder, KernelError};
    ///
    /// # let context = ContextBuilder::new().chain_type(ChainType::Regtest).build()?;
    /// # let chainman = ChainstateManager::builder(&context, "/data", "/blocks")?.build()?;
    /// let chain = chainman.active_chain();
    ///
    /// // Iterate through all blocks
    /// for entry in chain.iter() {
    ///     println!("Block {} at height {}",
    ///              entry.block_hash(),
    ///              entry.height());
    /// }
    ///
    /// // Or with enumerate for explicit height tracking
    /// for (height, entry) in chain.iter().enumerate() {
    ///     println!("Height {}: {}", height, entry.block_hash());
    /// }
    ///
    /// // Use iterator adapters
    /// let recent_blocks: Vec<_> = chain.iter()
    ///     .take(10)
    ///     .collect();
    /// # Ok::<(), KernelError>(())
    /// ```
    pub fn iter(&self) -> ChainIterator<'a> {
        ChainIterator::new(*self)
    }

    /// Returns the height of the chain tip.
    ///
    /// The height is the zero-based index of the tip block in the chain,
    /// where the genesis block has height 0. This is equivalent to
    /// calling `chain.tip().height()`.
    ///
    /// # Returns
    /// The height of the chain's tip block as an `i32`.
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::{ChainstateManager, ChainType, ContextBuilder, KernelError};
    ///
    /// # let context = ContextBuilder::new().chain_type(ChainType::Regtest).build()?;
    /// # let chainman = ChainstateManager::builder(&context, "/data", "/blocks")?.build()?;
    /// let chain = chainman.active_chain();
    /// let height = chain.height();
    ///
    /// println!("Chain has {} blocks (0 to {})", height + 1, height);
    /// # Ok::<(), KernelError>(())
    /// ```
    pub fn height(&self) -> i32 {
        unsafe { btck_chain_get_height(self.inner) }
    }
}

impl<'a> FromPtr<btck_Chain> for Chain<'a> {
    unsafe fn from_ptr(ptr: *const btck_Chain) -> Self {
        Chain {
            inner: ptr,
            marker: PhantomData,
        }
    }
}

impl<'a> Clone for Chain<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a> Copy for Chain<'a> {}
