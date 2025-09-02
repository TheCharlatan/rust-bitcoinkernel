use std::marker::PhantomData;

use libbitcoinkernel_sys::{
    btck_Chain, btck_chain_contains, btck_chain_destroy, btck_chain_get_by_height,
    btck_chain_get_genesis, btck_chain_get_tip,
};

use crate::{core::block::BlockTreeEntry, ffi::c_helpers};

use super::ChainstateManager;

/// Represents a chain instance for querying and traversal.
pub struct Chain {
    inner: *mut btck_Chain,
    marker: PhantomData<ChainstateManager>,
}

impl Chain {
    /// Creates a Chain from an FFI pointer for internal library use.
    pub(crate) fn from_ptr(inner: *mut btck_Chain) -> Self {
        Self {
            inner,
            marker: PhantomData,
        }
    }

    /// Returns the tip (highest block) of the active chain.
    pub fn tip(&self) -> BlockTreeEntry {
        BlockTreeEntry::from_ptr(unsafe { btck_chain_get_tip(self.inner) })
    }

    /// Returns the genesis block (height 0) of the chain.
    pub fn genesis(&self) -> BlockTreeEntry {
        BlockTreeEntry::from_ptr(unsafe { btck_chain_get_genesis(self.inner) })
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

        Some(BlockTreeEntry::from_ptr(entry))
    }

    /// Returns the next block after the given entry.
    pub fn next(&self, entry: &BlockTreeEntry) -> Option<BlockTreeEntry> {
        self.at_height((entry.height() + 1) as usize)
    }

    /// Checks if the given block entry is part of the active chain.
    pub fn contains(&self, entry: &BlockTreeEntry) -> bool {
        let result = unsafe { btck_chain_contains(self.inner, entry.as_ptr()) };
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
