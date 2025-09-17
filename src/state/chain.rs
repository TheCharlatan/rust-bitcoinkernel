use std::marker::PhantomData;

use libbitcoinkernel_sys::{
    btck_Chain, btck_chain_contains, btck_chain_get_by_height, btck_chain_get_genesis,
    btck_chain_get_height, btck_chain_get_tip,
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
