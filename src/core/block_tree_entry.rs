use std::marker::PhantomData;

use libbitcoinkernel_sys::{
    btck_BlockTreeEntry, btck_block_tree_entry_get_block_hash, btck_block_tree_entry_get_height,
    btck_block_tree_entry_get_previous,
};

use crate::{
    core::block::BlockHashRef,
    ffi::sealed::{AsPtr, FromPtr},
    ChainstateManager,
};

/// A block tree entry that is tied to a specific [`ChainstateManager`].
///
/// Internally the [`ChainstateManager`] keeps an in-memory of the current block
/// tree once it is loaded. The [`BlockTreeEntry`] points to an entry in this tree.
/// It is only valid as long as the [`ChainstateManager`] it was retrieved from
/// remains in scope.
#[derive(Debug)]
pub struct BlockTreeEntry<'a> {
    inner: *const btck_BlockTreeEntry,
    marker: PhantomData<&'a ChainstateManager>,
}

unsafe impl Send for BlockTreeEntry<'_> {}
unsafe impl Sync for BlockTreeEntry<'_> {}

impl<'a> BlockTreeEntry<'a> {
    /// Move to the previous entry in the block tree. E.g. from height n to
    /// height n-1.
    pub fn prev(self) -> Option<BlockTreeEntry<'a>> {
        let inner = unsafe { btck_block_tree_entry_get_previous(self.inner) };

        if inner.is_null() {
            return None;
        }

        Some(unsafe { BlockTreeEntry::from_ptr(inner) })
    }

    /// Returns the current height associated with this BlockTreeEntry.
    pub fn height(&self) -> i32 {
        unsafe { btck_block_tree_entry_get_height(self.inner) }
    }

    /// Returns the current block hash associated with this BlockTreeEntry.
    pub fn block_hash(&self) -> BlockHashRef<'_> {
        let hash_ptr = unsafe { btck_block_tree_entry_get_block_hash(self.inner) };
        unsafe { BlockHashRef::from_ptr(hash_ptr) }
    }
}

impl<'a> AsPtr<btck_BlockTreeEntry> for BlockTreeEntry<'a> {
    fn as_ptr(&self) -> *const btck_BlockTreeEntry {
        self.inner
    }
}

impl<'a> FromPtr<btck_BlockTreeEntry> for BlockTreeEntry<'a> {
    unsafe fn from_ptr(ptr: *const btck_BlockTreeEntry) -> Self {
        BlockTreeEntry {
            inner: ptr,
            marker: PhantomData,
        }
    }
}

impl<'a> Clone for BlockTreeEntry<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a> Copy for BlockTreeEntry<'a> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::test_utils::test_ref_trait_requirements;

    test_ref_trait_requirements!(
        test_blocktreeentry_implementations,
        BlockTreeEntry<'static>,
        btck_BlockTreeEntry
    );
}
