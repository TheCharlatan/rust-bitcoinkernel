// Copyright (c) 2023-present The Bitcoin Kernel developers
// Licensed under the MIT License. See LICENSE file in the project root.

use std::{ffi::c_void, marker::PhantomData};

use libbitcoinkernel_sys::{
    btck_Block, btck_BlockSpentOutputs, btck_BlockTreeEntry, btck_TransactionSpentOutputs,
    btck_block_copy, btck_block_count_transactions, btck_block_create, btck_block_destroy,
    btck_block_get_hash, btck_block_get_transaction_at, btck_block_hash_destroy,
    btck_block_spent_outputs_copy, btck_block_spent_outputs_count,
    btck_block_spent_outputs_destroy, btck_block_spent_outputs_get_transaction_spent_outputs_at,
    btck_block_to_bytes, btck_block_tree_entry_destroy, btck_block_tree_entry_get_block_hash,
    btck_block_tree_entry_get_height, btck_block_tree_entry_get_previous,
    btck_transaction_spent_outputs_copy, btck_transaction_spent_outputs_count,
    btck_transaction_spent_outputs_destroy, btck_transaction_spent_outputs_get_coin_at,
};

use crate::{c_serialize, state::ChainstateManager, KernelError, RefType};

use super::transaction::{Coin, Transaction};

/// A block tree entry that is tied to a specific [`ChainstateManager`].
///
/// Internally the [`ChainstateManager`] keeps an in-memory of the current block
/// tree once it is loaded. The [`BlockTreeEntry`] points to an entry in this tree.
/// It is only valid as long as the [`ChainstateManager`] it was retrieved from
/// remains in scope.
#[derive(Debug)]
pub struct BlockTreeEntry {
    inner: *mut btck_BlockTreeEntry,
    marker: PhantomData<ChainstateManager>,
}

unsafe impl Send for BlockTreeEntry {}
unsafe impl Sync for BlockTreeEntry {}

impl BlockTreeEntry {
    /// Creates a BlockTreeEntry from an FFI pointer for internal library use.
    pub(crate) fn from_ptr(inner: *mut btck_BlockTreeEntry) -> Self {
        Self {
            inner,
            marker: PhantomData,
        }
    }

    /// Move to the previous entry in the block tree. E.g. from height n to
    /// height n-1.
    pub fn prev(self) -> Result<BlockTreeEntry, KernelError> {
        let inner = unsafe { btck_block_tree_entry_get_previous(self.inner) };

        if inner.is_null() {
            return Err(KernelError::OutOfBounds);
        }

        Ok(BlockTreeEntry {
            inner,
            marker: self.marker,
        })
    }

    /// Returns the current height associated with this BlockTreeEntry.
    pub fn height(&self) -> i32 {
        unsafe { btck_block_tree_entry_get_height(self.inner) }
    }

    /// Returns the current block hash associated with this BlockTreeEntry.
    pub fn block_hash(&self) -> BlockHash {
        let hash = unsafe { btck_block_tree_entry_get_block_hash(self.inner) };
        let res = BlockHash {
            hash: unsafe { (&*hash).hash },
        };
        unsafe { btck_block_hash_destroy(hash) };
        res
    }

    /// Get the inner FFI pointer for internal library use
    pub(crate) fn as_ptr(&self) -> *mut btck_BlockTreeEntry {
        self.inner
    }
}

impl Drop for BlockTreeEntry {
    fn drop(&mut self) {
        unsafe { btck_block_tree_entry_destroy(self.inner) };
    }
}

/// A type for a Block hash.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct BlockHash {
    pub hash: [u8; 32],
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
    /// Creates a Block from an FFI pointer for internal library use.
    pub(crate) fn from_ptr(inner: *mut btck_Block) -> Self {
        Self { inner }
    }

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
        let tx = unsafe { btck_block_get_transaction_at(self.inner, index) };
        Ok(Transaction::from_ptr(tx))
    }

    /// Consensus encodes the block to Bitcoin wire format.
    pub fn consensus_encode(&self) -> Result<Vec<u8>, KernelError> {
        c_serialize(|callback, user_data| unsafe {
            btck_block_to_bytes(self.inner, Some(callback), user_data)
        })
    }

    /// Get the inner FFI pointer for internal library use
    pub(crate) fn as_ptr(&self) -> *mut btck_Block {
        self.inner
    }
}

impl TryFrom<Block> for Vec<u8> {
    type Error = KernelError;

    fn try_from(block: Block) -> Result<Self, KernelError> {
        block.consensus_encode()
    }
}

impl TryFrom<&[u8]> for Block {
    type Error = KernelError;

    fn try_from(raw_block: &[u8]) -> Result<Self, Self::Error> {
        let inner =
            unsafe { btck_block_create(raw_block.as_ptr() as *const c_void, raw_block.len()) };
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
    /// Creates BlockSpentOutputs from an FFI pointer for internal library use.
    pub(crate) fn from_ptr(inner: *mut btck_BlockSpentOutputs) -> Self {
        Self { inner }
    }

    /// Returns the number of transactions that have spent output data.
    ///
    /// Note: This excludes the coinbase transaction, which has no inputs.
    pub fn count(&self) -> usize {
        unsafe { btck_block_spent_outputs_count(self.inner) }
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
            btck_block_spent_outputs_get_transaction_spent_outputs_at(self.inner, transaction_index)
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
        unsafe { btck_transaction_spent_outputs_count(self.inner) }
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
            btck_transaction_spent_outputs_get_coin_at(self.inner as *const _, coin_index)
        };
        if coin_ptr.is_null() {
            return Err(KernelError::OutOfBounds);
        }

        Ok(RefType::new(Coin::from_ptr(coin_ptr)))
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
