use std::{ffi::c_void, marker::PhantomData};

use libbitcoinkernel_sys::{
    btck_Block, btck_BlockSpentOutputs, btck_Coin, btck_TransactionSpentOutputs, btck_block_copy,
    btck_block_count_transactions, btck_block_create, btck_block_destroy, btck_block_get_hash,
    btck_block_get_transaction_at, btck_block_hash_destroy, btck_block_spent_outputs_copy,
    btck_block_spent_outputs_count, btck_block_spent_outputs_destroy,
    btck_block_spent_outputs_get_transaction_spent_outputs_at, btck_block_to_bytes,
    btck_coin_confirmation_height, btck_coin_copy, btck_coin_destroy, btck_coin_get_output,
    btck_coin_is_coinbase, btck_transaction_spent_outputs_copy,
    btck_transaction_spent_outputs_count, btck_transaction_spent_outputs_destroy,
    btck_transaction_spent_outputs_get_coin_at,
};

use crate::{
    c_helpers, c_serialize,
    ffi::sealed::{AsPtr, FromMutPtr, FromPtr},
    KernelError,
};

use super::transaction::{TransactionRef, TxOutRef};

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
    pub fn new(raw_block: &[u8]) -> Result<Self, KernelError> {
        let inner =
            unsafe { btck_block_create(raw_block.as_ptr() as *const c_void, raw_block.len()) };

        if inner.is_null() {
            Err(KernelError::Internal(
                "Failed to create Block from bytes".to_string(),
            ))
        } else {
            Ok(Block { inner })
        }
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
        unsafe { btck_block_count_transactions(self.inner) }
    }

    /// Returns the transaction at the specified index.
    ///
    /// # Arguments
    /// * `index` - The zero-based index of the transaction (0 is the coinbase)
    ///
    /// # Errors
    /// Returns [`KernelError::OutOfBounds`] if the index is invalid.
    pub fn transaction(&self, index: usize) -> Result<TransactionRef<'_>, KernelError> {
        if index >= self.transaction_count() {
            return Err(KernelError::OutOfBounds);
        }
        let tx_ptr = unsafe { btck_block_get_transaction_at(self.inner, index) };
        Ok(unsafe { TransactionRef::from_ptr(tx_ptr) })
    }

    /// Consensus encodes the block to Bitcoin wire format.
    pub fn consensus_encode(&self) -> Result<Vec<u8>, KernelError> {
        c_serialize(|callback, user_data| unsafe {
            btck_block_to_bytes(self.inner, Some(callback), user_data)
        })
    }
}

impl AsPtr<btck_Block> for Block {
    fn as_ptr(&self) -> *const btck_Block {
        self.inner as *const _
    }
}

impl FromMutPtr<btck_Block> for Block {
    unsafe fn from_ptr(ptr: *mut btck_Block) -> Self {
        Block { inner: ptr }
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

impl TryFrom<&[u8]> for Block {
    type Error = KernelError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Block::new(bytes)
    }
}

impl TryFrom<Block> for Vec<u8> {
    type Error = KernelError;

    fn try_from(block: Block) -> Result<Self, Self::Error> {
        block.consensus_encode()
    }
}

impl TryFrom<&Block> for Vec<u8> {
    type Error = KernelError;

    fn try_from(block: &Block) -> Result<Self, Self::Error> {
        block.consensus_encode()
    }
}

/// Common operations for block spent outputs, implemented by both owned and borrowed types.
pub trait BlockSpentOutputsExt: AsPtr<btck_BlockSpentOutputs> {
    /// Returns the number of transactions that have spent output data.
    ///
    /// Note: This excludes the coinbase transaction, which has no inputs.
    fn count(&self) -> usize {
        unsafe { btck_block_spent_outputs_count(self.as_ptr()) }
    }

    /// Returns a reference to the spent outputs for a specific transaction in the block.
    ///
    /// # Arguments
    /// * `transaction_index` - The index of the transaction (0-based, excluding coinbase)
    ///
    /// # Returns
    /// * `Ok(RefType<TransactionSpentOutputs, BlockSpentOutputs>)` - A reference to the transaction's spent outputs
    /// * `Err(KernelError::OutOfBounds)` - If the index is invalid
    fn transaction_spent_outputs(
        &self,
        transaction_index: usize,
    ) -> Result<TransactionSpentOutputsRef<'_>, KernelError> {
        if transaction_index >= self.count() {
            return Err(KernelError::OutOfBounds);
        }
        let tx_out_ptr = unsafe {
            btck_block_spent_outputs_get_transaction_spent_outputs_at(
                self.as_ptr(),
                transaction_index,
            )
        };
        if tx_out_ptr.is_null() {
            return Err(KernelError::OutOfBounds);
        }
        Ok(unsafe { TransactionSpentOutputsRef::from_ptr(tx_out_ptr) })
    }
}

/// Spent output data for all transactions in a block.
///
/// This contains the previous outputs that were consumed by all transactions
/// in a specific block.
#[derive(Debug)]
pub struct BlockSpentOutputs {
    inner: *mut btck_BlockSpentOutputs,
}

unsafe impl Send for BlockSpentOutputs {}
unsafe impl Sync for BlockSpentOutputs {}

impl BlockSpentOutputs {
    pub fn as_ref(&self) -> BlockSpentOutputsRef<'_> {
        unsafe { BlockSpentOutputsRef::from_ptr(self.inner as *const _) }
    }
}

impl FromMutPtr<btck_BlockSpentOutputs> for BlockSpentOutputs {
    unsafe fn from_ptr(ptr: *mut btck_BlockSpentOutputs) -> Self {
        BlockSpentOutputs { inner: ptr }
    }
}

impl AsPtr<btck_BlockSpentOutputs> for BlockSpentOutputs {
    fn as_ptr(&self) -> *const btck_BlockSpentOutputs {
        self.inner as *const _
    }
}

impl BlockSpentOutputsExt for BlockSpentOutputs {}

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

pub struct BlockSpentOutputsRef<'a> {
    inner: *const btck_BlockSpentOutputs,
    marker: PhantomData<&'a ()>,
}

impl<'a> BlockSpentOutputsRef<'a> {
    pub fn to_owned(&self) -> BlockSpentOutputs {
        BlockSpentOutputs {
            inner: unsafe { btck_block_spent_outputs_copy(self.inner) },
        }
    }
}

impl<'a> AsPtr<btck_BlockSpentOutputs> for BlockSpentOutputsRef<'a> {
    fn as_ptr(&self) -> *const btck_BlockSpentOutputs {
        self.inner
    }
}

impl<'a> FromPtr<btck_BlockSpentOutputs> for BlockSpentOutputsRef<'a> {
    unsafe fn from_ptr(ptr: *const btck_BlockSpentOutputs) -> Self {
        BlockSpentOutputsRef {
            inner: ptr,
            marker: PhantomData,
        }
    }
}

impl<'a> BlockSpentOutputsExt for BlockSpentOutputsRef<'a> {}

impl<'a> Clone for BlockSpentOutputsRef<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a> Copy for BlockSpentOutputsRef<'a> {}

/// Common operations for transaction spent outputs, implemented by both owned and borrowed types.
pub trait TransactionSpentOutputsExt: AsPtr<btck_TransactionSpentOutputs> {
    /// Returns the number of coins spent by this transaction
    fn count(&self) -> usize {
        unsafe { btck_transaction_spent_outputs_count(self.as_ptr()) }
    }

    /// Returns a reference to the coin at the specified input index.
    ///
    /// # Arguments
    /// * `coin_index` - The index corresponding to the transaction input
    ///
    /// # Returns
    /// * `Ok(RefType<Coin, TransactionSpentOutputs>)` - A reference to the coin
    /// * `Err(KernelError::OutOfBounds)` - If the index is invalid
    fn coin(&self, coin_index: usize) -> Result<CoinRef<'_>, KernelError> {
        if coin_index >= self.count() {
            return Err(KernelError::OutOfBounds);
        }
        let coin_ptr =
            unsafe { btck_transaction_spent_outputs_get_coin_at(self.as_ptr(), coin_index) };
        Ok(unsafe { CoinRef::from_ptr(coin_ptr) })
    }
}

/// Spent output data for a single transaction.
///
/// Contains all the coins (UTXOs) that were consumed by a specific transaction's
/// inputs, in the same order as the transaction's inputs.
#[derive(Debug)]
pub struct TransactionSpentOutputs {
    inner: *mut btck_TransactionSpentOutputs,
}

unsafe impl Send for TransactionSpentOutputs {}
unsafe impl Sync for TransactionSpentOutputs {}

impl TransactionSpentOutputs {
    pub fn as_ref(&self) -> TransactionSpentOutputsRef<'_> {
        unsafe { TransactionSpentOutputsRef::from_ptr(self.inner as *const _) }
    }
}

impl AsPtr<btck_TransactionSpentOutputs> for TransactionSpentOutputs {
    fn as_ptr(&self) -> *const btck_TransactionSpentOutputs {
        self.inner as *const _
    }
}

impl TransactionSpentOutputsExt for TransactionSpentOutputs {}

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

pub struct TransactionSpentOutputsRef<'a> {
    inner: *const btck_TransactionSpentOutputs,
    marker: PhantomData<&'a ()>,
}

impl<'a> TransactionSpentOutputsRef<'a> {
    pub fn to_owned(&self) -> TransactionSpentOutputs {
        TransactionSpentOutputs {
            inner: unsafe { btck_transaction_spent_outputs_copy(self.inner) },
        }
    }
}

impl<'a> AsPtr<btck_TransactionSpentOutputs> for TransactionSpentOutputsRef<'a> {
    fn as_ptr(&self) -> *const btck_TransactionSpentOutputs {
        self.inner
    }
}

impl<'a> FromPtr<btck_TransactionSpentOutputs> for TransactionSpentOutputsRef<'a> {
    unsafe fn from_ptr(ptr: *const btck_TransactionSpentOutputs) -> Self {
        TransactionSpentOutputsRef {
            inner: ptr,
            marker: PhantomData,
        }
    }
}

impl<'a> TransactionSpentOutputsExt for TransactionSpentOutputsRef<'a> {}

impl<'a> Clone for TransactionSpentOutputsRef<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a> Copy for TransactionSpentOutputsRef<'a> {}

/// Common operations for coins, implemented by both owned and borrowed types.
pub trait CoinExt: AsPtr<btck_Coin> {
    /// Returns the height of the block where this coin was created.
    fn confirmation_height(&self) -> u32 {
        unsafe { btck_coin_confirmation_height(self.as_ptr()) }
    }

    /// Returns true if this coin came from a coinbase transaction.
    fn is_coinbase(&self) -> bool {
        let result = unsafe { btck_coin_is_coinbase(self.as_ptr()) };
        c_helpers::present(result)
    }

    /// Returns a reference to the transaction output data for this coin.
    ///
    /// # Returns
    /// * `Ok(RefType<TxOut, Coin>)` - A reference to the transaction output
    /// * `Err(KernelError::Internal)` - If the coin data is corrupted
    fn output(&self) -> TxOutRef<'_> {
        let output_ptr = unsafe { btck_coin_get_output(self.as_ptr()) };
        unsafe { TxOutRef::from_ptr(output_ptr) }
    }
}

/// A coin (UTXO) representing a transaction output.
///
/// Contains the transaction output data along with metadata about when
/// it was created and whether it came from a coinbase transaction.
#[derive(Debug)]
pub struct Coin {
    inner: *mut btck_Coin,
}

unsafe impl Send for Coin {}
unsafe impl Sync for Coin {}

impl Coin {
    pub fn as_ref(&self) -> CoinRef<'_> {
        unsafe { CoinRef::from_ptr(self.inner as *const _) }
    }
}

impl AsPtr<btck_Coin> for Coin {
    fn as_ptr(&self) -> *const btck_Coin {
        self.inner as *const _
    }
}

impl CoinExt for Coin {}

impl Clone for Coin {
    fn clone(&self) -> Self {
        Coin {
            inner: unsafe { btck_coin_copy(self.inner) },
        }
    }
}

impl Drop for Coin {
    fn drop(&mut self) {
        unsafe { btck_coin_destroy(self.inner) };
    }
}

pub struct CoinRef<'a> {
    inner: *const btck_Coin,
    marker: PhantomData<&'a ()>,
}

impl<'a> CoinRef<'a> {
    pub fn to_owned(&self) -> Coin {
        Coin {
            inner: unsafe { btck_coin_copy(self.inner) },
        }
    }
}

impl<'a> AsPtr<btck_Coin> for CoinRef<'a> {
    fn as_ptr(&self) -> *const btck_Coin {
        self.inner
    }
}

impl<'a> FromPtr<btck_Coin> for CoinRef<'a> {
    unsafe fn from_ptr(ptr: *const btck_Coin) -> Self {
        CoinRef {
            inner: ptr,
            marker: PhantomData,
        }
    }
}

impl<'a> CoinExt for CoinRef<'a> {}

impl<'a> Clone for CoinRef<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a> Copy for CoinRef<'a> {}
