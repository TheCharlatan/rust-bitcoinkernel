use std::{ffi::c_void, marker::PhantomData};

use libbitcoinkernel_sys::{
    btck_Block, btck_BlockHash, btck_BlockSpentOutputs, btck_Coin, btck_TransactionSpentOutputs,
    btck_block_copy, btck_block_count_transactions, btck_block_create, btck_block_destroy,
    btck_block_get_hash, btck_block_get_transaction_at, btck_block_hash_copy,
    btck_block_hash_create, btck_block_hash_destroy, btck_block_hash_equals,
    btck_block_hash_to_bytes, btck_block_spent_outputs_copy, btck_block_spent_outputs_count,
    btck_block_spent_outputs_destroy, btck_block_spent_outputs_get_transaction_spent_outputs_at,
    btck_block_to_bytes, btck_coin_confirmation_height, btck_coin_copy, btck_coin_destroy,
    btck_coin_get_output, btck_coin_is_coinbase, btck_transaction_spent_outputs_copy,
    btck_transaction_spent_outputs_count, btck_transaction_spent_outputs_destroy,
    btck_transaction_spent_outputs_get_coin_at,
};

use crate::{
    c_helpers, c_serialize,
    ffi::{
        c_helpers::present,
        sealed::{AsPtr, FromMutPtr, FromPtr},
    },
    KernelError,
};

use super::transaction::{TransactionRef, TxOutRef};

/// A type for a Block hash.
pub struct BlockHash {
    inner: *mut btck_BlockHash,
}

unsafe impl Send for BlockHash {}
unsafe impl Sync for BlockHash {}

impl BlockHash {
    pub fn new(raw_bytes: &[u8]) -> Result<Self, KernelError> {
        if raw_bytes.len() != 32 {
            return Err(KernelError::InvalidLength {
                expcted: 32,
                actual: raw_bytes.len(),
            });
        }
        let inner = unsafe { btck_block_hash_create(raw_bytes.as_ptr()) };

        if inner.is_null() {
            Err(KernelError::Internal(
                "Failed to create block hash from bytes".to_string(),
            ))
        } else {
            Ok(BlockHash { inner })
        }
    }

    /// Serializes the block hash to raw bytes.
    fn to_bytes(&self) -> [u8; 32] {
        let mut output = [0u8; 32];
        unsafe { btck_block_hash_to_bytes(self.inner, output.as_mut_ptr()) };
        output
    }
}

impl AsPtr<btck_BlockHash> for BlockHash {
    fn as_ptr(&self) -> *const btck_BlockHash {
        self.inner as *const _
    }
}

impl FromMutPtr<btck_BlockHash> for BlockHash {
    unsafe fn from_ptr(ptr: *mut btck_BlockHash) -> Self {
        BlockHash { inner: ptr }
    }
}

impl Clone for BlockHash {
    fn clone(&self) -> Self {
        BlockHash {
            inner: unsafe { btck_block_hash_copy(self.inner) },
        }
    }
}

impl Drop for BlockHash {
    fn drop(&mut self) {
        unsafe { btck_block_hash_destroy(self.inner) }
    }
}

impl From<[u8; 32]> for BlockHash {
    fn from(hash: [u8; 32]) -> Self {
        BlockHash::new(hash.as_slice()).expect("32-bytes array should always be valid")
    }
}

impl TryFrom<&[u8]> for BlockHash {
    type Error = KernelError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        BlockHash::new(bytes)
    }
}

impl From<BlockHash> for [u8; 32] {
    fn from(block_hash: BlockHash) -> Self {
        block_hash.to_bytes()
    }
}

impl From<&BlockHash> for [u8; 32] {
    fn from(block_hash: &BlockHash) -> Self {
        block_hash.to_bytes()
    }
}

impl PartialEq for BlockHash {
    fn eq(&self, other: &Self) -> bool {
        present(unsafe { btck_block_hash_equals(self.inner, other.inner) })
    }
}

impl Eq for BlockHash {}

impl std::fmt::Debug for BlockHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlockHash({:?})", self.to_bytes())
    }
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
        let hash_ptr = unsafe { btck_block_get_hash(self.inner) };
        unsafe { BlockHash::from_ptr(hash_ptr) }
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

    /// Returns an iterator over all transactions in this block.
    pub fn transactions(&self) -> BlockTransactionIter<'_> {
        BlockTransactionIter::new(self)
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

pub struct BlockTransactionIter<'a> {
    block: &'a Block,
    current_index: usize,
}

impl<'a> BlockTransactionIter<'a> {
    fn new(block: &'a Block) -> Self {
        Self {
            block,
            current_index: 0,
        }
    }
}

impl<'a> Iterator for BlockTransactionIter<'a> {
    type Item = TransactionRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.current_index;
        self.current_index += 1;
        self.block.transaction(index).ok()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self
            .block
            .transaction_count()
            .saturating_sub(self.current_index);
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for BlockTransactionIter<'a> {
    fn len(&self) -> usize {
        self.block
            .transaction_count()
            .saturating_sub(self.current_index)
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

    /// Returns an iterator over spent outputs for transactions in the block.
    fn iter(&self) -> BlockSpentOutputsIter<'_> {
        BlockSpentOutputsIter::new(unsafe { BlockSpentOutputsRef::from_ptr(self.as_ptr()) })
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

unsafe impl<'a> Send for BlockSpentOutputsRef<'a> {}
unsafe impl<'a> Sync for BlockSpentOutputsRef<'a> {}

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

pub struct BlockSpentOutputsIter<'a> {
    block_spent_outputs: BlockSpentOutputsRef<'a>,
    current_index: usize,
}

impl<'a> BlockSpentOutputsIter<'a> {
    fn new(block_spent_outputs: BlockSpentOutputsRef<'a>) -> Self {
        Self {
            block_spent_outputs,
            current_index: 0,
        }
    }
}

impl<'a> Iterator for BlockSpentOutputsIter<'a> {
    type Item = TransactionSpentOutputsRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_index >= self.block_spent_outputs.count() {
            return None;
        }

        let index = self.current_index;
        self.current_index += 1;

        let tx_out_ptr = unsafe {
            btck_block_spent_outputs_get_transaction_spent_outputs_at(
                self.block_spent_outputs.as_ptr(),
                index,
            )
        };

        if tx_out_ptr.is_null() {
            None
        } else {
            Some(unsafe { TransactionSpentOutputsRef::from_ptr(tx_out_ptr) })
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self
            .block_spent_outputs
            .count()
            .saturating_sub(self.current_index);
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for BlockSpentOutputsIter<'a> {
    fn len(&self) -> usize {
        self.block_spent_outputs
            .count()
            .saturating_sub(self.current_index)
    }
}

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

impl FromMutPtr<btck_TransactionSpentOutputs> for TransactionSpentOutputs {
    unsafe fn from_ptr(ptr: *mut btck_TransactionSpentOutputs) -> Self {
        TransactionSpentOutputs { inner: ptr }
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

unsafe impl<'a> Send for TransactionSpentOutputsRef<'a> {}
unsafe impl<'a> Sync for TransactionSpentOutputsRef<'a> {}

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

impl FromMutPtr<btck_Coin> for Coin {
    unsafe fn from_ptr(ptr: *mut btck_Coin) -> Self {
        Coin { inner: ptr }
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

unsafe impl<'a> Send for CoinRef<'a> {}
unsafe impl<'a> Sync for CoinRef<'a> {}

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

#[cfg(test)]
mod tests {

    use super::*;
    use crate::ffi::test_utils::{
        test_owned_clone_and_send, test_owned_trait_requirements, test_ref_trait_requirements,
    };
    use std::{
        fs::File,
        io::{BufRead, BufReader},
    };

    fn read_block_data() -> Vec<Vec<u8>> {
        let file = File::open("tests/block_data.txt").unwrap();
        let reader = BufReader::new(file);
        let mut lines = vec![];
        for line in reader.lines() {
            lines.push(hex::decode(line.unwrap()).unwrap());
        }
        lines
    }

    const VALID_HASH_BYTES1: [u8; 32] = [1u8; 32];
    const VALID_HASH_BYTES2: [u8; 32] = [2u8; 32];

    test_owned_trait_requirements!(test_block_hash_requirements, BlockHash, btck_BlockHash);

    test_owned_trait_requirements!(test_block_requirements, Block, btck_Block);

    test_owned_trait_requirements!(
        test_block_spent_outputs_requirements,
        BlockSpentOutputs,
        btck_BlockSpentOutputs
    );
    test_ref_trait_requirements!(
        test_block_spent_outputs_ref_requirements,
        BlockSpentOutputsRef<'static>,
        btck_BlockSpentOutputs
    );

    test_owned_trait_requirements!(
        test_transaction_spent_outputs_requirements,
        TransactionSpentOutputs,
        btck_TransactionSpentOutputs
    );
    test_ref_trait_requirements!(
        test_transaction_spent_outputs_ref_requirements,
        TransactionSpentOutputsRef<'static>,
        btck_TransactionSpentOutputs
    );

    test_owned_trait_requirements!(test_coin_requirements, Coin, btck_Coin);
    test_ref_trait_requirements!(test_coin_ref_requirements, CoinRef<'static>, btck_Coin);

    test_owned_clone_and_send!(
        test_block_hash_clone_send,
        BlockHash::from(VALID_HASH_BYTES1),
        BlockHash::from(VALID_HASH_BYTES2)
    );

    test_owned_clone_and_send!(
        test_block_clone_send,
        Block::new(&read_block_data()[0]).unwrap(),
        Block::new(&read_block_data()[1]).unwrap()
    );

    #[test]
    fn test_blockhash_new() {
        let bytes = [42u8; 32];
        let hash = BlockHash::new(bytes.as_slice());
        assert!(hash.is_ok());
    }

    #[test]
    fn test_blockhash_new_invalid_length() {
        let bytes = [1u8; 31];
        let hash = BlockHash::new(bytes.as_slice());
        assert!(matches!(hash, Err(KernelError::InvalidLength { .. })));
    }

    #[test]
    fn test_blockhash_try_from() {
        let bytes = [7u8; 32];
        let hash = BlockHash::try_from(bytes.as_slice());
        assert!(hash.is_ok());

        let short_bytes = [1u8; 16];
        let hash_err = BlockHash::try_from(short_bytes.as_slice());
        assert!(hash_err.is_err());
    }

    #[test]
    fn test_blockhash_into_array() {
        let original_bytes = VALID_HASH_BYTES1;
        let hash = BlockHash::from(original_bytes);
        let bytes: [u8; 32] = hash.into();
        assert_eq!(bytes, original_bytes);
    }

    #[test]
    fn test_blockhash_ref_into_array() {
        let original_bytes = VALID_HASH_BYTES1;
        let hash = BlockHash::from(original_bytes);
        let bytes: [u8; 32] = (&hash).into();
        assert_eq!(bytes, original_bytes);
    }

    #[test]
    fn test_blockhash_to_bytes() {
        let original_bytes = VALID_HASH_BYTES1;
        let hash = BlockHash::from(original_bytes);
        let bytes = hash.to_bytes();
        assert_eq!(bytes, original_bytes);
    }

    #[test]
    fn test_blockhash_equality() {
        let hash1 = BlockHash::from(VALID_HASH_BYTES1);
        let hash2 = BlockHash::from(VALID_HASH_BYTES2);
        let hash1_copy = BlockHash::from(VALID_HASH_BYTES1);

        assert_eq!(hash1, hash1_copy);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_blockhash_from_blocks() {
        let block_data = read_block_data();

        let block1 = Block::new(&block_data[0]).unwrap();
        let block2 = Block::new(&block_data[1]).unwrap();

        let hash1 = block1.hash();
        let hash2 = block2.hash();
        let hash1_again = block1.hash();

        assert_eq!(hash1, hash1_again);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_blockhash_bytes_roundtrip() {
        let original_bytes = VALID_HASH_BYTES1;
        let hash = BlockHash::from(original_bytes);
        let converted_bytes: [u8; 32] = hash.into();

        assert_eq!(original_bytes, converted_bytes);

        let hash2 = BlockHash::from(converted_bytes);
        let hash1_recreated = BlockHash::from(original_bytes);

        assert_eq!(hash1_recreated, hash2);
    }

    #[test]
    fn test_blockhash_debug() {
        let bytes = [5u8; 32];
        let hash = BlockHash::from(bytes);
        let debug_str = format!("{:?}", hash);
        assert!(debug_str.contains("BlockHash"));
    }

    #[test]
    fn test_multiple_conversions() {
        let original_bytes = VALID_HASH_BYTES1;
        let hash = BlockHash::from(original_bytes);

        let bytes1: [u8; 32] = (&hash).into();
        let bytes2: [u8; 32] = (&hash).into();
        let bytes3: [u8; 32] = (&hash).into();

        assert_eq!(bytes1, original_bytes);
        assert_eq!(bytes2, original_bytes);
        assert_eq!(bytes3, original_bytes);
    }

    #[test]
    fn test_block_new() {
        let block_data = read_block_data();
        let block = Block::new(&block_data[0]);
        assert!(block.is_ok());
    }

    #[test]
    fn test_block_new_invalid() {
        let invalid_data = [0u8; 10];
        let block = Block::new(invalid_data.as_slice());
        assert!(block.is_err());
    }

    #[test]
    fn test_block_empty() {
        let block = Block::new([].as_slice());
        assert!(block.is_err());
    }

    #[test]
    fn test_block_try_from() {
        let block_data = read_block_data();
        let block = Block::try_from(block_data[0].as_slice());
        assert!(block.is_ok());
    }

    #[test]
    fn test_block_transaction_count() {
        let block_data = read_block_data();
        let block = Block::new(&block_data[0]).unwrap();
        let count = block.transaction_count();
        assert!(count > 0);
    }

    #[test]
    fn test_block_transaction() {
        let block_data = read_block_data();
        let block = Block::new(&block_data[0]).unwrap();
        let tx = block.transaction(0);
        assert!(tx.is_ok());
    }

    #[test]
    fn test_block_transaction_out_of_bounds() {
        let block_data = read_block_data();
        let block = Block::new(&block_data[0]).unwrap();
        let count = block.transaction_count();
        let tx = block.transaction(count);
        assert!(matches!(tx, Err(KernelError::OutOfBounds)));
    }

    #[test]
    fn test_block_consensus_encode() {
        let block_data = read_block_data();
        let block = Block::new(&block_data[0]).unwrap();
        let encoded = block.consensus_encode();
        assert!(encoded.is_ok());
        let encoded_bytes = encoded.unwrap();
        assert!(!encoded_bytes.is_empty());
        assert_eq!(encoded_bytes.len(), block_data[0].len());
    }

    #[test]
    fn test_block_multiple_consensus_encode() {
        let block_data = read_block_data();
        let block = Block::new(&block_data[0]).unwrap();

        let bytes1 = block.consensus_encode().unwrap();
        let bytes2 = block.consensus_encode().unwrap();
        let bytes3 = block.consensus_encode().unwrap();

        assert_eq!(bytes1, block_data[0]);
        assert_eq!(bytes2, block_data[0]);
        assert_eq!(bytes3, block_data[0]);
    }

    #[test]
    fn test_block_try_into_vec() {
        let block_data = read_block_data();
        let block = Block::new(&block_data[0]).unwrap();
        let vec_result: Result<Vec<u8>, _> = block.clone().try_into();
        assert!(vec_result.is_ok());
    }

    #[test]
    fn test_block_try_into_vec_ref() {
        let block_data = read_block_data();
        let block = Block::new(&block_data[0]).unwrap();
        let vec_result: Result<Vec<u8>, _> = (&block).try_into();
        assert!(vec_result.is_ok());
    }

    #[test]
    fn test_block_multiple_transactions() {
        let block_data = read_block_data();
        let block = Block::new(&block_data[0]).unwrap();
        let count = block.transaction_count();

        for i in 0..count {
            let tx = block.transaction(i);
            assert!(tx.is_ok());
        }
    }

    #[test]
    fn test_different_blocks_different_hashes() {
        let block_data = read_block_data();

        let block1 = Block::new(&block_data[0]).unwrap();
        let block2 = Block::new(&block_data[1]).unwrap();

        assert_ne!(block1.hash(), block2.hash());
    }
}
