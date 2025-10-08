use std::{ffi::c_void, marker::PhantomData};

use libbitcoinkernel_sys::{
    btck_Transaction, btck_TransactionInput, btck_TransactionOutPoint, btck_TransactionOutput,
    btck_Txid, btck_transaction_copy, btck_transaction_count_inputs,
    btck_transaction_count_outputs, btck_transaction_create, btck_transaction_destroy,
    btck_transaction_get_input_at, btck_transaction_get_output_at, btck_transaction_get_txid,
    btck_transaction_input_copy, btck_transaction_input_destroy,
    btck_transaction_input_get_out_point, btck_transaction_out_point_copy,
    btck_transaction_out_point_destroy, btck_transaction_out_point_get_index,
    btck_transaction_out_point_get_txid, btck_transaction_output_copy,
    btck_transaction_output_create, btck_transaction_output_destroy,
    btck_transaction_output_get_amount, btck_transaction_output_get_script_pubkey,
    btck_transaction_to_bytes, btck_txid_copy, btck_txid_destroy, btck_txid_equals,
    btck_txid_to_bytes,
};

use crate::{
    c_serialize,
    ffi::{
        c_helpers::present,
        sealed::{AsPtr, FromMutPtr, FromPtr},
    },
    KernelError, ScriptPubkeyExt,
};

use super::script::ScriptPubkeyRef;

/// Common operations for transactions, implemented by both owned and borrowed types.
pub trait TransactionExt: AsPtr<btck_Transaction> {
    /// Returns the number of outputs in this transaction.
    fn output_count(&self) -> usize {
        unsafe { btck_transaction_count_outputs(self.as_ptr()) as usize }
    }

    /// Returns a reference to the output at the specified index.
    ///
    /// # Arguments
    /// * `index` - The zero-based index of the output to retrieve
    ///
    /// # Returns
    /// * `Ok(RefType<TxOut, Transaction>)` - A reference to the output
    /// * `Err(KernelError::OutOfBounds)` - If the index is invalid
    fn output(&self, index: usize) -> Result<TxOutRef<'_>, KernelError> {
        if index >= self.output_count() {
            return Err(KernelError::OutOfBounds);
        }

        let tx_out_ref =
            unsafe { TxOutRef::from_ptr(btck_transaction_get_output_at(self.as_ptr(), index)) };

        Ok(tx_out_ref)
    }

    fn input_count(&self) -> usize {
        unsafe { btck_transaction_count_inputs(self.as_ptr()) as usize }
    }

    /// Returns a reference to the input at the specified index.
    ///
    /// # Arguments
    /// * `index` - The zero-based index of the input to retrieve
    ///
    /// # Returns
    /// * `Ok(TxInRef)` - A reference to the input
    /// * `Err(KernelError::OutOfBounds)` - If the index is invalid
    fn input(&self, index: usize) -> Result<TxInRef<'_>, KernelError> {
        if index >= self.input_count() {
            return Err(KernelError::OutOfBounds);
        }

        let tx_in_ref =
            unsafe { TxInRef::from_ptr(btck_transaction_get_input_at(self.as_ptr(), index)) };
        Ok(tx_in_ref)
    }

    /// Returns a reference to the transaction ID (txid) of this transaction.
    fn txid(&self) -> TxidRef<'_> {
        let ptr = unsafe { btck_transaction_get_txid(self.as_ptr()) };
        unsafe { TxidRef::from_ptr(ptr) }
    }

    /// Consensus encodes the transaction to Bitcoin wire format.
    fn consensus_encode(&self) -> Result<Vec<u8>, KernelError> {
        c_serialize(|callback, user_data| unsafe {
            btck_transaction_to_bytes(self.as_ptr(), Some(callback), user_data)
        })
    }
}

/// A Bitcoin transaction.
pub struct Transaction {
    inner: *mut btck_Transaction,
}

unsafe impl Send for Transaction {}
unsafe impl Sync for Transaction {}

impl Transaction {
    pub fn new(transaction_bytes: &[u8]) -> Result<Self, KernelError> {
        let inner = unsafe {
            btck_transaction_create(
                transaction_bytes.as_ptr() as *const c_void,
                transaction_bytes.len(),
            )
        };

        if inner.is_null() {
            Err(KernelError::Internal(
                "Failed to create transaction from bytes".to_string(),
            ))
        } else {
            Ok(Transaction { inner })
        }
    }

    pub fn as_ref(&self) -> TransactionRef<'_> {
        unsafe { TransactionRef::from_ptr(self.inner as *const _) }
    }
}

impl AsPtr<btck_Transaction> for Transaction {
    fn as_ptr(&self) -> *const btck_Transaction {
        self.inner as *const _
    }
}

impl FromMutPtr<btck_Transaction> for Transaction {
    unsafe fn from_ptr(ptr: *mut btck_Transaction) -> Self {
        Transaction { inner: ptr }
    }
}

impl TransactionExt for Transaction {}

impl Clone for Transaction {
    fn clone(&self) -> Self {
        Transaction {
            inner: unsafe { btck_transaction_copy(self.inner) },
        }
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        unsafe { btck_transaction_destroy(self.inner) }
    }
}

impl TryFrom<&[u8]> for Transaction {
    type Error = KernelError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Transaction::new(bytes)
    }
}

impl TryFrom<Transaction> for Vec<u8> {
    type Error = KernelError;

    fn try_from(transaction: Transaction) -> Result<Self, Self::Error> {
        transaction.consensus_encode()
    }
}

impl TryFrom<&Transaction> for Vec<u8> {
    type Error = KernelError;

    fn try_from(transaction: &Transaction) -> Result<Self, Self::Error> {
        transaction.consensus_encode()
    }
}

pub struct TransactionRef<'a> {
    inner: *const btck_Transaction,
    marker: PhantomData<&'a ()>,
}

unsafe impl<'a> Send for TransactionRef<'a> {}
unsafe impl<'a> Sync for TransactionRef<'a> {}

impl<'a> TransactionRef<'a> {
    pub fn to_owned(&self) -> Transaction {
        Transaction {
            inner: unsafe { btck_transaction_copy(self.inner) },
        }
    }
}

impl<'a> AsPtr<btck_Transaction> for TransactionRef<'a> {
    fn as_ptr(&self) -> *const btck_Transaction {
        self.inner
    }
}

impl<'a> FromPtr<btck_Transaction> for TransactionRef<'a> {
    unsafe fn from_ptr(ptr: *const btck_Transaction) -> Self {
        TransactionRef {
            inner: ptr,
            marker: PhantomData,
        }
    }
}
impl<'a> TransactionExt for TransactionRef<'a> {}

impl<'a> Clone for TransactionRef<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a> Copy for TransactionRef<'a> {}

/// Common operations for transaction outputs, implemented by both owned and borrowed types.
pub trait TxOutExt: AsPtr<btck_TransactionOutput> {
    /// Returns the amount of this output in satoshis.
    fn value(&self) -> i64 {
        unsafe { btck_transaction_output_get_amount(self.as_ptr()) }
    }

    /// Returns a reference to the script pubkey that defines how this output can be spent.
    ///
    /// # Returns
    /// * `RefType<ScriptPubkey, TxOut>` - A reference to the script pubkey
    fn script_pubkey(&self) -> ScriptPubkeyRef<'_> {
        let ptr = unsafe { btck_transaction_output_get_script_pubkey(self.as_ptr()) };
        unsafe { ScriptPubkeyRef::from_ptr(ptr) }
    }
}

/// A single transaction output containing a value and spending conditions.
///
/// Transaction outputs can be created from a script pubkey and amount, or retrieved
/// from existing transactions. They represent spendable coins in the UTXO set.
#[derive(Debug)]
pub struct TxOut {
    inner: *mut btck_TransactionOutput,
}

unsafe impl Send for TxOut {}
unsafe impl Sync for TxOut {}

impl TxOut {
    /// Creates a new transaction output with the specified script and amount.
    ///
    /// # Arguments
    /// * `script_pubkey` - The script defining how this output can be spent
    /// * `amount` - The amount in satoshis
    pub fn new(script_pubkey: &impl ScriptPubkeyExt, amount: i64) -> Self {
        TxOut {
            inner: unsafe { btck_transaction_output_create(script_pubkey.as_ptr(), amount) },
        }
    }

    pub fn as_ref(&self) -> TxOutRef<'_> {
        unsafe { TxOutRef::from_ptr(self.inner as *const _) }
    }
}

impl AsPtr<btck_TransactionOutput> for TxOut {
    fn as_ptr(&self) -> *const btck_TransactionOutput {
        self.inner as *const _
    }
}

impl FromMutPtr<btck_TransactionOutput> for TxOut {
    unsafe fn from_ptr(ptr: *mut btck_TransactionOutput) -> Self {
        TxOut { inner: ptr }
    }
}

impl TxOutExt for TxOut {}

impl Clone for TxOut {
    fn clone(&self) -> Self {
        TxOut {
            inner: unsafe { btck_transaction_output_copy(self.inner) },
        }
    }
}

impl Drop for TxOut {
    fn drop(&mut self) {
        unsafe { btck_transaction_output_destroy(self.inner) }
    }
}

pub struct TxOutRef<'a> {
    inner: *const btck_TransactionOutput,
    marker: PhantomData<&'a ()>,
}

unsafe impl<'a> Send for TxOutRef<'a> {}
unsafe impl<'a> Sync for TxOutRef<'a> {}

impl<'a> TxOutRef<'a> {
    pub fn to_owned(&self) -> TxOut {
        TxOut {
            inner: unsafe { btck_transaction_output_copy(self.inner) },
        }
    }
}

impl<'a> AsPtr<btck_TransactionOutput> for TxOutRef<'a> {
    fn as_ptr(&self) -> *const btck_TransactionOutput {
        self.inner as *const _
    }
}

impl<'a> FromPtr<btck_TransactionOutput> for TxOutRef<'a> {
    unsafe fn from_ptr(ptr: *const btck_TransactionOutput) -> Self {
        TxOutRef {
            inner: ptr,
            marker: PhantomData,
        }
    }
}

impl<'a> TxOutExt for TxOutRef<'a> {}

impl<'a> Clone for TxOutRef<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a> Copy for TxOutRef<'a> {}

/// Common operations for transaction inputs, implemented by both owned and borrowed types.
pub trait TxInExt: AsPtr<btck_TransactionInput> {
    /// Returns a reference to the outpoint being spent by this input.
    ///
    /// The outpoint identifies which previous transaction output this input is spending.
    fn outpoint(&self) -> TxOutPointRef<'_> {
        let ptr = unsafe { btck_transaction_input_get_out_point(self.as_ptr()) };
        unsafe { TxOutPointRef::from_ptr(ptr) }
    }
}

/// A single transaction input referencing a previous output to be spent.
#[derive(Debug)]
pub struct TxIn {
    inner: *mut btck_TransactionInput,
}

unsafe impl Send for TxIn {}
unsafe impl Sync for TxIn {}

impl TxIn {
    pub fn as_ref(&self) -> TxInRef<'_> {
        unsafe { TxInRef::from_ptr(self.inner as *const _) }
    }
}

impl AsPtr<btck_TransactionInput> for TxIn {
    fn as_ptr(&self) -> *const btck_TransactionInput {
        self.inner as *const _
    }
}

impl FromMutPtr<btck_TransactionInput> for TxIn {
    unsafe fn from_ptr(ptr: *mut btck_TransactionInput) -> Self {
        TxIn { inner: ptr }
    }
}

impl TxInExt for TxIn {}

impl Clone for TxIn {
    fn clone(&self) -> Self {
        TxIn {
            inner: unsafe { btck_transaction_input_copy(self.inner) },
        }
    }
}

impl Drop for TxIn {
    fn drop(&mut self) {
        unsafe { btck_transaction_input_destroy(self.inner) }
    }
}

pub struct TxInRef<'a> {
    inner: *const btck_TransactionInput,
    marker: PhantomData<&'a ()>,
}

unsafe impl<'a> Send for TxInRef<'a> {}
unsafe impl<'a> Sync for TxInRef<'a> {}

impl<'a> TxInRef<'a> {
    /// Creates an owned copy of this transaction input.
    pub fn to_owned(&self) -> TxIn {
        TxIn {
            inner: unsafe { btck_transaction_input_copy(self.inner) },
        }
    }
}

impl<'a> AsPtr<btck_TransactionInput> for TxInRef<'a> {
    fn as_ptr(&self) -> *const btck_TransactionInput {
        self.inner as *const _
    }
}

impl<'a> FromPtr<btck_TransactionInput> for TxInRef<'a> {
    unsafe fn from_ptr(ptr: *const btck_TransactionInput) -> Self {
        TxInRef {
            inner: ptr,
            marker: PhantomData,
        }
    }
}

impl<'a> TxInExt for TxInRef<'a> {}

impl<'a> Clone for TxInRef<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a> Copy for TxInRef<'a> {}

/// Common operations for transaction out points, implemented by both owned and borrowed types.
pub trait TxOutPointExt: AsPtr<btck_TransactionOutPoint> {
    /// Returns the output index within the referenced transaction.
    ///
    /// This is the zero-based index of the output in the transaction's output list.
    fn index(&self) -> u32 {
        unsafe { btck_transaction_out_point_get_index(self.as_ptr()) }
    }

    /// Returns a reference to the transaction ID of the transaction containing this output.
    fn txid(&self) -> TxidRef<'_> {
        let ptr = unsafe { btck_transaction_out_point_get_txid(self.as_ptr()) };
        unsafe { TxidRef::from_ptr(ptr) }
    }
}

/// A reference to a specific output in a previous transaction.
///
/// An outpoint uniquely identifies a transaction output by combining a transaction ID
/// with an output index. Outpoints are used in transaction inputs to specify which
/// previous outputs are being spent.
#[derive(Debug)]
pub struct TxOutPoint {
    inner: *mut btck_TransactionOutPoint,
}

unsafe impl Send for TxOutPoint {}
unsafe impl Sync for TxOutPoint {}

impl TxOutPoint {
    /// Returns a borrowed reference to this outpoint.
    pub fn as_ref(&self) -> TxOutPointRef<'_> {
        unsafe { TxOutPointRef::from_ptr(self.inner as *const _) }
    }
}

impl AsPtr<btck_TransactionOutPoint> for TxOutPoint {
    fn as_ptr(&self) -> *const btck_TransactionOutPoint {
        self.inner as *const _
    }
}

impl FromMutPtr<btck_TransactionOutPoint> for TxOutPoint {
    unsafe fn from_ptr(ptr: *mut btck_TransactionOutPoint) -> Self {
        TxOutPoint { inner: ptr }
    }
}

impl TxOutPointExt for TxOutPoint {}

impl Clone for TxOutPoint {
    fn clone(&self) -> Self {
        TxOutPoint {
            inner: unsafe { btck_transaction_out_point_copy(self.inner) },
        }
    }
}

impl Drop for TxOutPoint {
    fn drop(&mut self) {
        unsafe { btck_transaction_out_point_destroy(self.inner) }
    }
}

pub struct TxOutPointRef<'a> {
    inner: *const btck_TransactionOutPoint,
    marker: PhantomData<&'a ()>,
}

unsafe impl<'a> Send for TxOutPointRef<'a> {}
unsafe impl<'a> Sync for TxOutPointRef<'a> {}

impl<'a> TxOutPointRef<'a> {
    /// Creates an owned copy of this outpoint.
    pub fn to_owned(&self) -> TxOutPoint {
        TxOutPoint {
            inner: unsafe { btck_transaction_out_point_copy(self.inner) },
        }
    }
}

impl<'a> AsPtr<btck_TransactionOutPoint> for TxOutPointRef<'a> {
    fn as_ptr(&self) -> *const btck_TransactionOutPoint {
        self.inner as *const _
    }
}

impl<'a> FromPtr<btck_TransactionOutPoint> for TxOutPointRef<'a> {
    unsafe fn from_ptr(ptr: *const btck_TransactionOutPoint) -> Self {
        TxOutPointRef {
            inner: ptr,
            marker: PhantomData,
        }
    }
}

impl<'a> TxOutPointExt for TxOutPointRef<'a> {}

impl<'a> Clone for TxOutPointRef<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a> Copy for TxOutPointRef<'a> {}

/// Common operations for transaction IDs, implemented by both owned and borrowed types.
pub trait TxidExt: AsPtr<btck_Txid> {
    /// Serializes the txid to raw bytes.
    fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        unsafe {
            btck_txid_to_bytes(self.as_ptr(), bytes.as_mut_ptr());
        }
        bytes
    }
}

#[derive(Debug)]
pub struct Txid {
    inner: *mut btck_Txid,
}

unsafe impl Send for Txid {}
unsafe impl Sync for Txid {}

impl Txid {
    pub fn as_ref(&self) -> TxidRef<'_> {
        unsafe { TxidRef::from_ptr(self.inner as *const _) }
    }
}

impl AsPtr<btck_Txid> for Txid {
    fn as_ptr(&self) -> *const btck_Txid {
        self.inner as *const _
    }
}

impl FromMutPtr<btck_Txid> for Txid {
    unsafe fn from_ptr(ptr: *mut btck_Txid) -> Self {
        Txid { inner: ptr }
    }
}

impl TxidExt for Txid {}

impl Clone for Txid {
    fn clone(&self) -> Self {
        Txid {
            inner: unsafe { btck_txid_copy(self.inner) },
        }
    }
}

impl Drop for Txid {
    fn drop(&mut self) {
        unsafe { btck_txid_destroy(self.inner) }
    }
}

impl PartialEq for Txid {
    fn eq(&self, other: &Self) -> bool {
        present(unsafe { btck_txid_equals(self.inner, other.inner) })
    }
}

impl PartialEq<TxidRef<'_>> for Txid {
    fn eq(&self, other: &TxidRef<'_>) -> bool {
        present(unsafe { btck_txid_equals(self.inner, other.inner) })
    }
}

impl Eq for Txid {}

#[derive(Debug)]
pub struct TxidRef<'a> {
    inner: *const btck_Txid,
    marker: PhantomData<&'a ()>,
}

unsafe impl<'a> Send for TxidRef<'a> {}
unsafe impl<'a> Sync for TxidRef<'a> {}

impl<'a> TxidRef<'a> {
    pub fn to_owned(&self) -> Txid {
        Txid {
            inner: unsafe { btck_txid_copy(self.inner) },
        }
    }
}

impl<'a> AsPtr<btck_Txid> for TxidRef<'a> {
    fn as_ptr(&self) -> *const btck_Txid {
        self.inner as *const _
    }
}

impl<'a> FromPtr<btck_Txid> for TxidRef<'a> {
    unsafe fn from_ptr(ptr: *const btck_Txid) -> Self {
        TxidRef {
            inner: ptr,
            marker: PhantomData,
        }
    }
}

impl<'a> TxidExt for TxidRef<'a> {}

impl<'a> Clone for TxidRef<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a> Copy for TxidRef<'a> {}

impl<'a> PartialEq for TxidRef<'a> {
    fn eq(&self, other: &Self) -> bool {
        present(unsafe { btck_txid_equals(self.inner, other.inner) })
    }
}

impl<'a> Eq for TxidRef<'a> {}

impl PartialEq<Txid> for TxidRef<'_> {
    fn eq(&self, other: &Txid) -> bool {
        present(unsafe { btck_txid_equals(self.inner, other.inner) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::test_utils::{
        test_owned_clone_and_send, test_owned_trait_requirements, test_ref_copy,
        test_ref_trait_requirements,
    };
    use crate::{Block, ScriptPubkey};
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    fn read_block_data() -> Vec<Vec<u8>> {
        let file = File::open("tests/block_data.txt").unwrap();
        let reader = BufReader::new(file);
        let mut lines = vec![];
        for line in reader.lines() {
            lines.push(hex::decode(line.unwrap()).unwrap());
        }
        lines
    }

    fn get_test_transactions() -> (Transaction, Transaction) {
        let block_data = read_block_data();
        let tx1 = Block::new(&block_data[1])
            .unwrap()
            .transaction(0)
            .unwrap()
            .to_owned();
        let tx2 = Block::new(&block_data[2])
            .unwrap()
            .transaction(0)
            .unwrap()
            .to_owned();
        (tx1, tx2)
    }

    fn get_test_txids() -> (Txid, Txid) {
        let (tx1, tx2) = get_test_transactions();
        (tx1.txid().to_owned(), tx2.txid().to_owned())
    }

    fn get_test_txins() -> (TxIn, TxIn) {
        let (tx1, tx2) = get_test_transactions();
        (
            tx1.as_ref().input(0).unwrap().to_owned(),
            tx2.as_ref().input(0).unwrap().to_owned(),
        )
    }

    fn get_test_txoutpoints() -> (TxOutPoint, TxOutPoint) {
        let (txin1, txin2) = get_test_txins();
        (txin1.outpoint().to_owned(), txin2.outpoint().to_owned())
    }

    test_owned_trait_requirements!(test_transaction_requirements, Transaction, btck_Transaction);
    test_ref_trait_requirements!(
        test_transaction_ref_requirements,
        TransactionRef<'static>,
        btck_Transaction
    );
    test_owned_clone_and_send!(
        test_transaction_clone_send,
        get_test_transactions().0,
        get_test_transactions().1
    );
    test_ref_copy!(test_transaction_ref_behavior, get_test_transactions().0);

    test_owned_trait_requirements!(test_txout_requirements, TxOut, btck_TransactionOutput);
    test_ref_trait_requirements!(
        test_txout_ref_requirements,
        TxOutRef<'static>,
        btck_TransactionOutput
    );
    test_owned_clone_and_send!(
        test_txout_clone_send,
        TxOut::new(&ScriptPubkey::new(&[0x76, 0xa9]).unwrap(), 100),
        TxOut::new(&ScriptPubkey::new(&[0x51]).unwrap(), 200)
    );
    test_ref_copy!(
        test_txout_ref_copy,
        TxOut::new(&ScriptPubkey::new(&[0x76, 0xa9]).unwrap(), 100)
    );

    test_owned_trait_requirements!(test_txin_requirements, TxIn, btck_TransactionInput);
    test_ref_trait_requirements!(
        test_txin_ref_requirements,
        TxInRef<'static>,
        btck_TransactionInput
    );
    test_owned_clone_and_send!(test_txin_clone_send, get_test_txins().0, get_test_txins().1);
    test_ref_copy!(test_txin_ref_copy, get_test_txins().0);

    test_owned_trait_requirements!(
        test_txoutpoint_requirements,
        TxOutPoint,
        btck_TransactionOutPoint
    );
    test_ref_trait_requirements!(
        test_txoutpoint_ref_requirements,
        TxOutPointRef<'static>,
        btck_TransactionOutPoint
    );
    test_owned_clone_and_send!(
        test_txoutpoint_clone_send,
        get_test_txoutpoints().0,
        get_test_txoutpoints().1
    );
    test_ref_copy!(test_txoutpoint_ref_copy, get_test_txoutpoints().0);

    test_owned_trait_requirements!(test_txid_requirements, Txid, btck_Txid);
    test_ref_trait_requirements!(test_txid_ref_requirements, TxidRef<'static>, btck_Txid);
    test_owned_clone_and_send!(test_txid_clone_send, get_test_txids().0, get_test_txids().1);
    test_ref_copy!(test_txid_ref_copy, get_test_txids().0);

    #[test]
    fn test_txid_equality() {
        let (tx1, tx2) = get_test_transactions();

        let txid1 = tx1.txid().to_owned();
        let txid2 = tx2.txid().to_owned();
        let txid1_copy = tx1.txid().to_owned();

        assert_eq!(txid1, txid1_copy,);
        assert_ne!(txid1, txid2,);

        let txid1_ref = txid1.as_ref();
        assert_eq!(txid1, txid1_ref,);
        assert_eq!(txid1_ref, txid1,);

        let txid2_ref = txid2.as_ref();
        assert_eq!(txid1_ref, txid1_ref);
        assert_ne!(txid1_ref, txid2_ref,);
    }
}
