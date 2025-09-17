use std::{ffi::c_void, marker::PhantomData};

use libbitcoinkernel_sys::{
    btck_Transaction, btck_TransactionOutput, btck_transaction_copy, btck_transaction_count_inputs,
    btck_transaction_count_outputs, btck_transaction_create, btck_transaction_destroy,
    btck_transaction_get_output_at, btck_transaction_output_copy, btck_transaction_output_create,
    btck_transaction_output_destroy, btck_transaction_output_get_amount,
    btck_transaction_output_get_script_pubkey, btck_transaction_to_bytes,
};

use crate::{
    c_serialize,
    ffi::sealed::{AsPtr, FromPtr},
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
