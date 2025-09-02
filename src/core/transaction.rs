use std::ffi::c_void;

use libbitcoinkernel_sys::{
    btck_Coin, btck_Transaction, btck_TransactionOutput, btck_coin_confirmation_height,
    btck_coin_copy, btck_coin_destroy, btck_coin_get_output, btck_coin_is_coinbase,
    btck_transaction_copy, btck_transaction_count_inputs, btck_transaction_count_outputs,
    btck_transaction_create, btck_transaction_destroy, btck_transaction_get_output_at,
    btck_transaction_output_copy, btck_transaction_output_create, btck_transaction_output_destroy,
    btck_transaction_output_get_amount, btck_transaction_output_get_script_pubkey,
    btck_transaction_to_bytes,
};

use crate::{c_serialize, ffi::c_helpers, KernelError, RefType};

use super::script::ScriptPubkey;

/// A coin (UTXO) representing a transaction output.
///
/// Contains the transaction output data along with metadata about when
/// it was created and whether it came from a coinbase transaction.
pub struct Coin {
    inner: *mut btck_Coin,
}

unsafe impl Send for Coin {}
unsafe impl Sync for Coin {}

impl Coin {
    /// Creates a Coin from an FFI pointer for internal library use.
    pub(crate) fn from_ptr(inner: *mut btck_Coin) -> Self {
        Self { inner }
    }

    /// Returns the height of the block where this coin was created.
    pub fn confirmation_height(&self) -> u32 {
        unsafe { btck_coin_confirmation_height(self.inner) }
    }

    /// Returns true if this coin came from a coinbase transaction.
    pub fn is_coinbase(&self) -> bool {
        let result = unsafe { btck_coin_is_coinbase(self.inner) };
        c_helpers::present(result)
    }

    /// Returns a reference to the transaction output data for this coin.
    ///
    /// # Returns
    /// * `Ok(RefType<TxOut, Coin>)` - A reference to the transaction output
    /// * `Err(KernelError::Internal)` - If the coin data is corrupted
    pub fn output(&self) -> Result<RefType<'_, TxOut, Coin>, KernelError> {
        let output_ptr = unsafe { btck_coin_get_output(self.inner) };
        if output_ptr.is_null() {
            return Err(KernelError::Internal(
                "Unexpected null pointer from btck_coin_get_output".to_string(),
            ));
        }
        Ok(RefType::new(TxOut { inner: output_ptr }))
    }
}

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

/// A Bitcoin transaction.
pub struct Transaction {
    inner: *mut btck_Transaction,
}

unsafe impl Send for Transaction {}
unsafe impl Sync for Transaction {}

impl Transaction {
    /// Creates a Transaction from an FFI pointer for internal library use.
    pub(crate) fn from_ptr(inner: *mut btck_Transaction) -> Self {
        Self { inner }
    }

    /// Returns the number of outputs in this transaction.
    pub fn output_count(&self) -> usize {
        unsafe { btck_transaction_count_outputs(self.inner) as usize }
    }

    /// Returns a reference to the output at the specified index.
    ///
    /// # Arguments
    /// * `index` - The zero-based index of the output to retrieve
    ///
    /// # Returns
    /// * `Ok(RefType<TxOut, Transaction>)` - A reference to the output
    /// * `Err(KernelError::OutOfBounds)` - If the index is invalid
    pub fn output(&self, index: usize) -> Result<RefType<'_, TxOut, Transaction>, KernelError> {
        if index >= self.output_count() {
            return Err(KernelError::OutOfBounds);
        }
        let output_ptr = unsafe { btck_transaction_get_output_at(self.inner, index) };
        Ok(RefType::new(TxOut { inner: output_ptr }))
    }

    pub fn input_count(&self) -> usize {
        unsafe { btck_transaction_count_inputs(self.inner) as usize }
    }

    /// Consensus encodes the transaction to Bitcoin wire format.
    pub fn consensus_encode(&self) -> Result<Vec<u8>, KernelError> {
        c_serialize(|callback, user_data| unsafe {
            btck_transaction_to_bytes(self.inner, Some(callback), user_data)
        })
    }

    /// Get the inner FFI pointer for internal library use
    pub(crate) fn as_ptr(&self) -> *mut btck_Transaction {
        self.inner
    }
}

impl TryFrom<Transaction> for Vec<u8> {
    type Error = KernelError;

    fn try_from(tx: Transaction) -> Result<Self, Self::Error> {
        tx.consensus_encode()
    }
}

impl TryFrom<&[u8]> for Transaction {
    type Error = KernelError;

    fn try_from(raw_transaction: &[u8]) -> Result<Self, Self::Error> {
        let inner = unsafe {
            btck_transaction_create(
                raw_transaction.as_ptr() as *const c_void,
                raw_transaction.len(),
            )
        };
        if inner.is_null() {
            return Err(KernelError::Internal(
                "Failed to decode raw transaction.".to_string(),
            ));
        }
        Ok(Transaction { inner })
    }
}

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
    pub fn new(script_pubkey: &ScriptPubkey, amount: i64) -> TxOut {
        TxOut {
            inner: unsafe { btck_transaction_output_create(script_pubkey.as_ptr(), amount) },
        }
    }

    /// Returns the amount of this output in satoshis.
    pub fn value(&self) -> i64 {
        unsafe { btck_transaction_output_get_amount(self.inner) }
    }

    /// Returns a reference to the script pubkey that defines how this output can be spent.
    ///
    /// # Returns
    /// * `RefType<ScriptPubkey, TxOut>` - A reference to the script pubkey
    pub fn script_pubkey(&self) -> RefType<'_, ScriptPubkey, TxOut> {
        RefType::new(ScriptPubkey::from_ptr(unsafe {
            btck_transaction_output_get_script_pubkey(self.inner)
        }))
    }

    /// Get the inner FFI pointer for internal library use
    pub(crate) fn as_ptr(&self) -> *mut btck_TransactionOutput {
        self.inner
    }
}

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
