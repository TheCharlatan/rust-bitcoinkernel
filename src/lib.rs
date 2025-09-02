#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::borrow::Borrow;
use std::ffi::NulError;
use std::marker::PhantomData;
use std::{fmt, panic};

use ffi::c_helpers;
use libbitcoinkernel_sys::*;

pub mod core;
pub mod ffi;
pub mod log;
pub mod notifications;
pub mod state;

pub use crate::core::{
    verify, Block, BlockHash, BlockSpentOutputs, BlockTreeEntry, Coin, ScriptPubkey,
    ScriptVerifyError, ScriptVerifyStatus, Transaction, TransactionSpentOutputs, TxOut, VERIFY_ALL,
    VERIFY_ALL_PRE_TAPROOT, VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY, VERIFY_DERSIG,
    VERIFY_NONE, VERIFY_NULLDUMMY, VERIFY_P2SH, VERIFY_TAPROOT, VERIFY_WITNESS,
};
pub use crate::log::{disable_logging, Log, Logger};
pub use crate::notifications::{
    BlockValidationResult, KernelNotificationInterfaceCallbacks, SynchronizationState,
    ValidationInterfaceCallbacks, ValidationMode, Warning,
};
pub use crate::state::{
    Chain, ChainIterator, ChainParams, ChainType, ChainstateManager, ChainstateManagerOptions,
    Context, ContextBuilder,
};

/// Serializes data using a C callback function pattern.
///
/// Takes a C function that writes data via a callback and returns the
/// serialized bytes as a Vec<u8>.
pub(crate) fn c_serialize<F>(c_function: F) -> Result<Vec<u8>, KernelError>
where
    F: FnOnce(
        unsafe extern "C" fn(*const std::ffi::c_void, usize, *mut std::ffi::c_void) -> i32,
        *mut std::ffi::c_void,
    ) -> i32,
{
    let mut buffer = Vec::new();

    unsafe extern "C" fn write_callback(
        data: *const std::ffi::c_void,
        len: usize,
        user_data: *mut std::ffi::c_void,
    ) -> i32 {
        panic::catch_unwind(|| {
            let buffer = &mut *(user_data as *mut Vec<u8>);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            buffer.extend_from_slice(slice);
            c_helpers::to_c_result(true)
        })
        .unwrap_or_else(|_| c_helpers::to_c_result(false))
    }

    let result = c_function(
        write_callback,
        &mut buffer as *mut Vec<u8> as *mut std::ffi::c_void,
    );

    if c_helpers::success(result) {
        Ok(buffer)
    } else {
        Err(KernelError::SerializationFailed)
    }
}

/// A collection of errors emitted by this library
#[derive(Debug)]
pub enum KernelError {
    Internal(String),
    CStringCreationFailed(String),
    InvalidOptions(String),
    OutOfBounds,
    ScriptVerify(ScriptVerifyError),
    SerializationFailed,
}

impl From<NulError> for KernelError {
    fn from(err: NulError) -> Self {
        KernelError::CStringCreationFailed(err.to_string())
    }
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KernelError::Internal(msg)
            | KernelError::CStringCreationFailed(msg)
            | KernelError::InvalidOptions(msg) => write!(f, "{msg}"),
            _ => write!(f, "Error!"),
        }
    }
}

/// A reference type that enforces lifetime relationships.
///
/// `RefType<'a, T, L>` represents a borrowed `T` that cannot outlive the owner `L`.
///
/// # Type Parameters
/// - `'a` - The lifetime of the borrow, tied to the owner's lifetime
/// - `T` - The borrowed type (e.g., `TxOut`, `ScriptPubkey`)
/// - `L` - The owner type (e.g., `Transaction`, `TxOut`)
pub struct RefType<'a, T, L> {
    inner: T,
    marker: PhantomData<&'a L>,
}

impl<'a, T, L> RefType<'a, T, L> {
    /// Creates a new RefType wrapping referenced data.
    pub(crate) fn new(inner: T) -> Self {
        RefType {
            inner,
            marker: PhantomData,
        }
    }

    /// Creates an owned copy of the borrowed data.
    ///
    /// This calls the underlying type's `Clone` implementation to create
    /// an independent copy that can outlive the original reference.
    pub fn to_owned(&self) -> T
    where
        T: Clone,
    {
        self.inner.clone()
    }
}

impl<'a, T, L> std::ops::Deref for RefType<'a, T, L> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'a, T, L> AsRef<T> for RefType<'a, T, L> {
    fn as_ref(&self) -> &T {
        &self.inner
    }
}

impl<'a, T, L> Borrow<T> for RefType<'a, T, L> {
    fn borrow(&self) -> &T {
        &self.inner
    }
}
