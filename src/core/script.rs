//! Script pubkey types and operations.
//!
//! This module provides types for working with script pubkeys (also known as
//! "locking scripts"), which define the conditions that must be met to spend a
//! [`TxOut`].
//!
//! # Types
//!
//! The module provides two types:
//!
//! - [`ScriptPubkey`]: An owned script pubkey that manages its own memory
//! - [`ScriptPubkeyRef`]: A borrowed reference to a script pubkey with a specific lifetime
//!
//! Both types implement the [`ScriptPubkeyExt`] trait, providing a unified interface
//! for all script pubkey operations regardless of ownership.
//!
//! # Examples
//!
//! ## Creating and working with script pubkeys
//!
//! ```no_run
//! # use bitcoinkernel::{prelude::*, ScriptPubkey};
//! // Create a simple script from raw bytes
//! let script = ScriptPubkey::new(&[0x76, 0xa9, 0x14]).unwrap();
//!
//! // Serialize back to bytes
//! let bytes = script.to_bytes();
//! assert_eq!(bytes, vec![0x76, 0xa9, 0x14]);
//!
//! // Use TryFrom for conversion
//! let script2 = ScriptPubkey::try_from(bytes.as_slice()).unwrap();
//! ```
//!
//! ## Creating standard script types
//!
//! ```no_run
//! # use bitcoinkernel::ScriptPubkey;
//! // P2PKH: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
//! let p2pkh_hex = "76a914deadbeefdeadbeefdeadbeefdeadbeefdeadbeef88ac";
//! let p2pkh = ScriptPubkey::new(&hex::decode(p2pkh_hex).unwrap()).unwrap();
//!
//! // P2SH: OP_HASH160 <scriptHash> OP_EQUAL
//! let p2sh_hex = "a914deadbeefdeadbeefdeadbeefdeadbeefdeadbeef87";
//! let p2sh = ScriptPubkey::new(&hex::decode(p2sh_hex).unwrap()).unwrap();
//!
//! // P2WPKH: OP_0 <20-byte-pubkey-hash>
//! let p2wpkh_hex = "0014deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
//! let p2wpkh = ScriptPubkey::new(&hex::decode(p2wpkh_hex).unwrap()).unwrap();
//! ```

use std::{ffi::c_void, marker::PhantomData};

use libbitcoinkernel_sys::{
    btck_ScriptPubkey, btck_script_pubkey_copy, btck_script_pubkey_create,
    btck_script_pubkey_destroy, btck_script_pubkey_to_bytes,
};

use crate::{
    c_serialize,
    ffi::sealed::{AsPtr, FromMutPtr, FromPtr},
    KernelError,
};

/// Common operations for script pubkeys, implemented by both owned and borrowed types.
///
/// This trait provides shared functionality for [`ScriptPubkey`] and [`ScriptPubkeyRef`],
/// allowing code to work with either owned or borrowed script pubkeys.
pub trait ScriptPubkeyExt: AsPtr<btck_ScriptPubkey> {
    /// Serializes the script to raw bytes.
    ///
    /// Returns the script's raw byte representation.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, ScriptPubkey};
    /// let script = ScriptPubkey::new(&[0x76, 0xa9]).unwrap();
    /// let bytes = script.to_bytes();
    /// assert_eq!(bytes, vec![0x76, 0xa9]);
    /// ```
    fn to_bytes(&self) -> Vec<u8> {
        c_serialize(|callback, user_data| unsafe {
            btck_script_pubkey_to_bytes(self.as_ptr(), Some(callback), user_data)
        })
        .expect("Script pubkey to_bytes should never fail")
    }
}

/// A single script pubkey containing spending conditions for a [`TxOut`].
///
/// Script pubkeys define the conditions that must be met to spend a transaction output.
/// They are also called "locking scripts" because they lock the output to specific
/// spending conditions.
///
/// Script pubkeys can be created from raw script bytes or retrieved from an existing
/// [`TxOut`].
///
/// # Examples
///
/// Creating a simple script:
///
/// ```no_run
/// # use bitcoinkernel::{prelude::*, ScriptPubkey};
/// let script_bytes = vec![0x76, 0xa9, 0x14]; // OP_DUP OP_HASH160 OP_PUSHBYTES_20
/// let script = ScriptPubkey::new(&script_bytes).unwrap();
/// assert_eq!(script.to_bytes(), script_bytes);
/// ```
#[derive(Debug)]
pub struct ScriptPubkey {
    inner: *mut btck_ScriptPubkey,
}

unsafe impl Send for ScriptPubkey {}
unsafe impl Sync for ScriptPubkey {}

impl ScriptPubkey {
    /// Creates a new script pubkey from raw script bytes.
    ///
    /// # Arguments
    ///
    /// * `script_bytes` - The raw bytes representing the script
    ///
    /// # Returns
    ///
    /// * `Ok(ScriptPubkey)` - Successfully created script pubkey
    /// * `Err(KernelError::Internal)` - If the script could not be created
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use bitcoinkernel::ScriptPubkey;
    /// // Create a P2PKH script
    /// let p2pkh = ScriptPubkey::new(&[
    ///     0x76, 0xa9, 0x14,  // OP_DUP OP_HASH160 OP_PUSHBYTES_20
    ///     // ... pubkey hash bytes ...
    ///     0x88, 0xac          // OP_EQUALVERIFY OP_CHECKSIG
    /// ]).unwrap();
    /// ```
    pub fn new(script_bytes: &[u8]) -> Result<Self, KernelError> {
        let inner = unsafe {
            btck_script_pubkey_create(script_bytes.as_ptr() as *const c_void, script_bytes.len())
        };

        if inner.is_null() {
            Err(KernelError::Internal(
                "Failed to create ScriptPubkey from bytes".to_string(),
            ))
        } else {
            Ok(ScriptPubkey { inner })
        }
    }

    /// Creates a borrowed reference to this script pubkey.
    ///
    /// This allows converting from an owned [`ScriptPubkey`] to a [`ScriptPubkeyRef`]
    /// without copying the underlying data.
    ///
    /// # Lifetime
    /// The returned reference is valid for the lifetime of this [`ScriptPubkey`].
    pub fn as_ref(&self) -> ScriptPubkeyRef<'_> {
        unsafe { ScriptPubkeyRef::from_ptr(self.inner as *const _) }
    }
}

impl AsPtr<btck_ScriptPubkey> for ScriptPubkey {
    fn as_ptr(&self) -> *const btck_ScriptPubkey {
        self.inner as *const _
    }
}

impl FromMutPtr<btck_ScriptPubkey> for ScriptPubkey {
    unsafe fn from_ptr(ptr: *mut btck_ScriptPubkey) -> Self {
        ScriptPubkey { inner: ptr }
    }
}

impl ScriptPubkeyExt for ScriptPubkey {}

impl Clone for ScriptPubkey {
    fn clone(&self) -> Self {
        ScriptPubkey {
            inner: unsafe { btck_script_pubkey_copy(self.inner) },
        }
    }
}

impl Drop for ScriptPubkey {
    fn drop(&mut self) {
        unsafe { btck_script_pubkey_destroy(self.inner) }
    }
}

impl TryFrom<&[u8]> for ScriptPubkey {
    type Error = KernelError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        ScriptPubkey::new(bytes)
    }
}

impl From<ScriptPubkey> for Vec<u8> {
    fn from(script: ScriptPubkey) -> Self {
        script.to_bytes()
    }
}

impl From<&ScriptPubkey> for Vec<u8> {
    fn from(script: &ScriptPubkey) -> Self {
        script.to_bytes()
    }
}

/// A borrowed reference to a script pubkey.
///
/// Provides zero-copy access to script pubkey data. It implements [`Copy`],
/// making it cheap to pass around.
///
/// # Lifetime
/// The reference is only valid as long as the data it references remains alive.
///
/// # Thread Safety
/// `ScriptPubkeyRef` is both [`Send`] and [`Sync`].
pub struct ScriptPubkeyRef<'a> {
    inner: *const btck_ScriptPubkey,
    marker: PhantomData<&'a ()>,
}

unsafe impl<'a> Send for ScriptPubkeyRef<'a> {}
unsafe impl<'a> Sync for ScriptPubkeyRef<'a> {}

impl<'a> ScriptPubkeyRef<'a> {
    /// Creates an owned copy of this script pubkey.
    ///
    /// This allocates a new [`ScriptPubkey`] with its own copy of the script data.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, ScriptPubkey};
    /// let owned_script = {
    ///     let script = ScriptPubkey::new(&[0x76, 0xa9]).unwrap();
    ///     let script_ref = script.as_ref();
    ///     script_ref.to_owned()  // Survives after script is dropped
    /// };
    /// assert_eq!(owned_script.to_bytes(), vec![0x76, 0xa9]);
    /// ```
    pub fn to_owned(&self) -> ScriptPubkey {
        ScriptPubkey {
            inner: unsafe { btck_script_pubkey_copy(self.inner) },
        }
    }
}

impl<'a> AsPtr<btck_ScriptPubkey> for ScriptPubkeyRef<'a> {
    fn as_ptr(&self) -> *const btck_ScriptPubkey {
        self.inner
    }
}

impl<'a> FromPtr<btck_ScriptPubkey> for ScriptPubkeyRef<'a> {
    unsafe fn from_ptr(ptr: *const btck_ScriptPubkey) -> Self {
        ScriptPubkeyRef {
            inner: ptr,
            marker: PhantomData,
        }
    }
}

impl<'a> ScriptPubkeyExt for ScriptPubkeyRef<'a> {}

impl<'a> From<ScriptPubkeyRef<'a>> for Vec<u8> {
    fn from(script_ref: ScriptPubkeyRef<'a>) -> Self {
        script_ref.to_bytes()
    }
}

impl<'a> From<&ScriptPubkeyRef<'a>> for Vec<u8> {
    fn from(script_ref: &ScriptPubkeyRef<'a>) -> Self {
        script_ref.to_bytes()
    }
}

impl<'a> Clone for ScriptPubkeyRef<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a> Copy for ScriptPubkeyRef<'a> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::test_utils::{
        test_owned_clone_and_send, test_owned_trait_requirements, test_ref_copy,
        test_ref_trait_requirements,
    };

    const SIMPLE_SCRIPT_1: &[u8] = &[0x76, 0xa9];
    const SIMPLE_SCRIPT_2: &[u8] = &[0x51];

    test_owned_trait_requirements!(
        test_scriptpubkey_implementations,
        ScriptPubkey,
        btck_ScriptPubkey
    );
    test_ref_trait_requirements!(
        test_scriptpubkey_ref_implementations,
        ScriptPubkeyRef<'static>,
        btck_ScriptPubkey
    );

    test_owned_clone_and_send!(
        test_scriptpubkey_clone_send,
        ScriptPubkey::new(SIMPLE_SCRIPT_1).unwrap(),
        ScriptPubkey::new(SIMPLE_SCRIPT_2).unwrap()
    );

    test_ref_copy!(
        test_scriptpubkey_ref_copy,
        ScriptPubkey::new(SIMPLE_SCRIPT_1).unwrap()
    );

    #[test]
    fn test_scriptpubkey_new() {
        let script_data = vec![0x76, 0xa9, 0x14];
        let script = ScriptPubkey::new(&script_data);
        assert!(script.is_ok());
    }

    #[test]
    fn test_scriptpubkey_empty() {
        let script = ScriptPubkey::new(&[]);
        assert!(script.is_ok());
    }

    #[test]
    fn test_scriptpubkey_try_from() {
        let script_data: &[u8] = &[0x76, 0xa9, 0x14];
        let script = ScriptPubkey::try_from(script_data);
        assert!(script.is_ok());
    }

    #[test]
    fn test_scriptpubkey_to_bytes() {
        let script_data = vec![0x76, 0xa9, 0x14];
        let script = ScriptPubkey::try_from(script_data.as_slice()).unwrap();
        let bytes = script.to_bytes();
        assert_eq!(bytes, script_data);
    }

    #[test]
    fn test_scriptpubkey_into_vec() {
        let script_data = vec![0x76, 0xa9, 0x14];
        let script = ScriptPubkey::try_from(script_data.as_slice()).unwrap();
        let bytes: Vec<u8> = script.into();
        assert_eq!(bytes, script_data);
    }

    #[test]
    fn test_scriptpubkey_ref_into_vec() {
        let script_data = vec![0x76, 0xa9, 0x14];
        let script = ScriptPubkey::try_from(script_data.as_slice()).unwrap();
        let bytes: Vec<u8> = (&script).into();
        assert_eq!(bytes, script_data);
    }

    #[test]
    fn test_scriptpubkey_as_ref() {
        let script_data = vec![0x76, 0xa9, 0x14];
        let owned_script = ScriptPubkey::try_from(script_data.as_slice()).unwrap();
        let script_ref = owned_script.as_ref();

        assert_eq!(script_ref.to_bytes(), script_data);
        assert_eq!(owned_script.to_bytes(), script_data);
    }

    #[test]
    fn test_scriptpubkey_ref_to_owned() {
        let script_data = vec![0x76, 0xa9, 0x14];
        let script = ScriptPubkey::try_from(script_data.as_slice()).unwrap();
        let script_ref = script.as_ref();
        let owned_script = script_ref.to_owned();

        let bytes1 = script_ref.to_bytes();
        let bytes2 = owned_script.to_bytes();

        assert_eq!(bytes1, bytes2);
        assert_eq!(bytes1, script_data);
    }

    #[test]
    fn test_scriptpubkey_ref_to_owned_survives_drop() {
        let owned_script = {
            let script_data = vec![0x76, 0xa9, 0x14];
            let script = ScriptPubkey::try_from(script_data.as_slice()).unwrap();
            let script_ref = script.as_ref();
            script_ref.to_owned()
        };

        let bytes = owned_script.to_bytes();
        assert_eq!(bytes, vec![0x76, 0xa9, 0x14]);
    }

    #[test]
    fn test_scriptpubkey_ref_into_vec_from_ref() {
        let script_data = vec![0x76, 0xa9, 0x14];
        let script = ScriptPubkey::try_from(script_data.as_slice()).unwrap();
        let script_ref = script.as_ref();

        let bytes: Vec<u8> = script_ref.into();
        assert_eq!(bytes, script_data);
    }

    #[test]
    fn test_scriptpubkey_ref_ref_into_vec() {
        let script_data = vec![0x76, 0xa9, 0x14];
        let script = ScriptPubkey::try_from(script_data.as_slice()).unwrap();
        let script_ref = script.as_ref();

        let bytes: Vec<u8> = (&script_ref).into();
        assert_eq!(bytes, script_data);
    }

    #[test]
    fn test_owned_and_ref_polymorphism() {
        let script_data = vec![0x76, 0xa9, 0x14];
        let owned_script = ScriptPubkey::try_from(script_data.as_slice()).unwrap();
        let script_ref = owned_script.as_ref();

        fn get_bytes_generic(script: &impl ScriptPubkeyExt) -> Vec<u8> {
            script.to_bytes()
        }

        let bytes_from_owned = get_bytes_generic(&owned_script);
        let bytes_from_ref = get_bytes_generic(&script_ref);

        assert_eq!(bytes_from_owned, script_data);
        assert_eq!(bytes_from_ref, script_data);
        assert_eq!(bytes_from_owned, bytes_from_ref);
    }

    #[test]
    fn test_large_script() {
        let script_data = vec![0xFF; 10000];
        let script = ScriptPubkey::new(&script_data);
        assert!(script.is_ok());

        let script = script.unwrap();
        assert_eq!(script.to_bytes(), script_data);
    }

    #[test]
    fn test_single_byte_script() {
        let script_data = vec![0x51];
        let script = ScriptPubkey::new(&script_data).unwrap();
        assert_eq!(script.to_bytes(), script_data);
    }

    #[test]
    fn test_multiple_conversions() {
        let script_data = vec![0x76, 0xa9, 0x14];
        let script = ScriptPubkey::try_from(script_data.as_slice()).unwrap();

        let bytes1 = script.to_bytes();
        let bytes2 = script.to_bytes();
        let bytes3 = script.to_bytes();

        assert_eq!(bytes1, script_data);
        assert_eq!(bytes2, script_data);
        assert_eq!(bytes3, script_data);
    }

    #[test]
    fn test_scriptpubkey_ref_multiple_to_bytes() {
        let script_data = vec![0x76, 0xa9];
        let script = ScriptPubkey::new(&script_data).unwrap();
        let script_ref = script.as_ref();

        let bytes1 = script_ref.to_bytes();
        let bytes2 = script_ref.to_bytes();

        assert_eq!(bytes1, script_data);
        assert_eq!(bytes2, script_data);
    }

    #[test]
    fn test_p2pkh_script() {
        // Standard P2PKH script: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
        let p2pkh = hex::decode("76a914deadbeefdeadbeefdeadbeefdeadbeefdeadbeef88ac").unwrap();
        let script = ScriptPubkey::new(&p2pkh).unwrap();
        assert_eq!(script.to_bytes(), p2pkh);
    }

    #[test]
    fn test_p2sh_script() {
        // Standard P2SH script: OP_HASH160 <scriptHash> OP_EQUAL
        let p2sh = hex::decode("a914deadbeefdeadbeefdeadbeefdeadbeefdeadbeef87").unwrap();
        let script = ScriptPubkey::new(&p2sh).unwrap();
        assert_eq!(script.to_bytes(), p2sh);
    }

    #[test]
    fn test_p2wpkh_script() {
        // Native SegWit P2WPKH: OP_0 <20-byte-pubkey-hash>
        let p2wpkh = hex::decode("0014deadbeefdeadbeefdeadbeefdeadbeefdeadbeef").unwrap();
        let script = ScriptPubkey::new(&p2wpkh).unwrap();
        assert_eq!(script.to_bytes(), p2wpkh);
    }

    #[test]
    fn test_p2wsh_script() {
        // Native SegWit P2WSH: OP_0 <32-byte-script-hash>
        let p2wsh =
            hex::decode("0020deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
                .unwrap();
        let script = ScriptPubkey::new(&p2wsh).unwrap();
        assert_eq!(script.to_bytes(), p2wsh);
    }

    #[test]
    fn test_op_return_script() {
        let op_return = hex::decode("6a0548656c6c6f").unwrap(); // OP_RETURN "Hello"
        let script = ScriptPubkey::new(&op_return).unwrap();
        assert_eq!(script.to_bytes(), op_return);
    }

    #[test]
    fn test_multisig_script() {
        let multisig = vec![0x51, 0x21, 0x03];
        let script = ScriptPubkey::new(&multisig).unwrap();
        assert_eq!(script.to_bytes(), multisig);
    }
}
