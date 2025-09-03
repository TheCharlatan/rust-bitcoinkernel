// Copyright (c) 2023-present The Bitcoin Kernel developers
// Licensed under the MIT License. See LICENSE file in the project root.

use std::ffi::c_void;

use libbitcoinkernel_sys::{
    btck_ScriptPubkey, btck_script_pubkey_copy, btck_script_pubkey_create,
    btck_script_pubkey_destroy, btck_script_pubkey_to_bytes,
};

use crate::{c_serialize, KernelError};

/// A single script pubkey containing spending conditions for a transaction output.
///
/// Script pubkeys can be created from raw script bytes or retrieved from existing
/// transaction outputs.
#[derive(Debug)]
pub struct ScriptPubkey {
    inner: *mut btck_ScriptPubkey,
}

unsafe impl Send for ScriptPubkey {}
unsafe impl Sync for ScriptPubkey {}

impl ScriptPubkey {
    /// Creates a ScriptPubkey from an FFI pointer for internal library use.
    pub(crate) fn from_ptr(inner: *mut btck_ScriptPubkey) -> Self {
        Self { inner }
    }

    /// Serializes the script to raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        c_serialize(|callback, user_data| unsafe {
            btck_script_pubkey_to_bytes(self.inner, Some(callback), user_data)
        })
        .expect("Script pubkey to_bytes should never fail")
    }

    /// Get the inner FFI pointer for internal library use
    pub(crate) fn as_ptr(&self) -> *mut btck_ScriptPubkey {
        self.inner
    }
}

impl From<ScriptPubkey> for Vec<u8> {
    fn from(pubkey: ScriptPubkey) -> Self {
        pubkey.to_bytes()
    }
}

impl TryFrom<&[u8]> for ScriptPubkey {
    type Error = KernelError;

    fn try_from(raw_script_pubkey: &[u8]) -> Result<Self, Self::Error> {
        let inner = unsafe {
            btck_script_pubkey_create(
                raw_script_pubkey.as_ptr() as *const c_void,
                raw_script_pubkey.len(),
            )
        };
        if inner.is_null() {
            return Err(KernelError::Internal(
                "Failed to decode raw script pubkey".to_string(),
            ));
        }
        Ok(ScriptPubkey { inner })
    }
}

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
