use std::{ffi::c_void, marker::PhantomData};

use libbitcoinkernel_sys::{
    btck_ScriptPubkey, btck_script_pubkey_copy, btck_script_pubkey_create,
    btck_script_pubkey_destroy, btck_script_pubkey_to_bytes,
};

use crate::{
    c_serialize,
    ffi::sealed::{AsPtr, FromPtr},
    KernelError,
};

/// Common operations for script pubkeys, implemented by both owned and borrowed types.
pub trait ScriptPubkeyExt: AsPtr<btck_ScriptPubkey> {
    /// Serializes the script to raw bytes.
    fn to_bytes(&self) -> Vec<u8> {
        c_serialize(|callback, user_data| unsafe {
            btck_script_pubkey_to_bytes(self.as_ptr(), Some(callback), user_data)
        })
        .expect("Script pubkey to_bytes should never fail")
    }
}

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

    pub fn as_ref(&self) -> ScriptPubkeyRef<'_> {
        unsafe { ScriptPubkeyRef::from_ptr(self.inner as *const _) }
    }
}

impl AsPtr<btck_ScriptPubkey> for ScriptPubkey {
    fn as_ptr(&self) -> *const btck_ScriptPubkey {
        self.inner as *const _
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

pub struct ScriptPubkeyRef<'a> {
    inner: *const btck_ScriptPubkey,
    marker: PhantomData<&'a ()>,
}

impl<'a> ScriptPubkeyRef<'a> {
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
