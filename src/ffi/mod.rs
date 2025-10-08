pub mod c_helpers;
pub mod constants;
#[cfg(test)]
pub mod test_utils;

pub(crate) mod sealed {
    pub trait AsPtr<T> {
        /// Returns a raw pointer to the underlying C object.
        fn as_ptr(&self) -> *const T;
    }

    pub trait FromPtr<T> {
        /// Creates a wrapper from a raw const C pointer.
        unsafe fn from_ptr(ptr: *const T) -> Self;
    }

    pub trait FromMutPtr<T> {
        /// Creates a wrapper from a raw mutable C pointer.
        unsafe fn from_ptr(ptr: *mut T) -> Self;
    }
}

pub use c_helpers::{enabled, present, success, to_c_bool, to_c_result, to_string};
pub(crate) use constants::*;
