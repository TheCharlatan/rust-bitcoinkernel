pub mod c_helpers;
pub mod constants;

pub(crate) mod sealed {
    pub trait AsPtr<T> {
        /// Returns a raw pointer to the underlying C object.
        fn as_ptr(&self) -> *const T;
    }
}

pub use c_helpers::{enabled, present, success, to_c_bool, to_c_result, to_string};
pub(crate) use constants::*;
