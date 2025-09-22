#[cfg(test)]
macro_rules! test_owned_trait_requirements {
    ($test_name:ident, $owned:ty, $ffi_type:ty) => {
        #[test]
        fn $test_name() {
            use crate::ffi::sealed::{AsPtr, FromMutPtr};

            fn assert_clone<T: Clone>() {}
            fn assert_send_sync<T: Send + Sync>() {}
            fn assert_as_ptr<T: AsPtr<U>, U>() {}
            fn assert_from_mut_ptr<T: FromMutPtr<U>, U>() {}

            assert_clone::<$owned>();
            assert_send_sync::<$owned>();
            assert_as_ptr::<$owned, $ffi_type>();
            assert_from_mut_ptr::<$owned, $ffi_type>();
        }
    };
}

#[cfg(test)]
macro_rules! test_ref_trait_requirements {
    ($test_name:ident, $ref:ty, $ffi_type:ty) => {
        #[test]
        fn $test_name() {
            use crate::ffi::sealed::{AsPtr, FromPtr};

            fn assert_clone<T: Clone>() {}
            fn assert_copy<T: Copy>() {}
            fn assert_send_sync<T: Send + Sync>() {}
            fn assert_as_ptr<T: AsPtr<U>, U>() {}
            fn assert_from_ptr<T: FromPtr<U>, U>() {}

            assert_clone::<$ref>();
            assert_copy::<$ref>();
            assert_send_sync::<$ref>();
            assert_as_ptr::<$ref, $ffi_type>();
            assert_from_ptr::<$ref, $ffi_type>();
        }
    };
}

#[cfg(test)]
pub(crate) use {test_owned_trait_requirements, test_ref_trait_requirements};
