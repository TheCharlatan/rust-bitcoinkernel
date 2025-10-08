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
macro_rules! test_owned_clone_and_send {
    ($test_name:ident, $obj1:expr, $obj2:expr) => {
        #[test]
        fn $test_name() {
            let obj1 = $obj1;
            let obj2 = $obj2;
            let clone1 = obj1.clone();
            let clone2 = obj2.clone();

            assert_ne!(
                obj1.as_ptr() as *const u8,
                clone1.as_ptr() as *const u8,
                "Clone should create independent object"
            );
            assert_ne!(
                obj2.as_ptr() as *const u8,
                clone2.as_ptr() as *const u8,
                "Clone should create independent object"
            );

            let handle1 = std::thread::spawn(move || {
                let _ptr = clone1.as_ptr();
                42
            });

            let handle2 = std::thread::spawn(move || {
                let _ptr = clone2.as_ptr();
                24
            });

            assert_eq!(handle1.join().unwrap(), 42);
            assert_eq!(handle2.join().unwrap(), 24);

            let _ptr1 = obj1.as_ptr();
            let _ptr2 = obj2.as_ptr();
        }
    };
}

#[cfg(test)]
macro_rules! test_ref_copy {
    ($test_name:ident, $owned:expr) => {
        #[test]
        fn $test_name() {
            let owned = $owned;
            let ref_val = owned.as_ref();

            let copied = ref_val;

            assert_eq!(
                ref_val.as_ptr() as *const u8,
                copied.as_ptr() as *const u8,
                "Copy should create identical reference"
            );

            let _ptr1 = ref_val.as_ptr();
            let _ptr2 = copied.as_ptr();
        }
    };
}

#[cfg(test)]
pub(crate) use {
    test_owned_clone_and_send, test_owned_trait_requirements, test_ref_copy,
    test_ref_trait_requirements,
};
