use std::ffi::c_void;

use libbitcoinkernel_sys::{btck_Block, btck_BlockTreeEntry, btck_BlockValidationState};

use crate::{
    ffi::sealed::{FromMutPtr, FromPtr},
    Block, BlockTreeEntry, BlockValidationStateRef,
};

/// Exposes the result after validating a block.
pub trait BlockCheckedCallback: Send + Sync {
    fn on_block_checked(&self, block: Block, state: BlockValidationStateRef);
}

impl<F> BlockCheckedCallback for F
where
    F: Fn(Block, BlockValidationStateRef) + Send + Sync + 'static,
{
    fn on_block_checked(&self, block: Block, state: BlockValidationStateRef) {
        self(block, state)
    }
}

/// Callback for when a new PoW valid block is found.
pub trait NewPoWValidBlockCallback: Send + Sync {
    fn on_new_pow_valid_block<'a>(&self, block: Block, entry: BlockTreeEntry<'a>);
}

impl<F> NewPoWValidBlockCallback for F
where
    F: for<'a> Fn(BlockTreeEntry<'a>, Block) + Send + Sync + 'static,
{
    fn on_new_pow_valid_block<'a>(&self, block: Block, entry: BlockTreeEntry<'a>) {
        self(entry, block)
    }
}

/// Callback for when a block is connected to the chain.
pub trait BlockConnectedCallback: Send + Sync {
    fn on_block_connected<'a>(&self, block: Block, entry: BlockTreeEntry<'a>);
}

impl<F> BlockConnectedCallback for F
where
    F: for<'a> Fn(Block, BlockTreeEntry<'a>) + Send + Sync + 'static,
{
    fn on_block_connected<'a>(&self, block: Block, entry: BlockTreeEntry<'a>) {
        self(block, entry)
    }
}

/// Callback for when a block is disconnected from the chain.
pub trait BlockDisconnectedCallback: Send + Sync {
    fn on_block_disconnected<'a>(&self, block: Block, entry: BlockTreeEntry<'a>);
}

impl<F> BlockDisconnectedCallback for F
where
    F: for<'a> Fn(Block, BlockTreeEntry<'a>) + Send + Sync + 'static,
{
    fn on_block_disconnected<'a>(&self, block: Block, entry: BlockTreeEntry<'a>) {
        self(block, entry)
    }
}

/// Registry for managing validation interface callback handlers.
#[derive(Default)]
pub struct ValidationCallbackRegistry {
    block_checked_handler: Option<Box<dyn BlockCheckedCallback>>,
    new_pow_valid_block_handler: Option<Box<dyn NewPoWValidBlockCallback>>,
    block_connected_handler: Option<Box<dyn BlockConnectedCallback>>,
    block_disconnected_handler: Option<Box<dyn BlockDisconnectedCallback>>,
}

impl ValidationCallbackRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_block_checked<T>(&mut self, handler: T) -> &mut Self
    where
        T: BlockCheckedCallback + 'static,
    {
        self.block_checked_handler = Some(Box::new(handler) as Box<dyn BlockCheckedCallback>);
        self
    }

    pub fn register_new_pow_valid_block<T>(&mut self, handler: T) -> &mut Self
    where
        T: NewPoWValidBlockCallback + 'static,
    {
        self.new_pow_valid_block_handler =
            Some(Box::new(handler) as Box<dyn NewPoWValidBlockCallback>);
        self
    }

    pub fn register_block_connected<T>(&mut self, handler: T) -> &mut Self
    where
        T: BlockConnectedCallback + 'static,
    {
        self.block_connected_handler = Some(Box::new(handler) as Box<dyn BlockConnectedCallback>);
        self
    }

    pub fn register_block_disconnected<T>(&mut self, handler: T) -> &mut Self
    where
        T: BlockDisconnectedCallback + 'static,
    {
        self.block_disconnected_handler =
            Some(Box::new(handler) as Box<dyn BlockDisconnectedCallback>);
        self
    }
}

pub(crate) unsafe extern "C" fn validation_user_data_destroy_wrapper(user_data: *mut c_void) {
    if !user_data.is_null() {
        let _ = Box::from_raw(user_data as *mut ValidationCallbackRegistry);
    }
}

pub(crate) unsafe extern "C" fn validation_block_checked_wrapper(
    user_data: *mut c_void,
    block: *mut btck_Block,
    state: *const btck_BlockValidationState,
) {
    let block = Block::from_ptr(block);
    let registry = &*(user_data as *mut ValidationCallbackRegistry);

    if let Some(ref handler) = registry.block_checked_handler {
        handler.on_block_checked(block, BlockValidationStateRef::from_ptr(state));
    }
}

pub(crate) unsafe extern "C" fn validation_new_pow_valid_block_wrapper(
    user_data: *mut c_void,
    block: *mut btck_Block,
    entry: *const btck_BlockTreeEntry,
) {
    let block = Block::from_ptr(block);
    let registry = &*(user_data as *mut ValidationCallbackRegistry);

    if let Some(ref handler) = registry.new_pow_valid_block_handler {
        handler.on_new_pow_valid_block(
            block,
            BlockTreeEntry::from_ptr(entry as *mut btck_BlockTreeEntry),
        );
    }
}

pub(crate) unsafe extern "C" fn validation_block_connected_wrapper(
    user_data: *mut c_void,
    block: *mut btck_Block,
    entry: *const btck_BlockTreeEntry,
) {
    let block = Block::from_ptr(block);
    let registry = &*(user_data as *mut ValidationCallbackRegistry);

    if let Some(ref handler) = registry.block_connected_handler {
        handler.on_block_connected(
            block,
            BlockTreeEntry::from_ptr(entry as *mut btck_BlockTreeEntry),
        );
    }
}

pub(crate) unsafe extern "C" fn validation_block_disconnected_wrapper(
    user_data: *mut c_void,
    block: *mut btck_Block,
    entry: *const btck_BlockTreeEntry,
) {
    let block = Block::from_ptr(block);
    let registry = &*(user_data as *mut ValidationCallbackRegistry);

    if let Some(ref handler) = registry.block_disconnected_handler {
        handler.on_block_disconnected(
            block,
            BlockTreeEntry::from_ptr(entry as *mut btck_BlockTreeEntry),
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use crate::{prelude::*, BlockValidationResult};

    use super::*;

    #[test]
    fn test_registry_stores_single_handler() {
        let mut registry = ValidationCallbackRegistry::new();

        registry.register_block_checked(|_block, state: BlockValidationStateRef| {
            assert_eq!(state.result(), BlockValidationResult::Consensus);
        });

        assert!(registry.block_checked_handler.is_some());
    }

    #[test]
    fn test_closure_trait_implementation() {
        let handler = |_block, _state: BlockValidationStateRef<'_>| {};
        let _: Box<dyn BlockCheckedCallback> = Box::new(handler);
    }

    #[test]
    fn test_block_checked_registration() {
        let mut registry = ValidationCallbackRegistry::new();
        registry.register_block_checked(|_block, _state: BlockValidationStateRef<'_>| {});
        assert!(registry.block_checked_handler.is_some());
    }

    #[test]
    fn test_new_pow_valid_block_registration() {
        fn handler(_entry: BlockTreeEntry, _block: Block) {}

        let mut registry = ValidationCallbackRegistry::new();
        registry.register_new_pow_valid_block(handler);
        assert!(registry.new_pow_valid_block_handler.is_some());
    }

    #[test]
    fn test_block_connected_registration() {
        fn handler(_block: Block, _entry: BlockTreeEntry) {}

        let mut registry = ValidationCallbackRegistry::new();
        registry.register_block_connected(handler);
        assert!(registry.block_connected_handler.is_some());
    }

    #[test]
    fn test_block_disconnected_registration() {
        fn handler(_block: Block, _entry: BlockTreeEntry) {}

        let mut registry = ValidationCallbackRegistry::new();
        registry.register_block_disconnected(handler);
        assert!(registry.block_disconnected_handler.is_some());
    }

    #[test]
    fn test_registry_default() {
        let registry = ValidationCallbackRegistry::default();
        assert!(registry.block_checked_handler.is_none());
        assert!(registry.new_pow_valid_block_handler.is_none());
        assert!(registry.block_connected_handler.is_none());
        assert!(registry.block_disconnected_handler.is_none());
    }

    #[test]
    fn test_block_checked_invocation() {
        let called = Arc::new(Mutex::new(false));
        let called_clone = Arc::clone(&called);

        let mut registry = ValidationCallbackRegistry::new();
        registry.register_block_checked(move |_block, _state: BlockValidationStateRef<'_>| {
            *called_clone.lock().unwrap() = true;
        });

        if let Some(ref handler) = registry.block_checked_handler {
            let block = unsafe { Block::from_ptr(std::ptr::null_mut()) };
            let state = unsafe { BlockValidationStateRef::from_ptr(std::ptr::null()) };
            handler.on_block_checked(block, state);
        }

        assert!(*called.lock().unwrap());
    }

    #[test]
    fn test_new_pow_valid_block_invocation() {
        let called = Arc::new(Mutex::new(false));
        let called_clone = Arc::clone(&called);

        let mut registry = ValidationCallbackRegistry::new();
        registry.register_new_pow_valid_block(move |_entry: BlockTreeEntry, _block: Block| {
            *called_clone.lock().unwrap() = true;
        });

        if let Some(ref handler) = registry.new_pow_valid_block_handler {
            let block = unsafe { Block::from_ptr(std::ptr::null_mut()) };
            let entry = unsafe { BlockTreeEntry::from_ptr(std::ptr::null_mut()) };
            handler.on_new_pow_valid_block(block, entry);
        }

        assert!(*called.lock().unwrap());
    }

    #[test]
    fn test_block_connected_invocation() {
        let called = Arc::new(Mutex::new(false));
        let called_clone = Arc::clone(&called);

        let mut registry = ValidationCallbackRegistry::new();
        registry.register_block_connected(move |_block: Block, _entry: BlockTreeEntry| {
            *called_clone.lock().unwrap() = true;
        });

        if let Some(ref handler) = registry.block_connected_handler {
            let block = unsafe { Block::from_ptr(std::ptr::null_mut()) };
            let entry = unsafe { BlockTreeEntry::from_ptr(std::ptr::null_mut()) };
            handler.on_block_connected(block, entry);
        }

        assert!(*called.lock().unwrap());
    }

    #[test]
    fn test_block_disconnected_invocation() {
        let called = Arc::new(Mutex::new(false));
        let called_clone = Arc::clone(&called);

        let mut registry = ValidationCallbackRegistry::new();
        registry.register_block_disconnected(move |_block: Block, _entry: BlockTreeEntry| {
            *called_clone.lock().unwrap() = true;
        });

        if let Some(ref handler) = registry.block_disconnected_handler {
            let block = unsafe { Block::from_ptr(std::ptr::null_mut()) };
            let entry = unsafe { BlockTreeEntry::from_ptr(std::ptr::null_mut()) };
            handler.on_block_disconnected(block, entry);
        }

        assert!(*called.lock().unwrap());
    }
}
