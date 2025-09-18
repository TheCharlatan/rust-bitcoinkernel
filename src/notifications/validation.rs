use std::ffi::c_void;

use libbitcoinkernel_sys::{
    btck_Block, btck_BlockValidationState, btck_block_validation_state_get_block_validation_result,
    btck_block_validation_state_get_validation_mode,
};

use crate::{ffi::sealed::FromMutPtr, Block};

use super::{BlockValidationResult, ValidationMode};

/// Exposes the result after validating a block.
pub trait BlockCheckedCallback: Send + Sync {
    fn on_block_checked(&self, block: Block, mode: ValidationMode, result: BlockValidationResult);
}

impl<F> BlockCheckedCallback for F
where
    F: Fn(Block, ValidationMode, BlockValidationResult) + Send + Sync + 'static,
{
    fn on_block_checked(&self, block: Block, mode: ValidationMode, result: BlockValidationResult) {
        self(block, mode, result)
    }
}

/// Registry for managing validation interface callback handlers.
#[derive(Default)]
pub struct ValidationCallbackRegistry {
    block_checked_handler: Option<Box<dyn BlockCheckedCallback>>,
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
}

pub(crate) unsafe extern "C" fn validation_user_data_destroy_wrapper(user_data: *mut c_void) {
    if !user_data.is_null() {
        let _ = Box::from_raw(user_data as *mut ValidationCallbackRegistry);
    }
}

pub(crate) unsafe extern "C" fn validation_block_checked_wrapper(
    user_data: *mut c_void,
    block: *mut btck_Block,
    stateIn: *const btck_BlockValidationState,
) {
    let registry = &*(user_data as *mut ValidationCallbackRegistry);

    if let Some(ref handler) = registry.block_checked_handler {
        let result = btck_block_validation_state_get_block_validation_result(stateIn);
        let mode = btck_block_validation_state_get_validation_mode(stateIn);
        handler.on_block_checked(Block::from_ptr(block), mode.into(), result.into());
    }
}
