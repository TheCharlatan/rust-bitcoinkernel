use std::ffi::c_void;

use libbitcoinkernel_sys::{
    btck_Block, btck_BlockValidationState, btck_block_validation_state_get_block_validation_result,
    btck_block_validation_state_get_validation_mode,
};

use crate::Block;

use super::{BlockValidationResult, ValidationMode};

/// Exposes the result after validating a block.
pub trait BlockChecked: Fn(Block, ValidationMode, BlockValidationResult) {}
impl<F: Fn(Block, ValidationMode, BlockValidationResult)> BlockChecked for F {}

/// A holder struct for validation interface callbacks
pub struct ValidationInterfaceCallbacks {
    /// Called after a block has completed validation and communicates its validation state.
    pub block_checked: Box<dyn BlockChecked>,
}

pub unsafe extern "C" fn vi_user_data_destroy_wrapper(user_data: *mut c_void) {
    if !user_data.is_null() {
        let _ = Box::from_raw(user_data as *mut ValidationInterfaceCallbacks);
    }
}

pub unsafe extern "C" fn vi_block_checked_wrapper(
    user_data: *mut c_void,
    block: *mut btck_Block,
    stateIn: *const btck_BlockValidationState,
) {
    let holder = &*(user_data as *mut ValidationInterfaceCallbacks);
    let result = btck_block_validation_state_get_block_validation_result(stateIn);
    let mode = btck_block_validation_state_get_validation_mode(stateIn);
    (holder.block_checked)(Block::from_ptr(block), mode.into(), result.into());
}
