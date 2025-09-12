use std::ffi::{c_char, c_void};

use libbitcoinkernel_sys::{
    btck_BlockTreeEntry, btck_SynchronizationState, btck_Warning, btck_block_hash_destroy,
    btck_block_tree_entry_get_block_hash,
};

use crate::{ffi::c_helpers, BlockHash, SynchronizationState, Warning};

/// The chain's tip was updated to the provided block hash.
pub trait BlockTip: Fn(SynchronizationState, BlockHash, f64) {}
impl<F: Fn(SynchronizationState, BlockHash, f64)> BlockTip for F {}

/// A new best block header was added.
pub trait HeaderTip: Fn(SynchronizationState, i64, i64, bool) {}
impl<F: Fn(SynchronizationState, i64, i64, bool)> HeaderTip for F {}

/// Reports on the current synchronization progress.
pub trait Progress: Fn(String, i32, bool) {}
impl<F: Fn(String, i32, bool)> Progress for F {}

/// A warning state issued by the kernel during validation.
pub trait WarningSet: Fn(Warning, String) {}
impl<F: Fn(Warning, String)> WarningSet for F {}

/// A previous condition leading to the issuance of a warning is no longer given.
pub trait WarningUnset: Fn(Warning) {}
impl<F: Fn(Warning)> WarningUnset for F {}

/// An error was encountered when flushing data to disk.
pub trait FlushError: Fn(String) {}
impl<F: Fn(String)> FlushError for F {}

/// An un-recoverable system error was encountered by the library.
pub trait FatalError: Fn(String) {}
impl<F: Fn(String)> FatalError for F {}

/// A callback holder struct for the notification interface calls.
pub struct KernelNotificationInterfaceCallbacks {
    pub kn_block_tip: Box<dyn BlockTip>,
    pub kn_header_tip: Box<dyn HeaderTip>,
    pub kn_progress: Box<dyn Progress>,
    pub kn_warning_set: Box<dyn WarningSet>,
    pub kn_warning_unset: Box<dyn WarningUnset>,
    pub kn_flush_error: Box<dyn FlushError>,
    pub kn_fatal_error: Box<dyn FatalError>,
}

pub unsafe extern "C" fn kn_user_data_destroy_wrapper(user_data: *mut c_void) {
    if !user_data.is_null() {
        let _ = Box::from_raw(user_data as *mut KernelNotificationInterfaceCallbacks);
    }
}

pub unsafe extern "C" fn kn_block_tip_wrapper(
    user_data: *mut c_void,
    state: btck_SynchronizationState,
    entry: *const btck_BlockTreeEntry,
    verification_progress: f64,
) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbacks);
    let hash = btck_block_tree_entry_get_block_hash(entry);
    let res = BlockHash { hash: (*hash).hash };
    btck_block_hash_destroy(hash);
    (holder.kn_block_tip)(state.into(), res, verification_progress);
}

pub unsafe extern "C" fn kn_header_tip_wrapper(
    user_data: *mut c_void,
    state: btck_SynchronizationState,
    height: i64,
    timestamp: i64,
    presync: i32,
) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbacks);
    (holder.kn_header_tip)(state.into(), height, timestamp, c_helpers::enabled(presync));
}

pub unsafe extern "C" fn kn_progress_wrapper(
    user_data: *mut c_void,
    title: *const c_char,
    title_len: usize,
    progress_percent: i32,
    resume_possible: i32,
) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbacks);
    (holder.kn_progress)(
        c_helpers::to_string(title, title_len),
        progress_percent,
        c_helpers::enabled(resume_possible),
    );
}

pub unsafe extern "C" fn kn_warning_set_wrapper(
    user_data: *mut c_void,
    warning: btck_Warning,
    message: *const c_char,
    message_len: usize,
) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbacks);
    (holder.kn_warning_set)(warning.into(), c_helpers::to_string(message, message_len));
}

pub unsafe extern "C" fn kn_warning_unset_wrapper(user_data: *mut c_void, warning: btck_Warning) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbacks);
    (holder.kn_warning_unset)(warning.into());
}

pub unsafe extern "C" fn kn_flush_error_wrapper(
    user_data: *mut c_void,
    message: *const c_char,
    message_len: usize,
) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbacks);
    (holder.kn_flush_error)(c_helpers::to_string(message, message_len));
}

pub unsafe extern "C" fn kn_fatal_error_wrapper(
    user_data: *mut c_void,
    message: *const c_char,
    message_len: usize,
) {
    let holder = &*(user_data as *mut KernelNotificationInterfaceCallbacks);
    (holder.kn_fatal_error)(c_helpers::to_string(message, message_len));
}
