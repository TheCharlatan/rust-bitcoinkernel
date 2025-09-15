use std::ffi::c_void;

use libbitcoinkernel_sys::{
    btck_ChainParameters, btck_ChainType, btck_Context, btck_ContextOptions,
    btck_NotificationInterfaceCallbacks, btck_ValidationInterfaceCallbacks,
    btck_chain_parameters_create, btck_chain_parameters_destroy, btck_context_create,
    btck_context_destroy, btck_context_interrupt, btck_context_options_create,
    btck_context_options_destroy, btck_context_options_set_chainparams,
    btck_context_options_set_notifications, btck_context_options_set_validation_interface,
};

use crate::{
    ffi::c_helpers,
    notifications::{
        notification::{
            kn_block_tip_wrapper, kn_fatal_error_wrapper, kn_flush_error_wrapper,
            kn_header_tip_wrapper, kn_progress_wrapper, kn_user_data_destroy_wrapper,
            kn_warning_set_wrapper, kn_warning_unset_wrapper,
        },
        validation::{vi_block_checked_wrapper, vi_user_data_destroy_wrapper},
    },
    KernelError, KernelNotificationInterfaceCallbacks, ValidationInterfaceCallbacks,
    BTCK_CHAIN_TYPE_MAINNET, BTCK_CHAIN_TYPE_REGTEST, BTCK_CHAIN_TYPE_SIGNET,
    BTCK_CHAIN_TYPE_TESTNET, BTCK_CHAIN_TYPE_TESTNET_4,
};

/// The chain parameters with which to configure a [`Context`].
pub struct ChainParams {
    inner: *mut btck_ChainParameters,
}

unsafe impl Send for ChainParams {}
unsafe impl Sync for ChainParams {}

impl ChainParams {
    pub fn new(chain_type: ChainType) -> ChainParams {
        let btck_chain_type = chain_type.into();
        ChainParams {
            inner: unsafe { btck_chain_parameters_create(btck_chain_type) },
        }
    }
}

impl Drop for ChainParams {
    fn drop(&mut self) {
        unsafe {
            btck_chain_parameters_destroy(self.inner);
        }
    }
}

/// The main context struct. This should be setup through the [`ContextBuilder`] and
/// has to be kept in memory for the duration of context-dependent library
/// operations.
///
pub struct Context {
    inner: *mut btck_Context,
}

unsafe impl Send for Context {}
unsafe impl Sync for Context {}

impl Context {
    pub fn interrupt(&self) -> Result<(), KernelError> {
        let result = unsafe { btck_context_interrupt(self.inner) };
        if c_helpers::success(result) {
            return Ok(());
        } else {
            return Err(KernelError::Internal(
                "Context interrupt failed.".to_string(),
            ));
        }
    }

    pub fn as_ptr(&self) -> *mut btck_Context {
        self.inner
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            btck_context_destroy(self.inner);
        }
    }
}

/// Builder struct for the kernel [`Context`].
///
/// The builder by default configures for mainnet and swallows any kernel
/// notifications.
pub struct ContextBuilder {
    inner: *mut btck_ContextOptions,
}

impl Default for ContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ContextBuilder {
    pub fn new() -> ContextBuilder {
        ContextBuilder {
            inner: unsafe { btck_context_options_create() },
        }
    }

    /// Consumes the builder and creates a [`Context`].
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::Internal`] if [`Context`] creation fails.
    pub fn build(self) -> Result<Context, KernelError> {
        let inner = unsafe { btck_context_create(self.inner) };
        if inner.is_null() {
            return Err(KernelError::Internal("Invalid context.".to_string()));
        }
        unsafe { btck_context_options_destroy(self.inner) };
        Ok(Context { inner })
    }

    /// Sets the notifications callbacks to the passed in holder struct
    pub fn kn_callbacks(
        self,
        kn_callbacks: Box<KernelNotificationInterfaceCallbacks>,
    ) -> ContextBuilder {
        let kn_pointer = Box::into_raw(kn_callbacks);
        unsafe {
            let holder = btck_NotificationInterfaceCallbacks {
                user_data: kn_pointer as *mut c_void,
                user_data_destroy: Some(kn_user_data_destroy_wrapper),
                block_tip: Some(kn_block_tip_wrapper),
                header_tip: Some(kn_header_tip_wrapper),
                progress: Some(kn_progress_wrapper),
                warning_set: Some(kn_warning_set_wrapper),
                warning_unset: Some(kn_warning_unset_wrapper),
                flush_error: Some(kn_flush_error_wrapper),
                fatal_error: Some(kn_fatal_error_wrapper),
            };
            btck_context_options_set_notifications(self.inner, holder);
        };
        self
    }

    /// Sets the chain type
    pub fn chain_type(self, chain_type: ChainType) -> ContextBuilder {
        let chain_params = ChainParams::new(chain_type);
        unsafe { btck_context_options_set_chainparams(self.inner, chain_params.inner) };
        self
    }

    /// Sets the validation interface callbacks
    pub fn validation_interface(
        self,
        vi_callbacks: Box<ValidationInterfaceCallbacks>,
    ) -> ContextBuilder {
        let vi_pointer = Box::into_raw(vi_callbacks);
        unsafe {
            let holder = btck_ValidationInterfaceCallbacks {
                user_data: vi_pointer as *mut c_void,
                user_data_destroy: Some(vi_user_data_destroy_wrapper),
                block_checked: Some(vi_block_checked_wrapper),
            };
            btck_context_options_set_validation_interface(self.inner, holder);
        }
        self
    }
}

/// Bitcoin network chain types.
///
/// Specifies which Bitcoin network the kernel should operate on.
/// Each chain type has different consensus rules and network parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ChainType {
    /// Bitcoin mainnet - the production network
    Mainnet = BTCK_CHAIN_TYPE_MAINNET,
    /// Bitcoin testnet - the original test network
    Testnet = BTCK_CHAIN_TYPE_TESTNET,
    /// Bitcoin testnet4 - the newer test network
    Testnet4 = BTCK_CHAIN_TYPE_TESTNET_4,
    /// Bitcoin signet - signed test network
    Signet = BTCK_CHAIN_TYPE_SIGNET,
    /// Regression test network for local development
    Regtest = BTCK_CHAIN_TYPE_REGTEST,
}

impl From<ChainType> for btck_ChainType {
    fn from(chain_type: ChainType) -> Self {
        chain_type as btck_ChainType
    }
}

impl From<btck_ChainType> for ChainType {
    fn from(value: btck_ChainType) -> Self {
        match value {
            BTCK_CHAIN_TYPE_MAINNET => ChainType::Mainnet,
            BTCK_CHAIN_TYPE_TESTNET => ChainType::Testnet,
            BTCK_CHAIN_TYPE_TESTNET_4 => ChainType::Testnet4,
            BTCK_CHAIN_TYPE_SIGNET => ChainType::Signet,
            BTCK_CHAIN_TYPE_REGTEST => ChainType::Regtest,
            _ => panic!("Unknown chain type: {}", value),
        }
    }
}
