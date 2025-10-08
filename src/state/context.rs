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
            notification_block_tip_wrapper, notification_fatal_error_wrapper,
            notification_flush_error_wrapper, notification_header_tip_wrapper,
            notification_progress_wrapper, notification_user_data_destroy_wrapper,
            notification_warning_set_wrapper, notification_warning_unset_wrapper, BlockTipCallback,
            FatalErrorCallback, FlushErrorCallback, HeaderTipCallback,
            NotificationCallbackRegistry, ProgressCallback, WarningSetCallback,
            WarningUnsetCallback,
        },
        validation::{
            validation_block_checked_wrapper, validation_block_connected_wrapper,
            validation_block_disconnected_wrapper, validation_new_pow_valid_block_wrapper,
            validation_user_data_destroy_wrapper, BlockCheckedCallback, BlockConnectedCallback,
            BlockDisconnectedCallback, NewPoWValidBlockCallback, ValidationCallbackRegistry,
        },
    },
    KernelError, BTCK_CHAIN_TYPE_MAINNET, BTCK_CHAIN_TYPE_REGTEST, BTCK_CHAIN_TYPE_SIGNET,
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
    notification_registry: Option<NotificationCallbackRegistry>,
    validation_registry: Option<ValidationCallbackRegistry>,
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
            notification_registry: None,
            validation_registry: None,
        }
    }

    /// Consumes the builder and creates a [`Context`].
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::Internal`] if [`Context`] creation fails.
    pub fn build(mut self) -> Result<Context, KernelError> {
        if let Some(registry) = self.notification_registry.take() {
            self.setup_notification_interface(registry);
        }
        if let Some(registry) = self.validation_registry.take() {
            self.setup_validation_interface(registry);
        }

        let inner = unsafe { btck_context_create(self.inner) };
        if inner.is_null() {
            return Err(KernelError::Internal("Invalid context.".to_string()));
        }
        unsafe { btck_context_options_destroy(self.inner) };
        Ok(Context { inner })
    }

    fn setup_notification_interface(&self, registry: NotificationCallbackRegistry) {
        let registry_ptr = Box::into_raw(Box::new(registry));
        unsafe {
            let holder = btck_NotificationInterfaceCallbacks {
                user_data: registry_ptr as *mut c_void,
                user_data_destroy: Some(notification_user_data_destroy_wrapper),
                block_tip: Some(notification_block_tip_wrapper),
                header_tip: Some(notification_header_tip_wrapper),
                progress: Some(notification_progress_wrapper),
                warning_set: Some(notification_warning_set_wrapper),
                warning_unset: Some(notification_warning_unset_wrapper),
                flush_error: Some(notification_flush_error_wrapper),
                fatal_error: Some(notification_fatal_error_wrapper),
            };
            btck_context_options_set_notifications(self.inner, holder);
        }
    }

    fn setup_validation_interface(&self, registry: ValidationCallbackRegistry) {
        let registry_ptr = Box::into_raw(Box::new(registry));
        unsafe {
            let holder = btck_ValidationInterfaceCallbacks {
                user_data: registry_ptr as *mut c_void,
                user_data_destroy: Some(validation_user_data_destroy_wrapper),
                block_checked: Some(validation_block_checked_wrapper),
                pow_valid_block: Some(validation_new_pow_valid_block_wrapper),
                block_connected: Some(validation_block_connected_wrapper),
                block_disconnected: Some(validation_block_disconnected_wrapper),
            };
            btck_context_options_set_validation_interface(self.inner, holder);
        }
    }

    /// Sets the chain type
    pub fn chain_type(self, chain_type: ChainType) -> ContextBuilder {
        let chain_params = ChainParams::new(chain_type);
        unsafe { btck_context_options_set_chainparams(self.inner, chain_params.inner) };
        self
    }

    pub fn with_block_tip_notification<T>(mut self, handler: T) -> Self
    where
        T: BlockTipCallback + 'static,
    {
        self.get_or_create_notification_registry()
            .register_block_tip(handler);
        self
    }

    pub fn with_progress_notification<T>(mut self, handler: T) -> Self
    where
        T: ProgressCallback + 'static,
    {
        self.get_or_create_notification_registry()
            .register_progress(handler);
        self
    }

    pub fn with_header_tip_notification<T>(mut self, handler: T) -> Self
    where
        T: HeaderTipCallback + 'static,
    {
        self.get_or_create_notification_registry()
            .register_header_tip(handler);
        self
    }

    pub fn with_warning_set_notification<T>(mut self, handler: T) -> Self
    where
        T: WarningSetCallback + 'static,
    {
        self.get_or_create_notification_registry()
            .register_warning_set(handler);
        self
    }

    pub fn with_warning_unset_notification<T>(mut self, handler: T) -> Self
    where
        T: WarningUnsetCallback + 'static,
    {
        self.get_or_create_notification_registry()
            .register_warning_unset(handler);
        self
    }

    pub fn with_flush_error_notification<T>(mut self, handler: T) -> Self
    where
        T: FlushErrorCallback + 'static,
    {
        self.get_or_create_notification_registry()
            .register_flush_error(handler);
        self
    }

    pub fn with_fatal_error_notification<T>(mut self, handler: T) -> Self
    where
        T: FatalErrorCallback + 'static,
    {
        self.get_or_create_notification_registry()
            .register_fatal_error(handler);
        self
    }

    pub fn notifications<F>(mut self, configure: F) -> Self
    where
        F: FnOnce(&mut NotificationCallbackRegistry),
    {
        let registry = self.get_or_create_notification_registry();
        configure(registry);
        self
    }

    fn get_or_create_notification_registry(&mut self) -> &mut NotificationCallbackRegistry {
        if self.notification_registry.is_none() {
            self.notification_registry = Some(NotificationCallbackRegistry::new());
        }
        self.notification_registry.as_mut().unwrap()
    }

    pub fn with_block_checked_validation<T>(mut self, handler: T) -> Self
    where
        T: BlockCheckedCallback + 'static,
    {
        self.get_or_create_validation_registry()
            .register_block_checked(handler);
        self
    }

    pub fn with_new_pow_valid_block<T>(mut self, handler: T) -> Self
    where
        T: NewPoWValidBlockCallback + 'static,
    {
        self.get_or_create_validation_registry()
            .register_new_pow_valid_block(handler);
        self
    }

    pub fn with_block_connected<T>(mut self, handler: T) -> Self
    where
        T: BlockConnectedCallback + 'static,
    {
        self.get_or_create_validation_registry()
            .register_block_connected(handler);
        self
    }

    pub fn with_block_disconnected<T>(mut self, handler: T) -> Self
    where
        T: BlockDisconnectedCallback + 'static,
    {
        self.get_or_create_validation_registry()
            .register_block_disconnected(handler);
        self
    }

    pub fn validation<F>(mut self, configure: F) -> Self
    where
        F: FnOnce(&mut ValidationCallbackRegistry),
    {
        let registry = self.get_or_create_validation_registry();
        configure(registry);
        self
    }

    fn get_or_create_validation_registry(&mut self) -> &mut ValidationCallbackRegistry {
        if self.validation_registry.is_none() {
            self.validation_registry = Some(ValidationCallbackRegistry::new());
        }
        self.validation_registry.as_mut().unwrap()
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

#[cfg(test)]
mod tests {
    use crate::notifications::types::BlockValidationStateRef;

    use super::*;

    #[test]
    fn test_notification_callback_registration_methods() {
        let mut builder = ContextBuilder::new();

        builder = builder
            .with_progress_notification(|_title, _percent, _resume| {})
            .with_block_tip_notification(|_state, _hash, _progress| {})
            .with_header_tip_notification(|_state, _height, _timestamp, _presync| {})
            .with_warning_set_notification(|_warning, _message| {})
            .with_warning_unset_notification(|_warning| {})
            .with_flush_error_notification(|_message| {})
            .with_fatal_error_notification(|_message| {});

        assert!(builder.notification_registry.is_some());
    }

    #[test]
    fn test_validation_callback_registration_method() {
        let mut builder = ContextBuilder::new();

        builder =
            builder.with_block_checked_validation(|_block, _state: BlockValidationStateRef<'_>| {});

        assert!(builder.validation_registry.is_some());
    }

    #[test]
    fn test_advanced_notification_configuration() {
        let mut builder = ContextBuilder::new();

        builder = builder.notifications(|registry| {
            registry.register_progress(|_title, _percent, _resume| {});
            registry.register_block_tip(|_state, _hash, _progress| {});
        });

        assert!(builder.notification_registry.is_some());
    }

    #[test]
    fn test_advanced_validation_configuration() {
        fn pow_handler(_pindex: crate::BlockTreeEntry, _block: crate::Block) {}
        fn connected_handler(_block: crate::Block, _pindex: crate::BlockTreeEntry) {}
        fn disconnected_handler(_block: crate::Block, _pindex: crate::BlockTreeEntry) {}

        let mut builder = ContextBuilder::new();

        builder = builder.validation(|registry| {
            registry.register_block_checked(|_block, _state: BlockValidationStateRef<'_>| {});
            registry.register_new_pow_valid_block(pow_handler);
            registry.register_block_connected(connected_handler);
            registry.register_block_disconnected(disconnected_handler);
        });

        assert!(builder.validation_registry.is_some());
    }

    #[test]
    fn test_mixed_callback_registration() {
        let mut builder = ContextBuilder::new();

        builder = builder
            .with_progress_notification(|_title, _percent, _resume| {})
            .with_block_checked_validation(|_block, _state: BlockValidationStateRef<'_>| {})
            .chain_type(ChainType::Testnet);

        assert!(builder.notification_registry.is_some());
        assert!(builder.validation_registry.is_some());
    }

    #[test]
    fn test_lazy_registry_creation() {
        let builder = ContextBuilder::new();

        assert!(builder.notification_registry.is_none());
        assert!(builder.validation_registry.is_none());
    }

    #[test]
    fn test_method_chaining_preserves_other_settings() {
        let builder = ContextBuilder::new()
            .chain_type(ChainType::Regtest)
            .with_progress_notification(|_title, _percent, _resume| {})
            .with_block_checked_validation(|_block, _state: BlockValidationStateRef<'_>| {});

        assert!(builder.notification_registry.is_some());
        assert!(builder.validation_registry.is_some());
    }

    #[test]
    fn test_build_with_callbacks() {
        let context_result = ContextBuilder::new()
            .with_progress_notification(|_title, _percent, _resume| {})
            .with_block_checked_validation(|_block, _state: BlockValidationStateRef<'_>| {})
            .chain_type(ChainType::Testnet)
            .build();

        assert!(context_result.is_ok());
        let _context = context_result.unwrap();
    }
}
