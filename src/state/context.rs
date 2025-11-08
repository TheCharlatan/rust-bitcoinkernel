//! Context initialization and configuration for the Bitcoin Kernel library.
//!
//! The [`Context`] holds the kernel library's logically global state and is
//! passed to operations that need access to this state. It should be kept in
//! scope for the duration of all operations that depend on it.
//!
//! # Overview
//!
//! The context is created using the builder pattern via [`ContextBuilder`],
//! which allows configuration of:
//! - Chain type (mainnet, testnet, regtest, etc.)
//! - Notification callbacks for chain events
//! - Validation callbacks for block processing
//!
//! # Examples
//!
//! ## Basic Usage
//!
//! ```no_run
//! use bitcoinkernel::{Context, ChainType, KernelError};
//!
//! // Create a default context (mainnet)
//! let context = Context::new()?;
//! # Ok::<(), KernelError>(())
//! ```
//!
//! ## With Chain Type
//!
//! ```no_run
//! use bitcoinkernel::{Context, ChainType, KernelError};
//!
//! // Create a regtest context for testing
//! let context = Context::builder()
//!     .chain_type(ChainType::Regtest)
//!     .build()?;
//! # Ok::<(), KernelError>(())
//! ```
//!
//! ## With Notifications
//!
//! ```no_run
//! use bitcoinkernel::{Context, ChainType, KernelError};
//!
//! let context = Context::builder()
//!     .chain_type(ChainType::Testnet)
//!     .with_progress_notification(|title, percent, _resume| {
//!         println!("{}: {}%", title, percent);
//!     })
//!     .with_block_tip_notification(|_state, hash, _progress| {
//!         println!("New block tip: {}", hash);
//!     })
//!     .build()?;
//! # Ok::<(), KernelError>(())
//! ```

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
    ffi::{c_helpers, sealed::AsPtr},
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

/// Chain parameters for configuring a [`Context`].
///
/// [`ChainParams`] encapsulates the consensus rules and network parameters
/// for a specific Bitcoin network (mainnet, testnet, regtest, etc.).
///
/// # Lifetime
/// The chain parameters are automatically cleaned up when dropped.
///
/// # Thread Safety
/// [`ChainParams`] can be safely sent between threads and shared via `Arc`.
///
/// # Examples
/// ```no_run
/// use bitcoinkernel::{ChainParams, ChainType};
///
/// let mainnet_params = ChainParams::new(ChainType::Mainnet);
/// let regtest_params = ChainParams::new(ChainType::Regtest);
/// ```
pub struct ChainParams {
    inner: *mut btck_ChainParameters,
}

unsafe impl Send for ChainParams {}
unsafe impl Sync for ChainParams {}

impl ChainParams {
    /// Creates new chain parameters for the specified chain type.
    ///
    /// # Arguments
    /// * `chain_type` - The Bitcoin network type to configure
    ///
    /// # Returns
    /// A new [`ChainParams`] instance configured for the specified chain.
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::{ChainParams, ChainType};
    ///
    /// let params = ChainParams::new(ChainType::Testnet);
    /// ```
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

/// The main context for the Bitcoin Kernel library.
///
/// The [`Context`] manages the global state of the Bitcoin Kernel library
/// and should be kept in memory for the duration of all context-dependent operations.
/// It is created via [`ContextBuilder`] and can be configured with various
/// chain types and callbacks.
///
/// # Lifetime
/// It is recommended to outlive any objects that depend on it, such as
/// [`ChainstateManager`](crate::ChainstateManager) instances.
///
/// # Thread Safety
/// [`Context`] can be safely sent between threads and shared via `Arc`.
///
/// # Examples
/// ```no_run
/// use bitcoinkernel::{Context, ChainType, KernelError};
///
/// // Simple creation with defaults
/// let context = Context::new()?;
///
/// // Using the builder for configuration
/// let context = Context::builder()
///     .chain_type(ChainType::Regtest)
///     .build()?;
/// # Ok::<(), KernelError>(())
/// ```
pub struct Context {
    inner: *mut btck_Context,
}

unsafe impl Send for Context {}
unsafe impl Sync for Context {}

impl Context {
    /// Returns a new [`ContextBuilder`] for constructing a context.
    ///
    /// This is the recommended way to create a [`Context`] when you need
    /// to configure chain types or register callbacks.
    ///
    /// # Returns
    /// A new [`ContextBuilder`] instance.
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::{Context, ChainType, KernelError};
    ///
    /// let context = Context::builder()
    ///     .chain_type(ChainType::Testnet)
    ///     .build()?;
    /// # Ok::<(), KernelError>(())
    /// ```
    pub fn builder() -> ContextBuilder {
        ContextBuilder::new()
    }

    /// Creates a new context with default settings (mainnet).
    ///
    /// This is a convenience method equivalent to calling
    /// `ContextBuilder::new().build()`.
    ///
    /// # Returns
    /// * `Ok(`[`Context`]`)` - On successful context creation
    /// * `Err(`[`KernelError::Internal`]`)` - If context creation fails
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::{Context, KernelError};
    ///
    /// let context = Context::new()?;
    /// # Ok::<(), KernelError>(())
    /// ```
    pub fn new() -> Result<Context, KernelError> {
        ContextBuilder::new().build()
    }

    /// Interrupts any ongoing operations in the context.
    ///
    /// This signals the context to stop any long-running operations that
    /// support interruption, such as reindex, importing or  processing blocks.
    ///
    /// # Returns
    /// * `Ok(())` - If the interrupt signal was successfully sent
    /// * `Err(`[`KernelError::Internal`]`)` - If the interrupt operation fails
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::{Context, KernelError};
    ///
    /// let context = Context::new()?;
    ///
    /// // Later, interrupt ongoing operations
    /// context.interrupt()?;
    /// # Ok::<(), KernelError>(())
    /// ```
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
}

impl AsPtr<btck_Context> for Context {
    fn as_ptr(&self) -> *const btck_Context {
        self.inner as *const _
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            btck_context_destroy(self.inner);
        }
    }
}

/// Builder for creating a [`Context`] with custom configuration.
///
/// The builder pattern allows flexible configuration of the Bitcoin Kernel
/// context before creation. By default, the builder configures for mainnet
/// with no callbacks registered.
///
/// # Configuration Options
/// - **Chain type**: Set via [`chain_type`](ContextBuilder::chain_type)
/// - **Notification callbacks**: Set via `with_*_notification` methods or [`notifications`](ContextBuilder::notifications)
/// - **Validation callbacks**: Set via `with_*_validation` methods or [`validation`](ContextBuilder::validation)
///
/// # Examples
///
/// ## Basic Configuration
/// ```no_run
/// use bitcoinkernel::{ContextBuilder, ChainType, KernelError};
///
/// let context = ContextBuilder::new()
///     .chain_type(ChainType::Regtest)
///     .build()?;
/// # Ok::<(), KernelError>(())
/// ```
///
/// ## With Individual Callbacks
/// ```no_run
/// use bitcoinkernel::{ContextBuilder, ChainType, KernelError};
///
/// let context = ContextBuilder::new()
///     .chain_type(ChainType::Testnet)
///     .with_progress_notification(|title, percent, _resume| {
///         println!("Progress: {} - {}%", title, percent);
///     })
///     .with_block_tip_notification(|_state, hash, _progress| {
///         println!("New tip: {}", hash);
///     })
///     .build()?;
/// # Ok::<(), KernelError>(())
/// ```
///
/// ## With Advanced Configuration
/// ```no_run
/// use bitcoinkernel::{Block, BlockValidationStateRef, ContextBuilder, ChainType, KernelError};
///
/// let context = ContextBuilder::new()
///     .chain_type(ChainType::Regtest)
///     .notifications(|registry| {
///         registry.register_progress(|title, percent, _resume| {
///             println!("{}: {}%", title, percent);
///         });
///         registry.register_warning_set(|warning, message| {
///             eprintln!("Warning: {} - {}", warning, message);
///         });
///     })
///     .validation(|registry| {
///         registry.register_block_checked(|block: Block, _state: BlockValidationStateRef<'_>| {
///             println!("Checked block: {}", block.hash());
///         });
///     })
///     .build()?;
/// # Ok::<(), KernelError>(())
/// ```
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
    /// Creates a new context builder with default settings.
    ///
    /// The builder is initialized with mainnet configuration and no callbacks.
    ///
    /// # Returns
    /// A new [`ContextBuilder`] instance.
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::ContextBuilder;
    ///
    /// let builder = ContextBuilder::new();
    /// ```
    pub fn new() -> ContextBuilder {
        ContextBuilder {
            inner: unsafe { btck_context_options_create() },
            notification_registry: None,
            validation_registry: None,
        }
    }

    /// Consumes the builder and creates a [`Context`].
    ///
    /// This finalizes the configuration and creates the actual context instance.
    /// All registered callbacks are set up during this process.
    ///
    /// # Returns
    /// * `Ok(`[`Context`]`)` - On successful context creation
    /// * `Err(`[`KernelError::Internal`]`)` - If context creation fails
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::{ContextBuilder, ChainType, KernelError};
    ///
    /// let context = ContextBuilder::new()
    ///     .chain_type(ChainType::Regtest)
    ///     .build()?;
    /// # Ok::<(), KernelError>(())
    /// ```
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

    /// Sets the Bitcoin network chain type.
    ///
    /// Configures the context to operate on the specified Bitcoin network.
    ///
    /// # Arguments
    /// * `chain_type` - The [`ChainType`] to configure (mainnet, testnet, etc.)
    ///
    /// # Returns
    /// The builder instance for method chaining.
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::{ContextBuilder, ChainType, KernelError};
    ///
    /// let context = ContextBuilder::new()
    ///     .chain_type(ChainType::Regtest)
    ///     .build()?;
    /// # Ok::<(), KernelError>(())
    /// ```
    pub fn chain_type(self, chain_type: ChainType) -> ContextBuilder {
        let chain_params = ChainParams::new(chain_type);
        unsafe { btck_context_options_set_chainparams(self.inner, chain_params.inner) };
        self
    }

    /// Registers a callback for block tip notifications.
    ///
    /// The callback is invoked when the chain's tip is updated to a new block.
    /// This happens during block validation and chain reorganizations.
    ///
    /// # Type Parameters
    /// * `T` - A type implementing [`BlockTipCallback`]
    ///
    /// # Arguments
    /// * `handler` - The callback function or closure that receives:
    ///   - `state` - The [`SynchronizationState`](crate::SynchronizationState) (initial download, etc.)
    ///   - `hash` - The [`BlockHash`](crate::BlockHash) of the new tip
    ///   - `progress` - Verification progress as an `f64` (0.0 to 1.0)
    ///
    /// # Returns
    /// The builder instance for method chaining.
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::{ContextBuilder, KernelError};
    ///
    /// let context = ContextBuilder::new()
    ///     .with_block_tip_notification(|_state, hash, progress| {
    ///         println!("Chain tip updated to: {} ({})", hash, progress);
    ///     })
    ///     .build()?;
    /// # Ok::<(), KernelError>(())
    /// ```
    pub fn with_block_tip_notification<T>(mut self, handler: T) -> Self
    where
        T: BlockTipCallback + 'static,
    {
        self.get_or_create_notification_registry()
            .register_block_tip(handler);
        self
    }

    /// Registers a callback for progress notifications.
    ///
    /// The callback is invoked to report on current block synchronization progress
    /// during operations such as initial block download or reindexing.
    ///
    /// # Type Parameters
    /// * `T` - A type implementing [`ProgressCallback`]
    ///
    /// # Arguments
    /// * `handler` - The callback function or closure that receives:
    ///   - `title` - Description of the current operation as a [`String`]
    ///   - `percent` - Progress percentage as an `i32` (0-100)
    ///   - `resume` - Whether the operation can be resumed if interrupted (as a `bool`)
    ///
    /// # Returns
    /// The builder instance for method chaining.
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::{ContextBuilder, KernelError};
    ///
    /// let context = ContextBuilder::new()
    ///     .with_progress_notification(|title, percent, resume| {
    ///         println!("{}: {}% (resumable: {})", title, percent, resume);
    ///     })
    ///     .build()?;
    /// # Ok::<(), KernelError>(())
    /// ```
    pub fn with_progress_notification<T>(mut self, handler: T) -> Self
    where
        T: ProgressCallback + 'static,
    {
        self.get_or_create_notification_registry()
            .register_progress(handler);
        self
    }

    /// Registers a callback for header tip notifications.
    ///
    /// The callback is invoked when a new best block header is added to the header
    /// chain. This typically occurs during the header synchronization phase, which
    /// happens before full block download.
    ///
    /// # Type Parameters
    /// * `T` - A type implementing [`HeaderTipCallback`]
    ///
    /// # Arguments
    /// * `handler` - The callback function or closure that receives:
    ///   - `state` - The [`SynchronizationState`](crate::SynchronizationState)
    ///   - `height` - The height of the new header tip as an `i64`
    ///   - `timestamp` - The timestamp of the header as an `i64`
    ///   - `presync` - Whether this is during pre-synchronization (as a `bool`)
    ///
    /// # Returns
    /// The builder instance for method chaining.
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::{ContextBuilder, KernelError};
    ///
    /// let context = ContextBuilder::new()
    ///     .with_header_tip_notification(|_state, height, timestamp, _presync| {
    ///         println!("New header at height {}, time={}", height, timestamp);
    ///     })
    ///     .build()?;
    /// # Ok::<(), KernelError>(())
    /// ```
    pub fn with_header_tip_notification<T>(mut self, handler: T) -> Self
    where
        T: HeaderTipCallback + 'static,
    {
        self.get_or_create_notification_registry()
            .register_header_tip(handler);
        self
    }

    /// Registers a callback for warning set notifications.
    ///
    /// The callback is invoked when a warning is issued by the kernel library
    /// during validation. This can include warnings about chain forks or other
    /// consensus-related issues.
    ///
    /// # Type Parameters
    /// * `T` - A type implementing [`WarningSetCallback`]
    ///
    /// # Arguments
    /// * `handler` - The callback function or closure that receives:
    ///   - `warning` - A [`Warning`](crate::Warning) identifier/category
    ///   - `message` - A human-readable description as a [`String`]
    ///
    /// # Returns
    /// The builder instance for method chaining.
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::{ContextBuilder, KernelError};
    ///
    /// let context = ContextBuilder::new()
    ///     .with_warning_set_notification(|warning, message| {
    ///         eprintln!("Kernel Warning [{}]: {}", warning, message);
    ///     })
    ///     .build()?;
    /// # Ok::<(), KernelError>(())
    pub fn with_warning_set_notification<T>(mut self, handler: T) -> Self
    where
        T: WarningSetCallback + 'static,
    {
        self.get_or_create_notification_registry()
            .register_warning_set(handler);
        self
    }

    /// Registers a callback for warning unset notifications.
    ///
    /// The callback is invoked when a previous condition that led to the issuance
    /// of a warning is no longer present. This indicates that the warning condition
    /// has been resolved.
    ///
    /// # Type Parameters
    /// * `T` - A type implementing [`WarningUnsetCallback`]
    ///
    /// # Arguments
    /// * `handler` - The callback function or closure that receives:
    ///   - `warning` - The [`Warning`](crate::Warning) identifier/category that was cleared
    ///
    /// # Returns
    /// The builder instance for method chaining.
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::{ContextBuilder, KernelError};
    ///
    /// let context = ContextBuilder::new()
    ///     .with_warning_unset_notification(|warning| {
    ///         println!("Warning [{}] has been cleared", warning);
    ///     })
    ///     .build()?;
    /// # Ok::<(), KernelError>(())
    /// ```
    pub fn with_warning_unset_notification<T>(mut self, handler: T) -> Self
    where
        T: WarningUnsetCallback + 'static,
    {
        self.get_or_create_notification_registry()
            .register_warning_unset(handler);
        self
    }

    /// Registers a callback for flush error notifications.
    ///
    /// The callback is invoked when an error occurs while flushing data
    /// to disk.
    ///
    /// # Type Parameters
    /// * `T` - A type implementing [`FlushErrorCallback`]
    ///
    /// # Arguments
    /// * `handler` - The callback function or closure that receives:
    ///   - `message` - The error message as a [`String`]
    ///
    /// # Returns
    /// The builder instance for method chaining.
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::{ContextBuilder, KernelError};
    ///
    /// let context = ContextBuilder::new()
    ///     .with_flush_error_notification(|message| {
    ///         eprintln!("Flush error: {}", message);
    ///     })
    ///     .build()?;
    /// # Ok::<(), KernelError>(())
    /// ```
    pub fn with_flush_error_notification<T>(mut self, handler: T) -> Self
    where
        T: FlushErrorCallback + 'static,
    {
        self.get_or_create_notification_registry()
            .register_flush_error(handler);
        self
    }

    /// Registers a callback for fatal error notifications.
    ///
    /// The callback is invoked when an unrecoverable system error is encountered
    /// by the library. These are critical errors that typically require the
    /// application to shut down gracefully.
    ///
    /// # Type Parameters
    /// * `T` - A type implementing [`FatalErrorCallback`]
    ///
    /// # Arguments
    /// * `handler` - The callback function or closure that receives:
    ///   - `message` - A description of the fatal error as a [`String`]
    ///
    /// # Returns
    /// The builder instance for method chaining.
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::{ContextBuilder, KernelError};
    ///
    /// let context = ContextBuilder::new()
    ///     .with_fatal_error_notification(|message| {
    ///         eprintln!("FATAL ERROR: {}", message);
    ///         // Perform cleanup and shutdown
    ///         std::process::exit(1);
    ///     })
    ///     .build()?;
    /// # Ok::<(), KernelError>(())
    /// ```
    pub fn with_fatal_error_notification<T>(mut self, handler: T) -> Self
    where
        T: FatalErrorCallback + 'static,
    {
        self.get_or_create_notification_registry()
            .register_fatal_error(handler);
        self
    }

    /// Configures multiple notification callbacks at once.
    ///
    /// This method provides access to the [`NotificationCallbackRegistry`]
    /// for advanced configuration of multiple callbacks.
    ///
    /// # Type Parameters
    /// * `F` - A closure taking a mutable reference to the registry
    ///
    /// # Arguments
    /// * `configure` - A closure that configures the notification registry
    ///
    /// # Returns
    /// The builder instance for method chaining.
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::{ContextBuilder, KernelError};
    ///
    /// let context = ContextBuilder::new()
    ///     .notifications(|registry| {
    ///         registry.register_progress(|title, percent, _resume| {
    ///             println!("{}: {}%", title, percent);
    ///         });
    ///         registry.register_block_tip(|_state, hash, _progress| {
    ///             println!("Tip: {}", hash);
    ///         });
    ///         registry.register_warning_set(|_warning, msg| {
    ///             eprintln!("Warning: {}", msg);
    ///         });
    ///     })
    ///     .build()?;
    /// # Ok::<(), KernelError>(())
    /// ```
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

    /// Registers a callback for block checked validation events.
    ///
    /// The callback is invoked when a new block has been fully validated.
    /// The validation state contains the result of the validation, including
    /// whether the block is valid and any rejection reasons if invalid.
    ///
    /// # Type Parameters
    /// * `T` - A type implementing [`BlockCheckedCallback`]
    ///
    /// # Arguments
    /// * `handler` - The callback function or closure that receives:
    ///   - `block` - The [`Block`](crate::Block) that was validated
    ///   - `state` - The [`BlockValidationStateRef`](crate::notifications::types::BlockValidationStateRef) containing the validation result
    ///
    /// # Returns
    /// The builder instance for method chaining.
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::{
    ///     prelude::*, Block, BlockValidationStateRef, ContextBuilder,
    ///     KernelError, ValidationMode,
    /// };
    ///
    /// let context = ContextBuilder::new()
    ///     .with_block_checked_validation(|block: Block, state: BlockValidationStateRef<'_>| {
    ///         println!("Block validated: {}", block.hash());
    ///         if state.mode() != ValidationMode::Valid {
    ///             eprintln!("Validation failed with result: {:?}", state.result());
    ///         }
    ///     })
    ///     .build()?;
    /// # Ok::<(), KernelError>(())
    /// ```
    pub fn with_block_checked_validation<T>(mut self, handler: T) -> Self
    where
        T: BlockCheckedCallback + 'static,
    {
        self.get_or_create_validation_registry()
            .register_block_checked(handler);
        self
    }

    /// Registers a callback for new proof-of-work valid block events.
    ///
    /// The callback is invoked when a new block extends the header chain and
    /// has a valid transaction and segwit merkle root.
    ///
    /// # Type Parameters
    /// * `T` - A type implementing [`NewPoWValidBlockCallback`]
    ///
    /// # Arguments
    /// * `handler` - The callback function or closure that receives:
    ///   - `entry` - The [`BlockTreeEntry`](crate::BlockTreeEntry) for the new block
    ///   - `block` - The [`Block`](crate::Block) data
    ///
    /// # Returns
    /// The builder instance for method chaining.
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::{Block, BlockTreeEntry, ContextBuilder, KernelError};
    ///
    /// let context = ContextBuilder::new()
    ///     .with_new_pow_valid_block_validation(|entry: BlockTreeEntry<'_>, block: Block| {
    ///         println!("New PoW-valid block at height {}: {}",
    ///                  entry.height(), block.hash());
    ///     })
    ///     .build()?;
    /// # Ok::<(), KernelError>(())
    /// ```
    pub fn with_new_pow_valid_block_validation<T>(mut self, handler: T) -> Self
    where
        T: NewPoWValidBlockCallback + 'static,
    {
        self.get_or_create_validation_registry()
            .register_new_pow_valid_block(handler);
        self
    }

    /// Registers a callback for block connected events.
    ///
    /// The callback is invoked when a block is valid and has now been connected
    /// to the best chain. This happens after the block passes full validation
    /// and becomes part of the active chain.
    ///
    /// # Type Parameters
    /// * `T` - A type implementing [`BlockConnectedCallback`]
    ///
    /// # Arguments
    /// * `handler` - The callback function or closure that receives:
    ///   - `block` - The [`Block`](crate::Block) that was connected
    ///   - `entry` - The [`BlockTreeEntry`](crate::BlockTreeEntry) representing the block's position in the chain
    ///
    /// # Returns
    /// The builder instance for method chaining.
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::{Block, BlockTreeEntry, ContextBuilder, KernelError};
    ///
    /// let context = ContextBuilder::new()
    ///     .with_block_connected_validation(|block: Block, entry: BlockTreeEntry<'_>| {
    ///         println!("Block connected at height {}: {}",
    ///                  entry.height(), block.hash());
    ///     })
    ///     .build()?;
    /// # Ok::<(), KernelError>(())
    /// ```
    pub fn with_block_connected_validation<T>(mut self, handler: T) -> Self
    where
        T: BlockConnectedCallback + 'static,
    {
        self.get_or_create_validation_registry()
            .register_block_connected(handler);
        self
    }

    /// Registers a callback for block disconnected events.
    ///
    /// The callback is invoked during a reorganization when a block has been
    /// removed from the best chain. This occurs when a competing chain with
    /// more cumulative work becomes the new active chain, requiring blocks
    /// from the old chain to be disconnected.
    ///
    /// # Type Parameters
    /// * `T` - A type implementing [`BlockDisconnectedCallback`]
    ///
    /// # Arguments
    /// * `handler` - The callback function or closure that receives:
    ///   - `block` - The [`Block`](crate::Block) that was disconnected
    ///   - `entry` - The [`BlockTreeEntry`](crate::BlockTreeEntry) for the disconnected block
    ///
    /// # Returns
    /// The builder instance for method chaining.
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::{Block, BlockTreeEntry, ContextBuilder, KernelError};
    ///
    /// let context = ContextBuilder::new()
    ///     .with_block_disconnected_validation(|block: Block, entry: BlockTreeEntry<'_>| {
    ///         println!("Block disconnected from height {}: {} (reorg)",
    ///                  entry.height(), block.hash());
    ///     })
    ///     .build()?;
    /// # Ok::<(), KernelError>(())
    /// ```
    pub fn with_block_disconnected_validation<T>(mut self, handler: T) -> Self
    where
        T: BlockDisconnectedCallback + 'static,
    {
        self.get_or_create_validation_registry()
            .register_block_disconnected(handler);
        self
    }

    /// Configures multiple validation callbacks at once.
    ///
    /// This method provides access to the [`ValidationCallbackRegistry`]
    /// for advanced configuration of multiple validation callbacks.
    ///
    /// # Type Parameters
    /// * `F` - A closure taking a mutable reference to the registry
    ///
    /// # Arguments
    /// * `configure` - A closure that configures the validation registry
    ///
    /// # Returns
    /// The builder instance for method chaining.
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::{Block, BlockTreeEntry, BlockValidationStateRef, ContextBuilder, KernelError};
    ///
    /// let context = ContextBuilder::new()
    ///     .validation(|registry| {
    ///         registry.register_block_checked(|block: Block, _state: BlockValidationStateRef<'_>| {
    ///             println!("Checked: {}", block.hash());
    ///         });
    ///         registry.register_block_connected(|_block, entry: BlockTreeEntry<'_>| {
    ///             println!("Connected at height {}", entry.height());
    ///         });
    ///         registry.register_block_disconnected(|_block, entry: BlockTreeEntry<'_>| {
    ///             println!("Disconnected from height {}", entry.height());
    ///         });
    ///     })
    ///     .build()?;
    /// # Ok::<(), KernelError>(())
    /// ```
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

impl Drop for ContextBuilder {
    fn drop(&mut self) {
        unsafe {
            btck_context_options_destroy(self.inner);
        }
    }
}

/// Bitcoin network chain types.
///
/// Specifies which Bitcoin network the kernel should operate on.
/// Each chain type has different consensus rules and network parameters.
///
/// # Variants
/// * [`Mainnet`](ChainType::Mainnet) - Production network with economic value
/// * [`Testnet`](ChainType::Testnet) - Test network for development and testing
/// * [`Testnet4`](ChainType::Testnet4) - Newer test network with tweaked block production
/// * [`Signet`](ChainType::Signet) - Test network with controlled, regular block production
/// * [`Regtest`](ChainType::Regtest) - Regression test network for local development
///
/// # Examples
/// ```no_run
/// use bitcoinkernel::{ChainType, ContextBuilder, KernelError};
///
/// // For production
/// let mainnet_ctx = ContextBuilder::new()
///     .chain_type(ChainType::Mainnet)
///     .build()?;
///
/// // For local testing
/// let regtest_ctx = ContextBuilder::new()
///     .chain_type(ChainType::Regtest)
///     .build()?;
/// # Ok::<(), KernelError>(())
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ChainType {
    /// Bitcoin mainnet - production network with economic value
    Mainnet = BTCK_CHAIN_TYPE_MAINNET,
    /// Bitcoin testnet3 - test network for development and testing
    Testnet = BTCK_CHAIN_TYPE_TESTNET,
    /// Bitcoin testnet4 - newer test network with tweaked block production
    Testnet4 = BTCK_CHAIN_TYPE_TESTNET_4,
    /// Bitcoin signet - test network with controlled, regular block production
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
    use crate::{BlockTreeEntry, BlockValidationStateRef};

    use super::*;

    #[test]
    fn test_chain_type_conversions() {
        let mainnet = ChainType::Mainnet;
        let btck_mainnet: btck_ChainType = mainnet.into();
        let back_to_mainnet: ChainType = btck_mainnet.into();
        assert_eq!(mainnet, back_to_mainnet);

        let testnet = ChainType::Testnet;
        let btck_testnet: btck_ChainType = testnet.into();
        let back_to_testnet: ChainType = btck_testnet.into();
        assert_eq!(testnet, back_to_testnet);

        let testnet4 = ChainType::Testnet4;
        let btck_testnet4: btck_ChainType = testnet4.into();
        let back_to_testnet4: ChainType = btck_testnet4.into();
        assert_eq!(testnet4, back_to_testnet4);

        let signet = ChainType::Signet;
        let btck_signet: btck_ChainType = signet.into();
        let back_to_signet: ChainType = btck_signet.into();
        assert_eq!(signet, back_to_signet);

        let regtest = ChainType::Regtest;
        let btck_regtest: btck_ChainType = regtest.into();
        let back_to_regtest: ChainType = btck_regtest.into();
        assert_eq!(regtest, back_to_regtest);
    }

    #[test]
    fn test_chain_type_equality() {
        assert_eq!(ChainType::Mainnet, ChainType::Mainnet);
        assert_ne!(ChainType::Mainnet, ChainType::Testnet);
        assert_ne!(ChainType::Testnet, ChainType::Testnet4);
        assert_ne!(ChainType::Signet, ChainType::Regtest);
    }

    #[test]
    fn test_chain_type_clone() {
        let mainnet = ChainType::Mainnet;
        let cloned = mainnet;
        assert_eq!(mainnet, cloned);
    }

    // ChainParams tests
    #[test]
    fn test_chain_params_creation() {
        let _mainnet_params = ChainParams::new(ChainType::Mainnet);
        let _testnet_params = ChainParams::new(ChainType::Testnet);
        let _testnet4_params = ChainParams::new(ChainType::Testnet4);
        let _signet_params = ChainParams::new(ChainType::Signet);
        let _regtest_params = ChainParams::new(ChainType::Regtest);
    }

    // Context tests
    #[test]
    fn test_context_creation_default() {
        let mut context = ContextBuilder::new().build();
        assert!(context.is_ok());
        context = Context::new();
        assert!(context.is_ok());
        context = Context::builder().build();
        assert!(context.is_ok());
    }

    #[test]
    fn test_context_creation_with_chain_types() {
        let mainnet = ContextBuilder::new().chain_type(ChainType::Mainnet).build();
        assert!(mainnet.is_ok());

        let testnet = ContextBuilder::new().chain_type(ChainType::Testnet).build();
        assert!(testnet.is_ok());

        let testnet4 = ContextBuilder::new()
            .chain_type(ChainType::Testnet4)
            .build();
        assert!(testnet4.is_ok());

        let signet = ContextBuilder::new().chain_type(ChainType::Signet).build();
        assert!(signet.is_ok());

        let regtest = ContextBuilder::new().chain_type(ChainType::Regtest).build();
        assert!(regtest.is_ok());
    }

    #[test]
    fn test_context_interrupt() {
        let context = ContextBuilder::new()
            .chain_type(ChainType::Regtest)
            .build()
            .unwrap();

        let result = context.interrupt();
        assert!(result.is_ok());
    }

    #[test]
    fn test_context_builder_default() {
        let builder1 = ContextBuilder::default();
        let builder2 = ContextBuilder::new();

        assert!(builder1.notification_registry.is_none());
        assert!(builder2.notification_registry.is_none());
        assert!(builder1.validation_registry.is_none());
        assert!(builder2.validation_registry.is_none());
    }

    // Callback tests
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
        fn pow_handler(_entry: crate::BlockTreeEntry, _block: crate::Block) {}
        fn connected_handler(_block: crate::Block, _entry: crate::BlockTreeEntry) {}
        fn disconnected_handler(_block: crate::Block, _entry: crate::BlockTreeEntry) {}

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
            .with_block_connected_validation(|_block, _block_index: BlockTreeEntry<'_>| {})
            .chain_type(ChainType::Testnet)
            .build();

        assert!(context_result.is_ok());
        let _context = context_result.unwrap();
    }
}
