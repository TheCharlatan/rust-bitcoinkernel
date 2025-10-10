use std::ffi::{c_char, c_void};

use libbitcoinkernel_sys::{
    btck_BlockTreeEntry, btck_SynchronizationState, btck_Warning,
    btck_block_tree_entry_get_block_hash,
};

use crate::{
    ffi::{c_helpers, sealed::FromMutPtr},
    BlockHash,
};

use super::{SynchronizationState, Warning};

/// The chain's tip was updated to the provided block hash.
pub trait BlockTipCallback: Send + Sync {
    fn on_block_tip(
        &self,
        state: SynchronizationState,
        hash: BlockHash,
        verification_progress: f64,
    );
}

/// A new best block header was added.
pub trait HeaderTipCallback: Send + Sync {
    fn on_header_tip(
        &self,
        state: SynchronizationState,
        height: i64,
        timestamp: i64,
        presync: bool,
    );
}

/// Reports on the current synchronization progress.
pub trait ProgressCallback: Send + Sync {
    fn on_progress(&self, title: String, percent: i32, resume_possible: bool);
}

/// A warning state issued by the kernel during validation.
pub trait WarningSetCallback: Send + Sync {
    fn on_warning_set(&self, warning: Warning, message: String);
}

/// A previous condition leading to the issuance of a warning is no longer given.
pub trait WarningUnsetCallback: Send + Sync {
    fn on_warning_unset(&self, warning: Warning);
}

/// An error was encountered when flushing data to disk.
pub trait FlushErrorCallback: Send + Sync {
    fn on_flush_error(&self, message: String);
}

/// An un-recoverable system error was encountered by the library.
pub trait FatalErrorCallback: Send + Sync {
    fn on_fatal_error(&self, message: String);
}

impl<F> BlockTipCallback for F
where
    F: Fn(SynchronizationState, BlockHash, f64) + Send + Sync + 'static,
{
    fn on_block_tip(&self, state: SynchronizationState, hash: BlockHash, progress: f64) {
        self(state, hash, progress)
    }
}

impl<F> HeaderTipCallback for F
where
    F: Fn(SynchronizationState, i64, i64, bool) + Send + Sync + 'static,
{
    fn on_header_tip(
        &self,
        state: SynchronizationState,
        height: i64,
        timestamp: i64,
        presync: bool,
    ) {
        self(state, height, timestamp, presync)
    }
}

impl<F> ProgressCallback for F
where
    F: Fn(String, i32, bool) + Send + Sync + 'static,
{
    fn on_progress(&self, title: String, percent: i32, resume_possible: bool) {
        self(title, percent, resume_possible)
    }
}

impl<F> WarningSetCallback for F
where
    F: Fn(Warning, String) + Send + Sync + 'static,
{
    fn on_warning_set(&self, warning: Warning, message: String) {
        self(warning, message)
    }
}

impl<F> WarningUnsetCallback for F
where
    F: Fn(Warning) + Send + Sync + 'static,
{
    fn on_warning_unset(&self, warning: Warning) {
        self(warning)
    }
}

impl<F> FlushErrorCallback for F
where
    F: Fn(String) + Send + Sync + 'static,
{
    fn on_flush_error(&self, message: String) {
        self(message)
    }
}

impl<F> FatalErrorCallback for F
where
    F: Fn(String) + Send + Sync + 'static,
{
    fn on_fatal_error(&self, message: String) {
        self(message)
    }
}

/// Registry for managing notification interface callback handlers.
#[derive(Default)]
pub struct NotificationCallbackRegistry {
    block_tip_handler: Option<Box<dyn BlockTipCallback>>,
    header_tip_handler: Option<Box<dyn HeaderTipCallback>>,
    progress_handler: Option<Box<dyn ProgressCallback>>,
    warning_set_handler: Option<Box<dyn WarningSetCallback>>,
    warning_unset_handler: Option<Box<dyn WarningUnsetCallback>>,
    flush_error_handler: Option<Box<dyn FlushErrorCallback>>,
    fatal_error_handler: Option<Box<dyn FatalErrorCallback>>,
}

impl NotificationCallbackRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_block_tip<T>(&mut self, handler: T) -> &mut Self
    where
        T: BlockTipCallback + 'static,
    {
        self.block_tip_handler = Some(Box::new(handler) as Box<dyn BlockTipCallback>);
        self
    }

    pub fn register_header_tip<T>(&mut self, handler: T) -> &mut Self
    where
        T: HeaderTipCallback + 'static,
    {
        self.header_tip_handler = Some(Box::new(handler) as Box<dyn HeaderTipCallback>);
        self
    }

    pub fn register_progress<T>(&mut self, handler: T) -> &mut Self
    where
        T: ProgressCallback + 'static,
    {
        self.progress_handler = Some(Box::new(handler) as Box<dyn ProgressCallback>);
        self
    }

    pub fn register_warning_set<T>(&mut self, handler: T) -> &mut Self
    where
        T: WarningSetCallback + 'static,
    {
        self.warning_set_handler = Some(Box::new(handler) as Box<dyn WarningSetCallback>);
        self
    }

    pub fn register_warning_unset<T>(&mut self, handler: T) -> &mut Self
    where
        T: WarningUnsetCallback + 'static,
    {
        self.warning_unset_handler = Some(Box::new(handler) as Box<dyn WarningUnsetCallback>);
        self
    }

    pub fn register_flush_error<T>(&mut self, handler: T) -> &mut Self
    where
        T: FlushErrorCallback + 'static,
    {
        self.flush_error_handler = Some(Box::new(handler) as Box<dyn FlushErrorCallback>);
        self
    }

    pub fn register_fatal_error<T>(&mut self, handler: T) -> &mut Self
    where
        T: FatalErrorCallback + 'static,
    {
        self.fatal_error_handler = Some(Box::new(handler) as Box<dyn FatalErrorCallback>);
        self
    }
}

pub(crate) unsafe extern "C" fn notification_user_data_destroy_wrapper(user_data: *mut c_void) {
    if !user_data.is_null() {
        let _ = Box::from_raw(user_data as *mut NotificationCallbackRegistry);
    }
}

pub(crate) unsafe extern "C" fn notification_block_tip_wrapper(
    user_data: *mut c_void,
    state: btck_SynchronizationState,
    entry: *const btck_BlockTreeEntry,
    verification_progress: f64,
) {
    let registry = &*(user_data as *mut NotificationCallbackRegistry);

    if let Some(ref handler) = registry.block_tip_handler {
        let hash_ptr = btck_block_tree_entry_get_block_hash(entry);
        let block_hash = BlockHash::from_ptr(hash_ptr);
        handler.on_block_tip(state.into(), block_hash, verification_progress);
    }
}

pub(crate) unsafe extern "C" fn notification_header_tip_wrapper(
    user_data: *mut c_void,
    state: btck_SynchronizationState,
    height: i64,
    timestamp: i64,
    presync: i32,
) {
    let registry = &*(user_data as *mut NotificationCallbackRegistry);

    if let Some(ref handler) = registry.header_tip_handler {
        handler.on_header_tip(state.into(), height, timestamp, c_helpers::enabled(presync));
    }
}

pub(crate) unsafe extern "C" fn notification_progress_wrapper(
    user_data: *mut c_void,
    title: *const c_char,
    title_len: usize,
    progress_percent: i32,
    resume_possible: i32,
) {
    let registry = &*(user_data as *mut NotificationCallbackRegistry);

    if let Some(ref handler) = registry.progress_handler {
        handler.on_progress(
            c_helpers::to_string(title, title_len),
            progress_percent,
            c_helpers::enabled(resume_possible),
        );
    }
}

pub(crate) unsafe extern "C" fn notification_warning_set_wrapper(
    user_data: *mut c_void,
    warning: btck_Warning,
    message: *const c_char,
    message_len: usize,
) {
    let registry = &*(user_data as *mut NotificationCallbackRegistry);
    if let Some(ref handler) = registry.warning_set_handler {
        handler.on_warning_set(warning.into(), c_helpers::to_string(message, message_len));
    }
}

pub(crate) unsafe extern "C" fn notification_warning_unset_wrapper(
    user_data: *mut c_void,
    warning: btck_Warning,
) {
    let registry = &*(user_data as *mut NotificationCallbackRegistry);
    if let Some(ref handler) = registry.warning_unset_handler {
        handler.on_warning_unset(warning.into());
    }
}

pub(crate) unsafe extern "C" fn notification_flush_error_wrapper(
    user_data: *mut c_void,
    message: *const c_char,
    message_len: usize,
) {
    let registry = &*(user_data as *mut NotificationCallbackRegistry);
    if let Some(ref handler) = registry.flush_error_handler {
        handler.on_flush_error(c_helpers::to_string(message, message_len));
    }
}

pub(crate) unsafe extern "C" fn notification_fatal_error_wrapper(
    user_data: *mut c_void,
    message: *const c_char,
    message_len: usize,
) {
    let registry = &*(user_data as *mut NotificationCallbackRegistry);
    if let Some(ref handler) = registry.fatal_error_handler {
        handler.on_fatal_error(c_helpers::to_string(message, message_len));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[test]
    fn test_registry_default() {
        let registry = NotificationCallbackRegistry::default();
        assert!(registry.block_tip_handler.is_none());
        assert!(registry.header_tip_handler.is_none());
        assert!(registry.progress_handler.is_none());
        assert!(registry.warning_set_handler.is_none());
        assert!(registry.warning_unset_handler.is_none());
        assert!(registry.flush_error_handler.is_none());
        assert!(registry.fatal_error_handler.is_none());
    }

    #[test]
    fn test_registry_stores_single_handler() {
        let mut registry = NotificationCallbackRegistry::new();

        registry.register_block_tip(|_state, _hash, progress| {
            assert_eq!(progress, 50_f64);
        });

        registry.register_header_tip(|_state, height, _timestamp, _presync| {
            assert_eq!(height, 100);
        });

        registry.register_progress(|_title, percent, _resume| {
            assert_eq!(percent, 50);
        });

        registry.register_warning_set(|warning, _message| {
            let _ = warning;
        });

        registry.register_warning_unset(|warning| {
            let _ = warning;
        });

        registry.register_flush_error(|message: String| {
            assert!(message.contains("test"));
        });

        registry.register_fatal_error(|message: String| {
            assert!(message.contains("fatal"));
        });

        assert!(registry.progress_handler.is_some());
        assert!(registry.block_tip_handler.is_some());
        assert!(registry.header_tip_handler.is_some());
        assert!(registry.warning_set_handler.is_some());
        assert!(registry.warning_unset_handler.is_some());
        assert!(registry.flush_error_handler.is_some());
        assert!(registry.fatal_error_handler.is_some());
    }

    #[test]
    fn test_closure_trait_implementation() {
        let handler = |_state, _hash, _progress| {};
        let _: Box<dyn BlockTipCallback> = Box::new(handler);

        let header_tip_handler = |_state, _height, _timestamp, _presync| {};
        let _: Box<dyn HeaderTipCallback> = Box::new(header_tip_handler);

        let progress_handler = |_title, _percent, _resume_possible| {};
        let _: Box<dyn ProgressCallback> = Box::new(progress_handler);

        let warning_set_handler = |_warning, _message| {};
        let _: Box<dyn WarningSetCallback> = Box::new(warning_set_handler);

        let warning_unset_handler = |_warning| {};
        let _: Box<dyn WarningUnsetCallback> = Box::new(warning_unset_handler);

        let flush_error_handler = |_message| {};
        let _: Box<dyn FlushErrorCallback> = Box::new(flush_error_handler);

        let fatal_error_handler = |_message| {};
        let _: Box<dyn FatalErrorCallback> = Box::new(fatal_error_handler);
    }

    #[test]
    fn test_block_tip_callback_invocation() {
        let called = Arc::new(Mutex::new(false));
        let progress_captured = Arc::new(Mutex::new(0.0f64));
        let called_clone = called.clone();
        let progress_clone = progress_captured.clone();

        let mut registry = NotificationCallbackRegistry::new();
        registry.register_block_tip(move |_state, _hash, progress| {
            *called_clone.lock().unwrap() = true;
            *progress_clone.lock().unwrap() = progress;
        });

        if let Some(ref handler) = registry.block_tip_handler {
            let hash = BlockHash::from([1u8; 32]);
            handler.on_block_tip(SynchronizationState::PostInit, hash, 0.75);
        }

        assert!(*called.lock().unwrap());
        assert_eq!(*progress_captured.lock().unwrap(), 0.75);
    }

    #[test]
    fn test_header_tip_callback_invocation() {
        let called = Arc::new(Mutex::new(false));
        let height_captured = Arc::new(Mutex::new(0i64));
        let timestamp_captured = Arc::new(Mutex::new(0i64));
        let presync_captured = Arc::new(Mutex::new(false));

        let called_clone = called.clone();
        let height_clone = height_captured.clone();
        let timestamp_clone = timestamp_captured.clone();
        let presync_clone = presync_captured.clone();

        let mut registry = NotificationCallbackRegistry::new();
        registry.register_header_tip(move |_state, height, timestamp, presync| {
            *called_clone.lock().unwrap() = true;
            *height_clone.lock().unwrap() = height;
            *timestamp_clone.lock().unwrap() = timestamp;
            *presync_clone.lock().unwrap() = presync;
        });

        if let Some(ref handler) = registry.header_tip_handler {
            handler.on_header_tip(SynchronizationState::InitDownload, 12345, 1234567890, true);
        }

        assert!(*called.lock().unwrap());
        assert_eq!(*height_captured.lock().unwrap(), 12345);
        assert_eq!(*timestamp_captured.lock().unwrap(), 1234567890);
        assert!(*presync_captured.lock().unwrap());
    }

    #[test]
    fn test_progress_callback_invocation() {
        let called = Arc::new(Mutex::new(false));
        let title_captured = Arc::new(Mutex::new(String::new()));
        let percent_captured = Arc::new(Mutex::new(0i32));
        let resume_captured = Arc::new(Mutex::new(false));

        let called_clone = called.clone();
        let title_clone = title_captured.clone();
        let percent_clone = percent_captured.clone();
        let resume_clone = resume_captured.clone();

        let mut registry = NotificationCallbackRegistry::new();
        registry.register_progress(move |title, percent, resume| {
            *called_clone.lock().unwrap() = true;
            *title_clone.lock().unwrap() = title;
            *percent_clone.lock().unwrap() = percent;
            *resume_clone.lock().unwrap() = resume;
        });

        if let Some(ref handler) = registry.progress_handler {
            handler.on_progress("Syncing".to_string(), 75, true);
        }

        assert!(*called.lock().unwrap());
        assert_eq!(*title_captured.lock().unwrap(), "Syncing");
        assert_eq!(*percent_captured.lock().unwrap(), 75);
        assert!(*resume_captured.lock().unwrap());
    }

    #[test]
    fn test_warning_set_callback_invocation() {
        let called = Arc::new(Mutex::new(false));
        let message_captured = Arc::new(Mutex::new(String::new()));

        let called_clone = called.clone();
        let message_clone = message_captured.clone();

        let mut registry = NotificationCallbackRegistry::new();
        registry.register_warning_set(move |_warning, message| {
            *called_clone.lock().unwrap() = true;
            *message_clone.lock().unwrap() = message;
        });

        if let Some(ref handler) = registry.warning_set_handler {
            handler.on_warning_set(Warning::LargeWorkInvalidChain, "Test warning".to_string());
        }

        assert!(*called.lock().unwrap());
        assert_eq!(*message_captured.lock().unwrap(), "Test warning");
    }

    #[test]
    fn test_warning_unset_callback_invocation() {
        let called = Arc::new(Mutex::new(false));
        let warning_captured = Arc::new(Mutex::new(None));

        let called_clone = called.clone();
        let warning_clone = warning_captured.clone();

        let mut registry = NotificationCallbackRegistry::new();
        registry.register_warning_unset(move |warning| {
            *called_clone.lock().unwrap() = true;
            *warning_clone.lock().unwrap() = Some(warning);
        });

        if let Some(ref handler) = registry.warning_unset_handler {
            handler.on_warning_unset(Warning::UnknownNewRulesActivated);
        }

        assert!(*called.lock().unwrap());
        assert!(matches!(
            *warning_captured.lock().unwrap(),
            Some(Warning::UnknownNewRulesActivated)
        ));
    }

    #[test]
    fn test_flush_error_callback_invocation() {
        let called = Arc::new(Mutex::new(false));
        let message_captured = Arc::new(Mutex::new(String::new()));

        let called_clone = called.clone();
        let message_clone = message_captured.clone();

        let mut registry = NotificationCallbackRegistry::new();
        registry.register_flush_error(move |message| {
            *called_clone.lock().unwrap() = true;
            *message_clone.lock().unwrap() = message;
        });

        if let Some(ref handler) = registry.flush_error_handler {
            handler.on_flush_error("Disk error".to_string());
        }

        assert!(*called.lock().unwrap());
        assert_eq!(*message_captured.lock().unwrap(), "Disk error");
    }

    #[test]
    fn test_fatal_error_callback_invocation() {
        let called = Arc::new(Mutex::new(false));
        let message_captured = Arc::new(Mutex::new(String::new()));

        let called_clone = called.clone();
        let message_clone = message_captured.clone();

        let mut registry = NotificationCallbackRegistry::new();
        registry.register_fatal_error(move |message| {
            *called_clone.lock().unwrap() = true;
            *message_clone.lock().unwrap() = message;
        });

        if let Some(ref handler) = registry.fatal_error_handler {
            handler.on_fatal_error("Critical failure".to_string());
        }

        assert!(*called.lock().unwrap());
        assert_eq!(*message_captured.lock().unwrap(), "Critical failure");
    }
}
