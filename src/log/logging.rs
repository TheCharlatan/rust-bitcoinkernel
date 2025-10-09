use std::ffi::{c_char, c_void};

use libbitcoinkernel_sys::{
    btck_LogCategory, btck_LogLevel, btck_LoggingConnection, btck_LoggingOptions,
    btck_logging_connection_create, btck_logging_connection_destroy, btck_logging_disable,
    btck_logging_disable_category, btck_logging_enable_category, btck_logging_set_level_category,
};

use crate::{
    ffi::{
        c_helpers, BTCK_LOG_CATEGORY_ALL, BTCK_LOG_CATEGORY_BENCH, BTCK_LOG_CATEGORY_BLOCKSTORAGE,
        BTCK_LOG_CATEGORY_COINDB, BTCK_LOG_CATEGORY_KERNEL, BTCK_LOG_CATEGORY_LEVELDB,
        BTCK_LOG_CATEGORY_MEMPOOL, BTCK_LOG_CATEGORY_PRUNE, BTCK_LOG_CATEGORY_RAND,
        BTCK_LOG_CATEGORY_REINDEX, BTCK_LOG_CATEGORY_VALIDATION, BTCK_LOG_LEVEL_DEBUG,
        BTCK_LOG_LEVEL_INFO, BTCK_LOG_LEVEL_TRACE,
    },
    KernelError,
};

/// A function for handling log messages produced by the kernel library.
pub trait Log {
    fn log(&self, message: &str);
}

unsafe extern "C" fn log_callback<T: Log + 'static>(
    user_data: *mut c_void,
    message: *const c_char,
    message_len: usize,
) {
    let message = unsafe { c_helpers::to_string(message, message_len) };
    let log = user_data as *mut T;
    (*log).log(&message);
}

unsafe extern "C" fn destroy_log_callback<T>(user_data: *mut c_void) {
    if !user_data.is_null() {
        let _ = Box::from_raw(user_data as *mut T);
    }
}

/// The logger object logs kernel log messages into a user-defined log function.
/// Messages logged by the kernel before this object is created are buffered in
/// a 1MB buffer. The kernel library internally uses a global logging instance.
pub struct Logger {
    inner: *mut btck_LoggingConnection,
}

impl Drop for Logger {
    fn drop(&mut self) {
        unsafe {
            btck_logging_connection_destroy(self.inner);
        }
    }
}

/// Permanently disable logging and stop buffering.
///
/// # Warning
///
/// This should only be called once during the lifetime of the program.
pub fn disable_logging() {
    unsafe {
        btck_logging_disable();
    }
}

impl Logger {
    /// Create a new Logger with the specified callback.
    pub fn new<T: Log + 'static>(log: T) -> Result<Logger, KernelError> {
        let options = btck_LoggingOptions {
            log_timestamps: c_helpers::to_c_bool(true),
            log_time_micros: c_helpers::to_c_bool(false),
            log_threadnames: c_helpers::to_c_bool(false),
            log_sourcelocations: c_helpers::to_c_bool(false),
            always_print_category_levels: c_helpers::to_c_bool(false),
        };

        let log_ptr = Box::into_raw(Box::new(log));

        let inner = unsafe {
            btck_logging_connection_create(
                Some(log_callback::<T>),
                log_ptr as *mut c_void,
                Some(destroy_log_callback::<T>),
                options,
            )
        };

        if inner.is_null() {
            unsafe {
                let _ = Box::from_raw(log_ptr);
            }
            return Err(KernelError::Internal(
                "Failed to create new logging connection.".to_string(),
            ));
        }

        Ok(Logger { inner })
    }

    /// Sets the logging level for a specific category.
    pub fn set_level_category(&self, category: LogCategory, level: LogLevel) {
        unsafe {
            btck_logging_set_level_category(category.into(), level.into());
        }
    }

    /// Enables logging for a specific category.
    pub fn enable_category(&self, category: LogCategory) {
        unsafe {
            btck_logging_enable_category(category.into());
        }
    }

    /// Disables logging for a specific category.
    pub fn disable_category(&self, category: LogCategory) {
        unsafe {
            btck_logging_disable_category(category.into());
        }
    }
}

/// Logging categories for Bitcoin Kernel messages.
///
/// Controls which types of log messages are emitted by the kernel library.
/// Categories can be combined to enable multiple types of logging simultaneously.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LogCategory {
    /// All logging categories enabled
    All = BTCK_LOG_CATEGORY_ALL,
    /// Benchmark and performance logging
    Bench = BTCK_LOG_CATEGORY_BENCH,
    /// Block storage operations
    BlockStorage = BTCK_LOG_CATEGORY_BLOCKSTORAGE,
    /// Coin database operations
    CoinDb = BTCK_LOG_CATEGORY_COINDB,
    /// LevelDB operations
    LevelDb = BTCK_LOG_CATEGORY_LEVELDB,
    /// Memory pool operations
    Mempool = BTCK_LOG_CATEGORY_MEMPOOL,
    /// Block pruning operations
    Prune = BTCK_LOG_CATEGORY_PRUNE,
    /// Random number generation
    Rand = BTCK_LOG_CATEGORY_RAND,
    /// Block reindexing operations
    Reindex = BTCK_LOG_CATEGORY_REINDEX,
    /// Block and transaction validation
    Validation = BTCK_LOG_CATEGORY_VALIDATION,
    /// Kernel-specific operations
    Kernel = BTCK_LOG_CATEGORY_KERNEL,
}

impl From<LogCategory> for btck_LogCategory {
    fn from(category: LogCategory) -> Self {
        category as btck_LogCategory
    }
}

impl From<btck_LogCategory> for LogCategory {
    fn from(value: btck_LogCategory) -> Self {
        match value {
            BTCK_LOG_CATEGORY_ALL => LogCategory::All,
            BTCK_LOG_CATEGORY_BENCH => LogCategory::Bench,
            BTCK_LOG_CATEGORY_BLOCKSTORAGE => LogCategory::BlockStorage,
            BTCK_LOG_CATEGORY_COINDB => LogCategory::CoinDb,
            BTCK_LOG_CATEGORY_LEVELDB => LogCategory::LevelDb,
            BTCK_LOG_CATEGORY_MEMPOOL => LogCategory::Mempool,
            BTCK_LOG_CATEGORY_PRUNE => LogCategory::Prune,
            BTCK_LOG_CATEGORY_RAND => LogCategory::Rand,
            BTCK_LOG_CATEGORY_REINDEX => LogCategory::Reindex,
            BTCK_LOG_CATEGORY_VALIDATION => LogCategory::Validation,
            BTCK_LOG_CATEGORY_KERNEL => LogCategory::Kernel,
            _ => panic!("Unknown log category: {}", value),
        }
    }
}

/// Logging levels for controlling message verbosity.
///
/// Determines the minimum severity level of messages that will be logged.
/// Higher levels include all messages from lower levels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LogLevel {
    /// Detailed trace information for debugging
    Trace = BTCK_LOG_LEVEL_TRACE,
    /// Debug information for development
    Debug = BTCK_LOG_LEVEL_DEBUG,
    /// General informational messages
    Info = BTCK_LOG_LEVEL_INFO,
}

impl From<LogLevel> for btck_LogLevel {
    fn from(level: LogLevel) -> Self {
        level as btck_LogLevel
    }
}

impl From<btck_LogLevel> for LogLevel {
    fn from(value: btck_LogLevel) -> Self {
        match value {
            BTCK_LOG_LEVEL_TRACE => LogLevel::Trace,
            BTCK_LOG_LEVEL_DEBUG => LogLevel::Debug,
            BTCK_LOG_LEVEL_INFO => LogLevel::Info,
            _ => panic!("Unknown log level: {}", value),
        }
    }
}
