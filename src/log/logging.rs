use std::ffi::{c_char, c_void};

use libbitcoinkernel_sys::{
    btck_LogCategory, btck_LogLevel, btck_LoggingConnection, btck_LoggingOptions,
    btck_logging_connection_create, btck_logging_connection_destroy, btck_logging_disable,
    btck_logging_disable_category, btck_logging_enable_category, btck_logging_set_level_category,
    btck_logging_set_options,
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

/// Set global logging options.
///
/// This changes global settings and will override settings for all existing
/// Logger instances.
pub fn set_logging_options(options: LoggingOptions) {
    let c_options = btck_LoggingOptions {
        log_timestamps: c_helpers::to_c_bool(options.log_timestamps),
        log_time_micros: c_helpers::to_c_bool(options.log_time_micros),
        log_threadnames: c_helpers::to_c_bool(options.log_threadnames),
        log_sourcelocations: c_helpers::to_c_bool(options.log_sourcelocations),
        always_print_category_levels: c_helpers::to_c_bool(options.always_print_category_levels),
    };

    unsafe {
        btck_logging_set_options(c_options);
    }
}

/// Options controlling the format of log messages.
#[derive(Debug, Clone, Copy)]
pub struct LoggingOptions {
    /// Prepend a timestamp to log messages.
    pub log_timestamps: bool,
    /// Log timestamps in microsecond precision.
    pub log_time_micros: bool,
    /// Prepend the name of the thread to log messages.
    pub log_threadnames: bool,
    /// Prepend the source location to log messages.
    pub log_sourcelocations: bool,
    /// Always print category and log level.
    pub always_print_category_levels: bool,
}

impl Default for LoggingOptions {
    fn default() -> Self {
        Self {
            log_timestamps: true,
            log_time_micros: false,
            log_threadnames: false,
            log_sourcelocations: false,
            always_print_category_levels: false,
        }
    }
}

impl Logger {
    /// Create a new Logger with the specified callback.
    ///
    /// Note: Logging options should be set using the global `set_logging_options`
    /// function before or after creating the Logger.
    pub fn new<T: Log + 'static>(log: T) -> Result<Logger, KernelError> {
        let log_ptr = Box::into_raw(Box::new(log));

        let inner = unsafe {
            btck_logging_connection_create(
                Some(log_callback::<T>),
                log_ptr as *mut c_void,
                Some(destroy_log_callback::<T>),
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

    /// Create a new Logger with the specified callback and options.
    ///
    /// This is a convenience method that sets the global logging options
    /// and then creates the Logger.
    pub fn new_with_options<T: Log + 'static>(
        log: T,
        options: LoggingOptions,
    ) -> Result<Logger, KernelError> {
        set_logging_options(options);
        Self::new(log)
    }

    /// Sets the logging level for a specific category.
    ///
    /// This changes a global setting and will override settings for all existing
    /// Logger instances.
    pub fn set_level_category(&self, category: LogCategory, level: LogLevel) {
        unsafe {
            btck_logging_set_level_category(category.into(), level.into());
        }
    }

    /// Enables logging for a specific category.
    ///
    /// This changes a global setting and will override settings for all existing
    /// Logger instances.
    pub fn enable_category(&self, category: LogCategory) {
        unsafe {
            btck_logging_enable_category(category.into());
        }
    }

    /// Disables logging for a specific category.
    ///
    /// This changes a global setting and will override settings for all existing
    /// Logger instances.
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

#[cfg(test)]
mod tests {
    use super::*;

    // LogCategory tests
    #[test]
    fn test_log_category_conversions() {
        let all = LogCategory::All;
        let btck_all: btck_LogCategory = all.into();
        let back_to_all: LogCategory = btck_all.into();
        assert_eq!(all, back_to_all);

        let bench = LogCategory::Bench;
        let btck_bench: btck_LogCategory = bench.into();
        let back_to_bench: LogCategory = btck_bench.into();
        assert_eq!(bench, back_to_bench);

        let block_storage = LogCategory::BlockStorage;
        let btck_block_storage: btck_LogCategory = block_storage.into();
        let back_to_block_storage: LogCategory = btck_block_storage.into();
        assert_eq!(block_storage, back_to_block_storage);

        let coin_db = LogCategory::CoinDb;
        let btck_coin_db: btck_LogCategory = coin_db.into();
        let back_to_coin_db: LogCategory = btck_coin_db.into();
        assert_eq!(coin_db, back_to_coin_db);

        let level_db = LogCategory::LevelDb;
        let btck_level_db: btck_LogCategory = level_db.into();
        let back_to_level_db: LogCategory = btck_level_db.into();
        assert_eq!(level_db, back_to_level_db);

        let mempool = LogCategory::Mempool;
        let btck_mempool: btck_LogCategory = mempool.into();
        let back_to_mempool: LogCategory = btck_mempool.into();
        assert_eq!(mempool, back_to_mempool);

        let prune = LogCategory::Prune;
        let btck_prune: btck_LogCategory = prune.into();
        let back_to_prune: LogCategory = btck_prune.into();
        assert_eq!(prune, back_to_prune);

        let rand = LogCategory::Rand;
        let btck_rand: btck_LogCategory = rand.into();
        let back_to_rand: LogCategory = btck_rand.into();
        assert_eq!(rand, back_to_rand);

        let reindex = LogCategory::Reindex;
        let btck_reindex: btck_LogCategory = reindex.into();
        let back_to_reindex: LogCategory = btck_reindex.into();
        assert_eq!(reindex, back_to_reindex);

        let validation = LogCategory::Validation;
        let btck_validation: btck_LogCategory = validation.into();
        let back_to_validation: LogCategory = btck_validation.into();
        assert_eq!(validation, back_to_validation);

        let kernel = LogCategory::Kernel;
        let btck_kernel: btck_LogCategory = kernel.into();
        let back_to_kernel: LogCategory = btck_kernel.into();
        assert_eq!(kernel, back_to_kernel);
    }

    #[test]
    fn test_log_category_equality() {
        assert_eq!(LogCategory::All, LogCategory::All);
        assert_ne!(LogCategory::All, LogCategory::Bench);
        assert_ne!(LogCategory::Validation, LogCategory::Kernel);
    }

    #[test]
    fn test_log_category_clone() {
        let validation = LogCategory::Validation;
        let cloned = validation;
        assert_eq!(validation, cloned);
    }

    // LogLevel tests
    #[test]
    fn test_log_level_conversions() {
        let trace = LogLevel::Trace;
        let btck_trace: btck_LogLevel = trace.into();
        let back_to_trace: LogLevel = btck_trace.into();
        assert_eq!(trace, back_to_trace);

        let debug = LogLevel::Debug;
        let btck_debug: btck_LogLevel = debug.into();
        let back_to_debug: LogLevel = btck_debug.into();
        assert_eq!(debug, back_to_debug);

        let info = LogLevel::Info;
        let btck_info: btck_LogLevel = info.into();
        let back_to_info: LogLevel = btck_info.into();
        assert_eq!(info, back_to_info);
    }

    #[test]
    fn test_log_level_equality() {
        assert_eq!(LogLevel::Info, LogLevel::Info);
        assert_ne!(LogLevel::Info, LogLevel::Debug);
        assert_ne!(LogLevel::Debug, LogLevel::Trace);
    }

    #[test]
    fn test_log_level_clone() {
        let info = LogLevel::Info;
        let cloned = info;
        assert_eq!(info, cloned);
    }

    #[test]
    fn test_logging_options_default() {
        let options = LoggingOptions::default();
        assert!(options.log_timestamps);
        assert!(!options.log_time_micros);
        assert!(!options.log_threadnames);
        assert!(!options.log_sourcelocations);
        assert!(!options.always_print_category_levels);
    }

    // Logger tests
    struct TestLog {
        messages: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl Log for TestLog {
        fn log(&self, message: &str) {
            self.messages.lock().unwrap().push(message.to_string());
        }
    }

    #[test]
    fn test_logger_creation() {
        let messages = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let test_log = TestLog {
            messages: messages.clone(),
        };

        let _logger = Logger::new(test_log);
        assert!(_logger.is_ok());
    }

    #[test]
    fn test_logger_creation_with_options() {
        let messages = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let test_log = TestLog {
            messages: messages.clone(),
        };

        let options = LoggingOptions {
            log_timestamps: true,
            log_time_micros: true,
            log_threadnames: true,
            log_sourcelocations: false,
            always_print_category_levels: true,
        };

        let _logger = Logger::new_with_options(test_log, options);
        assert!(_logger.is_ok());
    }

    #[test]
    fn test_logger_set_level_category() {
        let messages = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let test_log = TestLog {
            messages: messages.clone(),
        };

        let logger = Logger::new(test_log).unwrap();
        logger.set_level_category(LogCategory::Validation, LogLevel::Debug);
        logger.set_level_category(LogCategory::Kernel, LogLevel::Info);
    }

    #[test]
    fn test_logger_enable_category() {
        let messages = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let test_log = TestLog {
            messages: messages.clone(),
        };

        let logger = Logger::new(test_log).unwrap();
        logger.enable_category(LogCategory::Validation);
        logger.enable_category(LogCategory::Kernel);
    }

    #[test]
    fn test_logger_disable_category() {
        let messages = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let test_log = TestLog {
            messages: messages.clone(),
        };

        let logger = Logger::new(test_log).unwrap();
        logger.disable_category(LogCategory::Validation);
        logger.disable_category(LogCategory::Kernel);
    }

    #[test]
    fn test_all_log_categories() {
        let categories = [
            LogCategory::All,
            LogCategory::Bench,
            LogCategory::BlockStorage,
            LogCategory::CoinDb,
            LogCategory::LevelDb,
            LogCategory::Mempool,
            LogCategory::Prune,
            LogCategory::Rand,
            LogCategory::Reindex,
            LogCategory::Validation,
            LogCategory::Kernel,
        ];

        let messages = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let test_log = TestLog {
            messages: messages.clone(),
        };

        let logger = Logger::new(test_log).unwrap();

        for category in categories {
            logger.enable_category(category);
            logger.set_level_category(category, LogLevel::Debug);
        }
    }

    #[test]
    fn test_all_log_levels() {
        let levels = [LogLevel::Trace, LogLevel::Debug, LogLevel::Info];

        let messages = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let test_log = TestLog {
            messages: messages.clone(),
        };

        let logger = Logger::new(test_log).unwrap();

        for level in levels {
            logger.set_level_category(LogCategory::Validation, level);
        }
    }

    #[test]
    fn test_global_set_logging_options() {
        let options = LoggingOptions {
            log_timestamps: false,
            log_time_micros: true,
            log_threadnames: true,
            log_sourcelocations: true,
            always_print_category_levels: false,
        };

        set_logging_options(options);
    }
}
