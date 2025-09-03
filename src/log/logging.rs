// Copyright (c) 2023-present The Bitcoin Kernel developers
// Licensed under the MIT License. See LICENSE file in the project root.

use std::ffi::{c_char, c_void};

use libbitcoinkernel_sys::{
    btck_LogCategory, btck_LogLevel, btck_LoggingConnection, btck_LoggingOptions,
    btck_logging_connection_create, btck_logging_connection_destroy, btck_logging_disable,
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
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone)]
    struct TestLogger {
        messages: Arc<Mutex<Vec<String>>>,
    }

    impl TestLogger {
        fn new() -> Self {
            Self {
                messages: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn get_messages(&self) -> Vec<String> {
            self.messages.lock().unwrap().clone()
        }

        fn clear(&self) {
            self.messages.lock().unwrap().clear();
        }
    }

    impl Log for TestLogger {
        fn log(&self, message: &str) {
            self.messages.lock().unwrap().push(message.to_string());
        }
    }

    struct SimpleLogger;
    impl Log for SimpleLogger {
        fn log(&self, _message: &str) {}
    }

    #[test]
    fn test_log_category_from() {
        assert_eq!(
            btck_LogCategory::from(LogCategory::All),
            BTCK_LOG_CATEGORY_ALL
        );
        assert_eq!(
            btck_LogCategory::from(LogCategory::Bench),
            BTCK_LOG_CATEGORY_BENCH
        );
        assert_eq!(
            btck_LogCategory::from(LogCategory::BlockStorage),
            BTCK_LOG_CATEGORY_BLOCKSTORAGE
        );
        assert_eq!(
            btck_LogCategory::from(LogCategory::CoinDb),
            BTCK_LOG_CATEGORY_COINDB
        );
        assert_eq!(
            btck_LogCategory::from(LogCategory::LevelDb),
            BTCK_LOG_CATEGORY_LEVELDB
        );
        assert_eq!(
            btck_LogCategory::from(LogCategory::Mempool),
            BTCK_LOG_CATEGORY_MEMPOOL
        );
        assert_eq!(
            btck_LogCategory::from(LogCategory::Prune),
            BTCK_LOG_CATEGORY_PRUNE
        );
        assert_eq!(
            btck_LogCategory::from(LogCategory::Rand),
            BTCK_LOG_CATEGORY_RAND
        );
        assert_eq!(
            btck_LogCategory::from(LogCategory::Reindex),
            BTCK_LOG_CATEGORY_REINDEX
        );
        assert_eq!(
            btck_LogCategory::from(LogCategory::Validation),
            BTCK_LOG_CATEGORY_VALIDATION
        );
        assert_eq!(
            btck_LogCategory::from(LogCategory::Kernel),
            BTCK_LOG_CATEGORY_KERNEL
        );
    }

    #[test]
    fn test_log_category_from_reverse() {
        assert_eq!(LogCategory::from(BTCK_LOG_CATEGORY_ALL), LogCategory::All);
        assert_eq!(
            LogCategory::from(BTCK_LOG_CATEGORY_BENCH),
            LogCategory::Bench
        );
        assert_eq!(
            LogCategory::from(BTCK_LOG_CATEGORY_BLOCKSTORAGE),
            LogCategory::BlockStorage
        );
        assert_eq!(
            LogCategory::from(BTCK_LOG_CATEGORY_COINDB),
            LogCategory::CoinDb
        );
        assert_eq!(
            LogCategory::from(BTCK_LOG_CATEGORY_LEVELDB),
            LogCategory::LevelDb
        );
        assert_eq!(
            LogCategory::from(BTCK_LOG_CATEGORY_MEMPOOL),
            LogCategory::Mempool
        );
        assert_eq!(
            LogCategory::from(BTCK_LOG_CATEGORY_PRUNE),
            LogCategory::Prune
        );
        assert_eq!(LogCategory::from(BTCK_LOG_CATEGORY_RAND), LogCategory::Rand);
        assert_eq!(
            LogCategory::from(BTCK_LOG_CATEGORY_REINDEX),
            LogCategory::Reindex
        );
        assert_eq!(
            LogCategory::from(BTCK_LOG_CATEGORY_VALIDATION),
            LogCategory::Validation
        );
        assert_eq!(
            LogCategory::from(BTCK_LOG_CATEGORY_KERNEL),
            LogCategory::Kernel
        );
    }

    #[test]
    fn test_log_level_from() {
        assert_eq!(btck_LogLevel::from(LogLevel::Trace), BTCK_LOG_LEVEL_TRACE);
        assert_eq!(btck_LogLevel::from(LogLevel::Debug), BTCK_LOG_LEVEL_DEBUG);
        assert_eq!(btck_LogLevel::from(LogLevel::Info), BTCK_LOG_LEVEL_INFO);
    }

    #[test]
    fn test_log_level_from_reverse() {
        assert_eq!(LogLevel::from(BTCK_LOG_LEVEL_TRACE), LogLevel::Trace);
        assert_eq!(LogLevel::from(BTCK_LOG_LEVEL_DEBUG), LogLevel::Debug);
        assert_eq!(LogLevel::from(BTCK_LOG_LEVEL_INFO), LogLevel::Info);
    }

    #[test]
    fn test_log_category_debug() {
        assert_eq!(format!("{:?}", LogCategory::All), "All");
        assert_eq!(format!("{:?}", LogCategory::Bench), "Bench");
        assert_eq!(format!("{:?}", LogCategory::BlockStorage), "BlockStorage");
        assert_eq!(format!("{:?}", LogCategory::CoinDb), "CoinDb");
        assert_eq!(format!("{:?}", LogCategory::LevelDb), "LevelDb");
        assert_eq!(format!("{:?}", LogCategory::Mempool), "Mempool");
        assert_eq!(format!("{:?}", LogCategory::Prune), "Prune");
        assert_eq!(format!("{:?}", LogCategory::Rand), "Rand");
        assert_eq!(format!("{:?}", LogCategory::Reindex), "Reindex");
        assert_eq!(format!("{:?}", LogCategory::Validation), "Validation");
        assert_eq!(format!("{:?}", LogCategory::Kernel), "Kernel");
    }

    #[test]
    fn test_log_level_debug() {
        assert_eq!(format!("{:?}", LogLevel::Trace), "Trace");
        assert_eq!(format!("{:?}", LogLevel::Debug), "Debug");
        assert_eq!(format!("{:?}", LogLevel::Info), "Info");
    }

    #[test]
    fn test_log_category_equality() {
        assert_eq!(LogCategory::All, LogCategory::All);
        assert_ne!(LogCategory::All, LogCategory::Bench);
        assert_ne!(LogCategory::BlockStorage, LogCategory::CoinDb);
        assert_ne!(LogCategory::LevelDb, LogCategory::Mempool);
    }

    #[test]
    fn test_log_level_equality() {
        assert_eq!(LogLevel::Trace, LogLevel::Trace);
        assert_ne!(LogLevel::Trace, LogLevel::Debug);
        assert_ne!(LogLevel::Debug, LogLevel::Info);
    }

    #[test]
    fn test_log_category_clone_copy() {
        let original = LogCategory::Validation;
        let cloned = original.clone();
        let copied = original;
        assert_eq!(original, cloned);
        assert_eq!(original, copied);
    }

    #[test]
    fn test_log_level_clone_copy() {
        let original = LogLevel::Debug;
        let cloned = original.clone();
        let copied = original;
        assert_eq!(original, cloned);
        assert_eq!(original, copied);
    }

    #[test]
    fn test_log_category_round_trip_conversion() {
        let categories = vec![
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

        for category in categories {
            let raw: btck_LogCategory = category.into();
            let back = LogCategory::from(raw);
            assert_eq!(category, back);
        }
    }

    #[test]
    fn test_log_level_round_trip_conversion() {
        let levels = vec![LogLevel::Trace, LogLevel::Debug, LogLevel::Info];

        for level in levels {
            let raw: btck_LogLevel = level.into();
            let back = LogLevel::from(raw);
            assert_eq!(level, back);
        }
    }

    #[test]
    fn test_log_category_repr_values() {
        assert_eq!(LogCategory::All as u8, BTCK_LOG_CATEGORY_ALL);
        assert_eq!(LogCategory::Bench as u8, BTCK_LOG_CATEGORY_BENCH);
        assert_eq!(
            LogCategory::BlockStorage as u8,
            BTCK_LOG_CATEGORY_BLOCKSTORAGE
        );
        assert_eq!(LogCategory::CoinDb as u8, BTCK_LOG_CATEGORY_COINDB);
        assert_eq!(LogCategory::LevelDb as u8, BTCK_LOG_CATEGORY_LEVELDB);
        assert_eq!(LogCategory::Mempool as u8, BTCK_LOG_CATEGORY_MEMPOOL);
        assert_eq!(LogCategory::Prune as u8, BTCK_LOG_CATEGORY_PRUNE);
        assert_eq!(LogCategory::Rand as u8, BTCK_LOG_CATEGORY_RAND);
        assert_eq!(LogCategory::Reindex as u8, BTCK_LOG_CATEGORY_REINDEX);
        assert_eq!(LogCategory::Validation as u8, BTCK_LOG_CATEGORY_VALIDATION);
        assert_eq!(LogCategory::Kernel as u8, BTCK_LOG_CATEGORY_KERNEL);
    }

    #[test]
    fn test_log_level_repr_values() {
        assert_eq!(LogLevel::Trace as u8, BTCK_LOG_LEVEL_TRACE);
        assert_eq!(LogLevel::Debug as u8, BTCK_LOG_LEVEL_DEBUG);
        assert_eq!(LogLevel::Info as u8, BTCK_LOG_LEVEL_INFO);
    }

    #[test]
    #[should_panic(expected = "Unknown log category")]
    fn test_log_category_from_invalid_value() {
        let _invalid = LogCategory::from(255);
    }

    #[test]
    #[should_panic(expected = "Unknown log level")]
    fn test_log_level_from_invalid_value() {
        let _invalid = LogLevel::from(255);
    }

    #[test]
    fn test_simple_logger_creation() {
        let logger = Logger::new(SimpleLogger);
        assert!(logger.is_ok());
    }

    #[test]
    fn test_test_logger_creation() {
        let test_logger = TestLogger::new();
        let logger = Logger::new(test_logger);
        assert!(logger.is_ok());
    }

    #[test]
    fn test_test_logger_functionality() {
        let test_logger = TestLogger::new();

        test_logger.log("test message 1");
        test_logger.log("test message 2");

        let messages = test_logger.get_messages();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0], "test message 1");
        assert_eq!(messages[1], "test message 2");

        test_logger.clear();
        let messages = test_logger.get_messages();
        assert_eq!(messages.len(), 0);
    }

    struct CountingLogger {
        count: Arc<Mutex<usize>>,
    }

    impl CountingLogger {
        fn new() -> Self {
            Self {
                count: Arc::new(Mutex::new(0)),
            }
        }

        fn get_count(&self) -> usize {
            *self.count.lock().unwrap()
        }
    }

    impl Log for CountingLogger {
        fn log(&self, _message: &str) {
            *self.count.lock().unwrap() += 1;
        }
    }

    #[test]
    fn test_counting_logger() {
        let counting_logger = CountingLogger::new();
        assert_eq!(counting_logger.get_count(), 0);

        counting_logger.log("message 1");
        assert_eq!(counting_logger.get_count(), 1);

        counting_logger.log("message 2");
        counting_logger.log("message 3");
        assert_eq!(counting_logger.get_count(), 3);
    }

    #[test]
    fn test_logger_with_counting_logger() {
        let counting_logger = CountingLogger::new();
        let logger = Logger::new(counting_logger);
        assert!(logger.is_ok());
    }
}
