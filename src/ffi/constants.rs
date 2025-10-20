use crate::{
    btck_BlockValidationResult, btck_ChainType, btck_LogCategory, btck_LogLevel,
    btck_ScriptVerificationFlags, btck_ScriptVerifyStatus, btck_SynchronizationState,
    btck_ValidationMode, btck_Warning,
};

// Synchronization States
pub const BTCK_SYNCHRONIZATION_STATE_INIT_REINDEX: btck_SynchronizationState = 0;
pub const BTCK_SYNCHRONIZATION_STATE_INIT_DOWNLOAD: btck_SynchronizationState = 1;
pub const BTCK_SYNCHRONIZATION_STATE_POST_INIT: btck_SynchronizationState = 2;

// Warning Types
pub const BTCK_WARNING_UNKNOWN_NEW_RULES_ACTIVATED: btck_Warning = 0;
pub const BTCK_WARNING_LARGE_WORK_INVALID_CHAIN: btck_Warning = 1;

// Validation Modes
pub const BTCK_VALIDATION_MODE_VALID: btck_ValidationMode = 0;
pub const BTCK_VALIDATION_MODE_INVALID: btck_ValidationMode = 1;
pub const BTCK_VALIDATION_MODE_INTERNAL_ERROR: btck_ValidationMode = 2;

// Block Validation Results
pub const BTCK_BLOCK_VALIDATION_RESULT_UNSET: btck_BlockValidationResult = 0;
pub const BTCK_BLOCK_VALIDATION_RESULT_CONSENSUS: btck_BlockValidationResult = 1;
pub const BTCK_BLOCK_VALIDATION_RESULT_CACHED_INVALID: btck_BlockValidationResult = 2;
pub const BTCK_BLOCK_VALIDATION_RESULT_INVALID_HEADER: btck_BlockValidationResult = 3;
pub const BTCK_BLOCK_VALIDATION_RESULT_MUTATED: btck_BlockValidationResult = 4;
pub const BTCK_BLOCK_VALIDATION_RESULT_MISSING_PREV: btck_BlockValidationResult = 5;
pub const BTCK_BLOCK_VALIDATION_RESULT_INVALID_PREV: btck_BlockValidationResult = 6;
pub const BTCK_BLOCK_VALIDATION_RESULT_TIME_FUTURE: btck_BlockValidationResult = 7;
pub const BTCK_BLOCK_VALIDATION_RESULT_HEADER_LOW_WORK: btck_BlockValidationResult = 8;

// Log Categories
pub const BTCK_LOG_CATEGORY_ALL: btck_LogCategory = 0;
pub const BTCK_LOG_CATEGORY_BENCH: btck_LogCategory = 1;
pub const BTCK_LOG_CATEGORY_BLOCKSTORAGE: btck_LogCategory = 2;
pub const BTCK_LOG_CATEGORY_COINDB: btck_LogCategory = 3;
pub const BTCK_LOG_CATEGORY_LEVELDB: btck_LogCategory = 4;
pub const BTCK_LOG_CATEGORY_MEMPOOL: btck_LogCategory = 5;
pub const BTCK_LOG_CATEGORY_PRUNE: btck_LogCategory = 6;
pub const BTCK_LOG_CATEGORY_RAND: btck_LogCategory = 7;
pub const BTCK_LOG_CATEGORY_REINDEX: btck_LogCategory = 8;
pub const BTCK_LOG_CATEGORY_VALIDATION: btck_LogCategory = 9;
pub const BTCK_LOG_CATEGORY_KERNEL: btck_LogCategory = 10;

// Log Levels
pub const BTCK_LOG_LEVEL_TRACE: btck_LogLevel = 0;
pub const BTCK_LOG_LEVEL_DEBUG: btck_LogLevel = 1;
pub const BTCK_LOG_LEVEL_INFO: btck_LogLevel = 2;

// Script Verify Status
pub const BTCK_SCRIPT_VERIFY_STATUS_OK: btck_ScriptVerifyStatus = 0;
pub const BTCK_SCRIPT_VERIFY_STATUS_ERROR_INVALID_FLAGS_COMBINATION: btck_ScriptVerifyStatus = 1;
pub const BTCK_SCRIPT_VERIFY_STATUS_ERROR_SPENT_OUTPUTS_REQUIRED: btck_ScriptVerifyStatus = 2;

// Script Verification Flags
pub const BTCK_SCRIPT_VERIFICATION_FLAGS_NONE: btck_ScriptVerificationFlags = 0;
pub const BTCK_SCRIPT_VERIFICATION_FLAGS_P2SH: btck_ScriptVerificationFlags = 1 << 0;
pub const BTCK_SCRIPT_VERIFICATION_FLAGS_DERSIG: btck_ScriptVerificationFlags = 1 << 2;
pub const BTCK_SCRIPT_VERIFICATION_FLAGS_NULLDUMMY: btck_ScriptVerificationFlags = 1 << 4;
pub const BTCK_SCRIPT_VERIFICATION_FLAGS_CHECKLOCKTIMEVERIFY: btck_ScriptVerificationFlags = 1 << 9;
pub const BTCK_SCRIPT_VERIFICATION_FLAGS_CHECKSEQUENCEVERIFY: btck_ScriptVerificationFlags =
    1 << 10;
pub const BTCK_SCRIPT_VERIFICATION_FLAGS_WITNESS: btck_ScriptVerificationFlags = 1 << 11;
pub const BTCK_SCRIPT_VERIFICATION_FLAGS_TAPROOT: btck_ScriptVerificationFlags = 1 << 17;

pub const BTCK_SCRIPT_VERIFICATION_FLAGS_ALL: btck_ScriptVerificationFlags =
    BTCK_SCRIPT_VERIFICATION_FLAGS_P2SH
        | BTCK_SCRIPT_VERIFICATION_FLAGS_DERSIG
        | BTCK_SCRIPT_VERIFICATION_FLAGS_NULLDUMMY
        | BTCK_SCRIPT_VERIFICATION_FLAGS_CHECKLOCKTIMEVERIFY
        | BTCK_SCRIPT_VERIFICATION_FLAGS_CHECKSEQUENCEVERIFY
        | BTCK_SCRIPT_VERIFICATION_FLAGS_WITNESS
        | BTCK_SCRIPT_VERIFICATION_FLAGS_TAPROOT;

// Chain types
pub const BTCK_CHAIN_TYPE_MAINNET: btck_ChainType = 0;
pub const BTCK_CHAIN_TYPE_TESTNET: btck_ChainType = 1;
pub const BTCK_CHAIN_TYPE_TESTNET_4: btck_ChainType = 2;
pub const BTCK_CHAIN_TYPE_SIGNET: btck_ChainType = 3;
pub const BTCK_CHAIN_TYPE_REGTEST: btck_ChainType = 4;
