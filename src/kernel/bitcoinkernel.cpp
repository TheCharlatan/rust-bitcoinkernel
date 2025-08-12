// Copyright (c) 2022-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#define BITCOINKERNEL_BUILD

#include <kernel/bitcoinkernel.h>

#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <kernel/caches.h>
#include <kernel/chainparams.h>
#include <kernel/checks.h>
#include <kernel/context.h>
#include <kernel/notifications_interface.h>
#include <kernel/warning.h>
#include <logging.h>
#include <node/blockstorage.h>
#include <node/chainstate.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <sync.h>
#include <tinyformat.h>
#include <uint256.h>
#include <undo.h>
#include <util/fs.h>
#include <util/result.h>
#include <util/signalinterrupt.h>
#include <util/task_runner.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>

#include <cassert>
#include <cstddef>
#include <cstring>
#include <exception>
#include <functional>
#include <list>
#include <memory>
#include <span>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

using util::ImmediateTaskRunner;

// Define G_TRANSLATION_FUN symbol in libbitcoinkernel library so users of the
// library aren't required to export this symbol
extern const std::function<std::string(const char*)> G_TRANSLATION_FUN{nullptr};

static const kernel::Context btck_context_static{};

namespace {

/** Check that all specified flags are part of the libbitcoinkernel interface. */
bool verify_flags(unsigned int flags)
{
    return (flags & ~(btck_SCRIPT_FLAGS_VERIFY_ALL)) == 0;
}

bool is_valid_flag_combination(unsigned int flags)
{
    if (flags & SCRIPT_VERIFY_CLEANSTACK && ~flags & (SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS)) return false;
    if (flags & SCRIPT_VERIFY_WITNESS && ~flags & SCRIPT_VERIFY_P2SH) return false;
    return true;
}

BCLog::Level get_bclog_level(const btck_LogLevel level)
{
    switch (level) {
    case btck_LogLevel::btck_LOG_INFO: {
        return BCLog::Level::Info;
    }
    case btck_LogLevel::btck_LOG_DEBUG: {
        return BCLog::Level::Debug;
    }
    case btck_LogLevel::btck_LOG_TRACE: {
        return BCLog::Level::Trace;
    }
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

BCLog::LogFlags get_bclog_flag(const btck_LogCategory category)
{
    switch (category) {
    case btck_LogCategory::btck_LOG_BENCH: {
        return BCLog::LogFlags::BENCH;
    }
    case btck_LogCategory::btck_LOG_BLOCKSTORAGE: {
        return BCLog::LogFlags::BLOCKSTORAGE;
    }
    case btck_LogCategory::btck_LOG_COINDB: {
        return BCLog::LogFlags::COINDB;
    }
    case btck_LogCategory::btck_LOG_LEVELDB: {
        return BCLog::LogFlags::LEVELDB;
    }
    case btck_LogCategory::btck_LOG_MEMPOOL: {
        return BCLog::LogFlags::MEMPOOL;
    }
    case btck_LogCategory::btck_LOG_PRUNE: {
        return BCLog::LogFlags::PRUNE;
    }
    case btck_LogCategory::btck_LOG_RAND: {
        return BCLog::LogFlags::RAND;
    }
    case btck_LogCategory::btck_LOG_REINDEX: {
        return BCLog::LogFlags::REINDEX;
    }
    case btck_LogCategory::btck_LOG_VALIDATION: {
        return BCLog::LogFlags::VALIDATION;
    }
    case btck_LogCategory::btck_LOG_KERNEL: {
        return BCLog::LogFlags::KERNEL;
    }
    case btck_LogCategory::btck_LOG_ALL: {
        return BCLog::LogFlags::ALL;
    }
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

btck_SynchronizationState cast_state(SynchronizationState state)
{
    switch (state) {
    case SynchronizationState::INIT_REINDEX:
        return btck_SynchronizationState::btck_INIT_REINDEX;
    case SynchronizationState::INIT_DOWNLOAD:
        return btck_SynchronizationState::btck_INIT_DOWNLOAD;
    case SynchronizationState::POST_INIT:
        return btck_SynchronizationState::btck_POST_INIT;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

btck_Warning cast_btck_warning(kernel::Warning warning)
{
    switch (warning) {
    case kernel::Warning::UNKNOWN_NEW_RULES_ACTIVATED:
        return btck_Warning::btck_UNKNOWN_NEW_RULES_ACTIVATED;
    case kernel::Warning::LARGE_WORK_INVALID_CHAIN:
        return btck_Warning::btck_LARGE_WORK_INVALID_CHAIN;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

class KernelNotifications : public kernel::Notifications
{
private:
    btck_NotificationInterfaceCallbacks m_cbs;

public:
    KernelNotifications(btck_NotificationInterfaceCallbacks cbs)
        : m_cbs{cbs}
    {
    }

    kernel::InterruptResult blockTip(SynchronizationState state, CBlockIndex& index, double verification_progress) override
    {
        if (m_cbs.block_tip) m_cbs.block_tip((void*)m_cbs.user_data, cast_state(state), reinterpret_cast<const btck_BlockIndex*>(&index), verification_progress);
        return {};
    }
    void headerTip(SynchronizationState state, int64_t height, int64_t timestamp, bool presync) override
    {
        if (m_cbs.header_tip) m_cbs.header_tip((void*)m_cbs.user_data, cast_state(state), height, timestamp, presync);
    }
    void progress(const bilingual_str& title, int progress_percent, bool resume_possible) override
    {
        if (m_cbs.progress) m_cbs.progress((void*)m_cbs.user_data, title.original.c_str(), title.original.length(), progress_percent, resume_possible);
    }
    void warningSet(kernel::Warning id, const bilingual_str& message) override
    {
        if (m_cbs.warning_set) m_cbs.warning_set((void*)m_cbs.user_data, cast_btck_warning(id), message.original.c_str(), message.original.length());
    }
    void warningUnset(kernel::Warning id) override
    {
        if (m_cbs.warning_unset) m_cbs.warning_unset((void*)m_cbs.user_data, cast_btck_warning(id));
    }
    void flushError(const bilingual_str& message) override
    {
        if (m_cbs.flush_error) m_cbs.flush_error((void*)m_cbs.user_data, message.original.c_str(), message.original.length());
    }
    void fatalError(const bilingual_str& message) override
    {
        if (m_cbs.fatal_error) m_cbs.fatal_error((void*)m_cbs.user_data, message.original.c_str(), message.original.length());
    }
};

class KernelValidationInterface final : public CValidationInterface
{
public:
    const btck_ValidationInterfaceCallbacks m_cbs;

    explicit KernelValidationInterface(const btck_ValidationInterfaceCallbacks vi_cbs) : m_cbs{vi_cbs} {}

protected:
    void BlockChecked(const CBlock& block, const BlockValidationState& stateIn) override
    {
        if (m_cbs.block_checked) {
            m_cbs.block_checked((void*)m_cbs.user_data,
                                reinterpret_cast<const btck_BlockPointer*>(&block),
                                reinterpret_cast<const btck_BlockValidationState*>(&stateIn));
        }
    }
};

struct ContextOptions {
    mutable Mutex m_mutex;
    std::unique_ptr<const CChainParams> m_chainparams GUARDED_BY(m_mutex);
    std::unique_ptr<const KernelNotifications> m_notifications GUARDED_BY(m_mutex);
    std::unique_ptr<const KernelValidationInterface> m_validation_interface GUARDED_BY(m_mutex);
};

class Context
{
public:
    std::unique_ptr<kernel::Context> m_context;

    std::unique_ptr<KernelNotifications> m_notifications;

    std::unique_ptr<util::SignalInterrupt> m_interrupt;

    std::unique_ptr<ValidationSignals> m_signals;

    std::unique_ptr<const CChainParams> m_chainparams;

    std::unique_ptr<KernelValidationInterface> m_validation_interface;

    Context(const ContextOptions* options, bool& sane)
        : m_context{std::make_unique<kernel::Context>()},
          m_interrupt{std::make_unique<util::SignalInterrupt>()},
          m_signals{std::make_unique<ValidationSignals>(std::make_unique<ImmediateTaskRunner>())}
    {
        if (options) {
            LOCK(options->m_mutex);
            if (options->m_chainparams) {
                m_chainparams = std::make_unique<const CChainParams>(*options->m_chainparams);
            }
            if (options->m_notifications) {
                m_notifications = std::make_unique<KernelNotifications>(*options->m_notifications);
            }
            if (options->m_validation_interface) {
                m_validation_interface = std::make_unique<KernelValidationInterface>(*options->m_validation_interface);
                m_signals->RegisterValidationInterface(m_validation_interface.get());
            }

        }

        if (!m_chainparams) {
            m_chainparams = CChainParams::Main();
        }
        if (!m_notifications) {
            m_notifications = std::make_unique<KernelNotifications>(btck_NotificationInterfaceCallbacks{
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr});
        }

        if (!kernel::SanityChecks(*m_context)) {
            sane = false;
        }
    }

    ~Context()
    {
        m_signals->UnregisterValidationInterface(m_validation_interface.get());
    }
};

//! Helper struct to wrap the ChainstateManager-related Options
struct ChainstateManagerOptions {
    mutable Mutex m_mutex;
    ChainstateManager::Options m_chainman_options GUARDED_BY(m_mutex);
    node::BlockManager::Options m_blockman_options GUARDED_BY(m_mutex);
    std::shared_ptr<Context> m_context;
    node::ChainstateLoadOptions m_chainstate_load_options GUARDED_BY(m_mutex);

    ChainstateManagerOptions(const std::shared_ptr<Context>& context, const fs::path& data_dir, const fs::path& blocks_dir)
        : m_chainman_options{ChainstateManager::Options{
              .chainparams = *context->m_chainparams,
              .datadir = data_dir,
              .notifications = *context->m_notifications,
              .signals = context->m_signals.get()}},
          m_blockman_options{node::BlockManager::Options{
              .chainparams = *context->m_chainparams,
              .blocks_dir = blocks_dir,
              .notifications = *context->m_notifications,
              .block_tree_db_params = DBParams{
                  .path = data_dir / "blocks" / "index",
                  .cache_bytes = kernel::CacheSizes{DEFAULT_KERNEL_CACHE}.block_tree_db,
              }}},
          m_context{context},
          m_chainstate_load_options{node::ChainstateLoadOptions{}}
    {
    }
};

const BlockValidationState* cast_block_validation_state(const btck_BlockValidationState* block_validation_state)
{
    assert(block_validation_state);
    return reinterpret_cast<const BlockValidationState*>(block_validation_state);
}

const CBlock* cast_const_cblock(const btck_BlockPointer* block)
{
    assert(block);
    return reinterpret_cast<const CBlock*>(block);
}

const CBlockIndex* cast_const_block_index(const btck_BlockIndex* index)
{
    assert(index);
    return reinterpret_cast<const CBlockIndex*>(index);
}

} // namespace

struct btck_Transaction
{
    std::shared_ptr<const CTransaction> m_tx;
};

struct btck_TransactionOutput
{
    const CTxOut* m_txout;
    bool m_owned;
};

struct btck_ScriptPubkey
{
    const CScript* m_script;
    bool m_owned;
};

struct btck_LoggingConnection
{
    std::unique_ptr<std::list<std::function<void(const std::string&)>>::iterator> m_connection;
};

struct btck_ContextOptions
{
    std::unique_ptr<ContextOptions> m_opts;
};

struct btck_Context
{
    std::shared_ptr<Context> m_context;
};

struct btck_ChainParameters
{
    std::unique_ptr<const CChainParams> m_params;
};

struct btck_ChainstateManagerOptions
{
    std::unique_ptr<ChainstateManagerOptions> m_opts;
};

struct btck_ChainstateManager
{
    std::unique_ptr<ChainstateManager> m_chainman;
    std::shared_ptr<Context> m_context;
};

struct btck_Block
{
    std::shared_ptr<CBlock> m_block;
};

struct btck_BlockSpentOutputs
{
    std::shared_ptr<CBlockUndo> m_block_undo;
};

struct btck_TransactionSpentOutputs
{
    const CTxUndo* m_tx_undo;
    bool m_owned;
};

struct btck_Coin
{
    const Coin* m_coin;
    bool m_owned;
};

btck_Transaction* btck_transaction_create(const unsigned char* raw_transaction, size_t raw_transaction_len)
{
    try {
        DataStream stream{std::span{raw_transaction, raw_transaction_len}};
        auto tx{std::make_shared<CTransaction>(deserialize, TX_WITH_WITNESS, stream)};
        return new btck_Transaction{std::move(tx)};
    } catch (const std::exception&) {
        return nullptr;
    }
}

uint64_t btck_transaction_count_outputs(const btck_Transaction* transaction)
{
    return transaction->m_tx->vout.size();
}

btck_TransactionOutput* btck_transaction_get_output_at(const btck_Transaction* transaction, uint64_t output_index)
{
    assert(output_index < transaction->m_tx->vout.size());
    return new btck_TransactionOutput{&transaction->m_tx->vout[output_index], false};
}

uint64_t btck_transaction_count_inputs(const btck_Transaction* transaction)
{
    return transaction->m_tx->vin.size();
}

btck_Transaction* btck_transaction_copy(const btck_Transaction* transaction)
{
    return new btck_Transaction{transaction->m_tx};
}

void btck_transaction_destroy(btck_Transaction* transaction)
{
    if (!transaction) return;
    delete transaction;
    transaction = nullptr;
}

btck_ScriptPubkey* btck_script_pubkey_create(const unsigned char* script_pubkey, size_t script_pubkey_len)
{
    return new btck_ScriptPubkey{new CScript(script_pubkey, script_pubkey + script_pubkey_len), true};
}

btck_ByteArray* btck_script_pubkey_copy_data(const btck_ScriptPubkey* script_pubkey)
{
    auto byte_array{new btck_ByteArray{
        .data = new unsigned char[script_pubkey->m_script->size()],
        .size = script_pubkey->m_script->size(),
    }};

    std::memcpy(byte_array->data, script_pubkey->m_script->data(), byte_array->size);
    return byte_array;
}

btck_ScriptPubkey* btck_script_pubkey_copy(const btck_ScriptPubkey* script_pubkey)
{
    return new btck_ScriptPubkey{new CScript(*script_pubkey->m_script), true};
}

void btck_script_pubkey_destroy(btck_ScriptPubkey* script_pubkey)
{
    if (!script_pubkey) return;
    if (script_pubkey->m_owned) {
        delete script_pubkey->m_script;
    }
    delete script_pubkey;
    script_pubkey = nullptr;
}

btck_TransactionOutput* btck_transaction_output_create(const btck_ScriptPubkey* script_pubkey, int64_t amount)
{
    const CAmount& value{amount};
    return new btck_TransactionOutput{new CTxOut(value, *script_pubkey->m_script), true};
}

btck_TransactionOutput* btck_transaction_output_copy(const btck_TransactionOutput* output)
{
    return new btck_TransactionOutput{new CTxOut{*output->m_txout}, true};
}

btck_ScriptPubkey* btck_transaction_output_get_script_pubkey(const btck_TransactionOutput* output)
{
    const auto* script_pubkey{&output->m_txout->scriptPubKey};
    return new btck_ScriptPubkey{script_pubkey, false};
}

int64_t btck_transaction_output_get_amount(const btck_TransactionOutput* output)
{
    return output->m_txout->nValue;
}

void btck_transaction_output_destroy(btck_TransactionOutput* output)
{
    if (!output) return;
    if (output->m_owned) {
        delete output->m_txout;
    }
    delete output;
    output = nullptr;
}

bool btck_script_pubkey_verify(const btck_ScriptPubkey* script_pubkey,
                          const int64_t amount_,
                          const btck_Transaction* tx_to,
                          const btck_TransactionOutput** spent_outputs_, size_t spent_outputs_len,
                          const unsigned int input_index,
                          const unsigned int flags,
                          btck_ScriptVerifyStatus* status)
{
    const CAmount amount{amount_};

    if (!verify_flags(flags)) {
        if (status) *status = btck_SCRIPT_VERIFY_ERROR_INVALID_FLAGS;
        return false;
    }

    if (!is_valid_flag_combination(flags)) {
        if (status) *status = btck_SCRIPT_VERIFY_ERROR_INVALID_FLAGS_COMBINATION;
        return false;
    }

    if (flags & btck_SCRIPT_FLAGS_VERIFY_TAPROOT && spent_outputs_ == nullptr) {
        if (status) *status = btck_SCRIPT_VERIFY_ERROR_SPENT_OUTPUTS_REQUIRED;
        return false;
    }

    const CTransaction& tx{*tx_to->m_tx};
    std::vector<CTxOut> spent_outputs;
    if (spent_outputs_ != nullptr) {
        assert(spent_outputs_len == tx.vin.size());
        spent_outputs.reserve(spent_outputs_len);
        for (size_t i = 0; i < spent_outputs_len; i++) {
            const CTxOut& tx_out{*spent_outputs_[i]->m_txout};
            spent_outputs.push_back(tx_out);
        }
    }

    assert(input_index < tx.vin.size());
    PrecomputedTransactionData txdata{tx};

    if (spent_outputs_ != nullptr && flags & btck_SCRIPT_FLAGS_VERIFY_TAPROOT) {
        txdata.Init(tx, std::move(spent_outputs));
    }

    return VerifyScript(tx.vin[input_index].scriptSig,
                        *script_pubkey->m_script,
                        &tx.vin[input_index].scriptWitness,
                        flags,
                        TransactionSignatureChecker(&tx, input_index, amount, txdata, MissingDataBehavior::FAIL),
                        nullptr);
}

void btck_logging_set_level_category(const btck_LogCategory category, const btck_LogLevel level)
{
    if (category == btck_LogCategory::btck_LOG_ALL) {
        LogInstance().SetLogLevel(get_bclog_level(level));
    }

    LogInstance().AddCategoryLogLevel(get_bclog_flag(category), get_bclog_level(level));
}

void btck_logging_enable_category(const btck_LogCategory category)
{
    LogInstance().EnableCategory(get_bclog_flag(category));
}

void btck_logging_disable_category(const btck_LogCategory category)
{
    LogInstance().DisableCategory(get_bclog_flag(category));
}

void btck_logging_disable()
{
    LogInstance().DisableLogging();
}

btck_LoggingConnection* btck_logging_connection_create(btck_LogCallback callback,
                                                           const void* user_data,
                                                           const btck_LoggingOptions options)
{
    LogInstance().m_log_timestamps = options.log_timestamps;
    LogInstance().m_log_time_micros = options.log_time_micros;
    LogInstance().m_log_threadnames = options.log_threadnames;
    LogInstance().m_log_sourcelocations = options.log_sourcelocations;
    LogInstance().m_always_print_category_level = options.always_print_category_levels;

    auto connection{LogInstance().PushBackCallback([callback, user_data](const std::string& str) { callback((void*)user_data, str.c_str(), str.length()); })};

    try {
        // Only start logging if we just added the connection.
        if (LogInstance().NumConnections() == 1 && !LogInstance().StartLogging()) {
            LogError("Logger start failed.");
            LogInstance().DeleteCallback(connection);
            return nullptr;
        }
    } catch (std::exception&) {
        LogError("Logger start failed.");
        LogInstance().DeleteCallback(connection);
        return nullptr;
    }

    LogDebug(BCLog::KERNEL, "Logger connected.");

    return new btck_LoggingConnection{std::make_unique<std::list<std::function<void(const std::string&)>>::iterator>(connection)};
}

void btck_logging_connection_destroy(btck_LoggingConnection* connection)
{
    if (!connection) {
        return;
    }

    LogDebug(BCLog::KERNEL, "Logger disconnected.");
    LogInstance().DeleteCallback(*connection->m_connection);
    delete connection;

    // Switch back to buffering by calling DisconnectTestLogger if the
    // connection that was just removed was the last one.
    if (!LogInstance().Enabled()) {
        LogInstance().DisconnectTestLogger();
    }
    connection = nullptr;
}

btck_ChainParameters* btck_chain_parameters_create(const btck_ChainType chain_type)
{
    switch (chain_type) {
    case btck_ChainType::btck_CHAIN_TYPE_MAINNET: {
        return new btck_ChainParameters{CChainParams::Main()};
    }
    case btck_ChainType::btck_CHAIN_TYPE_TESTNET: {
        return new btck_ChainParameters{CChainParams::TestNet()};
    }
    case btck_ChainType::btck_CHAIN_TYPE_TESTNET_4: {
        return new btck_ChainParameters{CChainParams::TestNet4()};
    }
    case btck_ChainType::btck_CHAIN_TYPE_SIGNET: {
        return new btck_ChainParameters{CChainParams::SigNet({})};
    }
    case btck_ChainType::btck_CHAIN_TYPE_REGTEST: {
        return new btck_ChainParameters{CChainParams::RegTest({})};
    }
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

void btck_chain_parameters_destroy(btck_ChainParameters* chain_parameters)
{
    if (!chain_parameters) return;
    delete chain_parameters;
    chain_parameters = nullptr;
}

btck_ContextOptions* btck_context_options_create()
{
    return new btck_ContextOptions{std::make_unique<ContextOptions>()};
}

void btck_context_options_set_chainparams(btck_ContextOptions* options, const btck_ChainParameters* chain_parameters)
{
    // Copy the chainparams, so the caller can free it again
    LOCK(options->m_opts->m_mutex);
    options->m_opts->m_chainparams = std::make_unique<const CChainParams>(*chain_parameters->m_params);
}

void btck_context_options_set_notifications(btck_ContextOptions* options, btck_NotificationInterfaceCallbacks notifications)
{
    // The KernelNotifications are copy-initialized, so the caller can free them again.
    LOCK(options->m_opts->m_mutex);
    options->m_opts->m_notifications = std::make_unique<const KernelNotifications>(notifications);
}

void btck_context_options_set_validation_interface(btck_ContextOptions* options, btck_ValidationInterfaceCallbacks vi_cbs)
{
    LOCK(options->m_opts->m_mutex);
    options->m_opts->m_validation_interface = std::make_unique<KernelValidationInterface>(KernelValidationInterface(vi_cbs));
}

void btck_context_options_destroy(btck_ContextOptions* options)
{
    if (!options) return;
    delete options;
    options = nullptr;
}

btck_Context* btck_context_create(const btck_ContextOptions* options)
{
    bool sane{true};
    auto context{std::make_shared<Context>(options->m_opts.get(), sane)};
    if (!sane) {
        LogError("Kernel context sanity check failed.");
        return nullptr;
    }
    return new btck_Context{std::move(context)};
}

bool btck_context_interrupt(btck_Context* context)
{
    return (*context->m_context->m_interrupt)();
}

void btck_context_destroy(btck_Context* context)
{
    if (!context) return;
    delete context;
    context = nullptr;
}

btck_ValidationMode btck_block_validation_state_get_validation_mode(const btck_BlockValidationState* block_validation_state_)
{
    auto& block_validation_state = *cast_block_validation_state(block_validation_state_);
    if (block_validation_state.IsValid()) return btck_ValidationMode::btck_VALIDATION_STATE_VALID;
    if (block_validation_state.IsInvalid()) return btck_ValidationMode::btck_VALIDATION_STATE_INVALID;
    return btck_ValidationMode::btck_VALIDATION_STATE_ERROR;
}

btck_BlockValidationResult btck_block_validation_state_get_block_validation_result(const btck_BlockValidationState* block_validation_state_)
{
    auto& block_validation_state = *cast_block_validation_state(block_validation_state_);
    switch (block_validation_state.GetResult()) {
    case BlockValidationResult::BLOCK_RESULT_UNSET:
        return btck_BlockValidationResult::btck_BLOCK_RESULT_UNSET;
    case BlockValidationResult::BLOCK_CONSENSUS:
        return btck_BlockValidationResult::btck_BLOCK_CONSENSUS;
    case BlockValidationResult::BLOCK_CACHED_INVALID:
        return btck_BlockValidationResult::btck_BLOCK_CACHED_INVALID;
    case BlockValidationResult::BLOCK_INVALID_HEADER:
        return btck_BlockValidationResult::btck_BLOCK_INVALID_HEADER;
    case BlockValidationResult::BLOCK_MUTATED:
        return btck_BlockValidationResult::btck_BLOCK_MUTATED;
    case BlockValidationResult::BLOCK_MISSING_PREV:
        return btck_BlockValidationResult::btck_BLOCK_MISSING_PREV;
    case BlockValidationResult::BLOCK_INVALID_PREV:
        return btck_BlockValidationResult::btck_BLOCK_INVALID_PREV;
    case BlockValidationResult::BLOCK_TIME_FUTURE:
        return btck_BlockValidationResult::btck_BLOCK_TIME_FUTURE;
    case BlockValidationResult::BLOCK_HEADER_LOW_WORK:
        return btck_BlockValidationResult::btck_BLOCK_HEADER_LOW_WORK;
    } // no default case, so the compiler can warn about missing cases
    assert(false);
}

btck_ChainstateManagerOptions* btck_chainstate_manager_options_create(const btck_Context* context, const char* data_dir, size_t data_dir_len, const char* blocks_dir, size_t blocks_dir_len)
{
    try {
        fs::path abs_data_dir{fs::absolute(fs::PathFromString({data_dir, data_dir_len}))};
        fs::create_directories(abs_data_dir);
        fs::path abs_blocks_dir{fs::absolute(fs::PathFromString({blocks_dir, blocks_dir_len}))};
        fs::create_directories(abs_blocks_dir);
        auto chainman_opts{std::make_unique<ChainstateManagerOptions>(context->m_context, abs_data_dir, abs_blocks_dir)};
        return new btck_ChainstateManagerOptions{std::move(chainman_opts)};
    } catch (const std::exception& e) {
        LogError("Failed to create chainstate manager options: %s", e.what());
        return nullptr;
    }
}

void btck_chainstate_manager_options_set_worker_threads_num(btck_ChainstateManagerOptions* opts, int worker_threads)
{
    LOCK(opts->m_opts->m_mutex);
    opts->m_opts->m_chainman_options.worker_threads_num = worker_threads;
}

void btck_chainstate_manager_options_destroy(btck_ChainstateManagerOptions* options)
{
    if (!options) return;
    delete options;
    options = nullptr;
}

bool btck_chainstate_manager_options_set_wipe_dbs(btck_ChainstateManagerOptions* chainman_opts, bool wipe_block_tree_db, bool wipe_chainstate_db)
{
    if (wipe_block_tree_db && !wipe_chainstate_db) {
        LogError("Wiping the block tree db without also wiping the chainstate db is currently unsupported.");
        return false;
    }
    LOCK(chainman_opts->m_opts->m_mutex);
    chainman_opts->m_opts->m_blockman_options.block_tree_db_params.wipe_data = wipe_block_tree_db;
    chainman_opts->m_opts->m_chainstate_load_options.wipe_chainstate_db = wipe_chainstate_db;
    return true;
}

void btck_chainstate_manager_options_set_block_tree_db_in_memory(
    btck_ChainstateManagerOptions* chainman_opts,
    bool block_tree_db_in_memory)
{
    LOCK(chainman_opts->m_opts->m_mutex);
    chainman_opts->m_opts->m_blockman_options.block_tree_db_params.memory_only = block_tree_db_in_memory;
}

void btck_chainstate_manager_options_set_chainstate_db_in_memory(
    btck_ChainstateManagerOptions* chainman_opts,
    bool chainstate_db_in_memory)
{
    LOCK(chainman_opts->m_opts->m_mutex);
    chainman_opts->m_opts->m_chainstate_load_options.coins_db_in_memory = chainstate_db_in_memory;
}

btck_ChainstateManager* btck_chainstate_manager_create(
    const btck_ChainstateManagerOptions* chainman_opts)
{
    std::unique_ptr<ChainstateManager> chainman;
    try {
        LOCK(chainman_opts->m_opts->m_mutex);
        auto& context{chainman_opts->m_opts->m_context};
        chainman = std::make_unique<ChainstateManager>(*context->m_interrupt, chainman_opts->m_opts->m_chainman_options, chainman_opts->m_opts->m_blockman_options);
    } catch (const std::exception& e) {
        LogError("Failed to create chainstate manager: %s", e.what());
        return nullptr;
    }

    try {
        const auto chainstate_load_opts{WITH_LOCK(chainman_opts->m_opts->m_mutex, return chainman_opts->m_opts->m_chainstate_load_options)};

        kernel::CacheSizes cache_sizes{DEFAULT_KERNEL_CACHE};
        auto [status, chainstate_err]{node::LoadChainstate(*chainman, cache_sizes, chainstate_load_opts)};
        if (status != node::ChainstateLoadStatus::SUCCESS) {
            LogError("Failed to load chain state from your data directory: %s", chainstate_err.original);
            return nullptr;
        }
        std::tie(status, chainstate_err) = node::VerifyLoadedChainstate(*chainman, chainstate_load_opts);
        if (status != node::ChainstateLoadStatus::SUCCESS) {
            LogError("Failed to verify loaded chain state from your datadir: %s", chainstate_err.original);
            return nullptr;
        }

        for (Chainstate* chainstate : WITH_LOCK(chainman->GetMutex(), return chainman->GetAll())) {
            BlockValidationState state;
            if (!chainstate->ActivateBestChain(state, nullptr)) {
                LogError("Failed to connect best block: %s", state.ToString());
                return nullptr;
            }
        }
    } catch (const std::exception& e) {
        LogError("Failed to load chainstate: %s", e.what());
        return nullptr;
    }

    return new btck_ChainstateManager{std::move(chainman), chainman_opts->m_opts->m_context};
}

void btck_chainstate_manager_destroy(btck_ChainstateManager* chainman)
{
    if (!chainman) return;

    {
        LOCK(chainman->m_chainman->GetMutex());
        for (Chainstate* chainstate : chainman->m_chainman->GetAll()) {
            if (chainstate->CanFlushToDisk()) {
                chainstate->ForceFlushStateToDisk();
                chainstate->ResetCoinsViews();
            }
        }
    }

    delete chainman;
    chainman = nullptr;
}

bool btck_chainstate_manager_import_blocks(btck_ChainstateManager* chainman, const char** block_file_paths, size_t* block_file_paths_lens, size_t block_file_paths_len)
{
    try {
        std::vector<fs::path> import_files;
        import_files.reserve(block_file_paths_len);
        for (uint32_t i = 0; i < block_file_paths_len; i++) {
            if (block_file_paths[i] != nullptr) {
                import_files.emplace_back(std::string{block_file_paths[i], block_file_paths_lens[i]}.c_str());
            }
        }
        node::ImportBlocks(*chainman->m_chainman, import_files);
        chainman->m_chainman->ActiveChainstate().ForceFlushStateToDisk();
    } catch (const std::exception& e) {
        LogError("Failed to import blocks: %s", e.what());
        return false;
    }
    return true;
}

btck_Block* btck_block_create(const unsigned char* raw_block, size_t raw_block_length)
{
    auto block{std::make_shared<CBlock>()};

    DataStream stream{std::span{raw_block, raw_block_length}};

    try {
        stream >> TX_WITH_WITNESS(*block);
    } catch (const std::exception&) {
        LogDebug(BCLog::KERNEL, "Block decode failed.");
        return nullptr;
    }

    return new btck_Block{std::move(block)};
}

btck_Block* btck_block_copy(const btck_Block* block)
{
    return new btck_Block{block->m_block};
}

uint64_t btck_block_count_transactions(const btck_Block* block)
{
    return block->m_block->vtx.size();
}

btck_Transaction* btck_block_get_transaction_at(const btck_Block* block, uint64_t index)
{
    assert(index < block->m_block->vtx.size());
    return new btck_Transaction{block->m_block->vtx[index]};
}

void btck_byte_array_destroy(btck_ByteArray* byte_array)
{
    if (!byte_array) return;
    if (byte_array->data) {
        delete[] byte_array->data;
    }
    delete byte_array;
    byte_array = nullptr;
}

btck_ByteArray* btck_block_copy_data(btck_Block* block)
{
    DataStream ss{};
    ss << TX_WITH_WITNESS(*block->m_block);

    auto byte_array{new btck_ByteArray{
        .data = new unsigned char[ss.size()],
        .size = ss.size(),
    }};

    std::memcpy(byte_array->data, ss.data(), byte_array->size);

    return byte_array;
}

btck_ByteArray* btck_block_pointer_copy_data(const btck_BlockPointer* block_)
{
    auto block{cast_const_cblock(block_)};

    DataStream ss{};
    ss << TX_WITH_WITNESS(*block);

    auto byte_array{new btck_ByteArray{
        .data = new unsigned char[ss.size()],
        .size = ss.size(),
    }};

    std::memcpy(byte_array->data, ss.data(), byte_array->size);

    return byte_array;
}

btck_BlockHash* btck_block_get_hash(btck_Block* block)
{
    auto hash{block->m_block->GetHash()};
    auto block_hash = new btck_BlockHash{};
    std::memcpy(block_hash->hash, hash.begin(), sizeof(hash));
    return block_hash;
}

btck_BlockHash* btck_block_pointer_get_hash(const btck_BlockPointer* block_)
{
    auto block{cast_const_cblock(block_)};
    auto hash{block->GetHash()};
    auto block_hash = new btck_BlockHash{};
    std::memcpy(block_hash->hash, hash.begin(), sizeof(hash));
    return block_hash;
}

void btck_block_destroy(btck_Block* block)
{
    if (!block) return;
    delete block;
    block = nullptr;
}

btck_BlockIndex* btck_block_index_get_tip(btck_ChainstateManager* chainman)
{
    return reinterpret_cast<btck_BlockIndex*>(WITH_LOCK(chainman->m_chainman->GetMutex(), return chainman->m_chainman->ActiveChain().Tip()));
}

btck_BlockIndex* btck_block_index_get_genesis(btck_ChainstateManager* chainman)
{
    return reinterpret_cast<btck_BlockIndex*>(WITH_LOCK(chainman->m_chainman->GetMutex(), return chainman->m_chainman->ActiveChain().Genesis()));
}

btck_BlockIndex* btck_block_index_get_by_hash(btck_ChainstateManager* chainman, btck_BlockHash* block_hash)
{
    auto hash = uint256{std::span<const unsigned char>{(*block_hash).hash, 32}};
    auto block_index = WITH_LOCK(chainman->m_chainman->GetMutex(), return chainman->m_chainman->m_blockman.LookupBlockIndex(hash));
    if (!block_index) {
        LogDebug(BCLog::KERNEL, "A block with the given hash is not indexed.");
        return nullptr;
    }
    return reinterpret_cast<btck_BlockIndex*>(block_index);
}

btck_BlockIndex* btck_block_index_get_by_height(btck_ChainstateManager* chainman, int height)
{
    LOCK(chainman->m_chainman->GetMutex());

    if (height < 0 || height > chainman->m_chainman->ActiveChain().Height()) {
        LogDebug(BCLog::KERNEL, "Block height is out of range.");
        return nullptr;
    }
    return reinterpret_cast<btck_BlockIndex*>(chainman->m_chainman->ActiveChain()[height]);
}

btck_BlockIndex* btck_block_index_get_next(btck_ChainstateManager* chainman, const btck_BlockIndex* block_index_)
{
    const auto block_index{cast_const_block_index(block_index_)};

    auto next_block_index{WITH_LOCK(chainman->m_chainman->GetMutex(), return chainman->m_chainman->ActiveChain().Next(block_index))};

    if (!next_block_index) {
        LogTrace(BCLog::KERNEL, "The block index is the tip of the current chain, it does not have a next.");
    }

    return reinterpret_cast<btck_BlockIndex*>(next_block_index);
}

btck_BlockIndex* btck_block_index_get_previous(const btck_BlockIndex* block_index_)
{
    const CBlockIndex* block_index{cast_const_block_index(block_index_)};

    if (!block_index->pprev) {
        LogTrace(BCLog::KERNEL, "The block index is the genesis, it has no previous.");
        return nullptr;
    }

    return reinterpret_cast<btck_BlockIndex*>(block_index->pprev);
}

btck_Block* btck_block_read( btck_ChainstateManager* chainman, const btck_BlockIndex* block_index_)
{
    const CBlockIndex* block_index{cast_const_block_index(block_index_)};

    auto block{std::shared_ptr<CBlock>(new CBlock{})};
    if (!chainman->m_chainman->m_blockman.ReadBlock(*block, *block_index)) {
        LogError("Failed to read block.");
        return nullptr;
    }
    return new btck_Block{std::move(block)};;
}

btck_BlockSpentOutputs* btck_block_spent_outputs_read(btck_ChainstateManager* chainman, const btck_BlockIndex* block_index_)
{
    const auto block_index{cast_const_block_index(block_index_)};

    if (block_index->nHeight < 1) {
        LogDebug(BCLog::KERNEL, "The genesis block does not have any spent outputs.");
        return nullptr;
    }
    auto block_undo{std::make_shared<CBlockUndo>()};
    if (!chainman->m_chainman->m_blockman.ReadBlockUndo(*block_undo, *block_index)) {
        LogError("Failed to read block spent outputs data.");
        return nullptr;
    }
    return new btck_BlockSpentOutputs{std::move(block_undo)};
}

void btck_block_index_destroy(btck_BlockIndex* block_index)
{
    // This is just a dummy function. The user does not control block index memory.
    return;
}

btck_BlockSpentOutputs* btck_block_spent_outputs_copy(const btck_BlockSpentOutputs* block_spent_outputs)
{
    return new btck_BlockSpentOutputs{block_spent_outputs->m_block_undo};
}

uint64_t btck_block_spent_outputs_size(const btck_BlockSpentOutputs* block_spent_outputs)
{
    return block_spent_outputs->m_block_undo->vtxundo.size();
}

btck_TransactionSpentOutputs* btck_block_spent_outputs_get_transaction_spent_outputs_at(const btck_BlockSpentOutputs* block_spent_outputs, uint64_t transaction_index)
{
    assert(transaction_index < block_spent_outputs->m_block_undo->vtxundo.size());
    const auto* tx_undo{&block_spent_outputs->m_block_undo->vtxundo.at(transaction_index)};
    return new btck_TransactionSpentOutputs{tx_undo, false};
}

void btck_block_spent_outputs_destroy(btck_BlockSpentOutputs* block_spent_outputs)
{
    if (!block_spent_outputs) return;
    delete block_spent_outputs;
    block_spent_outputs = nullptr;
}

btck_TransactionSpentOutputs* btck_transaction_spent_outputs_copy(const btck_TransactionSpentOutputs* transaction_spent_outputs)
{
    return new btck_TransactionSpentOutputs{new CTxUndo{*transaction_spent_outputs->m_tx_undo}, true};
}

uint64_t btck_transaction_spent_outputs_size(const btck_TransactionSpentOutputs* transaction_spent_outputs)
{
    return transaction_spent_outputs->m_tx_undo->vprevout.size();
}

void btck_transaction_spent_outputs_destroy(btck_TransactionSpentOutputs* transaction_spent_outputs)
{
    if (!transaction_spent_outputs) return;
    if (transaction_spent_outputs->m_owned) {
        delete transaction_spent_outputs->m_tx_undo;
    }
    delete transaction_spent_outputs;
    transaction_spent_outputs = nullptr;
}

btck_Coin* btck_transaction_spent_outputs_get_coin_at(const btck_TransactionSpentOutputs* transaction_spent_outputs, uint64_t coin_index)
{
    assert(coin_index < transaction_spent_outputs->m_tx_undo->vprevout.size());
    const Coin* coin{&transaction_spent_outputs->m_tx_undo->vprevout.at(coin_index)};
    return new btck_Coin{coin, false};
}

btck_Coin* btck_coin_copy(const btck_Coin* coin)
{
    return new btck_Coin{new Coin{*coin->m_coin}, true};
}

int32_t btck_block_index_get_height(const btck_BlockIndex* block_index_)
{
    auto block_index{cast_const_block_index(block_index_)};
    return block_index->nHeight;
}

btck_BlockHash* btck_block_index_get_block_hash(const btck_BlockIndex* block_index_)
{
    auto block_index{cast_const_block_index(block_index_)};
    if (block_index->phashBlock == nullptr) {
        return nullptr;
    }
    auto block_hash = new btck_BlockHash{};
    std::memcpy(block_hash->hash, block_index->phashBlock->begin(), sizeof(*block_index->phashBlock));
    return block_hash;
}

void btck_block_hash_destroy(btck_BlockHash* hash)
{
    if (hash) delete hash;
    hash = nullptr;
}

uint32_t btck_coin_confirmation_height(const btck_Coin* coin)
{
    return coin->m_coin->nHeight;
}

bool btck_coin_is_coinbase(const btck_Coin* coin)
{
    return coin->m_coin->IsCoinBase();
}

btck_TransactionOutput* btck_coin_get_output(const btck_Coin* coin)
{
    const CTxOut* output{&coin->m_coin->out};
    return new btck_TransactionOutput{output, false};
}

void btck_coin_destroy(btck_Coin* coin)
{
    if (!coin) return;
    if (coin->m_owned) {
        delete coin->m_coin;
    }
    delete coin;
    coin = nullptr;
}

bool btck_chainstate_manager_process_block(
    btck_ChainstateManager* chainman,
    btck_Block* block,
    bool* new_block)
{
    return chainman->m_chainman->ProcessNewBlock(block->m_block, /*force_processing=*/true, /*min_pow_checked=*/true, /*new_block=*/new_block);
}
