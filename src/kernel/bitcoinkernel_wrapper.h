// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_BITCOINKERNEL_WRAPPER_H
#define BITCOIN_KERNEL_BITCOINKERNEL_WRAPPER_H

#include <kernel/bitcoinkernel.h>

#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace btck {

class Transaction;
class TransactionOutput;

template <typename T>
T check(T ptr)
{
    if (ptr == nullptr) {
        throw std::runtime_error("failed to instantiate btck object");
    }
    return ptr;
}

template <typename T>
class RefWrapper
{
private:
    T m_ref_data;
public:
    RefWrapper(T&& data) : m_ref_data{std::move(data)} {}

    // Copying this data type might be dangerous, so prohibit it.
    RefWrapper(const RefWrapper&) = delete;
    RefWrapper& operator=(const RefWrapper& other) = delete;

    T& Get()
    {
        return m_ref_data;
    }
};

class ScriptPubkey
{
private:
    struct Deleter {
        void operator()(btck_ScriptPubkey* ptr) const noexcept
        {
            btck_script_pubkey_destroy(ptr);
        }
    };

public:
    std::unique_ptr<btck_ScriptPubkey, Deleter> m_script_pubkey;

    ScriptPubkey(std::span<const unsigned char> script_pubkey)
        : m_script_pubkey{check(btck_script_pubkey_create(script_pubkey.data(), script_pubkey.size()))}
    {
    }

    int Verify(int64_t amount,
               const Transaction& tx_to,
               const std::span<const TransactionOutput> spent_outputs,
               unsigned int input_index,
               unsigned int flags,
               btck_ScriptVerifyStatus& status) const;

    // Copy constructor and assignment
    ScriptPubkey(const ScriptPubkey& other)
        : m_script_pubkey{check(btck_script_pubkey_copy(other.m_script_pubkey.get()))}
    {
    }
    ScriptPubkey& operator=(const ScriptPubkey& other)
    {
        if (this != &other) {
            m_script_pubkey.reset(check(btck_script_pubkey_copy(other.m_script_pubkey.get())));
        }
        return *this;
    }

    ScriptPubkey(btck_ScriptPubkey* script_pubkey)
        : m_script_pubkey{check(script_pubkey)}
    {
    }

    std::vector<unsigned char> GetScriptPubkeyData() const
    {
        auto serialized_data{btck_script_pubkey_copy_data(m_script_pubkey.get())};
        std::vector<unsigned char> vec{serialized_data->data, serialized_data->data + serialized_data->size};
        btck_byte_array_destroy(serialized_data);
        return vec;
    }
};

class TransactionOutput
{
private:
    struct Deleter {
        void operator()(btck_TransactionOutput* ptr) const noexcept
        {
            btck_transaction_output_destroy(ptr);
        }
    };

public:
    std::unique_ptr<btck_TransactionOutput, Deleter> m_transaction_output;

    TransactionOutput(const ScriptPubkey& script_pubkey, int64_t amount)
        : m_transaction_output{check(btck_transaction_output_create(script_pubkey.m_script_pubkey.get(), amount))}
    {
    }

    // Copy constructor and assignment
    TransactionOutput(const TransactionOutput& other)
        : m_transaction_output{check(btck_transaction_output_copy(other.m_transaction_output.get()))} { }
    TransactionOutput& operator=(const TransactionOutput& other)
    {
        if (this != &other) {
            m_transaction_output.reset(check(btck_transaction_output_copy(other.m_transaction_output.get())));
        }
        return *this;
    }

    TransactionOutput(btck_TransactionOutput* transaction_output)
        : m_transaction_output{check(transaction_output)}
    {
    }

    uint64_t GetAmount()
    {
        return btck_transaction_output_get_amount(m_transaction_output.get());
    }

    RefWrapper<ScriptPubkey> GetScriptPubkey()
    {
        return ScriptPubkey{btck_transaction_output_get_script_pubkey(m_transaction_output.get())};
    }
};

class Transaction
{
private:
    struct Deleter {
        void operator()(btck_Transaction* ptr) const noexcept
        {
            btck_transaction_destroy(ptr);
        }
    };

public:
    std::unique_ptr<btck_Transaction, Deleter> m_transaction;

    Transaction(std::span<const unsigned char> raw_transaction)
        : m_transaction{check(btck_transaction_create(raw_transaction.data(), raw_transaction.size()))}
    {
    }

    // Copy constructor and assignment
    Transaction(const Transaction& other)
        : m_transaction{check(btck_transaction_copy(other.m_transaction.get()))} { }
    Transaction& operator=(const Transaction& other)
    {
        if (this != &other) {
            m_transaction.reset(check(btck_transaction_copy(other.m_transaction.get())));
        }
        return *this;
    }

    Transaction(btck_Transaction* transaction)
        : m_transaction{check(transaction)}
    {
    }

    uint64_t CountOutputs()
    {
        return btck_transaction_count_outputs(m_transaction.get());
    }

    uint64_t CountInputs()
    {
        return btck_transaction_count_inputs(m_transaction.get());
    }

    RefWrapper<TransactionOutput> GetOutput(uint64_t index)
    {
        return TransactionOutput{btck_transaction_get_output_at(m_transaction.get(), index)};
    }
};

int ScriptPubkey::Verify(int64_t amount,
                  const Transaction& tx_to,
                  const std::span<const TransactionOutput> spent_outputs,
                  unsigned int input_index,
                  unsigned int flags,
                  btck_ScriptVerifyStatus& status) const
{
    const btck_TransactionOutput** spent_outputs_ptr = nullptr;
    std::vector<const btck_TransactionOutput*> raw_spent_outputs;
    if (spent_outputs.size() > 0) {
        raw_spent_outputs.reserve(spent_outputs.size());

        for (const auto& output : spent_outputs) {
            raw_spent_outputs.push_back(output.m_transaction_output.get());
        }
        spent_outputs_ptr = raw_spent_outputs.data();
    }
    return btck_script_pubkey_verify(
        m_script_pubkey.get(),
        amount,
        tx_to.m_transaction.get(),
        spent_outputs_ptr, spent_outputs.size(),
        input_index,
        flags,
        &status);
}

template <typename T>
concept Log = requires(T a, std::string_view message) {
    { a.LogMessage(message) } -> std::same_as<void>;
};

template <Log T>
class Logger
{
private:
    struct Deleter {
        void operator()(btck_LoggingConnection* ptr) const noexcept
        {
            btck_logging_connection_destroy(ptr);
        }
    };

    std::unique_ptr<T> m_log;
    std::unique_ptr<btck_LoggingConnection, Deleter> m_connection;

public:
    Logger(std::unique_ptr<T> log, const btck_LoggingOptions& logging_options)
        : m_log{std::move(log)},
          m_connection{check(btck_logging_connection_create(
              [](void* user_data, const char* message, size_t message_len) { static_cast<T*>(user_data)->LogMessage({message, message_len}); },
              m_log.get(),
              logging_options))}
    {
    }
};

template <typename T>
class KernelNotifications
{
private:
    btck_NotificationInterfaceCallbacks MakeCallbacks()
    {
        return btck_NotificationInterfaceCallbacks{
            .user_data = this,
            .block_tip = [](void* user_data, btck_SynchronizationState state, const btck_BlockIndex* index, double verification_progress) {
                static_cast<T*>(user_data)->BlockTipHandler(state, index, verification_progress);
            },
            .header_tip = [](void* user_data, btck_SynchronizationState state, int64_t height, int64_t timestamp, bool presync) {
                static_cast<T*>(user_data)->HeaderTipHandler(state, height, timestamp, presync);
            },
            .progress = [](void* user_data, const char* title, size_t title_len, int progress_percent, bool resume_possible) {
                static_cast<T*>(user_data)->ProgressHandler({title, title_len}, progress_percent, resume_possible);
            },
            .warning_set = [](void* user_data, btck_Warning warning, const char* message, size_t message_len) {
                static_cast<T*>(user_data)->WarningSetHandler(warning, {message, message_len});
            },
            .warning_unset = [](void* user_data, btck_Warning warning) { static_cast<T*>(user_data)->WarningUnsetHandler(warning); },
            .flush_error = [](void* user_data, const char* error, size_t error_len) { static_cast<T*>(user_data)->FlushErrorHandler({error, error_len}); },
            .fatal_error = [](void* user_data, const char* error, size_t error_len) { static_cast<T*>(user_data)->FatalErrorHandler({error, error_len}); },
        };
    }

    const btck_NotificationInterfaceCallbacks m_notifications;

public:
    KernelNotifications() : m_notifications{MakeCallbacks()} {}

    virtual ~KernelNotifications() = default;

    virtual void BlockTipHandler(btck_SynchronizationState state, const btck_BlockIndex* index, double verification_progress) {}

    virtual void HeaderTipHandler(btck_SynchronizationState state, int64_t height, int64_t timestamp, bool presync) {}

    virtual void ProgressHandler(std::string_view title, int progress_percent, bool resume_possible) {}

    virtual void WarningSetHandler(btck_Warning warning, std::string_view message) {}

    virtual void WarningUnsetHandler(btck_Warning warning) {}

    virtual void FlushErrorHandler(std::string_view error) {}

    virtual void FatalErrorHandler(std::string_view error) {}

    friend class ContextOptions;
};

struct BlockHashDeleter {
    void operator()(btck_BlockHash* ptr) const
    {
        btck_block_hash_destroy(ptr);
    }
};

class UnownedBlock
{
private:
    const btck_BlockPointer* m_block;

public:
    UnownedBlock(const btck_BlockPointer* block) : m_block{block} {}

    UnownedBlock(const UnownedBlock&) = delete;
    UnownedBlock& operator=(const UnownedBlock&) = delete;
    UnownedBlock(UnownedBlock&&) = delete;
    UnownedBlock& operator=(UnownedBlock&&) = delete;

    std::unique_ptr<btck_BlockHash, BlockHashDeleter> GetHash() const
    {
        return std::unique_ptr<btck_BlockHash, BlockHashDeleter>(btck_block_pointer_get_hash(m_block));
    }

    std::vector<unsigned char> GetBlockData() const
    {
        auto serialized_block{btck_block_pointer_copy_data(m_block)};
        std::vector<unsigned char> vec{serialized_block->data, serialized_block->data + serialized_block->size};
        btck_byte_array_destroy(serialized_block);
        return vec;
    }
};

class BlockValidationState
{
private:
    const btck_BlockValidationState* m_state;

public:
    BlockValidationState(const btck_BlockValidationState* state) : m_state{state} {}

    BlockValidationState(const BlockValidationState&) = delete;
    BlockValidationState& operator=(const BlockValidationState&) = delete;
    BlockValidationState(BlockValidationState&&) = delete;
    BlockValidationState& operator=(BlockValidationState&&) = delete;

    btck_ValidationMode ValidationMode() const
    {
        return btck_block_validation_state_get_validation_mode(m_state);
    }

    btck_BlockValidationResult BlockValidationResult() const
    {
        return btck_block_validation_state_get_block_validation_result(m_state);
    }
};

template <typename T>
class ValidationInterface
{
private:
    const btck_ValidationInterfaceCallbacks m_validation_interface;

public:
    ValidationInterface() : m_validation_interface{btck_ValidationInterfaceCallbacks{
                                .user_data = this,
                                .block_checked = [](void* user_data, const btck_BlockPointer* block, const btck_BlockValidationState* state) {
                                    static_cast<T*>(user_data)->BlockChecked(UnownedBlock{block}, BlockValidationState{state});
                                },
                            }}
    {
    }

    virtual ~ValidationInterface() = default;

    virtual void BlockChecked(UnownedBlock block, const BlockValidationState state) {}

    friend class ContextOptions;
};

class ChainParams
{
private:
    struct Deleter {
        void operator()(btck_ChainParameters* ptr) const noexcept
        {
            btck_chain_parameters_destroy(ptr);
        }
    };

    std::unique_ptr<btck_ChainParameters, Deleter> m_chain_params;

public:
    ChainParams(btck_ChainType chain_type) : m_chain_params{check(btck_chain_parameters_create(chain_type))} {}

    friend class ContextOptions;
};

class ContextOptions
{
private:
    struct Deleter {
        void operator()(btck_ContextOptions* ptr) const noexcept
        {
            btck_context_options_destroy(ptr);
        }
    };

    std::unique_ptr<btck_ContextOptions, Deleter> m_options;

public:
    ContextOptions() : m_options{check(btck_context_options_create())} {}

    void SetChainParams(ChainParams& chain_params) const
    {
        btck_context_options_set_chainparams(m_options.get(), chain_params.m_chain_params.get());
    }

    template <typename T>
    void SetNotifications(KernelNotifications<T>& notifications) const
    {
        btck_context_options_set_notifications(m_options.get(), notifications.m_notifications);
    }

    template <typename T>
    void SetValidationInterface(ValidationInterface<T>& validation_interface) const
    {
        btck_context_options_set_validation_interface(m_options.get(), validation_interface.m_validation_interface);
    }

    friend class Context;
};

class Context
{
private:
    struct Deleter {
        void operator()(btck_Context* ptr) const noexcept
        {
            btck_context_destroy(ptr);
        }
    };

public:
    std::unique_ptr<btck_Context, Deleter> m_context;

    Context(ContextOptions& opts)
        : m_context{check(btck_context_create(opts.m_options.get()))}
    {
    }

    Context()
        : m_context{check(btck_context_create(ContextOptions{}.m_options.get()))}
    {
    }
};

class ChainstateManagerOptions
{
private:
    struct Deleter {
        void operator()(btck_ChainstateManagerOptions* ptr) const noexcept
        {
            btck_chainstate_manager_options_destroy(ptr);
        }
    };

    std::unique_ptr<btck_ChainstateManagerOptions, Deleter> m_options;

public:
    ChainstateManagerOptions(const Context& context, const std::string& data_dir, const std::string& blocks_dir)
        : m_options{check(btck_chainstate_manager_options_create(context.m_context.get(), data_dir.c_str(), data_dir.length(), blocks_dir.c_str(), blocks_dir.length()))}
    {
    }

    void SetWorkerThreads(int worker_threads) const
    {
        btck_chainstate_manager_options_set_worker_threads_num(m_options.get(), worker_threads);
    }

    bool SetWipeDbs(bool wipe_block_tree, bool wipe_chainstate) const
    {
        return btck_chainstate_manager_options_set_wipe_dbs(m_options.get(), wipe_block_tree, wipe_chainstate);
    }

    void SetBlockTreeDbInMemory(bool block_tree_db_in_memory) const
    {
        btck_chainstate_manager_options_set_block_tree_db_in_memory(m_options.get(), block_tree_db_in_memory);
    }

    void SetChainstateDbInMemory(bool chainstate_db_in_memory) const
    {
        btck_chainstate_manager_options_set_chainstate_db_in_memory(m_options.get(), chainstate_db_in_memory);
    }

    friend class ChainMan;
};

class Block
{
private:
    struct Deleter {
        void operator()(btck_Block* ptr) const noexcept
        {
            btck_block_destroy(ptr);
        }
    };

public:
    std::unique_ptr<btck_Block, Deleter> m_block;

    Block(const std::span<const unsigned char> raw_block)
        : m_block{check(btck_block_create(raw_block.data(), raw_block.size()))}
    {
    }

    Block(btck_Block* block) : m_block{check(block)} {}

    // Copy constructor and assignment
    Block(const Block& other)
        : m_block{check(btck_block_copy(other.m_block.get()))} { }
    Block& operator=(const Block& other)
    {
        if (this != &other) {
            m_block.reset(check(btck_block_copy(other.m_block.get())));
        }
        return *this;
    }

    uint64_t CountOutputs()
    {
        return btck_block_count_transactions(m_block.get());
    }

    Transaction GetTransaction(uint64_t index)
    {
        return Transaction{btck_block_get_transaction_at(m_block.get(), index)};
    }

    std::unique_ptr<btck_BlockHash, BlockHashDeleter> GetHash() const
    {
        return std::unique_ptr<btck_BlockHash, BlockHashDeleter>(btck_block_get_hash(m_block.get()));
    }

    std::vector<unsigned char> GetBlockData() const
    {
        auto serialized_block{btck_block_copy_data(m_block.get())};
        std::vector<unsigned char> vec{serialized_block->data, serialized_block->data + serialized_block->size};
        btck_byte_array_destroy(serialized_block);
        return vec;
    }

    friend class ChainMan;
};

class Coin
{
private:
    struct Deleter {
        void operator()(btck_Coin* ptr) const noexcept
        {
            btck_coin_destroy(ptr);
        }
    };

    std::unique_ptr<btck_Coin, Deleter> m_coin;

public:
    Coin(btck_Coin* coin) : m_coin{check(coin)} {}

    // Copy constructor and assignment
    Coin(const Coin& other)
        : m_coin{check(btck_coin_copy(other.m_coin.get()))} { }
    Coin& operator=(const Coin& other)
    {
        if (this != &other) {
            m_coin.reset(check(btck_coin_copy(other.m_coin.get())));
        }
        return *this;
    }

    uint32_t GetConfirmationHeight() const { return btck_coin_confirmation_height(m_coin.get()); }

    bool IsCoinbase() const { return btck_coin_is_coinbase(m_coin.get()); }

    RefWrapper<TransactionOutput> GetOutput() const
    {
        return TransactionOutput{btck_coin_get_output(m_coin.get())};
    }
};

class TransactionSpentOutputs
{
private:
    struct Deleter {
        void operator()(btck_TransactionSpentOutputs* ptr) const noexcept
        {
            btck_transaction_spent_outputs_destroy(ptr);
        }
    };

    std::unique_ptr<btck_TransactionSpentOutputs, Deleter> m_transaction_spent_outputs;

public:
    uint64_t m_size;

    TransactionSpentOutputs(btck_TransactionSpentOutputs* transaction_spent_outputs)
        : m_transaction_spent_outputs{check(transaction_spent_outputs)},
          m_size{btck_transaction_spent_outputs_size(transaction_spent_outputs)}
    {
    }
    // Copy constructor and assignment
    TransactionSpentOutputs(const TransactionSpentOutputs& other)
        : m_transaction_spent_outputs{check(btck_transaction_spent_outputs_copy(other.m_transaction_spent_outputs.get()))},
          m_size{other.m_size}
    {
    }
    TransactionSpentOutputs& operator=(const TransactionSpentOutputs& other)
    {
        if (this != &other) {
            m_transaction_spent_outputs.reset(check(btck_transaction_spent_outputs_copy(other.m_transaction_spent_outputs.get())));
            m_size = btck_transaction_spent_outputs_size(m_transaction_spent_outputs.get());
        }
        return *this;
    }

    RefWrapper<Coin> GetCoin(uint64_t index) const
    {
        return Coin{btck_transaction_spent_outputs_get_coin_at(m_transaction_spent_outputs.get(), index)};
    }
};

class BlockSpentOutputs
{
private:
    struct Deleter {
        void operator()(btck_BlockSpentOutputs* ptr) const noexcept
        {
            btck_block_spent_outputs_destroy(ptr);
        }
    };

    std::unique_ptr<btck_BlockSpentOutputs, Deleter> m_block_spent_outputs;

public:
    uint64_t m_size;

    BlockSpentOutputs(btck_BlockSpentOutputs* block_spent_outputs)
        : m_block_spent_outputs{check(block_spent_outputs)},
          m_size{btck_block_spent_outputs_size(block_spent_outputs)}
    {
    }

    // Copy constructor and assignment
    BlockSpentOutputs(const BlockSpentOutputs& other)
        : m_block_spent_outputs{check(btck_block_spent_outputs_copy(other.m_block_spent_outputs.get()))},
          m_size{other.m_size}
    {
    }
    BlockSpentOutputs& operator=(const BlockSpentOutputs& other)
    {
        if (this != &other) {
            m_block_spent_outputs.reset(check(btck_block_spent_outputs_copy(other.m_block_spent_outputs.get())));
            m_size = btck_block_spent_outputs_size(m_block_spent_outputs.get());
        }
        return *this;
    }

    RefWrapper<TransactionSpentOutputs> GetTxSpentOutputs(uint64_t tx_undo_index) const
    {
        return TransactionSpentOutputs{btck_block_spent_outputs_get_transaction_spent_outputs_at(m_block_spent_outputs.get(), tx_undo_index)};
    }
};

class BlockIndex
{
private:
    struct Deleter {
        void operator()(btck_BlockIndex* ptr) const noexcept
        {
            btck_block_index_destroy(ptr);
        }
    };

    std::unique_ptr<btck_BlockIndex, Deleter> m_block_index;

public:
    BlockIndex(btck_BlockIndex* block_index) : m_block_index{check(block_index)} {}

    std::optional<BlockIndex> GetPreviousBlockIndex() const
    {
        if (!m_block_index) {
            return std::nullopt;
        }
        auto index{btck_block_index_get_previous(m_block_index.get())};
        if (!index) return std::nullopt;
        return index;
    }

    int32_t GetHeight() const
    {
        if (!m_block_index) {
            return -1;
        }
        return btck_block_index_get_height(m_block_index.get());
    }

    std::unique_ptr<btck_BlockHash, BlockHashDeleter> GetHash() const
    {
        if (!m_block_index) {
            return nullptr;
        }
        return std::unique_ptr<btck_BlockHash, BlockHashDeleter>(btck_block_index_get_block_hash(m_block_index.get()));
    }

    friend class ChainMan;
};

class ChainMan
{
private:
    btck_ChainstateManager* m_chainman;

public:
    ChainMan(const Context& context, const ChainstateManagerOptions& chainman_opts)
        : m_chainman{check(btck_chainstate_manager_create(chainman_opts.m_options.get()))}
    {
    }

    ChainMan(const ChainMan&) = delete;
    ChainMan& operator=(const ChainMan&) = delete;

    bool ImportBlocks(const std::span<const std::string> paths) const
    {
        std::vector<const char*> c_paths;
        std::vector<size_t> c_paths_lens;
        c_paths.reserve(paths.size());
        c_paths_lens.reserve(paths.size());
        for (const auto& path : paths) {
            c_paths.push_back(path.c_str());
            c_paths_lens.push_back(path.length());
        }

        return btck_chainstate_manager_import_blocks(m_chainman, c_paths.data(), c_paths_lens.data(), c_paths.size());
    }

    bool ProcessBlock(const Block& block, bool* new_block) const
    {
        return btck_chainstate_manager_process_block(m_chainman, block.m_block.get(), new_block);
    }

    BlockIndex GetBlockIndexFromTip() const
    {
        return btck_block_index_get_tip(m_chainman);
    }

    BlockIndex GetBlockIndexFromGenesis() const
    {
        return btck_block_index_get_genesis(m_chainman);
    }

    BlockIndex GetBlockIndexByHash(btck_BlockHash* block_hash) const
    {
        return btck_block_index_get_by_hash(m_chainman, block_hash);
    }

    std::optional<BlockIndex> GetBlockIndexByHeight(int height) const
    {
        auto index{btck_block_index_get_by_height(m_chainman, height)};
        if (!index) return std::nullopt;
        return index;
    }

    std::optional<BlockIndex> GetNextBlockIndex(BlockIndex& block_index) const
    {
        auto index{btck_block_index_get_next(m_chainman, block_index.m_block_index.get())};
        if (!index) return std::nullopt;
        return index;
    }

    std::optional<Block> ReadBlock(BlockIndex& block_index) const
    {
        auto block{btck_block_read(m_chainman, block_index.m_block_index.get())};
        if (!block) return std::nullopt;
        return block;
    }

    BlockSpentOutputs ReadBlockSpentOutputs(const BlockIndex& block_index) const
    {
        return btck_block_spent_outputs_read(m_chainman, block_index.m_block_index.get());
    }

    ~ChainMan()
    {
        btck_chainstate_manager_destroy(m_chainman);
    }
};

} // namespace btck

#endif // BITCOIN_KERNEL_BITCOINKERNEL_WRAPPER_H
