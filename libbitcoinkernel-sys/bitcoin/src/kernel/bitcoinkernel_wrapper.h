// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_KERNEL_BITCOINKERNEL_WRAPPER_H
#define BITCOIN_KERNEL_BITCOINKERNEL_WRAPPER_H

#include <kernel/bitcoinkernel.h>

#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

int verify_script(const std::span<const unsigned char> script_pubkey,
                  int64_t amount,
                  const std::span<const unsigned char> tx_to,
                  const std::span<const kernel_TransactionOutput> spent_outputs,
                  unsigned int input_index,
                  unsigned int flags,
                  kernel_ScriptVerifyStatus& status) noexcept
{
    auto spent_outputs_ptr = spent_outputs.size() > 0 ? spent_outputs.data() : nullptr;
    return kernel_verify_script(
        script_pubkey.data(), script_pubkey.size(),
        amount,
        tx_to.data(), tx_to.size(),
        spent_outputs_ptr, spent_outputs.size(),
        input_index,
        flags,
        &status);
}

template <typename T>
concept Log = requires(T a, const char* message) {
    { a.LogMessage(message) } -> std::same_as<void>;
};

template <Log T>
class Logger
{
private:
    struct Deleter {
        void operator()(kernel_LoggingConnection* ptr) const
        {
            kernel_logging_connection_destroy(ptr);
        }
    };

    std::unique_ptr<T> m_log;
    std::unique_ptr<kernel_LoggingConnection, Deleter> m_connection;

public:
    Logger(std::unique_ptr<T> log, const kernel_LoggingOptions& logging_options) noexcept
        : m_log{std::move(log)},
          m_connection{kernel_logging_connection_create(
              [](void* user_data, const char* message) { static_cast<T*>(user_data)->LogMessage(message); },
              m_log.get(),
              logging_options)}
    {
    }

    /** Check whether this Logger object is valid. */
    explicit operator bool() const noexcept { return bool{m_connection}; }
};

template <typename T>
class KernelNotifications
{
private:
    struct Deleter {
        void operator()(const kernel_Notifications* ptr) const
        {
            kernel_notifications_destroy(ptr);
        }
    };

    kernel_NotificationInterfaceCallbacks MakeCallbacks()
    {
        return kernel_NotificationInterfaceCallbacks{
            .user_data = this,
            .block_tip = [](void* user_data, kernel_SynchronizationState state, kernel_BlockIndex* index) {
                static_cast<T*>(user_data)->BlockTipHandler(state, index);
            },
            .header_tip = [](void* user_data, kernel_SynchronizationState state, int64_t height, int64_t timestamp, bool presync) {
                static_cast<T*>(user_data)->HeaderTipHandler(state, height, timestamp, presync);
            },
            .progress = [](void* user_data, const char* title, int progress_percent, bool resume_possible) {
                static_cast<T*>(user_data)->ProgressHandler(title, progress_percent, resume_possible);
            },
            .warning_set = [](void* user_data, kernel_Warning warning, const char* message) {
                static_cast<T*>(user_data)->WarningSetHandler(warning, message);
            },
            .warning_unset = [](void* user_data, kernel_Warning warning) { static_cast<T*>(user_data)->WarningUnsetHandler(warning); },
            .flush_error = [](void* user_data, const char* error) { static_cast<T*>(user_data)->FlushErrorHandler(error); },
            .fatal_error = [](void* user_data, const char* error) { static_cast<T*>(user_data)->FatalErrorHandler(error); },
        };
    }

    std::unique_ptr<const kernel_Notifications, Deleter> m_notifications;

public:
    KernelNotifications() : m_notifications{kernel_notifications_create(MakeCallbacks())} {}

    virtual ~KernelNotifications() = default;

    virtual void BlockTipHandler(kernel_SynchronizationState state, kernel_BlockIndex* index) {}

    virtual void HeaderTipHandler(kernel_SynchronizationState state, int64_t height, int64_t timestamp, bool presync) {}

    virtual void ProgressHandler(const char* title, int progress_percent, bool resume_possible) {}

    virtual void WarningSetHandler(kernel_Warning warning, const char* message) {}

    virtual void WarningUnsetHandler(kernel_Warning warning) {}

    virtual void FlushErrorHandler(const char* error) {}

    virtual void FatalErrorHandler(const char* error) {}

    friend class ContextOptions;
};

class ChainParams
{
private:
    struct Deleter {
        void operator()(const kernel_ChainParameters* ptr) const
        {
            kernel_chain_parameters_destroy(ptr);
        }
    };

    std::unique_ptr<const kernel_ChainParameters, Deleter> m_chain_params;

public:
    ChainParams(kernel_ChainType chain_type) noexcept : m_chain_params{kernel_chain_parameters_create(chain_type)} {}

    friend class ContextOptions;
};

template <typename T>
class TaskRunner
{
private:
    kernel_TaskRunnerCallbacks MakeCallbacks()
    {
        return kernel_TaskRunnerCallbacks{
            .user_data = this,
            .insert = [](void* user_data, kernel_ValidationEvent* event) { static_cast<T*>(user_data)->insert(event); },
            .flush = [](void* user_data) { static_cast<T*>(user_data)->flush(); },
            .size = [](void* user_data) -> unsigned int { return static_cast<T*>(user_data)->size(); },
        };
    }

    struct Deleter {
        void operator()(kernel_TaskRunner* ptr) const
        {
            kernel_task_runner_destroy(ptr);
        }
    };
    const std::unique_ptr<kernel_TaskRunner, Deleter> m_task_runner;

protected:
    virtual void insert(kernel_ValidationEvent* event)
    {
        kernel_execute_event_and_destroy(event);
    }

    virtual void flush() {}

    virtual size_t size() { return 0; }

public:
    TaskRunner() : m_task_runner{kernel_task_runner_create(MakeCallbacks())} {}

    virtual ~TaskRunner() = default;

    friend class ContextOptions;
};

class ContextOptions
{
private:
    struct Deleter {
        void operator()(kernel_ContextOptions* ptr) const
        {
            kernel_context_options_destroy(ptr);
        }
    };

    std::unique_ptr<kernel_ContextOptions, Deleter> m_options;

public:
    ContextOptions() noexcept : m_options{kernel_context_options_create()} {}

    bool SetChainParams(ChainParams& chain_params) const noexcept
    {
        return kernel_context_options_set(
            m_options.get(),
            kernel_ContextOptionType::kernel_CHAIN_PARAMETERS_OPTION,
            chain_params.m_chain_params.get());
    }

    template <typename T>
    bool SetNotifications(KernelNotifications<T>& notifications) const noexcept
    {
        return kernel_context_options_set(
            m_options.get(),
            kernel_ContextOptionType::kernel_NOTIFICATIONS_OPTION,
            notifications.m_notifications.get());
    }

    template <typename T>
    bool SetTaskRunner(TaskRunner<T>& task_runner) const noexcept
    {
        return kernel_context_options_set(
            m_options.get(),
            kernel_ContextOptionType::kernel_TASK_RUNNER_OPTION,
            task_runner.m_task_runner.get());
    }

    friend class Context;
};

class Context
{
private:
    struct Deleter {
        void operator()(kernel_Context* ptr) const
        {
            kernel_context_destroy(ptr);
        }
    };

public:
    std::unique_ptr<kernel_Context, Deleter> m_context;

    Context(ContextOptions& opts) noexcept
        : m_context{kernel_context_create(opts.m_options.get())}
    {
    }

    Context() noexcept
        : m_context{kernel_context_create(ContextOptions{}.m_options.get())}
    {
    }

    /** Check whether this Context object is valid. */
    explicit operator bool() const noexcept { return bool{m_context}; }
};

class UnownedBlock
{
private:
    const kernel_BlockPointer* m_block;

public:
    UnownedBlock(const kernel_BlockPointer* block) noexcept : m_block{block} {}

    UnownedBlock(const UnownedBlock&) = delete;
    UnownedBlock& operator=(const UnownedBlock&) = delete;
    UnownedBlock(UnownedBlock&&) = delete;
    UnownedBlock& operator=(UnownedBlock&&) = delete;

    std::vector<unsigned char> GetBlockData() const noexcept
    {
        auto serialized_block{kernel_copy_block_pointer_data(m_block)};
        std::vector<unsigned char> vec{serialized_block->data, serialized_block->data + serialized_block->size};
        kernel_byte_array_destroy(serialized_block);
        return vec;
    }
};

class BlockValidationState
{
private:
    const kernel_BlockValidationState* m_state;

public:
    BlockValidationState(const kernel_BlockValidationState* state) noexcept : m_state{state} {}

    BlockValidationState(const BlockValidationState&) = delete;
    BlockValidationState& operator=(const BlockValidationState&) = delete;
    BlockValidationState(BlockValidationState&&) = delete;
    BlockValidationState& operator=(BlockValidationState&&) = delete;

    kernel_ValidationMode ValidationMode() const noexcept
    {
        return kernel_get_validation_mode_from_block_validation_state(m_state);
    }

    kernel_BlockValidationResult BlockValidationResult() const noexcept
    {
        return kernel_get_block_validation_result_from_block_validation_state(m_state);
    }
};

template <typename T>
class ValidationInterface
{
private:
    struct Deleter {
        void operator()(kernel_ValidationInterface* ptr) const
        {
            kernel_validation_interface_destroy(ptr);
        }
    };

    const std::unique_ptr<kernel_ValidationInterface, Deleter> m_validation_interface;

public:
    ValidationInterface() noexcept : m_validation_interface{kernel_validation_interface_create(kernel_ValidationInterfaceCallbacks{
                                .user_data = this,
                                .block_checked = [](void* user_data, const kernel_BlockPointer* block, const kernel_BlockValidationState* state) {
                                    static_cast<T*>(user_data)->BlockChecked(UnownedBlock{block}, BlockValidationState{state});
                                },
                            })}
    {
    }

    virtual ~ValidationInterface() = default;

    virtual void BlockChecked(UnownedBlock block, const BlockValidationState state) {}

    bool Register(Context& context) const noexcept
    {
        return kernel_validation_interface_register(context.m_context.get(), m_validation_interface.get());
    }

    bool Unregister(Context& context) const noexcept
    {
        return kernel_validation_interface_unregister(context.m_context.get(), m_validation_interface.get());
    }
};

class ChainstateManagerOptions
{
private:
    struct Deleter {
        void operator()(kernel_ChainstateManagerOptions* ptr) const
        {
            kernel_chainstate_manager_options_destroy(ptr);
        }
    };

    std::unique_ptr<kernel_ChainstateManagerOptions, Deleter> m_options;

public:
    ChainstateManagerOptions(const Context& context, const std::string& data_dir) noexcept
        : m_options{kernel_chainstate_manager_options_create(context.m_context.get(), data_dir.c_str())}
    {
    }

    /** Check whether this ChainstateManagerOptions object is valid. */
    explicit operator bool() const noexcept { return bool{m_options}; }

    friend class ChainMan;
};

class BlockManagerOptions
{
private:
    struct Deleter {
        void operator()(kernel_BlockManagerOptions* ptr) const
        {
            kernel_block_manager_options_destroy(ptr);
        }
    };

    std::unique_ptr<kernel_BlockManagerOptions, Deleter> m_options;

public:
    BlockManagerOptions(const Context& context, const std::string& data_dir) noexcept
        : m_options{kernel_block_manager_options_create(context.m_context.get(), data_dir.c_str())}
    {
    }

    /** Check whether this BlockManagerOptions object is valid. */
    explicit operator bool() const noexcept { return bool{m_options}; }

    friend class ChainMan;
};

class ChainstateLoadOptions
{
private:
    struct Deleter {
        void operator()(kernel_ChainstateLoadOptions* ptr) const
        {
            kernel_chainstate_load_options_destroy(ptr);
        }
    };

    const std::unique_ptr<kernel_ChainstateLoadOptions, Deleter> m_options;

public:
    ChainstateLoadOptions() noexcept
        : m_options{kernel_chainstate_load_options_create()}
    {
    }

    void SetWipeBlockTreeDb(bool wipe_block_tree) const noexcept
    {
        kernel_chainstate_load_options_set(m_options.get(),
                                           kernel_ChainstateLoadOptionType::kernel_WIPE_BLOCK_TREE_DB_CHAINSTATE_LOAD_OPTION,
                                           wipe_block_tree);
    }

    void SetWipeChainstateDb(bool wipe_chainstate) const noexcept
    {
        kernel_chainstate_load_options_set(m_options.get(),
                                           kernel_ChainstateLoadOptionType::kernel_WIPE_CHAINSTATE_DB_CHAINSTATE_LOAD_OPTION,
                                           wipe_chainstate);
    }

    void SetChainstateDbInMemory(bool chainstate_db_in_memory) const noexcept
    {
        kernel_chainstate_load_options_set(m_options.get(),
                                           kernel_ChainstateLoadOptionType::kernel_CHAINSTATE_DB_IN_MEMORY_CHAINSTATE_LOAD_OPTION,
                                           chainstate_db_in_memory);
    }

    void SetBlockTreeDbInMemory(bool block_tree_db_in_memory) const noexcept
    {
        kernel_chainstate_load_options_set(m_options.get(),
                                           kernel_ChainstateLoadOptionType::kernel_BLOCK_TREE_DB_IN_MEMORY_CHAINSTATE_LOAD_OPTION,
                                           block_tree_db_in_memory);
    }

    friend class ChainMan;
};

class Block
{
private:
    struct Deleter {
        void operator()(kernel_Block* ptr) const
        {
            kernel_block_destroy(ptr);
        }
    };

    std::unique_ptr<kernel_Block, Deleter> m_block;

public:
    Block(const std::span<const unsigned char> raw_block) noexcept
        : m_block{kernel_block_create(raw_block.data(), raw_block.size())}
    {
    }

    /** Check whether this Block object is valid. */
    explicit operator bool() const noexcept { return bool{m_block}; }

    Block(kernel_Block* block) noexcept : m_block{block} {}

    std::vector<unsigned char> GetBlockData() const noexcept
    {
        auto serialized_block{kernel_copy_block_data(m_block.get())};
        std::vector<unsigned char> vec{serialized_block->data, serialized_block->data + serialized_block->size};
        kernel_byte_array_destroy(serialized_block);
        return vec;
    }

    friend class ChainMan;
};

struct TransactionOutputDeleter {
    void operator()(kernel_TransactionOutput* ptr) const
    {
        kernel_transaction_output_destroy(ptr);
    }
};

class BlockUndo
{
private:
    struct Deleter {
        void operator()(kernel_BlockUndo* ptr) const
        {
            kernel_block_undo_destroy(ptr);
        }
    };

    const std::unique_ptr<kernel_BlockUndo, Deleter> m_block_undo;

public:
    const uint64_t m_size;

    BlockUndo(kernel_BlockUndo* block_undo) noexcept
        : m_block_undo{block_undo},
          m_size{kernel_block_undo_size(block_undo)}
    {
    }

    BlockUndo(const BlockUndo&) = delete;
    BlockUndo& operator=(const BlockUndo&) = delete;

    uint64_t GetTxOutSize(uint64_t index) const noexcept
    {
        return kernel_get_transaction_undo_size(m_block_undo.get(), index);
    }

    std::unique_ptr<kernel_TransactionOutput, TransactionOutputDeleter> GetTxUndoPrevoutByIndex(
        uint64_t tx_undo_index,
        uint64_t tx_prevout_index) const noexcept
    {
        return std::unique_ptr<kernel_TransactionOutput, TransactionOutputDeleter>(
            kernel_get_undo_output_by_index(m_block_undo.get(), tx_undo_index, tx_prevout_index));
    }
};

struct BlockIndexInfoDeleter {
    void operator()(kernel_BlockIndexInfo* ptr) const
    {
        kernel_block_index_info_destroy(ptr);
    }
};

class BlockIndex
{
private:
    struct Deleter {
        void operator()(kernel_BlockIndex* ptr) const
        {
            kernel_block_index_destroy(ptr);
        }
    };

    std::unique_ptr<kernel_BlockIndex, Deleter> m_block_index;

public:
    BlockIndex(kernel_BlockIndex* block_index) noexcept : m_block_index{block_index} {}

    std::optional<BlockIndex> GetPreviousBlockIndex() const noexcept
    {
        if (!m_block_index) {
            return std::nullopt;
        }
        auto index{kernel_get_previous_block_index(m_block_index.get())};
        if (!index) return std::nullopt;
        return index;
    }

    std::unique_ptr<kernel_BlockIndexInfo, BlockIndexInfoDeleter> GetInfo() const noexcept
    {
        if (!m_block_index) {
            return nullptr;
        }
        return std::unique_ptr<kernel_BlockIndexInfo, BlockIndexInfoDeleter>(kernel_get_block_index_info(m_block_index.get()));
    }

    operator bool() const noexcept
    {
        return m_block_index && m_block_index.get();
    }

    friend class ChainMan;
};

class ChainMan
{
private:
    kernel_ChainstateManager* m_chainman;
    const Context& m_context;

public:
    ChainMan(const Context& context, const ChainstateManagerOptions& chainman_opts, const BlockManagerOptions& blockman_opts) noexcept
        : m_chainman{kernel_chainstate_manager_create(chainman_opts.m_options.get(), blockman_opts.m_options.get(), context.m_context.get())},
          m_context{context}
    {
    }

    /** Check whether this ChainMan object is valid. */
    explicit operator bool() const noexcept { return m_chainman != nullptr; }

    ChainMan(const ChainMan&) = delete;
    ChainMan& operator=(const ChainMan&) = delete;

    bool LoadChainstate(const ChainstateLoadOptions& chainstate_load_opts) const noexcept
    {
        return kernel_chainstate_manager_load_chainstate(m_context.m_context.get(), chainstate_load_opts.m_options.get(), m_chainman);
    }

    bool ImportBlocks(const std::span<const std::string> paths) const noexcept
    {
        std::vector<const char*> c_paths;
        c_paths.reserve(paths.size());
        for (const auto& path : paths) {
            c_paths.push_back(path.c_str());
        }

        return kernel_import_blocks(m_context.m_context.get(), m_chainman, c_paths.data(), c_paths.size());
    }

    bool ProcessBlock(Block& block, kernel_ProcessBlockStatus& status) const noexcept
    {
        return kernel_chainstate_manager_process_block(m_context.m_context.get(), m_chainman, block.m_block.get(), &status);
    }

    BlockIndex GetBlockIndexFromTip() const noexcept
    {
        return kernel_get_block_index_from_tip(m_context.m_context.get(), m_chainman);
    }

    BlockIndex GetBlockIndexFromGenesis() const noexcept
    {
        return kernel_get_block_index_from_genesis(m_context.m_context.get(), m_chainman);
    }

    std::optional<BlockIndex> GetBlockIndexByHeight(int height) const noexcept
    {
        auto index{kernel_get_block_index_by_height(m_context.m_context.get(), m_chainman, height)};
        if (!index) return std::nullopt;
        return index;
    }

    std::optional<BlockIndex> GetNextBlockIndex(BlockIndex& block_index) const noexcept
    {
        auto index{kernel_get_next_block_index(m_context.m_context.get(), block_index.m_block_index.get(), m_chainman)};
        if (!index) return std::nullopt;
        return index;
    }

    std::optional<Block> ReadBlock(BlockIndex& block_index) const noexcept
    {
        auto block{kernel_read_block_from_disk(m_context.m_context.get(), m_chainman, block_index.m_block_index.get())};
        if (!block) return std::nullopt;
        return block;
    }

    std::optional<BlockUndo> ReadBlockUndo(const BlockIndex& block_index) const noexcept
    {
        auto undo{kernel_read_block_undo_from_disk(m_context.m_context.get(), m_chainman, block_index.m_block_index.get())};
        if (!undo) return std::nullopt;
        return undo;
    }

    ~ChainMan()
    {
        kernel_chainstate_manager_destroy(m_chainman, m_context.m_context.get());
    }
};

#endif // BITCOIN_KERNEL_BITCOINKERNEL_WRAPPER_H
