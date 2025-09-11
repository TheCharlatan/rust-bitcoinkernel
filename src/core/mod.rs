pub mod block;
pub mod block_tree_entry;
pub mod script;
pub mod transaction;
pub mod verify;

pub use block::{
    Block, BlockHash, BlockSpentOutputs, BlockSpentOutputsRef, Coin, CoinRef,
    TransactionSpentOutputs, TransactionSpentOutputsRef,
};
pub use block_tree_entry::BlockTreeEntry;
pub use script::{ScriptPubkey, ScriptPubkeyRef};
pub use transaction::{Transaction, TransactionRef, TxOut, TxOutRef};

pub use block::{BlockSpentOutputsExt, CoinExt, TransactionSpentOutputsExt};
pub use script::ScriptPubkeyExt;
pub use transaction::{TransactionExt, TxOutExt};

pub use verify::{verify, ScriptVerifyError, ScriptVerifyStatus};

pub mod verify_flags {
    pub use super::verify::{
        VERIFY_ALL, VERIFY_ALL_PRE_TAPROOT, VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY,
        VERIFY_DERSIG, VERIFY_NONE, VERIFY_NULLDUMMY, VERIFY_P2SH, VERIFY_TAPROOT, VERIFY_WITNESS,
    };
}
