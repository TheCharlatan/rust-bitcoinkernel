pub mod block;
pub mod block_tree_entry;
pub mod transaction;

pub use block::{
    Block, BlockHash, BlockSpentOutputs, BlockSpentOutputsRef, Coin, CoinRef,
    TransactionSpentOutputs, TransactionSpentOutputsRef,
};
pub use block_tree_entry::BlockTreeEntry;
pub use transaction::{Transaction, TransactionRef, TxOut, TxOutRef};

pub use block::{BlockSpentOutputsExt, CoinExt, TransactionSpentOutputsExt};
pub use transaction::{TransactionExt, TxOutExt};
