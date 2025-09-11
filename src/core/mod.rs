pub mod block;
pub mod block_tree_entry;

pub use block::{
    Block, BlockHash, BlockSpentOutputs, BlockSpentOutputsRef, Coin, CoinRef,
    TransactionSpentOutputs, TransactionSpentOutputsRef,
};
pub use block_tree_entry::BlockTreeEntry;

pub use block::{BlockSpentOutputsExt, CoinExt, TransactionSpentOutputsExt};
