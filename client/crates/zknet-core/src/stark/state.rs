//! L2 state: ACCOUNTS balances in a depth-DEPTH Merkle tree of the in-AIR hash.
//! The state root is the tree root, a field element (bytes32 on L1).
//!
//! A batch is a list of transfers, posted to L1 as calldata (the data
//! availability layer): 10 bytes per tx, `from:u8 ‖ to:u8 ‖ amount:u64` big-endian.

use super::field::F;
use super::hash;
use serde::{Deserialize, Serialize};

pub const DEPTH: usize = 7;
pub const ACCOUNTS: usize = 1 << DEPTH;
pub const TX_BYTES: usize = 10;
pub const MAX_BATCH: usize = 16;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Tx {
    pub from: u8,
    pub to: u8,
    pub amount: u64,
}

impl Tx {
    /// The padding tx: account 0 sends 0 to itself.
    pub const NOOP: Tx = Tx { from: 0, to: 0, amount: 0 };
}

pub fn encode_txs(txs: &[Tx]) -> Vec<u8> {
    let mut out = Vec::with_capacity(txs.len() * TX_BYTES);
    for t in txs {
        out.push(t.from);
        out.push(t.to);
        out.extend_from_slice(&t.amount.to_be_bytes());
    }
    out
}

pub fn decode_txs(b: &[u8]) -> Option<Vec<Tx>> {
    if !b.len().is_multiple_of(TX_BYTES) {
        return None;
    }
    Some(
        b.chunks(TX_BYTES)
            .map(|c| Tx { from: c[0], to: c[1], amount: u64::from_be_bytes(c[2..10].try_into().unwrap()) })
            .collect(),
    )
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TxError {
    #[error("account {0} out of range")]
    Account(u8),
    #[error("tx {index}: balance {balance} < amount {amount}")]
    Insufficient { index: usize, balance: u64, amount: u64 },
    #[error("tx {index}: credit overflows u64")]
    Overflow { index: usize },
}

#[derive(Clone, Debug)]
pub struct State {
    pub balances: Vec<u64>,
    /// levels[0] = leaves, levels[DEPTH] = [root]
    levels: Vec<Vec<F>>,
}

impl State {
    pub fn new(balances: Vec<u64>) -> Self {
        assert_eq!(balances.len(), ACCOUNTS);
        let leaves: Vec<F> = balances.iter().map(|b| hash::leaf(F::from(*b))).collect();
        let mut levels = vec![leaves];
        for _ in 0..DEPTH {
            let prev = levels.last().unwrap();
            levels.push(prev.chunks(2).map(|p| hash::node(p[0], p[1])).collect());
        }
        State { balances, levels }
    }

    /// Default genesis: account i holds 1_000_000 * (i + 1).
    pub fn genesis() -> Self {
        Self::new((0..ACCOUNTS as u64).map(|i| 1_000_000 * (i + 1)).collect())
    }

    pub fn root(&self) -> F {
        self.levels[DEPTH][0]
    }

    /// Siblings bottom-up (level 1..=DEPTH): siblings[l-1] is the sibling of the
    /// height-(l-1) node on the path from `acct`.
    pub fn path(&self, acct: usize) -> Vec<F> {
        (0..DEPTH).map(|h| self.levels[h][(acct >> h) ^ 1]).collect()
    }

    pub fn set(&mut self, acct: usize, bal: u64) {
        self.balances[acct] = bal;
        self.levels[0][acct] = hash::leaf(F::from(bal));
        for h in 1..=DEPTH {
            let i = acct >> h;
            self.levels[h][i] = hash::node(self.levels[h - 1][2 * i], self.levels[h - 1][2 * i + 1]);
        }
    }

    /// Applies a batch in order (what the sequencer does before committing).
    pub fn apply(&mut self, txs: &[Tx]) -> Result<(), TxError> {
        for (index, t) in txs.iter().enumerate() {
            for a in [t.from, t.to] {
                if a as usize >= ACCOUNTS {
                    return Err(TxError::Account(a));
                }
            }
            let fb = self.balances[t.from as usize];
            let nb = fb.checked_sub(t.amount).ok_or(TxError::Insufficient { index, balance: fb, amount: t.amount })?;
            self.set(t.from as usize, nb);
            let tb = self.balances[t.to as usize];
            let nt = tb.checked_add(t.amount).ok_or(TxError::Overflow { index })?;
            self.set(t.to as usize, nt);
        }
        Ok(())
    }
}
