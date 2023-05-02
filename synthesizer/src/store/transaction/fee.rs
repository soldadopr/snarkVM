// Copyright (C) 2019-2023 Aleo Systems Inc.
// This file is part of the snarkVM library.

// The snarkVM library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// The snarkVM library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with the snarkVM library. If not, see <https://www.gnu.org/licenses/>.

use crate::{
    atomic_batch_scope,
    cow_to_cloned,
    cow_to_copied,
    process::Fee,
    snark::Proof,
    store::{
        helpers::{Map, MapRead},
        TransitionStorage,
        TransitionStore,
    },
};
use console::network::prelude::*;

use anyhow::Result;
use core::marker::PhantomData;

/// A trait for fee storage.
pub trait FeeStorage<N: Network>: Clone + Send + Sync {
    /// The mapping of `transaction ID` to `(fee transition ID, global state root, proof)`.
    type FeeMap: for<'a> Map<'a, N::TransactionID, (N::TransitionID, N::StateRoot, Option<Proof<N>>)>;
    /// The mapping of `fee transition ID` to `transaction ID`.
    type ReverseFeeMap: for<'a> Map<'a, N::TransitionID, N::TransactionID>;

    /// The transition storage.
    type TransitionStorage: TransitionStorage<N>;

    /// Initializes the fee storage.
    fn open(transition_store: TransitionStore<N, Self::TransitionStorage>) -> Result<Self>;

    /// Returns the fee map.
    fn fee_map(&self) -> &Self::FeeMap;
    /// Returns the reverse fee map.
    fn reverse_fee_map(&self) -> &Self::ReverseFeeMap;
    /// Returns the transition storage.
    fn transition_store(&self) -> &TransitionStore<N, Self::TransitionStorage>;

    /// Returns the optional development ID.
    fn dev(&self) -> Option<u16> {
        self.transition_store().dev()
    }

    /// Starts an atomic batch write operation.
    fn start_atomic(&self) {
        self.fee_map().start_atomic();
        self.reverse_fee_map().start_atomic();
        self.transition_store().start_atomic();
    }

    /// Checks if an atomic batch is in progress.
    fn is_atomic_in_progress(&self) -> bool {
        self.fee_map().is_atomic_in_progress()
            || self.reverse_fee_map().is_atomic_in_progress()
            || self.transition_store().is_atomic_in_progress()
    }

    /// Checkpoints the atomic batch.
    fn atomic_checkpoint(&self) {
        self.fee_map().atomic_checkpoint();
        self.reverse_fee_map().atomic_checkpoint();
        self.transition_store().atomic_checkpoint();
    }

    /// Rewinds the atomic batch to the previous checkpoint.
    fn atomic_rewind(&self) {
        self.fee_map().atomic_rewind();
        self.reverse_fee_map().atomic_rewind();
        self.transition_store().atomic_rewind();
    }

    /// Aborts an atomic batch write operation.
    fn abort_atomic(&self) {
        self.fee_map().abort_atomic();
        self.reverse_fee_map().abort_atomic();
        self.transition_store().abort_atomic();
    }

    /// Finishes an atomic batch write operation.
    fn finish_atomic(&self) -> Result<()> {
        self.fee_map().finish_atomic()?;
        self.reverse_fee_map().finish_atomic()?;
        self.transition_store().finish_atomic()
    }

    /// Stores the given `(transaction ID, fee)` pair into storage.
    fn insert(&self, transaction_id: N::TransactionID, fee: &Fee<N>) -> Result<()> {
        atomic_batch_scope!(self, {
            // Store the fee.
            self.fee_map()
                .insert(transaction_id, (*fee.transition_id(), fee.global_state_root(), fee.proof().cloned()))?;
            self.reverse_fee_map().insert(*fee.transition_id(), transaction_id)?;

            // Store the fee transition.
            self.transition_store().insert(fee)?;

            Ok(())
        })
    }

    /// Removes the fee for the given `transaction ID`.
    fn remove(&self, transaction_id: &N::TransactionID) -> Result<()> {
        // Retrieve the fee transition ID.
        let (transition_id, _, _) = match self.fee_map().get_confirmed(transaction_id)? {
            Some(fee_id) => cow_to_cloned!(fee_id),
            None => bail!("Failed to locate the fee transition ID for transaction '{transaction_id}'"),
        };

        atomic_batch_scope!(self, {
            // Remove the fee.
            self.fee_map().remove(transaction_id)?;
            self.reverse_fee_map().remove(&transition_id)?;

            // Remove the fee transition.
            self.transition_store().remove(&transition_id)?;

            Ok(())
        })
    }

    /// Returns the transaction ID that contains the given `transition ID`.
    fn find_transaction_id_from_transition_id(
        &self,
        transition_id: &N::TransitionID,
    ) -> Result<Option<N::TransactionID>> {
        match self.reverse_fee_map().get_confirmed(transition_id)? {
            Some(transaction_id) => Ok(Some(cow_to_copied!(transaction_id))),
            None => Ok(None),
        }
    }

    /// Returns the fee for the given `transaction ID`.
    fn get_fee(&self, transaction_id: &N::TransactionID) -> Result<Option<Fee<N>>> {
        // Retrieve the fee transition ID.
        let (fee_transition_id, global_state_root, proof) = match self.fee_map().get_confirmed(transaction_id)? {
            Some(fee) => cow_to_cloned!(fee),
            None => return Ok(None),
        };
        // Retrieve the fee transition.
        match self.transition_store().get_transition(&fee_transition_id)? {
            Some(transition) => Ok(Some(Fee::from(transition, global_state_root, proof))),
            None => bail!("Failed to locate the fee transition for transaction '{transaction_id}'"),
        }
    }
}

/// The fee store.
#[derive(Clone)]
pub struct FeeStore<N: Network, F: FeeStorage<N>> {
    /// The fee storage.
    storage: F,
    /// PhantomData.
    _phantom: PhantomData<N>,
}

impl<N: Network, F: FeeStorage<N>> FeeStore<N, F> {
    /// Initializes the fee store.
    pub fn open(transition_store: TransitionStore<N, F::TransitionStorage>) -> Result<Self> {
        // Initialize the fee storage.
        let storage = F::open(transition_store)?;
        // Return the fee store.
        Ok(Self { storage, _phantom: PhantomData })
    }

    /// Initializes a fee store from storage.
    pub fn from(storage: F) -> Self {
        Self { storage, _phantom: PhantomData }
    }

    /// Stores the given `(transaction_id, fee)` into storage.
    pub fn insert(&self, transaction_id: N::TransactionID, fee: &Fee<N>) -> Result<()> {
        self.storage.insert(transaction_id, fee)
    }

    /// Removes the fee for the given `transaction ID`.
    pub fn remove(&self, transaction_id: &N::TransactionID) -> Result<()> {
        self.storage.remove(transaction_id)
    }

    /// Returns the transition store.
    pub fn transition_store(&self) -> &TransitionStore<N, F::TransitionStorage> {
        self.storage.transition_store()
    }

    /// Starts an atomic batch write operation.
    pub fn start_atomic(&self) {
        self.storage.start_atomic();
    }

    /// Checks if an atomic batch is in progress.
    pub fn is_atomic_in_progress(&self) -> bool {
        self.storage.is_atomic_in_progress()
    }

    /// Checkpoints the atomic batch.
    pub fn atomic_checkpoint(&self) {
        self.storage.atomic_checkpoint();
    }

    /// Rewinds the atomic batch to the previous checkpoint.
    pub fn atomic_rewind(&self) {
        self.storage.atomic_rewind();
    }

    /// Aborts an atomic batch write operation.
    pub fn abort_atomic(&self) {
        self.storage.abort_atomic();
    }

    /// Finishes an atomic batch write operation.
    pub fn finish_atomic(&self) -> Result<()> {
        self.storage.finish_atomic()
    }

    /// Returns the optional development ID.
    pub fn dev(&self) -> Option<u16> {
        self.storage.dev()
    }
}

impl<N: Network, F: FeeStorage<N>> FeeStore<N, F> {
    /// Returns the fee for the given `transaction ID`.
    pub fn get_fee(&self, transaction_id: &N::TransactionID) -> Result<Option<Fee<N>>> {
        self.storage.get_fee(transaction_id)
    }
}

impl<N: Network, F: FeeStorage<N>> FeeStore<N, F> {
    /// Returns the transaction ID that deployed the given `transition ID`.
    pub fn find_transaction_id_from_transition_id(
        &self,
        transition_id: &N::TransitionID,
    ) -> Result<Option<N::TransactionID>> {
        self.storage.find_transaction_id_from_transition_id(transition_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{block::Transaction, store::helpers::memory::FeeMemory};

    #[test]
    fn test_insert_get_remove() {
        let rng = &mut TestRng::default();

        // Sample the fee transaction.
        let transaction = crate::vm::test_helpers::sample_fee_transaction(rng);
        let (transaction_id, fee) = match transaction {
            Transaction::Fee(id, fee) => (id, fee),
            _ => unreachable!("sample_fee_transaction should only return fee transactions"),
        };

        // Initialize a new transition store.
        let transition_store = TransitionStore::open(None).unwrap();
        // Initialize a new fee store.
        let fee_store = FeeMemory::open(transition_store).unwrap();

        // Ensure the fee transaction does not exist.
        let candidate = fee_store.get_fee(&transaction_id).unwrap();
        assert_eq!(None, candidate);

        // Insert the fee transaction.
        fee_store.insert(transaction_id, &fee).unwrap();

        // Retrieve the fee.
        let candidate = fee_store.get_fee(&transaction_id).unwrap();
        assert_eq!(Some(fee), candidate);

        // Remove the fee transaction.
        fee_store.remove(&transaction_id).unwrap();

        // Ensure the fee does not exist.
        let candidate = fee_store.get_fee(&transaction_id).unwrap();
        assert_eq!(None, candidate);
    }

    #[test]
    fn test_find_transaction_id() {
        let rng = &mut TestRng::default();

        // Sample the fee transaction.
        let transaction = crate::vm::test_helpers::sample_fee_transaction(rng);
        let (transaction_id, fee) = match transaction {
            Transaction::Fee(id, fee) => (id, fee),
            _ => unreachable!("sample_fee_transaction should only return fee transactions"),
        };
        let fee_transition_id = fee.id();

        // Initialize a new transition store.
        let transition_store = TransitionStore::open(None).unwrap();
        // Initialize a new fee store.
        let fee_store = FeeMemory::open(transition_store).unwrap();

        // Ensure the fee does not exist.
        let candidate = fee_store.get_fee(&transaction_id).unwrap();
        assert_eq!(None, candidate);

        // Ensure the transaction ID is not found.
        let candidate = fee_store.find_transaction_id_from_transition_id(fee_transition_id).unwrap();
        assert_eq!(None, candidate);

        // Insert the fee transaction.
        fee_store.insert(transaction_id, &fee).unwrap();

        // Find the transaction ID.
        let candidate = fee_store.find_transaction_id_from_transition_id(fee_transition_id).unwrap();
        assert_eq!(Some(transaction_id), candidate);

        // Remove the fee transaction.
        fee_store.remove(&transaction_id).unwrap();

        // Ensure the transaction ID is not found.
        let candidate = fee_store.find_transaction_id_from_transition_id(fee_transition_id).unwrap();
        assert_eq!(None, candidate);
    }
}
