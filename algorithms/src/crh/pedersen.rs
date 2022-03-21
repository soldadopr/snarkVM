// Copyright (C) 2019-2022 Aleo Systems Inc.
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

use crate::{hash_to_curve::hash_to_curve, CRHError, CRH};
use snarkvm_curves::{AffineCurve, ProjectiveCurve};
use snarkvm_fields::{ConstraintFieldError, Field, ToConstraintField};

use itertools::Itertools;
use std::{borrow::Cow, fmt::Debug};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PedersenCRH<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> {
    pub bases: Vec<Vec<G>>,
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> CRH
    for PedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>
{
    type Output = G::Affine;
    type Parameters = Vec<Vec<G>>;

    fn setup(message: &str) -> Self {
        let (num_windows, window_size) = Self::window();

        let bases = (0..num_windows)
            .map(|index| {
                // Construct an indexed message to attempt to sample a base.
                let (generator, _, _) = hash_to_curve::<G::Affine>(&format!("{message} at {index}"));
                let mut base = generator.into_projective();
                let mut powers = Vec::with_capacity(window_size);
                for _ in 0..window_size {
                    powers.push(base);
                    base.double_in_place();
                }
                powers
            })
            .collect();

        Self { bases }
    }

    fn hash(&self, input: &[bool]) -> Result<Self::Output, CRHError> {
        let (num_windows, window_size) = Self::window();

        let mut input = Cow::Borrowed(input);
        match input.len() <= window_size * num_windows {
            // Pad the input if it is under the required parameter size.
            true => input.to_mut().resize(window_size * num_windows, false),
            // Ensure the input size is within the parameter size,
            false => return Err(CRHError::IncorrectInputLength(input.len(), window_size, num_windows)),
        }

        // Compute sum of h_i^{m_i} for all i.
        Ok(input
            .chunks(window_size)
            .zip_eq(&self.bases)
            .flat_map(|(bits, powers)| {
                bits.iter().zip_eq(powers).flat_map(|(bit, base)| match bit {
                    true => Some(*base),
                    false => None,
                })
            })
            .sum::<G>()
            .into_affine())
    }

    fn parameters(&self) -> &Self::Parameters {
        &self.bases
    }

    fn window() -> (usize, usize) {
        (NUM_WINDOWS, WINDOW_SIZE)
    }
}

impl<F: Field, G: ProjectiveCurve + ToConstraintField<F>, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize>
    ToConstraintField<F> for PedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>
{
    #[inline]
    fn to_field_elements(&self) -> Result<Vec<F>, ConstraintFieldError> {
        Ok(Vec::new())
    }
}
