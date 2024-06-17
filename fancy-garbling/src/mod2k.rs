//! Module containing wire label for modulus `p^k`, here `p` is 2.
//! It is different from `WireModQ` because it needs `k` Blocks.
//! The label vector length is the same as the situation of `WireModQ`
//! but each element is not mod `p` but mod `p^k`.

use crate::util;
use rand::{CryptoRng, Rng, RngCore};
use scuttlebutt::Block;

/// Assuming mod can fit in u128.
/// Need `U256` (vectoreyes) to support larger values.
type U = u128;
const K_MAX: u16 = 128;

/// Representation of a `mod-p^k` wire, here `p = 2`.
///
/// We represent a `mod-p^k` wire alongside a list of `mod-p^k` digits.
///
/// Type `U` can be as large as `u128` to support large moduli of each digit.
/// But when using as the intermediate value in transformation between arithmetic
/// (crt) and boolean, the crt actual value cannot be more than `2^63`.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
// #[cfg_attr(feature = "serde", serde(try_from = "UntrustedWireMod2k"))]
#[derive(Debug, Clone, PartialEq, Default)]
pub struct WireMod2k {
    /// The power of 2. It should be less than `K_MAX` to fit type `U`.
    k: u16,
    /// A list of `mod-2^k` digits.
    ds: Vec<U>, // todo: consider setting U by k to save space.
}

impl WireMod2k {
    fn modulus(&self) -> U {
        if self.k < 1 || self.k >= K_MAX {
            panic!(
                "[WireModpk::modulus] 2's power k = {} must be [1, 128).",
                self.k
            )
        } else {
            1 << self.k
        }
    }

    fn rand<R: CryptoRng + RngCore>(rng: &mut R, k: u16) -> Self {
        if k < 1 || k >= K_MAX {
            panic!("[WireModpk::rand] 2's power k = {} must be [1, 128).", k);
        } else {
            let mask = (1 << k) - 1;
            let ds = (0..util::digits_per_u128(2))
                .map(|_| rng.gen::<U>() & mask)
                .collect();
            Self { k, ds }
        }
    }

    fn rand_delta<R: CryptoRng + Rng>(rng: &mut R, k: u16) -> Self {
        let mut w = Self::rand(rng, k);
        w.ds[0] = 1;
        w
    }

    fn digits(&self) -> Vec<U> {
        self.ds.clone()
    }

    fn color(&self) -> U {
        let color = self.ds[0];
        debug_assert!(color < self.modulus());
        color
    }

    fn plus_eq<'a>(&'a mut self, other: &Self) -> &'a mut Self {
        let q = self.modulus();
        let xs = &mut self.ds;
        let ys = &other.ds;

        // Assuming modulus has to be the same here
        // Will enforce by type system
        //debug_assert_eq!(, ymod);
        debug_assert_eq!(xs.len(), ys.len());
        xs.iter_mut().zip(ys.iter()).for_each(|(x, &y)| {
            let (zp, overflow) = (*x + y).overflowing_sub(q);
            *x = if overflow { *x + y } else { zp }
        });

        self
    }

    fn cmul_eq(&mut self, c: U) -> &mut Self {
        let q = self.modulus();
        let mask = q - 1;
        self.ds.iter_mut().for_each(|d| *d = (*d) * c & mask);
        self
    }

    fn negate_eq(&mut self) -> &mut Self {
        let q = self.modulus();
        self.ds.iter_mut().for_each(|d| {
            if *d > 0 {
                *d = q - *d;
            } else {
                *d = 0;
            }
        });
        self
    }

    fn zero(k: u16) -> Self {
        if k < 1 || k >= K_MAX {
            panic!("[WireModpk::zero] 2's power k = {} must be [1, 128).", k);
        }
        Self {
            k,
            ds: vec![0; util::digits_per_u128(2)],
        }
    }

    fn as_blocks(&self) -> Vec<Block> {
        let k = self.k;
        debug_assert_eq!(self.ds.len(), 128); // a Block is 128 bits.
        let mask = ((1 as U) << k) - 1;
        let mut current: u128 = 0; // can be optimized. vectoreyes: U8x16
        let mut bits_collected = 0;

        let result: Vec<Block> = self
            .ds
            .iter()
            .filter_map(|&num| {
                let bits = num & mask; // Extract the least significant k bits

                if bits_collected + k <= 128 {
                    current |= bits << bits_collected; // Place bits at the correct position
                    bits_collected += k;

                    if bits_collected == 128 {
                        let packed = current;
                        current = 0;
                        bits_collected = 0;
                        Some(Block::from(packed))
                    } else {
                        None
                    }
                } else {
                    let remaining_bits = 128 - bits_collected;
                    current |= (bits & ((1 << remaining_bits) - 1)) << bits_collected; // Fill the remaining bits
                    let packed = current;

                    current = bits >> remaining_bits; // Start a new u128 with the leftover bits
                    bits_collected = k - remaining_bits;

                    Some(Block::from(packed))
                }
            })
            .collect();
        result
    }

    /// Mod each digit by `2` and put into a Block.
    fn mod2_as_block(&self) -> Block {
        let k = self.k;
        if k < 1 || k >= K_MAX {
            panic!(
                "[WireModpk::mod_as_block] 2's power k = {} must be [1, 128).",
                k
            );
        }
        WireMod2k {
            k: 1,
            ds: self.ds.iter().map(|&d| d & 1).collect(),
        }
        .as_blocks()[0]
    }

    fn from_blocks(inp: Vec<Block>, k: u16) -> Self {
        if k < 1 || k >= K_MAX {
            panic!(
                "[WireModpk::from_blocks] 2's power k = {} must be [1, 128).",
                k
            );
        }

        let k_mask = ((1 as U) << k) - 1;

        let mut bits_from_last_block: U = 0;
        let mut bits_from_last_block_size: u16 = 0;

        let ds: Vec<U> = inp
            .iter()
            .flat_map(|&num| {
                let block = U::from(num); // can be optimized. vectoreyes: U8x16
                let mut collected: Vec<U> = Vec::new();

                let total_bits_in_block = 128 + bits_from_last_block_size;
                let num_k_bits_collectable: u16 = total_bits_in_block / k;

                // collect the first k bits
                let k_bits = (bits_from_last_block | (block << bits_from_last_block_size)) & k_mask;
                collected.push(k_bits);

                // collect the remaining num_k_bits_collectable * k bits
                for ith in 1..num_k_bits_collectable {
                    let k_bits = block >> (ith * k - bits_from_last_block_size) & k_mask;
                    collected.push(k_bits);
                }

                // leave the remaining bits for the next block
                bits_from_last_block_size = total_bits_in_block % k;
                if bits_from_last_block_size > 0 {
                    bits_from_last_block = block >> 128 - bits_from_last_block_size;
                } else {
                    bits_from_last_block = 0;
                }

                collected
            })
            .collect();
        Self { k, ds }
    }

    fn hash_to_mod(hash: Block) -> Self {
        Self::from_blocks(vec![hash], 1)
    }
}

////////////////////////////////////////////////////////////////////////////////
// tests
//
//
//

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn WireMod2k_packing() {
        let rng = &mut thread_rng();
        for k in 1..64 {
            for _ in 0..10 {
                let w = WireMod2k::rand(rng, k);
                assert_eq!(w, WireMod2k::from_blocks(w.as_blocks(), k));
            }
        }
    }
}
