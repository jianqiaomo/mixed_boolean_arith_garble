//! Module containing wire label for modulus `p^k`, here `p` is 2.
//! It is different from `WireModQ` because it needs `k` Blocks.
//! The label vector length is the same as the situation of `WireModQ`
//! but each element is not mod `p` but mod `p^k`.

use crate::errors::FancyError;
use crate::{util, Fancy};
use rand::{CryptoRng, Rng, RngCore};
use scuttlebutt::{Block, AES_HASH};

/// Assuming mod can fit in u128.
/// Need `U256` (vectoreyes) to support larger values.
pub type U = u128;
const K_MAX: u16 = 128;

/// Representation of a `mod-p^k` wire for mixed GC, here `p = 2`.
/// <https://doi.org/10.1007/978-3-031-58751-1_12>.
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

/// Trait implementing a `mod-2^k` wire for mixed GC that can be used for secure computation
/// via garbled circuits. <https://doi.org/10.1007/978-3-031-58751-1_12>.
pub trait WireLabelMod2k: Clone {
    /// Get a random wire label mod `2^k`, with the first digit set to `1`
    fn rand_delta<R: CryptoRng + Rng>(rng: &mut R, k: u16) -> Self;

    /// Get a random wire `mod 2^k`.
    fn rand<R: CryptoRng + RngCore>(rng: &mut R, k: u16) -> Self;

    /// Get the digits of the wire
    fn digits(&self) -> Vec<U>;

    /// Get the color digit of the wire.
    fn color(&self) -> U;

    /// Add another wire digit-wise into this one. Assumes that both wires have
    /// the same modulus.
    fn plus_eq<'a>(&'a mut self, other: &Self) -> &'a mut Self;

    /// Multiply each digit by a constant `c mod 2^k`.
    fn cmul_eq(&mut self, c: U) -> &mut Self;

    /// Negate all the digits mod 2^k.
    fn negate_eq(&mut self) -> &mut Self;

    /// The zero wire with modulus `2^k`
    fn zero(k: u16) -> Self;

    /// Pack the wire into k `Block`s.
    fn as_blocks(&self) -> Vec<Block>;

    /// Pack the wire from k `Block`s.
    fn from_blocks(inp: Vec<Block>, k: u16) -> Self;

    /// Mod each digit by `2` and put into a Block.
    fn mod2_as_block(&self) -> Block;

    /// Subroutine of hashback that converts the hash block into a valid wire of the given
    /// modulus. Also useful when batching hashes ahead of time for later conversion.
    /// Result is a wire with modulus `2`, i.e., `k=1`.
    fn hash_to_mod(hash: Block) -> Self;

    /// Compute the hash of this wire mod `2`, converting the result back to a wire.
    ///
    /// Uses fixed-key AES.
    fn hashback(&self, tweak: Block) -> Self {
        let hash = self.hash(tweak);
        Self::hash_to_mod(hash)
    }

    /// Convert this wire to mod `2` so that it is one Block size,
    /// then compute the hash of this wire.
    ///
    /// Uses fixed-key AES.
    #[inline(never)]
    fn hash(&self, tweak: Block) -> Block {
        AES_HASH.tccr_hash(tweak, self.mod2_as_block())
    }

    /// Negate all the digits `mod 2^k`, consuming it for chained computations.
    fn negate_mov(mut self) -> Self {
        self.negate_eq();
        self
    }

    /// Multiply each digit by a constant `c mod 2^k`, consuming it for chained computations.
    fn cmul_mov(mut self, c: U) -> Self {
        self.cmul_eq(c);
        self
    }

    /// Multiply each digit by a constant `c mod 2^k`, returning a new wire.
    fn cmul(&self, c: U) -> Self {
        self.clone().cmul_mov(c)
    }

    /// Add another wire into this one, consuming it for chained computations.
    fn plus_mov(mut self, other: &Self) -> Self {
        self.plus_eq(other);
        self
    }

    /// Add two wires digit-wise, returning a new wire.
    fn plus(&self, other: &Self) -> Self {
        self.clone().plus_mov(other)
    }

    /// Negate all the digits `mod q`, returning a new wire.
    fn negate(&self) -> Self {
        self.clone().negate_mov()
    }

    /// Subtract a wire from this one, consuming it for chained computations.
    fn minus_mov(mut self, other: &Self) -> Self {
        self.minus_eq(other);
        self
    }

    /// Subtract two wires, returning the result.
    fn minus(&self, other: &Self) -> Self {
        self.clone().minus_mov(other)
    }

    /// Subtract a wire from this one.
    fn minus_eq<'a>(&'a mut self, other: &Self) -> &'a mut Self {
        self.plus_eq(&other.negate());
        self
    }

    /// Compute label % `2^k`, returning a new wire.
    /// Note: this is not computing modulo of the original value.
    fn mask_2k(&self, k: u16) -> Self;

    /// Self OFB_XOR Hash(tweak, wire):
    /// Original hash encryption of the WireModQ is XORed with the WireModQ.
    /// Here we extend the XOR operation to the WireMod2^k in OFB mode.
    ///
    /// k Blocks WireMod2^k label XOR a Block (a WireModQ as encryption key)
    /// in OFB mode, returning a new wire.
    ///
    /// Enc_0 = self_0 XOR hash(tweak, wire);  
    /// Enc_i = self_i XOR hash((self_{i-1} XOR Enc_{i-1}), wire); (i = 1..k)
    ///
    /// * `tweak` - AES hash IV, typically the gate id.
    /// * `wire` - A WireModQ label as encryption key.
    fn xor_hash_ofb_back(&self, tweak: Block, wire: Block) -> Self;

    /// helper: Plaintexts OFB_XOR Hash(tweak, wire).
    /// Original hash encryption of the WireModQ is XORed with the WireModQ.
    /// Here we extend the XOR operation to the WireMod2^k in OFB mode.
    ///
    /// k Blocks WireMod2^k label XOR a Block (a WireModQ as encryption key)
    /// in OFB mode, returning a new wire.
    ///
    /// Enc_0 = Plaintexts_0 XOR hash(tweak, wire);  
    /// Enc_i = Plaintexts_i XOR hash((Plaintexts_{i-1} XOR Enc_{i-1}), wire); (i = 1..k)
    ///
    /// * `plaintext` - Plaintexts to be encrypted.
    /// * `tweak` - AES hash IV, typically the gate id.
    /// * `wire` - A WireModQ label as encryption key.
    fn block_xor_hash_ofb(plaintext: Vec<Block>, tweak: Block, wire: Block) -> Vec<Block> {
        let mut last_cipher_feedback = tweak;
        plaintext
            .iter()
            .map(|&block| {
                let IV = last_cipher_feedback;
                last_cipher_feedback = AES_HASH.tccr_hash(IV, wire);
                last_cipher_feedback ^ block
            })
            .collect::<Vec<Block>>()
    }

    /// Get k of the modulus 2^k.
    fn k(&self) -> u16;
}

impl WireMod2k {
    /// Create a new `mod-2^k` wire with the given `k` and digits.
    pub fn new(k: u16, ds: Vec<U>) -> Self {
        if k < 1 || k >= K_MAX {
            panic!(
                "[WireModpk::new] 2's power k = {} must be [1, {}).",
                k, K_MAX
            );
        }
        Self { k, ds }
    }

    // trait HasModulus return u16 which is not enough for 2^k moduli.
    /// Get the modulus of the wire.
    pub fn modulus(&self) -> U {
        if self.k < 1 || self.k >= K_MAX {
            panic!(
                "[WireModpk::modulus] 2's power k = {} must be [1, {}).",
                self.k, K_MAX
            )
        } else {
            1 << self.k
        }
    }
}

impl WireLabelMod2k for WireMod2k {
    fn rand<R: CryptoRng + RngCore>(rng: &mut R, k: u16) -> Self {
        if k < 1 || k >= K_MAX {
            panic!(
                "[WireModpk::rand] 2's power k = {} must be [1, {}).",
                k, K_MAX
            );
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
        debug_assert_eq!(self.k, other.k); // debug_assert_eq!(xs.len(), ys.len());
        xs.iter_mut().zip(ys.iter()).for_each(|(x, &y)| {
            let (zp, overflow) = (*x + y).overflowing_sub(q);
            *x = if overflow { *x + y } else { zp }
        });

        self
    }

    fn cmul_eq(&mut self, c: U) -> &mut Self {
        let q = self.modulus();
        let mask = q - 1;
        self.ds
            .iter_mut()
            .for_each(|d| *d = (*d).wrapping_mul(c) & mask);
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
            panic!(
                "[WireModpk::zero] 2's power k = {} must be [1, {}).",
                k, K_MAX
            );
        }
        Self {
            k,
            ds: vec![0; util::digits_per_u128(2)],
        }
    }

    fn mask_2k(&self, k: u16) -> Self {
        if k < 1 || k >= K_MAX {
            panic!(
                "[WireModpk::mask_2k] 2's power k = {} must be [1, {}).",
                k, K_MAX
            );
        }
        let mask = (1 << k) - 1;
        let ds = self.digits().iter().map(|&d| d & mask).collect();
        Self { k, ds }
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
                "[WireModpk::mod_as_block] 2's power k = {} must be [1, {}).",
                k, K_MAX
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
                "[WireModpk::from_blocks] 2's power k = {} must be [1, {}).",
                k, K_MAX
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

    fn xor_hash_ofb_back(&self, tweak: Block, wire: Block) -> Self {
        let blocks = self.as_blocks();
        Self::from_blocks(Self::block_xor_hash_ofb(blocks, tweak, wire), self.k())
    }

    fn k(&self) -> u16 {
        self.k
    }
}

/// WireMod2^k arithmetic computation.
/// Used for intermediate values in the mixed GC.
/// <https://doi.org/10.1007/978-3-031-58751-1_12>.
pub trait Mod2kArithmetic: Fancy {
    /// The underlying wire datatype created by an object implementing WireMod2^k.
    type ItemMod2k: WireLabelMod2k;

    /// Errors which may be thrown by the users of Fancy.
    type ErrorMod2k: std::fmt::Debug + std::fmt::Display + std::convert::From<FancyError>;

    /// Modulus change: Project a size of one Block, WireModQ label type `x`.
    /// Resulting wire has modulus `2^k`.
    ///
    /// `delta2k` is only required in bit composition, because the (mini)BC in Z_p^k Bit-Decomposition Gadget
    /// shares the delta mod 2^(k-i) in 0..k-1. We should not use the different / new delta2k in
    /// the bit composition chain operations.
    ///
    /// * `x` - Arithmetic WireModQ (2, 3, or q) wire label.
    /// * `delta2k` - (Only required in BC) WireMod 2^k label type delta. Ignore for evaluator. Ignore
    /// for general proj q to 2^k.
    /// * `k_out` - The power of 2 of the modulus `2^k`.
    fn mod_qto2k(
        &mut self,
        x: &Self::Item,
        delta2k: Option<&Self::ItemMod2k>,
        k_out: u16,
    ) -> Result<Self::ItemMod2k, Self::ErrorMod2k>;

    /// Decompose arithmetic wire mod `2^k` AK into bits.
    /// Returns a vector of wires Mod2.
    /// Link: <https://doi.org/10.1007/978-3-031-58751-1_12>
    ///
    /// * `AK` - Arithmetic wire to be decomposed, modulus `2^k`.
    /// * `end` - End index. Range of bits to be decomposed. Default is all bits. Can be used as `X mod 2^end`.
    fn mod2k_bit_decomposition(
        &mut self,
        AK: &Self::ItemMod2k,
        end: Option<u16>,
    ) -> Result<Vec<Self::Item>, Self::ErrorMod2k>;

    /// Compose WireMod2 into arithmetic wire. Returns wire in mod 2^k.
    /// Link: <https://doi.org/10.1007/978-3-031-58751-1_12>
    ///
    /// * `K_i` - Vector of WireMod2 to be composed into arithmetic wire.
    /// * `k` - Take first `k` elements of `K_i`, thus output power of 2 of the modulus `2^k`. Default is `K_i.len()`.
    /// * `c_i` - Optional for linear BC. The constants to be multiplied with the bits.
    fn mod2k_bit_composition(
        &mut self,
        K_i: &Vec<&Self::Item>,
        k: Option<u16>,
        c_i: Option<&Vec<u128>>,
    ) -> Result<Self::ItemMod2k, Self::ErrorMod2k>;

    /// Compute `div*_{N}(x)` in <https://doi.org/10.1007/978-3-031-58751-1_12>.
    /// Not a free operation.
    ///
    /// div: ⌊x/N⌋ can be represented as ⌊(mx) % 2^(2k+1) / 2^(k+k_E)⌋ for x < 2^k.
    ///
    /// * `x` - The dividend WireMod2k label.
    /// * `N` - The divisor, a public constant.
    /// * `limited_x` - Set to `true` only if `x` of mod 2^k is known limited in range
    /// `[0, ⌊k/2⌋)`, avoid to extend `x` to 2^(2k+1).
    fn cdiv(
        &mut self,
        x: &Self::ItemMod2k,
        N: U,
        limited_x: bool,
    ) -> Result<Self::ItemMod2k, Self::ErrorMod2k> {
        let (k, twok1): (u16, u16) = if limited_x {
            if x.k() & 1 == 1 {
                (x.k() / 2, x.k())
            } else {
                (x.k() / 2 - 1, x.k())
            }
        } else {
            (x.k(), 2 * x.k() + 1)
        };

        if N == 0 {
            // todo: N == 1, N >= (1 << k)
            panic!("[Mod2kArithmetic::cdiv] div N = {} not allowed.", N);
        } else {
            let num_bits = |value: u128| -> u16 {
                if value == 0 {
                    return 0;
                }
                (128 - value.leading_zeros()) as u16
            };
            let k_E = num_bits(N);
            let m = (((1 as U) << (k + k_E)) as U + N - 1) / N; // m = ceil(2^(k+k_E) / N), m >= 2^k

            let mx = if limited_x {
                x.cmul(m)
            } else {
                // extend x from 2^k to 2^(2k+1) label
                let x_bits = self.mod2k_bit_decomposition(x, None)?;
                let x_2k_1 = self.mod2k_bit_composition(
                    &x_bits.iter().map(|w| w).collect::<Vec<&Self::Item>>(),
                    Some(twok1),
                    None,
                )?;
                x_2k_1.cmul(m)
            };
            let mx_2k_1 = self.mod2k_bit_decomposition(&mx, None)?; // end: Some(2 * k + 1).
            let mx_2k_1_div_2_k_k_E = mx_2k_1 // mx mod 2^(2k+1) / 2^(k+k_E)
                .iter()
                .skip((k + k_E) as usize)
                .map(|w| w)
                .collect::<Vec<&Self::Item>>();
            let r = self.mod2k_bit_composition(&mx_2k_1_div_2_k_k_E, Some(x.k()), None)?;
            Ok(r)
        }
    }

    /// Compute `mod*_{N}(x)` in <https://doi.org/10.1007/978-3-031-58751-1_12>.
    /// Not a free operation.
    ///
    /// mod: `x % N` can be represented as `x - N * div*_{N}(x)` for x < 2^⌊k/2⌋.
    ///
    /// * `x` - The dividend WireMod2k label.
    /// * `N` - The modulus, a public constant.
    /// * `limited_x` - Set to `true` only if `x` of mod 2^k is known limited in range
    /// `[0, ⌊k/2⌋)`, avoid to extend `x` to 2^(2k+1).
    fn cmod(
        &mut self,
        x: &Self::ItemMod2k,
        N: U,
        limited_x: bool,
    ) -> Result<Self::ItemMod2k, Self::ErrorMod2k> {
        let k = x.k();
        if N == 0 || N == 1 {
            panic!("[Mod2kArithmetic::cmod] mod N = {} not allowed.", N);
        } else if N >= (1 << k) {
            Ok(x.clone())
        } else {
            let div = self.cdiv(x, N, limited_x)?;
            let N_div = div.cmul(N);
            let r = x.minus(&N_div);
            Ok(r)
        }
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
