use std::marker::PhantomData;

use crate::{
    check_binary,
    errors::{EvaluatorError, FancyError},
    fancy::{Fancy, FancyReveal},
    hash_wires,
    mod2k::{Mod2kArithmetic, WireLabelMod2k, WireMod2k},
    util::{a_prime_with_width, bits_per_modulus, output_tweak, q2pk, tweak, tweak2},
    wire::WireLabel,
    AllWire, ArithmeticWire, FancyArithmetic, FancyBinary, HasModulus, WireMod2,
};
use scuttlebutt::{AbstractChannel, Block};
use subtle::ConditionallySelectable;

use super::security_warning::warn_proj;

/// Streaming evaluator using a callback to receive ciphertexts as needed.
///
/// Evaluates a garbled circuit on the fly, using messages containing ciphertexts and
/// wires. Parallelizable.
pub struct Evaluator<C, Wire> {
    pub(crate) channel: C,
    current_gate: usize,
    current_output: usize,
    _phantom: PhantomData<Wire>,
}

impl<C: AbstractChannel, Wire: WireLabel> Evaluator<C, Wire> {
    /// Create a new `Evaluator`.
    pub fn new(channel: C) -> Self {
        Evaluator {
            channel,
            current_gate: 0,
            current_output: 0,
            _phantom: PhantomData,
        }
    }

    /// The current non-free gate index of the garbling computation.
    fn current_gate(&mut self) -> usize {
        let current = self.current_gate;
        self.current_gate += 1;
        current
    }

    /// The current output index of the garbling computation.
    fn current_output(&mut self) -> usize {
        let current = self.current_output;
        self.current_output += 1;
        current
    }

    /// Read a Wire from the reader.
    pub fn read_wire(&mut self, modulus: u16) -> Result<Wire, EvaluatorError> {
        let block = self.channel.read_block()?;
        Ok(Wire::from_block(block, modulus))
    }

    /// Evaluates an 'and' gate given two inputs wires and two half-gates from the garbler.
    ///
    /// Outputs C = A & B
    ///
    /// Used internally as a subroutine to implement 'and' gates for `FancyBinary`.
    fn evaluate_and_gate(
        &mut self,
        A: &WireMod2,
        B: &WireMod2,
        gate0: &Block,
        gate1: &Block,
    ) -> WireMod2 {
        let gate_num = self.current_gate();
        let g = tweak2(gate_num as u64, 0);

        let [hashA, hashB] = hash_wires([A, B], g);

        // garbler's half gate
        let L = WireMod2::from_block(
            Block::conditional_select(&hashA, &(hashA ^ *gate0), (A.color() as u8).into()),
            2,
        );

        // evaluator's half gate
        let R = WireMod2::from_block(
            Block::conditional_select(&hashB, &(hashB ^ *gate1), (B.color() as u8).into()),
            2,
        );

        L.plus_mov(&R.plus_mov(&A.cmul(B.color())))
    }
}

impl<C: AbstractChannel> FancyBinary for Evaluator<C, WireMod2> {
    /// Negate is a noop for the evaluator
    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, Self::Error> {
        Ok(*x)
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        Ok(x.plus(y))
    }

    fn and(&mut self, A: &Self::Item, B: &Self::Item) -> Result<Self::Item, Self::Error> {
        let gate0 = self.channel.read_block()?;
        let gate1 = self.channel.read_block()?;
        Ok(self.evaluate_and_gate(A, B, &gate0, &gate1))
    }
}

impl<C: AbstractChannel, Wire: WireLabel> FancyReveal for Evaluator<C, Wire> {
    fn reveal(&mut self, x: &Wire) -> Result<u16, EvaluatorError> {
        let val = self.output(x)?.expect("Evaluator always outputs Some(u16)");
        self.channel.write_u16(val)?;
        self.channel.flush()?;
        Ok(val)
    }
}

impl<C: AbstractChannel> FancyBinary for Evaluator<C, AllWire> {
    /// Overriding `negate` to be a noop: entirely handled on garbler's end
    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, Self::Error> {
        check_binary!(x);

        Ok(x.clone())
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        check_binary!(x);
        check_binary!(y);

        self.add(x, y)
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        if let (AllWire::Mod2(ref A), AllWire::Mod2(ref B)) = (x, y) {
            let gate0 = self.channel.read_block()?;
            let gate1 = self.channel.read_block()?;
            return Ok(AllWire::Mod2(self.evaluate_and_gate(A, B, &gate0, &gate1)));
        }

        // If we got here, one of the wires isn't binary
        check_binary!(x);
        check_binary!(y);

        // Shouldn't be reachable, unless the wire has modulus 2 but is not AllWire::Mod2()
        unreachable!()
    }
}

impl<C: AbstractChannel, Wire: WireLabel + ArithmeticWire> FancyArithmetic for Evaluator<C, Wire> {
    fn add(&mut self, x: &Wire, y: &Wire) -> Result<Wire, EvaluatorError> {
        if x.modulus() != y.modulus() {
            return Err(EvaluatorError::FancyError(FancyError::UnequalModuli));
        }
        Ok(x.plus(y))
    }

    fn sub(&mut self, x: &Wire, y: &Wire) -> Result<Wire, EvaluatorError> {
        if x.modulus() != y.modulus() {
            return Err(EvaluatorError::FancyError(FancyError::UnequalModuli));
        }
        Ok(x.minus(y))
    }

    fn cmul(&mut self, x: &Wire, c: u16) -> Result<Wire, EvaluatorError> {
        Ok(x.cmul(c))
    }

    fn mul(&mut self, A: &Wire, B: &Wire) -> Result<Wire, EvaluatorError> {
        if A.modulus() < B.modulus() {
            return self.mul(B, A);
        }
        let q = A.modulus();
        let qb = B.modulus();
        let unequal = q != qb;
        let ngates = q as usize + qb as usize - 2 + unequal as usize;
        let mut gate = Vec::with_capacity(ngates);
        {
            for _ in 0..ngates {
                let block = self.channel.read_block()?;
                gate.push(block);
            }
        }
        let gate_num = self.current_gate();
        let g = tweak2(gate_num as u64, 0);

        let [hashA, hashB] = hash_wires([A, B], g);

        // garbler's half gate
        let L = if A.color() == 0 {
            Wire::hash_to_mod(hashA, q)
        } else {
            let ct_left = gate[A.color() as usize - 1];
            Wire::from_block(ct_left ^ hashA, q)
        };

        // evaluator's half gate
        let R = if B.color() == 0 {
            Wire::hash_to_mod(hashB, q)
        } else {
            let ct_right = gate[(q + B.color()) as usize - 2];
            Wire::from_block(ct_right ^ hashB, q)
        };

        // hack for unequal mods
        // TODO: Batch this with original hash if unequal.
        let new_b_color = if unequal {
            let minitable = *gate.last().unwrap();
            let ct = u128::from(minitable) >> (B.color() * 16);
            let pt = u128::from(B.hash(tweak2(gate_num as u64, 1))) ^ ct;
            pt as u16
        } else {
            B.color()
        };

        let res = L.plus_mov(&R.plus_mov(&A.cmul(new_b_color)));
        Ok(res)
    }

    fn proj(&mut self, x: &Wire, q: u16, _: Option<Vec<u16>>) -> Result<Wire, EvaluatorError> {
        warn_proj();
        let ngates = (x.modulus() - 1) as usize;
        let mut gate = Vec::with_capacity(ngates);
        for _ in 0..ngates {
            let block = self.channel.read_block()?;
            gate.push(block);
        }
        let t = tweak(self.current_gate());
        if x.color() == 0 {
            Ok(x.hashback(t, q))
        } else {
            let ct = gate[x.color() as usize - 1];
            Ok(Wire::from_block(ct ^ x.hash(t), q))
        }
    }
}

impl<C: AbstractChannel, Wire: WireLabel + ArithmeticWire> Mod2kArithmetic for Evaluator<C, Wire> {
    type ItemMod2k = WireMod2k;
    type ErrorMod2k = EvaluatorError;

    fn bit_decomposition(&mut self, AK: &Wire, end: Option<u16>) -> Result<Vec<Wire>, Self::Error> {
        let q = AK.modulus();
        // bit decomposition takes mod q=p^k where p is in PRIMES. (assuming k=1)
        debug_assert!(1 == q2pk(q).1);
        let p = q2pk(q).0; // let p = q;
        let j = end.unwrap_or(bits_per_modulus(p));

        let l_j = (0..j)
            .map(|_| self.proj(AK, 2, None).unwrap())
            .collect::<Vec<Wire>>();
        Ok(l_j)
    }

    fn bit_composition(
        &mut self,
        K_j: &Vec<&Wire>,
        p: Option<u16>,
    ) -> Result<Wire, EvaluatorError> {
        // Assume all K_j is mod 2 (Boolean)
        debug_assert!(K_j.iter().all(|x| x.modulus() == 2));

        let j = K_j.len();
        // p is output wire prime that is enough to fit j bits
        let p = p.unwrap_or(a_prime_with_width(j as u16));

        let L = K_j
            .iter()
            .map(|K| {
                // let tab: Vec<u16> = (0..2).map(|x| (x << jth) % p).collect();
                self.proj(K, p, None).unwrap()
            })
            .fold(Wire::zero(p), |acc, x| acc.plus(&x));
        Ok(L)
    }

    fn mod_qto2k(
        &mut self,
        x: &Self::Item,
        _: Option<&Self::ItemMod2k>,
        k_out: u16,
        external: bool,
        external_table: Option<&Vec<Block>>,
    ) -> Result<(Self::ItemMod2k, Option<Vec<Block>>), Self::ErrorMod2k> {
        let k = k_out; // let k = delta2k.k();
        let ngates = (x.modulus() - 1) as usize;
        let mut gate = Vec::with_capacity(ngates);
        for nth in 0..ngates {
            let mut blocks = Vec::with_capacity(ngates);
            for ith in 0..k {
                if external {
                    blocks.push(external_table.unwrap()[nth * k as usize + ith as usize]);
                } else {
                    blocks.push(self.channel.read_block()?);
                }
            }
            gate.push(blocks);
        }
        let g = self.current_gate();
        let t = tweak(g);
        let r = if x.color() == 0 {
            WireMod2k::zero(k_out).xor_hash_ofb_back(t, x.as_block())
        } else {
            let ct = gate[x.color() as usize - 1].clone();
            WireMod2k::from_blocks(ct, k_out).xor_hash_ofb_back(t, x.as_block())
        };
        Ok((r, None))
    }

    fn mod2k_bit_composition(
        &mut self,
        K_i: &Vec<&Self::Item>,
        k: Option<u16>,
        _: Option<&Vec<u128>>,
    ) -> Result<Self::ItemMod2k, Self::ErrorMod2k> {
        debug_assert!(K_i.iter().all(|x| x.modulus() == 2));
        let k = k.unwrap_or(K_i.len() as u16); // output WireMod 2^k from k bits

        let Tab = (0..k as usize * std::cmp::min(k as usize, K_i.len()))
            .map(|_| self.channel.read_block().unwrap())
            .collect::<Vec<Block>>();

        // mod 2 to 2^k for each bit, then add them for free
        let L = K_i
            .iter()
            .take(k as usize)
            .enumerate()
            .map(|(ith, &mod2wire)| {
                self.mod_qto2k(
                    mod2wire,
                    None,
                    k,
                    true,
                    Some(&Vec::from(&Tab[ith * k as usize..(ith + 1) * k as usize])),
                )
                .unwrap()
                .0
            })
            .fold(WireMod2k::zero(k), |acc, mod2kwire| acc.plus(&mod2kwire));
        Ok(L)
    }

    fn mod2k_bit_decomposition(
        &mut self,
        AK: &Self::ItemMod2k,
        end: Option<u16>,
    ) -> Result<Vec<Self::Item>, Self::ErrorMod2k> {
        let k = AK.k();
        let end = end.unwrap_or(k);
        let Tab: Vec<Block> = (0..end as usize
            + (0..end - 1)
                .map(|ith| std::cmp::max(k - ith, 1) as usize)
                .sum::<usize>())
            .map(|_| self.channel.read_block().unwrap())
            .collect();
        let mut Tab_idx: usize = 0;
        let gate_num = self.current_gate();

        let mut L_i = AK.clone(); // initial: L^(0)
        let mut lower_l = Vec::with_capacity(end as usize);
        for ith in 0..end {
            let Tab_C_i = [Block::default(), Tab[Tab_idx]];
            Tab_idx += 1;
            let x_bar = L_i.color();
            let right = Tab_C_i[(x_bar & 1) as usize];
            let left = L_i.hash(tweak2(gate_num as u64, ith as u64));
            let lower_l_i = Wire::from_block(left ^ right, 2);

            // miniBC: use K_i[ith] and mod_qto2k to reconstruct D^(i) or L^(i+1)
            if ith < end - 1 {
                let k_out_miniBC = std::cmp::max(k as i16 - ith as i16, 1) as usize;
                let (D_i, _) = self
                    .mod_qto2k(
                        &lower_l_i,
                        None,
                        k_out_miniBC as u16,
                        true,
                        Some(&Vec::from(&Tab[Tab_idx..Tab_idx + k_out_miniBC])),
                    )
                    .unwrap();
                Tab_idx += k_out_miniBC;
                // L^(i+1) = (L^(i) - D^(i)) % 2^{k-i} / 2
                let temp_L_i_next = L_i.minus(&D_i);
                L_i = WireMod2k::new(
                    std::cmp::max(k as i16 - (ith + 1) as i16, 1) as u16,
                    temp_L_i_next.digits().iter().map(|x| x / 2).collect(),
                );
            }

            lower_l.push(lower_l_i);
        }
        Ok(lower_l)
    }
}

impl<C: AbstractChannel, Wire: WireLabel> Fancy for Evaluator<C, Wire> {
    type Item = Wire;
    type Error = EvaluatorError;

    fn constant(&mut self, _: u16, q: u16) -> Result<Wire, EvaluatorError> {
        self.read_wire(q)
    }

    fn output(&mut self, x: &Wire) -> Result<Option<u16>, EvaluatorError> {
        let q = x.modulus();
        let i = self.current_output();

        // Receive the output ciphertext from the garbler
        let ct = self.channel.read_blocks(q as usize)?;

        // Attempt to brute force x using the output ciphertext
        let mut decoded = None;
        for k in 0..q {
            let hashed_wire = x.hash(output_tweak(i, k));
            if hashed_wire == ct[k as usize] {
                decoded = Some(k);
                break;
            }
        }

        if let Some(output) = decoded {
            Ok(Some(output))
        } else {
            Err(EvaluatorError::DecodingFailed)
        }
    }
}
