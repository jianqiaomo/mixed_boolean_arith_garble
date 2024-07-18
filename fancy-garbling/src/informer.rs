//! `Informer` runs a fancy computation and learns information from it.

use crate::{
    fancy::{Fancy, FancyInput, FancyReveal, HasModulus},
    FancyArithmetic, FancyBinary, Mod2kArithmetic, WireLabelMod2k,
};
use scuttlebutt::Block;
use std::collections::{HashMap, HashSet};

/// Implements `Fancy`. Used to learn information about a `Fancy` computation in
/// a lightweight way.
pub struct Informer<F: Fancy> {
    /// The underlying fancy object.
    pub underlying: F,
    stats: InformerStats,
    time_stats: TimeStats,
}

/// The statistics revealed by the informer.
#[derive(Clone, Debug)]
pub struct InformerStats {
    garbler_input_moduli: Vec<u16>,
    evaluator_input_moduli: Vec<u16>,
    constants: HashSet<(u16, u16)>,
    outputs: Vec<u16>,
    nadds: usize,
    nsubs: usize,
    ncmuls: usize,
    nmuls: usize,
    nprojs: usize,
    ncompositions: usize,
    ndecompositions: usize,
    nmodqto2k: usize,
    nmod2k_BD: usize,
    nmod2k_BC: usize,
    nciphertexts: usize,
    moduli: HashMap<u16, usize>,
    moduli2k: HashMap<u16, usize>,
}

impl InformerStats {
    /// Number of garbler inputs in the fancy computation.
    pub fn num_garbler_inputs(&self) -> usize {
        self.garbler_input_moduli.len()
    }

    /// Moduli of garbler inputs in the fancy computation.
    pub fn garbler_input_moduli(&self) -> Vec<u16> {
        self.garbler_input_moduli.clone()
    }

    /// Number of evaluator inputs in the fancy computation.
    pub fn num_evaluator_inputs(&self) -> usize {
        self.evaluator_input_moduli.len()
    }

    /// Moduli of evaluator inputs in the fancy computation.
    pub fn evaluator_input_moduli(&self) -> Vec<u16> {
        self.evaluator_input_moduli.clone()
    }

    /// Number of constants in the fancy computation.
    pub fn num_consts(&self) -> usize {
        self.constants.len()
    }

    /// Number of outputs in the fancy computation.
    pub fn num_outputs(&self) -> usize {
        self.outputs.len()
    }

    /// Number of output ciphertexts.
    pub fn num_output_ciphertexts(&self) -> usize {
        self.outputs.iter().map(|&m| m as usize).sum()
    }

    /// Number of additions in the fancy computation.
    pub fn num_adds(&self) -> usize {
        self.nadds
    }

    /// Number of subtractions in the fancy computation.
    pub fn num_subs(&self) -> usize {
        self.nsubs
    }

    /// Number of scalar multiplications in the fancy computation.
    pub fn num_cmuls(&self) -> usize {
        self.ncmuls
    }

    /// Number of multiplications in the fancy computation.
    pub fn num_muls(&self) -> usize {
        self.nmuls
    }

    /// Number of projections in the fancy computation.
    pub fn num_projs(&self) -> usize {
        self.nprojs
    }

    /// Number of bit compositions in the fancy computation.
    pub fn num_compositions(&self) -> usize {
        self.ncompositions
    }

    /// Number of bit decompositions in the fancy computation.
    pub fn num_decompositions(&self) -> usize {
        self.ndecompositions
    }

    /// Number of mod_qto2k in the Mod2kArithmetic computation.
    pub fn num_modqto2k(&self) -> usize {
        self.nmodqto2k
    }

    /// Number of mod2k_bit_decomposition in the Mod2kArithmetic computation.
    pub fn num_mod2k_BD(&self) -> usize {
        self.nmod2k_BD
    }

    /// Number of mod2k_bit_composition in the Mod2kArithmetic computation.
    pub fn num_mod2k_BC(&self) -> usize {
        self.nmod2k_BC
    }

    /// Number of ciphertexts in the fancy computation.
    pub fn num_ciphertexts(&self) -> usize {
        self.nciphertexts
    }
}

impl std::fmt::Display for InformerStats {
    /// Print information about the fancy computation.
    ///
    /// For example, below is the output when run on `circuits/AES-non-expanded.txt`:
    /// ```text
    /// computation info:
    ///   garbler inputs:                  128 // comms cost: 16 Kb
    ///   evaluator inputs:                128 // comms cost: 48 Kb
    ///   outputs:                         128
    ///   output ciphertexts:              256 // comms cost: 32 Kb
    ///   constants:                         1 // comms cost: 0.125 Kb
    ///   additions:                     25124
    ///   subtractions:                   1692
    ///   cmuls:                             0
    ///   projections:                       0
    ///   multiplications:                6800
    ///   compositions:                      0
    ///   decompositions:                    0
    ///   mod_qto2k:                         0
    ///   mod2k_bit_composition:             0
    ///   mod2k_bit_decomposition:           0
    ///   ciphertexts:                   13600 // comms cost: 1.66 Mb (1700.00 Kb)
    ///   total comms cost:            1.75 Mb // 1700.00 Kb
    /// ```
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut total = 0.0;
        writeln!(f, "computation info:")?;
        let comm = self.num_garbler_inputs() as f64 * 128.0 / 1000.0;

        writeln!(
            f,
            "  garbler inputs:     {:16} // communication: {:.3} Kb",
            self.num_garbler_inputs(),
            comm
        )?;
        total += comm;
        // The cost of IKNP is 256 bits for one random and one 128 bit string
        // dependent on the random one. This is for each input bit, so for
        // modulus `q` we need to do `log2(q)` OTs.
        let comm = self.evaluator_input_moduli.iter().fold(0.0, |acc, q| {
            acc + (*q as f64).log2().ceil() * 384.0 / 1000.0
        });

        writeln!(
            f,
            "  evaluator inputs:   {:16} // communication: {:.3} Kb",
            self.num_evaluator_inputs(),
            comm
        )?;
        total += comm;
        let comm = self.num_output_ciphertexts() as f64 * 128.0 / 1000.0;

        writeln!(f, "  outputs:            {:16}", self.num_outputs())?;
        writeln!(
            f,
            "  output ciphertexts: {:16} // communication: {:.3} Kb",
            self.num_output_ciphertexts(),
            comm
        )?;
        total += comm;
        let comm = self.num_consts() as f64 * 128.0 / 1000.0;

        writeln!(
            f,
            "  constants:          {:16} // communication: {:.3} Kb",
            self.num_consts(),
            comm
        )?;
        total += comm;

        writeln!(f, "  additions:          {:16}", self.num_adds())?;
        writeln!(f, "  subtractions:       {:16}", self.num_subs())?;
        writeln!(f, "  cmuls:              {:16}", self.num_cmuls())?;
        writeln!(f, "  projections:        {:16}", self.num_projs())?;
        writeln!(f, "  multiplications:    {:16}", self.num_muls())?;
        writeln!(f, "  compositions:       {:16}", self.num_compositions())?;
        writeln!(f, "  decompositions:     {:16}", self.num_decompositions())?;
        writeln!(f, "  mod_qto2k:          {:16}", self.num_modqto2k())?;
        writeln!(f, "  mod2k_bit_composition: {:12}", self.num_mod2k_BC())?;
        writeln!(f, "  mod2k_bit_decomposition: {:10}", self.num_mod2k_BD())?;
        let cs = self.num_ciphertexts();
        let kb = cs as f64 * 128.0 / 1000.0;
        let mb = kb / 1000.0;
        writeln!(
            f,
            "  ciphertexts:        {:16} // communication: {:.3} Mb ({:.3} Kb)",
            cs, mb, kb
        )?;
        total += kb;

        let mb = total / 1000.0;
        writeln!(f, "  total communication:  {:11.3} Mb", mb)?;
        writeln!(f, "  wire moduli: {:#?}", self.moduli)?;
        writeln!(f, "  wire moduli 2^k: {:#?}", self.moduli2k)?;
        Ok(())
    }
}

/// The time statistics recorded by the informer. Unit is microsecond (us).
#[derive(Clone, Debug)]
pub struct TimeStats {
    nrepeat: usize,
    treceivem: Vec<f32>,
    tencodem: Vec<f32>,
    txor: Vec<f32>,
    tand: Vec<f32>,
    tnegate: Vec<f32>,
    tadds: Vec<f32>,
    tsubs: Vec<f32>,
    tcmuls: Vec<f32>,
    tmuls: Vec<f32>,
    tprojs: Vec<f32>,
    tcompositions: Vec<f32>,
    tdecompositions: Vec<f32>,
    tmodqto2k: Vec<f32>,
    tmod2k_BD: Vec<f32>,
    tmod2k_BC: Vec<f32>,
}

impl std::fmt::Display for TimeStats {
    /// Print the time statistics.
    ///
    /// ```text
    /// time info:
    ///   receive_many total:            0.000 us
    ///   encode_many total:             0.000 us
    ///   xor total:                     0.000 us
    ///   and total:                     0.000 us
    ///   negate total:                  0.000 us
    ///   add total:                     0.000 us
    ///   sub total:                     0.000 us
    ///   cmul total:                    0.000 us
    ///   mul total:                     0.000 us
    ///   proj total:                    0.000 us
    ///   bit_composition total:         0.000 us
    ///   bit_decomposition total:       0.000 us
    ///   mod_qto2k total:               0.000 us
    ///   mod2k_bit_decomposition total: 0.000 us
    ///   mod2k_bit_composition total:   0.000 us
    ///   total:                         0.000 us
    /// ```
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        writeln!(f, "time info under repeat {} times:", self.nrepeat)?;
        writeln!(f,"  {:?}", self.treceivem)?;
        let sum_rec = self.treceivem.iter().sum::<f32>();
        writeln!(f, "  receive_many total:            {:>8} us", sum_rec)?;
        writeln!(f,"  {:?}", self.tencodem)?;
        let sum_enc = self.tencodem.iter().sum::<f32>();
        writeln!(f, "  encode_many total:             {:>8} us", sum_enc)?;
        let enc_rec_total = sum_rec + sum_enc;
        let mut total = 0f32;
        writeln!(f,"  {:?}", self.txor)?;
        let sum = self.txor.iter().sum::<f32>();
        writeln!(f, "  xor total:                     {:>8} us", sum)?;
        total += sum;
        writeln!(f,"  {:?}", self.tand)?;
        let sum = self.tand.iter().sum::<f32>();
        writeln!(f, "  and total:                     {:>8} us", sum)?;
        total += sum;
        writeln!(f,"  {:?}", self.tnegate)?;
        let sum = self.tnegate.iter().sum::<f32>();
        writeln!(f, "  negate total:                  {:>8} us", sum)?;
        total += sum;
        writeln!(f,"  {:?}", self.tadds)?;
        let sum = self.tadds.iter().sum::<f32>();
        writeln!(f, "  add total:                     {:>8} us", sum)?;
        total += sum;
        writeln!(f,"  {:?}", self.tsubs)?;
        let sum = self.tsubs.iter().sum::<f32>();
        writeln!(f, "  sub total:                     {:>8} us", sum)?;
        total += sum;
        writeln!(f,"  {:?}", self.tcmuls)?;
        let sum = self.tcmuls.iter().sum::<f32>();
        writeln!(f, "  cmul total:                    {:>8} us", sum)?;
        total += sum;
        writeln!(f,"  {:?}", self.tmuls)?;
        let sum = self.tmuls.iter().sum::<f32>();
        writeln!(f, "  mul total:                     {:>8} us", sum)?;
        total += sum;
        writeln!(f,"  {:?}", self.tprojs)?;
        let sum = self.tprojs.iter().sum::<f32>();
        writeln!(f, "  proj total:                    {:>8} us", sum)?;
        total += sum;
        writeln!(f,"  {:?}", self.tcompositions)?;
        let sum = self.tcompositions.iter().sum::<f32>();
        writeln!(f, "  bit_composition total:         {:>8} us", sum)?;
        total += sum;
        writeln!(f,"  {:?}", self.tdecompositions)?;
        let sum = self.tdecompositions.iter().sum::<f32>();
        writeln!(f, "  bit_decomposition total:       {:>8} us", sum)?;
        total += sum;
        writeln!(f,"  {:?}", self.tmodqto2k)?;
        let sum = self.tmodqto2k.iter().sum::<f32>();
        writeln!(f, "  mod_qto2k total:               {:>8} us", sum)?;
        total += sum;
        writeln!(f,"  {:?}", self.tmod2k_BD)?;
        let sum = self.tmod2k_BD.iter().sum::<f32>();
        writeln!(f, "  mod2k_bit_decomposition total: {:>8} us", sum)?;
        total += sum;
        writeln!(f,"  {:?}", self.tmod2k_BC)?;
        let sum = self.tmod2k_BC.iter().sum::<f32>();
        writeln!(f, "  mod2k_bit_composition total:   {:>8} us", sum)?;
        total += sum;
        writeln!(f, "  total circuit compute:         {:>8} us", total)?;
        writeln!(f, "  total:                         {:>8} us", enc_rec_total + total)?;
        Ok(())
    }
}

impl<F: Fancy> Informer<F> {
    /// Make a new `Informer`.
    pub fn new(underlying: F) -> Informer<F> {
        Informer {
            underlying,
            stats: InformerStats {
                garbler_input_moduli: Vec::new(),
                evaluator_input_moduli: Vec::new(),
                constants: HashSet::new(),
                outputs: Vec::new(),
                nadds: 0,
                nsubs: 0,
                ncmuls: 0,
                nmuls: 0,
                nprojs: 0,
                ncompositions: 0,
                ndecompositions: 0,
                nmodqto2k: 0,
                nmod2k_BD: 0,
                nmod2k_BC: 0,
                nciphertexts: 0,
                moduli: HashMap::new(),
                moduli2k: HashMap::new(),
            },
            time_stats: TimeStats {
                nrepeat: 1,
                treceivem: Vec::new(),
                tencodem: Vec::new(),
                txor: Vec::new(),
                tand: Vec::new(),
                tnegate: Vec::new(),
                tadds: Vec::new(),
                tsubs: Vec::new(),
                tcmuls: Vec::new(),
                tmuls: Vec::new(),
                tprojs: Vec::new(),
                tcompositions: Vec::new(),
                tdecompositions: Vec::new(),
                tmodqto2k: Vec::new(),
                tmod2k_BD: Vec::new(),
                tmod2k_BC: Vec::new(),
            },
        }
    }

    /// Get the time statistics collected by the `Informer`
    pub fn time_stats(&self) -> TimeStats {
        self.time_stats.clone()
    }

    /// Set the number of repetitions for the time statistics
    pub fn time_stats_set_repeat(&mut self, nrepeat: usize) {
        self.time_stats.nrepeat = nrepeat;
    }

    /// Get the statistics collected by the `Informer`
    pub fn stats(&self) -> InformerStats {
        self.stats.clone()
    }

    fn update_moduli(&mut self, q: u16) {
        let entry = self.stats.moduli.entry(q).or_insert(0);
        *entry += 1;
    }

    /// Update the moduli of wire 2^k
    fn update_moduli2k(&mut self, k: u16) {
        let entry = self.stats.moduli2k.entry(k).or_insert(0);
        *entry += 1;
    }
}

impl<F: Fancy + FancyInput<Item = <F as Fancy>::Item, Error = <F as Fancy>::Error>> FancyInput
    for Informer<F>
{
    type Item = <F as Fancy>::Item;
    type Error = <F as Fancy>::Error;

    fn receive_many(&mut self, moduli: &[u16]) -> Result<Vec<Self::Item>, Self::Error> {
        self.stats
            // .garbler_input_moduli
            .evaluator_input_moduli
            .extend(moduli.iter().cloned());
        let start = SystemTime::now();
        let r = self.underlying.receive_many(moduli);
        let elapsed = start.elapsed().unwrap().as_micros();
        self.time_stats.treceivem.push(elapsed as f32);
        r
    }

    fn encode_many(
        &mut self,
        values: &[u16],
        moduli: &[u16],
    ) -> Result<Vec<Self::Item>, Self::Error> {
        self.stats
            .garbler_input_moduli
            .extend(moduli.iter().cloned());
        let start = SystemTime::now();
        let r = self.underlying.encode_many(values, moduli);
        let elapsed = start.elapsed().unwrap().as_micros();
        self.time_stats.tencodem.push(elapsed as f32);
        r
    }
}

impl<F: FancyBinary> FancyBinary for Informer<F> {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        let start = SystemTime::now();
        let result = (0..self.time_stats.nrepeat)
            .map(|_| self.underlying.xor(x, y))
            .last()
            .unwrap()?;
        let elapsed = start.elapsed().unwrap().as_micros();
        self.time_stats
            .txor
            .push(elapsed as f32 / self.time_stats.nrepeat as f32);
        self.stats.nadds += 1;
        self.update_moduli(x.modulus());
        Ok(result)
    }

    fn and(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        let start = SystemTime::now();
        let result = (0..self.time_stats.nrepeat)
            .map(|_| self.underlying.and(x, y))
            .last()
            .unwrap()?;
        let elapsed = start.elapsed().unwrap().as_micros();
        self.time_stats
            .tand
            .push(elapsed as f32 / self.time_stats.nrepeat as f32);
        self.stats.nmuls += 1;
        self.stats.nciphertexts += 2;
        self.update_moduli(x.modulus());
        Ok(result)
    }

    fn negate(&mut self, x: &Self::Item) -> Result<Self::Item, Self::Error> {
        let start = SystemTime::now();
        let result = (0..self.time_stats.nrepeat)
            .map(|_| self.underlying.negate(x))
            .last()
            .unwrap()?;
        let elapsed = start.elapsed().unwrap().as_micros();
        self.time_stats
            .tnegate
            .push(elapsed as f32 / self.time_stats.nrepeat as f32);

        // Technically only the garbler adds: noop for the evaluator
        self.stats.nadds += 1;
        self.update_moduli(x.modulus());
        Ok(result)
    }
}

impl<F: FancyArithmetic> FancyArithmetic for Informer<F> {
    // In general, for the below, we first check to see if the result succeeds before
    // updating the stats. That way we can avoid checking multiple times that, e.g.
    // the moduli are equal.

    fn add(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        let start = SystemTime::now();
        let result = (0..self.time_stats.nrepeat)
            .map(|_| self.underlying.add(x, y))
            .last()
            .unwrap()?;
        let elapsed = start.elapsed().unwrap().as_micros();
        self.time_stats
            .tadds
            .push(elapsed as f32 / self.time_stats.nrepeat as f32);
        self.stats.nadds += 1;
        self.update_moduli(x.modulus());
        Ok(result)
    }

    fn sub(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        let start = SystemTime::now();
        let result = (0..self.time_stats.nrepeat)
            .map(|_| self.underlying.sub(x, y))
            .last()
            .unwrap()?;
        let elapsed = start.elapsed().unwrap().as_micros();
        self.time_stats
            .tsubs
            .push(elapsed as f32 / self.time_stats.nrepeat as f32);
        self.stats.nsubs += 1;
        self.update_moduli(x.modulus());
        Ok(result)
    }

    fn cmul(&mut self, x: &Self::Item, y: u16) -> Result<Self::Item, Self::Error> {
        let start = SystemTime::now();
        let result = (0..self.time_stats.nrepeat)
            .map(|_| self.underlying.cmul(x, y))
            .last()
            .unwrap()?;
        let elapsed = start.elapsed().unwrap().as_micros();
        self.time_stats
            .tcmuls
            .push(elapsed as f32 / self.time_stats.nrepeat as f32);
        self.stats.ncmuls += 1;
        self.update_moduli(x.modulus());
        Ok(result)
    }

    fn mul(&mut self, x: &Self::Item, y: &Self::Item) -> Result<Self::Item, Self::Error> {
        if x.modulus() < y.modulus() {
            return self.mul(y, x);
        }
        let start = SystemTime::now();
        let result = (0..self.time_stats.nrepeat)
            .map(|_| self.underlying.mul(x, y))
            .last()
            .unwrap()?;
        let elapsed = start.elapsed().unwrap().as_micros();
        self.time_stats
            .tmuls
            .push(elapsed as f32 / self.time_stats.nrepeat as f32);
        self.stats.nmuls += 1;
        self.stats.nciphertexts += x.modulus() as usize + y.modulus() as usize - 2;
        if x.modulus() != y.modulus() {
            // there is an extra ciphertext to support nonequal inputs
            self.stats.nciphertexts += 1;
        }
        self.update_moduli(x.modulus());
        Ok(result)
    }

    fn proj(
        &mut self,
        x: &Self::Item,
        q: u16,
        tt: Option<Vec<u16>>,
    ) -> Result<Self::Item, Self::Error> {
        let start = SystemTime::now();
        let result = (0..self.time_stats.nrepeat)
            .map(|_| self.underlying.proj(x, q, tt.clone()))
            .last()
            .unwrap()?;
        let elapsed = start.elapsed().unwrap().as_micros();
        self.time_stats
            .tprojs
            .push(elapsed as f32 / self.time_stats.nrepeat as f32);
        self.stats.nprojs += 1;
        self.stats.nciphertexts += x.modulus() as usize - 1;
        self.update_moduli(q);
        Ok(result)
    }
}

impl<F: Fancy + Mod2kArithmetic> Mod2kArithmetic for Informer<F> {
    type ItemMod2k = F::ItemMod2k;
    type ErrorMod2k = F::ErrorMod2k;

    fn bit_composition(
        &mut self,
        K_j: &Vec<&Self::Item>,
        p: Option<u16>,
    ) -> Result<Self::Item, Self::Error> {
        let start = SystemTime::now();
        let result = (0..self.time_stats.nrepeat)
            .map(|_| self.underlying.bit_composition(K_j, p))
            .last()
            .unwrap()?;
        let elapsed = start.elapsed().unwrap().as_micros();
        self.time_stats
            .tcompositions
            .push(elapsed as f32 / self.time_stats.nrepeat as f32);
        self.stats.ncompositions += 1;
        self.stats.nciphertexts += K_j.len();
        self.update_moduli(p.unwrap_or(crate::util::a_prime_with_width(K_j.len() as u16)));
        Ok(result)
    }

    fn bit_decomposition(
        &mut self,
        AK: &Self::Item,
        end: Option<u16>,
    ) -> Result<Vec<Self::Item>, Self::Error> {
        let start = SystemTime::now();
        let result = (0..self.time_stats.nrepeat)
            .map(|_| self.underlying.bit_decomposition(AK, end))
            .last()
            .unwrap()?;
        let elapsed = start.elapsed().unwrap().as_micros();
        self.time_stats
            .tdecompositions
            .push(elapsed as f32 / self.time_stats.nrepeat as f32);
        self.stats.ndecompositions += 1;
        self.stats.nciphertexts += result.len() * (AK.modulus() - 1) as usize;
        self.update_moduli(2);
        Ok(result)
    }

    fn mod_qto2k(
        &mut self,
        x: &Self::Item,
        delta2k: Option<&Self::ItemMod2k>,
        k_out: u16,
    ) -> Result<Self::ItemMod2k, Self::ErrorMod2k> {
        let result = self.underlying.mod_qto2k(x, delta2k, k_out)?;
        self.stats.nmodqto2k += 1;
        self.stats.nciphertexts += k_out as usize * (x.modulus() - 1) as usize;
        self.update_moduli2k(k_out);
        Ok(result)
    }

    fn mod2k_bit_decomposition(
        &mut self,
        AK: &Self::ItemMod2k,
        end: Option<u16>,
    ) -> Result<Vec<Self::Item>, Self::ErrorMod2k> {
        let start = SystemTime::now();
        let result = (0..self.time_stats.nrepeat)
            .map(|_| self.underlying.mod2k_bit_decomposition(AK, end))
            .last()
            .unwrap()?;
        let elapsed = start.elapsed().unwrap().as_micros();
        self.time_stats
            .tmod2k_BD
            .push(elapsed as f32 / self.time_stats.nrepeat as f32);
        let k = AK.k();
        let end = end.unwrap_or(k);
        for ith in 0..(end - 1) {
            self.stats.nmodqto2k += 1;
            let k_out = std::cmp::max(k as i16 - ith as i16, 1) as u16;
            self.stats.nciphertexts +=
                k_out as usize * (result[ith as usize].modulus() - 1) as usize;
            self.update_moduli2k(k_out);
        }
        self.stats.nmod2k_BD += 1;
        self.stats.nciphertexts += end as usize;
        self.update_moduli(2);
        Ok(result)
    }

    fn mod2k_bit_composition(
        &mut self,
        K_i: &Vec<&Self::Item>,
        k: Option<u16>,
        c_i: Option<&Vec<u128>>,
    ) -> Result<Self::ItemMod2k, Self::ErrorMod2k> {
        let start = SystemTime::now();
        let result = (0..self.time_stats.nrepeat)
            .map(|_| self.underlying.mod2k_bit_composition(K_i, k, c_i))
            .last()
            .unwrap()?;
        let elapsed = start.elapsed().unwrap().as_micros();
        self.time_stats
            .tmod2k_BC
            .push(elapsed as f32 / self.time_stats.nrepeat as f32);
        let k = k.unwrap_or(K_i.len() as u16);
        for ith in 0..std::cmp::min(k, K_i.len() as u16) {
            self.stats.nmodqto2k += 1;
            self.stats.nciphertexts += k as usize * (K_i[ith as usize].modulus() - 1) as usize;
            self.update_moduli2k(k);
        }
        self.stats.nmod2k_BC += 1;
        self.update_moduli2k(k);
        Ok(result)
    }
}

impl<F: Fancy> Fancy for Informer<F> {
    type Item = F::Item;
    type Error = F::Error;

    fn constant(&mut self, val: u16, q: u16) -> Result<Self::Item, Self::Error> {
        self.stats.constants.insert((val, q));
        self.update_moduli(q);
        self.underlying.constant(val, q)
    }

    fn output(&mut self, x: &Self::Item) -> Result<Option<u16>, Self::Error> {
        let result = self.underlying.output(x)?;
        self.stats.outputs.push(x.modulus());
        Ok(result)
    }
}

impl<F: Fancy + FancyReveal> FancyReveal for Informer<F> {
    fn reveal(&mut self, x: &Self::Item) -> Result<u16, Self::Error> {
        self.stats.outputs.push(x.modulus());
        self.underlying.reveal(x)
    }
}
