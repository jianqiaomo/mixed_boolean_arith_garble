# `Garble Mixed Boolean and Arithmetic Circuits`

This library implements mixed Garbled Circuits (GC), i.e., 
transformations between Boolean and arithmetic 
GC without revealing plaintext values. 

The transformations include bit composition, where Boolean values 
are composed into CRT-arithmetic labels, and bit decomposition, which breaks 
CRT-arithmetic labels down into Boolean values. These methods allow for 
efficient and secure conversions between different types of GC, optimized 
for practical use in privacy-preserving computation.

# Profile

To explore how to use the conversion functions in this library, please refer 
to the examples provided in the `profile` branch. 

These examples will guide you in 
performing operation profiling, including communication and runtime measurements.

# Usage
## Conversion Functions

Here are the main conversion functions you will find in the library `fancy-garbling/src/fancy/crt.rs`:

```rust
fn crt_bit_decomposition(
    &mut self, 
    x: &CrtBundle<Self::Item>
) -> Result<BinaryBundle<Self::Item>, Self::ErrorMod2k>;

fn crt_bit_composition(
    &mut self, 
    x: &BinaryBundle<Self::Item>
) -> Result<CrtBundle<Self::Item>, Self::Error>;
```

An example to run the bit-decomposition function to convert a CRT arithmetic wire to
a Boolean wire is shown at the end.

## Major Changes

Major changes from the original `swanky/fancy-garbling/src`.

This library extends with the following modifications:

- Mixed GC (Conversions) Implementations: `mod2k.rs`, `fancy/crt.rs`, `garble/garbler.rs`, 
`garble/evaluator.rs`, `twopac/semihonest/garbler.rs`, `twopac/semihonest/evaluator.rs`.
- Improving old functions: `fancy.rs`, `fancy/binary.rs`.
- Some Base Operations: `util.rs`.
- Update Result: `informer.rs`, `dummy.rs`.

## Software Requirements

The software requirements remain the same as those in the [swanky library](https://github.com/GaloisInc/swanky).

# Acknowledgments

This work is forked from [swanky (fancy garbling)](https://github.com/GaloisInc/swanky). 

The mixed GC algorithm is based on the paper by Li and Liu (EUROCRYPT 2024), 
_How to Garble Mixed Circuits that Combine Boolean and Arithmetic Computations_.

# License

MIT License.

---

**The example to run the bit-decomposition function:**

```rust
fn run_crt_BD(gb_inputs: Vec<u128>, ev_inputs: Vec<u128>, bitwidth: usize) {
    let (sender, receiver) = unix_channel_pair();
    let n_gb_inputs = gb_inputs.len();
    let n_ev_inputs = ev_inputs.len();
    let mut crt_big_mod = util::modulus_with_width(bitwidth as u32);

    // ************ Garbler ************//
    let handle = std::thread::spawn(move || {
        let rng = AesRng::new();
        let start = SystemTime::now();
        let mut gb =
            Garbler::<UnixChannel, AesRng, OtSender, fancy_garbling::AllWire>::new(sender, rng)
                .unwrap();
        let xs = gb.crt_encode_many(&gb_inputs, crt_big_mod).unwrap();
        let ys = gb.crt_receive_many(n_ev_inputs, crt_big_mod).unwrap();
        let all_arith_values: Vec<&CrtBundle<AllWire>> = xs.iter().chain(ys.iter()).collect();
        let gb_output: Vec<BinaryBundle<AllWire>> = all_arith_values
            .iter()
            .map(|&x| gb.crt_bit_decomposition(x).unwrap())
            .collect();
        let gb_output_reveal: Vec<u128> = gb_output
            .iter()
            .map(|x| gb.bin_reveal(x).unwrap())
            .collect();
        println!("Gb Output: {:?}", gb_output_reveal);
    });

    //************ Evaluator ************//
    let rng = AesRng::new();
    let mut ev =
        Evaluator::<UnixChannel, AesRng, OtReceiver, fancy_garbling::AllWire>::new(receiver, rng)
            .unwrap();
    let xs = ev.crt_receive_many(n_gb_inputs, crt_big_mod).unwrap();
    let ys = ev.crt_encode_many(&ev_inputs, crt_big_mod).unwrap();
    let all_arith_values: Vec<&CrtBundle<AllWire>> = xs.iter().chain(ys.iter()).collect();
    let ev_output: Vec<BinaryBundle<AllWire>> = all_arith_values
        .iter()
        .map(|&x| ev.crt_bit_decomposition(x).unwrap())
        .collect();
    let ev_output_reveal: Vec<u128> = ev_output
        .iter()
        .map(|x| ev.bin_reveal(x).unwrap())
        .collect();
    handle.join().unwrap();
    println!("Ev Output: {:?}", ev_output_reveal);
}
```