use fancy_garbling::informer::Informer;
use fancy_garbling::util::{factor, modulus_with_width, modulus_with_width_opt};
use fancy_garbling::{
    informer::{GLOBAL_CHANNEL_TIME_EV, GLOBAL_CHANNEL_TIME_GB},
    twopac::semihonest::{Evaluator, Garbler},
    AllWire, BinaryBundle, FancyInput, FancyReveal,
};
use fancy_garbling::{BinaryGadgets, CrtBundle, CrtGadgets, HasModulus, MixCrtBinaryGadgets};
use ocelot::ot::{AlszReceiver as OtReceiver, AlszSender as OtSender};
use scuttlebutt::{unix_channel_pair, AesRng, UnixChannel};
use std::sync::atomic::Ordering;
use std::time::SystemTime;

enum BundleType {
    Binary(BinaryBundle<AllWire>),
    CRT(CrtBundle<AllWire>),
}

/// Repeat a function and take the last result.
/// * `party` - The party number, 0 for Garbler, 1 for Evaluator.
/// * `obj` - The object to call the method on. `gb` or `ev`.
/// * `method` - The method to call. `args` - The arguments to pass to the method.
/// * `repeat_times` - The number of times to repeat the function.
///
/// Returns (the last result, the average microsecond of the function).
macro_rules! time_repeat_and_take_last {
    ($party:expr, $obj:expr, $method:ident($($args:expr),*), $repeat_times:expr) => {{
        match $party {
            0 => {
                GLOBAL_CHANNEL_TIME_GB.store(0, Ordering::Relaxed);
            }
            1 => {
                GLOBAL_CHANNEL_TIME_EV.store(0, Ordering::Relaxed);
            }
            _ => panic!("Invalid party {}", $party),
        }
        let start = SystemTime::now();
        let result  = (0..$repeat_times)
            .map(|_| $obj.$method($($args),*))
            .last()
            .expect("The range should not be empty")
            .unwrap();
        let elapsed = start.elapsed().unwrap().as_micros();
        let channel_time = match $party {
            0 => GLOBAL_CHANNEL_TIME_GB.load(Ordering::Relaxed),
            1 => GLOBAL_CHANNEL_TIME_EV.load(Ordering::Relaxed),
            _ => panic!("Invalid party {}", $party),
        };
        // println!("Party {}, elapsed time: {} us, Channel time: {} us.", $party, elapsed, channel_time);
        (result, (elapsed - channel_time as u128) as f32 / $repeat_times as f32)
    }};
}

macro_rules! bin_encode_or_receive {
    ($party:expr, $enc0rec1:expr, $enc_value:expr, $bitwidth:expr) => {
        if $enc0rec1 == 0 {
            // Garbler
            $party.bin_encode($enc_value, $bitwidth).unwrap()
        } else {
            // Evaluator
            $party.bin_receive($bitwidth).unwrap()
        }
    };
}

macro_rules! crt_encode_or_receive {
    ($party:expr, $enc0rec1:expr, $enc_value:expr, $crt_big_mod:expr) => {
        if $enc0rec1 == 0 {
            // Garbler
            $party.crt_encode($enc_value, $crt_big_mod).unwrap()
        } else {
            // Evaluator
            $party.crt_receive($crt_big_mod).unwrap()
        }
    };
}

macro_rules! run_match_operation {
    ($party:expr, $gb0ev1: expr, $bund_method:expr, $operate:expr, $bitwidth:expr, $crt_big_mod:expr, $repeat:expr) => {{
        match $bund_method {
            "Bin" => {
                assert!($gb0ev1 == 0 || $gb0ev1 == 1, "Invalid party id {}", $gb0ev1);
                let xs = bin_encode_or_receive!($party, $gb0ev1, 5, $bitwidth);
                match $operate {
                    "XOR" => {
                        let ys = bin_encode_or_receive!($party, $gb0ev1 ^ 1, 3, $bitwidth);
                        let r = time_repeat_and_take_last!($gb0ev1, $party, bin_xor(&xs, &ys), $repeat);
                        (BundleType::Binary(r.0), r.1)
                    }
                    "AND" => {
                        let ys = bin_encode_or_receive!($party, $gb0ev1 ^ 1, 3, $bitwidth);
                        let r = time_repeat_and_take_last!($gb0ev1, $party, bin_and(&xs, &ys), $repeat);
                        (BundleType::Binary(r.0), r.1)
                    }
                    "Add" => {
                        let ys = bin_encode_or_receive!($party, $gb0ev1 ^ 1, 3, $bitwidth);
                        let r =
                            time_repeat_and_take_last!($gb0ev1, $party, bin_addition(&xs, &ys), $repeat);
                        (BundleType::Binary(r.0 .0), r.1)
                    }
                    "Sub" => {
                        let ys = bin_encode_or_receive!($party, $gb0ev1 ^ 1, 3, $bitwidth);
                        let r = time_repeat_and_take_last!(
                            $gb0ev1,
                            $party,
                            bin_subtraction(&xs, &ys),
                            $repeat
                        );
                        (BundleType::Binary(r.0 .0), r.1)
                    }
                    "Pub Mul" => {
                        let r = time_repeat_and_take_last!(
                            $gb0ev1,
                            $party,
                            bin_cmul(&xs, 3, $bitwidth),
                            $repeat
                        );
                        (BundleType::Binary(r.0), r.1)
                    }
                    "Pub Exp" => {
                        let r = time_repeat_and_take_last!($gb0ev1, $party, bin_cexp(&xs, 3), $repeat);
                        (BundleType::Binary(r.0), r.1)
                    }
                    "Mul" => {
                        let ys = bin_encode_or_receive!($party, $gb0ev1 ^ 1, 3, $bitwidth);
                        let r = time_repeat_and_take_last!($gb0ev1, $party, bin_mul(&xs, &ys), $repeat);
                        (BundleType::Binary(r.0), r.1)
                    }
                    "Div" => {
                        let ys = bin_encode_or_receive!($party, $gb0ev1 ^ 1, 3, $bitwidth);
                        let r = time_repeat_and_take_last!($gb0ev1, $party, bin_div(&xs, &ys), $repeat);
                        (BundleType::Binary(r.0), r.1)
                    }
                    "Mod" => {
                        let ys = bin_encode_or_receive!($party, $gb0ev1 ^ 1, 3, $bitwidth);
                        let r = time_repeat_and_take_last!($gb0ev1, $party, bin_mod(&xs, &ys), $repeat);
                        (BundleType::Binary(r.0), r.1)
                    }
                    "Mux" => {
                        let ys = bin_encode_or_receive!($party, $gb0ev1 ^ 1, 3, $bitwidth);
                        let r = time_repeat_and_take_last!(
                            $gb0ev1,
                            $party,
                            bin_multiplex(&xs.wires()[0], &xs, &ys),
                            $repeat
                        );
                        (BundleType::Binary(r.0), r.1)
                    }
                    "Geq" => {
                        let ys = bin_encode_or_receive!($party, $gb0ev1 ^ 1, 3, $bitwidth);
                        let r = time_repeat_and_take_last!($gb0ev1, $party, bin_geq(&xs, &ys), $repeat);
                        (BundleType::Binary(BinaryBundle::new(vec![r.0])), r.1)
                    }
                    "Bools to CRT" => {
                        let r = time_repeat_and_take_last!(
                            $gb0ev1,
                            $party,
                            crt_bit_composition(&xs),
                            $repeat
                        );
                        (BundleType::CRT(r.0), r.1)
                    }
                    _ => panic!("Invalid operation {}", $operate),
                }
            }
            "CRT" | "OPT" => {
                let xs = crt_encode_or_receive!($party, $gb0ev1, 5, $crt_big_mod);
                match $operate {
                    "Add" => {
                        let ys = crt_encode_or_receive!($party, $gb0ev1 ^ 1, 3, $crt_big_mod);
                        let r = time_repeat_and_take_last!($gb0ev1, $party, crt_add(&xs, &ys), $repeat);
                        (BundleType::CRT(r.0), r.1)
                    }
                    "Sub" => {
                        let ys = crt_encode_or_receive!($party, $gb0ev1 ^ 1, 3, $crt_big_mod);
                        let r = time_repeat_and_take_last!($gb0ev1, $party, crt_sub(&xs, &ys), $repeat);
                        (BundleType::CRT(r.0), r.1)
                    }
                    "Pub Mul" => {
                        let r = time_repeat_and_take_last!($gb0ev1, $party, crt_cmul(&xs, 3), $repeat);
                        (BundleType::CRT(r.0), r.1)
                    }
                    "Mul" => {
                        let ys = crt_encode_or_receive!($party, $gb0ev1 ^ 1, 3, $crt_big_mod);
                        let r = time_repeat_and_take_last!($gb0ev1, $party, crt_mul(&xs, &ys), $repeat);
                        (BundleType::CRT(r.0), r.1)
                    }
                    "Div" => {
                        let ys = crt_encode_or_receive!($party, $gb0ev1 ^ 1, 3, $crt_big_mod);
                        let r = time_repeat_and_take_last!($gb0ev1, $party, crt_div(&xs, &ys), $repeat);
                        (BundleType::CRT(r.0), r.1)
                    }
                    "Mod" => {
                        let ys = crt_encode_or_receive!($party, $gb0ev1 ^ 1, 3, $crt_big_mod);
                        let r = time_repeat_and_take_last!($gb0ev1, $party, crt_mod(&xs, &ys), $repeat);
                        (BundleType::CRT(r.0), r.1)
                    }
                    "Mux" => {
                        let ys = crt_encode_or_receive!($party, $gb0ev1 ^ 1, 3, $crt_big_mod);
                        let muxb = if $gb0ev1 == 0 {
                            // Garbler
                            $party.encode(1u16, 2).unwrap()
                        } else {
                            // Evaluator
                            $party.receive(2).unwrap()
                        };
                        let r = time_repeat_and_take_last!(
                            $gb0ev1,
                            $party,
                            crt_multiplex(&muxb, &xs, &ys),
                            $repeat
                        );
                        (BundleType::CRT(r.0), r.1)
                    }
                    "Pub Exp" => {
                        let r = time_repeat_and_take_last!($gb0ev1, $party, crt_cexp(&xs, 3), $repeat);
                        (BundleType::CRT(r.0), r.1)
                    }
                    "Pub Mod" => {
                        let modp = xs.wires()[0].modulus();
                        let r = time_repeat_and_take_last!($gb0ev1, $party, crt_rem(&xs, modp), $repeat);
                        (BundleType::CRT(r.0), r.1)
                    }
                    "Geq" => {
                        let ys = crt_encode_or_receive!($party, $gb0ev1 ^ 1, 3, $crt_big_mod);
                        let r = time_repeat_and_take_last!(
                            $gb0ev1,
                            $party,
                            crt_geq(&xs, &ys, "100%"),
                            $repeat
                        );
                        (BundleType::Binary(BinaryBundle::new(vec![r.0])), r.1)
                    }
                    "CRT to Bools" => {
                        let r = time_repeat_and_take_last!(
                            $gb0ev1,
                            $party,
                            crt_bit_decomposition(&xs),
                            $repeat
                        );
                        (BundleType::Binary(r.0), r.1)
                    }
                    _ => panic!("Invalid operation {}", $operate),
                }
            }
            _ => panic!("Invalid bundle method {}", $bund_method),
        }
    }};
}

fn profile_function(repeat: usize) {
    let binary_ops: Vec<&str> = vec![
        // "XOR",
        // "AND",
        // "Add",
        // "Sub",
        // "Pub Mul",
        // "Mul",
        // "Div",
        // "Mod",
        // "Mux",
        "Geq",
        // "Bools to CRT",
        // "Pub Exp",
    ];
    let crt_ops: Vec<&str> = vec![
        // "Add",
        // "Sub",
        // "Pub Mul",
        // "Mul",
        // // "Div", // PMR
        // // "Mod", // PMR
        // "Mux",
        // // "Geq", // PMR
        // "Pub Mod",
        // "Pub Exp",
        // "CRT to Bools",
    ];

    // ************ Profile Start ************//
    for (&bund_method, &ops) in vec!["Bin", "CRT", "OPT"]
        .iter()
        .zip(vec![&binary_ops, &crt_ops.clone(), &crt_ops].iter())
    {
        for bitwidth in (4..=8).step_by(4) {
            for &operate in ops.iter() {
                let (sender, receiver) = unix_channel_pair();
                let crt_big_mod = match bund_method {
                    "CRT" => modulus_with_width(bitwidth as u32),
                    "OPT" => modulus_with_width_opt(bitwidth as u32),
                    "Bin" => 0,
                    _ => panic!("Invalid bund_method {bund_method}"),
                };

                // ************ Garbler ************//
                let handle = std::thread::spawn(move || {
                    let rng = AesRng::new();
                    let mut gb = Informer::new(
                        Garbler::<UnixChannel, AesRng, OtSender, AllWire>::new(sender, rng)
                            .unwrap(),
                    );
                    let (gb_output, gb_microsecond) = run_match_operation!(
                        gb,
                        0,
                        bund_method,
                        operate,
                        bitwidth,
                        crt_big_mod,
                        repeat
                    );
                    let gb_output_reveal = match gb_output {
                        BundleType::Binary(bundle) => gb.bin_reveal(&bundle).unwrap(),
                        BundleType::CRT(bundle) => gb.crt_reveal(&bundle).unwrap(),
                    };
                    print!("Gb Output 5 op 3: {gb_output_reveal}; ");
                    print!(
                        "Bundle {bund_method}{:?}; Bitwidth {bitwidth}; Operate {operate};",
                        {
                            match bund_method {
                                "Bin" => vec![bitwidth as u16],
                                "CRT" | "OPT" => factor(crt_big_mod),
                                _ => panic!("Invalid bundle method {bund_method}"),
                            }
                        }
                    );
                    println!(" Garbling time: {} us;", gb_microsecond);
                    // println!("\n Gb Info: {}", gb.stats());
                });

                //************ Evaluator ************//
                let rng = AesRng::new();
                let mut ev =
                    Evaluator::<UnixChannel, AesRng, OtReceiver, AllWire>::new(receiver, rng)
                        .unwrap();
                let (ev_output, ev_microsecond) = run_match_operation!(
                    ev,
                    1,
                    bund_method,
                    operate,
                    bitwidth,
                    crt_big_mod,
                    repeat
                );
                let ev_output_reveal = match ev_output {
                    BundleType::Binary(bundle) => ev.bin_reveal(&bundle).unwrap(),
                    BundleType::CRT(bundle) => ev.crt_reveal(&bundle).unwrap(),
                };
                handle.join().unwrap();
                print!("Ev Output 5 op 3: {ev_output_reveal}; ");
                print!(
                    "Bundle {bund_method}{:?}; Bitwidth {bitwidth}; Operate {operate};",
                    {
                        match bund_method {
                            "Bin" => vec![bitwidth as u16],
                            "CRT" | "OPT" => factor(crt_big_mod),
                            _ => panic!("Invalid bundle method {bund_method}"),
                        }
                    }
                );
                println!(" Evaluating time: {} us;", ev_microsecond);
            }
        }
    }
}

fn main() {
    let repeat_test = 1024;
    profile_function(repeat_test);
}
