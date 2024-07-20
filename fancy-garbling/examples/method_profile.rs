use fancy_garbling::informer::Informer;
use fancy_garbling::util;
use fancy_garbling::{
    informer::{GLOBAL_CHANNEL_TIME_EV, GLOBAL_CHANNEL_TIME_GB},
    twopac::semihonest::{Evaluator, Garbler},
    AllWire, BinaryBundle, FancyInput, FancyReveal,
};
use fancy_garbling::{BinaryGadgets, CrtBundle, CrtGadgets, MixCrtBinaryGadgets};
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

fn profile_function(repeat: usize) {
    let binary_ops = vec![
        "XOR",
        "AND",
        "Add",
        "Sub",
        "Pub Mul",
        "Mul",
        "Div",
        "Mod",
        "Mux",
        "Geq",
        "Bools to CRT",
    ];
    let crt_ops = vec![
        "Add",
        "Sub",
        "Pub Mul",
        "Mul",
        "Div", // PMR
        "Mod", // PMR
        "Pub Mod",
        "Mux",
        "Geq", // PMR
        "Pub Exp",
        "CRT to Bools",
    ];

    for (&bund_method, &ops) in vec!["Binary", "CRT"]
        .iter()
        .zip(vec![&binary_ops, &crt_ops].iter())
    {
        for &bitwidth in [8, 16, 32].iter() {
            for &operate in ops.iter() {
                let (sender, receiver) = unix_channel_pair();

                // ************ Garbler ************//
                let handle = std::thread::spawn(move || {
                    let rng = AesRng::new();
                    let mut gb = Informer::new(
                        Garbler::<UnixChannel, AesRng, OtSender, AllWire>::new(sender, rng)
                            .unwrap(),
                    );
                    let (gb_output, gb_microsecond) = match bund_method {
                        "Binary" => {
                            let xs = gb.bin_encode(5, bitwidth).unwrap();
                            let ys = gb.bin_receive(bitwidth).unwrap();
                            match operate {
                                "XOR" => {
                                    let r = time_repeat_and_take_last!(
                                        0,
                                        gb,
                                        bin_xor(&xs, &ys),
                                        repeat
                                    );
                                    (BundleType::Binary(r.0), r.1)
                                }
                                "AND" => {
                                    let r = time_repeat_and_take_last!(
                                        0,
                                        gb,
                                        bin_and(&xs, &ys),
                                        repeat
                                    );
                                    (BundleType::Binary(r.0), r.1)
                                }
                                "Add" => {
                                    let r = time_repeat_and_take_last!(
                                        0,
                                        gb,
                                        bin_addition(&xs, &ys),
                                        repeat
                                    );
                                    (BundleType::Binary(r.0 .0), r.1)
                                }
                                "Sub" => {
                                    let r = time_repeat_and_take_last!(
                                        0,
                                        gb,
                                        bin_subtraction(&xs, &ys),
                                        repeat
                                    );
                                    (BundleType::Binary(r.0 .0), r.1)
                                }
                                "Pub Mul" => {
                                    let r = time_repeat_and_take_last!(
                                        0,
                                        gb,
                                        bin_cmul(&xs, 3, bitwidth),
                                        repeat
                                    );
                                    (BundleType::Binary(r.0), r.1)
                                }
                                "Mul" => {
                                    let r = time_repeat_and_take_last!(
                                        0,
                                        gb,
                                        bin_mul(&xs, &ys),
                                        repeat
                                    );
                                    (BundleType::Binary(r.0), r.1)
                                }
                                "Div" => {
                                    let r = time_repeat_and_take_last!(
                                        0,
                                        gb,
                                        bin_div(&xs, &ys),
                                        repeat
                                    );
                                    (BundleType::Binary(r.0), r.1)
                                }
                                "Mod" => {
                                    let r = time_repeat_and_take_last!(
                                        0,
                                        gb,
                                        bin_mod(&xs, &ys),
                                        repeat
                                    );
                                    (BundleType::Binary(r.0), r.1)
                                }
                                "Mux" => {
                                    let r = time_repeat_and_take_last!(
                                        0,
                                        gb,
                                        bin_multiplex(&xs.wires()[0], &xs, &ys),
                                        repeat
                                    );
                                    (BundleType::Binary(r.0), r.1)
                                }
                                "Geq" => {
                                    let r = time_repeat_and_take_last!(
                                        0,
                                        gb,
                                        bin_geq(&xs, &ys),
                                        repeat
                                    );
                                    (BundleType::Binary(BinaryBundle::new(vec![r.0])), r.1)
                                }
                                "Bools to CRT" => {
                                    let r = time_repeat_and_take_last!(
                                        0,
                                        gb,
                                        crt_bit_composition(&xs),
                                        repeat
                                    );
                                    (BundleType::CRT(r.0), r.1)
                                }
                                _ => panic!("Invalid operation {operate}"),
                            }
                        }
                        "CRT" => {
                            let crt_big_mod = util::modulus_with_width(bitwidth as u32);
                            let xs = gb.crt_encode(5, crt_big_mod).unwrap();
                            let ys = gb.crt_receive(crt_big_mod).unwrap();
                            match operate {
                                "Add" => {
                                    let r = time_repeat_and_take_last!(
                                        0,
                                        gb,
                                        crt_add(&xs, &ys),
                                        repeat
                                    );
                                    (BundleType::CRT(r.0), r.1)
                                }
                                "Sub" => {
                                    let r = time_repeat_and_take_last!(
                                        0,
                                        gb,
                                        crt_sub(&xs, &ys),
                                        repeat
                                    );
                                    (BundleType::CRT(r.0), r.1)
                                }
                                "Pub Mul" => {
                                    let r =
                                        time_repeat_and_take_last!(0, gb, crt_cmul(&xs, 3), repeat);
                                    (BundleType::CRT(r.0), r.1)
                                }
                                "Mul" => {
                                    let r = time_repeat_and_take_last!(
                                        0,
                                        gb,
                                        crt_mul(&xs, &ys),
                                        repeat
                                    );
                                    (BundleType::CRT(r.0), r.1)
                                }
                                "Div" => {
                                    let r = time_repeat_and_take_last!(
                                        0,
                                        gb,
                                        crt_div(&xs, &ys),
                                        repeat
                                    );
                                    (BundleType::CRT(r.0), r.1)
                                }
                                "Mod" => {
                                    let r = time_repeat_and_take_last!(
                                        0,
                                        gb,
                                        crt_mod(&xs, &ys),
                                        repeat
                                    );
                                    (BundleType::CRT(r.0), r.1)
                                }
                                "Mux" => {
                                    let muxb = gb.encode(1u16, 2).unwrap();
                                    let r = time_repeat_and_take_last!(
                                        0,
                                        gb,
                                        crt_multiplex(&muxb, &xs, &ys),
                                        repeat
                                    );
                                    (BundleType::CRT(r.0), r.1)
                                }
                                "Pub Exp" => {
                                    let r =
                                        time_repeat_and_take_last!(0, gb, crt_cexp(&xs, 3), repeat);
                                    (BundleType::CRT(r.0), r.1)
                                }
                                "Pub Mod" => {
                                    let r =
                                        time_repeat_and_take_last!(0, gb, crt_rem(&xs, 3), repeat);
                                    (BundleType::CRT(r.0), r.1)
                                }
                                "Geq" => {
                                    let r = time_repeat_and_take_last!(
                                        0,
                                        gb,
                                        crt_geq(&xs, &ys, "100%"),
                                        repeat
                                    );
                                    (BundleType::Binary(BinaryBundle::new(vec![r.0])), r.1)
                                }
                                "CRT to Bools" => {
                                    let r = time_repeat_and_take_last!(
                                        0,
                                        gb,
                                        crt_bit_decomposition(&xs),
                                        repeat
                                    );
                                    (BundleType::Binary(r.0), r.1)
                                }
                                _ => panic!("Invalid operation {operate}"),
                            }
                        }
                        _ => panic!("Invalid bundle method {bund_method}"),
                    };
                    let gb_output_reveal = match gb_output {
                        BundleType::Binary(bundle) => gb.bin_reveal(&bundle).unwrap(),
                        BundleType::CRT(bundle) => gb.crt_reveal(&bundle).unwrap(),
                    };
                    print!("Gb Output 5 op 3: {gb_output_reveal}; ");
                    print!("Bundle {bund_method}; Bitwidth {bitwidth}; Operate {operate}; ");
                    println!("Time: {} us;", gb_microsecond);
                    // println!("Gb Info: {}", gb.stats());
                });

                //************ Evaluator ************//
                let rng = AesRng::new();
                let mut ev =
                    Evaluator::<UnixChannel, AesRng, OtReceiver, AllWire>::new(receiver, rng)
                        .unwrap();
                let (ev_output, ev_microsecond) = match bund_method {
                    "Binary" => {
                        let xs = ev.bin_receive(bitwidth).unwrap();
                        let ys = ev.bin_encode(3, bitwidth).unwrap();
                        match operate {
                            "XOR" => {
                                let r =
                                    time_repeat_and_take_last!(1, ev, bin_xor(&xs, &ys), repeat);
                                (BundleType::Binary(r.0), r.1)
                            }
                            "AND" => {
                                let r =
                                    time_repeat_and_take_last!(1, ev, bin_and(&xs, &ys), repeat);
                                (BundleType::Binary(r.0), r.1)
                            }
                            "Add" => {
                                let r = time_repeat_and_take_last!(
                                    1,
                                    ev,
                                    bin_addition(&xs, &ys),
                                    repeat
                                );
                                (BundleType::Binary(r.0 .0), r.1)
                            }
                            "Sub" => {
                                let r = time_repeat_and_take_last!(
                                    1,
                                    ev,
                                    bin_subtraction(&xs, &ys),
                                    repeat
                                );
                                (BundleType::Binary(r.0 .0), r.1)
                            }
                            "Pub Mul" => {
                                let r = time_repeat_and_take_last!(
                                    1,
                                    ev,
                                    bin_cmul(&xs, 3, bitwidth),
                                    repeat
                                );
                                (BundleType::Binary(r.0), r.1)
                            }
                            "Mul" => {
                                let r =
                                    time_repeat_and_take_last!(1, ev, bin_mul(&xs, &ys), repeat);
                                (BundleType::Binary(r.0), r.1)
                            }
                            "Div" => {
                                let r =
                                    time_repeat_and_take_last!(1, ev, bin_div(&xs, &ys), repeat);
                                (BundleType::Binary(r.0), r.1)
                            }
                            "Mod" => {
                                let r =
                                    time_repeat_and_take_last!(1, ev, bin_mod(&xs, &ys), repeat);
                                (BundleType::Binary(r.0), r.1)
                            }
                            "Mux" => {
                                let r = time_repeat_and_take_last!(
                                    1,
                                    ev,
                                    bin_multiplex(&xs.wires()[0], &xs, &ys),
                                    repeat
                                );
                                (BundleType::Binary(r.0), r.1)
                            }
                            "Geq" => {
                                let r =
                                    time_repeat_and_take_last!(1, ev, bin_geq(&xs, &ys), repeat);
                                (BundleType::Binary(BinaryBundle::new(vec![r.0])), r.1)
                            }
                            "Bools to CRT" => {
                                let r = time_repeat_and_take_last!(
                                    1,
                                    ev,
                                    crt_bit_composition(&xs),
                                    repeat
                                );
                                (BundleType::CRT(r.0), r.1)
                            }
                            _ => panic!("Invalid operation {operate}"),
                        }
                    }
                    "CRT" => {
                        let crt_big_mod = util::modulus_with_width(bitwidth as u32);
                        let xs = ev.crt_receive(crt_big_mod).unwrap();
                        let ys = ev.crt_encode(3, crt_big_mod).unwrap();
                        match operate {
                            "Add" => {
                                let r =
                                    time_repeat_and_take_last!(1, ev, crt_add(&xs, &ys), repeat);
                                (BundleType::CRT(r.0), r.1)
                            }
                            "Sub" => {
                                let r =
                                    time_repeat_and_take_last!(1, ev, crt_sub(&xs, &ys), repeat);
                                (BundleType::CRT(r.0), r.1)
                            }
                            "Pub Mul" => {
                                let r = time_repeat_and_take_last!(1, ev, crt_cmul(&xs, 3), repeat);
                                (BundleType::CRT(r.0), r.1)
                            }
                            "Mul" => {
                                let r =
                                    time_repeat_and_take_last!(1, ev, crt_mul(&xs, &ys), repeat);
                                (BundleType::CRT(r.0), r.1)
                            }
                            "Div" => {
                                let r =
                                    time_repeat_and_take_last!(1, ev, crt_div(&xs, &ys), repeat);
                                (BundleType::CRT(r.0), r.1)
                            }
                            "Mod" => {
                                let r =
                                    time_repeat_and_take_last!(1, ev, crt_mod(&xs, &ys), repeat);
                                (BundleType::CRT(r.0), r.1)
                            }
                            "Mux" => {
                                let muxb = ev.receive(2).unwrap();
                                let r = time_repeat_and_take_last!(
                                    1,
                                    ev,
                                    crt_multiplex(&muxb, &xs, &ys),
                                    repeat
                                );
                                (BundleType::CRT(r.0), r.1)
                            }
                            "Pub Exp" => {
                                let r = time_repeat_and_take_last!(1, ev, crt_cexp(&xs, 3), repeat);
                                (BundleType::CRT(r.0), r.1)
                            }
                            "Pub Mod" => {
                                let r = time_repeat_and_take_last!(1, ev, crt_rem(&xs, 3), repeat);
                                (BundleType::CRT(r.0), r.1)
                            }
                            "Geq" => {
                                let r = time_repeat_and_take_last!(
                                    1,
                                    ev,
                                    crt_geq(&xs, &ys, "100%"),
                                    repeat
                                );
                                (BundleType::Binary(BinaryBundle::new(vec![r.0])), r.1)
                            }
                            "CRT to Bools" => {
                                let r = time_repeat_and_take_last!(
                                    1,
                                    ev,
                                    crt_bit_decomposition(&xs),
                                    repeat
                                );
                                (BundleType::Binary(r.0), r.1)
                            }
                            _ => panic!("Invalid operation {operate}"),
                        }
                    }
                    _ => panic!("Invalid bundle method {bund_method}"),
                };
                let ev_output_reveal = match ev_output {
                    BundleType::Binary(bundle) => ev.bin_reveal(&bundle).unwrap(),
                    BundleType::CRT(bundle) => ev.crt_reveal(&bundle).unwrap(),
                };
                handle.join().unwrap();
                print!("Ev Output 5 op 3: {ev_output_reveal}; ");
                print!("Bundle {bund_method}; Bitwidth {bitwidth}; Operate {operate}; ");
                println!("Time: {} us;", ev_microsecond);
            }
        }
    }
}

fn main() {
    let repeat_text = 2048;
    profile_function(repeat_text);
}
