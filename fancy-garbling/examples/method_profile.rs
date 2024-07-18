use fancy_garbling::informer::Informer;
use fancy_garbling::util;
use fancy_garbling::{
    twopac::semihonest::{Evaluator, Garbler},
    AllWire, BinaryBundle, FancyInput, FancyReveal,
};
use fancy_garbling::{BinaryGadgets, CrtBundle, CrtGadgets, MixCrtBinaryGadgets};
use ocelot::ot::{AlszReceiver as OtReceiver, AlszSender as OtSender};
use scuttlebutt::{unix_channel_pair, AesRng, UnixChannel};

enum BundleType {
    Binary(BinaryBundle<AllWire>),
    CRT(CrtBundle<AllWire>),
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
                    gb.time_stats_set_repeat(repeat);
                    let gb_output = match bund_method {
                        "Binary" => {
                            let xs = gb.bin_encode(5, bitwidth).unwrap();
                            let ys = gb.bin_receive(bitwidth).unwrap();
                            match operate {
                                "XOR" => BundleType::Binary(gb.bin_xor(&xs, &ys).unwrap()),
                                "AND" => BundleType::Binary(gb.bin_and(&xs, &ys).unwrap()),
                                "Add" => BundleType::Binary(gb.bin_addition(&xs, &ys).unwrap().0),
                                "Sub" => {
                                    BundleType::Binary(gb.bin_subtraction(&xs, &ys).unwrap().0)
                                }
                                "Pub Mul" => {
                                    BundleType::Binary(gb.bin_cmul(&xs, 3, bitwidth).unwrap())
                                }
                                "Mul" => BundleType::Binary(gb.bin_mul(&xs, &ys).unwrap()),
                                "Div" => BundleType::Binary(gb.bin_div(&xs, &ys).unwrap()),
                                "Mod" => BundleType::Binary(gb.bin_mod(&xs, &ys).unwrap()),
                                "Mux" => BundleType::Binary(
                                    gb.bin_multiplex(&xs.wires()[0], &xs, &ys).unwrap(),
                                ),
                                "Geq" => BundleType::Binary(BinaryBundle::new(vec![gb
                                    .bin_geq(&xs, &ys)
                                    .unwrap()])),
                                "Bools to CRT" => {
                                    BundleType::CRT(gb.crt_bit_composition(&xs).unwrap())
                                }
                                _ => panic!("Invalid operation {operate}"),
                            }
                        }
                        "CRT" => {
                            let crt_big_mod = util::modulus_with_width(bitwidth as u32);
                            let xs = gb.crt_encode(5, crt_big_mod).unwrap();
                            let ys = gb.crt_receive(crt_big_mod).unwrap();
                            match operate {
                                "Add" => BundleType::CRT(gb.crt_add(&xs, &ys).unwrap()),
                                "Sub" => BundleType::CRT(gb.crt_sub(&xs, &ys).unwrap()),
                                "Pub Mul" => BundleType::CRT(gb.crt_cmul(&xs, 3).unwrap()),
                                "Mul" => BundleType::CRT(gb.crt_mul(&xs, &ys).unwrap()),
                                "Div" => BundleType::CRT(gb.crt_div(&xs, &ys).unwrap()),
                                "Mod" => BundleType::CRT(gb.crt_mod(&xs, &ys).unwrap()),
                                "Mux" => {
                                    let muxb = gb.encode(1u16, 2).unwrap();
                                    BundleType::CRT(gb.crt_multiplex(&muxb, &xs, &ys).unwrap())
                                }
                                "Pub Exp" => BundleType::CRT(gb.crt_cexp(&xs, 3).unwrap()),
                                "Pub Mod" => BundleType::CRT(gb.crt_rem(&xs, 3).unwrap()),
                                "Geq" => BundleType::Binary(BinaryBundle::new(vec![gb
                                    .crt_geq(&xs, &ys, "100%")
                                    .unwrap()])),
                                "CRT to Bools" => {
                                    BundleType::Binary(gb.crt_bit_decomposition(&xs).unwrap())
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
                    println!("Gb Output 5 op 3: {gb_output_reveal}");
                    println!("Gb experiment settings. Bundle {bund_method}. Bitwidth {bitwidth}. Operate {operate}.");
                    println!("Gb Info: {}", gb.stats());
                    // println!("Gb Time: {}", gb.time_stats());
                });

                //************ Evaluator ************//
                let rng = AesRng::new();
                let mut ev = Informer::new(
                    Evaluator::<UnixChannel, AesRng, OtReceiver, AllWire>::new(receiver, rng)
                        .unwrap(),
                );
                ev.time_stats_set_repeat(repeat);
                let ev_output = match bund_method {
                    "Binary" => {
                        let xs = ev.bin_receive(bitwidth).unwrap();
                        let ys = ev.bin_encode(3, bitwidth).unwrap();
                        match operate {
                            "XOR" => BundleType::Binary(ev.bin_xor(&xs, &ys).unwrap()),
                            "AND" => BundleType::Binary(ev.bin_and(&xs, &ys).unwrap()),
                            "Add" => BundleType::Binary(ev.bin_addition(&xs, &ys).unwrap().0),
                            "Sub" => BundleType::Binary(ev.bin_subtraction(&xs, &ys).unwrap().0),
                            "Pub Mul" => BundleType::Binary(ev.bin_cmul(&xs, 3, bitwidth).unwrap()),
                            "Mul" => BundleType::Binary(ev.bin_mul(&xs, &ys).unwrap()),
                            "Div" => BundleType::Binary(ev.bin_div(&xs, &ys).unwrap()),
                            "Mod" => BundleType::Binary(ev.bin_mod(&xs, &ys).unwrap()),
                            "Mux" => BundleType::Binary(
                                ev.bin_multiplex(&xs.wires()[0], &xs, &ys).unwrap(),
                            ),
                            "Geq" => BundleType::Binary(BinaryBundle::new(vec![ev
                                .bin_geq(&xs, &ys)
                                .unwrap()])),
                            "Bools to CRT" => BundleType::CRT(ev.crt_bit_composition(&xs).unwrap()),
                            _ => panic!("Invalid operation {operate}"),
                        }
                    }
                    "CRT" => {
                        let crt_big_mod = util::modulus_with_width(bitwidth as u32);
                        let xs = ev.crt_receive(crt_big_mod).unwrap();
                        let ys = ev.crt_encode(3, crt_big_mod).unwrap();
                        match operate {
                            "Add" => BundleType::CRT(ev.crt_add(&xs, &ys).unwrap()),
                            "Sub" => BundleType::CRT(ev.crt_sub(&xs, &ys).unwrap()),
                            "Pub Mul" => BundleType::CRT(ev.crt_cmul(&xs, 3).unwrap()),
                            "Mul" => BundleType::CRT(ev.crt_mul(&xs, &ys).unwrap()),
                            "Div" => BundleType::CRT(ev.crt_div(&xs, &ys).unwrap()),
                            "Mod" => BundleType::CRT(ev.crt_mod(&xs, &ys).unwrap()),
                            "Mux" => {
                                let muxb = ev.receive(2).unwrap();
                                BundleType::CRT(ev.crt_multiplex(&muxb, &xs, &ys).unwrap())
                            }
                            "Pub Exp" => BundleType::CRT(ev.crt_cexp(&xs, 3).unwrap()),
                            "Pub Mod" => BundleType::CRT(ev.crt_rem(&xs, 3).unwrap()),
                            "Geq" => BundleType::Binary(BinaryBundle::new(vec![ev
                                .crt_geq(&xs, &ys, "100%")
                                .unwrap()])),
                            "CRT to Bools" => {
                                BundleType::Binary(ev.crt_bit_decomposition(&xs).unwrap())
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
                println!("Ev Output 5 op 3: {ev_output_reveal}");
                // println!("Ev experiment settings. Bundle {bund_method}. Bitwidth {bitwidth}. Operate {operate}.");
                // println!("Ev Info: {}", ev.stats());
                // println!("Ev Time: {}", ev.time_stats());
            }
        }
    }
}

fn main() {
    profile_function(1);
}
