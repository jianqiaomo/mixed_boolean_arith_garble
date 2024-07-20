use fancy_garbling::{
    circuit::{BinaryCircuit as Circuit, EvaluableCircuit},
    dummy::DummyVal,
    twopac::semihonest::{Evaluator, Garbler},
    util::a_prime_with_width,
    AllWire, BinaryBundle, Bundle, Fancy, FancyArithmetic, FancyInput, FancyReveal,
    Mod2kArithmetic, WireLabelMod2k, WireMod2, WireMod2k, WireModQ,
};
use fancy_garbling::{dummy::Dummy, informer::Informer};
use fancy_garbling::{util as numbers, WireLabel};
use fancy_garbling::{
    ArithmeticBundleGadgets, BinaryGadgets, BundleGadgets, CrtBundle, CrtGadgets, HasModulus,
    MixCrtBinaryGadgets,
};
use itertools::{concat, Itertools};
use ocelot::ot::{AlszReceiver as OtReceiver, AlszSender as OtSender};
use scuttlebutt::{unix_channel_pair, AesRng, Block, UnixChannel};
use std::{fs::File, io::BufReader, time::SystemTime};

fn circuit(fname: &str) -> Circuit {
    println!("* Circuit: {}", fname);
    Circuit::parse(BufReader::new(File::open(fname).unwrap())).unwrap()
}

fn run_circuit(circ: &mut Circuit, gb_inputs: Vec<u16>, ev_inputs: Vec<u16>) {
    let circ_ = circ.clone();
    let (sender, receiver) = unix_channel_pair();
    let n_gb_inputs = gb_inputs.len();
    let n_ev_inputs = ev_inputs.len();
    let total = SystemTime::now();
    let handle = std::thread::spawn(move || {
        let rng = AesRng::new();
        let start = SystemTime::now();
        let mut gb = Garbler::<UnixChannel, AesRng, OtSender, WireMod2>::new(sender, rng).unwrap();
        println!(
            "Garbler :: Initialization: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        let xs = gb.encode_many(&gb_inputs, &vec![2; n_gb_inputs]).unwrap();
        let ys = gb.receive_many(&vec![2; n_ev_inputs]).unwrap();
        println!(
            "Garbler :: Encoding inputs: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        let gb_output = circ_.eval(&mut gb, &xs, &ys).unwrap();
        println!(
            "Garbler :: Circuit garbling: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        println!("Gb Output: {:?}", gb_output);
    });
    let rng = AesRng::new();
    let start = SystemTime::now();
    let mut ev =
        Evaluator::<UnixChannel, AesRng, OtReceiver, WireMod2>::new(receiver, rng).unwrap();
    println!(
        "Evaluator :: Initialization: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let xs = ev.receive_many(&vec![2; n_gb_inputs]).unwrap();
    let ys = ev.encode_many(&ev_inputs, &vec![2; n_ev_inputs]).unwrap();
    println!(
        "Evaluator :: Encoding inputs: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let ev_output = circ.eval(&mut ev, &xs, &ys).unwrap();
    println!("Ev Output: {:?}", ev_output);
    println!(
        "Evaluator :: Circuit evaluation: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    handle.join().unwrap();
    println!("Total: {} ms", total.elapsed().unwrap().as_millis());
}

fn run_arithmetic(
    gb_inputs: Vec<u32>,
    ev_inputs: Vec<u32>,
    bitwidth: usize,
    moduli: u16,
    repeat: usize,
) {
    let (sender, receiver) = unix_channel_pair();
    let n_gb_inputs = gb_inputs.len();
    let n_ev_inputs = ev_inputs.len();

    // crt mods' multiplication: the biggest moduli (ring) under the given bitwidth
    // let crt_big_mod = numbers::modulus_with_width(bitwidth as u32);

    let total = SystemTime::now();

    //************ Garbler ************//
    let handle = std::thread::spawn(move || {
        let rng = AesRng::new();
        let start = SystemTime::now();
        let mut gb = Garbler::<UnixChannel, AesRng, OtSender, AllWire>::new(sender, rng).unwrap();
        println!(
            "Garbler :: Initialization: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        let xs = gb
            .encode_many(
                &gb_inputs.iter().map(|&x| x as u16).collect_vec(),
                &vec![moduli; n_gb_inputs],
            )
            .unwrap();
        let ys = gb.receive_many(&vec![moduli; n_ev_inputs]).unwrap();
        // let xs = gb.crt_encode_many(&gb_inputs, crt_big_mod).unwrap();
        // let ys = gb.crt_receive_many(n_ev_inputs, crt_big_mod).unwrap();
        println!(
            "Garbler :: Encoding inputs: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        let mut gb_output = vec![];
        for i in 0..n_gb_inputs {
            let x = &xs[i];
            let y = &ys[i];
            let mut z1 = None;
            for _ in 0..repeat {
                // z1 = Some(gb.crt_mul(x, y).unwrap());
                let z1 = gb.mul(x, y).unwrap();
            }
            gb_output.push(z1.unwrap());
        }
        println!(
            "Garbler :: Circuit garbling: {:.2} ms",
            start.elapsed().unwrap().as_millis() as f64 / 100.0
        );
        let gb_output = gb_output
            .iter()
            // .map(|x| gb.crt_reveal(&x).unwrap())
            .map(|x| gb.reveal(&x).unwrap())
            .collect_vec();
        println!("Gb Output: {:?}", gb_output);
    });

    //************ Evaluator ************//
    let rng = AesRng::new();
    let start = SystemTime::now();
    let mut ev = Evaluator::<UnixChannel, AesRng, OtReceiver, AllWire>::new(receiver, rng).unwrap();
    println!(
        "Evaluator :: Initialization: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let xs = ev.receive_many(&vec![moduli; n_gb_inputs]).unwrap();
    let ys = ev
        .encode_many(
            &ev_inputs.iter().map(|&x| x as u16).collect_vec(),
            &vec![moduli; n_ev_inputs],
        )
        .unwrap();
    // let xs = ev.crt_receive_many(n_gb_inputs, crt_big_mod).unwrap();
    // let ys = ev.crt_encode_many(&ev_inputs, crt_big_mod).unwrap();
    println!(
        "Evaluator :: Encoding inputs: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let mut ev_output = vec![];
    for i in 0..n_gb_inputs {
        let x = &xs[i];
        let y = &ys[i];
        let mut z1 = None;
        for _ in 0..repeat {
            // z1 = Some(ev.crt_mul(x, y).unwrap());
            let z1 = ev.mul(x, y).unwrap();
        }
        ev_output.push(z1.unwrap());
    }
    println!(
        "Evaluator :: Circuit evaluation: {:2} ms",
        start.elapsed().unwrap().as_millis() as f64 / 100.0
    );
    let ev_output = ev_output
        .iter()
        // .map(|x| ev.crt_reveal(&x).unwrap())
        .map(|x| ev.reveal(&x).unwrap())
        .collect_vec();
    println!("Ev Output: {:?}", ev_output);
    handle.join().unwrap();
    println!("Total: {} ms", total.elapsed().unwrap().as_millis());

    //************ Informer ************//
    // let mut informer = Informer::new(Dummy::new());
    // let xs = informer.crt_encode_many(&gb_inputs, crt_big_mod).unwrap();
    // // let ys = informer.crt_encode_many(&ev_inputs, crt_big_mod).unwrap();
    // let ys = informer.crt_receive_many(n_ev_inputs, crt_big_mod).unwrap();
    // let mut informer_output = vec![];
    // for i in 0..n_gb_inputs {
    //     let x = &xs[i];
    //     let y = &ys[i];
    //     let z1 = informer.crt_mul(x, y).unwrap();
    //     informer_output.push(z1);
    // }
    // let informer_output = informer_output.iter()
    //                         .map(|x| informer.crt_reveal(&x).unwrap())
    //                         .collect_vec();
    // println!("Informer Output: {:?}", informer_output);
    // println!("{}", informer.stats());
}

fn run_bc(gb_inputs: Vec<u16>, ev_inputs: Vec<u16>, repeat: usize) {
    let (sender, receiver) = unix_channel_pair();
    let n_gb_inputs = gb_inputs.len();
    let n_ev_inputs = ev_inputs.len();
    // print the bits of the inputs as MSB first
    println!(
        "Ev/Gb: {:?}/{:?}",
        ev_inputs
            .iter()
            .rev()
            .map(|x| format!("{:01b}", x))
            .collect_vec(),
        gb_inputs
            .iter()
            .rev()
            .map(|y| format!("{:01b}", y))
            .collect_vec()
    );

    // crt mods' multiplication: the biggest moduli (ring) under the given bitwidth
    // let crt_big_mod = numbers::modulus_with_width(bitwidth as u32);

    let total = SystemTime::now();
    let current_p = a_prime_with_width((n_gb_inputs + n_ev_inputs) as u16);
    println!(
        "Current Prime of {} bits: {}",
        n_gb_inputs + n_ev_inputs,
        current_p
    );

    // ************ Garbler ************//
    let handle = std::thread::spawn(move || {
        let rng = AesRng::new();
        let start = SystemTime::now();
        let mut gb = Garbler::<UnixChannel, AesRng, OtSender, AllWire>::new(sender, rng).unwrap();
        println!(
            "Garbler :: Initialization: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        let xs = gb.encode_many(&gb_inputs, &vec![2; n_gb_inputs]).unwrap();
        let ys = gb.receive_many(&vec![2; n_ev_inputs]).unwrap();
        let x1 = gb.encode(3, current_p).unwrap();
        let y1 = gb.receive(current_p).unwrap();
        println!(
            "Garbler :: Encoding inputs: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        // merge xs WireMod2 bits and ys WireMod2 bits into a single vector
        let decomp_bits: Vec<&AllWire> = xs.iter().chain(ys.iter()).collect_vec();
        let mut gb_output = AllWire::zero(2);
        let start = SystemTime::now();
        for _ in 0..repeat {
            gb_output = gb.bit_composition(&decomp_bits, None).unwrap();
            // gb_output = gb.mul(&gb_output, &x1).unwrap();
            // gb_output = gb.add(&gb_output, &y1).unwrap();
        }
        println!(
            "Garbler :: Circuit garbling: {:.2} ms",
            start.elapsed().unwrap().as_millis() as f64 / 100.0
        );
        let gb_output_reveal = gb.reveal(&gb_output).unwrap();
        println!("Gb Output: {:?}", gb_output_reveal);
    });

    //************ Evaluator ************//
    let rng = AesRng::new();
    let start = SystemTime::now();
    let mut ev = Evaluator::<UnixChannel, AesRng, OtReceiver, AllWire>::new(receiver, rng).unwrap();
    println!(
        "Evaluator :: Initialization: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let xs = ev.receive_many(&vec![2; n_gb_inputs]).unwrap();
    let ys = ev.encode_many(&ev_inputs, &vec![2; n_ev_inputs]).unwrap();
    let x1 = ev.receive(current_p).unwrap();
    let y1 = ev.encode(3, current_p).unwrap();
    println!(
        "Evaluator :: Encoding inputs: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let decomp_bits: Vec<&AllWire> = xs.iter().chain(ys.iter()).collect_vec();
    let start = SystemTime::now();
    let mut ev_output = AllWire::zero(2);
    for _ in 0..repeat {
        ev_output = ev.bit_composition(&decomp_bits, None).unwrap();
        // ev_output = ev.mul(&ev_output, &x1).unwrap();
        // ev_output = ev.add(&ev_output, &y1).unwrap();
    }
    println!(
        "Evaluator :: Circuit evaluation: {:2} ms",
        start.elapsed().unwrap().as_millis() as f64 / 100.0
    );
    let ev_output_reveal = ev.reveal(&ev_output).unwrap();
    println!("Ev Output: {:?}", ev_output_reveal);
    handle.join().unwrap();
    println!("Total: {} ms", total.elapsed().unwrap().as_millis());

    // // //************ Informer ************//
    // let mut informer = Informer::new(Dummy::new());
    // let xs = informer.encode_many(&gb_inputs, &vec![2; n_gb_inputs]).unwrap();
    // let ys = informer.receive_many(&vec![2; n_ev_inputs]).unwrap();
    // let decomp_bits: Vec<&DummyVal> = xs.iter().chain(ys.iter()).collect_vec();
    // let informer_output = informer.bit_composition(&decomp_bits).unwrap();
    // let informer_output_reveal = informer.reveal(&informer_output).unwrap();
    // println!("Informer Output: {:?}", informer_output_reveal);
    // println!("{}", informer.stats());
}

fn run_bd(gb_inputs: Vec<u16>, ev_inputs: Vec<u16>, repeat: usize) {
    let (sender, receiver) = unix_channel_pair();
    let n_gb_inputs = gb_inputs.len();
    let n_ev_inputs = ev_inputs.len();
    // print the bits of the inputs as MSB first
    println!(
        "Ev/Gb: {:?}/{:?}",
        ev_inputs
            .iter()
            .rev()
            .map(|x| format!("{:01b}", x))
            .collect_vec(),
        gb_inputs
            .iter()
            .rev()
            .map(|y| format!("{:01b}", y))
            .collect_vec()
    );

    // crt mods' multiplication: the biggest moduli (ring) under the given bitwidth
    // let crt_big_mod = numbers::modulus_with_width(bitwidth as u32);

    let total = SystemTime::now();

    // ************ Garbler ************//
    let handle = std::thread::spawn(move || {
        let rng = AesRng::new();
        let start = SystemTime::now();
        let mut gb = Garbler::<UnixChannel, AesRng, OtSender, AllWire>::new(sender, rng).unwrap();
        println!(
            "Garbler :: Initialization: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        let xs = gb.encode_many(&gb_inputs, &vec![17; n_gb_inputs]).unwrap();
        let ys = gb.receive_many(&vec![17; n_ev_inputs]).unwrap();
        let x1 = gb.encode(1, 2).unwrap();
        let y1 = gb.receive(2).unwrap();
        println!(
            "Garbler :: Encoding inputs: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let all_arith_values: Vec<&AllWire> = xs.iter().chain(ys.iter()).collect_vec();
        let mut gb_output = vec![];
        let start = SystemTime::now();
        for _ in 0..repeat {
            gb_output = all_arith_values
                .iter()
                .map(|&x| gb.bit_decomposition(x, None).unwrap())
                .collect();
        }
        println!(
            "Garbler :: Circuit garbling: {:.2} ms",
            start.elapsed().unwrap().as_millis() as f64 / 100.0
        );
        let gb_output_reveal: Vec<Vec<u16>> = gb_output
            .iter()
            .map(|x| gb.reveal_many(x).unwrap())
            .collect_vec();
        println!("Gb Output: {:?}", gb_output_reveal);
    });

    //************ Evaluator ************//
    let rng = AesRng::new();
    let start = SystemTime::now();
    let mut ev = Evaluator::<UnixChannel, AesRng, OtReceiver, AllWire>::new(receiver, rng).unwrap();
    println!(
        "Evaluator :: Initialization: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let xs = ev.receive_many(&vec![17; n_gb_inputs]).unwrap();
    let ys = ev.encode_many(&ev_inputs, &vec![17; n_ev_inputs]).unwrap();
    let x1 = ev.receive(2).unwrap();
    let y1 = ev.encode(1, 2).unwrap();
    println!(
        "Evaluator :: Encoding inputs: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let all_arith_values: Vec<&AllWire> = xs.iter().chain(ys.iter()).collect_vec();
    let start = SystemTime::now();
    let mut ev_output = vec![];
    for _ in 0..repeat {
        ev_output = all_arith_values
            .iter()
            .map(|&x| ev.bit_decomposition(x, None).unwrap())
            .collect();
    }
    println!(
        "Evaluator :: Circuit evaluation: {:2} ms",
        start.elapsed().unwrap().as_millis() as f64 / 100.0
    );
    let ev_output_reveal: Vec<Vec<u16>> = ev_output
        .iter()
        .map(|x| ev.reveal_many(x).unwrap())
        .collect_vec();
    println!("Ev Output: {:?}", ev_output_reveal);
    handle.join().unwrap();
    println!("Total: {} ms", total.elapsed().unwrap().as_millis());

    // // //************ Informer ************//
    // let mut informer = Informer::new(Dummy::new());
    // let xs = informer
    //     .encode_many(&gb_inputs, &vec![17; n_gb_inputs])
    //     .unwrap();
    // let ys = informer.receive_many(&vec![17; n_ev_inputs]).unwrap();
    // let all_arith_values: Vec<&DummyVal> = xs.iter().chain(ys.iter()).collect_vec();
    // let informer_output = all_arith_values
    //     .iter()
    //     .map(|&x| informer.bit_decomposition(x).unwrap())
    //     .collect_vec();
    // let informer_output_reveal: Vec<Vec<u16>> = informer_output
    //     .iter()
    //     .map(|x| informer.reveal_many(x).unwrap())
    //     .collect_vec();
    // println!("Informer Output: {:?}", informer_output_reveal);
    // println!("{}", informer.stats());
}

fn run_mod2k(gb_inputs: Vec<u16>, ev_inputs: Vec<u16>, repeat: usize) {
    let (sender, receiver) = unix_channel_pair();
    let n_gb_inputs = gb_inputs.len();
    let n_ev_inputs = ev_inputs.len();
    // print the bits of the inputs as MSB first
    println!(
        "Ev/Gb: {:?}/{:?}",
        ev_inputs
            .iter()
            .rev()
            .map(|x| format!("{:01b}", x))
            .collect_vec(),
        gb_inputs
            .iter()
            .rev()
            .map(|y| format!("{:01b}", y))
            .collect_vec()
    );

    // crt mods' multiplication: the biggest moduli (ring) under the given bitwidth
    // let crt_big_mod = numbers::modulus_with_width(bitwidth as u32);

    let total = SystemTime::now();
    let k: u16 = 8; // 2's power

    // ************ Garbler ************//
    let handle = std::thread::spawn(move || {
        let rng = AesRng::new();
        let start = SystemTime::now();
        let mut gb = Informer::new(
            Garbler::<UnixChannel, AesRng, OtSender, AllWire>::new(sender, rng).unwrap(),
        );
        println!(
            "Garbler :: Initialization: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        let xs = gb.encode_many(&gb_inputs, &vec![5; n_gb_inputs]).unwrap();
        let ys = gb.receive_many(&vec![5; n_ev_inputs]).unwrap();
        println!(
            "Garbler :: Encoding inputs: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let all_arith_values: Vec<&AllWire> = xs.iter().chain(ys.iter()).collect_vec();
        let mut gb_output = vec![];
        let start = SystemTime::now();
        for _ in 0..repeat {
            gb_output = all_arith_values
                .iter()
                .map(|&x| {
                    let x2k = gb.mod_qto2k(x, None, k, false, None).unwrap().0;
                    gb.cmod(&x2k, 23, false)
                })
                .collect();
        }
        println!(
            "Garbler :: Circuit garbling: {:.2} ms",
            start.elapsed().unwrap().as_millis() as f64 / 100.0
        );
        // println!("Gb Output: {:?}", gb_output[0].digits()); // debug
        // let gb_output_reveal: Vec<Vec<u16>> = gb_output
        //     .iter()
        //     .map(|x| gb.reveal_many(x).unwrap())
        //     .collect_vec();
        // println!("Gb Output: {:?}", gb_output_reveal);
        println!("Gb Info: {}", gb.stats());
    });

    //************ Evaluator ************//
    let rng = AesRng::new();
    let start = SystemTime::now();
    let mut ev = Informer::new(
        Evaluator::<UnixChannel, AesRng, OtReceiver, AllWire>::new(receiver, rng).unwrap(),
    );
    println!(
        "Evaluator :: Initialization: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let xs = ev.receive_many(&vec![5; n_gb_inputs]).unwrap();
    let ys = ev.encode_many(&ev_inputs, &vec![5; n_ev_inputs]).unwrap();
    println!(
        "Evaluator :: Encoding inputs: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let all_arith_values: Vec<&AllWire> = xs.iter().chain(ys.iter()).collect_vec();
    let mut ev_output = vec![];
    let start = SystemTime::now();
    for _ in 0..repeat {
        ev_output = all_arith_values
            .iter()
            .map(|&x| {
                let x2k = ev.mod_qto2k(x, None, k, false, None).unwrap().0;
                ev.cmod(&x2k, 23, false)
            })
            .collect();
    }
    println!(
        "Evaluator :: Circuit evaluation: {:2} ms",
        start.elapsed().unwrap().as_millis() as f64 / 100.0
    );
    // println!("Ev Output: {:?}", ev_output[0].digits()); // debug
    // let ev_output_reveal: Vec<Vec<u16>> = ev_output
    //     .iter()
    //     .map(|x| ev.reveal_many(x).unwrap())
    //     .collect_vec();
    // println!("Ev Output: {:?}", ev_output_reveal);
    println!("Ev Info: {}", ev.stats());
    handle.join().unwrap();
    println!("Total: {} ms", total.elapsed().unwrap().as_millis());
}

fn run_mod2k_BC(gb_inputs: Vec<u16>, ev_inputs: Vec<u16>, repeat: usize) {
    let (sender, receiver) = unix_channel_pair();
    let n_gb_inputs = gb_inputs.len();
    let n_ev_inputs = ev_inputs.len();
    // print the bits of the inputs as MSB first
    println!(
        "Ev/Gb: {:?}/{:?}",
        ev_inputs
            .iter()
            .rev()
            .map(|x| format!("{:01b}", x))
            .collect_vec(),
        gb_inputs
            .iter()
            .rev()
            .map(|y| format!("{:01b}", y))
            .collect_vec()
    );

    // crt mods' multiplication: the biggest moduli (ring) under the given bitwidth
    // let crt_big_mod = numbers::modulus_with_width(bitwidth as u32);

    let total = SystemTime::now();
    let k: u16 = 4; // 2's power

    // ************ Garbler ************//
    let handle = std::thread::spawn(move || {
        let rng = AesRng::new();
        let start = SystemTime::now();
        let mut gb = Garbler::<UnixChannel, AesRng, OtSender, AllWire>::new(sender, rng).unwrap();
        println!(
            "Garbler :: Initialization: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        let xs = gb.encode_many(&gb_inputs, &vec![2; n_gb_inputs]).unwrap();
        let ys = gb.receive_many(&vec![2; n_ev_inputs]).unwrap();
        println!(
            "Garbler :: Encoding inputs: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let all_arith_values: Vec<&AllWire> = xs.iter().chain(ys.iter()).collect_vec();
        let mut gb_output = WireLabelMod2k::zero(k);
        let start = SystemTime::now();
        for _ in 0..repeat {
            gb_output = gb
                .mod2k_bit_composition(&all_arith_values, None, None)
                .unwrap();
        }
        println!(
            "Garbler :: Circuit garbling: {:.2} ms",
            start.elapsed().unwrap().as_millis() as f64 / 100.0
        );
        println!("Gb Output: {:?}", gb_output.digits()); // debug
                                                         // let gb_output_reveal: Vec<Vec<u16>> = gb_output
                                                         //     .iter()
                                                         //     .map(|x| gb.reveal_many(x).unwrap())
                                                         //     .collect_vec();
                                                         // println!("Gb Output: {:?}", gb_output_reveal);
    });

    //************ Evaluator ************//
    let rng = AesRng::new();
    let start = SystemTime::now();
    let mut ev = Evaluator::<UnixChannel, AesRng, OtReceiver, AllWire>::new(receiver, rng).unwrap();
    println!(
        "Evaluator :: Initialization: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let xs = ev.receive_many(&vec![2; n_gb_inputs]).unwrap();
    let ys = ev.encode_many(&ev_inputs, &vec![2; n_ev_inputs]).unwrap();
    println!(
        "Evaluator :: Encoding inputs: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let all_arith_values: Vec<&AllWire> = xs.iter().chain(ys.iter()).collect_vec();
    let mut ev_output = WireLabelMod2k::zero(k);
    let start = SystemTime::now();
    for _ in 0..repeat {
        ev_output = ev
            .mod2k_bit_composition(&all_arith_values, None, None)
            .unwrap();
    }
    println!(
        "Evaluator :: Circuit evaluation: {:2} ms",
        start.elapsed().unwrap().as_millis() as f64 / 100.0
    );
    println!("Ev Output: {:?}", ev_output.digits()); // debug
                                                     // let ev_output_reveal: Vec<Vec<u16>> = ev_output
                                                     //     .iter()
                                                     //     .map(|x| ev.reveal_many(x).unwrap())
                                                     //     .collect_vec();
                                                     // println!("Ev Output: {:?}", ev_output_reveal);
    handle.join().unwrap();
    println!("Total: {} ms", total.elapsed().unwrap().as_millis());

    // // //************ Informer ************//
    // let mut informer = Informer::new(Dummy::new());
    // let xs = informer
    //     .encode_many(&gb_inputs, &vec![17; n_gb_inputs])
    //     .unwrap();
    // let ys = informer.receive_many(&vec![17; n_ev_inputs]).unwrap();
    // let all_arith_values: Vec<&DummyVal> = xs.iter().chain(ys.iter()).collect_vec();
    // let informer_output = all_arith_values
    //     .iter()
    //     .map(|&x| informer.bit_decomposition(x).unwrap())
    //     .collect_vec();
    // let informer_output_reveal: Vec<Vec<u16>> = informer_output
    //     .iter()
    //     .map(|x| informer.reveal_many(x).unwrap())
    //     .collect_vec();
    // println!("Informer Output: {:?}", informer_output_reveal);
    // println!("{}", informer.stats());
}

fn run_mod2k_BD(gb_inputs: Vec<u16>, ev_inputs: Vec<u16>, repeat: usize) {
    let (sender, receiver) = unix_channel_pair();
    let n_gb_inputs = gb_inputs.len();
    let n_ev_inputs = ev_inputs.len();
    // print the bits of the inputs as MSB first
    println!(
        "Ev/Gb: {:?}/{:?}",
        ev_inputs
            .iter()
            .rev()
            .map(|x| format!("{:01b}", x))
            .collect_vec(),
        gb_inputs
            .iter()
            .rev()
            .map(|y| format!("{:01b}", y))
            .collect_vec()
    );

    // crt mods' multiplication: the biggest moduli (ring) under the given bitwidth
    // let crt_big_mod = numbers::modulus_with_width(bitwidth as u32);

    let total = SystemTime::now();
    let k = n_gb_inputs + n_ev_inputs; // 2's power

    // ************ Garbler ************//
    let handle = std::thread::spawn(move || {
        let rng = AesRng::new();
        let start = SystemTime::now();
        let mut gb = Garbler::<UnixChannel, AesRng, OtSender, AllWire>::new(sender, rng).unwrap();
        println!(
            "Garbler :: Initialization: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        let xs = gb.encode_many(&gb_inputs, &vec![2; n_gb_inputs]).unwrap();
        let ys = gb.receive_many(&vec![2; n_ev_inputs]).unwrap();
        println!(
            "Garbler :: Encoding inputs: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let all_arith_values: Vec<&AllWire> = xs.iter().chain(ys.iter()).collect_vec();
        let mut gb_output = vec![AllWire::zero(k as u16); k];
        let start = SystemTime::now();
        for _ in 0..repeat {
            let gb_output_2k = gb
                .mod2k_bit_composition(&all_arith_values, None, None)
                .unwrap();
            // let gb_output_2k = gb.cmod(&gb_output_2k, 5).unwrap();
            gb_output = gb.mod2k_bit_decomposition(&gb_output_2k, Some(8)).unwrap();
        }
        println!(
            "Garbler :: Circuit garbling: {:.2} ms",
            start.elapsed().unwrap().as_millis() as f64 / 100.0
        );
        // println!("Gb Output: {:?}", gb_output.digits()); // debug
        let gb_output_reveal = gb.reveal_many(&gb_output).unwrap();
        println!("Gb Output: {:?}", gb_output_reveal);
    });

    //************ Evaluator ************//
    let rng = AesRng::new();
    let start = SystemTime::now();
    let mut ev = Evaluator::<UnixChannel, AesRng, OtReceiver, AllWire>::new(receiver, rng).unwrap();
    println!(
        "Evaluator :: Initialization: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let xs = ev.receive_many(&vec![2; n_gb_inputs]).unwrap();
    let ys = ev.encode_many(&ev_inputs, &vec![2; n_ev_inputs]).unwrap();
    println!(
        "Evaluator :: Encoding inputs: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let all_arith_values: Vec<&AllWire> = xs.iter().chain(ys.iter()).collect_vec();
    let mut ev_output = vec![AllWire::zero(k as u16); k];
    let start = SystemTime::now();
    for _ in 0..repeat {
        let ev_output_temp = ev
            .mod2k_bit_composition(&all_arith_values, None, None)
            .unwrap();
        // let ev_output_temp = ev.cmod(&ev_output_temp, 5).unwrap();
        ev_output = ev
            .mod2k_bit_decomposition(&ev_output_temp, Some(8))
            .unwrap();
    }
    println!(
        "Evaluator :: Circuit evaluation: {:2} ms",
        start.elapsed().unwrap().as_millis() as f64 / 100.0
    );
    // println!("Ev Output: {:?}", ev_output.digits()); // debug
    let ev_output_reveal = ev.reveal_many(&ev_output).unwrap();
    handle.join().unwrap();
    println!("Ev Output: {:?}", ev_output_reveal);
    println!("Total: {} ms", total.elapsed().unwrap().as_millis());

    // // //************ Informer ************//
    // let mut informer = Informer::new(Dummy::new());
    // let xs = informer
    //     .encode_many(&gb_inputs, &vec![17; n_gb_inputs])
    //     .unwrap();
    // let ys = informer.receive_many(&vec![17; n_ev_inputs]).unwrap();
    // let all_arith_values: Vec<&DummyVal> = xs.iter().chain(ys.iter()).collect_vec();
    // let informer_output = all_arith_values
    //     .iter()
    //     .map(|&x| informer.bit_decomposition(x).unwrap())
    //     .collect_vec();
    // let informer_output_reveal: Vec<Vec<u16>> = informer_output
    //     .iter()
    //     .map(|x| informer.reveal_many(x).unwrap())
    //     .collect_vec();
    // println!("Informer Output: {:?}", informer_output_reveal);
    // println!("{}", informer.stats());
}

fn run_crt_BD(gb_inputs: Vec<u128>, ev_inputs: Vec<u128>, bitwidth: usize, repeat: usize) {
    let (sender, receiver) = unix_channel_pair();
    let n_gb_inputs = gb_inputs.len();
    let n_ev_inputs = ev_inputs.len();
    // print the bits of the inputs as MSB first
    println!(
        "Ev/Gb: {:?}/{:?}",
        ev_inputs
            .iter()
            .rev()
            .map(|x| format!("{:01b}", x))
            .collect_vec(),
        gb_inputs
            .iter()
            .rev()
            .map(|y| format!("{:01b}", y))
            .collect_vec()
    );

    // crt mods' multiplication: the biggest moduli (ring) under the given bitwidth
    let mut crt_big_mod = numbers::modulus_with_width(bitwidth as u32);
    // for &p in numbers::PRIMES.iter() {
    //     if (crt_big_mod / p as u128) < (1 << bitwidth) as u128 {
    //         break;
    //     }
    //     crt_big_mod /= p as u128;
    // }

    let total = SystemTime::now();
    // let k = n_gb_inputs + n_ev_inputs; // 2's power

    // ************ Garbler ************//
    let handle = std::thread::spawn(move || {
        let rng = AesRng::new();
        let start = SystemTime::now();
        let mut gb = Informer::new(
            Garbler::<UnixChannel, AesRng, OtSender, AllWire>::new(sender, rng).unwrap(),
        );
        println!(
            "Garbler :: Initialization: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let start = SystemTime::now();
        let xs = gb.crt_encode_many(&gb_inputs, crt_big_mod).unwrap();
        let ys = gb.crt_receive_many(n_ev_inputs, crt_big_mod).unwrap();
        // let xs = gb.bin_encode_many(&gb_inputs, bitwidth).unwrap();
        // let ys = gb.bin_receive_many(n_ev_inputs, bitwidth).unwrap();
        println!(
            "Garbler :: Encoding inputs: {} ms",
            start.elapsed().unwrap().as_millis()
        );
        let all_arith_values = xs.iter().chain(ys.iter()).collect_vec();
        let start = SystemTime::now();
        let gb_output = Some(
            all_arith_values
                .iter()
                .map(|&x| gb.crt_bit_decomposition(x).unwrap())
                .collect_vec(),
        );
        // gb_output = Some(
        //     all_arith_values
        //         .iter()
        //         .map(|bund| gb.crt_bit_composition(bund).unwrap())
        //         .collect_vec(),
        // );
        println!(
            "Garbler :: Circuit garbling: {:.2} ms",
            start.elapsed().unwrap().as_millis() as f64 / 100.0
        );
        // println!("Gb Output: {:?}", gb_output.digits()); // debug
        let gb_output_reveal = gb_output
            .unwrap()
            .iter()
            .map(|x| (gb.bin_reveal(x).unwrap(), gb.reveal_bundle(x).unwrap()))
            // .map(|x| (gb.crt_reveal(x).unwrap(), gb.reveal_bundle(x).unwrap()))
            .collect_vec();
        println!("Gb Output: {:?}", gb_output_reveal);
        println!("Gb Info: {}", gb.stats());
    });

    //************ Evaluator ************//
    let rng = AesRng::new();
    let start = SystemTime::now();
    let mut ev = Informer::new(
        Evaluator::<UnixChannel, AesRng, OtReceiver, AllWire>::new(receiver, rng).unwrap(),
    );
    println!(
        "Evaluator :: Initialization: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let start = SystemTime::now();
    let xs = ev.crt_receive_many(n_gb_inputs, crt_big_mod).unwrap();
    let ys = ev.crt_encode_many(&ev_inputs, crt_big_mod).unwrap();
    // let xs = ev.bin_receive_many(n_gb_inputs, bitwidth).unwrap();
    // let ys = ev.bin_encode_many(&ev_inputs, bitwidth).unwrap();
    println!(
        "Evaluator :: Encoding inputs: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let all_arith_values = xs.iter().chain(ys.iter()).collect_vec();
    let start = SystemTime::now();
    let ev_output = Some(
        all_arith_values
            .iter()
            .map(|&x| ev.crt_bit_decomposition(x).unwrap())
            .collect_vec(),
    );
    // ev_output = Some(
    //     all_arith_values
    //         .iter()
    //         .map(|bund| ev.crt_bit_composition(bund).unwrap())
    //         .collect_vec(),
    // );
    println!(
        "Evaluator :: Circuit evaluation: {:2} ms",
        start.elapsed().unwrap().as_millis() as f64 / 100.0
    );
    // println!("Ev Output: {:?}", ev_output.digits()); // debug
    let ev_output_reveal = ev_output
        .unwrap()
        .iter()
        .map(|x| (ev.bin_reveal(x).unwrap(), ev.reveal_bundle(x).unwrap()))
        // .map(|x| (ev.crt_reveal(x).unwrap(), ev.reveal_bundle(x).unwrap()))
        .collect_vec();
    handle.join().unwrap();
    println!("Ev Output: {:?}", ev_output_reveal);
    println!("Ev Info: {}", ev.stats());
    println!("Total: {} ms", total.elapsed().unwrap().as_millis());
}

fn main() {
    // run_arithmetic(vec![14], vec![17], 8, 101, 1); // 293
    // run_bc(vec![0, 1], vec![0, 1], 1);
    // run_bd(vec![10], vec![], 1);
    // run_mod2k(vec![4], vec![], 1);
    // run_mod2k_BD(
    //     vec![0, 0, 0, 0], vec![1, 1, 0, 1, 1],
    //     1,
    // );
    run_crt_BD(vec![120], vec![], 32, 1);
}
