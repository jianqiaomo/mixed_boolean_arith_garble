use fancy_garbling::{
    circuit::{BinaryCircuit as Circuit, EvaluableCircuit}, dummy::DummyVal, twopac::semihonest::{Evaluator, Garbler}, AllWire, BinaryBundle, Fancy, FancyArithmetic, FancyInput, FancyReveal, WireMod2, WireModQ
};
use fancy_garbling::{dummy::Dummy, informer::Informer};
use fancy_garbling::{util as numbers, WireLabel};
use fancy_garbling::{
    ArithmeticBundleGadgets, BinaryGadgets, BundleGadgets, CrtBundle, CrtGadgets, HasModulus,
};
use itertools::{concat, Itertools};
use ocelot::ot::{AlszReceiver as OtReceiver, AlszSender as OtSender};
use scuttlebutt::{unix_channel_pair, AesRng, UnixChannel};
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
        // merge xs WireMod2 bits and ys WireMod2 bits into a single vector
        let decomp_bits: Vec<&AllWire> = xs.iter().chain(ys.iter()).collect_vec();
        let mut gb_output = AllWire::zero(2);
        let start = SystemTime::now();
        for _ in 0..repeat {
            gb_output = gb.bit_composition(&decomp_bits).unwrap();
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
    println!(
        "Evaluator :: Encoding inputs: {} ms",
        start.elapsed().unwrap().as_millis()
    );
    let decomp_bits: Vec<&AllWire> = xs.iter().chain(ys.iter()).collect_vec();
    let start = SystemTime::now();
    let mut ev_output = AllWire::zero(2);
    for _ in 0..repeat {
        ev_output = ev.bit_composition(&decomp_bits).unwrap();
    }
    println!(
        "Evaluator :: Circuit evaluation: {:2} ms",
        start.elapsed().unwrap().as_millis() as f64 / 100.0
    );
    let ev_output_reveal = ev.reveal(&ev_output).unwrap();
    println!("Ev Output: {:?}", ev_output_reveal);
    handle.join().unwrap();
    println!("Total: {} ms", total.elapsed().unwrap().as_millis());

    // //************ Informer ************//
    // let mut informer = Informer::new(Dummy::new());
    // let xs = informer.encode_many(&gb_inputs, &vec![2; n_gb_inputs]).unwrap();
    // let ys = informer.receive_many(&vec![2; n_ev_inputs]).unwrap();
    // let decomp_bits: Vec<&DummyVal> = xs.iter().chain(ys.iter()).collect_vec();
    // let informer_output = informer.bit_composition(&decomp_bits).unwrap();
    // let informer_output_reveal = informer.reveal(&informer_output).unwrap();
    // println!("Informer Output: {:?}", informer_output_reveal);
    // println!("{}", informer.stats());
}

fn main() {
    // let mut circ = circuit("circuits/small_example.txt");
    // run_circuit(&mut circ, vec![1; 1], vec![0; 1]);
    // let mut circ = circuit("circuits/adder_32bit.txt");
    // run_circuit(&mut circ, concat(vec![vec![1; 2], vec![0; 30]]), concat(vec![vec![1; 2], vec![0; 30]]));
    // let mut circ = circuit("circuits/AES-non-expanded.txt");
    // run_circuit(&mut circ, vec![1; 128], vec![0; 128]);
    // let mut circ = circuit("circuits/sha-1.txt");
    // run_circuit(&mut circ, vec![0; 512], vec![]);
    // let mut circ = circuit("circuits/sha-256.txt");
    // run_circuit(&mut circ, vec![0; 512], vec![]);
    // let mut circ = circuit("circuits/MatMult8x8-32.circuit.txt");
    // run_circuit(&mut circ, vec![1; 8*8*32], vec![1; 8*8*32]);
    // run_arithmetic(vec![14], vec![17], 8, 101, 1); // 293
    run_bc(vec![1, 1, 0, 1, 0], vec![1], 1);
}
