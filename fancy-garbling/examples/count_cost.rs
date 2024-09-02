use fancy_garbling::util;

fn num_bits(value: u128) -> u16 {
    if value == 0 {
        return 0;
    }
    (128 - value.leading_zeros()) as u16
}

fn bitdecomp(q_in: u16, num_bit_out: u16, row_reduce: bool) -> u16 {
    if row_reduce {
        (q_in - 1) * num_bit_out
    } else {
        (q_in) * num_bit_out
    }
}

fn modqto2k(k_out: u16, q_in: u16, row_reduce: bool) -> u16 {
    if row_reduce {
        k_out * (q_in - 1)
    } else {
        k_out * (q_in)
    }
}

fn bitcomp2k(num_bit_in: u16, k_out: u16, row_reduce: bool) -> u16 {
    let mut nciphertexts = 0;
    for _ in 0..std::cmp::min(k_out, num_bit_in) {
        nciphertexts += k_out * (2 - if row_reduce { 1 } else { 0 });
    }
    nciphertexts
}

fn bitdecomp2k(num_bit_out: u16, k_in: u16, row_reduce: bool) -> u16 {
    let mut nciphertexts = num_bit_out * if row_reduce { 1 } else { 2 };
    for ith in 0..(num_bit_out - 1) {
        let k_out = std::cmp::max(k_in as i16 - ith as i16, 1) as u16;
        nciphertexts += k_out * (2 - if row_reduce { 1 } else { 0 });
    }
    nciphertexts
}

// fn pubdiv_mod2k_our(k: u16, N: u128) -> u16 {
//     let k_E = num_bits(N);
//     bitdecomp2k(k, k)
//         + bitcomp2k(k, 2 * k + 1)
//         + bitdecomp2k(2 * k + 1, 2 * k + 1)
//         + bitcomp2k(2 * k + 1 - (k + k_E), k)
// }

// fn crt_bitdecomp_our(CRT_primes: &Vec<u16>) -> u16 {
//     let ps = CRT_primes;
//     let N = util::product(&ps);
//     let (c_i, k_bits) = util::crt_inv_constants(&ps);
//     let sum_x_bits = num_bits(
//         c_i.iter()
//             .zip(ps.iter())
//             .map(|(&c, &p)| c as u128 * (p as u128 - 1))
//             .fold(0, |acc, x| acc + x),
//     ); // potential max bits needed for Σcx
//     let mut nciphertexts = ps
//         .iter()
//         .fold(0, |acc, &p| acc + bitdecomp(p, num_bits(p as u128 - 1)));
//     // linear BC
//     let num_bin = ps.iter().fold(0, |acc, &p| acc + num_bits(p as u128 - 1));
//     nciphertexts += bitcomp2k(num_bin, sum_x_bits);
//     nciphertexts += pubdiv_mod2k_our(sum_x_bits, N);
//     nciphertexts += bitdecomp2k(k_bits, sum_x_bits);
//     nciphertexts
// }

fn pubdiv_mod2k_paper(k: u16, N: u128, row_reduce: bool) -> u16 {
    let k_E = num_bits(N);
    let k_actual: u16 = if k & 1 == 1 { k / 2 } else { k / 2 - 1 };
    bitdecomp2k(k, k, row_reduce)
        // + bitcomp2k(k, 2 * k + 1)
        // + bitdecomp2k(2 * k + 1, 2 * k + 1)
        + bitcomp2k(k - (k_actual + k_E), k, row_reduce)
}

fn crt_bitdecomp_paper(CRT_primes: &Vec<u16>, row_reduce: bool) -> u16 {
    let ps = CRT_primes;
    let N = util::product(&ps);
    let (c_i, k_bits) = util::crt_inv_constants(&ps);
    let sum_x_bits = num_bits(
        c_i.iter()
            .zip(ps.iter())
            .map(|(&c, &p)| c as u128 * (p as u128 - 1))
            .fold(0, |acc, x| acc + x),
    ); // potential max bits needed for Σcx

    let mut nciphertexts = ps.iter().fold(0, |acc, &p| {
        acc + bitdecomp(p, num_bits(p as u128 - 1), row_reduce)
    });
    // linear BC
    let num_bin = ps.iter().fold(0, |acc, &p| acc + num_bits(p as u128 - 1));
    nciphertexts += bitcomp2k(num_bin, 2 * sum_x_bits + 1, row_reduce);
    nciphertexts += pubdiv_mod2k_paper(2 * sum_x_bits + 1, N, row_reduce);
    nciphertexts += bitdecomp2k(k_bits, 2 * sum_x_bits + 1, row_reduce);
    nciphertexts
}

fn crt_bitcomp(CRT_primes: &Vec<u16>, bitwidth: u16, row_reduce: bool) -> u16 {
    let nciphertexts: u16 = CRT_primes
        .iter()
        .filter(|&p| p != &2u16) // no need to bit comp (mod change) from 2
        .map(|&p_i| {
            let x_i = (0..bitwidth)
                .map(|_| {
                    // proj (mod_change)
                    2 - if row_reduce { 1 } else { 0 }
                })
                .fold(0u16, |acc, x| acc + x);
            x_i
        })
        .fold(0, |acc, x| acc + x);
    nciphertexts
}

fn main() {
    let bitwidth: Vec<u16> = vec![4, 8, 16, 32, 64];
    // for &bw in bitwidth.iter() {
    //     let crt_big_mod = util::modulus_with_width(bw as u32);
    //     let crt_primes = util::factor(crt_big_mod);
    //     println!("bitwidth: {}, crt_primes: {:?}", bw, crt_primes);
    //     println!("crt_bitdecomp_our: {}", crt_bitdecomp_our(&crt_primes));
    //     println!("crt_bitdecomp_paper: {}", crt_bitdecomp_paper(&crt_primes));
    // };

    // for &bw in bitwidth.iter() {
    //     for &rr in [false, true].iter() {
    //         let crt_big_mod = util::modulus_with_width_opt(bw as u32);
    //         let crt_primes = util::factor(crt_big_mod);
    //         println!(
    //             "bitwidth: {}, crt_primes: {:?}, row_reduce: {} ",
    //             bw, crt_primes, rr
    //         );
    //         println!(
    //             "crt_bitdecomp_paper: {}, crt_bitcomp: {} ",
    //             crt_bitdecomp_paper(&crt_primes, rr), crt_bitcomp(&crt_primes, bw, rr)
    //         );
    //     }
    // }

    for bw in 3..128u16 {
        let crt_big_mod = util::modulus_with_width(bw as u32);
        let crt_primes = util::factor(crt_big_mod);
        let crt_big_mod_opt = util::modulus_with_width_opt(bw as u32);
        let crt_primes_opt = util::factor(crt_big_mod_opt);
        print!(
            "bitwidth: $2^{}$; crt_primes old: {:?}; Excess Range: {}; sum old: {}; ",
            bw,
            crt_primes,
            crt_big_mod as f64 / 2u128.pow(bw as u32) as f64,
            crt_primes.iter().sum::<u16>()
        );
        println!(
            "crt_primes new: {:?}; Excess Range: {}; sum new: {}; ",
            crt_primes_opt,
            crt_big_mod_opt as f64 / 2u128.pow(bw as u32) as f64,
            crt_primes_opt.iter().sum::<u16>()
        );
    }
}
