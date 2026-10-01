// #14 审计路径微基准(N=50;簇 D;2026-09-09)——款式同 π_link 3.1/6.2ms
// 计时对象:run_dkg(Setup)/份额解密 share_decrypt/份额核验 check_share_against_commitments/
// 组合 combine_decrypt(含 lagrange_zero)。(t,N)=(3,5)。
use plonkish_sm2_probe::sm2_dkg::{
    check_share_against_commitments, combine_decrypt, run_dkg_with_rng, share_decrypt, DkgParams,
};
use rand::RngCore;
use std::time::Instant;

struct Xor(u64);
impl RngCore for Xor {
    fn next_u32(&mut self) -> u32 { self.next_u64() as u32 }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    fn fill_bytes(&mut self, buf: &mut [u8]) { for c in buf.iter_mut() { *c = self.next_u64() as u8; } }
    fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), rand::Error> { self.fill_bytes(buf); Ok(()) }
}

fn ms(d: std::time::Duration) -> f64 { d.as_secs_f64() * 1000.0 }

fn main() {
    let n_iter = 50usize;
    // --- run_dkg 计时(50 次,注入确定性 RNG) ---
    let t0 = Instant::now();
    for i in 0..n_iter {
        let p = DkgParams { threshold: 3, n_committee: 5 };
        let mut rng = Xor(20260909u64.wrapping_add(i as u64));
        let _ = run_dkg_with_rng(&p, &mut rng).expect("dkg");
    }
    let dkg_ms = ms(t0.elapsed()) / n_iter as f64;

    // --- 一次审计 = t 份额解密 + t 份额核验 + 1 组合 ---
    let p = DkgParams { threshold: 3, n_committee: 5 };
    let mut rng = Xor(20260909);
    let (out, shares) = run_dkg_with_rng(&p, &mut rng).expect("dkg");
    let c1 = out.apk; // 同量级点乘载荷
    let subset: Vec<(usize, [u64; 4])> = (0..3).map(|i| (i + 1, shares.shares[i])).collect();
    let mut sd_tot = 0.0; let mut ck_tot = 0.0; let mut cb_tot = 0.0;
    for _ in 0..n_iter {
        let t0 = Instant::now();
        let _: Vec<_> = (0..3).map(|i| share_decrypt(&shares.shares[i], &c1)).collect();
        let t1 = Instant::now();
        for i in 0..3 {
            let _ = check_share_against_commitments(&shares.shares[i], i + 1, &out.commitments[0]);
        }
        let t2 = Instant::now();
        let _ = combine_decrypt(&c1, &c1, &subset);
        let t3 = Instant::now();
        sd_tot += ms(t1 - t0); ck_tot += ms(t2 - t1); cb_tot += ms(t3 - t2);
    }
    let sd = sd_tot / n_iter as f64; let ck = ck_tot / n_iter as f64; let cb = cb_tot / n_iter as f64;
    println!("#14 审计路径微基准 (t,N)=(3,5),N=50 次均值 [实测]:");
    println!("  run_dkg(Setup 全流程, N 委员广播+核验+聚合): {:.2} ms", dkg_ms);
    println!("  份额解密 share_decrypt x t=3            : {:.2} ms", sd);
    println!("  份额核验 check_share_against_commit x t : {:.2} ms", ck);
    println!("  组合 combine_decrypt(含 Lagrange, 1 次)  : {:.2} ms", cb);
    println!("  单次审计合计(解密+核验+组合)             : {:.2} ms", sd + ck + cb);
}
