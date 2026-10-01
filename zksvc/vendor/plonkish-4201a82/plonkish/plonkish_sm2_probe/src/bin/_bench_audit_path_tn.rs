// C10 · 门限三档审计路径实测（2026-09-11；十三项方案 item C10）
// 参数化 (t,N,iter) —— 原件 _bench_audit_path.rs（(3,5) 已发表口径）保持不动。
// 运行：cargo run --release -p plonkish_sm2_probe --bin _bench_audit_path_tn -- 2 3 50
use plonkish_sm2_probe::sm2_dkg::{
    check_share_against_commitments, combine_decrypt, run_dkg_with_rng, share_decrypt, DkgParams,
};
use rand::RngCore;
use std::time::Instant;

struct Xor(u64);
impl RngCore for Xor {
    fn next_u32(&mut self) -> u32 { self.next_u64() as u32 }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn fill_bytes(&mut self, buf: &mut [u8]) { for c in buf.iter_mut() { *c = self.next_u64() as u8; } }
    fn try_fill_bytes(&mut self, buf: &mut [u8]) -> Result<(), rand::Error> { self.fill_bytes(buf); Ok(()) }
}

fn ms(d: std::time::Duration) -> f64 { d.as_secs_f64() * 1000.0 }

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let t: usize = args.get(1).and_then(|v| v.parse().ok()).unwrap_or(3);
    let n: usize = args.get(2).and_then(|v| v.parse().ok()).unwrap_or(5);
    let n_iter: usize = args.get(3).and_then(|v| v.parse().ok()).unwrap_or(50);
    assert!(n >= 2 * t - 1, "N≥2t−1 前提");
    // --- run_dkg 计时（确定性 RNG 逐次漂移种子） ---
    let t0 = Instant::now();
    for i in 0..n_iter {
        let p = DkgParams { threshold: t, n_committee: n };
        let mut rng = Xor(20260911u64.wrapping_add(i as u64));
        let _ = run_dkg_with_rng(&p, &mut rng).expect("dkg");
    }
    let dkg_ms = ms(t0.elapsed()) / n_iter as f64;
    // --- 一次审计 = t 份额解密 + t 份额核验 + 1 组合 ---
    let p = DkgParams { threshold: t, n_committee: n };
    let mut rng = Xor(20260911);
    let (out, shares) = run_dkg_with_rng(&p, &mut rng).expect("dkg");
    let c1 = out.apk;
    let subset: Vec<(usize, [u64; 4])> = (0..t).map(|i| (i + 1, shares.shares[i])).collect();
    let mut sd_tot = 0.0; let mut ck_tot = 0.0; let mut cb_tot = 0.0;
    for _ in 0..n_iter {
        let t0 = Instant::now();
        let _: Vec<_> = (0..t).map(|i| share_decrypt(&shares.shares[i], &c1)).collect();
        let t1 = Instant::now();
        for i in 0..t {
            let _ = check_share_against_commitments(&shares.shares[i], i + 1, &out.commitments[0]);
        }
        let t2 = Instant::now();
        let _ = combine_decrypt(&c1, &c1, &subset);
        let t3 = Instant::now();
        sd_tot += ms(t1 - t0); ck_tot += ms(t2 - t1); cb_tot += ms(t3 - t2);
    }
    let sd = sd_tot / n_iter as f64; let ck = ck_tot / n_iter as f64; let cb = cb_tot / n_iter as f64;
    println!("[C10] 审计路径实测 (t,N)=({t},{n})，N={n_iter} 次均值 [实测]:");
    println!("  run_dkg(Setup 全流程): {:.2} ms", dkg_ms);
    println!("  份额解密 x t={t}: {:.2} ms", sd);
    println!("  份额核验 x t={t}: {:.2} ms", ck);
    println!("  组合(含 Lagrange): {:.2} ms", cb);
    println!("  单次审计合计: {:.2} ms", sd + ck + cb);
}
