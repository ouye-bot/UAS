//! ③手术 S1b 数学面对拍（zksvc 侧——vendor test cfg 的黄金向量路径是共享仓
//! 深度遗产，不在 vendor 侧跑测试）：L2b 窗口法终点 == affine_mul_bits 真值。

use plonkish_sm2_probe::sm2_ec_plonkish::{affine_mul_bits, Affine};
use plonkish_sm2_probe::sm2_ec_window_gadget::host_mul_g;
use plonkish_sm2_probe::sm2_params::fr_from_limbs;
use plonkish_sm2_probe::FpSM2;

fn g_coords() -> (FpSM2, FpSM2) {
    // SM2 生成元（GB/T 32918 推荐曲线参数）。
    let gx = plonkish_sm2_probe::sm2_params::hex_to_limbs_le(
        "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
    );
    let gy = plonkish_sm2_probe::sm2_params::hex_to_limbs_le(
        "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
    );
    (fr_from_limbs(&gx), fr_from_limbs(&gy))
}

fn bits_le(k: &FpSM2) -> Vec<bool> {
    let l = plonkish_sm2_probe::sm2_params::fr_to_limbs(k);
    (0..256).map(|i| ((l[i / 64] >> (i % 64)) & 1) == 1).collect()
}

#[test]
fn window_host_matches_native_mul_32rand() {
    let g = g_coords();
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for case in 0..32u32 {
        let limbs: [u64; 4] = [next(), next(), next(), next()];
        let k = fr_from_limbs(&limbs);
        let want: Affine = affine_mul_bits(&bits_le(&k), Some(g));
        let got = host_mul_g(&k, g);
        assert_eq!(want, got, "case {case} 窗口法与 native 失配");
    }
}
