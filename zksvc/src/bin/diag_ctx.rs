// 一次性诊断：ctx_tag/pred_id 折算值打印（与 Python 门控对照）
use zksvc::ctx_tag::{ctx_tag_from_challenge, fp_from_be32_hex};
use zksvc::profile::pred_id_fp;

fn main() {
    let challenge = {
        let s = "f48a7fb78c30babf05a1411e193a766cbbb6eff8ca8247a46dd2f4e6fed21bdb";
        let mut v = Vec::new();
        for i in (0..s.len()).step_by(2) {
            v.push(u8::from_str_radix(&s[i..i + 2], 16).unwrap());
        }
        v
    };
    let ctx = ctx_tag_from_challenge(&challenge);
    let ctx_hex: String = {
        use ff::PrimeField;
        let b = plonkish_sm2_probe::sm2_z_anchor::fe_be32(&ctx);
        b.iter().map(|x| format!("{x:02x}")).collect()
    };
    println!("ctx_tag_from_challenge = {ctx_hex}");

    let pred = "2c1ab4b3209c9bb8767e831d9714050abafd91d55a0824f1d35de53e8640240e|2ae2cb01bc99a18be37924e5483f22f0|policy-2026-09-v1";
    let pid = pred_id_fp(pred);
    let pid_hex: String = {
        use ff::PrimeField;
        let b = plonkish_sm2_probe::sm2_z_anchor::fe_be32(&pid);
        b.iter().map(|x| format!("{x:02x}")).collect()
    };
    println!("pred_id_fp             = {pid_hex}");
}
