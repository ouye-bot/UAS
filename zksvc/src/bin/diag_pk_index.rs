// 诊断（安全修复[严重1]）：定位 RA 公钥（pk_I）与 pk′ 坐标在 instances 中的下标。
// 用法: diag_pk_index <job.json>
use plonkish_sm2_probe::FpSM2;
use zksvc::assemble::assemble;

fn fe_from_be32(b: &[u8; 32]) -> FpSM2 {
    // 与 ctx_tag::fp_from_be32_hex 同构（大端 32B → 域元素）
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    zksvc::ctx_tag::fp_from_be32_hex(&hex).expect("非法域元素")
}

fn main() {
    let path = std::env::args().nth(1).expect("用法: diag_pk_index <job.json>");
    let text = std::fs::read_to_string(&path).expect("job 不可读");
    let spec: zksvc::profile::JobSpec = serde_json::from_str(&text).expect("spec 损坏");
    std::env::set_var("FZ_ZK_ALLOW_AUTH", "1");
    let asm = assemble(&spec).expect("装配失败");

    let ra_hex = match spec.input.as_ref().expect("input") {
        zksvc::profile::ProfileInput::Auth { ra_pk_hex, .. } => ra_pk_hex.clone(),
        _ => panic!("需 auth 档"),
    };
    let ra = hex::decode(&ra_hex).unwrap();
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(&ra[..32]);
    y.copy_from_slice(&ra[32..]);
    let pkx = fe_from_be32(&x);
    let pky = fe_from_be32(&y);

    let flat: Vec<&Vec<FpSM2>> = asm.instances.iter().collect();
    println!("instance columns = {}", flat.len());
    for (ci, col) in flat.iter().enumerate() {
        for (vi, v) in col.iter().enumerate() {
            if *v == pkx {
                println!("RA.pkx hit at inst[{ci}][{vi}]");
            }
            if *v == pky {
                println!("RA.pky hit at inst[{ci}][{vi}]");
            }
        }
    }
    // 命中行也列出 tag 名（若 tags 命中同列）
    for (name, idx) in &asm.tags {
        println!("tag {name} -> col {idx}");
    }
}
