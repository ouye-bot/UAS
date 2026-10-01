//! T1.3b 泄漏半径专项分析 · 逐列跨出示差异审计（2026-09-02）
//!
//! 判定问题（处置表 §九 D17=C 路线输入）：同一用户两次出示（固定
//! sk_u/id_u/attrs、不同会话随机数 r）的 witness 列矩阵逐列对比——
//! - diff==0 的列 = 跨出示逐位恒定 ⟹ 其 BaseFold Merkle 根逐位相同
//!   ⟹ 直接链接测试成立（证明串中该列承诺根可作会话关联指纹）；
//! - diff>0 的列 = 混列/随机化 ⟹ 无直接根相等测试，只剩线性泛函
//!   攻击面（方程计数 vs 列自由度）。
//!
//! 只读审计：装配两次、逐列比较、打印统计；不改任何装配语义。
//! 运行：cargo run --release --bin audit_leak_columns

use plonkish_sm2_probe::sm2_full_statement_assemble::{
    assemble_full_statement, witness_from,
};
use plonkish_sm2_probe::sm2_params::fr_from_limbs;
use plonkish_sm2_probe::sm2_verify_assemble::{
    assemble_show_z_merged, assemble_sm2_verify, verify_replay,
};

fn main() {
    let sk = [0x0B0Bu64, 0, 0, 0x0A0A];
    let mut id = [0u8; 32];
    id[..16].copy_from_slice(plonkish_sm2_probe::sm2_z_anchor::DEFAULT_ID);
    let r1 = [0x11u64, 0, 0, 0x22];
    let r2 = [0x33u64, 0, 0, 0x44];

    // 线选择（T1.3b 覆盖三线）：未设/2=T1 全语句线；ZANCHOR=1=merged；
    // ZANCHOR=0=standalone（与 probe_sm2_verify.rs 的语义约定一致）。
    let zanchor: u32 = std::env::var("ZANCHOR").ok().and_then(|v| v.parse().ok()).unwrap_or(2);

    let (a1, a2) = if zanchor == 1 || zanchor == 0 {
        // merged/standalone：同钥（test_issuer_key 体系）两会话签名。
        // 保守最小变化面：e/P_A 固定（同一凭证消息），仅 (r,s) 变 ——
        // 若这样都能指纹链接，更宽松场景更能。每条签名过 verify_replay
        // 自校验后才进装配（验证锚=verify_replay，非信任抄写）。
        use plonkish_sm2_probe::sm2_full_statement_assemble::sm2_sign_host;
        use plonkish_sm2_probe::sm2_params::fr_to_limbs;
        let d = sm2_sign_host::test_issuer_key();
        let pk = sm2_sign_host::pk_from_sk(&d);
        // P_A 必须与签名钥自洽（a2 向量的 P_A 私钥未知 ⟹ 不可用其点配新
        // 签名）；整条语句用 test_issuer_key 体系：P_A=[d]G，(r,s) 对同一
        // e 两 nonce 重签。审计只关心 witness 对会话随机数的敏感结构，
        // 用户值本身无关。
        let (pax, pay) = pk;
        let (e0, _r0, _s0, _pax0, _pay0) = plonkish_sm2_probe::sm2_verify_assemble::a2_inputs();
        let e_l = fr_to_limbs(&e0);
        let (r1v, s1v) = sm2_sign_host::sign_with_nonce(&e_l, &d, [0x0F0Fu64, 0, 0, 0x5EED]);
        let (r2v, s2v) = sm2_sign_host::sign_with_nonce(&e_l, &d, [0x0E0Eu64, 0, 0, 0x5EEC]);
        for (tag, (rv, sv)) in [("s1", (&r1v, &s1v)), ("s2", (&r2v, &s2v))] {
            assert!(
                verify_replay(
                    e0,
                    fr_from_limbs(rv),
                    fr_from_limbs(sv),
                    pk.0,
                    pk.1,
                )
                .ok,
                "{tag} 签名未过 verify_replay"
            );
        }
        let (e1, s1) = (e0, fr_from_limbs(&r1v));
        let s1b = fr_from_limbs(&s1v);
        let (e2, s2) = (e0, fr_from_limbs(&r2v));
        let s2b = fr_from_limbs(&s2v);
        if zanchor == 1 {
            let id16: &[u8] = plonkish_sm2_probe::sm2_z_anchor::DEFAULT_ID;
            let blocks = plonkish_sm2_probe::sm2_z_anchor::z_u_blocks(id16, &pax, &pay);
            let iv2 = plonkish_sm2_probe::sm2_z_anchor::z_u_prelude_state(id16);
            eprintln!("[audit] ZANCHOR=1 merged assembling show #1 ...");
            let a1 = assemble_show_z_merged(e1, s1, s1b, pax, pay, &blocks[2], &blocks[3], &iv2);
            eprintln!("[audit] assembling show #2 ...");
            let a2 = assemble_show_z_merged(e2, s2, s2b, pax, pay, &blocks[2], &blocks[3], &iv2);
            (a1, a2)
        } else {
            eprintln!("[audit] ZANCHOR=0 standalone assembling show #1 ...");
            let a1 = assemble_sm2_verify(e1, s1, s1b, pax, pay);
            eprintln!("[audit] assembling show #2 ...");
            let a2 = assemble_sm2_verify(e2, s2, s2b, pax, pay);
            (a1, a2)
        }
    } else {
        let w1 = witness_from(sk, id, r1);
        let w2 = witness_from(sk, id, r2);
        eprintln!("[audit] ZANCHOR=2 T1 assembling show #1 (r1) ...");
        let a1 = assemble_full_statement(&w1);
        eprintln!("[audit] assembling show #2 (r2) ...");
        let a2 = assemble_full_statement(&w2);
        (a1, a2)
    };

    let rows = a1.advice.first().map_or(0, |c| c.len());
    println!("advice_cols={}", a1.advice.len());
    println!("rows={rows}");
    println!(
        "instances_equal={}",
        a1.instances == a2.instances
    );
    println!(
        "instance_diff_cells={}",
        a1.instances
            .iter()
            .zip(a2.instances.iter())
            .map(|(x, y)| x.iter().zip(y.iter()).filter(|(p, q)| p != q).count())
            .sum::<usize>()
    );

    let mut same_cols: Vec<usize> = Vec::new();
    let mut diff_hist: std::collections::BTreeMap<usize, usize> = Default::default();
    let mut diff_rows_total = 0usize;
    let mut diff_tags: std::collections::BTreeMap<String, usize> = Default::default();
    let mut same_tags: std::collections::BTreeMap<String, usize> = Default::default();
    for (i, (c1, c2)) in a1.advice.iter().zip(a2.advice.iter()).enumerate() {
        let n = c1.len().min(c2.len());
        let d = c1[..n].iter().zip(c2[..n].iter()).filter(|(x, y)| x != y).count();
        diff_rows_total += d;
        let tag = a1.tags.get(i).map_or("<none>", |t| t.0).to_string();
        if d == 0 {
            same_cols.push(i);
            *same_tags.entry(tag).or_insert(0) += 1;
        } else {
            *diff_hist.entry(d).or_insert(0) += 1;
            *diff_tags.entry(tag).or_insert(0) += 1;
        }
    }

    println!("same_cols_count={}", same_cols.len());
    println!(
        "same_cols_ids={:?}",
        &same_cols[..same_cols.len().min(80)]
    );
    println!("diff_cols_count={}", a1.advice.len().min(a2.advice.len()) - same_cols.len());
    println!("diff_rows_total={diff_rows_total}");
    println!("diff_hist(row_diff -> col_count)={diff_hist:?}");
    println!("diff_tags={diff_tags:?}");
    println!("same_tags={same_tags:?}");
    println!("tags={:?}", a1.tags);
    println!("ctags={:?}", a1.ctags);
    println!("[audit] done");
}
