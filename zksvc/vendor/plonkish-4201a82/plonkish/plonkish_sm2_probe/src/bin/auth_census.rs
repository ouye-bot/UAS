//! AUTH 服务档结构普查器（R2 电路优化前置，2026-09-23）。
//!
//! 只读诊断：按 B4-T7 服务路径（黄金向量 v4 + SMT 空树见证 + SM3_LUT=1）
//! 装配一次，然后对 `Assembled` 做五面普查——
//! ① 结构五元组 + k + lookups；② 列分配账本（tags 逐家族列数）；
//! ③ 约束家族直方图（ctags 全表）；④ 列消耗普查：逐列 e_c（Σ2^|rot| 开口
//! 权重，t1_layout_screen 同口径）+ 零约束查询列 + 零触达列（无查询 ∧ 无环
//! ——死列候选，纯削减对象）；⑤ 环面：σ 列覆盖数/环边总数/逐列环成员数。
//!
//! 运行：cargo run --release -p plonkish_sm2_probe --bin auth_census
//! （装配 ~8s；全程零语义触碰——任何结构断言失败即 panic=环境漂移信号）。

use plonkish_sm2_probe::sm2_auth_assemble::{sn_hash_of, witness_from_auth, AuthPreimage};
use plonkish_sm2_probe::sm2_full_statement_assemble::{
    assemble_full_statement_auth, AuthCPreimage,
};
use plonkish_sm2_probe::sm2_params::{hex_to_limbs_le, fr_from_limbs};
use plonkish_sm2_probe::sm2_z_anchor::fe_be32;
use plonkish_sm2_probe::FpSM2;
use std::collections::{BTreeMap, BTreeSet};

// 包内相对路径换代（SN 绑定批，2026-10-06）：本工作区布局=uas/zksvc/vendor/
// plonkish-4201a82/...——7 级上行=uas 根（上游共享仓的 uas/uas 双层不存在）。
const VECTOR: &str = include_str!("../../../../../../../zksvc/tests/auth_golden_vector.json");

/// 极简扁平 JSON 字段提取（bin 无 serde_json——dev-dep 纪律）。
/// 仅支持 `"key": "str"` / `"key": num` 两形态；黄金向量为机器生成扁平对象。
fn jfind(text: &str, key: &str) -> String {
    let pat = format!("\"{key}\"");
    let rest = text.split(pat.as_str()).nth(1)
        .unwrap_or_else(|| panic!("缺字段 {key}"));
    let after_colon = rest.splitn(2, ':').nth(1).expect("缺冒号");
    let t = after_colon.trim_start();
    if let Some(stripped) = t.strip_prefix('"') {
        let end = stripped.find('"').expect("字符串未闭合");
        stripped[..end].to_string()
    } else {
        let num: String = t.chars().take_while(|c| c.is_ascii_digit()).collect();
        assert!(!num.is_empty(), "字段 {key} 非数值形态");
        num
    }
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn load_pi() -> (u32, u8, AuthPreimage) {
    let v = VECTOR;
    let pi = AuthPreimage {
        pk_ra: plonkish_sm2_probe::sm2_auth_assemble::pk_from_hex(&jfind(v, "ra_pub_hex")),
        id_prime: hex_to_bytes(&jfind(v, "id_prime_hex")).try_into().unwrap(),
        salt: hex_to_bytes(&jfind(v, "salt_hex")).try_into().unwrap(),
        id_number: jfind(v, "id_number").into_bytes().try_into().unwrap(),
        cert_level: jfind(v, "cert_level").parse::<u8>().unwrap(),
        class_id: v.contains("\"class_id\"")
            .then(|| jfind(v, "class_id")).unwrap_or_else(|| "0".into()).parse::<u8>().unwrap(),
        serial: jfind(v, "sn").into_bytes(),
        pk_holder: plonkish_sm2_probe::sm2_auth_assemble::pk_from_hex(&jfind(v, "holder_pub_hex")),
        sk_holder: hex_to_limbs_le(&jfind(v, "holder_priv_hex")),
        exp_u: jfind(v, "exp_u").parse::<u32>().unwrap(),
        sig_r: hex_to_limbs_le(&jfind(v, "sig_hex")[..64]),
        sig_s: hex_to_limbs_le(&jfind(v, "sig_hex")[64..]),
        // r 派生域（v5 起向量携带；缺省回退 spec 同值 ff*32——共享仓兼容面）。
        challenge: if v.contains("\"challenge_hex\"") {
            hex_to_bytes(&jfind(v, "challenge_hex"))
        } else {
            vec![0xff; 32]
        },
    };
    let required = jfind(v, "required_level").parse::<u32>().unwrap();
    (required, pi.class_id, pi)
}

fn main() {
    let t0 = std::time::Instant::now();
    std::env::set_var("SM3_LUT", "1");
    let (required, _class, pi) = load_pi();
    let w = witness_from_auth(&pi);
    let (siblings, _root0, _bits) = plonkish_sm2_probe::smt_weave::smt_default_witness();
    let key_be = fe_be32(&w.pk_u.0);
    let root = plonkish_sm2_probe::smt_weave::smt_blocks(&key_be, &siblings).1;
    let ap = AuthCPreimage {
        cert_be: u32::from(pi.cert_level).to_be_bytes(),
        class_id: pi.class_id,
        id_number: pi.id_number,
        sn_h: sn_hash_of(&pi.serial),
        serial: pi.serial.clone(),
        smt_siblings: Some(siblings),
        smt_root: Some(root),
    };
    let (asm, _hooks) = assemble_full_statement_auth(
        &w,
        pi.salt,
        ap,
        required,
        FpSM2::from(0xdead_beefu64),
        FpSM2::from(0x1234_5678u64),
        1_700_000_000,
    );
    let info = &asm.info;
    let np = info.preprocess_polys.len();
    let ncols = asm.advice.len();

    // ── ① 结构面 ──
    println!("== ① 结构 ==");
    println!(
        "constraints={} advice={} sel={} prep={} rings={} lookups={} instances={} k={}",
        info.constraints.len(), ncols, asm.num_selectors, np,
        info.permutations.len(), info.lookups.len(),
        asm.instances.first().map_or(0, |x| x.len()), info.k
    );

    // ── ② 列分配账本 ──
    println!("== ② 列分配账本（tags：家族→列数，按列数降序） ==");
    let mut tags: Vec<(&'static str, usize)> = asm.tags.clone();
    tags.sort_by_key(|&(_, n)| std::cmp::Reverse(n));
    let mut tag_total = 0usize;
    for (t, n) in &tags {
        tag_total += n;
        println!("  {:<28} {}", t, n);
    }
    println!("  tags 合计 {} 列（advice 实际 {}）", tag_total, ncols);

    // ── ③ 约束家族直方图 ──
    println!("== ③ 约束家族直方图（ctags，按条数降序） ==");
    let mut chist: BTreeMap<&'static str, usize> = BTreeMap::new();
    for t in &asm.ctags {
        *chist.entry(t).or_insert(0) += 1;
    }
    let mut ch: Vec<(&'static str, usize)> = chist.into_iter().collect();
    ch.sort_by_key(|&(_, n)| std::cmp::Reverse(n));
    for (t, n) in &ch {
        println!("  {:<28} {}", t, n);
    }
    println!("  家族数={} 约束合计={}", ch.len(), ch.iter().map(|x| x.1).sum::<usize>());

    // ── ④ 列消耗普查 ──
    // (poly,rot) 去重对 → 逐列 e_c；列→家族集
    let mut pairs: BTreeSet<(usize, i64)> = BTreeSet::new();
    let mut col_ctags: BTreeMap<usize, BTreeSet<&'static str>> = BTreeMap::new();
    for (ci, cc) in info.constraints.iter().enumerate() {
        for q in cc.used_query() {
            let poly = q.poly();
            let rot = q.rotation().0 as i64;
            pairs.insert((poly, rot));
            if poly > np + 1 {
                col_ctags.entry(poly - 1 - np).or_default().insert(asm.ctags[ci]);
            }
        }
    }
    // lookup 通道引用面：表达式树内 Polynomial(Query) 全量收集（⚠ lookup 列
    // 也是开口/求值消费面——死列判定必须含此面，否则误杀）
    {
        use plonkish_backend::util::expression::Expression;
        fn walk<F: ff::PrimeField>(e: &Expression<F>, out: &mut Vec<(usize, i64)>) {
            match e {
                Expression::Polynomial(q) => out.push((q.poly(), q.rotation().0 as i64)),
                Expression::Negated(a) => walk(a, out),
                Expression::DistributePowers(vs, a) => {
                    for v in vs {
                        walk(v, out);
                    }
                    walk(a, out);
                }
                Expression::Sum(a, b) | Expression::Product(a, b) => {
                    walk(a, out);
                    walk(b, out);
                }
                Expression::Scaled(a, _) => walk(a, out),
                _ => {}
            }
        }
        let mut lq: Vec<(usize, i64)> = Vec::new();
        for chan in &info.lookups {
            for (a, b) in chan {
                walk(a, &mut lq);
                walk(b, &mut lq);
            }
        }
        let mut lpairs: BTreeSet<(usize, i64)> = lq.into_iter().collect();
        println!("== ④-lookup 通道数={} 引用(poly,rot)对={} ==", info.lookups.len(), lpairs.len());
        for &(poly, d) in &lpairs {
            pairs.insert((poly, d));
            if poly > np + 1 {
                col_ctags.entry(poly - 1 - np).or_default().insert("lut.lookup");
            }
        }
    }
    let mut col_ec: BTreeMap<usize, u128> = BTreeMap::new();
    for &(poly, d) in &pairs {
        if poly > np + 1 {
            *col_ec.entry(poly - 1 - np).or_insert(0) += 1u128 << d.abs();
        }
    }

    {
        use plonkish_backend::util::expression::Expression as E2;
        fn walk2<F: ff::PrimeField>(e: &E2<F>, out: &mut Vec<(usize, i64)>) {
            match e {
                E2::Polynomial(q) => out.push((q.poly(), q.rotation().0 as i64)),
                E2::Negated(a) => walk2(a, out),
                E2::DistributePowers(vs, a) => { for v in vs { walk2(v, out); } walk2(a, out); }
                E2::Sum(a, b) | E2::Product(a, b) => { walk2(a, out); walk2(b, out); }
                E2::Scaled(a, _) => walk2(a, out),
                _ => {}
            }
        }
        for (ci, chan) in info.lookups.iter().enumerate() {
            let mut refs: Vec<(usize, i64)> = Vec::new();
            for (a, b) in chan { walk2(a, &mut refs); walk2(b, &mut refs); }
            let adv: Vec<usize> = refs.iter().filter(|&&(p, _)| p > np + 1).map(|&(p, _)| p - 1 - np).collect();
            println!("[lut-chan {}] advice 列引用: {:?}", ci, adv);
        }
    }
    // 环覆盖：列→环成员次数
    let mut col_ring: BTreeMap<usize, usize> = BTreeMap::new();
    let mut ring_edges = 0usize;
    for cyc in &info.permutations {
        ring_edges += cyc.len();
        for &(p, _) in cyc {
            if p > np + 1 {
                *col_ring.entry(p - 1 - np).or_insert(0) += 1;
            }
        }
    }
    let queried: BTreeSet<usize> = col_ec.keys().copied().collect();
    let ringed: BTreeSet<usize> = col_ring.keys().copied().collect();
    let dead: Vec<usize> = (0..ncols).filter(|c| !queried.contains(c) && !ringed.contains(c)).collect();
    let query_only: Vec<usize> = queried.difference(&ringed).copied().collect();
    let ring_only: Vec<usize> = ringed.difference(&queried).copied().collect();
    println!("== ④ 列消耗 ==");
    println!(
        "  查询列={} 环覆盖列={} 双无列(死列候选)={} 仅查询={} 仅环={}",
        queried.len(), ringed.len(), dead.len(), query_only.len(), ring_only.len()
    );
    if !dead.is_empty() {
        println!("  死列清单（首 40）: {:?}", &dead[..dead.len().min(40)]);
        // 邻域归因：死列 c 的 c-2..c+2 查询家族（死列常为某 gadget 组内弃子）
        for &c in dead.iter().take(24) {
            let mut nb: Vec<String> = Vec::new();
            for d in -2i64..=2i64 {
                let cc = c as i64 + d;
                if cc < 0 || cc as usize >= ncols {
                    continue;
                }
                let fam = col_ctags.get(&(cc as usize))
                    .map(|x| x.iter().copied().collect::<Vec<_>>().join("+"))
                    .unwrap_or_else(|| "-".into());
                nb.push(format!("{}{}:[{}]", if d == 0 { "*" } else { "" }, cc, fam));
            }
            println!("    死列 advice[{}] 邻域 {}", c, nb.join(" "));
        }
        // 完整清单落盘（死列差分工程输入）
        let path = std::env::var("AUTH_CENSUS_DEAD").unwrap_or_else(|_| "auth_dead_cols.txt".into());
        let text = dead.iter().map(|c| c.to_string()).collect::<Vec<_>>().join("\n");
        std::fs::write(&path, text).expect("死列清单落盘失败");
        println!("  完整死列清单 → {}（共 {} 列）", path, dead.len());
    }
    // e_c 头部（top 16）
    let mut ec: Vec<(usize, u128)> = col_ec.iter().map(|(&c, &e)| (c, e)).collect();
    ec.sort_by_key(|&(_, e)| std::cmp::Reverse(e));
    let heavy: u128 = ec.iter().filter(|&&(_, e)| e > 11).map(|&(_, e)| e).sum();
    println!(
        "  e_c>11 heavy 列数={} 质量={} | cur 对={} | Σ2^|d| 全体（E,PCS 开口代理）={} | 去重 (列,rot) 对={}",
        ec.iter().filter(|&&(_, e)| e > 11).count(), heavy,
        pairs.iter().filter(|&&(_, d)| d == 0).count(),
        col_ec.values().sum::<u128>(), pairs.len()
    );
    for &(c, e) in ec.iter().take(16) {
        let fam: Vec<&str> = col_ctags.get(&c).map(|x| x.iter().copied().collect()).unwrap_or_default();
        println!("    advice[{}] e_c={} ring_n={} families={:?}", c, e, col_ring.get(&c).copied().unwrap_or(0), fam);
    }

    // ── ⑤ 家族×（约束, 列）联合归因：哪个家族吃掉多少列/多少约束 ──
    println!("== ⑤ 家族联合归因（列按首要家族归属——约束查询优先，纯环列归 ring-only） ==");
    let mut fam_cols: BTreeMap<String, usize> = BTreeMap::new();
    for c in 0..ncols {
        let key = match col_ctags.get(&c) {
            Some(fs) if !fs.is_empty() => fs.iter().next().unwrap().to_string(),
            _ => if ringed.contains(&c) { "ring-only".into() } else { "dead/other".into() },
        };
        *fam_cols.entry(key).or_insert(0) += 1;
    }
    let mut fc: Vec<(String, usize)> = fam_cols.into_iter().collect();
    fc.sort_by_key(|&(_, n)| std::cmp::Reverse(n));
    for (t, n) in &fc {
        println!("  {:<28} {} 列", t, n);
    }

    // e2e 结构守卫（⑦代换代锚 2026-10-06——SM3 组列共享+查表通道合并）：漂移=
    // 环境漂移，当场爆。演进链：R3-3.1 判决行 44,383/10,360/544 [实测 SV 云服务
    // 器 12C/46G] → 电路手术 ~38.2K → 20,102 → 19,578（advice 10,283/实例 25/
    // lookups 548）→ ⑥代 19,608/10,534/556/26（SN 绑定第 5 组查表门+组合 A）→
    // ⑦代 19,434/8,410/195/26：69 组 SM3 查表门 34 列独占→lane band 列池 799 列
    //（XOR2 19 带 57 / XOR3 34 带 136 / MAJ 7 带 28 / CH 28 / SPLIT1 26 带 130 /
    // SPLIT3 46 带 230 / ADD 26 带 182 / INPUT 4 / CONST 每电路 1 共 4——SPLIT3
    // 2,688 行/组 > 4095/2 ⟹ 每带恰 1 组，列下界主体）；552 SM3 通道按 lane×band
    // 合并为 191；msg-limb 桥列 packing 704→128（行去重 first-fit 16 集×8）；
    // 门 276→102（lane×band + 每电路 const 门）。估算「~8 通道/全组 1 套 34 列」
    // 按扁平行带推得，忽略列角色对齐约束（一物理列承载两角色格 ⟹ 查表元组/
    // 线性门跨角色混载必违约）——实测以 census 为准（本断言）。
    assert_eq!(info.constraints.len(), 19_434, "AUTH 服务档约束数漂移（⑦代锚）");
    assert_eq!(ncols, 8_410, "AUTH 服务档 advice 列数漂移（⑦代锚）");
    assert_eq!(info.lookups.len(), 195, "AUTH 服务档 lookup 通道数漂移（⑦代锚）");
    println!("[auth-census] 完成耗时 {:?}", t0.elapsed());
    let _ = fr_from_limbs(&[0; 4]); // 保持 import 对拍面
}
