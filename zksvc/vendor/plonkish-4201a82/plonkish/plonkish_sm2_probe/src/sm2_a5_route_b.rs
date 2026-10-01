//! A5 · 批量开启路线 b(2026-09-15,十三项 A1 阶段 b 的本地 TDD 件)
//!
//! 路线 b = batch_open/batch_verify 的**个体开口按 (查询位置, poly) 去重**:
//! 同一列承诺在同一查询位置的值与 Merkle 路径确定相同,现行实现按 evals
//! 逐条重复书写——去重后每查询每个不同 poly 只写一次,验证侧同构重建,
//! **验证语义逐条不变**(同一组 Merkle 校验与线性组合核对,仅转录字节更少)。
//! 零声音性风险:被合并的是确定性重复数据,不引入新假设、不改任何检查。
//!
//! 开关门:`PCS_BATCH_DEDUP=1`(证明与验证两侧同读;默认关=字节级现行行为)。
//! TDD(本文件先行,红→绿):
//! 1. standalone 验签体(16,554 约束,reps=16 正确性档)OFF 证明+验证 Ok;
//! 2. 同电路 ON 证明+验证 Ok(验证结论逐断言相同=Ok);
//! 3. **尺寸对照**:ON 严格小于 OFF(存在同 poly 多旋转开口 ⟹ 必有去重收益);
//! 4. 负例:ON 下篡改证明首字节 ⟹ 验证必须失败(去重不弱化拒绝面)。
//! e12 禁跑纪律继承;256MB 栈工作线程(深表达式递归,bin 同款)。

use plonkish_backend::{
    backend::{hyperplonk::HyperPlonk, PlonkishBackend, PlonkishCircuit, PlonkishCircuitInfo},
    pcs::multilinear::{Basefold, BasefoldExtParams},
    util::{
        hash::Sm3,
        transcript::{InMemoryTranscript, SM3Transcript},
    },
    Error,
};
use crate::FpSM2;
use rand::{rngs::StdRng, SeedableRng};
use std::io::Cursor;

/// 正确性档 reps=16(与 e2e bin 一致)。
#[derive(Debug)]
pub struct A5Spec;
impl BasefoldExtParams for A5Spec {
    fn get_reps() -> usize {
        16
    }
    fn get_rate() -> usize {
        3
    }
    fn get_basecode_rounds() -> usize {
        0
    }
    fn get_rs_basecode() -> bool {
        false
    }
    fn get_code_type() -> String {
        "random".to_string()
    }
}

type Pcs = Basefold<FpSM2, Sm3, A5Spec>;
type Pb = HyperPlonk<Pcs>;
type T = SM3Transcript<Cursor<Vec<u8>>>;

#[derive(Clone, Debug)]
struct A5Circuit {
    info: PlonkishCircuitInfo<FpSM2>,
    advice: Vec<Vec<FpSM2>>,
    instances: Vec<Vec<FpSM2>>,
}

impl PlonkishCircuit<FpSM2> for A5Circuit {
    fn circuit_info_without_preprocess(&self) -> Result<PlonkishCircuitInfo<FpSM2>, Error> {
        Ok(self.info.clone())
    }
    fn circuit_info(&self) -> Result<PlonkishCircuitInfo<FpSM2>, Error> {
        Ok(self.info.clone())
    }
    fn instances(&self) -> &[Vec<FpSM2>] {
        &self.instances
    }
    fn synthesize(&self, round: usize, challenges: &[FpSM2]) -> Result<Vec<Vec<FpSM2>>, Error> {
        assert!(round == 0 && challenges.is_empty(), "单相电路无挑战");
        Ok(self.advice.clone())
    }
}

fn prove_verify_once(circ: &A5Circuit) -> (usize, bool) {
    let param = Pb::setup(&circ.circuit_info().unwrap(), StdRng::seed_from_u64(0x5EED)).unwrap();
    let (pp, vp) = Pb::preprocess(&param, &circ.circuit_info().unwrap()).unwrap();
    let proof = {
        let mut tr = T::new(());
        Pb::prove(&pp, circ, &mut tr, StdRng::seed_from_u64(0x5EED + 1)).unwrap();
        tr.into_proof()
    };
    let ok = {
        let mut tr = T::from_proof((), proof.as_slice());
        Pb::verify(&vp, &circ.instances, &mut tr, StdRng::seed_from_u64(0x5EED + 2)).is_ok()
    };
    (proof.len(), ok)
}

#[test]
fn a5_route_b_dedup_e2e() {
    let _env = crate::test_env::EnvGuard::toggle(&["PCS_BATCH_DEDUP"]);
    // （env 串行守卫：触达变量 Drop 恢复进入前值——跨测试泄漏清零）
    let child = std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(run_inner)
        .expect("起 256MB 栈工作线程失败");
    match child.join() {
        Ok(()) => {}
        Err(boxed) => std::panic::resume_unwind(boxed),
    }
}

fn run_inner() {
    let (e, r, s, pax, pay) = crate::sm2_verify_assemble::a2_inputs();
    let asm = crate::sm2_verify_assemble::assemble_sm2_verify(e, r, s, pax, pay);
    assert_eq!(asm.info.constraints.len(), 10_424, "standalone 形状漂移（2026-10-01 实测钉：旧钉 16,560 系修复后历史口径，db0bbb3 实测已漂移至 10,489[历史批次 legacy 面未回写]；本次换代 acc.chain 去重 −65=EG 窗 66→1 → 10,424）");
    let circ = A5Circuit {
        info: asm.info.clone(),
        advice: asm.advice.clone(),
        instances: asm.instances.clone(),
    };

    // ① OFF 基线(默认路径=现行字节级行为)。
    std::env::remove_var("PCS_BATCH_DEDUP");
    let (sz_off, ok_off) = prove_verify_once(&circ);
    assert!(ok_off, "OFF 档验证失败(基线必须 Ok)");

    // ② ON 档:验证结论逐断言相同(Ok)。
    std::env::set_var("PCS_BATCH_DEDUP", "1");
    let (sz_on, ok_on) = prove_verify_once(&circ);
    assert!(ok_on, "ON(去重)档验证失败——去重不得改变验证结论");

    // ③ 尺寸对照:ON 严格小于 OFF。
    eprintln!(
        "[A5] OFF proof={} B, ON(去重) proof={} B, 节省 {} B ({:.2}%)",
        sz_off,
        sz_on,
        sz_off - sz_on,
        100.0 * (sz_off - sz_on) as f64 / sz_off as f64
    );
    assert!(
        sz_on < sz_off,
        "去重未产生尺寸收益(ON={sz_on} OFF={sz_off})——电路须含同 poly 多旋转开口"
    );

    // ④前置诊断:OFF(现行)档同位篡改对照——判别末字节拒绝面是否原生存在。
    if std::env::var("A5_DIAG_OFF_TAMPER").map(|v| v == "1").unwrap_or(false) {
        std::env::remove_var("PCS_BATCH_DEDUP");
        let param_d = Pb::setup(&circ.circuit_info().unwrap(), StdRng::seed_from_u64(0x5EED)).unwrap();
        let (pp_d, vp_d) = Pb::preprocess(&param_d, &circ.circuit_info().unwrap()).unwrap();
        let mut pf = {
            let mut tr = T::new(());
            Pb::prove(&pp_d, &circ, &mut tr, StdRng::seed_from_u64(0x5EED + 1)).unwrap();
            tr.into_proof()
        };
        pf[0] ^= 0xFF;
        let mut tr = T::from_proof((), pf.as_slice());
        let v = Pb::verify(&vp_d, &circ.instances, &mut tr, StdRng::seed_from_u64(0x5EED + 2));
        eprintln!("[A5-DIAG] OFF 档末字节篡改 rejected={:?}", v.is_err());
        std::env::set_var("PCS_BATCH_DEDUP", "1");
    }

    // ④ 负例:ON 下篡改证明 ⟹ 拒绝(去重不弱化拒绝面)。
    let param = Pb::setup(&circ.circuit_info().unwrap(), StdRng::seed_from_u64(0x5EED)).unwrap();
    let (pp, vp) = Pb::preprocess(&param, &circ.circuit_info().unwrap()).unwrap();
    let mut proof = {
        let mut tr = T::new(());
        Pb::prove(&pp, &circ, &mut tr, StdRng::seed_from_u64(0x5EED + 1)).unwrap();
        tr.into_proof()
    };
    // 诊断定论(2026-09-15):末字节篡改在 OFF 原生档同样被接受(rejected=false,见 a5_diag2 日志)
    // ——非去重引入、不参与 FS 链。负例锚定首字节(实例承诺盐区首字节,必入 FS 状态)。
    // 🟡勘误(2026-09-16,A3 尺寸封闭式对账 drain=0/尾 0 字节):"转录尾部未消费字节"说法不成立——
    // 末字节=S11 末轮折叠路径最后一个哈希块,被读入但 verifier_query_phase 循环 0..num_rounds
    // 不认证末轮(final_oracle 已整段给出并经 virtual_open 校验)⟹ 每查询 128B 死数据(良性)。
    proof[0] ^= 0xFF;
    let mut tr = T::from_proof((), proof.as_slice());
    let verdict = Pb::verify(&vp, &circ.instances, &mut tr, StdRng::seed_from_u64(0x5EED + 2));
    assert!(verdict.is_err(), "ON 档篡改证明竟被接受——去重弱化拒绝面");

    std::env::remove_var("PCS_BATCH_DEDUP");
    eprintln!("[A5] 路线 b TDD 四断言全绿(去重只减字节,不改验证结论)");
}
