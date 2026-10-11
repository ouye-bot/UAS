//! 外层 sumcheck 批量求值通道（2026-10-11，路线甲：同域向量化——零语句/零
//! 语义/零电路）。
//!
//! 本模块只含 **F 无关**基础设施：
//! ① `PackedProgram`——把表达式 registry 的 `Calculation` 列表编译成「已解析
//!    操作数 + 槽位复用」的扁平操作流（SoA 求值器的索引面）；
//! ② `ProverStatePublic`/`RegistryPublic`——ProverState/ExpressionRegistry 的
//!    只读快照视图（backend 内部构造，执行体只读消费）；
//! ③ `PackedRegistration` + `register_packed`/`try_packed`——F-free 注册面：
//!    具体域 crate（plonkish_sm2_probe 的 FpSM2）在 prove 前注册本域 AVX2
//!    执行体。🔴 派遣 soundness 门=TypeId：注册声明的域与当前 F 逐位同一才
//!    放行（否则标量路径）——F-erased 入参经指针还原为**同一类型**的重解释。
//!    orphan 规则与泛型特化的相容性墙（blanket impl 与域特化 impl E0119 冲突
//!    实锤）由此绕开：类型无关的数据注册——无 impl 冲突；`try_packed` 的
//!    `F: 'static` bound 只落在 EvaluationsProver/调用链的显式签名上（本批
//!    传染面=eval.rs×2 impl + hyperplonk prover/verifier 函数签名 + hyperplonk/
//!    protostar impl 头，全部具体类型实例化收敛）。未注册=标量路径零变化
//!    （一切非 FpSM2 域、vendor 单测、wasm 构建原样）。
//!
//! 🔴 零语义边界：本通道只改变「求值在哪里/怎么算」，不改任何域运算的数学
//! 结果——packed 执行体逐 limb 复刻 ff_derive 的蒙哥马利语义（同 lazy 代表元
//! 位型），等价性由域差分对拍测试与同见证证明逐字节锚双实锤；sumcheck 各点
//! 独立求值+域加法交换律 ⟹ 点分组与并行划分变化零语义。
//! 差分位：`FZ_ZK_PACKED_SUMCHECK=0`（注册方消费；不注册=标量路径）。

use crate::util::{
    arithmetic::PrimeField,
    expression::evaluator::{Calculation, ExpressionRegistry, Offsets},
};
use std::{any::TypeId, marker::PhantomData, sync::OnceLock};

/// SoA 求值程序的单条操作（操作数已解析为 cache 槽位；输出=目标槽）。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum POp {
    /// cache[o] = cache[a] * cache[b]
    Mul(u32, u32, u32),
    /// cache[o] = cache[a] + cache[b]
    Add(u32, u32, u32),
    /// cache[o] = cache[a] - cache[b]
    Sub(u32, u32, u32),
    /// cache[o] = -cache[a]
    Neg(u32, u32),
}

impl POp {
    pub fn out(&self) -> u32 {
        match self {
            POp::Mul(_, _, o) | POp::Add(_, _, o) | POp::Sub(_, _, o) | POp::Neg(_, o) => *o,
        }
    }
}

/// 编译产物：扁平操作流 + 复用 scratch 槽位数。
/// 槽位布局与标量 cache 同构：`[0..calc_base)` = 常量/Identity/Lagrange/EqXY/
/// Poly 输入槽（编号不变）；`[calc_base..calc_base+scratch)` = 复用 scratch
/// （原 calc 槽经活跃区间线性扫描分配映射过去）。
#[derive(Clone, Debug)]
pub struct PackedProgram {
    pub ops: Vec<POp>,
    pub scratch: usize,
}

/// 把 registry 的计算列表编译为 SoA 操作流（槽位复用=活跃区间线性扫描）。
///
/// 🔴 复用只改「值放在哪个槽」，不改数据流：每条操作读的操作数与其在原
/// 列表中的唯一活跃定义一一对应（last_use 判死，死亡槽即刻回收），每条
/// 操作的算子与操作数值序同原列表 ⟹ 计算图同构。根输出=末条操作的输出槽
/// （registry 注册序最后一个 calculation 即表达式根 ⟹ 编译序末条=根；执行
/// 体读该槽即等价于标量路径的 `cache.cache.last()`——值同，槽号可异）。
pub fn compile_program(calcs: &[Calculation<usize>], calc_base: usize) -> PackedProgram {
    let n = calcs.len();
    if n == 0 {
        return PackedProgram { ops: Vec::new(), scratch: 0 };
    }
    // 每个原 calc 槽的最后一次被读位置（相对 op 序；不被后读=usize::MAX，仅根）。
    let mut last_use = vec![usize::MAX; n];
    for (i, c) in calcs.iter().enumerate() {
        let mut note = |idx: usize| {
            if idx >= calc_base {
                let rel = idx - calc_base;
                if rel < n {
                    last_use[rel] = i;
                }
            }
        };
        match c {
            Calculation::Negated(v) => note(*v),
            Calculation::Add(a, b) | Calculation::Sub(a, b) | Calculation::Mul(a, b) => {
                note(*a);
                note(*b);
            }
        }
    }
    // 按死亡时刻分桶（存相对 idx；回收时经 slot_map 换算成 scratch 槽号）。
    let mut deadlist: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (rel, lu) in last_use.iter().enumerate() {
        if *lu != usize::MAX {
            deadlist[*lu].push(rel);
        }
    }
    let mut slot_map = vec![0u32; n];
    // 🔴 全部槽号以**绝对槽号**落 POp（2026-10-11 根修：首版 scratch 用相对号，
    // walk 按绝对寻址 ⟹ scratch 覆盖常量/输入槽区——AUTH 的 α^i 常量面被冲毁
    // 全系数错；零检查测试因「结果恒零不依赖被毁常量」侥幸绿，AUTH 实弹揪出）。
    let resolve = |slot_map: &[u32], idx: usize| -> u32 {
        if idx >= calc_base {
            slot_map[idx - calc_base] + calc_base as u32
        } else {
            idx as u32
        }
    };
    let mut free: Vec<u32> = Vec::new();
    let mut next: u32 = 0;
    let mut ops = Vec::with_capacity(n);
    for (i, c) in calcs.iter().enumerate() {
        let rel_out = free.pop().unwrap_or_else(|| {
            let s = next;
            next += 1;
            s
        });
        slot_map[i] = rel_out;
        let out = rel_out + calc_base as u32;
        ops.push(match c {
            Calculation::Negated(v) => POp::Neg(resolve(&slot_map, *v), out),
            Calculation::Add(a, b) => {
                POp::Add(resolve(&slot_map, *a), resolve(&slot_map, *b), out)
            }
            Calculation::Sub(a, b) => {
                POp::Sub(resolve(&slot_map, *a), resolve(&slot_map, *b), out)
            }
            Calculation::Mul(a, b) => {
                POp::Mul(resolve(&slot_map, *a), resolve(&slot_map, *b), out)
            }
        });
        for rel in &deadlist[i] {
            free.push(slot_map[*rel]);
        }
    }
    PackedProgram { ops, scratch: next as usize }
}

/// 编译入口（eval.rs 惰性调用）：registry → PackedProgram。crate 内消费面。
pub(crate) fn program_of<F: PrimeField>(reg: &ExpressionRegistry<F>) -> PackedProgram {
    compile_program(reg.indexed_calculations(), reg.offsets().calculations())
}

/// ProverState 的只读公开视图（packed 执行体消费面——backend 内部构造，
/// 执行体只读）。字段与 `ProverState` 对应私有字段同源同值，构造即借用
/// 快照，零行为。`'a`=Cow 的底层多项式借用，`'b`=本视图对 state 的借用。
pub struct ProverStatePublic<'a, 'b, F: PrimeField> {
    pub num_vars: usize,
    pub degree: usize,
    pub round: usize,
    pub size: usize,
    pub identity: F,
    pub lagranges: &'b std::collections::HashMap<i32, (usize, F)>,
    pub eq_xys: &'b [crate::poly::multilinear::MultilinearPolynomial<F>],
    pub polys:
        &'b [Vec<std::borrow::Cow<'a, crate::poly::multilinear::MultilinearPolynomial<F>>>],
    pub challenges: &'b [F],
    pub _marker: PhantomData<(&'a (), &'b ())>,
}

/// registry 只读快照打包（packed 执行体一次取全）。
pub struct RegistryPublic<'a, F: PrimeField> {
    pub constants: &'a [F],
    pub lagranges: &'a [i32],
    pub eq_xys: &'a [usize],
    pub rotations: &'a [crate::util::expression::Rotation],
    pub polys: &'a [(crate::util::expression::Query, usize)],
    pub offsets: Offsets,
    pub _marker: PhantomData<&'a F>,
}

/// F-erased 执行体入参（TypeId 门放行后由注册方还原为本域具体类型——
/// 门保证 `F` 与注册域逐位同一 ⟹ 还原是同一类型重解释，sound）。
pub struct ExecThunk<'a, F: PrimeField> {
    pub first_round: bool,
    pub view: &'a ProverStatePublic<'a, 'a, F>,
    pub reg: &'a RegistryPublic<'a, F>,
    pub program: &'a PackedProgram,
    pub evals: *mut super::eval::Evaluations<F>,
    pub points: usize,
}

/// F-erased 执行体签名：入参=`&ExecThunk<'_, '_, 声明域>` 的 `*const u8`。
pub type ExecFn = fn(*const u8);

/// 注册体（域 crate 在 prove 前调用一次）。
/// `field`=注册域 TypeId（执行体派遣的 soundness 门）；`modulus`/`inv`=域常数
/// （执行体自行从本体常量取——此处冗余携带供 backend 侧对拍与未来复用）。
pub struct PackedRegistration {
    pub field: TypeId,
    pub modulus: [u64; 5],
    pub inv: u64,
    pub exec: ExecFn,
}

static PACKED_EXEC: OnceLock<Option<PackedRegistration>> = OnceLock::new();

/// 注册（幂等：OnceLock 首注册生效；重复调用零副作用）。
pub fn register_packed(reg: PackedRegistration) {
    let _ = PACKED_EXEC.set(Some(reg));
}

/// 当前注册体（未注册=None ⟹ 调用方走标量路径）。
pub fn packed_exec() -> Option<&'static PackedRegistration> {
    PACKED_EXEC.get().and_then(|o| o.as_ref())
}

/// 派遣入口（eval.rs 消费）：TypeId 门（声明域==当前 F 逐位同一）+ 执行。
/// 门不过（未注册/异域/程序空）=false ⟹ 调用方回退标量路径。
/// 诊断旋钮 `FZ_ZK_PACKED_MAX_ROUND`（仅 timer 构建消费；"N"=round≥N 回退
/// 标量——packed/标量偏差的逐轮二分定位用，发布构建零开销）。
pub fn try_packed<F: PrimeField + 'static>(
    first_round: bool,
    view: &ProverStatePublic<'_, '_, F>,
    reg: &RegistryPublic<'_, F>,
    program: &PackedProgram,
    evals: &mut super::eval::Evaluations<F>,
    points: usize,
) -> bool {
    let Some(px) = packed_exec() else {
        return false;
    };
    if px.field != TypeId::of::<F>() || program.ops.is_empty() || program.scratch == 0 {
        return false;
    }
    #[cfg(feature = "timer")]
    if let Ok(cap) = std::env::var("FZ_ZK_PACKED_MAX_ROUND") {
        if let Ok(n) = cap.parse::<usize>() {
            let round = view.round;
            if round >= n {
                return false;
            }
        }
    }
    let thunk = ExecThunk {
        first_round,
        view,
        reg,
        program,
        evals: evals as *mut super::eval::Evaluations<F>,
        points,
    };
    let erased = &thunk as *const ExecThunk<'_, F> as *const u8;
    (px.exec)(erased);
    true
}
