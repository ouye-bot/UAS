//! 飞证 ZK 证明服务——Rust 侧库面（zkc；B3 fork 自隐证通 SP-4 架构，AUTH 单档）。
//!
//! 职责边界：论文栈（plonkish_backend/plonkish_sm2_probe，路径依赖+钉定 commit）
//! 的**服务化封装**——装配参数化、prove→落盘→回读 verify、大文件 SM3 摘要、
//! verify-only 独立验证。不改论文栈任何语义；固定种子保证证明字节级复现。
//!
//! 任务面：Task 3 profile/assemble、Task 4 prove、Task 5 sm3file、Task 6 verify-only
//! （计划：crypto/01_设计文档/plans/2026-09-03-SP4-ZK证明服务.md）。

// A3（组合 A，2026-10-06）：mimalloc 全局分配器——prove 峰值窗列级分配 churn
// 压 Windows LFH 碎片残差。分配器换代零语义面：证明字节由转录链决定，与堆
// 布局无涉（固定种子/盐通道均不读堆地址）。
#[global_allocator]
static GLOBAL_ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub mod assemble;
pub mod ctx_tag;
pub mod pin_fingerprint;
pub mod profile;
pub mod prove;
pub mod sm3file;
pub mod sm3_host;
// 优化 2：跨证明确定性产物磁盘缓存（仅 pinned 公开输入确定性产物——随机性
// 纪律红线见模块头；每证明盲化 λ/transcript 熵绝不入缓存）。
pub mod zk_cache;
// SM3 查表化织入层重导出（部署默认函数——生产 pin 口径）。
pub use plonkish_sm2_probe::sm3_lookup_weave;

#[cfg(test)]
pub(crate) mod test_env {
    /// 跨模块共享 env 互斥（工单#3 同族：同一 env 变量的读写测试必须同一把锁。
    /// 2026-09-26 实弹定谂：prove.rs ENV_LOCK 与 assemble.rs TRAIL_ENV_LOCK
    /// 分立后并行态下假红（删 FZ_ZK_ALLOW_TRAIL 撞上并行的装配 unwrap）。
    pub(crate) static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
}
