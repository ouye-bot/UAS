//! 飞证 ZK 证明服务——Rust 侧库面（zkc；B3 fork 自隐证通 SP-4 架构，AUTH 单档）。
//!
//! 职责边界：论文栈（plonkish_backend/plonkish_sm2_probe，路径依赖+钉定 commit）
//! 的**服务化封装**——装配参数化、prove→落盘→回读 verify、大文件 SM3 摘要、
//! verify-only 独立验证。不改论文栈任何语义；固定种子保证证明字节级复现。
//!
//! 任务面：Task 3 profile/assemble、Task 4 prove、Task 5 sm3file、Task 6 verify-only
//! （计划：crypto/01_设计文档/plans/2026-09-03-SP4-ZK证明服务.md）。

pub mod assemble;
pub mod ctx_tag;
pub mod pin_fingerprint;
pub mod profile;
pub mod prove;
pub mod sm3file;
pub mod sm3_host;
// SM3 查表化织入层重导出（部署默认函数——生产 pin 口径）。
pub use plonkish_sm2_probe::sm3_lookup_weave;

#[cfg(test)]
pub(crate) mod test_env {
    /// 跨模块共享 env 互斥（工单#3 同族：同一 env 变量的读写测试必须同一把锁。
    /// 2026-09-26 实弹定谂：prove.rs ENV_LOCK 与 assemble.rs TRAIL_ENV_LOCK
    /// 分立后并行态下假红（删 FZ_ZK_ALLOW_TRAIL 撞上并行的装配 unwrap）。
    pub(crate) static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());
}
