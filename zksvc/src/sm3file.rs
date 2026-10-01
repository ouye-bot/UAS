//! 大文件 SM3 流式摘要（SP-4 Task 5）。
//!
//! 实现：crates.io `sm3` crate 标准 `Digest`（与论文栈 transcript 同源——
//! PROBE.md P2 定谳），`update` 分块流式，块常量 64_000。
//!
//! 对拍锚 = SP-2 Python `app.crypto.sm3`（全系统唯一哈希入口纪律的两侧
//! 端点）：GB/T 32905 权威向量与跨语言逐字节对拍由 Python 门禁承担
//! （`backend/tests/test_zk_sm3_cross.py`）；Rust 侧锚=分块与一次性 digest
//! 等价（`tests/sm3file.rs`）。0C 定谳：Python 侧引擎选择（OpenSSL C 实现
//! 优先+锚向量验证+gmssl 回落）与 Rust sm3 crate 同源 GB/T——引擎差异
//! 不构成语义差异。

use std::io::Read as _;
use std::path::Path;

use sm3::Digest as _;

/// 分块常量（计划 Task 5 钉定 64_000）。
pub const CHUNK: usize = 64_000;

/// 文件 SM3 hex。任何 IO 失败 = `Err`（不 panic——服务边界纪律）。
pub fn sm3_file_hex(path: &Path) -> Result<String, String> {
    let mut f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut h = sm3::Sm3::new();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = f.read(&mut buf).map_err(|e| format!("{}: {e}", path.display()))?;
        if n == 0 {
            break;
        }
        sm3::Digest::update(&mut h, &buf[..n]);
    }
    Ok(sm3::Digest::finalize(h)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect())
}
