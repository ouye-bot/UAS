//! host 侧 SM3 入口（sm3 crate 0.4.2 封装，锁版本与旧 zksvc 一致）。
//! 用途：pin 指纹 / proof_digest / 判决件 / 文件清单——B3 起的全部 host 哈希面。
//! 官方向量门禁=tests/sm3_vectors.rs（GB/T 32905 A.1/A.2 + 空消息一致性）。

use sm3::{Digest, Sm3};

/// hex 消息 → 32B 摘要的 hex（小写）。非法 hex 输入返回 Err。
pub fn sm3_hex(msg_hex: &str) -> Result<String, String> {
    let msg = hex::decode(msg_hex).map_err(|e| format!("非法 hex: {e}"))?;
    let mut h = Sm3::new();
    h.update(&msg);
    Ok(hex::encode(h.finalize()))
}

/// bytes → 32B 摘要。
pub fn sm3_bytes(msg: &[u8]) -> [u8; 32] {
    let mut h = Sm3::new();
    h.update(msg);
    let out = h.finalize();
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&out);
    buf
}
