//! 电路身份指纹（SP-4 Task 4）：Rust 侧独立复算 `SM3(<pin>|<aggregate>)`。
//!
//! 与 `scripts/verify_vendor_manifest.py` 同构（fail-closed 语义逐条对齐）：
//! ① 逐文件存在性+字节数+SM3 重算（声明序）② 聚合 = 逐文件声明 hex 串连接
//! 后整体 SM3 ③ `file_count` 与声明面一致。任何一步失败即 `Err`——
//! **电路身份不明不出证明**（prove_pipeline 前置调用，漂移=PinDrift 拒绝）。
//!
//! 摘要算法一律 SM3（sm3 crate，与论文栈 transcript 同源）——全系统唯一
//! 哈希入口纪律，禁 SHA 混用。指纹是 Task 11 电路版本承诺上链的承诺对象。

use std::path::Path;

use serde::Deserialize;
use sm3::{Digest, Sm3};

#[derive(Deserialize)]
struct Manifest {
    pin_commit: String,
    file_count: usize,
    files: Vec<FileEntry>,
}

#[derive(Deserialize)]
struct FileEntry {
    path: String,
    bytes: u64,
    sm3: String,
}

/// 复算 vendor 快照的电路身份指纹。
/// `vendor` = 快照目录（MANIFEST.json 位于其同级，0B 落点约定）。
pub fn vendor_fingerprint(vendor: &Path) -> Result<String, String> {
    let manifest_path = vendor
        .parent()
        .ok_or_else(|| "vendor 路径异常（无父目录）".to_string())?
        .join("MANIFEST.json");
    let text = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("MANIFEST 不可读 {}: {e}", manifest_path.display()))?;
    let m: Manifest =
        serde_json::from_str(&text).map_err(|e| format!("MANIFEST 损坏: {e}"))?;

    if m.file_count != m.files.len() {
        return Err(format!(
            "MANIFEST 声明面不自洽：file_count={} ≠ files.len()={}",
            m.file_count,
            m.files.len()
        ));
    }

    // fail-closed 逐文件重算（声明序）：任何漂移即整体拒绝
    let mut aggregate = Sm3::new();
    for f in &m.files {
        let p = vendor.join(&f.path);
        let data = std::fs::read(&p)
            .map_err(|e| format!("vendor 文件不可读 {}: {e}", f.path))?;
        if data.len() as u64 != f.bytes {
            return Err(format!("漂移（字节数）: {}", f.path));
        }
        let mut h = Sm3::new();
        h.update(&data);
        if hex_lower(&h.finalize()) != f.sm3 {
            return Err(format!("漂移（SM3）: {}", f.path));
        }
        aggregate.update(f.sm3.as_bytes());
    }

    Ok(format!("SM3({}|{})", m.pin_commit, hex_lower(&aggregate.finalize())))
}

fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 快自检：真树指纹可复算且前缀形态正确（完整对拍在
    /// tests/prove_standalone.rs 快①——与 MANIFEST 声明序重算逐字节比对）。
    /// pin 与快照路径从事实源 build_manifest.json 动态读取（upgrade_pin.sh
    /// 仪式更新）——硬编码 pin 会在升级后假红（a35498b 升级实测踩坑）。
    #[test]
    fn real_tree_fingerprint_shape() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let bm: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(root.join("build_manifest.json"))
                .expect("build_manifest.json 不可读"),
        )
        .expect("build_manifest.json 损坏");
        let rel = bm["snapshot_dir"].as_str().expect("snapshot_dir 缺失");
        // rel 形如 "zksvc/vendor/plonkish-<pin>"，相对 system 根（本 crate 父目录）
        let system_root = root.parent().expect("zksvc 必有父目录");
        let vendor = system_root.join(rel);
        if !vendor.is_dir() {
            return; // 快照不在本检出时静默（集成测试有 skipif 同款语义）
        }
        let pin = bm["pinned_commit_short"]
            .as_str()
            .expect("pinned_commit_short 缺失");
        let fp = vendor_fingerprint(&vendor).expect("真树必须绿");
        assert!(fp.starts_with(&format!("SM3({pin}|")), "{fp}");
    }
}
