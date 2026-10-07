//! 跨证明确定性产物磁盘缓存（优化 2：zksvc 跨证明确定性产物复用）。
//!
//! 设计定谳（与原"常驻 daemon 进程缓存"案的偏离及理由）：改为**磁盘工件缓存
//! + 惰性加载**——免守护进程生命周期/端口/桥改造；OS 页缓存天然承担"常驻"
//! （首次后近零加载成本），收益等价、复杂度与风险大幅更低。桥进程模型零改动。
//! （加载走 std::fs::read：bincode 反序列化本就要物化完整结构，mmap 语义零
//! 增量，且 memmap2 未离线钉定 vendored——不引新依赖。）
//!
//! 缓存内容（仅确定性公开产物）：prove 管线的 setup 参数与预处理产物 (pp,
//! vp)——σ 码字/表、G 窗表物理内嵌于 pp（vendor BasefoldProverParams 的
//! table_w_weights/table，setup 参数经 trim 的全量承载），故缓存 (pp,vp) 一并
//! 复用 setup 产物；命中时 setup+preprocess 两段全跳过。
//!
//! 🔴 随机性纪律红线（代码层钉死）：本模块写入面**只接受「由 pinned 公开输入
//! 确定性构造」的字节**——唯一生产入口是 prove.rs 的 `cached::<((pp,vp),..)>`
//! 调用点：setup 种子=公开常数 `SEED_SETUP`（StdRng::seed_from_u64；vendor
//! setup 的 table_seed/public_salt_seed 均由该 rng 派生），预处理承诺盐链=
//! ChaCha8(public_salt_seed ⊕ domain)（vendor batch_commit_public，跨进程可
//! 复现——2026-09-16 分相修复后的语义）；每证明的盲化 λ/m 列/transcript
//! 新鲜熵（OsRng）只在 `Pb::prove` 内消费，**物理上不经过本模块**（prove.rs
//! 的 build 闭包只含 setup+preprocess 两调用）。本模块自身零 RNG 引用。
//!
//! 缓存键=指纹键：SM3(域分隔 | 格式版本 | 电路身份指纹 | profile/reps/
//! log_rate/k | 规范化 info 结构摘要 | PCS 构型 tag)。指纹换代（repin ⟹
//! MANIFEST 变 ⟹ fingerprint 变）或结构/构型任一变化 ⟹ 键旋转——旧缓存自动
//! 失效，永不跨代误用。
//!
//! 完整性 fail-closed：条目=缓存目录下 `<key-hex>/` 子目录（工件 + manifest。
//! json）。manifest 记每个工件的 (名, 长度, SM3)。加载前任一工件缺失/长度不
//! 符/SM3 不匹配/manifest 损坏/工件反序列化失败 → 弃用整条目 → 全量重算并
//! 重写（**绝不使用不可校验的缓存**）。
//!
//! 不可用优雅降级：`FZ_ZK_CACHE_DIR` 未配置 / 目录不可建不可写 → 纯计算路径
//! （与现状完全一致），单测钉死。缓存侧任何失败都只降级（miss/Off），绝不使
//! prove 失败。
//!
//! 目录落点纪律（部署）：桥在 WSL 跑 zkc.exe——缓存必须落 ext4 本地盘
//! （禁 /mnt/c drvfs）。env 由桥/worker 拼装处透传（backend/app/zk/profile.py
//! zkc_env 缺省=FZ_ZK_CASES_DIR 同级 cache/，WSL 形态经 WSLENV /p 路径翻译）；
//! zkc 侧**无 env 即不开缓存**（hermetic：直跑 zkc 行为与现状一致）。

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Instant;

use sm3::{Digest, Sm3};

/// 缓存目录 env（未设置=缓存关闭——纯计算路径，与现状一致）。
pub const ENV_CACHE_DIR: &str = "FZ_ZK_CACHE_DIR";

/// 工件缓存格式版本（结构演进时 +1——键含此值，旧条目自然失效）。
pub const ARTIFACT_CACHE_FMT: u32 = 1;

/// 条目内工件名（prove.rs 集成点与 manifest 声明面共用单源）。
pub const NAMES: [&str; 2] = ["pp.bin", "vp.bin"];

/// 缓存结果状态（[zk-cache] 日志与上层打点面；秒数供 prove 窗收益实测）。
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// 命中：工件经 SM3 全量校验+反序列化成功（load_s=读盘+校验+重建全程）。
    Hit { load_s: f64 },
    /// 未命中（首跑/损坏自愈/键旋转）：build_s=重算耗时；write_ok=重写落盘成败。
    Miss { reason: String, build_s: f64, write_ok: bool },
    /// 缓存关闭（env 未配置或目录不可用——纯计算路径，行为与现状一致）。
    Off { reason: String },
}

impl Outcome {
    /// 短形态标签（打点面）。
    pub fn tag(&self) -> &'static str {
        match self {
            Outcome::Hit { .. } => "hit",
            Outcome::Miss { .. } => "miss",
            Outcome::Off { .. } => "off",
        }
    }
}

fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sm3_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sm3::new();
    h.update(data);
    h.finalize().into()
}

/// 键源串 → 键（条目目录名）。域分隔前缀与 info-cache 键（prove.rs）区分。
pub fn key_hex(key_src: &str) -> String {
    hex_lower(&sm3_bytes(key_src.as_bytes()))
}

/// 解析缓存目录：env 设置 → 建（可复用）；env 未设置/不可建 → None（关闭或
/// Off 降级——缓存侧任何失败都不阻塞 prove）。
pub fn cache_dir() -> Option<PathBuf> {
    let raw = std::env::var(ENV_CACHE_DIR).ok()?;
    // 空串/空白=显式关闭（防 "" 路径落 CWD；与 Python 侧空值语义对齐）
    if raw.trim().is_empty() {
        return None;
    }
    let p = PathBuf::from(&raw);
    match std::fs::create_dir_all(&p) {
        Ok(()) => Some(p),
        Err(e) => {
            eprintln!("[zk-cache] 目录不可用（降级纯计算）: {}: {e}", p.display());
            None
        }
    }
}

// ── manifest（伴生 SM3 自校验清单） ──

#[derive(serde::Serialize, serde::Deserialize)]
struct ManifestEntry {
    name: String,
    bytes: u64,
    sm3: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Manifest {
    fmt: u32,
    key: String,
    files: Vec<ManifestEntry>,
}

fn manifest_path(dir: &Path) -> PathBuf {
    dir.join("manifest.json")
}

/// 落盘单文件：tmp（pid 后缀防并发互踩）+ fsync + 原子落位（Windows rename
/// 不覆盖已存在——先删后移；并发同内容写幂等，竞窗内读者最坏校验失败→重算）。
fn write_atomic(path: &Path, data: &[u8]) -> bool {
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    let ok = std::fs::File::create(&tmp)
        .and_then(|mut f| {
            f.write_all(data)?;
            f.sync_all()
        })
        .is_ok();
    if !ok {
        let _ = std::fs::remove_file(&tmp);
        return false;
    }
    let _ = std::fs::remove_file(path);
    if std::fs::rename(&tmp, path).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return false;
    }
    true
}

/// 加载条目：任一工件缺失/长度不符/SM3 不匹配/manifest 损坏或与键/格式不符
/// → 清条目 + None。🔴 fail-closed：绝不返回未经 SM3 全量校验的字节。
pub fn load(dir: &Path, key: &str, names: &[&str]) -> Option<Vec<Vec<u8>>> {
    let entry = dir.join(key);
    let damaged = |reason: &str| {
        eprintln!("[zk-cache] 条目弃用（{reason}，重算重写）: {}", &key[..8]);
        let _ = std::fs::remove_dir_all(&entry);
        None::<Vec<Vec<u8>>>
    };
    let mtext = match std::fs::read_to_string(manifest_path(&entry)) {
        Ok(t) => t,
        Err(_) => return damaged("manifest 缺失/不可读"),
    };
    let m: Manifest = match serde_json::from_str(&mtext) {
        Ok(m) => m,
        Err(_) => return damaged("manifest 损坏"),
    };
    if m.fmt != ARTIFACT_CACHE_FMT || m.key != key || m.files.len() != names.len() {
        return damaged("manifest 与键/格式不符");
    }
    let mut out = Vec::with_capacity(names.len());
    for (fe, want_name) in m.files.iter().zip(names.iter()) {
        if fe.name != *want_name {
            return damaged("manifest 工件名不符");
        }
        let data = match std::fs::read(entry.join(&fe.name)) {
            Ok(d) => d,
            Err(_) => return damaged("工件缺失"),
        };
        if data.len() as u64 != fe.bytes {
            return damaged("工件长度不符");
        }
        if hex_lower(&sm3_bytes(&data)) != fe.sm3 {
            return damaged("工件 SM3 不匹配（篡改/损坏）");
        }
        out.push(data);
    }
    Some(out)
}

/// 弃用条目（反序列化失败等格式漂移形态的损坏——盘上字节过 SM3 但不可用）。
pub fn invalidate(dir: &Path, key: &str) {
    eprintln!("[zk-cache] 条目弃用（工件反序列化失败，重算重写）: {}", &key[..8]);
    let _ = std::fs::remove_dir_all(dir.join(key));
}

/// 重算后重写条目（best-effort：失败只记日志，绝不影响 prove 结果）。
/// 数据文件先落位，manifest 最后原子落位——读者要么见全条目、要么见可被
/// 校验拒掉的半条目（fail-closed 兜底）。
pub fn store(dir: &Path, key: &str, names: &[&str], blobs: &[Vec<u8>]) -> bool {
    debug_assert_eq!(names.len(), blobs.len());
    let entry = dir.join(key);
    if std::fs::create_dir_all(&entry).is_err() {
        eprintln!("[zk-cache] 条目目录不可建（跳过缓存）: {}", &key[..8]);
        return false;
    }
    for (name, data) in names.iter().zip(blobs.iter()) {
        if !write_atomic(&entry.join(name), data) {
            eprintln!("[zk-cache] 工件写失败（跳过缓存）: {}", &key[..8]);
            return false;
        }
    }
    let m = Manifest {
        fmt: ARTIFACT_CACHE_FMT,
        key: key.to_string(),
        files: names
            .iter()
            .zip(blobs.iter())
            .map(|(n, d)| ManifestEntry {
                name: (*n).to_string(),
                bytes: d.len() as u64,
                sm3: hex_lower(&sm3_bytes(d)),
            })
            .collect(),
    };
    match serde_json::to_vec(&m) {
        Ok(bytes) if write_atomic(&manifest_path(&entry), &bytes) => true,
        _ => {
            eprintln!("[zk-cache] manifest 写失败（跳过缓存）: {}", &key[..8]);
            false
        }
    }
}

/// 缓存取值核心（泛型产物面——生产唯一消费者是 prove.rs 的 (pp,vp) 集成点，
/// 其 build 闭包= pinned setup+preprocess，见模块头随机性纪律红线）。
///
/// 语义（三态，均不让 prove 失败）：
/// - env 未配置/目录不可用 → `Off`：build() 直跑，零盘上副作用（纯计算路径）；
/// - 命中（SM3 全量校验 + `from_bytes` 重建成功）→ `Hit`：**不调用 build**
///   （这就是收益面；重建失败=格式漂移形态损坏 → 弃条目走重算）；
/// - 未命中/损坏 → `Miss`：build() 重算 + 重写条目（build 失败 → `(None,
///   Miss{reason})`，由调用方映射为既有错误面——缓存不吞也不改错）。
pub fn cached<T>(
    key_src: &str,
    names: &[&str],
    from_bytes: impl Fn(&[Vec<u8>]) -> Option<T>,
    build: impl Fn() -> Result<(T, Vec<Vec<u8>>), String>,
) -> (Option<T>, Outcome) {
    let key = key_hex(key_src);
    // 尺寸门（2026-10-06 把关根修）：超大工件（AUTH pp 实测 4.26GB）读写
    // 磁盘+占页缓存的代价远超省下的 ~3.1s 初始化——只缓存小工件（TRAIL 档
    // 受益），超限即旁路：命中面视同缺失、落盘面跳过写。env 可调，0=无上限。
    let cap = cap_bytes();
    if let Some(dir) = cache_dir() {
        if let Some(blobs) = load(&dir, &key, names) {
            let total: u64 = blobs.iter().map(|b| b.len() as u64).sum();
            if let Some(c) = cap.filter(|&c| total > c) {
                invalidate(&dir, &key);
                eprintln!("[zk-cache] skip {} oversize {:.2}GB>cap（旁路纯计算）",
                    &key[..8], total as f64 / (1u64 << 30) as f64);
            } else {
                let t0 = Instant::now();
                if let Some(value) = from_bytes(&blobs) {
                    let load_s = t0.elapsed().as_secs_f64();
                    eprintln!("[zk-cache] hit {} load={:.1}s", &key[..8], load_s);
                    return (Some(value), Outcome::Hit { load_s });
                }
                invalidate(&dir, &key);
            }
        }
        let reason = "条目缺失/损坏/超限（首跑或自愈）".to_string();
        let t1 = Instant::now();
        return match build() {
            Ok((value, blobs)) => {
                let build_s = t1.elapsed().as_secs_f64();
                let total: u64 = blobs.iter().map(|b| b.len() as u64).sum();
                let write_ok = match cap.filter(|&c| total > c) {
                    Some(_) => false, // 超限不落盘（读侧同门，永不会读到超限条目）
                    None => store(&dir, &key, names, &blobs),
                };
                eprintln!(
                    "[zk-cache] miss {} build={:.1}s write={}",
                    &key[..8],
                    build_s,
                    if write_ok { "ok" } else { "skip(oversize)" }
                );
                (Some(value), Outcome::Miss { reason, build_s, write_ok })
            }
            Err(e) => (
                None,
                Outcome::Miss { reason: e, build_s: t1.elapsed().as_secs_f64(), write_ok: false },
            ),
        };
    }
    // 优雅降级：纯计算路径（与现状一致），零盘上副作用
    match build() {
        Ok((value, _)) => (
            Some(value),
            Outcome::Off { reason: format!("{} 未配置/不可用（纯计算）", ENV_CACHE_DIR) },
        ),
        Err(e) => (None, Outcome::Off { reason: e }),
    }
}

/// 缓存工件总尺寸上限：FZ_ZK_CACHE_MAX_BYTES（字节；缺省 768MiB；0=无上限）。
/// 防超大工件（AUTH pp GB 级）磁盘读写+页缓存占用反噬收益（把关定谳 2026-10-06）。
fn cap_bytes() -> Option<u64> {
    match std::env::var("FZ_ZK_CACHE_MAX_BYTES") {
        Ok(v) => v.trim().parse::<u64>().ok().map(|n| if n == 0 { u64::MAX } else { n }),
        Err(_) => Some(768 << 20),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 尺寸门测试：超限工件不落盘（write_ok=false），小工件正常缓存。
    #[test]
    fn oversize_artifact_bypasses_cache() {
        let _g = ENV_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("zkcap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("FZ_ZK_CACHE_DIR", &dir);
        std::env::set_var("FZ_ZK_CACHE_MAX_BYTES", "64");
        let key = format!("captest-{}", std::process::id());
        let big: Vec<u8> = vec![7u8; 128]; // >64B 上限
        let (v, out) = cached::<u32>(&key, &["pp.bin"], |_| None, || Ok((1u32, vec![big.clone()])));
        assert_eq!(v, Some(1));
        match out {
            Outcome::Miss { write_ok, .. } => assert!(!write_ok, "超限工件必须跳过落盘"),
            other => panic!("超限应为 Miss，实得 {other:?}"),
        }
        // 小工件正常写
        std::env::set_var("FZ_ZK_CACHE_MAX_BYTES", "1024");
        let (_v2, out2) = cached::<u32>(&key, &["pp.bin"], |_| None, || Ok((2u32, vec![vec![1u8; 32]])));
        match out2 {
            Outcome::Miss { write_ok, .. } => assert!(write_ok, "限内工件正常缓存"),
            other => panic!("限内应为 Miss，实得 {other:?}"),
        }
        std::env::remove_var("FZ_ZK_CACHE_DIR");
        std::env::remove_var("FZ_ZK_CACHE_MAX_BYTES");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// env 互斥（同族纪律：FZ_ZK_CACHE_DIR 读写测试共锁——prove.rs ENV_LOCK 同源）。
    use crate::test_env::ENV_MUTEX as ENV_LOCK;

    fn tmp_cache(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("fz-zkcache-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::env::set_var(ENV_CACHE_DIR, &d);
        d
    }

    fn cleanup(dir: &Path) {
        std::env::remove_var(ENV_CACHE_DIR);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// pinned 确定性构造器替身：字节=公开种子的纯函数（无 RNG——与生产 build
    /// 同构：setup/preprocess 输入全为 pinned 公开常数/公开输入）。
    fn pinned_bytes(seed: u64, n: usize) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                let mut h = Sm3::new();
                h.update(&seed.to_le_bytes());
                h.update(&(i as u32).to_le_bytes());
                h.finalize().iter().copied().collect::<Vec<u8>>()
            })
            .collect()
    }

    /// 生产集成点的同构封装（from_bytes=逐字节重建；build=确定性构造）。
    fn cached_pinned(
        key_src: &str,
        seed: u64,
        calls: &std::cell::Cell<usize>,
    ) -> (Option<Vec<Vec<u8>>>, Outcome) {
        cached(
            key_src,
            &NAMES,
            |blobs| Some(blobs.to_vec()),
            || {
                calls.set(calls.get() + 1);
                Ok((pinned_bytes(seed, NAMES.len()), pinned_bytes(seed, NAMES.len())))
            },
        )
    }

    /// ① 正常 roundtrip：miss 落盘 → hit 读回逐位一致（build 不再触发）；manifest 在场。
    #[test]
    fn roundtrip_miss_then_hit() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp_cache("rt");
        let src = "fz-zk-pp-cache|fmt=1|fp=SM3(pin|abc)|k=17";
        let calls = std::cell::Cell::new(0);
        let (got, o1) = cached_pinned(src, 7, &calls);
        assert_eq!(got, Some(pinned_bytes(7, NAMES.len())), "miss 路径必须回传 build 值");
        assert!(matches!(o1, Outcome::Miss { write_ok: true, .. }), "{o1:?}");
        assert_eq!(calls.get(), 1);
        assert!(manifest_path(&dir.join(key_hex(src))).is_file(), "manifest 必须在场");

        let (got2, o2) = cached_pinned(src, 7, &calls);
        assert_eq!(
            got2,
            Some(pinned_bytes(7, NAMES.len())),
            "hit 值与 miss 落盘值逐位一致"
        );
        assert!(matches!(o2, Outcome::Hit { .. }), "{o2:?}");
        assert_eq!(calls.get(), 1, "命中不得重触 build（收益面）");
        cleanup(&dir);
    }

    /// ② 篡改一字节 → SM3 拒收 → 重算重写（自愈后可再命中）。
    #[test]
    fn tampered_byte_fail_closed_recompute() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp_cache("tamper");
        let src = "fz-zk-pp-cache|fmt=1|fp=SM3(pin|tamper)";
        let calls = std::cell::Cell::new(0);
        let _ = cached_pinned(src, 11, &calls);
        // 篡改 pp.bin 一字节（同长度——专测 SM3 而非长度门）
        let entry = dir.join(key_hex(src));
        let mut b = std::fs::read(entry.join(NAMES[0])).unwrap();
        b[0] ^= 0x01;
        std::fs::write(entry.join(NAMES[0]), &b).unwrap();

        let (got, o) = cached_pinned(src, 11, &calls);
        assert!(
            matches!(o, Outcome::Miss { write_ok: true, .. }),
            "篡改必须弃缓存重算: {o:?}"
        );
        assert_eq!(calls.get(), 2, "篡改后必须重算");
        assert_eq!(got, Some(pinned_bytes(11, NAMES.len())), "重算值=确定性重建值");
        // 自愈后再次命中
        let (_, o2) = cached_pinned(src, 11, &calls);
        assert!(matches!(o2, Outcome::Hit { .. }), "重写后必须恢复命中: {o2:?}");
        assert_eq!(calls.get(), 2);
        cleanup(&dir);
    }

    /// ③ 删件 → 重算；manifest 损坏 → 重算（fail-closed 两形态）。
    #[test]
    fn deleted_artifact_and_broken_manifest_recompute() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp_cache("del");
        let src = "fz-zk-pp-cache|fmt=1|fp=SM3(pin|del)";
        let calls = std::cell::Cell::new(0);
        let _ = cached_pinned(src, 21, &calls);
        std::fs::remove_file(dir.join(key_hex(src)).join(NAMES[1])).unwrap();
        let (got, o) = cached_pinned(src, 21, &calls);
        assert!(matches!(o, Outcome::Miss { .. }), "删件必须 miss: {o:?}");
        assert_eq!(got, Some(pinned_bytes(21, NAMES.len())));

        // manifest 损坏（半写形态）
        std::fs::write(manifest_path(&dir.join(key_hex(src))), b"{broken").unwrap();
        let (_, o2) = cached_pinned(src, 21, &calls);
        assert!(matches!(o2, Outcome::Miss { .. }), "manifest 损坏必须 miss: {o2:?}");
        cleanup(&dir);
    }

    /// ④ 跨指纹键隔离：键 A 的条目永不服务键 B（指纹换代=旧缓存天然失效）。
    #[test]
    fn cross_fingerprint_key_isolation() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp_cache("iso");
        let src_a = "fz-zk-pp-cache|fmt=1|fp=SM3(pin-a|agg-a)";
        let src_b = "fz-zk-pp-cache|fmt=1|fp=SM3(pin-b|agg-b)";
        let ka = key_hex(src_a);
        let kb = key_hex(src_b);
        assert_ne!(ka, kb, "不同指纹必须键旋转");
        let calls = std::cell::Cell::new(0);
        let _ = cached_pinned(src_a, 31, &calls);
        assert!(dir.join(&ka).is_dir() && !dir.join(&kb).exists(), "B 不得落条目");

        let (got, o) = cached_pinned(src_b, 32, &calls);
        assert!(matches!(o, Outcome::Miss { .. }), "B 首调必 miss: {o:?}");
        assert_eq!(calls.get(), 2, "B 不得消费 A 的缓存");
        assert_ne!(got, Some(pinned_bytes(31, NAMES.len())), "B 的产物与 A 逐位不同（隔离）");
        cleanup(&dir);
    }

    /// ⑤ 确定性纯度：同输入两次产出缓存字节逐位一致；盘上字节=build 输出
    /// （零失真）；对照（OsRng 熵源）两次必互异——证明逐位比较器对随机性有
    /// 检出力，即「缓存内容与 OsRng 无关」的断言有牙（生产 build 输入=pinned
    /// 公开种子/公开输入，结构上无 OsRng 通道，见模块头红线）。
    #[test]
    fn determinism_purity_two_runs_byte_identical() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tmp_cache("purity");
        let src = "fz-zk-pp-cache|fmt=1|fp=SM3(pin|purity)";
        let calls = std::cell::Cell::new(0);
        let (a, _) = cached_pinned(src, 41, &calls);
        let ka = key_hex(src);
        let on_disk_a: Vec<Vec<u8>> =
            NAMES.iter().map(|n| std::fs::read(dir.join(&ka).join(n)).unwrap()).collect();
        // 清条目后二跑（绕开 hit 路径，专测「两次产出」的字节面）
        let _ = std::fs::remove_dir_all(dir.join(&ka));
        let (b, _) = cached_pinned(src, 41, &calls);
        assert_eq!(a, b, "同输入两次产出必须逐位一致");
        let on_disk_b: Vec<Vec<u8>> =
            NAMES.iter().map(|n| std::fs::read(dir.join(&ka).join(n)).unwrap()).collect();
        assert_eq!(on_disk_a, on_disk_b, "盘上缓存字节两跑一致");
        assert_eq!(
            a.as_deref(),
            Some(on_disk_b.as_slice()),
            "缓存字节=build 输出（零失真）"
        );

        // 对照：OsRng 熵源两次必互异（检出力证明——若缓存混入 OsRng，本比较器立红）
        use rand::RngCore;
        let rnd = || -> Vec<Vec<u8>> {
            (0..NAMES.len())
                .map(|_| {
                    let mut v = vec![0u8; 64];
                    rand::rngs::OsRng.fill_bytes(&mut v);
                    v
                })
                .collect()
        };
        assert_ne!(rnd(), rnd(), "对照失效：比较器检不出随机性（纯度断言无牙）");
        cleanup(&dir);
    }

    /// ⑥ 优雅降级：目录不可写（env 指向普通文件之下）→ Off + build 直跑、值
    /// 不损；env 未配置 → Off、零盘上副作用（与现状纯计算路径一致）。
    #[test]
    fn unwritable_or_unset_dir_degrades_to_pure_compute() {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // 不可写：占位普通文件充当父目录 → create_dir_all 必败
        let blocker = std::env::temp_dir().join(format!("fz-zkcache-block-{}", std::process::id()));
        std::fs::write(&blocker, b"not-a-dir").unwrap();
        std::env::set_var(ENV_CACHE_DIR, blocker.join("sub"));
        let want = pinned_bytes(51, NAMES.len());
        let (got, o) = cached(
            "fz-zk-pp-cache|fmt=1|fp=SM3(pin|deg)",
            &NAMES,
            |blobs| Some(blobs.to_vec()),
            || Ok((want.clone(), want.clone())),
        );
        assert!(matches!(o, Outcome::Off { .. }), "不可写必须 Off: {o:?}");
        assert_eq!(got, Some(want.clone()), "降级纯计算值不损");

        // 未配置：零盘上副作用（不建任何目录）
        std::env::remove_var(ENV_CACHE_DIR);
        let sentinel = std::env::temp_dir().join(format!("fz-zkcache-unset-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&sentinel);
        let (got2, o2) = cached(
            "fz-zk-pp-cache|fmt=1|fp=SM3(pin|unset)",
            &NAMES,
            |blobs| Some(blobs.to_vec()),
            || Ok((want.clone(), want.clone())),
        );
        assert!(matches!(o2, Outcome::Off { .. }), "未配置必须 Off: {o2:?}");
        assert_eq!(got2, Some(want));
        assert!(!sentinel.exists(), "未配置不得有任何盘上副作用");
        let _ = std::fs::remove_file(&blocker);
    }
}
