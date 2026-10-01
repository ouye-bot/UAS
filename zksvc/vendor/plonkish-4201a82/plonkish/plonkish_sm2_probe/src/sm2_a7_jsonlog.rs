//! T8 · (A7) 测试体系：机器可读 JSONL 日志（2026-09-15，波4 T8 规格）
//!
//! 用法：A7 测试体首行 `let _t8 = crate::a7_jsonlog::CaseGuard::new(用例名, 输入描述);`
//! —— RAII 析出一条 JSON 记录（用例名/输入哈希/判定/耗时毫秒/时间戳）。
//! 输出目标：环境变量 `A7_JSON_LOG` 给出路径时**追加** JSONL 文件（Zenodo 工件层）；
//! 未设时仅 stderr 回显（`[T8-JSON]` 前缀），零文件副作用。
//! 输入哈希 = SM3(输入描述)（本仓自产哈希，零新依赖）；判定 = 析构时
//! `std::thread::panicking()` 检测（PASS/FAIL——测试失败走 panic 路径）。
//! 工件口径：一条记录 = 一个测试用例的一次完整执行；分批放量（A7_T1_N 等）
//! 的每批各自一行，输入描述携带批参数与环境变量取值。

use std::io::Write as _;
use std::time::Instant;

pub struct CaseGuard {
    name: String,
    input: String,
    t0: Instant,
}

impl CaseGuard {
    pub fn new(name: &str, input: &str) -> Self {
        Self {
            name: name.to_string(),
            input: input.to_string(),
            t0: Instant::now(),
        }
    }
}

impl Drop for CaseGuard {
    fn drop(&mut self) {
        let verdict = if std::thread::panicking() { "FAIL" } else { "PASS" };
        let duration_ms = self.t0.elapsed().as_millis();
        let digest = crate::sm3_native_ref::hash(self.input.as_bytes());
        let hash_hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // JSON 字符串转义（输入描述仅测试参数文本；保守转义反斜杠/引号/控制符）。
        let esc = |s: &str| -> String {
            s.chars()
                .map(|c| match c {
                    '\\' => "\\\\".into(),
                    '"' => "\\\"".into(),
                    '\n' => "\\n".into(),
                    '\r' => "\\r".into(),
                    '\t' => "\\t".into(),
                    c if (c as u32) < 0x20 => format!("\\u{:04x}", c as u32),
                    c => c.to_string(),
                })
                .collect()
        };
        let line = format!(
            "{{\"case\":\"{}\",\"input\":\"{}\",\"input_hash_sm3\":\"{}\",\"verdict\":\"{}\",\"duration_ms\":{},\"unix_ts\":{}}}\n",
            esc(&self.name),
            esc(&self.input),
            hash_hex,
            verdict,
            duration_ms,
            ts
        );
        eprint!("[T8-JSON] {}", line);
        if let Ok(path) = std::env::var("A7_JSON_LOG") {
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
                let _ = f.write_all(line.as_bytes());
            }
        }
    }
}
