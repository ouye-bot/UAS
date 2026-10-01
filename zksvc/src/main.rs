//! zkc —— 飞证单任务 CLI 薄壳（B3 fork 自隐证通 SP-4 架构；AUTH 单档）。
//!
//! 用法：`zkc prove --spec <job.json> --out <dir>`
//! 退出码：0 = verdict OK；2 = FAIL/一切非 OK（判决纪律）；1 = 用法/参数错误。
//! 本壳只做参数解析与退出码映射，全部语义在库面（zksvc::prove）。

use std::path::Path;
use std::process::exit;

use zksvc::profile::JobSpec;
use zksvc::prove::{apply_pcs_deployment_defaults, prove_pipeline, verify_pipeline, EXIT_FAIL};
use zksvc::sm3_lookup_weave::apply_sm3_lut_deployment_default;
use zksvc::sm3file::sm3_file_hex;

fn main() {
    // 部署默认（SV-3 2026-09-17）：叶交织承诺默认开；显式 PCS_INTERLEAVE=0 保留 legacy。
    // 放在二进制边界而非库面：prove 与 verify 子命令同一进程同一默认——prover/verifier 构型同值。
    apply_pcs_deployment_defaults();
    apply_sm3_lut_deployment_default();
    let args: Vec<String> = std::env::args().collect();
    match run(&args) {
        Ok(code) => exit(code),
        Err(msg) => {
            eprintln!("zkc: {msg}");
            exit(1);
        }
    }
}

fn usage() -> String {
    "用法: zkc prove --spec <job.json> --out <dir>\n      zkc verify --spec <job.json> --proof <p> [--verdict <verdict.json>]\n      zkc verify-instances --instances <i.json> --proof <p> --vp <vp.bin> --expected <e.json>
      zkc sm3 --file <path>"
        .to_string()
}

fn run(args: &[String]) -> Result<i32, String> {
    match args.get(1).map(String::as_str) {
        Some("prove") => cmd_prove(args),
        Some("verify") => cmd_verify(args),
        Some("verify-instances") => cmd_verify_instances(args),
        Some("sm3") => cmd_sm3(args),
        Some(other) => Err(format!("未知子命令 {other}\n{}", usage())),
        None => Err(usage()),
    }
}

/// `zkc verify --spec <j> --proof <p> [--verdict <v>]`：verify-only 独立验证。
/// exit 0 = OK；exit 2 = FAIL（判决纪律，含六负例矩阵——SM3 先拒/指纹不符/
/// 跨档位/截断/翻转/垃圾，全部无 panic 逃逸）；用法错误 = 1。
fn cmd_verify(args: &[String]) -> Result<i32, String> {
    let mut spec_path: Option<String> = None;
    let mut proof_path: Option<String> = None;
    let mut verdict_path: Option<String> = None;
    let mut param_path: Option<String> = None;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--spec" => {
                spec_path = Some(args.get(i + 1).ok_or("--spec 缺值")?.clone());
                i += 2;
            }
            "--proof" => {
                proof_path = Some(args.get(i + 1).ok_or("--proof 缺值")?.clone());
                i += 2;
            }
            "--verdict" => {
                verdict_path = Some(args.get(i + 1).ok_or("--verdict 缺值")?.clone());
                i += 2;
            }
            "--param" => {
                param_path = Some(args.get(i + 1).ok_or("--param 缺值")?.clone());
                i += 2;
            }
            other => return Err(format!("未知参数 {other}\n{}", usage())),
        }
    }
    let spec_path = spec_path.ok_or("缺 --spec")?;
    let proof_path = proof_path.ok_or("缺 --proof")?;

    let text =
        std::fs::read_to_string(&spec_path).map_err(|e| format!("spec 不可读 {spec_path}: {e}"))?;
    let spec: JobSpec =
        serde_json::from_str(&text).map_err(|e| format!("spec 解析失败: {e}"))?;

    match verify_pipeline(
        &spec,
        Path::new(&proof_path),
        verdict_path.as_deref().map(Path::new),
        param_path.as_deref().map(Path::new),
    ) {
        Ok(rep) if rep.verdict == "OK" => {
            println!("zkc verify: OK");
            Ok(0)
        }
        Ok(rep) => {
            eprintln!("zkc verify: FAIL {}", rep.reason.unwrap_or_default());
            Ok(EXIT_FAIL)
        }
        Err(e) => {
            eprintln!("zkc verify: 错误 {e}");
            Ok(EXIT_FAIL)
        }
    }
}

/// `zkc sm3 --file <p>`：文件 SM3 hex → stdout；IO 失败 = exit 2。
fn cmd_sm3(args: &[String]) -> Result<i32, String> {
    let mut file: Option<String> = None;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--file" => {
                file = Some(args.get(i + 1).ok_or("--file 缺值")?.clone());
                i += 2;
            }
            other => return Err(format!("未知参数 {other}\n{}", usage())),
        }
    }
    let file = file.ok_or("缺 --file")?;
    match sm3_file_hex(Path::new(&file)) {
        Ok(hex) => {
            println!("{hex}");
            Ok(0)
        }
        Err(e) => {
            eprintln!("zkc sm3: {e}");
            Ok(EXIT_FAIL)
        }
    }
}

fn cmd_prove(args: &[String]) -> Result<i32, String> {
    let mut spec_path: Option<String> = None;
    let mut out_dir: Option<String> = None;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--spec" => {
                spec_path = Some(args.get(i + 1).ok_or("--spec 缺值")?.clone());
                i += 2;
            }
            "--out" => {
                out_dir = Some(args.get(i + 1).ok_or("--out 缺值")?.clone());
                i += 2;
            }
            other => return Err(format!("未知参数 {other}\n{}", usage())),
        }
    }
    let spec_path = spec_path.ok_or("缺 --spec")?;
    let out_dir = out_dir.ok_or("缺 --out")?;

    let text =
        std::fs::read_to_string(&spec_path).map_err(|e| format!("spec 不可读 {spec_path}: {e}"))?;
    let spec: JobSpec =
        serde_json::from_str(&text).map_err(|e| format!("spec 解析失败: {e}"))?;

    match prove_pipeline(&spec, Path::new(&out_dir)) {
        Ok(report) => match report.verdict.as_str() {
            "OK" => {
                println!(
                    "zkc prove: OK {}B sm3={} fingerprint={} pcs={}",
                    report.proof_bytes_len,
                    report.proof_sm3_hex,
                    report.fingerprint,
                    report.pcs_switches.tag()
                );
                Ok(0)
            }
            _ => {
                eprintln!("zkc prove: FAIL {:?}", report.verify_error);
                Ok(EXIT_FAIL)
            }
        },
        Err(e) => {
            eprintln!("zkc prove: 错误 {e}");
            Ok(EXIT_FAIL) // 判决纪律：一切非 OK = 2
        }
    }
}

/// `zkc verify-instances`：实例驱动验证（R1-1a——服务端零秘密验证面）。
/// canonical 电路参照读 env FZ_AUTH_CANONICAL_SPEC；期望绑定由服务端独立重导出。
fn cmd_verify_instances(args: &[String]) -> Result<i32, String> {
    let mut instances: Option<String> = None;
    let mut proof: Option<String> = None;
    let mut vp: Option<String> = None;
    let mut expected: Option<String> = None;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--instances" => instances = Some(args.get(i + 1).ok_or("--instances 缺值")?.clone()),
            "--proof" => proof = Some(args.get(i + 1).ok_or("--proof 缺值")?.clone()),
            "--vp" => vp = Some(args.get(i + 1).ok_or("--vp 缺值")?.clone()),
            "--expected" => expected = Some(args.get(i + 1).ok_or("--expected 缺值")?.clone()),
            other => return Err(format!("未知参数 {other}")),
        }
        i += 2;
    }
    let (instances, proof, vp, expected) = (
        instances.ok_or("缺 --instances")?,
        proof.ok_or("缺 --proof")?,
        vp.ok_or("缺 --vp")?,
        expected.ok_or("缺 --expected")?,
    );
    let expect_text = std::fs::read_to_string(&expected)
        .map_err(|e| format!("期望绑定不可读 {expected}: {e}"))?;
    let expect: zksvc::prove::BindingExpectations =
        serde_json::from_str(&expect_text).map_err(|e| format!("期望绑定损坏: {e}"))?;
    let report = zksvc::prove::verify_instances(
        std::path::Path::new(&proof),
        std::path::Path::new(&vp),
        std::path::Path::new(&instances),
        &expect,
    )
    .map_err(|e| format!("{e}"))?;
    println!(
        "zkc verify-instances: {} {}",
        report.verdict,
        report.reason.as_deref().unwrap_or("")
    );
    Ok(if report.verdict == "OK" { 0 } else { 2 })
}
