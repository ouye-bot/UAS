//! ③手术 S2 试点判决测试：C₁ 循环 window 化后的 AUTH 装配与全管线。
//!
//! 门 1（结构）：装配成功+ec.win.* 约束家族在场+r 位世界 recomp 在场
//! 门 2（管线）：canonical witness 全管线 prove→盘上回读 verify OK

use zksvc::assemble::assemble;
use zksvc::profile::JobSpec;

fn load_canonical() -> JobSpec {
    let text = std::fs::read_to_string("tests/auth_canonical_spec.json").expect("spec 缺失");
    serde_json::from_str(&text).expect("spec 损坏")
}

#[test]
fn auth_pilot_structure_has_window_families() {
    std::env::set_var("FZ_ZK_ALLOW_AUTH", "1");
    let spec = load_canonical();
    let asm = assemble(&spec).expect("装配失败");
    let fams: Vec<&str> = asm.ctags.iter().copied().collect();
    for tag in [
        "ec.win.dshift",
        "ec.win.idx",
        "ec.win.init.x",
        "ec.win.init.y",
        "ec.win.add.lam",
        "ec.win.add.sx",
        "ec.win.add.sy",
        "ec.win.diff",
        "ec.win.r.recomp",
    ] {
        assert!(fams.contains(&tag), "缺 window 约束家族 {tag}");
    }
    // 旧 const_base 循环从 6→5：e8/e9 系列家族计数由 census 权威（S4 换代），
    // 此处仅断言 C₁ 位车道环已退役（无独立断言面——census 记账）。
}

#[test]
#[ignore] // ~2 分钟全管线——手动跑或收口窗
fn auth_pilot_full_pipeline_prove_verify() {
    std::env::set_var("FZ_ZK_ALLOW_AUTH", "1");
    // 部署默认（SV-3）：库直调绕过 zkc main ⟹ 必须显式应用交织默认
    // （教训㊿+91：非交织构型=数倍时延+16× proof 尺寸的噪音源）。
    zksvc::prove::apply_pcs_deployment_defaults();
    let spec = load_canonical();
    let out = std::env::temp_dir().join(format!("fz-pilot-{}", std::process::id()));
    let report = zksvc::prove::prove_pipeline(&spec, &out).expect("prove 管线失败");
    assert_eq!(report.verdict, "OK", "回读 verify 未过：{:?}", report.verify_error);
    let _ = std::fs::remove_dir_all(&out);
}
