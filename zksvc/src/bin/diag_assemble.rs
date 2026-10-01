// 一次性诊断：装配真实 job.json → 打印 binding 输入与输出实例 19/20 对照
use zksvc::assemble::assemble;

fn main() {
    let path = std::env::args().nth(1).expect("用法: diag_assemble <job.json>");
    let text = std::fs::read_to_string(&path).expect("job 不可读");
    let spec: zksvc::profile::JobSpec = serde_json::from_str(&text).expect("spec 损坏");
    let binding = spec.binding.as_ref().expect("缺 binding");
    println!("binding.challenge_hex = {}", binding.challenge_hex);
    println!("binding.pred_id       = {}", binding.pred_id);
    println!("binding.t_epoch       = {}", binding.t_epoch);
    println!("binding.required      = {}", binding.required_level);

    std::env::set_var("FZ_ZK_ALLOW_AUTH", "1");
    std::env::set_var("SM3_LUT", "1");
    let asm = assemble(&spec).expect("装配失败");
    println!("instances[19] = {:?}", asm.instances[0][19]);
    println!("instances[20] = {:?}", asm.instances[0][20]);
    println!("instances[21] = {:?}", asm.instances[0][21]);
    println!("instances[22] = {:?}", asm.instances[0][22]);
    println!("instances[23] = {:?}", asm.instances[0][23]);
    println!("instances[24] = {:?}", asm.instances[0][24]);
}
