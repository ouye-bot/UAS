//! 三语言对拍 Rust 面：官方向量单一事实源（include_str! 编译期锚定——向量漂移=编译失败）。
//! 事实源=backend/app/crypto/vectors/sm3_official.json（与 Python/TS 共享）。

use serde_json::Value;

const SM3_JSON: &str = include_str!("../../backend/app/crypto/vectors/sm3_official.json");

fn vectors(key: &str) -> Vec<(String, String, String)> {
    let v: Value = serde_json::from_str(SM3_JSON).expect("向量 JSON 解析");
    v[key]
        .as_array()
        .expect("向量数组")
        .iter()
        .map(|item| {
            (
                item["name"].as_str().unwrap().to_string(),
                item["msg_hex"].as_str().unwrap().to_string(),
                item["digest_hex"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[test]
fn sm3_official_vectors() {
    let mut n = 0;
    for (name, msg_hex, digest_hex) in vectors("vectors").into_iter().chain(vectors("extra_consistency")) {
        let out = zksvc::sm3_host::sm3_hex(&msg_hex).expect(&name);
        assert_eq!(out, digest_hex.to_lowercase(), "向量 {name}");
        n += 1;
    }
    assert!(n >= 3, "官方向量至少 3 组（A.1/A.2/空消息）");
}

#[test]
fn sm3_rejects_non_hex() {
    assert!(zksvc::sm3_host::sm3_hex("zz").is_err());
    assert!(zksvc::sm3_host::sm3_hex("").is_ok()); // 空消息合法（一致性向量在用）
}
