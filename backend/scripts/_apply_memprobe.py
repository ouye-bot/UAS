# -*- coding: utf-8 -*-
"""用已完成的真实出证产物走受理→验证→取件（端到端后段验证）。"""
import json
import secrets
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.authz.policy import POLICY_VERSION  # noqa: E402

API = "http://127.0.0.1:8000"


def api_get(path):
    with urllib.request.urlopen(API + path, timeout=30) as r:
        return json.loads(r.read().decode())


def api_post(path, body):
    req = urllib.request.Request(API + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())


def main():
    job_path = sys.argv[1]
    spec = json.load(open(job_path, encoding="utf-8"))
    inp, binding = spec["input"], spec["binding"]
    # pred_id 串内嵌 plan|nonce 明文（T6 复合折算输入）
    plan_hash_hex, nonce_hex, _pv = binding["pred_id"].split("|")
    rev_root_hex = inp["smt_root_hex"]
    t_start = binding["t_epoch"]

    case_dir = Path(os.environ.get("FZ_ZK_CASES_DIR", "fz-zk-cases")) / "memprobe"
    case_dir.mkdir(parents=True, exist_ok=True)
    for name in ("proof.bin", "verifier_param.bin", "instances.json"):
        (case_dir / name).write_bytes((Path(job_path).parent / "out" / name).read_bytes())
    print("[1] 出证产物就位:", case_dir)

    rc, apply = api_post("/authz/apply", {
        "session_pk_hex": "22" * 64,  # 占位会话钥（本验证不含取件解密段）
        "sub_cred_message_hex": MSG_HEX,
        "sub_sig_hex": SIG_HEX,
        "sub_cred_hash_hex": SUB_HASH_HEX,
        "nonce_hex": nonce_hex,
        "plan_hash_hex": plan_hash_hex,
        "class_id": inp["class_id"],
        "case_id": "memprobe",
        "rev_root_hex": rev_root_hex,
        "t_start": t_start,
        "t_end": t_start + 3600,
    })
    print("[2] 受理:", rc, json.dumps(apply, ensure_ascii=False)[:200])


if __name__ == "__main__":
    main()
