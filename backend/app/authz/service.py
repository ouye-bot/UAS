"""授权服务受理层（B4）：门控序（D19 廉价先于昂贵）+回执+令牌签发。

门控序（框架 §7.2）：①会话公钥格式 →②子凭证签名 SM2 验签（公开提交）→
③nonce 链上查重 →④电路 pin 比对 →通过进 ZK 验证队列（worker 异步）。
电路内仍全量验证——宿主检查=DoS 门控，电路=密码学权威（两层角色分离）。

匿名红线：applications/receipts 全程零身份列；令牌经会话钥 ECIES 加密返回；
128bit 回执码（CSPRNG）支持异步/跨设备取件。
"""

from __future__ import annotations

import json
import secrets
from collections.abc import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.authz.models import Application, Receipt
from app.authz.policy import PolicyError, get_rule
from app.crypto.sm2 import encrypt as ecies_encrypt
from app.crypto.sm2 import sign_digest, verify_digest
from app.crypto.sm3 import sm3_bytes
from app.kms import engine_signing_keypair, kms_domain_key
from app.ra.credential import digest_e_bytes


class AuthzError(Exception):
    def __init__(self, code: str, message: str = "", status: int = 400) -> None:
        self.code = code
        self.message = message
        self.status = status


class AuthzDeps:
    """环境注入面（链/zkc/pin——测试替身位，生产接线在 worker/router 装配）。"""

    def __init__(self) -> None:
        self._pin_fingerprint: str | None = None  # 本地 MANIFEST 指纹（None=惰性读）
        self.chain_nonce_used = _stub_nonce_unused
        self.chain_rev_root = _stub_rev_root
        # 链公示 pin（阶段一 D-Ⅰ-5）：None=未发布跳过；bytes32=已发布（=sm3(本地
        # 指纹串) 形态——publish_pin 仪式与回读同构）
        self.chain_pin: Callable[[], bytes | None] = _stub_chain_pin
        # 链级子凭证查重（阶段四）：默认无链面=False（未使用）
        self.chain_sub_used: Callable[[bytes], bool] = _stub_sub_unused
        # 政策公示对拍（阶段四）：None=未知（fake/CI 跳过）；False=链上未公示 → 拒。
        # B-P1-1：支持 callable（per-apply 真实现形态——router 注入 lambda），
        # 门控内形态归一；只认 bool/可调用两种，勿再引入第三形态
        self.chain_policy_published: bool | Callable[[], bool | None] | None = None

    def pin_fingerprint(self) -> str:
        """电路 pin 指纹（vendor MANIFEST——fail-closed 比对源）。"""
        import os

        root = os.environ.get("FZ_ZKSVC_DIR")
        if not root:
            raise AuthzError("pin_unavailable", "FZ_ZKSVC_DIR 未配置", 500)
        try:
            with open(f"{root}/vendor/MANIFEST.json", encoding="utf-8") as f:
                man = json.load(f)
            return f"SM3({man['pin_commit']}|{man['aggregate_sm3']})"
        except OSError as e:
            raise AuthzError("pin_unavailable", f"MANIFEST 读取失败: {e}", 500) from e


def _stub_nonce_unused(nonce: bytes) -> bool:
    return False


def _stub_rev_root() -> tuple[int, str]:
    return (0, "00" * 32)


def _stub_sub_unused(cred_hash: bytes) -> bool:
    return False


def _stub_chain_pin() -> bytes | None:
    return None


_DEFAULT_DEPS = AuthzDeps()


# ---- R1-1b：域元素形态折算（与 Rust fe_be32 一致——BE 整数 mod p）----
_P = int(__import__("gmssl").sm2.default_ecc_table["p"], 16)


def _fe_be32_hex_from_digest(digest):
    """SM3 摘要 -> FpSM2 规范 BE32 hex（int(digest) mod p；ctx_tag/pred_id 同式）。
    digest 支持 bytes（原始 32B 摘要）或 hex str。"""
    v = int.from_bytes(digest, "big") if isinstance(digest, (bytes, bytearray)) else int(digest, 16)
    return (v % _P).to_bytes(32, "big").hex()


def _fe_be32_hex_from_u64(v):
    return (v % _P).to_bytes(32, "big").hex()


def _fe_be32_hex_from_bytes32(b):
    # fold_words_be(root)（B6-d10 口径分野：词序折叠 ≠ 真 BE 整数 fold_be_integer）：
    # e = Σ_k u32::from_be_bytes(root[4k..4k+4]) · 2^(32k) mod p（首词最低位权，
    # fe_be32 大端序列化后 w0 落末尾）。与 zksvc smt_weave.rs 权威式逐字对齐——
    # 曾误写为 BE 整数口径（注释"即整数本身"错误）⟹ 实例 23 全拒。
    e = 0
    for k in range(8):
        e += int.from_bytes(b[4 * k : 4 * k + 4], "big") * (1 << (32 * k))
    return (e % _P).to_bytes(32, "big").hex()


def binding_challenge(plan_hash_hex, nonce_hex):
    """绑定挑战：HMAC-SM3(服务密钥, plan|nonce)——确定性/免存储/不可伪造。
    实现=app.crypto.hmac_sm3 单源（B-P3 尾项收敛——本地第二实现已删）。"""
    from app.crypto.hmac_sm3 import hmac_sm3
    from app.kms import authz_binding_key

    key = authz_binding_key()
    msg = bytes.fromhex(plan_hash_hex) + bytes.fromhex(nonce_hex)
    return hmac_sm3(key, msg)[:32].hex()


def binding_pred_id(plan_hash_hex, nonce_hex, policy_version):
    """pred_id 串（T6 复合折算输入——电路实例 20 的原像）。"""
    return f"{plan_hash_hex}|{nonce_hex}|{policy_version}"


def server_sn_hash_hex(session: Session, sub_cred_hash_hex: str) -> str:
    """SN 绑定换代（2026-10-06）：服务端权威 sn_hash——sub_cred_hash →
    sub_credentials → credentials.serial_hex 解析原文后自算 SM3 全 32B
    （零客户端自报）。健全性链：sub_cred_hash=SM3(M_A′) 已由受理门核对 ⟹
    本行解析到的凭证=签发 M_A′ 的同一凭证（RA 签名面）；电路第 5 组
    digest(sn_witness)==实例 25 + SM3 抗碰撞 ⟹ 证明者私知 serial 原文。
    历史凭证（serial_hex=NULL）fail-closed 人话拒绝（重新登记后申请）。"""
    from sqlalchemy import select

    from app.ra.models import Credential, SubCredential

    sub = session.scalar(
        select(SubCredential).where(
            SubCredential.sub_cred_hash_hex == sub_cred_hash_hex.lower()
        )
    )
    if sub is None:
        raise AuthzError("sub_cred_unknown", "子凭证不在库（无法解析序列号溯源）", 404)
    cred = session.get(Credential, sub.credential_id)
    if cred is None or not cred.serial_hex:
        raise AuthzError(
            "sn_unresolved",
            "凭证序列号溯源缺失（历史凭证无 sn 溯源——重新登记后申请）",
            409,
        )
    try:
        serial = bytes.fromhex(cred.serial_hex)
    except ValueError as e:
        raise AuthzError("sn_unresolved", "凭证序列号形态非法", 409) from e
    return sm3_bytes(serial).hex()


def admission_gate(
    session: Session,
    deps: AuthzDeps,
    *,
    session_pk_hex: str,
    sub_cred_message_hex: str,
    sub_sig_hex: str,
    sub_cred_hash_hex: str,
    nonce_hex: str,
    plan_hash_hex: str,
    class_id: int,
    proof_path: str,
    spec_path: str,
    rev_root_hex: str,
    t_start: int = 0,
    t_end: int = 0,
    case_id: str = "",
    sorties: int = 1,
) -> Application:
    """受理门控序（四步廉价检查→入队）。全部通过=返回已入队申请。

    case_id（批 4-1 服务端权威归属）：非空时执行案卷绑定门——首个申请把
    case_id 与 (sub_cred_hash, nonce, session_pk) 材料绑定落库；此后携同
    case_id 的申请材料一致=幂等受理（原申请原回执直接返回，不重复入队）、
    不一致=409 case_taken。空值（直呼门控的测试/工具面）不参与绑定。
    sorties（2026-10-06 授权包配额制）：本授权覆盖架次数 1~5，缺省 1=
    与令牌一次性历史语义逐字等价；越界=400 bad_sorties（fail-closed）。"""
    # ⓪ 授权包配额形检（廉价先于昂贵——门控序最前）
    if not (1 <= int(sorties) <= 5):
        raise AuthzError("bad_sorties", "架次配额须 1~5（授权包多架次上限）")
    # ① 会话公钥格式（128 hex——ECIES 取件目标）
    spk = session_pk_hex.lower()
    if len(spk) != 128 or not all(c in "0123456789abcdef" for c in spk):
        raise AuthzError("bad_session_key", "会话公钥须 128 hex（SM2 x‖y）")
    # 曲线方程校验（S5 安全修复——非曲线点会在 ECIES 封发抛异常→毒丸申请
    # 无限重试占满 worker：匿名 DoS）
    from app.crypto.sm2 import assert_pub

    try:
        assert_pub(spk)
    except Exception as e:
        raise AuthzError("bad_session_key", f"会话公钥不在 SM2 曲线上: {e}") from e
    # ② 子凭证签名验签（公开提交兼作准入票据——一次性数据，毫秒级）
    msg = bytes.fromhex(sub_cred_message_hex) if sub_cred_message_hex else b""
    if len(msg) != 165:
        raise AuthzError("bad_sub_message", "子凭证报文须 165B/330hex（M_A′）")
    e = digest_e_bytes(msg)
    # 子凭证的验签公钥=RA（与主凭证同源签发面）
    from app.kms import ra_pub_hex_of

    if not verify_digest(ra_pub_hex_of(), e, sub_sig_hex):
        raise AuthzError("bad_sub_signature", "子凭证签名验证失败（非 RA 签发或篡改）")
    # ②' 子凭证哈希服务器重算对拍（2026-09-28 安全深检 A-P1-1 根修）：一次性
    # 查重（③'/库唯一索引/链上 usedSubCreds/消费回写）此前全部键在客户端自报
    # 的 sub_cred_hash_hex 上——同 (msg,sig) 配不同 hash 可一张子凭证铸无限
    # 授权。签发面公式=sm3(M_A′)（ra/service.py:247），服务器手里就有 msg：
    # 现算对拍，不一致即拒。此后所有一次性查重键=服务器权威值。
    sub_hash_recomputed = sm3_bytes(msg).hex()
    if sub_cred_hash_hex.lower() != sub_hash_recomputed:
        raise AuthzError(
            "sub_cred_hash_mismatch",
            "子凭证哈希与报文不符（重算不一致——拒绝受理）", 409)
    # ⓪' 出证案卷归属门（批 4-1 服务端权威——置于服务器权威哈希重算之后，
    # 材料比对全部用服务器侧权威值）：case_id 是桥端出证任务产物目录号——
    # 此前客户端可给定任意已存在案卷目录触发验证与授权登记（抢注面）。现：
    # 首个申请绑定 case_id↔材料；后续携同 case_id——材料一致=幂等受理（原
    # 申请原回执，重试/网络重发安全）；材料不一致=409 case_taken（该出证
    # 案卷已归属其他申请）。跨案卷的子凭证/nonce 一次性判决（409
    # sub_cred_used/nonce_used）原样保留，不因本门放松。
    if case_id:
        bound = session.scalar(select(Application).where(Application.case_id == case_id))
        if bound is not None:
            same_material = (
                bound.sub_cred_hash_hex == sub_hash_recomputed
                and bound.nonce_hex == nonce_hex.lower()
                and bound.session_pk_hex == session_pk_hex.lower()
            )
            if not same_material:
                raise AuthzError(
                    "case_taken",
                    "该出证案卷已归属其他申请（case_id 已绑定在案的受理材料与本次不一致）"
                    "——请使用自己的出证任务号重新申请",
                    409,
                )
            return bound
    # ③ nonce 链上查重（cheap——链客户端 view call）
    nonce = bytes.fromhex(nonce_hex)
    if len(nonce) != 16:
        raise AuthzError("bad_nonce", "nonce 须 16B/32hex")
    if deps.chain_nonce_used(nonce):
        raise AuthzError("nonce_used", "nonce 已烧毁（重放）", 409)
    # ③' 链级子凭证查重（阶段四）：数据库换代/多实例场景下库查重不完整——
    # 链上 usedSubCreds 是授权单一性的完整事实
    if deps.chain_sub_used(bytes.fromhex(sub_cred_hash_hex)):
        raise AuthzError("sub_cred_used", "子凭证已使用（链级查重）", 409)
    # ③'' 政策公示对拍（fail-closed）：None=无链面跳过（fake/CI）。
    # 形态归一（B-P1-1 回归根修）：注入面支持 bool 或 callable（per-apply 求值
    # 的真实现=callable；测试替身多为 bool）——旧代码按 `is False` 比对，
    # callable 恒不等于 False ⟹ 防线静默失效（单测全绿、产品路径死码）。
    _pol_pub = deps.chain_policy_published
    _pol_pub = _pol_pub() if callable(_pol_pub) else _pol_pub
    if _pol_pub is False:
        raise AuthzError("policy_unpublished", "政策表未在链上公示或已变更（fail-closed）", 409)

    # ④ 电路 pin 比对（本地 MANIFEST vs 链上公示——fail-closed；未发布=None 跳过）。
    # 比对形态（阶段一 D-Ⅰ-5）：链上 bytes32=sm3(本地指纹串) 摘要——单向摘要
    # 避免指纹串本体上链（发布仪式 scripts/publish_pin.py 同构闭环）。
    local_pin = deps.pin_fingerprint()
    chain_pin = deps.chain_pin()
    if chain_pin is not None and chain_pin != sm3_bytes(local_pin.encode()):
        raise AuthzError("pin_mismatch", "电路指纹与链上公示不符（拒绝验证）", 409)
    # 政策面（class 查表——fail-closed 未开放类拒）
    try:
        alt_max, required = get_rule(class_id)
    except PolicyError as e:
        raise AuthzError(e.code, e.message) from e
    # rev_root 与链上当前纪元一致性（廉价检查——电路内已数学强制，此处快速失败）
    _epoch, chain_root = deps.chain_rev_root()
    if rev_root_hex != chain_root:
        raise AuthzError("stale_rev_root", "撤销纪元根与链上不一致（刷新见证后重试）", 409)
    # ⑤ 实例一致性（R1-1b：实例驱动验证面——公开实例与申请绑定逐位核对；
    #    T6 服务侧强制闭环。任何一维不符=拒绝，先于 ZK 验证排队）
    import json as _json

    from app.authz.policy import POLICY_VERSION

    try:
        with open(spec_path, encoding="utf-8") as f:
            inst = _json.load(f).get("instances")
    except (OSError, ValueError) as e:
        raise AuthzError("instances_missing", f"公开实例文件缺失/损坏: {e}", 400) from e
    if not isinstance(inst, list) or len(inst) < 26:
        raise AuthzError("instances_malformed", "公开实例文件形态非法（需 >=26 项）", 400)

    def _expect(idx, want_hex, name):
        got = inst[idx]
        if not isinstance(got, str) or got.lower() != want_hex.lower():
            raise AuthzError(
                "instance_mismatch",
                f"实例 {idx}（{name}）与申请绑定不一致——拒绝",
                409,
            )

    challenge_hex = binding_challenge(plan_hash_hex, nonce_hex)
    # 电路装配规范映射（zksvc ctx_tag.rs / profile.rs）：ctx_tag=SM3(challenge) mod p、
    # pred_id=SM3("FZ-ZKSVC-PRED-ID"+pred) mod p——与装配同式，逐位可比。
    inst19 = _fe_be32_hex_from_digest(sm3_bytes(bytes.fromhex(challenge_hex)))
    pred_str = binding_pred_id(plan_hash_hex, nonce_hex, POLICY_VERSION)
    pred_digest = sm3_bytes((b"FZ-ZKSVC-PRED-ID" + b"\x01") + pred_str.encode())
    _expect(19, inst19, "ctx_tag")
    _expect(20, _fe_be32_hex_from_digest(pred_digest), "pred_id")
    _expect(21, _fe_be32_hex_from_u64(t_start), "t_epoch")
    _expect(22, _fe_be32_hex_from_u64(required), "required_level")
    _expect(24, _fe_be32_hex_from_u64(class_id), "class_id")
    _expect(23, _fe_be32_hex_from_bytes32(bytes.fromhex(rev_root_hex)), "rev_root")
    # SN 绑定换代（2026-10-06）：实例 25=sn_hash——权威=服务端从
    # sub_cred_hash→sub_credentials→credentials 解析 sn 后自算 SM3 全 32B
    #（零客户端自报）。**词折叠口径（prove 窗 e2e ⑤ 实弹定谳）**：电路第 5 组
    # digest 词根环与 SMT 根环同族=fold_words_be（w0 最低权——序列化后呈词序
    # 倒排），非真 BE 整数折叠；故用 _fe_be32_hex_from_bytes32（与实例 23
    # rev_root 同式），曾误用 _fe_be32_hex_from_digest 被 e2e 逐位对拍抓出。
    server_sn_hex = server_sn_hash_hex(session, sub_cred_hash_hex)
    _expect(25, _fe_be32_hex_from_bytes32(bytes.fromhex(server_sn_hex)), "sn_hash")
    if t_start <= 0 or t_end <= t_start:
        raise AuthzError("bad_window", "授权窗口非法（t_end 须大于 t_start）", 400)
    # 授权窗上限（S5 安全修复）：t_end 须 ≤ t_start+政策窗（缺省 6h）——
    # 防「10 年令牌」自报长窗（电路只钉 exp≥t_epoch，不钉窗长）
    import os as _os2

    max_window = int(_os2.environ.get("FZ_MAX_TOKEN_WINDOW_S", "21600"))
    if t_end - t_start > max_window:
        raise AuthzError("window_too_long", f"授权窗超过上限 {max_window}s", 409)
    # 时间锚新鲜度（R1 收口对抗自查增面）：t_epoch 是证明语句「凭证 exp_u ≥ t_epoch」
    # 的锚——无新鲜度门时恶意申请者可用远古 t_start 回溯（exp 检查空转+窗口洗白）。
    # 窗口须覆盖真实出证时长（本机 prove 分钟级+排队）——默认 1800s，env 可调。
    import os as _os
    import time as _time

    slack = int(_os.environ.get("FZ_APPLY_FRESHNESS_S", "1800"))
    now = int(_time.time())
    if not (now - slack <= t_start <= now + slack):
        raise AuthzError(
            "stale_t_epoch",
            f"授权窗起点偏离服务时间超过 {slack}s（时间锚过期/超前——重新出证）",
            409,
        )
    # ⑥ 凭证有效期覆盖核对（S6 安全闭环 2026-10-04）：AUTH 电路语句只证
    # exp_u ≥ t_epoch（实例 21=t_start=出证时刻）——「exp_u=now+1min 的合法
    # 子凭证（RA 签名为真）申请满 6h 授权窗」形态电路为真、上述各门全过，
    # 令牌却覆盖凭证死后近 6 小时。宿主面补核对：授权窗整体必须被凭证有效
    # 期覆盖（exp_u ≥ t_end）。取舍依据=规划裁决取强语义（整窗覆盖）：弱语义
    # （exp_u ≥ t_start）与电路重复、防线空转；诚实流不受伤——RA 子凭证
    # TTL=24h（ra/service.py SUB_CRED_TTL_HOURS）＞ 政策窗上限 6h。
    # exp_u 明文在已验签报文 M_A′ 内：布局 160B 前缀+4B exp+1B par=165B
    # （ra/credential.py build_message），即 msg[160:164] BE u32。
    exp_u = int.from_bytes(msg[160:164], "big")
    if exp_u < t_end:
        raise AuthzError(
            "cred_expired_window",
            "凭证有效期不覆盖申请的授权窗——请重新登记后申请",
            409,
        )

    # 子凭证唯一性（库级+链级双保险——受理面先库查）
    # R3-1.2（评审 P1-2）：仅 pending/approved 占用子凭证——rejected 放行重申
    # （与 0009 部分唯一索引同口径；一次性语义由"approved 即 consumed"保持）
    dup = session.scalar(
        select(Application).where(
            Application.sub_cred_hash_hex == sub_cred_hash_hex,
            Application.status.in_(["pending", "approved"]),
        )
    )
    if dup is not None:
        raise AuthzError("sub_cred_used", "子凭证已使用（一次性）", 409)
    # 库级 nonce 查重（S5：链写面 stub/排队期的兜底——授权单一性不空转）
    if session.scalar(select(Application.nonce_hex).where(Application.nonce_hex == nonce_hex)):
        raise AuthzError("nonce_used", "nonce 已使用（重放）", 409)
    # 语句摘要（S5[严重1]）：e=digest(M_A′) 入库——worker 传 expected.e_hex 钉实例 0，
    # 使「电路证明自签凭证 + 受理提交真子凭证」的组合攻击失效
    # e 为标量域元素（电路实例 0 = e mod n——SM2 阶）——归一化后落库
    from gmssl.sm2 import default_ecc_table

    _n = int(default_ecc_table["n"], 16)
    e_hex = format(int.from_bytes(e, "big") % _n, "064x")
    app_row = Application(
        case_id=(case_id or None),  # 批 4-1：案卷唯一归属（空=直呼门控不绑定）
        e_hex=e_hex,
        # 绑定挑战快照（2026-10-07 prove 窗根修）：落**本门⑤刚钉过实例 19** 的
        # 同一值——worker 复验消费库值与验证同源，不再按各自进程 env 重建钥控
        # HMAC（两进程 FZ_AUTHZ_BINDING_KEY 漂移曾致真案卷实例 19 假拒，实测
        # e2e_auth_full ⑥）。公开值：绑定面已下发客户端，无新增暴露面。
        challenge_hex=challenge_hex,
        session_pk_hex=session_pk_hex.lower(),
        sub_sig_hex=sub_sig_hex,
        sub_cred_hash_hex=sub_cred_hash_hex,
        nonce_hex=nonce_hex,
        plan_hash_hex=plan_hash_hex,
        class_id=class_id,
        policy_version="",
        proof_path=proof_path,
        spec_path=spec_path,
        rev_root_hex=rev_root_hex,
        t_start=t_start,
        t_end=t_end,
        sorties=int(sorties),
        exp_u=exp_u,  # S6 闭环归档源：worker 写判决件 expected.exp_u
        status="pending",
    )
    session.add(app_row)
    # 回执（128bit CSPRNG——零身份列）
    receipt = Receipt(code_hex=secrets.token_bytes(16).hex(), application_id=0)
    session.add(receipt)
    session.flush()
    receipt.application_id = app_row.id
    app_row.receipt_id = receipt.id
    session.commit()
    return app_row


def _reject_code_of(reason: str) -> str:
    """reject_reason 前缀折算稳定业务码（B3 人话化）：`rev_root_moved: …` →
    `rev_root_moved`——前端按码分流专属判词。非 `snake_code: ` 形态的自由
    文本（zkc 退出日志/transient 尾巴等）统一归 `verify_rejected`，不伪造
    业务语义。"""
    head = reason.split(":", 1)[0].strip() if reason else ""
    if head and all(c.isalnum() and not c.isupper() or c == "_" for c in head) and "_" in head:
        return head
    return "verify_rejected"


def receipt_of(session: Session, code_hex: str) -> dict:
    """回执取件：waiting（验证中）/ready+令牌密文/failed+拒绝理由（B3）。

    failed 态新增 reject_reason（Application.reject_reason 原文）与
    reject_code（前缀稳定码，_reject_code_of 折算）——被吊销飞手在回执
    取件面直接看到「吊销已生效」而非裸「验证拒绝」；ready/waiting 响应
    形态零变化（加字段不破既有）。"""
    r = session.scalar(select(Receipt).where(Receipt.code_hex == code_hex))
    if r is None:
        raise AuthzError("receipt_not_found", "回执码不存在", 404)
    out: dict = {"status": r.status}
    if r.status == "ready" and r.token_cipher is not None:
        out["token_cipher_hex"] = r.token_cipher.hex()
    if r.status == "failed":
        app_row = session.get(Application, r.application_id)
        reason = (app_row.reject_reason if app_row is not None else "") or ""
        out["reject_reason"] = reason
        out["reject_code"] = _reject_code_of(reason)
    return out


# ---- 令牌签发（worker 消费——B4-d3 定长 JSON+SM2 签名）----

TOKEN_FIELDS = (
    "authId",
    "plan_hash",
    "alt_max",
    "t_start",
    "t_end",
    "nonce",
    "policy_version",
)
# B4-d7 历史口径：sn_hash 曾不入令牌（链上+令牌双零设备信息；D9 机制升级
# 记录在案）——⑥代（2026-10-06）起令牌载荷含 sn_hash（见 build_token）。
# 🔴→✅ 口径换代（2026-10-06 ⑥代交付）：下方历史披露「电路内无 sn_h 等值钉、
# 解锁面一证多机无事前拦截、令牌级设备绑定须 vendor 电路换代——已挂账未
# 实施」已过时。现状：AUTH 电路公开实例 25=sn_hash（服务端权威 SM3(serial)，
# 词折叠 fold_words_be），build_token 载荷含 sn_hash（engine 签名域覆盖），
# 桥第 6 查 sn_mismatch 拒解锁——一证多机拦截全链闭环；签发面原像认证+
# 事后设备交叉审计（audit/device_check.py）保留为纵深防线。残余=真机 SE。


def build_token(
    *,
    auth_id: int,
    plan_hash_hex: str,
    alt_max: int,
    t_start: int,
    t_end: int,
    nonce_hex: str,
    policy_version: str,
    sn_hash_hex: str = "",
) -> str:
    """SN 绑定换代（2026-10-06）：载荷增 sn_hash（服务端权威 SM3(serial) 全
    32B hex）——入 body ⟹ engine 签名域覆盖（sign_token 对 body 原文签名）；
    桥第 6 查=SM3(本机 SN)==token.sn_hash（sitl_link/telemetry，不符=sn_mismatch）。"""
    body = json.dumps(
        {
            "authId": auth_id,
            "plan_hash": plan_hash_hex,
            "alt_max": alt_max,
            "t_start": t_start,
            "t_end": t_end,
            "nonce": nonce_hex,
            "policy_version": policy_version,
            "sn_hash": sn_hash_hex,
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    return body


def sign_token(body: str) -> str:
    sk, _pk = engine_signing_keypair()
    e = sm3_bytes(body.encode())
    return sign_digest(sk, e)


def token_hash(body: str) -> str:
    return sm3_bytes(body.encode()).hex()


def seal_receipt(
    session: Session, receipt_id: int, token_body: str, sig_hex: str, session_pk_hex: str
) -> None:
    """令牌封发：会话钥 ECIES 加密落回执。"""
    payload = (token_body + "|" + sig_hex).encode()
    cipher = ecies_encrypt(session_pk_hex, payload)
    r = session.get(Receipt, receipt_id)
    if r is None:
        raise AuthzError("receipt_not_found", "回执不存在", 404)
    r.token_cipher = cipher
    r.status = "ready"
    session.commit()


# ---- wrap 工具（A3 通道②消费同族——RA 侧用）----


def wrap_secret(plaintext: bytes, aad: bytes = b"FZ-WRAP") -> bytes:
    """域钥对称 wrap（nonce‖ct‖tag 打包——A3 通道②消费同族）。"""
    from app.crypto.sm4 import SM4GCM

    key = kms_domain_key(b"FZ-KMS|ra-store-wrap")
    g = SM4GCM(key)
    nonce = secrets.token_bytes(12)
    ct, tag = g.encrypt(nonce, plaintext, aad)
    return nonce + ct + tag


def unwrap_secret(blob: bytes, aad: bytes = b"FZ-WRAP") -> bytes:
    from app.crypto.sm4 import SM4GCM

    key = kms_domain_key(b"FZ-KMS|ra-store-wrap")
    g = SM4GCM(key)
    nonce, ct, tag = blob[:12], blob[12:-16], blob[-16:]
    return g.decrypt(nonce, ct, tag, aad)
