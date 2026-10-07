/*
 * 飞证 · 授权注册表（B1）
 * recordAuth 携带 subCredHash（D18：子凭证哈希——每申请全新，同一飞手链上
 * 授权记录逐次不可关联）与 proofDigest（D17：已验 ZK 证明的 SM3 摘要——
 * 第三方可对链上摘要事后复验判决件，作弊可检出）。
 * nonce 链级烧毁（授权单一性）；子凭证唯一性（B1-d2 链级强制一次性）。
 * authId 全系统贯穿键；链上无身份列。
 * 授权包配额制（2026-10-06 拍板，多架次场景）：recordAuth 增 sorties（1~5）
 * ——安全语义从「令牌一次性」上移为「配额一次性」：AuthRecord.remaining 随
 * engine 消费回报（consumeSortie）逐架次递减，remaining==0 即配额耗尽；
 * revokeAuth 同时清零配额（撤销即时终结全部剩余架次）。每架次仍走全新
 * 闸门序+独立 ARM+独立消费回报，链上零身份列不变（D18 语义不变）。
 */
pragma solidity ^0.4.25;

contract FlightAuthRegistry {

    address public admin;
    address public engine;
    modifier onlyAdmin() { require(msg.sender == admin, "not admin"); _; }
    modifier onlyEngine() { require(msg.sender == engine, "not engine"); _; }

    constructor() public { admin = msg.sender; }

    struct AuthRecord {
        bytes32 tokenHash;
        bytes16 nonce;
        // B3b-d6（2026-09-20 队友六问 A1 拍板）：删 snHash 公开字段——链上公开
        // snHash=跨次设备级关联点，违背 D18 逐次不可关联。此设计保持不变。
        // ✅ 口径换代（2026-10-06 ⑥代交付，与 backend/app/authz/service.py
        // 对齐）：设备与凭证的绑定已由电路+令牌+桥三层承担——AUTH 电路公开
        // 实例 25=sn_hash（服务端权威 SM3(serial)，词折叠 fold_words_be），
        // 令牌载荷含 sn_hash（engine 签名域覆盖），桥第 6 查 sn_mismatch 拒
        // 解锁——一证多机拦截全链闭环，且链上本表仍零设备字段（D18 语义
        // 不变）。历史批 3.1「电路内无 SN 等值钉、换代挂账未实施」已随 vendor
        // 电路换代闭环；残余边界=真机 SE（本源 SN 读数可信根）。
        // 注：本注释为纯注释改动，零字节码变化。
        uint8 classId;
        uint16 altMaxM;
        uint40 tStart;
        uint40 tEnd;
        bytes32 subCredHash;
        bytes32 proofDigest;
        uint8 status; // 0=有效 1=撤销
        uint8 revokeReason;
        uint8 remaining; // 剩余架次配额（1~5；consumeSortie 递减，0=耗尽/撤销清零）
        uint64 ts;
    }

    AuthRecord[] private _auths; // authId = index + 1（从 1 起，0=无效）
    mapping(bytes16 => bool) public usedNonces;
    mapping(bytes32 => bool) public usedSubCreds;
    mapping(bytes32 => uint256) public tokenAuthIds; // tokenHash → authId（B5 闸门验证）

    event AuthRecorded(uint256 indexed authId, bytes32 tokenHash, bytes16 nonce,
                       uint8 classId, uint16 altMaxM, uint40 tStart, uint40 tEnd,
                       bytes32 subCredHash, bytes32 proofDigest, uint8 sorties,
                       address engine, uint64 ts);
    event NonceBurned(bytes16 indexed nonce, address engine, uint64 ts);
    event AuthRevoked(uint256 indexed authId, uint8 reason, address engine, uint64 ts);
    event SortieConsumed(uint256 indexed authId, uint8 remaining, address engine, uint64 ts);

    function recordAuth(bytes32 tokenHash, bytes16 nonce,
                        uint8 classId, uint16 altMaxM, uint40 tStart, uint40 tEnd,
                        bytes32 subCredHash, bytes32 proofDigest, uint8 sorties)
        external onlyEngine returns (uint256 authId)
    {
        require(sorties >= 1 && sorties <= 5, "bad sorties");
        require(!usedNonces[nonce], "nonce burned");
        require(!usedSubCreds[subCredHash], "subcred used");
        require(tokenAuthIds[tokenHash] == 0, "token exists");
        usedNonces[nonce] = true;
        usedSubCreds[subCredHash] = true;
        tokenAuthIds[tokenHash] = _auths.length + 1;
        _auths.push(AuthRecord(tokenHash, nonce, classId, altMaxM, tStart, tEnd,
                              subCredHash, proofDigest, 0, 0, sorties, uint64(now)));
        authId = _auths.length;
        emit AuthRecorded(authId, tokenHash, nonce, classId, altMaxM, tStart, tEnd,
                          subCredHash, proofDigest, sorties, msg.sender, uint64(now));
    }

    function burnNonce(bytes16 nonce) external onlyEngine {
        require(!usedNonces[nonce], "nonce burned");
        usedNonces[nonce] = true;
        emit NonceBurned(nonce, msg.sender, uint64(now));
    }

    function revokeAuth(uint256 authId, uint8 reason) external onlyEngine {
        require(authId >= 1 && authId <= _auths.length, "bad authId");
        AuthRecord storage r = _auths[authId - 1];
        require(r.status == 0, "already revoked");
        r.status = 1;
        r.revokeReason = reason;
        r.remaining = 0; // 配额制：撤销即时清零剩余架次（全部架次终结合法性）
        emit AuthRevoked(authId, reason, msg.sender, uint64(now));
    }

    function consumeSortie(uint256 authId) external onlyEngine {
        // 消费回报链写（授权包配额制）：bridge ARM 成功 → backend /authz/consume
        // → engine 本函数——remaining-=1。remaining==0 即配额耗尽（拒绝=fail-
        // closed）；撤销态同样拒绝（撤销清零后无可消费配额）。
        require(authId >= 1 && authId <= _auths.length, "bad authId");
        AuthRecord storage r = _auths[authId - 1];
        require(r.status == 0, "auth revoked");
        require(r.remaining > 0, "quota exhausted");
        r.remaining -= 1;
        emit SortieConsumed(authId, r.remaining, msg.sender, uint64(now));
    }

    function remainingOf(uint256 authId) external view returns (uint8) {
        require(authId >= 1 && authId <= _auths.length, "bad authId");
        return _auths[authId - 1].remaining;
    }

    function nonceUsed(bytes16 nonce) external view returns (bool) {
        return usedNonces[nonce];
    }

    function getAuth(uint256 authId) external view returns
        (bytes32, bytes16, uint8, uint16, uint40, uint40, bytes32, bytes32, uint8, uint8, uint64, uint8)
    {
        require(authId >= 1 && authId <= _auths.length, "bad authId");
        AuthRecord storage r = _auths[authId - 1];
        return (r.tokenHash, r.nonce, r.classId, r.altMaxM, r.tStart, r.tEnd,
                r.subCredHash, r.proofDigest, r.status, r.revokeReason, r.ts, r.remaining);
    }

    function authCount() external view returns (uint256) { return _auths.length; }

    event RoleChanged(string role, address previous, address current, uint64 ts);
    function setEngine(address next) external onlyAdmin {
        emit RoleChanged("engine", engine, next, uint64(now));
        engine = next;
    }

    // ---- 管理面移交（批 3.2：admin→governor 多签+时间锁，一次性仪式）----
    function transferAdmin(address next) external onlyAdmin {
        require(next != address(0), "bad admin");
        emit RoleChanged("admin", admin, next, uint64(now));
        admin = next;
    }
}
