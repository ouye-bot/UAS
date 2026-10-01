/*
 * 飞证 · 授权注册表（B1）
 * recordAuth 携带 subCredHash（D18：子凭证哈希——每申请全新，同一飞手链上
 * 授权记录逐次不可关联）与 proofDigest（D17：已验 ZK 证明的 SM3 摘要——
 * 第三方可对链上摘要事后复验判决件，作弊可检出）。
 * nonce 链级烧毁（授权单一性）；子凭证唯一性（B1-d2 链级强制一次性）。
 * authId 全系统贯穿键；链上无身份列。
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
        // B3b-d6（2026-09-20 队友六问 A1 拍板）：删 snHash 公开字段——设备与
        // 凭证的绑定由证明承担（sn_h 在承诺 C 内、C 被 RA 签名覆盖、电路验签），
        // 链上公开 snHash=跨次设备级关联点，违背 D18 逐次不可关联。
        uint8 classId;
        uint16 altMaxM;
        uint40 tStart;
        uint40 tEnd;
        bytes32 subCredHash;
        bytes32 proofDigest;
        uint8 status; // 0=有效 1=撤销
        uint8 revokeReason;
        uint64 ts;
    }

    AuthRecord[] private _auths; // authId = index + 1（从 1 起，0=无效）
    mapping(bytes16 => bool) public usedNonces;
    mapping(bytes32 => bool) public usedSubCreds;
    mapping(bytes32 => uint256) public tokenAuthIds; // tokenHash → authId（B5 闸门验证）

    event AuthRecorded(uint256 indexed authId, bytes32 tokenHash, bytes16 nonce,
                       uint8 classId, uint16 altMaxM, uint40 tStart, uint40 tEnd,
                       bytes32 subCredHash, bytes32 proofDigest, address engine, uint64 ts);
    event NonceBurned(bytes16 indexed nonce, address engine, uint64 ts);
    event AuthRevoked(uint256 indexed authId, uint8 reason, address engine, uint64 ts);

    function recordAuth(bytes32 tokenHash, bytes16 nonce,
                        uint8 classId, uint16 altMaxM, uint40 tStart, uint40 tEnd,
                        bytes32 subCredHash, bytes32 proofDigest)
        external onlyEngine returns (uint256 authId)
    {
        require(!usedNonces[nonce], "nonce burned");
        require(!usedSubCreds[subCredHash], "subcred used");
        require(tokenAuthIds[tokenHash] == 0, "token exists");
        usedNonces[nonce] = true;
        usedSubCreds[subCredHash] = true;
        tokenAuthIds[tokenHash] = _auths.length + 1;
        _auths.push(AuthRecord(tokenHash, nonce, classId, altMaxM, tStart, tEnd,
                              subCredHash, proofDigest, 0, 0, uint64(now)));
        authId = _auths.length;
        emit AuthRecorded(authId, tokenHash, nonce, classId, altMaxM, tStart, tEnd,
                          subCredHash, proofDigest, msg.sender, uint64(now));
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
        emit AuthRevoked(authId, reason, msg.sender, uint64(now));
    }

    function nonceUsed(bytes16 nonce) external view returns (bool) {
        return usedNonces[nonce];
    }

    function getAuth(uint256 authId) external view returns
        (bytes32, bytes16, uint8, uint16, uint40, uint40, bytes32, bytes32, uint8, uint8, uint64)
    {
        require(authId >= 1 && authId <= _auths.length, "bad authId");
        AuthRecord storage r = _auths[authId - 1];
        return (r.tokenHash, r.nonce, r.classId, r.altMaxM, r.tStart, r.tEnd,
                r.subCredHash, r.proofDigest, r.status, r.revokeReason, r.ts);
    }

    function authCount() external view returns (uint256) { return _auths.length; }

    event RoleChanged(string role, address previous, address current, uint64 ts);
    function setEngine(address next) external onlyAdmin {
        emit RoleChanged("engine", engine, next, uint64(now));
        engine = next;
    }
}
