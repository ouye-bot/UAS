/*
 * 飞证 · 遥测锚定（B1）
 * 检查点=每 60s 上链的遥测链头（设备钥签名链下验证后由授权服务转发——B1-d1：
 * 链不验签名，engine 是唯一转发面=权限收敛）；seq 单调强制（防乱序/重放）；
 * 违规事件自动取证（eventType: 1=固件围栏触发 2=地面站监测超限 3=通信中断 4=迫降记录）。
 * 轨迹本体永不上链（只有链头）。
 */
pragma solidity ^0.4.25;

contract TelemetryAnchor {

    address public admin;
    address public engine;
    modifier onlyAdmin() { require(msg.sender == admin, "not admin"); _; }
    modifier onlyEngine() { require(msg.sender == engine, "not engine"); _; }

    constructor() public { admin = msg.sender; }

    struct Checkpoint { bytes32 chainHead; uint32 seq; uint64 ts; }
    mapping(uint256 => Checkpoint) public latest; // authId → 最新
    mapping(uint256 => mapping(uint32 => bytes32)) public anchoredHeads; // authId → seq → 链头（历史可查）

    event CheckpointAnchored(uint256 indexed authId, uint32 seq, bytes32 chainHead, bytes deviceSig, uint64 ts);
    event EventRecorded(uint256 indexed authId, uint8 eventType, bytes32 eventHash, address engine, uint64 ts);

    function anchorCheckpoint(uint256 authId, uint32 seq, bytes32 chainHead, bytes deviceSig) external onlyEngine {
        Checkpoint storage c = latest[authId];
        require(seq == c.seq + 1, "seq not monotonic");
        c.chainHead = chainHead;
        c.seq = seq;
        c.ts = uint64(now);
        anchoredHeads[authId][seq] = chainHead;
        emit CheckpointAnchored(authId, seq, chainHead, deviceSig, uint64(now));
    }

    function recordEvent(uint256 authId, uint8 eventType, bytes32 eventHash) external onlyEngine {
        require(eventType >= 1 && eventType <= 4, "bad eventType");
        emit EventRecorded(authId, eventType, eventHash, msg.sender, uint64(now));
    }

    function verifyHead(uint256 authId, bytes32 chainHead) external view returns (bool) {
        return latest[authId].chainHead == chainHead;
    }

    function latestSeq(uint256 authId) external view returns (uint32) {
        return latest[authId].seq;
    }

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
