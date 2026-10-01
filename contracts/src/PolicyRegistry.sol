/*
 * 飞证 · 政策注册表（B1）
 * 政策参数版本化公示（种子=《无人驾驶航空器飞行管理暂行条例》公开数值）；
 * 电路身份指纹（pinCircuit——授权服务启动 fail-closed 比对，A8）；
 * 机型类规则表（classId→高度上限+所需资质等级——公开数据，Remote ID 口径）。
 */
pragma solidity ^0.4.25;

contract PolicyRegistry {

    address public admin;
    modifier onlyAdmin() { require(msg.sender == admin, "not admin"); _; }

    constructor() public { admin = msg.sender; }

    struct Policy { bytes32 paramsHash; uint64 ts; }
    string[] public policyVersions;
    // solc 0.4.25 不支持动态长度 key 的 public mapping 访问器——内部 bytes32 键
    // （keccak256(version)；国密链 EVM 层哈希=SM3）+ 显式查询函数
    mapping(bytes32 => Policy) private _policies;
    string public currentVersion;
    bytes32 public circuitPin; // 电路指纹（pin 仪式公示）

    event PolicyPublished(string version, bytes32 paramsHash, address admin, uint64 ts);
    event CircuitPinned(bytes32 pinFingerprint, address admin, uint64 ts);

    function publishPolicy(string version, bytes32 paramsHash) external onlyAdmin {
        bytes32 k = keccak256(bytes(version));
        require(_policies[k].ts == 0, "version exists");
        _policies[k] = Policy(paramsHash, uint64(now));
        policyVersions.push(version);
        currentVersion = version;
        emit PolicyPublished(version, paramsHash, msg.sender, uint64(now));
    }

    function getPolicy(string version) external view returns (bytes32, uint64) {
        Policy storage p = _policies[keccak256(bytes(version))];
        return (p.paramsHash, p.ts);
    }

    function pinCircuit(bytes32 pinFingerprint) external onlyAdmin {
        circuitPin = pinFingerprint;
        emit CircuitPinned(pinFingerprint, msg.sender, uint64(now));
    }

    struct ClassRule { uint16 altMaxM; uint8 requiredLevel; uint64 ts; }
    mapping(uint8 => ClassRule) public classRules;

    event ClassRuleSet(uint8 indexed classId, uint16 altMaxM, uint8 requiredLevel, address admin, uint64 ts);

    function setClassRule(uint8 classId, uint16 altMaxM, uint8 requiredLevel) external onlyAdmin {
        require(requiredLevel >= 1 && requiredLevel <= 4, "bad level");
        classRules[classId] = ClassRule(altMaxM, requiredLevel, uint64(now));
        emit ClassRuleSet(classId, altMaxM, requiredLevel, msg.sender, uint64(now));
    }

    function getClassRule(uint8 classId) external view returns (uint16, uint8) {
        ClassRule storage r = classRules[classId];
        return (r.altMaxM, r.requiredLevel);
    }
}
