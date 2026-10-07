/*
 * 飞证 · 身份注册表（B1）
 * 主凭证哈希+状态（D18：仅此合约存主凭证）；撤销累加器纪元根公示（D14：
 * setRevocationRoot 单调纪元，被吊销者下一次申请即被 AUTH 电路数学拒绝）；
 * 令状日志（审计方写入，追溯行为上链）。
 * 权限：ra=登记权威（写凭证与纪元根）；auditor=审计方（令状）；admin=部署者（换钥）。
 */
pragma solidity ^0.4.25;

contract IdentityRegistry {

    address public admin;
    address public ra;
    address public auditor;

    modifier onlyAdmin() { require(msg.sender == admin, "not admin"); _; }
    modifier onlyRA() { require(msg.sender == ra, "not ra"); _; }
    modifier onlyAuditor() { require(msg.sender == auditor, "not auditor"); _; }

    constructor() public { admin = msg.sender; }

    // ---- 主凭证（credKind: 1=个人飞手 2=机构机队）----
    struct CredRecord { uint8 status; uint8 credKind; uint64 ts; }
    // status: 0=不存在 1=有效 2=吊销 3=冻结
    mapping(bytes32 => CredRecord) public creds;

    event CommitmentRegistered(bytes32 indexed masterCredHash, uint8 credKind, address ra, uint64 ts);
    event StatusChanged(bytes32 indexed masterCredHash, uint8 status, address ra, uint64 ts);

    function registerCommitment(bytes32 masterCredHash, uint8 credKind) external onlyRA {
        require(creds[masterCredHash].status == 0, "cred exists");
        require(credKind == 1 || credKind == 2, "bad kind");
        creds[masterCredHash] = CredRecord(1, credKind, uint64(now));
        emit CommitmentRegistered(masterCredHash, credKind, msg.sender, uint64(now));
    }

    function setStatus(bytes32 masterCredHash, uint8 status) external onlyRA {
        require(creds[masterCredHash].status != 0, "cred absent");
        require(status >= 1 && status <= 3, "bad status");
        creds[masterCredHash].status = status;
        emit StatusChanged(masterCredHash, status, msg.sender, uint64(now));
    }

    // ---- 撤销累加器纪元根（D14：单调纪元，RA 每次吊销/恢复后公示新根）----
    uint64 public revEpoch = 0;
    bytes32 public revRoot;
    mapping(uint64 => bytes32) public revRoots;

    event RevocationRootSet(uint64 indexed epoch, bytes32 revRoot, address ra, uint64 ts);

    function setRevocationRoot(uint64 epoch, bytes32 newRoot) external onlyRA {
        require(epoch == revEpoch + 1, "epoch not monotonic");
        revEpoch = epoch;
        revRoot = newRoot;
        revRoots[epoch] = newRoot;
        emit RevocationRootSet(epoch, newRoot, msg.sender, uint64(now));
    }

    function isRevoked(bytes32 masterCredHash) external view returns (bool) {
        return creds[masterCredHash].status == 2;
    }

    function getCred(bytes32 masterCredHash) external view returns (uint8, uint8, uint64) {
        CredRecord storage c = creds[masterCredHash];
        return (c.status, c.credKind, c.ts);
    }

    // ---- 令状日志（B7 追溯：令状在案=RA 协作解锁前置）----
    mapping(bytes32 => bool) public warrants;

    event WarrantLogged(bytes32 indexed warrantHash, bytes32 scopeHash, address auditor, uint64 ts);

    function logWarrant(bytes32 warrantHash, bytes32 scopeHash) external onlyAuditor {
        require(!warrants[warrantHash], "warrant exists");
        warrants[warrantHash] = true;
        emit WarrantLogged(warrantHash, scopeHash, msg.sender, uint64(now));
    }

    // ---- 解锁留痕（B7：RA 协作解锁的链上审计锚——一次性，令状必须先在案）----
    mapping(bytes32 => bool) public warrantUnlocks;

    event WarrantUnlockLogged(bytes32 indexed warrantHash, bytes32 credHash, address ra, uint64 ts);

    function logWarrantUnlock(bytes32 warrantHash, bytes32 credHash) external onlyRA {
        require(warrants[warrantHash], "warrant not on file");
        require(!warrantUnlocks[warrantHash], "unlock already logged");
        warrantUnlocks[warrantHash] = true;
        emit WarrantUnlockLogged(warrantHash, credHash, msg.sender, uint64(now));
    }

    // ---- 治理（换钥面）----
    event RoleChanged(string role, address previous, address current, uint64 ts);

    function setRA(address next) external onlyAdmin {
        emit RoleChanged("ra", ra, next, uint64(now));
        ra = next;
    }

    function setAuditor(address next) external onlyAdmin {
        emit RoleChanged("auditor", auditor, next, uint64(now));
        auditor = next;
    }

    // ---- 管理面移交（批 3.2：admin→governor 多签+时间锁，一次性仪式）----
    function transferAdmin(address next) external onlyAdmin {
        require(next != address(0), "bad admin");
        emit RoleChanged("admin", admin, next, uint64(now));
        admin = next;
    }
}
