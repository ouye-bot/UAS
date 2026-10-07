/*
 * 飞证 · 联盟链治理多签+时间锁（批 3.2）
 * owners=[admin,RA,auditor] 三钥（部署时注入，不新增钥）、required=2；
 * 时间锁延迟 delay（秒，构造参数——FZ_GOVERNOR_DELAY_S 语义）。缺省部署
 * 10s 仅保测试性：🔴 生产环境必须调大（建议 ≥86400=24h），给全部 owner
 * 留出对恶意/误操作提案的观察与 cancel 撤销窗。
 *
 * 治理面语义：四业务合约的 onlyAdmin 面（政策/指纹公示+角色授予）移交本
 * 合约后，任何 admin 面写入必须走三步仪式——
 *   propose(target,calldataHash,description)：owner 提案（calldata 哈希承诺）
 *   confirm(proposalId)：owner 各一票不可重复；票数达 required 即锁定
 *                        eta=now+delay（Queued 态）
 *   execute(target,value,calldata)：到期后执行；calldata 逐位对拍提案哈希，
 *                        防替换（篡改即"无此提案"拒）
 * 生命周期事件全程上链：Proposed/Confirmed/Executed/Cancelled。
 * 读写零变化面：RA/engine/auditor 业务角色与全部 read 面不经本合约。
 */
pragma solidity ^0.4.25;

contract AdminGovernor {

    // FISCO BCOS 2.x block.timestamp=毫秒（真链 2026-10-05 实测：getBlockByNumber
    // ts=13 位毫秒）——delay 构造参数语义为秒，入 eta 前换算到链时间戳单位
    uint64 private constant _SEC_TO_TS = 1000;

    address[3] public owners;
    uint8 public required; // 法定票数（部署=2）
    uint32 public delay;   // 时间锁延迟（秒）——eta=法定人数达成时点+delay
    uint256 public proposalCount;

    enum Status { Active, Queued, Executed, Cancelled }

    struct Proposal {
        address target;
        bytes32 calldataHash;
        string description;
        uint64 eta;         // 法定人数达成时点+delay（Active 期=0）
        uint8 confirmations;
        Status status;
    }

    mapping(uint256 => Proposal) private _proposals;
    mapping(uint256 => mapping(address => bool)) private _confirmedBy;
    // 待决提案按调用指纹 keccak256(target‖calldataHash) 索引——execute 无
    // proposalId 形参，靠本索引 O(1) 定位；执行/取消即清除（0=无待决）
    mapping(bytes32 => uint256) private _pendingByCall;

    event Proposed(uint256 indexed proposalId, address target, bytes32 calldataHash,
                   string description, address proposer, uint64 ts);
    event Confirmed(uint256 indexed proposalId, address confirmer,
                    uint8 confirmations, uint64 eta, uint64 ts);
    event Executed(uint256 indexed proposalId, address target, uint256 value, uint64 ts);
    event Cancelled(uint256 indexed proposalId, address by, uint64 ts);

    modifier onlyOwner() {
        require(_isOwner(msg.sender), "not owner");
        _;
    }

    constructor(address[3] memory _owners, uint8 _required, uint32 _delay) public {
        require(_required >= 1 && _required <= 3, "bad required");
        for (uint8 i = 0; i < 3; i++) {
            require(_owners[i] != address(0), "zero owner");
            for (uint8 j = 0; j < i; j++) {
                require(_owners[i] != _owners[j], "dup owner");
            }
            owners[i] = _owners[i];
        }
        required = _required;
        delay = _delay;
    }

    function _isOwner(address a) internal view returns (bool) {
        return a == owners[0] || a == owners[1] || a == owners[2];
    }

    function isOwner(address a) external view returns (bool) {
        return _isOwner(a);
    }

    function getProposal(uint256 proposalId) external view
        returns (address target, bytes32 calldataHash, string description,
                 uint64 eta, uint8 confirmations, uint8 status)
    {
        Proposal storage p = _proposals[proposalId];
        return (p.target, p.calldataHash, p.description, p.eta,
                p.confirmations, uint8(p.status));
    }

    function proposalOfCall(address target, bytes32 calldataHash) external view
        returns (uint256)
    {
        return _pendingByCall[keccak256(abi.encodePacked(target, calldataHash))];
    }

    function propose(address target, bytes32 calldataHash, string description)
        external onlyOwner returns (uint256 proposalId)
    {
        require(target != address(0), "bad target");
        bytes32 key = keccak256(abi.encodePacked(target, calldataHash));
        require(_pendingByCall[key] == 0, "dup pending call");
        proposalCount = proposalCount + 1;
        proposalId = proposalCount;
        _proposals[proposalId] = Proposal(
            target, calldataHash, description, 0, 0, Status.Active);
        _pendingByCall[key] = proposalId;
        emit Proposed(proposalId, target, calldataHash, description,
                      msg.sender, uint64(now));
    }

    function confirm(uint256 proposalId) external onlyOwner {
        Proposal storage p = _proposals[proposalId];
        require(p.status == Status.Active, "not active");
        require(!_confirmedBy[proposalId][msg.sender], "already confirmed");
        _confirmedBy[proposalId][msg.sender] = true;
        p.confirmations = p.confirmations + 1;
        if (p.confirmations >= required) {
            p.status = Status.Queued;
            p.eta = uint64(now) + uint64(delay) * _SEC_TO_TS;
        }
        emit Confirmed(proposalId, msg.sender, p.confirmations, p.eta, uint64(now));
    }

    function cancel(uint256 proposalId) external onlyOwner {
        Proposal storage p = _proposals[proposalId];
        require(p.status == Status.Active || p.status == Status.Queued,
                "not cancellable");
        p.status = Status.Cancelled;
        delete _pendingByCall[keccak256(abi.encodePacked(p.target, p.calldataHash))];
        emit Cancelled(proposalId, msg.sender, uint64(now));
    }

    function execute(address target, uint256 value, bytes callData) external onlyOwner {
        bytes32 chash = keccak256(callData);
        bytes32 key = keccak256(abi.encodePacked(target, chash));
        uint256 proposalId = _pendingByCall[key];
        require(proposalId != 0, "no such proposal");
        Proposal storage p = _proposals[proposalId];
        require(p.status == Status.Queued, "not queued");
        require(p.confirmations >= required, "quorum not met");
        require(uint64(now) >= p.eta, "timelock not expired");
        require(p.target == target && p.calldataHash == chash, "call mismatch");
        p.status = Status.Executed;
        delete _pendingByCall[key];
        require(target.call.value(value)(callData), "exec failed");
        emit Executed(proposalId, target, value, uint64(now));
    }
}
