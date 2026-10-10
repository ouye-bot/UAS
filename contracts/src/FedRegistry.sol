/*
 * 飞证 · 互认注册表（⑥站多机构一期，2026-10-10）
 * 成员机构登记/退出（governor 治理面——k-of-n 提案仪式写入）+ 各机构撤销根
 * 逐域公示 + 全局聚合根（写时重算哈希聚合）。
 *
 * 一期诚实口径（不动电路——电路 pk_RA 单钥锚保持，多机构=组织/管理域分层）：
 * - 撤销树=系统级共享单树（AUTH 电路实例 23 绑定唯一 rev_root）；机构锚
 *   （revAnchors）=共享树根的**机构署名锚**（谁在何时把共享树推到哪个根——
 *   机构归因公示）；全局聚合根=对全部机构 (orgId,epoch,root) 的哈希承诺——
 *   任何域的吊销即时进入共享树 ⟹ 任何域受理面即时生效（任务书④语义）。
 * - 二期（电路内互认集成员证明）换真 per-org 树：本合约结构不变，锚语义升级。
 * - 机构退出（retire）：锚**冻结保留**在聚合内（退出机构的历史吊销永久互认，
 *   不得以退出换撤销失效——fail-closed），且退出后不得再推根（require active）。
 * 权限：admin=governor（机构准入治理面）；各机构 ra 地址=setOrgRevRoot 唯一
 * 推根钥（一期=系统 RA 钥同构多域署名，二期=各机构独立 RA 钥）。
 */
pragma solidity ^0.4.25;

contract FedRegistry {

    address public admin;

    modifier onlyAdmin() { require(msg.sender == admin, "not admin"); _; }

    // ---- 成员机构 ----
    struct Org { uint8 status; bytes32 name; address ra; uint64 ts; }
    // status: 0=不存在 1=active 2=retired（退出——锚冻结保留）
    mapping(bytes32 => Org) public orgs;
    bytes32[] public orgIds;      // 登记序（聚合遍历序=公示序）
    uint256 public orgActive;     // active 机构数

    event OrgRegistered(bytes32 indexed orgId, bytes32 name, address ra, address admin, uint64 ts);
    event OrgRetired(bytes32 indexed orgId, address admin, uint64 ts);

    function registerOrg(bytes32 orgId, bytes32 name, address ra) external onlyAdmin {
        require(orgs[orgId].status == 0, "org exists");
        require(ra != address(0), "bad ra");
        orgs[orgId] = Org(1, name, ra, uint64(now));
        orgIds.push(orgId);
        orgActive += 1;
        emit OrgRegistered(orgId, name, ra, msg.sender, uint64(now));
    }

    function retireOrg(bytes32 orgId) external onlyAdmin {
        require(orgs[orgId].status == 1, "org not active");
        orgs[orgId].status = 2;
        orgActive -= 1;
        emit OrgRetired(orgId, msg.sender, uint64(now));
        // 聚合根不变：退出机构锚冻结保留（历史吊销永久互认——fail-closed）
    }

    // ---- 撤销根逐域公示 + 全局聚合 ----
    struct RevAnchor { uint64 epoch; bytes32 root; uint64 ts; }
    mapping(bytes32 => RevAnchor) public revAnchors;   // orgId → 最新锚（逐域单调纪元）
    bytes32 public globalRevRoot;                      // 聚合根=SM3(逐机构 orgId‖epoch‖root)（GM 链 keccak256=SM3 同构）
    uint64 public globalRevEpoch;                      // 聚合纪元（任一机构推根即 +1——单调计数）

    event OrgRevRootSet(
        bytes32 indexed orgId, uint64 epoch, bytes32 root,
        bytes32 globalRoot, uint64 globalEpoch, address ra, uint64 ts
    );

    function setOrgRevRoot(bytes32 orgId, uint64 epoch, bytes32 root) external {
        require(orgs[orgId].status == 1, "org not active");
        require(msg.sender == orgs[orgId].ra, "not org ra");
        // 逐域严格递增（非 +1 连续——镜像锚须与共享树纪元锁步，而共享树纪元
        // 可能被治理烟测/历史推根预置跳档；「新于当前」即安全属性：防重放+防回滚）
        require(epoch > revAnchors[orgId].epoch, "epoch not monotonic");
        revAnchors[orgId] = RevAnchor(epoch, root, uint64(now));
        globalRevEpoch += 1;
        globalRevRoot = _aggregate();
        emit OrgRevRootSet(orgId, epoch, root, globalRevRoot, globalRevEpoch, msg.sender, uint64(now));
    }

    function _aggregate() private view returns (bytes32) {
        bytes memory buf = new bytes(0);
        for (uint256 i = 0; i < orgIds.length; i++) {
            bytes32 oid = orgIds[i];
            RevAnchor storage a = revAnchors[oid];
            buf = abi.encodePacked(buf, oid, a.epoch, a.root);
        }
        return keccak256(buf);
    }

    // ---- 治理面移交（③站同款：admin→governor，一次性仪式）----
    event RoleChanged(string role, address previous, address current, uint64 ts);

    function transferAdmin(address next) external onlyAdmin {
        require(next != address(0), "bad admin");
        emit RoleChanged("admin", admin, next, uint64(now));
        admin = next;
    }

    constructor() public { admin = msg.sender; }
}
