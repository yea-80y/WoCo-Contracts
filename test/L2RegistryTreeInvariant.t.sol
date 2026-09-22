// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {L2Registry} from "../src/durin/L2Registry.sol";

/**
 * Invariant campaign for the name tree v2.1 keeps (owner decision 2026-09-17,
 * "the fusion"; audits 937 F8 / 938 H-2):
 *
 *   - `childCount[p]` is exactly the number of live names directly beneath p,
 *     the base name included;
 *   - every live name but the base name has a live parent;
 *   - `parentOf` is the name each node was created beneath;
 *   - `totalSupply` is the number of live names.
 *
 * The handler drives a fixed tree three levels deep beneath the base name,
 * minted whole before each run —
 * mints, releases by the holder and by the parent's holder, parent transfers,
 * plain transfers and admin transfers — from every kind of caller, and keeps
 * its own MODEL of who holds what, never read back from the registry. The
 * model predicts whether each call must succeed; a disagreement in either
 * direction is recorded.
 *
 * Kept in its own file because invariant campaigns are slow.
 */
contract TreeHandler is Test {
    L2Registry public immutable registry;
    address public immutable admin;
    address public immutable registrarActor = makeAddr("tree-registrar");

    /// Index 0 is the base name. Every other index names its parent's index
    /// and a label.
    uint256 public constant COUNT = 11;
    uint256[COUNT] internal parentIdx;
    string[COUNT] internal labelOf;
    bytes32[COUNT] public nodes;

    address[4] internal people;

    // ── The model ──────────────────────────────────────────────────────────
    address[COUNT] public modelOwner;
    bool[COUNT] public everMinted;

    // ── Witnesses ──────────────────────────────────────────────────────────
    uint256 public deepMints;
    uint256 public refusedForChildren;
    uint256 public releasesByParent;
    uint256 public parentTransfers;
    uint256 public adminTransfersOverChildren;

    bool public modelDisagreed;
    string public disagreement;

    constructor(L2Registry registry_, address admin_) {
        registry = registry_;
        admin = admin_;
        people = [makeAddr("t-alice"), makeAddr("t-bob"), makeAddr("t-carol"), makeAddr("t-dave")];

        // base ─ a ─ c ─ e
        //      │   └ d ─ f
        //      └ b ─ g ─ h
        //          └ i ─ j
        parentIdx = [uint256(0), 0, 0, 1, 1, 3, 4, 2, 7, 2, 9];
        labelOf = ["", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j"];
        nodes[0] = registry_.baseNode();
        modelOwner[0] = admin_;
        for (uint256 i = 1; i < COUNT; ++i) {
            nodes[i] = keccak256(abi.encodePacked(nodes[parentIdx[i]], keccak256(bytes(labelOf[i]))));
        }
    }

    function parentOfIdx(uint256 i) external view returns (uint256) {
        return parentIdx[i];
    }

    function liveChildren(uint256 p) public view returns (uint256 n) {
        for (uint256 j = 1; j < COUNT; ++j) {
            if (parentIdx[j] == p && modelOwner[j] != address(0)) n++;
        }
    }

    function liveCount() external view returns (uint256 n) {
        for (uint256 j; j < COUNT; ++j) {
            if (modelOwner[j] != address(0)) n++;
        }
    }

    function _idx(uint256 seed) internal pure returns (uint256) {
        return 1 + (seed % (COUNT - 1));
    }

    /// Half the time, a name that has live children, when there is one.
    function _idxPreferringParents(uint256 seed) internal view returns (uint256) {
        uint256 i = _idx(seed);
        if (seed % 2 == 1 || liveChildren(i) != 0) return i;
        for (uint256 k; k < COUNT - 1; ++k) {
            uint256 j = 1 + ((i - 1 + k) % (COUNT - 1));
            if (liveChildren(j) != 0) return j;
        }
        return i;
    }

    function _person(uint256 seed) internal view returns (address) {
        return people[seed % people.length];
    }

    /// Mints the whole tree, parents first, each name to someone other than
    /// its parent's holder. Called once from `setUp`, so every run starts from
    /// a full tree and every rule is reachable from its first call.
    function grow() external {
        bytes[] memory none = new bytes[](0);
        for (uint256 i = 1; i < COUNT; ++i) {
            uint256 p = parentIdx[i];
            address by = p == 0 ? registrarActor : modelOwner[p];
            address to = people[i % people.length];
            if (to == modelOwner[p]) to = people[(i + 1) % people.length];
            vm.prank(by);
            registry.createSubnode(nodes[p], labelOf[i], to, none);
            modelOwner[i] = to;
            everMinted[i] = true;
        }
    }

    // ── Actions ────────────────────────────────────────────────────────────

    /// Beneath the base name the registrar mints; deeper, the parent's holder
    /// does — or, when `byStranger`, someone who may not.
    function mint(uint256 seed, uint256 toSeed, bool byStranger) external {
        uint256 i = _idx(seed);
        uint256 p = parentIdx[i];
        address to = _person(toSeed);
        // Mostly a holder other than the parent's, so that a parent acting on
        // a child is acting on someone else's name.
        if (p != 0 && to == modelOwner[p] && toSeed % 4 != 0) to = _person(toSeed % 4 + 1);
        address by;
        bool allowed;
        if (p == 0) {
            by = byStranger ? _person(toSeed % 4 + 1) : registrarActor;
            allowed = !byStranger;
        } else {
            address parentHolder = modelOwner[p];
            by = byStranger || parentHolder == address(0) ? _person(toSeed % 4 + 1) : parentHolder;
            allowed = parentHolder != address(0) && by == parentHolder;
        }
        bool expected = allowed && modelOwner[i] == address(0);

        bytes[] memory none = new bytes[](0);
        vm.prank(by);
        try registry.createSubnode(nodes[p], labelOf[i], to, none) {
            _agree(expected, true, "createSubnode");
            modelOwner[i] = to;
            everMinted[i] = true;
            if (p != 0) deepMints++;
        } catch {
            _agree(expected, false, "createSubnode");
        }
    }

    function release(uint256 seed, uint256 bySeed, uint8 who) external {
        uint256 i = _idx(seed);
        uint256 p = parentIdx[i];
        address holder = modelOwner[i];
        address parentHolder = p == 0 ? address(0) : modelOwner[p];
        address by = who % 3 == 0 && holder != address(0)
            ? holder
            : who % 3 == 1 && parentHolder != address(0) ? parentHolder : _person(bySeed);
        if (who % 3 == 2 && p == 0) by = admin; // the base name's holder, who has no parent door

        bool authorised = holder != address(0) && (by == holder || (parentHolder != address(0) && by == parentHolder));
        bool childless = liveChildren(i) == 0;
        bool expected = authorised && childless;

        vm.prank(by);
        try registry.release(nodes[i]) {
            _agree(expected, true, "release");
            if (by != holder) releasesByParent++;
            modelOwner[i] = address(0);
        } catch (bytes memory err) {
            _agree(expected, false, "release");
            if (authorised && !childless) {
                if (bytes4(err) != L2Registry.HasChildren.selector) _agree(true, false, "release: wrong refusal");
                refusedForChildren++;
            }
        }
    }

    function parentTransfer(uint256 seed, uint256 bySeed, uint256 toSeed, bool asParent) external {
        uint256 i = _idx(seed);
        uint256 p = parentIdx[i];
        address holder = modelOwner[i];
        address parentHolder = p == 0 ? address(0) : modelOwner[p];
        address by = asParent && parentHolder != address(0) ? parentHolder : _person(bySeed);
        if (asParent && p == 0) by = admin;
        address to = _person(toSeed);
        bool expected = holder != address(0) && parentHolder != address(0) && by == parentHolder && to != holder;

        vm.prank(by);
        try registry.parentTransfer(nodes[i], to) {
            _agree(expected, true, "parentTransfer");
            modelOwner[i] = to;
            parentTransfers++;
        } catch {
            _agree(expected, false, "parentTransfer");
        }
    }

    function transfer(uint256 seed, uint256 toSeed) external {
        uint256 i = _idx(seed);
        address holder = modelOwner[i];
        address to = _person(toSeed);
        bool expected = holder != address(0);

        vm.prank(holder == address(0) ? to : holder);
        try registry.transferFrom(holder, to, uint256(nodes[i])) {
            _agree(expected, true, "transferFrom");
            modelOwner[i] = to;
        } catch {
            _agree(expected, false, "transferFrom");
        }
    }

    function adminTransfer(uint256 seed, uint256 toSeed) external {
        uint256 i = _idxPreferringParents(seed);
        address holder = modelOwner[i];
        address to = _person(toSeed);
        bool expected = holder != address(0) && to != holder;

        vm.prank(admin);
        try registry.adminTransfer(nodes[i], to) {
            _agree(expected, true, "adminTransfer");
            if (liveChildren(i) != 0) adminTransfersOverChildren++;
            modelOwner[i] = to;
        } catch {
            _agree(expected, false, "adminTransfer");
        }
    }

    function _agree(bool expected, bool actual, string memory what) internal {
        if (expected != actual && !modelDisagreed) {
            modelDisagreed = true;
            disagreement = string.concat(what, actual ? " was accepted against the model" : " was refused against the model");
        }
    }
}

contract L2RegistryTreeInvariantTest is Test {
    L2Registry registry;
    TreeHandler handler;

    function setUp() public {
        address admin = makeAddr("tree-admin");
        registry = L2Registry(Clones.clone(address(new L2Registry())));
        registry.initialize("woco.eth", "WoCo Names", "", admin);

        handler = new TreeHandler(registry, admin);
        address registrarActor = handler.registrarActor();
        vm.prank(admin);
        registry.addRegistrar(registrarActor);
        handler.grow();

        bytes4[] memory selectors = new bytes4[](10);
        // Mints weighted up, so the tree grows deep enough to matter.
        selectors[0] = TreeHandler.mint.selector;
        selectors[1] = TreeHandler.mint.selector;
        selectors[2] = TreeHandler.mint.selector;
        selectors[3] = TreeHandler.release.selector;
        selectors[4] = TreeHandler.release.selector;
        selectors[5] = TreeHandler.release.selector;
        selectors[6] = TreeHandler.parentTransfer.selector;
        selectors[7] = TreeHandler.parentTransfer.selector;
        selectors[8] = TreeHandler.transfer.selector;
        selectors[9] = TreeHandler.adminTransfer.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        targetContract(address(handler));
    }

    /// Every call went the way the independent model said the rules require.
    /// forge-config: default.invariant.runs = 64
    function invariant_TheTreeAcceptsExactlyWhatTheRulesAllow() public view {
        assertFalse(handler.modelDisagreed(), handler.disagreement());
    }

    /// The counts, the links, liveness and supply, for every node.
    /// forge-config: default.invariant.runs = 64
    function invariant_TheTreeIsExactlyTheModel() public view {
        uint256 count = handler.COUNT();
        for (uint256 i; i < count; ++i) {
            bytes32 node = handler.nodes(i);
            address holder = handler.modelOwner(i);
            assertEq(registry.owner(node), holder, "a holder diverged from the model");
            assertEq(registry.childCount(node), handler.liveChildren(i), "a child count diverged from the live children");
            if (i == 0) {
                assertEq(registry.parentOf(node), bytes32(0), "the base name has a parent");
                continue;
            }
            bytes32 parent = handler.nodes(handler.parentOfIdx(i));
            assertEq(registry.parentOf(node), handler.everMinted(i) ? parent : bytes32(0), "a parent link is wrong");
            if (holder != address(0)) {
                assertTrue(registry.owner(parent) != address(0), "a live name has a released parent");
            }
        }
        assertEq(registry.totalSupply(), handler.liveCount(), "supply is not the number of live names");
    }

    function afterInvariant() public view {
        assertGt(handler.deepMints(), 0, "campaign never minted beneath a name");
        assertGt(handler.refusedForChildren(), 0, "campaign never had a release refused for its children");
        assertGt(handler.releasesByParent(), 0, "campaign never had a parent's holder release a child");
        assertGt(handler.parentTransfers(), 0, "campaign never moved a child by parentTransfer");
        assertGt(handler.adminTransfersOverChildren(), 0, "campaign never seized a name that had children");
    }
}
