// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {L2Registry} from "../src/durin/L2Registry.sol";

/**
 * Invariant campaign for the property the v2 record rules exist to deliver
 * (WoCo-Contracts #21):
 *
 *   A name's records hold ONLY writes made since its current holding began,
 *   by its holder or an enrolled registrar. An approvee or operator moves the
 *   name and does nothing else (v2.1, audits 937 F4 / 938 H-1, M-7) — a move to
 *   the name's own holder changes nothing at all (948 / 949).
 *
 * The handler keeps its own MODEL of who holds each name, who is approved,
 * who is an operator and whether the registrar is enrolled, built from the
 * calls it makes and never read back from the registry. Every ownership change
 * and every record write or clear is attempted by every kind of caller; the
 * model predicts whether the registry must accept it, and a disagreement in
 * EITHER direction is recorded — a refused legitimate write is as much a
 * defect as an accepted illegitimate one. The records themselves are then
 * compared with the last write the model saw accepted in the current holding.
 *
 * WHAT THIS CAMPAIGN DOES NOT COVER: the admin handover (the admin is never a
 * holder of the names under test), children below the fuzzed names — which
 * `L2RegistryTreeInvariant.t.sol` covers — and signatures, pinned by their own
 * suite. The admin is never enrolled as a registrar here;
 * that accepted power is pinned in the unit suites instead.
 *
 * Kept in its own file because invariant campaigns are slow.
 */
contract RecordsHandler is Test {
    L2Registry public immutable registry;
    address public immutable admin;
    address public immutable registrarActor = makeAddr("registrar");
    bytes32 public immutable baseNode;

    address[4] internal people;
    string[3] internal labels;

    // ── The model ──────────────────────────────────────────────────────────
    mapping(bytes32 node => address) public modelOwner;
    mapping(bytes32 node => address) public modelApproved;
    mapping(address owner => mapping(address operator => bool)) public modelOperator;
    bool public modelRegistrarEnrolled = true;
    mapping(bytes32 node => bytes) public modelContenthash;
    mapping(bytes32 node => string) public modelText;
    mapping(bytes32 node => bytes) public modelAddr;

    // ── Witnesses ──────────────────────────────────────────────────────────
    /// Every action can be refused, so "the model never disagreed" is only
    /// evidence if each kind of attempt was made — and Foundry checks these
    /// after EVERY run, so each run must make them.
    uint256 public ownershipChanges;
    uint256 public acceptedWrites;
    uint256 public refusedWrites;
    uint256 public acceptedClears;
    uint256 public refusedClears;
    uint256 public writesToAbsentNames;
    /// Attempts by an approvee or operator of the holder, who must be refused
    /// records, clears and burns — the v2.1 rule this campaign most needs to see.
    uint256 public delegateAttempts;
    /// Moves to the name's current holder, which must change nothing.
    uint256 public selfTransfers;

    bool public modelDisagreed;
    string public disagreement;

    constructor(L2Registry registry_, address admin_) {
        registry = registry_;
        admin = admin_;
        baseNode = registry_.baseNode();
        people = [makeAddr("alice"), makeAddr("bob"), makeAddr("carol"), makeAddr("dave")];
        labels = ["venue", "shop", "band"];
    }

    function nodeAt(uint256 i) public view returns (bytes32) {
        return keccak256(abi.encodePacked(baseNode, keccak256(bytes(labels[i % labels.length]))));
    }

    function nodeCount() external view returns (uint256) {
        return labels.length;
    }

    // ── Ownership changes ──────────────────────────────────────────────────

    function mint(uint256 labelSeed, uint256 toSeed) external {
        uint256 i = labelSeed % labels.length;
        bytes32 node = nodeAt(i);
        address to = people[toSeed % people.length];
        bool expected = modelRegistrarEnrolled && modelOwner[node] == address(0);

        bytes[] memory none = new bytes[](0);
        vm.prank(registrarActor);
        try registry.createSubnode(baseNode, labels[i], to, none) {
            _agree(expected, true, "mint");
            _newHolding(node, to);
        } catch {
            _agree(expected, false, "mint");
        }
    }

    function transfer(uint256 labelSeed, uint256 bySeed, uint256 toSeed) external {
        bytes32 node = nodeAt(labelSeed);
        address by = people[bySeed % people.length];
        address to = people[toSeed % people.length];
        address holder = modelOwner[node];
        bool expected = holder != address(0) && _actsForHolder(node, by);

        vm.prank(by);
        try registry.transferFrom(holder, to, uint256(node)) {
            _agree(expected, true, "transferFrom");
            if (to == holder) {
                // A move to the current holder is not a change of holding: the
                // records stay, the version stays, and only the per-token
                // approval is cleared, by OpenZeppelin (audits 948 / 949).
                selfTransfers++;
                modelApproved[node] = address(0);
            } else {
                _newHolding(node, to);
            }
        } catch {
            _agree(expected, false, "transferFrom");
        }
    }

    function release(uint256 labelSeed, uint256 bySeed) external {
        bytes32 node = nodeAt(labelSeed);
        address by = people[bySeed % people.length];
        // The holder only: these names sit beneath the base name, so no
        // parent's holder may act, and approvals never reach a burn.
        bool expected = modelOwner[node] != address(0) && by == modelOwner[node];

        vm.prank(by);
        try registry.release(node) {
            _agree(expected, true, "release");
            _newHolding(node, address(0));
        } catch {
            _agree(expected, false, "release");
        }
    }

    function adminTransfer(uint256 labelSeed, uint256 toSeed) external {
        bytes32 node = nodeAt(labelSeed);
        address to = people[toSeed % people.length];
        bool expected = modelOwner[node] != address(0) && to != modelOwner[node];

        vm.prank(admin);
        try registry.adminTransfer(node, to) {
            _agree(expected, true, "adminTransfer");
            _newHolding(node, to);
        } catch {
            _agree(expected, false, "adminTransfer");
        }
    }

    // ── Authority that is not ownership ────────────────────────────────────

    function approve(uint256 labelSeed, uint256 bySeed, uint256 toSeed) external {
        bytes32 node = nodeAt(labelSeed);
        address by = people[bySeed % people.length];
        address to = people[toSeed % people.length];
        address holder = modelOwner[node];
        // ERC-721: the holder or its operator may approve; an approvee may not.
        bool expected = holder != address(0) && (by == holder || modelOperator[holder][by]);

        vm.prank(by);
        try registry.approve(to, uint256(node)) {
            _agree(expected, true, "approve");
            modelApproved[node] = to;
        } catch {
            _agree(expected, false, "approve");
        }
    }

    function setOperator(uint256 bySeed, uint256 operatorSeed, bool on) external {
        address by = people[bySeed % people.length];
        address op = people[operatorSeed % people.length];

        vm.prank(by);
        registry.setApprovalForAll(op, on);
        modelOperator[by][op] = on;
    }

    function toggleRegistrar(bool on) external {
        vm.prank(admin);
        if (on) registry.addRegistrar(registrarActor);
        else registry.removeRegistrar(registrarActor);
        modelRegistrarEnrolled = on;
    }

    /// The holder approves someone — for this name or for all of its names —
    /// and that someone tries to write, clear and burn. Each must be refused.
    /// Its own action so that every run makes the attempt the v2.1 rule is
    /// about, rather than waiting for the other actions to line one up.
    function delegateTries(uint256 labelSeed, uint256 delegateSeed, bool forAll, uint256 valueSeed) external {
        bytes32 node = nodeAt(labelSeed);
        address holder = modelOwner[node];
        if (holder == address(0)) return;
        address delegate = people[delegateSeed % people.length];
        if (delegate == holder) delegate = people[(delegateSeed % people.length + 1) % people.length];

        vm.prank(holder);
        if (forAll) {
            registry.setApprovalForAll(delegate, true);
            modelOperator[holder][delegate] = true;
        } else {
            registry.approve(delegate, uint256(node));
            modelApproved[node] = delegate;
        }
        delegateAttempts++;

        bytes memory value = abi.encodePacked(hex"e40101fa011b20", keccak256(abi.encode(valueSeed)));
        vm.prank(delegate);
        try registry.setContenthash(node, value) {
            _agree(false, true, "a delegate's record write");
        } catch {}
        vm.prank(delegate);
        try registry.clearRecords(node) {
            _agree(false, true, "a delegate's clearRecords");
        } catch {}
        vm.prank(delegate);
        try registry.release(node) {
            _agree(false, true, "a delegate's release");
        } catch {}
        // And the move that changes nothing: the records must survive it.
        vm.prank(delegate);
        try registry.transferFrom(holder, holder, uint256(node)) {
            selfTransfers++;
            modelApproved[node] = address(0);
        } catch {}
    }

    // ── Records ────────────────────────────────────────────────────────────

    function write(uint256 labelSeed, uint256 writerSeed, bool asHolder, uint8 kind, uint256 valueSeed) external {
        bytes32 node = nodeAt(labelSeed);
        address writer = _pickWriter(node, writerSeed, asHolder);
        bool present = modelOwner[node] != address(0);
        bool expected = present
            && ((writer == registrarActor && modelRegistrarEnrolled) || writer == modelOwner[node]);
        if (!present) writesToAbsentNames++;

        kind %= 3;
        bool ok;
        if (kind == 0) {
            bytes memory value = abi.encodePacked(hex"e40101fa011b20", keccak256(abi.encode(valueSeed)));
            vm.prank(writer);
            try registry.setContenthash(node, value) {
                ok = true;
                modelContenthash[node] = value;
            } catch {}
        } else if (kind == 1) {
            string memory value = vm.toString(valueSeed);
            vm.prank(writer);
            try registry.setText(node, "url", value) {
                ok = true;
                modelText[node] = value;
            } catch {}
        } else {
            bytes memory value = abi.encodePacked(address(uint160(valueSeed)));
            vm.prank(writer);
            try registry.setAddr(node, 60, value) {
                ok = true;
                modelAddr[node] = value;
            } catch {}
        }

        _agree(expected, ok, "record write");
        if (ok) acceptedWrites++;
        else refusedWrites++;
    }

    function clear(uint256 labelSeed, uint256 writerSeed, bool asHolder) external {
        bytes32 node = nodeAt(labelSeed);
        address writer = _pickWriter(node, writerSeed, asHolder);
        // The holder only: a registrar is refused even when enrolled, and so
        // are the holder's approvees and operators.
        bool expected = modelOwner[node] != address(0) && writer == modelOwner[node];

        vm.prank(writer);
        try registry.clearRecords(node) {
            _agree(expected, true, "clearRecords");
            _clearModel(node);
            acceptedClears++;
        } catch {
            _agree(expected, false, "clearRecords");
            refusedClears++;
        }
    }

    // ── Model helpers ──────────────────────────────────────────────────────

    /// The holder, its per-token approvee, or an operator of the holder: who
    /// may MOVE the name.
    function _actsForHolder(bytes32 node, address who) internal view returns (bool) {
        address holder = modelOwner[node];
        return holder != address(0)
            && (who == holder || modelApproved[node] == who || modelOperator[holder][who]);
    }

    /// Half the attempts come from the holder itself, when there is one, so
    /// every run lands writes and clears; the rest from anyone who might try —
    /// the four people, whoever the holder approved, the registrar, the admin.
    function _pickWriter(bytes32 node, uint256 seed, bool asHolder) internal view returns (address) {
        if (asHolder && modelOwner[node] != address(0)) return modelOwner[node];
        uint256 k = seed % (people.length + 3);
        if (k < people.length) return people[k];
        if (k == people.length) return modelApproved[node] == address(0) ? people[0] : modelApproved[node];
        return k == people.length + 1 ? registrarActor : admin;
    }

    function _newHolding(bytes32 node, address to) internal {
        modelOwner[node] = to;
        modelApproved[node] = address(0);
        _clearModel(node);
        ownershipChanges++;
    }

    function _clearModel(bytes32 node) internal {
        delete modelContenthash[node];
        delete modelText[node];
        delete modelAddr[node];
    }

    function _agree(bool expected, bool actual, string memory what) internal {
        if (expected != actual && !modelDisagreed) {
            modelDisagreed = true;
            disagreement = string.concat(what, actual ? " was accepted against the model" : " was refused against the model");
        }
    }
}

contract L2RegistryRecordsInvariantTest is Test {
    L2Registry registry;
    RecordsHandler handler;

    function setUp() public {
        address admin = makeAddr("admin");
        registry = L2Registry(Clones.clone(address(new L2Registry())));
        registry.initialize("woco.eth", "WoCo Names", "", admin);

        handler = new RecordsHandler(registry, admin);
        address registrarActor = handler.registrarActor();
        vm.prank(admin);
        registry.addRegistrar(registrarActor);

        bytes4[] memory selectors = new bytes4[](10);
        selectors[0] = RecordsHandler.mint.selector;
        selectors[1] = RecordsHandler.transfer.selector;
        selectors[2] = RecordsHandler.release.selector;
        selectors[3] = RecordsHandler.adminTransfer.selector;
        selectors[4] = RecordsHandler.approve.selector;
        selectors[5] = RecordsHandler.setOperator.selector;
        selectors[6] = RecordsHandler.toggleRegistrar.selector;
        selectors[7] = RecordsHandler.write.selector;
        selectors[8] = RecordsHandler.clear.selector;
        selectors[9] = RecordsHandler.delegateTries.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        targetContract(address(handler));
    }

    /// Every attempt — ownership change, approval, write, clear — went the way
    /// the independent model said the rules require.
    /// forge-config: default.invariant.runs = 64
    function invariant_TheRegistryAcceptsExactlyWhatTheRulesAllow() public view {
        assertFalse(handler.modelDisagreed(), handler.disagreement());
    }

    /// Each name's holder, and each record, is exactly what the model holds:
    /// the last write accepted since the current holding began, or nothing.
    /// forge-config: default.invariant.runs = 64
    function invariant_RecordsAreExactlyTheCurrentHoldingsAcceptedWrites() public view {
        uint256 n = handler.nodeCount();
        for (uint256 i; i < n; ++i) {
            bytes32 node = handler.nodeAt(i);
            assertEq(registry.owner(node), handler.modelOwner(node), "holder diverged from the model");
            assertEq(registry.contenthash(node), handler.modelContenthash(node), "contenthash outlived its holding");
            assertEq(registry.text(node, "url"), handler.modelText(node), "text record outlived its holding");
            assertEq(registry.addr(node, 60), handler.modelAddr(node), "addr record outlived its holding");
        }
    }

    /// Coverage, not correctness — here rather than in an invariant body, which
    /// is also evaluated at setup, when every counter is legitimately zero.
    function afterInvariant() public view {
        assertGt(handler.ownershipChanges(), 0, "campaign never changed a holding");
        assertGt(handler.acceptedWrites(), 0, "campaign never landed a record write");
        assertGt(handler.refusedWrites(), 0, "campaign never had a record write refused");
        assertGt(handler.acceptedClears(), 0, "campaign never cleared records");
        assertGt(handler.refusedClears(), 0, "campaign never had a clear refused");
        assertGt(handler.writesToAbsentNames(), 0, "campaign never tried to write a name that does not exist");
        assertGt(handler.delegateAttempts(), 0, "campaign never had an approvee or operator try to act");
        assertGt(handler.selfTransfers(), 0, "campaign never moved a name to its own holder");
    }
}
