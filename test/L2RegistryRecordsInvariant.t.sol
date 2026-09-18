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
 *   by its holder or an enrolled registrar. Nobody acts for the holder: v2.2
 *   refuses every ERC-721 approval (audit 950; v2.1 had let approvals move the
 *   name, and a move to oneself turned out to be every holder power). A move
 *   to the name's own holder changes nothing at all (948 / 949).
 *
 * The handler keeps its own MODEL of who holds each name and whether the
 * registrar is enrolled, built from the calls it makes and never read back
 * from the registry. It has no model of approvals because none can exist: every
 * attempt to make one must be refused, and `invariant_NoApprovalEverExists`
 * reads the registry to confirm it. Every ownership change
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
    /// Approvals attempted — per-token or for all, by anyone — every one of
    /// which must be refused (v2.2).
    uint256 public refusedDelegations;
    /// Attempts by a party the holder tried to approve, who must be refused the
    /// name, its records, clears and burns — the rule this campaign most needs
    /// to see.
    uint256 public delegateAttempts;
    /// Moves to the name's current holder, which must change nothing.
    uint256 public selfTransfers;
    /// Of those, the ones made while the name actually HELD a record — without
    /// these the "records survive a self-transfer" clause is vacuous.
    uint256 public selfTransfersOverRecords;

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
        // Only the holder moves a name (v2.2): there are no approvees.
        bool expected = holder != address(0) && by == holder;

        vm.prank(by);
        try registry.transferFrom(holder, to, uint256(node)) {
            _agree(expected, true, "transferFrom");
            if (to == holder) {
                // A move to the current holder is not a change of holding: the
                // records stay and the version stays (audits 948 / 949).
                _countSelfTransfer(node);
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
        // parent's holder may act.
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

    /// v2.2: nobody may approve, the holder included, for any name — live or
    /// not — and the zero address (a "revocation") is refused like any other.
    function approve(uint256 labelSeed, uint256 bySeed, uint256 toSeed, bool revoke) external {
        bytes32 node = nodeAt(labelSeed);
        address by = _pickApprover(node, bySeed);
        address to = revoke ? address(0) : people[toSeed % people.length];

        vm.prank(by);
        try registry.approve(to, uint256(node)) {
            _agree(false, true, "approve");
        } catch {
            _agree(false, false, "approve");
            refusedDelegations++;
        }
    }

    function setOperator(uint256 bySeed, uint256 operatorSeed, bool on) external {
        address by = people[bySeed % people.length];
        address op = people[operatorSeed % people.length];

        vm.prank(by);
        try registry.setApprovalForAll(op, on) {
            _agree(false, true, "setApprovalForAll");
        } catch {
            _agree(false, false, "setApprovalForAll");
            refusedDelegations++;
        }
    }

    function toggleRegistrar(bool on) external {
        vm.prank(admin);
        if (on) registry.addRegistrar(registrarActor);
        else registry.removeRegistrar(registrarActor);
        modelRegistrarEnrolled = on;
    }

    /// The holder tries to approve someone — for this name or for all of its
    /// names — and is refused. That someone then tries every door an approval
    /// used to open, directly or through a move to itself: take the name,
    /// write, clear, burn, move it to its holder. Each must be refused. Last,
    /// the HOLDER moves the name to itself, which must change nothing. Its own
    /// action so that every run makes the attempts the v2.2 rule is about,
    /// rather than waiting for the other actions to line one up.
    function delegateTries(uint256 labelSeed, uint256 delegateSeed, bool forAll, uint256 valueSeed) external {
        bytes32 node = nodeAt(labelSeed);
        address holder = modelOwner[node];
        if (holder == address(0)) return;
        // The clause this action exists to exercise is "the records survive a move
        // to the holder". Ownership churn wipes records constantly, so left to
        // chance the name is usually empty and the clause is vacuous. Give it one.
        if (!_hasRecord(node)) {
            bytes memory seeded =
                abi.encodePacked(hex"e40101fa011b20", keccak256(abi.encode(labelSeed, delegateSeed)));
            vm.prank(holder);
            try registry.setContenthash(node, seeded) {
                modelContenthash[node] = seeded;
            } catch {
                _agree(true, false, "the holder's own record write");
            }
        }

        address delegate = people[delegateSeed % people.length];
        if (delegate == holder) delegate = people[(delegateSeed % people.length + 1) % people.length];

        vm.prank(holder);
        if (forAll) {
            try registry.setApprovalForAll(delegate, true) {
                _agree(false, true, "the holder's setApprovalForAll");
            } catch {
                refusedDelegations++;
            }
        } else {
            try registry.approve(delegate, uint256(node)) {
                _agree(false, true, "the holder's approve");
            } catch {
                refusedDelegations++;
            }
        }
        delegateAttempts++;

        vm.prank(delegate);
        try registry.transferFrom(holder, delegate, uint256(node)) {
            _agree(false, true, "a would-be delegate taking the name");
        } catch {}

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
        vm.prank(delegate);
        try registry.transferFrom(holder, holder, uint256(node)) {
            _agree(false, true, "a would-be delegate's self-transfer");
        } catch {}
        // And the move that changes nothing: the holder's own. The records
        // must survive it. The holder is authorised, so a refusal here is a
        // disagreement, not an uninteresting outcome.
        vm.prank(holder);
        try registry.transferFrom(holder, holder, uint256(node)) {
            _countSelfTransfer(node);
        } catch {
            _agree(true, false, "the holder's self-transfer");
        }
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

    /// Half the attempts come from the holder itself, when there is one, so
    /// every run lands writes and clears; the rest from anyone who might try —
    /// the four people, the registrar, the admin.
    function _pickWriter(bytes32 node, uint256 seed, bool asHolder) internal view returns (address) {
        if (asHolder && modelOwner[node] != address(0)) return modelOwner[node];
        uint256 k = seed % (people.length + 2);
        if (k < people.length) return people[k];
        return k == people.length ? registrarActor : admin;
    }

    /// The holder most of the time — the approval this campaign most needs
    /// refused is the one a holder would make — otherwise anyone.
    function _pickApprover(bytes32 node, uint256 seed) internal view returns (address) {
        if (seed % 2 == 0 && modelOwner[node] != address(0)) return modelOwner[node];
        uint256 k = seed % (people.length + 2);
        if (k < people.length) return people[k];
        return k == people.length ? registrarActor : admin;
    }

    /// Everyone who could ever have been named an approvee or an operator.
    function everyone() external view returns (address[] memory all) {
        all = new address[](people.length + 2);
        for (uint256 i; i < people.length; ++i) all[i] = people[i];
        all[people.length] = registrarActor;
        all[people.length + 1] = admin;
    }

    function _hasRecord(bytes32 node) internal view returns (bool) {
        return modelContenthash[node].length > 0 || bytes(modelText[node]).length > 0
            || modelAddr[node].length > 0;
    }

    /// A self-transfer changes nothing of the registry's own.
    function _countSelfTransfer(bytes32 node) internal {
        selfTransfers++;
        if (_hasRecord(node)) {
            selfTransfersOverRecords++;
        }
    }

    function _newHolding(bytes32 node, address to) internal {
        modelOwner[node] = to;
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

    /// No approval exists, for any live name or any pair of parties (Fable 950
    /// consult §8): the two approval mappings are permanently empty, whatever
    /// the campaign attempted. Read from the registry, not the model.
    /// forge-config: default.invariant.runs = 64
    function invariant_NoApprovalEverExists() public view {
        uint256 n = handler.nodeCount();
        for (uint256 i; i < n; ++i) {
            bytes32 node = handler.nodeAt(i);
            if (registry.owner(node) != address(0)) {
                assertEq(registry.getApproved(uint256(node)), address(0), "a per-token approval exists");
            }
        }
        assertEq(registry.getApproved(uint256(registry.baseNode())), address(0), "the base name has an approvee");
        address[] memory all = handler.everyone();
        for (uint256 a; a < all.length; ++a) {
            for (uint256 b; b < all.length; ++b) {
                assertFalse(registry.isApprovedForAll(all[a], all[b]), "an operator approval exists");
            }
        }
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
        assertGt(handler.refusedDelegations(), 0, "campaign never had an approval refused");
        assertGt(handler.delegateAttempts(), 0, "campaign never had a would-be delegate try to act");
        assertGt(handler.selfTransfers(), 0, "campaign never moved a name to its own holder");
        assertGt(
            handler.selfTransfersOverRecords(),
            0,
            "campaign never moved a name that held a record to its own holder"
        );
    }
}
