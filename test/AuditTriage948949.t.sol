// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {L2Registry} from "../src/durin/L2Registry.sol";
import {L2Resolver} from "../src/durin/L2Resolver.sol";
import {UniversalSigValidatorFixture as Validator} from "./fixtures/UniversalSigValidatorFixture.sol";

/**
 * TRIAGE of the $1 audit reports on sub-ENS v2.1: LeftClaw engagements 948
 * (whole system) and 949 (registry + resolver in depth), both pinned to
 * `eb8216e`. Reports: `~/projects/woco-571-handover/AUDIT_94{8,9}_*.md`.
 *
 * Each test reproduces ONE claim against the code as it stands, and asserts
 * what the contract does TODAY. A green run means the claim is real as stated.
 * Nothing here is a fix: when one lands, its test is inverted, as the 937/938
 * triage was.
 */
contract AuditTriage948949Test is Test {
    L2Registry registry;

    address admin = makeAddr("admin");
    address registrar = makeAddr("registrar");
    address operator = makeAddr("operator");
    address approvee = makeAddr("approvee");
    address relayer = makeAddr("relayer");

    uint256 constant HOLDER_KEY = 0xA11CE;
    address holder = vm.addr(HOLDER_KEY);

    bytes constant SITE = hex"e40101fa011b20d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162";

    function setUp() public {
        vm.etch(Validator.ADDR, Validator.CODE);
        vm.warp(1_800_000_000);
        registry = L2Registry(Clones.clone(address(new L2Registry())));
        registry.initialize("woco.eth", "WoCo Names", "", admin);
        vm.prank(admin);
        registry.addRegistrar(registrar);
    }

    /// NB: the base-node read is hoisted above the prank — a view call inside
    /// the pranked call's arguments would consume the prank.
    function _mint(string memory label, address to) internal returns (bytes32 node) {
        bytes32 base = registry.baseNode();
        bytes[] memory none = new bytes[](0);
        vm.prank(registrar);
        node = registry.createSubnode(base, label, to, none);
    }

    function _repeat(bytes1 c, uint256 n) internal pure returns (string memory) {
        bytes memory b = new bytes(n);
        for (uint256 i; i < n; ++i) b[i] = c;
        return string(b);
    }

    /*//////////////////////////////////////////////////////////////
        948 [1] = 949 [1] (Medium, both reports, independently) — an
        ERC-721 approvee or operator moves the record version, and so
        wipes the records and voids a pending release signature, by
        transferring the name to its own holder.
    //////////////////////////////////////////////////////////////*/

    function test_M1_anOperatorWipesTheRecordsWithASelfTransfer() public {
        bytes32 node = _mint("venue", holder);
        vm.startPrank(holder);
        registry.setContenthash(node, SITE);
        registry.setAddr(node, holder);
        registry.setApprovalForAll(operator, true);
        vm.stopPrank();
        uint64 versionBefore = registry.recordVersions(node);

        vm.prank(operator);
        registry.transferFrom(holder, holder, uint256(node));

        assertEq(registry.owner(node), holder, "the name did not move");
        assertEq(registry.recordVersions(node), versionBefore + 1, "CLAIM FAILS: the version did not move");
        assertEq(registry.contenthash(node).length, 0, "CLAIM FAILS: the site pointer survived");
        assertEq(registry.addr(node), address(0), "CLAIM FAILS: addr survived");
    }

    /// The same through a per-token approval, and repeatable: the approval is
    /// not consumed by the move.
    function test_M1_aPerTokenApproveeCanDoItRepeatedly() public {
        bytes32 node = _mint("venue", holder);
        for (uint256 i; i < 3; ++i) {
            vm.startPrank(holder);
            registry.setContenthash(node, SITE);
            registry.approve(approvee, uint256(node));
            vm.stopPrank();

            vm.prank(approvee);
            registry.transferFrom(holder, holder, uint256(node));
            assertEq(registry.contenthash(node).length, 0, "CLAIM FAILS: the site pointer survived");
        }
        assertEq(registry.recordVersions(node), 4, "one bump per self-transfer");
    }

    /// And it voids a release the holder has already signed and handed to a
    /// relayer — the version is the digest's nonce.
    function test_M1_itVoidsAPendingReleaseSignature() public {
        bytes32 node = _mint("venue", holder);
        vm.prank(holder);
        registry.setApprovalForAll(operator, true);
        uint256 expiration = block.timestamp + 10 minutes;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(HOLDER_KEY, registry.releaseDigest(node, expiration));
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(operator);
        registry.transferFrom(holder, holder, uint256(node));

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        registry.releaseWithSignature(node, expiration, holder, sig);
        assertEq(registry.owner(node), holder, "CLAIM FAILS: the signature still released the name");
    }

    /// The base name is out of reach: `_update` refuses every move of it.
    function test_M1_theBaseNameIsNotReachableThisWay() public {
        bytes32 base = registry.baseNode();
        vm.startPrank(admin);
        registry.setContenthash(base, SITE);
        registry.setApprovalForAll(operator, true);
        vm.stopPrank();

        vm.expectRevert(L2Registry.AdminHandoverRequired.selector);
        vm.prank(operator);
        registry.transferFrom(admin, admin, uint256(base));
        assertEq(registry.contenthash(base), SITE, "the base name's records survive");
    }

    /// What the same-owner move does NOT do, so a fix is scoped: supply and
    /// holder are untouched, and `adminTransfer` / `parentTransfer` already
    /// refuse it by name.
    function test_M1_whatTheSelfTransferLeavesAlone() public {
        bytes32 node = _mint("venue", holder);
        uint256 supplyBefore = registry.totalSupply();

        vm.prank(holder);
        registry.transferFrom(holder, holder, uint256(node));

        assertEq(registry.totalSupply(), supplyBefore, "supply moved");
        assertEq(registry.owner(node), holder);
        assertEq(registry.balanceOf(holder), 1);

        vm.expectRevert(L2Registry.AdminTransferSameOwner.selector);
        vm.prank(admin);
        registry.adminTransfer(node, holder);

        bytes[] memory none = new bytes[](0);
        vm.prank(holder);
        bytes32 child = registry.createSubnode(node, "shop", holder, none);
        vm.expectRevert(L2Registry.ParentTransferSameOwner.selector);
        vm.prank(holder);
        registry.parentTransfer(child, holder);
    }

    /*//////////////////////////////////////////////////////////////
        948 [2] / 949 [6] (Low / Info) — `dnsDecode`'s write past the
        string's length, at the wire cap with a boundary-length label.
    //////////////////////////////////////////////////////////////*/

    /// A name at the 255-byte wire cap whose leftmost label is exactly 32 bytes
    /// — the shape the report names — decodes, hashes and releases correctly.
    /// Wire: 33 + 64 + 64 + 64 + 20 + 10 = 255.
    function test_L2_theWireCapWithABoundaryLabelStillDecodesAndHashes() public {
        string memory l32 = _repeat("a", 32);
        string memory l63 = _repeat("b", 63);
        string memory l19 = _repeat("c", 19);
        bytes[] memory none = new bytes[](0);

        bytes32 n = _mint(l19, holder);
        vm.startPrank(holder);
        n = registry.createSubnode(n, l63, holder, none);
        n = registry.createSubnode(n, l63, holder, none);
        n = registry.createSubnode(n, l63, holder, none);
        n = registry.createSubnode(n, l32, holder, none);
        vm.stopPrank();

        assertEq(registry.names(n).length, 255, "premise: at the wire cap");
        string memory full = string.concat(l32, ".", l63, ".", l63, ".", l63, ".", l19, ".woco.eth");
        assertEq(bytes(full).length, 253);
        assertEq(registry.decodeName(registry.names(n)), full, "decode");

        uint256 exp = block.timestamp + 600;
        assertEq(registry.releaseDigest(n, exp), _digest(full, n, registry.recordVersions(n), exp), "digest");

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(HOLDER_KEY, registry.releaseDigest(n, exp));
        vm.prank(relayer);
        registry.releaseWithSignature(n, exp, holder, abi.encodePacked(r, s, v));
        assertEq(registry.owner(n), address(0), "a name at the cap could not be released");
    }

    function _digest(string memory fullName, bytes32 node, uint64 version, uint256 exp)
        internal
        view
        returns (bytes32)
    {
        bytes32 domain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("WoCo Names"),
                keccak256("2"),
                block.chainid,
                address(registry)
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Release(string name,bytes32 node,uint64 recordVersion,uint256 expiration)"),
                keccak256(bytes(fullName)),
                node,
                version,
                exp
            )
        );
        return keccak256(abi.encodePacked(hex"1901", domain, structHash));
    }

    /*//////////////////////////////////////////////////////////////
        948 [3] = 949 [2] (Low) — a validator with no code on the
        chain fails CLOSED: the smart-account rail stops working, no
        name becomes unreleasable.
    //////////////////////////////////////////////////////////////*/

    function test_L3_aValidatorWithNoCodeFailsClosedAndLeavesReleaseIntact() public {
        Wallet1271 wallet = new Wallet1271();
        bytes32 node = _mint("venue", address(wallet));
        uint256 expiration = block.timestamp + 10 minutes;
        wallet.approveHash(registry.releaseDigest(node, expiration));
        vm.etch(Validator.ADDR, "");

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        registry.releaseWithSignature(node, expiration, address(wallet), hex"1271");
        assertEq(registry.owner(node), address(wallet), "CLAIM FAILS: it did not fail closed");

        // The holder's own call still works, so nothing is stranded.
        vm.prank(address(wallet));
        registry.release(node);
        assertEq(registry.owner(node), address(0));
    }
}

/// @dev The smallest ERC-1271 wallet: approves exact digests.
contract Wallet1271 is IERC1271 {
    mapping(bytes32 => bool) public approved;

    function approveHash(bytes32 hash) external {
        approved[hash] = true;
    }

    function isValidSignature(bytes32 hash, bytes memory) external view returns (bytes4) {
        return approved[hash] ? IERC1271.isValidSignature.selector : bytes4(0);
    }
}
