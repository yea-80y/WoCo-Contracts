// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {L2Registry} from "../src/durin/L2Registry.sol";
import {L2Resolver} from "../src/durin/L2Resolver.sol";
import {WoCoRegistrar} from "../src/WoCoRegistrar.sol";

/**
 * TRIAGE of the $1 audit reports on sub-ENS v2: LeftClaw engagements 937 (the
 * whole system, findings F1-F39) and 938 (registry + resolver in depth,
 * H/M/L). Reports: `~/projects/woco-571-handover/AUDIT_93{7,8}_*.md`.
 *
 * Every test here reproduces ONE claim against the code as merged (master
 * `e469ed7`, the commit both audits read), and asserts what the contract does
 * TODAY. So a green run means the claim is real as stated; a test that starts
 * failing is a fix landing, and at that point the test becomes the regression
 * test for that fix — with its assertions inverted.
 *
 * Nothing here is a fix. Which of these to fix is the owner's and Fable's call:
 * the registry cannot be patched once deployed, and it is deployed nowhere but
 * the Arbitrum Sepolia rehearsal.
 *
 * NOTE on `vm.prank`: it applies to the NEXT external call, so a view read of
 * the registry passed as an argument would consume it. Every read used to build
 * a pranked call is hoisted above the prank.
 */
contract AuditTriage937938Test is Test {
    L2Registry registry;
    WoCoRegistrar registrar; // the real policy layer, for the registrar findings

    address admin = makeAddr("admin");
    address bareRegistrar = makeAddr("bareRegistrar"); // an enrolled address, no policy in front
    address sponsor = makeAddr("sponsor");
    address holder = makeAddr("holder");
    address approvee = makeAddr("approvee");
    address operator = makeAddr("operator");
    address stranger = makeAddr("stranger");
    address buyer = makeAddr("buyer");
    address treasury = makeAddr("treasury");

    bytes constant SITE = hex"e40101fa011b20d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162";
    bytes constant EVIL = hex"e40101fa011b201111111111111111111111111111111111111111111111111111111111111111";

    function setUp() public {
        registry = L2Registry(Clones.clone(address(new L2Registry())));
        registry.initialize("woco.eth", "WoCo Names", "", admin);
        registrar = new WoCoRegistrar(address(registry), admin, sponsor, _productionReservedLabels());
        vm.startPrank(admin);
        registry.addRegistrar(bareRegistrar);
        registry.addRegistrar(address(registrar));
        vm.stopPrank();
    }

    /// The list both deploy scripts use.
    function _productionReservedLabels() internal pure returns (string[] memory labels) {
        labels = new string[](8);
        labels[0] = "woco";
        labels[1] = "admin";
        labels[2] = "support";
        labels[3] = "help";
        labels[4] = "www";
        labels[5] = "api";
        labels[6] = "app";
        labels[7] = "mail";
    }

    function _mint(string memory label, address to) internal returns (bytes32 node) {
        bytes32 base = registry.baseNode();
        bytes[] memory none = new bytes[](0);
        vm.prank(bareRegistrar);
        node = registry.createSubnode(base, label, to, none);
    }

    function _bytes(address a) internal pure returns (bytes memory) {
        return abi.encodePacked(a);
    }

    /*//////////////////////////////////////////////////////////////
        938 [H-1] = 937 [F4] — an ERC-721 approval is also a
        record-write approval, so a marketplace listing approval can
        repoint where the name's payments go, with no Transfer event
        and no change of holder.
    //////////////////////////////////////////////////////////////*/

    function test_H1_F4_operatorForAll_redirectsPaymentsWithoutMovingTheName() public {
        bytes32 node = _mint("alice", holder);
        vm.prank(holder);
        registry.setAddr(node, 60, _bytes(holder));
        uint64 versionBefore = registry.recordVersions(node);

        // The approval every marketplace listing flow asks for.
        vm.prank(holder);
        registry.setApprovalForAll(operator, true);

        vm.prank(operator);
        registry.setAddr(node, 60, _bytes(stranger));

        assertEq(registry.addr(node, 60), _bytes(stranger), "CLAIM FAILS: the operator could not repoint addr(60)");
        assertEq(registry.owner(node), holder, "the name itself moved");
        assertEq(registry.recordVersions(node), versionBefore, "a record write is not an ownership change");
    }

    function test_H1_F4_perTokenApprovee_redirectsPaymentsToo() public {
        bytes32 node = _mint("alice", holder);
        vm.prank(holder);
        registry.approve(approvee, uint256(node));

        vm.prank(approvee);
        registry.setAddr(node, 60, _bytes(stranger));

        assertEq(registry.addr(node, 60), _bytes(stranger));
        assertEq(registry.owner(node), holder);
    }

    /*//////////////////////////////////////////////////////////////
        938 [M-7] — the same approvals also reach `release`, which is
        irreversible, while `createSubnode` refuses them.
    //////////////////////////////////////////////////////////////*/

    function test_M7_operatorForAll_canBurnTheName() public {
        bytes32 node = _mint("alice", holder);
        vm.prank(holder);
        registry.setApprovalForAll(operator, true);

        vm.prank(operator);
        registry.release(node);

        assertEq(registry.owner(node), address(0), "CLAIM FAILS: the operator could not burn the name");
        (address previous,) = registry.lastRelease(node);
        assertEq(previous, holder, "the release is recorded against the holder, not the operator");
    }

    function test_M7_butTheSameOperatorCannotCreateASubname() public {
        bytes32 node = _mint("alice", holder);
        vm.prank(holder);
        registry.setApprovalForAll(operator, true);

        bytes[] memory none = new bytes[](0);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        vm.prank(operator);
        registry.createSubnode(node, "shop", operator, none);
    }

    /*//////////////////////////////////////////////////////////////
        938 [H-2] = 937 [F8] — names created beneath a name outlive
        that name's release or seizure, so a takedown does not take
        down the subtree.
    //////////////////////////////////////////////////////////////*/

    function test_H2_F8_childSurvivesTheParentsReleaseAndReIssue() public {
        bytes32 parent = _mint("acme", stranger);
        bytes[] memory none = new bytes[](0);
        vm.startPrank(stranger);
        bytes32 child = registry.createSubnode(parent, "pay", stranger, none);
        registry.setAddr(child, 60, _bytes(stranger));
        registry.release(parent);
        vm.stopPrank();

        // The freed label is re-issued to someone else, as the plan intends.
        bytes32 reissued = _mint("acme", buyer);
        assertEq(reissued, parent, "same node");
        assertEq(registry.owner(parent), buyer);

        // ... but the subtree beneath it never moved.
        assertEq(registry.owner(child), stranger, "CLAIM FAILS: the child did not survive");
        assertEq(registry.addr(child, 60), _bytes(stranger), "the child's records survived too");

        // And the new parent holder has no standing over it.
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, child));
        vm.prank(buyer);
        registry.clearRecords(child);

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, child));
        vm.prank(buyer);
        registry.release(child);
    }

    function test_H2_F8_childSurvivesAdminTransferOfTheParent() public {
        bytes32 parent = _mint("acme", stranger);
        bytes[] memory none = new bytes[](0);
        vm.prank(stranger);
        bytes32 child = registry.createSubnode(parent, "pay", stranger, none);

        // The documented takedown: the name reaches its rightful holder.
        vm.prank(admin);
        registry.adminTransfer(parent, buyer);

        assertEq(registry.owner(parent), buyer);
        assertEq(registry.owner(child), stranger, "CLAIM FAILS: adminTransfer reached the child");
        // The admin can chase the child, but only one node per transaction and
        // only once it has found it off-chain (there is no on-chain child index).
        vm.prank(admin);
        registry.adminTransfer(child, buyer);
        assertEq(registry.owner(child), buyer);
    }

    /*//////////////////////////////////////////////////////////////
        937 [F1] = 938 [M-8] — `createSubnode`'s trailing batch is
        pinned to the new node but not to record setters, so a mint
        can burn the name it just announced.
    //////////////////////////////////////////////////////////////*/

    function test_F1_M8_theMintsOwnBatchCanBurnTheNameItJustCreated() public {
        bytes32 base = registry.baseNode();
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encodeWithSelector(L2Registry.release.selector, registry.makeNode(base, "ghost"));

        uint256 supplyBefore = registry.totalSupply();
        vm.prank(bareRegistrar);
        bytes32 node = registry.createSubnode(base, "ghost", bareRegistrar, data);

        assertEq(registry.owner(node), address(0), "CLAIM FAILS: the batched release did not run");
        assertEq(registry.totalSupply(), supplyBefore, "supply is back where it started");
        // `createSubnode` still returned the node and emitted NewOwner +
        // SubnodeCreated for a name that no longer exists by the end of the call.
        assertTrue(node != bytes32(0));
    }

    /*//////////////////////////////////////////////////////////////
        937 [F2] — release signatures can be signed ahead for future
        record versions, so the documented revocation (bump the
        version) only activates the next signature in the ladder.
    //////////////////////////////////////////////////////////////*/

    function test_F2_preSignedSignatureForTheNextVersionSurvivesRevocation() public {
        (address sigHolder, uint256 sigPk) = makeAddrAndKey("sigHolder");
        bytes32 node = _mint("alice", sigHolder);
        assertEq(registry.recordVersions(node), 1, "a fresh mint is version 1");

        // Signed for version 2, which does not exist yet, and never expires.
        uint256 expiration = type(uint256).max;
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(
            keccak256(
                abi.encode(
                    registry.RELEASE_TYPEHASH(), address(registry), block.chainid, node, uint64(2), expiration
                )
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sigPk, digest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // The documented revocation: the holder bumps the record version.
        vm.prank(sigHolder);
        registry.clearRecords(node);
        assertEq(registry.recordVersions(node), 2, "clearRecords moved the version");

        // Which is exactly what the pre-signed signature was waiting for.
        vm.prank(stranger);
        registry.releaseWithSignature(node, expiration, sigHolder, signature);
        assertEq(registry.owner(node), address(0), "CLAIM FAILS: the pre-signed release was refused");
    }

    /*//////////////////////////////////////////////////////////////
        937 [F7] / 938 [M-9] — registrar record-write authority is
        registry-wide, and the holder-side branch accepts the admin's
        delegates: both reach the base name's own records.
    //////////////////////////////////////////////////////////////*/

    function test_F7_anyRegistrarCanWriteTheBaseNamesRecords() public {
        bytes32 base = registry.baseNode();
        vm.prank(bareRegistrar);
        registry.setText(base, "url", "https://evil.example");
        assertEq(registry.text(base, "url"), "https://evil.example", "CLAIM FAILS: the base name refused a registrar");
    }

    function test_M9_anAdminsOperatorCanWipeTheBaseNamesRecords() public {
        bytes32 base = registry.baseNode();
        vm.prank(admin);
        registry.setText(base, "url", "https://woco.example");

        vm.prank(admin);
        registry.setApprovalForAll(operator, true);
        vm.prank(operator);
        registry.clearRecords(base);

        assertEq(registry.text(base, "url"), "", "CLAIM FAILS: the admin's operator could not wipe the base name");
        // ... while the same operator still cannot MOVE the base name (924 F-2).
        vm.expectRevert(L2Registry.AdminHandoverRequired.selector);
        vm.prank(operator);
        registry.transferFrom(admin, stranger, uint256(base));
    }

    /*//////////////////////////////////////////////////////////////
        937 [F9] = 938 [M-3] — the base label skips every rule
        `_addLabel` enforces on child labels.
    //////////////////////////////////////////////////////////////*/

    function test_F9_M3_theBaseLabelSkipsLabelValidation() public {
        L2Registry rogue = L2Registry(Clones.clone(address(new L2Registry())));
        // A quote and a slash: each refused in a child label.
        rogue.initialize('woco", "image": "https://evil/x.png', "WoCo Names", "", admin);

        bytes32 rogueBase = rogue.baseNode();
        bytes memory baseName = rogue.names(rogueBase);
        bool hasQuote;
        for (uint256 i; i < baseName.length; ++i) {
            if (baseName[i] == 0x22) hasQuote = true;
        }
        assertTrue(hasQuote, "CLAIM FAILS: initialize refused the quote a child label cannot contain");

        // And every child inherits those bytes in its own wire name.
        vm.prank(admin);
        rogue.addRegistrar(bareRegistrar);
        bytes[] memory none = new bytes[](0);
        vm.prank(bareRegistrar);
        bytes32 child = rogue.createSubnode(rogueBase, "alice", holder, none);
        assertGt(rogue.names(child).length, baseName.length);
    }

    /*//////////////////////////////////////////////////////////////
        Registrar findings — the replaceable layer (937 F5, F6, F11,
        F12, F21).
    //////////////////////////////////////////////////////////////*/

    function test_F11_aReservedLabelInAnotherCaseDoesNotReserveAnything() public {
        string[] memory reserved = new string[](1);
        reserved[0] = "WoCo"; // a natural way to write a brand list
        WoCoRegistrar brandGuard = new WoCoRegistrar(address(registry), admin, sponsor, reserved);
        vm.prank(admin);
        registry.addRegistrar(address(brandGuard));

        assertTrue(brandGuard.available("woco"), "CLAIM FAILS: the lowercase label reads as reserved");
        string[] memory keys = new string[](0);
        bytes32 base = registry.baseNode();
        vm.prank(sponsor);
        brandGuard.register("woco", holder, SITE, keys, keys);
        assertEq(registry.owner(registry.makeNode(base, "woco")), holder);
    }

    function test_F5_aSponsorCanRepointAPlatformNameTheRegistrarWouldNeverMint() public {
        // The platform mints its own reserved label directly, through the admin.
        bytes32 base = registry.baseNode();
        bytes[] memory none = new bytes[](0);
        vm.startPrank(admin);
        registry.addRegistrar(admin);
        bytes32 node = registry.createSubnode(base, "app", treasury, none);
        registry.setContenthash(node, SITE);
        vm.stopPrank();

        string[] memory keys = new string[](0);
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.LabelIsReserved.selector, "app"));
        vm.prank(sponsor);
        registrar.register("app", stranger, SITE, keys, keys); // minting it is refused...

        vm.prank(sponsor);
        registrar.setContenthash("app", EVIL); // ... repointing it is not.
        assertEq(registry.contenthash(node), EVIL, "CLAIM FAILS: setContenthash refused the reserved label");
    }

    function test_F6_tighteningTheWindowRefundsAMaxedOutRecipient() public {
        string[] memory keys = new string[](0);
        for (uint256 i; i < 30; ++i) {
            vm.prank(sponsor);
            registrar.register(string.concat("name-", vm.toString(i)), holder, SITE, keys, keys);
        }
        (uint32 remaining,) = registrar.mintAllowance(holder);
        assertEq(remaining, 0, "the recipient is at the cap");

        vm.warp(block.timestamp + 2 days); // still inside the 30-day window
        vm.prank(admin);
        registrar.setMintRateCap(5, 1 days); // a TIGHTER cap

        (remaining,) = registrar.mintAllowance(holder);
        assertEq(remaining, 5, "CLAIM FAILS: tightening did not refund the allowance");
        vm.prank(sponsor);
        registrar.register("thirty-first", holder, SITE, keys, keys);
    }

    function test_F12_aSponsorCanSpendSomeoneElsesAllowanceWithoutTheirConsent() public {
        string[] memory keys = new string[](0);
        for (uint256 i; i < 30; ++i) {
            vm.prank(sponsor);
            registrar.register(string.concat("junk-", vm.toString(i)), holder, SITE, keys, keys);
        }

        (, uint64 resetsAt) = registrar.mintAllowance(holder);
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.MintRateCapExceeded.selector, holder, resetsAt));
        vm.prank(sponsor);
        registrar.register("the-one-they-wanted", holder, SITE, keys, keys);
    }

    function test_F21_releasingDoesNotGiveTheHolderTheirOwnLabelBack() public {
        string[] memory keys = new string[](0);
        for (uint256 i; i < 30; ++i) {
            vm.prank(sponsor);
            registrar.register(string.concat("name-", vm.toString(i)), holder, SITE, keys, keys);
        }
        bytes32 base = registry.baseNode();
        bytes32 node = registry.makeNode(base, "name-0");
        vm.prank(holder);
        registry.release(node);

        (, uint64 resetsAt) = registrar.mintAllowance(holder);
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.MintRateCapExceeded.selector, holder, resetsAt));
        vm.prank(sponsor);
        registrar.register("name-0", holder, SITE, keys, keys); // the previous holder cannot...

        vm.prank(sponsor);
        registrar.register("name-0", buyer, SITE, keys, keys); // ... but a watcher of Released can.
        assertEq(registry.owner(node), buyer, "CLAIM FAILS: the label was not free to anyone else");
    }
}
