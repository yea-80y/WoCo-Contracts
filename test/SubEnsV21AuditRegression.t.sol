// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {L2Registry} from "../src/durin/L2Registry.sol";
import {L2Resolver} from "../src/durin/L2Resolver.sol";
import {WoCoRegistrar} from "../src/WoCoRegistrar.sol";
import {UniversalSigValidatorFixture as Validator} from "./fixtures/UniversalSigValidatorFixture.sol";

/**
 * Regression tests for the $1 audit reports on sub-ENS v2: LeftClaw engagements
 * 937 (the whole system, findings F1-F39) and 938 (registry + resolver in depth,
 * H/M/L). Reports: `~/projects/woco-571-handover/AUDIT_93{7,8}_*.md`.
 *
 * This file began as the triage (`AuditTriage937938.t.sol`, commit d72b934):
 * sixteen tests, each reproducing one claim against v2 and asserting the defect.
 * Each is kept here in the same order and turned round — the SAME sequence,
 * asserting what v2.1 promises instead (WoCo-Contracts #21 / #22, Fable consult
 * of 2026-09-17). Two stand as they were, by design, and say so.
 *
 * After them, the cases the consult named and the new guards that have no
 * finding of their own.
 *
 * NOTE on `vm.prank`: it applies to the NEXT external call, so a view read of
 * the registry passed as an argument would consume it. Every read used to build
 * a pranked call is hoisted above the prank.
 */
contract SubEnsV21AuditRegressionTest is Test {
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

    uint256 constant T0 = 1_800_000_000;

    function setUp() public {
        vm.etch(Validator.ADDR, Validator.CODE);
        vm.warp(T0);
        registry = L2Registry(Clones.clone(address(new L2Registry())));
        registry.initialize("woco.eth", "WoCo Names", "", admin);
        registrar = new WoCoRegistrar(address(registry), sponsor, _productionReservedLabels());
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

    function _child(bytes32 parent, string memory label, address to) internal returns (bytes32 node) {
        address parentHolder = registry.owner(parent);
        bytes[] memory none = new bytes[](0);
        vm.prank(parentHolder);
        node = registry.createSubnode(parent, label, to, none);
    }

    function _bytes(address a) internal pure returns (bytes memory) {
        return abi.encodePacked(a);
    }

    /// The v2.1 release digest, built from its fields rather than read from
    /// the registry, so a signature can be made for a version that does not
    /// exist yet.
    function _releaseDigest(string memory fullName, bytes32 node, uint64 version, uint256 expiration)
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
                expiration
            )
        );
        return keccak256(abi.encodePacked(hex"1901", domain, structHash));
    }

    function _sign(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _register30(address to, string memory prefix) internal {
        string[] memory keys = new string[](0);
        for (uint256 i; i < 30; ++i) {
            vm.prank(sponsor);
            registrar.register(string.concat(prefix, vm.toString(i)), to, SITE, keys, keys);
        }
    }

    /*//////////////////////////////////////////////////////////////
        938 [H-1] = 937 [F4] — an ERC-721 approval was also a
        record-write approval. v2.1: records are the holder's; an
        approval moves the token and nothing else.
    //////////////////////////////////////////////////////////////*/

    function test_H1_F4_anOperatorForAllCannotRepointPayments() public {
        bytes32 node = _mint("alice", holder);
        vm.prank(holder);
        registry.setAddr(node, 60, _bytes(holder));
        uint64 versionBefore = registry.recordVersions(node);

        // The approval every marketplace listing flow asks for.
        vm.prank(holder);
        registry.setApprovalForAll(operator, true);

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        vm.prank(operator);
        registry.setAddr(node, 60, _bytes(stranger));

        assertEq(registry.addr(node, 60), _bytes(holder), "the operator repointed addr(60)");
        assertEq(registry.owner(node), holder);
        assertEq(registry.recordVersions(node), versionBefore);

        // What the approval IS for still works — and the sale resets the records.
        vm.prank(operator);
        registry.transferFrom(holder, buyer, uint256(node));
        assertEq(registry.owner(node), buyer);
        assertEq(registry.addr(node, 60).length, 0, "the buyer received the seller's addr");
    }

    function test_H1_F4_aPerTokenApproveeCannotRepointPaymentsEither() public {
        bytes32 node = _mint("alice", holder);
        vm.prank(holder);
        registry.approve(approvee, uint256(node));

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        vm.prank(approvee);
        registry.setAddr(node, 60, _bytes(stranger));

        assertEq(registry.addr(node, 60).length, 0);
        assertEq(registry.owner(node), holder);

        vm.prank(approvee);
        registry.transferFrom(holder, buyer, uint256(node));
        assertEq(registry.owner(node), buyer, "the approvee could not move the token");
    }

    /*//////////////////////////////////////////////////////////////
        938 [M-7] — the same approvals reached `release`, which is
        irreversible, while `createSubnode` refused them. v2.1: both
        refuse them.
    //////////////////////////////////////////////////////////////*/

    function test_M7_anOperatorForAllCannotBurnTheName() public {
        bytes32 node = _mint("alice", holder);
        vm.prank(holder);
        registry.setApprovalForAll(operator, true);

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        vm.prank(operator);
        registry.release(node);

        assertEq(registry.owner(node), holder, "the operator burned the name");
        (address previous,) = registry.lastRelease(node);
        assertEq(previous, address(0));
    }

    /// Unchanged, by design: creation was always the holder's alone.
    function test_M7_andTheSameOperatorStillCannotCreateASubname() public {
        bytes32 node = _mint("alice", holder);
        vm.prank(holder);
        registry.setApprovalForAll(operator, true);

        bytes[] memory none = new bytes[](0);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        vm.prank(operator);
        registry.createSubnode(node, "shop", operator, none);
    }

    /*//////////////////////////////////////////////////////////////
        938 [H-2] = 937 [F8] — names beneath a name outlived its
        release or seizure. v2.1 ("the fusion", owner 2026-09-17): a
        name with children cannot be released, and the holder of a
        name may move or release the names directly beneath it.
    //////////////////////////////////////////////////////////////*/

    function test_H2_F8_aNameWithChildrenCannotBeReleasedSoNoneSurvivesAReIssue() public {
        bytes32 parent = _mint("acme", stranger);
        bytes[] memory none = new bytes[](0);
        vm.startPrank(stranger);
        bytes32 child = registry.createSubnode(parent, "pay", stranger, none);
        registry.setAddr(child, 60, _bytes(stranger));

        vm.expectRevert(abi.encodeWithSelector(L2Registry.HasChildren.selector, parent, 1));
        registry.release(parent);

        // The only way to free the label is to clear what hangs beneath it.
        registry.release(child);
        registry.release(parent);
        vm.stopPrank();

        bytes32 reissued = _mint("acme", buyer);
        assertEq(reissued, parent, "same node");
        assertEq(registry.owner(parent), buyer);

        assertEq(registry.owner(child), address(0), "a child survived the re-issue");
        assertEq(registry.addr(child, 60).length, 0, "the child's records survived");
        assertEq(registry.childCount(parent), 0);

        // The new holder starts the subtree afresh.
        vm.prank(buyer);
        bytes32 fresh = registry.createSubnode(parent, "pay", buyer, none);
        assertEq(fresh, child);
        assertEq(registry.addr(child, 60).length, 0, "the fresh child inherited records");
    }

    /// Seizure is never blocked and never cascades; the new parent holder takes
    /// the child back one step later.
    function test_H2_F8_afterAdminTransferTheNewParentHolderTakesTheChildBack() public {
        bytes32 parent = _mint("acme", stranger);
        bytes[] memory none = new bytes[](0);
        vm.startPrank(stranger);
        bytes32 child = registry.createSubnode(parent, "pay", stranger, none);
        registry.setAddr(child, 60, _bytes(stranger));
        vm.stopPrank();

        // The documented takedown, with a child hanging beneath the name.
        vm.prank(admin);
        registry.adminTransfer(parent, buyer);

        assertEq(registry.owner(parent), buyer);
        assertEq(registry.owner(child), stranger, "adminTransfer cascaded");

        // The previous parent holder has no standing left.
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, child));
        vm.prank(stranger);
        registry.parentTransfer(child, stranger);

        vm.prank(buyer);
        registry.parentTransfer(child, buyer);
        assertEq(registry.owner(child), buyer);
        assertEq(registry.addr(child, 60).length, 0, "the child's records survived the move");
    }

    /*//////////////////////////////////////////////////////////////
        937 [F1] = 938 [M-8] — `createSubnode`'s trailing batch could
        burn the name it had just announced. v2.1: the batch must leave
        the name where the mint put it.
    //////////////////////////////////////////////////////////////*/

    function test_F1_M8_theMintsOwnBatchCannotBurnTheNameItCreated() public {
        bytes32 base = registry.baseNode();
        bytes32 ghost = registry.makeNode(base, "ghost");
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encodeWithSelector(L2Registry.release.selector, ghost);

        uint256 supplyBefore = registry.totalSupply();
        vm.expectRevert(abi.encodeWithSelector(L2Registry.SubnodeMovedDuringCreation.selector, ghost));
        vm.prank(bareRegistrar);
        registry.createSubnode(base, "ghost", bareRegistrar, data);

        assertEq(registry.owner(ghost), address(0));
        assertEq(registry.totalSupply(), supplyBefore);
        assertEq(registry.childCount(base), 0);
    }

    /*//////////////////////////////////////////////////////////////
        937 [F2] — release signatures could be signed ahead for record
        versions that did not exist yet, and never expire. v2.1: no
        signature lives longer than MAX_RELEASE_SIGNATURE_TTL.
    //////////////////////////////////////////////////////////////*/

    function test_F2_aSignatureForTheNextVersionCannotOutliveTheCeiling() public {
        (address sigHolder, uint256 sigPk) = makeAddrAndKey("sigHolder");
        bytes32 node = _mint("alice", sigHolder);
        assertEq(registry.recordVersions(node), 1, "a fresh mint is version 1");

        // Signed for version 2, which does not exist yet, and never expires.
        uint256 forever = type(uint256).max;
        bytes memory foreverSig = _sign(sigPk, _releaseDigest("alice.woco.eth", node, 2, forever));

        vm.prank(sigHolder);
        registry.clearRecords(node);
        assertEq(registry.recordVersions(node), 2);

        vm.expectRevert(L2Registry.ExpirationTooFar.selector);
        vm.prank(stranger);
        registry.releaseWithSignature(node, forever, sigHolder, foreverSig);

        // A rung within the ceiling is still a rung — but it dies with its own
        // short life, which the holder chose when signing.
        uint256 soon = block.timestamp + registry.MAX_RELEASE_SIGNATURE_TTL();
        bytes memory soonSig = _sign(sigPk, _releaseDigest("alice.woco.eth", node, 3, soon));
        vm.prank(sigHolder);
        registry.clearRecords(node);
        vm.warp(soon + 1);
        vm.expectRevert(L2Registry.SignatureExpired.selector);
        vm.prank(stranger);
        registry.releaseWithSignature(node, soon, sigHolder, soonSig);

        assertEq(registry.owner(node), sigHolder, "a pre-signed release went through");
    }

    /*//////////////////////////////////////////////////////////////
        937 [F7] / 938 [M-9] — registrar record authority reached the
        base name, and the admin's delegates could wipe it. v2.1: the
        base name's records are its holder's alone.
    //////////////////////////////////////////////////////////////*/

    function test_F7_noRegistrarWritesTheBaseNamesRecords() public {
        bytes32 base = registry.baseNode();
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, base));
        vm.prank(bareRegistrar);
        registry.setText(base, "url", "https://evil.example");
        assertEq(bytes(registry.text(base, "url")).length, 0);

        // Not even the admin's own registrar enrolment: the admin writes the
        // base name as its holder, and that path is unaffected.
        vm.startPrank(admin);
        registry.addRegistrar(admin);
        registry.setText(base, "url", "https://woco.example");
        vm.stopPrank();
        assertEq(registry.text(base, "url"), "https://woco.example");
    }

    function test_M9_anAdminsOperatorCannotWipeTheBaseNamesRecords() public {
        bytes32 base = registry.baseNode();
        vm.prank(admin);
        registry.setText(base, "url", "https://woco.example");

        vm.prank(admin);
        registry.setApprovalForAll(operator, true);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, base));
        vm.prank(operator);
        registry.clearRecords(base);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, base));
        vm.prank(operator);
        registry.setText(base, "url", "https://evil.example");

        assertEq(registry.text(base, "url"), "https://woco.example", "the admin's operator touched the base name");
        // ... and still cannot MOVE the base name (924 F-2).
        vm.expectRevert(L2Registry.AdminHandoverRequired.selector);
        vm.prank(operator);
        registry.transferFrom(admin, stranger, uint256(base));
    }

    /*//////////////////////////////////////////////////////////////
        937 [F9] = 938 [M-3] — the base label skipped every rule
        `_addLabel` enforces on child labels. v2.1: `initialize` holds
        each label of the base name to them.
    //////////////////////////////////////////////////////////////*/

    function test_F9_M3_theBaseLabelIsHeldToTheLabelRules() public {
        L2Registry rogue = L2Registry(Clones.clone(address(new L2Registry())));
        // The triage's name. Split on its dots, the label holding the quotes
        // is everything before the last one.
        string memory rogueName = 'woco", "image": "https://evil/x.png';

        vm.expectRevert(
            abi.encodeWithSelector(L2Registry.LabelInvalidCharacter.selector, 'woco", "image": "https://evil/x')
        );
        rogue.initialize(rogueName, "WoCo Names", "", admin);

        // Nothing stuck: the refused call left the clone uninitialised.
        rogue.initialize("woco.eth", "WoCo Names", "", admin);
        assertEq(rogue.baseNode(), vm.ensNamehash("woco.eth"));
    }

    function test_P6_everyWayABaseNameCanBeMalformedIsRefused() public {
        string[6] memory empties = ["", ".", ".eth", "woco.", "woco..eth", "woco.eth."];
        for (uint256 i; i < empties.length; ++i) {
            L2Registry r = L2Registry(Clones.clone(address(new L2Registry())));
            vm.expectRevert(L2Registry.LabelTooShort.selector);
            r.initialize(empties[i], "WoCo Names", "", admin);
        }

        string memory sixtyFour = _repeat("a", 64);
        L2Registry longLabel = L2Registry(Clones.clone(address(new L2Registry())));
        vm.expectRevert(abi.encodeWithSelector(L2Registry.LabelTooLong.selector, sixtyFour));
        longLabel.initialize(string.concat(sixtyFour, ".eth"), "WoCo Names", "", admin);

        // Four 63-byte labels are 256 bytes on the wire with the root.
        string memory l63 = _repeat("b", 63);
        string memory tooLong = string.concat(l63, ".", l63, ".", l63, ".", l63);
        L2Registry longName = L2Registry(Clones.clone(address(new L2Registry())));
        vm.expectRevert(abi.encodeWithSelector(L2Registry.NameTooLong.selector, l63));
        longName.initialize(tooLong, "WoCo Names", "", admin);

        L2Registry control = L2Registry(Clones.clone(address(new L2Registry())));
        vm.expectRevert(abi.encodeWithSelector(L2Registry.LabelInvalidCharacter.selector, "wo\\co"));
        control.initialize("wo\\co.eth", "WoCo Names", "", admin);
    }

    /// The split names the same node, and writes the same wire bytes, as the
    /// ENS algorithm — for one label, two, and three.
    function test_P6_theSplitMatchesENS() public {
        string[3] memory names_ = ["eth", "woco.eth", "events.woco.eth"];
        bytes[3] memory wires = [
            bytes(hex"0365746800"),
            bytes(hex"04776f636f0365746800"),
            bytes(hex"066576656e747304776f636f0365746800")
        ];
        for (uint256 i; i < names_.length; ++i) {
            L2Registry r = L2Registry(Clones.clone(address(new L2Registry())));
            r.initialize(names_[i], "WoCo Names", "", admin);
            assertEq(r.baseNode(), vm.ensNamehash(names_[i]), names_[i]);
            assertEq(r.names(r.baseNode()), wires[i], names_[i]);
            assertEq(r.decodeName(r.names(r.baseNode())), names_[i]);
        }
    }

    /// Audit 937 F10 / 938 L-1: the unvalidated `namehash(string)` helper is
    /// gone. Nothing called it; clients derive nodes off chain.
    function test_P6_theNamehashHelperIsGone() public {
        (bool ok, bytes memory ret) = address(registry).call(abi.encodeWithSignature("namehash(string)", "woco.eth"));
        assertFalse(ok, "namehash(string) still answers");
        assertEq(ret.length, 0);
    }

    /*//////////////////////////////////////////////////////////////
        Registrar findings — the replaceable layer (937 F5, F6, F11,
        F12, F21).
    //////////////////////////////////////////////////////////////*/

    function test_F11_aReservedLabelInAnotherCaseIsRefused() public {
        string[] memory reserved = new string[](1);
        reserved[0] = "WoCo"; // a natural way to write a brand list
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.InvalidLabel.selector, "WoCo"));
        new WoCoRegistrar(address(registry), sponsor, reserved);

        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.InvalidLabel.selector, "WoCo"));
        vm.prank(admin);
        registrar.setReserved("WoCo", true);

        assertFalse(registrar.available("woco"), "the production list reserves the lowercase label");
    }

    function test_F5_aSponsorCannotRepointAPlatformNameTheRegistrarWouldNeverMint() public {
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
        registrar.register("app", stranger, SITE, keys, keys);

        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.LabelIsReserved.selector, "app"));
        vm.prank(sponsor);
        registrar.setContenthash("app", EVIL);
        assertEq(registry.contenthash(node), SITE, "the sponsor repointed a reserved name");
    }

    function test_F6_tighteningTheCapDoesNotRefundAnOpenWindow() public {
        _register30(holder, "name-");
        (uint32 remaining, uint64 resetsAt) = registrar.mintAllowance(holder);
        assertEq(remaining, 0, "the recipient is at the cap");
        assertEq(resetsAt, uint64(T0 + 30 days));

        vm.warp(block.timestamp + 2 days); // still inside the 30-day window
        vm.prank(admin);
        registrar.setMintRateCap(5, 1 days); // a TIGHTER cap and a SHORTER window

        (remaining, resetsAt) = registrar.mintAllowance(holder);
        assertEq(remaining, 0, "tightening refunded the allowance");
        assertEq(resetsAt, uint64(T0 + 30 days), "the open window's end moved");

        string[] memory keys = new string[](0);
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.MintRateCapExceeded.selector, holder, uint64(T0 + 30 days)));
        vm.prank(sponsor);
        registrar.register("thirty-first", holder, SITE, keys, keys);

        // The window ends when it was opened to end; the next one is 1 day long.
        vm.warp(T0 + 30 days);
        vm.prank(sponsor);
        registrar.register("thirty-first", holder, SITE, keys, keys);
        (uint64 end,) = registrar.mintWindow(holder);
        assertEq(end, uint64(T0 + 31 days));
    }

    function test_F12_theOwnerCanGiveASpentAllowanceBack() public {
        _register30(holder, "junk-");

        string[] memory keys = new string[](0);
        (, uint64 resetsAt) = registrar.mintAllowance(holder);
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.MintRateCapExceeded.selector, holder, resetsAt));
        vm.prank(sponsor);
        registrar.register("the-one-they-wanted", holder, SITE, keys, keys);

        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotRegistryAdmin.selector, sponsor));
        vm.prank(sponsor);
        registrar.resetMintWindow(holder);

        vm.prank(admin);
        registrar.resetMintWindow(holder);
        (uint32 remaining,) = registrar.mintAllowance(holder);
        assertEq(remaining, 30);

        vm.prank(sponsor);
        registrar.register("the-one-they-wanted", holder, SITE, keys, keys);
        assertEq(registry.owner(registry.makeNode(registry.baseNode(), "the-one-they-wanted")), holder);
    }

    function test_F21_releasingLetsTheHolderTakeTheirOwnLabelBack() public {
        _register30(holder, "name-");
        bytes32 base = registry.baseNode();
        bytes32 node = registry.makeNode(base, "name-0");
        vm.prank(holder);
        registry.release(node);

        string[] memory keys = new string[](0);
        vm.prank(sponsor);
        registrar.register("name-0", holder, SITE, keys, keys); // the previous holder can...
        assertEq(registry.owner(node), holder, "the holder could not take its own label back");
        (, uint32 count) = registrar.mintWindow(holder);
        assertEq(count, 30, "taking one's own label back cost a mint");

        // ... while a new label still costs, and so does someone else's.
        (, uint64 resetsAt) = registrar.mintAllowance(holder);
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.MintRateCapExceeded.selector, holder, resetsAt));
        vm.prank(sponsor);
        registrar.register("brand-new", holder, SITE, keys, keys);

        bytes32 buyersOld = registry.makeNode(base, "buyers-old");
        vm.prank(sponsor);
        registrar.register("buyers-old", buyer, SITE, keys, keys);
        vm.prank(buyer);
        registry.release(buyersOld);
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.MintRateCapExceeded.selector, holder, resetsAt));
        vm.prank(sponsor);
        registrar.register("buyers-old", holder, SITE, keys, keys);
    }

    /*//////////////////////////////////////////////////////////////
        THE FUSION — parent control, one level at a time
    //////////////////////////////////////////////////////////////*/

    function test_Fusion_ThePartsAreRecordedFromCreation() public {
        bytes32 base = registry.baseNode();
        bytes32 venue = _mint("venue", holder);
        bytes32 shop = _child(venue, "shop", stranger);
        bytes32 till = _child(shop, "till", buyer);

        assertEq(registry.parentOf(base), bytes32(0));
        assertEq(registry.parentOf(venue), base);
        assertEq(registry.parentOf(shop), venue);
        assertEq(registry.parentOf(till), shop);
        assertEq(registry.childCount(base), 1);
        assertEq(registry.childCount(venue), 1);
        assertEq(registry.childCount(shop), 1);
        assertEq(registry.childCount(till), 0);
    }

    function test_Fusion_AParentHolderMovesOrReleasesItsChild() public {
        bytes32 venue = _mint("venue", holder);
        bytes32 shop = _child(venue, "shop", stranger);
        bytes32 bar = _child(venue, "bar", stranger);
        vm.prank(stranger);
        registry.setContenthash(shop, EVIL);

        vm.prank(holder);
        registry.parentTransfer(shop, buyer);
        assertEq(registry.owner(shop), buyer);
        assertEq(registry.contenthash(shop).length, 0, "the move kept the records");
        assertEq(registry.childCount(venue), 2, "a move is not a release");

        // The parent holder releases, and the event names it as the operator
        // while the record keeps the child's holder.
        vm.expectEmit(true, true, true, true, address(registry));
        emit L2Registry.Released(bar, stranger, holder);
        vm.prank(holder);
        registry.release(bar);
        (address previous,) = registry.lastRelease(bar);
        assertEq(previous, stranger);
        assertEq(registry.childCount(venue), 1);
    }

    /// Parent control is movement, not record authority.
    function test_Fusion_AParentHolderCannotWriteOrClearItsChildsRecords() public {
        bytes32 venue = _mint("venue", holder);
        bytes32 shop = _child(venue, "shop", stranger);
        vm.prank(stranger);
        registry.setContenthash(shop, SITE);

        vm.startPrank(holder);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, shop));
        registry.setContenthash(shop, EVIL);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, shop));
        registry.clearRecords(shop);
        vm.stopPrank();
        assertEq(registry.contenthash(shop), SITE);
    }

    function test_Fusion_OneLevelAtATime() public {
        bytes32 venue = _mint("venue", holder);
        bytes32 shop = _child(venue, "shop", stranger);
        bytes32 till = _child(shop, "till", buyer);

        vm.startPrank(holder);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, till));
        registry.parentTransfer(till, holder);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, till));
        registry.release(till);

        // Take the child first; then the grandchild is the holder's child's.
        registry.parentTransfer(shop, holder);
        registry.parentTransfer(till, holder);
        vm.stopPrank();
        assertEq(registry.owner(till), holder);
    }

    /// Beneath the base name the admin's door is `adminTransfer`, never these.
    function test_Fusion_TheAdminHasNoParentDoorBeneathTheBaseName() public {
        bytes32 venue = _mint("venue", holder);

        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, venue));
        registry.parentTransfer(venue, admin);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, venue));
        registry.release(venue);
        registry.adminTransfer(venue, buyer);
        vm.stopPrank();
        assertEq(registry.owner(venue), buyer);
    }

    function test_Fusion_NobodyElseHasAParentDoor() public {
        bytes32 venue = _mint("venue", holder);
        bytes32 shop = _child(venue, "shop", stranger);
        vm.prank(holder);
        registry.setApprovalForAll(operator, true);

        address[4] memory callers = [operator, bareRegistrar, admin, buyer];
        for (uint256 i; i < callers.length; ++i) {
            vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, shop));
            vm.prank(callers[i]);
            registry.parentTransfer(shop, callers[i]);
            vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, shop));
            vm.prank(callers[i]);
            registry.release(shop);
        }
        // The zero address, which a base-name child's parent door resolves to.
        bytes32 base = registry.baseNode();
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, venue));
        vm.prank(address(0));
        registry.parentTransfer(venue, stranger);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, venue));
        vm.prank(address(0));
        registry.release(venue);
        assertEq(registry.owner(venue), holder);
        assertEq(registry.owner(base), admin);
    }

    function test_Fusion_ParentTransferRefusals() public {
        bytes32 venue = _mint("venue", holder);
        bytes32 shop = _child(venue, "shop", stranger);
        bytes32 missing = registry.makeNode(venue, "missing");
        bytes32 base = registry.baseNode();

        vm.startPrank(holder);
        vm.expectRevert(L2Registry.ParentTransferToZero.selector);
        registry.parentTransfer(shop, address(0));
        vm.expectRevert(abi.encodeWithSelector(L2Registry.ParentTransferUnregistered.selector, missing));
        registry.parentTransfer(missing, buyer);
        vm.expectRevert(L2Registry.ParentTransferSameOwner.selector);
        registry.parentTransfer(shop, stranger);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, base));
        registry.parentTransfer(base, holder);
        vm.stopPrank();

        assertEq(registry.owner(shop), stranger);
        assertEq(registry.recordVersions(shop), 1, "a refused move reset the records");
    }

    function test_Fusion_ParentTransferEmitsItsOwnEvent() public {
        bytes32 venue = _mint("venue", holder);
        bytes32 shop = _child(venue, "shop", stranger);

        vm.expectEmit(true, true, true, true, address(registry));
        emit L2Registry.ParentTransfer(shop, stranger, buyer);
        vm.prank(holder);
        registry.parentTransfer(shop, buyer);
    }

    /// Seizure is never blocked: a name with a whole subtree still moves.
    function test_Fusion_AdminTransferIsNeverBlockedByChildren() public {
        bytes32 venue = _mint("venue", holder);
        bytes32 shop = _child(venue, "shop", stranger);
        _child(shop, "till", buyer);

        vm.prank(admin);
        registry.adminTransfer(venue, treasury);
        vm.prank(admin);
        registry.adminTransfer(shop, treasury);
        assertEq(registry.owner(venue), treasury);
        assertEq(registry.owner(shop), treasury);
    }

    /// The counted child blocks the signed path too: `_release` is the funnel.
    function test_Fusion_HasChildrenBlocksTheSignedReleaseToo() public {
        (address sigHolder, uint256 sigPk) = makeAddrAndKey("sigHolder");
        bytes32 venue = _mint("venue", sigHolder);
        _child(venue, "shop", stranger);
        uint256 expiration = block.timestamp + 10 minutes;
        bytes memory sig = _sign(sigPk, registry.releaseDigest(venue, expiration));

        vm.expectRevert(abi.encodeWithSelector(L2Registry.HasChildren.selector, venue, 1));
        vm.prank(stranger);
        registry.releaseWithSignature(venue, expiration, sigHolder, sig);
    }

    /// A child released and minted again is counted once.
    function test_Fusion_AReMintedChildIsCountedOnce() public {
        bytes32 venue = _mint("venue", holder);
        bytes32 shop = _child(venue, "shop", stranger);
        vm.prank(stranger);
        registry.release(shop);
        assertEq(registry.childCount(venue), 0);

        _child(venue, "shop", buyer);
        assertEq(registry.childCount(venue), 1);
        assertEq(registry.parentOf(shop), venue);

        vm.prank(holder);
        registry.release(shop);
        vm.prank(holder);
        registry.release(venue);
        assertEq(registry.childCount(registry.baseNode()), 0);
    }

    /// The moved child is still counted beneath its parent, so the parent is
    /// still blocked — moving is not a way round `HasChildren`.
    function test_Fusion_MovingAChildAwayDoesNotUnblockTheParent() public {
        bytes32 venue = _mint("venue", holder);
        bytes32 shop = _child(venue, "shop", holder);

        vm.startPrank(holder);
        registry.parentTransfer(shop, buyer);
        vm.expectRevert(abi.encodeWithSelector(L2Registry.HasChildren.selector, venue, 1));
        registry.release(venue);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
        THE CREATION BATCH — post-condition, not an allowlist
    //////////////////////////////////////////////////////////////*/

    /// Record writes are what the batch is for.
    function test_Batch_RecordWritesStillWork() public {
        bytes32 base = registry.baseNode();
        bytes32 node = registry.makeNode(base, "venue");
        bytes[] memory data = new bytes[](2);
        data[0] = abi.encodeWithSignature("setContenthash(bytes32,bytes)", node, SITE);
        data[1] = abi.encodeWithSignature("setText(bytes32,string,string)", node, "url", "https://venue.example");

        vm.prank(bareRegistrar);
        registry.createSubnode(base, "venue", holder, data);
        assertEq(registry.contenthash(node), SITE);
        assertEq(registry.text(node, "url"), "https://venue.example");
        assertEq(registry.recordVersions(node), 1);
    }

    /// A self-mint may nest a mint of its own beneath the new name: it is a
    /// call the caller could make next, and it carries its own checks.
    function test_Batch_ANestedCreateSubnodeIsAllowed() public {
        bytes32 venue = _mint("venue", holder);
        bytes32 shop = registry.makeNode(venue, "shop");
        bytes32 till = registry.makeNode(shop, "till");
        bytes[] memory none = new bytes[](0);
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encodeCall(L2Registry.createSubnode, (shop, "till", buyer, none));

        vm.prank(holder);
        registry.createSubnode(venue, "shop", holder, data);
        assertEq(registry.owner(shop), holder);
        assertEq(registry.owner(till), buyer);
        assertEq(registry.childCount(shop), 1);
        assertEq(registry.childCount(venue), 1);
    }

    function test_Batch_AnyMoveOfTheNewNameIsRefused() public {
        bytes32 base = registry.baseNode();
        bytes32 node = registry.makeNode(base, "venue");
        bytes[] memory data = new bytes[](1);

        // adminTransfer, by the admin enrolled as a registrar.
        vm.prank(admin);
        registry.addRegistrar(admin);
        data[0] = abi.encodeCall(L2Registry.adminTransfer, (node, stranger));
        vm.expectRevert(abi.encodeWithSelector(L2Registry.SubnodeMovedDuringCreation.selector, node));
        vm.prank(admin);
        registry.createSubnode(base, "venue", holder, data);

        // clearRecords, by a registrar minting to itself.
        data[0] = abi.encodeCall(L2Registry.clearRecords, (node));
        vm.expectRevert(abi.encodeWithSelector(L2Registry.SubnodeMovedDuringCreation.selector, node));
        vm.prank(bareRegistrar);
        registry.createSubnode(base, "venue", bareRegistrar, data);

        // parentTransfer and release, by the holder of the parent.
        bytes32 parent = _mint("parent", holder);
        bytes32 child = registry.makeNode(parent, "child");
        data[0] = abi.encodeCall(L2Registry.parentTransfer, (child, stranger));
        vm.expectRevert(abi.encodeWithSelector(L2Registry.SubnodeMovedDuringCreation.selector, child));
        vm.prank(holder);
        registry.createSubnode(parent, "child", buyer, data);

        data[0] = abi.encodeCall(L2Registry.release, (child));
        vm.expectRevert(abi.encodeWithSelector(L2Registry.SubnodeMovedDuringCreation.selector, child));
        vm.prank(holder);
        registry.createSubnode(parent, "child", buyer, data);

        assertEq(registry.owner(node), address(0));
        assertEq(registry.owner(child), address(0));
        assertEq(registry.childCount(parent), 0);
    }

    /// A transfer cannot even be batched: its first word is an address, which
    /// the node pin refuses before anything runs.
    function test_Batch_ATransferFailsTheNodePin() public {
        bytes32 base = registry.baseNode();
        bytes32 node = registry.makeNode(base, "venue");
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encodeWithSignature("transferFrom(address,address,uint256)", bareRegistrar, stranger, uint256(node));

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.BatchNodeMismatch.selector, node));
        vm.prank(bareRegistrar);
        registry.createSubnode(base, "venue", bareRegistrar, data);
    }

    /// The events are emitted before the batch, so a log reader sees the mint
    /// before the records written in it.
    function test_Batch_TheMintIsLoggedBeforeTheRecords() public {
        bytes32 base = registry.baseNode();
        bytes32 node = registry.makeNode(base, "venue");
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encodeWithSignature("setContenthash(bytes32,bytes)", node, SITE);

        vm.recordLogs();
        vm.prank(bareRegistrar);
        registry.createSubnode(base, "venue", holder, data);
        bytes32 created = keccak256("SubnodeCreated(bytes32,bytes,address)");
        bytes32 changed = keccak256("ContenthashChanged(bytes32,bytes)");
        int256 createdAt = -1;
        int256 changedAt = -1;
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == created) createdAt = int256(i);
            if (logs[i].topics[0] == changed) changedAt = int256(i);
        }
        assertGt(createdAt, -1);
        assertGt(changedAt, createdAt, "a record was logged before the mint");
    }

    /*//////////////////////////////////////////////////////////////
        THE REGISTRY HOLDS NOTHING (937 F19, 938 L-3)
    //////////////////////////////////////////////////////////////*/

    function test_Self_NoNameIsEverSentToTheRegistry() public {
        address self = address(registry);
        bytes32 base = registry.baseNode();
        bytes[] memory none = new bytes[](0);

        vm.expectRevert(L2Registry.RecipientIsRegistry.selector);
        vm.prank(bareRegistrar);
        registry.createSubnode(base, "venue", self, none);

        bytes32 venue = _mint("venue", holder);
        bytes32 shop = _child(venue, "shop", stranger);

        vm.expectRevert(L2Registry.RecipientIsRegistry.selector);
        vm.prank(admin);
        registry.adminTransfer(venue, self);

        vm.expectRevert(L2Registry.RecipientIsRegistry.selector);
        vm.prank(holder);
        registry.transferFrom(holder, self, uint256(venue));

        vm.expectRevert(L2Registry.RecipientIsRegistry.selector);
        vm.prank(holder);
        registry.safeTransferFrom(holder, self, uint256(venue));

        vm.expectRevert(L2Registry.RecipientIsRegistry.selector);
        vm.prank(holder);
        registry.parentTransfer(shop, self);

        L2Registry fresh = L2Registry(Clones.clone(address(new L2Registry())));
        vm.expectRevert(L2Registry.RecipientIsRegistry.selector);
        fresh.initialize("woco.eth", "WoCo Names", "", address(fresh));

        assertEq(registry.balanceOf(self), 0);
    }

    /// The admin seat cannot reach the registry either: a nominee must call
    /// `acceptAdmin` itself, and the registry never calls out as itself. The
    /// only self-call left is `createSubnode`'s batch, which keeps the caller
    /// and refuses an item that does not name the new node — `acceptAdmin()`
    /// names nothing, so it is refused before it runs.
    function test_Self_TheSeatCannotBeAcceptedByTheRegistry() public {
        vm.prank(admin);
        registry.nominateAdmin(address(registry));

        vm.expectRevert(abi.encodeWithSelector(L2Registry.NotPendingAdmin.selector, stranger));
        vm.prank(stranger);
        registry.acceptAdmin();

        bytes32 base = registry.baseNode();
        bytes32 node = registry.makeNode(base, "venue");
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encodeCall(L2Registry.acceptAdmin, ());
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.BatchNodeMismatch.selector, node));
        vm.prank(bareRegistrar);
        registry.createSubnode(base, "venue", bareRegistrar, data);

        assertEq(registry.owner(), admin);
    }

    /*//////////////////////////////////////////////////////////////
        THE SIGNATURE CEILING (937 F2, F3, F25 / 938 L-10)
    //////////////////////////////////////////////////////////////*/

    function test_Ceiling_TheLastAcceptedSecondAndTheFirstRefused() public {
        (address sigHolder, uint256 sigPk) = makeAddrAndKey("sigHolder");
        bytes32 a = _mint("alpha", sigHolder);
        bytes32 b = _mint("bravo", sigHolder);
        uint256 edge = block.timestamp + 48 hours;
        assertEq(registry.MAX_RELEASE_SIGNATURE_TTL(), 48 hours);

        bytes memory tooFar = _sign(sigPk, registry.releaseDigest(a, edge + 1));
        vm.expectRevert(L2Registry.ExpirationTooFar.selector);
        vm.prank(stranger);
        registry.releaseWithSignature(a, edge + 1, sigHolder, tooFar);

        bytes memory atEdge = _sign(sigPk, registry.releaseDigest(b, edge));
        vm.prank(stranger);
        registry.releaseWithSignature(b, edge, sigHolder, atEdge);
        assertEq(registry.owner(b), address(0));
    }

    /*//////////////////////////////////////////////////////////////
        THE VALIDATOR, BOUNDED (938 M-5, L-7 / 937 F18, F19)
    //////////////////////////////////////////////////////////////*/

    function _walletName(address wallet, string memory label) internal returns (bytes32 node, uint256 exp) {
        node = _mint(label, wallet);
        exp = block.timestamp + 10 minutes;
    }

    /// Any failure inside the validator is our refusal, never its revert.
    function test_Validator_ARevertIsARefusal() public {
        Approves1271 wallet = new Approves1271();
        (bytes32 node, uint256 exp) = _walletName(address(wallet), "venue");
        wallet.approve(registry.releaseDigest(node, exp));
        vm.mockCallRevert(Validator.ADDR, bytes(""), abi.encodeWithSignature("Error(string)", "validator blew up"));

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        vm.prank(stranger);
        registry.releaseWithSignature(node, exp, address(wallet), hex"1271");
        assertEq(registry.owner(node), address(wallet));
    }

    /// A revert is a refusal even when its data happens to be the 32 bytes of
    /// `true`: the call's own success flag decides first.
    function test_Validator_ARevertCarryingTrueIsStillARefusal() public {
        Approves1271 wallet = new Approves1271();
        (bytes32 node, uint256 exp) = _walletName(address(wallet), "venue");
        vm.mockCallRevert(Validator.ADDR, bytes(""), abi.encode(uint256(1)));

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        vm.prank(stranger);
        registry.releaseWithSignature(node, exp, address(wallet), hex"1271");
        assertEq(registry.owner(node), address(wallet));
    }

    /// The LOWER bound of `VALIDATOR_GAS` (Fable sign-off F3): a wallet that
    /// spends ~700k before answering — the size of an undeployed passkey
    /// account's deployment plus a P-256 verification — must still be believed.
    /// Without this, trimming the constant would pass every other test and
    /// refuse every real passkey release.
    function test_Validator_AHeavyButHonestWalletIsBelieved() public {
        Spends1271 wallet = new Spends1271();
        (bytes32 node, uint256 exp) = _walletName(address(wallet), "heavy");
        wallet.approve(registry.releaseDigest(node, exp));
        vm.etch(Validator.ADDR, address(new Asks1271()).code);

        vm.prank(stranger);
        registry.releaseWithSignature(node, exp, address(wallet), hex"1271");
        assertEq(registry.owner(node), address(0), "a wallet within the gas bound was refused");
    }

    /// Only a clean `true` is yes: a malformed or oversized answer is no.
    function test_Validator_AnythingButACleanTrueIsARefusal() public {
        Approves1271 wallet = new Approves1271();
        (bytes32 node, uint256 exp) = _walletName(address(wallet), "venue");
        wallet.approve(registry.releaseDigest(node, exp));

        bytes[4] memory answers = [
            abi.encode(uint256(2)),
            bytes(""),
            abi.encodePacked(uint8(1)),
            abi.encode(uint256(1), uint256(1))
        ];
        for (uint256 i; i < answers.length; ++i) {
            vm.mockCall(Validator.ADDR, bytes(""), answers[i]);
            vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
            vm.prank(stranger);
            registry.releaseWithSignature(node, exp, address(wallet), hex"1271");
        }

        vm.mockCall(Validator.ADDR, bytes(""), abi.encode(uint256(1)));
        vm.prank(stranger);
        registry.releaseWithSignature(node, exp, address(wallet), hex"1271");
        assertEq(registry.owner(node), address(0), "a clean true was refused");
    }

    /// A wallet that burns every unit of gas it is given costs the submitter
    /// at most the bound, and the refusal is still ours.
    function test_Validator_GasIsBounded() public {
        BurnsGas1271 wallet = new BurnsGas1271();
        (bytes32 node, uint256 exp) = _walletName(address(wallet), "venue");

        bytes memory call_ = abi.encodeCall(L2Registry.releaseWithSignature, (node, exp, address(wallet), hex"1271"));
        uint256 before = gasleft();
        vm.prank(stranger);
        (bool ok, bytes memory ret) = address(registry).call{gas: 20_000_000}(call_);
        uint256 used = before - gasleft();

        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        assertLt(used, 1_300_000, "the validator was given more than the bound");
        assertEq(registry.owner(node), address(wallet));
    }

    bytes32 constant ERC6492_SUFFIX = 0x6492649264926492649264926492649264926492649264926492649264926492;

    function _wrap6492(address factory, bytes memory factoryCalldata) internal pure returns (bytes memory) {
        return abi.encodePacked(abi.encode(factory, factoryCalldata, hex"1271"), ERC6492_SUFFIX);
    }

    /// Audit 938 L-7. The validator at the pinned address cannot change state
    /// before it answers — its ERC-1271 call is static and its counterfactual
    /// path unwinds — but that is a property of someone else's bytecode. Here a
    /// validator that DOES act first stands in for it: it has the holder move
    /// the name, or clear it, then says yes. The signature was for the name as
    /// it was; the release is refused.
    function test_Validator_TheVersionIsReadAgainAfterIt() public {
        vm.etch(Validator.ADDR, address(new ActsThenApproves()).code);
        for (uint8 mode; mode < 2; ++mode) {
            PreparesOnCall1271 wallet = new PreparesOnCall1271(registry, mode, buyer);
            (bytes32 node, uint256 exp) = _walletName(address(wallet), mode == 0 ? "cleared" : "handed");
            wallet.arm(node, registry.releaseDigest(node, exp));

            vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
            vm.prank(stranger);
            registry.releaseWithSignature(node, exp, address(wallet), hex"1271");
        }
    }

    /// The control for the test above: the same validator, moving nothing, is
    /// believed — so the refusal above is about the move.
    function test_Validator_AValidatorThatActsButMovesNothingIsBelieved() public {
        vm.etch(Validator.ADDR, address(new ActsThenApproves()).code);
        PreparesOnCall1271 wallet = new PreparesOnCall1271(registry, 2, buyer);
        (bytes32 node, uint256 exp) = _walletName(address(wallet), "still");
        wallet.arm(node, registry.releaseDigest(node, exp));

        vm.prank(stranger);
        registry.releaseWithSignature(node, exp, address(wallet), hex"1271");
        assertEq(registry.owner(node), address(0));
    }

    /// The pinned validator's own behaviour, which L-7 rests on: for a deployed
    /// wallet it names no factory and retries nothing — a "prepare" step in the
    /// signature is never run, and the wallet's first answer stands.
    function test_Validator_ThePinnedValidatorRunsNoPrepareStepForADeployedWallet() public {
        PreparesOnCall1271 wallet = new PreparesOnCall1271(registry, 0, buyer);
        (bytes32 node, uint256 exp) = _walletName(address(wallet), "venue");
        wallet.arm(node, registry.releaseDigest(node, exp));
        bytes memory sig = _wrap6492(address(wallet), abi.encodeCall(PreparesOnCall1271.prepare, ()));

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        vm.prank(stranger);
        registry.releaseWithSignature(node, exp, address(wallet), sig);
        assertEq(registry.recordVersions(node), 1, "the prepare step ran");
    }

    /// A counterfactual holder: the validator deploys it, asks, and undoes the
    /// deployment. The release goes through and the wallet is still undeployed.
    function test_Validator_ACounterfactualHolderReleases() public {
        Deployer6492 factory = new Deployer6492();
        bytes memory initCode = type(Approves1271).creationCode;
        address wallet = factory.addressOf(bytes32(0), initCode);
        (bytes32 node, uint256 exp) = _walletName(wallet, "future");
        bytes32 digest = registry.releaseDigest(node, exp);
        assertEq(wallet.code.length, 0, "premise: the holder is counterfactual");

        bytes memory sig =
            _wrap6492(address(factory), abi.encodeCall(Deployer6492.deployAndApprove, (bytes32(0), initCode, digest)));
        vm.prank(stranger);
        registry.releaseWithSignature(node, exp, wallet, sig);
        assertEq(registry.owner(node), address(0));
        assertEq(wallet.code.length, 0, "the validator's deployment was kept");
    }

    /*//////////////////////////////////////////////////////////////
        EIP-712 (937 F3 / 938 M-2)
    //////////////////////////////////////////////////////////////*/

    /// The digest, rebuilt by Foundry's own EIP-712 encoder from the typed data
    /// a wallet would be shown.
    function test_712_TheDigestIsTheTypedDataAWalletIsShown() public {
        bytes32 node = _mint("alice", holder);
        uint256 exp = block.timestamp + 10 minutes;
        string memory json = string.concat(
            '{"types":{"EIP712Domain":[{"name":"name","type":"string"},{"name":"version","type":"string"},',
            '{"name":"chainId","type":"uint256"},{"name":"verifyingContract","type":"address"}],',
            '"Release":[{"name":"name","type":"string"},{"name":"node","type":"bytes32"},',
            '{"name":"recordVersion","type":"uint64"},{"name":"expiration","type":"uint256"}]},',
            '"primaryType":"Release","domain":{"name":"WoCo Names","version":"2","chainId":',
            vm.toString(block.chainid),
            ',"verifyingContract":"',
            vm.toString(address(registry)),
            '"},"message":{"name":"alice.woco.eth","node":"',
            vm.toString(node),
            '","recordVersion":1,"expiration":',
            vm.toString(exp),
            "}}"
        );
        assertEq(registry.releaseDigest(node, exp), vm.eip712HashTypedData(json));
    }

    /// The vector the app pins (`apps/web/test/sub-ens-release-typed-data.test.ts`
    /// in WoCo-Event-App): a registry clone at 0x1234…7890 on Arbitrum One,
    /// "alice" at record version 1, expiring at 1,800,000,600.
    function test_712_ThePinnedVector() public {
        address at = 0x1234567890123456789012345678901234567890;
        address impl = address(new L2Registry());
        vm.etch(at, abi.encodePacked(hex"363d3d373d3d3d363d73", impl, hex"5af43d82803e903d91602b57fd5bf3"));
        vm.chainId(42161);
        L2Registry pinned = L2Registry(at);
        pinned.initialize("woco.eth", "WoCo Names", "", admin);
        vm.prank(admin);
        pinned.addRegistrar(bareRegistrar);
        bytes[] memory none = new bytes[](0);
        bytes32 base = pinned.baseNode();
        vm.prank(bareRegistrar);
        bytes32 node = pinned.createSubnode(base, "alice", holder, none);

        assertEq(node, vm.ensNamehash("alice.woco.eth"));
        assertEq(pinned.recordVersions(node), 1);
        assertEq(
            pinned.releaseDigest(node, 1_800_000_600),
            0xcea241832188eef27baf500e3b8092fef292cac6e8f0cc049747e5c1ba5ba82a
        );
    }

    /// `releaseDigest` decodes the stored name with `ENSDNSUtils.dnsDecode`,
    /// which writes past its allocation. Names whose decoded length sits on the
    /// allocation's 32-byte boundaries (31, 32, 33, 63, 64, 65 bytes) hash as an
    /// independent encoder says (Fable sign-off, Q3).
    function test_712_TheDigestAtAllocationBoundaries() public {
        uint256[6] memory lens = [uint256(22), 23, 24, 54, 55, 56];
        for (uint256 i; i < lens.length; ++i) {
            string memory label = _repeat(bytes1(uint8(0x61 + i)), lens[i]);
            bytes32 node = _mint(label, holder);
            string memory full = string.concat(label, ".woco.eth");
            assertEq(bytes(full).length, lens[i] + 9);
            uint256 exp = block.timestamp + 600 + i;
            assertEq(registry.releaseDigest(node, exp), _releaseDigest(full, node, 1, exp), full);
            assertEq(registry.decodeName(registry.names(node)), full);
        }
    }

    /// ... and at the 255-byte wire cap, end to end through a real release.
    function test_712_TheDigestAtTheNameCap() public {
        (address sigHolder, uint256 sigPk) = makeAddrAndKey("capHolder");
        string memory l63 = _repeat("x", 63);
        string memory l52 = _repeat("y", 52);
        bytes32 n = _mint(l63, holder);
        n = _child(n, l63, holder);
        n = _child(n, l63, holder);
        n = _child(n, l52, sigHolder);
        assertEq(registry.names(n).length, 255, "premise: at the cap");

        string memory full = string.concat(l52, ".", l63, ".", l63, ".", l63, ".woco.eth");
        assertEq(registry.decodeName(registry.names(n)), full);
        uint256 exp = block.timestamp + 600;
        assertEq(registry.releaseDigest(n, exp), _releaseDigest(full, n, 1, exp));

        bytes memory sig = _sign(sigPk, registry.releaseDigest(n, exp));
        vm.prank(stranger);
        registry.releaseWithSignature(n, exp, sigHolder, sig);
        assertEq(registry.owner(n), address(0));
    }

    /// ERC-5267, read from the CLONE: the name and version come from the
    /// implementation's immutables, the address and chain from the clone.
    function test_712_TheCloneReportsItsOwnDomain() public view {
        (
            bytes1 fields,
            string memory name_,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
            uint256[] memory extensions
        ) = registry.eip712Domain();
        assertEq(fields, hex"0f");
        assertEq(name_, "WoCo Names");
        assertEq(version, "2");
        assertEq(chainId, block.chainid);
        assertEq(verifyingContract, address(registry));
        assertEq(salt, bytes32(0));
        assertEq(extensions.length, 0);
    }

    /// Two clones, one implementation: the same name and version cannot be
    /// replayed across them.
    function test_712_EachCloneHasItsOwnDomain() public {
        L2Registry other = L2Registry(Clones.clone(address(new L2Registry())));
        other.initialize("woco.eth", "WoCo Names", "", admin);
        vm.prank(admin);
        other.addRegistrar(bareRegistrar);
        bytes[] memory none = new bytes[](0);
        bytes32 base = other.baseNode();
        vm.prank(bareRegistrar);
        other.createSubnode(base, "alice", holder, none);
        bytes32 node = _mint("alice", holder);
        uint256 exp = block.timestamp + 10 minutes;

        assertTrue(other.releaseDigest(node, exp) != registry.releaseDigest(node, exp));
    }

    function test_712_ThereIsNoDigestForANameNeverMinted() public {
        bytes32 node = registry.makeNode(registry.baseNode(), "nobody");
        vm.expectRevert();
        registry.releaseDigest(node, block.timestamp);
    }

    /*//////////////////////////////////////////////////////////////
        ABI TERMINATES (937 F20 / 938 M-6)
    //////////////////////////////////////////////////////////////*/

    function test_ABI_TheTopBitTerminates() public {
        bytes32 node = _mint("alice", holder);
        uint256 top = 1 << 255;

        (uint256 ct, bytes memory data) = registry.ABI{gas: 1_000_000}(node, top);
        assertEq(ct, 0);
        assertEq(data.length, 0);
        (ct, data) = registry.ABI{gas: 1_000_000}(node, type(uint256).max);
        assertEq(ct, 0);

        vm.prank(holder);
        registry.setABI(node, top, hex"ab");
        (ct, data) = registry.ABI(node, top);
        assertEq(ct, top);
        assertEq(data, hex"ab");
        (ct, data) = registry.ABI(node, type(uint256).max);
        assertEq(ct, top, "the top content type is unreachable");

        vm.prank(holder);
        registry.setABI(node, 4, hex"cd");
        (ct, data) = registry.ABI(node, type(uint256).max);
        assertEq(ct, 4, "the lowest matching content type comes first");
        (ct,) = registry.ABI(node, 3);
        assertEq(ct, 0);
    }

    function testFuzz_ABI_AlwaysTerminates(uint256 contentTypes) public {
        bytes32 node = _mint("alice", holder);
        (uint256 ct,) = registry.ABI{gas: 1_000_000}(node, contentTypes);
        assertEq(ct, 0);
    }

    /*//////////////////////////////////////////////////////////////
        SUPPLY IS KEPT BY THE FUNNEL (938 L-5)
    //////////////////////////////////////////////////////////////*/

    function test_Supply_CountsEveryMintAndBurnAndNothingElse() public {
        assertEq(registry.totalSupply(), 1, "the base name");
        bytes32 venue = _mint("venue", holder);
        bytes32 shop = _child(venue, "shop", stranger);
        assertEq(registry.totalSupply(), 3);

        vm.prank(holder);
        registry.parentTransfer(shop, buyer);
        vm.prank(admin);
        registry.adminTransfer(venue, treasury);
        vm.prank(treasury);
        registry.transferFrom(treasury, holder, uint256(venue));
        address dao = makeAddr("dao");
        vm.prank(admin);
        registry.nominateAdmin(dao);
        vm.prank(dao);
        registry.acceptAdmin();
        assertEq(registry.totalSupply(), 3, "a move changed the supply");

        vm.prank(holder);
        registry.release(shop);
        vm.prank(holder);
        registry.release(venue);
        assertEq(registry.totalSupply(), 1);
    }

    function _repeat(bytes1 c, uint256 n) internal pure returns (string memory) {
        bytes memory b = new bytes(n);
        for (uint256 i; i < n; ++i) b[i] = c;
        return string(b);
    }
}

/// @dev An ERC-1271 wallet that approves exactly the digests it is told to.
contract Approves1271 is IERC1271 {
    mapping(bytes32 => bool) public approved;

    function approve(bytes32 hash) external {
        approved[hash] = true;
    }

    function isValidSignature(bytes32 hash, bytes memory) external view returns (bytes4) {
        return approved[hash] ? IERC1271.isValidSignature.selector : bytes4(0);
    }
}

/// @dev An ERC-1271 wallet that spends ~700k gas before approving `approved`.
contract Spends1271 {
    bytes32 public approved;

    function approve(bytes32 h) external {
        approved = h;
    }

    function isValidSignature(bytes32 h, bytes memory) external view returns (bytes4) {
        uint256 start = gasleft();
        uint256 x;
        while (start - gasleft() < 700_000) {
            x = uint256(keccak256(abi.encode(x)));
        }
        return h == approved ? IERC1271.isValidSignature.selector : bytes4(0);
    }
}

/// @dev A validator that simply asks the signer through ERC-1271, with all the
///      gas it was given. Etched over the pinned validator.
contract Asks1271 {
    function isValidSig(address signer, bytes32 hash, bytes calldata) external view returns (bool) {
        (bool ok, bytes memory ret) =
            signer.staticcall(abi.encodeCall(IERC1271.isValidSignature, (hash, bytes(""))));
        return ok && ret.length >= 32 && bytes4(ret) == IERC1271.isValidSignature.selector;
    }
}

/// @dev An ERC-1271 wallet whose answer never comes: it spends all it is given.
contract BurnsGas1271 is IERC1271 {
    function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) {
        uint256 x;
        while (true) {
            x = uint256(keccak256(abi.encode(x)));
        }
        return bytes4(0);
    }
}

/// @dev A deployed ERC-1271 wallet that approves nothing until its public
///      `prepare` runs. `prepare` then approves the armed digest and, by mode,
///      clears the name's records (0), hands the name to `other` (1), or moves
///      nothing (2).
contract PreparesOnCall1271 is IERC1271 {
    L2Registry internal immutable registry;
    uint8 internal immutable mode;
    address internal immutable other;
    bytes32 internal node;
    bytes32 internal armed;
    bytes32 internal approved;

    constructor(L2Registry registry_, uint8 mode_, address other_) {
        registry = registry_;
        mode = mode_;
        other = other_;
    }

    function arm(bytes32 node_, bytes32 digest) external {
        node = node_;
        armed = digest;
    }

    function prepare() external {
        if (mode == 0) registry.clearRecords(node);
        else if (mode == 1) registry.transferFrom(address(this), other, uint256(node));
        approved = armed;
    }

    function isValidSignature(bytes32 hash, bytes memory) external view returns (bytes4) {
        return approved != bytes32(0) && hash == approved ? IERC1271.isValidSignature.selector : bytes4(0);
    }
}

/// @dev A validator that has the signer run its `prepare` step before it
///      answers, then asks the signer. Etched over the pinned validator.
contract ActsThenApproves {
    function isValidSig(address signer, bytes32 hash, bytes calldata) external returns (bool) {
        PreparesOnCall1271(signer).prepare();
        return IERC1271(signer).isValidSignature(hash, "") == IERC1271.isValidSignature.selector;
    }
}

/// @dev The ERC-6492 factory: CREATE2 with a salt, and a variant that also
///      tells an `Approves1271` which digest to approve.
contract Deployer6492 {
    function addressOf(bytes32 salt, bytes memory initCode) external view returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(hex"ff", address(this), salt, keccak256(initCode))))));
    }

    function deploy(bytes32 salt, bytes memory initCode) public returns (address a) {
        assembly {
            a := create2(0, add(initCode, 0x20), mload(initCode), salt)
        }
        require(a != address(0), "deploy failed");
    }

    function deployAndApprove(bytes32 salt, bytes memory initCode, bytes32 digest) external returns (address a) {
        a = deploy(salt, initCode);
        Approves1271(a).approve(digest);
    }
}
