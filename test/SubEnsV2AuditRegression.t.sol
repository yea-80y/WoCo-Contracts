// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IExtendedResolver} from "@ensdomains/ens-contracts/resolvers/profiles/IExtendedResolver.sol";
import {WoCoRegistrar} from "../src/WoCoRegistrar.sol";
import {L2Registry} from "../src/durin/L2Registry.sol";
import {L2Resolver} from "../src/durin/L2Resolver.sol";
import {UniversalSigValidatorFixture as Validator} from "./fixtures/UniversalSigValidatorFixture.sol";

/**
 * Regression tests for the claims in LeftClaw audits 924, 925 and 927 that were
 * reproduced against v1 (WoCo-Contracts `1deb45a`) before the v2 redeploy
 * (#21, #22).
 *
 * Each test is a triage reproduction turned round: the SAME sequence, run
 * against v2, asserting the outcome the fix promises instead of the defect.
 * Where v1's reproduction rested on a fact about the world that is still true —
 * the ERC-6492 validator deployed on Arbitrum accepting an all-zero signature
 * for signer 0 — that premise is pinned too, so a future path back to it is
 * caught by name.
 *
 * Findings fixed outside this file, so they are not repeated here:
 *   924 F-11 (7702 release)  — L2RegistryReleaseWithSignature.t.sol
 *   924 F-10 / 927 M9 (init) — DeploySubEnsRegistry.t.sol
 *   927 M2 (old registrar)   — RedeployRegistrar.t.sol
 *   925 #3 (window bound)    — WoCoRegistrarRateCap.t.sol
 *   925 #5 / 927 M8 (renounce), 925 #1 ABI — WoCoRegistrar.t.sol
 */
contract SubEnsV2AuditRegressionTest is Test {
    L2Registry registry;
    WoCoRegistrar registrar;

    address admin = makeAddr("admin");
    address sponsor = makeAddr("sponsor");
    address stranger = makeAddr("stranger");
    address victim = makeAddr("victim");

    uint256 constant HOLDER_KEY = 0xA11CE;
    address holder = vm.addr(HOLDER_KEY);

    uint256 constant NOW = 1_800_000_000;

    bytes constant SITE = hex"e40101fa011b20d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162";
    bytes constant OTHER = hex"e40101fa011b201111111111111111111111111111111111111111111111111111111111111111";

    /// r = s = 0, v = 27: ecrecover returns the zero address for it.
    bytes JUNK = abi.encodePacked(bytes32(0), bytes32(0), uint8(27));

    function setUp() public {
        vm.etch(Validator.ADDR, Validator.CODE);
        registry = L2Registry(Clones.clone(address(new L2Registry())));
        registry.initialize("woco.eth", "WoCo Names", "", admin);
        registrar = new WoCoRegistrar(address(registry), sponsor, new string[](0));
        vm.prank(admin);
        registry.addRegistrar(address(registrar));
        vm.warp(NOW);
    }

    function _register(string memory label, address owner_, bytes memory ch) internal returns (bytes32 node) {
        string[] memory none = new string[](0);
        vm.prank(sponsor);
        registrar.register(label, owner_, ch, none, none);
        node = registry.makeNode(registry.baseNode(), label);
    }

    /*//////////////////////////////////////////////////////////////
                    924 F-1 (Critical claim, reproduced on v1)
    //////////////////////////////////////////////////////////////*/

    /// The premise, still true of the validator every registry on Arbitrum
    /// uses: it accepts an all-zero signature for the zero address. v2 must
    /// never ask it about a signer that could be zero.
    function test_924F1_premise_theValidatorStillAcceptsSignerZeroWithAZeroSignature() public {
        (bool ok, bytes memory ret) = Validator.ADDR.call(
            abi.encodeWithSignature("isValidSig(address,bytes32,bytes)", address(0), keccak256("anything"), JUNK)
        );
        assertTrue(ok);
        assertTrue(abi.decode(ret, (bool)), "premise changed: the validator no longer accepts signer 0");
    }

    /// v1: a stranger passed `signer = address(0)` and JUNK to the signed
    /// setters and rewrote contenthash, addr and text. The same calls now reach
    /// no function, and nothing changes.
    function test_924F1_theStrangersExactCallsReachNoFunction() public {
        bytes32 node = _register("venue", holder, SITE);
        bytes32 base = registry.baseNode();

        bytes[] memory calls = new bytes[](4);
        calls[0] = abi.encodeWithSignature(
            "setContenthashWithSignature(bytes32,bytes,uint256,address,bytes)", node, OTHER, NOW + 1, address(0), JUNK
        );
        calls[1] = abi.encodeWithSignature(
            "setAddrWithSignature(bytes32,uint256,bytes,uint256,address,bytes)",
            node, uint256(60), abi.encodePacked(stranger), NOW + 1, address(0), JUNK
        );
        calls[2] = abi.encodeWithSignature(
            "setTextWithSignature(bytes32,string,string,uint256,address,bytes)",
            node, "url", "https://elsewhere.example", NOW + 1, address(0), JUNK
        );
        calls[3] = abi.encodeWithSignature(
            "setContenthashWithSignature(bytes32,bytes,uint256,address,bytes)", base, OTHER, NOW + 1, address(0), JUNK
        );

        for (uint256 i; i < calls.length; ++i) {
            vm.prank(stranger);
            (bool ok, bytes memory ret) = address(registry).call(calls[i]);
            assertFalse(ok);
            assertEq(ret.length, 0, "a signed setter still exists");
        }

        assertEq(registry.contenthash(node), SITE);
        assertEq(registry.addr(node), holder);
        assertEq(bytes(registry.text(node, "url")).length, 0);
        assertEq(registry.contenthash(base).length, 0);
    }

    /// And the direct setters refuse a stranger, on a name and on the base name.
    function test_924F1_aStrangerCannotWriteAnyRecordDirectly() public {
        bytes32 node = _register("venue", holder, SITE);
        bytes32 base = registry.baseNode();

        vm.startPrank(stranger);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        registry.setContenthash(node, OTHER);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        registry.setAddr(node, 60, abi.encodePacked(stranger));
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        registry.setText(node, "url", "https://elsewhere.example");
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, base));
        registry.setContenthash(base, OTHER);
        vm.stopPrank();
    }

    /// The one path left that consults the validator puts `_isAuthorized` in
    /// front of it, and that refuses the zero address — so the validator's
    /// answer about signer 0 is never asked for. With the validator made to
    /// explode, the refusal is still ours.
    function test_924F1_releaseWithSignatureRefusesSignerZeroBeforeTheValidator() public {
        bytes32 node = _register("venue", holder, SITE);
        vm.mockCallRevert(Validator.ADDR, bytes(""), "validator must not be reached");

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        vm.prank(stranger);
        registry.releaseWithSignature(node, NOW + 1, address(0), JUNK);

        assertEq(registry.owner(node), holder);
    }

    /// v1's stopgap was the holder approving itself; a transfer cleared it and
    /// reopened the hole. Approval state no longer matters either way.
    function test_924F1_approvalStateNoLongerMatters() public {
        bytes32 node = _register("venue", holder, SITE);

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        vm.prank(stranger);
        registry.setContenthash(node, OTHER);

        vm.startPrank(holder);
        registry.approve(holder, uint256(node));
        registry.transferFrom(holder, victim, uint256(node));
        vm.stopPrank();
        assertEq(registry.getApproved(uint256(node)), address(0));

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        vm.prank(stranger);
        registry.setContenthash(node, OTHER);
    }

    /*//////////////////////////////////////////////////////////////
                    924 F-2 (High claim, reproduced on v1)
    //////////////////////////////////////////////////////////////*/

    /// v1: an operator-for-all approved by the admin moved the base name — the
    /// whole admin role — in one call.
    function test_924F2_anOperatorForAllOfTheAdminCannotMoveTheSeat() public {
        address op = makeAddr("operator");
        address other = makeAddr("other");
        uint256 baseToken = uint256(registry.baseNode());
        vm.prank(admin);
        registry.setApprovalForAll(op, true);

        vm.expectRevert(L2Registry.AdminHandoverRequired.selector);
        vm.prank(op);
        registry.transferFrom(admin, other, baseToken);

        assertEq(registry.owner(), admin);
    }

    /*//////////////////////////////////////////////////////////////
          924 F-3 / 927 H2 / 925 #2 — records seeded before a mint
    //////////////////////////////////////////////////////////////*/

    /// v1: the sponsor set a contenthash on an unminted label, and the mint
    /// handed it to the first holder. Refused at the registrar by name, refused
    /// at the registry for the registrar contract itself, and the first holder
    /// starts clean.
    function test_927H2_nothingCanBeSeededOnAnUnmintedLabel() public {
        bytes32 node = registry.makeNode(registry.baseNode(), "future");

        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.LabelNotRegistered.selector, "future"));
        vm.prank(sponsor);
        registrar.setContenthash("future", OTHER);

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        vm.prank(address(registrar));
        registry.setContenthash(node, OTHER);

        _register("future", victim, "");
        assertEq(registry.owner(node), victim);
        assertEq(registry.contenthash(node).length, 0, "the first holder inherited a seeded record");
    }

    /// v1 (927 H2's refutation): the admin enrolled itself and cleared an
    /// unminted label. Neither clearing nor writing an unminted label works now.
    function test_927H2_theAdminAsRegistrarCannotTouchAnUnmintedLabel() public {
        bytes32 node = registry.makeNode(registry.baseNode(), "future");
        vm.prank(admin);
        registry.addRegistrar(admin);

        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        registry.clearRecords(node);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        registry.setContenthash(node, OTHER);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                    927 H1 (High claim, reproduced on v1)
    //////////////////////////////////////////////////////////////*/

    /// v1: `adminTransfer(node, sameHolder)` was refused as a wipe-in-place,
    /// yet `addRegistrar(self)` + `clearRecords(node)` did exactly that. The
    /// one-call wipe is refused both ways now.
    function test_927H1_theAdminCannotWipeANameInPlace() public {
        bytes32 node = _register("venue", holder, SITE);

        vm.expectRevert(L2Registry.AdminTransferSameOwner.selector);
        vm.prank(admin);
        registry.adminTransfer(node, holder);

        vm.startPrank(admin);
        registry.addRegistrar(admin);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        registry.clearRecords(node);
        vm.stopPrank();

        assertEq(registry.owner(node), holder);
        assertEq(registry.contenthash(node), SITE, "the name was wiped in place");
    }

    /// What remains, by owner decision (2026-09-14, option a): the admin seat,
    /// enrolled as a registrar, can overwrite a record in place. Pinned as the
    /// accepted power, visible on chain through `RegistrarAdded`.
    function test_927H1_theAcceptedPower_theAdminSeatCanOverwriteARecordInPlace() public {
        bytes32 node = _register("venue", holder, SITE);

        vm.startPrank(admin);
        registry.addRegistrar(admin);
        registry.setContenthash(node, OTHER);
        vm.stopPrank();

        assertEq(registry.contenthash(node), OTHER);
        assertEq(registry.owner(node), holder, "the name itself did not move");
    }

    /*//////////////////////////////////////////////////////////////
          927 H3 / 924 F-3 — the recipient that releases mid-mint
    //////////////////////////////////////////////////////////////*/

    /// v1: `_safeMint` called the recipient, which released the name; the
    /// registrar's records landed on the freed label for the next registrant.
    /// Now nothing calls the recipient: it keeps the name, with its records.
    function test_927H3_theRecipientIsNotCalledSoCannotReleaseMidMint() public {
        ReleasesOnReceive receiver = new ReleasesOnReceive(registry);
        string[] memory keys = new string[](1);
        string[] memory vals = new string[](1);
        keys[0] = "avatar";
        vals[0] = "chosen-by-first-recipient";

        vm.prank(sponsor);
        registrar.register("coolbrand", address(receiver), OTHER, keys, vals);
        bytes32 node = registry.makeNode(registry.baseNode(), "coolbrand");

        assertEq(receiver.calls(), 0, "the recipient was called during the mint");
        assertEq(registry.owner(node), address(receiver));
        assertFalse(registrar.available("coolbrand"));
        assertEq(registry.contenthash(node), OTHER);
        assertEq(registry.text(node, "avatar"), "chosen-by-first-recipient");
    }

    /// And when that holder does release, later, the next registrant of the
    /// label starts from empty records.
    function test_927H3_aReleasedLabelsNextRegistrantStartsClean() public {
        ReleasesOnReceive receiver = new ReleasesOnReceive(registry);
        string[] memory keys = new string[](1);
        string[] memory vals = new string[](1);
        keys[0] = "avatar";
        vals[0] = "chosen-by-first-recipient";
        vm.prank(sponsor);
        registrar.register("coolbrand", address(receiver), OTHER, keys, vals);
        bytes32 node = registry.makeNode(registry.baseNode(), "coolbrand");

        vm.prank(address(receiver));
        registry.release(node);

        _register("coolbrand", victim, "");
        assertEq(registry.owner(node), victim);
        assertEq(registry.contenthash(node).length, 0, "the next registrant inherited the contenthash");
        assertEq(bytes(registry.text(node, "avatar")).length, 0, "the next registrant inherited a text record");
        assertEq(registry.addr(node), victim);
    }

    /// The same, for the case that made v1's defect reachable from a plain
    /// wallet: an EOA carrying an EIP-7702 delegation to such a receiver.
    function test_927H3_aDelegatedEoaRecipientIsNotCalledEither() public {
        uint256 key = 0xE0A;
        address eoa = vm.addr(key);
        vm.signAndAttachDelegation(address(new ReleasesOnReceive(registry)), key);

        bytes32 node = _register("coolbrand", eoa, OTHER);

        assertEq(registry.owner(node), eoa, "the delegated recipient released the name mid-mint");
        assertEq(registry.contenthash(node), OTHER);
    }

    /*//////////////////////////////////////////////////////////////
                    925 #1 (High claim, reproduced on v1)
    //////////////////////////////////////////////////////////////*/

    /// v1: the permit signed (label, owner, expiry) only, so its submitter chose
    /// the records. The entry point is gone.
    function test_925H1_registerWithPermitIsGone() public {
        vm.prank(stranger);
        (bool ok, bytes memory ret) = address(registrar).call(
            abi.encodeWithSignature(
                "registerWithPermit(string,address,bytes,string[],string[],uint256,bytes)",
                "alice-conf", holder, OTHER, new string[](0), new string[](0), NOW + 15 minutes, JUNK
            )
        );
        assertFalse(ok);
        assertEq(ret.length, 0, "registerWithPermit still exists");
    }

    /*//////////////////////////////////////////////////////////////
                    924 F-5 / 927 M6 (reproduced on v1)
    //////////////////////////////////////////////////////////////*/

    /// v1: a plain transfer kept the seller's addr and contenthash.
    function test_924F5_aPlainTransferClearsTheSellersRecords() public {
        bytes32 node = _register("venue", holder, SITE);
        address buyerAddr = makeAddr("buyer");

        vm.prank(holder);
        registry.transferFrom(holder, buyerAddr, uint256(node));

        assertEq(registry.addr(node), address(0), "the buyer's name still pays the seller");
        assertEq(registry.contenthash(node).length, 0, "the buyer's name still shows the seller's site");
    }

    /*//////////////////////////////////////////////////////////////
                          THE READ-ONLY FINDINGS
    //////////////////////////////////////////////////////////////*/

    /// 924 F-8 / 927 L14: v1's registrar branch named any parent.
    function test_924F8_aRegistrarCannotMintUnderAParentThatDoesNotExist() public {
        bytes32 missing = registry.makeNode(registry.baseNode(), "missing");
        bytes[] memory none = new bytes[](0);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, missing));
        vm.prank(address(registrar));
        registry.createSubnode(missing, "child", victim, none);
    }

    /// 924 F-14 / F-15 / 927 L23: v1 checked label length against 255 only.
    function test_924F14_F15_labelsRespectTheDnsLimitAndJsonSafeBytes() public {
        bytes32 base = registry.baseNode();
        bytes[] memory none = new bytes[](0);
        string memory quoted = string(abi.encodePacked("a", bytes1(0x22), "b"));

        vm.prank(admin);
        registry.addRegistrar(admin);

        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSelector(L2Registry.LabelInvalidCharacter.selector, quoted));
        registry.createSubnode(base, quoted, victim, none);
        vm.expectRevert(abi.encodeWithSelector(L2Registry.LabelInvalidCharacter.selector, "a.b"));
        registry.createSubnode(base, "a.b", victim, none);
        vm.stopPrank();
    }

    /// 924 F-16.
    function test_924F16_supportsInterfaceReportsExtendedResolver() public view {
        assertTrue(registry.supportsInterface(type(IExtendedResolver).interfaceId));
    }

    /// 924 F-18.
    function test_924F18_addRegistrarRefusesTheZeroAddress() public {
        vm.expectRevert(L2Registry.RegistrarIsZeroAddress.selector);
        vm.prank(admin);
        registry.addRegistrar(address(0));
    }

    /// 924 F-6 / 927 I10: in v1 any registrar could bump a name's version with
    /// `clearRecords` and so void its holder's release signature.
    function test_924F6_aRegistrarCannotVoidAHoldersReleaseSignature() public {
        bytes32 node = _register("venue", holder, SITE);
        bytes32 digestBefore = registry.releaseDigest(node, NOW + 1);

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        vm.prank(address(registrar));
        registry.clearRecords(node);

        assertEq(registry.releaseDigest(node, NOW + 1), digestBefore);
    }
}

/// @dev The recipient from the 927 H3 reproduction: releases whatever it is sent.
contract ReleasesOnReceive is IERC721Receiver {
    L2Registry immutable registry;
    uint256 public calls;

    constructor(L2Registry r) {
        registry = r;
    }

    function onERC721Received(address, address, uint256 tokenId, bytes calldata) external returns (bytes4) {
        calls++;
        registry.release(bytes32(tokenId));
        return this.onERC721Received.selector;
    }
}
