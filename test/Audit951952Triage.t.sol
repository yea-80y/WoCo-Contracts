// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IERC721Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {ERC721Wrapper} from "@openzeppelin/contracts/token/ERC721/extensions/ERC721Wrapper.sol";
import {IMulticallable} from "@ensdomains/ens-contracts/resolvers/IMulticallable.sol";
import {L2Registry} from "../src/durin/L2Registry.sol";
import {L2Resolver} from "../src/durin/L2Resolver.sol";
import {WoCoRegistrar} from "../src/WoCoRegistrar.sol";
import {UniversalSigValidatorFixture as Validator} from "./fixtures/UniversalSigValidatorFixture.sol";

/**
 * Triage of LeftClaw jobs 951 (L2Registry / L2Resolver) and 952 (WoCoRegistrar),
 * both against `bc00d91`. Reports:
 * `~/projects/woco-571-handover/AUDIT_951_SUBENS_V22_REGISTRY.md` and
 * `AUDIT_952_SUBENS_V22_REGISTRAR.md`.
 *
 * Each test reproduces one claim AS THE AUDITOR STATED IT, written before any
 * ruling, so green means "the mechanism is real" and says nothing yet about
 * severity or whether to change anything. Where the report's own example or
 * proposed fix is wrong, the test shows that too.
 */
contract Audit951952TriageTest is Test {
    L2Registry registry;
    WoCoRegistrar registrar;
    bytes32 base;

    address admin = makeAddr("admin");
    address sponsor = makeAddr("sponsor");
    address alice = makeAddr("alice");
    address brand = makeAddr("brand");
    address infringer = makeAddr("infringer");
    address stranger = makeAddr("stranger");
    address buyer = makeAddr("buyer");

    uint256 constant HOLDER_KEY = 0xA11CE;
    address signer = vm.addr(HOLDER_KEY);

    uint256 constant NOW = 1_800_000_000;
    bytes constant SITE = hex"e40101fa011b20d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162";
    bytes constant H1 = hex"e40101fa011b201111111111111111111111111111111111111111111111111111111111111111";
    bytes constant H2 = hex"e40101fa011b202222222222222222222222222222222222222222222222222222222222222222";

    function setUp() public {
        vm.etch(Validator.ADDR, Validator.CODE);
        vm.warp(NOW);
        registry = L2Registry(Clones.clone(address(new L2Registry())));
        registry.initialize("woco.eth", "WoCo Names", "", admin);
        registrar = new WoCoRegistrar(address(registry), sponsor, new string[](0));
        vm.prank(admin);
        registry.addRegistrar(address(registrar));
        base = registry.baseNode();
    }

    function _mint(string memory label, address to) internal returns (bytes32) {
        vm.prank(sponsor);
        return registrar.register(label, to);
    }

    function _mintUnder(bytes32 parent, string memory label, address to) internal returns (bytes32 node) {
        vm.prank(registry.owner(parent));
        node = registry.createSubnode(parent, label, to, new bytes[](0));
    }

    function _sign(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    /*//////////////////////////////////////////////////////////////
        951 F-1 (High): an adminTransfer below the first level is
        undone by the holder of the name above it.
    //////////////////////////////////////////////////////////////*/

    function test_951_F1_theParentHolderTakesBackASeizedSecondLevelName() public {
        bytes32 p = _mint("alice", alice);
        bytes32 n = _mintUnder(p, "nike", alice);

        vm.prank(admin);
        registry.adminTransfer(n, brand);
        assertEq(registry.owner(n), brand);

        vm.prank(alice);
        registry.parentTransfer(n, alice);
        assertEq(registry.owner(n), alice, "claim: the seizure is undone in one call");
    }

    /// The contrast the report draws: at the first level the seizure is final,
    /// because `_parentHolder` is zero beneath the base name.
    function test_951_F1_aFirstLevelSeizureIsFinal() public {
        bytes32 p = _mint("alice", alice);
        vm.prank(admin);
        registry.adminTransfer(p, brand);

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, p));
        vm.prank(alice);
        registry.parentTransfer(p, alice);
    }

    /// What the seat can already do: seize the name AND the one above it. The
    /// parent's power follows the parent, so nothing is left to undo it with.
    function test_951_F1_seizingTheParentTooMakesItFinal() public {
        bytes32 p = _mint("alice", alice);
        bytes32 n = _mintUnder(p, "nike", alice);

        vm.startPrank(admin);
        registry.adminTransfer(n, brand);
        registry.adminTransfer(p, brand);
        vm.stopPrank();

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, n));
        vm.prank(alice);
        registry.parentTransfer(n, alice);
        vm.expectRevert(); // alice holds nothing above n any more
        vm.prank(alice);
        registry.release(n);
        assertEq(registry.owner(n), brand);
    }

    /// One level up is not enough deeper down: `_parentHolder` looks one level
    /// up, and the first-level holder climbs back down a level at a time. The
    /// seizure is final only with the whole chain up to the first level.
    function test_951_F1_atDepthThreeTheWholeChainMustBeTaken() public {
        bytes32 p = _mint("alice", alice);
        bytes32 q = _mintUnder(p, "shop", alice);
        bytes32 n = _mintUnder(q, "nike", alice);

        vm.startPrank(admin);
        registry.adminTransfer(n, brand);
        registry.adminTransfer(q, brand);
        vm.stopPrank();

        vm.startPrank(alice);
        registry.parentTransfer(q, alice);
        registry.parentTransfer(n, alice);
        vm.stopPrank();
        assertEq(registry.owner(n), alice, "two levels taken, still undone");

        vm.startPrank(admin);
        registry.adminTransfer(n, brand);
        registry.adminTransfer(q, brand);
        registry.adminTransfer(p, brand);
        vm.stopPrank();
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, q));
        vm.prank(alice);
        registry.parentTransfer(q, alice);
    }

    /*//////////////////////////////////////////////////////////////
        951 F-2 (High): seizing a parent leaves every name beneath it
        with its holder; the parent cannot be released while they live.
    //////////////////////////////////////////////////////////////*/

    function test_951_F2_theChildKeepsItsHolderAndRecordsAfterTheParentIsSeized() public {
        bytes32 p = _mint("nike", infringer);
        bytes32 c = _mintUnder(p, "shop", infringer);
        vm.prank(infringer);
        registry.setContenthash(c, SITE);

        vm.prank(admin);
        registry.adminTransfer(p, brand);

        assertEq(registry.owner(c), infringer, "claim: the child stays");
        assertEq(registry.contenthash(c), SITE, "claim: its records stay");
        vm.prank(infringer);
        registry.setContenthash(c, H1); // claim: still writable by the old holder
        assertEq(registry.contenthash(c), H1);

        vm.expectRevert(abi.encodeWithSelector(L2Registry.HasChildren.selector, p, 1));
        vm.prank(brand);
        registry.release(p);
    }

    /// The documented remedy (`adminTransfer` NatSpec): the new holder takes the
    /// child with `parentTransfer`, which resets its records, and then the
    /// parent releases. The old holder's writes stop at the move.
    function test_951_F2_theNewHolderUnwindsTheSubtreeTopDown() public {
        bytes32 p = _mint("nike", infringer);
        bytes32 c = _mintUnder(p, "shop", infringer);
        bytes32 g = _mintUnder(c, "deep", infringer);
        vm.prank(infringer);
        registry.setContenthash(c, SITE);

        vm.prank(admin);
        registry.adminTransfer(p, brand);

        vm.startPrank(brand);
        registry.parentTransfer(c, brand);
        assertEq(registry.contenthash(c), "", "the move resets the child's records");
        registry.parentTransfer(g, brand);
        registry.release(g);
        registry.release(c);
        registry.release(p);
        vm.stopPrank();

        vm.expectRevert(); // nothing left for the old holder to write
        vm.prank(infringer);
        registry.setContenthash(c, H1);
    }

    /// The report's fix — refuse `adminTransfer` while `childCount != 0` — would
    /// hand the infringer a veto: one live child and the seat cannot take the
    /// parent at all. Shown here as the precondition it would key on.
    function test_951_F2_oneChildIsAllTheProposedFixWouldNeedToBlockASeizure() public {
        bytes32 p = _mint("nike", infringer);
        _mintUnder(p, "x", infringer);
        assertEq(registry.childCount(p), 1);
        // Today the seizure succeeds regardless:
        vm.prank(admin);
        registry.adminTransfer(p, brand);
        assertEq(registry.owner(p), brand);
    }

    /*//////////////////////////////////////////////////////////////
        951 F-3 (Medium): non-ASCII and non-UTF-8 label bytes mint
        beneath a holder's name and reach tokenURI's JSON.
    //////////////////////////////////////////////////////////////*/

    function test_951_F3_aLoneHighByteMintsAndTokenURIIsNotUtf8() public {
        bytes32 p = _mint("alice", alice);
        bytes32 n = _mintUnder(p, string(abi.encodePacked(hex"80")), alice);

        bytes memory json = abi.encodePacked('{"name": "', hex"80", '.alice.woco.eth"}');
        assertEq(
            registry.tokenURI(uint256(n)),
            string.concat("data:application/json;base64,", Base64.encode(json)),
            "claim: a lone 0x80 reaches the JSON, which is then not UTF-8"
        );
    }

    function test_951_F3_bidiAndInvisibleCharactersMintBeneathAHolderName() public {
        bytes32 p = _mint("alice", alice);
        // UTF-8 bytes: solc refuses an unbalanced bidi override in a literal.
        _mintUnder(p, string(abi.encodePacked(hex"e280ae", "kcatta")), alice); // U+202E RIGHT-TO-LEFT OVERRIDE
        _mintUnder(p, string(abi.encodePacked("ni", hex"e2808b", "ke")), alice); // U+200B ZERO WIDTH SPACE
        _mintUnder(p, string(abi.encodePacked("a", hex"e38082", "b")), alice); // U+3002 IDEOGRAPHIC FULL STOP
    }

    /// The first level is registrar policy, and the registrar refuses them.
    function test_951_F3_theRegistrarRefusesThemAtTheFirstLevel() public {
        string[3] memory labels = [
            string(abi.encodePacked(hex"e280ae", "kcatta")),
            string(abi.encodePacked("ni", hex"e2808b", "ke")),
            string(abi.encodePacked(hex"808080"))
        ];
        for (uint256 i; i < labels.length; ++i) {
            vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.InvalidLabel.selector, labels[i]));
            vm.prank(sponsor);
            registrar.register(labels[i], alice);
        }
    }

    /*//////////////////////////////////////////////////////////////
        951 F-4 (Medium): IERC721 is reported while approve reverts.
        The report's concrete stranding example is OpenZeppelin's
        ERC721Wrapper. It does not strand: its exit is a push.
    //////////////////////////////////////////////////////////////*/

    function test_951_F4_reportsIERC721AndRefusesApproveEvenForTheHolder() public {
        bytes32 n = _mint("alice", alice);
        assertTrue(registry.supportsInterface(type(IERC721).interfaceId));
        vm.expectRevert(L2Registry.DelegationNotSupported.selector);
        vm.prank(alice);
        registry.approve(buyer, uint256(n));
    }

    function test_951_F4_openZeppelinsWrapperRoundTripsANameByPush() public {
        bytes32 n = _mint("alice", alice);
        WrapperVault vault = new WrapperVault(IERC721(address(registry)));

        // In: the wrapper's pull (`depositFor`) needs an approval and fails;
        // the holder's push lands through `onERC721Received`.
        uint256[] memory ids = new uint256[](1);
        ids[0] = uint256(n);
        vm.expectRevert(
            abi.encodeWithSelector(IERC721Errors.ERC721InsufficientApproval.selector, address(vault), uint256(n))
        );
        vm.prank(alice);
        vault.depositFor(alice, ids);

        vm.prank(alice);
        registry.safeTransferFrom(alice, address(vault), uint256(n));
        assertEq(registry.owner(n), address(vault));
        assertEq(vault.ownerOf(uint256(n)), alice);

        // Out: `withdrawTo` moves the name as its holder. No approval anywhere.
        vm.prank(alice);
        vault.withdrawTo(alice, ids);
        assertEq(registry.owner(n), alice, "the name is stranded");
    }

    /*//////////////////////////////////////////////////////////////
        951 F-5 (Low): createSubnode's node check compares calldata,
        so `acceptAdmin()` padded with the new node runs in the batch.
    //////////////////////////////////////////////////////////////*/

    function test_951_F5_aPaddedAcceptAdminRunsInsideTheMintBatch() public {
        bytes32 p = _mint("nominee", alice);
        vm.prank(admin);
        registry.nominateAdmin(alice);

        bytes32 sub = registry.makeNode(p, "k");
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encodePacked(L2Registry.acceptAdmin.selector, sub);
        vm.prank(alice);
        registry.createSubnode(p, "k", alice, data);

        assertEq(registry.owner(), alice, "claim: the seat moved inside the batch");
        assertEq(registry.adminEpoch(), 1);
        assertFalse(registry.registrars(address(registrar)), "the epoch moved as in a plain call");
    }

    /// It is the caller's own call, with the caller's own authority: anyone
    /// else's padded `acceptAdmin` fails with `acceptAdmin`'s own reason.
    function test_951_F5_aNonNomineeIsRefusedByAcceptAdminItself() public {
        bytes32 p = _mint("other", stranger);
        vm.prank(admin);
        registry.nominateAdmin(alice);

        bytes32 sub = registry.makeNode(p, "k");
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encodePacked(L2Registry.acceptAdmin.selector, sub);
        vm.expectRevert(abi.encodeWithSelector(L2Registry.NotPendingAdmin.selector, stranger));
        vm.prank(stranger);
        registry.createSubnode(p, "k", stranger, data);
    }

    /// The existing test the report names (`test_Self_TheSeatCannotBeAcceptedByTheRegistry`)
    /// sends a bare 4-byte item, so it trips the length clause and never the
    /// node comparison. Its docstring's reason — "`acceptAdmin()` names
    /// nothing, so it is refused before it runs" — holds only unpadded. Its
    /// property still holds padded, for `acceptAdmin`'s own reason.
    function test_951_F5_theRegistryStillCannotAcceptTheSeatPadded() public {
        vm.prank(admin);
        registry.nominateAdmin(address(registry));
        vm.prank(admin);
        registry.addRegistrar(stranger);

        bytes32 sub = registry.makeNode(base, "venue");
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encodePacked(L2Registry.acceptAdmin.selector, sub);
        vm.expectRevert(abi.encodeWithSelector(L2Registry.NotPendingAdmin.selector, stranger));
        vm.prank(stranger);
        registry.createSubnode(base, "venue", stranger, data);
        assertEq(registry.owner(), admin);
    }

    /*//////////////////////////////////////////////////////////////
        951 F-12 (Low): IL2Resolver still extends IMulticallable.
    //////////////////////////////////////////////////////////////*/

    function test_951_F12_aCallTypedAgainstTheInterfaceRevertsWithNoData() public {
        (bool ok, bytes memory ret) =
            address(registry).call(abi.encodeCall(IMulticallable.multicall, (new bytes[](0))));
        assertFalse(ok);
        assertEq(ret.length, 0, "claim: indistinguishable from out-of-gas");
        assertFalse(registry.supportsInterface(type(IMulticallable).interfaceId));
    }

    /*//////////////////////////////////////////////////////////////
        952 [1] (Medium): a retake is charged to neither window, so a
        release/retake loop never moves the registrar-wide counter.
    //////////////////////////////////////////////////////////////*/

    function test_952_1_aRetakeLoopLeavesBothWindowsUntouched() public {
        bytes32 n = _mint("grind", alice);
        (uint32 globalAfterFirst,) = registrar.globalMintAllowance();
        (uint32 recipientAfterFirst,) = registrar.mintAllowance(alice);
        assertEq(globalAfterFirst, 299);

        for (uint256 i; i < 5; ++i) {
            vm.prank(alice);
            registry.release(n);
            n = _mint("grind", alice);
        }
        (uint32 globalNow,) = registrar.globalMintAllowance();
        (uint32 recipientNow,) = registrar.mintAllowance(alice);
        assertEq(globalNow, globalAfterFirst, "claim: five real mints, zero charged");
        assertEq(recipientNow, recipientAfterFirst);
    }

    /// The loop mints nothing new: the label comes back to the address that
    /// released it. Any OTHER recipient of a released label is charged.
    function test_952_1_aReleasedLabelTakenBySomeoneElseIsCharged() public {
        bytes32 n = _mint("grind", alice);
        vm.prank(alice);
        registry.release(n);
        _mint("grind", buyer);
        (uint32 globalNow,) = registrar.globalMintAllowance();
        assertEq(globalNow, 298);
    }

    /*//////////////////////////////////////////////////////////////
        952 [2] (Medium): a holder's unrelayed pointer signature
        survives the holder's own release and retake.
    //////////////////////////////////////////////////////////////*/

    function test_952_2_anUnrelayedSignatureSurvivesReleaseAndRetake() public {
        bytes32 n = _mint("alice", signer);
        uint256 exp = block.timestamp + 10 minutes;
        bytes memory s1 = _sign(HOLDER_KEY, registrar.setContenthashDigest(n, H1, exp));

        vm.prank(signer);
        registry.release(n);
        _mint("alice", signer);

        vm.prank(stranger);
        registrar.setContenthashWithSignature("alice", H1, exp, s1);
        assertEq(registry.contenthash(n), H1, "claim: the pre-release signature writes");
    }

    /// And it is dead while anyone else holds the name: the check is against
    /// the CURRENT holder.
    function test_952_2_itIsRefusedWhileSomeoneElseHoldsTheName() public {
        bytes32 n = _mint("alice", signer);
        uint256 exp = block.timestamp + 10 minutes;
        bytes memory s1 = _sign(HOLDER_KEY, registrar.setContenthashDigest(n, H1, exp));

        vm.prank(signer);
        registry.transferFrom(signer, buyer, uint256(n));

        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotHolderSignature.selector, n));
        vm.prank(stranger);
        registrar.setContenthashWithSignature("alice", H1, exp, s1);
    }

    /// The report's Option B (bump the nonce in `register`) covers only a
    /// return through the registrar. A name that comes back by TRANSFER keeps
    /// the nonce too, so the same signature writes after a sale and buy-back.
    function test_952_2_aBuyBackRevivesItTooSoOptionBIsPartial() public {
        bytes32 n = _mint("alice", signer);
        uint256 exp = block.timestamp + 10 minutes;
        bytes memory s1 = _sign(HOLDER_KEY, registrar.setContenthashDigest(n, H1, exp));

        vm.prank(signer);
        registry.transferFrom(signer, buyer, uint256(n));
        vm.prank(buyer);
        registry.transferFrom(buyer, signer, uint256(n));

        vm.prank(stranger);
        registrar.setContenthashWithSignature("alice", H1, exp, s1);
        assertEq(registry.contenthash(n), H1);
    }

    /*//////////////////////////////////////////////////////////////
        952 [3] (Medium): no reset for the registrar-wide window.
    //////////////////////////////////////////////////////////////*/

    function test_952_3_aFullGlobalWindowIsLiftedAtOnceByRaisingTheCap() public {
        for (uint256 r; r < 10; ++r) {
            address to = address(uint160(0x1000 + r));
            for (uint256 i; i < 30; ++i) {
                _mint(string.concat("n", vm.toString(r), "x", vm.toString(i)), to);
            }
        }
        (uint32 remaining, uint64 resetsAt) = registrar.globalMintAllowance();
        assertEq(remaining, 0);

        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.GlobalMintCapExceeded.selector, resetsAt));
        vm.prank(sponsor);
        registrar.register("honest", alice);

        // removeSponsor does not touch the window (claim)...
        vm.prank(admin);
        registrar.removeSponsor(sponsor);
        (remaining,) = registrar.globalMintAllowance();
        assertEq(remaining, 0);

        // ...and the documented lever lifts it in one call.
        address fresh = makeAddr("freshSponsor");
        vm.startPrank(admin);
        registrar.addSponsor(fresh);
        registrar.setGlobalMintRateCap(600, 1 hours);
        vm.stopPrank();
        vm.prank(fresh);
        registrar.register("honest", alice);
        assertEq(registry.owner(registry.makeNode(base, "honest")), alice);
    }

    /*//////////////////////////////////////////////////////////////
        952 [4] (Low): register(label, address(0)) — inert today.
    //////////////////////////////////////////////////////////////*/

    function test_952_4_aMintToZeroIsRefusedByTheRegistry() public {
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721InvalidReceiver.selector, address(0)));
        vm.prank(sponsor);
        registrar.register("zero", address(0));
        (uint32 remaining,) = registrar.globalMintAllowance();
        assertEq(remaining, 300, "nothing was charged");
    }

    /*//////////////////////////////////////////////////////////////
        952 Lead "stale resolver data on remint" — refuted.
    //////////////////////////////////////////////////////////////*/

    function test_952_lead_aRemintStartsWithEmptyRecords() public {
        bytes32 n = _mint("alice", alice);
        vm.prank(alice);
        registry.setContenthash(n, SITE);
        vm.prank(alice);
        registry.release(n);
        _mint("alice", buyer);
        assertEq(registry.contenthash(n), "");
    }
}

/// OpenZeppelin 5.6.1's ERC721Wrapper, made concrete. Test-only.
contract WrapperVault is ERC721Wrapper {
    constructor(IERC721 underlying_) ERC721("Wrapped", "W") ERC721Wrapper(underlying_) {}
}
