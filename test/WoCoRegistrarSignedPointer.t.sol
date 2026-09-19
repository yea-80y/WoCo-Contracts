// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {WoCoRegistrar} from "../src/WoCoRegistrar.sol";
import {L2Registry} from "../src/durin/L2Registry.sol";
import {L2Resolver} from "../src/durin/L2Resolver.sol";
import {UniversalSigValidatorFixture as Validator} from "./fixtures/UniversalSigValidatorFixture.sol";
import {PreparesOnCall1271, ActsThenApproves} from "./SubEnsV21AuditRegression.t.sol";

/**
 * The registrar after the sponsor-key consult (Fable, 2026-09-19; owner adopted
 * it the same day, report `~/projects/woco-571-handover/FABLE_SPONSOR_ARCH_CONSULT_REPORT.md`).
 *
 * The sponsor may create an EMPTY name and pay for what a holder signed, and
 * nothing more: the sponsor-only `setContenthash` is gone, the one post-mint
 * write is `setContenthashWithSignature`, and a registrar-wide cap bounds what
 * any sponsor key can mint.
 *
 * Began as the consult's `ScratchSignedPointer.t.sol` (14 tests, all green
 * against its prototype); adapted to the two-argument `register`, and extended
 * with: the holder re-read after the validator (the one departure from the
 * prototype, mirroring `L2Registry.releaseWithSignature`), the nonce consumed
 * before the validator call, the two EIP-712 domains kept apart, plain ECDSA
 * never reaching the validator, and a pinned digest for the app's client.
 */
contract WoCoRegistrarSignedPointerTest is Test {
    L2Registry registry;
    WoCoRegistrar registrar;

    address admin = makeAddr("admin");
    address sponsor = makeAddr("sponsor");
    address relayer = makeAddr("relayer");
    address buyer = makeAddr("buyer");

    uint256 constant HOLDER_KEY = 0xA11CE;
    uint256 constant STRANGER_KEY = 0xB0B;
    address holder = vm.addr(HOLDER_KEY);
    address stranger = vm.addr(STRANGER_KEY);

    uint256 constant NOW = 1_800_000_000;
    uint256 constant EXPIRY = NOW + 10 minutes;

    bytes constant H1 = hex"e40101fa011b201111111111111111111111111111111111111111111111111111111111111111";
    bytes constant H2 = hex"e40101fa011b202222222222222222222222222222222222222222222222222222222222222222";

    event ContenthashUpdated(bytes32 indexed node, string label, bytes contenthash);
    event GlobalMintRateCapSet(uint32 maxMintsPerWindow, uint64 mintWindowSeconds);

    function setUp() public {
        vm.etch(Validator.ADDR, Validator.CODE);
        registry = L2Registry(Clones.clone(address(new L2Registry())));
        registry.initialize("woco.eth", "WoCo Names", "", admin);
        registrar = new WoCoRegistrar(address(registry), sponsor, new string[](0));
        vm.prank(admin);
        registry.addRegistrar(address(registrar));
        vm.warp(NOW);
    }

    function _mint(string memory label, address to) internal returns (bytes32 node) {
        vm.prank(sponsor);
        node = registrar.register(label, to);
    }

    function _sign(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _pointerSig(uint256 key, bytes32 node, bytes memory hash, uint256 exp) internal view returns (bytes memory) {
        return _sign(key, registrar.setContenthashDigest(node, hash, exp));
    }

    /*//////////////////////////////////////////////////////////////
                    HOLDER-SIGNED POINTER WRITES
    //////////////////////////////////////////////////////////////*/

    function test_holderSignatureRelayedByAnyone() public {
        bytes32 node = _mint("punkpub", holder);
        bytes memory sig = _pointerSig(HOLDER_KEY, node, H1, EXPIRY);

        vm.expectEmit(true, false, false, true, address(registrar));
        emit ContenthashUpdated(node, "punkpub", H1);
        vm.prank(relayer); // not the sponsor: the signature is the authority
        registrar.setContenthashWithSignature("punkpub", H1, EXPIRY, sig);

        assertEq(registry.contenthash(node), H1);
        assertEq(registrar.pointerNonce(node), 1);
    }

    function test_sponsorAloneCannotRepoint() public {
        bytes32 node = _mint("punkpub", holder);

        (bool ok,) = address(registrar).call(abi.encodeWithSignature("setContenthash(string,bytes)", "punkpub", H1));
        assertFalse(ok, "sponsor-only setContenthash must not exist");

        bytes memory forged = _pointerSig(STRANGER_KEY, node, H1, EXPIRY);
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotHolderSignature.selector, node));
        vm.prank(sponsor);
        registrar.setContenthashWithSignature("punkpub", H1, EXPIRY, forged);

        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotHolderSignature.selector, node));
        vm.prank(sponsor);
        registrar.setContenthashWithSignature("punkpub", H1, EXPIRY, hex"deadbeef");

        assertEq(registry.contenthash(node), "");
        assertEq(registrar.pointerNonce(node), 0, "a refused write consumed the nonce");
    }

    function test_signatureIsSingleUse() public {
        bytes32 node = _mint("punkpub", holder);
        bytes memory sig = _pointerSig(HOLDER_KEY, node, H1, EXPIRY);
        vm.prank(relayer);
        registrar.setContenthashWithSignature("punkpub", H1, EXPIRY, sig);

        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotHolderSignature.selector, node));
        vm.prank(relayer);
        registrar.setContenthashWithSignature("punkpub", H1, EXPIRY, sig);
    }

    function test_signatureBindsTheContenthash() public {
        bytes32 node = _mint("punkpub", holder);
        bytes memory sig = _pointerSig(HOLDER_KEY, node, H1, EXPIRY);
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotHolderSignature.selector, node));
        vm.prank(relayer);
        registrar.setContenthashWithSignature("punkpub", H2, EXPIRY, sig);
    }

    function test_signatureBindsTheExpiration() public {
        bytes32 node = _mint("punkpub", holder);
        bytes memory sig = _pointerSig(HOLDER_KEY, node, H1, EXPIRY);
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotHolderSignature.selector, node));
        vm.prank(relayer);
        registrar.setContenthashWithSignature("punkpub", H1, EXPIRY + 1, sig);
    }

    function test_signatureBindsTheName() public {
        bytes32 a = _mint("punkpub", holder);
        _mint("otherpub", holder);
        bytes memory sig = _pointerSig(HOLDER_KEY, a, H1, EXPIRY);
        bytes32 b = registry.makeNode(registry.baseNode(), "otherpub");
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotHolderSignature.selector, b));
        vm.prank(relayer);
        registrar.setContenthashWithSignature("otherpub", H1, EXPIRY, sig);
    }

    function test_sellerSignatureDiesWithTheSale() public {
        bytes32 node = _mint("punkpub", holder);
        bytes memory sig = _pointerSig(HOLDER_KEY, node, H1, EXPIRY);

        vm.prank(holder);
        registry.transferFrom(holder, buyer, uint256(node));

        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotHolderSignature.selector, node));
        vm.prank(relayer);
        registrar.setContenthashWithSignature("punkpub", H1, EXPIRY, sig);
    }

    function test_expiryWindow() public {
        bytes32 node = _mint("punkpub", holder);

        bytes memory late = _pointerSig(HOLDER_KEY, node, H1, NOW - 1);
        vm.expectRevert(WoCoRegistrar.SignatureExpired.selector);
        registrar.setContenthashWithSignature("punkpub", H1, NOW - 1, late);

        uint256 far = NOW + 48 hours + 1;
        bytes memory tooFar = _pointerSig(HOLDER_KEY, node, H1, far);
        vm.expectRevert(WoCoRegistrar.ExpirationTooFar.selector);
        registrar.setContenthashWithSignature("punkpub", H1, far, tooFar);

        // The edges themselves are accepted.
        bytes memory now_ = _pointerSig(HOLDER_KEY, node, H1, NOW);
        registrar.setContenthashWithSignature("punkpub", H1, NOW, now_);
        uint256 edge = NOW + 48 hours;
        bytes memory atEdge = _pointerSig(HOLDER_KEY, node, H2, edge);
        registrar.setContenthashWithSignature("punkpub", H2, edge, atEdge);
        assertEq(registry.contenthash(node), H2);
    }

    function test_unmintedLabelRefused() public {
        bytes memory sig = _sign(HOLDER_KEY, keccak256("anything"));
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.LabelNotRegistered.selector, "nobody"));
        registrar.setContenthashWithSignature("nobody", H1, EXPIRY, sig);
    }

    function test_contractHolderThroughERC1271() public {
        Wallet1271 wallet = new Wallet1271();
        bytes32 node = _mint("punkpub", address(wallet));
        wallet.approve(registrar.setContenthashDigest(node, H1, EXPIRY));

        vm.prank(relayer);
        registrar.setContenthashWithSignature("punkpub", H1, EXPIRY, hex"1271");
        assertEq(registry.contenthash(node), H1);
    }

    function test_contractHolderRefusedWhenItDidNotApprove() public {
        Wallet1271 wallet = new Wallet1271();
        bytes32 node = _mint("punkpub", address(wallet));
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotHolderSignature.selector, node));
        vm.prank(relayer);
        registrar.setContenthashWithSignature("punkpub", H1, EXPIRY, hex"1271");
    }

    /// A holder can always write its own records at the registry with no
    /// registrar at all — the path for a holder whose signature cannot verify
    /// on this chain (a Coinbase Smart Wallet signs for Base).
    function test_holderNeedsNoRegistrarForItsOwnRecords() public {
        bytes32 node = _mint("punkpub", holder);
        vm.prank(holder);
        registry.setContenthash(node, H2);
        assertEq(registry.contenthash(node), H2);
    }

    /// Plain ECDSA is checked first; the validator is not reached.
    function test_aPlainSignatureNeverReachesTheValidator() public {
        bytes32 node = _mint("punkpub", holder);
        bytes memory sig = _pointerSig(HOLDER_KEY, node, H1, EXPIRY);
        vm.mockCallRevert(Validator.ADDR, bytes(""), "validator must not be reached");
        vm.prank(relayer);
        registrar.setContenthashWithSignature("punkpub", H1, EXPIRY, sig);
        assertEq(registry.contenthash(node), H1);
    }

    /*//////////////////////////////////////////////////////////////
        THE HOLDER IS READ AGAIN AFTER THE VALIDATOR (as the registry
        reads the record version again in releaseWithSignature)
    //////////////////////////////////////////////////////////////*/

    /// A validator that has the holder move the name before it answers "yes":
    /// the signature was the old holder's, so the write is refused.
    function test_aNameMovedWhileTheValidatorRanIsRefused() public {
        vm.etch(Validator.ADDR, address(new ActsThenApproves()).code);
        PreparesOnCall1271 wallet = new PreparesOnCall1271(registry, 1, buyer);
        bytes32 node = _mint("punkpub", address(wallet));
        wallet.arm(node, registrar.setContenthashDigest(node, H1, EXPIRY));

        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotHolderSignature.selector, node));
        vm.prank(relayer);
        registrar.setContenthashWithSignature("punkpub", H1, EXPIRY, hex"1271");
        assertEq(registry.owner(node), address(wallet), "the refused call's move was not undone");
    }

    /// The control: an acting validator whose action leaves the holder in place
    /// (it clears the records) is believed — the re-read is about the holder.
    function test_aValidatorThatActsButMovesNothingIsBelieved() public {
        vm.etch(Validator.ADDR, address(new ActsThenApproves()).code);
        PreparesOnCall1271 wallet = new PreparesOnCall1271(registry, 0, buyer);
        bytes32 node = _mint("punkpub", address(wallet));
        wallet.arm(node, registrar.setContenthashDigest(node, H1, EXPIRY));

        vm.prank(relayer);
        registrar.setContenthashWithSignature("punkpub", H1, EXPIRY, hex"1271");
        assertEq(registry.contenthash(node), H1);
    }

    /*//////////////////////////////////////////////////////////////
        THE VALIDATOR'S ANSWER — the registry's rules, in the registrar's
        own copy of the call (audit 950 Low 12 shape)
    //////////////////////////////////////////////////////////////*/

    function _walletName() internal returns (Wallet1271 wallet, bytes32 node) {
        wallet = new Wallet1271();
        node = _mint("punkpub", address(wallet));
        wallet.approve(registrar.setContenthashDigest(node, H1, EXPIRY));
    }

    /// Only a clean one-word `true` is yes.
    function test_validator_anythingButACleanTrueIsARefusal() public {
        (, bytes32 node) = _walletName();
        bytes[4] memory answers =
            [abi.encode(uint256(2)), bytes(""), abi.encodePacked(uint8(1)), abi.encode(uint256(1), uint256(1))];
        for (uint256 i; i < answers.length; ++i) {
            vm.mockCall(Validator.ADDR, bytes(""), answers[i]);
            vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotHolderSignature.selector, node));
            vm.prank(relayer);
            registrar.setContenthashWithSignature("punkpub", H1, EXPIRY, hex"1271");
        }
        vm.mockCall(Validator.ADDR, bytes(""), abi.encode(uint256(1)));
        vm.prank(relayer);
        registrar.setContenthashWithSignature("punkpub", H1, EXPIRY, hex"1271");
        assertEq(registry.contenthash(node), H1, "a clean true was refused");
    }

    /// A revert is a refusal even when its data is the 32 bytes of `true`.
    function test_validator_aRevertCarryingTrueIsStillARefusal() public {
        (, bytes32 node) = _walletName();
        vm.mockCallRevert(Validator.ADDR, bytes(""), abi.encode(uint256(1)));
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotHolderSignature.selector, node));
        vm.prank(relayer);
        registrar.setContenthashWithSignature("punkpub", H1, EXPIRY, hex"1271");
    }

    /// A validator with no code fails closed; the holder's own registry write
    /// still works, so nothing is stranded.
    function test_validator_withNoCodeFailsClosed() public {
        (Wallet1271 wallet, bytes32 node) = _walletName();
        vm.etch(Validator.ADDR, "");
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotHolderSignature.selector, node));
        vm.prank(relayer);
        registrar.setContenthashWithSignature("punkpub", H1, EXPIRY, hex"1271");

        vm.prank(address(wallet));
        registry.setContenthash(node, H1);
        assertEq(registry.contenthash(node), H1);
    }

    /// A validator answering with ~600 KB costs the submitter nothing extra:
    /// one word is copied, never the buffer.
    function test_validator_aReturnDataBombCostsTheSubmitterNothingExtra() public {
        (, bytes32 node) = _walletName();
        vm.etch(Validator.ADDR, address(new ReturnsHugeAnswer()).code);
        bytes memory call_ =
            abi.encodeCall(WoCoRegistrar.setContenthashWithSignature, ("punkpub", H1, EXPIRY, bytes(hex"1271")));

        uint256 before = gasleft();
        vm.prank(relayer);
        (bool ok, bytes memory ret) = address(registrar).call{gas: 20_000_000}(call_);
        uint256 used = before - gasleft();

        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(WoCoRegistrar.NotHolderSignature.selector, node));
        assertLt(used, 1_150_000, "the submitter paid for the validator's answer");
    }

    /*//////////////////////////////////////////////////////////////
        THE NONCE IS SPENT BEFORE THE VALIDATOR IS CALLED (S-04)
    //////////////////////////////////////////////////////////////*/

    /// A validator that re-enters with the SAME signature before answering. The
    /// re-entry sees the moved nonce, so its digest differs and the holder never
    /// approved it: one signature, one write. With the nonce moved AFTER the
    /// validator, the re-entry would see the same digest and write twice.
    function test_aReentrantValidatorGetsOneWriteFromOneSignature() public {
        Wallet1271 wallet = new Wallet1271();
        bytes32 node = _mint("punkpub", address(wallet));
        wallet.approve(registrar.setContenthashDigest(node, H1, EXPIRY));

        vm.etch(Validator.ADDR, address(new ReentersOnce()).code);
        ReentersOnce(Validator.ADDR).arm(registrar, "punkpub", H1, EXPIRY, hex"1271");

        vm.recordLogs();
        vm.prank(relayer);
        registrar.setContenthashWithSignature("punkpub", H1, EXPIRY, hex"1271");

        uint256 writes;
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bytes32 topic = keccak256("ContenthashUpdated(bytes32,string,bytes)");
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter == address(registrar) && logs[i].topics[0] == topic) writes++;
        }
        assertTrue(ReentersOnce(Validator.ADDR).reentered(), "premise: the validator re-entered");
        assertEq(writes, 1, "one signature bought more than one write");
        assertEq(registrar.pointerNonce(node), 1);
    }

    /*//////////////////////////////////////////////////////////////
        TWO DOMAINS, NEVER CROSSED
    //////////////////////////////////////////////////////////////*/

    /// A release signature is not a pointer signature, and a pointer signature
    /// is not a release signature: different domains ("WoCo Names" / "2" on the
    /// registry, "WoCo Registrar" / "1" here) and different types.
    function test_releaseAndPointerSignaturesNeverCross() public {
        bytes32 node = _mint("punkpub", holder);

        bytes memory releaseSig = _sign(HOLDER_KEY, registry.releaseDigest(node, EXPIRY));
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotHolderSignature.selector, node));
        registrar.setContenthashWithSignature("punkpub", H1, EXPIRY, releaseSig);

        bytes memory pointerSig = _pointerSig(HOLDER_KEY, node, H1, EXPIRY);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        registry.releaseWithSignature(node, EXPIRY, holder, pointerSig);

        assertEq(registry.owner(node), holder);
    }

    /// The digest, rebuilt by hand the way a wallet would, is what the
    /// registrar computes — and the vector the app's client pins.
    function test_712_TheDigestIsTheTypedDataAWalletSigns() public {
        bytes32 node = _mint("alice", holder);
        bytes32 domain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("WoCo Registrar"),
                keccak256("1"),
                block.chainid,
                address(registrar)
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("SetContenthash(string name,bytes32 node,bytes contenthash,uint256 nonce,uint256 expiration)"),
                keccak256("alice.woco.eth"),
                node,
                keccak256(H1),
                uint256(0),
                EXPIRY
            )
        );
        assertEq(registrar.setContenthashDigest(node, H1, EXPIRY), keccak256(abi.encodePacked(hex"1901", domain, structHash)));
        assertEq(registrar.SET_CONTENTHASH_TYPEHASH(), keccak256("SetContenthash(string name,bytes32 node,bytes contenthash,uint256 nonce,uint256 expiration)"));
    }

    /// The vector the app's client test pins, on Arbitrum One at a fixed
    /// registrar address. A drift on either side fails a build, not a bind.
    function test_712_ThePinnedVector() public {
        vm.chainId(42161);
        address at = 0x2222222222222222222222222222222222222222;
        deployCodeTo("WoCoRegistrar.sol:WoCoRegistrar", abi.encode(address(registry), sponsor, new string[](0)), at);
        WoCoRegistrar pinned = WoCoRegistrar(at);
        vm.prank(admin);
        registry.addRegistrar(at);
        vm.prank(sponsor);
        bytes32 node = pinned.register("alice", holder);

        assertEq(node, vm.ensNamehash("alice.woco.eth"));
        assertEq(pinned.setContenthashDigest(node, H1, 1_800_000_600), PINNED_POINTER_DIGEST);
    }

    bytes32 constant PINNED_POINTER_DIGEST = 0xef298aebfab76e89d2bc72bf1bbbecf149cee2142b1e44bafcd04fe04607a085;

    /*//////////////////////////////////////////////////////////////
                        REGISTRAR-WIDE MINT CAP
    //////////////////////////////////////////////////////////////*/

    function test_globalCapDefaults() public {
        assertEq(registrar.maxGlobalMintsPerWindow(), 300);
        assertEq(registrar.globalMintWindowSeconds(), 1 hours);
        (uint32 remaining, uint64 resetsAt) = registrar.globalMintAllowance();
        assertEq(remaining, 300);
        assertEq(resetsAt, NOW + 1 hours);

        vm.expectEmit(false, false, false, true);
        emit GlobalMintRateCapSet(300, 1 hours);
        new WoCoRegistrar(address(registry), sponsor, new string[](0));
    }

    function test_globalCapTripsThenResets() public {
        vm.prank(admin);
        registrar.setGlobalMintRateCap(3, 1 hours);

        _mint("aaa", makeAddr("r1"));
        _mint("bbb", makeAddr("r2"));
        _mint("ccc", makeAddr("r3"));
        (uint32 remaining, uint64 resetsAt) = registrar.globalMintAllowance();
        assertEq(remaining, 0);
        assertEq(resetsAt, NOW + 1 hours);

        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.GlobalMintCapExceeded.selector, uint64(NOW + 1 hours)));
        vm.prank(sponsor);
        registrar.register("ddd", makeAddr("r4"));

        vm.warp(NOW + 1 hours);
        _mint("ddd", makeAddr("r4"));
        (remaining,) = registrar.globalMintAllowance();
        assertEq(remaining, 2);
    }

    /// Raising the cap lifts a refusal at once, without closing the window.
    function test_globalCapRaisedLiftsTheRefusalNow() public {
        vm.prank(admin);
        registrar.setGlobalMintRateCap(1, 1 hours);
        _mint("aaa", makeAddr("r1"));
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.GlobalMintCapExceeded.selector, uint64(NOW + 1 hours)));
        vm.prank(sponsor);
        registrar.register("bbb", makeAddr("r2"));

        vm.prank(admin);
        registrar.setGlobalMintRateCap(5, 1 hours);
        _mint("bbb", makeAddr("r2"));
        (, uint64 resetsAt) = registrar.globalMintAllowance();
        assertEq(resetsAt, NOW + 1 hours, "retuning moved the open window's end");
    }

    function test_globalCapDoesNotChargeARetake() public {
        vm.prank(admin);
        registrar.setGlobalMintRateCap(1, 1 hours);

        bytes32 node = _mint("aaa", holder);
        vm.prank(holder);
        registry.release(node);

        _mint("aaa", holder); // retake: charged to neither window
        (uint32 remaining,) = registrar.globalMintAllowance();
        assertEq(remaining, 0);

        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.GlobalMintCapExceeded.selector, uint64(NOW + 1 hours)));
        vm.prank(sponsor);
        registrar.register("bbb", stranger);
    }

    /// Both caps charge the same mint, and the recipient's refusal comes first.
    function test_bothCapsChargeOneMint() public {
        address r = makeAddr("r");
        _mint("aaa", r);
        (, uint32 recipientCount) = registrar.mintWindow(r);
        (, uint32 globalCount) = registrar.globalMintWindow();
        assertEq(recipientCount, 1);
        assertEq(globalCount, 1);
    }

    function test_globalCapIsOwnerTunedOnly() public {
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotRegistryAdmin.selector, sponsor));
        vm.prank(sponsor);
        registrar.setGlobalMintRateCap(1_000_000, 1 hours);

        // Read before the prank: a view call in the arguments would consume it.
        uint64 maxWindow = registrar.MAX_MINT_WINDOW_SECONDS();
        vm.startPrank(admin);
        vm.expectRevert(WoCoRegistrar.InvalidMintRateCap.selector);
        registrar.setGlobalMintRateCap(0, 1 hours);
        vm.expectRevert(WoCoRegistrar.InvalidMintRateCap.selector);
        registrar.setGlobalMintRateCap(1, 0);
        vm.expectRevert(WoCoRegistrar.InvalidMintRateCap.selector);
        registrar.setGlobalMintRateCap(1, maxWindow + 1);
        registrar.setGlobalMintRateCap(1, maxWindow);
        vm.stopPrank();
    }

    /// Pointer writes are NOT capped: they are holder-signed, so a cap would
    /// only ever refuse a holder's own instruction.
    function test_pointerWritesAreNotCapped() public {
        vm.prank(admin);
        registrar.setGlobalMintRateCap(1, 1 hours);
        bytes32 node = _mint("aaa", holder);
        for (uint256 i; i < 5; ++i) {
            bytes memory sig = _pointerSig(HOLDER_KEY, node, H1, EXPIRY);
            vm.prank(relayer);
            registrar.setContenthashWithSignature("aaa", H1, EXPIRY, sig);
        }
        assertEq(registrar.pointerNonce(node), 5);
    }
}

/// @dev The smallest ERC-1271 wallet: approves exact digests.
contract Wallet1271 is IERC1271 {
    mapping(bytes32 => bool) public approved;

    function approve(bytes32 digest) external {
        approved[digest] = true;
    }

    function isValidSignature(bytes32 hash, bytes memory) external view returns (bytes4) {
        return approved[hash] ? IERC1271.isValidSignature.selector : bytes4(0);
    }
}

/// @dev A validator that, the first time it is asked, re-enters the registrar
///      with the same arguments before asking the signer. Etched over the
///      pinned validator. Test-only.
contract ReentersOnce {
    WoCoRegistrar internal registrar;
    string internal label;
    bytes internal contenthash;
    uint256 internal expiration;
    bytes internal signature;
    bool public reentered;

    function arm(WoCoRegistrar r, string calldata l, bytes calldata ch, uint256 exp, bytes calldata sig) external {
        registrar = r;
        label = l;
        contenthash = ch;
        expiration = exp;
        signature = sig;
    }

    function isValidSig(address signer, bytes32 hash, bytes calldata) external returns (bool) {
        if (!reentered) {
            reentered = true;
            try registrar.setContenthashWithSignature(label, contenthash, expiration, signature) {} catch {}
        }
        return IERC1271(signer).isValidSignature(hash, "") == IERC1271.isValidSignature.selector;
    }
}

/// @dev A validator whose answer is a ~600 KB buffer of zeros. Test-only.
contract ReturnsHugeAnswer {
    fallback() external {
        assembly {
            return(0, 600000)
        }
    }
}
