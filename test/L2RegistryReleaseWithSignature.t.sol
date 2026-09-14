// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {WoCoRegistrar} from "../src/WoCoRegistrar.sol";
import {L2Registry} from "../src/durin/L2Registry.sol";
import {L2Resolver} from "../src/durin/L2Resolver.sol";
import {UniversalSigValidatorFixture as Validator} from "./fixtures/UniversalSigValidatorFixture.sol";

/**
 * Tests for `L2Registry.releaseWithSignature` — `release` authorised by the
 * holder's signature so that someone else (the platform) may submit and pay.
 * Added for WoCo-Event-App #464 on 2026-09-03; like the other two files it
 * freezes a SHAPE, because the registry is an unpatchable clone. The promise:
 *
 *   "If you sign a release, anyone can hand it in for you — but only for the
 *    name, the registry, the chain and the deadline you signed, only once,
 *    and only if you could have released it yourself. Nobody can turn any
 *    other signature of yours into a release."
 *
 * The signature checks run against the REAL ERC-6492 validator bytecode
 * (etched from Arbitrum Sepolia, see the fixture), not a stand-in.
 */
contract L2RegistryReleaseWithSignatureTest is Test {
    using MessageHashUtils for bytes32;

    L2Registry registry;
    WoCoRegistrar registrar;

    address admin = makeAddr("admin");
    address sponsor = makeAddr("sponsor");
    /// The platform's hot wallet in production: it pays, it never authorises.
    address relayer = makeAddr("relayer");

    uint256 constant HOLDER_KEY = 0xA11CE;
    uint256 constant STRANGER_KEY = 0xB0B;
    uint256 constant APPROVEE_KEY = 0xCA7;
    address holder = vm.addr(HOLDER_KEY);
    address stranger = vm.addr(STRANGER_KEY);
    address approvee = vm.addr(APPROVEE_KEY);

    uint256 constant NOW = 1_800_000_000;
    uint256 constant EXPIRY = NOW + 15 minutes;

    bytes constant SWARM_HASH =
        hex"e40101fa011b20d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162";

    event Released(bytes32 indexed node, address indexed previousOwner, address indexed operator);
    event VersionChanged(bytes32 indexed node, uint64 newVersion);
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    function setUp() public {
        vm.etch(Validator.ADDR, Validator.CODE);

        registry = L2Registry(Clones.clone(address(new L2Registry())));
        registry.initialize("woco.eth", "WoCo Names", "", admin);
        registrar = new WoCoRegistrar(address(registry), admin, sponsor, new string[](0));

        vm.prank(admin);
        registry.addRegistrar(address(registrar));

        vm.warp(NOW);
    }

    function _register(string memory label, address owner_) internal returns (bytes32 node) {
        string[] memory keys = new string[](1);
        string[] memory vals = new string[](1);
        keys[0] = "url";
        vals[0] = "https://old-holder.example";
        vm.prank(sponsor);
        registrar.register(label, owner_, SWARM_HASH, keys, vals);
        node = registry.makeNode(registry.baseNode(), label);
    }

    function _sign(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signRelease(uint256 key, bytes32 node) internal view returns (bytes memory) {
        return _sign(key, registry.releaseDigest(node, EXPIRY));
    }

    /*//////////////////////////////////////////////////////////////
                          THE RAIL WORKS
    //////////////////////////////////////////////////////////////*/

    function test_ReleaseWithSignature_AStrangerMaySubmitWhatTheHolderSigned() public {
        bytes32 node = _register("venue", holder);
        bytes memory sig = _signRelease(HOLDER_KEY, node);

        // `operator` is the SIGNER, not the relayer that paid.
        vm.expectEmit(true, true, true, true, address(registry));
        emit Released(node, holder, holder);

        vm.prank(relayer);
        registry.releaseWithSignature(node, EXPIRY, holder, sig);

        assertEq(registry.owner(node), address(0), "burned");
        assertEq(registry.balanceOf(holder), 0);
        assertEq(registry.balanceOf(relayer), 0, "the relayer gained nothing");
        assertTrue(registrar.available("venue"), "label back in the pool");
    }

    function test_ReleaseWithSignature_HasExactlyReleasesEffects() public {
        bytes32 a = _register("bysender", holder);
        bytes32 b = _register("bysig", holder);
        uint256 supplyBefore = registry.totalSupply();

        vm.prank(holder);
        registry.release(a);
        vm.prank(relayer);
        registry.releaseWithSignature(b, EXPIRY, holder, _signRelease(HOLDER_KEY, b));

        assertEq(registry.totalSupply(), supplyBefore - 2, "both decrement supply");
        assertEq(registry.contenthash(a).length, 0, "records cleared (sender path)");
        assertEq(registry.contenthash(b).length, 0, "records cleared (signature path)");
        assertEq(registry.recordVersions(a), registry.recordVersions(b), "same version bump");
        (address prevA, uint64 atA) = registry.lastRelease(a);
        (address prevB, uint64 atB) = registry.lastRelease(b);
        assertEq(prevA, prevB);
        assertEq(atA, atB);
        assertEq(prevB, holder);
        assertEq(atB, uint64(NOW));
    }

    /// The mint moved the record version to 1; the burn moves it to 2.
    function test_ReleaseWithSignature_EmitsTheSameThreeEvents() public {
        bytes32 node = _register("venue", holder);
        bytes memory sig = _signRelease(HOLDER_KEY, node);

        vm.expectEmit(true, true, true, true, address(registry));
        emit Transfer(holder, address(0), uint256(node));
        vm.expectEmit(true, true, true, true, address(registry));
        emit VersionChanged(node, 2);
        vm.expectEmit(true, true, true, true, address(registry));
        emit Released(node, holder, holder);

        vm.prank(relayer);
        registry.releaseWithSignature(node, EXPIRY, holder, sig);
    }

    function test_ReleaseWithSignature_ByPerTokenApprovee() public {
        bytes32 node = _register("venue", holder);
        vm.prank(holder);
        registry.approve(approvee, uint256(node));

        bytes memory sig = _signRelease(APPROVEE_KEY, node);

        vm.expectEmit(true, true, true, true, address(registry));
        emit Released(node, holder, approvee);

        vm.prank(relayer);
        registry.releaseWithSignature(node, EXPIRY, approvee, sig);
        assertEq(registry.owner(node), address(0));
    }

    function test_ReleaseWithSignature_ByOperatorForAll() public {
        bytes32 node = _register("venue", holder);
        vm.prank(holder);
        registry.setApprovalForAll(approvee, true);
        bytes memory sig = _signRelease(APPROVEE_KEY, node);

        vm.prank(relayer);
        registry.releaseWithSignature(node, EXPIRY, approvee, sig);
        assertEq(registry.owner(node), address(0));
    }

    /// A smart-account holder: the validator routes to ERC-1271 and the wallet
    /// answers for its own signature. This is the passkey / email path. The
    /// wallet implements no ERC-721 receiver: a v2 mint never asks for one.
    function test_ReleaseWithSignature_ContractWalletThroughERC1271() public {
        Wallet1271 wallet = new Wallet1271();
        bytes32 node = _register("venue", address(wallet));
        bytes32 digest = registry.releaseDigest(node, EXPIRY);
        wallet.approveHash(digest);

        vm.expectEmit(true, true, true, true, address(registry));
        emit Released(node, address(wallet), address(wallet));

        vm.prank(relayer);
        registry.releaseWithSignature(node, EXPIRY, address(wallet), hex"1271");
        assertEq(registry.owner(node), address(0));
    }

    function test_ReleaseWithSignature_ContractWalletThatDoesNotApproveIsRefused() public {
        Wallet1271 wallet = new Wallet1271();
        bytes32 node = _register("venue", address(wallet));
        // Approved SOME hash, not this digest.
        wallet.approveHash(keccak256("something else"));

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        registry.releaseWithSignature(node, EXPIRY, address(wallet), hex"1271");
        assertEq(registry.owner(node), address(wallet), "still held");
    }

    /*//////////////////////////////////////////////////////////////
                 PLAIN ECDSA FIRST, THE VALIDATOR ON A MISS
    //////////////////////////////////////////////////////////////*/

    /// A plain key signature is settled by ECDSA recovery alone. With the
    /// validator made to explode, an EOA holder's release still goes through —
    /// so the validator, and its counterfactual-deploy path, was never touched.
    function test_ReleaseWithSignature_APlainSignatureNeverReachesTheValidator() public {
        bytes32 node = _register("venue", holder);
        bytes memory sig = _signRelease(HOLDER_KEY, node);
        vm.mockCallRevert(Validator.ADDR, bytes(""), "validator must not be reached");

        vm.prank(relayer);
        registry.releaseWithSignature(node, EXPIRY, holder, sig);
        assertEq(registry.owner(node), address(0));
    }

    /// Audit 924 F-11. An EOA with an EIP-7702 delegation has code, so the
    /// validator asks its delegate through ERC-1271 — and a delegate need not
    /// accept the account key's own signature. Pinned both ways: the real
    /// validator refuses the key's signature for such an account, and the
    /// registry accepts it, because recovery is tried first.
    function test_ReleaseWithSignature_A7702DelegatedEoaSignsWithItsOwnKey() public {
        uint256 key = 0x7702;
        address account = vm.addr(key);
        Wallet1271 delegate = new Wallet1271(); // approves nothing
        vm.signAndAttachDelegation(address(delegate), key);
        bytes32 node = _register("venue", account);
        assertGt(account.code.length, 0, "premise: the delegated account has code");

        bytes memory sig = _signRelease(key, node);
        bytes32 digest = registry.releaseDigest(node, EXPIRY);
        (bool ok, bytes memory ret) = Validator.ADDR.call(
            abi.encodeWithSignature("isValidSig(address,bytes32,bytes)", account, digest, sig)
        );
        assertTrue(ok, "premise: the validator answers");
        assertFalse(abi.decode(ret, (bool)), "premise: the validator refuses the key's signature for a delegated account");

        vm.prank(relayer);
        registry.releaseWithSignature(node, EXPIRY, account, sig);
        assertEq(registry.owner(node), address(0), "the account's own key could not release its name");
    }

    /*//////////////////////////////////////////////////////////////
                 ONLY WHO COULD HAVE RELEASED IT THEMSELVES
    //////////////////////////////////////////////////////////////*/

    function test_ReleaseWithSignature_RevertForAStrangerSigner() public {
        bytes32 node = _register("venue", holder);
        bytes memory sig = _signRelease(STRANGER_KEY, node); // valid, for the wrong person

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        registry.releaseWithSignature(node, EXPIRY, stranger, sig);
        assertEq(registry.owner(node), holder);
    }

    /// The authorisation check comes BEFORE the signature is examined: with the
    /// validator made to explode, a stranger is still refused with our own
    /// error, proving the validator was never reached for them.
    function test_ReleaseWithSignature_StrangerIsRefusedBeforeTheValidatorIsConsulted() public {
        bytes32 node = _register("venue", holder);
        bytes memory sig = _signRelease(STRANGER_KEY, node);
        vm.mockCallRevert(Validator.ADDR, bytes(""), "validator must not be reached");

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        registry.releaseWithSignature(node, EXPIRY, stranger, sig);
    }

    function test_ReleaseWithSignature_RevertWhenTheSignatureIsNotTheSigners() public {
        bytes32 node = _register("venue", holder);
        bytes memory sig = _signRelease(STRANGER_KEY, node); // names the holder, signed by another

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        registry.releaseWithSignature(node, EXPIRY, holder, sig);
        assertEq(registry.owner(node), holder);
    }

    function test_ReleaseWithSignature_RevokedApproveeCannotRelease() public {
        bytes32 node = _register("venue", holder);
        vm.startPrank(holder);
        registry.approve(approvee, uint256(node));
        registry.approve(address(0), uint256(node));
        vm.stopPrank();
        bytes memory sig = _signRelease(APPROVEE_KEY, node);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        registry.releaseWithSignature(node, EXPIRY, approvee, sig);
        assertEq(registry.owner(node), holder);
    }

    /// Registrars and the admin can sign like anyone else — and are refused
    /// like anyone else. No platform power arrives through this door.
    function test_ReleaseWithSignature_PlatformSignaturesAreRefused() public {
        bytes32 node = _register("venue", holder);
        uint256 adminKey = 0xAD;
        address adminSigner = vm.addr(adminKey);
        vm.prank(admin);
        registry.addRegistrar(adminSigner);
        assertTrue(registry.registrars(adminSigner), "precondition: a registrar");
        // NB: the helper makes a view call; it must run BEFORE the prank and the
        // expectRevert, or those attach to it instead of to the release.
        bytes memory sig = _signRelease(adminKey, node);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        registry.releaseWithSignature(node, EXPIRY, adminSigner, sig);
        assertEq(registry.owner(node), holder);
    }

    /*//////////////////////////////////////////////////////////////
              ONLY THIS NAME, THIS REGISTRY, THIS CHAIN, ONCE
    //////////////////////////////////////////////////////////////*/

    function test_ReleaseWithSignature_RevertWhenExpired() public {
        bytes32 node = _register("venue", holder);
        bytes memory sig = _signRelease(HOLDER_KEY, node);
        vm.warp(EXPIRY + 1);

        vm.prank(relayer);
        vm.expectRevert(L2Registry.SignatureExpired.selector);
        registry.releaseWithSignature(node, EXPIRY, holder, sig);
    }

    function test_ReleaseWithSignature_ValidUntilTheLastSecond() public {
        bytes32 node = _register("venue", holder);
        bytes memory sig = _signRelease(HOLDER_KEY, node);
        vm.warp(EXPIRY);

        vm.prank(relayer);
        registry.releaseWithSignature(node, EXPIRY, holder, sig);
        assertEq(registry.owner(node), address(0));
    }

    function test_ReleaseWithSignature_CannotBeReplayedAgainstAReMint() public {
        bytes32 node = _register("venue", holder);
        bytes memory sig = _signRelease(HOLDER_KEY, node);
        bytes32 digestBefore = registry.releaseDigest(node, EXPIRY);

        vm.prank(relayer);
        registry.releaseWithSignature(node, EXPIRY, holder, sig);

        // Same label, same holder, minted again — a real sequence when a user
        // frees a name and takes it back.
        bytes32 again = _register("venue", holder);
        assertEq(again, node, "precondition: same node");
        assertTrue(registry.releaseDigest(node, EXPIRY) != digestBefore, "the digest moved with the version");

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        registry.releaseWithSignature(node, EXPIRY, holder, sig);
        assertEq(registry.owner(node), holder, "the re-minted name survives the replay");
    }

    /// A signature dies when the name changes hands, even if it comes straight
    /// back: v1 bumped the version only on release, so a holder who sold a name
    /// and bought it back found their old signature live again.
    function test_ReleaseWithSignature_DiesWhenTheNameChangesHandsAndReturns() public {
        bytes32 node = _register("venue", holder);
        bytes memory sig = _signRelease(HOLDER_KEY, node);

        vm.prank(holder);
        registry.transferFrom(holder, stranger, uint256(node));
        vm.prank(stranger);
        registry.transferFrom(stranger, holder, uint256(node));
        assertEq(registry.owner(node), holder, "precondition: back with the signer");

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        registry.releaseWithSignature(node, EXPIRY, holder, sig);
        assertEq(registry.owner(node), holder);
    }

    function test_ReleaseWithSignature_CannotBeReplayedOnAnotherRegistry() public {
        bytes32 node = _register("venue", holder);
        bytes memory sig = _signRelease(HOLDER_KEY, node);

        // A second registry with the same parent name: identical node, same holder.
        L2Registry other = L2Registry(Clones.clone(address(new L2Registry())));
        other.initialize("woco.eth", "WoCo Names", "", admin);
        WoCoRegistrar otherRegistrar = new WoCoRegistrar(address(other), admin, sponsor, new string[](0));
        vm.prank(admin);
        other.addRegistrar(address(otherRegistrar));
        vm.prank(sponsor);
        otherRegistrar.register("venue", holder, SWARM_HASH, new string[](0), new string[](0));
        assertEq(other.owner(node), holder, "precondition: same node, same holder, other registry");
        assertEq(other.recordVersions(node), registry.recordVersions(node), "precondition: same record version");

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        other.releaseWithSignature(node, EXPIRY, holder, sig);
    }

    function test_ReleaseWithSignature_CannotBeReplayedOnAnotherChain() public {
        bytes32 node = _register("venue", holder);
        bytes memory sig = _signRelease(HOLDER_KEY, node);

        vm.chainId(42161);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        registry.releaseWithSignature(node, EXPIRY, holder, sig);
    }

    /// The domain tag is what separates a release from any other 32-byte
    /// personal-sign message of the holder's: the same fields signed WITHOUT
    /// the typehash are refused.
    function test_ReleaseWithSignature_TheSameFieldsWithoutTheTypehashAreRefused() public {
        bytes32 node = _register("venue", holder);
        bytes32 untagged = keccak256(
            abi.encode(address(registry), block.chainid, node, registry.recordVersions(node), EXPIRY)
        ).toEthSignedMessageHash();
        bytes memory sig = _sign(HOLDER_KEY, untagged);

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        registry.releaseWithSignature(node, EXPIRY, holder, sig);
        assertEq(registry.owner(node), holder, "the name survives");
    }

    /*//////////////////////////////////////////////////////////////
                        THE SAME REFUSALS AS RELEASE
    //////////////////////////////////////////////////////////////*/

    function test_ReleaseWithSignature_RevertOnBaseNode() public {
        bytes32 base = registry.baseNode();
        bytes memory sig = _sign(HOLDER_KEY, registry.releaseDigest(base, EXPIRY));

        vm.prank(relayer);
        vm.expectRevert(L2Registry.ReleaseBaseNode.selector);
        registry.releaseWithSignature(base, EXPIRY, holder, sig);
    }

    function test_ReleaseWithSignature_RevertOnUnregisteredName() public {
        bytes32 node = registry.makeNode(registry.baseNode(), "nobody");
        bytes memory sig = _sign(HOLDER_KEY, registry.releaseDigest(node, EXPIRY));

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(L2Registry.ReleaseUnregistered.selector, node));
        registry.releaseWithSignature(node, EXPIRY, holder, sig);
    }

    /*//////////////////////////////////////////////////////////////
                     THE DIGEST IS PINNED FOR CLIENTS
    //////////////////////////////////////////////////////////////*/

    /// A client that rebuilds the digest instead of reading it must land on
    /// the same bytes; and the typehash string is frozen with the registry.
    /// The record version at mint is 1: the mint is an ownership change.
    function test_ReleaseWithSignature_DigestFormulaIsPinned() public {
        bytes32 node = _register("venue", holder);
        assertEq(registry.recordVersions(node), 1, "a fresh name's record version");
        bytes32 expected = keccak256(
            abi.encode(
                keccak256(
                    "WoCoRelease(address registry,uint256 chainId,bytes32 node,uint64 recordVersion,uint256 expiration)"
                ),
                address(registry),
                block.chainid,
                node,
                uint64(1),
                EXPIRY
            )
        ).toEthSignedMessageHash();
        assertEq(registry.releaseDigest(node, EXPIRY), expected);
        // Frozen with the registry: a different string here is a different contract.
        assertEq(registry.RELEASE_TYPEHASH(), 0x07afadc76277c3eeb107a6e5f76aa8a4a6a8cb3439a468c964f320f452f1bdfc);
    }
}

/// @dev The smallest possible ERC-1271 wallet: approves exact digests. No
///      ERC-721 receiver, on purpose: a v2 mint calls nothing on its recipient.
contract Wallet1271 is IERC1271 {
    mapping(bytes32 => bool) public approved;

    function approveHash(bytes32 hash) external {
        approved[hash] = true;
    }

    function isValidSignature(bytes32 hash, bytes memory) external view returns (bytes4) {
        return approved[hash] ? IERC1271.isValidSignature.selector : bytes4(0);
    }
}
