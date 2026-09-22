// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {WoCoRegistrar} from "../src/WoCoRegistrar.sol";
import {L2Registry} from "../src/durin/L2Registry.sol";
import {L2Resolver} from "../src/durin/L2Resolver.sol";

contract WoCoRegistrarTest is Test {
    L2Registry registry;
    WoCoRegistrar registrar;

    event NameRegistered(bytes32 indexed node, string label, address indexed owner);
    event ContenthashUpdated(bytes32 indexed node, string label, bytes contenthash);

    address admin = makeAddr("admin");
    address sponsor = makeAddr("sponsor");
    address organiser;
    uint256 organiserKey;
    address stranger = makeAddr("stranger");

    // A short Swarm bzz reference, ENS contenthash-encoded bytes (shape only).
    bytes constant SWARM_HASH = hex"e40101fa011b20d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162";

    function setUp() public {
        (organiser, organiserKey) = makeAddrAndKey("organiser");
        registry = L2Registry(Clones.clone(address(new L2Registry())));
        registry.initialize("woco.eth", "WoCo Names", "", admin);

        registrar = new WoCoRegistrar(address(registry), sponsor, _reserved());

        vm.prank(admin);
        registry.addRegistrar(address(registrar));
    }

    /*//////////////////////////////////////////////////////////////
                              HELPERS
    //////////////////////////////////////////////////////////////*/

    function _reserved() internal pure returns (string[] memory labels) {
        labels = new string[](1);
        labels[0] = "admin";
    }

    /// The organiser's signature over the pointer digest, as the app builds it.
    function _pointerSig(bytes32 node, bytes memory ch, uint256 expiration) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(organiserKey, registrar.setContenthashDigest(node, ch, expiration));
        return abi.encodePacked(r, s, v);
    }

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTION
    //////////////////////////////////////////////////////////////*/

    /// Sponsor and reserved labels are set by the constructor. There is no
    /// owner to set: the registry's admin is the owner from the first block, so
    /// no deployer key holds the role even for a block, and no ownership event
    /// is ever emitted.
    function test_constructor_sponsorAndReservedLabelsFromTheFirstBlock_ownerIsTheRegistryAdmin() public {
        vm.recordLogs();
        WoCoRegistrar fresh = new WoCoRegistrar(address(registry), sponsor, _reserved());
        Vm.Log[] memory logs = vm.getRecordedLogs();

        assertEq(fresh.owner(), admin);
        assertEq(fresh.owner(), registry.owner());
        assertTrue(fresh.authorisedSponsors(sponsor), "sponsor not authorised");
        assertTrue(fresh.reserved(keccak256("admin")), "reserved label not reserved");
        assertFalse(fresh.available("admin"));
        assertEq(address(fresh.registry()), address(registry));
        assertEq(fresh.coinType(), 0x80000000 | block.chainid);

        bytes32 ownershipTransferred = keccak256("OwnershipTransferred(address,address)");
        bytes32 transferStarted = keccak256("OwnershipTransferStarted(address,address)");
        for (uint256 i; i < logs.length; ++i) {
            assertTrue(logs[i].topics[0] != transferStarted, "an ownership handover was started");
            assertTrue(logs[i].topics[0] != ownershipTransferred, "an ownership event was emitted");
        }
    }

    /// Audit 937 F11: a reserved label `register` would never see reserves
    /// nothing. Refused at construction as it is in `setReserved`.
    function test_constructor_refusesAReservedLabelRegisterWouldReject() public {
        string[] memory labels = new string[](2);
        labels[0] = "admin";
        labels[1] = "WoCo";
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.InvalidLabel.selector, "WoCo"));
        new WoCoRegistrar(address(registry), sponsor, labels);
    }

    /// No transaction comes from the zero address, so a zero sponsor authorises
    /// nobody — but `authorisedSponsors(0)` reading true would let a deploy with
    /// an unset sponsor pass its checks with no working one.
    function test_constructor_refusesTheZeroSponsor() public {
        vm.expectRevert(WoCoRegistrar.SponsorIsZeroAddress.selector);
        new WoCoRegistrar(address(registry), address(0), _reserved());
    }

    function test_addSponsor_refusesTheZeroAddress() public {
        vm.expectRevert(WoCoRegistrar.SponsorIsZeroAddress.selector);
        vm.prank(admin);
        registrar.addSponsor(address(0));
        assertFalse(registrar.authorisedSponsors(address(0)));
    }

    /// Nor through the registrar can a name be minted to the zero address:
    /// "held by nobody" is what `available` and the pointer write read as free.
    function test_register_refusesTheZeroAddressAsHolder() public {
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("ERC721InvalidReceiver(address)")), address(0)));
        vm.prank(sponsor);
        registrar.register("myband", address(0));
        assertTrue(registrar.available("myband"));
    }

    /*//////////////////////////////////////////////////////////////
                          register() — sponsor path
    //////////////////////////////////////////////////////////////*/

    /// v2.2 (sponsor-key consult): the mint writes the name, its holder and the
    /// holder's own address records — and nothing a sponsor could choose.
    function test_register_mintsToOrganiserWithOnlyItsOwnAddressRecords() public {
        vm.prank(sponsor);
        bytes32 node = registrar.register("myband", organiser);

        assertEq(registry.owner(node), organiser, "organiser owns the name");
        assertEq(registry.addr(node), organiser, "addr(60) is the organiser");
        assertEq(registry.addr(node, registrar.coinType()), abi.encodePacked(organiser), "chain addr is the organiser");
        assertEq(registry.contenthash(node).length, 0, "the mint wrote a pointer");
        assertEq(bytes(registry.text(node, "description")).length, 0, "the mint wrote a text record");
        assertFalse(registrar.available("myband"), "no longer available");
    }

    /// The holder writes its own profile records at the registry: no registrar,
    /// no sponsor, no signature.
    function test_register_theHolderWritesItsOwnTextRecords() public {
        vm.prank(sponsor);
        bytes32 node = registrar.register("craufurd-arms", organiser);

        vm.prank(organiser);
        registry.setText(node, "description", "Independent music venue");
        assertEq(registry.text(node, "description"), "Independent music venue");
    }

    function test_register_revertsForNonSponsor() public {
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotAuthorisedSponsor.selector, stranger));
        vm.prank(stranger);
        registrar.register("myband", organiser);
    }

    function test_register_revertsForReservedLabel() public {
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.LabelIsReserved.selector, "admin"));
        vm.prank(sponsor);
        registrar.register("admin", organiser);
    }

    function test_register_revertsForInvalidLabel() public {
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.InvalidLabel.selector, "My-Band"));
        vm.prank(sponsor);
        registrar.register("My-Band", organiser);
    }

    /// The single ownership check sits after the LAST record write — the ETH
    /// address record. Against a registry that hands the name away during that
    /// write, registration is refused — so a check moved any earlier would let
    /// this through.
    function test_register_refusesWhenTheNameMovesDuringTheLastWrite() public {
        DivertingRegistry diverting = new DivertingRegistry(stranger);
        WoCoRegistrar r = new WoCoRegistrar(address(diverting), sponsor, new string[](0));
        bytes32 node = diverting.makeNode(diverting.baseNode(), "myband");

        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NameMovedDuringRegistration.selector, node));
        vm.prank(sponsor);
        r.register("myband", organiser);
    }

    /// The control for the test above: the same stand-in, told not to divert,
    /// registers normally. The refusal is about the move.
    function test_register_theStandInRegistersWhenNothingMoves() public {
        DivertingRegistry diverting = new DivertingRegistry(address(0));
        WoCoRegistrar r = new WoCoRegistrar(address(diverting), sponsor, new string[](0));

        vm.prank(sponsor);
        bytes32 node = r.register("myband", organiser);
        assertEq(diverting.owner(node), organiser);
    }

    /*//////////////////////////////////////////////////////////////
          setContenthashWithSignature — the one post-mint write
          (the deep cases live in WoCoRegistrarSignedPointer.t.sol)
    //////////////////////////////////////////////////////////////*/

    function test_pointer_theHoldersSignatureRepointsOnRedeploy() public {
        vm.prank(sponsor);
        bytes32 node = registrar.register("myband", organiser);

        bytes memory newHash = hex"e40101fa011b2000000000000000000000000000000000000000000000000000000000deadbeef";
        uint256 expiration = block.timestamp + 10 minutes;
        bytes memory sig = _pointerSig(node, newHash, expiration);
        vm.prank(sponsor);
        registrar.setContenthashWithSignature("myband", newHash, expiration, sig);

        assertEq(registry.contenthash(node), newHash);
    }

    /// v2.2: the sponsor-only setter is gone. A sponsor holding no signature
    /// cannot repoint a name, and the old selector reaches no function.
    function test_pointer_theSponsorAloneCannotRepoint() public {
        vm.prank(sponsor);
        bytes32 node = registrar.register("myband", organiser);

        (bool ok, bytes memory ret) =
            address(registrar).call(abi.encodeWithSignature("setContenthash(string,bytes)", "myband", SWARM_HASH));
        assertFalse(ok, "the sponsor-only setter still answers");
        assertEq(ret.length, 0, "the sponsor-only setter reverted from inside a function, so it exists");

        uint256 expiration = block.timestamp + 10 minutes;
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotHolderSignature.selector, node));
        vm.prank(sponsor);
        registrar.setContenthashWithSignature("myband", SWARM_HASH, expiration, hex"00");
        assertEq(registry.contenthash(node).length, 0);
    }

    /// Audit 925 finding 2 / 927 H2. A pointer set on a label nobody holds would
    /// have become its first holder's site. Refused by name, and the first
    /// holder's records start empty.
    function test_pointer_refusesALabelNobodyHolds() public {
        bytes memory seeded = hex"e40101fa011b201111111111111111111111111111111111111111111111111111111111111111";
        uint256 expiration = block.timestamp + 10 minutes;
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.LabelNotRegistered.selector, "future"));
        vm.prank(sponsor);
        registrar.setContenthashWithSignature("future", seeded, expiration, hex"00");

        vm.prank(sponsor);
        bytes32 node = registrar.register("future", organiser);
        assertEq(registry.contenthash(node).length, 0, "the first holder inherited a pointer");
    }

    function test_pointer_refusesEmpty() public {
        vm.prank(sponsor);
        bytes32 node = registrar.register("myband", organiser);
        uint256 expiration = block.timestamp + 10 minutes;
        bytes memory sig = _pointerSig(node, "", expiration);

        vm.expectRevert(WoCoRegistrar.EmptyContenthash.selector);
        registrar.setContenthashWithSignature("myband", "", expiration, sig);
    }

    /// Audit 937 F5: a label `register` would refuse is refused here too, in
    /// the same order — so a reserved name the platform minted through another
    /// registrar is out of this registrar's reach, signature or not.
    function test_pointer_refusesAReservedOrInvalidLabel() public {
        bytes32 base = registry.baseNode();
        bytes[] memory none = new bytes[](0);
        vm.startPrank(admin);
        registry.addRegistrar(admin);
        bytes32 reservedNode = registry.createSubnode(base, "admin", organiser, none);
        bytes32 casedNode = registry.createSubnode(base, "MyBand", organiser, none);
        vm.stopPrank();
        uint256 expiration = block.timestamp + 10 minutes;

        vm.startPrank(sponsor);
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.LabelIsReserved.selector, "admin"));
        registrar.setContenthashWithSignature("admin", SWARM_HASH, expiration, hex"00");
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.InvalidLabel.selector, "MyBand"));
        registrar.setContenthashWithSignature("MyBand", SWARM_HASH, expiration, hex"00");
        // Invalid before reserved before empty, as in `register`.
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.InvalidLabel.selector, "MyBand"));
        registrar.setContenthashWithSignature("MyBand", "", expiration, hex"00");
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.LabelIsReserved.selector, "admin"));
        registrar.setContenthashWithSignature("admin", "", expiration, hex"00");
        vm.stopPrank();

        assertEq(registry.contenthash(reservedNode).length, 0);
        assertEq(registry.contenthash(casedNode).length, 0);
    }

    /// Anyone may submit a holder's signature: relaying needs no role.
    function test_pointer_anyoneMayRelayTheHoldersSignature() public {
        vm.prank(sponsor);
        bytes32 node = registrar.register("myband", organiser);
        uint256 expiration = block.timestamp + 10 minutes;
        bytes memory sig = _pointerSig(node, hex"e301", expiration);

        vm.prank(stranger);
        registrar.setContenthashWithSignature("myband", hex"e301", expiration, sig);
        assertEq(registry.contenthash(node), hex"e301");
    }

    /*//////////////////////////////////////////////////////////////
                           VALIDATION + ADMIN
    //////////////////////////////////////////////////////////////*/

    function test_validation_rejectsBadLabels() public view {
        assertFalse(registrar.available("ab"), "too short");
        assertFalse(registrar.available("-myband"), "leading hyphen");
        assertFalse(registrar.available("myband-"), "trailing hyphen");
        assertFalse(registrar.available("my--band"), "double hyphen");
        assertFalse(registrar.available("MyBand"), "uppercase");
        assertFalse(registrar.available("my_band"), "underscore");
        assertFalse(registrar.available("admin"), "reserved");
        assertTrue(registrar.available("my-band-3"), "valid label");
    }

    function test_available_falseAfterMint() public {
        assertTrue(registrar.available("myband"));
        vm.prank(sponsor);
        registrar.register("myband", organiser);
        assertFalse(registrar.available("myband"));
    }

    /// Every lever answers to the registry admin alone — not a stranger, not a
    /// sponsor, not the registrar's own registry holder-side.
    function test_admin_everyPolicyLeverIsOwnerOnly() public {
        address[2] memory callers = [stranger, sponsor];
        for (uint256 i; i < callers.length; ++i) {
            bytes memory refusal = abi.encodeWithSelector(WoCoRegistrar.NotRegistryAdmin.selector, callers[i]);
            vm.startPrank(callers[i]);
            vm.expectRevert(refusal);
            registrar.addSponsor(stranger);
            vm.expectRevert(refusal);
            registrar.removeSponsor(sponsor);
            vm.expectRevert(refusal);
            registrar.setReserved("myband", true);
            vm.expectRevert(refusal);
            registrar.setMintRateCap(1, 1);
            vm.expectRevert(refusal);
            registrar.setGlobalMintRateCap(1, 1);
            vm.expectRevert(refusal);
            registrar.resetMintWindow(organiser);
            vm.stopPrank();
        }
    }

    /// Audit 937 F11.
    function test_admin_setReservedRefusesALabelRegisterWouldReject() public {
        string[4] memory bad = ["WoCo", "ab", "-lead", "under_score"];
        vm.startPrank(admin);
        for (uint256 i; i < bad.length; ++i) {
            vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.InvalidLabel.selector, bad[i]));
            registrar.setReserved(bad[i], true);
            vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.InvalidLabel.selector, bad[i]));
            registrar.setReserved(bad[i], false);
        }
        registrar.setReserved("woco", true);
        vm.stopPrank();
        assertFalse(registrar.available("woco"));
    }

    /// `removeSponsor` is the pause: the removed key can no longer mint. It is
    /// ALL a sponsor key could do alone — the pointer relay stays open, because
    /// a holder's signature needs no sponsor, and a relay by the removed key is
    /// as good as anyone's.
    function test_admin_removeSponsorStopsItsMintsAndNothingElse() public {
        vm.prank(sponsor);
        bytes32 node = registrar.register("myband", organiser);

        vm.prank(admin);
        registrar.removeSponsor(sponsor);

        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotAuthorisedSponsor.selector, sponsor));
        vm.prank(sponsor);
        registrar.register("another", organiser);

        uint256 expiration = block.timestamp + 10 minutes;
        bytes memory sig = _pointerSig(node, hex"e301", expiration);
        vm.prank(sponsor);
        registrar.setContenthashWithSignature("myband", hex"e301", expiration, sig);
        assertEq(registry.contenthash(node), hex"e301");
    }

    /*//////////////////////////////////////////////////////////////
                              OWNERSHIP
    //////////////////////////////////////////////////////////////*/

    /// Audit 937 F13 / 938 M-4: the owner is the registry's admin, read live.
    /// The seat's handover moves the registrar in the same transaction — the
    /// nominee holds nothing before it accepts, the previous admin nothing
    /// after.
    function test_ownership_followsTheRegistryAdminSeat() public {
        address dao = makeAddr("dao");

        vm.prank(admin);
        registry.nominateAdmin(dao);
        assertEq(registrar.owner(), admin, "ownership moved before acceptance");
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotRegistryAdmin.selector, dao));
        vm.prank(dao);
        registrar.addSponsor(dao);

        assertTrue(registry.registrars(address(registrar)));
        vm.prank(dao);
        registry.acceptAdmin();
        assertEq(registrar.owner(), dao);
        // Ownership follows the seat; ENROLMENT does not (v2.2, audit 950
        // Medium 3). The new admin re-enrols in its acceptance batch.
        assertFalse(registry.registrars(address(registrar)), "the enrolment survived the handover");

        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotRegistryAdmin.selector, admin));
        vm.prank(admin);
        registrar.addSponsor(admin);

        vm.prank(dao);
        registrar.removeSponsor(sponsor);
        assertFalse(registrar.authorisedSponsors(sponsor));
    }

    /// There is no ownership of its own to hand over or give up: the
    /// `Ownable2Step` surface is absent, renounce included, so no call can
    /// strand the owner powers — including the one response to a leaked sponsor
    /// key.
    function test_ownership_hasNoSurfaceOfItsOwn() public {
        bytes[4] memory calls = [
            abi.encodeWithSignature("renounceOwnership()"),
            abi.encodeWithSignature("transferOwnership(address)", stranger),
            abi.encodeWithSignature("acceptOwnership()"),
            abi.encodeWithSignature("pendingOwner()")
        ];
        for (uint256 i; i < calls.length; ++i) {
            vm.prank(admin);
            (bool ok, bytes memory ret) = address(registrar).call(calls[i]);
            assertFalse(ok, "an ownership function still answers");
            assertEq(ret.length, 0, "an ownership call reverted from inside a function, so the function exists");
        }
        assertEq(registrar.owner(), admin);
    }

    /*//////////////////////////////////////////////////////////////
                          THE PERMIT RAIL IS GONE
    //////////////////////////////////////////////////////////////*/

    /// Audit 925 finding 1: the permit signed only (label, owner, expiry), so its
    /// submitter chose the records. The whole surface is removed, not patched —
    /// each of these calls reaches no function at all.
    function test_abi_thePermitSurfaceIsAbsent() public {
        bytes[] memory calls = new bytes[](7);
        calls[0] = abi.encodeWithSignature(
            "registerWithPermit(string,address,bytes,string[],string[],uint256,bytes)",
            "myband", organiser, SWARM_HASH, new string[](0), new string[](0), block.timestamp, hex""
        );
        calls[1] = abi.encodeWithSignature("platformSigner()");
        calls[2] = abi.encodeWithSignature("setPlatformSigner(address)", stranger);
        calls[3] = abi.encodeWithSignature("usedPermits(bytes32)", bytes32(0));
        calls[4] = abi.encodeWithSignature("PERMIT_TYPEHASH()");
        calls[5] = abi.encodeWithSignature("PERMIT_TTL()");
        calls[6] = abi.encodeWithSignature("DOMAIN_SEPARATOR()");

        for (uint256 i; i < calls.length; ++i) {
            vm.prank(admin);
            (bool ok, bytes memory ret) = address(registrar).call(calls[i]);
            assertFalse(ok, "a permit-era function still answers");
            assertEq(ret.length, 0, "a permit-era call reverted from inside a function, so the function exists");
        }
    }

    /// The server encodes calls from its OWN human-readable ABI
    /// (sub-ens-contract.ts), never from this contract's artefact: a changed
    /// signature here would break minting with no compile error anywhere. v2.2
    /// changed three on purpose; the app's fragments move with them.
    function test_abi_theServersSelectorsArePinned() public view {
        assertEq(WoCoRegistrar.register.selector, bytes4(keccak256("register(string,address)")));
        assertEq(
            WoCoRegistrar.setContenthashWithSignature.selector,
            bytes4(keccak256("setContenthashWithSignature(string,bytes,uint256,bytes)"))
        );
        assertEq(
            WoCoRegistrar.setContenthashDigest.selector,
            bytes4(keccak256("setContenthashDigest(bytes32,bytes,uint256)"))
        );
        assertEq(registrar.pointerNonce.selector, bytes4(keccak256("pointerNonce(bytes32)")));
        assertEq(WoCoRegistrar.globalMintAllowance.selector, bytes4(keccak256("globalMintAllowance()")));
        assertEq(WoCoRegistrar.GlobalMintCapExceeded.selector, bytes4(keccak256("GlobalMintCapExceeded(uint64)")));
        assertEq(WoCoRegistrar.NotHolderSignature.selector, bytes4(keccak256("NotHolderSignature(bytes32)")));
        assertEq(WoCoRegistrar.SignatureExpired.selector, bytes4(keccak256("SignatureExpired()")));
        assertEq(WoCoRegistrar.ExpirationTooFar.selector, bytes4(keccak256("ExpirationTooFar()")));
        assertEq(WoCoRegistrar.available.selector, bytes4(keccak256("available(string)")));
        assertEq(WoCoRegistrar.mintAllowance.selector, bytes4(keccak256("mintAllowance(address)")));
        assertEq(WoCoRegistrar.setMintRateCap.selector, bytes4(keccak256("setMintRateCap(uint32,uint64)")));
        assertEq(
            WoCoRegistrar.MintRateCapExceeded.selector, bytes4(keccak256("MintRateCapExceeded(address,uint64)"))
        );
        assertEq(WoCoRegistrar.InvalidLabel.selector, bytes4(keccak256("InvalidLabel(string)")));
        assertEq(WoCoRegistrar.LabelIsReserved.selector, bytes4(keccak256("LabelIsReserved(string)")));
    }

    /// v2.2: the pre-v2.2 entry points reach no function.
    function test_abi_theV21EntryPointsAreGone() public {
        bytes[2] memory calls = [
            abi.encodeWithSignature(
                "register(string,address,bytes,string[],string[])",
                "myband", organiser, SWARM_HASH, new string[](0), new string[](0)
            ),
            abi.encodeWithSignature("setContenthash(string,bytes)", "myband", SWARM_HASH)
        ];
        for (uint256 i; i < calls.length; ++i) {
            vm.prank(sponsor);
            (bool ok, bytes memory ret) = address(registrar).call(calls[i]);
            assertFalse(ok, "a v2.1 entry point still answers");
            assertEq(ret.length, 0, "a v2.1 call reverted from inside a function, so the function exists");
        }
    }

    /// Audit 937 F36: the events carry the node as their indexed key, so a log
    /// filter can find a name, and the label as readable data.
    function test_events_areIndexedByNodeAndCarryTheLabel() public {
        bytes32 node = registry.makeNode(registry.baseNode(), "myband");

        vm.expectEmit(true, true, false, true, address(registrar));
        emit NameRegistered(node, "myband", organiser);
        vm.prank(sponsor);
        registrar.register("myband", organiser);

        bytes memory next = hex"e40101fa011b2000000000000000000000000000000000000000000000000000000000deadbeef";
        uint256 expiration = block.timestamp + 10 minutes;
        bytes memory sig = _pointerSig(node, next, expiration);
        vm.expectEmit(true, false, false, true, address(registrar));
        emit ContenthashUpdated(node, "myband", next);
        registrar.setContenthashWithSignature("myband", next, expiration, sig);

        assertEq(keccak256("NameRegistered(bytes32,string,address)"), WoCoRegistrar.NameRegistered.selector);
        assertEq(keccak256("ContenthashUpdated(bytes32,string,bytes)"), WoCoRegistrar.ContenthashUpdated.selector);
    }
}

/// @dev Stands in for a registry that calls out during a registration: it mints
///      like the real one, but hands the name to `diverted` (unless it is zero)
///      while the registrar is still writing records — on the ETH address
///      record, the LAST write `register` makes.
contract DivertingRegistry {
    bytes32 public constant baseNode = keccak256("base");
    address public immutable diverted;
    mapping(bytes32 node => address) internal holders;

    function owner() external pure returns (address) {
        return address(0xAD);
    }

    function owner(bytes32 node) external view returns (address) {
        return holders[node];
    }

    function lastRelease(bytes32) external pure returns (address, uint64) {
        return (address(0), 0);
    }

    constructor(address diverted_) {
        diverted = diverted_;
    }

    function makeNode(bytes32 parentNode, string calldata label) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(parentNode, keccak256(bytes(label))));
    }

    function createSubnode(bytes32 parentNode, string calldata label, address to, bytes[] calldata)
        external
        returns (bytes32 node)
    {
        node = makeNode(parentNode, label);
        holders[node] = to;
    }

    function setAddr(bytes32 node, uint256 coinType, bytes calldata) external {
        if (coinType == 60 && diverted != address(0)) holders[node] = diverted;
    }
}
