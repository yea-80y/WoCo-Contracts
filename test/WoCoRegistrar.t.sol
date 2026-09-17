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

    event NameRegistered(bytes32 indexed node, string label, address indexed owner, bytes contenthash);
    event ContenthashUpdated(bytes32 indexed node, string label, bytes contenthash);

    address admin = makeAddr("admin");
    address sponsor = makeAddr("sponsor");
    address organiser = makeAddr("organiser");
    address stranger = makeAddr("stranger");

    // A short Swarm bzz reference, ENS contenthash-encoded bytes (shape only).
    bytes constant SWARM_HASH = hex"e40101fa011b20d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162";

    function setUp() public {
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

    function _emptyText() internal pure returns (string[] memory keys, string[] memory vals) {
        keys = new string[](0);
        vals = new string[](0);
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
    /// "held by nobody" is what `available` and `setContenthash` read as free.
    function test_register_refusesTheZeroAddressAsHolder() public {
        (string[] memory keys, string[] memory vals) = _emptyText();
        vm.expectRevert(abi.encodeWithSelector(bytes4(keccak256("ERC721InvalidReceiver(address)")), address(0)));
        vm.prank(sponsor);
        registrar.register("myband", address(0), SWARM_HASH, keys, vals);
        assertTrue(registrar.available("myband"));
    }

    /*//////////////////////////////////////////////////////////////
                          register() — sponsor path
    //////////////////////////////////////////////////////////////*/

    function test_register_mintsToOrganiserAndSetsContenthash() public {
        (string[] memory keys, string[] memory vals) = _emptyText();

        vm.prank(sponsor);
        bytes32 node = registrar.register("myband", organiser, SWARM_HASH, keys, vals);

        assertEq(registry.owner(node), organiser, "organiser owns the name");
        assertEq(registry.contenthash(node), SWARM_HASH, "Swarm pointer set");
        assertEq(registry.addr(node), organiser, "addr(60) is the organiser");
        assertEq(registry.addr(node, registrar.coinType()), abi.encodePacked(organiser), "chain addr is the organiser");
        assertFalse(registrar.available("myband"), "no longer available");
    }

    function test_register_setsProfileTextRecords() public {
        string[] memory keys = new string[](2);
        string[] memory vals = new string[](2);
        keys[0] = "description";
        vals[0] = "Independent music venue";
        keys[1] = "avatar";
        vals[1] = "bzz://d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162";

        vm.prank(sponsor);
        bytes32 node = registrar.register("craufurd-arms", organiser, SWARM_HASH, keys, vals);

        assertEq(registry.text(node, "description"), "Independent music venue");
        assertEq(registry.text(node, "avatar"), vals[1]);
    }

    function test_register_revertsForNonSponsor() public {
        (string[] memory keys, string[] memory vals) = _emptyText();
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotAuthorisedSponsor.selector, stranger));
        vm.prank(stranger);
        registrar.register("myband", organiser, SWARM_HASH, keys, vals);
    }

    function test_register_revertsForReservedLabel() public {
        (string[] memory keys, string[] memory vals) = _emptyText();
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.LabelIsReserved.selector, "admin"));
        vm.prank(sponsor);
        registrar.register("admin", organiser, SWARM_HASH, keys, vals);
    }

    function test_register_revertsForInvalidLabel() public {
        (string[] memory keys, string[] memory vals) = _emptyText();
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.InvalidLabel.selector, "My-Band"));
        vm.prank(sponsor);
        registrar.register("My-Band", organiser, SWARM_HASH, keys, vals);
    }

    function test_register_revertsForArrayMismatch() public {
        string[] memory keys = new string[](1);
        string[] memory vals = new string[](0);
        keys[0] = "description";
        vm.expectRevert(WoCoRegistrar.ArrayLengthMismatch.selector);
        vm.prank(sponsor);
        registrar.register("myband", organiser, SWARM_HASH, keys, vals);
    }

    /// The single ownership check sits after the LAST record write. Against a
    /// registry that hands the name away during that write, registration is
    /// refused — so a check moved any earlier would let this through.
    function test_register_refusesWhenTheNameMovesDuringTheLastWrite() public {
        DivertingRegistry diverting = new DivertingRegistry(stranger);
        WoCoRegistrar r = new WoCoRegistrar(address(diverting), sponsor, new string[](0));
        string[] memory keys = new string[](1);
        string[] memory vals = new string[](1);
        keys[0] = "url";
        vals[0] = "https://organiser.example";
        bytes32 node = diverting.makeNode(diverting.baseNode(), "myband");

        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NameMovedDuringRegistration.selector, node));
        vm.prank(sponsor);
        r.register("myband", organiser, SWARM_HASH, keys, vals);
    }

    /// The control for the test above: the same stand-in, with nothing to
    /// divert on, registers normally. The refusal is about the move.
    function test_register_theStandInRegistersWhenNothingMoves() public {
        DivertingRegistry diverting = new DivertingRegistry(stranger);
        WoCoRegistrar r = new WoCoRegistrar(address(diverting), sponsor, new string[](0));
        (string[] memory keys, string[] memory vals) = _emptyText();

        vm.prank(sponsor);
        bytes32 node = r.register("myband", organiser, SWARM_HASH, keys, vals);
        assertEq(diverting.owner(node), organiser);
    }

    /*//////////////////////////////////////////////////////////////
                              setContenthash
    //////////////////////////////////////////////////////////////*/

    function test_setContenthash_updatesOnRedeploy() public {
        (string[] memory keys, string[] memory vals) = _emptyText();
        vm.prank(sponsor);
        bytes32 node = registrar.register("myband", organiser, SWARM_HASH, keys, vals);

        bytes memory newHash = hex"e40101fa011b2000000000000000000000000000000000000000000000000000000000deadbeef";
        vm.prank(sponsor);
        registrar.setContenthash("myband", newHash);

        assertEq(registry.contenthash(node), newHash);
    }

    /// Audit 925 finding 2 / 927 H2. A pointer set on a label nobody holds would
    /// have become its first holder's site. Refused by name here, and the first
    /// holder's records start empty.
    function test_setContenthash_refusesALabelNobodyHolds() public {
        bytes memory seeded = hex"e40101fa011b201111111111111111111111111111111111111111111111111111111111111111";
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.LabelNotRegistered.selector, "future"));
        vm.prank(sponsor);
        registrar.setContenthash("future", seeded);

        (string[] memory keys, string[] memory vals) = _emptyText();
        vm.prank(sponsor);
        bytes32 node = registrar.register("future", organiser, "", keys, vals);
        assertEq(registry.contenthash(node).length, 0, "the first holder inherited a pointer");
    }

    function test_setContenthash_refusesEmpty() public {
        (string[] memory keys, string[] memory vals) = _emptyText();
        vm.prank(sponsor);
        bytes32 node = registrar.register("myband", organiser, SWARM_HASH, keys, vals);

        vm.expectRevert(WoCoRegistrar.EmptyContenthash.selector);
        vm.prank(sponsor);
        registrar.setContenthash("myband", "");
        assertEq(registry.contenthash(node), SWARM_HASH);
    }

    /// Audit 937 F5: a label `register` would refuse is refused here too, in
    /// the same order — so a reserved name the platform minted through another
    /// registrar is out of this sponsor's reach.
    function test_setContenthash_refusesAReservedOrInvalidLabel() public {
        bytes32 base = registry.baseNode();
        bytes[] memory none = new bytes[](0);
        vm.startPrank(admin);
        registry.addRegistrar(admin);
        bytes32 reservedNode = registry.createSubnode(base, "admin", organiser, none);
        bytes32 casedNode = registry.createSubnode(base, "MyBand", organiser, none);
        vm.stopPrank();

        vm.startPrank(sponsor);
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.LabelIsReserved.selector, "admin"));
        registrar.setContenthash("admin", SWARM_HASH);
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.InvalidLabel.selector, "MyBand"));
        registrar.setContenthash("MyBand", SWARM_HASH);
        // Invalid before reserved before empty, as in `register`.
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.InvalidLabel.selector, "MyBand"));
        registrar.setContenthash("MyBand", "");
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.LabelIsReserved.selector, "admin"));
        registrar.setContenthash("admin", "");
        vm.stopPrank();

        assertEq(registry.contenthash(reservedNode).length, 0);
        assertEq(registry.contenthash(casedNode).length, 0);
    }

    function test_setContenthash_refusesNonSponsor() public {
        (string[] memory keys, string[] memory vals) = _emptyText();
        vm.prank(sponsor);
        registrar.register("myband", organiser, SWARM_HASH, keys, vals);

        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotAuthorisedSponsor.selector, stranger));
        vm.prank(stranger);
        registrar.setContenthash("myband", hex"e301");
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
        (string[] memory keys, string[] memory vals) = _emptyText();
        assertTrue(registrar.available("myband"));
        vm.prank(sponsor);
        registrar.register("myband", organiser, SWARM_HASH, keys, vals);
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

    /// `removeSponsor` is the pause: the removed key can neither mint nor repoint.
    function test_admin_removeSponsorStopsItsMintsAndRepoints() public {
        (string[] memory keys, string[] memory vals) = _emptyText();
        vm.prank(sponsor);
        registrar.register("myband", organiser, SWARM_HASH, keys, vals);

        vm.prank(admin);
        registrar.removeSponsor(sponsor);

        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotAuthorisedSponsor.selector, sponsor));
        vm.prank(sponsor);
        registrar.register("another", organiser, SWARM_HASH, keys, vals);

        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotAuthorisedSponsor.selector, sponsor));
        vm.prank(sponsor);
        registrar.setContenthash("myband", hex"e301");
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

        vm.prank(dao);
        registry.acceptAdmin();
        assertEq(registrar.owner(), dao);

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
    /// signature here would break minting with no compile error anywhere.
    function test_abi_theServersSelectorsAreUnchanged() public pure {
        assertEq(
            WoCoRegistrar.register.selector,
            bytes4(keccak256("register(string,address,bytes,string[],string[])"))
        );
        assertEq(WoCoRegistrar.setContenthash.selector, bytes4(keccak256("setContenthash(string,bytes)")));
        assertEq(WoCoRegistrar.available.selector, bytes4(keccak256("available(string)")));
        assertEq(WoCoRegistrar.mintAllowance.selector, bytes4(keccak256("mintAllowance(address)")));
        assertEq(WoCoRegistrar.setMintRateCap.selector, bytes4(keccak256("setMintRateCap(uint32,uint64)")));
        assertEq(
            WoCoRegistrar.MintRateCapExceeded.selector, bytes4(keccak256("MintRateCapExceeded(address,uint64)"))
        );
        assertEq(WoCoRegistrar.InvalidLabel.selector, bytes4(keccak256("InvalidLabel(string)")));
        assertEq(WoCoRegistrar.LabelIsReserved.selector, bytes4(keccak256("LabelIsReserved(string)")));
    }

    /// Audit 937 F36: the events carry the node as their indexed key, so a log
    /// filter can find a name, and the label as readable data.
    function test_events_areIndexedByNodeAndCarryTheLabel() public {
        (string[] memory keys, string[] memory vals) = _emptyText();
        bytes32 node = registry.makeNode(registry.baseNode(), "myband");

        vm.expectEmit(true, true, false, true, address(registrar));
        emit NameRegistered(node, "myband", organiser, SWARM_HASH);
        vm.prank(sponsor);
        registrar.register("myband", organiser, SWARM_HASH, keys, vals);

        bytes memory next = hex"e40101fa011b2000000000000000000000000000000000000000000000000000000000deadbeef";
        vm.expectEmit(true, false, false, true, address(registrar));
        emit ContenthashUpdated(node, "myband", next);
        vm.prank(sponsor);
        registrar.setContenthash("myband", next);

        assertEq(
            keccak256("NameRegistered(bytes32,string,address,bytes)"),
            WoCoRegistrar.NameRegistered.selector
        );
        assertEq(keccak256("ContenthashUpdated(bytes32,string,bytes)"), WoCoRegistrar.ContenthashUpdated.selector);
    }
}

/// @dev Stands in for a registry that calls out during a registration: it mints
///      like the real one, but hands the name to `diverted` while the registrar
///      is still writing records — on a text write, the LAST kind of write.
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

    function setAddr(bytes32, uint256, bytes calldata) external {}

    function setContenthash(bytes32, bytes calldata) external {}

    function setText(bytes32 node, string calldata, string calldata) external {
        holders[node] = diverted;
    }
}
