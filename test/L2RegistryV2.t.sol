// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IERC721Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IMulticallable} from "@ensdomains/ens-contracts/resolvers/IMulticallable.sol";
import {IABIResolver} from "@ensdomains/ens-contracts/resolvers/profiles/IABIResolver.sol";
import {IAddrResolver} from "@ensdomains/ens-contracts/resolvers/profiles/IAddrResolver.sol";
import {IAddressResolver} from "@ensdomains/ens-contracts/resolvers/profiles/IAddressResolver.sol";
import {IContentHashResolver} from "@ensdomains/ens-contracts/resolvers/profiles/IContentHashResolver.sol";
import {IExtendedResolver} from "@ensdomains/ens-contracts/resolvers/profiles/IExtendedResolver.sol";
import {ITextResolver} from "@ensdomains/ens-contracts/resolvers/profiles/ITextResolver.sol";
import {IVersionableResolver} from "@ensdomains/ens-contracts/resolvers/profiles/IVersionableResolver.sol";
import {L2Registry} from "../src/durin/L2Registry.sol";
import {L2Resolver} from "../src/durin/L2Resolver.sol";

/**
 * The v2 registry's own promises (WoCo-Contracts #21), each pinned by a test
 * that fails when the code delivering it is removed:
 *
 *   - A name's records belong to its CURRENT holding. Every ownership change —
 *     mint, transfer, reassignment, burn, admin handover — starts a fresh
 *     record version, and approvals are not ownership changes.
 *   - The admin seat moves only by nomination and acceptance.
 *   - A registrar creates names beneath the base name only; a holder beneath
 *     its own names; nothing is called on a recipient.
 *   - Labels and names respect the DNS limits and never break `tokenURI`'s JSON.
 *   - ONE rule decides who writes records, and `clearRecords` is the holder's.
 *   - The signed record setters and their nonces are gone; the selectors the
 *     server encodes by hand are unchanged.
 *
 * The registrar here is a bare address in `registrars`, not WoCoRegistrar, so
 * that these tests exercise the REGISTRY's rules with no registrar policy in
 * front of them.
 */
contract L2RegistryV2Test is Test {
    L2Registry registry;

    address admin = makeAddr("admin");
    address registrar = makeAddr("registrar");
    address holder = makeAddr("holder");
    address approvee = makeAddr("approvee");
    address operator = makeAddr("operator");
    address stranger = makeAddr("stranger");
    address buyer = makeAddr("buyer");
    address dao = makeAddr("dao");

    bytes constant SITE =
        hex"e40101fa011b20d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162";
    bytes constant OTHER =
        hex"e40101fa011b201111111111111111111111111111111111111111111111111111111111111111";

    event VersionChanged(bytes32 indexed node, uint64 newVersion);
    event AdminNominated(address indexed admin, address indexed nominee);
    event AdminAccepted(address indexed previousAdmin, address indexed newAdmin);
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    function setUp() public {
        registry = L2Registry(Clones.clone(address(new L2Registry())));
        registry.initialize("woco.eth", "WoCo Names", "", admin);
        vm.prank(admin);
        registry.addRegistrar(registrar);
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _mint(string memory label, address to) internal returns (bytes32 node) {
        bytes32 base = registry.baseNode();
        bytes[] memory none = new bytes[](0);
        vm.prank(registrar);
        node = registry.createSubnode(base, label, to, none);
    }

    function _writeAll(bytes32 node, address by) internal {
        vm.startPrank(by);
        registry.setContenthash(node, SITE);
        registry.setText(node, "url", "https://holder.example");
        registry.setAddr(node, holder);
        registry.setABI(node, 1, hex"01");
        vm.stopPrank();
    }

    function _assertNoRecords(bytes32 node, string memory why) internal view {
        assertEq(registry.contenthash(node).length, 0, why);
        assertEq(bytes(registry.text(node, "url")).length, 0, why);
        assertEq(registry.addr(node), address(0), why);
        (uint256 contentType, bytes memory data) = registry.ABI(node, 1);
        assertEq(contentType, 0, why);
        assertEq(data.length, 0, why);
    }

    /// Every record setter, for one node.
    function _setterCalls(bytes32 node) internal pure returns (bytes[] memory calls) {
        calls = new bytes[](5);
        calls[0] = abi.encodeWithSignature("setContenthash(bytes32,bytes)", node, OTHER);
        calls[1] = abi.encodeWithSignature("setText(bytes32,string,string)", node, "url", "https://other.example");
        calls[2] = abi.encodeWithSignature("setAddr(bytes32,address)", node, address(0xBEEF));
        calls[3] = abi.encodeWithSignature(
            "setAddr(bytes32,uint256,bytes)", node, uint256(60), abi.encodePacked(address(0xBEEF))
        );
        calls[4] = abi.encodeWithSignature("setABI(bytes32,uint256,bytes)", node, uint256(1), hex"02");
    }

    /// Every setter must succeed for `by`.
    function _assertCanWrite(address by, bytes32 node, string memory who) internal {
        bytes[] memory calls = _setterCalls(node);
        for (uint256 i; i < calls.length; ++i) {
            vm.prank(by);
            (bool ok,) = address(registry).call(calls[i]);
            assertTrue(ok, string.concat(who, " could not write a record"));
        }
    }

    /// Every setter must refuse `by`, with `Unauthorized(node)`, and change nothing.
    function _assertCannotWrite(address by, bytes32 node, string memory who) internal {
        bytes memory before = registry.contenthash(node);
        bytes[] memory calls = _setterCalls(node);
        for (uint256 i; i < calls.length; ++i) {
            vm.prank(by);
            (bool ok, bytes memory ret) = address(registry).call(calls[i]);
            assertFalse(ok, string.concat(who, " wrote a record"));
            assertEq(ret, abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node), "wrong refusal");
        }
        assertEq(registry.contenthash(node), before);
    }

    function _repeat(bytes1 c, uint256 n) internal pure returns (string memory) {
        bytes memory b = new bytes(n);
        for (uint256 i; i < n; ++i) b[i] = c;
        return string(b);
    }

    /*//////////////////////////////////////////////////////////////
          RECORDS BELONG TO THE CURRENT HOLDING — EVERY OWNERSHIP CHANGE
    //////////////////////////////////////////////////////////////*/

    /// A mint is an ownership change: a fresh name starts at version 1, so
    /// nothing written under version 0 can ever be read through it.
    function test_Version_AMintStartsAFreshVersion() public {
        bytes32 base = registry.baseNode();
        bytes32 node = registry.makeNode(base, "venue");
        bytes[] memory none = new bytes[](0);

        vm.expectEmit(true, false, false, true, address(registry));
        emit VersionChanged(node, 1);
        vm.prank(registrar);
        registry.createSubnode(base, "venue", holder, none);

        assertEq(registry.recordVersions(node), 1);
    }

    /// Audit 924 F-5: a buyer received the seller's records.
    function test_Version_ATransferResetsEveryRecord() public {
        bytes32 node = _mint("venue", holder);
        _writeAll(node, holder);

        vm.prank(holder);
        registry.transferFrom(holder, buyer, uint256(node));

        _assertNoRecords(node, "the buyer received the seller's records");
        assertEq(registry.recordVersions(node), 2);
        _assertCannotWrite(holder, node, "the seller");
        _assertCanWrite(buyer, node, "the buyer");
    }

    function test_Version_BothSafeTransfersResetEveryRecord() public {
        bytes32 a = _mint("venue", holder);
        bytes32 b = _mint("other", holder);
        _writeAll(a, holder);
        _writeAll(b, holder);

        vm.startPrank(holder);
        registry.safeTransferFrom(holder, buyer, uint256(a));
        registry.safeTransferFrom(holder, buyer, uint256(b), hex"1234");
        vm.stopPrank();

        _assertNoRecords(a, "safeTransferFrom kept the records");
        _assertNoRecords(b, "safeTransferFrom with data kept the records");
    }

    function test_Version_AnOperatorsTransferResetsEveryRecord() public {
        bytes32 node = _mint("venue", holder);
        _writeAll(node, holder);
        vm.prank(holder);
        registry.setApprovalForAll(operator, true);

        vm.prank(operator);
        registry.transferFrom(holder, buyer, uint256(node));

        _assertNoRecords(node, "an operator's transfer kept the records");
    }

    /// Approvals grant authority; they do not change the holding.
    function test_Version_ApprovalsAreNotOwnershipChanges() public {
        bytes32 node = _mint("venue", holder);
        _writeAll(node, holder);

        vm.startPrank(holder);
        registry.approve(approvee, uint256(node));
        registry.setApprovalForAll(operator, true);
        vm.stopPrank();

        assertEq(registry.recordVersions(node), 1);
        assertEq(registry.contenthash(node), SITE, "an approval wiped the records");
    }

    /*//////////////////////////////////////////////////////////////
                    THE ADMIN SEAT MOVES BY HANDOVER ONLY
    //////////////////////////////////////////////////////////////*/

    function test_Handover_NominateThenAcceptMovesTheSeat() public {
        uint256 baseToken = uint256(registry.baseNode());

        vm.expectEmit(true, true, false, true, address(registry));
        emit AdminNominated(admin, dao);
        vm.prank(admin);
        registry.nominateAdmin(dao);
        assertEq(registry.pendingAdmin(), dao);
        assertEq(registry.owner(), admin, "the seat moved before acceptance");

        vm.expectEmit(true, true, true, true, address(registry));
        emit Transfer(admin, dao, baseToken);
        vm.expectEmit(true, true, false, true, address(registry));
        emit AdminAccepted(admin, dao);
        vm.prank(dao);
        registry.acceptAdmin();

        assertEq(registry.owner(), dao);
        assertEq(registry.pendingAdmin(), address(0), "the handover stayed open");
        assertEq(registry.balanceOf(admin), 0);
        assertEq(registry.balanceOf(dao), 1);
    }

    function test_Handover_TheNewAdminHoldsEveryAdminPowerAndTheOldOneNone() public {
        bytes32 node = _mint("venue", holder);
        bytes32 base = registry.baseNode();
        vm.prank(admin);
        registry.nominateAdmin(dao);
        vm.prank(dao);
        registry.acceptAdmin();

        vm.startPrank(admin);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, base));
        registry.addRegistrar(admin);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, base));
        registry.removeRegistrar(registrar);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, base));
        registry.adminTransfer(node, admin);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, base));
        registry.nominateAdmin(admin);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, base));
        registry.setBaseURI("https://old-admin.example/");
        vm.stopPrank();

        vm.startPrank(dao);
        registry.adminTransfer(node, buyer);
        registry.removeRegistrar(registrar);
        vm.stopPrank();
        assertEq(registry.owner(node), buyer);
        assertFalse(registry.registrars(registrar));
    }

    function test_Handover_OnlyTheAdminNominates() public {
        bytes32 base = registry.baseNode();

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, base));
        vm.prank(stranger);
        registry.nominateAdmin(stranger);

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, base));
        vm.prank(registrar);
        registry.nominateAdmin(registrar);

        assertEq(registry.pendingAdmin(), address(0));
    }

    function test_Handover_OnlyTheNomineeAccepts() public {
        vm.prank(admin);
        registry.nominateAdmin(dao);

        vm.expectRevert(abi.encodeWithSelector(L2Registry.NotPendingAdmin.selector, stranger));
        vm.prank(stranger);
        registry.acceptAdmin();

        vm.expectRevert(abi.encodeWithSelector(L2Registry.NotPendingAdmin.selector, admin));
        vm.prank(admin);
        registry.acceptAdmin();

        assertEq(registry.owner(), admin);
    }

    /// With no handover open there is no nominee, and zero is refused outright —
    /// even to a caller presenting itself as the zero address, for whom the
    /// move would be a burn of the admin seat.
    function test_Handover_WithNoHandoverOpenNobodyAccepts() public {
        vm.expectRevert(abi.encodeWithSelector(L2Registry.NotPendingAdmin.selector, dao));
        vm.prank(dao);
        registry.acceptAdmin();

        vm.expectRevert(abi.encodeWithSelector(L2Registry.NotPendingAdmin.selector, address(0)));
        vm.prank(address(0));
        registry.acceptAdmin();

        assertEq(registry.owner(), admin, "the seat moved");
    }

    function test_Handover_NominatingZeroCancels() public {
        vm.startPrank(admin);
        registry.nominateAdmin(dao);
        registry.nominateAdmin(address(0));
        vm.stopPrank();
        assertEq(registry.pendingAdmin(), address(0));

        vm.expectRevert(abi.encodeWithSelector(L2Registry.NotPendingAdmin.selector, dao));
        vm.prank(dao);
        registry.acceptAdmin();
    }

    function test_Handover_RenominatingReplacesTheNominee() public {
        address other = makeAddr("other-dao");
        vm.startPrank(admin);
        registry.nominateAdmin(dao);
        registry.nominateAdmin(other);
        vm.stopPrank();

        vm.expectRevert(abi.encodeWithSelector(L2Registry.NotPendingAdmin.selector, dao));
        vm.prank(dao);
        registry.acceptAdmin();

        vm.prank(other);
        registry.acceptAdmin();
        assertEq(registry.owner(), other);
    }

    /// Accepting would move nothing, reset the base name's records, and log a
    /// handover that did not happen.
    function test_Handover_TheAdminCannotNominateItself() public {
        vm.expectRevert(L2Registry.NomineeIsAdmin.selector);
        vm.prank(admin);
        registry.nominateAdmin(admin);
    }

    function test_Handover_AcceptingTwiceIsRefused() public {
        vm.prank(admin);
        registry.nominateAdmin(dao);
        vm.prank(dao);
        registry.acceptAdmin();

        vm.expectRevert(abi.encodeWithSelector(L2Registry.NotPendingAdmin.selector, dao));
        vm.prank(dao);
        registry.acceptAdmin();
    }

    /// The handover is an ownership change like any other.
    function test_Handover_TheBaseNamesRecordsResetOnHandover() public {
        bytes32 base = registry.baseNode();
        vm.prank(admin);
        registry.setContenthash(base, SITE);
        uint64 versionBefore = registry.recordVersions(base);

        vm.prank(admin);
        registry.nominateAdmin(dao);
        vm.prank(dao);
        registry.acceptAdmin();

        assertEq(registry.contenthash(base).length, 0, "the base name's records survived the handover");
        assertEq(registry.recordVersions(base), versionBefore + 1);
    }

    /// Audit 924 F-2, and the single-step footgun v1's deploy script warned
    /// about: not even the holder moves the seat by an ERC-721 transfer.
    function test_BaseName_EvenItsHolderCannotTransferIt() public {
        uint256 baseToken = uint256(registry.baseNode());

        vm.startPrank(admin);
        vm.expectRevert(L2Registry.AdminHandoverRequired.selector);
        registry.transferFrom(admin, dao, baseToken);
        vm.expectRevert(L2Registry.AdminHandoverRequired.selector);
        registry.safeTransferFrom(admin, dao, baseToken);
        vm.expectRevert(L2Registry.AdminHandoverRequired.selector);
        registry.safeTransferFrom(admin, dao, baseToken, hex"00");
        vm.stopPrank();

        assertEq(registry.owner(), admin);
    }

    function test_BaseName_ApproveesAndOperatorsCannotMoveIt() public {
        uint256 baseToken = uint256(registry.baseNode());
        vm.startPrank(admin);
        registry.approve(approvee, baseToken);
        registry.setApprovalForAll(operator, true);
        vm.stopPrank();

        vm.expectRevert(L2Registry.AdminHandoverRequired.selector);
        vm.prank(approvee);
        registry.transferFrom(admin, approvee, baseToken);

        vm.expectRevert(L2Registry.AdminHandoverRequired.selector);
        vm.prank(operator);
        registry.safeTransferFrom(admin, operator, baseToken);

        assertEq(registry.owner(), admin);
    }

    /*//////////////////////////////////////////////////////////////
                          WHO CREATES NAMES
    //////////////////////////////////////////////////////////////*/

    /// Audit 924 F-8: v1 let a registrar name any parent, minted or not.
    function test_Create_ARegistrarCreatesBeneathTheBaseNameOnly() public {
        bytes32 venue = _mint("venue", holder);
        bytes32 unminted = registry.makeNode(registry.baseNode(), "unminted");
        bytes[] memory none = new bytes[](0);

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, venue));
        vm.prank(registrar);
        registry.createSubnode(venue, "shop", holder, none);

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, unminted));
        vm.prank(registrar);
        registry.createSubnode(unminted, "shop", holder, none);
    }

    function test_Create_AHolderCreatesBeneathItsOwnName() public {
        bytes32 venue = _mint("venue", holder);
        bytes[] memory none = new bytes[](0);

        vm.prank(holder);
        bytes32 shop = registry.createSubnode(venue, "shop", buyer, none);

        assertEq(registry.owner(shop), buyer);
        assertEq(registry.decodeName(registry.names(shop)), "shop.venue.woco.eth");
    }

    /// A live name cannot be minted over, by anyone, and the refusal names the
    /// label and the parent. Without the explicit check the mint still fails
    /// — inside OpenZeppelin, as `ERC721InvalidSender(0)` — so it is the error
    /// that is pinned here.
    function test_Create_ALiveNameCannotBeMintedOver() public {
        bytes32 venue = _mint("venue", holder);
        bytes32 base = registry.baseNode();
        bytes[] memory none = new bytes[](0);

        vm.expectRevert(abi.encodeWithSelector(L2Registry.NotAvailable.selector, "venue", base));
        vm.prank(registrar);
        registry.createSubnode(base, "venue", stranger, none);

        assertEq(registry.owner(venue), holder);
        assertEq(registry.recordVersions(venue), 1, "a refused mint moved the version");
    }

    /// Creation stays with the holder alone: approvals are for moving and
    /// writing a name, not for minting beneath it.
    function test_Create_ApproveesOperatorsAndTheAdminCannotCreate() public {
        bytes32 venue = _mint("venue", holder);
        bytes[] memory none = new bytes[](0);
        vm.startPrank(holder);
        registry.approve(approvee, uint256(venue));
        registry.setApprovalForAll(operator, true);
        vm.stopPrank();

        address[3] memory callers = [approvee, operator, admin];
        for (uint256 i; i < callers.length; ++i) {
            vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, venue));
            vm.prank(callers[i]);
            registry.createSubnode(venue, "shop", callers[i], none);
        }
    }

    /// Audit 927 H3: a mint calls nothing on its recipient, so a recipient can
    /// neither refuse a name nor act mid-mint.
    function test_Create_NothingIsCalledOnTheRecipient() public {
        CountsReceives counter = new CountsReceives();
        RefusesReceives refuser = new RefusesReceives();

        _mint("counted", address(counter));
        bytes32 refused = _mint("refused", address(refuser));

        assertEq(counter.calls(), 0, "the recipient was called during the mint");
        assertEq(registry.owner(refused), address(refuser), "a refusing recipient blocked the mint");
    }

    /// `data` runs after the mint, on the fresh version, with the caller's own
    /// authority.
    function test_Create_MulticallDataLandsAfterTheMint() public {
        bytes32 venue = _mint("venue", holder);
        bytes32 shop = registry.makeNode(venue, "shop");
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encodeWithSignature("setContenthash(bytes32,bytes)", shop, SITE);

        vm.prank(holder);
        registry.createSubnode(venue, "shop", holder, data);

        assertEq(registry.contenthash(shop), SITE);
        assertEq(registry.recordVersions(shop), 1);
    }

    /// ... and a caller minting to someone else has no record authority over
    /// the new name, so its data is refused with the whole mint.
    function test_Create_MulticallDataCarriesNoAuthorityOverSomeoneElsesName() public {
        bytes32 venue = _mint("venue", holder);
        bytes32 shop = registry.makeNode(venue, "shop");
        bytes[] memory data = new bytes[](1);
        data[0] = abi.encodeWithSignature("setContenthash(bytes32,bytes)", shop, SITE);

        vm.expectRevert();
        vm.prank(holder);
        registry.createSubnode(venue, "shop", buyer, data);
        assertEq(registry.owner(shop), address(0));
    }

    /*//////////////////////////////////////////////////////////////
                          LABELS AND NAMES
    //////////////////////////////////////////////////////////////*/

    /// Audit 924 F-14: v1 accepted 255-byte labels the gateway never resolves.
    function test_Label_SixtyThreeBytesMintsAndSixtyFourDoesNot() public {
        string memory max = _repeat("a", 63);
        string memory over = _repeat("a", 64);
        bytes32 base = registry.baseNode();
        bytes[] memory none = new bytes[](0);

        _mint(max, holder);

        vm.expectRevert(abi.encodeWithSelector(L2Registry.LabelTooLong.selector, over));
        vm.prank(registrar);
        registry.createSubnode(base, over, holder, none);
    }

    function test_Label_EmptyIsRefused() public {
        bytes32 base = registry.baseNode();
        bytes[] memory none = new bytes[](0);
        vm.expectRevert(L2Registry.LabelTooShort.selector);
        vm.prank(registrar);
        registry.createSubnode(base, "", holder, none);
    }

    /// Audit 924 F-15 / 927 L23: the bytes that break the name's decoding or
    /// `tokenURI`'s JSON.
    function test_Label_EveryForbiddenByteIsRefused() public {
        bytes1[9] memory forbidden = [bytes1(0x00), 0x01, 0x09, 0x0a, 0x1f, 0x22, 0x2e, 0x5c, 0x0d];
        bytes32 base = registry.baseNode();
        bytes[] memory none = new bytes[](0);
        for (uint256 i; i < forbidden.length; ++i) {
            string memory label = string(abi.encodePacked("ab", forbidden[i], "cd"));
            vm.expectRevert(abi.encodeWithSelector(L2Registry.LabelInvalidCharacter.selector, label));
            vm.prank(registrar);
            registry.createSubnode(base, label, holder, none);
        }
    }

    /// The bytes either side of each rule are allowed. Case and unicode are the
    /// registrar's policy, not the registry's.
    function test_Label_TheBytesEitherSideOfTheRulesAreAllowed() public {
        bytes1[9] memory allowed = [bytes1(0x20), 0x21, 0x23, 0x2d, 0x2f, 0x5b, 0x5d, 0x7f, 0xc3];
        for (uint256 i; i < allowed.length; ++i) {
            string memory label = string(abi.encodePacked("ab", allowed[i], "cd"));
            bytes32 node = _mint(label, holder);
            assertEq(registry.owner(node), holder);
        }
    }

    function testFuzz_Label_AcceptedExactlyWhenEveryByteIsAllowed(bytes memory label) public {
        if (label.length == 0) label = hex"61";
        if (label.length > 63) {
            assembly {
                mstore(label, 63)
            }
        }
        bool expected = true;
        for (uint256 i; i < label.length; ++i) {
            bytes1 c = label[i];
            if (c < 0x20 || c == 0x2e || c == 0x22 || c == 0x5c) expected = false;
        }

        bytes32 base = registry.baseNode();
        bytes[] memory none = new bytes[](0);
        vm.prank(registrar);
        try registry.createSubnode(base, string(label), holder, none) {
            assertTrue(expected, "a forbidden byte was accepted");
        } catch (bytes memory err) {
            assertFalse(expected, "an allowed label was refused");
            assertEq(bytes4(err), L2Registry.LabelInvalidCharacter.selector);
        }
    }

    /// The whole wire-format name is capped at 255 bytes, the DNS limit.
    /// "woco.eth" is 10 bytes on the wire (04 woco 03 eth 00); each 63-byte
    /// label adds 64.
    function test_Name_TheWholeNameIsCappedAt255Bytes() public {
        bytes32 a = _mint(_repeat("a", 63), holder); // 74
        bytes[] memory none = new bytes[](0);
        string memory b = _repeat("b", 63);
        string memory c = _repeat("c", 63);
        string memory fits = _repeat("d", 52);
        string memory tooLong = _repeat("e", 53);

        vm.startPrank(holder);
        bytes32 nb = registry.createSubnode(a, b, holder, none); // 138
        bytes32 nc = registry.createSubnode(nb, c, holder, none); // 202
        vm.expectRevert(abi.encodeWithSelector(L2Registry.NameTooLong.selector, tooLong));
        registry.createSubnode(nc, tooLong, holder, none); // 256
        bytes32 nd = registry.createSubnode(nc, fits, holder, none); // 255
        vm.stopPrank();

        assertEq(registry.names(nd).length, 255);
    }

    /// `tokenURI` concatenates the decoded name into JSON. For every label the
    /// registry accepts — here, any printable ASCII — the result parses, and
    /// parses back to the name.
    function testFuzz_TokenURI_IsValidJsonForEveryAcceptedLabel(bytes memory raw) public {
        if (raw.length == 0) raw = hex"61";
        if (raw.length > 63) {
            assembly {
                mstore(raw, 63)
            }
        }
        for (uint256 i; i < raw.length; ++i) {
            uint8 c = 0x20 + (uint8(raw[i]) % 95);
            if (c == 0x22 || c == 0x2e || c == 0x5c) c = 0x61;
            raw[i] = bytes1(c);
        }
        string memory label = string(raw);
        bytes32 node = _mint(label, holder);

        string memory name = string.concat(label, ".woco.eth");
        string memory json = string.concat('{"name": "', name, '"}');
        assertEq(registry.tokenURI(uint256(node)), string.concat("data:application/json;base64,", Base64.encode(bytes(json))));
        assertEq(vm.parseJsonString(json, ".name"), name, "the JSON did not parse back to the name");
    }

    /*//////////////////////////////////////////////////////////////
                    ONE RULE FOR WHO WRITES RECORDS
    //////////////////////////////////////////////////////////////*/

    function test_Records_TheHolderSideWrites() public {
        bytes32 byHolder = _mint("by-holder", holder);
        bytes32 byApprovee = _mint("by-approvee", holder);
        bytes32 byOperator = _mint("by-operator", holder);
        vm.startPrank(holder);
        registry.approve(approvee, uint256(byApprovee));
        registry.setApprovalForAll(operator, true);
        vm.stopPrank();

        _assertCanWrite(holder, byHolder, "the holder");
        _assertCanWrite(approvee, byApprovee, "a per-token approvee");
        _assertCanWrite(operator, byOperator, "an operator-for-all");
    }

    function test_Records_ARegistrarWritesANameThatExists() public {
        bytes32 node = _mint("venue", holder);
        _assertCanWrite(registrar, node, "a registrar");
    }

    /// Audit 927 H2 / 924 F-3: nothing — not even a registrar — writes a label
    /// before it is minted, so nothing can reach its first holder.
    function test_Records_NobodyWritesANameThatDoesNotExist() public {
        bytes32 unminted = registry.makeNode(registry.baseNode(), "future");
        _assertCannotWrite(registrar, unminted, "a registrar");
        _assertCannotWrite(admin, unminted, "the admin");
        _assertCannotWrite(stranger, unminted, "a stranger");
    }

    function test_Records_NobodyWritesAReleasedName() public {
        bytes32 node = _mint("venue", holder);
        vm.prank(holder);
        registry.release(node);

        _assertCannotWrite(registrar, node, "a registrar");
        _assertCannotWrite(holder, node, "the previous holder");
    }

    /// Audit 924 F-1: v1's check let a caller name the zero address as the
    /// signer. There is no signer parameter now; a stranger, and the admin
    /// that has not enrolled itself, are refused like anyone else.
    function test_Records_StrangersAndAnUnenrolledAdminAreRefused() public {
        bytes32 node = _mint("venue", holder);
        _assertCannotWrite(stranger, node, "a stranger");
        _assertCannotWrite(admin, node, "the admin");
    }

    function test_Records_TheSellerAndEveryoneActingForItLoseAuthorityOnTransfer() public {
        bytes32 node = _mint("venue", holder);
        vm.startPrank(holder);
        registry.approve(approvee, uint256(node));
        registry.setApprovalForAll(operator, true);
        registry.transferFrom(holder, buyer, uint256(node));
        vm.stopPrank();

        _assertCannotWrite(holder, node, "the seller");
        _assertCannotWrite(approvee, node, "the seller's approvee");
        _assertCannotWrite(operator, node, "the seller's operator");
    }

    function test_Records_ARevokedApproveeIsRefused() public {
        bytes32 node = _mint("venue", holder);
        vm.startPrank(holder);
        registry.approve(approvee, uint256(node));
        registry.approve(address(0), uint256(node));
        vm.stopPrank();

        _assertCannotWrite(approvee, node, "a revoked approvee");
    }

    function test_Records_AMulticallCarriesNoAuthorityOfItsOwn() public {
        bytes32 node = _mint("venue", holder);
        bytes[] memory calls = new bytes[](1);
        calls[0] = abi.encodeWithSignature("setContenthash(bytes32,bytes)", node, OTHER);

        vm.expectRevert();
        vm.prank(stranger);
        registry.multicall(calls);

        vm.expectRevert();
        vm.prank(stranger);
        registry.multicallWithNodeCheck(node, calls);
    }

    /// Audit 924 F-18.
    function test_Records_AddRegistrarRefusesTheZeroAddress() public {
        vm.expectRevert(L2Registry.RegistrarIsZeroAddress.selector);
        vm.prank(admin);
        registry.addRegistrar(address(0));
        assertFalse(registry.registrars(address(0)));
    }

    /*//////////////////////////////////////////////////////////////
                     clearRecords IS THE HOLDER'S
    //////////////////////////////////////////////////////////////*/

    function test_Clear_TheHolderSideClears() public {
        bytes32 byHolder = _mint("by-holder", holder);
        bytes32 byApprovee = _mint("by-approvee", holder);
        bytes32 byOperator = _mint("by-operator", holder);
        _writeAll(byHolder, holder);
        _writeAll(byApprovee, holder);
        _writeAll(byOperator, holder);
        vm.startPrank(holder);
        registry.approve(approvee, uint256(byApprovee));
        registry.setApprovalForAll(operator, true);
        vm.stopPrank();

        vm.prank(holder);
        registry.clearRecords(byHolder);
        vm.prank(approvee);
        registry.clearRecords(byApprovee);
        vm.prank(operator);
        registry.clearRecords(byOperator);

        _assertNoRecords(byHolder, "the holder could not clear");
        _assertNoRecords(byApprovee, "an approvee could not clear");
        _assertNoRecords(byOperator, "an operator could not clear");
    }

    /// Audit 927 H1: in v1 the admin enrolled itself as a registrar and cleared
    /// a name in place. Refused to registrars, to the admin, and to the admin
    /// enrolled as a registrar.
    function test_Clear_RegistrarsAndTheAdminAreRefused() public {
        bytes32 node = _mint("venue", holder);
        _writeAll(node, holder);

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        vm.prank(registrar);
        registry.clearRecords(node);

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        vm.prank(admin);
        registry.clearRecords(node);

        vm.prank(admin);
        registry.addRegistrar(admin);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        vm.prank(admin);
        registry.clearRecords(node);

        assertEq(registry.contenthash(node), SITE, "the records were wiped");
        assertEq(registry.recordVersions(node), 1);
    }

    function test_Clear_NobodyClearsANameThatDoesNotExist() public {
        bytes32 unminted = registry.makeNode(registry.baseNode(), "future");
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, unminted));
        vm.prank(registrar);
        registry.clearRecords(unminted);
    }

    /*//////////////////////////////////////////////////////////////
                              INTERFACES
    //////////////////////////////////////////////////////////////*/

    /// Audit 924 F-16: the registry always implemented ENSIP-10 `resolve` and
    /// never said so.
    function test_Interfaces_ReportsEverythingItImplements() public view {
        assertTrue(registry.supportsInterface(type(IExtendedResolver).interfaceId), "IExtendedResolver");
        assertTrue(registry.supportsInterface(type(IAddrResolver).interfaceId), "IAddrResolver");
        assertTrue(registry.supportsInterface(type(IAddressResolver).interfaceId), "IAddressResolver");
        assertTrue(registry.supportsInterface(type(IContentHashResolver).interfaceId), "IContentHashResolver");
        assertTrue(registry.supportsInterface(type(ITextResolver).interfaceId), "ITextResolver");
        assertTrue(registry.supportsInterface(type(IABIResolver).interfaceId), "IABIResolver");
        assertTrue(registry.supportsInterface(type(IVersionableResolver).interfaceId), "IVersionableResolver");
        assertTrue(registry.supportsInterface(type(IMulticallable).interfaceId), "IMulticallable");
        assertTrue(registry.supportsInterface(type(IERC721).interfaceId), "IERC721");
        assertTrue(registry.supportsInterface(type(IERC165).interfaceId), "IERC165");
        assertFalse(registry.supportsInterface(0xffffffff), "the ERC-165 invalid id");
    }

    /*//////////////////////////////////////////////////////////////
                                  ABI
    //////////////////////////////////////////////////////////////*/

    /// Audit 924 F-1 / F-4 / F-7: the four signed setters are removed, not
    /// patched, and `nonces` with them. Each call reaches no function.
    function test_Abi_TheSignedSettersAndNoncesAreGone() public {
        bytes32 node = _mint("venue", holder);
        bytes[] memory calls = new bytes[](5);
        calls[0] = abi.encodeWithSignature(
            "setAddrWithSignature(bytes32,uint256,bytes,uint256,address,bytes)",
            node, uint256(60), abi.encodePacked(stranger), block.timestamp, address(0), new bytes(65)
        );
        calls[1] = abi.encodeWithSignature(
            "setTextWithSignature(bytes32,string,string,uint256,address,bytes)",
            node, "url", "x", block.timestamp, address(0), new bytes(65)
        );
        calls[2] = abi.encodeWithSignature(
            "setContenthashWithSignature(bytes32,bytes,uint256,address,bytes)",
            node, OTHER, block.timestamp, address(0), new bytes(65)
        );
        calls[3] = abi.encodeWithSignature(
            "setABIWithSignature(bytes32,uint256,bytes,uint256,address,bytes)",
            node, uint256(1), hex"02", block.timestamp, address(0), new bytes(65)
        );
        calls[4] = abi.encodeWithSignature("nonces(bytes32)", node);

        for (uint256 i; i < calls.length; ++i) {
            (bool ok, bytes memory ret) = address(registry).call(calls[i]);
            assertFalse(ok, "a v1 signed-setter function still answers");
            assertEq(ret.length, 0, "the call reverted from inside a function, so the function exists");
        }
    }

    /// The server and the client encode registry calls from their OWN
    /// human-readable ABIs (sub-ens-contract.ts, release-digest.ts, l2-reader.ts),
    /// never from this artefact. A changed signature here breaks them with no
    /// compile error anywhere, so the signatures are written out.
    function test_Abi_TheSelectorsTheAppEncodesByHandAreUnchanged() public view {
        // Reads — getters and inherited functions included: each hand-written
        // signature must answer on this contract, which has no fallback.
        bytes32 base = registry.baseNode();
        bytes[7] memory reads = [
            abi.encodeWithSignature("ownerOf(uint256)", uint256(base)),
            abi.encodeWithSignature("names(bytes32)", base),
            abi.encodeWithSignature("lastRelease(bytes32)", base),
            abi.encodeWithSignature("contenthash(bytes32)", base),
            abi.encodeWithSignature("recordVersions(bytes32)", base),
            abi.encodeWithSignature("RELEASE_TYPEHASH()"),
            abi.encodeWithSignature(
                "resolve(bytes,bytes)", hex"04776f636f0365746800", abi.encodeWithSignature("contenthash(bytes32)", base)
            )
        ];
        for (uint256 i; i < reads.length; ++i) {
            (bool ok, bytes memory ret) = address(registry).staticcall(reads[i]);
            assertTrue(ok && ret.length > 0, "a read the app encodes by hand does not answer");
        }

        // Writes, events and errors declared here: compared at compile time.
        assertEq(L2Registry.decodeName.selector, bytes4(keccak256("decodeName(bytes)")));
        assertEq(L2Registry.release.selector, bytes4(keccak256("release(bytes32)")));
        assertEq(
            L2Registry.releaseWithSignature.selector,
            bytes4(keccak256("releaseWithSignature(bytes32,uint256,address,bytes)"))
        );
        assertEq(L2Registry.releaseDigest.selector, bytes4(keccak256("releaseDigest(bytes32,uint256)")));

        assertEq(L2Registry.Released.selector, keccak256("Released(bytes32,address,address)"));
        assertEq(L2Resolver.Unauthorized.selector, bytes4(keccak256("Unauthorized(bytes32)")));
        assertEq(L2Registry.SignatureExpired.selector, bytes4(keccak256("SignatureExpired()")));
        assertEq(L2Registry.ReleaseBaseNode.selector, bytes4(keccak256("ReleaseBaseNode()")));
        assertEq(L2Registry.ReleaseUnregistered.selector, bytes4(keccak256("ReleaseUnregistered(bytes32)")));
        assertEq(IERC721Errors.ERC721NonexistentToken.selector, bytes4(keccak256("ERC721NonexistentToken(uint256)")));
    }
}

/// @dev Counts ERC-721 receiver calls, and accepts each.
contract CountsReceives is IERC721Receiver {
    uint256 public calls;

    function onERC721Received(address, address, uint256, bytes calldata) external returns (bytes4) {
        calls++;
        return IERC721Receiver.onERC721Received.selector;
    }
}

/// @dev Refuses every ERC-721 it is offered.
contract RefusesReceives is IERC721Receiver {
    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        revert("no names here");
    }
}
