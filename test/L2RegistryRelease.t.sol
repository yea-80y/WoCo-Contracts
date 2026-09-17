// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IERC721Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {WoCoRegistrar} from "../src/WoCoRegistrar.sol";
import {L2Registry} from "../src/durin/L2Registry.sol";
import {L2Resolver} from "../src/durin/L2Resolver.sol";

/**
 * Tests for `L2Registry.release` — the holder-initiated burn added to the
 * vendored Durin registry for WoCo-Event-App #464.
 *
 * Like the adminTransfer file, this one exists to freeze a SHAPE: the registry
 * ships as an EIP-1167 clone and cannot be patched, so every clause below is a
 * permanent promise. The promise is:
 *
 *   "You can give a name back. Only you can do it — or, for a name issued
 *    beneath another name, whoever holds that one. An approval you gave a
 *    marketplace cannot. The platform cannot do it to you. A name with names
 *    beneath it goes back only once they are gone. When it goes, it stops
 *    resolving to your records at once, the registry remembers you held it,
 *    and the label is free for anyone to take through the normal mint path."
 *
 * Every guard in `release` has a test here that fails when the guard is
 * deleted. The two facts it stores are pinned even though nothing on chain
 * reads them yet — that is the point of storing them.
 */
contract L2RegistryReleaseTest is Test {
    L2Registry registry;
    WoCoRegistrar registrar;

    address admin = makeAddr("admin");
    address sponsor = makeAddr("sponsor");
    address organiser = makeAddr("organiser");
    address stranger = makeAddr("stranger");
    address operator = makeAddr("operator");

    bytes constant SWARM_HASH =
        hex"e40101fa011b20d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162";
    bytes constant OTHER_HASH =
        hex"e40101fa011b201111111111111111111111111111111111111111111111111111111111111111";

    event Released(bytes32 indexed node, address indexed previousOwner, address indexed operator);
    event VersionChanged(bytes32 indexed node, uint64 newVersion);
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    function setUp() public {
        // The production shape: our implementation, cloned, initialised.
        registry = L2Registry(Clones.clone(address(new L2Registry())));
        registry.initialize("woco.eth", "WoCo Names", "", admin);

        registrar = new WoCoRegistrar(address(registry), sponsor, new string[](0));

        vm.prank(admin);
        registry.addRegistrar(address(registrar));

        // A realistic timestamp, so `releasedAt` is not being compared to 1.
        vm.warp(1_800_000_000);
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

    /*//////////////////////////////////////////////////////////////
                          THE PRIMITIVE WORKS
    //////////////////////////////////////////////////////////////*/

    function test_Release_BurnsTheName() public {
        bytes32 node = _register("venue", organiser);
        assertEq(registry.balanceOf(organiser), 1, "precondition");

        vm.prank(organiser);
        registry.release(node);

        assertEq(registry.owner(node), address(0), "name still has an owner");
        assertEq(registry.balanceOf(organiser), 0, "balance not decremented");
        assertTrue(registrar.available("venue"), "label is not available again");

        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721NonexistentToken.selector, uint256(node)));
        registry.ownerOf(uint256(node));
    }

    /// Records must stop resolving in the SAME transaction. Checked before any
    /// re-mint so that the registrar overwriting `addr`/`contenthash` on mint
    /// cannot mask a missing version bump.
    function test_Release_ClearsRecordsInTheSameTransaction() public {
        bytes32 node = _register("venue", organiser);
        assertEq(registry.contenthash(node), SWARM_HASH, "precondition: site is set");
        assertEq(registry.text(node, "url"), "https://old-holder.example", "precondition: text is set");
        assertEq(registry.addr(node, 60), abi.encodePacked(organiser), "precondition: addr is set");

        vm.prank(organiser);
        registry.release(node);

        assertEq(registry.contenthash(node), "", "contenthash still resolves");
        assertEq(registry.text(node, "url"), "", "text record still resolves");
        assertEq(registry.addr(node, 60), "", "addr(60) still resolves to the old holder");
    }

    /// The two facts nothing reads yet. They are the whole reason the burn is
    /// not just `_burn`: a future registrar policy can only be enforced on
    /// chain if the frozen layer kept them.
    function test_Release_RecordsWhoHeldItAndWhen() public {
        bytes32 node = _register("venue", organiser);
        (address by, uint64 at) = registry.lastRelease(node);
        assertEq(by, address(0), "precondition: no release yet");
        assertEq(at, 0, "precondition: no release yet");

        vm.warp(1_800_000_000 + 12 days);
        vm.prank(organiser);
        registry.release(node);

        (by, at) = registry.lastRelease(node);
        assertEq(by, organiser, "previousOwner not recorded");
        assertEq(at, uint64(1_800_000_000 + 12 days), "releasedAt not recorded");
    }

    function test_Release_DecrementsTotalSupply() public {
        uint256 before = registry.totalSupply(); // base name only
        bytes32 node = _register("venue", organiser);
        assertEq(registry.totalSupply(), before + 1, "precondition");

        vm.prank(organiser);
        registry.release(node);

        assertEq(registry.totalSupply(), before, "totalSupply counts a burned name");
    }

    /// The mint moved the record version to 1; the burn moves it to 2.
    function test_Release_EmitsReleasedVersionChangedAndTransfer() public {
        bytes32 node = _register("venue", organiser);

        vm.expectEmit(true, true, true, true, address(registry));
        emit Transfer(organiser, address(0), uint256(node));
        vm.expectEmit(true, false, false, true, address(registry));
        emit VersionChanged(node, 2);
        vm.expectEmit(true, true, true, true, address(registry));
        emit Released(node, organiser, organiser);

        vm.prank(organiser);
        registry.release(node);
    }

    /*//////////////////////////////////////////////////////////////
                    WHO MAY CALL IT — AND WHO MAY NOT
    //////////////////////////////////////////////////////////////*/

    /// Audit 938 M-7. v2 followed the ERC-721 convention — whoever may
    /// transfer the token may burn it. An approval is what a marketplace asks
    /// for to list a name, and a burn cannot be undone, so v2.1 refuses both
    /// kinds of approval. They still move the token.
    function test_Release_RevertForPerTokenApprovee() public {
        bytes32 node = _register("venue", organiser);
        vm.prank(organiser);
        registry.approve(operator, uint256(node));

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        vm.prank(operator);
        registry.release(node);
        assertEq(registry.owner(node), organiser, "an approvee burned the name");

        vm.prank(operator);
        registry.transferFrom(organiser, operator, uint256(node));
        assertEq(registry.owner(node), operator, "the approval no longer moves the token");
    }

    function test_Release_RevertForOperatorForAll() public {
        bytes32 node = _register("venue", organiser);
        vm.prank(organiser);
        registry.setApprovalForAll(operator, true);

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        vm.prank(operator);
        registry.release(node);

        assertEq(registry.owner(node), organiser, "an operator burned the name");
    }

    /// The holder of the name directly above may release it (the fusion,
    /// owner decision 2026-09-17). The event records the holder as
    /// `previousOwner` and the parent's holder as `operator`, so the two are
    /// distinguishable afterwards.
    function test_Release_ByTheParentsHolder() public {
        bytes32 venue = _register("venue", organiser);
        address childHolder = makeAddr("childHolder");
        bytes[] memory noData = new bytes[](0);
        vm.prank(organiser);
        bytes32 shop = registry.createSubnode(venue, "shop", childHolder, noData);

        vm.expectEmit(true, true, true, true, address(registry));
        emit Released(shop, childHolder, organiser);
        vm.prank(organiser);
        registry.release(shop);

        assertEq(registry.owner(shop), address(0));
        (address by,) = registry.lastRelease(shop);
        assertEq(by, childHolder, "previousOwner must be the holder, not the parent's holder");
    }

    /// A revoked approval is refused like any other.
    function test_Release_RevokedApproveeCannotRelease() public {
        bytes32 node = _register("venue", organiser);
        vm.startPrank(organiser);
        registry.approve(operator, uint256(node));
        registry.approve(address(0), uint256(node));
        vm.stopPrank();

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        vm.prank(operator);
        registry.release(node);

        assertEq(registry.owner(node), organiser);
    }

    function test_Release_RevertForStranger() public {
        bytes32 node = _register("venue", organiser);

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        vm.prank(stranger);
        registry.release(node);

        assertEq(registry.owner(node), organiser, "name was burned by a stranger");
    }

    /// The clause that makes this "no platform power": neither the hot sponsor
    /// key, nor the registrar contract that mints and writes records, nor the
    /// registry admin can release a name they do not hold. Registrars are
    /// authorised for RECORD writes on any node; that authority must not leak
    /// into burning.
    function test_Release_PlatformCannotReleaseAHoldersName() public {
        bytes32 node = _register("venue", organiser);

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        vm.prank(sponsor);
        registry.release(node);

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        vm.prank(address(registrar));
        registry.release(node);

        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        vm.prank(admin);
        registry.release(node);

        assertEq(registry.owner(node), organiser, "the platform burned a holder's name");
        assertEq(registry.contenthash(node), SWARM_HASH, "records were wiped without a burn");
    }

    /// The admin holds `baseNode`, and is its holder in every ERC-721 sense —
    /// but burning it would leave the registry with no admin, forever. Refused
    /// even for the holder.
    function test_Release_RevertOnBaseNode() public {
        bytes32 base = registry.baseNode();

        vm.expectRevert(L2Registry.ReleaseBaseNode.selector);
        vm.prank(admin);
        registry.release(base);

        assertEq(registry.owner(), admin, "registry lost its admin");
    }

    function test_Release_RevertOnUnregisteredName() public {
        bytes32 node = registry.makeNode(registry.baseNode(), "neverminted");

        vm.expectRevert(abi.encodeWithSelector(L2Registry.ReleaseUnregistered.selector, node));
        vm.prank(stranger);
        registry.release(node);
    }

    /// Releasing twice is releasing an unregistered name. Pinned because a
    /// double release must not decrement `totalSupply` a second time or
    /// overwrite `lastRelease` with a zero holder.
    function test_Release_RevertOnSecondRelease() public {
        bytes32 node = _register("venue", organiser);
        vm.prank(organiser);
        registry.release(node);
        uint256 supplyAfterFirst = registry.totalSupply();

        vm.expectRevert(abi.encodeWithSelector(L2Registry.ReleaseUnregistered.selector, node));
        vm.prank(organiser);
        registry.release(node);

        assertEq(registry.totalSupply(), supplyAfterFirst);
        (address by,) = registry.lastRelease(node);
        assertEq(by, organiser, "release record was overwritten");
    }

    /*//////////////////////////////////////////////////////////////
                        WHAT HAPPENS AFTERWARDS
    //////////////////////////////////////////////////////////////*/

    /// The label goes back to the pool for ANYONE — no hold, no preference for
    /// the previous holder. That is the decision recorded on #464 (the 30-day
    /// hold was dropped); if it changes, it changes in the registrar.
    function test_Release_ThenAnyoneCanReMintThroughTheRegistrar() public {
        bytes32 node = _register("venue", organiser);
        bytes memory nameBefore = registry.names(node);
        vm.prank(organiser);
        registry.release(node);

        string[] memory keys = new string[](0);
        string[] memory vals = new string[](0);
        vm.prank(sponsor);
        bytes32 reminted = registrar.register("venue", stranger, OTHER_HASH, keys, vals);

        assertEq(reminted, node, "same label, same node");
        assertEq(registry.owner(node), stranger, "re-mint did not land");
        assertEq(registry.contenthash(node), OTHER_HASH, "new holder's site not set");
        assertEq(registry.names(node), nameBefore, "names[node] changed across a release + re-mint");
        assertEq(registry.totalSupply(), 2, "totalSupply drifted across release + re-mint");
    }

    /// The re-minter must not inherit anything the previous holder wrote. The
    /// registrar overwrites addr + contenthash on mint, so the TEXT record is
    /// the one that would leak — it is exactly what the version bump exists for.
    function test_Release_ReMintDoesNotInheritThePreviousHoldersRecords() public {
        bytes32 node = _register("venue", organiser);
        vm.prank(organiser);
        registry.release(node);

        string[] memory keys = new string[](0);
        string[] memory vals = new string[](0);
        vm.prank(sponsor);
        registrar.register("venue", stranger, OTHER_HASH, keys, vals);

        assertEq(registry.text(node, "url"), "", "new holder inherited the old text record");
        assertEq(registry.addr(node, 60), abi.encodePacked(stranger), "addr(60) is not the new holder");
    }

    /// Pins the footgun documented on `lastRelease`: the record is history and
    /// outlives a re-mint. A registrar reading it must check `owner(node)` first.
    function test_Release_LastReleaseSurvivesAReMint() public {
        bytes32 node = _register("venue", organiser);
        vm.prank(organiser);
        registry.release(node);
        (, uint64 at) = registry.lastRelease(node);

        string[] memory keys = new string[](0);
        string[] memory vals = new string[](0);
        vm.prank(sponsor);
        registrar.register("venue", stranger, OTHER_HASH, keys, vals);

        (address by, uint64 atAfter) = registry.lastRelease(node);
        assertEq(by, organiser, "history was cleared by the re-mint");
        assertEq(atAfter, at);
        assertEq(registry.owner(node), stranger, "and the name is live again");
    }

    /// A released name is unregistered, so the admin power has nothing to move.
    function test_Release_AdminTransferOnAReleasedNameReverts() public {
        bytes32 node = _register("venue", organiser);
        vm.prank(organiser);
        registry.release(node);

        vm.expectRevert(abi.encodeWithSelector(L2Registry.AdminTransferUnregistered.selector, node));
        vm.prank(admin);
        registry.adminTransfer(node, stranger);
    }

    /// A released name is not an NFT any more — no metadata, no owner query.
    function test_Release_TokenURIRevertsAfterRelease() public {
        bytes32 node = _register("venue", organiser);
        vm.prank(organiser);
        registry.release(node);

        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721NonexistentToken.selector, uint256(node)));
        registry.tokenURI(uint256(node));
    }

    function test_Release_DoesNotTouchOtherNames() public {
        bytes32 venue = _register("venue", organiser);
        bytes32 other = _register("other", stranger);

        vm.prank(organiser);
        registry.release(venue);

        assertEq(registry.owner(other), stranger);
        assertEq(registry.contenthash(other), SWARM_HASH);
        (address by,) = registry.lastRelease(other);
        assertEq(by, address(0));
    }

    /// Audit 938 H-2 / 937 F8, which v2 stated here as a residual: children
    /// outlived their parent's release, with their records, and whoever
    /// re-minted the parent found a live subtree it had no standing over. A
    /// name with children cannot be released now; they go first — released by
    /// their holder or by the parent's — and the re-minter starts clean.
    function test_Release_ANameWithChildrenGoesBackOnlyOnceTheyAreGone() public {
        bytes32 venue = _register("venue", organiser);
        address childHolder = makeAddr("childHolder");

        bytes[] memory noData = new bytes[](0);
        vm.prank(organiser); // parent's holder may create children
        bytes32 shop = registry.createSubnode(venue, "shop", childHolder, noData);
        vm.prank(organiser);
        bytes32 bar = registry.createSubnode(venue, "bar", organiser, noData);
        vm.prank(childHolder);
        registry.setContenthash(shop, OTHER_HASH);

        vm.expectRevert(abi.encodeWithSelector(L2Registry.HasChildren.selector, venue, 2));
        vm.prank(organiser);
        registry.release(venue);

        vm.prank(childHolder);
        registry.release(shop);
        vm.expectRevert(abi.encodeWithSelector(L2Registry.HasChildren.selector, venue, 1));
        vm.prank(organiser);
        registry.release(venue);

        vm.startPrank(organiser);
        registry.release(bar);
        registry.release(venue);
        vm.stopPrank();
        assertEq(registry.childCount(venue), 0);

        // Re-mint the parent to someone else: nothing hangs beneath it.
        string[] memory keys = new string[](0);
        string[] memory vals = new string[](0);
        vm.prank(sponsor);
        registrar.register("venue", stranger, SWARM_HASH, keys, vals);
        assertEq(registry.owner(shop), address(0), "a child outlived its parent");
        assertEq(registry.contenthash(shop).length, 0, "a child's records outlived it");

        vm.prank(stranger);
        bytes32 again = registry.createSubnode(venue, "shop", stranger, noData);
        assertEq(again, shop);
        assertEq(registry.contenthash(shop).length, 0, "the new child inherited records");
    }
}
