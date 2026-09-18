// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IERC721Metadata} from "@openzeppelin/contracts/token/ERC721/extensions/IERC721Metadata.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC721Errors} from "@openzeppelin/contracts/interfaces/draft-IERC6093.sol";
import {IMulticallable} from "@ensdomains/ens-contracts/resolvers/IMulticallable.sol";
import {IExtendedResolver} from "@ensdomains/ens-contracts/resolvers/profiles/IExtendedResolver.sol";
import {L2Registry} from "../src/durin/L2Registry.sol";
import {L2Resolver} from "../src/durin/L2Resolver.sol";
import {WoCoRegistrar} from "../src/WoCoRegistrar.sol";

/**
 * Regression tests for the $1 re-audit of sub-ENS v2.1: LeftClaw engagement
 * 950, which read `f4a673b`. Report:
 * `~/projects/woco-571-handover/AUDIT_950_SUBENS_V21_REGISTRY_REAUDIT.md`.
 *
 * Began as `test/Audit950Triage.t.sol` (commit `7dc5638`): six reproductions,
 * all green on v2.1, written before the report was judged. Fable's design
 * consult (`FABLE_950_DESIGN_CONSULT_REPORT.md`) added six more that make the
 * same moves as separate PLAIN calls, across blocks, with no batch anywhere —
 * the proof that the root was the approval, not the batch. The owner chose
 * Branch A (2026-09-18): the registry refuses ERC-721 delegation outright and
 * drops the public `multicall`. Every reproduction is turned round here.
 *
 * Each shape now fails at its FIRST step — the approval — and the would-be
 * taker is refused as the stranger it is. The tests keep going past that
 * point on purpose: they show that nothing the approval would have reached is
 * reachable without it.
 */
contract SubEnsV22Audit950RegressionTest is Test {
    L2Registry registry;
    WoCoRegistrar registrar;

    address admin = makeAddr("admin");
    address sponsor = makeAddr("sponsor");
    address bareRegistrar = makeAddr("bareRegistrar");
    address holder = makeAddr("holder");
    address victim = makeAddr("victim");
    address attacker = makeAddr("attacker");
    address buyer = makeAddr("buyer");

    bytes constant SITE = hex"e40101fa011b20d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162";

    function setUp() public {
        vm.warp(1_800_000_000);
        registry = L2Registry(Clones.clone(address(new L2Registry())));
        registry.initialize("woco.eth", "WoCo Names", "", admin);
        registrar = new WoCoRegistrar(address(registry), sponsor, new string[](0));
        vm.startPrank(admin);
        registry.addRegistrar(address(registrar));
        registry.addRegistrar(bareRegistrar);
        vm.stopPrank();
    }

    function _mint(string memory label, address to) internal returns (bytes32) {
        vm.prank(sponsor);
        return registrar.register(label, to, "", new string[](0), new string[](0));
    }

    function _mintUnder(bytes32 parent, string memory label, address to) internal returns (bytes32 node) {
        bytes[] memory none = new bytes[](0);
        address parentHolder = registry.owner(parent);
        vm.prank(parentHolder);
        node = registry.createSubnode(parent, label, to, none);
    }

    function _expectNotApproved(address spender, bytes32 node) internal {
        vm.expectRevert(
            abi.encodeWithSelector(IERC721Errors.ERC721InsufficientApproval.selector, spender, uint256(node))
        );
    }

    /*//////////////////////////////////////////////////////////////
        950 [2] (Medium): a two-leg round trip restored the 948/949
        record wipe — two ordinary transfers by an operator, repeatable
        because an operator approval survives a transfer.
    //////////////////////////////////////////////////////////////*/

    function test_950_M_roundTripIsRefusedAtTheApproval() public {
        bytes32 node = _mint("venue", holder);
        vm.startPrank(holder);
        registry.setContenthash(node, SITE);
        registry.setAddr(node, 60, abi.encodePacked(holder));
        vm.expectRevert(L2Registry.DelegationNotSupported.selector);
        registry.setApprovalForAll(attacker, true); // what a marketplace listing asks for
        vm.stopPrank();
        uint64 v0 = registry.recordVersions(node);

        _expectNotApproved(attacker, node);
        vm.prank(attacker);
        registry.transferFrom(holder, attacker, uint256(node));

        assertEq(registry.owner(node), holder);
        assertEq(registry.recordVersions(node), v0, "the version moved");
        assertEq(registry.contenthash(node), SITE, "contenthash destroyed");
        assertEq(registry.addr(node, 60), abi.encodePacked(holder), "addr destroyed");
    }

    function test_950_M_noOperatorApprovalExistsToRepeatWith() public {
        bytes32 node = _mint("venue", holder);
        vm.expectRevert(L2Registry.DelegationNotSupported.selector);
        vm.prank(holder);
        registry.setApprovalForAll(attacker, true);
        assertFalse(registry.isApprovedForAll(holder, attacker), "an operator approval exists");

        uint64 v0 = registry.recordVersions(node);
        for (uint256 i; i < 3; ++i) {
            _expectNotApproved(attacker, node);
            vm.prank(attacker);
            registry.transferFrom(holder, attacker, uint256(node));
        }
        assertEq(registry.recordVersions(node), v0, "the version moved");
    }

    /*//////////////////////////////////////////////////////////////
        950 [1] (High): a momentary holder used holder-only doors —
        release, parentTransfer — through the public `multicall`, and
        handed the token back. The batch is gone (its selector reaches
        no function) and so is the approval that made the holder.
    //////////////////////////////////////////////////////////////*/

    function test_950_H_noApproveeCanBurnTheName() public {
        bytes32 node = _mint("venue", holder);
        vm.expectRevert(L2Registry.DelegationNotSupported.selector);
        vm.prank(holder);
        registry.approve(attacker, uint256(node)); // a single per-token approval
        assertEq(registry.getApproved(uint256(node)), address(0));

        bytes[] memory batch = new bytes[](2);
        batch[0] = abi.encodeCall(registry.transferFrom, (holder, attacker, uint256(node)));
        batch[1] = abi.encodeCall(registry.release, (node));
        vm.prank(attacker);
        (bool ok,) = address(registry).call(abi.encodeWithSelector(IMulticallable.multicall.selector, batch));
        assertFalse(ok, "the public batch still exists");

        _expectNotApproved(attacker, node);
        vm.prank(attacker);
        registry.transferFrom(holder, attacker, uint256(node));
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        vm.prank(attacker);
        registry.release(node);

        assertEq(registry.owner(node), holder, "the name is burned");
    }

    /// The recovery path the report said could not undo a burn is never
    /// needed for this shape; it still works on the live name.
    function test_950_H_theNameStaysRecoverable() public {
        bytes32 node = _mint("venue", holder);
        vm.expectRevert(L2Registry.DelegationNotSupported.selector);
        vm.prank(holder);
        registry.approve(attacker, uint256(node));

        _expectNotApproved(attacker, node);
        vm.prank(attacker);
        registry.transferFrom(holder, attacker, uint256(node));

        vm.prank(admin);
        registry.adminTransfer(node, buyer);
        assertEq(registry.owner(node), buyer);
    }

    /// The most severe variant: one approval on a PARENT reached third-party
    /// children. The approval is refused, and the would-be taker is not the
    /// parent's holder, so neither child door opens.
    function test_950_H_noThirdPartyChildSeizure() public {
        bytes32 parent = _mint("market", holder);
        bytes32 childA = _mintUnder(parent, "stallone", victim);
        bytes32 childB = _mintUnder(parent, "stalltwo", victim);

        vm.expectRevert(L2Registry.DelegationNotSupported.selector);
        vm.prank(holder);
        registry.approve(attacker, uint256(parent));

        _expectNotApproved(attacker, parent);
        vm.prank(attacker);
        registry.transferFrom(holder, attacker, uint256(parent));
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, childA));
        vm.prank(attacker);
        registry.parentTransfer(childA, attacker);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, childB));
        vm.prank(attacker);
        registry.release(childB);

        assertEq(registry.owner(childA), victim, "third-party name seized");
        assertEq(registry.owner(childB), victim, "third-party name burned");
        assertEq(registry.owner(parent), holder);
        assertEq(registry.childCount(parent), 2);
    }

    /// Claimed: createSubnode's guard was walked past by a second batch item.
    /// Not a defect (consult §1): as two calls each tells the truth — the
    /// registrar mints to itself, then releases its own name, and both events
    /// fire. What the guard exists for — `createSubnode` announcing a name its
    /// own batch then moved — is still refused.
    function test_950_H_createSubnodeAndAReleaseAreTwoTruthfulCalls() public {
        bytes32 base = registry.baseNode();
        bytes[] memory none = new bytes[](0);
        bytes32 subnode = registry.makeNode(base, "ghost");

        bytes[] memory inBatch = new bytes[](1);
        inBatch[0] = abi.encodeCall(registry.release, (subnode));
        vm.expectRevert(abi.encodeWithSelector(L2Registry.SubnodeMovedDuringCreation.selector, subnode));
        vm.prank(bareRegistrar);
        registry.createSubnode(base, "ghost", bareRegistrar, inBatch);

        vm.recordLogs();
        vm.startPrank(bareRegistrar);
        registry.createSubnode(base, "ghost", bareRegistrar, none);
        registry.release(subnode);
        vm.stopPrank();

        bytes32 created = keccak256("SubnodeCreated(bytes32,bytes,address)");
        bytes32 released = keccak256("Released(bytes32,address,address)");
        bool sawCreated;
        bool sawReleased;
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == created && logs[i].topics[1] == subnode) sawCreated = true;
            if (logs[i].topics[0] == released && logs[i].topics[1] == subnode) sawReleased = true;
        }
        assertTrue(sawCreated && sawReleased, "each call must log what it did");
        assertEq(registry.owner(subnode), address(0));
    }

    /*//////////////////////////////////////////////////////////////
        THE ROOT (Fable consult §1): every 950 variant as SEPARATE
        plain calls, across blocks, no batch. Green on v2.1; each is
        now refused at the approval.
    //////////////////////////////////////////////////////////////*/

    function test_root_burn_twoPlainCallsAreRefused() public {
        bytes32 node = _mint("venue", holder);
        vm.expectRevert(L2Registry.DelegationNotSupported.selector);
        vm.prank(holder);
        registry.approve(attacker, uint256(node));

        _expectNotApproved(attacker, node);
        vm.prank(attacker);
        registry.transferFrom(holder, attacker, uint256(node));
        vm.roll(block.number + 1);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, node));
        vm.prank(attacker);
        registry.release(node);

        assertEq(registry.owner(node), holder, "burned with two ordinary calls");
    }

    function test_root_childSeizure_fourPlainCallsAreRefused() public {
        bytes32 parent = _mint("market", holder);
        bytes32 childA = _mintUnder(parent, "stallone", victim);
        bytes32 childB = _mintUnder(parent, "stalltwo", victim);
        vm.expectRevert(L2Registry.DelegationNotSupported.selector);
        vm.prank(holder);
        registry.approve(attacker, uint256(parent));

        _expectNotApproved(attacker, parent);
        vm.prank(attacker);
        registry.transferFrom(holder, attacker, uint256(parent));
        vm.roll(block.number + 1);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, childA));
        vm.prank(attacker);
        registry.parentTransfer(childA, attacker);
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, childB));
        vm.prank(attacker);
        registry.release(childB);
        vm.roll(block.number + 1);
        _expectNotApproved(attacker, parent);
        vm.prank(attacker);
        registry.transferFrom(attacker, holder, uint256(parent));

        assertEq(registry.owner(childA), victim, "seized with plain calls");
        assertEq(registry.owner(childB), victim, "burned with plain calls");
        assertEq(registry.owner(parent), holder);
    }

    /// v2.1: after a take-and-release, `lastRelease` named the taker, and the
    /// registrar re-minted the victim's label to it free of the rate cap. Now
    /// no take happens, so no forged record exists and the label stays held.
    function test_root_noLastReleaseForgery() public {
        bytes32 node = _mint("venue", holder);
        vm.expectRevert(L2Registry.DelegationNotSupported.selector);
        vm.prank(holder);
        registry.approve(attacker, uint256(node));
        _expectNotApproved(attacker, node);
        vm.prank(attacker);
        registry.transferFrom(holder, attacker, uint256(node));

        (address releasedBy,) = registry.lastRelease(node);
        assertEq(releasedBy, address(0), "a release record exists");
        assertEq(registry.owner(node), holder);
        bytes32 base = registry.baseNode();
        vm.expectRevert(abi.encodeWithSelector(L2Registry.NotAvailable.selector, "venue", base));
        vm.prank(sponsor);
        registrar.register("venue", attacker, "", new string[](0), new string[](0));
    }

    /// Unchanged, and by design (the owner's fusion decision, 2026-09-17): a
    /// holder-initiated SALE of a parent sells the authority over the names
    /// directly beneath it. An approval only ever let an approvee be that
    /// buyer at a price of zero; the sale itself is the holder's to make.
    function test_root_buyerInheritsChildAuthority_byDesign() public {
        bytes32 parent = _mint("market", holder);
        bytes32 childA = _mintUnder(parent, "stallone", victim);
        vm.prank(holder);
        registry.transferFrom(holder, buyer, uint256(parent));
        vm.prank(buyer);
        registry.parentTransfer(childA, buyer);
        assertEq(registry.owner(childA), buyer, "the buyer of a parent may take its children");
    }

    /// Batching never granted authority, and now it does not exist at all.
    function test_root_thereIsNoPublicBatch() public {
        bytes32 node = _mint("venue", holder);
        bytes[] memory batch = new bytes[](2);
        batch[0] = abi.encodeCall(registry.transferFrom, (holder, attacker, uint256(node)));
        batch[1] = abi.encodeCall(registry.release, (node));

        address[2] memory callers = [attacker, holder];
        for (uint256 i; i < callers.length; ++i) {
            vm.prank(callers[i]);
            (bool ok,) = address(registry).call(abi.encodeWithSelector(IMulticallable.multicall.selector, batch));
            assertFalse(ok, "multicall(bytes[]) must not exist");
            vm.prank(callers[i]);
            (ok,) = address(registry).call(
                abi.encodeWithSelector(IMulticallable.multicallWithNodeCheck.selector, node, batch)
            );
            assertFalse(ok, "multicallWithNodeCheck(bytes32,bytes[]) must not exist");
        }
        assertEq(registry.owner(node), holder);
    }

    /*//////////////////////////////////////////////////////////////
        BRANCH A, stated directly (Fable consult §2).
    //////////////////////////////////////////////////////////////*/

    /// Every form of delegation is refused, revocations included, and for
    /// every caller — the holder, a stranger, the admin on the base name.
    function test_A_everyApprovalIsRefused() public {
        bytes32 node = _mint("venue", holder);
        uint256 base = uint256(registry.baseNode());
        address[3] memory callers = [holder, attacker, admin];
        for (uint256 i; i < callers.length; ++i) {
            vm.startPrank(callers[i]);
            vm.expectRevert(L2Registry.DelegationNotSupported.selector);
            registry.approve(attacker, uint256(node));
            vm.expectRevert(L2Registry.DelegationNotSupported.selector);
            registry.approve(address(0), uint256(node));
            vm.expectRevert(L2Registry.DelegationNotSupported.selector);
            registry.approve(buyer, base);
            vm.expectRevert(L2Registry.DelegationNotSupported.selector);
            registry.setApprovalForAll(attacker, true);
            vm.expectRevert(L2Registry.DelegationNotSupported.selector);
            registry.setApprovalForAll(attacker, false);
            vm.stopPrank();
        }
        assertEq(registry.getApproved(uint256(node)), address(0));
        assertFalse(registry.isApprovedForAll(holder, attacker));
    }

    /// The two views stay truthful: `getApproved` reverts for a name that does
    /// not exist, as EIP-721 requires, and is zero otherwise.
    function test_A_theApprovalViewsStayTruthful() public {
        bytes32 node = _mint("venue", holder);
        assertEq(registry.getApproved(uint256(node)), address(0));
        bytes32 missing = registry.makeNode(registry.baseNode(), "missing");
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721NonexistentToken.selector, uint256(missing)));
        registry.getApproved(uint256(missing));
        assertFalse(registry.isApprovedForAll(holder, holder));
    }

    /// The holder moves its own name by both transfer paths; a stranger cannot.
    function test_A_theHolderMovesAndAStrangerCannot() public {
        bytes32 node = _mint("venue", holder);
        _expectNotApproved(attacker, node);
        vm.prank(attacker);
        registry.transferFrom(holder, attacker, uint256(node));
        _expectNotApproved(attacker, node);
        vm.prank(attacker);
        registry.safeTransferFrom(holder, attacker, uint256(node));

        vm.prank(holder);
        registry.transferFrom(holder, buyer, uint256(node));
        assertEq(registry.owner(node), buyer);
        vm.prank(buyer);
        registry.safeTransferFrom(buyer, holder, uint256(node));
        assertEq(registry.owner(node), holder);
    }

    /// A move of a name no one holds names the missing token, not an approval.
    function test_A_aMissingNameIsReportedAsMissing() public {
        bytes32 missing = registry.makeNode(registry.baseNode(), "missing");
        vm.expectRevert(abi.encodeWithSelector(IERC721Errors.ERC721NonexistentToken.selector, uint256(missing)));
        vm.prank(holder);
        registry.transferFrom(holder, buyer, uint256(missing));
    }

    /// No `Approval` or `ApprovalForAll` event is ever logged, including by
    /// the approval clear OpenZeppelin runs inside every move.
    function test_A_noApprovalEventOnAnyMove() public {
        vm.recordLogs();
        bytes32 node = _mint("venue", holder);
        vm.prank(holder);
        registry.transferFrom(holder, buyer, uint256(node));
        vm.prank(admin);
        registry.adminTransfer(node, holder);
        vm.prank(holder);
        registry.release(node);

        bytes32 approval = keccak256("Approval(address,address,uint256)");
        bytes32 approvalForAll = keccak256("ApprovalForAll(address,address,bool)");
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            assertTrue(logs[i].topics[0] != approval && logs[i].topics[0] != approvalForAll, "an approval event");
        }
    }

    function test_A_interfaces() public view {
        assertTrue(registry.supportsInterface(type(IERC721).interfaceId), "IERC721 still reported");
        assertTrue(registry.supportsInterface(type(IERC721Metadata).interfaceId), "IERC721Metadata");
        assertTrue(registry.supportsInterface(type(IExtendedResolver).interfaceId), "IExtendedResolver");
        assertFalse(registry.supportsInterface(type(IMulticallable).interfaceId), "IMulticallable");
    }

    /// The createSubnode batch still writes records for a registrar, now
    /// bubbles the inner reason (950 Low 6), refuses an item for another node
    /// or too short to name one, and its post-batch guard still fires.
    function test_A_createSubnodeBatchStillWorksAndBubbles() public {
        bytes32 base = registry.baseNode();
        bytes32 sub = registry.makeNode(base, "venue");
        bytes[] memory batch = new bytes[](1);
        batch[0] = abi.encodeCall(registry.setContenthash, (sub, SITE));
        vm.prank(bareRegistrar);
        registry.createSubnode(base, "venue", holder, batch);
        assertEq(registry.contenthash(sub), SITE, "the registrar wrote the record in the batch");

        bytes32 other = registry.makeNode(base, "other");
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.BatchNodeMismatch.selector, other));
        vm.prank(bareRegistrar);
        registry.createSubnode(base, "other", holder, batch); // still names venue

        batch[0] = abi.encodePacked(registry.setContenthash.selector, bytes31(sub)); // 35 bytes
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.BatchNodeMismatch.selector, other));
        vm.prank(bareRegistrar);
        registry.createSubnode(base, "other", holder, batch);

        bytes32 third = registry.makeNode(base, "third");
        batch[0] = abi.encodeCall(registry.clearRecords, (third)); // a registrar may not clear
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, third));
        vm.prank(bareRegistrar);
        registry.createSubnode(base, "third", holder, batch);

        batch[0] = abi.encodeCall(registry.release, (third));
        vm.expectRevert(abi.encodeWithSelector(L2Registry.SubnodeMovedDuringCreation.selector, third));
        vm.prank(bareRegistrar);
        registry.createSubnode(base, "third", bareRegistrar, batch);
    }

    /*//////////////////////////////////////////////////////////////
        A SALE STILL WORKS WITHOUT APPROVALS (owner's question,
        2026-09-18). The seller PUSHES the name into an escrow
        contract, which as the holder sends it on when paid. The escrow
        is a separate contract; the frozen registry need not know it.
    //////////////////////////////////////////////////////////////*/

    function test_Sale_aPushedListingSettlesAtomically() public {
        NameEscrow escrow = new NameEscrow(IERC721(address(registry)));
        vm.deal(buyer, 10 ether);
        bytes32 node = _mint("venue", holder);
        uint256 id = uint256(node);

        vm.expectRevert(L2Registry.DelegationNotSupported.selector);
        vm.prank(holder);
        registry.approve(address(escrow), id); // the marketplace way is closed

        vm.prank(holder);
        registry.safeTransferFrom(holder, address(escrow), id, abi.encode(1 ether));
        assertEq(registry.ownerOf(id), address(escrow), "the escrow holds it while listed");

        uint256 before = holder.balance;
        vm.prank(buyer);
        escrow.buy{value: 1 ether}(id);
        assertEq(registry.ownerOf(id), buyer, "the buyer has the name");
        assertEq(holder.balance, before + 1 ether, "the seller was paid in the same transaction");
    }

    function test_Sale_theSellerCanWithdrawAnUnsoldListing() public {
        NameEscrow escrow = new NameEscrow(IERC721(address(registry)));
        bytes32 node = _mint("venue", holder);
        vm.prank(holder);
        registry.safeTransferFrom(holder, address(escrow), uint256(node), abi.encode(1 ether));
        vm.prank(holder);
        escrow.cancel(uint256(node));
        assertEq(registry.ownerOf(uint256(node)), holder, "back with the seller");
    }

    /// Listing is a real change of holder, so the records reset: a site on the
    /// name goes dark while it is listed. Stated so no listing flow claims
    /// otherwise.
    function test_Sale_listingResetsTheRecords() public {
        NameEscrow escrow = new NameEscrow(IERC721(address(registry)));
        bytes32 node = _mint("venue", holder);
        vm.prank(holder);
        registry.setContenthash(node, SITE);
        vm.prank(holder);
        registry.safeTransferFrom(holder, address(escrow), uint256(node), abi.encode(1 ether));
        assertEq(registry.contenthash(node).length, 0);
    }
}

/// @dev The smallest trustless name sale with no approvals: listed by a push,
///      settled by the escrow as the holder. Test-only.
contract NameEscrow is IERC721Receiver {
    IERC721 public immutable registry;

    struct Listing {
        address seller;
        uint256 price;
    }

    mapping(uint256 id => Listing) public listings;

    constructor(IERC721 r) {
        registry = r;
    }

    function onERC721Received(address, address from, uint256 id, bytes calldata data) external returns (bytes4) {
        require(msg.sender == address(registry), "not the registry");
        listings[id] = Listing(from, abi.decode(data, (uint256)));
        return this.onERC721Received.selector;
    }

    function buy(uint256 id) external payable {
        Listing memory l = listings[id];
        require(l.seller != address(0) && msg.value == l.price, "bad listing or price");
        delete listings[id];
        registry.safeTransferFrom(address(this), msg.sender, id);
        (bool ok,) = l.seller.call{value: msg.value}("");
        require(ok, "pay seller");
    }

    function cancel(uint256 id) external {
        Listing memory l = listings[id];
        require(msg.sender == l.seller, "not the seller");
        delete listings[id];
        registry.safeTransferFrom(address(this), l.seller, id);
    }
}
