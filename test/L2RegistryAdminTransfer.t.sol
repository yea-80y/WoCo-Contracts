// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {WoCoRegistrar} from "../src/WoCoRegistrar.sol";
import {L2Registry} from "../src/durin/L2Registry.sol";

/**
 * Tests for `L2Registry.adminTransfer` — the governed reassignment added to the
 * vendored Durin registry for WoCo-Event-App #422.
 *
 * The point of these tests is as much about what the power CANNOT do as what it
 * can. Upstream Durin has no reclaim at all, and the registry ships as an
 * EIP-1167 clone that cannot be upgraded, so the shape frozen here is permanent.
 * Each test below pins one clause of the public promise:
 *
 *   "Your name is an NFT we can never re-issue over, and never burn from
 *    where it stands. The registry admin — intended to be a DAO multisig — can
 *    reassign it, on-chain and visibly, under a published policy."
 *
 * "From where it stands", because the admin can end a name in two visible
 * steps: reassign it to an address it controls, then release it there as its
 * holder (audit 937 F14 / 938 M-1; accepted power, see `adminTransfer`).
 */
contract L2RegistryAdminTransferTest is Test {
    L2Registry    registry;
    WoCoRegistrar registrar;

    address admin     = makeAddr("admin");
    address sponsor   = makeAddr("sponsor");
    address organiser = makeAddr("organiser");
    address claimant  = makeAddr("claimant"); // e.g. the rightful trademark holder
    address stranger  = makeAddr("stranger");

    bytes constant SWARM_HASH =
        hex"e40101fa011b20d1de9994b4d039f6548d191eb26786769f580809256b4685ef316805265ea162";
    bytes constant OTHER_HASH =
        hex"e40101fa011b201111111111111111111111111111111111111111111111111111111111111111";

    event AdminTransfer(bytes32 indexed node, address indexed previousOwner, address indexed newOwner);
    event VersionChanged(bytes32 indexed node, uint64 newVersion);

    function setUp() public {
        // The production shape: our implementation, cloned, initialised.
        registry = L2Registry(Clones.clone(address(new L2Registry())));
        registry.initialize("woco.eth", "WoCo Names", "", admin);

        registrar = new WoCoRegistrar(address(registry), sponsor, new string[](0));

        vm.prank(admin);
        registry.addRegistrar(address(registrar));
    }

    function _register(string memory label, address owner_) internal returns (bytes32 node) {
        string[] memory keys = new string[](0);
        string[] memory vals = new string[](0);
        vm.prank(sponsor);
        registrar.register(label, owner_, SWARM_HASH, keys, vals);
        node = registry.makeNode(registry.baseNode(), label);
    }

    // ── The power works ───────────────────────────────────────────────────────

    function test_AdminTransfer_ReassignsTheName() public {
        bytes32 node = _register("venue", organiser);
        assertEq(registry.owner(node), organiser);

        vm.prank(admin);
        registry.adminTransfer(node, claimant);

        assertEq(registry.owner(node), claimant, "name did not move");
    }

    /// The motivating case: a squatted name reaches its rightful holder. Burning
    /// could not achieve this, because `createSubnode` reverts `NotAvailable`
    /// for an owned node and the name could never be reissued.
    function test_AdminTransfer_LetsTheRightfulHolderReceiveASquattedName() public {
        bytes32 node = _register("realvenue", stranger); // squatter mints first

        vm.prank(admin);
        registry.adminTransfer(node, claimant);

        assertEq(registry.owner(node), claimant);

        // And the new holder controls it for real — they can set their own site.
        vm.prank(claimant);
        registry.setContenthash(node, OTHER_HASH);
        assertEq(registry.contenthash(node), OTHER_HASH);
    }

    /// Records are cleared in the same transaction, so the name stops resolving
    /// to the previous holder's site immediately rather than after a follow-up.
    function test_AdminTransfer_ClearsPreviousHoldersRecords() public {
        bytes32 node = _register("venue", organiser);
        assertEq(registry.contenthash(node), SWARM_HASH, "precondition: site is set");

        vm.prank(admin);
        registry.adminTransfer(node, claimant);

        assertEq(registry.contenthash(node), "", "name still resolves to the old site");
    }

    /// Reassignment must be distinguishable on chain from an ordinary sale —
    /// that legibility is the entire argument for having the power in the open.
    /// The mint moved the record version to 1; the reassignment moves it to 2.
    function test_AdminTransfer_EmitsDistinctEvent() public {
        bytes32 node = _register("venue", organiser);
        assertEq(registry.recordVersions(node), 1, "precondition: the mint is an ownership change");

        vm.expectEmit(true, false, false, true, address(registry));
        emit VersionChanged(node, 2);
        vm.expectEmit(true, true, true, true, address(registry));
        emit AdminTransfer(node, organiser, claimant);

        vm.prank(admin);
        registry.adminTransfer(node, claimant);
    }

    // ── The power is bounded ──────────────────────────────────────────────────

    function test_AdminTransfer_RevertNotRegistryOwner() public {
        bytes32 node = _register("venue", organiser);

        vm.expectRevert();
        vm.prank(stranger);
        registry.adminTransfer(node, claimant);

        // The organiser cannot reassign to themselves out of someone else's name.
        vm.expectRevert();
        vm.prank(organiser);
        registry.adminTransfer(node, organiser);
    }

    /// The sponsor holds the hot key that does routine automated work. It must
    /// NOT be able to reassign names — that separation is the reason this power
    /// lives on the registry owner rather than the registrar.
    function test_AdminTransfer_SponsorAndRegistrarCannotReassign() public {
        bytes32 node = _register("venue", organiser);

        vm.expectRevert();
        vm.prank(sponsor);
        registry.adminTransfer(node, claimant);

        vm.expectRevert();
        vm.prank(address(registrar));
        registry.adminTransfer(node, claimant);

        assertEq(registry.owner(node), organiser, "name moved despite the revert");
    }

    /// Burning is deliberately not reachable through this function: a burned
    /// name could never be reissued.
    function test_AdminTransfer_RevertToZeroAddress() public {
        bytes32 node = _register("venue", organiser);

        vm.expectRevert(L2Registry.AdminTransferToZero.selector);
        vm.prank(admin);
        registry.adminTransfer(node, address(0));
    }

    /// The admin seat changes hands only through `nominateAdmin` + `acceptAdmin`.
    /// Routing it through the abuse path would let one call hand over the whole
    /// registry; the error names the right door.
    function test_AdminTransfer_RevertOnBaseNode() public {
        // Read baseNode BEFORE expectRevert — otherwise the cheatcode binds to
        // the `baseNode()` view call instead of the transfer.
        bytes32 base = registry.baseNode();

        vm.expectRevert(L2Registry.AdminTransferBaseNode.selector);
        vm.prank(admin);
        registry.adminTransfer(base, claimant);

        assertEq(registry.owner(), admin, "registry admin changed");
    }

    function test_AdminTransfer_RevertOnUnregisteredName() public {
        bytes32 node = registry.makeNode(registry.baseNode(), "neverminted");

        vm.expectRevert(
            abi.encodeWithSelector(L2Registry.AdminTransferUnregistered.selector, node)
        );
        vm.prank(admin);
        registry.adminTransfer(node, claimant);
    }

    /// Scope check: this moves a token. It does not weaken `NotAvailable`, so
    /// the admin still cannot mint over a live name.
    function test_AdminTransfer_DoesNotEnableMintingOverALiveName() public {
        _register("venue", organiser);

        string[] memory keys = new string[](0);
        string[] memory vals = new string[](0);
        vm.expectRevert();
        vm.prank(sponsor);
        registrar.register("venue", claimant, SWARM_HASH, keys, vals);
    }

    /// After reassignment the previous holder has no residual control.
    function test_AdminTransfer_PreviousHolderLosesControl() public {
        bytes32 node = _register("venue", organiser);

        vm.prank(admin);
        registry.adminTransfer(node, claimant);

        vm.expectRevert();
        vm.prank(organiser);
        registry.setContenthash(node, OTHER_HASH);
    }

    /// A reassigned name is a normal NFT afterwards — the new holder can sell it
    /// on. Stated as a test because the abuse policy has to account for it.
    function test_AdminTransfer_ReassignedNameRemainsTransferable() public {
        bytes32 node = _register("venue", organiser);

        vm.prank(admin);
        registry.adminTransfer(node, claimant);

        vm.prank(claimant);
        registry.transferFrom(claimant, stranger, uint256(node));
        assertEq(registry.owner(node), stranger);
    }

    /// Self-transfer must be refused. `_transfer` permits `from == to`, so
    /// without an explicit guard `adminTransfer(node, currentOwner)` moves
    /// nothing but still resets the records — a one-call wipe-in-place with no
    /// transfer use.
    function test_AdminTransfer_RevertSelfTransfer() public {
        bytes32 node = _register("venue", organiser);

        vm.expectRevert(L2Registry.AdminTransferSameOwner.selector);
        vm.prank(admin);
        registry.adminTransfer(node, organiser);

        assertEq(registry.contenthash(node), SWARM_HASH, "records were wiped in place");
    }

    /// The classic forced-transfer hazard: a stale approval surviving the move
    /// would let the previous holder's approvee take the name straight back.
    /// v2.2 refuses approvals outright, so there is none to survive; the
    /// would-be accomplice is refused like any stranger.
    function test_AdminTransfer_StaleApprovalCannotClawBack() public {
        bytes32 node = _register("venue", organiser);

        address accomplice = makeAddr("accomplice");
        vm.prank(organiser);
        vm.expectRevert(L2Registry.DelegationNotSupported.selector);
        registry.approve(accomplice, uint256(node));

        vm.prank(admin);
        registry.adminTransfer(node, claimant);

        vm.expectRevert();
        vm.prank(accomplice);
        registry.transferFrom(claimant, organiser, uint256(node));

        assertEq(registry.owner(node), claimant);
    }

    /// Records cleared must mean ALL record types, not just the contenthash —
    /// the address records are the money-relevant ones.
    function test_AdminTransfer_ClearsAddrAndTextNotJustContenthash() public {
        string[] memory keys = new string[](1);
        string[] memory vals = new string[](1);
        keys[0] = "url";
        vals[0] = "https://squatter.example";

        vm.prank(sponsor);
        registrar.register("venue", organiser, SWARM_HASH, keys, vals);
        bytes32 node = registry.makeNode(registry.baseNode(), "venue");

        assertEq(registry.addr(node), organiser, "precondition: addr set at mint");
        assertEq(registry.text(node, "url"), "https://squatter.example");

        vm.prank(admin);
        registry.adminTransfer(node, claimant);

        assertEq(registry.addr(node), address(0), "addr record survived");
        assertEq(registry.text(node, "url"), "", "text record survived");

        // And the new holder can set their own.
        vm.prank(claimant);
        registry.setAddr(node, claimant);
        assertEq(registry.addr(node), claimant);
    }

    /// Reassigning a parent does NOT cascade to children the previous holder
    /// minted — a cascade would be unbounded gas. The admin must chase each
    /// child individually (they are discoverable via SubnodeCreated). Pinned
    /// because the abuse policy and takedown runbook depend on knowing it.
    function test_AdminTransfer_DoesNotCascadeToChildren() public {
        bytes32 parent = _register("venue", organiser);

        bytes[] memory noData = new bytes[](0);
        vm.prank(organiser);
        registry.createSubnode(parent, "shop", organiser, noData);
        bytes32 child = registry.makeNode(parent, "shop");
        assertEq(registry.owner(child), organiser);

        vm.prank(admin);
        registry.adminTransfer(parent, claimant);

        assertEq(registry.owner(parent), claimant, "parent moved");
        assertEq(registry.owner(child), organiser, "child is NOT cascaded - chase it separately");

        // The admin can chase it, one node at a time.
        vm.prank(admin);
        registry.adminTransfer(child, claimant);
        assertEq(registry.owner(child), claimant);
    }

    /// A forced transfer must not be blockable by a hostile or non-compliant
    /// recipient — which is why `_transfer` is used rather than a safe transfer.
    function test_AdminTransfer_SucceedsToRecipientThatRejectsERC721() public {
        bytes32 node = _register("venue", organiser);
        address inert = address(new RejectsERC721());

        vm.prank(admin);
        registry.adminTransfer(node, inert);
        assertEq(registry.owner(node), inert, "a hostile receiver blocked a forced transfer");

        // And a mis-send is recoverable: the power can simply re-run.
        vm.prank(admin);
        registry.adminTransfer(node, claimant);
        assertEq(registry.owner(node), claimant);
    }

    /// The accepted power, pinned so no published policy claims more than the
    /// contract delivers (owner decision 2026-09-14): the admin seat can rewrite
    /// any name's records IN PLACE, in two visible transactions, by enrolling
    /// itself as a registrar. The name does not move.
    function test_Governance_CanReachAddrRecordsViaAddRegistrar() public {
        bytes32 node = _register("venue", organiser);

        vm.startPrank(admin);
        registry.addRegistrar(admin);
        registry.setAddr(node, stranger);
        vm.stopPrank();

        assertEq(registry.addr(node), stranger);
        assertEq(registry.owner(node), organiser, "the name itself did not move");
    }

    /// The two visible steps by which the admin seat can end a name, pinned so
    /// no policy says "never burned" (audit 937 F14 / 938 M-1).
    function test_Governance_CanEndANameInTwoVisibleSteps() public {
        bytes32 node = _register("venue", organiser);

        vm.expectEmit(true, true, true, true, address(registry));
        emit AdminTransfer(node, organiser, admin);
        vm.startPrank(admin);
        registry.adminTransfer(node, admin);
        registry.release(node);
        vm.stopPrank();

        assertEq(registry.owner(node), address(0));
        (address previous,) = registry.lastRelease(node);
        assertEq(previous, admin, "the release record names the seat, not the organiser");
    }

    // ── setText removal ───────────────────────────────────────────────────────

    /// `setText` was removed from the registrar (#422): the server never called
    /// it, so it was standing authority over holders' profile records with no
    /// operational benefit. The holder retains their own path via the registry.
    function test_HolderCanStillSetOwnTextRecords() public {
        bytes32 node = _register("venue", organiser);

        vm.prank(organiser);
        registry.setText(node, "url", "https://example.com");
        assertEq(registry.text(node, "url"), "https://example.com");
    }
}

contract RejectsERC721 {
    // Deliberately implements no onERC721Received.
}
