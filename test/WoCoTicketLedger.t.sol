// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {WoCoTicketLedger} from "../src/WoCoTicketLedger.sol";

/**
 * WoCoTicketLedger tests.
 *
 * NOTE ON COVERAGE: WoCoEventV2's 57 tests put nearly all of their negative-path
 * coverage on `payAndClaim`/`batchPayAndClaim`. Mutation testing on that suite
 * showed 11 of the 12 guards on `claimFor`/`batchClaimFor` — the only paths ever
 * reachable in production — could each be deleted with all 57 tests still
 * passing. Only `claimFor`'s `SalesClosed` check was caught.
 *
 * So this file is NOT a port of the old negative paths onto a smaller surface;
 * the guard tests below are written against the sponsor paths for the first
 * time. Every guard in the contract has a test that fails if it is removed.
 */
contract WoCoTicketLedgerTest is Test {
    WoCoTicketLedger public ledger;

    address owner     = address(0x1);
    address sponsor   = address(0x2);
    address organiser = address(0x3);
    address buyer     = address(0x6);
    address recipient = address(0x8);
    address daoAuth   = address(0x9);
    address stranger  = address(0xBEEF);

    bytes32 constant MANIFEST = keccak256("manifest");
    uint64  constant SUPPLY   = 10;
    uint64  END_TS; // set in setUp (block.timestamp + 7d)

    function setUp() public {
        ledger = new WoCoTicketLedger(owner, sponsor);
        // safe: block.timestamp + 7 days well within uint64
        // forge-lint: disable-next-line(unsafe-typecast)
        END_TS = uint64(block.timestamp + 7 days);
    }

    /// Registration goes through the sponsor wallet, as it does in production:
    /// the caller is the platform, `organiser` is stamped separately.
    function _register() internal returns (bytes32 eventId) {
        vm.prank(sponsor);
        eventId = ledger.registerEvent(organiser, SUPPLY, MANIFEST, END_TS);
    }

    /// Mirrors the contract's derivation. Written out in full rather than
    /// calling a helper on the contract, so a change to the derivation has to
    /// be made deliberately in two places instead of silently agreeing with
    /// itself. The server keeps a third copy in `deriveEventId`.
    function _expectedId(address registrant, uint256 nonce) internal view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(ledger), registrant, nonce));
    }

    function _owners(uint256 n) internal view returns (address[] memory a) {
        a = new address[](n);
        for (uint256 i; i < n; ++i) a[i] = buyer;
    }

    // ── Constructor ───────────────────────────────────────────────────────────

    function test_Constructor_SetsState() public view {
        assertEq(ledger.owner(), owner);
        assertTrue(ledger.authorisedSponsors(sponsor));
        assertEq(ledger.disputeAuthority(), owner);
    }

    function test_Constructor_RevertZeroSponsor() public {
        vm.expectRevert(WoCoTicketLedger.ZeroAddress.selector);
        new WoCoTicketLedger(owner, address(0));
    }

    // ── registerEvent ─────────────────────────────────────────────────────────

    function test_RegisterEvent_Success_Core() public {
        bytes32 eventId = _register();
        (uint64 totalSupply, uint64 nextSlot, address org, bytes32 manifest) =
            ledger.getEvent(eventId);

        assertEq(totalSupply, SUPPLY);
        assertEq(nextSlot, 0);
        assertEq(org, organiser);
        assertEq(manifest, MANIFEST);
    }

    function test_RegisterEvent_Success_Status() public {
        bytes32 eventId = _register();
        (uint64 endTs, bool cancelled) = ledger.getEventStatus(eventId);
        assertEq(endTs, END_TS);
        assertFalse(cancelled);
    }

    /// The core semantic change from V2: the caller is the platform's sponsor
    /// wallet, and `organiser` is a stamped field, NOT `msg.sender`. Under V2
    /// this address was the sponsor for every production event.
    function test_RegisterEvent_StampsOrganiserNotCaller() public {
        bytes32 eventId = _register();
        (, , address org, ) = ledger.getEvent(eventId);
        assertEq(org, organiser);
        assertTrue(org != sponsor, "organiser must not be the registrant");
    }

    /// eventId derivation is keyed by the REGISTRANT and clients predict ids
    /// from sequential nonces. Guards that derivation against silent change.
    function test_RegisterEvent_NonceIncrementsPerRegistrant() public {
        assertEq(ledger.registrantNonce(sponsor), 0);

        bytes32 first  = _register();
        assertEq(ledger.registrantNonce(sponsor), 1);
        bytes32 second = _register();
        assertEq(ledger.registrantNonce(sponsor), 2);

        assertTrue(first != second);
        assertEq(first,  _expectedId(sponsor, 0));
        assertEq(second, _expectedId(sponsor, 1));

        // The organiser's own counter is untouched — it is not the key.
        assertEq(ledger.registrantNonce(organiser), 0);
    }

    /// The cutover regression. WoCoEventV2 hashed only (msg.sender, nonce), so
    /// this ledger — same sponsor wallet, nonce restarting at 0 — reproduced
    /// V2's ids exactly. Ids live in Swarm feeds that outlive a migration, so
    /// after a flip an old id would resolve here and, once the count passed it,
    /// return a DIFFERENT event: wrong supply, wrong gate, a mint against
    /// someone else's allocation.
    function test_RegisterEvent_IdCannotCollideWithV2Derivation() public {
        bytes32 id = _register();

        bytes32 v2Shape = keccak256(abi.encode(sponsor, uint256(0)));
        assertTrue(id != v2Shape, "ledger id reproduced V2's derivation");
        assertEq(id, _expectedId(sponsor, 0));
    }

    /// Domain separation by contract: two deployments cannot mint the same id
    /// from the same registrant at the same nonce. This is what makes a future
    /// successor contract structurally safe rather than dependent on remembering
    /// to use a fresh sponsor wallet.
    function test_RegisterEvent_IdDiffersAcrossContractInstances() public {
        WoCoTicketLedger other = new WoCoTicketLedger(owner, sponsor);

        vm.prank(sponsor);
        bytes32 idA = ledger.registerEvent(organiser, SUPPLY, MANIFEST, END_TS);
        vm.prank(sponsor);
        bytes32 idB = other.registerEvent(organiser, SUPPLY, MANIFEST, END_TS);

        // Same registrant, same nonce (0 on each), same args — only the
        // deployment differs.
        assertEq(ledger.registrantNonce(sponsor), 1);
        assertEq(other.registrantNonce(sponsor), 1);
        assertTrue(idA != idB, "two deployments minted the same eventId");
    }

    /// Domain separation by chain: the same contract at the same address on two
    /// chains cannot mint the same id. Already a live ambiguity for V1, which is
    /// deployed on both Base Sepolia and Arbitrum Sepolia.
    function test_RegisterEvent_IdDiffersAcrossChains() public {
        uint256 originalChain = block.chainid;

        vm.chainId(8453);
        vm.prank(sponsor);
        bytes32 onBase = ledger.registerEvent(organiser, SUPPLY, MANIFEST, END_TS);
        assertEq(onBase, keccak256(abi.encode(uint256(8453), address(ledger), sponsor, uint256(0))));

        // The same (contract, registrant, nonce) on a different chain would have
        // produced a different id — which is the property under test.
        assertTrue(
            onBase != keccak256(abi.encode(originalChain, address(ledger), sponsor, uint256(0))),
            "chainid does not participate in the derivation"
        );

        vm.chainId(originalChain);
    }

    function test_RegisterEvent_RevertZeroOrganiser() public {
        vm.expectRevert(WoCoTicketLedger.ZeroAddress.selector);
        vm.prank(sponsor);
        ledger.registerEvent(address(0), SUPPLY, MANIFEST, END_TS);
    }

    function test_RegisterEvent_RevertZeroSupply() public {
        vm.expectRevert(WoCoTicketLedger.InsufficientSupply.selector);
        vm.prank(sponsor);
        ledger.registerEvent(organiser, 0, MANIFEST, END_TS);
    }

    function test_RegisterEvent_RevertZeroManifest() public {
        vm.expectRevert(WoCoTicketLedger.ZeroAddress.selector);
        vm.prank(sponsor);
        ledger.registerEvent(organiser, SUPPLY, bytes32(0), END_TS);
    }

    function test_RegisterEvent_RevertPastEndTs() public {
        vm.expectRevert(WoCoTicketLedger.InvalidEventEnd.selector);
        vm.prank(sponsor);
        // forge-lint: disable-next-line(unsafe-typecast)
        ledger.registerEvent(organiser, SUPPLY, MANIFEST, uint64(block.timestamp));
    }

    /// Registration is permissionless — it is not a sponsor-gated call. This
    /// pins that deliberately, so a future change has to argue with a test.
    function test_RegisterEvent_OpenToAnyCaller() public {
        vm.prank(stranger);
        bytes32 eventId = ledger.registerEvent(organiser, SUPPLY, MANIFEST, END_TS);
        (, , address org, ) = ledger.getEvent(eventId);
        assertEq(org, organiser);
        assertEq(ledger.registrantNonce(stranger), 1);
    }

    // ── claimFor: happy path ──────────────────────────────────────────────────

    function test_ClaimFor_SponsorMints() public {
        bytes32 eventId = _register();

        vm.prank(sponsor);
        uint256 slot = ledger.claimFor(eventId, buyer, keccak256("stripe-ref"));

        assertEq(slot, 0);
        assertEq(ledger.slotOwner(eventId, 0), buyer);

        (address slotOwner_, address claimer, bytes32 ref) = ledger.getSlotData(eventId, 0);
        assertEq(slotOwner_, buyer);
        assertEq(claimer, sponsor);
        assertEq(ref, keccak256("stripe-ref"));
    }

    function test_ClaimFor_AllocatesSequentially() public {
        bytes32 eventId = _register();

        vm.prank(sponsor);
        assertEq(ledger.claimFor(eventId, buyer, bytes32(0)), 0);
        vm.prank(sponsor);
        assertEq(ledger.claimFor(eventId, recipient, bytes32(0)), 1);

        (, uint64 nextSlot, , ) = ledger.getEvent(eventId);
        assertEq(nextSlot, 2);
        assertEq(ledger.remaining(eventId), SUPPLY - 2);
    }

    // ── claimFor: guards (NEW coverage — none of these existed on this path) ──

    function test_ClaimFor_RevertUnauthorised() public {
        bytes32 eventId = _register();
        vm.expectRevert(WoCoTicketLedger.NotAuthorised.selector);
        vm.prank(buyer);
        ledger.claimFor(eventId, buyer, bytes32(0));
    }

    function test_ClaimFor_RevertZeroOwner() public {
        bytes32 eventId = _register();
        vm.expectRevert(WoCoTicketLedger.ZeroAddress.selector);
        vm.prank(sponsor);
        ledger.claimFor(eventId, address(0), bytes32(0));
    }

    function test_ClaimFor_RevertEventNotFound() public {
        vm.expectRevert(WoCoTicketLedger.EventNotFound.selector);
        vm.prank(sponsor);
        ledger.claimFor(keccak256("nope"), buyer, bytes32(0));
    }

    function test_ClaimFor_RevertCancelled() public {
        bytes32 eventId = _register();
        vm.prank(organiser);
        ledger.cancelEvent(eventId);

        vm.expectRevert(WoCoTicketLedger.AlreadyCancelled.selector);
        vm.prank(sponsor);
        ledger.claimFor(eventId, buyer, bytes32(0));
    }

    function test_ClaimFor_RevertAfterEventEnds() public {
        bytes32 eventId = _register();
        vm.warp(uint256(END_TS));

        vm.expectRevert(WoCoTicketLedger.SalesClosed.selector);
        vm.prank(sponsor);
        ledger.claimFor(eventId, buyer, bytes32(0));
    }

    function test_ClaimFor_RevertSoldOut() public {
        bytes32 eventId = _register();

        vm.prank(sponsor);
        ledger.batchClaimFor(eventId, _owners(SUPPLY), bytes32(0));

        vm.expectRevert(WoCoTicketLedger.InsufficientSupply.selector);
        vm.prank(sponsor);
        ledger.claimFor(eventId, buyer, bytes32(0));
    }

    // ── batchClaimFor: happy path ─────────────────────────────────────────────

    function test_BatchClaimFor_Sponsor() public {
        bytes32 eventId = _register();
        address[] memory owners = new address[](2);
        owners[0] = buyer;
        owners[1] = recipient;

        vm.prank(sponsor);
        uint256 first = ledger.batchClaimFor(eventId, owners, keccak256("stripe-batch"));

        assertEq(first, 0);
        assertEq(ledger.slotOwner(eventId, 0), buyer);
        assertEq(ledger.slotOwner(eventId, 1), recipient);

        // Both slots resolve to the same batch metadata.
        (, address claimer0, bytes32 ref0) = ledger.getSlotData(eventId, 0);
        (, address claimer1, bytes32 ref1) = ledger.getSlotData(eventId, 1);
        assertEq(claimer0, sponsor);
        assertEq(claimer1, sponsor);
        assertEq(ref0, keccak256("stripe-batch"));
        assertEq(ref1, keccak256("stripe-batch"));
    }

    function test_BatchClaimFor_ExactlyFillsSupply() public {
        bytes32 eventId = _register();
        vm.prank(sponsor);
        ledger.batchClaimFor(eventId, _owners(SUPPLY), bytes32(0));
        assertEq(ledger.remaining(eventId), 0);
    }

    // ── batchClaimFor: guards (NEW coverage on this path) ─────────────────────

    function test_BatchClaimFor_RevertUnauthorised() public {
        bytes32 eventId = _register();
        vm.expectRevert(WoCoTicketLedger.NotAuthorised.selector);
        vm.prank(buyer);
        ledger.batchClaimFor(eventId, _owners(2), bytes32(0));
    }

    function test_BatchClaimFor_RevertEmpty() public {
        bytes32 eventId = _register();
        vm.expectRevert(WoCoTicketLedger.BatchEmpty.selector);
        vm.prank(sponsor);
        ledger.batchClaimFor(eventId, new address[](0), bytes32(0));
    }

    function test_BatchClaimFor_RevertTooLarge() public {
        vm.prank(sponsor);
        bytes32 eventId = ledger.registerEvent(organiser, 200, MANIFEST, END_TS);

        vm.expectRevert(WoCoTicketLedger.BatchTooLarge.selector);
        vm.prank(sponsor);
        ledger.batchClaimFor(eventId, _owners(101), bytes32(0));
    }

    function test_BatchClaimFor_AcceptsBatchLimit() public {
        vm.prank(sponsor);
        bytes32 eventId = ledger.registerEvent(organiser, 200, MANIFEST, END_TS);

        vm.prank(sponsor);
        ledger.batchClaimFor(eventId, _owners(100), bytes32(0));
        assertEq(ledger.remaining(eventId), 100);
    }

    function test_BatchClaimFor_RevertOverflowsSupply() public {
        bytes32 eventId = _register();
        vm.expectRevert(WoCoTicketLedger.InsufficientSupply.selector);
        vm.prank(sponsor);
        ledger.batchClaimFor(eventId, _owners(SUPPLY + 1), bytes32(0));
    }

    function test_BatchClaimFor_RevertZeroOwner() public {
        bytes32 eventId = _register();
        address[] memory owners = new address[](2);
        owners[0] = buyer;
        owners[1] = address(0);

        vm.expectRevert(WoCoTicketLedger.ZeroAddress.selector);
        vm.prank(sponsor);
        ledger.batchClaimFor(eventId, owners, bytes32(0));
    }

    function test_BatchClaimFor_RevertEventNotFound() public {
        vm.expectRevert(WoCoTicketLedger.EventNotFound.selector);
        vm.prank(sponsor);
        ledger.batchClaimFor(keccak256("nope"), _owners(2), bytes32(0));
    }

    function test_BatchClaimFor_RevertCancelled() public {
        bytes32 eventId = _register();
        vm.prank(organiser);
        ledger.cancelEvent(eventId);

        vm.expectRevert(WoCoTicketLedger.AlreadyCancelled.selector);
        vm.prank(sponsor);
        ledger.batchClaimFor(eventId, _owners(2), bytes32(0));
    }

    function test_BatchClaimFor_RevertAfterEventEnds() public {
        bytes32 eventId = _register();
        vm.warp(uint256(END_TS));

        vm.expectRevert(WoCoTicketLedger.SalesClosed.selector);
        vm.prank(sponsor);
        ledger.batchClaimFor(eventId, _owners(2), bytes32(0));
    }

    // ── cancelEvent ───────────────────────────────────────────────────────────

    function test_Cancel_OrganiserCancels() public {
        bytes32 eventId = _register();

        vm.prank(organiser);
        ledger.cancelEvent(eventId);

        (, bool cancelled) = ledger.getEventStatus(eventId);
        assertTrue(cancelled);
    }

    /// The stamped organiser cancels — NOT the registrant. Under V2 these were
    /// the same address in production; here they are deliberately different.
    function test_Cancel_RevertRegistrantIsNotOrganiser() public {
        bytes32 eventId = _register();
        vm.expectRevert(WoCoTicketLedger.NotOrganiser.selector);
        vm.prank(sponsor);
        ledger.cancelEvent(eventId);
    }

    /// The guarantee: a sponsor's only power is to append slots. An authorised
    /// sponsor — including any future payments contract — cannot cancel.
    function test_Cancel_SponsorCannotCancel() public {
        bytes32 eventId = _register();

        address paymentsContract = address(0xAA1);
        vm.prank(owner);
        ledger.addSponsor(paymentsContract);

        vm.expectRevert(WoCoTicketLedger.NotOrganiser.selector);
        vm.prank(paymentsContract);
        ledger.cancelEvent(eventId);
    }

    function test_Cancel_RevertNotOrganiser() public {
        bytes32 eventId = _register();
        vm.expectRevert(WoCoTicketLedger.NotOrganiser.selector);
        vm.prank(buyer);
        ledger.cancelEvent(eventId);
    }

    function test_Cancel_RevertDouble() public {
        bytes32 eventId = _register();
        vm.prank(organiser);
        ledger.cancelEvent(eventId);

        vm.expectRevert(WoCoTicketLedger.AlreadyCancelled.selector);
        vm.prank(organiser);
        ledger.cancelEvent(eventId);
    }

    function test_Cancel_RevertEventNotFound() public {
        vm.expectRevert(WoCoTicketLedger.EventNotFound.selector);
        vm.prank(organiser);
        ledger.cancelEvent(keccak256("nope"));
    }

    /// Cancellation must actually stop minting — the flag is only meaningful
    /// because the mint paths read it.
    function test_Cancel_BlocksBothMintPaths() public {
        bytes32 eventId = _register();
        vm.prank(organiser);
        ledger.cancelEvent(eventId);

        vm.expectRevert(WoCoTicketLedger.AlreadyCancelled.selector);
        vm.prank(sponsor);
        ledger.claimFor(eventId, buyer, bytes32(0));

        vm.expectRevert(WoCoTicketLedger.AlreadyCancelled.selector);
        vm.prank(sponsor);
        ledger.batchClaimFor(eventId, _owners(1), bytes32(0));
    }

    /// Slots minted before cancellation are untouched — cancelling stops future
    /// mints, it does not rewrite the ledger.
    function test_Cancel_PreservesExistingSlots() public {
        bytes32 eventId = _register();
        vm.prank(sponsor);
        ledger.claimFor(eventId, buyer, keccak256("ref"));

        vm.prank(organiser);
        ledger.cancelEvent(eventId);

        assertEq(ledger.slotOwner(eventId, 0), buyer);
        (address o, address c, bytes32 r) = ledger.getSlotData(eventId, 0);
        assertEq(o, buyer);
        assertEq(c, sponsor);
        assertEq(r, keccak256("ref"));
    }

    // ── forceCancelEvent ──────────────────────────────────────────────────────

    function test_ForceCancel_DisputeAuthorityCancels() public {
        bytes32 eventId = _register();

        vm.prank(owner);
        ledger.forceCancelEvent(eventId);

        (, bool cancelled) = ledger.getEventStatus(eventId);
        assertTrue(cancelled);
    }

    function test_ForceCancel_RevertNotDisputeAuthority() public {
        bytes32 eventId = _register();

        // Not the organiser, not a sponsor, not a stranger.
        vm.expectRevert(WoCoTicketLedger.NotDisputeAuthority.selector);
        vm.prank(organiser);
        ledger.forceCancelEvent(eventId);

        vm.expectRevert(WoCoTicketLedger.NotDisputeAuthority.selector);
        vm.prank(sponsor);
        ledger.forceCancelEvent(eventId);
    }

    function test_ForceCancel_RevertDouble() public {
        bytes32 eventId = _register();
        vm.prank(owner);
        ledger.forceCancelEvent(eventId);

        vm.expectRevert(WoCoTicketLedger.AlreadyCancelled.selector);
        vm.prank(owner);
        ledger.forceCancelEvent(eventId);
    }

    function test_ForceCancel_RevertEventNotFound() public {
        vm.expectRevert(WoCoTicketLedger.EventNotFound.selector);
        vm.prank(owner);
        ledger.forceCancelEvent(keccak256("nope"));
    }

    function test_SetDisputeAuthority_RotatesPower() public {
        bytes32 eventId = _register();

        vm.prank(owner);
        ledger.setDisputeAuthority(daoAuth);
        assertEq(ledger.disputeAuthority(), daoAuth);

        // Old authority loses the power.
        vm.expectRevert(WoCoTicketLedger.NotDisputeAuthority.selector);
        vm.prank(owner);
        ledger.forceCancelEvent(eventId);

        vm.prank(daoAuth);
        ledger.forceCancelEvent(eventId);
        (, bool cancelled) = ledger.getEventStatus(eventId);
        assertTrue(cancelled);
    }

    function test_SetDisputeAuthority_RevertZero() public {
        vm.expectRevert(WoCoTicketLedger.ZeroAddress.selector);
        vm.prank(owner);
        ledger.setDisputeAuthority(address(0));
    }

    // ── Views ─────────────────────────────────────────────────────────────────

    function test_GetEvent_RevertNotFound() public {
        vm.expectRevert(WoCoTicketLedger.EventNotFound.selector);
        ledger.getEvent(keccak256("nope"));
    }

    function test_GetEventStatus_RevertNotFound() public {
        vm.expectRevert(WoCoTicketLedger.EventNotFound.selector);
        ledger.getEventStatus(keccak256("nope"));
    }

    function test_Remaining_UnknownEventIsZero() public view {
        assertEq(ledger.remaining(keccak256("nope")), 0);
    }

    function test_SlotOwner_UnclaimedIsZero() public {
        bytes32 eventId = _register();
        assertEq(ledger.slotOwner(eventId, 5), address(0));
    }

    // ── Admin ─────────────────────────────────────────────────────────────────

    function test_AddRemoveSponsor() public {
        address newSponsor = address(0x99);
        vm.prank(owner);
        ledger.addSponsor(newSponsor);
        assertTrue(ledger.authorisedSponsors(newSponsor));

        vm.prank(owner);
        ledger.removeSponsor(newSponsor);
        assertFalse(ledger.authorisedSponsors(newSponsor));
    }

    function test_AddSponsor_RevertZero() public {
        vm.expectRevert(WoCoTicketLedger.ZeroAddress.selector);
        vm.prank(owner);
        ledger.addSponsor(address(0));
    }

    /// The replacement mechanism the split exists for: swapping the sponsor set
    /// changes who may mint, and leaves every existing slot exactly where it is.
    function test_SponsorSwap_RevokesMintAndPreservesSlots() public {
        bytes32 eventId = _register();

        vm.prank(sponsor);
        ledger.claimFor(eventId, buyer, bytes32(0));

        address newPayments = address(0xBB1);
        vm.startPrank(owner);
        ledger.removeSponsor(sponsor);
        ledger.addSponsor(newPayments);
        vm.stopPrank();

        // Old sponsor can no longer mint.
        vm.expectRevert(WoCoTicketLedger.NotAuthorised.selector);
        vm.prank(sponsor);
        ledger.claimFor(eventId, recipient, bytes32(0));

        // New one can, and the earlier slot is untouched.
        vm.prank(newPayments);
        assertEq(ledger.claimFor(eventId, recipient, bytes32(0)), 1);
        assertEq(ledger.slotOwner(eventId, 0), buyer);
    }

    // ── Event emission ────────────────────────────────────────────────────────
    //
    // The server parses these logs out of tx receipts — `registerEventV2` reads
    // the `Registered` log for the eventId, and `parseSlotClaimedSlots` reads
    // `SlotClaimed` for allocated slots. Log shape IS the server's API, so a
    // deleted or corrupted `emit` is a production break that no state assertion
    // in this file would catch.

    event Registered(
        bytes32 indexed eventId,
        address indexed organiser,
        address indexed registrant,
        uint64  supply,
        bytes32 manifestRef,
        uint64  eventEndTs
    );
    event SlotClaimed(
        bytes32 indexed eventId,
        uint256 indexed slot,
        address indexed owner,
        address claimer,
        bytes32 orderRef
    );
    event EventCancelled(bytes32 indexed eventId, address indexed by);

    function test_Emit_Registered() public {
        bytes32 expectedId = _expectedId(sponsor, 0);

        vm.expectEmit(true, true, true, true, address(ledger));
        emit Registered(expectedId, organiser, sponsor, SUPPLY, MANIFEST, END_TS);

        vm.prank(sponsor);
        ledger.registerEvent(organiser, SUPPLY, MANIFEST, END_TS);
    }

    function test_Emit_SlotClaimed() public {
        bytes32 eventId = _register();

        vm.expectEmit(true, true, true, true, address(ledger));
        emit SlotClaimed(eventId, 0, buyer, sponsor, keccak256("ref"));

        vm.prank(sponsor);
        ledger.claimFor(eventId, buyer, keccak256("ref"));
    }

    /// One log per slot, each carrying its own owner — the server counts these
    /// to map a batch back to individual allocated slots.
    function test_Emit_SlotClaimed_OnePerBatchMember() public {
        bytes32 eventId = _register();
        address[] memory owners = new address[](2);
        owners[0] = buyer;
        owners[1] = recipient;

        vm.expectEmit(true, true, true, true, address(ledger));
        emit SlotClaimed(eventId, 0, buyer, sponsor, keccak256("batch"));
        vm.expectEmit(true, true, true, true, address(ledger));
        emit SlotClaimed(eventId, 1, recipient, sponsor, keccak256("batch"));

        vm.prank(sponsor);
        ledger.batchClaimFor(eventId, owners, keccak256("batch"));
    }

    function test_Emit_EventCancelled_CarriesCanceller() public {
        bytes32 eventId = _register();

        vm.expectEmit(true, true, false, true, address(ledger));
        emit EventCancelled(eventId, organiser);
        vm.prank(organiser);
        ledger.cancelEvent(eventId);

        // forceCancelEvent emits the same event, stamped with the authority —
        // that is how the two cancellation routes are told apart on chain.
        bytes32 second = _register();
        vm.expectEmit(true, true, false, true, address(ledger));
        emit EventCancelled(second, owner);
        vm.prank(owner);
        ledger.forceCancelEvent(second);
    }

    /// Admin events are the on-chain record of who holds mint and dispute
    /// authority. Nothing off-chain parses them, but an authority change that
    /// leaves no trace defeats the point of an auditable ledger.
    event SponsorAdded(address indexed sponsor);
    event SponsorRemoved(address indexed sponsor);
    event DisputeAuthorityUpdated(address indexed authority);

    function test_Emit_ConstructorLogsInitialAuthority() public {
        vm.expectEmit(true, false, false, true);
        emit SponsorAdded(sponsor);
        vm.expectEmit(true, false, false, true);
        emit DisputeAuthorityUpdated(owner);

        new WoCoTicketLedger(owner, sponsor);
    }

    function test_Emit_SponsorAddedAndRemoved() public {
        address newSponsor = address(0x99);

        vm.expectEmit(true, false, false, true, address(ledger));
        emit SponsorAdded(newSponsor);
        vm.prank(owner);
        ledger.addSponsor(newSponsor);

        vm.expectEmit(true, false, false, true, address(ledger));
        emit SponsorRemoved(newSponsor);
        vm.prank(owner);
        ledger.removeSponsor(newSponsor);
    }

    function test_Emit_DisputeAuthorityUpdated() public {
        vm.expectEmit(true, false, false, true, address(ledger));
        emit DisputeAuthorityUpdated(daoAuth);
        vm.prank(owner);
        ledger.setDisputeAuthority(daoAuth);
    }

    // ── Boundaries the guarantee depends on ───────────────────────────────────

    /// The cutoff is exclusive: the last second before `eventEndTs` still
    /// mints. Only the revert side of this boundary was covered otherwise.
    function test_ClaimFor_SucceedsOneSecondBeforeCutoff() public {
        bytes32 eventId = _register();
        vm.warp(uint256(END_TS) - 1);

        vm.prank(sponsor);
        assertEq(ledger.claimFor(eventId, buyer, bytes32(0)), 0);
    }

    /// Pins the documented scope of the guarantee: registration is
    /// permissionless, so a sponsor CAN register its own event and cancel it.
    /// That is not sponsor authority — it is what any address can do — but it
    /// is the reason the natspec sentence is scoped, so it is pinned here
    /// deliberately rather than left for a reader to discover as a refutation.
    function test_Guarantee_SponsorMayCancelOnlyItsOwnRegistrations() public {
        // An event the sponsor did NOT register: cancel is closed to it.
        bytes32 theirs = _register();
        vm.expectRevert(WoCoTicketLedger.NotOrganiser.selector);
        vm.prank(sponsor);
        ledger.cancelEvent(theirs);

        // An event the sponsor registered naming ITSELF organiser: cancel opens.
        vm.prank(sponsor);
        bytes32 ours = ledger.registerEvent(sponsor, SUPPLY, MANIFEST, END_TS);
        vm.prank(sponsor);
        ledger.cancelEvent(ours);

        (, bool cancelled) = ledger.getEventStatus(ours);
        assertTrue(cancelled);
        // The other event is untouched — the power does not generalise.
        (, bool stillLive) = ledger.getEventStatus(theirs);
        assertFalse(stillLive);
    }

    /// `organiser` is an unauthenticated assertion: anyone may name any address.
    /// Pinned so the property is deliberate, and so indexers inherit the warning.
    function test_Register_OrganiserIsAssertedNotProven() public {
        vm.prank(stranger);
        bytes32 eventId = ledger.registerEvent(organiser, SUPPLY, MANIFEST, END_TS);

        (, , address org, ) = ledger.getEvent(eventId);
        assertEq(org, organiser, "stranger named an organiser that never consented");

        // The blast radius is bounded: the named organiser gains only the
        // one-way, buyer-protective cancel on this event.
        vm.prank(organiser);
        ledger.cancelEvent(eventId);
        (, bool cancelled) = ledger.getEventStatus(eventId);
        assertTrue(cancelled);
    }

    /// getSlotData on an UNCLAIMED slot returns the batch-0 claimer/orderRef,
    /// not zeroes, because `batchFirstSlot` defaults to 0. Callers must gate on
    /// `owner`. Pinned because payments will read this view.
    function test_GetSlotData_UnclaimedSlotMisattributesBatchFields() public {
        bytes32 eventId = _register();

        vm.prank(sponsor);
        ledger.claimFor(eventId, buyer, keccak256("real-order"));

        (address owner_, address claimer, bytes32 ref) = ledger.getSlotData(eventId, 7);

        assertEq(owner_, address(0), "slot 7 was never claimed");
        // These are slot 0's values leaking through, NOT zeroes — the exact
        // reason the natspec tells callers to check `owner` first.
        assertEq(claimer, sponsor);
        assertEq(ref, keccak256("real-order"));
    }

    function test_Admin_RevertNonOwner() public {
        vm.expectRevert();
        vm.prank(buyer);
        ledger.addSponsor(address(0x99));

        vm.expectRevert();
        vm.prank(buyer);
        ledger.removeSponsor(sponsor);

        vm.expectRevert();
        vm.prank(buyer);
        ledger.setDisputeAuthority(daoAuth);
    }
}
