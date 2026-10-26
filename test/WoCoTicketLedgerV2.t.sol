// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {WoCoTicketLedger} from "../src/WoCoTicketLedger.sol";

/**
 * Version 2 of WoCoTicketLedger: seats the registrant can change
 * (`setSupply`), a cutoff it can only move later (`extendSalesEnd`), the
 * platform's replacement of a bearer ticket (`reissue`), and the one-way off
 * switch for it (`disableBearerMints`).
 *
 * As in WoCoTicketLedger.t.sol, every new guard has a test that fails if the
 * guard is removed; the invariant suite proves the properties across random
 * sequences.
 */
contract WoCoTicketLedgerV2Test is Test {
    WoCoTicketLedger public ledger;

    address owner     = address(0x1);
    address sponsor   = address(0x2);
    address organiser = address(0x3);
    address sponsor2  = address(0x4);
    address daoAuth   = address(0x9);
    address stranger  = address(0xBEEF);
    address fresh     = address(0xF2E5);

    uint256 constant HOLDER_KEY = 0xA11CE;
    address holder;

    bytes32 constant MANIFEST = keccak256("manifest");
    bytes32 constant ORDER    = keccak256("order");
    uint64  constant SUPPLY   = 10;
    uint64  END_TS;

    function setUp() public {
        ledger = new WoCoTicketLedger(owner, sponsor, type(uint32).max);
        holder = vm.addr(HOLDER_KEY);
        // forge-lint: disable-next-line(unsafe-typecast)
        END_TS = uint64(block.timestamp + 7 days);
        vm.prank(owner);
        ledger.addSponsor(sponsor2, type(uint32).max);
    }

    function _register() internal returns (bytes32 eventId) {
        vm.prank(sponsor);
        eventId = ledger.registerEvent(organiser, SUPPLY, MANIFEST, END_TS);
    }

    function _owners(uint256 n, address to) internal pure returns (address[] memory a) {
        a = new address[](n);
        for (uint256 i; i < n; ++i) a[i] = to;
    }

    function _bearer(bytes32 eventId, uint256 n, address to) internal returns (uint256 first) {
        vm.prank(sponsor);
        first = ledger.batchClaimBearer(eventId, _owners(n, to), ORDER);
    }

    function _slots(uint256 a) internal pure returns (uint256[] memory s) {
        s = new uint256[](1);
        s[0] = a;
    }

    function _slots(uint256 a, uint256 b) internal pure returns (uint256[] memory s) {
        s = new uint256[](2);
        s[0] = a;
        s[1] = b;
    }

    function _reissue(bytes32 eventId, uint256[] memory slots) internal returns (uint256 first) {
        vm.prank(sponsor);
        first = ledger.reissue(eventId, slots, _owners(slots.length, fresh), ORDER);
    }

    function _live(bytes32 eventId) internal view returns (uint64 live) {
        (, live, ) = ledger.getEventAdmin(eventId);
    }

    // ── registrant ────────────────────────────────────────────────────────────

    function test_RegistrantIsTheCaller() public {
        bytes32 id = _register();
        (address registrant, uint64 live, uint32 revoked) = ledger.getEventAdmin(id);
        assertEq(registrant, sponsor);
        assertEq(live, 0);
        assertEq(revoked, 0);
    }

    function test_GetEventAdmin_UnknownEvent() public {
        vm.expectRevert(WoCoTicketLedger.EventNotFound.selector);
        ledger.getEventAdmin(keccak256("nope"));
    }

    // ── setSupply ─────────────────────────────────────────────────────────────

    function test_SetSupply_RaiseLetsMoreSell() public {
        bytes32 id = _register();
        vm.prank(sponsor);
        ledger.batchClaimFor(id, _owners(SUPPLY, holder), ORDER);
        assertEq(ledger.remaining(id), 0);

        vm.expectEmit(true, false, false, true);
        emit WoCoTicketLedger.SupplySet(id, SUPPLY, SUPPLY + 5);
        vm.prank(sponsor);
        ledger.setSupply(id, SUPPLY + 5);

        assertEq(ledger.remaining(id), 5);
        vm.prank(sponsor);
        ledger.batchClaimFor(id, _owners(5, holder), ORDER);
        assertEq(ledger.remaining(id), 0);
    }

    function test_SetSupply_LowerToExactlyLive() public {
        bytes32 id = _register();
        vm.prank(sponsor);
        ledger.batchClaimFor(id, _owners(4, holder), ORDER);
        vm.prank(sponsor);
        ledger.setSupply(id, 4);
        (uint64 total, , , ) = ledger.getEvent(id);
        assertEq(total, 4);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.InsufficientSupply.selector);
        ledger.claimFor(id, holder, ORDER);
    }

    function test_SetSupply_NeverBelowLive() public {
        bytes32 id = _register();
        vm.prank(sponsor);
        ledger.batchClaimFor(id, _owners(4, holder), ORDER);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.InsufficientSupply.selector);
        ledger.setSupply(id, 3);
    }

    function test_SetSupply_NeverZero() public {
        bytes32 id = _register();
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.InsufficientSupply.selector);
        ledger.setSupply(id, 0);
    }

    function test_SetSupply_UnchangedRefused() public {
        bytes32 id = _register();
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.SupplyUnchanged.selector);
        ledger.setSupply(id, SUPPLY);
    }

    function test_SetSupply_RegistrantOnly() public {
        bytes32 id = _register();
        address[4] memory notRegistrant = [organiser, owner, sponsor2, stranger];
        for (uint256 i; i < notRegistrant.length; ++i) {
            vm.prank(notRegistrant[i]);
            vm.expectRevert(WoCoTicketLedger.NotRegistrant.selector);
            ledger.setSupply(id, SUPPLY + 1);
        }
    }

    function test_SetSupply_RefusedAfterCancel() public {
        bytes32 id = _register();
        vm.prank(organiser);
        ledger.cancelEvent(id);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.AlreadyCancelled.selector);
        ledger.setSupply(id, SUPPLY + 1);
    }

    function test_SetSupply_RefusedAfterCutoff() public {
        bytes32 id = _register();
        vm.warp(END_TS);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.SalesClosed.selector);
        ledger.setSupply(id, SUPPLY + 1);
    }

    function test_SetSupply_UnknownEvent() public {
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.EventNotFound.selector);
        ledger.setSupply(keccak256("nope"), 5);
    }

    // ── extendSalesEnd ────────────────────────────────────────────────────────

    function test_ExtendSalesEnd_ReopensAClosedEvent() public {
        bytes32 id = _register();
        vm.warp(END_TS + 1);
        assertEq(ledger.remaining(id), 0);
        uint64 later = END_TS + 30 days;

        vm.expectEmit(true, false, false, true);
        emit WoCoTicketLedger.SalesEndExtended(id, END_TS, later);
        vm.prank(sponsor);
        ledger.extendSalesEnd(id, later);

        (uint64 endTs, ) = ledger.getEventStatus(id);
        assertEq(endTs, later);
        vm.prank(sponsor);
        ledger.claimFor(id, holder, ORDER);
    }

    function test_ExtendSalesEnd_NeverEarlierOrEqual() public {
        bytes32 id = _register();
        vm.startPrank(sponsor);
        vm.expectRevert(WoCoTicketLedger.InvalidEventEnd.selector);
        ledger.extendSalesEnd(id, END_TS);
        vm.expectRevert(WoCoTicketLedger.InvalidEventEnd.selector);
        ledger.extendSalesEnd(id, END_TS - 1);
        vm.stopPrank();
    }

    function test_ExtendSalesEnd_NeverIntoThePast() public {
        bytes32 id = _register();
        vm.warp(END_TS + 10 days);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.InvalidEventEnd.selector);
        ledger.extendSalesEnd(id, END_TS + 5 days);
    }

    function test_ExtendSalesEnd_RegistrantOnly() public {
        bytes32 id = _register();
        address[4] memory notRegistrant = [organiser, owner, sponsor2, stranger];
        for (uint256 i; i < notRegistrant.length; ++i) {
            vm.prank(notRegistrant[i]);
            vm.expectRevert(WoCoTicketLedger.NotRegistrant.selector);
            ledger.extendSalesEnd(id, END_TS + 1 days);
        }
    }

    function test_ExtendSalesEnd_RefusedAfterCancel() public {
        bytes32 id = _register();
        vm.prank(organiser);
        ledger.cancelEvent(id);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.AlreadyCancelled.selector);
        ledger.extendSalesEnd(id, END_TS + 1 days);
    }

    function test_ExtendSalesEnd_UnknownEvent() public {
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.EventNotFound.selector);
        ledger.extendSalesEnd(keccak256("nope"), END_TS + 1 days);
    }

    // ── bearer mints ──────────────────────────────────────────────────────────

    function test_BearerBit_OnlyThroughBatchClaimBearer() public {
        bytes32 id = _register();
        vm.startPrank(sponsor);
        uint256 holderSlot = ledger.claimFor(id, holder, ORDER);
        uint256 batchSlot = ledger.batchClaimFor(id, _owners(1, holder), ORDER);
        uint256 bearerSlot = ledger.batchClaimBearer(id, _owners(1, holder), ORDER);
        vm.stopPrank();

        (, bool b0) = ledger.getSlotFlags(id, holderSlot);
        (, bool b1) = ledger.getSlotFlags(id, batchSlot);
        (bool revoked, bool b2) = ledger.getSlotFlags(id, bearerSlot);
        assertFalse(b0, "claimFor minted bearer");
        assertFalse(b1, "batchClaimFor minted bearer");
        assertTrue(b2, "batchClaimBearer did not mint bearer");
        assertFalse(revoked);
    }

    function test_BatchClaimBearer_SameSupplyRule() public {
        bytes32 id = _register();
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.InsufficientSupply.selector);
        ledger.batchClaimBearer(id, _owners(SUPPLY + 1, holder), ORDER);
    }

    function test_BatchClaimBearer_SponsorsOnly() public {
        bytes32 id = _register();
        vm.prank(stranger);
        vm.expectRevert(WoCoTicketLedger.NotAuthorised.selector);
        ledger.batchClaimBearer(id, _owners(1, holder), ORDER);
    }

    // ── reissue: the happy path ───────────────────────────────────────────────

    function test_Reissue_RevokesAndReplacesOneForOne() public {
        bytes32 id = _register();
        uint256 first = _bearer(id, 3, holder);
        uint64 remainingBefore = uint64(ledger.remaining(id));

        vm.expectEmit(true, true, true, true);
        emit WoCoTicketLedger.SlotRevoked(id, first, holder, 3);
        vm.expectEmit(true, true, true, true);
        emit WoCoTicketLedger.SlotRevoked(id, first + 2, holder, 4);
        vm.expectEmit(true, true, true, true);
        emit WoCoTicketLedger.SlotClaimed(id, 3, fresh, sponsor, ORDER);
        uint256 replacement = _reissue(id, _slots(first, first + 2));
        assertEq(replacement, 3);

        // The old slots: nobody holds them, history kept.
        for (uint256 s = first; s <= first + 2; s += 2) {
            assertEq(ledger.slotOwner(id, s), address(0));
            (address h, address c, bytes32 r) = ledger.getSlotData(id, s);
            assertEq(h, address(0), "a revoked slot still has a holder");
            assertEq(c, sponsor, "a revoked slot lost its claimer");
            assertEq(r, ORDER, "a revoked slot lost its orderRef");
            (bool revoked, bool bearer) = ledger.getSlotFlags(id, s);
            assertTrue(revoked && bearer);
        }
        // The sibling is untouched.
        assertEq(ledger.slotOwner(id, first + 1), holder);
        // The replacements: fresh, bearer, the sale's order.
        for (uint256 s = 3; s <= 4; ++s) {
            assertEq(ledger.slotOwner(id, s), fresh);
            (, bool bearer) = ledger.getSlotFlags(id, s);
            assertTrue(bearer, "a replacement must stay replaceable");
        }
        (, uint64 nextSlot, , ) = ledger.getEvent(id);
        (, uint64 live, uint32 revokedCount) = ledger.getEventAdmin(id);
        assertEq(nextSlot, 5);
        assertEq(live, 3, "a reissue used a seat");
        assertEq(revokedCount, 2);
        assertEq(ledger.remaining(id), remainingBefore, "seats left moved");
    }

    function test_Reissue_WorksOnASoldOutEvent() public {
        bytes32 id = _register();
        _bearer(id, SUPPLY, holder);
        assertEq(ledger.remaining(id), 0);
        _reissue(id, _slots(0));
        assertEq(ledger.slotOwner(id, SUPPLY), fresh);
        assertEq(ledger.remaining(id), 0);
        // Still sold out: the replacement did not open a seat.
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.InsufficientSupply.selector);
        ledger.claimFor(id, holder, ORDER);
    }

    function test_Reissue_ChargedToTheMintCap_AllOrNothing() public {
        bytes32 id = _register();
        _bearer(id, 3, holder);
        vm.prank(owner);
        ledger.setSponsorMintCap(sponsor, 1);
        vm.prank(sponsor);
        vm.expectRevert();
        ledger.reissue(id, _slots(0, 1), _owners(2, fresh), ORDER);
        (bool r0, ) = ledger.getSlotFlags(id, 0);
        (bool r1, ) = ledger.getSlotFlags(id, 1);
        assertFalse(r0 || r1, "a refused reissue revoked something");
        assertEq(ledger.slotOwner(id, 0), holder);
    }

    // ── reissue: what it may never touch ──────────────────────────────────────

    function test_Reissue_NotBearer() public {
        bytes32 id = _register();
        vm.prank(sponsor);
        uint256 s = ledger.claimFor(id, holder, ORDER);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.NotBearer.selector);
        ledger.reissue(id, _slots(s), _owners(1, fresh), ORDER);
    }

    function test_Reissue_MovedSlotIsHeld() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        vm.prank(holder);
        ledger.transferSlot(id, s, stranger);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.SlotHeld.selector);
        ledger.reissue(id, _slots(s), _owners(1, fresh), ORDER);
    }

    function test_Reissue_AnotherSponsorsSlot() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        vm.prank(sponsor2);
        vm.expectRevert(WoCoTicketLedger.NotSlotClaimer.selector);
        ledger.reissue(id, _slots(s), _owners(1, fresh), ORDER);
    }

    function test_Reissue_AlreadyRevoked() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        _reissue(id, _slots(s));
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.SlotIsRevoked.selector);
        ledger.reissue(id, _slots(s), _owners(1, fresh), ORDER);
    }

    function test_Reissue_DuplicateInOneCall() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.SlotIsRevoked.selector);
        ledger.reissue(id, _slots(s, s), _owners(2, fresh), ORDER);
    }

    function test_Reissue_UnclaimedSlot() public {
        bytes32 id = _register();
        _bearer(id, 1, holder);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.SlotUnclaimed.selector);
        ledger.reissue(id, _slots(1), _owners(1, fresh), ORDER);
    }

    /// The first replacement's index is listed: it does not exist before this
    /// call, so it is refused rather than minted and revoked in one breath.
    function test_Reissue_NeverItsOwnReplacement() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.SlotUnclaimed.selector);
        ledger.reissue(id, _slots(s, s + 1), _owners(2, fresh), ORDER);
    }

    function test_Reissue_RemovedSponsor() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        vm.prank(owner);
        ledger.removeSponsor(sponsor);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.NotAuthorised.selector);
        ledger.reissue(id, _slots(s), _owners(1, fresh), ORDER);
    }

    function test_Reissue_RefusedAfterCancel() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        vm.prank(organiser);
        ledger.cancelEvent(id);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.AlreadyCancelled.selector);
        ledger.reissue(id, _slots(s), _owners(1, fresh), ORDER);
    }

    function test_Reissue_RefusedAfterCutoff() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        vm.warp(END_TS);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.SalesClosed.selector);
        ledger.reissue(id, _slots(s), _owners(1, fresh), ORDER);
    }

    function test_Reissue_ShapeGuards() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        vm.startPrank(sponsor);
        vm.expectRevert(WoCoTicketLedger.LengthMismatch.selector);
        ledger.reissue(id, _slots(s), _owners(2, fresh), ORDER);
        vm.expectRevert(WoCoTicketLedger.BatchEmpty.selector);
        ledger.reissue(id, new uint256[](0), new address[](0), ORDER);
        vm.expectRevert(WoCoTicketLedger.BatchTooLarge.selector);
        ledger.reissue(id, new uint256[](101), new address[](101), ORDER);
        vm.expectRevert(WoCoTicketLedger.ZeroAddress.selector);
        ledger.reissue(id, _slots(s), _owners(1, address(0)), ORDER);
        vm.expectRevert(WoCoTicketLedger.TransferToLedger.selector);
        ledger.reissue(id, _slots(s), _owners(1, address(ledger)), ORDER);
        vm.expectRevert(WoCoTicketLedger.EventNotFound.selector);
        ledger.reissue(keccak256("nope"), _slots(s), _owners(1, fresh), ORDER);
        vm.stopPrank();
    }

    function test_Reissue_SponsorsOnly() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        vm.prank(stranger);
        vm.expectRevert(WoCoTicketLedger.NotAuthorised.selector);
        ledger.reissue(id, _slots(s), _owners(1, fresh), ORDER);
    }

    /// After a reissue, live accounting holds the line: supply bounds seats in
    /// use, not slots ever minted.
    function test_Reissue_LiveAccountingBoundsLaterMints() public {
        bytes32 id = _register();
        _bearer(id, SUPPLY - 1, holder);
        _reissue(id, _slots(0));
        assertEq(ledger.remaining(id), 1);
        vm.prank(sponsor);
        ledger.claimFor(id, holder, ORDER);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.InsufficientSupply.selector);
        ledger.claimFor(id, holder, ORDER);
    }

    // ── a revoked slot never moves again ──────────────────────────────────────

    function test_RevokedSlot_RefusesBothTransferPaths() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(HOLDER_KEY, ledger.transferSlotDigest(id, s, stranger, deadline));
        _reissue(id, _slots(s));

        vm.prank(holder);
        vm.expectRevert(WoCoTicketLedger.SlotIsRevoked.selector);
        ledger.transferSlot(id, s, stranger);

        vm.expectRevert(WoCoTicketLedger.SlotIsRevoked.selector);
        ledger.transferSlotWithSignature(id, s, stranger, deadline, abi.encodePacked(r, sig, v));
    }

    // ── the off switch ────────────────────────────────────────────────────────

    function test_DisableBearerMints_OwnerOnly() public {
        vm.prank(owner);
        ledger.setDisputeAuthority(daoAuth);
        address[4] memory notOwner = [sponsor, organiser, daoAuth, stranger];
        for (uint256 i; i < notOwner.length; ++i) {
            vm.prank(notOwner[i]);
            vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, notOwner[i]));
            ledger.disableBearerMints();
        }
    }

    function test_DisableBearerMints_OneWay() public {
        vm.expectEmit(true, false, false, false);
        emit WoCoTicketLedger.BearerMintsDisabled(owner);
        vm.prank(owner);
        ledger.disableBearerMints();
        assertTrue(ledger.bearerMintsDisabled());
        vm.prank(owner);
        vm.expectRevert(WoCoTicketLedger.AlreadyDisabled.selector);
        ledger.disableBearerMints();
    }

    function test_DisableBearerMints_EndsBearerAndReissue_OnlyThose() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        vm.prank(owner);
        ledger.disableBearerMints();

        vm.startPrank(sponsor);
        vm.expectRevert(WoCoTicketLedger.BearerMintsOff.selector);
        ledger.batchClaimBearer(id, _owners(1, holder), ORDER);
        vm.expectRevert(WoCoTicketLedger.BearerMintsOff.selector);
        ledger.reissue(id, _slots(s), _owners(1, fresh), ORDER);

        // Everything else carries on.
        ledger.claimFor(id, holder, ORDER);
        ledger.batchClaimFor(id, _owners(1, holder), ORDER);
        ledger.setSupply(id, SUPPLY + 1);
        ledger.extendSalesEnd(id, END_TS + 1 days);
        vm.stopPrank();
        vm.prank(holder);
        ledger.transferSlot(id, s, stranger);
        assertEq(ledger.slotOwner(id, s), stranger);
    }

    // ── views ─────────────────────────────────────────────────────────────────

    function test_GetSlotFlags_UnclaimedSlot() public {
        bytes32 id = _register();
        (bool revoked, bool bearer) = ledger.getSlotFlags(id, 0);
        assertFalse(revoked || bearer);
        (address h, address c, bytes32 r) = ledger.getSlotData(id, 0);
        assertEq(h, address(0));
        assertEq(c, address(0));
        assertEq(r, bytes32(0));
    }
}
