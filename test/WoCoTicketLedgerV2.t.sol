// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {WoCoTicketLedger} from "../src/WoCoTicketLedger.sol";

/**
 * Version 2 of WoCoTicketLedger: seats the registrant can change
 * (`setSupply`), a cutoff it can only move later (`extendSalesEnd`), the
 * platform's re-point of a bearer ticket to a fresh key (`reissue`), and the
 * one-way off switch for it (`disableBearerMints`).
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

    function _reissue(bytes32 eventId, uint256[] memory slots, address to) internal {
        vm.prank(sponsor);
        ledger.reissue(eventId, slots, _owners(slots.length, to));
    }

    function _nextSlot(bytes32 eventId) internal view returns (uint64 nextSlot) {
        (, nextSlot, , ) = ledger.getEvent(eventId);
    }

    function _held(bytes32 eventId, uint256 slot) internal view returns (bool held) {
        (, held) = ledger.getSlotFlags(eventId, slot);
    }

    // ── registrant ────────────────────────────────────────────────────────────

    function test_RegistrantIsTheCaller() public {
        bytes32 id = _register();
        assertEq(ledger.getRegistrant(id), sponsor);
    }

    function test_GetRegistrant_UnknownEvent() public {
        vm.expectRevert(WoCoTicketLedger.EventNotFound.selector);
        ledger.getRegistrant(keccak256("nope"));
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

    function test_SetSupply_LowerToExactlyMinted() public {
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

    function test_SetSupply_NeverBelowMinted() public {
        bytes32 id = _register();
        vm.prank(sponsor);
        ledger.batchClaimFor(id, _owners(4, holder), ORDER);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.InsufficientSupply.selector);
        ledger.setSupply(id, 3);
    }

    /// A reissue keeps the slot, so it never frees one: the floor after it is
    /// still every slot minted.
    function test_SetSupply_FloorUnmovedByReissue() public {
        bytes32 id = _register();
        _bearer(id, 4, holder);
        _reissue(id, _slots(0), fresh);
        vm.startPrank(sponsor);
        vm.expectRevert(WoCoTicketLedger.InsufficientSupply.selector);
        ledger.setSupply(id, 3);
        ledger.setSupply(id, 4);
        vm.stopPrank();
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

        (bool b0, ) = ledger.getSlotFlags(id, holderSlot);
        (bool b1, ) = ledger.getSlotFlags(id, batchSlot);
        (bool b2, bool held) = ledger.getSlotFlags(id, bearerSlot);
        assertFalse(b0, "claimFor minted bearer");
        assertFalse(b1, "batchClaimFor minted bearer");
        assertTrue(b2, "batchClaimBearer did not mint bearer");
        assertFalse(held, "a fresh mint reads as held");
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

    function test_Reissue_RepointsInPlace() public {
        bytes32 id = _register();
        uint256 first = _bearer(id, 3, holder);
        uint256 remainingBefore = ledger.remaining(id);

        vm.expectEmit(true, true, true, true);
        emit WoCoTicketLedger.SlotReissued(id, first, holder, fresh);
        vm.expectEmit(true, true, true, true);
        emit WoCoTicketLedger.SlotReissued(id, first + 2, holder, fresh);
        _reissue(id, _slots(first, first + 2), fresh);

        for (uint256 s = first; s <= first + 2; s += 2) {
            (address h, address c, bytes32 r) = ledger.getSlotData(id, s);
            assertEq(h, fresh, "not re-pointed");
            assertEq(c, sponsor, "the sale's claimer was rewritten");
            assertEq(r, ORDER, "the sale's orderRef was rewritten");
            (bool bearer, bool held) = ledger.getSlotFlags(id, s);
            assertTrue(bearer, "a reissued slot must stay replaceable");
            assertFalse(held, "a reissue is not a holder's move");
            assertEq(ledger.transferNonces(id, s), 1, "the old key's signatures still count");
        }
        // The sibling is untouched.
        assertEq(ledger.slotOwner(id, first + 1), holder);
        assertEq(ledger.transferNonces(id, first + 1), 0);
        // No slot minted, no seat used.
        assertEq(_nextSlot(id), 3, "a reissue minted a slot");
        assertEq(ledger.remaining(id), remainingBefore, "seats left moved");
    }

    /// The point of re-pointing in place: the ticket's edition (slot + 1) is
    /// one the manifest committed, also on a sold-out event.
    function test_Reissue_KeepsTheEditionOnASoldOutEvent() public {
        bytes32 id = _register();
        _bearer(id, SUPPLY, holder);
        _reissue(id, _slots(SUPPLY - 1), fresh);
        assertEq(ledger.slotOwner(id, SUPPLY - 1), fresh);
        assertEq(_nextSlot(id), SUPPLY, "an index past the supply was used");
        assertEq(ledger.remaining(id), 0);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.InsufficientSupply.selector);
        ledger.claimFor(id, holder, ORDER);
    }

    function test_Reissue_UsesNoSeat() public {
        bytes32 id = _register();
        _bearer(id, SUPPLY - 1, holder);
        _reissue(id, _slots(0), fresh);
        assertEq(ledger.remaining(id), 1);
        vm.prank(sponsor);
        ledger.claimFor(id, holder, ORDER);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.InsufficientSupply.selector);
        ledger.claimFor(id, holder, ORDER);
    }

    /// The old key cannot move the slot afterwards, by either path, and a
    /// signature it made before is dead.
    function test_Reissue_OldKeyLosesTheSlot() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(HOLDER_KEY, ledger.transferSlotDigest(id, s, stranger, deadline));
        _reissue(id, _slots(s), fresh);

        vm.prank(holder);
        vm.expectRevert(WoCoTicketLedger.NotSlotOwner.selector);
        ledger.transferSlot(id, s, stranger);

        vm.expectRevert(WoCoTicketLedger.NotSlotOwner.selector);
        ledger.transferSlotWithSignature(id, s, stranger, deadline, abi.encodePacked(r, sig, v));
        assertEq(ledger.slotOwner(id, s), fresh);
    }

    /// What only reissue's nonce bump refuses: the slot comes back to the old
    /// key (re-pointed away and back, which callers must never do), and the
    /// old key's signature, still inside its deadline, names the right `from`
    /// again. Without the bump its nonce would match too.
    function test_Reissue_NonceKillsAnOldSignatureAfterARoundTrip() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(HOLDER_KEY, ledger.transferSlotDigest(id, s, stranger, deadline));
        _reissue(id, _slots(s), fresh);
        _reissue(id, _slots(s), holder);
        assertEq(ledger.slotOwner(id, s), holder);

        vm.expectRevert(WoCoTicketLedger.NotSlotOwner.selector);
        ledger.transferSlotWithSignature(id, s, stranger, deadline, abi.encodePacked(r, sig, v));
    }

    /// A cutoff moved later reopens reissue with sales: the same window.
    function test_Reissue_ReopensWithAnExtendedCutoff() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        vm.warp(END_TS);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.SalesClosed.selector);
        ledger.reissue(id, _slots(s), _owners(1, fresh));

        vm.prank(sponsor);
        ledger.extendSalesEnd(id, END_TS + 1 days);
        _reissue(id, _slots(s), fresh);
        assertEq(ledger.slotOwner(id, s), fresh);
    }

    /// A slot can be reissued again (the platform limits how often), until a
    /// holder moves it: then a key someone keeps holds it, for good.
    function test_Reissue_RepeatsUntilAHolderMoves() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, stranger);
        _reissue(id, _slots(s), fresh);
        _reissue(id, _slots(s), holder);
        assertEq(ledger.slotOwner(id, s), holder);

        vm.prank(holder);
        ledger.transferSlot(id, s, stranger);
        assertTrue(_held(id, s), "a holder's move did not mark the slot held");

        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.SlotHeld.selector);
        ledger.reissue(id, _slots(s), _owners(1, fresh));
    }

    function test_Reissue_ChargedToTheMintCap_AllOrNothing() public {
        bytes32 id = _register();
        _bearer(id, 3, holder);
        vm.prank(owner);
        ledger.setSponsorMintCap(sponsor, 1);
        // The move out of unlimited closed the window, so the refusing call
        // opens one (in memory) ending a window from now. Read before the
        // prank: a call in expectRevert's arguments would consume it.
        uint64 resetsAt = uint64(block.timestamp + ledger.MINT_WINDOW());
        vm.prank(sponsor);
        vm.expectRevert(abi.encodeWithSelector(WoCoTicketLedger.MintCapExceeded.selector, sponsor, resetsAt));
        ledger.reissue(id, _slots(0, 1), _owners(2, fresh));
        assertEq(ledger.slotOwner(id, 0), holder, "a refused reissue moved a slot");
        assertEq(ledger.slotOwner(id, 1), holder, "a refused reissue moved a slot");
    }

    // ── reissue: what it may never touch ──────────────────────────────────────

    function test_Reissue_NotBearer() public {
        bytes32 id = _register();
        vm.prank(sponsor);
        uint256 s = ledger.claimFor(id, holder, ORDER);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.NotBearer.selector);
        ledger.reissue(id, _slots(s), _owners(1, fresh));
    }

    function test_Reissue_MovedSlotIsHeld() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        vm.prank(holder);
        ledger.transferSlot(id, s, stranger);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.SlotHeld.selector);
        ledger.reissue(id, _slots(s), _owners(1, fresh));
    }

    function test_Reissue_SignedMoveMakesHeldToo() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(HOLDER_KEY, ledger.transferSlotDigest(id, s, stranger, deadline));
        ledger.transferSlotWithSignature(id, s, stranger, deadline, abi.encodePacked(r, sig, v));
        assertTrue(_held(id, s));
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.SlotHeld.selector);
        ledger.reissue(id, _slots(s), _owners(1, fresh));
    }

    function test_Reissue_AnotherSponsorsSlot() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        vm.prank(sponsor2);
        vm.expectRevert(WoCoTicketLedger.NotSlotClaimer.selector);
        ledger.reissue(id, _slots(s), _owners(1, fresh));
    }

    function test_Reissue_DuplicateInOneCall() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.SlotsNotAscending.selector);
        ledger.reissue(id, _slots(s, s), _owners(2, fresh));
    }

    function test_Reissue_Descending() public {
        bytes32 id = _register();
        _bearer(id, 2, holder);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.SlotsNotAscending.selector);
        ledger.reissue(id, _slots(1, 0), _owners(2, fresh));
    }

    function test_Reissue_UnclaimedSlot() public {
        bytes32 id = _register();
        _bearer(id, 1, holder);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.SlotUnclaimed.selector);
        ledger.reissue(id, _slots(1), _owners(1, fresh));
    }

    function test_Reissue_ToTheSameKey() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.TransferToSelf.selector);
        ledger.reissue(id, _slots(s), _owners(1, holder));
    }

    function test_Reissue_RemovedSponsor() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        vm.prank(owner);
        ledger.removeSponsor(sponsor);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.NotAuthorised.selector);
        ledger.reissue(id, _slots(s), _owners(1, fresh));
    }

    function test_Reissue_RefusedAfterCancel() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        vm.prank(organiser);
        ledger.cancelEvent(id);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.AlreadyCancelled.selector);
        ledger.reissue(id, _slots(s), _owners(1, fresh));
    }

    function test_Reissue_RefusedAfterCutoff() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        vm.warp(END_TS);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.SalesClosed.selector);
        ledger.reissue(id, _slots(s), _owners(1, fresh));
    }

    function test_Reissue_ShapeGuards() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        vm.startPrank(sponsor);
        vm.expectRevert(WoCoTicketLedger.LengthMismatch.selector);
        ledger.reissue(id, _slots(s), _owners(2, fresh));
        vm.expectRevert(WoCoTicketLedger.BatchEmpty.selector);
        ledger.reissue(id, new uint256[](0), new address[](0));
        vm.expectRevert(WoCoTicketLedger.BatchTooLarge.selector);
        ledger.reissue(id, new uint256[](101), new address[](101));
        vm.expectRevert(WoCoTicketLedger.ZeroAddress.selector);
        ledger.reissue(id, _slots(s), _owners(1, address(0)));
        vm.expectRevert(WoCoTicketLedger.TransferToLedger.selector);
        ledger.reissue(id, _slots(s), _owners(1, address(ledger)));
        vm.expectRevert(WoCoTicketLedger.EventNotFound.selector);
        ledger.reissue(keccak256("nope"), _slots(s), _owners(1, fresh));
        vm.stopPrank();
    }

    function test_Reissue_SponsorsOnly() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        vm.prank(stranger);
        vm.expectRevert(WoCoTicketLedger.NotAuthorised.selector);
        ledger.reissue(id, _slots(s), _owners(1, fresh));
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
        ledger.reissue(id, _slots(s), _owners(1, fresh));

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

    // ── the server's ABI ──────────────────────────────────────────────────────

    /// The server encodes calls, decodes reverts and parses logs from its OWN
    /// human-readable ABI (`LEDGER2_ABI` in event-contract-ledger.ts), never
    /// from this artefact, so a signature drift here compiles everywhere and
    /// fails only on chain. Written out, as in WoCoTicketLedger.t.sol's version
    /// 1 pin, so that drift has to be made in two places.
    function test_ServerAbi_Version2SelectorsUnchanged() public view {
        assertEq(bytes32(WoCoTicketLedger.batchClaimBearer.selector), bytes32(bytes4(keccak256("batchClaimBearer(bytes32,address[],bytes32)"))));
        assertEq(bytes32(WoCoTicketLedger.reissue.selector),          bytes32(bytes4(keccak256("reissue(bytes32,uint256[],address[])"))));
        assertEq(bytes32(WoCoTicketLedger.getSlotFlags.selector),     bytes32(bytes4(keccak256("getSlotFlags(bytes32,uint256)"))));
        assertEq(bytes32(WoCoTicketLedger.getRegistrant.selector),    bytes32(bytes4(keccak256("getRegistrant(bytes32)"))));
        assertEq(bytes32(WoCoTicketLedger.setSupply.selector),        bytes32(bytes4(keccak256("setSupply(bytes32,uint64)"))));
        assertEq(bytes32(WoCoTicketLedger.extendSalesEnd.selector),   bytes32(bytes4(keccak256("extendSalesEnd(bytes32,uint64)"))));
        assertEq(bytes32(ledger.bearerMintsDisabled.selector),        bytes32(bytes4(keccak256("bearerMintsDisabled()"))));

        assertEq(WoCoTicketLedger.SlotReissued.selector,        keccak256("SlotReissued(bytes32,uint256,address,address)"));
        assertEq(WoCoTicketLedger.SupplySet.selector,           keccak256("SupplySet(bytes32,uint64,uint64)"));
        assertEq(WoCoTicketLedger.SalesEndExtended.selector,    keccak256("SalesEndExtended(bytes32,uint64,uint64)"));
        assertEq(WoCoTicketLedger.BearerMintsDisabled.selector, keccak256("BearerMintsDisabled(address)"));

        assertEq(bytes32(WoCoTicketLedger.BearerMintsOff.selector),    bytes32(bytes4(keccak256("BearerMintsOff()"))));
        assertEq(bytes32(WoCoTicketLedger.LengthMismatch.selector),    bytes32(bytes4(keccak256("LengthMismatch()"))));
        assertEq(bytes32(WoCoTicketLedger.SlotsNotAscending.selector), bytes32(bytes4(keccak256("SlotsNotAscending()"))));
        assertEq(bytes32(WoCoTicketLedger.NotBearer.selector),         bytes32(bytes4(keccak256("NotBearer()"))));
        assertEq(bytes32(WoCoTicketLedger.NotSlotClaimer.selector),    bytes32(bytes4(keccak256("NotSlotClaimer()"))));
        assertEq(bytes32(WoCoTicketLedger.SlotHeld.selector),          bytes32(bytes4(keccak256("SlotHeld()"))));
        assertEq(bytes32(WoCoTicketLedger.NotRegistrant.selector),     bytes32(bytes4(keccak256("NotRegistrant()"))));
        assertEq(bytes32(WoCoTicketLedger.SupplyUnchanged.selector),   bytes32(bytes4(keccak256("SupplyUnchanged()"))));
    }

    // ── views ─────────────────────────────────────────────────────────────────

    function test_GetSlotFlags_UnclaimedSlot() public {
        bytes32 id = _register();
        (bool bearer, bool held) = ledger.getSlotFlags(id, 0);
        assertFalse(bearer || held);
        (address h, address c, bytes32 r) = ledger.getSlotData(id, 0);
        assertEq(h, address(0));
        assertEq(c, address(0));
        assertEq(r, bytes32(0));
    }
}
