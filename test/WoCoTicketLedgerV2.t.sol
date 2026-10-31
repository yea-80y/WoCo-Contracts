// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {WoCoTicketLedger} from "../src/WoCoTicketLedger.sol";

/**
 * Version 2 of WoCoTicketLedger: terms the ORGANISER holds from registration
 * (supply it can lower and restore, never above the registered supply; a
 * cutoff it can only move later, while open and at most `MAX_SALES_EXTENSION`
 * ahead; cancellation), as its account or its organiser key, directly or by an
 * EIP-712 signature anyone submits; the key moved only by the account
 * (`setOrganiserKey`); seated events (a seat per ticket, never held twice,
 * moved only on the organiser key's consent); the platform's re-point of a
 * bearer ticket to a fresh key (`reissue`), and the one-way off switch
 * (`disableBearerMints`).
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
    uint256 constant ORG_KEY   = 0x0E6;
    uint256 constant ORG_KEY_2 = 0x0E7;
    uint256 constant OTHER_KEY = 0xBAD;
    address orgKey;
    address orgKey2;

    bytes32 constant MANIFEST = keccak256("manifest");
    bytes32 constant ORDER    = keccak256("order");
    uint64  constant SUPPLY   = 10;
    uint64  END_TS;

    function setUp() public {
        ledger = new WoCoTicketLedger(owner, sponsor, type(uint32).max);
        holder = vm.addr(HOLDER_KEY);
        orgKey = vm.addr(ORG_KEY);
        orgKey2 = vm.addr(ORG_KEY_2);
        // forge-lint: disable-next-line(unsafe-typecast)
        END_TS = uint64(block.timestamp + 7 days);
        vm.prank(owner);
        ledger.addSponsor(sponsor2, type(uint32).max);
    }

    function _register() internal returns (bytes32 eventId) {
        vm.prank(sponsor);
        eventId = ledger.registerEvent(organiser, orgKey, SUPPLY, MANIFEST, END_TS);
    }

    function _registerSeated() internal returns (bytes32 eventId) {
        vm.prank(sponsor);
        eventId = ledger.registerSeatedEvent(organiser, orgKey, SUPPLY, MANIFEST, END_TS);
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

    function _ids(bytes32 a) internal pure returns (bytes32[] memory ids) {
        ids = new bytes32[](1);
        ids[0] = a;
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

    function _sign(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _deadline() internal view returns (uint256) {
        return block.timestamp + 1 hours;
    }

    // ── registration and the organiser key ───────────────────────────────────

    function test_Register_StoresTheKeyAndLogsIt() public {
        vm.expectEmit(true, true, true, true, address(ledger));
        emit WoCoTicketLedger.OrganiserKeySet(
            keccak256(abi.encode(block.chainid, address(ledger), sponsor, uint256(0))), address(0), orgKey
        );
        bytes32 id = _register();
        assertEq(ledger.getOrganiserKey(id), orgKey);
        assertFalse(ledger.isSeated(id));
    }

    function test_Register_KeyNeverZeroNorTheLedger() public {
        vm.startPrank(sponsor);
        vm.expectRevert(WoCoTicketLedger.ZeroAddress.selector);
        ledger.registerEvent(organiser, address(0), SUPPLY, MANIFEST, END_TS);
        vm.expectRevert(WoCoTicketLedger.TransferToLedger.selector);
        ledger.registerEvent(organiser, address(ledger), SUPPLY, MANIFEST, END_TS);
        vm.expectRevert(WoCoTicketLedger.ZeroAddress.selector);
        ledger.registerSeatedEvent(organiser, address(0), SUPPLY, MANIFEST, END_TS);
        vm.stopPrank();
    }

    /// An EOA organiser registering its own events may be its own key.
    function test_Register_KeyMayBeTheOrganiser() public {
        vm.prank(organiser);
        bytes32 id = ledger.registerEvent(organiser, organiser, SUPPLY, MANIFEST, END_TS);
        vm.prank(organiser);
        ledger.setSupply(id, SUPPLY - 1);
    }

    function test_Register_SeatedMarksTheEventAndSharesTheNonce() public {
        bytes32 ga = _register();
        vm.expectEmit(true, false, false, false, address(ledger));
        emit WoCoTicketLedger.Seated(keccak256(abi.encode(block.chainid, address(ledger), sponsor, uint256(1))));
        bytes32 seatedId = _registerSeated();
        assertEq(seatedId, keccak256(abi.encode(block.chainid, address(ledger), sponsor, uint256(1))));
        assertTrue(ledger.isSeated(seatedId));
        assertFalse(ledger.isSeated(ga));
        assertEq(ledger.getOrganiserKey(seatedId), orgKey);
    }

    function test_Views_UnknownEvent() public {
        bytes32 nope = keccak256("nope");
        vm.expectRevert(WoCoTicketLedger.EventNotFound.selector);
        ledger.getOrganiserKey(nope);
        vm.expectRevert(WoCoTicketLedger.EventNotFound.selector);
        ledger.isSeated(nope);
        vm.expectRevert(WoCoTicketLedger.EventNotFound.selector);
        ledger.getRegisteredSupply(nope);
    }

    function test_GetRegisteredSupply() public {
        bytes32 id = _register();
        assertEq(ledger.getRegisteredSupply(id), SUPPLY);
    }

    // ── setSupply ─────────────────────────────────────────────────────────────

    function test_SetSupply_LowerThenRaiseBackLetsMoreSell() public {
        bytes32 id = _register();
        vm.prank(sponsor);
        ledger.batchClaimFor(id, _owners(SUPPLY - 5, holder), ORDER);

        vm.expectEmit(true, false, false, true);
        emit WoCoTicketLedger.SupplySet(id, SUPPLY, SUPPLY - 5);
        vm.prank(organiser);
        ledger.setSupply(id, SUPPLY - 5);
        assertEq(ledger.remaining(id), 0);

        vm.expectEmit(true, false, false, true);
        emit WoCoTicketLedger.SupplySet(id, SUPPLY - 5, SUPPLY);
        vm.prank(orgKey);
        ledger.setSupply(id, SUPPLY);

        assertEq(ledger.remaining(id), 5);
        vm.prank(sponsor);
        ledger.batchClaimFor(id, _owners(5, holder), ORDER);
        assertEq(ledger.remaining(id), 0);
    }

    /// The manifest commits an edition for each registered ticket and no more
    /// (audit 1059 L-1), so a supply past them is refused, lowered first or not.
    function test_SetSupply_NeverAboveRegistered() public {
        bytes32 id = _register();
        vm.startPrank(organiser);
        vm.expectRevert(WoCoTicketLedger.SupplyAboveRegistered.selector);
        ledger.setSupply(id, SUPPLY + 1);
        ledger.setSupply(id, SUPPLY - 1);
        vm.expectRevert(WoCoTicketLedger.SupplyAboveRegistered.selector);
        ledger.setSupply(id, SUPPLY + 1);
        vm.stopPrank();
        assertEq(ledger.getRegisteredSupply(id), SUPPLY, "the ceiling moved with the supply");
    }

    function test_SetSupply_LowerToExactlyMinted() public {
        bytes32 id = _register();
        vm.prank(sponsor);
        ledger.batchClaimFor(id, _owners(4, holder), ORDER);
        vm.prank(organiser);
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
        vm.prank(organiser);
        vm.expectRevert(WoCoTicketLedger.InsufficientSupply.selector);
        ledger.setSupply(id, 3);
    }

    /// A reissue keeps the slot, so it never frees one: the floor after it is
    /// still every slot minted.
    function test_SetSupply_FloorUnmovedByReissue() public {
        bytes32 id = _register();
        _bearer(id, 4, holder);
        _reissue(id, _slots(0), fresh);
        vm.startPrank(organiser);
        vm.expectRevert(WoCoTicketLedger.InsufficientSupply.selector);
        ledger.setSupply(id, 3);
        ledger.setSupply(id, 4);
        vm.stopPrank();
    }

    function test_SetSupply_NeverZero() public {
        bytes32 id = _register();
        vm.prank(organiser);
        vm.expectRevert(WoCoTicketLedger.InsufficientSupply.selector);
        ledger.setSupply(id, 0);
    }

    function test_SetSupply_UnchangedRefused() public {
        bytes32 id = _register();
        vm.prank(organiser);
        vm.expectRevert(WoCoTicketLedger.SupplyUnchanged.selector);
        ledger.setSupply(id, SUPPLY);
    }

    /// The organiser's account or its key, nobody else: not the sponsor that
    /// registered it, not the owner, not another sponsor.
    function test_SetSupply_OrganiserOnly() public {
        bytes32 id = _register();
        address[4] memory notOrganiser = [sponsor, owner, sponsor2, stranger];
        for (uint256 i; i < notOrganiser.length; ++i) {
            vm.prank(notOrganiser[i]);
            vm.expectRevert(WoCoTicketLedger.NotOrganiser.selector);
            ledger.setSupply(id, SUPPLY - 1);
        }
    }

    function test_SetSupply_RefusedAfterCancel() public {
        bytes32 id = _register();
        vm.prank(organiser);
        ledger.cancelEvent(id);
        vm.prank(organiser);
        vm.expectRevert(WoCoTicketLedger.AlreadyCancelled.selector);
        ledger.setSupply(id, SUPPLY - 1);
    }

    function test_SetSupply_RefusedAfterCutoff() public {
        bytes32 id = _register();
        vm.warp(END_TS);
        vm.prank(organiser);
        vm.expectRevert(WoCoTicketLedger.SalesClosed.selector);
        ledger.setSupply(id, SUPPLY - 1);
    }

    function test_SetSupply_UnknownEvent() public {
        vm.prank(organiser);
        vm.expectRevert(WoCoTicketLedger.EventNotFound.selector);
        ledger.setSupply(keccak256("nope"), 5);
    }

    // ── extendSalesEnd ────────────────────────────────────────────────────────

    function test_ExtendSalesEnd_KeepsAnOpenEventSelling() public {
        bytes32 id = _register();
        uint64 later = END_TS + 30 days;

        vm.expectEmit(true, false, false, true);
        emit WoCoTicketLedger.SalesEndExtended(id, END_TS, later);
        vm.prank(organiser);
        ledger.extendSalesEnd(id, later);

        (uint64 endTs, ) = ledger.getEventStatus(id);
        assertEq(endTs, later);
        vm.warp(END_TS + 1);
        vm.prank(sponsor);
        ledger.claimFor(id, holder, ORDER);
    }

    /// The cutoff is the event's real end: once it has passed, the event is
    /// over and is registered again, never reopened (audit 1059 L-4).
    function test_ExtendSalesEnd_RefusedAfterCutoff() public {
        bytes32 id = _register();
        vm.warp(END_TS);
        assertEq(ledger.remaining(id), 0);
        vm.prank(organiser);
        vm.expectRevert(WoCoTicketLedger.SalesClosed.selector);
        ledger.extendSalesEnd(id, END_TS + 30 days);
    }

    /// At most `MAX_SALES_EXTENSION` past now, however many calls are made in
    /// one block (audit 1059 M-1).
    function test_ExtendSalesEnd_AtMostMaxAheadOfNow() public {
        bytes32 id = _register();
        uint256 max = ledger.MAX_SALES_EXTENSION();
        assertEq(max, 730 days);
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 limit = uint64(block.timestamp + max);

        vm.startPrank(orgKey);
        vm.expectRevert(WoCoTicketLedger.SalesEndTooFar.selector);
        ledger.extendSalesEnd(id, limit + 1);
        vm.expectRevert(WoCoTicketLedger.SalesEndTooFar.selector);
        ledger.extendSalesEnd(id, type(uint64).max);
        ledger.extendSalesEnd(id, limit);
        // A second call in the same block gains nothing.
        vm.expectRevert(WoCoTicketLedger.SalesEndTooFar.selector);
        ledger.extendSalesEnd(id, limit + 1);
        vm.stopPrank();

        (uint64 endTs, ) = ledger.getEventStatus(id);
        assertEq(endTs, limit);
    }

    /// Per call, not in total (audit 1060 L-1): the organiser can move it
    /// again before each cutoff.
    function test_ExtendSalesEnd_RatchetsAcrossCalls() public {
        bytes32 id = _register();
        uint256 max = ledger.MAX_SALES_EXTENSION();
        for (uint256 i; i < 3; ++i) {
            // forge-lint: disable-next-line(unsafe-typecast)
            uint64 limit = uint64(block.timestamp + max);
            vm.prank(organiser);
            ledger.extendSalesEnd(id, limit);
            vm.warp(limit - 1);
        }
        (uint64 endTs, ) = ledger.getEventStatus(id);
        assertGt(endTs, END_TS + 2 * max);
    }

    function test_ExtendSalesEnd_NeverEarlierOrEqual() public {
        bytes32 id = _register();
        vm.startPrank(organiser);
        vm.expectRevert(WoCoTicketLedger.InvalidEventEnd.selector);
        ledger.extendSalesEnd(id, END_TS);
        vm.expectRevert(WoCoTicketLedger.InvalidEventEnd.selector);
        ledger.extendSalesEnd(id, END_TS - 1);
        vm.stopPrank();
    }

    function test_ExtendSalesEnd_OrganiserOnly() public {
        bytes32 id = _register();
        address[4] memory notOrganiser = [sponsor, owner, sponsor2, stranger];
        for (uint256 i; i < notOrganiser.length; ++i) {
            vm.prank(notOrganiser[i]);
            vm.expectRevert(WoCoTicketLedger.NotOrganiser.selector);
            ledger.extendSalesEnd(id, END_TS + 1 days);
        }
    }

    function test_ExtendSalesEnd_RefusedAfterCancel() public {
        bytes32 id = _register();
        vm.prank(organiser);
        ledger.cancelEvent(id);
        vm.prank(organiser);
        vm.expectRevert(WoCoTicketLedger.AlreadyCancelled.selector);
        ledger.extendSalesEnd(id, END_TS + 1 days);
    }

    function test_ExtendSalesEnd_UnknownEvent() public {
        vm.prank(organiser);
        vm.expectRevert(WoCoTicketLedger.EventNotFound.selector);
        ledger.extendSalesEnd(keccak256("nope"), END_TS + 1 days);
    }

    // ── cancel ────────────────────────────────────────────────────────────────

    function test_Cancel_ByTheKeyLogsTheKey() public {
        bytes32 id = _register();
        vm.expectEmit(true, true, false, true, address(ledger));
        emit WoCoTicketLedger.EventCancelled(id, orgKey, false);
        vm.prank(orgKey);
        ledger.cancelEvent(id);
        (, bool cancelled) = ledger.getEventStatus(id);
        assertTrue(cancelled);
        assertEq(ledger.termsNonces(id), 1, "a cancel did not consume the terms nonce");
    }

    function test_Cancel_SponsorsCannot() public {
        bytes32 id = _register();
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.NotOrganiser.selector);
        ledger.cancelEvent(id);
    }

    // ── signed terms ──────────────────────────────────────────────────────────

    /// The digest is plain EIP-712 under ("WoCoTicketLedger", "2", chain,
    /// ledger), so a wallet signing typed data produces it.
    function test_SignedTerms_DigestsAreEip712() public {
        bytes32 id = _register();
        bytes32 domain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("WoCoTicketLedger"),
                keccak256("2"),
                block.chainid,
                address(ledger)
            )
        );
        uint256 deadline = _deadline();
        bytes32 supplyStruct = keccak256(
            abi.encode(keccak256("SetSupply(bytes32 eventId,uint64 supply,uint256 nonce,uint256 deadline)"), id, uint64(7), uint256(0), deadline)
        );
        assertEq(ledger.setSupplyDigest(id, 7, deadline), keccak256(abi.encodePacked("\x19\x01", domain, supplyStruct)));

        bytes32 extendStruct = keccak256(
            abi.encode(
                keccak256("ExtendSalesEnd(bytes32 eventId,uint64 eventEndTs,uint256 nonce,uint256 deadline)"),
                id, uint64(END_TS + 1), uint256(0), deadline
            )
        );
        assertEq(
            ledger.extendSalesEndDigest(id, END_TS + 1, deadline),
            keccak256(abi.encodePacked("\x19\x01", domain, extendStruct))
        );

        bytes32 cancelStruct = keccak256(
            abi.encode(keccak256("CancelEvent(bytes32 eventId,uint256 nonce,uint256 deadline)"), id, uint256(0), deadline)
        );
        assertEq(ledger.cancelEventDigest(id, deadline), keccak256(abi.encodePacked("\x19\x01", domain, cancelStruct)));
    }

    function test_SignedSetSupply_AnyoneSubmits() public {
        bytes32 id = _register();
        uint256 deadline = _deadline();
        bytes memory sig = _sign(ORG_KEY, ledger.setSupplyDigest(id, 6, deadline));
        vm.prank(stranger);
        ledger.setSupplyWithSignature(id, 6, deadline, sig);
        (uint64 total, , , ) = ledger.getEvent(id);
        assertEq(total, 6);
        assertEq(ledger.termsNonces(id), 1);
    }

    function test_SignedSetSupply_OnlyTheEventsKey() public {
        bytes32 id = _register();
        uint256 deadline = _deadline();
        uint256[3] memory wrong = [OTHER_KEY, HOLDER_KEY, ORG_KEY_2];
        for (uint256 i; i < wrong.length; ++i) {
            bytes memory sig = _sign(wrong[i], ledger.setSupplyDigest(id, 6, deadline));
            vm.expectRevert(WoCoTicketLedger.NotOrganiserKey.selector);
            ledger.setSupplyWithSignature(id, 6, deadline, sig);
        }
    }

    /// A signature names every field: another supply, event or deadline is
    /// another message, and recovers to another address.
    function test_SignedSetSupply_FieldsAreBound() public {
        bytes32 id = _register();
        bytes32 other = _register();
        uint256 deadline = _deadline();
        bytes memory sig = _sign(ORG_KEY, ledger.setSupplyDigest(id, 6, deadline));
        vm.expectRevert(WoCoTicketLedger.NotOrganiserKey.selector);
        ledger.setSupplyWithSignature(id, 5, deadline, sig);
        vm.expectRevert(WoCoTicketLedger.NotOrganiserKey.selector);
        ledger.setSupplyWithSignature(other, 6, deadline, sig);
        vm.expectRevert(WoCoTicketLedger.NotOrganiserKey.selector);
        ledger.setSupplyWithSignature(id, 6, deadline - 1, sig);
    }

    /// Spent once, dead: even when the supply is back where it signed for,
    /// only the consumed nonce refuses it.
    function test_SignedSetSupply_NoReplay() public {
        bytes32 id = _register();
        uint256 deadline = _deadline();
        bytes memory sig = _sign(ORG_KEY, ledger.setSupplyDigest(id, 6, deadline));
        ledger.setSupplyWithSignature(id, 6, deadline, sig);
        vm.prank(organiser);
        ledger.setSupply(id, SUPPLY);
        vm.expectRevert(WoCoTicketLedger.NotOrganiserKey.selector);
        ledger.setSupplyWithSignature(id, 6, deadline, sig);
    }

    /// Every terms write consumes the nonce, on either path, so a direct write
    /// kills a signature made before it.
    function test_SignedTerms_DirectWriteKillsAPendingSignature() public {
        bytes32 id = _register();
        uint256 deadline = _deadline();
        bytes memory sig = _sign(ORG_KEY, ledger.setSupplyDigest(id, 6, deadline));
        vm.prank(organiser);
        ledger.extendSalesEnd(id, END_TS + 1 days);
        assertEq(ledger.termsNonces(id), 1);
        vm.expectRevert(WoCoTicketLedger.NotOrganiserKey.selector);
        ledger.setSupplyWithSignature(id, 6, deadline, sig);
    }

    function test_SignedTerms_Deadlines() public {
        bytes32 id = _register();
        uint256 ttl = ledger.MAX_TERMS_SIGNATURE_TTL();
        assertEq(ttl, 48 hours);

        uint256 past = block.timestamp - 1;
        bytes memory sig = _sign(ORG_KEY, ledger.setSupplyDigest(id, 6, past));
        vm.expectRevert(WoCoTicketLedger.SignatureExpired.selector);
        ledger.setSupplyWithSignature(id, 6, past, sig);

        uint256 tooFar = block.timestamp + ttl + 1;
        sig = _sign(ORG_KEY, ledger.setSupplyDigest(id, 6, tooFar));
        vm.expectRevert(WoCoTicketLedger.DeadlineTooFar.selector);
        ledger.setSupplyWithSignature(id, 6, tooFar, sig);

        uint256 edge = block.timestamp + ttl;
        sig = _sign(ORG_KEY, ledger.setSupplyDigest(id, 6, edge));
        ledger.setSupplyWithSignature(id, 6, edge, sig);

        // The deadline itself still counts.
        uint256 now_ = block.timestamp;
        sig = _sign(ORG_KEY, ledger.setSupplyDigest(id, 7, now_));
        ledger.setSupplyWithSignature(id, 7, now_, sig);
    }

    function test_SignedTerms_MalformedSignatureRefused() public {
        bytes32 id = _register();
        uint256 deadline = _deadline();
        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureLength.selector, 3));
        ledger.setSupplyWithSignature(id, 6, deadline, hex"010203");
    }

    function test_SignedTerms_UnknownEvent() public {
        uint256 deadline = _deadline();
        bytes32 nope = keccak256("nope");
        bytes memory sig = _sign(ORG_KEY, ledger.setSupplyDigest(nope, 6, deadline));
        vm.expectRevert(WoCoTicketLedger.EventNotFound.selector);
        ledger.setSupplyWithSignature(nope, 6, deadline, sig);
    }

    /// The signed path shares the direct path's rules.
    function test_SignedSetSupply_SameRules() public {
        bytes32 id = _register();
        uint256 deadline = _deadline();
        bytes memory sig = _sign(ORG_KEY, ledger.setSupplyDigest(id, SUPPLY + 1, deadline));
        vm.expectRevert(WoCoTicketLedger.SupplyAboveRegistered.selector);
        ledger.setSupplyWithSignature(id, SUPPLY + 1, deadline, sig);
    }

    function test_SignedExtendSalesEnd() public {
        bytes32 id = _register();
        uint256 deadline = _deadline();
        uint64 later = END_TS + 3 days;
        bytes memory sig = _sign(ORG_KEY, ledger.extendSalesEndDigest(id, later, deadline));
        vm.expectEmit(true, false, false, true, address(ledger));
        emit WoCoTicketLedger.SalesEndExtended(id, END_TS, later);
        vm.prank(stranger);
        ledger.extendSalesEndWithSignature(id, later, deadline, sig);
        (uint64 endTs, ) = ledger.getEventStatus(id);
        assertEq(endTs, later);

        bytes memory wrong = _sign(OTHER_KEY, ledger.extendSalesEndDigest(id, later + 1, deadline));
        vm.expectRevert(WoCoTicketLedger.NotOrganiserKey.selector);
        ledger.extendSalesEndWithSignature(id, later + 1, deadline, wrong);
    }

    /// `by` is the organiser key, never whoever submitted it.
    function test_SignedCancel_LogsTheKey() public {
        bytes32 id = _register();
        uint256 deadline = _deadline();
        bytes memory sig = _sign(ORG_KEY, ledger.cancelEventDigest(id, deadline));
        vm.expectEmit(true, true, false, true, address(ledger));
        emit WoCoTicketLedger.EventCancelled(id, orgKey, false);
        vm.prank(stranger);
        ledger.cancelEventWithSignature(id, deadline, sig);
        (, bool cancelled) = ledger.getEventStatus(id);
        assertTrue(cancelled);

        bytes memory again = _sign(ORG_KEY, ledger.cancelEventDigest(id, deadline));
        vm.expectRevert(WoCoTicketLedger.AlreadyCancelled.selector);
        ledger.cancelEventWithSignature(id, deadline, again);
    }

    function test_SignedCancel_OnlyTheEventsKey() public {
        bytes32 id = _register();
        uint256 deadline = _deadline();
        bytes memory sig = _sign(OTHER_KEY, ledger.cancelEventDigest(id, deadline));
        vm.expectRevert(WoCoTicketLedger.NotOrganiserKey.selector);
        ledger.cancelEventWithSignature(id, deadline, sig);
        uint256 tooFar = block.timestamp + ledger.MAX_TERMS_SIGNATURE_TTL() + 1;
        sig = _sign(ORG_KEY, ledger.cancelEventDigest(id, tooFar));
        vm.expectRevert(WoCoTicketLedger.DeadlineTooFar.selector);
        ledger.cancelEventWithSignature(id, tooFar, sig);
    }

    // ── setOrganiserKey ───────────────────────────────────────────────────────

    function test_SetOrganiserKey_RotatesAndRetiresTheOldKey() public {
        bytes32 id = _register();
        uint256 deadline = _deadline();
        bytes memory pending = _sign(ORG_KEY, ledger.setSupplyDigest(id, 6, deadline));

        vm.expectEmit(true, true, true, true, address(ledger));
        emit WoCoTicketLedger.OrganiserKeySet(id, orgKey, orgKey2);
        vm.prank(organiser);
        ledger.setOrganiserKey(_ids(id), orgKey2);
        assertEq(ledger.getOrganiserKey(id), orgKey2);

        // The old key's pending signature, a fresh one, and its direct call: all dead.
        vm.expectRevert(WoCoTicketLedger.NotOrganiserKey.selector);
        ledger.setSupplyWithSignature(id, 6, deadline, pending);
        bytes memory fresh_ = _sign(ORG_KEY, ledger.setSupplyDigest(id, 6, deadline));
        vm.expectRevert(WoCoTicketLedger.NotOrganiserKey.selector);
        ledger.setSupplyWithSignature(id, 6, deadline, fresh_);
        vm.prank(orgKey);
        vm.expectRevert(WoCoTicketLedger.NotOrganiser.selector);
        ledger.setSupply(id, 6);

        bytes memory byNew = _sign(ORG_KEY_2, ledger.setSupplyDigest(id, 6, deadline));
        ledger.setSupplyWithSignature(id, 6, deadline, byNew);
    }

    /// Only the organiser's ACCOUNT moves the key: not the key itself, not a
    /// sponsor, not the owner.
    function test_SetOrganiserKey_AccountOnly() public {
        bytes32 id = _register();
        address[4] memory notAccount = [orgKey, sponsor, owner, stranger];
        for (uint256 i; i < notAccount.length; ++i) {
            vm.prank(notAccount[i]);
            vm.expectRevert(WoCoTicketLedger.NotOrganiser.selector);
            ledger.setOrganiserKey(_ids(id), orgKey2);
        }
        assertEq(ledger.getOrganiserKey(id), orgKey);
    }

    function test_SetOrganiserKey_ManyEventsAllOrNothing() public {
        bytes32 a = _register();
        bytes32 b = _register();
        vm.prank(stranger);
        bytes32 notTheirs = ledger.registerEvent(stranger, orgKey, SUPPLY, MANIFEST, END_TS);

        bytes32[] memory ids = new bytes32[](3);
        ids[0] = a;
        ids[1] = b;
        ids[2] = notTheirs;
        vm.prank(organiser);
        vm.expectRevert(WoCoTicketLedger.NotOrganiser.selector);
        ledger.setOrganiserKey(ids, orgKey2);
        assertEq(ledger.getOrganiserKey(a), orgKey, "a refused batch moved a key");

        bytes32[] memory two = new bytes32[](2);
        two[0] = a;
        two[1] = b;
        vm.prank(organiser);
        ledger.setOrganiserKey(two, orgKey2);
        assertEq(ledger.getOrganiserKey(a), orgKey2);
        assertEq(ledger.getOrganiserKey(b), orgKey2);
        assertEq(ledger.termsNonces(a), 1);
        assertEq(ledger.termsNonces(b), 1);
    }

    function test_SetOrganiserKey_Guards() public {
        bytes32 id = _register();
        vm.startPrank(organiser);
        vm.expectRevert(WoCoTicketLedger.BatchEmpty.selector);
        ledger.setOrganiserKey(new bytes32[](0), orgKey2);
        vm.expectRevert(WoCoTicketLedger.ZeroAddress.selector);
        ledger.setOrganiserKey(_ids(id), address(0));
        vm.expectRevert(WoCoTicketLedger.TransferToLedger.selector);
        ledger.setOrganiserKey(_ids(id), address(ledger));
        vm.expectRevert(WoCoTicketLedger.OrganiserKeyUnchanged.selector);
        ledger.setOrganiserKey(_ids(id), orgKey);
        vm.expectRevert(WoCoTicketLedger.EventNotFound.selector);
        ledger.setOrganiserKey(_ids(keccak256("nope")), orgKey2);
        // An id listed twice: the second entry is unchanged.
        bytes32[] memory twice = new bytes32[](2);
        twice[0] = id;
        twice[1] = id;
        vm.expectRevert(WoCoTicketLedger.OrganiserKeyUnchanged.selector);
        ledger.setOrganiserKey(twice, orgKey2);
        vm.stopPrank();
    }

    /// A rotation never fails on an old event: cancelled and past-cutoff ids move too.
    function test_SetOrganiserKey_ClosedEventsMove() public {
        bytes32 cancelled = _register();
        vm.prank(organiser);
        ledger.cancelEvent(cancelled);
        bytes32 lapsed = _register();
        vm.warp(END_TS);
        bytes32[] memory ids = new bytes32[](2);
        ids[0] = cancelled;
        ids[1] = lapsed;
        vm.prank(organiser);
        ledger.setOrganiserKey(ids, orgKey2);
        assertEq(ledger.getOrganiserKey(cancelled), orgKey2);
        assertEq(ledger.getOrganiserKey(lapsed), orgKey2);
    }

    /// Sponsors hold no terms: removing one leaves every event's terms where
    /// the organiser has them, and minting carries on through another sponsor.
    function test_RemovingASponsorTouchesNoTerms() public {
        bytes32 id = _register();
        vm.prank(owner);
        ledger.removeSponsor(sponsor);
        vm.prank(organiser);
        ledger.setSupply(id, SUPPLY - 1);
        vm.prank(sponsor2);
        ledger.claimFor(id, holder, ORDER);
    }

    // ── seats: minting ────────────────────────────────────────────────────────

    function _seats(uint256 a) internal pure returns (uint256[] memory s) {
        s = new uint256[](1);
        s[0] = a;
    }

    function _seats(uint256 a, uint256 b) internal pure returns (uint256[] memory s) {
        s = new uint256[](2);
        s[0] = a;
        s[1] = b;
    }

    function _claimSeats(bytes32 id, uint256[] memory seats, address to) internal returns (uint256 first) {
        vm.prank(sponsor);
        first = ledger.batchClaimSeats(id, _owners(seats.length, to), seats, ORDER);
    }

    function _claimSeatsBearer(bytes32 id, uint256[] memory seats, address to) internal returns (uint256 first) {
        vm.prank(sponsor);
        first = ledger.batchClaimSeatsBearer(id, _owners(seats.length, to), seats, ORDER);
    }

    function _seatTaken(bytes32 id, uint256 seat) internal view returns (bool) {
        return ledger.seatWord(id, seat >> 8) & (uint256(1) << (seat & 255)) != 0;
    }

    function test_ClaimSeats_SlotsStaySequentialSeatsAreChosen() public {
        bytes32 id = _registerSeated();
        vm.expectEmit(true, true, false, true, address(ledger));
        emit WoCoTicketLedger.SeatAssigned(id, 0, 7);
        vm.expectEmit(true, true, false, true, address(ledger));
        emit WoCoTicketLedger.SeatAssigned(id, 1, 2);
        uint256 first = _claimSeats(id, _seats(7, 2), holder);
        assertEq(first, 0);
        assertEq(ledger.seatOf(id, 0), 7);
        assertEq(ledger.seatOf(id, 1), 2);
        assertEq(ledger.seatWord(id, 0), (uint256(1) << 7) | (uint256(1) << 2));
        assertEq(_nextSlot(id), 2);
        assertEq(ledger.slotOwner(id, 1), holder);
        assertEq(ledger.seatOf(id, 2), ledger.NO_SEAT(), "an unclaimed slot has a seat");
    }

    function test_ClaimSeats_SeatZeroAndTheLastSeat() public {
        bytes32 id = _registerSeated();
        _claimSeats(id, _seats(0, SUPPLY - 1), holder);
        assertEq(ledger.seatOf(id, 0), 0, "seat 0 reads as no seat");
        assertEq(ledger.seatOf(id, 1), SUPPLY - 1);
    }

    /// A seat in a word other than the first, and the bit layout across words.
    function test_ClaimSeats_SecondWord() public {
        vm.prank(sponsor);
        bytes32 id = ledger.registerSeatedEvent(organiser, orgKey, 600, MANIFEST, END_TS);
        _claimSeats(id, _seats(255, 256), holder);
        assertEq(ledger.seatWord(id, 0), uint256(1) << 255);
        assertEq(ledger.seatWord(id, 1), 1);
        assertEq(ledger.seatOf(id, 1), 256);
    }

    function test_ClaimSeats_NeverATakenSeat() public {
        bytes32 id = _registerSeated();
        _claimSeats(id, _seats(3), holder);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.SeatTaken.selector);
        ledger.batchClaimSeats(id, _owners(1, holder), _seats(3), ORDER);
        // Within one batch too.
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.SeatTaken.selector);
        ledger.batchClaimSeats(id, _owners(2, holder), _seats(4, 4), ORDER);
        assertEq(_nextSlot(id), 1, "a refused batch minted");
    }

    /// Below the REGISTERED supply: a lowered supply caps the count, never the choice.
    function test_ClaimSeats_SeatBelowRegisteredSupply() public {
        bytes32 id = _registerSeated();
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.InvalidSeat.selector);
        ledger.batchClaimSeats(id, _owners(1, holder), _seats(SUPPLY), ORDER);

        vm.prank(organiser);
        ledger.setSupply(id, 2);
        _claimSeats(id, _seats(SUPPLY - 1, SUPPLY - 2), holder);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.InsufficientSupply.selector);
        ledger.batchClaimSeats(id, _owners(1, holder), _seats(0), ORDER);
    }

    function test_ClaimSeats_LengthMustMatch() public {
        bytes32 id = _registerSeated();
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.LengthMismatch.selector);
        ledger.batchClaimSeats(id, _owners(2, holder), _seats(1), ORDER);
    }

    /// Each kind refuses the other's mint paths: no seatless ticket on a
    /// seated event, no seat on a GA one.
    function test_KindsRefuseEachOthersMints() public {
        bytes32 seatedId = _registerSeated();
        bytes32 ga = _register();
        vm.startPrank(sponsor);
        vm.expectRevert(WoCoTicketLedger.SeatedEvent.selector);
        ledger.claimFor(seatedId, holder, ORDER);
        vm.expectRevert(WoCoTicketLedger.SeatedEvent.selector);
        ledger.batchClaimFor(seatedId, _owners(1, holder), ORDER);
        vm.expectRevert(WoCoTicketLedger.SeatedEvent.selector);
        ledger.batchClaimBearer(seatedId, _owners(1, holder), ORDER);
        vm.expectRevert(WoCoTicketLedger.NotSeated.selector);
        ledger.batchClaimSeats(ga, _owners(1, holder), _seats(0), ORDER);
        vm.expectRevert(WoCoTicketLedger.NotSeated.selector);
        ledger.batchClaimSeatsBearer(ga, _owners(1, holder), _seats(0), ORDER);
        vm.stopPrank();
    }

    function test_ClaimSeats_SponsorsOnly() public {
        bytes32 id = _registerSeated();
        vm.startPrank(organiser);
        vm.expectRevert(WoCoTicketLedger.NotAuthorised.selector);
        ledger.batchClaimSeats(id, _owners(1, holder), _seats(0), ORDER);
        vm.expectRevert(WoCoTicketLedger.NotAuthorised.selector);
        ledger.batchClaimSeatsBearer(id, _owners(1, holder), _seats(0), ORDER);
        vm.stopPrank();
    }

    function test_ClaimSeatsBearer_MintsBearer() public {
        bytes32 id = _registerSeated();
        uint256 s = _claimSeatsBearer(id, _seats(5), holder);
        (bool bearer, bool held) = ledger.getSlotFlags(id, s);
        assertTrue(bearer);
        assertFalse(held);
        _claimSeats(id, _seats(6), holder);
        (bool notBearer, ) = ledger.getSlotFlags(id, s + 1);
        assertFalse(notBearer);
    }

    function test_GaTicketsHaveNoSeat() public {
        bytes32 id = _register();
        vm.prank(sponsor);
        ledger.claimFor(id, holder, ORDER);
        assertEq(ledger.seatOf(id, 0), ledger.NO_SEAT());
        assertEq(ledger.seatWord(id, 0), 0);
    }

    /// A reissue re-points the ticket and keeps its seat.
    function test_Reissue_KeepsTheSeat() public {
        bytes32 id = _registerSeated();
        uint256 s = _claimSeatsBearer(id, _seats(4), holder);
        _reissue(id, _slots(s), fresh);
        assertEq(ledger.slotOwner(id, s), fresh);
        assertEq(ledger.seatOf(id, s), 4);
        assertTrue(_seatTaken(id, 4));
    }

    // ── seats: moves ──────────────────────────────────────────────────────────

    function _reseatBearer(bytes32 id, uint256 slot, uint256 toSeat) internal {
        uint256 deadline = _deadline();
        bytes memory sig = _sign(ORG_KEY, ledger.reseatDigest(id, slot, toSeat, deadline));
        vm.prank(stranger);
        ledger.reseatBearer(id, slot, toSeat, deadline, sig);
    }

    function test_ReseatBearer_MovesOnTheOrganisersSignature() public {
        bytes32 id = _registerSeated();
        uint256 s = _claimSeatsBearer(id, _seats(1), holder);
        vm.expectEmit(true, true, false, true, address(ledger));
        emit WoCoTicketLedger.SlotReseated(id, s, 1, 8);
        _reseatBearer(id, s, 8);

        assertEq(ledger.seatOf(id, s), 8);
        assertFalse(_seatTaken(id, 1), "the old seat was not freed");
        assertTrue(_seatTaken(id, 8));
        assertEq(ledger.slotOwner(id, s), holder, "a seat move changed the holder");
        assertFalse(_held(id, s), "a bearer move made the slot held");
        assertEq(ledger.transferNonces(id, s), 1, "a seat move did not consume the nonce");
        // The freed seat sells again.
        _claimSeats(id, _seats(1), fresh);
    }

    /// Out to `NO_SEAT` for a move to another band, and back into a seat.
    function test_ReseatBearer_ToNoSeatAndBack() public {
        bytes32 id = _registerSeated();
        uint256 s = _claimSeatsBearer(id, _seats(2), holder);
        uint256 noSeat = ledger.NO_SEAT();
        _reseatBearer(id, s, noSeat);
        assertEq(ledger.seatOf(id, s), noSeat);
        assertEq(ledger.seatWord(id, 0), 0);

        _reseatBearer(id, s, 3);
        assertEq(ledger.seatOf(id, s), 3);
    }

    function test_ReseatBearer_Refusals() public {
        bytes32 id = _registerSeated();
        uint256 s = _claimSeatsBearer(id, _seats(1, 2), holder);
        uint256 deadline = _deadline();

        bytes memory sig = _sign(ORG_KEY, ledger.reseatDigest(id, s, 2, deadline));
        vm.expectRevert(WoCoTicketLedger.SeatTaken.selector);
        ledger.reseatBearer(id, s, 2, deadline, sig);

        sig = _sign(ORG_KEY, ledger.reseatDigest(id, s, 1, deadline));
        vm.expectRevert(WoCoTicketLedger.SeatUnchanged.selector);
        ledger.reseatBearer(id, s, 1, deadline, sig);

        sig = _sign(ORG_KEY, ledger.reseatDigest(id, s, SUPPLY, deadline));
        vm.expectRevert(WoCoTicketLedger.InvalidSeat.selector);
        ledger.reseatBearer(id, s, SUPPLY, deadline, sig);

        sig = _sign(OTHER_KEY, ledger.reseatDigest(id, s, 5, deadline));
        vm.expectRevert(WoCoTicketLedger.NotOrganiserKey.selector);
        ledger.reseatBearer(id, s, 5, deadline, sig);

        // The holder's key is not the organiser's.
        sig = _sign(HOLDER_KEY, ledger.reseatDigest(id, s, 5, deadline));
        vm.expectRevert(WoCoTicketLedger.NotOrganiserKey.selector);
        ledger.reseatBearer(id, s, 5, deadline, sig);

        sig = _sign(ORG_KEY, ledger.reseatDigest(id, 9, 5, deadline));
        vm.expectRevert(WoCoTicketLedger.SlotUnclaimed.selector);
        ledger.reseatBearer(id, 9, 5, deadline, sig);

        uint256 tooFar = block.timestamp + ledger.MAX_TERMS_SIGNATURE_TTL() + 1;
        sig = _sign(ORG_KEY, ledger.reseatDigest(id, s, 5, tooFar));
        vm.expectRevert(WoCoTicketLedger.DeadlineTooFar.selector);
        ledger.reseatBearer(id, s, 5, tooFar, sig);
    }

    function test_ReseatBearer_NotBearerNorHeld() public {
        bytes32 id = _registerSeated();
        uint256 nonBearer = _claimSeats(id, _seats(1), holder);
        uint256 bearerSlot = _claimSeatsBearer(id, _seats(2), holder);
        uint256 deadline = _deadline();

        bytes memory sig = _sign(ORG_KEY, ledger.reseatDigest(id, nonBearer, 5, deadline));
        vm.expectRevert(WoCoTicketLedger.NotBearer.selector);
        ledger.reseatBearer(id, nonBearer, 5, deadline, sig);

        vm.prank(holder);
        ledger.transferSlot(id, bearerSlot, fresh);
        sig = _sign(ORG_KEY, ledger.reseatDigest(id, bearerSlot, 5, deadline));
        vm.expectRevert(WoCoTicketLedger.SlotHeld.selector);
        ledger.reseatBearer(id, bearerSlot, 5, deadline, sig);
        // The seat travelled with the transfer.
        assertEq(ledger.seatOf(id, bearerSlot), 2);
    }

    /// A consent dies once used, and once the slot moves any other way.
    function test_ReseatBearer_ConsentIsSingleUse() public {
        bytes32 id = _registerSeated();
        uint256 s = _claimSeatsBearer(id, _seats(1), holder);
        uint256 deadline = _deadline();
        bytes memory sig = _sign(ORG_KEY, ledger.reseatDigest(id, s, 5, deadline));
        bytes memory later = _sign(ORG_KEY, ledger.reseatDigest(id, s, 6, deadline));
        ledger.reseatBearer(id, s, 5, deadline, sig);
        // Back to seat 1 by another consent, then the spent one again.
        _reseatBearer(id, s, 1);
        vm.expectRevert(WoCoTicketLedger.NotOrganiserKey.selector);
        ledger.reseatBearer(id, s, 5, deadline, sig);
        // One made before the moves is dead too.
        vm.expectRevert(WoCoTicketLedger.NotOrganiserKey.selector);
        ledger.reseatBearer(id, s, 6, deadline, later);

        // A reissue kills a pending consent.
        bytes memory pending = _sign(ORG_KEY, ledger.reseatDigest(id, s, 7, deadline));
        _reissue(id, _slots(s), fresh);
        vm.expectRevert(WoCoTicketLedger.NotOrganiserKey.selector);
        ledger.reseatBearer(id, s, 7, deadline, pending);
    }

    function test_ReseatBearer_EndsWithTheOffSwitch() public {
        bytes32 id = _registerSeated();
        uint256 s = _claimSeatsBearer(id, _seats(1), holder);
        vm.prank(owner);
        ledger.disableBearerMints();
        uint256 deadline = _deadline();
        bytes memory sig = _sign(ORG_KEY, ledger.reseatDigest(id, s, 5, deadline));
        vm.expectRevert(WoCoTicketLedger.BearerMintsOff.selector);
        ledger.reseatBearer(id, s, 5, deadline, sig);
    }

    function test_Reseat_RefusedOnGaCancelledAndClosed() public {
        bytes32 ga = _register();
        uint256 g = _bearer(ga, 1, holder);
        uint256 deadline = _deadline();
        bytes memory sig = _sign(ORG_KEY, ledger.reseatDigest(ga, g, 1, deadline));
        vm.expectRevert(WoCoTicketLedger.NotSeated.selector);
        ledger.reseatBearer(ga, g, 1, deadline, sig);

        bytes32 id = _registerSeated();
        uint256 s = _claimSeatsBearer(id, _seats(1), holder);
        vm.prank(organiser);
        ledger.cancelEvent(id);
        sig = _sign(ORG_KEY, ledger.reseatDigest(id, s, 5, deadline));
        vm.expectRevert(WoCoTicketLedger.AlreadyCancelled.selector);
        ledger.reseatBearer(id, s, 5, deadline, sig);

        bytes32 closed = _registerSeated();
        uint256 c = _claimSeatsBearer(closed, _seats(1), holder);
        vm.warp(END_TS);
        uint256 d2 = block.timestamp + 1 hours;
        sig = _sign(ORG_KEY, ledger.reseatDigest(closed, c, 5, d2));
        vm.expectRevert(WoCoTicketLedger.SalesClosed.selector);
        ledger.reseatBearer(closed, c, 5, d2, sig);
    }

    // ── two-party reseat ──────────────────────────────────────────────────────

    function test_Reseat_OrganiserAndHolder() public {
        bytes32 id = _registerSeated();
        uint256 s = _claimSeats(id, _seats(1), holder);
        uint256 deadline = _deadline();
        bytes32 digest = ledger.reseatDigest(id, s, 9, deadline);
        vm.expectEmit(true, true, false, true, address(ledger));
        emit WoCoTicketLedger.SlotReseated(id, s, 1, 9);
        vm.prank(stranger);
        ledger.reseat(id, s, 9, deadline, _sign(ORG_KEY, digest), _sign(HOLDER_KEY, digest));
        assertEq(ledger.seatOf(id, s), 9);
        assertTrue(_held(id, s), "a holder-signed move did not mark the slot held");
        assertEq(ledger.slotOwner(id, s), holder);
    }

    /// Neither party alone: the holder cannot take a free seat, the organiser
    /// cannot move a ticket someone holds the key to.
    function test_Reseat_BothConsentsNeeded() public {
        bytes32 id = _registerSeated();
        uint256 s = _claimSeats(id, _seats(1), holder);
        uint256 deadline = _deadline();
        bytes32 digest = ledger.reseatDigest(id, s, 9, deadline);
        bytes memory h = _sign(HOLDER_KEY, digest);
        bytes memory o = _sign(ORG_KEY, digest);

        vm.expectRevert(WoCoTicketLedger.NotOrganiserKey.selector);
        ledger.reseat(id, s, 9, deadline, h, h);
        vm.expectRevert(WoCoTicketLedger.NotSlotOwner.selector);
        ledger.reseat(id, s, 9, deadline, o, o);
        vm.expectRevert(WoCoTicketLedger.NotSlotOwner.selector);
        ledger.reseat(id, s, 9, deadline, o, _sign(OTHER_KEY, digest));
        assertEq(ledger.seatOf(id, s), 1);
    }

    /// The holder's consent dies with the slot's move: after a transfer, the
    /// new holder must sign.
    function test_Reseat_HolderConsentDiesWithATransfer() public {
        bytes32 id = _registerSeated();
        uint256 s = _claimSeats(id, _seats(1), holder);
        uint256 deadline = _deadline();
        bytes32 digest = ledger.reseatDigest(id, s, 9, deadline);
        bytes memory h = _sign(HOLDER_KEY, digest);
        bytes memory o = _sign(ORG_KEY, digest);
        vm.prank(holder);
        ledger.transferSlot(id, s, fresh);
        vm.expectRevert(WoCoTicketLedger.NotOrganiserKey.selector);
        ledger.reseat(id, s, 9, deadline, o, h);
    }

    /// One key in both roles (the organiser key holds the ticket) passes, once.
    function test_Reseat_OneKeyBothRoles() public {
        bytes32 id = _registerSeated();
        uint256 s = _claimSeats(id, _seats(1), orgKey);
        uint256 deadline = _deadline();
        bytes32 digest = ledger.reseatDigest(id, s, 9, deadline);
        bytes memory sig = _sign(ORG_KEY, digest);
        ledger.reseat(id, s, 9, deadline, sig, sig);
        assertEq(ledger.seatOf(id, s), 9);
        vm.expectRevert(WoCoTicketLedger.NotOrganiserKey.selector);
        ledger.reseat(id, s, 9, deadline, sig, sig);
    }

    /// It survives the off switch: the road for tickets whose holders keep keys.
    function test_Reseat_SurvivesTheOffSwitch() public {
        bytes32 id = _registerSeated();
        uint256 s = _claimSeats(id, _seats(1), holder);
        vm.prank(owner);
        ledger.disableBearerMints();
        uint256 deadline = _deadline();
        bytes32 digest = ledger.reseatDigest(id, s, 9, deadline);
        ledger.reseat(id, s, 9, deadline, _sign(ORG_KEY, digest), _sign(HOLDER_KEY, digest));
        assertEq(ledger.seatOf(id, s), 9);
    }

    /// After a two-party move the slot is held: neither `reissue` nor
    /// `reseatBearer` reaches it.
    function test_Reseat_PutsABearerSlotOutOfThePlatformsReach() public {
        bytes32 id = _registerSeated();
        uint256 s = _claimSeatsBearer(id, _seats(1), holder);
        uint256 deadline = _deadline();
        bytes32 digest = ledger.reseatDigest(id, s, 9, deadline);
        ledger.reseat(id, s, 9, deadline, _sign(ORG_KEY, digest), _sign(HOLDER_KEY, digest));
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.SlotHeld.selector);
        ledger.reissue(id, _slots(s), _owners(1, fresh));
        bytes memory sig = _sign(ORG_KEY, ledger.reseatDigest(id, s, 3, deadline));
        vm.expectRevert(WoCoTicketLedger.SlotHeld.selector);
        ledger.reseatBearer(id, s, 3, deadline, sig);
    }

    function test_ReseatDigest_IsEip712() public {
        bytes32 id = _registerSeated();
        uint256 s = _claimSeats(id, _seats(1), holder);
        uint256 deadline = _deadline();
        bytes32 domain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256("WoCoTicketLedger"),
                keccak256("2"),
                block.chainid,
                address(ledger)
            )
        );
        bytes32 structHash = keccak256(
            abi.encode(
                keccak256("Reseat(bytes32 eventId,uint256 slot,uint256 toSeat,address holder,uint256 nonce,uint256 deadline)"),
                id, s, uint256(9), holder, uint256(0), deadline
            )
        );
        assertEq(ledger.reseatDigest(id, s, 9, deadline), keccak256(abi.encodePacked("\x19\x01", domain, structHash)));
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
        // No slot minted, no supply used.
        assertEq(_nextSlot(id), 3, "a reissue minted a slot");
        assertEq(ledger.remaining(id), remainingBefore, "supply left moved");
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

    function test_Reissue_UsesNoSupply() public {
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

    /// Reissue follows a cutoff moved later: the same window as sales.
    function test_Reissue_FollowsAnExtendedCutoff() public {
        bytes32 id = _register();
        uint256 s = _bearer(id, 1, holder);
        vm.prank(organiser);
        ledger.extendSalesEnd(id, END_TS + 1 days);
        vm.warp(END_TS);
        _reissue(id, _slots(s), fresh);
        assertEq(ledger.slotOwner(id, s), fresh);

        vm.warp(END_TS + 1 days);
        vm.prank(sponsor);
        vm.expectRevert(WoCoTicketLedger.SalesClosed.selector);
        ledger.reissue(id, _slots(s), _owners(1, holder));
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
        bytes32 seatedId = _registerSeated();
        uint256 s = _bearer(id, 1, holder);
        vm.prank(owner);
        ledger.disableBearerMints();

        vm.startPrank(sponsor);
        vm.expectRevert(WoCoTicketLedger.BearerMintsOff.selector);
        ledger.batchClaimBearer(id, _owners(1, holder), ORDER);
        vm.expectRevert(WoCoTicketLedger.BearerMintsOff.selector);
        ledger.batchClaimSeatsBearer(seatedId, _owners(1, holder), _seats(0), ORDER);
        vm.expectRevert(WoCoTicketLedger.BearerMintsOff.selector);
        ledger.reissue(id, _slots(s), _owners(1, fresh));

        // Everything else carries on.
        ledger.claimFor(id, holder, ORDER);
        ledger.batchClaimFor(id, _owners(1, holder), ORDER);
        ledger.batchClaimSeats(seatedId, _owners(1, holder), _seats(0), ORDER);
        vm.stopPrank();
        vm.startPrank(organiser);
        ledger.setSupply(id, SUPPLY - 1);
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
        assertEq(bytes32(WoCoTicketLedger.registerEvent.selector),       bytes32(bytes4(keccak256("registerEvent(address,address,uint64,bytes32,uint64)"))));
        assertEq(bytes32(WoCoTicketLedger.registerSeatedEvent.selector), bytes32(bytes4(keccak256("registerSeatedEvent(address,address,uint64,bytes32,uint64)"))));
        assertEq(bytes32(WoCoTicketLedger.batchClaimBearer.selector), bytes32(bytes4(keccak256("batchClaimBearer(bytes32,address[],bytes32)"))));
        assertEq(bytes32(WoCoTicketLedger.batchClaimSeats.selector),  bytes32(bytes4(keccak256("batchClaimSeats(bytes32,address[],uint256[],bytes32)"))));
        assertEq(bytes32(WoCoTicketLedger.batchClaimSeatsBearer.selector), bytes32(bytes4(keccak256("batchClaimSeatsBearer(bytes32,address[],uint256[],bytes32)"))));
        assertEq(bytes32(WoCoTicketLedger.reissue.selector),          bytes32(bytes4(keccak256("reissue(bytes32,uint256[],address[])"))));
        assertEq(bytes32(WoCoTicketLedger.getSlotFlags.selector),     bytes32(bytes4(keccak256("getSlotFlags(bytes32,uint256)"))));
        assertEq(bytes32(WoCoTicketLedger.getOrganiserKey.selector),  bytes32(bytes4(keccak256("getOrganiserKey(bytes32)"))));
        assertEq(bytes32(WoCoTicketLedger.isSeated.selector),         bytes32(bytes4(keccak256("isSeated(bytes32)"))));
        assertEq(bytes32(WoCoTicketLedger.seatOf.selector),           bytes32(bytes4(keccak256("seatOf(bytes32,uint256)"))));
        assertEq(bytes32(WoCoTicketLedger.seatWord.selector),         bytes32(bytes4(keccak256("seatWord(bytes32,uint256)"))));
        assertEq(bytes32(WoCoTicketLedger.setSupply.selector),        bytes32(bytes4(keccak256("setSupply(bytes32,uint64)"))));
        assertEq(bytes32(WoCoTicketLedger.setSupplyWithSignature.selector), bytes32(bytes4(keccak256("setSupplyWithSignature(bytes32,uint64,uint256,bytes)"))));
        assertEq(bytes32(WoCoTicketLedger.extendSalesEnd.selector),   bytes32(bytes4(keccak256("extendSalesEnd(bytes32,uint64)"))));
        assertEq(bytes32(WoCoTicketLedger.extendSalesEndWithSignature.selector), bytes32(bytes4(keccak256("extendSalesEndWithSignature(bytes32,uint64,uint256,bytes)"))));
        assertEq(bytes32(WoCoTicketLedger.cancelEventWithSignature.selector), bytes32(bytes4(keccak256("cancelEventWithSignature(bytes32,uint256,bytes)"))));
        assertEq(bytes32(WoCoTicketLedger.setOrganiserKey.selector),  bytes32(bytes4(keccak256("setOrganiserKey(bytes32[],address)"))));
        assertEq(bytes32(WoCoTicketLedger.reseatBearer.selector),     bytes32(bytes4(keccak256("reseatBearer(bytes32,uint256,uint256,uint256,bytes)"))));
        assertEq(bytes32(WoCoTicketLedger.reseat.selector),           bytes32(bytes4(keccak256("reseat(bytes32,uint256,uint256,uint256,bytes,bytes)"))));
        assertEq(bytes32(WoCoTicketLedger.setSupplyDigest.selector),  bytes32(bytes4(keccak256("setSupplyDigest(bytes32,uint64,uint256)"))));
        assertEq(bytes32(WoCoTicketLedger.extendSalesEndDigest.selector), bytes32(bytes4(keccak256("extendSalesEndDigest(bytes32,uint64,uint256)"))));
        assertEq(bytes32(WoCoTicketLedger.cancelEventDigest.selector), bytes32(bytes4(keccak256("cancelEventDigest(bytes32,uint256)"))));
        assertEq(bytes32(WoCoTicketLedger.reseatDigest.selector),     bytes32(bytes4(keccak256("reseatDigest(bytes32,uint256,uint256,uint256)"))));
        assertEq(bytes32(ledger.termsNonces.selector),                bytes32(bytes4(keccak256("termsNonces(bytes32)"))));
        assertEq(bytes32(ledger.bearerMintsDisabled.selector),        bytes32(bytes4(keccak256("bearerMintsDisabled()"))));
        assertEq(bytes32(WoCoTicketLedger.getRegisteredSupply.selector), bytes32(bytes4(keccak256("getRegisteredSupply(bytes32)"))));
        assertEq(bytes32(ledger.MAX_SALES_EXTENSION.selector),        bytes32(bytes4(keccak256("MAX_SALES_EXTENSION()"))));
        assertEq(bytes32(ledger.MAX_TERMS_SIGNATURE_TTL.selector),    bytes32(bytes4(keccak256("MAX_TERMS_SIGNATURE_TTL()"))));
        assertEq(bytes32(ledger.NO_SEAT.selector),                    bytes32(bytes4(keccak256("NO_SEAT()"))));

        assertEq(WoCoTicketLedger.Registered.selector,          keccak256("Registered(bytes32,address,address,uint64,bytes32,uint64)"));
        assertEq(WoCoTicketLedger.SlotReissued.selector,        keccak256("SlotReissued(bytes32,uint256,address,address)"));
        assertEq(WoCoTicketLedger.SupplySet.selector,           keccak256("SupplySet(bytes32,uint64,uint64)"));
        assertEq(WoCoTicketLedger.SalesEndExtended.selector,    keccak256("SalesEndExtended(bytes32,uint64,uint64)"));
        assertEq(WoCoTicketLedger.BearerMintsDisabled.selector, keccak256("BearerMintsDisabled(address)"));
        assertEq(WoCoTicketLedger.OrganiserKeySet.selector,     keccak256("OrganiserKeySet(bytes32,address,address)"));
        assertEq(WoCoTicketLedger.Seated.selector,              keccak256("Seated(bytes32)"));
        assertEq(WoCoTicketLedger.SeatAssigned.selector,        keccak256("SeatAssigned(bytes32,uint256,uint256)"));
        assertEq(WoCoTicketLedger.SlotReseated.selector,        keccak256("SlotReseated(bytes32,uint256,uint256,uint256)"));

        assertEq(ledger.SET_SUPPLY_TYPEHASH(),       keccak256("SetSupply(bytes32 eventId,uint64 supply,uint256 nonce,uint256 deadline)"));
        assertEq(ledger.EXTEND_SALES_END_TYPEHASH(), keccak256("ExtendSalesEnd(bytes32 eventId,uint64 eventEndTs,uint256 nonce,uint256 deadline)"));
        assertEq(ledger.CANCEL_EVENT_TYPEHASH(),     keccak256("CancelEvent(bytes32 eventId,uint256 nonce,uint256 deadline)"));
        assertEq(ledger.RESEAT_TYPEHASH(),           keccak256("Reseat(bytes32 eventId,uint256 slot,uint256 toSeat,address holder,uint256 nonce,uint256 deadline)"));

        assertEq(bytes32(WoCoTicketLedger.BearerMintsOff.selector),    bytes32(bytes4(keccak256("BearerMintsOff()"))));
        assertEq(bytes32(WoCoTicketLedger.LengthMismatch.selector),    bytes32(bytes4(keccak256("LengthMismatch()"))));
        assertEq(bytes32(WoCoTicketLedger.SlotsNotAscending.selector), bytes32(bytes4(keccak256("SlotsNotAscending()"))));
        assertEq(bytes32(WoCoTicketLedger.NotBearer.selector),         bytes32(bytes4(keccak256("NotBearer()"))));
        assertEq(bytes32(WoCoTicketLedger.NotSlotClaimer.selector),    bytes32(bytes4(keccak256("NotSlotClaimer()"))));
        assertEq(bytes32(WoCoTicketLedger.SlotHeld.selector),          bytes32(bytes4(keccak256("SlotHeld()"))));
        assertEq(bytes32(WoCoTicketLedger.NotOrganiserKey.selector),   bytes32(bytes4(keccak256("NotOrganiserKey()"))));
        assertEq(bytes32(WoCoTicketLedger.SupplyUnchanged.selector),   bytes32(bytes4(keccak256("SupplyUnchanged()"))));
        assertEq(bytes32(WoCoTicketLedger.SupplyAboveRegistered.selector), bytes32(bytes4(keccak256("SupplyAboveRegistered()"))));
        assertEq(bytes32(WoCoTicketLedger.SalesEndTooFar.selector),    bytes32(bytes4(keccak256("SalesEndTooFar()"))));
        assertEq(bytes32(WoCoTicketLedger.OrganiserKeyUnchanged.selector), bytes32(bytes4(keccak256("OrganiserKeyUnchanged()"))));
        assertEq(bytes32(WoCoTicketLedger.DeadlineTooFar.selector),    bytes32(bytes4(keccak256("DeadlineTooFar()"))));
        assertEq(bytes32(WoCoTicketLedger.SeatedEvent.selector),       bytes32(bytes4(keccak256("SeatedEvent()"))));
        assertEq(bytes32(WoCoTicketLedger.NotSeated.selector),         bytes32(bytes4(keccak256("NotSeated()"))));
        assertEq(bytes32(WoCoTicketLedger.InvalidSeat.selector),       bytes32(bytes4(keccak256("InvalidSeat()"))));
        assertEq(bytes32(WoCoTicketLedger.SeatTaken.selector),         bytes32(bytes4(keccak256("SeatTaken()"))));
        assertEq(bytes32(WoCoTicketLedger.SeatUnchanged.selector),     bytes32(bytes4(keccak256("SeatUnchanged()"))));
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
