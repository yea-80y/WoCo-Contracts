// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {WoCoTicketLedger} from "../src/WoCoTicketLedger.sol";

/**
 * Tests for `WoCoTicketLedger.transferSlotWithSignature` — a slot move
 * authorised by the holder's SIGNATURE, so that someone else (the platform, or
 * anyone) may submit it and pay the gas. Added for WoCo-Event-App #298 (owner
 * decision 2026-09-13). The ledger is immutable, so like the registry's
 * signature suites this file freezes a SHAPE. The promise:
 *
 *   "If you sign 'move ticket N to X', anyone can hand it in for you — but only
 *    for that ticket, that recipient, this ledger, this chain and the deadline
 *    you signed; only while you still hold the ticket; and only until it next
 *    moves. Whoever hands it in cannot send the ticket anywhere else."
 *
 * The holder-only path and the shared guards are pinned in
 * WoCoTicketLedger.t.sol. They are re-checked here through the signature path,
 * because that path recovers a signer BEFORE reaching them.
 */
contract WoCoTicketLedgerSignedTransferTest is Test {
    WoCoTicketLedger ledger;

    address owner     = address(0x1);
    address sponsor   = address(0x2);
    address organiser = address(0x3);
    /// The platform's hot wallet in production: it pays, it never authorises.
    address relayer   = makeAddr("relayer");

    uint256 constant HOLDER_KEY   = 0xA11CE;
    uint256 constant STRANGER_KEY = 0xB0B;
    address holder    = vm.addr(HOLDER_KEY);
    address stranger  = vm.addr(STRANGER_KEY);
    address recipient = makeAddr("recipient");
    address other     = makeAddr("other");

    bytes32 constant MANIFEST = keccak256("manifest");
    uint64  constant SUPPLY   = 10;
    uint256 constant NOW      = 1_800_000_000;
    uint256 constant DEADLINE = NOW + 15 minutes;
    uint64  constant END_TS   = 1_800_604_800; // NOW + 7 days

    /// Written out rather than read from the contract, so the encoding clients
    /// build is pinned by an independent copy (same reasoning as `_expectedId`
    /// in WoCoTicketLedger.t.sol).
    bytes32 constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 constant TRANSFER_TYPEHASH =
        keccak256("TransferSlot(bytes32 eventId,uint256 slot,address from,address to,uint256 nonce,uint256 deadline)");

    function setUp() public {
        vm.warp(NOW);
        ledger = new WoCoTicketLedger(owner, sponsor);
    }

    function _registerAndClaim(WoCoTicketLedger l, address to)
        internal
        returns (bytes32 eventId, uint256 slot)
    {
        vm.prank(sponsor);
        eventId = l.registerEvent(organiser, SUPPLY, MANIFEST, END_TS);
        vm.prank(sponsor);
        slot = l.claimFor(eventId, to, keccak256("stripe-ref"));
    }

    function _claimToHolder() internal returns (bytes32 eventId, uint256 slot) {
        return _registerAndClaim(ledger, holder);
    }

    function _sign(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _digest(
        address verifyingContract,
        uint256 chainId,
        bytes32 eventId,
        uint256 slot,
        address from,
        address to,
        uint256 nonce,
        uint256 deadline
    ) internal pure returns (bytes32) {
        bytes32 domainSeparator = keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("WoCoTicketLedger"), keccak256("1"), chainId, verifyingContract)
        );
        bytes32 structHash = keccak256(abi.encode(TRANSFER_TYPEHASH, eventId, slot, from, to, nonce, deadline));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    /// The holder's signature for moving (eventId, slot) to `to`, over the
    /// independently built digest at the slot's current nonce.
    function _holderSigns(bytes32 eventId, uint256 slot, address to, uint256 deadline)
        internal
        view
        returns (bytes memory)
    {
        uint256 nonce = ledger.transferNonces(eventId, slot);
        return _sign(HOLDER_KEY, _digest(address(ledger), block.chainid, eventId, slot, holder, to, nonce, deadline));
    }

    // ── the happy path ────────────────────────────────────────────────────────

    function test_HolderSigns_RelayerSubmits_SlotMoves() public {
        (bytes32 eventId, uint256 slot) = _claimToHolder();
        bytes memory sig = _holderSigns(eventId, slot, recipient, DEADLINE);

        vm.expectEmit(true, true, true, true);
        emit WoCoTicketLedger.SlotTransferred(eventId, slot, holder, recipient);

        vm.prank(relayer);
        ledger.transferSlotWithSignature(eventId, slot, recipient, DEADLINE, sig);

        assertEq(ledger.slotOwner(eventId, slot), recipient, "slot did not move");
        assertEq(ledger.transferNonces(eventId, slot), 1, "a move must consume the nonce");
    }

    /// The production shape: the sponsor wallet submits. It pays; it gains nothing.
    function test_SponsorMaySubmitWhatTheHolderSigned() public {
        (bytes32 eventId, uint256 slot) = _claimToHolder();
        bytes memory sig = _holderSigns(eventId, slot, recipient, DEADLINE);

        vm.prank(sponsor);
        ledger.transferSlotWithSignature(eventId, slot, recipient, DEADLINE, sig);
        assertEq(ledger.slotOwner(eventId, slot), recipient);
    }

    // ── the encoding, pinned ─────────────────────────────────────────────────

    function test_Digest_MatchesIndependentEip712Encoding() public {
        (bytes32 eventId, uint256 slot) = _claimToHolder();
        assertEq(
            ledger.transferSlotDigest(eventId, slot, recipient, DEADLINE),
            _digest(address(ledger), block.chainid, eventId, slot, holder, recipient, 0, DEADLINE),
            "contract digest drifted from the EIP-712 encoding clients build"
        );
        assertEq(ledger.TRANSFER_SLOT_TYPEHASH(), TRANSFER_TYPEHASH, "typehash string changed");
    }

    function test_Eip712Domain_IsAdvertised() public view {
        (, string memory name, string memory version, uint256 chainId, address verifyingContract, , ) =
            ledger.eip712Domain();
        assertEq(name, "WoCoTicketLedger");
        assertEq(version, "1");
        assertEq(chainId, block.chainid);
        assertEq(verifyingContract, address(ledger));
    }

    // ── whoever submits cannot change what was signed ─────────────────────────

    function test_SubmitterCannotRedirect() public {
        (bytes32 eventId, uint256 slot) = _claimToHolder();
        bytes memory sig = _holderSigns(eventId, slot, recipient, DEADLINE);

        vm.prank(relayer);
        vm.expectRevert(WoCoTicketLedger.NotSlotOwner.selector);
        ledger.transferSlotWithSignature(eventId, slot, other, DEADLINE, sig);
        assertEq(ledger.slotOwner(eventId, slot), holder, "slot must be untouched");
    }

    function test_SubmitterCannotExtendDeadline() public {
        (bytes32 eventId, uint256 slot) = _claimToHolder();
        bytes memory sig = _holderSigns(eventId, slot, recipient, DEADLINE);

        vm.prank(relayer);
        vm.expectRevert(WoCoTicketLedger.NotSlotOwner.selector);
        ledger.transferSlotWithSignature(eventId, slot, recipient, DEADLINE + 1 days, sig);
    }

    function test_SubmitterCannotApplyItToAnotherSlot() public {
        (bytes32 eventId, uint256 slot) = _claimToHolder();
        vm.prank(sponsor);
        uint256 slot2 = ledger.claimFor(eventId, holder, keccak256("second-order"));
        bytes memory sig = _holderSigns(eventId, slot, recipient, DEADLINE);

        vm.prank(relayer);
        vm.expectRevert(WoCoTicketLedger.NotSlotOwner.selector);
        ledger.transferSlotWithSignature(eventId, slot2, recipient, DEADLINE, sig);
    }

    // ── only the current holder's signature counts ────────────────────────────

    function test_StrangerSignatureRejected() public {
        (bytes32 eventId, uint256 slot) = _claimToHolder();
        bytes memory sig = _sign(STRANGER_KEY, ledger.transferSlotDigest(eventId, slot, stranger, DEADLINE));

        vm.prank(stranger);
        vm.expectRevert(WoCoTicketLedger.NotSlotOwner.selector);
        ledger.transferSlotWithSignature(eventId, slot, stranger, DEADLINE, sig);
    }

    /// Authority follows the slot: once it has moved, the previous holder's
    /// key signs nothing that counts.
    function test_PreviousHolderCannotSignAfterMoving() public {
        (bytes32 eventId, uint256 slot) = _claimToHolder();
        vm.prank(holder);
        ledger.transferSlot(eventId, slot, recipient);

        bytes memory sig = _sign(HOLDER_KEY, ledger.transferSlotDigest(eventId, slot, other, DEADLINE));
        vm.prank(relayer);
        vm.expectRevert(WoCoTicketLedger.NotSlotOwner.selector);
        ledger.transferSlotWithSignature(eventId, slot, other, DEADLINE, sig);
    }

    // ── one use, and dead once the slot moves ────────────────────────────────

    function test_SignatureIsSingleUse() public {
        (bytes32 eventId, uint256 slot) = _claimToHolder();
        bytes memory sig = _holderSigns(eventId, slot, recipient, DEADLINE);

        vm.prank(relayer);
        ledger.transferSlotWithSignature(eventId, slot, recipient, DEADLINE, sig);

        vm.prank(relayer);
        vm.expectRevert(WoCoTicketLedger.NotSlotOwner.selector);
        ledger.transferSlotWithSignature(eventId, slot, recipient, DEADLINE, sig);
    }

    /// THE REASON THE NONCE EXISTS. After A→B→A the signed (from, to, deadline)
    /// is true again; only the consumed nonce stops B being handed the ticket a
    /// second time without A signing anything new.
    function test_RoundTripDoesNotReviveASpentSignature() public {
        (bytes32 eventId, uint256 slot) = _claimToHolder();
        bytes memory sig = _holderSigns(eventId, slot, recipient, DEADLINE);

        vm.prank(relayer);
        ledger.transferSlotWithSignature(eventId, slot, recipient, DEADLINE, sig);
        vm.prank(recipient);
        ledger.transferSlot(eventId, slot, holder);
        assertEq(ledger.slotOwner(eventId, slot), holder, "precondition: back with the holder");

        vm.prank(relayer);
        vm.expectRevert(WoCoTicketLedger.NotSlotOwner.selector);
        ledger.transferSlotWithSignature(eventId, slot, recipient, DEADLINE, sig);
    }

    /// A signature not yet submitted dies when the slot moves the OTHER way —
    /// `transferSlot` consumes the same nonce. The slot is brought back to the
    /// signer first, so `from` alone would not catch it.
    function test_HolderPathKillsAPendingSignature() public {
        (bytes32 eventId, uint256 slot) = _claimToHolder();
        bytes memory pending = _holderSigns(eventId, slot, recipient, DEADLINE);

        vm.prank(holder);
        ledger.transferSlot(eventId, slot, other);
        assertEq(ledger.transferNonces(eventId, slot), 1, "transferSlot must consume the nonce too");
        vm.prank(other);
        ledger.transferSlot(eventId, slot, holder);

        vm.prank(relayer);
        vm.expectRevert(WoCoTicketLedger.NotSlotOwner.selector);
        ledger.transferSlotWithSignature(eventId, slot, recipient, DEADLINE, pending);
    }

    /// The new holder can use the signature path in turn, at the nonce now on chain.
    function test_ChainedSignedMoves() public {
        uint256 nextKey = 0xC0FFEE;
        address nextHolder = vm.addr(nextKey);
        (bytes32 eventId, uint256 slot) = _claimToHolder();

        bytes memory first = _holderSigns(eventId, slot, nextHolder, DEADLINE);
        vm.prank(relayer);
        ledger.transferSlotWithSignature(eventId, slot, nextHolder, DEADLINE, first);

        bytes memory second =
            _sign(nextKey, _digest(address(ledger), block.chainid, eventId, slot, nextHolder, other, 1, DEADLINE));
        vm.prank(relayer);
        ledger.transferSlotWithSignature(eventId, slot, other, DEADLINE, second);

        assertEq(ledger.slotOwner(eventId, slot), other);
        assertEq(ledger.transferNonces(eventId, slot), 2);
    }

    // ── deadline ─────────────────────────────────────────────────────────────

    function test_ValidAtTheDeadlineSecond() public {
        (bytes32 eventId, uint256 slot) = _claimToHolder();
        bytes memory sig = _holderSigns(eventId, slot, recipient, DEADLINE);

        vm.warp(DEADLINE);
        vm.prank(relayer);
        ledger.transferSlotWithSignature(eventId, slot, recipient, DEADLINE, sig);
        assertEq(ledger.slotOwner(eventId, slot), recipient);
    }

    function test_RejectsAfterDeadline() public {
        (bytes32 eventId, uint256 slot) = _claimToHolder();
        bytes memory sig = _holderSigns(eventId, slot, recipient, DEADLINE);

        vm.warp(DEADLINE + 1);
        vm.prank(relayer);
        vm.expectRevert(WoCoTicketLedger.SignatureExpired.selector);
        ledger.transferSlotWithSignature(eventId, slot, recipient, DEADLINE, sig);
    }

    // ── bound to this chain and this deployment ──────────────────────────────

    function test_RejectsOnAnotherChain() public {
        (bytes32 eventId, uint256 slot) = _claimToHolder();
        bytes memory sig = _holderSigns(eventId, slot, recipient, DEADLINE);

        vm.chainId(block.chainid + 1);
        vm.prank(relayer);
        vm.expectRevert(WoCoTicketLedger.NotSlotOwner.selector);
        ledger.transferSlotWithSignature(eventId, slot, recipient, DEADLINE, sig);
    }

    /// Same chain, same (eventId, slot, holder, nonce, deadline) — only the
    /// verifying contract in the domain differs. The positive control at the end
    /// proves the refusal came from that difference and nothing else.
    function test_RejectsASignatureMadeForAnotherDeployment() public {
        WoCoTicketLedger ledger2 = new WoCoTicketLedger(owner, sponsor);
        (bytes32 eventId, uint256 slot) = _registerAndClaim(ledger2, holder);

        bytes memory wrongDomain = _sign(
            HOLDER_KEY, _digest(address(ledger), block.chainid, eventId, slot, holder, recipient, 0, DEADLINE)
        );
        vm.prank(relayer);
        vm.expectRevert(WoCoTicketLedger.NotSlotOwner.selector);
        ledger2.transferSlotWithSignature(eventId, slot, recipient, DEADLINE, wrongDomain);

        bytes memory rightDomain = _sign(
            HOLDER_KEY, _digest(address(ledger2), block.chainid, eventId, slot, holder, recipient, 0, DEADLINE)
        );
        vm.prank(relayer);
        ledger2.transferSlotWithSignature(eventId, slot, recipient, DEADLINE, rightDomain);
        assertEq(ledger2.slotOwner(eventId, slot), recipient, "positive control");
    }

    // ── shared guards, reached through the signature path ────────────────────

    function test_Guard_ZeroAddress() public {
        (bytes32 eventId, uint256 slot) = _claimToHolder();
        bytes memory sig = _holderSigns(eventId, slot, address(0), DEADLINE);

        vm.prank(relayer);
        vm.expectRevert(WoCoTicketLedger.ZeroAddress.selector);
        ledger.transferSlotWithSignature(eventId, slot, address(0), DEADLINE, sig);
        assertEq(ledger.slotOwner(eventId, slot), holder, "slot must be untouched");
    }

    /// An unclaimed slot's digest names `from = address(0)`. Any real key can sign
    /// it; it must be refused as unclaimed, never read as authority.
    function test_Guard_UnclaimedSlot() public {
        vm.prank(sponsor);
        bytes32 eventId = ledger.registerEvent(organiser, SUPPLY, MANIFEST, END_TS);
        bytes memory sig = _sign(HOLDER_KEY, ledger.transferSlotDigest(eventId, 0, recipient, DEADLINE));

        vm.prank(relayer);
        vm.expectRevert(WoCoTicketLedger.SlotUnclaimed.selector);
        ledger.transferSlotWithSignature(eventId, 0, recipient, DEADLINE, sig);
    }

    function test_Guard_SelfTransfer() public {
        (bytes32 eventId, uint256 slot) = _claimToHolder();
        bytes memory sig = _holderSigns(eventId, slot, holder, DEADLINE);

        vm.prank(relayer);
        vm.expectRevert(WoCoTicketLedger.TransferToSelf.selector);
        ledger.transferSlotWithSignature(eventId, slot, holder, DEADLINE, sig);
    }

    // ── malformed signatures ─────────────────────────────────────────────────

    function test_RejectsWrongLengthSignature() public {
        (bytes32 eventId, uint256 slot) = _claimToHolder();
        bytes memory sig = _holderSigns(eventId, slot, recipient, DEADLINE);
        bytes memory truncated = new bytes(64);
        for (uint256 i; i < 64; ++i) truncated[i] = sig[i];

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureLength.selector, 64));
        ledger.transferSlotWithSignature(eventId, slot, recipient, DEADLINE, truncated);
    }

    /// The holder's own signature in its malleable twin form (s' = n - s, v
    /// flipped). Raw `ecrecover` accepts it; the contract must not, or the same
    /// authorisation would exist under two distinct byte strings.
    function test_RejectsMalleableHighSSignature() public {
        (bytes32 eventId, uint256 slot) = _claimToHolder();
        bytes32 digest = _digest(address(ledger), block.chainid, eventId, slot, holder, recipient, 0, DEADLINE);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(HOLDER_KEY, digest);
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 highS = bytes32(n - uint256(s));
        uint8 flippedV = v == 27 ? 28 : 27;

        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureS.selector, highS));
        ledger.transferSlotWithSignature(eventId, slot, recipient, DEADLINE, abi.encodePacked(r, highS, flippedV));
    }

    // ── what the path does NOT restrict, same as transferSlot ─────────────────

    /// Cancellation and the sales cutoff govern CLAIMING, not ownership of a
    /// slot already claimed — on this path exactly as on `transferSlot`.
    function test_AllowedAfterCancellationAndEventEnd() public {
        (bytes32 eventId, uint256 slot) = _claimToHolder();
        vm.prank(organiser);
        ledger.cancelEvent(eventId);
        vm.warp(END_TS + 1);

        uint256 deadline = block.timestamp + 15 minutes;
        bytes memory sig = _holderSigns(eventId, slot, recipient, deadline);
        vm.prank(relayer);
        ledger.transferSlotWithSignature(eventId, slot, recipient, deadline, sig);
        assertEq(ledger.slotOwner(eventId, slot), recipient);
    }
}
