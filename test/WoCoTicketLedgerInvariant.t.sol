// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {WoCoTicketLedger} from "../src/WoCoTicketLedger.sol";

/**
 * Invariant tests for WoCoTicketLedger.
 *
 * These exist to test the guarantee the contract's natspec makes, rather than
 * individual guards: ALLOCATION is append-only (a slot, once handed out, is
 * never un-handed-out and `nextSlot` only grows), within stamped supply, and
 * stamped terms never move.
 *
 * OWNERSHIP is a separate matter and is NOT permanent: a slot's holder can move
 * it — by sending `transferSlot`, or by signing a move that anyone submits
 * through `transferSlotWithSignature`. What stays true — and what the campaign
 * proves — is that nothing BUT the holder's authority can: not a non-holder
 * caller, not a non-holder's signature, and not a signature already spent.
 * That is the sponsor-boundary guarantee the split exists for.
 *
 * The handler is an authorised sponsor AND the stamped organiser of half the
 * events it registers (a fixed address, `ORGANISER_B`, pranked, of the rest),
 * so it holds strictly MORE power than a real payments contract would — it can
 * cancel, which a sponsor cannot do on an event it did not register. If the
 * invariants hold for it, they hold for any sponsor.
 *
 * VERSION 2 adds moving parts, each with its own rule here: supply moves only
 * through `setSupply`, never below the slots minted and never above the
 * registered supply; the cutoff moves only later, only while open and at most
 * `MAX_SALES_EXTENSION` ahead of now; and a slot is re-pointed by `reissue`
 * only if it was minted bearer and no holder has moved it, in place (no slot
 * minted, no supply used), and never after `disableBearerMints`. Terms change
 * only on the ORGANISER's authority: its account or its current key, sending
 * the call or signing it for any submitter; never a stranger, a sponsor that
 * is not the organiser, a key it rotated away from, or a spent signature. The
 * key moves only by the organiser's account (`setOrganiserKey`). On a SEATED
 * event no seat is ever held by two tickets, the seat bitmap is exactly the
 * seats tickets hold, and a seat moves only on the organiser key's consent
 * (plus the holder's, through `reseat`).
 *
 * WHAT THIS CAMPAIGN DOES NOT COVER: the handler never calls
 * `forceCancelEvent`, `addSponsor`/`removeSponsor`, or `setDisputeAuthority`,
 * so these invariants say nothing about admin churn. Those paths are covered
 * by the unit suite instead. The signature ENCODINGS (domain, typehashes,
 * field order) are pinned by the unit suites, not here: the handler signs the
 * contract's own digest views exactly as the contract computes them.
 *
 * Kept in its own file because invariant campaigns are slow; the unit suites
 * run in milliseconds and stay the fast feedback loop.
 */
contract LedgerHandler is Test {
    WoCoTicketLedger internal ledger;

    bytes32[] public eventIds;

    /// Terms recorded at registration, and kept current through the two calls
    /// that may change them (`setSupply`, `extendSalesEnd`), to prove nothing
    /// else rewrites them.
    struct Stamped {
        uint64  totalSupply;
        uint64  eventEndTs;
        address organiser;
        bytes32 manifestRef;
        bool    seenCancelled;
        uint64  registeredSupply;
    }

    mapping(bytes32 => Stamped) public stamped;

    /// Slot owners observed at mint time, to prove slots are never rewritten.
    mapping(bytes32 => mapping(uint256 => address)) public seenSlotOwner;
    /// Coverage witnesses. Every handler action early-returns on unusable input,
    /// so "the flag stayed false" is only meaningful if attempts were actually
    /// made — without these the invariant passes vacuously.
    uint256 public transfersMade;
    uint256 public unauthorisedAttempts;
    uint256 public signedTransfersMade;
    uint256 public signedUnauthorisedAttempts;
    uint256 public replayAttempts;
    /// Replays made after the slot was handed BACK to its signer, before the
    /// deadline — so the consumed nonce is the only thing that can refuse them.
    uint256 public nonceOnlyReplays;
    /// Set if anything but the holder's authority ever moved a slot. Must stay false.
    bool public unauthorisedTransferSucceeded;
    mapping(bytes32 => uint256) public seenSlotCount;

    /// Keys the handler can sign with. The signature path can only be exercised
    /// on slots minted to these, so their (event, slot) pairs are kept rather
    /// than leaving the fuzzer to find one among the fuzzed owners.
    uint256[] internal actorKeys;
    mapping(address => uint256) internal keyOf;
    bytes32[] internal actorSlotEvent;
    uint256[] internal actorSlotIndex;

    /// The last signature that moved a slot, kept to replay.
    struct SpentSignature {
        bytes32 eventId;
        uint256 slot;
        address from;
        address to;
        uint256 deadline;
        bytes   sig;
    }

    SpentSignature internal lastSpent;
    bool internal hasSpent;

    // ── version 2 ─────────────────────────────────────────────────────────────

    address internal ledgerOwner;
    mapping(bytes32 => mapping(uint256 => bool)) public seenBearer;
    /// A slot its holder has moved at least once: out of `reissue`'s reach.
    mapping(bytes32 => mapping(uint256 => bool)) public seenMoved;
    bytes32[] internal bearerSlotEvent;
    uint256[] internal bearerSlotIndex;

    uint256 public reissuesMade;
    uint256 public ineligibleReissueAttempts;
    uint256 public supplySets;
    uint256 public cutoffExtensions;
    bool public bearerMintsSeenDisabled;
    /// Set if a reissue or bearer mint landed that the rules forbid: a
    /// non-bearer or moved slot re-pointed, or either after the off switch.
    bool public forbiddenReissue;
    /// Set if a reissue minted a slot (moved `nextSlot`).
    bool public reissueUsedASeat;
    /// Set if the cutoff ever moved earlier.
    bool public cutoffMovedEarlier;
    /// Attempts at terms version 2 forbids (audit 1059): supply above the
    /// registered supply, a cutoff past `MAX_SALES_EXTENSION`, extending a
    /// cutoff that has passed. Each flag is set if one ever landed.
    uint256 public aboveRegisteredAttempts;
    uint256 public tooFarAttempts;
    uint256 public lapsedExtendAttempts;
    bool public supplyAboveRegisteredLanded;
    bool public cutoffTooFarLanded;
    bool public lapsedCutoffExtended;

    // ── the organiser's authority ──────────────────────────────────────────────

    /// The organiser of every event whose organiser is not the handler.
    address internal constant ORGANISER_B = address(0x0B0B);
    /// Organiser keys the handler can sign with; events start on one and
    /// rotate among them (`rotateKey`).
    uint256[] internal orgKeys;

    /// The organiser key each event must have: set at registration, moved
    /// only by `rotateKey` when the organiser's `setOrganiserKey` lands.
    mapping(bytes32 => address) public expectedKey;
    /// A key the event's key rotated away from, kept to prove it lost its power.
    mapping(bytes32 => uint256) internal retiredKey;
    bytes32[] internal rotatedEvents;

    uint256 public signedTermsMade;
    uint256 public directKeyTermsMade;
    uint256 public keyRotations;
    uint256 public unauthorisedTermsAttempts;
    uint256 public retiredKeyAttempts;
    uint256 public termsReplayAttempts;
    uint256 public outsiderKeyMoveAttempts;
    /// Set if a terms write landed without the organiser's authority: a
    /// stranger, a non-organiser sponsor, a retired key, a spent signature.
    bool public unauthorisedTermsLanded;
    /// Set if anyone but the organiser's account moved its key.
    bool public keyMovedByOutsider;

    /// The last signed `setSupply`, kept to replay.
    struct SpentTerms {
        bytes32 eventId;
        uint64  supply;
        uint256 deadline;
        bytes   sig;
    }

    SpentTerms internal lastSpentTerms;
    bool internal hasSpentTerms;

    // ── seats ─────────────────────────────────────────────────────────────────

    bytes32[] public seatedIds;
    mapping(bytes32 => bool) public seated;
    /// Seat + 1 per slot as the handler saw it land; 0 = no seat.
    mapping(bytes32 => mapping(uint256 => uint256)) public seenSeat;
    /// Seated slots minted to an actor key, so `reseat` has holders that sign.
    bytes32[] internal actorSeatEvent;
    uint256[] internal actorSeatSlot;

    uint256 public seatMints;
    uint256 public takenSeatAttempts;
    uint256 public bearerReseats;
    uint256 public holderReseats;
    uint256 public unauthorisedReseatAttempts;
    uint256 public kindMismatchAttempts;
    /// Set if a mint landed on a seat a ticket held, a seat moved without the
    /// organiser key (and, for a held slot, the holder), or a mint path
    /// landed on the other kind of event.
    bool public seatRuleBroken;

    constructor(WoCoTicketLedger _ledger, address _ledgerOwner) {
        ledger = _ledger;
        ledgerOwner = _ledgerOwner;
        for (uint256 k = 0xA1; k <= 0xA4; ++k) {
            actorKeys.push(k);
            keyOf[vm.addr(k)] = k;
        }
        for (uint256 k = 0xB1; k <= 0xB3; ++k) {
            orgKeys.push(k);
            keyOf[vm.addr(k)] = k;
        }
    }

    function eventCount() external view returns (uint256) {
        return eventIds.length;
    }

    function registerEvent(uint256 supply, bytes32 manifestRef, uint256 endOffset) external {
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 supply64 = uint64(bound(supply, 1, 500));
        if (manifestRef == bytes32(0)) manifestRef = bytes32(uint256(1));
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 endTs = uint64(block.timestamp + bound(endOffset, 1, 365 days));

        // Handler is its own organiser on half, so it can exercise cancelEvent
        // without a prank; `ORGANISER_B` is the organiser of the other half.
        // Bit 1 picks a seated registration, so both kinds share every action.
        address organiser = uint256(manifestRef) & 1 == 0 ? address(this) : ORGANISER_B;
        address key = vm.addr(orgKeys[uint256(manifestRef) % orgKeys.length]);
        bool asSeated = uint256(manifestRef) & 2 != 0;
        bytes32 id = asSeated
            ? ledger.registerSeatedEvent(organiser, key, supply64, manifestRef, endTs)
            : ledger.registerEvent(organiser, key, supply64, manifestRef, endTs);
        _track(id, supply64, endTs, organiser, manifestRef, key, asSeated);
    }

    function _track(
        bytes32 id,
        uint64 supply,
        uint64 endTs,
        address organiser,
        bytes32 manifestRef,
        address key,
        bool asSeated
    ) internal {
        eventIds.push(id);
        stamped[id] = Stamped({
            totalSupply:   supply,
            eventEndTs:    endTs,
            organiser:     organiser,
            manifestRef:   manifestRef,
            seenCancelled: false,
            registeredSupply: supply
        });
        expectedKey[id] = key;
        if (asSeated) {
            seated[id] = true;
            seatedIds.push(id);
        }
    }

    /// A fresh open GA event the handler registers, named for `organiser`.
    function _registerFresh(address organiser) internal returns (bytes32 id) {
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 freshEnd = uint64(block.timestamp + 30 days);
        bytes32 manifest = bytes32(uint256(7));
        address key = vm.addr(orgKeys[0]);
        id = ledger.registerEvent(organiser, key, 100, manifest, freshEnd);
        _track(id, 100, freshEnd, organiser, manifest, key, false);
    }

    /// A fresh open SEATED event, organised by the handler.
    function _registerFreshSeated() internal returns (bytes32 id) {
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 freshEnd = uint64(block.timestamp + 30 days);
        bytes32 manifest = bytes32(uint256(11));
        address key = vm.addr(orgKeys[1]);
        id = ledger.registerSeatedEvent(address(this), key, 300, manifest, freshEnd);
        _track(id, 300, freshEnd, address(this), manifest, key, true);
    }

    function claimFor(uint256 eventIndex, address owner, bytes32 orderRef) external {
        if (eventIds.length == 0) return;
        bytes32 id = eventIds[bound(eventIndex, 0, eventIds.length - 1)];
        if (owner == address(0)) owner = address(0x1);

        try ledger.claimFor(id, owner, orderRef) returns (uint256 slot) {
            if (seated[id]) seatRuleBroken = true;
            _recordSlot(id, slot, owner);
        } catch {
            // Reverts are expected (sold out, cancelled, past cutoff) and are
            // themselves the property under test — the invariants below assert
            // that no state moved.
        }
    }

    /// Mint to a key the handler holds, so the signature path has slots to act on.
    function claimForActor(uint256 eventIndex, uint256 actorSeed, bytes32 orderRef) external {
        if (eventIds.length == 0) return;
        bytes32 id = eventIds[bound(eventIndex, 0, eventIds.length - 1)];
        address actor = vm.addr(actorKeys[bound(actorSeed, 0, actorKeys.length - 1)]);

        try ledger.claimFor(id, actor, orderRef) returns (uint256 slot) {
            if (seated[id]) seatRuleBroken = true;
            _recordSlot(id, slot, actor);
            actorSlotEvent.push(id);
            actorSlotIndex.push(slot);
        } catch {
            // See claimFor.
        }
    }

    function batchClaimFor(uint256 eventIndex, uint256 n, address owner, bytes32 orderRef) external {
        if (eventIds.length == 0) return;
        bytes32 id = eventIds[bound(eventIndex, 0, eventIds.length - 1)];
        uint256 count = bound(n, 1, 100);
        if (owner == address(0)) owner = address(0x1);

        address[] memory owners = new address[](count);
        for (uint256 i; i < count; ++i) owners[i] = owner;

        try ledger.batchClaimFor(id, owners, orderRef) returns (uint256 first) {
            if (seated[id]) seatRuleBroken = true;
            for (uint256 i; i < count; ++i) _recordSlot(id, first + i, owner);
        } catch {
            // See claimFor.
        }
    }

    /// Move a slot, pranking as its current owner — the only caller the
    /// contract accepts. Ownership is tracked through the move so the invariant
    /// asserts "changed only by its owner", not "never changed".
    function transferSlot(uint256 eventIndex, uint256 slotSeed, address newOwner) external {
        if (eventIds.length == 0) return;
        (bytes32 id, uint256 slot) = _claimedSlot(eventIndex, slotSeed);
        if (slot == type(uint256).max) return;
        address current = seenSlotOwner[id][slot];
        if (newOwner == address(0) || newOwner == current) return;

        vm.prank(current);
        try ledger.transferSlot(id, slot, newOwner) {
            seenSlotOwner[id][slot] = newOwner;
            seenMoved[id][slot] = true;
            transfersMade++;
        } catch {
            // See claimFor.
        }
    }

    /// A transfer attempted by someone who is NOT the holder. Must always
    /// revert; the invariant's job is to prove no state moved when it did.
    function transferSlotUnauthorised(uint256 eventIndex, uint256 slotSeed, address caller) external {
        if (eventIds.length == 0) return;
        (bytes32 id, uint256 slot) = _claimedSlot(eventIndex, slotSeed);
        if (slot == type(uint256).max) return;
        address current = seenSlotOwner[id][slot];
        if (caller == current || caller == address(0)) return;

        unauthorisedAttempts++;
        vm.prank(caller);
        try ledger.transferSlot(id, slot, caller) {
            // A success here is the failure: it means someone who does not hold
            // the slot moved it. Recorded so the invariant reports it.
            unauthorisedTransferSucceeded = true;
        } catch {}
    }

    /// A move the current holder SIGNED, handed in by an arbitrary submitter.
    function transferSlotSigned(uint256 pick, uint256 toSeed, address submitter) external {
        uint256 n = actorSlotEvent.length;
        if (n == 0) return;
        uint256 i = bound(pick, 0, n - 1);
        bytes32 id = actorSlotEvent[i];
        uint256 slot = actorSlotIndex[i];

        address current = seenSlotOwner[id][slot];
        uint256 key = keyOf[current];
        if (key == 0) return; // moved to a fuzzed owner by the holder path
        address to = vm.addr(actorKeys[bound(toSeed, 0, actorKeys.length - 1)]);
        if (to == current) return;
        if (submitter == address(0)) submitter = address(0xCAFE);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(key, ledger.transferSlotDigest(id, slot, to, deadline));

        vm.prank(submitter);
        try ledger.transferSlotWithSignature(id, slot, to, deadline, sig) {
            seenSlotOwner[id][slot] = to;
            seenMoved[id][slot] = true;
            signedTransfersMade++;
            lastSpent = SpentSignature({eventId: id, slot: slot, from: current, to: to, deadline: deadline, sig: sig});
            hasSpent = true;
        } catch {
            // See claimFor.
        }
    }

    /// A signature from a key that does NOT hold the slot, naming itself as
    /// recipient. Must always revert.
    function transferSlotSignedUnauthorised(uint256 pick, uint256 signerSeed, address submitter) external {
        uint256 n = actorSlotEvent.length;
        if (n == 0) return;
        uint256 i = bound(pick, 0, n - 1);
        bytes32 id = actorSlotEvent[i];
        uint256 slot = actorSlotIndex[i];

        address current = seenSlotOwner[id][slot];
        uint256 key = actorKeys[bound(signerSeed, 0, actorKeys.length - 1)];
        address signer = vm.addr(key);
        if (current == address(0) || signer == current) return;
        if (submitter == address(0)) submitter = address(0xCAFE);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(key, ledger.transferSlotDigest(id, slot, signer, deadline));

        signedUnauthorisedAttempts++;
        vm.prank(submitter);
        try ledger.transferSlotWithSignature(id, slot, signer, deadline, sig) {
            unauthorisedTransferSucceeded = true;
        } catch {}
    }

    /// Hand in again the last signature that already moved a slot. The nonce it
    /// committed to has been consumed, so it must never land a second time.
    function replaySpentSignature(address submitter) external {
        if (!hasSpent) return;
        if (submitter == address(0)) submitter = address(0xCAFE);
        SpentSignature memory s = lastSpent;

        replayAttempts++;
        vm.prank(submitter);
        try ledger.transferSlotWithSignature(s.eventId, s.slot, s.to, s.deadline, s.sig) {
            unauthorisedTransferSucceeded = true;
        } catch {}
    }

    /// The replay that isolates the nonce. `replaySpentSignature` is mostly refused
    /// because the slot's owner has changed, which says nothing about the nonce.
    /// Here a fresh signed move is spent, the recipient hands the slot BACK to the
    /// signer through the holder path, and the spent signature is handed in again
    /// inside its deadline — so it differs from a valid one ONLY in its consumed nonce.
    ///
    /// The whole sequence runs in this one call (WoCo-Contracts #18). Built from
    /// `lastSpent`, it needed a signed move whose 1-hour deadline and slot both
    /// survived until this action was picked, while `warp` jumps up to 30 days — and
    /// some seeds never got one in 64 runs, failing the coverage check in afterInvariant.
    function replayAfterRoundTrip(uint256 pick, uint256 toSeed, address submitter) external {
        uint256 n = actorSlotEvent.length;
        if (n == 0) return;
        uint256 i = bound(pick, 0, n - 1);
        bytes32 id = actorSlotEvent[i];
        uint256 slot = actorSlotIndex[i];

        address from = seenSlotOwner[id][slot];
        uint256 key = keyOf[from];
        // Moved to a fuzzed owner by the holder path: mint a fresh actor slot
        // in this same call, so the witness never starves as the action list grows.
        if (key == 0) {
            id = _openGaEvent(pick);
            key = actorKeys[bound(toSeed, 0, actorKeys.length - 1)];
            from = vm.addr(key);
            try ledger.claimFor(id, from, bytes32(uint256(19))) returns (uint256 s) {
                _recordSlot(id, s, from);
                actorSlotEvent.push(id);
                actorSlotIndex.push(s);
                slot = s;
            } catch {
                return;
            }
        }
        uint256 t = bound(toSeed, 0, actorKeys.length - 1);
        address to = vm.addr(actorKeys[t]);
        if (to == from) to = vm.addr(actorKeys[(t + 1) % actorKeys.length]);
        if (submitter == address(0)) submitter = address(0xCAFE);

        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(key, ledger.transferSlotDigest(id, slot, to, deadline));

        vm.prank(submitter);
        try ledger.transferSlotWithSignature(id, slot, to, deadline, sig) {
            seenSlotOwner[id][slot] = to;
            seenMoved[id][slot] = true;
            signedTransfersMade++;
        } catch {
            return;
        }

        vm.prank(to);
        try ledger.transferSlot(id, slot, from) {
            seenSlotOwner[id][slot] = from;
            transfersMade++;
        } catch {
            return;
        }

        nonceOnlyReplays++;
        vm.prank(submitter);
        try ledger.transferSlotWithSignature(id, slot, to, deadline, sig) {
            unauthorisedTransferSucceeded = true;
        } catch {}
    }

    // ── version 2 actions ─────────────────────────────────────────────────────

    function batchClaimBearer(uint256 eventIndex, uint256 n, address owner, bytes32 orderRef) external {
        if (eventIds.length == 0) return;
        bytes32 id = eventIds[bound(eventIndex, 0, eventIds.length - 1)];
        uint256 count = bound(n, 1, 100);
        if (owner == address(0)) owner = address(0x1);

        address[] memory owners = new address[](count);
        for (uint256 i; i < count; ++i) owners[i] = owner;

        try ledger.batchClaimBearer(id, owners, orderRef) returns (uint256 first) {
            if (bearerMintsSeenDisabled) forbiddenReissue = true;
            if (seated[id]) seatRuleBroken = true;
            for (uint256 i; i < count; ++i) _recordBearer(id, first + i, owner);
        } catch {
            // See claimFor.
        }
    }

    /// Reissue one bearer slot. The pick must be reissuable NOW (not moved, its
    /// event still on sale); when it is not, a bearer slot is minted on an open
    /// event first, in this same call, so the campaign never starves of
    /// reissues once warps and cancels have closed the early events (the #18
    /// lesson: a precondition built by other random actions may never exist).
    function reissue(uint256 eventIndex, uint256 pick, address newOwner) external {
        if (eventIds.length == 0) return;
        bytes32 id;
        uint256 slot;
        bool found;
        if (bearerSlotEvent.length > 0) {
            uint256 i = bound(pick, 0, bearerSlotEvent.length - 1);
            id = bearerSlotEvent[i];
            slot = bearerSlotIndex[i];
            (uint64 endTs, bool cancelled) = ledger.getEventStatus(id);
            found = !seenMoved[id][slot] && !cancelled && block.timestamp < endTs;
        }
        if (!found) {
            id = _openGaEvent(eventIndex);
            address[] memory one = new address[](1);
            one[0] = address(0x3);
            try ledger.batchClaimBearer(id, one, bytes32(uint256(5))) returns (uint256 first) {
                if (bearerMintsSeenDisabled) forbiddenReissue = true;
                _recordBearer(id, first, address(0x3));
                slot = first;
            } catch {
                return;
            }
        }

        address current = seenSlotOwner[id][slot];
        if (newOwner == address(0) || newOwner == address(ledger)) newOwner = address(0x2);
        if (newOwner == current) newOwner = current == address(0x4) ? address(0x5) : address(0x4);

        (, uint64 nextBefore, , ) = ledger.getEvent(id);
        uint256[] memory slots = new uint256[](1);
        slots[0] = slot;
        address[] memory owners = new address[](1);
        owners[0] = newOwner;
        try ledger.reissue(id, slots, owners) {
            if (bearerMintsSeenDisabled || seenMoved[id][slot] || !seenBearer[id][slot]) forbiddenReissue = true;
            (, uint64 nextAfter, , ) = ledger.getEvent(id);
            if (nextAfter != nextBefore) reissueUsedASeat = true;
            seenSlotOwner[id][slot] = newOwner;
            reissuesMade++;
        } catch {
            // See claimFor.
        }
    }

    /// Reissue a slot the rules put out of reach: minted non-bearer, moved by
    /// its holder, or anything after the off switch. Must always revert. When
    /// the pick is not out of reach, a non-bearer slot is minted on an open
    /// event in this same call, so the witness never starves (seed 0x1 did).
    function reissueIneligible(uint256 eventIndex, uint256 slotSeed, address newOwner) external {
        if (eventIds.length == 0) return;
        bytes32 id = eventIds[bound(eventIndex, 0, eventIds.length - 1)];
        uint256 count = seenSlotCount[id];
        uint256 slot;
        bool eligible = true;
        if (count > 0) {
            slot = bound(slotSeed, 0, count - 1);
            eligible = seenBearer[id][slot] && !seenMoved[id][slot] && !bearerMintsSeenDisabled;
        }
        if (eligible) {
            id = _openGaEvent(eventIndex);
            try ledger.claimFor(id, address(0x3), bytes32(uint256(6))) returns (uint256 s) {
                _recordSlot(id, s, address(0x3));
                slot = s;
            } catch {
                return;
            }
        }
        if (newOwner == address(0)) newOwner = address(0x2);

        uint256[] memory slots = new uint256[](1);
        slots[0] = slot;
        address[] memory owners = new address[](1);
        owners[0] = newOwner;
        ineligibleReissueAttempts++;
        try ledger.reissue(id, slots, owners) {
            forbiddenReissue = true;
        } catch {}
    }

    /// A supply the event can take now, or 0 if none differs from the current.
    function _nextSupply(bytes32 id, uint256 supplySeed) internal view returns (uint64 supply) {
        (uint64 current, uint64 minted, , ) = ledger.getEvent(id);
        uint64 floor = minted == 0 ? 1 : minted;
        uint64 ceiling = stamped[id].registeredSupply;
        // forge-lint: disable-next-line(unsafe-typecast)
        supply = uint64(bound(supplySeed, floor, ceiling));
        if (supply == current) {
            if (current < ceiling) supply = current + 1;
            else if (current > floor) supply = current - 1;
            else return 0;
        }
    }

    /// On the organiser's authority, by one of its three roads picked by
    /// `road`: its account sending the call, its key sending it, or its key's
    /// signature handed in by any submitter.
    function setSupply(uint256 eventIndex, uint256 supplySeed, uint256 road, address submitter) external {
        if (eventIds.length == 0) return;
        bytes32 id = _openEvent(eventIndex);
        uint64 supply = _nextSupply(id, supplySeed);
        if (supply == 0) return;
        uint256 r = road % 3;
        bool landed;
        if (r == 2) {
            uint256 deadline = block.timestamp + 1 hours;
            bytes memory sig = _sign(keyOf[expectedKey[id]], ledger.setSupplyDigest(id, supply, deadline));
            if (submitter == address(0)) submitter = address(0xCAFE);
            vm.prank(submitter);
            try ledger.setSupplyWithSignature(id, supply, deadline, sig) {
                landed = true;
                signedTermsMade++;
                lastSpentTerms = SpentTerms({eventId: id, supply: supply, deadline: deadline, sig: sig});
                hasSpentTerms = true;
            } catch {}
        } else {
            vm.prank(r == 0 ? stamped[id].organiser : expectedKey[id]);
            try ledger.setSupply(id, supply) {
                landed = true;
                if (r == 1) directKeyTermsMade++;
            } catch {}
        }
        if (landed) {
            stamped[id].totalSupply = supply;
            supplySets++;
        }
    }

    /// As `setSupply`: the account or the key directly, or the key's signature.
    function extendSalesEnd(uint256 eventIndex, uint256 offset, uint256 road, address submitter) external {
        if (eventIds.length == 0) return;
        bytes32 id = _openEvent(eventIndex);
        // `_openEvent` returns an event whose cutoff is still ahead.
        (uint64 endTs, ) = ledger.getEventStatus(id);
        uint256 limit = block.timestamp + ledger.MAX_SALES_EXTENSION();
        if (limit <= endTs) return;
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 newEnd = uint64(endTs + bound(offset, 1, limit - endTs));
        uint256 r = road % 3;
        bool landed;
        if (r == 2) {
            uint256 deadline = block.timestamp + 1 hours;
            bytes memory sig = _sign(keyOf[expectedKey[id]], ledger.extendSalesEndDigest(id, newEnd, deadline));
            if (submitter == address(0)) submitter = address(0xCAFE);
            vm.prank(submitter);
            try ledger.extendSalesEndWithSignature(id, newEnd, deadline, sig) {
                landed = true;
                signedTermsMade++;
            } catch {}
        } else {
            vm.prank(r == 0 ? stamped[id].organiser : expectedKey[id]);
            try ledger.extendSalesEnd(id, newEnd) {
                landed = true;
                if (r == 1) directKeyTermsMade++;
            } catch {}
        }
        if (landed) {
            if (newEnd <= stamped[id].eventEndTs) cutoffMovedEarlier = true;
            stamped[id].eventEndTs = newEnd;
            cutoffExtensions++;
        }
    }

    /// Terms attempted WITHOUT the organiser's authority: a stranger or a
    /// sponsor sending it, a signature from a key that is not the event's, or
    /// a signature from a key it rotated away from. Must always revert.
    function termsUnauthorised(uint256 eventIndex, uint256 supplySeed, uint256 road, address caller) external {
        if (eventIds.length == 0) return;
        bytes32 id = _openEvent(eventIndex);
        uint64 supply = _nextSupply(id, supplySeed);
        if (supply == 0) return;
        uint256 r = road % 3;
        if (r == 0) {
            if (caller == stamped[id].organiser || caller == expectedKey[id]) caller = address(0xBAD);
            unauthorisedTermsAttempts++;
            vm.prank(caller);
            try ledger.setSupply(id, supply) {
                unauthorisedTermsLanded = true;
            } catch {}
            // The handler is a sponsor: being one is no authority either.
            if (stamped[id].organiser != address(this)) {
                unauthorisedTermsAttempts++;
                try ledger.cancelEvent(id) {
                    unauthorisedTermsLanded = true;
                } catch {}
            }
        } else {
            // An actor key: never an organiser key here.
            uint256 wrong = actorKeys[bound(supplySeed, 0, actorKeys.length - 1)];
            unauthorisedTermsAttempts++;
            uint256 deadline = block.timestamp + 1 hours;
            bytes memory sig = _sign(wrong, ledger.setSupplyDigest(id, supply, deadline));
            vm.prank(caller == address(0) ? address(0xCAFE) : caller);
            try ledger.setSupplyWithSignature(id, supply, deadline, sig) {
                unauthorisedTermsLanded = true;
            } catch {}
        }
    }

    /// A signature from a key the event's key was rotated away from: from a
    /// rotated event still open, else one rotated in this same call. Must
    /// always revert.
    function termsByRetiredKey(uint256 pick, uint256 supplySeed, address submitter) external {
        bytes32 id;
        bool found;
        if (rotatedEvents.length > 0) {
            id = rotatedEvents[bound(pick, 0, rotatedEvents.length - 1)];
            (uint64 endTs, bool cancelled) = ledger.getEventStatus(id);
            found = !cancelled && block.timestamp < endTs && vm.addr(retiredKey[id]) != expectedKey[id]
                && _nextSupply(id, supplySeed) != 0;
        }
        if (!found) {
            id = _registerFresh(address(this));
            bytes32[] memory ids = new bytes32[](1);
            ids[0] = id;
            address next = vm.addr(orgKeys[2]);
            ledger.setOrganiserKey(ids, next);
            retiredKey[id] = keyOf[expectedKey[id]];
            rotatedEvents.push(id);
            expectedKey[id] = next;
            keyRotations++;
        }
        uint64 supply = _nextSupply(id, supplySeed);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _sign(retiredKey[id], ledger.setSupplyDigest(id, supply, deadline));
        retiredKeyAttempts++;
        vm.prank(submitter == address(0) ? address(0xCAFE) : submitter);
        try ledger.setSupplyWithSignature(id, supply, deadline, sig) {
            unauthorisedTermsLanded = true;
        } catch {}
    }

    /// Hand in again the last signed `setSupply`. Its nonce is consumed, so it
    /// must never land twice, even once the supply is back where it signed for.
    function replaySpentTerms(address submitter) external {
        SpentTerms memory s = lastSpentTerms;
        bool live;
        if (hasSpentTerms) {
            (uint64 endTs, bool cancelled) = ledger.getEventStatus(s.eventId);
            live = block.timestamp <= s.deadline && !cancelled && block.timestamp < endTs;
        }
        // No live spent signature: spend one in this same call.
        if (!live) {
            bytes32 fresh = _registerFresh(address(this));
            uint64 target = _nextSupply(fresh, 50);
            uint256 deadline = block.timestamp + 1 hours;
            bytes memory sig = _sign(keyOf[expectedKey[fresh]], ledger.setSupplyDigest(fresh, target, deadline));
            try ledger.setSupplyWithSignature(fresh, target, deadline, sig) {
                stamped[fresh].totalSupply = target;
                supplySets++;
                signedTermsMade++;
            } catch {
                return;
            }
            s = SpentTerms({eventId: fresh, supply: target, deadline: deadline, sig: sig});
            lastSpentTerms = s;
            hasSpentTerms = true;
        }
        (uint64 current, , , ) = ledger.getEvent(s.eventId);
        // Restore a different supply first, so a refusal can only be the nonce.
        if (current == s.supply) {
            uint64 other = _nextSupply(s.eventId, uint256(s.supply) + 1);
            if (other == 0) return;
            vm.prank(stamped[s.eventId].organiser);
            try ledger.setSupply(s.eventId, other) {
                stamped[s.eventId].totalSupply = other;
                supplySets++;
            } catch {
                return;
            }
        }
        termsReplayAttempts++;
        vm.prank(submitter == address(0) ? address(0xCAFE) : submitter);
        try ledger.setSupplyWithSignature(s.eventId, s.supply, s.deadline, s.sig) {
            unauthorisedTermsLanded = true;
        } catch {}
    }

    /// The organiser's account moves the key to another organiser key. The
    /// key it leaves is kept, to prove it loses every power.
    function rotateKey(uint256 eventIndex, uint256 keySeed) external {
        if (eventIds.length == 0) return;
        bytes32 id = eventIds[bound(eventIndex, 0, eventIds.length - 1)];
        address current = expectedKey[id];
        uint256 k = bound(keySeed, 0, orgKeys.length - 1);
        address next = vm.addr(orgKeys[k]);
        if (next == current) next = vm.addr(orgKeys[(k + 1) % orgKeys.length]);

        bytes32[] memory ids = new bytes32[](1);
        ids[0] = id;
        vm.prank(stamped[id].organiser);
        try ledger.setOrganiserKey(ids, next) {
            retiredKey[id] = keyOf[current];
            rotatedEvents.push(id);
            expectedKey[id] = next;
            keyRotations++;
        } catch {}
    }

    /// The key moved by anyone but the organiser's account: the key itself, a
    /// stranger, the handler on an event it does not organise. Must revert.
    function rotateKeyUnauthorised(uint256 eventIndex, address caller) external {
        if (eventIds.length == 0) return;
        bytes32 id = eventIds[bound(eventIndex, 0, eventIds.length - 1)];
        if (caller == stamped[id].organiser) caller = expectedKey[id];
        bytes32[] memory ids = new bytes32[](1);
        ids[0] = id;
        outsiderKeyMoveAttempts++;
        vm.prank(caller);
        try ledger.setOrganiserKey(ids, address(0xF00D)) {
            keyMovedByOutsider = true;
        } catch {}
    }

    // ── seats ─────────────────────────────────────────────────────────────────

    /// A seated event still on sale: the picked one if so, else a fresh one.
    function _openSeated(uint256 pick) internal returns (bytes32 id) {
        uint256 n = seatedIds.length;
        if (n > 0) {
            id = seatedIds[bound(pick, 0, n - 1)];
            (uint64 endTs, bool cancelled) = ledger.getEventStatus(id);
            (uint64 supply, uint64 minted, , ) = ledger.getEvent(id);
            if (!cancelled && block.timestamp < endTs && minted < supply) return id;
        }
        id = _registerFreshSeated();
    }

    /// A free seat at or after `seed`, or `type(uint256).max` if all are held.
    /// Reads each bitmap word once: a seated event here has at most two.
    function _freeSeat(bytes32 id, uint256 seed) internal view returns (uint256) {
        uint256 total = stamped[id].registeredSupply;
        uint256[2] memory words = [ledger.seatWord(id, 0), total > 256 ? ledger.seatWord(id, 1) : 0];
        uint256 start = bound(seed, 0, total - 1);
        for (uint256 k; k < total; ++k) {
            uint256 s = (start + k) % total;
            if (words[s >> 8] & (uint256(1) << (s & 255)) == 0) return s;
        }
        return type(uint256).max;
    }

    /// Mint `n` seated slots into free seats, bearer or not, to `owner` or to
    /// an actor key (so `reseat` has holders that sign).
    function claimSeats(uint256 pick, uint256 n, uint256 seatSeed, uint256 actorSeed, bool bearer) external {
        bytes32 id = _openSeated(pick);
        (uint64 supply, uint64 minted, , ) = ledger.getEvent(id);
        uint256 count = bound(n, 1, 5);
        if (minted + count > supply) count = supply - minted;
        if (count == 0) return;

        address[] memory owners = new address[](count);
        uint256[] memory seats = new uint256[](count);
        address owner = vm.addr(actorKeys[bound(actorSeed, 0, actorKeys.length - 1)]);
        uint256 seed = seatSeed;
        for (uint256 i; i < count; ++i) {
            owners[i] = owner;
            uint256 s = _freeSeat(id, seed);
            if (s == type(uint256).max) return;
            // Seats already chosen in this batch are not yet set on chain.
            for (uint256 j; j < i; ++j) if (seats[j] == s) s = _freeSeat(id, s + 1);
            if (s == type(uint256).max) return;
            seats[i] = s;
            seed = s + 7;
        }
        // A duplicate inside the batch the free-seat walk could not avoid is
        // left in: the mint must refuse it.
        bool landed;
        uint256 first;
        if (bearer && !bearerMintsSeenDisabled) {
            try ledger.batchClaimSeatsBearer(id, owners, seats, bytes32(uint256(12))) returns (uint256 f) {
                landed = true;
                first = f;
            } catch {}
        } else {
            bearer = false;
            try ledger.batchClaimSeats(id, owners, seats, bytes32(uint256(13))) returns (uint256 f) {
                landed = true;
                first = f;
            } catch {}
        }
        if (!landed) return;
        for (uint256 i; i < count; ++i) {
            uint256 slot = first + i;
            if (bearer) _recordBearer(id, slot, owner);
            else _recordSlot(id, slot, owner);
            seenSeat[id][slot] = seats[i] + 1;
            actorSeatEvent.push(id);
            actorSeatSlot.push(slot);
        }
        seatMints++;
    }

    /// Every general-admission mint path on an open seated event. Must always
    /// revert: a seated event never has a seatless ticket.
    function gaMintOnSeated(uint256 pick, uint256 road) external {
        bytes32 id = _openSeated(pick);
        address[] memory one = new address[](1);
        one[0] = address(0x3);
        kindMismatchAttempts++;
        uint256 r = road % 3;
        if (r == 0) {
            try ledger.claimFor(id, address(0x3), bytes32(uint256(18))) {
                seatRuleBroken = true;
            } catch {}
        } else if (r == 1) {
            try ledger.batchClaimFor(id, one, bytes32(uint256(18))) {
                seatRuleBroken = true;
            } catch {}
        } else {
            try ledger.batchClaimBearer(id, one, bytes32(uint256(18))) {
                seatRuleBroken = true;
            } catch {}
        }
    }

    /// A seat mint into a seat a ticket already holds. Must always revert.
    function claimTakenSeat(uint256 pick) external {
        bytes32 id;
        uint256 held;
        bool usable;
        if (actorSeatEvent.length > 0) {
            uint256 i = bound(pick, 0, actorSeatEvent.length - 1);
            id = actorSeatEvent[i];
            held = seenSeat[id][actorSeatSlot[i]];
            (uint64 endTs, bool cancelled) = ledger.getEventStatus(id);
            (uint64 supply, uint64 minted, , ) = ledger.getEvent(id);
            usable = held != 0 && !cancelled && block.timestamp < endTs && minted < supply;
        }
        address[] memory owners = new address[](1);
        owners[0] = address(0x3);
        uint256[] memory seats = new uint256[](1);
        // No usable held seat: take one in this same call.
        if (!usable) {
            id = _openSeated(pick);
            uint256 seat = _freeSeat(id, pick);
            if (seat == type(uint256).max) return;
            seats[0] = seat;
            try ledger.batchClaimSeats(id, owners, seats, bytes32(uint256(17))) returns (uint256 f) {
                _recordSlot(id, f, address(0x3));
                seenSeat[id][f] = seat + 1;
            } catch {
                return;
            }
            (uint64 supply2, uint64 minted2, , ) = ledger.getEvent(id);
            if (minted2 >= supply2) return;
            held = seat + 1;
        }
        seats[0] = held - 1;
        takenSeatAttempts++;
        try ledger.batchClaimSeats(id, owners, seats, bytes32(uint256(14))) {
            seatRuleBroken = true;
        } catch {}
    }

    /// Move a seated ticket: a bearer one on the organiser key's signature
    /// alone, any one on the key's and its holder's. Picks a free seat, or
    /// `NO_SEAT` now and then.
    function reseat(uint256 pick, uint256 seatSeed, bool twoParty, address submitter) external {
        bytes32 id;
        uint256 slot;
        bool usable;
        if (actorSeatEvent.length > 0) {
            uint256 i = bound(pick, 0, actorSeatEvent.length - 1);
            id = actorSeatEvent[i];
            slot = actorSeatSlot[i];
            (uint64 endTs, bool cancelled) = ledger.getEventStatus(id);
            usable = !cancelled && block.timestamp < endTs && keyOf[seenSlotOwner[id][slot]] != 0;
            if (!twoParty) usable = usable && seenBearer[id][slot] && !seenMoved[id][slot];
        }
        // An unusable pick gets a fresh seat minted in this same call, so the
        // move witnesses never starve (the #18 lesson).
        if (!usable) {
            if (!twoParty && bearerMintsSeenDisabled) return;
            id = _openSeated(pick);
            uint256 seat = _freeSeat(id, seatSeed + 1);
            if (seat == type(uint256).max) return;
            address[] memory one = new address[](1);
            one[0] = vm.addr(actorKeys[bound(pick, 0, actorKeys.length - 1)]);
            uint256[] memory seats = new uint256[](1);
            seats[0] = seat;
            if (twoParty) {
                try ledger.batchClaimSeats(id, one, seats, bytes32(uint256(15))) returns (uint256 f) {
                    slot = f;
                } catch {
                    return;
                }
            } else {
                try ledger.batchClaimSeatsBearer(id, one, seats, bytes32(uint256(16))) returns (uint256 f) {
                    slot = f;
                } catch {
                    return;
                }
            }
            if (twoParty) _recordSlot(id, slot, one[0]);
            else _recordBearer(id, slot, one[0]);
            seenSeat[id][slot] = seat + 1;
            actorSeatEvent.push(id);
            actorSeatSlot.push(slot);
        }

        uint256 toSeat = seatSeed % 9 == 0 ? ledger.NO_SEAT() : _freeSeat(id, seatSeed);
        if (toSeat == type(uint256).max) return;
        if (toSeat == ledger.NO_SEAT() && seenSeat[id][slot] == 0) return;
        if (submitter == address(0)) submitter = address(0xCAFE);
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = ledger.reseatDigest(id, slot, toSeat, deadline);
        bytes memory orgSig = _sign(keyOf[expectedKey[id]], digest);

        bool bearerPath = !twoParty && seenBearer[id][slot] && !seenMoved[id][slot] && !bearerMintsSeenDisabled;
        bool landed;
        if (bearerPath) {
            vm.prank(submitter);
            try ledger.reseatBearer(id, slot, toSeat, deadline, orgSig) {
                landed = true;
                bearerReseats++;
            } catch {}
        } else {
            uint256 holderKey = keyOf[seenSlotOwner[id][slot]];
            if (holderKey == 0) return; // moved to a key the handler does not hold
            vm.prank(submitter);
            try ledger.reseat(id, slot, toSeat, deadline, orgSig, _sign(holderKey, digest)) {
                landed = true;
                holderReseats++;
                seenMoved[id][slot] = true;
            } catch {}
        }
        if (landed) seenSeat[id][slot] = toSeat == ledger.NO_SEAT() ? 0 : toSeat + 1;
    }

    /// A seat move without the consent it needs: a bearer move signed by a
    /// key that is not the organiser's, a holder's signature alone (as both
    /// signatures), a held slot through `reseatBearer`. Must always revert.
    function reseatUnauthorised(uint256 pick, uint256 seatSeed, uint256 road) external {
        if (actorSeatEvent.length == 0) return;
        uint256 i = bound(pick, 0, actorSeatEvent.length - 1);
        bytes32 id = actorSeatEvent[i];
        uint256 slot = actorSeatSlot[i];
        uint256 toSeat = _freeSeat(id, seatSeed);
        if (toSeat == type(uint256).max) return;
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 digest = ledger.reseatDigest(id, slot, toSeat, deadline);
        uint256 r = road % 3;
        unauthorisedReseatAttempts++;
        if (r == 0) {
            bytes memory wrong = _sign(actorKeys[bound(seatSeed, 0, actorKeys.length - 1)], digest);
            try ledger.reseatBearer(id, slot, toSeat, deadline, wrong) {
                seatRuleBroken = true;
            } catch {}
        } else if (r == 1) {
            uint256 holderKey = keyOf[seenSlotOwner[id][slot]];
            if (holderKey == 0 || vm.addr(holderKey) == expectedKey[id]) return;
            bytes memory h = _sign(holderKey, digest);
            try ledger.reseat(id, slot, toSeat, deadline, h, h) {
                seatRuleBroken = true;
            } catch {}
        } else {
            if (!seenMoved[id][slot]) return;
            bytes memory orgSig = _sign(keyOf[expectedKey[id]], digest);
            try ledger.reseatBearer(id, slot, toSeat, deadline, orgSig) {
                seatRuleBroken = true;
            } catch {}
        }
    }

    /// Always refused: a supply above the registered one.
    function setSupplyAboveRegistered(uint256 eventIndex, uint256 overSeed) external {
        if (eventIds.length == 0) return;
        bytes32 id = _openEvent(eventIndex);
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 supply = stamped[id].registeredSupply + uint64(bound(overSeed, 1, 1000));
        aboveRegisteredAttempts++;
        vm.prank(stamped[id].organiser);
        try ledger.setSupply(id, supply) {
            supplyAboveRegisteredLanded = true;
        } catch {}
    }

    /// Always refused: a cutoff more than `MAX_SALES_EXTENSION` past now.
    function extendSalesEndTooFar(uint256 eventIndex, uint256 overSeed) external {
        if (eventIds.length == 0) return;
        bytes32 id = _openEvent(eventIndex);
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 newEnd = uint64(block.timestamp + ledger.MAX_SALES_EXTENSION() + bound(overSeed, 1, 365 days));
        tooFarAttempts++;
        vm.prank(stamped[id].organiser);
        try ledger.extendSalesEnd(id, newEnd) {
            cutoffTooFarLanded = true;
        } catch {}
    }

    /// Always refused: moving a cutoff that has passed. Uses an event the
    /// campaign closed if there is one, else closes a fresh one, so the
    /// witness never starves.
    function extendLapsedEvent(uint256 eventIndex, uint256 offset) external {
        if (eventIds.length == 0) return;
        uint256 n = eventIds.length;
        uint256 start = bound(eventIndex, 0, n - 1);
        bytes32 id;
        bool found;
        for (uint256 k; k < n; ++k) {
            bytes32 candidate = eventIds[(start + k) % n];
            (uint64 endTs, bool cancelled) = ledger.getEventStatus(candidate);
            if (!cancelled && block.timestamp >= endTs) {
                id = candidate;
                found = true;
                break;
            }
        }
        if (!found) {
            // forge-lint: disable-next-line(unsafe-typecast)
            uint64 end = uint64(block.timestamp + 1);
            bytes32 manifest = bytes32(uint256(8));
            address key = vm.addr(orgKeys[0]);
            id = ledger.registerEvent(address(this), key, 10, manifest, end);
            _track(id, 10, end, address(this), manifest, key, false);
            vm.warp(end);
        }
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 newEnd = uint64(block.timestamp + bound(offset, 1, 365 days));
        lapsedExtendAttempts++;
        vm.prank(stamped[id].organiser);
        try ledger.extendSalesEnd(id, newEnd) {
            lapsedCutoffExtended = true;
        } catch {}
    }

    /// The off switch. Held back until a reissue and a bearer seat move have
    /// run, or most campaigns would switch it off before exercising either.
    function disableBearerMints() external {
        if (reissuesMade == 0 || bearerReseats == 0 || bearerMintsSeenDisabled) return;
        vm.prank(ledgerOwner);
        ledger.disableBearerMints();
        bearerMintsSeenDisabled = true;
    }

    /// An event still on sale: the picked one if so, else a fresh one. Random
    /// cancels and warps close every event within a few dozen calls, and the
    /// version-2 coverage checks must not starve on that. A fresh event is
    /// registered exactly as `registerEvent` does, so it is tracked the same.
    function _openEvent(uint256 eventIndex) internal returns (bytes32 id) {
        id = eventIds[bound(eventIndex, 0, eventIds.length - 1)];
        (uint64 endTs, bool cancelled) = ledger.getEventStatus(id);
        (uint64 supply, uint64 minted, , ) = ledger.getEvent(id);
        if (!cancelled && block.timestamp < endTs && minted < supply) return id;
        id = _registerFresh(address(this));
    }

    /// As `_openEvent`, but general admission: the GA mint fallbacks below
    /// must not starve on a seated pick, which refuses them.
    function _openGaEvent(uint256 eventIndex) internal returns (bytes32 id) {
        id = _openEvent(eventIndex);
        if (seated[id]) id = _registerFresh(address(this));
    }

    function _recordBearer(bytes32 id, uint256 slot, address owner) internal {
        _recordSlot(id, slot, owner);
        seenBearer[id][slot] = true;
        bearerSlotEvent.push(id);
        bearerSlotIndex.push(slot);
    }

    function cancelEvent(uint256 eventIndex) external {
        if (eventIds.length == 0) return;
        bytes32 id = eventIds[bound(eventIndex, 0, eventIds.length - 1)];

        vm.prank(stamped[id].organiser);
        try ledger.cancelEvent(id) {
            stamped[id].seenCancelled = true;
        } catch {}
    }

    function warp(uint256 secondsForward) external {
        vm.warp(block.timestamp + bound(secondsForward, 1, 30 days));
    }

    /// A claimed slot to move: the pick if it is one, else one minted on an
    /// open event in the same call, so the transfer witnesses never starve as
    /// the action list grows (#31). `type(uint256).max` if even the mint fails.
    function _claimedSlot(uint256 eventIndex, uint256 slotSeed) internal returns (bytes32 id, uint256 slot) {
        id = eventIds[bound(eventIndex, 0, eventIds.length - 1)];
        uint256 count = seenSlotCount[id];
        if (count > 0) {
            slot = bound(slotSeed, 0, count - 1);
            if (seenSlotOwner[id][slot] != address(0)) return (id, slot);
        }
        id = _openGaEvent(eventIndex);
        try ledger.claimFor(id, address(0x3), bytes32(uint256(10))) returns (uint256 s) {
            _recordSlot(id, s, address(0x3));
            slot = s;
        } catch {
            slot = type(uint256).max;
        }
    }

    function _recordSlot(bytes32 id, uint256 slot, address owner) internal {
        seenSlotOwner[id][slot] = owner;
        uint256 c = seenSlotCount[id];
        if (slot + 1 > c) seenSlotCount[id] = slot + 1;
    }

    function _sign(uint256 key, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }
}

contract WoCoTicketLedgerInvariantTest is Test {
    WoCoTicketLedger internal ledger;
    LedgerHandler    internal handler;

    address owner = address(0x1);

    function setUp() public {
        // Deploy with the handler as the initial authorised sponsor.
        ledger  = new WoCoTicketLedger(owner, address(0xDEAD), type(uint32).max);
        handler = new LedgerHandler(ledger, owner);

        vm.prank(owner);
        ledger.addSponsor(address(handler), type(uint32).max);

        // Seeded, so every version-2 action has an event to act on from the
        // first step rather than waiting for the fuzzer to register one.
        handler.registerEvent(50, bytes32(uint256(1)), 30 days);
        handler.registerEvent(200, bytes32(uint256(2)), 200 days);
        // One spent signature from the start, so `replaySpentSignature` always
        // has something to replay however the campaign then runs.
        handler.claimForActor(0, 0, bytes32(uint256(9)));
        handler.transferSlotSigned(0, 1, address(0xCAFE));

        targetContract(address(handler));
    }

    /// Never oversell: allocation never exceeds the event's supply, whoever
    /// moved it and however. A reissue mints nothing, so this covers it too.
    /// forge-config: default.invariant.runs = 64
    function invariant_NeverOversells() public view {
        uint256 n = handler.eventCount();
        for (uint256 i; i < n; ++i) {
            bytes32 id = handler.eventIds(i);
            (uint64 totalSupply, uint64 nextSlot, , ) = ledger.getEvent(id);
            assertLe(nextSlot, totalSupply, "nextSlot exceeded supply");
            assertLe(totalSupply, ledger.getRegisteredSupply(id), "supply above the registered supply");
        }
    }

    /// Terms change only as version 2 allows: supply only by `setSupply` and
    /// the cutoff only later by `extendSalesEnd` (the handler tracks both, on
    /// every road), organiser and manifest never, the organiser key only by
    /// the organiser's account, and none of it on anyone else's authority: a
    /// stranger, a sponsor that is not the organiser, a key not the event's, a
    /// key it rotated away from, or a spent signature.
    /// forge-config: default.invariant.runs = 64
    function invariant_TermsMoveOnlyAsAllowed() public view {
        assertFalse(handler.cutoffMovedEarlier(), "the sales cutoff moved earlier");
        assertFalse(handler.supplyAboveRegisteredLanded(), "supply was set above the registered supply");
        assertFalse(handler.cutoffTooFarLanded(), "a cutoff moved past MAX_SALES_EXTENSION");
        assertFalse(handler.lapsedCutoffExtended(), "a cutoff that had passed was moved");
        assertFalse(handler.unauthorisedTermsLanded(), "terms changed without the organiser's authority");
        assertFalse(handler.keyMovedByOutsider(), "someone but the organiser's account moved its key");
        uint256 n = handler.eventCount();
        for (uint256 i; i < n; ++i) {
            bytes32 id = handler.eventIds(i);
            (uint64 sSupply, uint64 sEndTs, address sOrg, bytes32 sManifest, , uint64 sRegistered) =
                handler.stamped(id);
            assertEq(ledger.getRegisteredSupply(id), sRegistered, "registeredSupply changed after registration");

            (uint64 totalSupply, , address org, bytes32 manifest) = ledger.getEvent(id);
            (uint64 endTs, ) = ledger.getEventStatus(id);

            assertEq(totalSupply, sSupply,   "totalSupply moved other than by setSupply");
            assertEq(org,         sOrg,      "organiser changed after registration");
            assertEq(manifest,    sManifest, "manifestRef changed after registration");
            assertEq(endTs,       sEndTs,    "eventEndTs moved other than by extendSalesEnd");
            assertEq(ledger.getOrganiserKey(id), handler.expectedKey(id), "organiser key moved other than as allowed");
            assertEq(ledger.isSeated(id), handler.seated(id), "an event changed kind");
        }
    }

    /// Seats: on a seated event every claimed slot holds exactly the seat the
    /// handler saw it take (or none, after a move to `NO_SEAT`), the bitmap
    /// holds exactly those seats, so no seat is held twice; a GA event holds
    /// no seat at all. No mint landed on a held seat or on the other kind of
    /// event, and no seat moved without the consent it needs.
    /// forge-config: default.invariant.runs = 64
    function invariant_SeatsAreHeldOnce() public view {
        assertFalse(handler.seatRuleBroken(), "a seat rule was broken");
        uint256 noSeat = ledger.NO_SEAT();
        uint256 n = handler.eventCount();
        for (uint256 i; i < n; ++i) {
            bytes32 id = handler.eventIds(i);
            if (!handler.seated(id)) {
                // A GA event's seat bitmap stays empty (its supply here is at most 500).
                assertEq(ledger.seatWord(id, 0) | ledger.seatWord(id, 1), 0, "a GA event holds a seat");
                continue;
            }
            (, uint64 minted, , ) = ledger.getEvent(id);
            uint256 held;
            for (uint256 s; s < minted; ++s) {
                uint256 seat = ledger.seatOf(id, s);
                uint256 seen = handler.seenSeat(id, s);
                assertEq(seat, seen == 0 ? noSeat : seen - 1, "a ticket's seat moved other than as allowed");
                if (seat == noSeat) continue;
                assertTrue(ledger.seatWord(id, seat >> 8) & (uint256(1) << (seat & 255)) != 0, "a held seat reads free");
                held++;
            }
            uint256 bits;
            uint256 words = (uint256(ledger.getRegisteredSupply(id)) + 255) >> 8;
            for (uint256 w; w < words; ++w) bits += _popcount(ledger.seatWord(id, w));
            assertEq(bits, held, "the seat bitmap is not exactly the seats tickets hold");
        }
    }

    function _popcount(uint256 x) internal pure returns (uint256 c) {
        while (x != 0) {
            x &= x - 1;
            ++c;
        }
    }

    /// Reissue reaches only what the rules allow: no non-bearer or
    /// holder-moved slot, nor anything after the off switch, was ever
    /// re-pointed or bearer-minted, and no reissue minted a slot. The flags
    /// are what the handler saw: `bearer` exactly as minted, `held` exactly
    /// when a holder has moved the slot (never set by a reissue).
    /// forge-config: default.invariant.runs = 64
    function invariant_ReissueIsBounded() public view {
        assertFalse(handler.forbiddenReissue(), "a reissue or bearer mint landed that the rules forbid");
        assertFalse(handler.reissueUsedASeat(), "a reissue minted a slot");
        uint256 n = handler.eventCount();
        for (uint256 i; i < n; ++i) {
            bytes32 id = handler.eventIds(i);
            uint256 count = handler.seenSlotCount(id);
            for (uint256 s; s < count; ++s) {
                if (ledger.slotOwner(id, s) == address(0)) continue;
                (bool bearer, bool held) = ledger.getSlotFlags(id, s);
                assertEq(bearer, handler.seenBearer(id, s), "a slot's bearer bit is not as minted");
                assertEq(held, handler.seenMoved(id, s), "held is not exactly 'a holder moved it'");
            }
        }
    }

    /// The off switch is one-way.
    /// forge-config: default.invariant.runs = 64
    function invariant_BearerOffSwitchIsOneWay() public view {
        if (handler.bearerMintsSeenDisabled()) {
            assertTrue(ledger.bearerMintsDisabled(), "bearer mints were switched back on");
        }
    }

    /// Cancellation is one-way. Payments reads this flag to open refunds, so a
    /// cancelled event must never silently revert to live.
    /// forge-config: default.invariant.runs = 64
    function invariant_CancellationIsOneWay() public view {
        uint256 n = handler.eventCount();
        for (uint256 i; i < n; ++i) {
            bytes32 id = handler.eventIds(i);
            (, , , , bool seenCancelled, ) = handler.stamped(id);
            if (!seenCancelled) continue;
            (, bool cancelled) = ledger.getEventStatus(id);
            assertTrue(cancelled, "a cancelled event became live again");
        }
    }

    /// Coverage, not correctness — and it has to live here rather than in the
    /// invariant body, because an invariant is also evaluated at SETUP, when no
    /// handler call has run and every counter is legitimately zero.
    ///
    /// Without this, `invariant_SlotsAreOnlyMovedByTheirOwner` would pass
    /// trivially in any campaign that never managed a transfer: the handler
    /// early-returns on unusable input, so "no unauthorised move succeeded" is
    /// only evidence if unauthorised moves were actually attempted — on both
    /// paths, and as a replay.
    function afterInvariant() public view {
        assertGt(handler.transfersMade(), 0, "campaign never exercised transferSlot");
        assertGt(
            handler.unauthorisedAttempts(),
            0,
            "campaign never attempted an unauthorised move"
        );
        assertGt(handler.signedTransfersMade(), 0, "campaign never exercised transferSlotWithSignature");
        assertGt(
            handler.signedUnauthorisedAttempts(),
            0,
            "campaign never attempted a signature from a non-holder"
        );
        assertGt(handler.replayAttempts(), 0, "campaign never replayed a spent signature");
        assertGt(
            handler.nonceOnlyReplays(),
            0,
            "campaign never replayed a spent signature with only the nonce standing"
        );
        assertGt(handler.reissuesMade(), 0, "campaign never exercised reissue");
        assertGt(handler.ineligibleReissueAttempts(), 0, "campaign never attempted an ineligible reissue");
        assertGt(handler.supplySets(), 0, "campaign never exercised setSupply");
        assertGt(handler.cutoffExtensions(), 0, "campaign never exercised extendSalesEnd");
        assertGt(handler.aboveRegisteredAttempts(), 0, "campaign never tried a supply above the registered one");
        assertGt(handler.tooFarAttempts(), 0, "campaign never tried a cutoff past MAX_SALES_EXTENSION");
        assertGt(handler.lapsedExtendAttempts(), 0, "campaign never tried to move a cutoff that had passed");
        assertGt(handler.signedTermsMade(), 0, "campaign never landed a signed terms action");
        assertGt(handler.directKeyTermsMade(), 0, "campaign never had the key send terms itself");
        assertGt(handler.keyRotations(), 0, "campaign never rotated an organiser key");
        assertGt(handler.unauthorisedTermsAttempts(), 0, "campaign never tried terms without authority");
        assertGt(handler.retiredKeyAttempts(), 0, "campaign never tried a rotated-away key");
        assertGt(handler.termsReplayAttempts(), 0, "campaign never replayed a spent terms signature");
        assertGt(handler.outsiderKeyMoveAttempts(), 0, "campaign never tried to move a key from outside");
        assertGt(handler.seatMints(), 0, "campaign never minted seats");
        assertGt(handler.takenSeatAttempts(), 0, "campaign never tried a held seat");
        assertGt(handler.bearerReseats(), 0, "campaign never landed reseatBearer");
        assertGt(handler.holderReseats(), 0, "campaign never landed a two-party reseat");
        assertGt(handler.unauthorisedReseatAttempts(), 0, "campaign never tried a seat move without consent");
        assertGt(handler.kindMismatchAttempts(), 0, "campaign never tried a GA mint on a seated event");
    }

    /// A slot's owner changes ONLY through a transfer its own owner authorised —
    /// by sending it, or by signing it — or through version 2's `reissue` of a
    /// bearer slot no holder has moved, which `invariant_ReissueIsBounded`
    /// fences.
    ///
    /// This used to read "once a slot has an owner, that owner never changes",
    /// and that literal form is no longer true — transfers exist so a ticket
    /// can change hands. The sentence overstated its own purpose. What the
    /// split protects (see the contract header) is that SPONSOR authority
    /// grants exactly one power: appending new slots, never touching existing
    /// ones. A transfer the holder authorises does not cross that boundary, and
    /// the handler holds strictly more power than a real payments contract, so
    /// if no sponsor/organiser/clock/submitter action rewrites a slot here,
    /// none can.
    ///
    /// The handler tracks ownership THROUGH both transfer paths and reissue, so
    /// this still fails on any rewrite that came from none of them — which is
    /// the property that was actually load-bearing all along.
    /// forge-config: default.invariant.runs = 64
    function invariant_SlotsAreOnlyMovedByTheirOwner() public view {
        assertFalse(
            handler.unauthorisedTransferSucceeded(),
            "a slot was moved without its holder's authority"
        );
        uint256 n = handler.eventCount();
        for (uint256 i; i < n; ++i) {
            bytes32 id = handler.eventIds(i);
            uint256 count = handler.seenSlotCount(id);
            for (uint256 s; s < count; ++s) {
                address expected = handler.seenSlotOwner(id, s);
                if (expected == address(0)) continue;
                assertEq(ledger.slotOwner(id, s), expected, "an existing slot was rewritten");
            }
        }
    }
}
