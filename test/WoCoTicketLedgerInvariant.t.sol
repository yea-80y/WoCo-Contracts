// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {WoCoTicketLedger} from "../src/WoCoTicketLedger.sol";

/**
 * Invariant tests for WoCoTicketLedger.
 *
 * These exist to test the guarantee the contract's natspec makes, rather than
 * individual guards: allocation is append-only, within stamped supply, and
 * stamped terms never move.
 *
 * The handler is an authorised sponsor AND the stamped organiser of every
 * event it registers, so it holds strictly MORE power than a real payments
 * contract would — it can cancel, which a sponsor cannot do on an event it did
 * not register. If the invariants hold for it, they hold for any sponsor.
 *
 * WHAT THIS CAMPAIGN DOES NOT COVER: the handler never calls
 * `forceCancelEvent`, `addSponsor`/`removeSponsor`, or `setDisputeAuthority`,
 * so these invariants say nothing about admin churn. Those paths are covered
 * by the unit suite instead.
 *
 * Kept in its own file because invariant campaigns are slow; the unit suite in
 * WoCoTicketLedger.t.sol runs in milliseconds and stays the fast feedback loop.
 */
contract LedgerHandler is Test {
    WoCoTicketLedger internal ledger;

    bytes32[] public eventIds;

    /// Terms recorded at registration, to prove nothing rewrites them later.
    struct Stamped {
        uint64  totalSupply;
        uint64  eventEndTs;
        address organiser;
        bytes32 manifestRef;
        bool    seenCancelled;
    }

    mapping(bytes32 => Stamped) public stamped;

    /// Slot owners observed at mint time, to prove slots are never rewritten.
    mapping(bytes32 => mapping(uint256 => address)) public seenSlotOwner;
    mapping(bytes32 => uint256) public seenSlotCount;

    constructor(WoCoTicketLedger _ledger) {
        ledger = _ledger;
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

        // Handler is its own organiser, so it can also exercise cancelEvent.
        bytes32 id = ledger.registerEvent(address(this), supply64, manifestRef, endTs);

        eventIds.push(id);
        stamped[id] = Stamped({
            totalSupply:   supply64,
            eventEndTs:    endTs,
            organiser:     address(this),
            manifestRef:   manifestRef,
            seenCancelled: false
        });
    }

    function claimFor(uint256 eventIndex, address owner, bytes32 orderRef) external {
        if (eventIds.length == 0) return;
        bytes32 id = eventIds[bound(eventIndex, 0, eventIds.length - 1)];
        if (owner == address(0)) owner = address(0x1);

        try ledger.claimFor(id, owner, orderRef) returns (uint256 slot) {
            _recordSlot(id, slot, owner);
        } catch {
            // Reverts are expected (sold out, cancelled, past cutoff) and are
            // themselves the property under test — the invariants below assert
            // that no state moved.
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
            for (uint256 i; i < count; ++i) _recordSlot(id, first + i, owner);
        } catch {
            // See claimFor.
        }
    }

    function cancelEvent(uint256 eventIndex) external {
        if (eventIds.length == 0) return;
        bytes32 id = eventIds[bound(eventIndex, 0, eventIds.length - 1)];

        try ledger.cancelEvent(id) {
            stamped[id].seenCancelled = true;
        } catch {}
    }

    function warp(uint256 secondsForward) external {
        vm.warp(block.timestamp + bound(secondsForward, 1, 30 days));
    }

    function _recordSlot(bytes32 id, uint256 slot, address owner) internal {
        seenSlotOwner[id][slot] = owner;
        uint256 c = seenSlotCount[id];
        if (slot + 1 > c) seenSlotCount[id] = slot + 1;
    }
}

contract WoCoTicketLedgerInvariantTest is Test {
    WoCoTicketLedger internal ledger;
    LedgerHandler    internal handler;

    address owner = address(0x1);

    function setUp() public {
        // Deploy with the handler as the initial authorised sponsor.
        ledger  = new WoCoTicketLedger(owner, address(0xDEAD));
        handler = new LedgerHandler(ledger);

        vm.prank(owner);
        ledger.addSponsor(address(handler));

        targetContract(address(handler));
    }

    /// Never oversell: allocation can only reach the stamped supply.
    /// forge-config: default.invariant.runs = 64
    function invariant_NeverOversells() public view {
        uint256 n = handler.eventCount();
        for (uint256 i; i < n; ++i) {
            bytes32 id = handler.eventIds(i);
            (uint64 totalSupply, uint64 nextSlot, , ) = ledger.getEvent(id);
            assertLe(nextSlot, totalSupply, "nextSlot exceeded stamped supply");
        }
    }

    /// Terms stamped at registration are immutable. Nothing a sponsor, an
    /// organiser, or the passage of time does may reinterpret them.
    /// forge-config: default.invariant.runs = 64
    function invariant_StampedTermsAreImmutable() public view {
        uint256 n = handler.eventCount();
        for (uint256 i; i < n; ++i) {
            bytes32 id = handler.eventIds(i);
            (uint64 sSupply, uint64 sEndTs, address sOrg, bytes32 sManifest, ) =
                handler.stamped(id);

            (uint64 totalSupply, , address org, bytes32 manifest) = ledger.getEvent(id);
            (uint64 endTs, ) = ledger.getEventStatus(id);

            assertEq(totalSupply, sSupply,   "totalSupply changed after registration");
            assertEq(org,         sOrg,      "organiser changed after registration");
            assertEq(manifest,    sManifest, "manifestRef changed after registration");
            assertEq(endTs,       sEndTs,    "eventEndTs changed after registration");
        }
    }

    /// Cancellation is one-way. Payments reads this flag to open refunds, so a
    /// cancelled event must never silently revert to live.
    /// forge-config: default.invariant.runs = 64
    function invariant_CancellationIsOneWay() public view {
        uint256 n = handler.eventCount();
        for (uint256 i; i < n; ++i) {
            bytes32 id = handler.eventIds(i);
            (, , , , bool seenCancelled) = handler.stamped(id);
            if (!seenCancelled) continue;
            (, bool cancelled) = ledger.getEventStatus(id);
            assertTrue(cancelled, "a cancelled event became live again");
        }
    }

    /// Slots are append-only: once a slot has an owner, that owner never
    /// changes. This is the property the whole split exists to protect.
    /// forge-config: default.invariant.runs = 64
    function invariant_SlotsAreAppendOnly() public view {
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
