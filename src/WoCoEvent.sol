// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/access/Ownable2Step.sol";

/**
 * @title WoCoEvent
 * @notice On-chain slot registry for WoCo v2 ticketing (Pattern A, Stripe-only v1).
 *
 * Responsibilities:
 *   - registerEvent: binds an organiser-signed Merkle manifest to an atomic
 *     slot counter on-chain. Returns a deterministic eventId the organiser
 *     cannot front-run or collide with.
 *   - claimFor: atomically allocates the next slot to a buyer's burner address.
 *   - batchClaimFor: allocates N contiguous slots in one tx, storing the shared
 *     orderRef ONCE per batch instead of per slot (≈50% SSTORE reduction for
 *     large group bookings).
 *
 * Storage layout — efficiency notes:
 *   slots[eventId][slot] = (address owner, uint96 batchFirstSlot) — single SSTORE
 *     per slot (address+uint96 pack to 32 bytes exactly). `batchFirstSlot` points
 *     back to the first slot of the batch that wrote it (== slot itself for
 *     single claims), which is the key into batchOrderRef.
 *   batchOrderRef[eventId][firstSlot] = orderRef — one SSTORE per BATCH, not per
 *     slot. A batch of 100 tickets writes 101 SSTOREs total (100 slots + 1
 *     orderRef) vs 200 in a naive design.
 *
 * Sponsorship: `claimFor` / `batchClaimFor` are gated by `onlyAuthorised`.
 * The platform sponsor wallet pays gas; users never need an EOA.
 *
 * Owner role (Ownable2Step):
 *   - Deployed with deployer EOA as initial owner.
 *   - User rotates to a 2-of-N multisig post-deploy (one tx, no redeploy).
 *
 * eventId derivation:
 *   eventId = keccak256(abi.encode(msg.sender, organiserNonce[msg.sender]++))
 *   First event for an organiser uses nonce 0, second nonce 1, etc. Closes the
 *   front-run / collision attack: caller cannot specify or predict the eventId
 *   of another organiser.
 *
 * Slot indices are 0-based (0..totalSupply-1), matching POD edition `slot + 1`.
 */
contract WoCoEvent is Ownable2Step {
    struct Event {
        uint256 totalSupply;
        uint256 nextSlot;
        address organiser;
        bytes32 manifestRef;
    }

    /// Packed slot record: 20-byte owner + 12-byte batchFirstSlot pointer.
    /// Fits in one 32-byte storage word — one SSTORE per slot write.
    struct Slot {
        address owner;
        uint96 batchFirstSlot;
    }

    mapping(bytes32 => Event) public events;
    mapping(bytes32 => mapping(uint256 => Slot)) public slots;
    /// Indexed by the FIRST slot of the batch that wrote it. For single
    /// `claimFor` calls, firstSlot == the slot itself. For `batchClaimFor`,
    /// every slot in the batch points back to firstSlot here.
    mapping(bytes32 => mapping(uint96 => bytes32)) public batchOrderRef;
    mapping(address => bool) public authorisedSponsors;
    mapping(address => uint256) public organiserNonce;

    event Registered(
        bytes32 indexed eventId,
        address indexed organiser,
        uint256 supply,
        bytes32 manifestRef
    );

    event SlotClaimed(
        bytes32 indexed eventId,
        uint256 slot,
        address indexed buyer,
        bytes32 orderRef
    );

    event SponsorAdded(address indexed sponsor);
    event SponsorRemoved(address indexed sponsor);

    modifier onlyAuthorised() {
        require(authorisedSponsors[msg.sender], "Not authorised");
        _;
    }

    constructor(address initialOwner, address initialSponsor)
        Ownable(initialOwner)
    {
        require(initialSponsor != address(0), "Zero sponsor");
        authorisedSponsors[initialSponsor] = true;
        emit SponsorAdded(initialSponsor);
    }

    /// @notice Register a new event on-chain.
    function registerEvent(uint256 supply, bytes32 manifestRef)
        external
        returns (bytes32 eventId)
    {
        require(supply > 0, "Supply must be > 0");
        require(manifestRef != bytes32(0), "Zero manifestRef");
        require(supply <= type(uint96).max, "Supply too large");

        eventId = keccak256(abi.encode(msg.sender, organiserNonce[msg.sender]++));

        events[eventId] = Event({
            totalSupply: supply,
            nextSlot: 0,
            organiser: msg.sender,
            manifestRef: manifestRef
        });

        emit Registered(eventId, msg.sender, supply, manifestRef);
    }

    /**
     * @notice Atomically allocate the next available slot to a buyer.
     * @return slot 0-based slot index. Corresponds to POD edition `slot + 1`.
     */
    function claimFor(bytes32 eventId, address burner, bytes32 orderRef)
        external
        onlyAuthorised
        returns (uint256 slot)
    {
        Event storage ev = events[eventId];
        require(ev.totalSupply > 0, "Event not found");
        require(ev.nextSlot < ev.totalSupply, "Sold out");

        slot = ev.nextSlot;
        unchecked { ev.nextSlot = slot + 1; }

        // Single claim is a degenerate batch of size 1: batchFirstSlot == slot.
        slots[eventId][slot] = Slot({ owner: burner, batchFirstSlot: uint96(slot) });
        batchOrderRef[eventId][uint96(slot)] = orderRef;

        emit SlotClaimed(eventId, slot, burner, orderRef);
    }

    /**
     * @notice Atomically allocate N contiguous slots in a single transaction.
     *         All-or-nothing — reverts if the batch would exceed totalSupply.
     *
     *         Storage cost: N owner-slot SSTOREs + 1 orderRef SSTORE. For a
     *         100-ticket batch that's 101 SSTOREs vs ~200 in a naive design,
     *         saving ≈ 100 × 22.1k = 2.2M gas per batch.
     *
     * @param eventId The registered event.
     * @param burners One burner address per ticket. Length 1..100. Larger
     *                orders are chunked client-side (e.g. 200 → 2 calls of 100).
     * @param orderRef Shared encrypted-order ref (one form submission, N tickets).
     * @return firstSlot 0-based index of the FIRST allocated slot. The N slots
     *                   claimed are firstSlot..firstSlot + N - 1.
     */
    function batchClaimFor(bytes32 eventId, address[] calldata burners, bytes32 orderRef)
        external
        onlyAuthorised
        returns (uint256 firstSlot)
    {
        uint256 n = burners.length;
        require(n > 0, "Empty batch");
        // 100 slots ≈ 5M gas — well under any chain's block limit. Server
        // chunks larger orders into multiple sequential calls.
        require(n <= 100, "Batch too large");

        Event storage ev = events[eventId];
        require(ev.totalSupply > 0, "Event not found");

        firstSlot = ev.nextSlot;
        require(firstSlot + n <= ev.totalSupply, "Insufficient supply");

        // One SSTORE for the shared orderRef — every slot in this batch
        // resolves orderRef through batchFirstSlot == firstSlot.
        uint96 firstSlot96 = uint96(firstSlot);
        batchOrderRef[eventId][firstSlot96] = orderRef;

        // Slot writes: one packed SSTORE each + one LOG3 event.
        // `unchecked` is safe: i < n <= 100 (no overflow on ++i), and
        // firstSlot + n <= totalSupply already verified (no overflow on
        // firstSlot + i since i < n).
        for (uint256 i = 0; i < n;) {
            uint256 slot;
            address burner = burners[i];
            unchecked {
                slot = firstSlot + i;
            }
            slots[eventId][slot] = Slot({ owner: burner, batchFirstSlot: firstSlot96 });
            emit SlotClaimed(eventId, slot, burner, orderRef);
            unchecked { ++i; }
        }

        unchecked { ev.nextSlot = firstSlot + n; }
    }

    /**
     * @notice View — returns the owner and encrypted-order ref for a slot.
     *         The orderRef is resolved via the slot's batchFirstSlot pointer
     *         into batchOrderRef. Off-chain verifiers should prefer this view
     *         over reading the raw mappings.
     */
    function getSlotData(bytes32 eventId, uint256 slot)
        external
        view
        returns (address owner, bytes32 orderRef)
    {
        Slot memory s = slots[eventId][slot];
        return (s.owner, batchOrderRef[eventId][s.batchFirstSlot]);
    }

    /// @notice Convenience: owner-only view. Same as slots(eventId, slot).owner
    ///         but exposed as a stable single-return getter for off-chain tools.
    function slotOwner(bytes32 eventId, uint256 slot) external view returns (address) {
        return slots[eventId][slot].owner;
    }

    /// @notice Convenience: orderRef-only view. Walks the batchFirstSlot pointer.
    function slotOrderRef(bytes32 eventId, uint256 slot) external view returns (bytes32) {
        Slot memory s = slots[eventId][slot];
        return batchOrderRef[eventId][s.batchFirstSlot];
    }

    function addSponsor(address sponsor) external onlyOwner {
        require(sponsor != address(0), "Zero address");
        authorisedSponsors[sponsor] = true;
        emit SponsorAdded(sponsor);
    }

    function removeSponsor(address sponsor) external onlyOwner {
        authorisedSponsors[sponsor] = false;
        emit SponsorRemoved(sponsor);
    }
}
