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
 *   - claimFor: atomically allocates the next slot to a buyer's burner address
 *     and records the encrypted-order ref. Called by the platform sponsor
 *     wallet on every successful Stripe webhook.
 *
 * This contract holds no value. No payable functions in v1 — `payAndClaim`
 * ships in v1.5. External audit is deferred until that point; Slither +
 * Foundry fuzz is sufficient for a no-value contract.
 *
 * Owner role (Ownable2Step):
 *   - Deployed with deployer EOA as initial owner.
 *   - User rotates to a 2-of-N multisig post-deploy (one tx, no redeploy).
 *   - Ownable2Step prevents accidental lockout on owner rotation.
 *
 * eventId derivation:
 *   eventId = keccak256(abi.encode(msg.sender, organiserNonce[msg.sender]++))
 *   Nonce is read THEN incremented (Solidity post-increment semantics).
 *   First event for an organiser uses nonce 0, second uses nonce 1, etc.
 *   This closes the front-run / collision attack: caller cannot specify
 *   or predict the eventId of another organiser.
 *
 * Slot indices are 0-based (0..totalSupply-1), matching the POD edition
 * array stored in the Mantaray manifest on Swarm.
 */
contract WoCoEvent is Ownable2Step {
    struct Event {
        uint256 totalSupply;
        uint256 nextSlot;
        address organiser;
        bytes32 manifestRef;
    }

    mapping(bytes32 => Event) public events;
    mapping(bytes32 => mapping(uint256 => address)) public slotOwner;
    mapping(bytes32 => mapping(uint256 => bytes32)) public slotOrderRef;
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

    /**
     * @param initialOwner  Deployer EOA — rotated to multisig post-deploy.
     * @param initialSponsor Platform sponsor wallet — pays gas for Stripe claims.
     *                       Deployer EOA is safe as initial value; rotated to
     *                       a dedicated sponsor key before production load.
     */
    constructor(address initialOwner, address initialSponsor)
        Ownable(initialOwner)
    {
        require(initialSponsor != address(0), "Zero sponsor");
        authorisedSponsors[initialSponsor] = true;
        emit SponsorAdded(initialSponsor);
    }

    /**
     * @notice Register a new event on-chain.
     * @param supply      Number of claimable slots (ticket supply). Must be > 0.
     * @param manifestRef keccak256(dagCbor(manifestBody)) — the same digest the
     *                    organiser's ed25519 signature covers, and what offline
     *                    scanners verify against. Computed by `manifestDigest()`
     *                    in `packages/shared/src/pod/canonical.ts`.
     * @return eventId    Derived deterministically: keccak256(abi.encode(msg.sender,
     *                    organiserNonce[msg.sender]++)). Nonce is read then bumped.
     */
    function registerEvent(uint256 supply, bytes32 manifestRef)
        external
        returns (bytes32 eventId)
    {
        require(supply > 0, "Supply must be > 0");
        require(manifestRef != bytes32(0), "Zero manifestRef");

        // Post-increment: eventId uses nonce value BEFORE the bump.
        // organiserNonce becomes nonce+1 after this line.
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
     *         Called by the platform sponsor wallet on Stripe webhook receipt.
     * @param eventId   The registered event.
     * @param burner    Buyer's client-generated burner address. Platform never
     *                  sees the corresponding private key.
     * @param orderRef  keccak256 of the SealedBox upload ref (encrypted buyer
     *                  order data on Swarm). Carried in the SlotClaimed event
     *                  so the chain log is the claims index — no Swarm feed
     *                  walk required for dashboard reconstruction.
     * @return slot     0-based slot index. Corresponds to POD edition `slot + 1`
     *                  in the 1-based Mantaray manifest.
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
        ev.nextSlot = slot + 1;
        slotOwner[eventId][slot] = burner;
        slotOrderRef[eventId][slot] = orderRef;

        emit SlotClaimed(eventId, slot, burner, orderRef);
    }

    /**
     * @notice Convenience view: return the slot owner and encrypted-order ref together.
     *         Organiser calls this for each slot 0..nextSlot-1 to reconstruct the
     *         attendee list without walking any Swarm feed.
     */
    function getSlotData(bytes32 eventId, uint256 slot)
        external
        view
        returns (address owner, bytes32 orderRef)
    {
        return (slotOwner[eventId][slot], slotOrderRef[eventId][slot]);
    }

    /**
     * @notice Authorise a new sponsor wallet to call claimFor.
     *         Only the multisig owner can call this.
     */
    function addSponsor(address sponsor) external onlyOwner {
        require(sponsor != address(0), "Zero address");
        authorisedSponsors[sponsor] = true;
        emit SponsorAdded(sponsor);
    }

    /**
     * @notice Revoke a sponsor wallet's claim authority.
     *         Only the multisig owner can call this.
     */
    function removeSponsor(address sponsor) external onlyOwner {
        authorisedSponsors[sponsor] = false;
        emit SponsorRemoved(sponsor);
    }
}
