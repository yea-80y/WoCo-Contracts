// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable2Step, Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";

/**
 * @title WoCoTicketLedger
 * @notice Allocation ledger for event tickets. Mints slots; never holds funds.
 *
 * This contract is the successor to WoCoEventV2 with all payment handling
 * removed. Money lives in a separate, independently-audited and independently
 * replaceable contract (WoCoPayments). The split exists so that replacing the
 * money contract never puts the ticket ledger back in front of an auditor.
 *
 * ── The guarantee this contract makes ────────────────────────────────────────
 *
 *   On an event it did not itself register, sponsor authority grants exactly
 *   ONE power: appending new slots — within the supply stamped at
 *   registration, before `eventEndTs`, and only while not cancelled.
 *
 * Sponsors cannot cancel such an event, cannot alter its stamped terms, and
 * cannot touch slots that already exist. That statement is what a payments
 * contract — present or future, correct or buggy — is audited against, and it
 * holds for every sponsor without re-reading this contract.
 *
 * Stated precisely, because the scope matters: `registerEvent` is
 * PERMISSIONLESS. A sponsor may therefore also register its own events and,
 * having stamped itself as their organiser, cancel those. That is not sponsor
 * authority — it is what any address can do, and it reaches only events that
 * caller created. The guarantee above is about the events it did not.
 *
 * ── The trust boundary with WoCoPayments ─────────────────────────────────────
 *
 * The dependency is one-directional: payments reads this ledger, this ledger
 * never reads or calls payments. Payments live-reads `cancelled` and
 * `eventEndTs` rather than stamping copies, because this contract is deployed
 * once and never replaced — its immutability is enforced by its own bytecode,
 * so a live read cannot drift while a stamped copy can.
 *
 * The direction that must hold: NO state transition here may ever make
 * payments less conservative. Every bit payments can read may only close sales
 * or open refunds — never accelerate, enlarge, or redirect a payout.
 *   - `cancelled` is one-way (false → true). It only stops mints and opens
 *     refunds.
 *   - `eventEndTs` is immutable. Release time downstream is `eventEndTs +
 *     releaseDelay`, so it can never be pulled earlier than buyers agreed to.
 *
 * COROLLARY, for anyone who later makes the sales cutoff mutable (see #294):
 * it must be MONOTONIC-INCREASE-ONLY. Extending the cutoff delays release,
 * which is conservative. Shortening it pulls the organiser's withdrawal
 * forward, which is the rug this rule exists to prevent.
 *
 * NOTE FOR THE PAYMENTS SPEC: WoCoEventV2 ordered cancel-before-withdraw
 * inside one contract (`cancelEvent` reverted `AlreadyWithdrawn`). Split
 * apart, this ledger cannot see whether payments has paid out, so the state
 * (cancelled = true, withdrawn = true) is reachable: an organiser may withdraw
 * on payments after release, then cancel here. Payments MUST therefore treat
 * `cancelled` as NECESSARY BUT NOT SUFFICIENT for a refund and gate on its own
 * withdrawn/balance state. `cancelled` opens refunds only out of escrow that
 * payments still holds.
 *
 * ── Why there is no drop gate ────────────────────────────────────────────────
 *
 * WoCoEventV2 carried a `dropGate` whose only two call sites were on the
 * payment paths; the sponsor paths never consulted it. Rather than wire an
 * organiser-chosen external call into the middle of card fulfilment — where a
 * reverting gate would fail a mint for a payment already taken — mint
 * eligibility is decided BEFORE money moves, by whichever sponsor is calling.
 * A gate belongs in the sponsor contract, not here: this ledger has no
 * permissionless mint path, so it has nothing to gate.
 *
 * ── Identity ─────────────────────────────────────────────────────────────────
 *
 * `organiser` is stamped explicitly and is NOT the caller. In production the
 * registrant is the platform's sponsor wallet acting on the organiser's
 * behalf, so `msg.sender` identifies the platform, not the event's owner.
 * A future self-registration path passes its own address here.
 *
 * WARNING — `organiser` IS AN ASSERTION, NOT A PROOF. Registration is
 * permissionless and the parameter is unauthenticated: any caller may register
 * an event naming any address as organiser, and `Registered` will carry that
 * address in its indexed `organiser` topic. Only `registrant` is authenticated
 * (it is `msg.sender`). Indexers and any future consumer MUST NOT treat a
 * `Registered` log as evidence that the named organiser consented; filter on
 * `registrant`, or require a signature at a higher layer. The consequence
 * inside this contract is contained: a stamped organiser can only ever cancel
 * the event that named them, which is buyer-protective and one-way.
 *
 * `registrantNonce` is keyed by the REGISTRANT (`msg.sender`), not by
 * `organiser` — it is the eventId derivation counter. Renamed from V1/V2's
 * `organiserNonce`, which became a misnomer the moment `organiser` stopped
 * being `msg.sender`: on a contract deployed once and read by auditors, a
 * permanent misnomer costs more than a rename in a cascade already happening.
 *
 * ── No reentrancy guard, deliberately ────────────────────────────────────────
 *
 * There is not a single external call in this contract — no token transfers,
 * no gate callback, no hook. Nothing here can re-enter, so there is no guard,
 * and its absence is the accurate signal. WoCoEventV2 needed `ReentrancyGuard`
 * because it moved ERC-20 and invoked an organiser-supplied gate; both are
 * gone. Carrying the guard anyway would cost gas on the hottest path and imply
 * a hazard an auditor would then waste time hunting for.
 *
 * Slot indices are 0-based (matches v1 and V2).
 */
contract WoCoTicketLedger is Ownable2Step {
    /// Packed layout — 3 storage slots (V2 used 5).
    ///
    /// Slot 0: totalSupply(64) + nextSlot(64) + eventEndTs(64) + exists(8) + cancelled(8)
    /// Slot 1: organiser(160)
    /// Slot 2: manifestRef(256)
    struct Event {
        // ---- slot 0 ----
        uint64 totalSupply;
        uint64 nextSlot;
        uint64 eventEndTs;
        bool   exists;
        bool   cancelled;
        // ---- slot 1 ----
        address organiser;
        // ---- slot 2 ----
        bytes32 manifestRef;
    }

    /// Packed: address (20) + uint64 (8) = 28 bytes, one SSTORE per slot.
    struct Slot {
        address owner;
        uint64  batchFirstSlot;
    }

    // ── Storage ───────────────────────────────────────────────────────────────

    /// Address allowed to `forceCancelEvent`. Initially the owner; designed to
    /// be rotated to a multisig / DAO. Deliberately NOT the payments contract:
    /// keeping this a human-controlled address is what keeps the dependency
    /// one-directional.
    address public disputeAuthority;

    mapping(bytes32 => Event) private _events;
    mapping(bytes32 => mapping(uint256 => Slot)) public slots;
    mapping(bytes32 => mapping(uint64 => bytes32)) public batchOrderRef;
    mapping(bytes32 => mapping(uint64 => address)) public batchClaimer;

    /// eventId derivation counter, keyed by REGISTRANT. See the note above.
    mapping(address => uint256) public registrantNonce;

    /// Addresses permitted to mint. The Stripe webhook's sponsor wallet today;
    /// WoCoPayments once it ships; any future sponsor contract after that.
    mapping(address => bool) public authorisedSponsors;

    // ── Events ────────────────────────────────────────────────────────────────

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

    event SponsorAdded(address indexed sponsor);
    event SponsorRemoved(address indexed sponsor);
    event DisputeAuthorityUpdated(address indexed authority);

    // ── Errors ────────────────────────────────────────────────────────────────

    error EventNotFound();
    error BatchEmpty();
    error BatchTooLarge();
    error InsufficientSupply();
    error ZeroAddress();
    error NotAuthorised();
    error NotOrganiser();
    error NotDisputeAuthority();
    error AlreadyCancelled();
    error InvalidEventEnd();
    error SalesClosed();

    // ── Modifiers ─────────────────────────────────────────────────────────────

    modifier onlyAuthorised() {
        if (!authorisedSponsors[msg.sender]) revert NotAuthorised();
        _;
    }

    modifier onlyDisputeAuthority() {
        if (msg.sender != disputeAuthority) revert NotDisputeAuthority();
        _;
    }

    // ── Constructor ───────────────────────────────────────────────────────────

    constructor(address initialOwner, address initialSponsor) Ownable(initialOwner) {
        if (initialSponsor == address(0)) revert ZeroAddress();

        disputeAuthority = initialOwner;

        authorisedSponsors[initialSponsor] = true;
        emit SponsorAdded(initialSponsor);
        emit DisputeAuthorityUpdated(initialOwner);
    }

    // ── Event lifecycle ───────────────────────────────────────────────────────

    /**
     * @notice Register a new event.
     * @param organiser    The event's owner of record. NOT the caller: in
     *                     production the caller is the platform's sponsor
     *                     wallet registering on the organiser's behalf. This
     *                     is the address that may later `cancelEvent`.
     * @param supply       Total tickets. Must fit in uint64 and be non-zero.
     * @param manifestRef  Off-chain ticket-manifest commit.
     * @param eventEndTs   UNIX seconds; the on-chain sales cutoff. `claimFor`
     *                     reverts `SalesClosed` at or after this. Immutable
     *                     once stamped — see the monotonicity note above.
     */
    function registerEvent(
        address organiser,
        uint64  supply,
        bytes32 manifestRef,
        uint64  eventEndTs
    ) external returns (bytes32 eventId) {
        if (organiser == address(0))       revert ZeroAddress();
        if (supply == 0)                   revert InsufficientSupply();
        if (manifestRef == bytes32(0))     revert ZeroAddress();
        if (eventEndTs <= block.timestamp) revert InvalidEventEnd();

        // DOMAIN-SEPARATED by chain and contract, then keyed by the registrant.
        //
        // WoCoEventV2 hashed only (msg.sender, nonce). That makes an id
        // ambiguous about WHICH deployment it belongs to, and two concrete
        // collisions follow from it:
        //   · A successor contract registering from the same sponsor wallet
        //     reproduces the predecessor's ids exactly, because its nonce
        //     starts at 0 again. Ids stored off chain (Swarm feeds outlive any
        //     migration) would then resolve against the new contract and, once
        //     its count passed them, silently return a DIFFERENT event.
        //   · The same contract deployed to two chains yields identical ids —
        //     already true of V1 on Base Sepolia and Arbitrum Sepolia.
        //
        // Including `block.chainid` and `address(this)` makes an id unique per
        // (chain, contract, registrant, nonce), so those collisions are not
        // merely unlikely but unrepresentable. This is the same discipline as
        // the EIP-712 domain separators used elsewhere in the platform, and it
        // is why the fix is structural rather than a rule about never reusing
        // a sponsor wallet — a rule that holds only until someone forgets it.
        //
        // The off-chain mirror of this formula lives in the server's
        // `deriveEventId` (lib/event/onchain-registry.ts). Changing one without
        // the other makes the registration walk silently find nothing, which
        // reads as "never registered" and re-broadcasts a duplicate.
        eventId = keccak256(
            abi.encode(block.chainid, address(this), msg.sender, registrantNonce[msg.sender]++)
        );

        _events[eventId] = Event({
            totalSupply: supply,
            nextSlot:    0,
            eventEndTs:  eventEndTs,
            exists:      true,
            cancelled:   false,
            organiser:   organiser,
            manifestRef: manifestRef
        });

        emit Registered(eventId, organiser, msg.sender, supply, manifestRef, eventEndTs);
    }

    // ── Mint paths (authorised sponsors only) ─────────────────────────────────

    /**
     * @notice Mint a single slot. Authorised sponsors only. No funds move here
     *         — whoever called has already settled payment on their own side.
     */
    function claimFor(bytes32 eventId, address owner, bytes32 orderRef)
        external
        onlyAuthorised
        returns (uint256 slot)
    {
        if (owner == address(0)) revert ZeroAddress();
        Event storage ev = _events[eventId];
        if (!ev.exists)                       revert EventNotFound();
        if (ev.cancelled)                     revert AlreadyCancelled();
        if (block.timestamp >= ev.eventEndTs) revert SalesClosed();
        if (ev.nextSlot >= ev.totalSupply)    revert InsufficientSupply();

        uint64 first = ev.nextSlot;
        slot = uint256(first);
        // safe: first < totalSupply ≤ uint64.max
        unchecked { ev.nextSlot = first + 1; }

        slots[eventId][slot] = Slot({owner: owner, batchFirstSlot: first});
        batchOrderRef[eventId][first] = orderRef;
        batchClaimer[eventId][first]  = msg.sender;

        emit SlotClaimed(eventId, slot, owner, msg.sender, orderRef);
    }

    /**
     * @notice Mint N contiguous slots in one call. Authorised sponsors only.
     */
    function batchClaimFor(
        bytes32 eventId,
        address[] calldata owners,
        bytes32 orderRef
    ) external onlyAuthorised returns (uint256 firstSlot) {
        uint256 n = owners.length;
        if (n == 0)  revert BatchEmpty();
        if (n > 100) revert BatchTooLarge();
        // n ≤ 100 ⇒ fits trivially in uint64
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 n64 = uint64(n);

        Event storage ev = _events[eventId];
        if (!ev.exists)                       revert EventNotFound();
        if (ev.cancelled)                     revert AlreadyCancelled();
        if (block.timestamp >= ev.eventEndTs) revert SalesClosed();

        uint64 first = ev.nextSlot;
        firstSlot = uint256(first);
        unchecked {
            if (uint256(first) + n > ev.totalSupply) revert InsufficientSupply();
        }

        batchOrderRef[eventId][first] = orderRef;
        batchClaimer[eventId][first]  = msg.sender;

        for (uint256 i; i < n;) {
            address owner = owners[i];
            if (owner == address(0)) revert ZeroAddress();
            uint256 s;
            unchecked { s = firstSlot + i; }
            slots[eventId][s] = Slot({owner: owner, batchFirstSlot: first});
            emit SlotClaimed(eventId, s, owner, msg.sender, orderRef);
            unchecked { ++i; }
        }

        unchecked { ev.nextSlot = first + n64; }
    }

    // ── Cancellation ──────────────────────────────────────────────────────────

    /**
     * @notice Cancel an event. One-way. Stops all further minting, and lets a
     *         payments contract open refunds for whatever it still holds.
     *
     *         Organiser only. Sponsors deliberately CANNOT cancel — that is
     *         what keeps the sponsor capability to "append slots" and nothing
     *         more. The platform cancels through `forceCancelEvent`, which is
     *         a separate, separately-visible power.
     */
    function cancelEvent(bytes32 eventId) external {
        Event storage ev = _events[eventId];
        if (!ev.exists)                 revert EventNotFound();
        if (msg.sender != ev.organiser) revert NotOrganiser();
        if (ev.cancelled)               revert AlreadyCancelled();

        ev.cancelled = true;
        emit EventCancelled(eventId, msg.sender);
    }

    /**
     * @notice Cancel an event when the organiser will not — or cannot. Dispute
     *         authority only. Same one-way flag as `cancelEvent`; separate
     *         entrypoint so the power is distinguishable on chain from an
     *         organiser's own cancellation.
     *
     *         "or cannot" is load-bearing today: no code in the platform calls
     *         `cancelEvent` yet, so until an organiser-facing cancel is wired
     *         (the stamped organiser is a Kernel smart account or EOA and can
     *         call it directly — the sponsored-userop rail already exists for
     *         EAS attestations), every real cancellation arrives here. If the
     *         server should instead relay an organiser's cancellation, this
     *         contract needs a signature-authorised `cancelEventBySig` and it
     *         must be added BEFORE deploy — the contract is immutable.
     *
     *         This is buyer-protective and one-way: it can only stop minting
     *         and open refunds, never move money toward the organiser. A
     *         compromised dispute-authority key can grief (stop sales, force
     *         refunds to original payers); it cannot steal.
     */
    function forceCancelEvent(bytes32 eventId) external onlyDisputeAuthority {
        Event storage ev = _events[eventId];
        if (!ev.exists)   revert EventNotFound();
        if (ev.cancelled) revert AlreadyCancelled();

        ev.cancelled = true;
        emit EventCancelled(eventId, msg.sender);
    }

    // ── Views ─────────────────────────────────────────────────────────────────

    /// @notice Core event params stamped at registration.
    function getEvent(bytes32 eventId)
        external
        view
        returns (
            uint64 totalSupply,
            uint64 nextSlot,
            address organiser,
            bytes32 manifestRef
        )
    {
        Event memory ev = _events[eventId];
        if (!ev.exists) revert EventNotFound();
        return (ev.totalSupply, ev.nextSlot, ev.organiser, ev.manifestRef);
    }

    /// @notice Sales cutoff + cancellation state. These are the two bits a
    ///         payments contract live-reads across the boundary.
    function getEventStatus(bytes32 eventId)
        external
        view
        returns (uint64 eventEndTs, bool cancelled)
    {
        Event memory ev = _events[eventId];
        if (!ev.exists) revert EventNotFound();
        return (ev.eventEndTs, ev.cancelled);
    }

    /// @notice Slot owner plus the batch attribution it was minted under.
    /// @dev CALLERS MUST CHECK `owner` FIRST. An unclaimed slot has no batch,
    ///      so `batchFirstSlot` reads as its default 0 and the other two
    ///      returns are those of the batch at slot 0 — real data belonging to
    ///      a different slot, not zero values. `owner == address(0)` means the
    ///      slot is unclaimed and `claimer`/`orderRef` MUST be ignored.
    ///      (Inherited from V2; payments will read this view.)
    function getSlotData(bytes32 eventId, uint256 slot)
        external
        view
        returns (address owner, address claimer, bytes32 orderRef)
    {
        Slot memory sd = slots[eventId][slot];
        return (
            sd.owner,
            batchClaimer[eventId][sd.batchFirstSlot],
            batchOrderRef[eventId][sd.batchFirstSlot]
        );
    }

    function slotOwner(bytes32 eventId, uint256 slot) external view returns (address) {
        return slots[eventId][slot].owner;
    }

    function remaining(bytes32 eventId) external view returns (uint256) {
        Event memory ev = _events[eventId];
        if (!ev.exists) return 0;
        return ev.totalSupply - ev.nextSlot;
    }

    // ── Admin ─────────────────────────────────────────────────────────────────

    function addSponsor(address sponsor) external onlyOwner {
        if (sponsor == address(0)) revert ZeroAddress();
        authorisedSponsors[sponsor] = true;
        emit SponsorAdded(sponsor);
    }

    function removeSponsor(address sponsor) external onlyOwner {
        authorisedSponsors[sponsor] = false;
        emit SponsorRemoved(sponsor);
    }

    function setDisputeAuthority(address authority) external onlyOwner {
        if (authority == address(0)) revert ZeroAddress();
        disputeAuthority = authority;
        emit DisputeAuthorityUpdated(authority);
    }
}
