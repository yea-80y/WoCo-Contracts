// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable2Step, Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/**
 * @title WoCoEventV2
 * @notice On-chain ticket registry with buyer-pays-directly + escrow.
 *
 * Buyer flow:
 *   `payAndClaim` / `batchPayAndClaim` pulls USDC, mints slot(s) atomically,
 *   and holds the proceeds in this contract. Funds are released to the
 *   organiser only after `eventEndTs + releaseDelay`, and only if the event
 *   is not cancelled or frozen.
 *
 * Stripe coexistence:
 *   `claimFor` / `batchClaimFor` mint without pulling token. These paths
 *   do NOT enter escrow — fiat is held/refunded by Stripe off-chain.
 *
 * Refunds:
 *   The organiser may cancel any unfinished event with `cancelEvent`.
 *   Buyers of crypto-paid slots then call `claimRefund(eventId, slot)` to
 *   pull back the gross they paid (including platform fee). Stripe slots
 *   are refunded via Stripe — this contract holds none of their money.
 *
 * Dispute hooks:
 *   `disputeAuthority` (initially the contract owner — DAO-swappable later)
 *   can `freezeEvent` an individual event to pause withdrawal during a
 *   dispute, and `forceCancelEvent` to open refunds when an organiser is
 *   a bad actor. No contract-wide pause exists by design.
 *
 * Out of scope (future):
 *   - Organiser bond at registration (slashed on upheld dispute).
 *   - Yield on idle escrow USDC — via a separate `WoCoYieldVault` companion.
 *   - On-chain reputation scoring (consume events emitted here).
 *   - Native ETH payments / commit-reveal lottery (separate companions).
 *
 * Storage layout (per-slot is one packed SSTORE):
 *   slots[eventId][slot]              = (address owner, uint64 batchFirstSlot)
 *   batchOrderRef[eventId][firstSlot] = bytes32 orderRef
 *   batchClaimer[eventId][firstSlot]  = address payer
 *   batchEscrowed[eventId][firstSlot] = bool   (true if paid via crypto path)
 *
 * Slot indices are 0-based (matches v1).
 */
contract WoCoEventV2 is Ownable2Step, ReentrancyGuard {
    using SafeERC20 for IERC20;

    /// Packed layout — 5 storage slots.
    ///
    /// Slot 0: priceBaseUnits(128) + totalSupply(64) + nextSlot(64)             = 256
    /// Slot 1: organiser(160) + platformFeeBps(16) + flags(32) + releaseDelay(32) + spare(16) = 256
    ///         flags = cancelled(8) + withdrawn(8) + frozen(8) + exists(8)
    /// Slot 2: payoutRecipient(160) + eventEndTs(64) + spare(32)                = 256
    /// Slot 3: dropGate(160) + spare(96)                                         = 256
    /// Slot 4: manifestRef(256)
    struct Event {
        // ---- slot 0 ----
        uint128 priceBaseUnits;
        uint64  totalSupply;
        uint64  nextSlot;
        // ---- slot 1 ----
        address organiser;
        uint16  platformFeeBps;
        bool    exists;
        bool    cancelled;
        bool    withdrawn;
        bool    frozen;
        uint32  releaseDelay;
        // ---- slot 2 ----
        address payoutRecipient;
        uint64  eventEndTs;
        // ---- slot 3 ----
        address dropGate;
        // ---- slot 4 ----
        bytes32 manifestRef;
    }

    /// Packed: address (20) + uint64 (8) = 28 bytes, one SSTORE per slot.
    struct Slot {
        address owner;
        uint64  batchFirstSlot;
    }

    // ── Storage ───────────────────────────────────────────────────────────────

    IERC20 public immutable paymentToken;
    address public platformTreasury;
    uint16  public defaultPlatformFeeBps;

    /// Default delay between `eventEndTs` and when organiser may withdraw.
    /// Per-event value is stamped at registration so later owner changes
    /// cannot retroactively alter the agreement with the buyer.
    uint32  public defaultReleaseDelay;

    /// Address allowed to `freezeEvent` / `forceCancelEvent`. Initially the
    /// owner; designed to be swappable to a DAO / multisig later.
    address public disputeAuthority;

    mapping(bytes32 => Event) private _events;
    mapping(bytes32 => mapping(uint256 => Slot)) public slots;
    mapping(bytes32 => mapping(uint64 => bytes32)) public batchOrderRef;
    mapping(bytes32 => mapping(uint64 => address)) public batchClaimer;
    mapping(bytes32 => mapping(uint64 => bool))    public batchEscrowed;
    mapping(bytes32 => mapping(uint256 => bool))   public slotRefunded;
    mapping(bytes32 => uint256) public escrowBalance;
    mapping(address => uint256) public organiserNonce;

    /// Legacy authorised-sponsor set: kept so the Stripe webhook path
    /// (`claimFor`) keeps working during the v1 → v2 transition.
    mapping(address => bool) public authorisedSponsors;

    // ── Events ────────────────────────────────────────────────────────────────

    event Registered(
        bytes32 indexed eventId,
        address indexed organiser,
        uint64 supply,
        uint128 priceBaseUnits,
        address payoutRecipient,
        address dropGate,
        bytes32 manifestRef,
        uint64  eventEndTs,
        uint32  releaseDelay
    );

    event SlotClaimed(
        bytes32 indexed eventId,
        uint256 indexed slot,
        address indexed owner,
        address claimer,
        bytes32 orderRef
    );

    event PaymentSettled(
        bytes32 indexed eventId,
        address indexed claimer,
        uint64 firstSlot,
        uint64 quantity,
        uint256 gross
    );

    event EventCancelled(bytes32 indexed eventId, address indexed by);
    event EventFrozen(bytes32 indexed eventId, bool frozen);
    event EventWithdrawn(bytes32 indexed eventId, uint256 gross, uint256 fee, uint256 net);
    event SlotRefunded(bytes32 indexed eventId, uint256 indexed slot, address indexed to, uint256 amount);

    event SponsorAdded(address indexed sponsor);
    event SponsorRemoved(address indexed sponsor);
    event PlatformTreasuryUpdated(address indexed treasury);
    event DefaultFeeUpdated(uint16 bps);
    event DefaultReleaseDelayUpdated(uint32 delay);
    event DisputeAuthorityUpdated(address indexed authority);

    // ── Errors ────────────────────────────────────────────────────────────────

    error EventNotFound();
    error BatchEmpty();
    error BatchTooLarge();
    error InsufficientSupply();
    error ZeroAddress();
    error FeeTooHigh();
    error GateVetoed();
    error NotAuthorised();
    error NotOrganiser();
    error NotDisputeAuthority();
    error AlreadyCancelled();
    error AlreadyWithdrawn();
    error EventIsFrozen();
    error TooEarly();
    error NotCancelled();
    error NotEscrowed();
    error AlreadyRefunded();
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

    constructor(
        address initialOwner,
        address initialSponsor,
        IERC20  paymentToken_,
        address platformTreasury_,
        uint16  defaultPlatformFeeBps_
    ) Ownable(initialOwner) {
        if (initialSponsor == address(0))     revert ZeroAddress();
        if (address(paymentToken_) == address(0)) revert ZeroAddress();
        if (platformTreasury_ == address(0))  revert ZeroAddress();
        if (defaultPlatformFeeBps_ > 1_000)   revert FeeTooHigh(); // ≤ 10 %

        paymentToken          = paymentToken_;
        platformTreasury      = platformTreasury_;
        defaultPlatformFeeBps = defaultPlatformFeeBps_;
        defaultReleaseDelay   = 24 hours;
        disputeAuthority      = initialOwner;

        authorisedSponsors[initialSponsor] = true;
        emit SponsorAdded(initialSponsor);
        emit PlatformTreasuryUpdated(platformTreasury_);
        emit DefaultFeeUpdated(defaultPlatformFeeBps_);
        emit DefaultReleaseDelayUpdated(24 hours);
        emit DisputeAuthorityUpdated(initialOwner);
    }

    // ── Event lifecycle ───────────────────────────────────────────────────────

    /**
     * @notice Register a new event. Caller becomes the organiser of record.
     * @param supply           Total tickets to mint. Must fit in uint64.
     * @param priceBaseUnits   Per-ticket price in payment-token base units.
     * @param payoutRecipient  Address that receives funds at withdraw time.
     * @param dropGate         Optional gate contract; address(0) = open FIFO.
     * @param manifestRef      Off-chain ticket-manifest commit.
     * @param eventEndTs       UNIX seconds when withdrawal eligibility starts
     *                         counting (event end). Must be > block.timestamp.
     *                         Use a sensible default if "no fixed end".
     */
    function registerEvent(
        uint64  supply,
        uint128 priceBaseUnits,
        address payoutRecipient,
        address dropGate,
        bytes32 manifestRef,
        uint64  eventEndTs
    ) external returns (bytes32 eventId) {
        if (supply == 0)                       revert InsufficientSupply();
        if (payoutRecipient == address(0))     revert ZeroAddress();
        if (manifestRef == bytes32(0))         revert ZeroAddress();
        if (eventEndTs <= block.timestamp)     revert InvalidEventEnd();

        eventId = keccak256(abi.encode(msg.sender, organiserNonce[msg.sender]++));

        uint32 delay = defaultReleaseDelay;

        _events[eventId] = Event({
            priceBaseUnits:   priceBaseUnits,
            totalSupply:      supply,
            nextSlot:         0,
            organiser:        msg.sender,
            payoutRecipient:  payoutRecipient,
            platformFeeBps:   defaultPlatformFeeBps,
            dropGate:         dropGate,
            exists:           true,
            cancelled:        false,
            withdrawn:        false,
            frozen:           false,
            releaseDelay:     delay,
            eventEndTs:       eventEndTs,
            manifestRef:      manifestRef
        });

        emit Registered(
            eventId,
            msg.sender,
            supply,
            priceBaseUnits,
            payoutRecipient,
            dropGate,
            manifestRef,
            eventEndTs,
            delay
        );
    }

    // ── Buyer claim path (the agent-friendly, no-server primitive) ────────────

    /**
     * @notice Pay for and atomically claim one ticket. Funds enter escrow.
     */
    function payAndClaim(bytes32 eventId, address owner, bytes32 orderRef)
        external
        nonReentrant
        returns (uint256 slot)
    {
        return _payAndClaim(msg.sender, eventId, owner, orderRef);
    }

    function _payAndClaim(
        address payer,
        bytes32 eventId,
        address owner,
        bytes32 orderRef
    ) internal returns (uint256 slot) {
        if (owner == address(0)) revert ZeroAddress();
        Event storage ev = _events[eventId];
        if (!ev.exists)                          revert EventNotFound();
        if (ev.cancelled)                        revert AlreadyCancelled();
        if (block.timestamp >= ev.eventEndTs)    revert SalesClosed();
        if (ev.nextSlot >= ev.totalSupply)       revert InsufficientSupply();

        // CEI: write slot state BEFORE invoking the external gate. Combined
        // with `nonReentrant` on every fund-moving entrypoint, a malicious
        // gate cannot re-enter to read a stale `nextSlot`.
        uint64 first = ev.nextSlot;
        slot = uint256(first);
        // safe: first < totalSupply ≤ uint64.max
        unchecked { ev.nextSlot = first + 1; }

        slots[eventId][slot] = Slot({owner: owner, batchFirstSlot: first});
        batchOrderRef[eventId][first] = orderRef;
        batchClaimer[eventId][first]  = payer;

        _runGate(ev.dropGate, eventId, payer, owner, 1);

        emit SlotClaimed(eventId, slot, owner, payer, orderRef);

        _settle(ev, eventId, payer, first, 1);
    }

    /**
     * @notice Pay for and atomically claim N contiguous tickets.
     */
    function batchPayAndClaim(
        bytes32 eventId,
        address[] calldata owners,
        bytes32 orderRef
    ) external nonReentrant returns (uint256 firstSlot) {
        uint256 n = owners.length;
        if (n == 0)  revert BatchEmpty();
        if (n > 100) revert BatchTooLarge();
        // n ≤ 100 ⇒ fits trivially in uint64
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 n64 = uint64(n);

        Event storage ev = _events[eventId];
        if (!ev.exists)   revert EventNotFound();
        if (ev.cancelled) revert AlreadyCancelled();
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

        // CEI: gate runs AFTER all slot state is written, so a malicious
        // dropGate cannot re-enter and observe a stale `nextSlot`. `nonReentrant`
        // on this entrypoint also forecloses re-entrant claim paths.
        _runGate(ev.dropGate, eventId, msg.sender, address(0), n64);

        _settle(ev, eventId, msg.sender, first, n64);
    }

    /**
     * @notice One-tx `permit` + claim. Saves the user a separate `approve`.
     */
    function payAndClaimWithPermit(
        bytes32 eventId,
        address owner,
        bytes32 orderRef,
        uint256 permitValue,
        uint256 permitDeadline,
        uint8   v,
        bytes32 r,
        bytes32 s
    ) external nonReentrant returns (uint256) {
        try IERC20Permit(address(paymentToken)).permit(
            msg.sender,
            address(this),
            permitValue,
            permitDeadline,
            v, r, s
        ) {} catch {}

        return _payAndClaim(msg.sender, eventId, owner, orderRef);
    }

    // ── Legacy sponsor path (Stripe webhook transition) ───────────────────────

    /// @notice Mint a single slot WITHOUT pulling payment. Authorised sponsors
    ///         only. Used by the Stripe webhook for card-paid tickets where
    ///         fiat settled off chain — funds NOT placed in this contract's
    ///         escrow (Stripe handles refunds for its own settlements).
    function claimFor(bytes32 eventId, address owner, bytes32 orderRef)
        external
        nonReentrant
        onlyAuthorised
        returns (uint256 slot)
    {
        if (owner == address(0)) revert ZeroAddress();
        Event storage ev = _events[eventId];
        if (!ev.exists)                    revert EventNotFound();
        if (ev.cancelled)                  revert AlreadyCancelled();
        if (block.timestamp >= ev.eventEndTs) revert SalesClosed();
        if (ev.nextSlot >= ev.totalSupply) revert InsufficientSupply();

        uint64 first = ev.nextSlot;
        slot = uint256(first);
        unchecked { ev.nextSlot = first + 1; }

        slots[eventId][slot] = Slot({owner: owner, batchFirstSlot: first});
        batchOrderRef[eventId][first] = orderRef;
        batchClaimer[eventId][first]  = msg.sender;
        // batchEscrowed stays false — no on-chain refund obligation.

        emit SlotClaimed(eventId, slot, owner, msg.sender, orderRef);
    }

    function batchClaimFor(
        bytes32 eventId,
        address[] calldata owners,
        bytes32 orderRef
    ) external nonReentrant onlyAuthorised returns (uint256 firstSlot) {
        uint256 n = owners.length;
        if (n == 0)  revert BatchEmpty();
        if (n > 100) revert BatchTooLarge();
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 n64 = uint64(n);

        Event storage ev = _events[eventId];
        if (!ev.exists)   revert EventNotFound();
        if (ev.cancelled) revert AlreadyCancelled();
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

    // ── Escrow lifecycle ──────────────────────────────────────────────────────

    /**
     * @notice Cancel an event. Once cancelled, no further claims may occur
     *         and buyers of crypto-paid slots may pull refunds via
     *         `claimRefund`. Stripe fiat refunds happen off-chain.
     */
    function cancelEvent(bytes32 eventId) external {
        Event storage ev = _events[eventId];
        if (!ev.exists)             revert EventNotFound();
        if (msg.sender != ev.organiser) revert NotOrganiser();
        if (ev.cancelled)           revert AlreadyCancelled();
        if (ev.withdrawn)           revert AlreadyWithdrawn();

        ev.cancelled = true;
        emit EventCancelled(eventId, msg.sender);
    }

    /**
     * @notice Organiser withdraws escrowed proceeds. Eligible only after
     *         `eventEndTs + releaseDelay`, and only if not cancelled or
     *         frozen. Platform fee is taken at this step (not at claim time)
     *         so that fees are also refundable in the cancellation path.
     */
    function withdraw(bytes32 eventId) external nonReentrant {
        Event storage ev = _events[eventId];
        if (!ev.exists)             revert EventNotFound();
        if (msg.sender != ev.organiser) revert NotOrganiser();
        if (ev.cancelled)           revert AlreadyCancelled();
        if (ev.frozen)              revert EventIsFrozen();
        if (ev.withdrawn)           revert AlreadyWithdrawn();
        if (block.timestamp < uint256(ev.eventEndTs) + uint256(ev.releaseDelay)) revert TooEarly();

        uint256 gross = escrowBalance[eventId];
        ev.withdrawn = true;
        escrowBalance[eventId] = 0;

        if (gross == 0) {
            emit EventWithdrawn(eventId, 0, 0, 0);
            return;
        }

        uint256 fee = (gross * ev.platformFeeBps) / 10_000;
        uint256 net;
        unchecked { net = gross - fee; }

        if (fee > 0) paymentToken.safeTransfer(platformTreasury, fee);
        paymentToken.safeTransfer(ev.payoutRecipient, net);

        emit EventWithdrawn(eventId, gross, fee, net);
    }

    /**
     * @notice Pull a refund for a single crypto-paid slot after the event
     *         has been cancelled. Refunds the gross paid (price including
     *         fee) to whoever originally paid for the batch. Stripe slots
     *         (no batchEscrowed) are out of scope — Stripe refunds those.
     */
    function claimRefund(bytes32 eventId, uint256 slot) external nonReentrant {
        Event storage ev = _events[eventId];
        if (!ev.exists)         revert EventNotFound();
        if (!ev.cancelled)      revert NotCancelled();
        if (slotRefunded[eventId][slot]) revert AlreadyRefunded();

        Slot memory sd = slots[eventId][slot];
        if (sd.owner == address(0)) revert EventNotFound(); // slot never claimed
        uint64 first = sd.batchFirstSlot;
        if (!batchEscrowed[eventId][first]) revert NotEscrowed();

        address recipient_ = batchClaimer[eventId][first];
        uint256 amount = uint256(ev.priceBaseUnits);

        slotRefunded[eventId][slot] = true;
        // safe: every escrowed slot contributed `priceBaseUnits` to the balance
        unchecked { escrowBalance[eventId] -= amount; }

        paymentToken.safeTransfer(recipient_, amount);
        emit SlotRefunded(eventId, slot, recipient_, amount);
    }

    // ── Dispute hooks ─────────────────────────────────────────────────────────

    /**
     * @notice Freeze or unfreeze a single event. Frozen events cannot be
     *         withdrawn from. Surgical, per-event only — there is no
     *         contract-wide pause by design.
     */
    function freezeEvent(bytes32 eventId, bool frozen) external onlyDisputeAuthority {
        Event storage ev = _events[eventId];
        if (!ev.exists) revert EventNotFound();
        ev.frozen = frozen;
        emit EventFrozen(eventId, frozen);
    }

    /**
     * @notice Force-cancel an event when the organiser is a bad actor and
     *         refuses to cancel themselves. Opens refunds for crypto buyers.
     *         Future iteration: gate behind on-chain dispute resolution.
     */
    function forceCancelEvent(bytes32 eventId) external onlyDisputeAuthority {
        Event storage ev = _events[eventId];
        if (!ev.exists)     revert EventNotFound();
        if (ev.cancelled)   revert AlreadyCancelled();
        if (ev.withdrawn)   revert AlreadyWithdrawn();

        ev.cancelled = true;
        emit EventCancelled(eventId, msg.sender);
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    function _settle(
        Event storage ev,
        bytes32 eventId,
        address payer,
        uint64 firstSlot,
        uint64 quantity
    ) internal {
        if (ev.priceBaseUnits == 0) {
            // Free events: no token movement, no escrow obligation.
            emit PaymentSettled(eventId, payer, firstSlot, quantity, 0);
            return;
        }

        uint256 gross = uint256(ev.priceBaseUnits) * quantity;

        // Hold the entire gross in this contract until withdraw or refund.
        paymentToken.safeTransferFrom(payer, address(this), gross);
        unchecked { escrowBalance[eventId] += gross; }
        batchEscrowed[eventId][firstSlot] = true;

        emit PaymentSettled(eventId, payer, firstSlot, quantity, gross);
    }

    function _runGate(
        address gate,
        bytes32 eventId,
        address claimer,
        address owner,
        uint64 quantity
    ) internal {
        if (gate == address(0)) return;
        // External call. Gates MUST be trusted (set by organiser at register).
        bool ok = IWoCoDropGate(gate).check(eventId, claimer, owner, quantity);
        if (!ok) revert GateVetoed();
    }

    // ── Views ─────────────────────────────────────────────────────────────────

    /// @notice Core event params stamped at registration.
    function getEvent(bytes32 eventId)
        external
        view
        returns (
            uint64 totalSupply,
            uint64 nextSlot,
            uint128 priceBaseUnits,
            address organiser,
            address payoutRecipient,
            uint16 platformFeeBps,
            address dropGate,
            bytes32 manifestRef
        )
    {
        Event memory ev = _events[eventId];
        if (!ev.exists) revert EventNotFound();
        return (
            ev.totalSupply,
            ev.nextSlot,
            ev.priceBaseUnits,
            ev.organiser,
            ev.payoutRecipient,
            ev.platformFeeBps,
            ev.dropGate,
            ev.manifestRef
        );
    }

    /// @notice Escrow / dispute status. Split from `getEvent` to keep both
    ///         within Solidity's return-stack budget.
    function getEventStatus(bytes32 eventId)
        external
        view
        returns (
            uint64 eventEndTs,
            uint32 releaseDelay,
            bool cancelled,
            bool withdrawn,
            bool frozen,
            uint256 escrow
        )
    {
        Event memory ev = _events[eventId];
        if (!ev.exists) revert EventNotFound();
        return (
            ev.eventEndTs,
            ev.releaseDelay,
            ev.cancelled,
            ev.withdrawn,
            ev.frozen,
            escrowBalance[eventId]
        );
    }

    function getSlotData(bytes32 eventId, uint256 slot)
        external
        view
        returns (address owner, address claimer, bytes32 orderRef, bool escrowed, bool refunded)
    {
        Slot memory sd = slots[eventId][slot];
        return (
            sd.owner,
            batchClaimer[eventId][sd.batchFirstSlot],
            batchOrderRef[eventId][sd.batchFirstSlot],
            batchEscrowed[eventId][sd.batchFirstSlot],
            slotRefunded[eventId][slot]
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

    function releaseTime(bytes32 eventId) external view returns (uint256) {
        Event memory ev = _events[eventId];
        if (!ev.exists) return 0;
        return uint256(ev.eventEndTs) + uint256(ev.releaseDelay);
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

    function setPlatformTreasury(address treasury) external onlyOwner {
        if (treasury == address(0)) revert ZeroAddress();
        platformTreasury = treasury;
        emit PlatformTreasuryUpdated(treasury);
    }

    function setDefaultPlatformFeeBps(uint16 bps) external onlyOwner {
        if (bps > 1_000) revert FeeTooHigh();
        defaultPlatformFeeBps = bps;
        emit DefaultFeeUpdated(bps);
    }

    function setDefaultReleaseDelay(uint32 delay) external onlyOwner {
        defaultReleaseDelay = delay;
        emit DefaultReleaseDelayUpdated(delay);
    }

    function setDisputeAuthority(address authority) external onlyOwner {
        if (authority == address(0)) revert ZeroAddress();
        disputeAuthority = authority;
        emit DisputeAuthorityUpdated(authority);
    }
}

/**
 * @notice Optional gate contract called before a claim is allocated.
 *
 *         Gate implementations veto by returning `false` or reverting.
 *         Examples (separate contracts, not in scope here):
 *           - WoCoSelfGate: requires Self proof-of-personhood for `claimer`
 *           - WoCoAllowlistGate: verifies an EIP-712 organiser signature
 *           - WoCoLotteryGate: confirms `owner` is a winning entrant from a
 *             prior commit-reveal + VRF round
 */
interface IWoCoDropGate {
    function check(
        bytes32 eventId,
        address claimer,
        address owner,
        uint64 quantity
    ) external returns (bool);
}
