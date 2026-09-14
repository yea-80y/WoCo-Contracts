// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable2Step, Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title WoCoTicketLedger
 * @notice Allocation ledger for event tickets. Mints slots and lets their
 *         owners move them; never holds funds.
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
 * ALSO FOR THE PAYMENTS SPEC — newly load-bearing since `transferSlot`: a
 * refund MUST bind to payments' OWN record of who paid, NEVER to a slot's
 * CURRENT owner. `owner` used to be immutable, so keying on it was merely
 * unusual; now a holder can move it, and a payments contract that read
 * `getSlotData(...).owner` to pick a payee would let a ledger transition
 * redirect money — the one thing the rule above forbids. WoCoEventV2 already
 * got this right by paying `batchClaimer` (WoCoEventV2.sol:537); keep that shape.
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
 * This contract never calls another contract — no token transfers, no gate
 * callback, no hook. Nothing here can re-enter, so there is no guard, and its
 * absence is the accurate signal. WoCoEventV2 needed `ReentrancyGuard` because
 * it moved ERC-20 and invoked an organiser-supplied gate; both are gone.
 * Carrying the guard anyway would cost gas on the hottest path and imply a
 * hazard an auditor would then waste time hunting for.
 *
 * The one call of any kind is the `ecrecover` precompile inside the signature
 * check of `transferSlotWithSignature`. A precompile runs no contract code and
 * cannot re-enter. Keeping it that way is why that function accepts plain
 * (EOA) signatures only: an ERC-1271 path would have to call the signer's
 * contract, and would be the first call out of this ledger.
 *
 * Slot indices are 0-based (matches v1 and V2).
 */
contract WoCoTicketLedger is Ownable2Step, EIP712 {
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

    /// Per-slot counter consumed by EVERY ownership change, on either transfer
    /// path. A signed transfer commits to its current value, so a signature is
    /// dead once used and dead once the slot moves any other way — including a
    /// round trip back to the signer, after which (from, to, deadline) alone
    /// would validate again.
    mapping(bytes32 => mapping(uint256 => uint256)) public transferNonces;

    /// EIP-712 type a holder signs to move a slot (domain: "WoCoTicketLedger",
    /// version "1", this chain, this contract). `from` and `nonce` are read from
    /// storage at submission, never supplied by the submitter.
    bytes32 public constant TRANSFER_SLOT_TYPEHASH = keccak256(
        "TransferSlot(bytes32 eventId,uint256 slot,address from,address to,uint256 nonce,uint256 deadline)"
    );

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

    /// @notice A claimed slot changed hands. Emitted ONLY by the two transfer
    ///         paths, `transferSlot` and `transferSlotWithSignature`, identically.
    /// @dev Indexers MUST fold this over `SlotClaimed`: after a transfer the
    ///      current holder is no longer the address in the original claim log.
    ///      It is also the invalidation signal for anything holding a SNAPSHOT
    ///      of slot owners — the offline check-in pack above all, which is
    ///      sound only as of the block it was built at.
    event SlotTransferred(
        bytes32 indexed eventId,
        uint256 indexed slot,
        address indexed from,
        address to
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
    error SlotUnclaimed();
    error NotSlotOwner();
    error TransferToSelf();
    error SignatureExpired();
    error EmptyManifestRef();
    error RenounceDisabled();

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

    constructor(address initialOwner, address initialSponsor)
        Ownable(initialOwner)
        EIP712("WoCoTicketLedger", "1")
    {
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
     * @param manifestRef  Off-chain ticket-manifest commit. Must be non-zero.
     *                     Refused with its own `EmptyManifestRef`, not the
     *                     `ZeroAddress` a zero organiser gets, so a caller can
     *                     tell which argument was wrong.
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
        if (manifestRef == bytes32(0))     revert EmptyManifestRef();
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
     * @param eventId  The event to mint in.
     * @param to       The slot's first holder. Cannot be zero: `owner ==
     *                 address(0)` is how this contract encodes "never claimed".
     *                 Named `to`, not `owner`, so it cannot shadow
     *                 `Ownable.owner()` — under that name a later edit reaching
     *                 for the contract's owner in this body would silently get
     *                 the buyer instead.
     * @param orderRef Off-chain order commit, stored once for the batch and
     *                 returned by `getSlotData`.
     */
    function claimFor(bytes32 eventId, address to, bytes32 orderRef)
        external
        onlyAuthorised
        returns (uint256 slot)
    {
        if (to == address(0)) revert ZeroAddress();
        Event storage ev = _events[eventId];
        if (!ev.exists)                       revert EventNotFound();
        if (ev.cancelled)                     revert AlreadyCancelled();
        if (block.timestamp >= ev.eventEndTs) revert SalesClosed();
        if (ev.nextSlot >= ev.totalSupply)    revert InsufficientSupply();

        uint64 first = ev.nextSlot;
        slot = uint256(first);
        // safe: first < totalSupply ≤ uint64.max
        unchecked { ev.nextSlot = first + 1; }

        slots[eventId][slot] = Slot({owner: to, batchFirstSlot: first});
        batchOrderRef[eventId][first] = orderRef;
        batchClaimer[eventId][first]  = msg.sender;

        emit SlotClaimed(eventId, slot, to, msg.sender, orderRef);
    }

    /**
     * @notice Mint N contiguous slots in one call. Authorised sponsors only.
     * @param eventId  The event to mint in.
     * @param owners   One first holder per slot, in slot order; none may be
     *                 zero. The loop binds each to `to`, not `owner`, for the
     *                 shadowing reason given on `claimFor`.
     * @param orderRef Stored once for the whole batch: every slot in it
     *                 resolves to this ref, and to the calling sponsor as
     *                 `claimer`.
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
            address to = owners[i];
            if (to == address(0)) revert ZeroAddress();
            uint256 s;
            unchecked { s = firstSlot + i; }
            slots[eventId][s] = Slot({owner: to, batchFirstSlot: first});
            emit SlotClaimed(eventId, s, to, msg.sender, orderRef);
            unchecked { ++i; }
        }

        unchecked { ev.nextSlot = first + n64; }
    }

    // ── Cancellation ──────────────────────────────────────────────────────────

    /**
     * @notice Move a claimed slot to a new owner. THE SLOT'S OWNER ONLY — who
     *         either sends this call, or signs a message naming the recipient
     *         that anyone may submit (`transferSlotWithSignature`).
     *
     * @dev Without this a slot's owner is permanent, so a ticket can never
     *      change hands — no resale, no gifting, no correcting a mis-delivered
     *      ticket — and this contract cannot be upgraded after deploy. That is
     *      why it is here rather than in a successor.
     *
     *      HOLDER-AUTHORISED, AND THAT IS THE POINT. No sponsor path, no
     *      operator/approval model, no batch form. The sponsor is a hot key
     *      that mints on every sale, and the guarantee this contract is built
     *      to keep is that such a key can only ever APPEND. A transfer the
     *      current owner authorises does not touch that. The holder is the only
     *      authority either path consults — here as `msg.sender`; in
     *      `transferSlotWithSignature` as the signer of a message that NAMES
     *      the recipient — so whoever submits gains nothing: it cannot choose
     *      the recipient, reuse the signature, or act without one. A "to
     *      whoever pays" form, in which the submitter picks the recipient, is
     *      the approval model this contract deliberately omits.
     *
     *      A PLATFORM-AUTHORISED TRANSFER WAS CONSIDERED AND REJECTED. It would
     *      let the platform move a ticket for a buyer whose key it had
     *      discarded — convenient, and the reason it was raised — but it grants
     *      custody of every ticket ever minted to the most exposed key in the
     *      system, permanently and unrevokeably. Retaining buyers' keys to reach
     *      the same outcome off chain was rejected too (WoCo-Event-App #298,
     *      owner decision 2026-09-13): a ticket minted to a key nobody holds
     *      stays where it is. Tickets meant to move must be minted to a key
     *      their holder controls.
     *
     *      ⚠️ THIS SHRINKS THE OFFLINE CHECK-IN PACK'S SOUNDNESS WINDOW, and
     *      the door is the consumer that assumed permanence. The pack snapshots
     *      slot owners and verifies offline against that snapshot, so a slot
     *      transferred AFTER a pack was built still passes the door with the
     *      seller's old QR. `SlotTransferred` exists to be subscribed to for
     *      exactly this: a resale surface MUST invalidate or refresh affected
     *      packs. The contract cannot enforce that; the door is off chain.
     *
     *      PROVENANCE IS NOT REWRITTEN. `getSlotData` keeps returning the
     *      original `claimer` and `orderRef` for the batch this slot was minted
     *      in; only `owner` moves. Anything asking "who holds this now" must
     *      read `owner`/`slotOwner`, never `claimer`.
     *
     *      NOT BLOCKED BY CANCELLATION OR BY `eventEndTs`. Those govern
     *      CLAIMING — whether new slots may be handed out. A slot already
     *      claimed is the holder's, and a ticket outlives its event as a record
     *      of attendance. Blocking either would make cancellation reach into
     *      existing slots' capabilities, which is exactly the coupling this
     *      split removed. A cancelled event's slot conveys nothing claimable;
     *      whether it is worth having is visible on chain and is the resale
     *      surface's problem, not this contract's.
     *
     *      NOTE ON CONTRACT RECIPIENTS: door verification is plain `ecrecover`
     *      with no ERC-1271 path, so a slot transferred to a smart-contract
     *      address cannot pass the door under the current scheme. Not blocked
     *      here — that is a scheme limitation, and the ledger should not encode
     *      it — but callers should warn.
     *
     * @param eventId  The event the slot belongs to.
     * @param slot     Zero-based slot index.
     * @param newOwner The address that will hold it. Cannot be zero: `owner ==
     *                 address(0)` is how this contract encodes "never claimed"
     *                 (see `getSlotData`), so burning would make a sold slot
     *                 read as available to every consumer. Burn is deliberately
     *                 impossible.
     */
    function transferSlot(bytes32 eventId, uint256 slot, address newOwner) external {
        _transfer(eventId, slot, msg.sender, newOwner);
    }

    /**
     * @notice Move a claimed slot on its owner's SIGNATURE, so that whoever
     *         submits the transaction — the platform, or anyone — pays the gas.
     *
     * @dev WHY IT EXISTS. `transferSlot` authorises by `msg.sender`, so the
     *      holder must send it and pay for it. Ticket-holding keys are plain
     *      EOAs — the door verifies with `ecrecover`, which a smart account
     *      cannot satisfy — and a paymaster sponsors smart-account operations,
     *      not a plain key's transaction. A holder with no gas could therefore
     *      never move a ticket. Same reason as `L2Registry.releaseWithSignature`
     *      (WoCo-Event-App #464). This contract is immutable, so it had to
     *      exist before deploy or never.
     *
     *      WHAT IT DOES NOT ADD: power for the submitter. The signed message
     *      names the recipient; a submitter can deliver exactly what the holder
     *      signed or decline to, never redirect it. See `transferSlot` for why
     *      there is no form in which the submitter picks the recipient.
     *
     *      WHAT THE SIGNATURE COMMITS TO: `TransferSlot(eventId, slot, from, to,
     *      nonce, deadline)` under the EIP-712 domain ("WoCoTicketLedger", "1",
     *      chain id, this contract). `from` and `nonce` come from storage, so a
     *      signature counts only while its signer holds the slot, and only
     *      until the slot next moves by EITHER path (`transferNonces`). The
     *      domain stops it being replayed on another chain or deployment.
     *
     *      EOA SIGNATURES ONLY, deliberately — see "No reentrancy guard" in the
     *      contract header. A slot held by a contract account moves through
     *      `transferSlot`, called by that account. OpenZeppelin's
     *      `ECDSA.recoverCalldata` (reads the signature straight from calldata,
     *      no memory copy) rejects malformed and malleable (high-s) signatures
     *      and never returns address(0), which no slot owner can be.
     *
     *      ERRORS. A wrong field, a wrong domain, a stale nonce or a non-holder's
     *      key all recover to some other address and revert `NotSlotOwner`; there
     *      is no separate invalid-signature error. A client can check before
     *      submitting by recovering its signature locally against
     *      `transferSlotDigest`. Malformed and high-s signatures revert with
     *      OpenZeppelin's `ECDSAInvalidSignature*` errors.
     *
     *      NO REVOCATION, deliberately (owner decision 2026-09-13). An unsubmitted
     *      signature cannot be cancelled on chain except by moving the slot, which
     *      consumes the nonce. Signatures are meant to be created at the moment of
     *      use, submitted straight away, and given short deadlines, so an unused
     *      one simply lapses. Do not build a flow in which someone holds a
     *      signature to submit later.
     *
     *      Everything `transferSlot` documents — the check-in pack window,
     *      provenance, cancellation and `eventEndTs`, contract recipients —
     *      applies unchanged: both paths share `_transfer`.
     *
     * @param eventId   The event the slot belongs to.
     * @param slot      Zero-based slot index.
     * @param newOwner  The recipient named in the signed message.
     * @param deadline  Unix seconds; the signature is void after it.
     * @param signature The holder's signature over
     *                  `transferSlotDigest(eventId, slot, newOwner, deadline)`.
     */
    function transferSlotWithSignature(
        bytes32 eventId,
        uint256 slot,
        address newOwner,
        uint256 deadline,
        bytes calldata signature
    ) external {
        if (block.timestamp > deadline) revert SignatureExpired();
        address signer = ECDSA.recoverCalldata(transferSlotDigest(eventId, slot, newOwner, deadline), signature);
        _transfer(eventId, slot, signer, newOwner);
    }

    /**
     * @notice The EIP-712 digest a holder signs to authorise
     *         `transferSlotWithSignature(eventId, slot, newOwner, deadline, …)`.
     * @dev Bound to the slot's CURRENT owner and nonce, so it changes whenever
     *      the slot moves. Wallets that sign typed data build the same struct
     *      themselves; this view serves signers of a raw digest and lets tests
     *      pin the encoding.
     */
    function transferSlotDigest(bytes32 eventId, uint256 slot, address newOwner, uint256 deadline)
        public
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    TRANSFER_SLOT_TYPEHASH,
                    eventId,
                    slot,
                    slots[eventId][slot].owner,
                    newOwner,
                    transferNonces[eventId][slot],
                    deadline
                )
            )
        );
    }

    /// @dev The move both transfer paths share. `authority` is what the calling
    ///      path proved: `msg.sender` for `transferSlot`, the recovered signer
    ///      for `transferSlotWithSignature`. Neither can be address(0).
    function _transfer(bytes32 eventId, uint256 slot, address authority, address newOwner) internal {
        if (newOwner == address(0)) revert ZeroAddress();

        Slot storage sd = slots[eventId][slot];
        address previousOwner = sd.owner;

        // Distinct selector from NotSlotOwner on purpose. Holder-only auth
        // already subsumes this (address(0) is never an authority), but a
        // guard no test can tell apart from another is a guard that reads as
        // deletable. Separate errors keep each one independently killable.
        if (previousOwner == address(0)) revert SlotUnclaimed();
        if (authority != previousOwner) revert NotSlotOwner();

        // `from == to` writes nothing yet would still emit SlotTransferred —
        // and the log shape IS the API here, so a phantom transfer is something
        // indexers and the resale surface would act on. (The sibling registry
        // in this repo shipped this same shape as a real defect, where a
        // self-"transfer" moved nothing but still bumped record versions. The
        // harm differs — there it wiped state, here it is a false event — but
        // the omission is identical, so it is refused rather than tolerated.)
        if (newOwner == previousOwner) revert TransferToSelf();

        // ONLY the owner field. Never reconstruct the struct: writing
        // `Slot({owner: newOwner, batchFirstSlot: 0})` compiles and silently
        // re-points this slot's claimer/orderRef at batch 0's real data — a
        // live misattribution, not zero values.
        sd.owner = newOwner;
        // Consumed by every move, on either path — see `transferNonces`.
        unchecked { ++transferNonces[eventId][slot]; }

        emit SlotTransferred(eventId, slot, previousOwner, newOwner);
    }

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

    /// @notice Slot owner plus the batch attribution it was minted under. All
    ///         three are zero for a slot that was never claimed.
    /// @dev The unclaimed zeroes are returned explicitly, not read. Such a slot
    ///      has no batch, so its `batchFirstSlot` reads as the default 0, and
    ///      reading through would return the claimer and orderRef of the batch
    ///      at slot 0 — real data belonging to a different slot. V2 returned
    ///      exactly that and told callers to check `owner` first; payments will
    ///      read this view, and a rule every caller must remember is one some
    ///      caller forgets.
    ///
    ///      `owner == address(0)` is still THE test for "unclaimed".
    function getSlotData(bytes32 eventId, uint256 slot)
        external
        view
        returns (address owner, address claimer, bytes32 orderRef)
    {
        Slot memory sd = slots[eventId][slot];
        if (sd.owner == address(0)) return (address(0), address(0), bytes32(0));
        return (
            sd.owner,
            batchClaimer[eventId][sd.batchFirstSlot],
            batchOrderRef[eventId][sd.batchFirstSlot]
        );
    }

    function slotOwner(bytes32 eventId, uint256 slot) external view returns (address) {
        return slots[eventId][slot].owner;
    }

    /// @notice Slots remaining to be sold now: zero once the event is cancelled
    ///         or past its sales cutoff, whatever stamped supply is left.
    /// @dev The two zero cases copy the mint paths' guards exactly — `cancelled`
    ///      and `block.timestamp >= eventEndTs` — so a non-zero answer means
    ///      `claimFor`, in the same state and block, will not revert
    ///      `AlreadyCancelled` or `SalesClosed`. Change those guards and these
    ///      must change with them. Reporting stamped supply instead would show
    ///      a cancelled or closed event as on sale; that figure, regardless of
    ///      state, is `getEvent`'s `totalSupply - nextSlot`.
    ///
    ///      Reverts `EventNotFound` for an unknown id, like `getEvent` and
    ///      `getEventStatus`: returning 0 made a mistyped id indistinguishable
    ///      from a sold-out event.
    function remaining(bytes32 eventId) external view returns (uint256) {
        Event memory ev = _events[eventId];
        if (!ev.exists)                       revert EventNotFound();
        if (ev.cancelled)                     return 0;
        if (block.timestamp >= ev.eventEndTs) return 0;
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

    /// @notice Disabled: always reverts `RenounceDisabled`.
    /// @dev Renouncing would set `owner` to address(0) for good, and every
    ///      `onlyOwner` power would go with it — `addSponsor`, `removeSponsor`,
    ///      `setDisputeAuthority`. A leaked sponsor key could then never be
    ///      removed, nor a lost dispute authority replaced, on a contract that
    ///      is deployed once. `Ownable2Step` makes transfers two-step but leaves
    ///      renounce a single call, and renounce is the only road to a zero
    ///      owner: a transfer takes effect only when its recipient accepts,
    ///      which address(0) cannot do. Hand ownership on with
    ///      `transferOwnership` + `acceptOwnership` instead.
    ///
    ///      `pure` and unguarded: there is nothing left to authorise, so every
    ///      caller gets the same answer. The selector is unchanged.
    function renounceOwnership() public pure override {
        revert RenounceDisabled();
    }
}
