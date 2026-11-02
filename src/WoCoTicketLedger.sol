// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable2Step, Ownable} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @dev `WoCoTicketLedger.UNLIMITED_MINTS`, at file level so the deploy script
///      can import the one definition (a contract's constant cannot be read
///      from its type).
uint32 constant LEDGER_UNLIMITED_MINTS = type(uint32).max;

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
 * Version 2 (EIP-712 domain version "2") adds, over the deployed version 1:
 * terms the ORGANISER holds from registration and can act on by signature
 * (supply it can lower and restore, never above the supply it registered; a
 * sales cutoff it can only move later, while still open and at most two years
 * ahead; cancellation), seated events, and the platform's replacement of a
 * bearer ticket (`reissue`), with a one-way off switch (`disableBearerMints`).
 *
 * ── The guarantee this contract makes ────────────────────────────────────────
 *
 *   Sponsor authority grants exactly TWO powers, both within that sponsor's
 *   hourly mint cap, before `eventEndTs` and only while not cancelled:
 *     1. appending new slots, within the event's supply (and, on a seated
 *        event, into free seats);
 *     2. re-pointing a BEARER slot it minted itself, that no holder has ever
 *        moved, to a fresh key (`reissue`), until the owner calls
 *        `disableBearerMints`.
 *
 * Sponsors cannot cancel an event, cannot alter its terms, cannot move a
 * seat, and cannot touch any other slot that already exists: not one minted
 * by another sponsor, not one minted non-bearer, not one its holder has ever
 * moved. That statement is what a payments contract — present or future,
 * correct or buggy — is audited against, and it holds for every sponsor
 * without re-reading this contract. The owner holds no power over an event's
 * supply, cutoff or seats either: it appoints and caps sponsors, sets the
 * dispute authority (the one address besides the organiser that can cancel,
 * through `forceCancelEvent`; the owner by default), and can end bearer
 * minting for good (audit 1152 I-11).
 *
 * The platform keeps three powers in all: minting and `reissue`, both within
 * a sponsor's cap, and `forceCancelEvent` through the dispute authority, which
 * only stops sales and opens refunds.
 *
 * ── Terms: the organiser and its key ─────────────────────────────────────────
 *
 * An event's terms are its supply (`setSupply`), its sales cutoff
 * (`extendSalesEnd`) and its cancellation (`cancelEvent`). They belong to the
 * ORGANISER from registration: no button to take them, and nobody else holds
 * them on its behalf. Two addresses act for it:
 *   - `organiser`, its account (a Kernel smart account in production), which
 *     may act directly and is the ONLY address that can move the key
 *     (`setOrganiserKey`);
 *   - `organiserKey`, a plain key the organiser derives from its current
 *     account secret, which may act directly or, as in production, SIGN each
 *     action (`setSupplyWithSignature`, `extendSalesEndWithSignature`,
 *     `cancelEventWithSignature`) for anyone to submit and pay for. The
 *     platform relays and can change nothing on its own. A signed action
 *     names every field, commits to `termsNonces[eventId]` and names its own
 *     window, `issuedAt` to `deadline`, at most `MAX_TERMS_SIGNATURE_TTL`
 *     long: usable only inside it, and never later (audit 1152 L-2).
 *
 * Every organiser signature, terms or seat move, also dies on the organiser's
 * next write to the event: a terms change, a key move, or `revokeSignatures`,
 * which changes nothing else and is the organiser's way to cancel what it has
 * signed but not yet seen land (audit 1153 L-1).
 *
 * The key is per EVENT, not per organiser: registration is permissionless, so
 * a per-organiser record set at registration would let anyone name the key of
 * an organiser that has not registered yet. A key on a junk registration
 * controls only that registration.
 *
 * Rotation: when a passkey is removed the account's secret changes, and the
 * account moves the key (`setOrganiserKey`) in the same operation that moves
 * its key ring, so the removed device's key loses the events at once. An
 * account that is lost leaves its events' terms as they are: sales run to the
 * cutoff, and the dispute authority can still stop them and open refunds.
 * There is deliberately no owner lever to move an organiser's key: that would
 * be the platform control this design removes.
 *
 * A LEAKED organiser key, until the account moves it, can do exactly what the
 * organiser can and nothing more: cancel (one-way, buyer-protective), set
 * supply anywhere from what is minted up to `registeredSupply` (so it can also
 * undo a reduction), move the cutoff later within `MAX_SALES_EXTENSION`, move
 * or empty (`NO_SEAT`) the seat of any bearer ticket nobody has moved, until
 * `disableBearerMints`, with a holder's signature, move that holder's
 * ticket, and void its own pending signatures (`revokeSignatures`). None of it
 * moves money toward anyone, and it cannot move the key: only the account can.
 * The platform never names the account as its own key; an EOA organiser that
 * registers itself may, and then its key IS the account, so a leak of it is a
 * leak of the account (audit 1155 I-1).
 *
 * Not all of it can be undone after the account moves the key (audit 1152
 * L-3). A cutoff it extends stays extended, by the monotonic rule below: up to
 * `MAX_SALES_EXTENSION` per move, it keeps the sales window open and delays
 * whatever keys on `eventEndTs`. The new key can seat bearer tickets again,
 * but not into a seat the leaked key's holder has since taken: a key holder
 * who also holds tickets can empty bearer tickets out of seats and `reseat`
 * its own tickets into them, and a `reseat` sets `held`, which puts those
 * tickets beyond the new key. A seat it empties is also free for sale until
 * the new key restores the ticket. Accepted, not engineered out: a lever over
 * `held` tickets is the power `held` exists to remove, and every remedy left
 * is off chain: a leak is met by moving the key at once, a seat picker must
 * not sell a seat an organiser-only move freed until the account confirms it,
 * and the last resort is cancellation (`cancelEvent` or `forceCancelEvent`)
 * with refunds.
 *
 * ── Seats ────────────────────────────────────────────────────────────────────
 *
 * A seated event (`registerSeatedEvent`) has `supply` seats, indices
 * `0 .. registeredSupply - 1`, whose labels `manifestRef` commits off chain.
 * Slots stay SEQUENTIAL exactly as on a general-admission event; each ticket's
 * seat is recorded beside its slot (`seatOf`) and one bit per seat records
 * that a ticket holds it (`seatWord`), so no seat is ever sold twice. Each
 * kind refuses the other's mint paths, so a seated event never MINTS a
 * seatless ticket and a general-admission event never has a seat. The one
 * seatless ticket a seated event can hold is one moved to `NO_SEAT`, which the
 * door must refuse (see `seatOf`).
 *
 * A seat moves only with the organiser's consent: `reseatBearer` on its key's
 * signature for a bearer ticket nobody holds the key to (until
 * `disableBearerMints`), `reseat` on its key's AND the holder's signature for
 * any ticket. No sponsor and no owner can move a seat. The ticket's QR is
 * unchanged by a move (it binds the edition, not the seat), and a move to
 * `NO_SEAT` empties the seat for a move to another band, which is another
 * event. Seats cannot be added after registration (a new registration is
 * another band), and a seat is one event's: a season is one ticket per event.
 *
 * A seat a band move empties is NOT sold by minting (audit 1152 L-4): a seated
 * event's supply is its seat count, so once it has sold out no new slot
 * exists for it, and `seatWord` then shows the seat free while `remaining()`
 * is 0. It is refilled by seating the seatless ticket that left it: for a
 * card (bearer) ticket, `reissue` that slot to the next buyer's fresh key and
 * `reseatBearer` it into the seat (by the sponsor that minted it, before the
 * cutoff, while not cancelled and until `disableBearerMints`; after that the
 * seat stays empty); for a `held` ticket, only its holder can hand the slot
 * on (`transferSlot`), and a `reseat` then seats it. A refilled slot keeps the
 * ORIGINAL sale's claimer and `orderRef`, so the next buyer's order is keyed
 * on `SlotReissued`, never on the slot's `orderRef`. A seat picker reads
 * `remaining()` with `seatWord`, and never offers a seat it cannot fill.
 *
 * ── Reissue: the platform replacing a bearer ticket ──────────────────────────
 *
 * Card tickets are minted to a one-off key that signs the ticket and is then
 * discarded, so such a ticket can never move (`transferSlot` needs its key).
 * When one is emailed to a mistyped address that exists, a stranger holds a
 * ticket the door accepts. `reissue` is the remedy: it points that slot at a
 * fresh key. The old ticket's signature then recovers to a key that no longer
 * owns the slot, so a door that verifies against the chain refuses it, and the
 * ticket signed by the fresh key takes its place. This IS the platform moving
 * a ticket, which the platform-authorised transfer rejected below
 * (`transferSlot`) would also have done. What differs:
 *   - SCOPE: only slots minted through `batchClaimBearer` or
 *     `batchClaimSeatsBearer` by the calling
 *     sponsor and never moved by a holder since (`held`). A slot minted to its
 *     holder's own key (`batchClaimFor`, `claimFor`), or moved there, is out
 *     of reach from then on, with no action by the holder.
 *   - BOUNDS: each re-point is charged to the hourly mint cap like a mint, so
 *     `setSponsorMintCap(sponsor, 0)` stops it. That is also the width of a
 *     leaked sponsor key here: per window, up to its cap, it can re-point any
 *     bearer slot it minted, and by then moving each one as its new holder
 *     (which sets `held`) put it beyond reissue for good. An `UNLIMITED_MINTS`
 *     sponsor is unbounded in this too, so card sales must mint through a
 *     capped sponsor.
 *   - VISIBILITY: every re-point is a `SlotReissued` log.
 *   - OFF-RAMP: `disableBearerMints` ends bearer minting and reissue for good.
 *     It is one-way so that it is a commitment anyone can read on chain, not a
 *     policy the owner could reverse. Sales, supply changes and transfers
 *     carry on after it.
 *
 * WHY IN PLACE, NOT REVOKE-AND-MINT. The slot index is the ticket's edition
 * number off chain (edition = slot + 1), and the manifest committed by
 * `manifestRef` holds exactly one leaf per edition up to the supply it was
 * registered with. A replacement appended at `nextSlot` would be an edition
 * the manifest never committed, refused at the door as out of range on a
 * sold-out event. Keeping the index keeps the edition (and any seat), uses no
 * supply, and
 * keeps every off-chain record keyed by slot valid.
 *
 * Refunds and chargebacks are NOT reissues: they can be reversed (a refund
 * that fails, a dispute that is won), so they stay off chain.
 *
 * SPONSOR ROTATION. Reissue checks the slot's minting sponsor, so a sponsor
 * key removed from service can no longer reissue the bearer tickets it minted
 * (they still verify at the door). That is the right outcome for a key that
 * leaked, and it is not transferable: the power to re-point a ticket stays
 * with the key that minted it. For a routine rotation, add the new key, keep
 * the old one authorised with a small cap for reissue only, and remove it
 * once the last bearer event it minted into is over. After a leak,
 * `removeSponsor(old)` ends all of it; no event's terms need repair, because
 * no sponsor holds any.
 *
 * ── What bounds a sponsor (audit 959 M-1) ────────────────────────────────────
 *
 * "Can only append" is not "harmless": appending is the valuable act. A slot
 * is a ticket the door accepts, and supply once allocated never comes back.
 * A card sponsor is a hot key that must be online around the clock, and the
 * chain cannot check the Stripe payment it acts on. So every sponsor is also
 * bounded by an hourly mint cap the owner sets per sponsor: a leaked key takes
 * at most its cap per window, and at most twice it across a window boundary
 * (see `MintAllowance`), until the owner calls `removeSponsor` or
 * `setSponsorMintCap(sponsor, 0)`. Either lever withdraws all of it: minting
 * and reissue. It can register junk events of its own, which control only
 * themselves and which the platform never sells.
 *
 * `UNLIMITED_MINTS` is for a sponsor whose mints the chain CAN check — a
 * payments contract that mints only in the transaction that takes the money.
 * Caps are per sponsor, not shared, so one rail's leak or on-sale can never
 * exhaust another's allowance. Scoping sponsors to events was rejected: one
 * platform key registers AND mints every event, so it would bound nothing.
 * The flip side (audit 960 L-7): one sponsor's cap is shared by every event it
 * mints into, so a busy on-sale can use an hour that another event's buyers
 * then wait out. That is watched off chain (`sponsorMintAllowance`) and met by
 * raising the cap, not by partitioning it here.
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
 *   - `eventEndTs` only ever moves LATER (`extendSalesEnd`, the organiser
 *     only), only while it has not passed, and never more than
 *     `MAX_SALES_EXTENSION` ahead of the moment it moves. Release time
 *     downstream is `eventEndTs + releaseDelay`, so it can never be pulled
 *     earlier than buyers agreed to. The bound is per move, not in total
 *     (audit 1060 L-1): the organiser can move it again before each cutoff,
 *     without limit, and so can delay its own event's release indefinitely.
 *     Anything off chain that keys a deadline on this value must bound it
 *     itself. Payments must still do its release arithmetic in uint256 (a
 *     registered `eventEndTs` itself is unbounded, below).
 *   - Supply is not read across the boundary: changing it (`setSupply`)
 *     decides how many tickets may still be sold, never who is paid or when.
 *     It never passes the edition commitment: `manifestRef` has no setter and
 *     commits the editions the event was registered with, and supply can go
 *     down and back up to that number (`registeredSupply`), never above it.
 *     More seats than that is a new registration.
 *
 * `registerEvent` leaves the cutoff unbounded on purpose: registration sets an
 * event's terms before any buyer exists (collectables register a cutoff a
 * century out), while an extension changes terms that money was taken under.
 *
 * WHY THE CUTOFF IS MONOTONIC-INCREASE-ONLY (#294): extending it delays
 * release, which is conservative. Shortening it would pull the organiser's
 * withdrawal forward, which is the rug this rule exists to prevent. Any later
 * change to `extendSalesEnd` must keep that.
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
 * redirect money — the one thing the rule above forbids. Nor is the batch's
 * `claimer` (`getSlotData`) a payee: here it is the MINTING SPONSOR, which for
 * every card sale is the same platform wallet whoever paid (audit 960 I-6).
 * WoCoEventV2 paid its claimer (WoCoEventV2.sol:537) because there the claimer
 * was the payer; on this ledger that is true only of a payments contract
 * minting its own sales, and even then its own record of who paid is the key.
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
 * `organiser` and `organiserKey` are stamped explicitly and are NOT the
 * caller. In production the registering address is the platform's sponsor
 * wallet acting on the organiser's behalf, so `msg.sender` identifies the
 * platform, not the event's owner; it is recorded (`Registered.registrant`)
 * and holds no power over the event. A self-registration passes its own
 * addresses.
 *
 * WARNING — `organiser` AND `organiserKey` ARE ASSERTIONS, NOT PROOFS.
 * Registration is permissionless and both parameters are unauthenticated: any
 * caller may register an event naming any addresses, and `Registered` will
 * carry the organiser in its indexed topic. Indexers and any future consumer
 * MUST NOT treat a `Registered` log as evidence that the named organiser
 * consented; filter on `registrant` (the authenticated `msg.sender`), or
 * require a signature at a higher layer, as the platform does before it
 * registers (it checks the organiser holds the key). The consequence inside
 * this contract is contained: the named organiser and key control only the
 * event that named them, and cancelling it is buyer-protective and one-way.
 *
 * `registrantNonce` is keyed by the registering address (`msg.sender`), not
 * by `organiser` — it is the eventId derivation counter. Renamed from V1/V2's
 * `organiserNonce`, which became a misnomer the moment `organiser` stopped
 * being `msg.sender`.
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
 * The one call of any kind is the `ecrecover` precompile inside the
 * signature checks (`transferSlotWithSignature`, the signed terms actions,
 * the seat moves). A precompile runs no contract code and cannot re-enter.
 * Keeping it that way is why they accept plain (EOA) signatures only: an
 * ERC-1271 path would have to call the signer's contract, and would be the
 * first call out of this ledger. A smart-account organiser acts through its
 * key, or calls the direct paths itself.
 *
 * Slot indices are 0-based (matches v1 and V2).
 */
contract WoCoTicketLedger is Ownable2Step, EIP712 {
    /// Packed layout — 4 storage slots (V2 used 5).
    ///
    /// Slot 0: totalSupply(64) + nextSlot(64) + eventEndTs(64) + exists(8) + cancelled(8) + seated(8)
    /// Slot 1: organiser(160) + registeredSupply(64)
    /// Slot 2: manifestRef(256)
    /// Slot 3: organiserKey(160)
    struct Event {
        // ---- slot 0 ----
        uint64 totalSupply;
        uint64 nextSlot;
        uint64 eventEndTs;
        bool   exists;
        bool   cancelled;
        /// Fixed at registration (`registerSeatedEvent`): every ticket has a
        /// seat, minted through the seat paths only. See "Seats".
        bool   seated;
        // ---- slot 1 ----
        address organiser;
        /// The supply at registration, written once: the editions `manifestRef`
        /// commits, and so the ceiling `setSupply` can never pass. On a seated
        /// event also the number of seats, so a seat index is below it.
        uint64  registeredSupply;
        // ---- slot 2 ----
        bytes32 manifestRef;
        // ---- slot 3 ----
        /// The key that signs the event's terms for the organiser (see
        /// "Terms"). Set at registration, moved only by `organiser`
        /// (`setOrganiserKey`).
        address organiserKey;
    }

    /// Packed: address (20) + uint64 (8) + 2 bools = 30 bytes, one SSTORE per slot.
    ///
    /// `bearer` is set at mint and never changes: true only through
    /// `batchClaimBearer` and `batchClaimSeatsBearer`, for a ticket whose key
    /// is not kept. Only a bearer
    /// slot can be reissued. `held` is set by the first holder-authorised move
    /// (`_transfer`) and never cleared: from then on a key someone keeps holds
    /// the slot, and `reissue` cannot reach it. A reissue does not set it.
    struct Slot {
        address owner;
        uint64  batchFirstSlot;
        bool    bearer;
        bool    held;
    }

    // ── Storage ───────────────────────────────────────────────────────────────

    /// Address allowed to `forceCancelEvent`. Initially the owner, and moves
    /// with an ownership handover whenever it equals the outgoing owner
    /// (`_transferOwnership`); while it is a different address, a handover
    /// leaves it where it is. Deliberately NOT the payments contract:
    /// keeping this a human-controlled address is what keeps the dependency
    /// one-directional.
    address public disputeAuthority;

    mapping(bytes32 => Event) private _events;
    // Private (audit 959 L-2): public getters here returned another batch's
    // claimer and orderRef for an unclaimed slot. `getSlotData` and `slotOwner`
    // are the reads, and the only ones that get unclaimed slots right.
    mapping(bytes32 => mapping(uint256 => Slot)) private _slots;
    mapping(bytes32 => mapping(uint64 => bytes32)) private _batchOrderRef;
    mapping(bytes32 => mapping(uint64 => address)) private _batchClaimer;

    /// Seat + 1 per slot of a seated event; 0 = no seat (a GA event, an
    /// unclaimed slot, or a ticket moved to another band, `NO_SEAT`). Read
    /// through `seatOf`.
    mapping(bytes32 => mapping(uint256 => uint64)) private _seatOf;
    /// One bit per seat, set while a ticket holds it. Read through `seatWord`.
    mapping(bytes32 => mapping(uint256 => uint256)) private _seatTaken;

    /// eventId derivation counter, keyed by the REGISTERING address
    /// (`msg.sender`). See the note above.
    mapping(address => uint256) public registrantNonce;

    /// Addresses permitted to mint. The Stripe webhook's sponsor wallet today;
    /// WoCoPayments once it ships; any future sponsor contract after that.
    mapping(address => bool) public authorisedSponsors;

    /// Per-event counter consumed by every ORGANISER write to the event's terms
    /// or its organiser key, on either path, direct or signed: `setSupply`,
    /// `extendSalesEnd`, `cancelEvent`, `setOrganiserKey` and `revokeSignatures`.
    /// Every organiser-signed action, terms AND seat moves, commits to its
    /// current value, so a signature is dead once used (a seat move by its
    /// slot's `transferNonces`) and dead once any other organiser write lands
    /// first: a new key, even one moved back to an earlier
    /// key, finds no earlier signature alive (audit 1153 L-1). Seat moves do not
    /// consume it, so several can be signed at once. `forceCancelEvent` leaves
    /// it: once cancelled, every terms and seat path refuses anyway (audit 1152
    /// I-2).
    mapping(bytes32 => uint256) public termsNonces;

    /// One-way: once true, `batchClaimBearer`, `batchClaimSeatsBearer`,
    /// `reissue` and `reseatBearer` revert for good. Set by
    /// `disableBearerMints` (owner only); nothing clears it.
    bool public bearerMintsDisabled;

    /// @notice A sponsor's hourly mint accounting. One slot.
    /// @dev `perHour` is `UNLIMITED_MINTS` (no accounting at all), 0 (the
    ///      sponsor stays authorised but mints nothing), or a cap. The window's
    ///      END is stored, not its start, and a retune between finite caps
    ///      writes only `perHour`, so it never re-anchors an open window or hands
    ///      back spent allowance (the registrar's audit 937 F6). Fixed window, opened
    ///      by the first mint after the last one ended: across a boundary a
    ///      sponsor can mint up to twice its cap in a few seconds, accepted for
    ///      a backstop in exchange for one slot and no loops. The window runs on
    ///      Arbitrum's `block.timestamp` (audit 960 L-5), under the chain-time
    ///      rule stated on `registerEvent`'s `eventEndTs`. So the bound is "cap
    ///      per window of chain time", not per wall-clock hour.
    ///
    ///      Moving into or out of `UNLIMITED_MINTS` closes the open window
    ///      (audit 960 M-2): unlimited mints are never counted, so a count from
    ///      before an unlimited spell is stale, not spent allowance.
    struct MintAllowance {
        uint32 perHour;
        uint32 used;
        uint64 windowEnd;
    }

    mapping(address => MintAllowance) private _mintAllowance;

    /// @notice `perHour` meaning "no cap".
    uint32 public constant UNLIMITED_MINTS = LEDGER_UNLIMITED_MINTS;

    /// @notice Every capped sponsor's window. Fixed, not owner-tunable: the
    ///         cap is the one knob, and a tunable window is what let the
    ///         registrar's owner brick minting by overflow (audit 925 F3).
    uint64 public constant MINT_WINDOW = 1 hours;

    /// @notice How far ahead of now `extendSalesEnd` may move a cutoff. Absolute
    ///         from now, not a step per call, which a loop in one block would
    ///         multiply (audit 1059 M-1). Two festival cycles.
    uint64 public constant MAX_SALES_EXTENSION = 730 days;

    /// Per-slot counter consumed by EVERY ownership change and seat move: both
    /// transfer paths, `reissue` and `_reseat` (audit 1155 I-3). A signed
    /// transfer or seat move commits to its current value, so a signature is
    /// dead once used and dead once the slot moves any other way — including a
    /// round trip back to the signer, after which (from, to, deadline) alone
    /// would validate again. A seat move therefore also kills the holder's
    /// pending signed transfer of that slot; the holder signs again.
    mapping(bytes32 => mapping(uint256 => uint256)) public transferNonces;

    /// Per-seat counter bumped each time the seat is FREED (`_freeSeat`). A seat
    /// move commits to its target seat's value, so a signed move that reverted
    /// `SeatTaken` is dead once that seat changes hands, rather than landing
    /// later when it frees (audit 1155 L-1). A take needs no bump: the move
    /// cannot land while the seat is held, and the free that follows bumps it.
    /// `NO_SEAT` is never freed, so a move out of a seat always reads 0.
    mapping(bytes32 => mapping(uint256 => uint256)) public seatNonces;

    /// EIP-712 type a holder signs to move a slot (domain: "WoCoTicketLedger",
    /// version "2", this chain, this contract). `from` and `nonce` are read from
    /// storage at submission, never supplied by the submitter.
    bytes32 public constant TRANSFER_SLOT_TYPEHASH = keccak256(
        "TransferSlot(bytes32 eventId,uint256 slot,address from,address to,uint256 nonce,uint256 deadline)"
    );

    /// EIP-712 types the organiser key signs (same domain). `nonce` is
    /// `termsNonces[eventId]`, read from storage at submission. `issuedAt` and
    /// `deadline` are the window the signer names (see `MAX_TERMS_SIGNATURE_TTL`).
    bytes32 public constant SET_SUPPLY_TYPEHASH = keccak256(
        "SetSupply(bytes32 eventId,uint64 supply,uint256 nonce,uint256 issuedAt,uint256 deadline)"
    );
    bytes32 public constant EXTEND_SALES_END_TYPEHASH = keccak256(
        "ExtendSalesEnd(bytes32 eventId,uint64 eventEndTs,uint256 nonce,uint256 issuedAt,uint256 deadline)"
    );
    bytes32 public constant CANCEL_EVENT_TYPEHASH = keccak256(
        "CancelEvent(bytes32 eventId,uint256 nonce,uint256 issuedAt,uint256 deadline)"
    );
    bytes32 public constant REVOKE_SIGNATURES_TYPEHASH = keccak256(
        "RevokeSignatures(bytes32 eventId,uint256 nonce,uint256 issuedAt,uint256 deadline)"
    );

    /// EIP-712 types of a seat move. `holder` and `nonce` are the slot's current
    /// owner and `transferNonces[eventId][slot]`, `termsNonce` is
    /// `termsNonces[eventId]`, and `seatNonce` is `seatNonces[eventId][toSeat]`,
    /// all read from storage at submission: a consent dies when the slot moves
    /// by any path, when the organiser writes anything (terms, key,
    /// `revokeSignatures`), and when its target seat changes hands; moves on
    /// different slots never collide. One type per path (audit 1152 L-1):
    /// `Reseat` is the two-party move, signed by the organiser key AND the
    /// holder, and sets `held`; `ReseatBearer` is the organiser key alone on a
    /// bearer ticket. So a consent given for one path can never be submitted
    /// through the other, and a holder's signed move always sets `held`.
    ///
    /// Each move is signed and lands on its own, so a rearrangement of several
    /// dependent moves - a swap is `a` to `NO_SEAT`, `b` into `a`'s seat, `a`
    /// into `b`'s, each signed against the nonces the moves before it leave -
    /// can be landed part-way by whoever holds the signatures, leaving a ticket
    /// seatless until the organiser revokes and re-signs (audit 1156 L-1). Such
    /// a sequence is submitted atomically: the organiser's own account sends
    /// all of it in one transaction, all or nothing, rather than handing the
    /// signatures to a relayer.
    bytes32 public constant RESEAT_TYPEHASH = keccak256(
        "Reseat(bytes32 eventId,uint256 slot,uint256 toSeat,address holder,uint256 nonce,uint256 termsNonce,uint256 seatNonce,uint256 issuedAt,uint256 deadline)"
    );
    bytes32 public constant RESEAT_BEARER_TYPEHASH = keccak256(
        "ReseatBearer(bytes32 eventId,uint256 slot,uint256 toSeat,address holder,uint256 nonce,uint256 termsNonce,uint256 seatNonce,uint256 issuedAt,uint256 deadline)"
    );

    /// @notice The longest window a signed terms action or seat move may name.
    ///         Each signature names its window, `issuedAt` to `deadline`, at
    ///         most this long, and is usable only inside it (the registrar's
    ///         ceiling, `WoCoRegistrar.sol`). The window is part of what is
    ///         signed, so a signature asking for longer is refused for good,
    ///         not merely until its deadline comes near (audit 1152 L-2). The
    ///         chain cannot tell a post-dated `issuedAt` from an honest one: a
    ///         window set in the future is a standing option until it opens,
    ///         and is what the signer signed. So clients stamp `issuedAt` from
    ///         their clock, never ahead of it, and the relayer refuses anything
    ///         whose `issuedAt` is ahead of the latest block. CHAIN time, under
    ///         the rule stated on `registerEvent`'s `eventEndTs` (audit 961
    ///         L-2): backdate `issuedAt` by about 15 minutes, since a lagging
    ///         chain clock only delays a signature (`SignatureNotYetValid`
    ///         until chain time reaches it), and every minute backdated comes
    ///         off the window's usable span. A signature can stay valid up to
    ///         ~24h past the wall-clock deadline, or lapse early.
    uint256 public constant MAX_TERMS_SIGNATURE_TTL = 48 hours;

    /// @notice `seatOf` for a slot with no seat, and the `toSeat` that moves a
    ///         ticket out of its seat (to another band, a separate event).
    uint256 public constant NO_SEAT = type(uint64).max;

    // ── Events ────────────────────────────────────────────────────────────────

    /// @dev `registrant` is the address that registered (`msg.sender`). It
    ///      holds no power over the event; the organiser key does
    ///      (`OrganiserKeySet`). Unchanged from version 1, so the server's
    ///      registration walk reads both versions.
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
    ///
    ///      `to` is indexed rather than `slot` (audit 959 I-4, #562): "what did
    ///      wallet X receive" is what a wallet, passport or door asks, and only
    ///      an indexed field can be filtered by the node. `slot` decodes from
    ///      data.
    event SlotTransferred(
        bytes32 indexed eventId,
        uint256 slot,
        address indexed from,
        address indexed to
    );

    /// @dev `forced` is true for `forceCancelEvent`, false for the organiser's
    ///      own `cancelEvent` (audit 960 L-4): `by` alone cannot tell them apart
    ///      when the dispute authority is also an event's organiser.
    event EventCancelled(bytes32 indexed eventId, address indexed by, bool forced);

    event SponsorAdded(address indexed sponsor);
    event SponsorRemoved(address indexed sponsor);
    event SponsorMintCapSet(address indexed sponsor, uint32 perHour);
    event DisputeAuthorityUpdated(address indexed authority);

    /// @notice The organiser set the event's supply (`setSupply`).
    event SupplySet(bytes32 indexed eventId, uint64 previous, uint64 supply);

    /// @notice The organiser moved the sales cutoff later (`extendSalesEnd`).
    event SalesEndExtended(bytes32 indexed eventId, uint64 previous, uint64 eventEndTs);

    /// @notice The event is seated (`registerSeatedEvent`). Emitted once, after
    ///         `Registered`.
    event Seated(bytes32 indexed eventId);

    /// @notice A seat mint gave `slot` the seat `seat`.
    event SeatAssigned(bytes32 indexed eventId, uint256 indexed slot, uint256 seat);

    /// @notice A ticket moved seat. `toSeat` is `NO_SEAT` when it left its
    ///         seat for another band.
    /// @dev Like `SlotTransferred`, it invalidates any snapshot of seats (the
    ///      check-in pack). The QR is unchanged: the ticket message binds the
    ///      edition, not the seat.
    event SlotReseated(bytes32 indexed eventId, uint256 indexed slot, uint256 fromSeat, uint256 toSeat);

    /// @notice The key that signs the event's terms changed. `previous` is
    ///         address(0) at registration.
    /// @dev Indexers fold this from registration on for the current key;
    ///      `getOrganiserKey` reads it.
    event OrganiserKeySet(bytes32 indexed eventId, address indexed previous, address indexed key);

    /// @notice The organiser voided every signed action and seat move it had
    ///         not yet seen land (`revokeSignatures`). `by` is the caller on the
    ///         direct path, the organiser key on the signed one.
    event SignaturesRevoked(bytes32 indexed eventId, address indexed by);

    /// @notice `reissue` pointed a bearer slot at a fresh key.
    /// @dev Indexers MUST fold this over `SlotClaimed` as they fold
    ///      `SlotTransferred`: after it the holder is no longer the address in
    ///      the claim log. A separate event, not `SlotTransferred`, so a
    ///      platform re-point is never mistaken for a holder's own move. Like
    ///      that event, it invalidates any snapshot of slot owners (the offline
    ///      check-in pack): a pack built before it still accepts the old ticket
    ///      until refreshed. `slot` is indexed: "what happened to this ticket"
    ///      is the question, and the new key is one nobody looks up.
    event SlotReissued(bytes32 indexed eventId, uint256 indexed slot, address indexed from, address to);

    /// @notice The owner ended bearer minting, reissue and `reseatBearer`, for good.
    event BearerMintsDisabled(address indexed by);

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
    error NotSponsor();
    /// @dev `windowResetsAt` is when the sponsor's window ends. If its cap is 0
    ///      the reset lifts nothing: read `sponsorMintAllowance(sponsor).perHour`
    ///      before retrying. If the last window had already ended, the call
    ///      opened a new one only in memory and reverted with it (audit 961
    ///      I-4): the value is when a window opened by that call would end, and
    ///      nothing was stored, so the next mint opens its own window.
    error MintCapExceeded(address sponsor, uint64 windowResetsAt);
    error TransferToLedger();
    /// @dev A signed terms action or seat move whose signature does not
    ///      recover to the event's organiser key: a wrong field, domain, stale
    ///      nonce or another key all land here, as in `NotSlotOwner`.
    error NotOrganiserKey();
    error SupplyUnchanged();
    error LengthMismatch();
    /// @dev `reissue`'s slots must be strictly ascending, so none appears twice.
    error SlotsNotAscending();
    error NotBearer();
    error NotSlotClaimer();
    /// @dev A holder has moved the slot at least once (`held`), so a key
    ///      someone keeps holds it and it is out of `reissue`'s reach.
    error SlotHeld();
    error BearerMintsOff();
    error AlreadyDisabled();
    /// @dev Never above the supply the event was registered with: more seats
    ///      than that is a new registration (a new ticket type).
    error SupplyAboveRegistered();
    /// @dev Later than `block.timestamp + MAX_SALES_EXTENSION`.
    error SalesEndTooFar();
    /// @dev A signed window (`deadline - issuedAt`) longer than
    ///      `MAX_TERMS_SIGNATURE_TTL`. Final: the window is signed.
    error DeadlineTooFar();
    /// @dev A signature whose `issuedAt` is still ahead of chain time.
    error SignatureNotYetValid();
    /// @dev A general-admission mint path called on a seated event.
    error SeatedEvent();
    /// @dev A seat path called on a general-admission event.
    error NotSeated();
    /// @dev A seat at or above the registered supply (`NO_SEAT` aside, where a
    ///      move accepts it).
    error InvalidSeat();
    /// @dev Another ticket holds the seat.
    error SeatTaken();
    /// @dev A seat move to the seat the ticket already has.
    error SeatUnchanged();

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

    constructor(address initialOwner, address initialSponsor, uint32 initialSponsorPerHour)
        Ownable(initialOwner)
        EIP712("WoCoTicketLedger", "2")
    {
        disputeAuthority = initialOwner;

        _addSponsor(initialSponsor, initialSponsorPerHour);
        emit DisputeAuthorityUpdated(initialOwner);
    }

    // ── Event lifecycle ───────────────────────────────────────────────────────

    /**
     * @notice Register a new general-admission event. `registerSeatedEvent`
     *         registers a seated one.
     * @param organiser    The event's owner of record: the account that may
     *                     act on its terms directly and move `organiserKey`
     *                     (`setOrganiserKey`). NOT the caller: in production
     *                     the caller is the platform's sponsor wallet
     *                     registering on the organiser's behalf.
     * @param organiserKey The key that signs the event's terms for the
     *                     organiser (see "Terms"). Non-zero, never this
     *                     contract. The platform checks off chain that the
     *                     organiser holds it before registering; here it is an
     *                     assertion, like `organiser`.
     * @param supply       Total tickets. Must fit in uint64 and be non-zero.
     * @param manifestRef  Off-chain ticket-manifest commit. Must be non-zero.
     *                     Refused with its own `EmptyManifestRef`, not the
     *                     `ZeroAddress` a zero organiser gets, so a caller can
     *                     tell which argument was wrong.
     * @param eventEndTs   UNIX seconds; the on-chain sales cutoff. `claimFor`
     *                     reverts `SalesClosed` at or after this. Only ever
     *                     moves later (`extendSalesEnd`, while it has not
     *                     passed) — see the monotonicity note above.
     *                     It is CHAIN time (audit 961 M-2). The sequencer stamps
     *                     blocks from its own clock, which in practice tracks
     *                     real time to seconds. The hard rule on the final
     *                     chain: each block's timestamp is CLAMPED into
     *                     [P - 24h, P + 768 s], P being the timestamp of the L1
     *                     block that posts its batch, and is never below the
     *                     previous block's (Arbitrum One
     *                     `SequencerInbox.maxTimeVariation`, read on L1
     *                     2026-09-24, governance can change it; nitro
     *                     `arbstate/inbox.go` getNextMsg,
     *                     `arbos/block_processor.go` createNewHeader). P is the
     *                     POSTING time, so a sequencer that holds batches back
     *                     can stamp blocks ahead of when a transaction was
     *                     ordered by that delay plus 768 s. So this cutoff can
     *                     arrive up to ~24h late, or early. The platform
     *                     enforces the real cutoff off chain, before any charge;
     *                     this is the backstop. Nothing that moves money may
     *                     rely on this value finer than hours (Arbitrum's own
     *                     guidance): release delays belong in days. A late clock
     *                     only delays a release, which is safe.
     */
    function registerEvent(
        address organiser,
        address organiserKey,
        uint64  supply,
        bytes32 manifestRef,
        uint64  eventEndTs
    ) external returns (bytes32 eventId) {
        eventId = _register(organiser, organiserKey, supply, manifestRef, eventEndTs, false);
    }

    /**
     * @notice Register a new SEATED event: `supply` seats, indices
     *         `0 .. supply - 1`, every ticket minted with one
     *         (`batchClaimSeats`, `batchClaimSeatsBearer`). The labels are
     *         committed off chain by `manifestRef`. Same arguments and checks
     *         as `registerEvent`, which stays byte-identical, so the server's
     *         registration walk and `Registered` read both kinds alike.
     */
    function registerSeatedEvent(
        address organiser,
        address organiserKey,
        uint64  supply,
        bytes32 manifestRef,
        uint64  eventEndTs
    ) external returns (bytes32 eventId) {
        eventId = _register(organiser, organiserKey, supply, manifestRef, eventEndTs, true);
        emit Seated(eventId);
    }

    function _register(
        address organiser,
        address organiserKey,
        uint64  supply,
        bytes32 manifestRef,
        uint64  eventEndTs,
        bool    seated
    ) private returns (bytes32 eventId) {
        if (organiser == address(0))       revert ZeroAddress();
        if (organiserKey == address(0))    revert ZeroAddress();
        // The ledger signs nothing and never calls itself, so a key or an
        // organiser set to it could never act (audit 1155 I-8).
        if (organiserKey == address(this)) revert TransferToLedger();
        if (organiser == address(this))    revert TransferToLedger();
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
        // reads as "never registered" and re-broadcasts a duplicate. Both kinds
        // share the one counter, so a seated id never collides with a GA one.
        eventId = keccak256(
            abi.encode(block.chainid, address(this), msg.sender, registrantNonce[msg.sender]++)
        );

        _events[eventId] = Event({
            totalSupply:  supply,
            nextSlot:     0,
            eventEndTs:   eventEndTs,
            exists:       true,
            cancelled:    false,
            seated:       seated,
            organiser:    organiser,
            registeredSupply: supply,
            manifestRef:  manifestRef,
            organiserKey: organiserKey
        });

        emit Registered(eventId, organiser, msg.sender, supply, manifestRef, eventEndTs);
        emit OrganiserKeySet(eventId, address(0), organiserKey);
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
        // Same sink as `_transfer` refuses, by the mint road (audit 960 M-1).
        if (to == address(this)) revert TransferToLedger();
        Event storage ev = _events[eventId];
        if (!ev.exists)                       revert EventNotFound();
        // A seatless ticket must never exist on a seated event.
        if (ev.seated)                        revert SeatedEvent();
        if (ev.cancelled)                     revert AlreadyCancelled();
        if (block.timestamp >= ev.eventEndTs) revert SalesClosed();
        if (ev.nextSlot >= ev.totalSupply)    revert InsufficientSupply();
        _consumeMintAllowance(1);

        uint64 first = ev.nextSlot;
        slot = uint256(first);
        // safe: first < totalSupply ≤ uint64.max
        unchecked { ev.nextSlot = first + 1; }

        _slots[eventId][slot] = Slot({owner: to, batchFirstSlot: first, bearer: false, held: false});
        _batchOrderRef[eventId][first] = orderRef;
        _batchClaimer[eventId][first]  = msg.sender;

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
        firstSlot = _claimBatch(eventId, owners, orderRef, false, false);
    }

    /**
     * @notice Mint N contiguous BEARER slots: tickets whose key the platform
     *         does not keep (the card checkout's one-off keys). Only bearer
     *         slots can later be replaced by `reissue`. Authorised sponsors
     *         only, until `disableBearerMints`.
     * @dev Same checks and logs as `batchClaimFor`; the only difference is the
     *      `bearer` bit, read back through `getSlotFlags`.
     */
    function batchClaimBearer(
        bytes32 eventId,
        address[] calldata owners,
        bytes32 orderRef
    ) external onlyAuthorised returns (uint256 firstSlot) {
        if (bearerMintsDisabled) revert BearerMintsOff();
        firstSlot = _claimBatch(eventId, owners, orderRef, true, false);
    }

    /**
     * @notice Mint N contiguous slots of a SEATED event, slot `firstSlot + i`
     *         to `owners[i]` in seat `seats[i]`. Authorised sponsors only.
     * @dev Slots stay sequential, exactly as on a general-admission event; the
     *      seat is recorded beside the slot. Each seat must be below the
     *      registered supply and free (`SeatTaken`), including against an
     *      earlier entry of the same batch. Below the REGISTERED supply, not
     *      the current one: a lowered supply caps how many tickets sell, never
     *      which seats may be chosen.
     */
    function batchClaimSeats(
        bytes32 eventId,
        address[] calldata owners,
        uint256[] calldata seats,
        bytes32 orderRef
    ) external onlyAuthorised returns (uint256 firstSlot) {
        firstSlot = _claimSeats(eventId, owners, seats, orderRef, false);
    }

    /// @notice `batchClaimSeats` minting BEARER slots, as `batchClaimBearer`.
    ///         Until `disableBearerMints`.
    function batchClaimSeatsBearer(
        bytes32 eventId,
        address[] calldata owners,
        uint256[] calldata seats,
        bytes32 orderRef
    ) external onlyAuthorised returns (uint256 firstSlot) {
        if (bearerMintsDisabled) revert BearerMintsOff();
        firstSlot = _claimSeats(eventId, owners, seats, orderRef, true);
    }

    function _claimSeats(
        bytes32 eventId,
        address[] calldata owners,
        uint256[] calldata seats,
        bytes32 orderRef,
        bool bearer
    ) private returns (uint256 firstSlot) {
        uint256 n = owners.length;
        if (seats.length != n) revert LengthMismatch();
        firstSlot = _claimBatch(eventId, owners, orderRef, bearer, true);
        uint64 seatCount = _events[eventId].registeredSupply;
        for (uint256 i; i < n;) {
            uint256 seat = seats[i];
            if (seat >= seatCount) revert InvalidSeat();
            _takeSeat(eventId, seat);
            uint256 s;
            // safe: firstSlot + i < totalSupply < 2^64, checked in _claimBatch
            unchecked { s = firstSlot + i; }
            // forge-lint: disable-next-line(unsafe-typecast)
            _seatOf[eventId][s] = uint64(seat) + 1; // safe: seat < registeredSupply <= 2^64 - 1
            emit SeatAssigned(eventId, s, seat);
            // safe: i < n <= 100
            unchecked { ++i; }
        }
    }

    /// @dev Sets the seat's bit, refusing one already set.
    function _takeSeat(bytes32 eventId, uint256 seat) private {
        uint256 bit = uint256(1) << (seat & 255);
        uint256 word = _seatTaken[eventId][seat >> 8];
        if (word & bit != 0) revert SeatTaken();
        _seatTaken[eventId][seat >> 8] = word | bit;
    }

    /// @dev Clears the seat's bit and bumps its `seatNonces`, so a signed move
    ///      into it made while it was held stays dead. Only called for a seat a
    ///      ticket holds.
    function _freeSeat(bytes32 eventId, uint256 seat) private {
        _seatTaken[eventId][seat >> 8] &= ~(uint256(1) << (seat & 255));
        unchecked { ++seatNonces[eventId][seat]; }
    }

    /**
     * @notice Point bearer slots at fresh keys, all or nothing: slot
     *         `slots[i]` goes to `newOwners[i]`. Same index, so the same
     *         edition, the same seat on a seated event, and no supply used.
     *         Authorised sponsors only, until
     *         `disableBearerMints`. See "Reissue" in the contract header for
     *         what this power is and what bounds it.
     * @dev Each slot must be claimed, bearer, minted by the CALLING sponsor and
     *      never moved by a holder (`held`). `slots` strictly ascending, so none
     *      is listed twice. Charged to the hourly mint cap like any mint, and
     *      refused once the event is cancelled or past its cutoff. Consumes the
     *      slot's transfer nonce, so a signature the old key made is dead. A
     *      slot can be reissued again: limiting that is the platform's rule.
     *      `getSlotData` keeps the batch's claimer and orderRef: the sale.
     *
     *      CALLERS MUST NEVER RE-POINT A SLOT TO AN ADDRESS THAT HAS HELD IT.
     *      Only `to == current owner` is refused here; pointing it back at an
     *      earlier holder makes that holder's ticket verify at the door again,
     *      because the door checks the ticket's signer against `slotOwner`.
     *      Mint every re-point to a freshly generated key.
     * @param eventId   The event the slots belong to.
     * @param slots     The slots to re-point, strictly ascending.
     * @param newOwners One fresh holder per slot, in the same order.
     */
    function reissue(
        bytes32 eventId,
        uint256[] calldata slots,
        address[] calldata newOwners
    ) external onlyAuthorised {
        if (bearerMintsDisabled) revert BearerMintsOff();
        uint256 n = slots.length;
        if (newOwners.length != n) revert LengthMismatch();
        _openForMint(eventId, n);

        for (uint256 i; i < n;) {
            if (i != 0 && slots[i] <= slots[i - 1]) revert SlotsNotAscending();
            _repoint(eventId, slots[i], newOwners[i]);
            // safe: i < n <= 100
            unchecked { ++i; }
        }
    }

    /// @dev One `reissue` re-point.
    function _repoint(bytes32 eventId, uint256 slot, address to) private {
        if (to == address(0)) revert ZeroAddress();
        if (to == address(this)) revert TransferToLedger();

        Slot storage sd = _slots[eventId][slot];
        address previous = sd.owner;
        // Mints are contiguous and nothing clears an owner, so owner 0 is
        // exactly "never claimed".
        if (previous == address(0)) revert SlotUnclaimed();
        if (!sd.bearer) revert NotBearer();
        if (_batchClaimer[eventId][sd.batchFirstSlot] != msg.sender) revert NotSlotClaimer();
        if (sd.held) revert SlotHeld();
        // A phantom re-point would still emit `SlotReissued`; see `_transfer`.
        if (to == previous) revert TransferToSelf();

        // ONLY the owner field, as in `_transfer`: `bearer`, `held` and the
        // batch attribution stay as minted.
        sd.owner = to;
        unchecked { ++transferNonces[eventId][slot]; }

        emit SlotReissued(eventId, slot, previous, to);
    }

    /// @dev The checks every mint path shares, the supply bound aside (`reissue`
    ///      uses no supply). Charges `n` to the caller's hourly cap.
    function _openForMint(bytes32 eventId, uint256 n) private returns (Event storage ev) {
        if (n == 0)  revert BatchEmpty();
        if (n > 100) revert BatchTooLarge();
        ev = _events[eventId];
        if (!ev.exists)                       revert EventNotFound();
        if (ev.cancelled)                     revert AlreadyCancelled();
        if (block.timestamp >= ev.eventEndTs) revert SalesClosed();
        _consumeMintAllowance(n);
    }

    /// @dev `seatPath` is true for the seat mints only: each path refuses the
    ///      other kind of event, so no seatless ticket exists on a seated event
    ///      and no seat on a general-admission one.
    function _claimBatch(bytes32 eventId, address[] calldata owners, bytes32 orderRef, bool bearer, bool seatPath)
        private
        returns (uint256 firstSlot)
    {
        uint256 n = owners.length;
        Event storage ev = _openForMint(eventId, n);
        if (ev.seated != seatPath) {
            if (seatPath) revert NotSeated();
            revert SeatedEvent();
        }
        uint64 first = ev.nextSlot;
        firstSlot = uint256(first);
        // safe: first < 2^64 and n <= 100, so the uint256 sum cannot overflow
        unchecked {
            if (firstSlot + n > ev.totalSupply) revert InsufficientSupply();
        }

        _batchOrderRef[eventId][first] = orderRef;
        _batchClaimer[eventId][first]  = msg.sender;

        for (uint256 i; i < n;) {
            address to = owners[i];
            if (to == address(0)) revert ZeroAddress();
            if (to == address(this)) revert TransferToLedger();
            uint256 s;
            // safe: firstSlot + i < first + n <= totalSupply < 2^64
            unchecked { s = firstSlot + i; }
            _slots[eventId][s] = Slot({owner: to, batchFirstSlot: first, bearer: bearer, held: false});
            emit SlotClaimed(eventId, s, to, msg.sender, orderRef);
            // safe: i < n <= 100
            unchecked { ++i; }
        }

        // safe: first + n <= totalSupply <= uint64.max, checked above; n <= 100 fits uint64
        // forge-lint: disable-next-line(unsafe-typecast)
        unchecked { ev.nextSlot = first + uint64(n); }
    }

    // ── Terms: supply, sales cutoff, cancellation, the organiser key ──────────

    /**
     * @notice Set the event's supply: fewer tickets for a smaller venue, and
     *         back up again, never above the supply it was registered with.
     *         The ORGANISER only: its account (`organiser`) or its organiser
     *         key, sending this call. `setSupplyWithSignature` takes the key's
     *         signature instead, so anyone can submit it.
     * @dev An absolute value, not a delta, so a retried transaction changes
     *      nothing twice. Never below the slots minted (a sold ticket is never
     *      taken back), never 0, and never above `registeredSupply`: the
     *      edition commitment (`manifestRef`) has a leaf for exactly that many,
     *      so a ticket past it is one the door has no edition for (audit 1059
     *      L-1). More than that is a new registration. Refused once cancelled
     *      (terminal) or past the sales cutoff. On a seated event it caps how
     *      many seats sell, never which.
     */
    function setSupply(bytes32 eventId, uint64 supply) external {
        _setSupply(_directTerms(eventId), eventId, supply);
    }

    /// @notice `setSupply` on the organiser key's EIP-712 signature over
    ///         `setSupplyDigest(eventId, supply, issuedAt, deadline)`. Anyone
    ///         may submit.
    function setSupplyWithSignature(
        bytes32 eventId,
        uint64 supply,
        uint256 issuedAt,
        uint256 deadline,
        bytes calldata signature
    ) external {
        _checkWindow(issuedAt, deadline);
        Event storage ev = _signedTerms(eventId, setSupplyDigest(eventId, supply, issuedAt, deadline), signature);
        _setSupply(ev, eventId, supply);
    }

    function _setSupply(Event storage ev, bytes32 eventId, uint64 supply) private {
        if (ev.cancelled)                     revert AlreadyCancelled();
        if (block.timestamp >= ev.eventEndTs) revert SalesClosed();
        if (supply == ev.totalSupply)         revert SupplyUnchanged();
        if (supply == 0 || supply < ev.nextSlot) revert InsufficientSupply();
        if (supply > ev.registeredSupply)     revert SupplyAboveRegistered();

        unchecked { ++termsNonces[eventId]; }
        uint64 previous = ev.totalSupply;
        ev.totalSupply = supply;
        emit SupplySet(eventId, previous, supply);
    }

    /**
     * @notice Move the sales cutoff LATER, for a postponed event, while it is
     *         still open. The ORGANISER only, as `setSupply`;
     *         `extendSalesEndWithSignature` takes the key's signature. Never
     *         earlier: see the monotonicity note in the header.
     * @dev Refused once the cutoff has passed (audit 1059 L-4): the cutoff is
     *      the event's real end, so a postponement is known before it, and an
     *      event that is over is registered again rather than reopened. At most
     *      `MAX_SALES_EXTENSION` ahead of now (audit 1059 M-1), per call: the
     *      organiser can call again (audit 1060 L-1, see the header). Ask for
     *      it with margin: chain time can sit ~24h off the wall clock, and
     *      `SalesClosed` is final.
     */
    function extendSalesEnd(bytes32 eventId, uint64 eventEndTs) external {
        _extendSalesEnd(_directTerms(eventId), eventId, eventEndTs);
    }

    /// @notice `extendSalesEnd` on the organiser key's EIP-712 signature over
    ///         `extendSalesEndDigest(eventId, eventEndTs, issuedAt, deadline)`.
    function extendSalesEndWithSignature(
        bytes32 eventId,
        uint64 eventEndTs,
        uint256 issuedAt,
        uint256 deadline,
        bytes calldata signature
    ) external {
        _checkWindow(issuedAt, deadline);
        Event storage ev =
            _signedTerms(eventId, extendSalesEndDigest(eventId, eventEndTs, issuedAt, deadline), signature);
        _extendSalesEnd(ev, eventId, eventEndTs);
    }

    function _extendSalesEnd(Event storage ev, bytes32 eventId, uint64 eventEndTs) private {
        if (ev.cancelled)                     revert AlreadyCancelled();
        if (block.timestamp >= ev.eventEndTs) revert SalesClosed();
        // With the cutoff still ahead, later than it is later than now.
        if (eventEndTs <= ev.eventEndTs)      revert InvalidEventEnd();
        if (eventEndTs > block.timestamp + MAX_SALES_EXTENSION) revert SalesEndTooFar();

        unchecked { ++termsNonces[eventId]; }
        uint64 previous = ev.eventEndTs;
        ev.eventEndTs = eventEndTs;
        emit SalesEndExtended(eventId, previous, eventEndTs);
    }

    /**
     * @notice Point the organiser key of the caller's events at `key`. The
     *         ORGANISER'S ACCOUNT only (`organiser`), for every id: the key
     *         itself cannot move the key. All or nothing.
     * @dev The rotation at a passkey removal: the account adds this call to
     *      the same operation that moves its key ring, so the old key and the
     *      new one swap with nothing in between. Consumes each event's
     *      `termsNonces`, so every signature the old key made, terms or seat
     *      move, is dead, and stays dead if the key ever comes back. Not
     *      refused once cancelled or past the cutoff, nor for an id already on
     *      `key` (skipped, no nonce spent): a rotation must not fail on one
     *      old or retried event. A wrong id (unknown, or another organiser's)
     *      still reverts the batch. No size cap: the organiser pays for its
     *      own list.
     */
    function setOrganiserKey(bytes32[] calldata eventIds, address key) external {
        uint256 n = eventIds.length;
        if (n == 0)                 revert BatchEmpty();
        if (key == address(0))      revert ZeroAddress();
        if (key == address(this))   revert TransferToLedger();

        for (uint256 i; i < n;) {
            bytes32 eventId = eventIds[i];
            Event storage ev = _events[eventId];
            if (!ev.exists)               revert EventNotFound();
            if (msg.sender != ev.organiser) revert NotOrganiser();
            address previous = ev.organiserKey;
            // Already on this key (a retried rotation, an id listed twice):
            // nothing moves, no nonce is spent. Never a revert: this call
            // rides inside the passkey-removal operation (audit 960 I-3's
            // rule for an emergency lever).
            if (previous == key) {
                unchecked { ++i; }
                continue;
            }

            unchecked { ++termsNonces[eventId]; }
            ev.organiserKey = key;
            emit OrganiserKeySet(eventId, previous, key);
            unchecked { ++i; }
        }
    }

    /**
     * @notice Void every organiser-signed action and seat move for the event
     *         that has not landed yet, and change nothing else. The ORGANISER
     *         only, as `setSupply`; `revokeSignaturesWithSignature` takes the
     *         key's signature. The app's "cancel" on a change still being saved.
     * @dev Consumes `termsNonces` (audit 1153 L-1), the bulk cancel signed
     *      approvals carry elsewhere (a counter, as an order book's). A holder's
     *      own signed `transferSlot` is untouched: it is the holder's, not the
     *      organiser's. Not refused once cancelled or past the cutoff: it can
     *      only take power away, so it never fails on an old event.
     */
    function revokeSignatures(bytes32 eventId) external {
        _directTerms(eventId);
        _revoke(eventId, msg.sender);
    }

    /// @notice `revokeSignatures` on the organiser key's EIP-712 signature over
    ///         `revokeSignaturesDigest(eventId, issuedAt, deadline)`. Anyone may
    ///         submit.
    function revokeSignaturesWithSignature(
        bytes32 eventId,
        uint256 issuedAt,
        uint256 deadline,
        bytes calldata signature
    ) external {
        _checkWindow(issuedAt, deadline);
        Event storage ev =
            _signedTerms(eventId, revokeSignaturesDigest(eventId, issuedAt, deadline), signature);
        _revoke(eventId, ev.organiserKey);
    }

    /// @dev `by` is who revoked: the caller on the direct path, the organiser
    ///      key on the signed one (never the submitter).
    function _revoke(bytes32 eventId, address by) private {
        unchecked { ++termsNonces[eventId]; }
        emit SignaturesRevoked(eventId, by);
    }

    /// @dev The direct terms path: the organiser's account, or its key, sends
    ///      the call.
    function _directTerms(bytes32 eventId) private view returns (Event storage ev) {
        ev = _events[eventId];
        if (!ev.exists) revert EventNotFound();
        if (msg.sender != ev.organiser && msg.sender != ev.organiserKey) revert NotOrganiser();
    }

    /// @dev The signed terms path: the signature must recover to the event's
    ///      organiser key. EOA signatures only (see "No reentrancy guard").
    function _signedTerms(bytes32 eventId, bytes32 digest, bytes calldata signature)
        private
        view
        returns (Event storage ev)
    {
        ev = _events[eventId];
        if (!ev.exists) revert EventNotFound();
        if (ECDSA.recoverCalldata(digest, signature) != ev.organiserKey) revert NotOrganiserKey();
    }

    /// @dev Every signed terms action and seat move: inside the window it
    ///      names, and that window no longer than `MAX_TERMS_SIGNATURE_TTL`.
    ///      In this order, so `deadline - issuedAt` cannot underflow.
    function _checkWindow(uint256 issuedAt, uint256 deadline) private view {
        if (block.timestamp > deadline) revert SignatureExpired();
        if (issuedAt > block.timestamp) revert SignatureNotYetValid();
        if (deadline - issuedAt > MAX_TERMS_SIGNATURE_TTL) revert DeadlineTooFar();
    }

    // ── Seats ─────────────────────────────────────────────────────────────────

    /**
     * @notice Move a BEARER ticket of a seated event to seat `toSeat`, on the
     *         organiser key's signature over `reseatBearerDigest(eventId, slot,
     *         toSeat, issuedAt, deadline)`. For a card ticket, whose key nobody
     *         holds: a wheelchair space, a broken seat. Anyone may submit.
     *         Until `disableBearerMints`.
     * @dev The slot must be bearer and never moved by a holder (`held`), the
     *      reach of `reissue`, but with the ORGANISER'S consent, not the
     *      platform's: no sponsor can move a seat. `toSeat` is a free seat, or
     *      `NO_SEAT` to empty it for a move to another band (a separate event:
     *      mint the new ticket there). The QR is unchanged. Consumes the slot's
     *      transfer nonce. No cap charge: it appends nothing and needs the
     *      organiser's signature. Refused once cancelled or past the cutoff.
     */
    function reseatBearer(
        bytes32 eventId,
        uint256 slot,
        uint256 toSeat,
        uint256 issuedAt,
        uint256 deadline,
        bytes calldata organiserSig
    ) external {
        if (bearerMintsDisabled) revert BearerMintsOff();
        _checkWindow(issuedAt, deadline);
        bytes32 digest = reseatBearerDigest(eventId, slot, toSeat, issuedAt, deadline);
        Event storage ev = _signedTerms(eventId, digest, organiserSig);
        Slot storage sd = _slots[eventId][slot];
        if (sd.owner == address(0)) revert SlotUnclaimed();
        if (!sd.bearer) revert NotBearer();
        if (sd.held) revert SlotHeld();
        _reseat(ev, eventId, slot, toSeat);
    }

    /**
     * @notice Move ANY ticket of a seated event to seat `toSeat`, on two
     *         signatures over the same `reseatDigest(eventId, slot, toSeat,
     *         issuedAt, deadline)`: the organiser key's (the seat map is the
     *         organiser's) and the holder's (the ticket is theirs). Anyone may
     *         submit.
     * @dev Two-party on purpose: a holder alone could take any free seat,
     *      including ones the organiser holds back off chain, and an organiser
     *      alone could move a ticket someone holds the key to. Sets `held`:
     *      a key someone keeps signed for the slot, so `reissue` and
     *      `reseatBearer` no longer reach it. The digest is this path's own
     *      type, so the organiser's half cannot be submitted through
     *      `reseatBearer` to skip `held` (audit 1152 L-1). Survives
     *      `disableBearerMints`. EOA holders only, as
     *      `transferSlotWithSignature`.
     */
    function reseat(
        bytes32 eventId,
        uint256 slot,
        uint256 toSeat,
        uint256 issuedAt,
        uint256 deadline,
        bytes calldata organiserSig,
        bytes calldata holderSig
    ) external {
        _checkWindow(issuedAt, deadline);
        bytes32 digest = reseatDigest(eventId, slot, toSeat, issuedAt, deadline);
        Event storage ev = _signedTerms(eventId, digest, organiserSig);
        Slot storage sd = _slots[eventId][slot];
        if (sd.owner == address(0)) revert SlotUnclaimed();
        if (ECDSA.recoverCalldata(digest, holderSig) != sd.owner) revert NotSlotOwner();
        sd.held = true;
        _reseat(ev, eventId, slot, toSeat);
    }

    /// @dev The move both seat paths share, after their authorisation.
    function _reseat(Event storage ev, bytes32 eventId, uint256 slot, uint256 toSeat) private {
        if (!ev.seated)                       revert NotSeated();
        if (ev.cancelled)                     revert AlreadyCancelled();
        if (block.timestamp >= ev.eventEndTs) revert SalesClosed();

        uint64 stored = _seatOf[eventId][slot];
        uint256 fromSeat = stored == 0 ? NO_SEAT : uint256(stored) - 1;
        if (toSeat == fromSeat) revert SeatUnchanged();

        if (fromSeat != NO_SEAT) _freeSeat(eventId, fromSeat);
        if (toSeat == NO_SEAT) {
            _seatOf[eventId][slot] = 0;
        } else {
            if (toSeat >= ev.registeredSupply) revert InvalidSeat();
            _takeSeat(eventId, toSeat);
            // forge-lint: disable-next-line(unsafe-typecast)
            _seatOf[eventId][slot] = uint64(toSeat) + 1; // safe: toSeat < registeredSupply <= 2^64 - 1
        }
        unchecked { ++transferNonces[eventId][slot]; }

        emit SlotReseated(eventId, slot, fromSeat, toSeat);
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
     *      Version 2's `reissue` is the one narrow exception, accepted by the
     *      owner on 2026-10-26 with its off switch: only slots minted bearer
     *      (to a key nobody holds) by the calling sponsor, never one a holder
     *      has moved, within the mint cap, and never after
     *      `disableBearerMints`. It reaches no ticket minted to, or moved to, a
     *      key someone keeps. See "Reissue" in the contract header.
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
     *      nonce, deadline)` under the EIP-712 domain ("WoCoTicketLedger", "2",
     *      chain id, this contract). `from` and `nonce` come from storage, so a
     *      signature counts only while its signer holds the slot, and only
     *      until the slot next moves by EITHER transfer path or by `reissue`
     *      (`transferNonces`). The domain stops it being replayed on another
     *      chain or deployment.
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
     *      `deadline` is CHAIN time (audit 961 L-2), under the rule stated on
     *      `registerEvent`'s `eventEndTs`: a signature can stay valid up to
     *      ~24h past the wall-clock deadline, or lapse early. To void one for certain, move the slot,
     *      which consumes the nonce.
     *
     *      The digest names `from` and the nonce as read at SUBMISSION (audit
     *      961 L-4). A message naming the signer as `from` for a slot it does
     *      not yet hold becomes valid once the slot is minted, or later moved,
     *      to it while the nonce still equals the one it signed.
     *      Wallets and the platform must never ask a holder to sign a transfer
     *      for a slot it does not hold now.
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
                    _slots[eventId][slot].owner,
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
        // The ledger holds no key and never calls itself, so a slot sent here
        // could never move again: the burn this contract forbids, by another
        // road (audit 959 I-8). Its own error, so the guard is killable alone.
        if (newOwner == address(this)) revert TransferToLedger();

        Slot storage sd = _slots[eventId][slot];
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

        // ONLY these fields. Never reconstruct the struct: writing
        // `Slot({owner: newOwner, batchFirstSlot: 0, ...})` compiles and silently
        // re-points this slot's claimer/orderRef at batch 0's real data — a
        // live misattribution, not zero values.
        sd.owner = newOwner;
        // A key someone keeps holds it now: out of `reissue`'s reach for good.
        sd.held = true;
        // Consumed by every move: either transfer path, and `reissue` — see `transferNonces`.
        unchecked { ++transferNonces[eventId][slot]; }

        emit SlotTransferred(eventId, slot, previousOwner, newOwner);
    }

    /**
     * @notice Cancel an event. One-way. Stops all further minting, and lets a
     *         payments contract open refunds for whatever it still holds.
     *
     *         The ORGANISER only: its account or its organiser key, sending
     *         this call; `cancelEventWithSignature` takes the key's signature.
     *         Sponsors deliberately CANNOT cancel — that is what keeps the
     *         sponsor capability to "append slots" and nothing more. The
     *         platform cancels through `forceCancelEvent`, which is a
     *         separate, separately-visible power.
     */
    function cancelEvent(bytes32 eventId) external {
        _cancel(_directTerms(eventId), eventId, msg.sender);
    }

    /// @notice `cancelEvent` on the organiser key's EIP-712 signature over
    ///         `cancelEventDigest(eventId, issuedAt, deadline)`. Anyone may
    ///         submit; the signed 48-hour window keeps a held signature from
    ///         being a standing option to cancel.
    function cancelEventWithSignature(
        bytes32 eventId,
        uint256 issuedAt,
        uint256 deadline,
        bytes calldata signature
    ) external {
        _checkWindow(issuedAt, deadline);
        Event storage ev = _signedTerms(eventId, cancelEventDigest(eventId, issuedAt, deadline), signature);
        _cancel(ev, eventId, ev.organiserKey);
    }

    /// @dev `by` is who cancelled: the caller on the direct path, the
    ///      organiser key on the signed one (never the submitter).
    function _cancel(Event storage ev, bytes32 eventId, address by) private {
        if (ev.cancelled) revert AlreadyCancelled();
        unchecked { ++termsNonces[eventId]; }
        ev.cancelled = true;
        emit EventCancelled(eventId, by, false);
    }

    /**
     * @notice Cancel an event when the organiser will not — or cannot. Dispute
     *         authority only. Same one-way flag as `cancelEvent`; separate
     *         entrypoint so the power is distinguishable on chain from an
     *         organiser's own cancellation (`EventCancelled.forced`).
     *
     *         "or cannot" is load-bearing: until an organiser-facing cancel is
     *         wired (the platform relaying `cancelEventWithSignature`), every
     *         real cancellation arrives here; and an organiser whose account
     *         is lost can no longer cancel at all.
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
        emit EventCancelled(eventId, msg.sender, true);
    }

    // ── Views ─────────────────────────────────────────────────────────────────

    /// @notice Core event params. `totalSupply` is the CURRENT supply
    ///         (`setSupply` moves it, never above `getRegisteredSupply`);
    ///         `manifestRef` is the one registered.
    /// @dev Same signature as version 1, so a reader written for it works here.
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
    ///      caller forgets. `owner == address(0)` is still THE test for
    ///      "unclaimed".
    ///
    ///      Same signature and meaning as version 1. After a `reissue` or a
    ///      transfer, `holder` is the new key and `claimer`/`orderRef` stay
    ///      the sale's.
    function getSlotData(bytes32 eventId, uint256 slot)
        external
        view
        returns (address holder, address claimer, bytes32 orderRef)
    {
        Slot memory sd = _slots[eventId][slot];
        if (sd.owner == address(0)) return (address(0), address(0), bytes32(0));
        return (
            sd.owner,
            _batchClaimer[eventId][sd.batchFirstSlot],
            _batchOrderRef[eventId][sd.batchFirstSlot]
        );
    }

    /// @notice address(0) for a slot that was never claimed.
    function slotOwner(bytes32 eventId, uint256 slot) external view returns (address) {
        return _slots[eventId][slot].owner;
    }

    /// @notice Whether a slot was minted bearer, and whether a holder has
    ///         moved it since (`held`). `reissue` reaches a slot only while it
    ///         is bearer and not held. Both false for an unclaimed slot.
    function getSlotFlags(bytes32 eventId, uint256 slot) external view returns (bool bearer, bool held) {
        Slot memory sd = _slots[eventId][slot];
        return (sd.bearer, sd.held);
    }

    /// @notice The key that signs the event's terms and seat moves for the
    ///         organiser (`OrganiserKeySet`).
    function getOrganiserKey(bytes32 eventId) external view returns (address) {
        Event storage ev = _events[eventId];
        if (!ev.exists) revert EventNotFound();
        return ev.organiserKey;
    }

    /// @notice Whether the event was registered seated (`registerSeatedEvent`).
    function isSeated(bytes32 eventId) external view returns (bool) {
        Event storage ev = _events[eventId];
        if (!ev.exists) revert EventNotFound();
        return ev.seated;
    }

    /// @notice The slot's seat, or `NO_SEAT`: on a general-admission event, for
    ///         an unclaimed slot, and for a ticket moved out of its seat. A
    ///         door refuses a seated event's ticket that reads `NO_SEAT`.
    function seatOf(bytes32 eventId, uint256 slot) external view returns (uint256) {
        uint64 stored = _seatOf[eventId][slot];
        return stored == 0 ? NO_SEAT : uint256(stored) - 1;
    }

    /// @notice Seats `256 * word .. 256 * word + 255` as a bitmap, bit set =
    ///         taken: a seat picker reads 256 seats per call.
    function seatWord(bytes32 eventId, uint256 word) external view returns (uint256) {
        return _seatTaken[eventId][word];
    }

    /// @notice What the organiser key signs for `setSupplyWithSignature`.
    /// @dev Bound to the CURRENT `termsNonces`, so it changes after every
    ///      terms write. Wallets that sign typed data build the same struct.
    function setSupplyDigest(bytes32 eventId, uint64 supply, uint256 issuedAt, uint256 deadline)
        public
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(abi.encode(SET_SUPPLY_TYPEHASH, eventId, supply, termsNonces[eventId], issuedAt, deadline))
        );
    }

    /// @notice What the organiser key signs for `extendSalesEndWithSignature`.
    function extendSalesEndDigest(bytes32 eventId, uint64 eventEndTs, uint256 issuedAt, uint256 deadline)
        public
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(EXTEND_SALES_END_TYPEHASH, eventId, eventEndTs, termsNonces[eventId], issuedAt, deadline)
            )
        );
    }

    /// @notice What the organiser key signs for `cancelEventWithSignature`.
    function cancelEventDigest(bytes32 eventId, uint256 issuedAt, uint256 deadline) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(abi.encode(CANCEL_EVENT_TYPEHASH, eventId, termsNonces[eventId], issuedAt, deadline))
        );
    }

    /// @notice What the organiser key signs for `revokeSignaturesWithSignature`.
    function revokeSignaturesDigest(bytes32 eventId, uint256 issuedAt, uint256 deadline)
        public
        view
        returns (bytes32)
    {
        return _hashTypedDataV4(
            keccak256(abi.encode(REVOKE_SIGNATURES_TYPEHASH, eventId, termsNonces[eventId], issuedAt, deadline))
        );
    }

    /// @notice What the organiser key AND the holder sign for `reseat`.
    ///         Bound to the slot's CURRENT owner and transfer nonce, the event's
    ///         CURRENT `termsNonces` and the target seat's CURRENT `seatNonces`,
    ///         so it changes whenever the slot moves or reseats, whenever the
    ///         organiser writes anything, and whenever the target seat is freed.
    function reseatDigest(bytes32 eventId, uint256 slot, uint256 toSeat, uint256 issuedAt, uint256 deadline)
        public
        view
        returns (bytes32)
    {
        return _seatMoveDigest(RESEAT_TYPEHASH, eventId, slot, toSeat, issuedAt, deadline);
    }

    /// @notice What the organiser key signs for `reseatBearer`. Bound as
    ///         `reseatDigest`, under its own type (audit 1152 L-1).
    function reseatBearerDigest(bytes32 eventId, uint256 slot, uint256 toSeat, uint256 issuedAt, uint256 deadline)
        public
        view
        returns (bytes32)
    {
        return _seatMoveDigest(RESEAT_BEARER_TYPEHASH, eventId, slot, toSeat, issuedAt, deadline);
    }

    function _seatMoveDigest(
        bytes32 typehash,
        bytes32 eventId,
        uint256 slot,
        uint256 toSeat,
        uint256 issuedAt,
        uint256 deadline
    ) private view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    typehash,
                    eventId,
                    slot,
                    toSeat,
                    _slots[eventId][slot].owner,
                    transferNonces[eventId][slot],
                    termsNonces[eventId],
                    seatNonces[eventId][toSeat],
                    issuedAt,
                    deadline
                )
            )
        );
    }

    /// @notice The supply the event was registered with: the editions its
    ///         `manifestRef` commits, and the most `setSupply` can set.
    function getRegisteredSupply(bytes32 eventId) external view returns (uint64) {
        Event storage ev = _events[eventId];
        if (!ev.exists) revert EventNotFound();
        return ev.registeredSupply;
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
    ///      It says nothing about any sponsor's hourly cap, nor whether a batch
    ///      of a given size fits (audit 960 I-8): those are
    ///      `sponsorMintAllowance` and this figure read together.
    ///
    ///      Reverts `EventNotFound` for an unknown id, like `getEvent` and
    ///      `getEventStatus`: returning 0 made a mistyped id indistinguishable
    ///      from a sold-out event.
    function remaining(bytes32 eventId) external view returns (uint256) {
        Event memory ev = _events[eventId];
        if (!ev.exists)                       revert EventNotFound();
        if (ev.cancelled)                     return 0;
        if (block.timestamp >= ev.eventEndTs) return 0;
        // safe: every path keeps nextSlot <= totalSupply (mint bounds, setSupply's floor)
        unchecked { return ev.totalSupply - ev.nextSlot; }
    }

    // ── Admin ─────────────────────────────────────────────────────────────────

    /// @notice Authorise `sponsor` to mint, at most `perHour` slots per hour.
    /// @dev The cap is required, never defaulted: choosing it is the decision
    ///      that bounds a leaked key. `UNLIMITED_MINTS` for a sponsor the chain
    ///      can check. Re-adding a removed sponsor keeps its open window
    ///      unless the new cap crosses the unlimited boundary (see
    ///      `MintAllowance`).
    function addSponsor(address sponsor, uint32 perHour) external onlyOwner {
        _addSponsor(sponsor, perHour);
    }

    /// @dev Succeeds, and emits, for an address that is not a sponsor, on
    ///      purpose (audit 960 I-3, 961 L-1): the emergency lever must stay
    ///      idempotent, so a Safe batch never reverts because a key was
    ///      already removed. `authorisedSponsors` is the state; the event is
    ///      not proof a sponsor existed. A sponsor holds no event's terms, so
    ///      removing one ends its minting and reissue and nothing else.
    function removeSponsor(address sponsor) external onlyOwner {
        authorisedSponsors[sponsor] = false;
        emit SponsorRemoved(sponsor);
    }

    /// @notice Retune an authorised sponsor's hourly cap. Takes effect on its
    ///         next mint; raising it lifts a refusal at once, and 0 stops the
    ///         sponsor minting without de-authorising it.
    /// @dev Between finite caps it writes `perHour` only: the open window keeps
    ///      its end and its count. Into or out of `UNLIMITED_MINTS` it closes the
    ///      window (audit 960 M-2).
    function setSponsorMintCap(address sponsor, uint32 perHour) external onlyOwner {
        if (!authorisedSponsors[sponsor]) revert NotSponsor();
        _setMintCap(sponsor, perHour);
    }

    /// @notice A sponsor's cap, what it may still mint now, and when its window
    ///         ends. For `/api/health` to report "mint cap reached until <time>"
    ///         before a sale fails, rather than after.
    /// @dev No open window: `mintable` is the whole cap and `windowResetsAt`
    ///      is when a window opened now would end. Unlimited: `mintable` is
    ///      `UNLIMITED_MINTS` and `windowResetsAt` 0. Says nothing about
    ///      authorisation; that is `authorisedSponsors`.
    function sponsorMintAllowance(address sponsor)
        external
        view
        returns (uint32 perHour, uint32 mintable, uint64 windowResetsAt)
    {
        MintAllowance memory a = _mintAllowance[sponsor];
        perHour = a.perHour;
        if (perHour == UNLIMITED_MINTS) return (perHour, UNLIMITED_MINTS, 0);
        uint64 nowTs = uint64(block.timestamp);
        if (nowTs >= a.windowEnd) return (perHour, perHour, nowTs + MINT_WINDOW);
        // A lowered cap can sit below what the window already spent.
        mintable = a.used >= perHour ? 0 : perHour - a.used;
        windowResetsAt = a.windowEnd;
    }

    /// @notice End bearer minting (`batchClaimBearer`, `batchClaimSeatsBearer`),
    ///         `reissue` and `reseatBearer`, for good. One-way: there is no
    ///         function that turns them back on, so once it is called anyone can
    ///         read on chain that the platform can no longer replace a ticket.
    ///         Sales through `batchClaimFor`/`claimFor`/`batchClaimSeats`, the
    ///         organiser's terms, `reseat` and transfers carry on.
    /// @dev The off-ramp for the day tickets are minted to keys their holders
    ///      control (WoCo-Event-App #298): call it once the last bearer sale's
    ///      event is over.
    function disableBearerMints() external onlyOwner {
        if (bearerMintsDisabled) revert AlreadyDisabled();
        bearerMintsDisabled = true;
        emit BearerMintsDisabled(msg.sender);
    }

    function setDisputeAuthority(address authority) external onlyOwner {
        if (authority == address(0)) revert ZeroAddress();
        // The ledger never calls itself, so this would brick force-cancel (audit 960 I-9).
        if (authority == address(this)) revert TransferToLedger();
        disputeAuthority = authority;
        emit DisputeAuthorityUpdated(authority);
    }

    /// @dev Moves `disputeAuthority` with ownership while the two are the same
    ///      address (audit 959 L-1). A handover is often made BECAUSE the old
    ///      owner's signers are suspect, and without this the old owner kept
    ///      `forceCancelEvent` over every event, one-way, until a second call
    ///      caught it. THE RULE: at a handover, if the dispute authority IS the
    ///      outgoing owner it moves to the new owner; otherwise it stays where
    ///      it is. It is keyed on the address, not on a "set apart" flag, on
    ///      purpose (audit
    ///      960 L-1): after `setDisputeAuthority(D)` and a handover to D, D holds
    ///      both roles, and a flag would let a later handover away from D leave
    ///      the retiring D with force-cancel, which is exactly the defect above.
    ///      `previous == address(0)` is the constructor's call, whose body sets
    ///      the authority itself.
    ///
    ///      A convenience for an honest owner, not a control against a
    ///      malicious one (audit 961 I-2): the owner can set the authority
    ///      anywhere but zero and this contract, with `setDisputeAuthority`, at
    ///      any time.
    function _transferOwnership(address newOwner) internal override {
        address previous = owner();
        super._transferOwnership(newOwner);
        if (previous != address(0) && disputeAuthority == previous) {
            disputeAuthority = newOwner;
            emit DisputeAuthorityUpdated(newOwner);
        }
    }

    function _addSponsor(address sponsor, uint32 perHour) private {
        if (sponsor == address(0)) revert ZeroAddress();
        authorisedSponsors[sponsor] = true;
        emit SponsorAdded(sponsor);
        _setMintCap(sponsor, perHour);
    }

    function _setMintCap(address sponsor, uint32 perHour) private {
        MintAllowance storage a = _mintAllowance[sponsor];
        // Crossing the unlimited boundary closes the window; see `MintAllowance`.
        if ((a.perHour == UNLIMITED_MINTS) != (perHour == UNLIMITED_MINTS)) {
            a.used = 0;
            a.windowEnd = 0;
        }
        a.perHour = perHour;
        emit SponsorMintCapSet(sponsor, perHour);
    }

    /// @dev Charges `n` slots to the calling sponsor's window, opening a fresh
    ///      window if the last one has ended. Reverts with the reset time so the
    ///      server can report it. Unlimited sponsors skip it without a write.
    function _consumeMintAllowance(uint256 n) internal {
        MintAllowance memory a = _mintAllowance[msg.sender];
        if (a.perHour == UNLIMITED_MINTS) return;
        uint64 nowTs = uint64(block.timestamp);
        if (nowTs >= a.windowEnd) {
            a.windowEnd = nowTs + MINT_WINDOW;
            a.used = 0;
        }
        if (uint256(a.used) + n > a.perHour) revert MintCapExceeded(msg.sender, a.windowEnd);
        // safe: used + n <= perHour < 2^32 by the check above
        // forge-lint: disable-next-line(unsafe-typecast)
        a.used += uint32(n);
        _mintAllowance[msg.sender] = a;
    }

    /// @notice Disabled: always reverts `RenounceDisabled`.
    /// @dev Renouncing would set `owner` to address(0) for good, and every
    ///      `onlyOwner` power would go with it — `addSponsor`, `removeSponsor`,
    ///      `setSponsorMintCap`, `setDisputeAuthority`. A leaked sponsor key could then never be
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
