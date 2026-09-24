# Audit brief: WoCoTicketLedger re-audit after LeftClaw job 960

Read this whole file before starting. It is the engagement's scope, context, guarantees and focus.

## Scope
- `src/WoCoTicketLedger.sol` and `script/DeployTicketLedger.s.sol`, at the commit this file is in.
- Chain: Arbitrum One (42161). Not deployed yet. The contract is deployed once and can never be upgraded
  or patched, so every finding is actionable before deploy.
- Dependencies at the same commit: `lib/openzeppelin-contracts` v5.6.1 (Ownable2Step, EIP712, ECDSA).
- Tests (under `test/`): `WoCoTicketLedgerAudit960.t.sol`, `WoCoTicketLedgerAudit959.t.sol` (includes a fuzz
  test and a cap invariant), `DeployTicketLedger.t.sol`, `WoCoTicketLedger.t.sol`,
  `WoCoTicketLedgerSignedTransfer.t.sol`, `WoCoTicketLedgerInvariant.t.sol`.
- Deliver findings in the report only. Do not open GitHub issues.

## What it is
The ticket allocation ledger for an event platform. It holds no funds and makes no calls to other
contracts. `registerEvent` is permissionless and stamps a supply, a manifest commit, an organiser and a
sales cutoff; the event id is `keccak256(chainid, this contract, registrant, registrant nonce)`. Authorised
sponsors mint slots (tickets) to buyer addresses, one at a time or up to 100 per batch, within supply,
before the cutoff, while not cancelled, and within the sponsor's hourly mint cap. The organiser, or the
dispute authority, can cancel. A slot's current owner can move it directly (`transferSlot`) or with an
EIP-712 signature naming the recipient that anyone may submit (`transferSlotWithSignature`: domain
"WoCoTicketLedger" / "1", per-slot nonce, deadline). A slot can never be burned. An Ownable2Step owner (a
Safe native to Arbitrum One) manages sponsors, caps and the dispute authority; `renounceOwnership` always
reverts.

Deployment plan: the Safe is `initialOwner`, so it is also the first dispute authority. The first sponsor
is a fresh platform-held EOA that mints after a card payment settles off chain (the chain cannot see the
card payment), capped at about 1,000 slots per hour. A future payments contract that mints only in the
transaction that takes the money would be added later as a second sponsor with `UNLIMITED_MINTS`.

## History
Audited as LeftClaw jobs 928 (at `7352d0a`), 959 (at `52a44cb`) and 960 (at `fe5f518`). Please read this
commit as new code, not as a diff, and say whether any finding from those jobs still applies.

Changes after job 960:
1. 960 M-1: `claimFor` and `batchClaimFor` refuse `address(this)` as a first holder (`TransferToLedger`),
   matching the transfer paths.
2. 960 M-2: `_setMintCap` closes the open window (resets `used` and `windowEnd`) when a sponsor moves into or
   out of `UNLIMITED_MINTS`. Between finite caps a retune still writes only `perHour`, so an open window keeps
   its end and count.
3. 960 L-4: `EventCancelled(bytes32 indexed eventId, address indexed by, bool forced)`; `forced` is true only
   for `forceCancelEvent`.
4. Deploy script (960 L-2, L-6, I-4, I-5): the first sponsor's cap must be finite and non-zero; off known
   testnets (31337, 421614, 84532, 11155111, 11155420) the owner must have code, must answer `getThreshold()`
   with one non-zero word, must list `INITIAL_OWNER_SIGNER` as an owner (`isOwner` answers 1), and must be
   neither the sponsor nor the deployer; owner, dispute authority, sponsor and cap are read back after deploy.
   Inputs come through a virtual `_config()` so tests never set the process environment. The "unlimited"
   value is one file-level constant (`LEDGER_UNLIMITED_MINTS`) shared by the contract and the script.
5. 960 I-9: `setDisputeAuthority` refuses `address(this)` (`TransferToLedger`).
6. Natspec only: 960 L-5 (the window runs on the sequencer's `block.timestamp`), L-7 (one sponsor's cap is
   shared across the events it mints into), I-6 (`claimer` is the minting sponsor, not the payer), I-8
   (`remaining()` covers neither caps nor batch size).

Kept after job 960, with reasons (please challenge them):
- 960 L-1: the dispute authority follows an ownership handover whenever it equals the OUTGOING owner, keyed
  on the address, not on a sticky "set apart" flag. With a flag, after `setDisputeAuthority(D)` and a handover
  to D, a later handover away from D would leave the retiring D with `forceCancelEvent` - the defect job 959
  L-1 fixed.
- 960 I-3: `removeSponsor` accepts an address that is not a sponsor, so an emergency Safe batch never reverts
  because a key was already removed.
- 960 L-3, I-1, I-2, I-7, I-10, I-11: unchanged (cosmetic, off-chain by design, or recoverable in one
  owner transaction).

## Guarantees to test
1. A sponsor can only append: it can mint new slots within supply, before the cutoff and within its cap, but
   can never move, cancel or rewrite an existing slot, or change a registered event.
2. Within one window a capped sponsor mints at most the highest cap in force during that window; no retune,
   remove or re-add between finite caps hands back spent allowance or re-anchors the window; one sponsor's use
   never affects another's; crossing `UNLIMITED_MINTS` starts a fresh window.
3. A slot moves only with its current owner's authority. A signed transfer cannot be redirected, replayed,
   reused after the slot has moved, or used on another chain or contract.
4. Supply is never exceeded, and stamped terms never change after registration. No path creates a slot owned
   by `address(0)` or by the ledger itself.
5. After an ownership handover the previous owner never holds the dispute authority (it moves with the
   handover if the previous owner held it; an authority that was a different address stays put). The
   previous owner keeps power over the ledger only if it is also a sponsor.

## Please focus on
1. The M-2 change: every sequence of `addSponsor`, `setSponsorMintCap` (including `UNLIMITED_MINTS` and 0),
   `removeSponsor` and mints across window boundaries. Can any owner action or sponsor sequence exceed
   guarantee 2, or leave a sponsor wrongly blocked?
2. The `_transferOwnership` override and the L-1 rule: any path that moves or strands the dispute authority
   against guarantee 5.
3. The mint-path `address(this)` guards and the new `EventCancelled` layout (an indexer rebuilding state from
   logs).
4. The deploy script's checks: can a wrong owner, sponsor or cap still get through on a production chain?
5. Anything the earlier jobs did not examine.

## Design assumptions (challenge them if they do not hold)
The owner is a trusted Safe and can set any cap, including unlimited, and can add itself as a sponsor. The cap
is a backstop against a leaked sponsor key, not a proof of payment. Per-event sponsor scoping was rejected
because one platform key registers and mints every event. There is no function to cancel a signed but
unsubmitted transfer: signatures are created at the moment of use with short deadlines, and an unused one
lapses or is voided by moving the slot. Transfer signatures are EOA-only, with no ERC-1271 path. `organiser`
is the registrant's assertion, not a proof.
