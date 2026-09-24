// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {WoCoTicketLedger} from "../src/WoCoTicketLedger.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/**
 * The fixes for LeftClaw audit 959 (re-audit of 52a44cb):
 *   M-1  per-sponsor hourly mint cap (a leaked hot key takes at most a cap per hour)
 *   L-1  disputeAuthority follows an Ownable2Step handover while tied to the owner
 *   L-2  the raw slot/batch getters are gone; getSlotData is the read
 *   I-4  SlotTransferred indexes `to`, not `slot`
 *   I-8  a slot cannot be sent to the ledger itself
 *
 * Each guard has a test here that fails if the guard is removed.
 */
contract WoCoTicketLedgerAudit959Test is Test {
    WoCoTicketLedger public ledger;

    address owner     = address(0x1);
    address sponsor   = address(0x2);
    address sponsor2  = address(0x22);
    address organiser = address(0x3);
    address buyer     = address(0x6);
    address newOwner  = address(0x7);
    address daoAuth   = address(0x9);
    address stranger  = address(0xBEEF);

    uint32  constant CAP      = 5;
    bytes32 constant MANIFEST = keccak256("manifest");
    uint64  constant SUPPLY   = 1_000;
    uint256 constant NOW      = 1_800_000_000;
    uint64  constant END_TS   = 1_800_604_800; // NOW + 7 days

    event SponsorAdded(address indexed sponsor);
    event SponsorMintCapSet(address indexed sponsor, uint32 perHour);
    event DisputeAuthorityUpdated(address indexed authority);

    function setUp() public {
        vm.warp(NOW);
        ledger = new WoCoTicketLedger(owner, sponsor, CAP);
    }

    function _register() internal returns (bytes32 eventId) {
        vm.prank(sponsor);
        eventId = ledger.registerEvent(organiser, SUPPLY, MANIFEST, END_TS);
    }

    function _owners(uint256 n) internal view returns (address[] memory a) {
        a = new address[](n);
        for (uint256 i; i < n; ++i) a[i] = buyer;
    }

    function _mint(address as_, bytes32 eventId, uint256 n) internal {
        vm.prank(as_);
        ledger.batchClaimFor(eventId, _owners(n), keccak256("order"));
    }

    function _remaining(address s) internal view returns (uint32 remaining) {
        (, remaining, ) = ledger.sponsorMintAllowance(s);
    }

    // ── M-1: the cap ──────────────────────────────────────────────────────────

    function test_Cap_ConstructorStampsTheInitialSponsorsCap() public {
        (uint32 perHour, uint32 remaining, uint64 resetsAt) = ledger.sponsorMintAllowance(sponsor);
        assertEq(perHour, CAP);
        assertEq(remaining, CAP);
        assertEq(resetsAt, NOW + 1 hours);

        vm.expectEmit(true, false, false, true);
        emit SponsorAdded(sponsor);
        vm.expectEmit(true, false, false, true);
        emit SponsorMintCapSet(sponsor, 7);
        new WoCoTicketLedger(owner, sponsor, 7);
    }

    function test_Cap_ClaimForRefusesTheMintPastTheCap() public {
        bytes32 eventId = _register();
        for (uint256 i; i < CAP; ++i) {
            vm.prank(sponsor);
            ledger.claimFor(eventId, buyer, bytes32(i));
        }
        assertEq(_remaining(sponsor), 0);

        vm.expectRevert(abi.encodeWithSelector(WoCoTicketLedger.MintCapExceeded.selector, sponsor, uint64(NOW + 1 hours)));
        vm.prank(sponsor);
        ledger.claimFor(eventId, buyer, bytes32(uint256(99)));
    }

    /// A batch is charged per SLOT, and one that does not fit is refused whole:
    /// no partial mint that leaves some buyers of one order without a ticket.
    function test_Cap_BatchIsChargedPerSlotAndRefusedWhole() public {
        bytes32 eventId = _register();
        _mint(sponsor, eventId, 4);
        assertEq(_remaining(sponsor), 1);

        vm.expectRevert(abi.encodeWithSelector(WoCoTicketLedger.MintCapExceeded.selector, sponsor, uint64(NOW + 1 hours)));
        vm.prank(sponsor);
        ledger.batchClaimFor(eventId, _owners(2), keccak256("order"));

        (, uint64 nextSlot, , ) = ledger.getEvent(eventId);
        assertEq(nextSlot, 4, "refused batch minted nothing");
        _mint(sponsor, eventId, 1);
        assertEq(_remaining(sponsor), 0);
    }

    function test_Cap_WindowReopensExactlyAtItsEnd() public {
        bytes32 eventId = _register();
        _mint(sponsor, eventId, CAP);

        vm.warp(NOW + 1 hours - 1);
        vm.expectRevert(abi.encodeWithSelector(WoCoTicketLedger.MintCapExceeded.selector, sponsor, uint64(NOW + 1 hours)));
        vm.prank(sponsor);
        ledger.claimFor(eventId, buyer, 0);

        vm.warp(NOW + 1 hours);
        _mint(sponsor, eventId, CAP);
        (, uint32 remaining, uint64 resetsAt) = ledger.sponsorMintAllowance(sponsor);
        assertEq(remaining, 0);
        assertEq(resetsAt, NOW + 2 hours, "the new window runs from the mint that opened it");
    }

    /// Unlimited skips the accounting entirely: nothing is charged, so capping
    /// the sponsor afterwards finds no window open and a full allowance.
    function test_Cap_UnlimitedChargesNothing() public {
        uint32 unlimited = ledger.UNLIMITED_MINTS();
        vm.prank(owner);
        ledger.addSponsor(sponsor2, unlimited);
        bytes32 eventId = _register();

        _mint(sponsor2, eventId, 100);
        _mint(sponsor2, eventId, 100);
        (uint32 perHour, uint32 remaining, uint64 resetsAt) = ledger.sponsorMintAllowance(sponsor2);
        assertEq(perHour, unlimited);
        assertEq(remaining, unlimited);
        assertEq(resetsAt, 0);

        vm.prank(owner);
        ledger.setSponsorMintCap(sponsor2, CAP);
        assertEq(_remaining(sponsor2), CAP, "unlimited mints were never charged to a window");
    }

    function test_Cap_ZeroStopsMintingButKeepsTheSponsorAuthorised() public {
        bytes32 eventId = _register();
        vm.prank(owner);
        ledger.setSponsorMintCap(sponsor, 0);

        vm.expectRevert(abi.encodeWithSelector(WoCoTicketLedger.MintCapExceeded.selector, sponsor, uint64(NOW + 1 hours)));
        vm.prank(sponsor);
        ledger.claimFor(eventId, buyer, 0);
        assertTrue(ledger.authorisedSponsors(sponsor));

        vm.prank(owner);
        ledger.setSponsorMintCap(sponsor, CAP);
        _mint(sponsor, eventId, 1);
    }

    /// The registrar's audit 937 F6 lesson: a retune must never re-anchor an
    /// open window or hand back allowance already spent.
    function test_Cap_RetuneKeepsTheOpenWindowAndItsCount() public {
        bytes32 eventId = _register();
        _mint(sponsor, eventId, 3);

        vm.prank(owner);
        ledger.setSponsorMintCap(sponsor, CAP);
        assertEq(_remaining(sponsor), 2, "same cap again gives nothing back");

        vm.prank(owner);
        ledger.setSponsorMintCap(sponsor, 2);
        assertEq(_remaining(sponsor), 0, "a lowered cap below the spent count leaves nothing");
        vm.expectRevert(abi.encodeWithSelector(WoCoTicketLedger.MintCapExceeded.selector, sponsor, uint64(NOW + 1 hours)));
        vm.prank(sponsor);
        ledger.claimFor(eventId, buyer, 0);

        vm.warp(NOW + 30 minutes);
        vm.prank(owner);
        ledger.setSponsorMintCap(sponsor, 10);
        (, uint32 remaining, uint64 resetsAt) = ledger.sponsorMintAllowance(sponsor);
        assertEq(remaining, 7, "raising lifts the refusal at once");
        assertEq(resetsAt, NOW + 1 hours, "and the window keeps its end");
        _mint(sponsor, eventId, 7);
    }

    function test_Cap_IsPerSponsor() public {
        vm.prank(owner);
        ledger.addSponsor(sponsor2, CAP);
        bytes32 eventId = _register();

        _mint(sponsor, eventId, CAP);
        assertEq(_remaining(sponsor2), CAP, "one sponsor's spend is not another's");
        _mint(sponsor2, eventId, CAP);
    }

    function test_Cap_RemoveAndReAddKeepsTheOpenWindow() public {
        bytes32 eventId = _register();
        _mint(sponsor, eventId, CAP);

        vm.startPrank(owner);
        ledger.removeSponsor(sponsor);
        ledger.addSponsor(sponsor, CAP);
        vm.stopPrank();

        assertEq(_remaining(sponsor), 0);
        vm.expectRevert(abi.encodeWithSelector(WoCoTicketLedger.MintCapExceeded.selector, sponsor, uint64(NOW + 1 hours)));
        vm.prank(sponsor);
        ledger.claimFor(eventId, buyer, 0);
    }

    function test_SetSponsorMintCap_OwnerOnly() public {
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        vm.prank(stranger);
        ledger.setSponsorMintCap(sponsor, 1_000);

        // Nor can the sponsor lift its own cap.
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, sponsor));
        vm.prank(sponsor);
        ledger.setSponsorMintCap(sponsor, 1_000);
    }

    /// A typo'd address must fail loudly, not "cap" an address that mints nothing.
    function test_SetSponsorMintCap_RefusesANonSponsor() public {
        vm.expectRevert(WoCoTicketLedger.NotSponsor.selector);
        vm.prank(owner);
        ledger.setSponsorMintCap(stranger, 0);

        vm.prank(owner);
        ledger.removeSponsor(sponsor);
        vm.expectRevert(WoCoTicketLedger.NotSponsor.selector);
        vm.prank(owner);
        ledger.setSponsorMintCap(sponsor, 0);
    }

    function test_AddSponsor_EmitsItsCap() public {
        vm.expectEmit(true, false, false, true, address(ledger));
        emit SponsorAdded(sponsor2);
        vm.expectEmit(true, false, false, true, address(ledger));
        emit SponsorMintCapSet(sponsor2, 42);
        vm.prank(owner);
        ledger.addSponsor(sponsor2, 42);
    }

    /// Within one window a capped sponsor never mints more than its cap,
    /// whatever mix of single and batch mints it tries.
    function testFuzz_Cap_OneWindowNeverExceedsTheCap(uint8[8] memory sizes) public {
        bytes32 eventId = _register();
        uint256 minted;
        for (uint256 i; i < sizes.length; ++i) {
            uint256 n = bound(sizes[i], 1, 4);
            vm.prank(sponsor);
            try ledger.batchClaimFor(eventId, _owners(n), 0) {
                minted += n;
            } catch {}
        }
        assertLe(minted, CAP);
        (, uint64 nextSlot, , ) = ledger.getEvent(eventId);
        assertEq(nextSlot, minted);
    }

    /// The server reads these by its own human-readable ABI (health + error
    /// map), so their selectors are pinned from written-out signatures.
    function test_ServerAbi_CapSelectors() public view {
        assertEq(bytes32(WoCoTicketLedger.sponsorMintAllowance.selector), bytes32(bytes4(keccak256("sponsorMintAllowance(address)"))));
        assertEq(bytes32(WoCoTicketLedger.MintCapExceeded.selector),      bytes32(bytes4(keccak256("MintCapExceeded(address,uint64)"))));
        assertEq(bytes32(ledger.authorisedSponsors.selector),             bytes32(bytes4(keccak256("authorisedSponsors(address)"))));
    }

    // ── L-1: dispute authority follows the owner ──────────────────────────────

    function test_DisputeAuthority_MovesWithAHandover() public {
        bytes32 eventId = _register();
        vm.prank(owner);
        ledger.transferOwnership(newOwner);
        assertEq(ledger.disputeAuthority(), owner, "a pending transfer moves nothing");

        vm.expectEmit(true, false, false, true, address(ledger));
        emit DisputeAuthorityUpdated(newOwner);
        vm.prank(newOwner);
        ledger.acceptOwnership();
        assertEq(ledger.disputeAuthority(), newOwner);

        vm.expectRevert(WoCoTicketLedger.NotDisputeAuthority.selector);
        vm.prank(owner);
        ledger.forceCancelEvent(eventId);

        vm.prank(newOwner);
        ledger.forceCancelEvent(eventId);
    }

    /// The constructor's own `_transferOwnership` call must not move the
    /// authority: the body sets it, once, with one event.
    function test_DisputeAuthority_ConstructorLogsItOnce() public {
        vm.recordLogs();
        WoCoTicketLedger l = new WoCoTicketLedger(owner, sponsor, CAP);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 n;
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == keccak256("DisputeAuthorityUpdated(address)")) ++n;
        }
        assertEq(n, 1);
        assertEq(l.disputeAuthority(), owner);
    }

    function test_DisputeAuthority_SetApartStaysOnAHandover() public {
        vm.prank(owner);
        ledger.setDisputeAuthority(daoAuth);

        vm.prank(owner);
        ledger.transferOwnership(newOwner);
        vm.prank(newOwner);
        ledger.acceptOwnership();

        assertEq(ledger.owner(), newOwner);
        assertEq(ledger.disputeAuthority(), daoAuth);
    }

    // ── L-2: raw getters are gone ─────────────────────────────────────────────

    function test_RawSlotGettersAreNotExposed() public {
        bytes32 eventId = _register();
        _mint(sponsor, eventId, 1);
        // The old public names, and the private ones in case `public` comes back.
        bytes[6] memory calls = [
            abi.encodeWithSignature("slots(bytes32,uint256)", eventId, uint256(0)),
            abi.encodeWithSignature("batchOrderRef(bytes32,uint64)", eventId, uint64(0)),
            abi.encodeWithSignature("batchClaimer(bytes32,uint64)", eventId, uint64(0)),
            abi.encodeWithSignature("_slots(bytes32,uint256)", eventId, uint256(0)),
            abi.encodeWithSignature("_batchOrderRef(bytes32,uint64)", eventId, uint64(0)),
            abi.encodeWithSignature("_batchClaimer(bytes32,uint64)", eventId, uint64(0))
        ];
        for (uint256 i; i < calls.length; ++i) {
            (bool ok, ) = address(ledger).staticcall(calls[i]);
            assertFalse(ok);
        }
    }

    // ── I-4: SlotTransferred indexes the recipient ────────────────────────────

    function test_SlotTransferred_IndexesEventFromAndTo() public {
        bytes32 eventId = _register();
        vm.prank(sponsor);
        uint256 slot = ledger.claimFor(eventId, buyer, 0);

        vm.recordLogs();
        vm.prank(buyer);
        ledger.transferSlot(eventId, slot, newOwner);
        Vm.Log[] memory logs = vm.getRecordedLogs();

        assertEq(logs.length, 1);
        assertEq(logs[0].topics.length, 4);
        assertEq(logs[0].topics[0], keccak256("SlotTransferred(bytes32,uint256,address,address)"));
        assertEq(logs[0].topics[1], eventId);
        assertEq(logs[0].topics[2], bytes32(uint256(uint160(buyer))));
        assertEq(logs[0].topics[3], bytes32(uint256(uint160(newOwner))));
        assertEq(logs[0].data, abi.encode(slot));
    }

    // ── I-8: never to the ledger itself ───────────────────────────────────────

    function test_Transfer_ToTheLedgerItselfIsRefused() public {
        bytes32 eventId = _register();
        vm.prank(sponsor);
        uint256 slot = ledger.claimFor(eventId, buyer, 0);

        vm.expectRevert(WoCoTicketLedger.TransferToLedger.selector);
        vm.prank(buyer);
        ledger.transferSlot(eventId, slot, address(ledger));
    }

    function test_SignedTransfer_ToTheLedgerItselfIsRefused() public {
        uint256 pk = 0xA11CE;
        address holder = vm.addr(pk);
        bytes32 eventId = _register();
        vm.prank(sponsor);
        uint256 slot = ledger.claimFor(eventId, holder, 0);

        uint256 deadline = NOW + 15 minutes;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ledger.transferSlotDigest(eventId, slot, address(ledger), deadline));

        vm.expectRevert(WoCoTicketLedger.TransferToLedger.selector);
        vm.prank(stranger);
        ledger.transferSlotWithSignature(eventId, slot, address(ledger), deadline, abi.encodePacked(r, s, v));
    }
}

/// Drives a capped sponsor through random mints, clock moves and retunes.
contract CapHandler is Test {
    WoCoTicketLedger public ledger;
    address public owner;
    bytes32 public eventId;

    uint32  public cap;
    uint64  public windowEnd;
    uint256 public mintedInWindow;
    uint256 public maxCapInWindow;

    constructor(WoCoTicketLedger ledger_, address owner_, bytes32 eventId_, uint32 cap_) {
        ledger = ledger_;
        owner = owner_;
        eventId = eventId_;
        cap = cap_;
    }

    function mint(uint256 n) external {
        n = bound(n, 1, 20);
        address[] memory to = new address[](n);
        for (uint256 i; i < n; ++i) to[i] = address(0xB0B);
        try ledger.batchClaimFor(eventId, to, 0) {
            (, , uint64 end) = ledger.sponsorMintAllowance(address(this));
            if (end != windowEnd) {
                windowEnd = end;
                mintedInWindow = 0;
                maxCapInWindow = cap;
            }
            mintedInWindow += n;
        } catch {}
    }

    function warp(uint256 dt) external {
        vm.warp(block.timestamp + bound(dt, 0, 2 hours));
    }

    function retune(uint256 c) external {
        // forge-lint: disable-next-line(unsafe-typecast)
        cap = uint32(bound(c, 0, 50));
        vm.prank(owner);
        ledger.setSponsorMintCap(address(this), cap);
        if (cap > maxCapInWindow) maxCapInWindow = cap;
    }
}

contract WoCoTicketLedgerCapInvariantTest is Test {
    WoCoTicketLedger internal ledger;
    CapHandler       internal handler;

    address owner = address(0x1);

    function setUp() public {
        vm.warp(1_800_000_000);
        ledger = new WoCoTicketLedger(owner, address(0xDEAD), 1);
        vm.prank(address(0xDEAD));
        bytes32 eventId = ledger.registerEvent(address(0x3), type(uint64).max, keccak256("m"), uint64(block.timestamp + 3650 days));
        handler = new CapHandler(ledger, owner, eventId, 10);
        vm.prank(owner);
        ledger.addSponsor(address(handler), 10);
        targetContract(address(handler));
    }

    /// Whatever the owner does mid-window, a sponsor mints at most the highest
    /// cap that was in force during that window. Retunes never re-open it.
    function invariant_CappedSponsorStaysWithinItsWindowCap() public view {
        assertLe(handler.mintedInWindow(), handler.maxCapInWindow());
    }
}
