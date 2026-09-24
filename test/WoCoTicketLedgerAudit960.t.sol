// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {WoCoTicketLedger} from "../src/WoCoTicketLedger.sol";

/**
 * The fixes for LeftClaw audit 960 (re-audit of fe5f518):
 *   M-1  the mint paths refuse the ledger itself as a first holder
 *   M-2  leaving UNLIMITED_MINTS starts a fresh window, not a stale one
 *   L-1  (kept, pinned) at a handover the outgoing owner never keeps the
 *        dispute authority unless it was set to a DIFFERENT address
 *   L-4  EventCancelled says which path cancelled
 */
contract WoCoTicketLedgerAudit960Test is Test {
    WoCoTicketLedger public ledger;

    address owner     = address(0x1);
    address sponsor   = address(0x2);
    address organiser = address(0x3);
    address buyer     = address(0x6);
    address safeD     = address(0xD);
    address safeE     = address(0xE);

    uint32  constant CAP      = 5;
    bytes32 constant MANIFEST = keccak256("manifest");
    uint64  constant SUPPLY   = 1_000;
    uint256 constant NOW      = 1_800_000_000;
    uint64  constant END_TS   = 1_800_604_800;

    function setUp() public {
        vm.warp(NOW);
        ledger = new WoCoTicketLedger(owner, sponsor, CAP);
    }

    function _register() internal returns (bytes32 eventId) {
        vm.prank(sponsor);
        eventId = ledger.registerEvent(organiser, SUPPLY, MANIFEST, END_TS);
    }

    function _mint(bytes32 eventId, uint256 n) internal {
        address[] memory a = new address[](n);
        for (uint256 i; i < n; ++i) a[i] = buyer;
        vm.prank(sponsor);
        ledger.batchClaimFor(eventId, a, 0);
    }

    // ── M-1 ───────────────────────────────────────────────────────────────────

    function test_ClaimFor_RefusesTheLedgerAsFirstHolder() public {
        bytes32 eventId = _register();
        vm.expectRevert(WoCoTicketLedger.TransferToLedger.selector);
        vm.prank(sponsor);
        ledger.claimFor(eventId, address(ledger), 0);
    }

    function test_BatchClaimFor_RefusesTheLedgerAnywhereInTheBatch() public {
        bytes32 eventId = _register();
        address[] memory a = new address[](3);
        a[0] = buyer;
        a[1] = address(ledger);
        a[2] = buyer;
        vm.expectRevert(WoCoTicketLedger.TransferToLedger.selector);
        vm.prank(sponsor);
        ledger.batchClaimFor(eventId, a, 0);
    }

    // ── M-2 ───────────────────────────────────────────────────────────────────

    /// Unlimited mints are never counted, so a count from before an unlimited
    /// spell is stale, not spent allowance. The audit's trace, at CAP = 5.
    function test_Cap_LeavingUnlimitedStartsAFreshWindow() public {
        bytes32 eventId = _register();
        _mint(eventId, CAP);

        uint32 unlimited = ledger.UNLIMITED_MINTS();
        vm.warp(NOW + 10);
        vm.prank(owner);
        ledger.setSponsorMintCap(sponsor, unlimited);
        _mint(eventId, 50);

        vm.warp(NOW + 30 minutes);
        vm.prank(owner);
        ledger.setSponsorMintCap(sponsor, CAP);
        (uint32 perHour, uint32 mintable, uint64 resetsAt) = ledger.sponsorMintAllowance(sponsor);
        assertEq(perHour, CAP);
        assertEq(mintable, CAP, "restored cap starts empty");
        assertEq(resetsAt, NOW + 30 minutes + 1 hours, "window opens at the next mint");

        _mint(eventId, CAP);
        vm.expectRevert(abi.encodeWithSelector(WoCoTicketLedger.MintCapExceeded.selector, sponsor, uint64(NOW + 30 minutes + 1 hours)));
        vm.prank(sponsor);
        ledger.claimFor(eventId, buyer, 0);
    }

    /// Between finite caps the open window still keeps its count: only the
    /// unlimited boundary resets it.
    function test_Cap_FiniteToFiniteStillKeepsTheWindow() public {
        bytes32 eventId = _register();
        _mint(eventId, 3);
        vm.prank(owner);
        ledger.setSponsorMintCap(sponsor, 10);
        (, uint32 mintable, ) = ledger.sponsorMintAllowance(sponsor);
        assertEq(mintable, 7);
    }

    // ── L-1 (behaviour kept) ──────────────────────────────────────────────────

    /// The audit's sequence: set apart to D, hand ownership to D, then D hands
    /// it to E. D is then BOTH roles and is retiring, so it must lose both - a
    /// sticky "set apart" flag would leave the retired D with force-cancel,
    /// which is the audit 959 L-1 defect.
    function test_DisputeAuthority_OutgoingOwnerNeverKeepsIt() public {
        vm.startPrank(owner);
        ledger.setDisputeAuthority(safeD);
        ledger.transferOwnership(safeD);
        vm.stopPrank();
        vm.prank(safeD);
        ledger.acceptOwnership();
        assertEq(ledger.disputeAuthority(), safeD);

        vm.prank(safeD);
        ledger.transferOwnership(safeE);
        vm.prank(safeE);
        ledger.acceptOwnership();
        assertEq(ledger.disputeAuthority(), safeE, "the retiring owner does not keep force-cancel");
    }

    // ── L-4 ───────────────────────────────────────────────────────────────────

    function _cancelLog() internal returns (Vm.Log memory log) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(logs.length, 1);
        log = logs[0];
    }

    function test_EventCancelled_SaysWhichPathCancelled() public {
        bytes32 a = _register();
        bytes32 b = _register();

        vm.recordLogs();
        vm.prank(organiser);
        ledger.cancelEvent(a);
        Vm.Log memory own = _cancelLog();
        assertEq(own.topics[0], keccak256("EventCancelled(bytes32,address,bool)"));
        assertEq(own.topics[1], a);
        assertEq(own.topics[2], bytes32(uint256(uint160(organiser))));
        assertEq(own.data, abi.encode(false));

        vm.recordLogs();
        vm.prank(owner);
        ledger.forceCancelEvent(b);
        Vm.Log memory forced = _cancelLog();
        assertEq(forced.topics[0], keccak256("EventCancelled(bytes32,address,bool)"));
        assertEq(forced.topics[2], bytes32(uint256(uint160(owner))));
        assertEq(forced.data, abi.encode(true));
    }
}

contract WoCoTicketLedgerAudit960DisputeTest is Test {
    /// audit 960 I-9 / Fable N6: the ledger never calls itself, so it can never
    /// be the dispute authority.
    function test_SetDisputeAuthority_RefusesTheLedgerItself() public {
        WoCoTicketLedger ledger = new WoCoTicketLedger(address(0x1), address(0x2), 5);
        vm.expectRevert(WoCoTicketLedger.TransferToLedger.selector);
        vm.prank(address(0x1));
        ledger.setDisputeAuthority(address(ledger));
    }
}
