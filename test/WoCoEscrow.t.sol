// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/WoCoEscrow.sol";

contract WoCoEscrowTest is Test {
    WoCoEscrow public escrow;

    address organiser  = address(0x1);
    address attendee1  = address(0x2);
    address attendee2  = address(0x3);
    address attacker   = address(0x4);
    address arbitrator = address(0x10);
    address feeWallet  = address(0x11);

    bytes32 eventId = keccak256("test-event-123");
    uint256 releaseTime;

    uint256 constant FEE_BP = 150;         // 1.5%
    uint256 constant DENOM  = 10_000;

    function setUp() public {
        escrow = new WoCoEscrow(arbitrator, feeWallet);
        releaseTime = block.timestamp + 7 days;
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    function _pay(address who, uint256 amount) internal {
        vm.deal(who, amount);
        vm.prank(who);
        escrow.payETH{value: amount}(eventId, organiser, releaseTime);
    }

    function _fee(uint256 amount) internal pure returns (uint256) {
        return (amount * FEE_BP) / DENOM;
    }

    // ── Constructor ───────────────────────────────────────────────────────────

    function test_Constructor_SetsArbitratorAndFeeRecipient() public view {
        assertEq(escrow.arbitrator(), arbitrator);
        assertEq(escrow.feeRecipient(), feeWallet);
    }

    function test_Constructor_RevertZeroArbitrator() public {
        vm.expectRevert("Invalid arbitrator");
        new WoCoEscrow(address(0), feeWallet);
    }

    function test_Constructor_RevertZeroFeeRecipient() public {
        vm.expectRevert("Invalid fee recipient");
        new WoCoEscrow(arbitrator, address(0));
    }

    // ── Auto-init on first payment ────────────────────────────────────────────

    function test_AutoInit_OnFirstPayETH() public {
        _pay(attendee1, 0.01 ether);

        (address org, uint256 rt, uint256 bal, bool exists, bool disputed, uint32 flags) = escrow.getEscrowInfo(eventId);
        assertEq(org, organiser);
        assertEq(rt, releaseTime);
        assertEq(bal, 0.01 ether);
        assertTrue(exists);
        assertFalse(disputed);
        assertEq(flags, 0);
    }

    function test_AutoInit_SubsequentPaymentsIgnoreOrgAndTime() public {
        _pay(attendee1, 0.01 ether);

        // Second attendee passes different organiser — ignored, existing escrow used
        vm.deal(attendee2, 1 ether);
        vm.prank(attendee2);
        escrow.payETH{value: 0.02 ether}(eventId, address(0x999), block.timestamp + 1 days);

        (address org,, uint256 bal,,,) = escrow.getEscrowInfo(eventId);
        assertEq(org, organiser); // organiser unchanged
        assertEq(bal, 0.03 ether);
    }

    function test_AutoInit_RevertIfReleaseTimeInPast() public {
        vm.deal(attendee1, 1 ether);
        vm.prank(attendee1);
        vm.expectRevert("Release time must be in the future");
        escrow.payETH{value: 0.01 ether}(eventId, organiser, block.timestamp - 1);
    }

    function test_AutoInit_RevertIfNoOrganiser() public {
        vm.deal(attendee1, 1 ether);
        vm.prank(attendee1);
        vm.expectRevert("Organiser required on first payment");
        escrow.payETH{value: 0.01 ether}(eventId, address(0), releaseTime);
    }

    // ── Pay ETH ───────────────────────────────────────────────────────────────

    function test_PayETH() public {
        _pay(attendee1, 0.01 ether);
        assertEq(escrow.getETHBalance(eventId), 0.01 ether);
    }

    function test_PayETH_MultipleAttendees() public {
        _pay(attendee1, 0.01 ether);
        _pay(attendee2, 0.02 ether);
        assertEq(escrow.getETHBalance(eventId), 0.03 ether);
    }

    function test_PayETH_RevertIfZero() public {
        vm.prank(attendee1);
        vm.expectRevert("Must send ETH");
        escrow.payETH{value: 0}(eventId, organiser, releaseTime);
    }

    // ── Release with fee ──────────────────────────────────────────────────────

    function test_Release_ETH_TakesFee() public {
        uint256 paid = 0.08 ether;
        _pay(attendee1, 0.05 ether);
        _pay(attendee2, 0.03 ether);

        vm.warp(releaseTime + 1);

        uint256 organiserBefore = organiser.balance;
        uint256 feeBefore       = feeWallet.balance;

        vm.prank(organiser);
        address[] memory tokens = new address[](0);
        escrow.release(eventId, tokens);

        uint256 expectedFee       = _fee(paid);          // 1.5% of 0.08 ETH = 0.0012 ETH
        uint256 expectedOrganiser = paid - expectedFee;   // 0.0788 ETH

        assertEq(organiser.balance - organiserBefore, expectedOrganiser);
        assertEq(feeWallet.balance  - feeBefore,      expectedFee);
        assertEq(escrow.getETHBalance(eventId), 0);
    }

    function test_Release_RevertIfTooEarly() public {
        _pay(attendee1, 0.01 ether);

        vm.prank(organiser);
        address[] memory tokens = new address[](0);
        vm.expectRevert("Funds are still locked");
        escrow.release(eventId, tokens);
    }

    function test_Release_RevertIfNotOrganiser() public {
        _pay(attendee1, 0.01 ether);
        vm.warp(releaseTime + 1);

        vm.prank(attendee1);
        address[] memory tokens = new address[](0);
        vm.expectRevert("Not organiser");
        escrow.release(eventId, tokens);
    }

    function test_Release_RevertIfEscrowNotExist() public {
        vm.warp(releaseTime + 1);
        vm.prank(organiser);
        address[] memory tokens = new address[](0);
        vm.expectRevert("Not organiser");
        escrow.release(eventId, tokens);
    }

    // ── Flagging / dispute ────────────────────────────────────────────────────

    function test_FlagEvent_MarksDisputed() public {
        _pay(attendee1, 0.01 ether);

        vm.prank(attendee1);
        escrow.flagEvent(eventId);

        (,,,, bool disputed, uint32 flags) = escrow.getEscrowInfo(eventId);
        assertTrue(disputed);
        assertEq(flags, 1);
        assertTrue(escrow.hasFlagged(eventId, attendee1));
    }

    function test_FlagEvent_MultipleFlaggers() public {
        _pay(attendee1, 0.01 ether);

        vm.prank(attendee1);
        escrow.flagEvent(eventId);

        vm.prank(attendee2);
        escrow.flagEvent(eventId);

        (,,,, bool disputed, uint32 flags) = escrow.getEscrowInfo(eventId);
        assertTrue(disputed);
        assertEq(flags, 2);
    }

    function test_FlagEvent_RevertDoubleFlag() public {
        _pay(attendee1, 0.01 ether);

        vm.prank(attendee1);
        escrow.flagEvent(eventId);

        vm.prank(attendee1);
        vm.expectRevert("Already flagged");
        escrow.flagEvent(eventId);
    }

    function test_FlagEvent_RevertAfterReleaseTime() public {
        _pay(attendee1, 0.01 ether);
        vm.warp(releaseTime + 1);

        vm.prank(attendee1);
        vm.expectRevert("Flag window has closed");
        escrow.flagEvent(eventId);
    }

    function test_FlagEvent_RevertIfEscrowNotExist() public {
        vm.prank(attendee1);
        vm.expectRevert("Escrow does not exist");
        escrow.flagEvent(eventId);
    }

    function test_Release_RevertIfDisputed() public {
        _pay(attendee1, 0.01 ether);

        vm.prank(attendee1);
        escrow.flagEvent(eventId);

        vm.warp(releaseTime + 1);

        vm.prank(organiser);
        address[] memory tokens = new address[](0);
        vm.expectRevert("Escrow is disputed - awaiting arbitration");
        escrow.release(eventId, tokens);
    }

    // ── Dispute resolution ────────────────────────────────────────────────────

    function test_ResolveDispute_True_AllowsRelease() public {
        uint256 paid = 0.05 ether;
        _pay(attendee1, paid);

        vm.prank(attendee1);
        escrow.flagEvent(eventId);

        // Arbitrator clears the dispute
        vm.prank(arbitrator);
        address[] memory tokens = new address[](0);
        escrow.resolveDispute(eventId, true, tokens);

        (,,,, bool disputed, uint32 flags) = escrow.getEscrowInfo(eventId);
        assertFalse(disputed);
        assertEq(flags, 0);

        // Organiser can now release
        vm.warp(releaseTime + 1);
        uint256 before = organiser.balance;
        vm.prank(organiser);
        escrow.release(eventId, tokens);
        assertGt(organiser.balance, before);
    }

    function test_ResolveDispute_False_ConfiscatesToFeeRecipient() public {
        uint256 paid = 0.05 ether;
        _pay(attendee1, paid);

        vm.prank(attendee1);
        escrow.flagEvent(eventId);

        uint256 feeBefore = feeWallet.balance;

        vm.prank(arbitrator);
        address[] memory tokens = new address[](0);
        escrow.resolveDispute(eventId, false, tokens);

        assertEq(feeWallet.balance - feeBefore, paid); // full amount confiscated
        assertEq(escrow.getETHBalance(eventId), 0);
    }

    function test_ResolveDispute_RevertIfNotDisputed() public {
        _pay(attendee1, 0.01 ether);

        vm.prank(arbitrator);
        address[] memory tokens = new address[](0);
        vm.expectRevert("Not disputed");
        escrow.resolveDispute(eventId, true, tokens);
    }

    function test_ResolveDispute_RevertIfNotArbitrator() public {
        _pay(attendee1, 0.01 ether);

        vm.prank(attendee1);
        escrow.flagEvent(eventId);

        vm.prank(attacker);
        address[] memory tokens = new address[](0);
        vm.expectRevert("Not arbitrator");
        escrow.resolveDispute(eventId, true, tokens);
    }

    // ── setArbitrator ─────────────────────────────────────────────────────────

    function test_SetArbitrator() public {
        address newArb = address(0x20);
        vm.prank(arbitrator);
        escrow.setArbitrator(newArb);
        assertEq(escrow.arbitrator(), newArb);
    }

    function test_SetArbitrator_RevertIfNotArbitrator() public {
        vm.prank(attacker);
        vm.expectRevert("Not arbitrator");
        escrow.setArbitrator(address(0x20));
    }

    function test_SetArbitrator_RevertZeroAddress() public {
        vm.prank(arbitrator);
        vm.expectRevert("Invalid arbitrator");
        escrow.setArbitrator(address(0));
    }

    // ── Deposit tracking ─────────────────────────────────────────────────────

    function test_DepositTracking_ETH() public {
        _pay(attendee1, 0.05 ether);
        _pay(attendee2, 0.03 ether);
        _pay(attendee1, 0.02 ether); // second deposit from same payer

        assertEq(escrow.getETHDeposit(eventId, attendee1), 0.07 ether);
        assertEq(escrow.getETHDeposit(eventId, attendee2), 0.03 ether);
        assertEq(escrow.getETHDeposit(eventId, attacker), 0);
    }

    // ── Token array length cap ───────────────────────────────────────────────

    function test_Release_RevertIfTooManyTokens() public {
        _pay(attendee1, 0.01 ether);
        vm.warp(releaseTime + 1);

        // Build array of 21 tokens (exceeds MAX_TOKENS = 20)
        address[] memory tokens = new address[](21);
        for (uint256 i = 0; i < 21; i++) {
            tokens[i] = address(uint160(0x100 + i));
        }

        vm.prank(organiser);
        vm.expectRevert("Too many tokens");
        escrow.release(eventId, tokens);
    }

    function test_ResolveDispute_RevertIfTooManyTokens() public {
        _pay(attendee1, 0.01 ether);

        vm.prank(attendee1);
        escrow.flagEvent(eventId);

        address[] memory tokens = new address[](21);
        for (uint256 i = 0; i < 21; i++) {
            tokens[i] = address(uint160(0x100 + i));
        }

        vm.prank(arbitrator);
        vm.expectRevert("Too many tokens");
        escrow.resolveDispute(eventId, false, tokens);
    }

    // ── View helpers ──────────────────────────────────────────────────────────

    function test_GetEscrowInfo_DefaultsForNonExistent() public view {
        (address org, uint256 rt, uint256 bal, bool exists, bool disputed, uint32 flags) = escrow.getEscrowInfo(eventId);
        assertEq(org, address(0));
        assertEq(rt, 0);
        assertEq(bal, 0);
        assertFalse(exists);
        assertFalse(disputed);
        assertEq(flags, 0);
    }
}
