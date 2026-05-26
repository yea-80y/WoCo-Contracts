// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {WoCoEventV2, IWoCoDropGate} from "../src/WoCoEventV2.sol";

/// Mock USDC — 6 decimals, EIP-2612 permit support.
contract MockUSDC is ERC20Permit {
    constructor() ERC20("Mock USDC", "USDC") ERC20Permit("Mock USDC") {}
    function decimals() public pure override returns (uint8) { return 6; }
    function mint(address to, uint256 amount) external { _mint(to, amount); }
}

contract AllowAllGate is IWoCoDropGate {
    uint256 public callCount;
    function check(bytes32, address, address, uint64) external returns (bool) {
        callCount++;
        return true;
    }
}

contract DenyAllGate is IWoCoDropGate {
    function check(bytes32, address, address, uint64) external pure returns (bool) {
        return false;
    }
}

contract RevertGate is IWoCoDropGate {
    error GateError();
    function check(bytes32, address, address, uint64) external pure returns (bool) {
        revert GateError();
    }
}

contract WoCoEventV2Test is Test {
    WoCoEventV2 public woco;
    MockUSDC    public usdc;

    address owner     = address(0x1);
    address sponsor   = address(0x2);
    address organiser = address(0x3);
    address treasury  = address(0x4);
    address payout    = address(0x5);
    address buyer     = address(0x6);
    address agent     = address(0x7);
    address recipient = address(0x8);
    address daoAuth   = address(0x9);

    uint256 permitBuyerKey = 0xA11CE;
    address permitBuyer;

    bytes32 constant MANIFEST = keccak256("manifest");
    uint64  constant SUPPLY   = 10;
    uint128 constant PRICE    = 10_000_000; // 10 USDC (6 decimals)
    uint16  constant FEE_BPS  = 150;        // 1.5 %
    uint64  END_TS;                          // set in setUp (block.timestamp + 7d)

    function setUp() public {
        usdc = new MockUSDC();
        woco = new WoCoEventV2(owner, sponsor, IERC20(address(usdc)), treasury, FEE_BPS);

        permitBuyer = vm.addr(permitBuyerKey);

        // safe: block.timestamp + 7 days well within uint64
        // forge-lint: disable-next-line(unsafe-typecast)
        END_TS = uint64(block.timestamp + 7 days);

        usdc.mint(buyer,       1_000_000_000);
        usdc.mint(agent,       1_000_000_000);
        usdc.mint(permitBuyer, 1_000_000_000);
    }

    // ── Constructor ───────────────────────────────────────────────────────────

    function test_Constructor_SetsState() public view {
        assertEq(woco.owner(), owner);
        assertTrue(woco.authorisedSponsors(sponsor));
        assertEq(address(woco.paymentToken()), address(usdc));
        assertEq(woco.platformTreasury(), treasury);
        assertEq(woco.defaultPlatformFeeBps(), FEE_BPS);
        assertEq(woco.defaultReleaseDelay(), 24 hours);
        assertEq(woco.disputeAuthority(), owner);
    }

    function test_Constructor_RevertZeroSponsor() public {
        vm.expectRevert(WoCoEventV2.ZeroAddress.selector);
        new WoCoEventV2(owner, address(0), IERC20(address(usdc)), treasury, FEE_BPS);
    }

    function test_Constructor_RevertZeroToken() public {
        vm.expectRevert(WoCoEventV2.ZeroAddress.selector);
        new WoCoEventV2(owner, sponsor, IERC20(address(0)), treasury, FEE_BPS);
    }

    function test_Constructor_RevertFeeTooHigh() public {
        vm.expectRevert(WoCoEventV2.FeeTooHigh.selector);
        new WoCoEventV2(owner, sponsor, IERC20(address(usdc)), treasury, 1_001);
    }

    // ── registerEvent ─────────────────────────────────────────────────────────

    function _register() internal returns (bytes32 eventId) {
        vm.prank(organiser);
        eventId = woco.registerEvent(SUPPLY, PRICE, payout, address(0), MANIFEST, END_TS);
    }

    function test_RegisterEvent_Success_Core() public {
        bytes32 eventId = _register();
        (
            uint64 totalSupply,
            uint64 nextSlot,
            uint128 price,
            address org,
            address payoutRecipient,
            uint16 feeBps,
            address dropGate,
            bytes32 manifest
        ) = woco.getEvent(eventId);

        assertEq(totalSupply, SUPPLY);
        assertEq(nextSlot, 0);
        assertEq(price, PRICE);
        assertEq(org, organiser);
        assertEq(payoutRecipient, payout);
        assertEq(feeBps, FEE_BPS);
        assertEq(dropGate, address(0));
        assertEq(manifest, MANIFEST);
    }

    function test_RegisterEvent_Success_Status() public {
        bytes32 eventId = _register();
        (
            uint64 endTs,
            uint32 delay,
            bool cancelled,
            bool withdrawn,
            bool frozen,
            uint256 escrow
        ) = woco.getEventStatus(eventId);
        assertEq(endTs, END_TS);
        assertEq(delay, 24 hours);
        assertFalse(cancelled);
        assertFalse(withdrawn);
        assertFalse(frozen);
        assertEq(escrow, 0);
    }

    function test_RegisterEvent_RevertZeroSupply() public {
        vm.expectRevert(WoCoEventV2.InsufficientSupply.selector);
        vm.prank(organiser);
        woco.registerEvent(0, PRICE, payout, address(0), MANIFEST, END_TS);
    }

    function test_RegisterEvent_RevertZeroPayout() public {
        vm.expectRevert(WoCoEventV2.ZeroAddress.selector);
        vm.prank(organiser);
        woco.registerEvent(SUPPLY, PRICE, address(0), address(0), MANIFEST, END_TS);
    }

    function test_RegisterEvent_RevertZeroManifest() public {
        vm.expectRevert(WoCoEventV2.ZeroAddress.selector);
        vm.prank(organiser);
        woco.registerEvent(SUPPLY, PRICE, payout, address(0), bytes32(0), END_TS);
    }

    function test_RegisterEvent_RevertPastEndTs() public {
        vm.expectRevert(WoCoEventV2.InvalidEventEnd.selector);
        vm.prank(organiser);
        // forge-lint: disable-next-line(unsafe-typecast)
        woco.registerEvent(SUPPLY, PRICE, payout, address(0), MANIFEST, uint64(block.timestamp));
    }

    function test_RegisterEvent_FreeAllowed() public {
        vm.prank(organiser);
        bytes32 eventId = woco.registerEvent(SUPPLY, 0, payout, address(0), MANIFEST, END_TS);
        (, , uint128 price, , , , , ) = woco.getEvent(eventId);
        assertEq(price, 0);
    }

    // ── payAndClaim (escrow path) ─────────────────────────────────────────────

    function _approveAndClaim(address who, bytes32 eventId, address slotOwner)
        internal
        returns (uint256 slot)
    {
        vm.prank(who);
        usdc.approve(address(woco), type(uint256).max);
        vm.prank(who);
        slot = woco.payAndClaim(eventId, slotOwner, bytes32(0));
    }

    function test_PayAndClaim_HoldsInEscrow() public {
        bytes32 eventId = _register();

        uint256 buyerBefore    = usdc.balanceOf(buyer);
        uint256 payoutBefore   = usdc.balanceOf(payout);
        uint256 treasuryBefore = usdc.balanceOf(treasury);
        uint256 wocoBefore     = usdc.balanceOf(address(woco));

        uint256 slot = _approveAndClaim(buyer, eventId, buyer);

        assertEq(slot, 0);
        assertEq(woco.slotOwner(eventId, 0), buyer);
        assertEq(woco.remaining(eventId), SUPPLY - 1);

        // Funds sit in escrow — neither payout nor treasury receives anything yet.
        assertEq(usdc.balanceOf(buyer),    buyerBefore - PRICE);
        assertEq(usdc.balanceOf(payout),   payoutBefore);
        assertEq(usdc.balanceOf(treasury), treasuryBefore);
        assertEq(usdc.balanceOf(address(woco)), wocoBefore + PRICE);
        assertEq(woco.escrowBalance(eventId), PRICE);

        (, , , bool escrowed, bool refunded) = woco.getSlotData(eventId, 0);
        assertTrue(escrowed);
        assertFalse(refunded);
    }

    function test_PayAndClaim_AgentPaysForRecipient() public {
        bytes32 eventId = _register();
        uint256 slot = _approveAndClaim(agent, eventId, recipient);
        assertEq(slot, 0);
        assertEq(woco.slotOwner(eventId, 0), recipient);

        (address slotOwner, address claimer, , , ) = woco.getSlotData(eventId, 0);
        assertEq(slotOwner, recipient);
        assertEq(claimer, agent);
    }

    function test_PayAndClaim_RevertZeroOwner() public {
        bytes32 eventId = _register();
        vm.prank(buyer);
        usdc.approve(address(woco), type(uint256).max);
        vm.expectRevert(WoCoEventV2.ZeroAddress.selector);
        vm.prank(buyer);
        woco.payAndClaim(eventId, address(0), bytes32(0));
    }

    function test_PayAndClaim_RevertEventNotFound() public {
        vm.prank(buyer);
        usdc.approve(address(woco), type(uint256).max);
        vm.expectRevert(WoCoEventV2.EventNotFound.selector);
        vm.prank(buyer);
        woco.payAndClaim(bytes32(uint256(0xdead)), buyer, bytes32(0));
    }

    function test_PayAndClaim_RevertSoldOut() public {
        bytes32 eventId = _register();
        vm.prank(buyer);
        usdc.approve(address(woco), type(uint256).max);
        for (uint256 i; i < SUPPLY; ++i) {
            vm.prank(buyer);
            woco.payAndClaim(eventId, buyer, bytes32(0));
        }
        vm.expectRevert(WoCoEventV2.InsufficientSupply.selector);
        vm.prank(buyer);
        woco.payAndClaim(eventId, buyer, bytes32(0));
    }

    function test_PayAndClaim_RevertAfterEventEnds() public {
        // No money should be acceptable into escrow once sales close — otherwise
        // post-withdraw deposits would be stuck (can neither withdraw nor refund).
        bytes32 eventId = _register();
        vm.warp(uint256(END_TS) + 1);

        vm.prank(buyer);
        usdc.approve(address(woco), type(uint256).max);
        vm.expectRevert(WoCoEventV2.SalesClosed.selector);
        vm.prank(buyer);
        woco.payAndClaim(eventId, buyer, bytes32(0));
    }

    function test_ClaimFor_RevertAfterEventEnds() public {
        bytes32 eventId = _register();
        vm.warp(uint256(END_TS) + 1);

        vm.expectRevert(WoCoEventV2.SalesClosed.selector);
        vm.prank(sponsor);
        woco.claimFor(eventId, buyer, bytes32(0));
    }

    function test_PayAndClaim_RevertCancelled() public {
        bytes32 eventId = _register();
        vm.prank(organiser);
        woco.cancelEvent(eventId);

        vm.prank(buyer);
        usdc.approve(address(woco), type(uint256).max);
        vm.expectRevert(WoCoEventV2.AlreadyCancelled.selector);
        vm.prank(buyer);
        woco.payAndClaim(eventId, buyer, bytes32(0));
    }

    function test_PayAndClaim_FreeEventNoTransfer() public {
        vm.prank(organiser);
        bytes32 eventId = woco.registerEvent(SUPPLY, 0, payout, address(0), MANIFEST, END_TS);

        uint256 buyerBefore = usdc.balanceOf(buyer);

        vm.prank(buyer);
        uint256 slot = woco.payAndClaim(eventId, buyer, bytes32(0));

        assertEq(slot, 0);
        assertEq(woco.slotOwner(eventId, 0), buyer);
        assertEq(usdc.balanceOf(buyer), buyerBefore);
        assertEq(woco.escrowBalance(eventId), 0);

        // Free claims do NOT mark the batch as escrowed — no refund obligation.
        (, , , bool escrowed, ) = woco.getSlotData(eventId, 0);
        assertFalse(escrowed);
    }

    // ── batchPayAndClaim ──────────────────────────────────────────────────────

    function test_BatchPayAndClaim_HoldsBatchInEscrow() public {
        bytes32 eventId = _register();
        address[] memory owners = new address[](3);
        owners[0] = recipient;
        owners[1] = recipient;
        owners[2] = recipient;

        vm.prank(buyer);
        usdc.approve(address(woco), type(uint256).max);
        vm.prank(buyer);
        uint256 first = woco.batchPayAndClaim(eventId, owners, keccak256("order-ref"));

        assertEq(first, 0);
        for (uint256 i; i < 3; ++i) assertEq(woco.slotOwner(eventId, i), recipient);
        assertEq(woco.remaining(eventId), SUPPLY - 3);

        (, address claimer, bytes32 ref, bool escrowed, ) = woco.getSlotData(eventId, 0);
        assertEq(claimer, buyer);
        assertEq(ref, keccak256("order-ref"));
        assertTrue(escrowed);

        // Slot 2 resolves shared metadata via batchFirstSlot pointer
        (, address claimer2, bytes32 ref2, bool escrowed2, ) = woco.getSlotData(eventId, 2);
        assertEq(claimer2, buyer);
        assertEq(ref2, keccak256("order-ref"));
        assertTrue(escrowed2);

        assertEq(usdc.balanceOf(treasury), 0);
        assertEq(usdc.balanceOf(payout),   0);
        assertEq(woco.escrowBalance(eventId), PRICE * 3);
    }

    function test_BatchPayAndClaim_RevertEmpty() public {
        bytes32 eventId = _register();
        address[] memory owners = new address[](0);
        vm.expectRevert(WoCoEventV2.BatchEmpty.selector);
        vm.prank(buyer);
        woco.batchPayAndClaim(eventId, owners, bytes32(0));
    }

    function test_BatchPayAndClaim_RevertOverflow() public {
        bytes32 eventId = _register();
        address[] memory owners = new address[](11);
        for (uint256 i; i < 11; ++i) owners[i] = recipient;
        vm.prank(buyer);
        usdc.approve(address(woco), type(uint256).max);
        vm.expectRevert(WoCoEventV2.InsufficientSupply.selector);
        vm.prank(buyer);
        woco.batchPayAndClaim(eventId, owners, bytes32(0));
    }

    function test_BatchPayAndClaim_RevertTooLarge() public {
        bytes32 eventId = _register();
        address[] memory owners = new address[](101);
        for (uint256 i; i < 101; ++i) owners[i] = recipient;
        vm.expectRevert(WoCoEventV2.BatchTooLarge.selector);
        vm.prank(buyer);
        woco.batchPayAndClaim(eventId, owners, bytes32(0));
    }

    function test_BatchPayAndClaim_RevertZeroOwner() public {
        bytes32 eventId = _register();
        address[] memory owners = new address[](2);
        owners[0] = recipient;
        owners[1] = address(0);
        vm.prank(buyer);
        usdc.approve(address(woco), type(uint256).max);
        vm.expectRevert(WoCoEventV2.ZeroAddress.selector);
        vm.prank(buyer);
        woco.batchPayAndClaim(eventId, owners, bytes32(0));
    }

    // ── payAndClaimWithPermit ─────────────────────────────────────────────────

    bytes32 constant PERMIT_TYPEHASH = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
    );

    function _signPermit(uint256 pk, address spender, uint256 value, uint256 deadline)
        internal
        view
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        address signer = vm.addr(pk);
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            usdc.DOMAIN_SEPARATOR(),
            keccak256(abi.encode(
                PERMIT_TYPEHASH,
                signer,
                spender,
                value,
                usdc.nonces(signer),
                deadline
            ))
        ));
        (v, r, s) = vm.sign(pk, digest);
    }

    function test_PayAndClaimWithPermit_HappyPath() public {
        bytes32 eventId = _register();

        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) =
            _signPermit(permitBuyerKey, address(woco), PRICE, deadline);

        vm.prank(permitBuyer);
        uint256 slot = woco.payAndClaimWithPermit(
            eventId, permitBuyer, bytes32(0),
            PRICE, deadline, v, r, s
        );

        assertEq(slot, 0);
        assertEq(woco.slotOwner(eventId, 0), permitBuyer);
        assertEq(usdc.allowance(permitBuyer, address(woco)), 0);
        assertEq(woco.escrowBalance(eventId), PRICE);
    }

    function test_PayAndClaimWithPermit_FrontRunPermitConsumed() public {
        bytes32 eventId = _register();

        uint256 deadline = block.timestamp + 1 hours;
        (uint8 v, bytes32 r, bytes32 s) =
            _signPermit(permitBuyerKey, address(woco), PRICE, deadline);

        usdc.permit(permitBuyer, address(woco), PRICE, deadline, v, r, s);

        vm.prank(permitBuyer);
        uint256 slot = woco.payAndClaimWithPermit(
            eventId, permitBuyer, bytes32(0),
            PRICE, deadline, v, r, s
        );
        assertEq(slot, 0);
    }

    // ── Drop-gate hook ────────────────────────────────────────────────────────

    function test_DropGate_AllowAllInvokes() public {
        AllowAllGate gate = new AllowAllGate();
        vm.prank(organiser);
        bytes32 eventId = woco.registerEvent(SUPPLY, PRICE, payout, address(gate), MANIFEST, END_TS);

        vm.prank(buyer);
        usdc.approve(address(woco), type(uint256).max);
        vm.prank(buyer);
        woco.payAndClaim(eventId, buyer, bytes32(0));

        assertEq(gate.callCount(), 1);
    }

    function test_DropGate_DenyVetoesClaim() public {
        DenyAllGate gate = new DenyAllGate();
        vm.prank(organiser);
        bytes32 eventId = woco.registerEvent(SUPPLY, PRICE, payout, address(gate), MANIFEST, END_TS);

        vm.prank(buyer);
        usdc.approve(address(woco), type(uint256).max);
        vm.expectRevert(WoCoEventV2.GateVetoed.selector);
        vm.prank(buyer);
        woco.payAndClaim(eventId, buyer, bytes32(0));
    }

    function test_DropGate_RevertBubbles() public {
        RevertGate gate = new RevertGate();
        vm.prank(organiser);
        bytes32 eventId = woco.registerEvent(SUPPLY, PRICE, payout, address(gate), MANIFEST, END_TS);

        vm.prank(buyer);
        usdc.approve(address(woco), type(uint256).max);
        vm.expectRevert(RevertGate.GateError.selector);
        vm.prank(buyer);
        woco.payAndClaim(eventId, buyer, bytes32(0));
    }

    // ── Legacy sponsor path (Stripe webhook) ──────────────────────────────────

    function test_ClaimFor_SponsorMintsWithoutPayment() public {
        bytes32 eventId = _register();
        uint256 treasuryBefore = usdc.balanceOf(treasury);
        uint256 payoutBefore   = usdc.balanceOf(payout);

        vm.prank(sponsor);
        uint256 slot = woco.claimFor(eventId, buyer, keccak256("stripe-ref"));

        assertEq(slot, 0);
        assertEq(woco.slotOwner(eventId, 0), buyer);
        assertEq(usdc.balanceOf(treasury), treasuryBefore);
        assertEq(usdc.balanceOf(payout),   payoutBefore);
        assertEq(woco.escrowBalance(eventId), 0);

        (, address claimer, bytes32 ref, bool escrowed, ) = woco.getSlotData(eventId, 0);
        assertEq(claimer, sponsor);
        assertEq(ref, keccak256("stripe-ref"));
        assertFalse(escrowed);
    }

    function test_ClaimFor_RevertUnauthorised() public {
        bytes32 eventId = _register();
        vm.expectRevert(WoCoEventV2.NotAuthorised.selector);
        vm.prank(buyer);
        woco.claimFor(eventId, buyer, bytes32(0));
    }

    function test_BatchClaimFor_Sponsor() public {
        bytes32 eventId = _register();
        address[] memory owners = new address[](2);
        owners[0] = buyer;
        owners[1] = recipient;

        vm.prank(sponsor);
        uint256 first = woco.batchClaimFor(eventId, owners, keccak256("stripe-batch"));

        assertEq(first, 0);
        assertEq(woco.slotOwner(eventId, 0), buyer);
        assertEq(woco.slotOwner(eventId, 1), recipient);
        assertEq(usdc.balanceOf(treasury), 0);
        assertEq(woco.escrowBalance(eventId), 0);
    }

    // ── Escrow: withdraw (happy path) ─────────────────────────────────────────

    function test_Withdraw_HappyPath_PaysOrganiserAndTreasury() public {
        bytes32 eventId = _register();
        _approveAndClaim(buyer, eventId, buyer);
        _approveAndClaim(buyer, eventId, buyer);
        // 2 × PRICE in escrow

        uint256 expectedFee = (uint256(PRICE) * 2 * FEE_BPS) / 10_000;
        uint256 expectedNet = (uint256(PRICE) * 2) - expectedFee;

        // Cannot withdraw before release time
        vm.expectRevert(WoCoEventV2.TooEarly.selector);
        vm.prank(organiser);
        woco.withdraw(eventId);

        // Warp past eventEndTs + releaseDelay
        vm.warp(uint256(END_TS) + 24 hours + 1);

        uint256 treasuryBefore = usdc.balanceOf(treasury);
        uint256 payoutBefore   = usdc.balanceOf(payout);

        vm.prank(organiser);
        woco.withdraw(eventId);

        assertEq(usdc.balanceOf(treasury), treasuryBefore + expectedFee);
        assertEq(usdc.balanceOf(payout),   payoutBefore + expectedNet);
        assertEq(woco.escrowBalance(eventId), 0);

        (, , , , , uint256 escrow) = woco.getEventStatus(eventId);
        assertEq(escrow, 0);
    }

    function test_Withdraw_RevertDoubleWithdraw() public {
        bytes32 eventId = _register();
        _approveAndClaim(buyer, eventId, buyer);
        vm.warp(uint256(END_TS) + 24 hours + 1);

        vm.prank(organiser);
        woco.withdraw(eventId);

        vm.expectRevert(WoCoEventV2.AlreadyWithdrawn.selector);
        vm.prank(organiser);
        woco.withdraw(eventId);
    }

    function test_Withdraw_RevertNotOrganiser() public {
        bytes32 eventId = _register();
        _approveAndClaim(buyer, eventId, buyer);
        vm.warp(uint256(END_TS) + 24 hours + 1);

        vm.expectRevert(WoCoEventV2.NotOrganiser.selector);
        vm.prank(buyer);
        woco.withdraw(eventId);
    }

    function test_Withdraw_RevertWhenCancelled() public {
        bytes32 eventId = _register();
        _approveAndClaim(buyer, eventId, buyer);

        vm.prank(organiser);
        woco.cancelEvent(eventId);

        vm.warp(uint256(END_TS) + 24 hours + 1);
        vm.expectRevert(WoCoEventV2.AlreadyCancelled.selector);
        vm.prank(organiser);
        woco.withdraw(eventId);
    }

    function test_Withdraw_RevertWhenFrozen() public {
        bytes32 eventId = _register();
        _approveAndClaim(buyer, eventId, buyer);

        vm.prank(owner);
        woco.freezeEvent(eventId, true);

        vm.warp(uint256(END_TS) + 24 hours + 1);
        vm.expectRevert(WoCoEventV2.EventIsFrozen.selector);
        vm.prank(organiser);
        woco.withdraw(eventId);
    }

    function test_Withdraw_ZeroEscrowOk() public {
        // Event with no crypto claims — withdraw still callable, no-op transfer
        bytes32 eventId = _register();
        vm.warp(uint256(END_TS) + 24 hours + 1);

        uint256 treasuryBefore = usdc.balanceOf(treasury);
        vm.prank(organiser);
        woco.withdraw(eventId);
        assertEq(usdc.balanceOf(treasury), treasuryBefore);
    }

    // ── Escrow: cancel + refund ───────────────────────────────────────────────

    function test_Cancel_RevertNotOrganiser() public {
        bytes32 eventId = _register();
        vm.expectRevert(WoCoEventV2.NotOrganiser.selector);
        vm.prank(buyer);
        woco.cancelEvent(eventId);
    }

    function test_Cancel_RevertDouble() public {
        bytes32 eventId = _register();
        vm.prank(organiser);
        woco.cancelEvent(eventId);
        vm.expectRevert(WoCoEventV2.AlreadyCancelled.selector);
        vm.prank(organiser);
        woco.cancelEvent(eventId);
    }

    function test_Refund_HappyPath_PaysBackPayer() public {
        bytes32 eventId = _register();
        uint256 buyerBefore = usdc.balanceOf(buyer);
        _approveAndClaim(buyer, eventId, recipient); // agent-style: buyer pays for recipient
        assertEq(usdc.balanceOf(buyer), buyerBefore - PRICE);

        vm.prank(organiser);
        woco.cancelEvent(eventId);

        // Anyone may call claimRefund; the refund still goes to the original payer.
        woco.claimRefund(eventId, 0);

        assertEq(usdc.balanceOf(buyer), buyerBefore);
        assertEq(woco.escrowBalance(eventId), 0);

        (, , , , bool refunded) = woco.getSlotData(eventId, 0);
        assertTrue(refunded);
    }

    function test_Refund_RevertNotCancelled() public {
        bytes32 eventId = _register();
        _approveAndClaim(buyer, eventId, buyer);
        vm.expectRevert(WoCoEventV2.NotCancelled.selector);
        woco.claimRefund(eventId, 0);
    }

    function test_Refund_RevertNotEscrowed() public {
        // Stripe slot — claimFor — must not be refundable here.
        bytes32 eventId = _register();
        vm.prank(sponsor);
        woco.claimFor(eventId, buyer, bytes32(0));

        vm.prank(organiser);
        woco.cancelEvent(eventId);

        vm.expectRevert(WoCoEventV2.NotEscrowed.selector);
        woco.claimRefund(eventId, 0);
    }

    function test_Refund_RevertDouble() public {
        bytes32 eventId = _register();
        _approveAndClaim(buyer, eventId, buyer);
        vm.prank(organiser);
        woco.cancelEvent(eventId);

        woco.claimRefund(eventId, 0);
        vm.expectRevert(WoCoEventV2.AlreadyRefunded.selector);
        woco.claimRefund(eventId, 0);
    }

    function test_Refund_BatchFanout_PaysFullBatchBackToOnePayer() public {
        bytes32 eventId = _register();
        address[] memory owners = new address[](3);
        owners[0] = recipient;
        owners[1] = recipient;
        owners[2] = recipient;

        uint256 buyerBefore = usdc.balanceOf(buyer);
        vm.prank(buyer);
        usdc.approve(address(woco), type(uint256).max);
        vm.prank(buyer);
        woco.batchPayAndClaim(eventId, owners, bytes32(0));

        vm.prank(organiser);
        woco.cancelEvent(eventId);

        for (uint256 i; i < 3; ++i) woco.claimRefund(eventId, i);

        assertEq(usdc.balanceOf(buyer), buyerBefore);
        assertEq(woco.escrowBalance(eventId), 0);
    }

    function test_Refund_MixedCryptoStripe_OnlyCryptoRefunded() public {
        bytes32 eventId = _register();
        uint256 buyerBefore = usdc.balanceOf(buyer);

        // Slot 0: crypto
        _approveAndClaim(buyer, eventId, buyer);

        // Slot 1: Stripe (no escrow)
        vm.prank(sponsor);
        woco.claimFor(eventId, buyer, bytes32(0));

        assertEq(woco.escrowBalance(eventId), PRICE);

        vm.prank(organiser);
        woco.cancelEvent(eventId);

        // Crypto refundable
        woco.claimRefund(eventId, 0);
        assertEq(usdc.balanceOf(buyer), buyerBefore);

        // Stripe slot must NOT be refundable through this contract
        vm.expectRevert(WoCoEventV2.NotEscrowed.selector);
        woco.claimRefund(eventId, 1);
    }

    // ── Dispute hooks ─────────────────────────────────────────────────────────

    function test_Freeze_OnlyDisputeAuthority() public {
        bytes32 eventId = _register();
        vm.expectRevert(WoCoEventV2.NotDisputeAuthority.selector);
        vm.prank(buyer);
        woco.freezeEvent(eventId, true);
    }

    function test_Freeze_UnfreezeRestoresWithdraw() public {
        bytes32 eventId = _register();
        _approveAndClaim(buyer, eventId, buyer);

        vm.prank(owner);
        woco.freezeEvent(eventId, true);
        vm.warp(uint256(END_TS) + 24 hours + 1);

        vm.expectRevert(WoCoEventV2.EventIsFrozen.selector);
        vm.prank(organiser);
        woco.withdraw(eventId);

        vm.prank(owner);
        woco.freezeEvent(eventId, false);

        vm.prank(organiser);
        woco.withdraw(eventId);
        assertGt(usdc.balanceOf(payout), 0);
    }

    function test_ForceCancel_OpensRefunds() public {
        bytes32 eventId = _register();
        _approveAndClaim(buyer, eventId, buyer);

        // Bad-actor organiser refuses to cancel — dispute authority forces it.
        vm.expectRevert(WoCoEventV2.NotDisputeAuthority.selector);
        vm.prank(buyer);
        woco.forceCancelEvent(eventId);

        vm.prank(owner);
        woco.forceCancelEvent(eventId);

        uint256 buyerBefore = usdc.balanceOf(buyer);
        woco.claimRefund(eventId, 0);
        assertEq(usdc.balanceOf(buyer), buyerBefore + PRICE);
    }

    function test_SetDisputeAuthority_RotatesPower() public {
        // After rotation the new authority can freeze; old one cannot.
        bytes32 eventId = _register();
        vm.prank(owner);
        woco.setDisputeAuthority(daoAuth);

        vm.expectRevert(WoCoEventV2.NotDisputeAuthority.selector);
        vm.prank(owner);
        woco.freezeEvent(eventId, true);

        vm.prank(daoAuth);
        woco.freezeEvent(eventId, true);
        (, , , , bool frozen, ) = woco.getEventStatus(eventId);
        assertTrue(frozen);
    }

    // ── Admin ─────────────────────────────────────────────────────────────────

    function test_AddRemoveSponsor() public {
        address newSponsor = address(0x99);
        vm.prank(owner);
        woco.addSponsor(newSponsor);
        assertTrue(woco.authorisedSponsors(newSponsor));

        vm.prank(owner);
        woco.removeSponsor(newSponsor);
        assertFalse(woco.authorisedSponsors(newSponsor));
    }

    function test_SetTreasury() public {
        address newTreasury = address(0xAA);
        vm.prank(owner);
        woco.setPlatformTreasury(newTreasury);
        assertEq(woco.platformTreasury(), newTreasury);
    }

    function test_SetDefaultFee() public {
        vm.prank(owner);
        woco.setDefaultPlatformFeeBps(250);
        assertEq(woco.defaultPlatformFeeBps(), 250);
    }

    function test_SetDefaultFee_RevertTooHigh() public {
        vm.prank(owner);
        vm.expectRevert(WoCoEventV2.FeeTooHigh.selector);
        woco.setDefaultPlatformFeeBps(1_001);
    }

    function test_SetDefaultReleaseDelay() public {
        vm.prank(owner);
        woco.setDefaultReleaseDelay(48 hours);
        assertEq(woco.defaultReleaseDelay(), 48 hours);

        // Existing events keep their stamped delay — verify by registering AFTER
        // the change and confirming new events pick up the new default.
        vm.prank(organiser);
        bytes32 eventId = woco.registerEvent(SUPPLY, PRICE, payout, address(0), MANIFEST, END_TS);
        (, uint32 delay, , , , ) = woco.getEventStatus(eventId);
        assertEq(delay, 48 hours);
    }

    function test_Admin_RevertNonOwner() public {
        vm.expectRevert();
        vm.prank(buyer);
        woco.addSponsor(address(0x99));
    }
}
