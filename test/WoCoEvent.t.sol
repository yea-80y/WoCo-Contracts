// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "forge-std/StdInvariant.sol";
import "../src/WoCoEvent.sol";

// ── Unit + fuzz tests ──────────────────────────────────────────────────────────

contract WoCoEventTest is Test {
    WoCoEvent public woco;

    address owner     = address(0x1);
    address sponsor   = address(0x2);
    address organiser = address(0x3);
    address burner    = address(0x4);
    address attacker  = address(0x5);
    address newOwner  = address(0x6);

    bytes32 constant MANIFEST = keccak256("test-manifest");
    uint256 constant SUPPLY   = 10;

    function setUp() public {
        woco = new WoCoEvent(owner, sponsor);
    }

    // ── Constructor ────────────────────────────────────────────────────────────

    function test_Constructor_SetsOwnerAndSponsor() public view {
        assertEq(woco.owner(), owner);
        assertTrue(woco.authorisedSponsors(sponsor));
    }

    function test_Constructor_RevertZeroSponsor() public {
        vm.expectRevert("Zero sponsor");
        new WoCoEvent(owner, address(0));
    }

    // ── registerEvent ──────────────────────────────────────────────────────────

    function test_RegisterEvent_Success() public {
        vm.prank(organiser);
        bytes32 eventId = woco.registerEvent(SUPPLY, MANIFEST);

        (uint256 supply, uint256 nextSlot, address org, bytes32 ref) = woco.events(eventId);
        assertEq(supply, SUPPLY);
        assertEq(nextSlot, 0);
        assertEq(org, organiser);
        assertEq(ref, MANIFEST);
    }

    function test_RegisterEvent_DeriveEventId() public {
        // eventId = keccak256(abi.encode(msg.sender, nonce_before_bump))
        // First call: nonce = 0, so eventId = keccak256(abi.encode(organiser, 0))
        bytes32 expected = keccak256(abi.encode(organiser, uint256(0)));

        vm.prank(organiser);
        bytes32 eventId = woco.registerEvent(SUPPLY, MANIFEST);

        assertEq(eventId, expected);
    }

    function test_RegisterEvent_BumpsNonce() public {
        vm.startPrank(organiser);
        assertEq(woco.organiserNonce(organiser), 0);
        woco.registerEvent(SUPPLY, MANIFEST);
        assertEq(woco.organiserNonce(organiser), 1);
        woco.registerEvent(SUPPLY, MANIFEST);
        assertEq(woco.organiserNonce(organiser), 2);
        vm.stopPrank();
    }

    function test_RegisterEvent_TwoCallsYieldDifferentIds() public {
        vm.startPrank(organiser);
        bytes32 id1 = woco.registerEvent(SUPPLY, MANIFEST);
        bytes32 id2 = woco.registerEvent(SUPPLY, MANIFEST);
        vm.stopPrank();

        assertTrue(id1 != id2);
    }

    function test_RegisterEvent_RevertZeroSupply() public {
        vm.prank(organiser);
        vm.expectRevert("Supply must be > 0");
        woco.registerEvent(0, MANIFEST);
    }

    function test_RegisterEvent_RevertZeroManifestRef() public {
        vm.prank(organiser);
        vm.expectRevert("Zero manifestRef");
        woco.registerEvent(SUPPLY, bytes32(0));
    }

    function test_RegisterEvent_EmitsRegistered() public {
        bytes32 expected = keccak256(abi.encode(organiser, uint256(0)));

        vm.prank(organiser);
        vm.expectEmit(true, true, false, true);
        emit WoCoEvent.Registered(expected, organiser, SUPPLY, MANIFEST);
        woco.registerEvent(SUPPLY, MANIFEST);
    }

    // ── claimFor ───────────────────────────────────────────────────────────────

    function _register() internal returns (bytes32) {
        vm.prank(organiser);
        return woco.registerEvent(SUPPLY, MANIFEST);
    }

    function test_ClaimFor_AllocatesFirstSlot() public {
        bytes32 eventId  = _register();
        bytes32 orderRef = keccak256("order-1");

        vm.prank(sponsor);
        uint256 slot = woco.claimFor(eventId, burner, orderRef);

        assertEq(slot, 0);
        assertEq(woco.slotOwner(eventId, 0), burner);
        assertEq(woco.slotOrderRef(eventId, 0), orderRef);
    }

    function test_ClaimFor_StoresOrderRef() public {
        bytes32 eventId  = _register();
        bytes32 orderRef = keccak256("my-sealed-box-ref");

        vm.prank(sponsor);
        woco.claimFor(eventId, burner, orderRef);

        assertEq(woco.slotOrderRef(eventId, 0), orderRef);
    }

    function test_GetSlotData_ReturnsOwnerAndOrderRef() public {
        bytes32 eventId  = _register();
        bytes32 orderRef = keccak256("order-ref-abc");

        vm.prank(sponsor);
        woco.claimFor(eventId, burner, orderRef);

        (address owner, bytes32 ref) = woco.getSlotData(eventId, 0);
        assertEq(owner, burner);
        assertEq(ref, orderRef);
    }

    function test_GetSlotData_UnclaimedSlotReturnsZero() public {
        bytes32 eventId = _register();

        (address owner, bytes32 ref) = woco.getSlotData(eventId, 0);
        assertEq(owner, address(0));
        assertEq(ref, bytes32(0));
    }

    function test_GetSlotData_MultipleSlots() public {
        bytes32 eventId  = _register();
        bytes32 orderRef0 = keccak256("order-0");
        bytes32 orderRef1 = keccak256("order-1");
        address burner2  = address(0x42);

        vm.startPrank(sponsor);
        woco.claimFor(eventId, burner, orderRef0);
        woco.claimFor(eventId, burner2, orderRef1);
        vm.stopPrank();

        (address owner0, bytes32 ref0) = woco.getSlotData(eventId, 0);
        (address owner1, bytes32 ref1) = woco.getSlotData(eventId, 1);

        assertEq(owner0, burner);
        assertEq(ref0, orderRef0);
        assertEq(owner1, burner2);
        assertEq(ref1, orderRef1);
    }

    function test_ClaimFor_AllocatesSequentialSlots() public {
        bytes32 eventId = _register();
        address burner2 = address(0x99);

        vm.startPrank(sponsor);
        uint256 slot0 = woco.claimFor(eventId, burner, keccak256("o1"));
        uint256 slot1 = woco.claimFor(eventId, burner2, keccak256("o2"));
        vm.stopPrank();

        assertEq(slot0, 0);
        assertEq(slot1, 1);
        assertEq(woco.slotOwner(eventId, 0), burner);
        assertEq(woco.slotOwner(eventId, 1), burner2);
    }

    function test_ClaimFor_AllSlotsFillToSupply() public {
        bytes32 eventId = _register();

        vm.startPrank(sponsor);
        for (uint256 i = 0; i < SUPPLY; i++) {
            uint256 slot = woco.claimFor(
                eventId,
                address(uint160(i + 100)),
                bytes32(i)
            );
            assertEq(slot, i);
        }
        vm.stopPrank();

        (, uint256 nextSlot, ,) = woco.events(eventId);
        assertEq(nextSlot, SUPPLY);
    }

    function test_ClaimFor_RevertOversell() public {
        vm.prank(organiser);
        bytes32 eventId = woco.registerEvent(1, MANIFEST);

        vm.startPrank(sponsor);
        woco.claimFor(eventId, burner, keccak256("o1"));

        vm.expectRevert("Sold out");
        woco.claimFor(eventId, address(0x99), keccak256("o2"));
        vm.stopPrank();
    }

    function test_ClaimFor_RevertUnauthorised() public {
        bytes32 eventId = _register();

        vm.prank(attacker);
        vm.expectRevert("Not authorised");
        woco.claimFor(eventId, burner, keccak256("o1"));
    }

    function test_ClaimFor_RevertEventNotFound() public {
        bytes32 badId = keccak256("nonexistent");

        vm.prank(sponsor);
        vm.expectRevert("Event not found");
        woco.claimFor(badId, burner, keccak256("o1"));
    }

    function test_ClaimFor_EmitsSlotClaimed() public {
        bytes32 eventId  = _register();
        bytes32 orderRef = keccak256("order-1");

        vm.prank(sponsor);
        vm.expectEmit(true, false, true, true);
        emit WoCoEvent.SlotClaimed(eventId, 0, burner, orderRef);
        woco.claimFor(eventId, burner, orderRef);
    }

    function test_ClaimFor_NextSlotIncrements() public {
        bytes32 eventId = _register();

        vm.prank(sponsor);
        woco.claimFor(eventId, burner, keccak256("o1"));

        (, uint256 nextSlot, ,) = woco.events(eventId);
        assertEq(nextSlot, 1);
    }

    // ── batchClaimFor ──────────────────────────────────────────────────────────

    function test_BatchClaimFor_AllocatesNContiguousSlots() public {
        bytes32 eventId = _register();
        address[] memory burners = new address[](3);
        burners[0] = address(0xA1);
        burners[1] = address(0xA2);
        burners[2] = address(0xA3);
        bytes32 orderRef = keccak256("shared-order");

        vm.prank(sponsor);
        uint256 firstSlot = woco.batchClaimFor(eventId, burners, orderRef);

        assertEq(firstSlot, 0);
        assertEq(woco.slotOwner(eventId, 0), burners[0]);
        assertEq(woco.slotOwner(eventId, 1), burners[1]);
        assertEq(woco.slotOwner(eventId, 2), burners[2]);
        assertEq(woco.slotOrderRef(eventId, 0), orderRef);
        assertEq(woco.slotOrderRef(eventId, 1), orderRef);
        assertEq(woco.slotOrderRef(eventId, 2), orderRef);

        (, uint256 nextSlot, ,) = woco.events(eventId);
        assertEq(nextSlot, 3);
    }

    function test_BatchClaimFor_FollowsExistingClaims() public {
        bytes32 eventId = _register();

        vm.prank(sponsor);
        woco.claimFor(eventId, burner, keccak256("solo"));

        address[] memory burners = new address[](2);
        burners[0] = address(0xB1);
        burners[1] = address(0xB2);

        vm.prank(sponsor);
        uint256 firstSlot = woco.batchClaimFor(eventId, burners, keccak256("batch"));
        assertEq(firstSlot, 1);
        assertEq(woco.slotOwner(eventId, 1), burners[0]);
        assertEq(woco.slotOwner(eventId, 2), burners[1]);
    }

    function test_BatchClaimFor_RevertEmpty() public {
        bytes32 eventId = _register();
        address[] memory burners = new address[](0);
        vm.prank(sponsor);
        vm.expectRevert("Empty batch");
        woco.batchClaimFor(eventId, burners, keccak256("x"));
    }

    function test_BatchClaimFor_RevertTooLarge() public {
        bytes32 eventId = _register();
        address[] memory burners = new address[](101);
        for (uint256 i = 0; i < 101; i++) burners[i] = address(uint160(i + 1));
        vm.prank(sponsor);
        vm.expectRevert("Batch too large");
        woco.batchClaimFor(eventId, burners, keccak256("x"));
    }

    function test_BatchClaimFor_RevertInsufficientSupply() public {
        vm.prank(organiser);
        bytes32 eventId = woco.registerEvent(2, MANIFEST);

        address[] memory burners = new address[](3);
        burners[0] = address(0xC1);
        burners[1] = address(0xC2);
        burners[2] = address(0xC3);

        vm.prank(sponsor);
        vm.expectRevert("Insufficient supply");
        woco.batchClaimFor(eventId, burners, keccak256("x"));

        // Nothing was written
        (, uint256 nextSlot, ,) = woco.events(eventId);
        assertEq(nextSlot, 0);
    }

    function test_BatchClaimFor_RevertUnauthorised() public {
        bytes32 eventId = _register();
        address[] memory burners = new address[](1);
        burners[0] = burner;
        vm.prank(attacker);
        vm.expectRevert("Not authorised");
        woco.batchClaimFor(eventId, burners, keccak256("x"));
    }

    function test_BatchClaimFor_EmitsOneEventPerSlot() public {
        bytes32 eventId = _register();
        address[] memory burners = new address[](2);
        burners[0] = address(0xD1);
        burners[1] = address(0xD2);
        bytes32 orderRef = keccak256("batch-emit");

        vm.prank(sponsor);
        vm.expectEmit(true, false, true, true);
        emit WoCoEvent.SlotClaimed(eventId, 0, burners[0], orderRef);
        vm.expectEmit(true, false, true, true);
        emit WoCoEvent.SlotClaimed(eventId, 1, burners[1], orderRef);
        woco.batchClaimFor(eventId, burners, orderRef);
    }

    function test_BatchClaimFor_MaxSize100() public {
        // Register an event with 100-supply so the full batch fits.
        vm.prank(organiser);
        bytes32 eventId = woco.registerEvent(100, MANIFEST);

        address[] memory burners = new address[](100);
        for (uint256 i = 0; i < 100; i++) burners[i] = address(uint160(i + 1));

        vm.prank(sponsor);
        uint256 firstSlot = woco.batchClaimFor(eventId, burners, keccak256("max"));
        assertEq(firstSlot, 0);

        (, uint256 nextSlot, ,) = woco.events(eventId);
        assertEq(nextSlot, 100);
    }

    // ── Sponsor management ─────────────────────────────────────────────────────

    function test_AddSponsor_OwnerCanAdd() public {
        address newSponsor = address(0x77);

        vm.prank(owner);
        woco.addSponsor(newSponsor);

        assertTrue(woco.authorisedSponsors(newSponsor));
    }

    function test_AddSponsor_RevertNonOwner() public {
        vm.prank(attacker);
        vm.expectRevert();
        woco.addSponsor(address(0x77));
    }

    function test_AddSponsor_RevertZeroAddress() public {
        vm.prank(owner);
        vm.expectRevert("Zero address");
        woco.addSponsor(address(0));
    }

    function test_RemoveSponsor_OwnerCanRemove() public {
        vm.prank(owner);
        woco.removeSponsor(sponsor);

        assertFalse(woco.authorisedSponsors(sponsor));
    }

    function test_RemoveSponsor_RevertNonOwner() public {
        vm.prank(attacker);
        vm.expectRevert();
        woco.removeSponsor(sponsor);
    }

    function test_RemoveSponsor_RevokedSponsorCannotClaim() public {
        bytes32 eventId = _register();

        vm.prank(owner);
        woco.removeSponsor(sponsor);

        vm.prank(sponsor);
        vm.expectRevert("Not authorised");
        woco.claimFor(eventId, burner, keccak256("o1"));
    }

    function test_AddRemoveSponsor_EmitsEvents() public {
        address newSponsor = address(0x88);

        vm.startPrank(owner);

        vm.expectEmit(true, false, false, false);
        emit WoCoEvent.SponsorAdded(newSponsor);
        woco.addSponsor(newSponsor);

        vm.expectEmit(true, false, false, false);
        emit WoCoEvent.SponsorRemoved(newSponsor);
        woco.removeSponsor(newSponsor);

        vm.stopPrank();
    }

    // ── Ownable2Step ───────────────────────────────────────────────────────────

    function test_Ownable2Step_PendingOwnerAccepts() public {
        vm.prank(owner);
        woco.transferOwnership(newOwner);

        assertEq(woco.pendingOwner(), newOwner);
        assertEq(woco.owner(), owner); // not yet transferred

        vm.prank(newOwner);
        woco.acceptOwnership();

        assertEq(woco.owner(), newOwner);
        assertEq(woco.pendingOwner(), address(0));
    }

    function test_Ownable2Step_RevertAcceptByNonPending() public {
        vm.prank(owner);
        woco.transferOwnership(newOwner);

        vm.prank(attacker);
        vm.expectRevert();
        woco.acceptOwnership();
    }

    function test_Ownable2Step_NewOwnerCanManageSponsors() public {
        vm.prank(owner);
        woco.transferOwnership(newOwner);
        vm.prank(newOwner);
        woco.acceptOwnership();

        address freshSponsor = address(0x88);
        vm.prank(newOwner);
        woco.addSponsor(freshSponsor);

        assertTrue(woco.authorisedSponsors(freshSponsor));
    }

    function test_Ownable2Step_OldOwnerCannotManageAfterTransfer() public {
        vm.prank(owner);
        woco.transferOwnership(newOwner);
        vm.prank(newOwner);
        woco.acceptOwnership();

        vm.prank(owner);
        vm.expectRevert();
        woco.addSponsor(address(0x99));
    }

    // ── eventId collision / front-run scenarios ────────────────────────────────

    function test_EventIdCollision_TwoOrganisersDifferentIds() public {
        address org2 = address(0x44);

        vm.prank(organiser);
        bytes32 id1 = woco.registerEvent(SUPPLY, MANIFEST);

        vm.prank(org2);
        bytes32 id2 = woco.registerEvent(SUPPLY, MANIFEST);

        assertTrue(id1 != id2);
    }

    function test_EventIdCollision_SameOrganiserDifferentNonce() public {
        vm.startPrank(organiser);
        bytes32 id1 = woco.registerEvent(SUPPLY, MANIFEST);
        bytes32 id2 = woco.registerEvent(SUPPLY, MANIFEST);
        vm.stopPrank();

        assertTrue(id1 != id2);
    }

    function test_EventIdCollision_FrontRunnerCannotOccupyOthersSlot() public {
        // An attacker registers an event with nonce 0 before the legitimate
        // organiser. They get a different eventId because their sender differs.
        // The legitimate organiser's eventId is still keccak256(organiser, 0).
        bytes32 attackerEventId;
        vm.prank(attacker);
        attackerEventId = woco.registerEvent(SUPPLY, MANIFEST);

        bytes32 expected = keccak256(abi.encode(organiser, uint256(0)));
        vm.prank(organiser);
        bytes32 organiserEventId = woco.registerEvent(SUPPLY, MANIFEST);

        assertEq(organiserEventId, expected);
        assertTrue(attackerEventId != organiserEventId);
    }

    // ── Fuzz tests ─────────────────────────────────────────────────────────────

    function testFuzz_RegisterEvent(uint256 supply, bytes32 manifestRef) public {
        supply = bound(supply, 1, type(uint96).max);
        vm.assume(manifestRef != bytes32(0));

        bytes32 expected = keccak256(abi.encode(organiser, uint256(0)));

        vm.prank(organiser);
        bytes32 eventId = woco.registerEvent(supply, manifestRef);

        assertEq(eventId, expected);

        (uint256 storedSupply, uint256 nextSlot, address org, bytes32 ref) = woco.events(eventId);
        assertEq(storedSupply, supply);
        assertEq(nextSlot, 0);
        assertEq(org, organiser);
        assertEq(ref, manifestRef);
    }

    function testFuzz_ClaimFor_SlotAllocation(uint256 supply) public {
        supply = bound(supply, 1, 200);
        bytes32 manifestRef = bytes32(uint256(0xdeadbeef));

        vm.prank(organiser);
        bytes32 eventId = woco.registerEvent(supply, manifestRef);

        vm.startPrank(sponsor);
        for (uint256 i = 0; i < supply; i++) {
            uint256 slot = woco.claimFor(
                eventId,
                address(uint160(i + 1)),
                bytes32(i)
            );
            assertEq(slot, i);
        }

        vm.expectRevert("Sold out");
        woco.claimFor(eventId, burner, bytes32(supply));
        vm.stopPrank();

        (, uint256 nextSlot, ,) = woco.events(eventId);
        assertEq(nextSlot, supply);
    }
}

// ── Invariant test ─────────────────────────────────────────────────────────────

/**
 * Handler contract called by the Foundry fuzzer.
 * The handler itself is added as an authorised sponsor so it can call claimFor
 * directly without pranking, which is cleaner in invariant test contexts.
 */
contract WoCoEventHandler is Test {
    WoCoEvent internal woco;

    bytes32[] public registeredEventIds;

    constructor(WoCoEvent _woco) {
        woco = _woco;
    }

    function registerEvent(uint256 supply, bytes32 manifestRef) external {
        supply = bound(supply, 1, 500);
        if (manifestRef == bytes32(0)) manifestRef = bytes32(uint256(1));

        bytes32 id = woco.registerEvent(supply, manifestRef);
        registeredEventIds.push(id);
    }

    function claimFor(
        uint256 eventIndex,
        address burner,
        bytes32 orderRef
    ) external {
        if (registeredEventIds.length == 0) return;
        eventIndex = bound(eventIndex, 0, registeredEventIds.length - 1);
        bytes32 eventId = registeredEventIds[eventIndex];

        (uint256 totalSupply, uint256 nextSlot, ,) = woco.events(eventId);
        if (nextSlot >= totalSupply) return; // already sold out, skip

        if (burner == address(0)) burner = address(0x1);

        // Handler is authorised sponsor — calls directly (no prank needed)
        woco.claimFor(eventId, burner, orderRef);
    }

    function getEventCount() external view returns (uint256) {
        return registeredEventIds.length;
    }
}

contract WoCoEventInvariantTest is Test {
    WoCoEvent     internal woco;
    WoCoEventHandler internal handler;

    address constant OWNER = address(0x1);

    function setUp() public {
        // Deploy with this test contract as initial sponsor so we can
        // immediately add the handler after it's created.
        woco = new WoCoEvent(OWNER, address(this));

        handler = new WoCoEventHandler(woco);

        // Handler is both the organiser (msg.sender on registerEvent calls)
        // and an authorised sponsor (calls claimFor directly).
        vm.prank(OWNER);
        woco.addSponsor(address(handler));

        targetContract(address(handler));
    }

    /**
     * Core safety invariant: the number of claimed slots never exceeds
     * the declared totalSupply for any registered event.
     */
    function invariant_nextSlotNeverExceedsSupply() public view {
        uint256 count = handler.getEventCount();
        for (uint256 i = 0; i < count; i++) {
            bytes32 eventId = handler.registeredEventIds(i);
            (uint256 totalSupply, uint256 nextSlot, ,) = woco.events(eventId);
            assertLe(nextSlot, totalSupply, "nextSlot exceeded totalSupply");
        }
    }
}
