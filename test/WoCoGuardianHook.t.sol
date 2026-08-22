// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {WoCoGuardianHook} from "../src/recovery/WoCoGuardianHook.sol";

/// @dev Semantics locks for the guardian hook (WoCo-Event-App #164, #148).
///      Two properties carry the whole design and are asserted in several shapes:
///        1. preCheck refuses everyone outside the account's CURRENT set;
///        2. nothing — not re-install, not clear-then-install, not uninstall-then-
///           install — brings a removed guardian back.
contract WoCoGuardianHookTest is Test {
    WoCoGuardianHook hook;

    address kernelA = makeAddr("kernelA");
    address kernelB = makeAddr("kernelB");
    address g1 = makeAddr("guardian1");
    address g2 = makeAddr("guardian2");
    address g3 = makeAddr("guardian3");
    address stranger = makeAddr("stranger");

    event GuardiansSet(address indexed account, address[] guardians);
    event GuardianAdded(address indexed account, address indexed guardian);
    event GuardianRevoked(address indexed account, address indexed guardian);
    event GuardiansCleared(address indexed account);

    function setUp() public {
        hook = new WoCoGuardianHook();
    }

    function _arr(address a) internal pure returns (address[] memory r) {
        r = new address[](1);
        r[0] = a;
    }

    function _arr(address a, address b) internal pure returns (address[] memory r) {
        r = new address[](2);
        r[0] = a;
        r[1] = b;
    }

    function _arr(address a, address b, address c) internal pure returns (address[] memory r) {
        r = new address[](3);
        r[0] = a;
        r[1] = b;
        r[2] = c;
    }

    /// @dev What Kernel's fallback does: hook.preCheck(originalCaller, value, data) with msg.sender = account.
    function _preCheck(address account, address caller) internal returns (bytes memory) {
        vm.prank(account);
        return hook.preCheck(caller, 0, hex"ac39fd0f");
    }

    // ---------------------------------------------------------------- install

    function test_onInstall_setsExactly() public {
        vm.prank(kernelA);
        vm.expectEmit(true, false, false, true);
        emit GuardiansSet(kernelA, _arr(g1, g2));
        hook.onInstall(abi.encode(_arr(g1, g2)));

        assertEq(hook.guardiansOf(kernelA), _arr(g1, g2));
        assertEq(hook.guardianCount(kernelA), 2);
        assertTrue(hook.isGuardian(kernelA, g1));
        assertTrue(hook.isGuardian(kernelA, g2));
        assertFalse(hook.isGuardian(kernelA, g3));
        assertTrue(hook.isInitialized(kernelA));
    }

    /// @dev THE defect this contract exists to fix: a second install must REPLACE, not OR.
    function test_onInstall_replacesPreviousSet() public {
        vm.startPrank(kernelA);
        hook.onInstall(abi.encode(_arr(g1)));
        hook.onInstall(abi.encode(_arr(g2)));
        vm.stopPrank();

        assertEq(hook.guardiansOf(kernelA), _arr(g2));
        assertFalse(hook.isGuardian(kernelA, g1));
        assertTrue(hook.isGuardian(kernelA, g2));
        vm.expectRevert(abi.encodeWithSelector(WoCoGuardianHook.NotAGuardian.selector, kernelA, g1));
        _preCheck(kernelA, g1);
    }

    function test_onInstall_rejectsZeroDuplicateAndCap() public {
        vm.startPrank(kernelA);
        vm.expectRevert(WoCoGuardianHook.ZeroGuardian.selector);
        hook.onInstall(abi.encode(_arr(address(0))));
        vm.expectRevert(abi.encodeWithSelector(WoCoGuardianHook.DuplicateGuardian.selector, g1));
        hook.onInstall(abi.encode(_arr(g1, g1)));

        address[] memory tooMany = new address[](hook.MAX_GUARDIANS() + 1);
        for (uint256 i; i < tooMany.length; ++i) tooMany[i] = address(uint160(i + 1));
        vm.expectRevert(abi.encodeWithSelector(WoCoGuardianHook.TooManyGuardians.selector, tooMany.length));
        hook.onInstall(abi.encode(tooMany));
        vm.stopPrank();
        // A reverted install left nothing behind.
        assertEq(hook.guardianCount(kernelA), 0);
        assertFalse(hook.isInitialized(kernelA));
    }

    function test_onInstall_emptyListClears() public {
        vm.startPrank(kernelA);
        hook.onInstall(abi.encode(_arr(g1)));
        hook.onInstall(abi.encode(new address[](0)));
        vm.stopPrank();
        assertEq(hook.guardianCount(kernelA), 0);
        assertFalse(hook.isInitialized(kernelA));
        assertFalse(hook.isGuardian(kernelA, g1));
    }

    // --------------------------------------------------------------- preCheck

    function test_preCheck_allowsCurrentGuardianOnly() public {
        vm.prank(kernelA);
        hook.onInstall(abi.encode(_arr(g1)));

        bytes memory ctx = _preCheck(kernelA, g1);
        assertEq(ctx.length, 0);

        vm.expectRevert(abi.encodeWithSelector(WoCoGuardianHook.NotAGuardian.selector, kernelA, stranger));
        _preCheck(kernelA, stranger);
        // The account itself is not a guardian either.
        vm.expectRevert(abi.encodeWithSelector(WoCoGuardianHook.NotAGuardian.selector, kernelA, kernelA));
        _preCheck(kernelA, kernelA);
    }

    function test_preCheck_refusesEverythingWhenNoSet() public {
        vm.expectRevert(abi.encodeWithSelector(WoCoGuardianHook.NotAGuardian.selector, kernelA, g1));
        _preCheck(kernelA, g1);
    }

    function test_preCheck_isScopedPerAccount() public {
        vm.prank(kernelA);
        hook.onInstall(abi.encode(_arr(g1)));
        vm.prank(kernelB);
        hook.onInstall(abi.encode(_arr(g2)));

        _preCheck(kernelA, g1);
        _preCheck(kernelB, g2);
        vm.expectRevert(abi.encodeWithSelector(WoCoGuardianHook.NotAGuardian.selector, kernelA, g2));
        _preCheck(kernelA, g2);
        vm.expectRevert(abi.encodeWithSelector(WoCoGuardianHook.NotAGuardian.selector, kernelB, g1));
        _preCheck(kernelB, g1);
    }

    function test_postCheck_isANoOp() public {
        hook.postCheck("");
        hook.postCheck(hex"deadbeef");
    }

    // ----------------------------------------------------------------- revoke

    function test_revokeGuardian_middleKeepsIndexesConsistent() public {
        vm.startPrank(kernelA);
        hook.onInstall(abi.encode(_arr(g1, g2, g3)));
        vm.expectEmit(true, true, false, true);
        emit GuardianRevoked(kernelA, g2);
        hook.revokeGuardian(g2);
        vm.stopPrank();

        // swap-pop: g3 moved into g2's slot
        assertEq(hook.guardiansOf(kernelA), _arr(g1, g3));
        assertFalse(hook.isGuardian(kernelA, g2));
        assertTrue(hook.isGuardian(kernelA, g3));
        vm.expectRevert(abi.encodeWithSelector(WoCoGuardianHook.NotAGuardian.selector, kernelA, g2));
        _preCheck(kernelA, g2);
        _preCheck(kernelA, g3);

        // the moved guardian's index is still right: revoking it works and leaves g1
        vm.prank(kernelA);
        hook.revokeGuardian(g3);
        assertEq(hook.guardiansOf(kernelA), _arr(g1));
        assertFalse(hook.isGuardian(kernelA, g3));
    }

    function test_revokeGuardian_lastAndOnly() public {
        vm.startPrank(kernelA);
        hook.onInstall(abi.encode(_arr(g1, g2)));
        hook.revokeGuardian(g2); // last element
        assertEq(hook.guardiansOf(kernelA), _arr(g1));
        hook.revokeGuardian(g1); // only element
        vm.stopPrank();
        assertEq(hook.guardianCount(kernelA), 0);
        assertFalse(hook.isInitialized(kernelA));
        assertFalse(hook.isGuardian(kernelA, g1));
        assertFalse(hook.isGuardian(kernelA, g2));
    }

    function test_revokeGuardian_unknownReverts() public {
        vm.startPrank(kernelA);
        hook.onInstall(abi.encode(_arr(g1)));
        vm.expectRevert(abi.encodeWithSelector(WoCoGuardianHook.UnknownGuardian.selector, kernelA, g2));
        hook.revokeGuardian(g2);
        // revoking twice is the same mistake
        hook.revokeGuardian(g1);
        vm.expectRevert(abi.encodeWithSelector(WoCoGuardianHook.UnknownGuardian.selector, kernelA, g1));
        hook.revokeGuardian(g1);
        vm.stopPrank();
    }

    function test_revokeGuardian_onlyAffectsCaller() public {
        vm.prank(kernelA);
        hook.onInstall(abi.encode(_arr(g1)));
        // kernelB (or anyone) naming g1 touches only ITS OWN (empty) set.
        vm.prank(kernelB);
        vm.expectRevert(abi.encodeWithSelector(WoCoGuardianHook.UnknownGuardian.selector, kernelB, g1));
        hook.revokeGuardian(g1);
        assertTrue(hook.isGuardian(kernelA, g1));
    }

    // ------------------------------------------------------------- add / clear

    function test_addGuardian() public {
        vm.startPrank(kernelA);
        vm.expectEmit(true, true, false, true);
        emit GuardianAdded(kernelA, g1);
        hook.addGuardian(g1);
        hook.addGuardian(g2);
        vm.expectRevert(abi.encodeWithSelector(WoCoGuardianHook.DuplicateGuardian.selector, g1));
        hook.addGuardian(g1);
        vm.expectRevert(WoCoGuardianHook.ZeroGuardian.selector);
        hook.addGuardian(address(0));
        vm.stopPrank();
        assertEq(hook.guardiansOf(kernelA), _arr(g1, g2));
    }

    function test_addGuardian_respectsCap() public {
        vm.startPrank(kernelA);
        uint256 cap = hook.MAX_GUARDIANS();
        for (uint256 i; i < cap; ++i) hook.addGuardian(address(uint160(i + 1)));
        vm.expectRevert(abi.encodeWithSelector(WoCoGuardianHook.TooManyGuardians.selector, cap + 1));
        hook.addGuardian(address(uint160(cap + 1)));
        vm.stopPrank();
        assertEq(hook.guardianCount(kernelA), cap);
    }

    function test_clearGuardians_and_onUninstall() public {
        vm.startPrank(kernelA);
        hook.onInstall(abi.encode(_arr(g1, g2)));
        vm.expectEmit(true, false, false, true);
        emit GuardiansCleared(kernelA);
        hook.clearGuardians();
        assertEq(hook.guardianCount(kernelA), 0);
        assertFalse(hook.isGuardian(kernelA, g1));

        hook.onInstall(abi.encode(_arr(g3)));
        hook.onUninstall("");
        vm.stopPrank();
        assertEq(hook.guardianCount(kernelA), 0);
        assertFalse(hook.isInitialized(kernelA));
        vm.expectRevert(abi.encodeWithSelector(WoCoGuardianHook.NotAGuardian.selector, kernelA, g3));
        _preCheck(kernelA, g3);
    }

    function test_setGuardians_replaces() public {
        vm.startPrank(kernelA);
        hook.onInstall(abi.encode(_arr(g1)));
        hook.setGuardians(_arr(g2, g3));
        vm.stopPrank();
        assertEq(hook.guardiansOf(kernelA), _arr(g2, g3));
        assertFalse(hook.isGuardian(kernelA, g1));
    }

    // ------------------------------------------------------- no resurrection

    /// @dev The sequence that resurrects guardians on the ZeroDev hook must not here.
    function test_noResurrection_clearThenInstall() public {
        vm.startPrank(kernelA);
        hook.onInstall(abi.encode(_arr(g1)));
        hook.clearGuardians();
        hook.onInstall(abi.encode(_arr(g2)));
        vm.stopPrank();
        assertFalse(hook.isGuardian(kernelA, g1));
        vm.expectRevert(abi.encodeWithSelector(WoCoGuardianHook.NotAGuardian.selector, kernelA, g1));
        _preCheck(kernelA, g1);
    }

    function test_noResurrection_uninstallThenInstall() public {
        vm.startPrank(kernelA);
        hook.onInstall(abi.encode(_arr(g1, g2)));
        hook.onUninstall("");
        hook.onInstall(abi.encode(_arr(g3)));
        vm.stopPrank();
        assertEq(hook.guardiansOf(kernelA), _arr(g3));
        assertFalse(hook.isGuardian(kernelA, g1));
        assertFalse(hook.isGuardian(kernelA, g2));
    }

    function test_noResurrection_revokeThenReinstallOthers() public {
        vm.startPrank(kernelA);
        hook.onInstall(abi.encode(_arr(g1, g2)));
        hook.revokeGuardian(g1);
        // re-install naming only the survivors (what "add another backup" composes)
        hook.onInstall(abi.encode(_arr(g2, g3)));
        vm.stopPrank();
        assertFalse(hook.isGuardian(kernelA, g1));
        assertTrue(hook.isGuardian(kernelA, g2));
        assertTrue(hook.isGuardian(kernelA, g3));
    }

    // ------------------------------------------------------------- module type

    function test_isModuleType_onlyHook() public view {
        assertTrue(hook.isModuleType(4));
        assertFalse(hook.isModuleType(1));
        assertFalse(hook.isModuleType(2));
        assertFalse(hook.isModuleType(3));
        assertFalse(hook.isModuleType(5));
        assertFalse(hook.isModuleType(0));
    }

    // ------------------------------------------------------------------- fuzz

    /// @dev Random adds and revokes never leave the list and the index map disagreeing.
    function testFuzz_listAndIndexStayConsistent(uint8[16] calldata ops, uint8[16] calldata who) public {
        vm.startPrank(kernelA);
        for (uint256 i; i < ops.length; ++i) {
            address g = address(uint160(uint256(who[i] % 8) + 1)); // 8 candidate guardians, never zero
            if (ops[i] % 2 == 0) {
                if (!hook.isGuardian(kernelA, g)) hook.addGuardian(g);
            } else {
                if (hook.isGuardian(kernelA, g)) hook.revokeGuardian(g);
            }
            _assertConsistent(kernelA);
        }
        vm.stopPrank();
    }

    function _assertConsistent(address account) internal view {
        address[] memory list = hook.guardiansOf(account);
        assertEq(hook.guardianCount(account), list.length);
        for (uint256 i; i < list.length; ++i) {
            assertTrue(hook.isGuardian(account, list[i]), "listed but not a guardian");
            for (uint256 j = i + 1; j < list.length; ++j) {
                assertTrue(list[i] != list[j], "duplicate in list");
            }
        }
        for (uint256 k = 1; k <= 8; ++k) {
            address g = address(uint160(k));
            bool listed;
            for (uint256 i; i < list.length; ++i) {
                if (list[i] == g) listed = true;
            }
            assertEq(hook.isGuardian(account, g), listed, "membership disagrees with list");
        }
    }
}
