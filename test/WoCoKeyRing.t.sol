// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {Test} from "forge-std/Test.sol";
import {WoCoKeyRing} from "../src/WoCoKeyRing.sol";
import {DeployKeyRing} from "../script/DeployKeyRing.s.sol";

contract WoCoKeyRingTest is Test {
    WoCoKeyRing reg;
    address constant ACCOUNT = address(0xA11CE);
    address constant OTHER = address(0xB0B);

    event RingSet(address indexed account, bytes32 indexed prev, bytes32 ring);

    function setUp() public {
        reg = new WoCoKeyRing();
    }

    /// The app hard-codes this address (@woco/shared keyring/anchor.ts). A compiler, setting or
    /// submodule change that moves the CREATE2 address must fail here, not at the first ring write.
    function test_singletonAddress_isPinned() public {
        assertEq(new DeployKeyRing().predict(), 0xf5dbe22C7C9F1A19ab39DC2770F246e0C4283AAb);
    }

    function test_firstRing_fromNone() public {
        vm.expectEmit(true, true, false, true, address(reg));
        emit RingSet(ACCOUNT, bytes32(0), bytes32(uint256(1)));
        vm.prank(ACCOUNT);
        reg.setRing(bytes32(0), bytes32(uint256(1)));
        assertEq(reg.ringOf(ACCOUNT), bytes32(uint256(1)));
    }

    function test_nextRing_needsTheCurrentOne() public {
        vm.startPrank(ACCOUNT);
        reg.setRing(bytes32(0), bytes32(uint256(1)));
        reg.setRing(bytes32(uint256(1)), bytes32(uint256(2)));
        vm.expectRevert(abi.encodeWithSelector(WoCoKeyRing.StaleRing.selector, bytes32(uint256(2))));
        reg.setRing(bytes32(uint256(1)), bytes32(uint256(3)));
        vm.stopPrank();
        assertEq(reg.ringOf(ACCOUNT), bytes32(uint256(2)));
    }

    function test_aRingIsNeverCleared() public {
        vm.startPrank(ACCOUNT);
        reg.setRing(bytes32(0), bytes32(uint256(1)));
        vm.expectRevert(WoCoKeyRing.NoRing.selector);
        reg.setRing(bytes32(uint256(1)), bytes32(0));
        vm.expectRevert(WoCoKeyRing.NoRing.selector);
        reg.setRing(bytes32(0), bytes32(0));
        vm.stopPrank();
        assertEq(reg.ringOf(ACCOUNT), bytes32(uint256(1)));
    }

    function test_onlyTheAccountMovesItsEntry() public {
        vm.prank(ACCOUNT);
        reg.setRing(bytes32(0), bytes32(uint256(1)));
        // Another caller's write lands on its own entry, whatever prev it names.
        vm.prank(OTHER);
        reg.setRing(bytes32(0), bytes32(uint256(9)));
        assertEq(reg.ringOf(ACCOUNT), bytes32(uint256(1)));
        assertEq(reg.ringOf(OTHER), bytes32(uint256(9)));
        vm.prank(OTHER);
        vm.expectRevert(abi.encodeWithSelector(WoCoKeyRing.StaleRing.selector, bytes32(uint256(9))));
        reg.setRing(bytes32(uint256(1)), bytes32(uint256(5)));
    }

    function testFuzz_compareAndSwap(address account, bytes32[4] calldata rings, bytes32 wrong) public {
        bytes32 prev;
        for (uint256 i; i < rings.length; i++) {
            vm.assume(rings[i] != bytes32(0));
            if (wrong != prev) {
                vm.prank(account);
                vm.expectRevert(abi.encodeWithSelector(WoCoKeyRing.StaleRing.selector, prev));
                reg.setRing(wrong, rings[i]);
            }
            vm.prank(account);
            reg.setRing(prev, rings[i]);
            assertEq(reg.ringOf(account), rings[i]);
            prev = rings[i];
        }
    }
}
