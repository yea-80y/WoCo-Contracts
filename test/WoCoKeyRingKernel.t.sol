// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import {WoCoKeyRing} from "../src/WoCoKeyRing.sol";
import {WeightedRootKernelTest, IKernel31, IWeighted, Execution} from "./WeightedRootKernel.t.sol";

/// @notice The key ring moves in the SAME batch as the co-owner list (WoCo-Event-App #186), against the
///         Kernel v3.1 + WeightedECDSAValidator runtime bytecode captured from Arbitrum One (the harness
///         in WeightedRootKernel.t.sol, whose own tests run here too):
///
///         K1  removal = [renew(list without the passkey), setRing(prev, next)]: both land, and the
///             removed key no longer validates, so it can never move the ring again.
///         K2  a stale prev reverts the WHOLE batch: the passkey stays on the list and the ring stays put,
///             never "removed but keys unchanged" (the batch is sent with execType DEFAULT, not TRY).
///         K3  the first add = [changeRootValidator, uninstallValidation(ECDSA), setRing(0, first)].
contract WoCoKeyRingKernelTest is WeightedRootKernelTest {
    bytes32 constant R0 = keccak256("ring 0");
    bytes32 constant R1 = keccak256("ring 1");

    function _switchWithRing(WoCoKeyRing reg, address[] memory signers, bytes32 ring) internal {
        Execution[] memory calls = new Execution[](3);
        calls[0] = Execution(
            address(kernel),
            0,
            abi.encodeCall(IKernel31.changeRootValidator, (_vid(WEIGHTED), address(0), _enable(signers), hex""))
        );
        calls[1] = Execution(
            address(kernel), 0, abi.encodeCall(IKernel31.uninstallValidation, (_vid(ECDSA_VALIDATOR), hex"", hex""))
        );
        calls[2] = Execution(address(reg), 0, abi.encodeCall(WoCoKeyRing.setRing, (bytes32(0), ring)));
        vm.prank(ENTRYPOINT);
        kernel.execute(BATCH_MODE, abi.encode(calls));
    }

    function _renewWithRing(WoCoKeyRing reg, address[] memory signers, bytes32 prev, bytes32 next) internal {
        address[] memory s = _sortDesc(signers);
        uint24[] memory w = new uint24[](s.length);
        for (uint256 i; i < s.length; i++) w[i] = 1;
        Execution[] memory calls = new Execution[](2);
        calls[0] = Execution(WEIGHTED, 0, abi.encodeCall(IWeighted.renew, (s, w, 1, 0)));
        calls[1] = Execution(address(reg), 0, abi.encodeCall(WoCoKeyRing.setRing, (prev, next)));
        vm.prank(ENTRYPOINT);
        kernel.execute(BATCH_MODE, abi.encode(calls));
    }

    function test_K3_firstAdd_switchAndRingInOneBatch() public {
        WoCoKeyRing reg = new WoCoKeyRing();
        _switchWithRing(reg, _pair(A, B), R0);
        assertEq(kernel.rootValidator(), _vid(WEIGHTED));
        assertEq(reg.ringOf(address(kernel)), R0);
        assertTrue(_userOpValid(PK_A));
        assertTrue(_userOpValid(PK_B));
    }

    function test_K1_removalAndNewRing_landTogether() public {
        WoCoKeyRing reg = new WoCoKeyRing();
        _switchWithRing(reg, _three(A, B, C), R0);
        assertTrue(_userOpValid(PK_C));

        _renewWithRing(reg, _pair(A, B), R0, R1);
        assertEq(reg.ringOf(address(kernel)), R1);
        assertFalse(_userOpValid(PK_C));
        assertTrue(_userOpValid(PK_A));
        assertTrue(_userOpValid(PK_B));
    }

    function test_K2_staleRing_revertsTheRemovalToo() public {
        WoCoKeyRing reg = new WoCoKeyRing();
        _switchWithRing(reg, _three(A, B, C), R0);

        vm.expectRevert();
        this.renewWithRingExternal(reg, _pair(A, B), keccak256("stale"), R1);

        assertEq(reg.ringOf(address(kernel)), R0);
        assertTrue(_userOpValid(PK_C));
        (uint24 weightC,) = IWeighted(WEIGHTED).guardian(C, address(kernel));
        assertEq(weightC, 1);
    }

    /// External so `expectRevert` can wrap the prank + execute pair as one call.
    function renewWithRingExternal(WoCoKeyRing reg, address[] memory signers, bytes32 prev, bytes32 next) external {
        _renewWithRing(reg, signers, prev, next);
    }
}
