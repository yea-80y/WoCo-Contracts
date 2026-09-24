// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {L1Resolver} from "../src/durin/L1Resolver.sol";
import {Lookup} from "../src/durin/interfaces/IAnswerModule.sol";
import {L1ResolverBase} from "./L1ResolverBase.sol";

/**
 * The built-in path: the WoCo gateway signs, this contract checks.
 *
 * Signed hash (audit 964 M-2 adds the chain id):
 *   keccak256(0x1900 ‖ address(this) ‖ uint256 chainid ‖ uint64 expires ‖
 *             keccak256(request) ‖ keccak256(result))
 * where `request` is the gateway's request (`callData`), never the wider
 * `extraData`. Each hash below is built here from first principles, so the
 * tests check the contract against the format, not against itself.
 */
contract L1ResolverSignedPathTest is L1ResolverBase {
    address nameOwner = makeAddr("nameOwner");
    address l2Registry = makeAddr("l2Registry");
    bytes constant RESULT = hex"000000000000000000000000ea1478b3818f3a06b83ceb7ec6f710a51115d879";

    bytes callData;
    bytes extraData;

    function setUp() public override {
        super.setUp();
        _configure(_own("woco.eth", nameOwner), nameOwner, _registrySettings(l2Registry));
        (bool ok, bytes memory ret) = _resolveRaw(_dns("nabil.woco.eth"), _addrQuery(_node("nabil.woco.eth")));
        assertFalse(ok);
        (,, callData,, extraData) = _decodeLookup(ret);
    }

    function _hash(address target, uint256 chainId, uint64 expires, bytes memory request, bytes memory result)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(hex"1900", target, chainId, expires, keccak256(request), keccak256(result)));
    }

    function _response(uint256 pk, bytes32 h, uint64 expires) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, h);
        return abi.encode(RESULT, expires, abi.encodePacked(r, s, v));
    }

    function test_Signed_AValidAnswerVerifies() public view {
        uint64 expires = uint64(block.timestamp + 600);
        bytes memory response =
            _response(gatewaySignerPk, _hash(address(resolver), block.chainid, expires, callData, RESULT), expires);
        assertEq(resolver.resolveWithProof(response, extraData), RESULT);
    }

    /// The same bytes on another chain recover to someone else.
    function test_Signed_TheChainIdIsBound() public {
        uint64 expires = uint64(block.timestamp + 600);
        bytes memory response =
            _response(gatewaySignerPk, _hash(address(resolver), block.chainid, expires, callData, RESULT), expires);
        vm.chainId(block.chainid + 1);
        vm.expectRevert(L1Resolver.InvalidSignature.selector);
        resolver.resolveWithProof(response, extraData);
    }

    /// The v1 preimage (no chain id, 94 bytes) never verifies on v2.
    function test_Signed_TheLegacyFormatIsRefused() public {
        uint64 expires = uint64(block.timestamp + 600);
        bytes32 legacy = keccak256(
            abi.encodePacked(hex"1900", address(resolver), expires, keccak256(callData), keccak256(RESULT))
        );
        vm.expectRevert(L1Resolver.InvalidSignature.selector);
        resolver.resolveWithProof(_response(gatewaySignerPk, legacy, expires), extraData);
    }

    /// Position and width of the chain id are part of the format.
    function test_Signed_TheChainIdIsAFullWordRightAfterTheTarget() public {
        uint64 expires = uint64(block.timestamp + 600);
        bytes32 narrow = keccak256(
            abi.encodePacked(
                hex"1900", address(resolver), uint64(block.chainid), expires, keccak256(callData), keccak256(RESULT)
            )
        );
        vm.expectRevert(L1Resolver.InvalidSignature.selector);
        resolver.resolveWithProof(_response(gatewaySignerPk, narrow, expires), extraData);

        bytes32 moved = keccak256(
            abi.encodePacked(hex"1900", address(resolver), expires, block.chainid, keccak256(callData), keccak256(RESULT))
        );
        vm.expectRevert(L1Resolver.InvalidSignature.selector);
        resolver.resolveWithProof(_response(gatewaySignerPk, moved, expires), extraData);
    }

    /// The gateway signs the request it received, not this contract's
    /// extraData layout.
    function test_Signed_OverTheRequestNotTheExtraData() public {
        uint64 expires = uint64(block.timestamp + 600);
        bytes memory response =
            _response(gatewaySignerPk, _hash(address(resolver), block.chainid, expires, extraData, RESULT), expires);
        vm.expectRevert(L1Resolver.InvalidSignature.selector);
        resolver.resolveWithProof(response, extraData);
    }

    function test_Signed_AnExpiredAnswerIsRefused() public {
        vm.warp(1_000_000);
        uint64 expires = uint64(block.timestamp - 1);
        bytes memory response =
            _response(gatewaySignerPk, _hash(address(resolver), block.chainid, expires, callData, RESULT), expires);
        vm.expectRevert("SignatureVerifier: Signature expired");
        resolver.resolveWithProof(response, extraData);

        // The last valid second still verifies.
        expires = uint64(block.timestamp);
        response =
            _response(gatewaySignerPk, _hash(address(resolver), block.chainid, expires, callData, RESULT), expires);
        assertEq(resolver.resolveWithProof(response, extraData), RESULT);
    }

    function test_Signed_AnotherKeyIsRefused() public {
        (, uint256 otherPk) = makeAddrAndKey("not-the-gateway");
        uint64 expires = uint64(block.timestamp + 600);
        bytes memory response =
            _response(otherPk, _hash(address(resolver), block.chainid, expires, callData, RESULT), expires);
        vm.expectRevert(L1Resolver.InvalidSignature.selector);
        resolver.resolveWithProof(response, extraData);
    }

    /// Rotation is the defence against a leaked key: outstanding answers die at once.
    function test_Signed_RotationInvalidatesOutstandingAnswers() public {
        uint64 expires = uint64(block.timestamp + 600);
        bytes memory response =
            _response(gatewaySignerPk, _hash(address(resolver), block.chainid, expires, callData, RESULT), expires);
        vm.prank(resolverOwner);
        resolver.setSigner(makeAddr("rotated"));
        vm.expectRevert(L1Resolver.InvalidSignature.selector);
        resolver.resolveWithProof(response, extraData);
    }

    /// The built-in path's extraData is (module 0, the query, the request).
    function test_Signed_ExtraDataCarriesModuleZeroAndTheRequest() public view {
        (address module,, bytes memory request) =
            abi.decode(extraData, (address, Lookup, bytes));
        assertEq(module, address(0));
        assertEq(request, callData);
    }
}

