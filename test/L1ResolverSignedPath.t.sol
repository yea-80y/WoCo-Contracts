// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {L1Resolver} from "../src/durin/L1Resolver.sol";
import {Lookup} from "../src/durin/interfaces/IAnswerModule.sol";
import {L1ResolverBase} from "./L1ResolverBase.sol";
import {SignatureVerifier} from "../src/durin/lib/SignatureVerifier.sol";

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
        vm.expectRevert(abi.encodeWithSelector(SignatureVerifier.SignatureExpired.selector, expires));
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

    /// A vector the REAL gateway handler produced (woco_app
    /// `apps/server/src/lib/ens-gateway/ccip.ts` at 37fdcfd8, branch
    /// feat/ens-gateway-chain-bound; pinned in its own `ens-gateway.test.ts`):
    /// resolver 0x1111…1111 on chain 1, signer 0x7099…79C8, now 1_800_000_000,
    /// `nabil.woco.eth` addr on the v2.2 registry. Both repos carry these bytes
    /// by hand: a gateway change fails only the gateway test, so regenerate
    /// and re-pin BOTH whenever it does.
    address constant GOLDEN_TARGET = 0x1111111111111111111111111111111111111111;
    address constant GOLDEN_SIGNER = 0x70997970C51812dc3A010C7d01b50e0d17dc79C8;
    bytes constant GOLDEN_REQUEST =
        hex"21759430000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000a4b10000000000000000000000004c2265470e0134c0a2df6902ebcb5397a40102a80000000000000000000000000000000000000000000000000000000000000010056e6162696c04776f636f03657468000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000243b3b57dec8062a52e62f372f92d47336f9230c01106d562e2ff375c8ff5ae0a19e4b9eb900000000000000000000000000000000000000000000000000000000";
    bytes constant GOLDEN_RESULT = hex"000000000000000000000000ea1478b3818f3a06b83ceb7ec6f710a51115d879";
    bytes constant GOLDEN_RESPONSE =
        hex"0000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000006b49d45800000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000ea1478b3818f3a06b83ceb7ec6f710a51115d87900000000000000000000000000000000000000000000000000000000000000414c8548db5c48a5063537b3a02b86075ec75986bc945c64d236305bdcbdb4fab62bdbec2c48eaedebf07003b0265061a8ab2ce0141b748ac0727c4f8daaaa44981b00000000000000000000000000000000000000000000000000000000000000";

    function test_Signed_TheGatewaysOwnVectorVerifies() public {
        deployCodeTo(
            "L1Resolver.sol:L1Resolver",
            abi.encode(GATEWAY_URL, GOLDEN_SIGNER, resolverOwner, address(wrapper)),
            GOLDEN_TARGET
        );
        L1Resolver golden = L1Resolver(GOLDEN_TARGET);
        Lookup memory q; // the signature path never reads the query
        bytes memory extra = abi.encode(address(0), q, GOLDEN_REQUEST);

        vm.chainId(1);
        vm.warp(1_800_000_000);
        assertEq(golden.resolveWithProof(GOLDEN_RESPONSE, extra), GOLDEN_RESULT);

        vm.chainId(421614);
        vm.expectRevert(L1Resolver.InvalidSignature.selector);
        golden.resolveWithProof(GOLDEN_RESPONSE, extra);
    }

    /// The built-in path's extraData is (module 0, the query, the request).
    function test_Signed_ExtraDataCarriesModuleZeroAndTheRequest() public view {
        (address module,, bytes memory request) =
            abi.decode(extraData, (address, Lookup, bytes));
        assertEq(module, address(0));
        assertEq(request, callData);
    }
}

