// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {NameEncoder} from "@ensdomains/ens-contracts/utils/NameEncoder.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {L1Resolver} from "../src/durin/L1Resolver.sol";
import {MockENS, MockAddrResolver, MockNameWrapper} from "./mocks/L1Mocks.sol";

/**
 * The two L1Resolver v2 changes (WoCo-Contracts #23, audit 926):
 *   1. ownership cannot be renounced, and moves only in two steps;
 *   2. a one-label or root name reverts `UnsupportedName`, not an underflow panic.
 * Everything else, including the signed-answer checks, is upstream and covered by
 * L1ResolverFallback.t.sol unchanged.
 */
contract L1ResolverV2Test is Test {
    address constant ENS_ADDRESS = 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e;
    bytes32 constant WRAPPER_NODE = 0xdee478ba2734e34d81c6adc77a32d75b29007895efa2fe60921f1c315e1ec7d9;
    string constant GATEWAY_URL = "https://events-api.woco-net.com/api/ens-gateway/v1/{sender}/{data}";

    L1Resolver resolver;
    address owner = makeAddr("resolverOwner");
    address newOwner = makeAddr("newOwner");
    address stranger = makeAddr("stranger");
    address gatewaySigner = makeAddr("gatewaySigner");

    function setUp() public {
        vm.etch(ENS_ADDRESS, address(new MockENS()).code);
        MockENS ens = MockENS(ENS_ADDRESS);
        ens.setResolver(WRAPPER_NODE, address(new MockAddrResolver(address(new MockNameWrapper()))));
        resolver = new L1Resolver(GATEWAY_URL, gatewaySigner, owner);
    }

    // ── 1. renounce and the two-step handover ────────────────────────────────

    function test_Renounce_AlwaysReverts() public {
        vm.expectRevert(L1Resolver.RenounceDisabled.selector);
        vm.prank(owner);
        resolver.renounceOwnership();

        vm.expectRevert(L1Resolver.RenounceDisabled.selector);
        vm.prank(stranger);
        resolver.renounceOwnership();

        assertEq(resolver.owner(), owner, "the owner survives every renounce attempt");
    }

    /// The selector a Safe transaction builder pre-filled on 2026-09-21.
    function test_Renounce_IsTheSelectorTheSafeBuilderPrefills() public pure {
        assertEq(L1Resolver.renounceOwnership.selector, bytes4(0x715018a6));
    }

    function test_Transfer_TakesEffectOnlyWhenTheNewOwnerAccepts() public {
        vm.prank(owner);
        resolver.transferOwnership(newOwner);
        assertEq(resolver.owner(), owner, "a proposal moves nothing");
        assertEq(resolver.pendingOwner(), newOwner);

        // Still the old owner's contract until the accept.
        vm.prank(owner);
        resolver.setURL("https://old-owner-still-in-charge.example");

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        vm.prank(stranger);
        resolver.acceptOwnership();

        vm.prank(newOwner);
        resolver.acceptOwnership();
        assertEq(resolver.owner(), newOwner);
        assertEq(resolver.pendingOwner(), address(0));

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, owner));
        vm.prank(owner);
        resolver.setSigner(stranger);

        vm.prank(newOwner);
        resolver.setSigner(stranger);
        assertEq(resolver.signer(), stranger);
    }

    /// A proposal to a mistyped address can be replaced before anyone accepts.
    function test_Transfer_AProposalCanBeReplaced() public {
        vm.prank(owner);
        resolver.transferOwnership(stranger);
        vm.prank(owner);
        resolver.transferOwnership(newOwner);
        assertEq(resolver.pendingOwner(), newOwner);

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        vm.prank(stranger);
        resolver.acceptOwnership();
    }

    // ── 2. one-label and root names ──────────────────────────────────────────

    function test_Resolve_OneLabelNameRevertsUnsupportedName() public {
        (bytes memory eth,) = NameEncoder.dnsEncodeName("eth");
        vm.expectRevert(L1Resolver.UnsupportedName.selector);
        resolver.resolve(eth, abi.encodeWithSignature("addr(bytes32)", bytes32(0)));
    }

    function test_Resolve_RootNameRevertsUnsupportedName() public {
        vm.expectRevert(L1Resolver.UnsupportedName.selector);
        resolver.resolve(hex"00", abi.encodeWithSignature("addr(bytes32)", bytes32(0)));
    }
}
