// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {NameEncoder} from "@ensdomains/ens-contracts/utils/NameEncoder.sol";
import {L1Resolver} from "../src/durin/L1Resolver.sol";

interface IENSRegistry {
    function resolver(bytes32 node) external view returns (address);
}

interface INameWrapperSetResolver {
    function setResolver(bytes32 node, address resolver) external;
    function ownerOf(uint256 id) external view returns (address);
}

/**
 * Rehearses the #23 swap on a fork of Ethereum mainnet: deploy L1Resolver v2 with
 * the live gateway URL and signer, have the owner Safe configure it and point
 * woco.eth at it, and prove that what the world resolves is unchanged - the apex
 * record (woco.eth.limo) byte for byte, and every subname's OffchainLookup
 * except for the resolver's own address. Then roll back.
 *
 * Skipped unless MAINNET_RPC_URL is set (the public endpoint is enough; the fork
 * is near the tip). Run: MAINNET_RPC_URL=https://ethereum-rpc.publicnode.com \
 *   forge test --match-path test/L1ResolverV2Fork.t.sol -vv
 */
contract L1ResolverV2ForkTest is Test {
    IENSRegistry constant ENS = IENSRegistry(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);
    INameWrapperSetResolver constant NAME_WRAPPER = INameWrapperSetResolver(0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401);
    L1Resolver constant LIVE = L1Resolver(0x172031E6a8428617B05F2002e0e278bb8fb3Ed8A);
    address constant SAFE = 0xD26abFb5fBd37eFBD876e87cB169286eF0f14BA2;
    address constant L2_REGISTRY_V22 = 0x4c2265470e0134C0a2df6902ebcb5397a40102a8;
    uint64 constant ARBITRUM_ONE = 42161;

    bytes32 node;
    bytes wocoName;
    bool forked;

    function setUp() public {
        string memory rpc = vm.envOr("MAINNET_RPC_URL", string(""));
        if (bytes(rpc).length == 0) return;
        vm.createSelectFork(rpc);
        forked = true;
        (wocoName, node) = NameEncoder.dnsEncodeName("woco.eth");
    }

    function _lookup(L1Resolver r, bytes memory name, bytes memory data) internal view returns (bool ok, bytes memory ret) {
        (ok, ret) = address(r).staticcall(abi.encodeCall(L1Resolver.resolve, (name, data)));
    }

    // State carried between the rehearsal's steps (one function is too deep a stack).
    L1Resolver v2;
    bytes apexQuery;
    bytes apexBefore;
    bytes subName;
    bytes subQuery;
    bytes subBefore;

    function test_Fork_SwapKeepsWhatTheWorldResolves() public {
        if (!forked) {
            vm.skip(true);
            return;
        }
        _recordLiveState();
        _deployAndSwap();
        _checkApexUnchanged();
        _checkSubnameLookupUnchanged();
        _checkRenounceRefusedAndRollback();
    }

    function _recordLiveState() internal {
        assertEq(ENS.resolver(node), address(LIVE), "woco.eth resolves through the live L1Resolver");
        assertEq(NAME_WRAPPER.ownerOf(uint256(node)), SAFE, "the Safe holds woco.eth");
        assertEq(LIVE.owner(), SAFE);
        (uint64 l2Chain, address l2Registry) = LIVE.l2Registry(node);
        assertEq(l2Chain, ARBITRUM_ONE);
        assertEq(l2Registry, L2_REGISTRY_V22, "v2.2 registry since 2026-09-21");

        apexQuery = abi.encodeWithSignature("contenthash(bytes32)", node);
        bool apexOk;
        (apexOk, apexBefore) = _lookup(LIVE, wocoName, apexQuery);
        assertTrue(apexOk, "the live apex answers on L1");

        bytes32 subNode;
        (subName, subNode) = NameEncoder.dnsEncodeName("nabil.woco.eth");
        subQuery = abi.encodeWithSignature("addr(bytes32)", subNode);
        bool subOk;
        (subOk, subBefore) = _lookup(LIVE, subName, subQuery);
        assertFalse(subOk, "a subname goes offchain");
    }

    /// Deploy v2 exactly as the swap will (the live URL and signer, the Safe as
    /// owner), then the Safe's three transactions, in order.
    function _deployAndSwap() internal {
        v2 = new L1Resolver(LIVE.url(), LIVE.signer(), SAFE);
        assertEq(v2.owner(), SAFE);
        (uint64 l2Chain, address l2Registry) = LIVE.l2Registry(node);
        address fallbackResolver = LIVE.fallbackResolver(node);
        vm.startPrank(SAFE);
        v2.setL2Registry(node, l2Chain, l2Registry);
        v2.setFallbackResolver(node, fallbackResolver);
        NAME_WRAPPER.setResolver(node, address(v2));
        vm.stopPrank();
        assertEq(ENS.resolver(node), address(v2), "woco.eth now resolves through v2");
    }

    /// woco.eth.limo keeps serving the same site.
    function _checkApexUnchanged() internal view {
        (bool ok, bytes memory apexAfter) = _lookup(v2, wocoName, apexQuery);
        assertTrue(ok);
        assertEq(apexAfter, apexBefore, "apex contenthash unchanged");
    }

    /// A subname's OffchainLookup is identical except for the resolver address.
    function _checkSubnameLookupUnchanged() internal view {
        (bool ok, bytes memory subAfter) = _lookup(v2, subName, subQuery);
        assertFalse(ok);
        assertEq(bytes4(subAfter), L1Resolver.OffchainLookup.selector);
        (address senderBefore, string[] memory urlsBefore, bytes memory callBefore,,) = _decodeLookup(subBefore);
        (address senderAfter, string[] memory urlsAfter, bytes memory callAfter, bytes4 cbAfter,) = _decodeLookup(subAfter);
        assertEq(senderBefore, address(LIVE));
        assertEq(senderAfter, address(v2), "the gateway must now serve v2's address");
        assertEq(urlsAfter.length, 1);
        assertEq(urlsAfter[0], urlsBefore[0], "same gateway URL");
        assertEq(callAfter, callBefore, "same gateway request");
        assertEq(cbAfter, L1Resolver.resolveWithProof.selector);
    }

    function _checkRenounceRefusedAndRollback() internal {
        vm.expectRevert(L1Resolver.RenounceDisabled.selector);
        vm.prank(SAFE);
        v2.renounceOwnership();

        // Rollback is one Safe transaction.
        vm.prank(SAFE);
        NAME_WRAPPER.setResolver(node, address(LIVE));
        assertEq(ENS.resolver(node), address(LIVE));
        (, bytes memory apexRolledBack) = _lookup(LIVE, wocoName, apexQuery);
        assertEq(apexRolledBack, apexBefore);
    }

    function _decodeLookup(bytes memory revertData)
        internal
        pure
        returns (address sender, string[] memory urls, bytes memory callData, bytes4 callback, bytes memory extraData)
    {
        bytes memory body = new bytes(revertData.length - 4);
        for (uint256 i; i < body.length; ++i) body[i] = revertData[i + 4];
        (sender, urls, callData, callback, extraData) = abi.decode(body, (address, string[], bytes, bytes4, bytes));
    }
}
