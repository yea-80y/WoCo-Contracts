// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {NameEncoder} from "@ensdomains/ens-contracts/utils/NameEncoder.sol";
import {L1Resolver, INameWrapper} from "../src/durin/L1Resolver.sol";
import {Lookup} from "../src/durin/interfaces/IAnswerModule.sol";
import {IL1ResolverV1} from "./mocks/IL1ResolverV1.sol";

interface IENSRegistry {
    function resolver(bytes32 node) external view returns (address);
}

interface INameWrapperSetResolver {
    function setResolver(bytes32 node, address resolver) external;
    function ownerOf(uint256 id) external view returns (address);
}

interface IUniversalResolverFind {
    function findResolver(bytes calldata name) external view returns (address, bytes32, uint256);
}

/**
 * Rehearses the #23 swap on a fork of Ethereum mainnet: deploy L1Resolver v2 with
 * the live gateway URL and signer, the Safe as owner and the canonical
 * NameWrapper; the Safe pre-positions woco.eth's settings, then points woco.eth
 * at v2. What the world resolves must be unchanged - the apex record
 * (woco.eth.limo) byte for byte, and every subname's gateway request byte for
 * byte (only the resolver's own address changes). ENS's live UniversalResolver
 * must reach v2 with the node v2 itself derives, for a plain name and for its
 * `[labelhash]` form. Then roll back.
 *
 * Skipped unless MAINNET_RPC_URL is set (the public endpoint is enough; the fork
 * is near the tip). Run: MAINNET_RPC_URL=https://ethereum-rpc.publicnode.com \
 *   forge test --match-path test/L1ResolverV2Fork.t.sol -vv
 */
contract L1ResolverV2ForkTest is Test {
    IENSRegistry constant ENS = IENSRegistry(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);
    INameWrapperSetResolver constant NAME_WRAPPER = INameWrapperSetResolver(0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401);
    IUniversalResolverFind constant UNIVERSAL_RESOLVER =
        IUniversalResolverFind(0xED73a03F19e8D849E44a39252d222c6ad5217E1e);
    IL1ResolverV1 constant LIVE = IL1ResolverV1(0x172031E6a8428617B05F2002e0e278bb8fb3Ed8A);
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

    function _lookup(address r, bytes memory name, bytes memory data) internal view returns (bool ok, bytes memory ret) {
        (ok, ret) = r.staticcall(abi.encodeCall(L1Resolver.resolve, (name, data)));
    }

    // State carried between the rehearsal's steps (one function is too deep a stack).
    L1Resolver v2;
    L1Resolver.Settings settings;
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
        _checkTheUniversalResolverReachesV2();
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
        (apexOk, apexBefore) = _lookup(address(LIVE), wocoName, apexQuery);
        assertTrue(apexOk, "the live apex answers on L1");

        bytes32 subNode;
        (subName, subNode) = NameEncoder.dnsEncodeName("nabil.woco.eth");
        subQuery = abi.encodeWithSignature("addr(bytes32)", subNode);
        bool subOk;
        (subOk, subBefore) = _lookup(address(LIVE), subName, subQuery);
        assertFalse(subOk, "a subname goes offchain");
    }

    /// Deploy v2 exactly as the swap will, then the Safe's two transactions:
    /// settings first (so nothing resolves differently at the swap), then the swap.
    function _deployAndSwap() internal {
        v2 = new L1Resolver(LIVE.url(), LIVE.signer(), SAFE, INameWrapper(address(NAME_WRAPPER)));
        assertEq(v2.owner(), SAFE);
        assertEq(address(v2.nameWrapper()), address(NAME_WRAPPER));

        (uint64 l2Chain, address l2Registry) = LIVE.l2Registry(node);
        settings.chainId = l2Chain;
        settings.registry = l2Registry;
        settings.fallbackResolver = LIVE.fallbackResolver(node);

        vm.startPrank(SAFE);
        v2.configure(node, SAFE, settings);
        (bytes32 routedNode, address routedOwner, L1Resolver.Settings memory routed) = v2.routeFor(wocoName);
        assertEq(routedNode, node);
        assertEq(routedOwner, SAFE, "routeFor names the Safe before the swap");
        assertEq(routed.registry, l2Registry);
        NAME_WRAPPER.setResolver(node, address(v2));
        vm.stopPrank();
        assertEq(ENS.resolver(node), address(v2), "woco.eth now resolves through v2");
    }

    /// woco.eth.limo keeps serving the same site.
    function _checkApexUnchanged() internal view {
        (bool ok, bytes memory apexAfter) = _lookup(address(v2), wocoName, apexQuery);
        assertTrue(ok);
        assertEq(apexAfter, apexBefore, "apex contenthash unchanged");
    }

    /// The gateway receives the byte-identical request; only the sender and
    /// the (v2-only) extraData layout differ.
    function _checkSubnameLookupUnchanged() internal view {
        (bool ok, bytes memory subAfter) = _lookup(address(v2), subName, subQuery);
        assertFalse(ok);
        assertEq(bytes4(subAfter), L1Resolver.OffchainLookup.selector);
        (address senderBefore, string[] memory urlsBefore, bytes memory callBefore,,) = _decodeLookup(subBefore);
        (address senderAfter, string[] memory urlsAfter, bytes memory callAfter, bytes4 cbAfter, bytes memory extraAfter) =
            _decodeLookup(subAfter);
        assertEq(senderBefore, address(LIVE));
        assertEq(senderAfter, address(v2), "the gateway must now serve v2's address");
        assertEq(urlsAfter.length, 1);
        assertEq(urlsAfter[0], urlsBefore[0], "same gateway URL");
        assertEq(callAfter, callBefore, "same gateway request");
        assertEq(cbAfter, L1Resolver.resolveWithProof.selector);
        Lookup memory q = Lookup({
            name: subName,
            data: subQuery,
            chainId: settings.chainId,
            registry: settings.registry,
            moduleData: ""
        });
        assertEq(extraAfter, abi.encode(address(0), q, callAfter), "extraData = (module 0, query, request)");
    }

    /// ENS's own UniversalResolver reaches v2, and the node it derives is the
    /// one v2 routes on - for the plain name and for its `[labelhash]` form.
    function _checkTheUniversalResolverReachesV2() internal view {
        bytes memory bracketed =
            bytes.concat(_bracketLabel(keccak256("nabil")), hex"04", bytes("woco"), hex"03", bytes("eth"), hex"00");
        bytes[2] memory names = [subName, bracketed];
        for (uint256 i; i < 2; ++i) {
            (address found, bytes32 urNode,) = UNIVERSAL_RESOLVER.findResolver(names[i]);
            assertEq(found, address(v2), "the UniversalResolver does not reach v2");
            assertEq(urNode, vm.ensNamehash("nabil.woco.eth"), "the UniversalResolver derived another node");

            (bool ok, bytes memory ret) =
                _lookup(address(v2), names[i], abi.encodeWithSignature("addr(bytes32)", urNode));
            assertFalse(ok);
            (,, bytes memory callData,,) = _decodeLookup(ret);
            (,,, address registry) = abi.decode(_afterSelector(callData), (bytes, bytes, uint64, address));
            assertEq(registry, settings.registry, "v2 routed the name elsewhere");
        }
    }

    function _checkRenounceRefusedAndRollback() internal {
        vm.expectRevert(L1Resolver.RenounceDisabled.selector);
        vm.prank(SAFE);
        v2.renounceOwnership();

        // Rollback is one Safe transaction; v1's settings were never touched.
        vm.prank(SAFE);
        NAME_WRAPPER.setResolver(node, address(LIVE));
        assertEq(ENS.resolver(node), address(LIVE));
        (, bytes memory apexRolledBack) = _lookup(address(LIVE), wocoName, apexQuery);
        assertEq(apexRolledBack, apexBefore);
    }

    function _bracketLabel(bytes32 h) internal pure returns (bytes memory label) {
        bytes memory hexChars = bytes(vm.toString(h));
        label = new bytes(67);
        label[0] = bytes1(uint8(66));
        label[1] = "[";
        for (uint256 i; i < 64; ++i) label[2 + i] = hexChars[2 + i];
        label[66] = "]";
    }

    function _decodeLookup(bytes memory revertData)
        internal
        pure
        returns (address sender, string[] memory urls, bytes memory callData, bytes4 callback, bytes memory extraData)
    {
        (sender, urls, callData, callback, extraData) =
            abi.decode(_afterSelector(revertData), (address, string[], bytes, bytes4, bytes));
    }

    function _afterSelector(bytes memory b) internal pure returns (bytes memory out) {
        out = new bytes(b.length - 4);
        for (uint256 i; i < out.length; ++i) out[i] = b[i + 4];
    }
}
