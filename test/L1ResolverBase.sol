// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {NameEncoder} from "@ensdomains/ens-contracts/utils/NameEncoder.sol";
import {L1Resolver, INameWrapper, IResolverService} from "../src/durin/L1Resolver.sol";
import {Lookup} from "../src/durin/interfaces/IAnswerModule.sol";
import {MockENS, MockNameWrapper} from "./mocks/L1Mocks.sol";

/// @dev Exposes the label walk so tests can compare it with ENS's own hashing.
contract L1ResolverHarness is L1Resolver {
    constructor(string memory url_, address signer_, address owner_, INameWrapper wrapper_)
        L1Resolver(url_, signer_, owner_, wrapper_)
    {}

    function suffixNodes(bytes calldata name) external pure returns (bytes32[] memory) {
        return _suffixNodes(name);
    }
}

/// @dev A contract that owns names and makes arbitrary calls - the shape of a Safe.
contract Executor {
    function exec(address target, bytes calldata data) external returns (bytes memory) {
        (bool ok, bytes memory ret) = target.call(data);
        if (!ok) {
            assembly {
                revert(add(ret, 0x20), mload(ret))
            }
        }
        return ret;
    }
}

/// Shared setup for the L1Resolver v2 suite: a mock ENS registry etched at the
/// canonical address, a mock NameWrapper, and helpers that build names, own
/// them and read back where a query was routed.
abstract contract L1ResolverBase is Test {
    address constant ENS_ADDRESS = 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e;
    string constant GATEWAY_URL = "https://events-api.woco-net.com/api/ens-gateway/v1/{sender}/{data}";
    uint64 constant ARBITRUM_ONE = 42161;

    MockENS ens;
    MockNameWrapper wrapper;
    L1ResolverHarness resolver;

    address resolverOwner = makeAddr("resolverOwner");
    address gatewaySigner;
    uint256 gatewaySignerPk;

    function setUp() public virtual {
        vm.etch(ENS_ADDRESS, address(new MockENS()).code);
        ens = MockENS(ENS_ADDRESS);
        wrapper = new MockNameWrapper();
        (gatewaySigner, gatewaySignerPk) = makeAddrAndKey("gatewaySigner");
        resolver = new L1ResolverHarness(GATEWAY_URL, gatewaySigner, resolverOwner, INameWrapper(address(wrapper)));
    }

    /*//////////////////////////////////////////////////////////////
                            NAMES AND OWNERS
    //////////////////////////////////////////////////////////////*/

    function _dns(string memory name) internal pure returns (bytes memory dnsName) {
        (dnsName,) = NameEncoder.dnsEncodeName(name);
    }

    function _node(string memory name) internal pure returns (bytes32 node) {
        (, node) = NameEncoder.dnsEncodeName(name);
    }

    function _own(string memory name, address who) internal returns (bytes32 node) {
        node = _node(name);
        ens.setOwner(node, who);
    }

    function _ownWrapped(string memory name, address who) internal returns (bytes32 node) {
        node = _node(name);
        ens.setOwner(node, address(wrapper));
        wrapper.setOwner(uint256(node), who);
    }

    /*//////////////////////////////////////////////////////////////
                               SETTINGS
    //////////////////////////////////////////////////////////////*/

    function _registrySettings(address registry) internal pure returns (L1Resolver.Settings memory s) {
        s.chainId = ARBITRUM_ONE;
        s.registry = registry;
    }

    function _fallbackSettings(address fallbackResolver) internal pure returns (L1Resolver.Settings memory s) {
        s.fallbackResolver = fallbackResolver;
    }

    function _configure(bytes32 node, address who, L1Resolver.Settings memory s) internal {
        vm.prank(who);
        resolver.configure(node, who, s);
    }

    /*//////////////////////////////////////////////////////////////
                         READING A LOOKUP BACK
    //////////////////////////////////////////////////////////////*/

    function _addrQuery(bytes32 node) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("addr(bytes32)", node);
    }

    /// @dev `resolve()` as a raw call, so a test can inspect either outcome.
    function _resolveRaw(bytes memory name, bytes memory data) internal view returns (bool ok, bytes memory ret) {
        (ok, ret) = address(resolver).staticcall(abi.encodeCall(L1Resolver.resolve, (name, data)));
    }

    function _decodeLookup(bytes memory revertData)
        internal
        pure
        returns (address sender, string[] memory urls, bytes memory callData, bytes4 callback, bytes memory extraData)
    {
        assertEq(bytes4(revertData), L1Resolver.OffchainLookup.selector, "not an OffchainLookup");
        (sender, urls, callData, callback, extraData) =
            abi.decode(_afterSelector(revertData), (address, string[], bytes, bytes4, bytes));
    }

    /// @dev The L2 chain and registry the built-in path sent `name` to.
    function _routedTo(string memory name) internal view returns (uint64 chainId, address registry) {
        (bool ok, bytes memory ret) = _resolveRaw(_dns(name), _addrQuery(_node(name)));
        assertFalse(ok, string.concat(name, ": expected an OffchainLookup"));
        (,, bytes memory callData,,) = _decodeLookup(ret);
        (,, chainId, registry) = abi.decode(_afterSelector(callData), (bytes, bytes, uint64, address));
    }

    /// @dev Upstream's OffchainLookup for the built-in path, rebuilt from first
    ///      principles: the gateway request is byte-identical to v1's, and
    ///      `extraData` is (module 0, the query, that request).
    function _expectedBuiltInLookup(bytes memory name, bytes memory data, L1Resolver.Settings memory s)
        internal
        view
        returns (bytes memory)
    {
        bytes memory callData = abi.encodeWithSelector(
            IResolverService.stuffedResolveCall.selector, name, data, s.chainId, s.registry
        );
        string[] memory urls = new string[](1);
        urls[0] = GATEWAY_URL;
        Lookup memory q =
            Lookup({name: name, data: data, chainId: s.chainId, registry: s.registry, moduleData: s.moduleData});
        return abi.encodeWithSelector(
            L1Resolver.OffchainLookup.selector,
            address(resolver),
            urls,
            callData,
            L1Resolver.resolveWithProof.selector,
            abi.encode(address(0), q, callData)
        );
    }

    function _afterSelector(bytes memory b) internal pure returns (bytes memory out) {
        out = new bytes(b.length - 4);
        for (uint256 i; i < out.length; ++i) {
            out[i] = b[i + 4];
        }
    }
}
