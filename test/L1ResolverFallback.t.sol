// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {L1Resolver} from "../src/durin/L1Resolver.sol";
import {L1ResolverBase} from "./L1ResolverBase.sol";
import {MockPublicResolver, RevertingResolver} from "./mocks/L1Mocks.sol";

/**
 * The apex fallback (WoCo-Event-App #419), carried into v2 as a field of a
 * node's settings.
 *
 * Once `woco.eth` points at this contract, a query for `woco.eth` itself - the
 * WoCo app's own contenthash, served by eth.limo - would go to the gateway like
 * a subname and the app would go dark. The fallback keeps the apex answering
 * from L1. Two properties carry it, each with its own tests:
 *
 *   1. UNSET, the apex and every subname produce the built-in OffchainLookup,
 *      compared byte for byte with an expectation built independently.
 *   2. SET, only the name ITSELF is diverted. Subnames - the entire point of the
 *      registry - still go offchain, byte-identically.
 */
contract L1ResolverFallbackTest is L1ResolverBase {
    MockPublicResolver publicResolver;
    address l2Registry = makeAddr("l2Registry");
    address nameOwner = makeAddr("nameOwner");

    bytes32 wocoNode;
    bytes wocoName;

    /// The live apex record: `e40101fa011b20` + the frontend feed manifest ref.
    bytes constant APEX_CONTENTHASH =
        hex"e40101fa011b20d66c6ff7650a468c2fd98439c8f04547b5b8a4b933d349ff16db1d0b00c23adc";

    function setUp() public override {
        super.setUp();
        wocoName = _dns("woco.eth");
        wocoNode = _own("woco.eth", nameOwner);
        _configure(wocoNode, nameOwner, _registrySettings(l2Registry));

        publicResolver = new MockPublicResolver();
        publicResolver.setContenthash(wocoNode, APEX_CONTENTHASH);
    }

    /*//////////////////////////////////////////////////////////////
                      1. UNSET => BUILT-IN LOOKUPS
    //////////////////////////////////////////////////////////////*/

    /// With no fallback the apex goes offchain - precisely what takes the app
    /// down, and why the opt-in exists.
    function test_Unset_ApexProducesTheBuiltInLookup() public {
        bytes memory data = abi.encodeWithSignature("contenthash(bytes32)", wocoNode);
        vm.expectRevert(_expectedBuiltInLookup(wocoName, data, _registrySettings(l2Registry)));
        resolver.resolve(wocoName, data);
    }

    function test_Unset_SubnameProducesTheBuiltInLookup() public {
        bytes memory name = _dns("venue.woco.eth");
        bytes memory data = _addrQuery(_node("venue.woco.eth"));
        vm.expectRevert(_expectedBuiltInLookup(name, data, _registrySettings(l2Registry)));
        resolver.resolve(name, data);
    }

    function test_Unset_DeepSubnameProducesTheBuiltInLookup() public {
        bytes memory name = _dns("shop.venue.woco.eth");
        bytes memory data = _addrQuery(_node("shop.venue.woco.eth"));
        vm.expectRevert(_expectedBuiltInLookup(name, data, _registrySettings(l2Registry)));
        resolver.resolve(name, data);
    }

    /*//////////////////////////////////////////////////////////////
                  2. SET => ONLY THE NAME ITSELF IS DIVERTED
    //////////////////////////////////////////////////////////////*/

    function test_Set_ApexAnswersFromL1WithoutTouchingTheGateway() public {
        _setFallback(address(publicResolver));
        bytes memory data = abi.encodeWithSignature("contenthash(bytes32)", wocoNode);
        bytes memory result = resolver.resolve(wocoName, data);
        assertEq(abi.decode(result, (bytes)), APEX_CONTENTHASH, "apex did not answer from L1");
    }

    /// The property everything else rests on. A fallback that also caught
    /// subnames would silently disable the whole registry while the apex kept
    /// working - i.e. it would look fine.
    function test_Set_SubnamesStillGoOffchainUnchanged() public {
        L1Resolver.Settings memory s = _setFallback(address(publicResolver));
        bytes memory name = _dns("venue.woco.eth");
        bytes memory data = _addrQuery(_node("venue.woco.eth"));
        vm.expectRevert(_expectedBuiltInLookup(name, data, s));
        resolver.resolve(name, data);
    }

    function test_Set_DeepSubnamesStillGoOffchainUnchanged() public {
        L1Resolver.Settings memory s = _setFallback(address(publicResolver));
        bytes memory name = _dns("shop.venue.woco.eth");
        bytes memory data = _addrQuery(_node("shop.venue.woco.eth"));
        vm.expectRevert(_expectedBuiltInLookup(name, data, s));
        resolver.resolve(name, data);
    }

    /// Keyed per name: one parent opting in does not answer for another.
    function test_Set_IsScopedToItsOwnName() public {
        bytes32 other = _own("other.eth", nameOwner);
        _configure(other, nameOwner, _fallbackSettings(address(publicResolver)));

        bytes memory data = abi.encodeWithSignature("contenthash(bytes32)", wocoNode);
        vm.expectRevert(_expectedBuiltInLookup(wocoName, data, _registrySettings(l2Registry)));
        resolver.resolve(wocoName, data);
    }

    /// Any record type passes through: the Public Resolver keeps its storage
    /// across a `setResolver`, so whatever is there must keep answering.
    function test_Set_PassesThroughOtherRecordTypes() public {
        publicResolver.setText(wocoNode, "url", "https://woco-net.com");
        _setFallback(address(publicResolver));
        bytes memory data = abi.encodeWithSignature("text(bytes32,string)", wocoNode, "url");
        assertEq(abi.decode(resolver.resolve(wocoName, data), (string)), "https://woco-net.com");
    }

    /// Unsetting is the rollback path and must restore the built-in lookup exactly.
    function test_Set_CanBeUnsetAndTheBuiltInLookupReturns() public {
        _setFallback(address(publicResolver));
        _setFallback(address(0));
        bytes memory data = abi.encodeWithSignature("contenthash(bytes32)", wocoNode);
        vm.expectRevert(_expectedBuiltInLookup(wocoName, data, _registrySettings(l2Registry)));
        resolver.resolve(wocoName, data);
    }

    /// Swallowing a failure into empty bytes would report "no contenthash" -
    /// for the apex, the app vanishing with no error anywhere.
    function test_Set_FallbackRevertIsBubbledNotSwallowed() public {
        _setFallback(address(new RevertingResolver()));
        vm.expectRevert(RevertingResolver.Nope.selector);
        resolver.resolve(wocoName, abi.encodeWithSignature("contenthash(bytes32)", wocoNode));
    }

    /// A fallback with no registry says "nothing beneath me is served here".
    function test_FallbackOnly_ServesTheApexAndRefusesSubnames() public {
        _configure(wocoNode, nameOwner, _fallbackSettings(address(publicResolver)));

        bytes memory apex = resolver.resolve(wocoName, abi.encodeWithSignature("contenthash(bytes32)", wocoNode));
        assertEq(abi.decode(apex, (bytes)), APEX_CONTENTHASH);

        vm.expectRevert(abi.encodeWithSelector(L1Resolver.NotServed.selector, wocoNode));
        resolver.resolve(_dns("venue.woco.eth"), _addrQuery(_node("venue.woco.eth")));
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _setFallback(address r) internal returns (L1Resolver.Settings memory s) {
        s = _registrySettings(l2Registry);
        s.fallbackResolver = r;
        _configure(wocoNode, nameOwner, s);
    }
}
