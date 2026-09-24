// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {L1Resolver} from "../src/durin/L1Resolver.sol";
import {Lookup} from "../src/durin/interfaces/IAnswerModule.sol";
import {L1ResolverBase} from "./L1ResolverBase.sol";
import {MockPublicResolver} from "./mocks/L1Mocks.sol";
import {TaggingModule, SyncModule, NotAModule} from "./mocks/AnswerModuleMocks.sol";

/**
 * Answer modules: a name owner's own way to answer (a proof verifier, their own
 * signer, an onchain source), and the `owner()`-set default that lets every
 * name that has not chosen one move off the WoCo signer without a redeploy.
 *
 * The binding property: the callback judges an answer with the module named in
 * `extraData`, never one read from storage at callback time, so an answer
 * judged by one module can never be judged by another.
 */
contract L1ResolverModulesTest is L1ResolverBase {
    address alice = makeAddr("alice");
    address registryA = makeAddr("registryA");

    TaggingModule m1;
    TaggingModule m2;
    bytes32 venue;
    bytes name;
    bytes data;

    function setUp() public override {
        super.setUp();
        m1 = new TaggingModule(keccak256("m1"));
        m2 = new TaggingModule(keccak256("m2"));
        venue = _own("venue.eth", alice);
        name = _dns("x.venue.eth");
        data = _addrQuery(_node("x.venue.eth"));
    }

    function _withModule(address module, bytes memory moduleData) internal returns (L1Resolver.Settings memory s) {
        s = _registrySettings(registryA);
        s.module = module;
        s.moduleData = moduleData;
        _configure(venue, alice, s);
    }

    function _lookupOf() internal view returns (string[] memory urls, bytes memory callData, bytes memory extraData) {
        (bool ok, bytes memory ret) = _resolveRaw(name, data);
        assertFalse(ok, "expected an OffchainLookup");
        address sender;
        bytes4 callback;
        (sender, urls, callData, callback, extraData) = _decodeLookup(ret);
        assertEq(sender, address(resolver), "sender must be the resolver, never the module");
        assertEq(callback, L1Resolver.resolveWithProof.selector);
    }

    function _query(L1Resolver.Settings memory s) internal view returns (Lookup memory) {
        return Lookup({name: name, data: data, chainId: s.chainId, registry: s.registry, moduleData: s.moduleData});
    }

    /*//////////////////////////////////////////////////////////////
                           PER-NAME MODULE
    //////////////////////////////////////////////////////////////*/

    function test_Module_ShapesTheLookupAndJudgesTheAnswer() public {
        L1Resolver.Settings memory s = _withModule(address(m1), hex"c0ffee");
        Lookup memory q = _query(s);
        (string[] memory wantUrls, bytes memory wantCall) = m1.prepare(q);

        (string[] memory urls, bytes memory callData, bytes memory extraData) = _lookupOf();
        assertEq(urls.length, 1);
        assertEq(urls[0], wantUrls[0], "the module's URLs");
        assertEq(callData, wantCall, "the module's request");
        assertEq(extraData, abi.encode(address(m1), q, callData), "one fixed extraData layout");

        bytes memory answer = resolver.resolveWithProof(abi.encode(m1.tag(), "ok"), extraData);
        assertEq(answer, abi.encode(m1.tag(), bytes(hex"c0ffee")), "moduleData must reach verify untouched");
    }

    function test_Module_ARejectionBubbles() public {
        _withModule(address(m1), "");
        (,, bytes memory extraData) = _lookupOf();
        bytes memory wrongResponse = abi.encode(m2.tag(), "ok");
        vm.expectRevert(TaggingModule.Rejected.selector);
        resolver.resolveWithProof(wrongResponse, extraData);
    }

    /// An answer prepared under m1, presented with extraData naming m2, is
    /// judged by m2 - which refuses it.
    function test_Module_TheCallbackUsesTheModuleNamedInExtraData() public {
        _withModule(address(m1), "");
        (,, bytes memory extraData) = _lookupOf();
        (, Lookup memory q, bytes memory callData) = abi.decode(extraData, (address, Lookup, bytes));

        bytes memory m1Response = abi.encode(m1.tag(), "ok");
        vm.expectRevert(TaggingModule.WrongCallData.selector);
        resolver.resolveWithProof(m1Response, abi.encode(address(m2), q, callData));

        // The same request routed to the signature path is judged as a signature.
        (, uint256 otherPk) = makeAddrAndKey("not-the-gateway");
        bytes memory result = hex"1234";
        uint64 expires = uint64(block.timestamp + 60);
        bytes32 h = keccak256(
            abi.encodePacked(hex"1900", address(resolver), block.chainid, expires, keccak256(callData), keccak256(result))
        );
        (uint8 v, bytes32 r, bytes32 sv) = vm.sign(otherPk, h);
        vm.expectRevert(L1Resolver.InvalidSignature.selector);
        resolver.resolveWithProof(abi.encode(result, expires, abi.encodePacked(r, sv, v)), abi.encode(address(0), q, callData));
    }

    /// Changing the default between lookup and callback cannot re-route an
    /// answer already in flight: the module comes from extraData.
    function test_Module_TheDefaultIsNotReadAtCallbackTime() public {
        _configure(venue, alice, _registrySettings(registryA));
        vm.prank(resolverOwner);
        resolver.setDefaultModule(address(m1));
        (,, bytes memory extraData) = _lookupOf();

        vm.prank(resolverOwner);
        resolver.setDefaultModule(address(m2));
        bytes memory answer = resolver.resolveWithProof(abi.encode(m1.tag(), "ok"), extraData);
        assertEq(answer, abi.encode(m1.tag(), bytes("")));
    }

    function test_Module_ASyncModuleAnswersOnchain() public {
        _withModule(address(new SyncModule()), "");
        assertEq(resolver.resolve(name, data), abi.encode("onchain", data));
    }

    function test_Module_SetTimeChecks() public {
        address eoa = makeAddr("eoa");
        address notAModule = address(new NotAModule());
        L1Resolver.Settings memory s = _registrySettings(registryA);

        s.module = eoa;
        vm.expectRevert(abi.encodeWithSelector(L1Resolver.ModuleNotSupported.selector, eoa));
        vm.prank(alice);
        resolver.configure(venue, alice, s);

        s.module = notAModule;
        vm.expectRevert(abi.encodeWithSelector(L1Resolver.ModuleNotSupported.selector, notAModule));
        vm.prank(alice);
        resolver.configure(venue, alice, s);

        vm.startPrank(resolverOwner);
        vm.expectRevert(abi.encodeWithSelector(L1Resolver.ModuleNotSupported.selector, eoa));
        resolver.setDefaultModule(eoa);
        vm.expectRevert(abi.encodeWithSelector(L1Resolver.ModuleNotSupported.selector, notAModule));
        resolver.setDefaultModule(notAModule);
        vm.stopPrank();
    }

    /*//////////////////////////////////////////////////////////////
                            DEFAULT MODULE
    //////////////////////////////////////////////////////////////*/

    function test_DefaultModule_MovesEveryNameThatHasNotChosen() public {
        L1Resolver.Settings memory s = _registrySettings(registryA);
        _configure(venue, alice, s);

        // Unset: the built-in path, byte for byte.
        vm.expectRevert(_expectedBuiltInLookup(name, data, s));
        resolver.resolve(name, data);

        vm.expectEmit(false, false, false, true, address(resolver));
        emit L1Resolver.DefaultModuleChanged(address(m1));
        vm.prank(resolverOwner);
        resolver.setDefaultModule(address(m1));
        (, bytes memory callData, bytes memory extraData) = _lookupOf();
        (, bytes memory wantCall) = m1.prepare(_query(s));
        assertEq(callData, wantCall, "the default module answers");
        assertEq(extraData, abi.encode(address(m1), _query(s), callData));

        // Back to zero restores the built-in path.
        vm.prank(resolverOwner);
        resolver.setDefaultModule(address(0));
        vm.expectRevert(_expectedBuiltInLookup(name, data, s));
        resolver.resolve(name, data);
    }

    /// A name owner's own module is outside the default's reach.
    function test_DefaultModule_APerNameModuleWins() public {
        L1Resolver.Settings memory s = _withModule(address(m2), "");
        vm.prank(resolverOwner);
        resolver.setDefaultModule(address(m1));

        (, bytes memory callData,) = _lookupOf();
        (, bytes memory wantCall) = m2.prepare(_query(s));
        assertEq(callData, wantCall, "the default overrode the owner's choice");
    }

    /// A fallback-only node serves nothing beneath it, default or not.
    function test_DefaultModule_DoesNotServeBeneathAFallbackOnlyNode() public {
        _configure(venue, alice, _fallbackSettings(address(new MockPublicResolver())));
        vm.prank(resolverOwner);
        resolver.setDefaultModule(address(m1));

        vm.expectRevert(abi.encodeWithSelector(L1Resolver.NotServed.selector, venue));
        resolver.resolve(name, data);
    }

    /// A per-name module with no registry still serves beneath the node.
    function test_Module_WorksWithoutARegistry() public {
        L1Resolver.Settings memory s;
        s.module = address(m1);
        _configure(venue, alice, s);
        (, bytes memory callData,) = _lookupOf();
        (, bytes memory wantCall) = m1.prepare(_query(s));
        assertEq(callData, wantCall);
    }
}
