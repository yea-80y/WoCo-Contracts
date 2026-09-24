// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {BytesUtils} from "@ensdomains/ens-contracts/utils/BytesUtils.sol";
import {IExtendedResolver} from "@ensdomains/ens-contracts/resolvers/profiles/IExtendedResolver.sol";
import {L1Resolver, INameWrapper} from "../src/durin/L1Resolver.sol";
import {L1ResolverBase, Executor} from "./L1ResolverBase.sol";
import {MockPublicResolver} from "./mocks/L1Mocks.sol";

/**
 * L1Resolver v2 (audit 964, #23): the resolver other owners' names point at.
 *
 *   A. ownership: Ownable2Step, renounce always reverts, a fixed NameWrapper;
 *   B. the walk: names read label by label, the DEEPEST configured ancestor
 *      routes, nothing configured never goes offchain (M-1, L-2);
 *   C. settings follow the current owner (H-1), written into the writer's own
 *      slot or by the operator ENS itself would accept;
 *   D. the views an operator checks a setup with.
 * The fallback, the signed path and answer modules have their own files.
 */
contract L1ResolverV2Test is L1ResolverBase {
    address newOwner = makeAddr("newOwner");
    address stranger = makeAddr("stranger");
    address alice = makeAddr("alice");
    address bob = makeAddr("bob");
    address carol = makeAddr("carol");

    address registryA = makeAddr("registryA");
    address registryB = makeAddr("registryB");
    address registryC = makeAddr("registryC");

    /*//////////////////////////////////////////////////////////////
                              A. OWNERSHIP
    //////////////////////////////////////////////////////////////*/

    function test_Constructor_SetsEverything() public view {
        assertEq(resolver.url(), GATEWAY_URL);
        assertEq(resolver.signer(), gatewaySigner);
        assertEq(resolver.owner(), resolverOwner);
        assertEq(address(resolver.nameWrapper()), address(wrapper));
        assertEq(resolver.defaultModule(), address(0));
    }

    /// The wrapper is immutable, so a typo there could never be fixed.
    function test_Constructor_RefusesACodelessNameWrapper() public {
        vm.expectRevert(L1Resolver.NameWrapperHasNoCode.selector);
        new L1Resolver(GATEWAY_URL, gatewaySigner, resolverOwner, INameWrapper(makeAddr("not-a-wrapper")));

        vm.expectRevert(L1Resolver.NameWrapperHasNoCode.selector);
        new L1Resolver(GATEWAY_URL, gatewaySigner, resolverOwner, INameWrapper(address(0)));
    }

    function test_Renounce_AlwaysReverts() public {
        vm.expectRevert(L1Resolver.RenounceDisabled.selector);
        vm.prank(resolverOwner);
        resolver.renounceOwnership();

        vm.expectRevert(L1Resolver.RenounceDisabled.selector);
        vm.prank(stranger);
        resolver.renounceOwnership();

        assertEq(resolver.owner(), resolverOwner, "ownership moved");
    }

    /// The selector a Safe transaction builder pre-filled on 2026-09-21.
    function test_Renounce_IsTheSelectorTheSafeBuilderPrefills() public pure {
        assertEq(L1Resolver.renounceOwnership.selector, bytes4(0x715018a6));
    }

    function test_Transfer_TakesEffectOnlyWhenTheNewOwnerAccepts() public {
        vm.prank(resolverOwner);
        resolver.transferOwnership(newOwner);
        assertEq(resolver.owner(), resolverOwner, "moved before acceptance");
        assertEq(resolver.pendingOwner(), newOwner);

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        vm.prank(stranger);
        resolver.acceptOwnership();

        vm.prank(newOwner);
        resolver.acceptOwnership();
        assertEq(resolver.owner(), newOwner);
        assertEq(resolver.pendingOwner(), address(0));

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, resolverOwner));
        vm.prank(resolverOwner);
        resolver.setSigner(stranger);
    }

    function test_Transfer_AProposalCanBeReplaced() public {
        vm.startPrank(resolverOwner);
        resolver.transferOwnership(stranger);
        resolver.transferOwnership(newOwner);
        vm.stopPrank();

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        vm.prank(stranger);
        resolver.acceptOwnership();
    }

    /// Proposing the zero address cancels a handover; nobody can accept it.
    function test_Transfer_CanBeCancelledWithTheZeroAddress() public {
        vm.startPrank(resolverOwner);
        resolver.transferOwnership(newOwner);
        resolver.transferOwnership(address(0));
        vm.stopPrank();
        assertEq(resolver.pendingOwner(), address(0));

        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, newOwner));
        vm.prank(newOwner);
        resolver.acceptOwnership();
        assertEq(resolver.owner(), resolverOwner);
    }

    function test_AdminSetters_AreOwnerOnly() public {
        vm.startPrank(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        resolver.setURL("https://elsewhere/{sender}/{data}");
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        resolver.setSigner(stranger);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, stranger));
        resolver.setDefaultModule(address(0));
        vm.stopPrank();
    }

    /// The UniversalResolver calls `supportsInterface` with 50k gas.
    function test_SupportsInterface_ExtendedResolverAndERC165Cheaply() public view {
        uint256 before = gasleft();
        bool ext = resolver.supportsInterface(type(IExtendedResolver).interfaceId);
        assertLt(before - gasleft(), 50_000);
        assertTrue(ext);
        assertTrue(resolver.supportsInterface(0x01ffc9a7));
        assertFalse(resolver.supportsInterface(0xffffffff));
    }

    /*//////////////////////////////////////////////////////////////
                               B. THE WALK
    //////////////////////////////////////////////////////////////*/

    function test_Walk_HonestNamesRouteToTheConfiguredNode() public {
        bytes32 venue = _own("venue.eth", alice);
        _configure(venue, alice, _registrySettings(registryA));
        bytes32 venueUk = _own("venue.co.uk", bob);
        _configure(venueUk, bob, _registrySettings(registryB));

        (, address r1) = _routedTo("sub.venue.eth");
        (, address r2) = _routedTo("a.b.c.venue.eth");
        (uint64 chain, address r3) = _routedTo("x.venue.co.uk");
        assertEq(r1, registryA);
        assertEq(r2, registryA);
        assertEq(r3, registryB, "a three-label parent is honoured");
        assertEq(chain, ARBITRUM_ONE);

        // The built-in lookup, byte for byte.
        bytes memory name = _dns("sub.venue.eth");
        bytes memory data = _addrQuery(_node("sub.venue.eth"));
        vm.expectRevert(_expectedBuiltInLookup(name, data, _registrySettings(registryA)));
        resolver.resolve(name, data);
    }

    function test_Walk_DeepestConfiguredAncestorWins() public {
        _configure(_own("brand.eth", alice), alice, _registrySettings(registryA));
        _configure(_own("events.brand.eth", carol), carol, _registrySettings(registryC));

        (, address deep) = _routedTo("x.events.brand.eth");
        (, address shallow) = _routedTo("y.brand.eth");
        (, address itself) = _routedTo("events.brand.eth");
        assertEq(deep, registryC, "the child's settings govern its subtree");
        assertEq(shallow, registryA);
        assertEq(itself, registryC, "a node with no fallback goes offchain with its own registry");
    }

    /// A node's settings are a complete statement for its subtree: a
    /// fallback-only child is not overridden by its parent's registry.
    function test_Walk_StopsAtTheDeepestConfiguredNode() public {
        MockPublicResolver pr = new MockPublicResolver();
        _configure(_own("brand.eth", alice), alice, _registrySettings(registryA));
        bytes32 events = _own("events.brand.eth", carol);
        _configure(events, carol, _fallbackSettings(address(pr)));

        vm.expectRevert(abi.encodeWithSelector(L1Resolver.NotServed.selector, events));
        resolver.resolve(_dns("x.events.brand.eth"), _addrQuery(_node("x.events.brand.eth")));
    }

    /// Audit 969 L-2: the TLD's own node is never consulted, even if whoever
    /// owns it wrote settings - a TLD is never a tenant.
    function test_Walk_NeverConsultsTheTld() public {
        _configure(_own("eth", alice), alice, _registrySettings(registryA));
        _own("venue.eth", bob);

        (bool ok, bytes memory ret) = _resolveRaw(_dns("sub.venue.eth"), _addrQuery(_node("sub.venue.eth")));
        assertFalse(ok);
        assertEq(bytes4(ret), L1Resolver.NoConfiguredAncestor.selector, "the TLD's settings routed a query");
        (bytes32 node,,) = resolver.routeFor(_dns("venue.eth"));
        assertEq(node, bytes32(0), "routeFor reached the TLD");
    }

    /// Refused here, not sent to the gateway with zero values.
    function test_Walk_NothingConfiguredNeverGoesOffchain() public {
        _own("venue.eth", alice);
        (bool ok, bytes memory ret) = _resolveRaw(_dns("sub.venue.eth"), _addrQuery(_node("sub.venue.eth")));
        assertFalse(ok);
        assertEq(bytes4(ret), L1Resolver.NoConfiguredAncestor.selector);
    }

    function test_Walk_RootAndSingleLabelAreUnsupported() public {
        vm.expectRevert(L1Resolver.UnsupportedName.selector);
        resolver.resolve(hex"00", "");
        vm.expectRevert(L1Resolver.UnsupportedName.selector);
        resolver.resolve(_dns("eth"), "");
    }

    /// Each strictness rule on its own: two encodings of one name must not both
    /// be lookups.
    function test_Walk_MalformedEncodingsAreUnsupported() public {
        _configure(_own("woco.eth", alice), alice, _registrySettings(registryA));
        bytes memory ok = _dns("x.woco.eth");

        bytes[4] memory bad = [
            bytes(""),
            bytes.concat(hex"0178", hex"04776f636f", hex"03657468"), // no terminator
            bytes.concat(ok, hex"00"), // bytes after the terminator
            bytes.concat(hex"0178", hex"04776f636f", hex"0a657468") // last label runs past the end
        ];
        for (uint256 i; i < bad.length; ++i) {
            (bool success, bytes memory ret) = _resolveRaw(bad[i], _addrQuery(_node("x.woco.eth")));
            assertFalse(success);
            assertEq(bytes4(ret), L1Resolver.UnsupportedName.selector, vm.toString(i));
        }
        (, address r) = _routedTo("x.woco.eth");
        assertEq(r, registryA, "the well-formed name still routes");
    }

    /// Audit 964 M-1: a label containing "." is one label, never two.
    function test_Walk_ADotInsideALabelIsOneLabel() public {
        _configure(_own("woco.eth", alice), alice, _registrySettings(registryA));

        // [1]"x" [8]"woco.eth" [0]: "x" under a single label "woco.eth".
        bytes memory crafted = bytes.concat(hex"0178", hex"08", bytes("woco.eth"), hex"00");
        (bool ok, bytes memory ret) = _resolveRaw(crafted, _addrQuery(_node("x.woco.eth")));
        assertFalse(ok);
        assertEq(bytes4(ret), L1Resolver.NoConfiguredAncestor.selector, "the dotted label reached woco.eth's settings");

        // [8]"woco.eth" [0]: one label, so it can never reach woco.eth's fallback.
        bytes memory oneLabel = bytes.concat(hex"08", bytes("woco.eth"), hex"00");
        (ok, ret) = _resolveRaw(oneLabel, "");
        assertFalse(ok);
        assertEq(bytes4(ret), L1Resolver.UnsupportedName.selector);
    }

    function test_Walk_BracketLabelsAreLabelhashes() public {
        _configure(_own("venue.eth", alice), alice, _registrySettings(registryA));

        bytes memory hashed = bytes.concat(_bracket(keccak256("venue")), hex"03", bytes("eth"), hex"00");
        (bool ok, bytes memory ret) = _resolveRaw(bytes.concat(hex"0178", hashed), "");
        assertFalse(ok);
        (,, bytes memory callData,,) = _decodeLookup(ret);
        (,,, address registry) = abi.decode(_afterSelector(callData), (bytes, bytes, uint64, address));
        assertEq(registry, registryA, "x.[labelhash(venue)].eth routes as x.venue.eth");

        // The same bracket form with a non-hex character is refused, not hashed.
        bytes memory invalid = _bracket(keccak256("venue"));
        invalid[10] = "g";
        (ok, ret) = _resolveRaw(bytes.concat(hex"0178", invalid, hex"03", bytes("eth"), hex"00"), "");
        assertFalse(ok);
        assertEq(bytes4(ret), L1Resolver.UnsupportedName.selector);

        // 66 bytes without the brackets is an ordinary label, hashed literally.
        bytes memory plain = _bracket(keccak256("venue"));
        plain[1] = "(";
        bytes32[] memory nodes = resolver.suffixNodes(bytes.concat(plain, hex"03", bytes("eth"), hex"00"));
        bytes memory label = new bytes(66);
        for (uint256 i; i < 66; ++i) label[i] = plain[i + 1];
        assertEq(nodes[0], keccak256(abi.encodePacked(_node("eth"), keccak256(label))));
    }

    /// A `[labelhash]` label yields exactly the node its plain label does, at
    /// every suffix. (The fork test checks the same against ENS's live
    /// UniversalResolver; the vendored one does not build against OZ v5.)
    function test_Walk_BracketAndPlainLabelsGiveTheSameNodes() public view {
        bytes memory plain = _dns("a.venue.eth");
        bytes memory bracketed = bytes.concat(hex"0161", _bracket(keccak256("venue")), hex"03", bytes("eth"), hex"00");
        bytes32[] memory p = resolver.suffixNodes(plain);
        bytes32[] memory b = resolver.suffixNodes(bracketed);
        assertEq(p.length, 3);
        assertEq(b.length, 3);
        for (uint256 k; k < 3; ++k) assertEq(b[k], p[k], vm.toString(k));
        assertEq(p[0], vm.ensNamehash("a.venue.eth"));
    }

    function testFuzz_Walk_NodesEqualENSNamehash(uint8 labelCount, bytes32 seed) public view {
        uint256 count = bound(labelCount, 2, 6);
        bytes memory name;
        uint256[] memory offsets = new uint256[](count);
        for (uint256 k; k < count; ++k) {
            uint256 len = 1 + uint256(keccak256(abi.encode(seed, k))) % 40;
            bytes memory label = new bytes(len);
            for (uint256 j; j < len; ++j) label[j] = bytes1(uint8(uint256(keccak256(abi.encode(seed, k, j)))));
            offsets[k] = name.length;
            name = bytes.concat(name, bytes1(uint8(len)), label);
        }
        name = bytes.concat(name, hex"00");

        bytes32[] memory nodes = resolver.suffixNodes(name);
        assertEq(nodes.length, count);
        for (uint256 k; k < count; ++k) {
            assertEq(nodes[k], BytesUtils.namehash(name, offsets[k]));
        }
    }

    /*//////////////////////////////////////////////////////////////
                 C. SETTINGS FOLLOW THE CURRENT OWNER (H-1)
    //////////////////////////////////////////////////////////////*/

    /// Anyone may fill their OWN slot; it is read only once they own the name.
    function test_Settings_AStrangersSlotAppliesOnlyOnceTheyOwnTheName() public {
        bytes32 woco = _ownWrapped("woco.eth", alice);
        _configure(woco, alice, _registrySettings(registryA));

        L1Resolver.Settings memory mine = _registrySettings(registryB);
        vm.expectEmit(true, true, true, true, address(resolver));
        emit L1Resolver.Configured(woco, stranger, stranger, mine);
        _configure(woco, stranger, mine);

        (, address before) = _routedTo("x.woco.eth");
        assertEq(before, registryA, "a stranger's write changed the route");

        wrapper.setOwner(uint256(woco), stranger);
        (, address afterSale) = _routedTo("x.woco.eth");
        assertEq(afterSale, registryB, "the new owner's own slot applies at once");
    }

    /// A sale leaves nothing behind: the buyer starts empty.
    function test_Settings_ABuyerStartsClean() public {
        bytes32 venue = _ownWrapped("venue.eth", alice);
        _configure(venue, alice, _registrySettings(registryA));

        wrapper.setOwner(uint256(venue), bob);
        (bool ok, bytes memory ret) = _resolveRaw(_dns("x.venue.eth"), _addrQuery(_node("x.venue.eth")));
        assertFalse(ok);
        assertEq(bytes4(ret), L1Resolver.NoConfiguredAncestor.selector, "the seller's settings survived the sale");
    }

    function test_Settings_ACustodyMoveHasZeroDowntime() public {
        address oldSafe = makeAddr("oldSafe");
        address newSafe = makeAddr("newSafe");
        bytes32 woco = _ownWrapped("woco.eth", oldSafe);
        _configure(woco, oldSafe, _registrySettings(registryA));

        _configure(woco, newSafe, _registrySettings(registryA));
        (, address during) = _routedTo("x.woco.eth");
        wrapper.setOwner(uint256(woco), newSafe);
        (, address afterMove) = _routedTo("x.woco.eth");
        assertEq(during, registryA);
        assertEq(afterMove, registryA);

        _configure(woco, oldSafe, _registrySettings(registryC));
        (, address stillNew) = _routedTo("x.woco.eth");
        assertEq(stillNew, registryA, "the old custodian can still steer the name");
    }

    function test_Settings_UnwrapAndRewrapKeepTheSameSlot() public {
        bytes32 venue = _ownWrapped("venue.eth", alice);
        _configure(venue, alice, _registrySettings(registryA));

        ens.setOwner(venue, alice); // unwrapped
        (, address unwrapped) = _routedTo("x.venue.eth");
        ens.setOwner(venue, address(wrapper)); // re-wrapped
        (, address rewrapped) = _routedTo("x.venue.eth");
        assertEq(unwrapped, registryA);
        assertEq(rewrapped, registryA);
    }

    /// Without the wrapper branch a wrapped name would read the wrapper's own
    /// (always empty) slot.
    function test_Settings_WrappedNamesAreReadThroughTheWrapper() public {
        bytes32 venue = _ownWrapped("venue.eth", alice);
        _configure(venue, alice, _registrySettings(registryA));
        assertEq(resolver.effectiveOwner(venue), alice);
        (, address r) = _routedTo("x.venue.eth");
        assertEq(r, registryA);
    }

    /// Past its wrapper expiry a wrapped .eth name reads as unowned; a new
    /// registrant starts from their own (empty) slot.
    function test_Settings_AnExpiredWrappedNameStopsResolving() public {
        bytes32 venue = _ownWrapped("venue.eth", alice);
        _configure(venue, alice, _registrySettings(registryA));

        wrapper.setOwner(uint256(venue), address(0));
        (bool ok, bytes memory ret) = _resolveRaw(_dns("x.venue.eth"), _addrQuery(_node("x.venue.eth")));
        assertFalse(ok);
        assertEq(bytes4(ret), L1Resolver.NoConfiguredAncestor.selector);

        wrapper.setOwner(uint256(venue), bob);
        (ok, ret) = _resolveRaw(_dns("x.venue.eth"), _addrQuery(_node("x.venue.eth")));
        assertEq(bytes4(ret), L1Resolver.NoConfiguredAncestor.selector, "the new registrant inherited settings");

        _configure(venue, bob, _registrySettings(registryB));
        (, address r) = _routedTo("x.venue.eth");
        assertEq(r, registryB);
    }

    /// An unwrapped .eth name keeps its registry owner after expiry, so its
    /// settings resolve until the name is reassigned - as with any ENS resolver.
    function test_Settings_UnwrappedExpiryKeepsSettingsUntilReassigned() public {
        bytes32 venue = _own("venue.eth", alice);
        _configure(venue, alice, _registrySettings(registryA));
        (, address r) = _routedTo("x.venue.eth");
        assertEq(r, registryA);

        ens.setOwner(venue, bob);
        (bool ok, bytes memory ret) = _resolveRaw(_dns("x.venue.eth"), _addrQuery(_node("x.venue.eth")));
        assertFalse(ok);
        assertEq(bytes4(ret), L1Resolver.NoConfiguredAncestor.selector);
    }

    /// A -> B -> A: A's own earlier settings come back. Self-scoped by design.
    function test_Settings_RevivesTheOwnersOwnEarlierSettings() public {
        bytes32 venue = _ownWrapped("venue.eth", alice);
        _configure(venue, alice, _registrySettings(registryA));
        wrapper.setOwner(uint256(venue), bob);
        wrapper.setOwner(uint256(venue), alice);
        (, address r) = _routedTo("x.venue.eth");
        assertEq(r, registryA);
    }

    function test_Settings_AContractOwnerConfiguresItsOwnSlot() public {
        Executor safe = new Executor();
        bytes32 woco = _ownWrapped("woco.eth", address(safe));
        safe.exec(
            address(resolver),
            abi.encodeCall(L1Resolver.configure, (woco, address(safe), _registrySettings(registryA)))
        );
        (, address r) = _routedTo("x.woco.eth");
        assertEq(r, registryA);
    }

    /// Clearing makes the node unconfigured, so queries fall to its parent.
    function test_Settings_ClearingFallsBackToTheParent() public {
        _configure(_own("brand.eth", alice), alice, _registrySettings(registryA));
        bytes32 events = _own("events.brand.eth", carol);
        _configure(events, carol, _registrySettings(registryC));
        L1Resolver.Settings memory empty;
        _configure(events, carol, empty);

        (, address r) = _routedTo("x.events.brand.eth");
        assertEq(r, registryA);
    }

    /// Slot zero can never be written, and unowned levels are skipped.
    function test_Settings_TheZeroOwnerIsNeverASlot() public {
        vm.expectRevert(L1Resolver.Unauthorized.selector);
        vm.prank(address(0));
        resolver.configure(_node("venue.eth"), address(0), _registrySettings(registryA));

        (address owner, L1Resolver.Settings memory s) = resolver.settingsOf(_node("venue.eth"));
        assertEq(owner, address(0));
        assertEq(s.registry, address(0));
    }

    function test_Configure_RefusesACodelessFallback() public {
        bytes32 venue = _own("venue.eth", alice);
        address nothing = makeAddr("nothing-deployed-here");
        vm.expectRevert(abi.encodeWithSelector(L1Resolver.FallbackResolverHasNoCode.selector, nothing));
        vm.prank(alice);
        resolver.configure(venue, alice, _fallbackSettings(nothing));
    }

    /*//////////////////////////////////////////////////////////////
                    C2. OPERATORS, WHERE ENS ALLOWS THEM
    //////////////////////////////////////////////////////////////*/

    function test_Configure_ARegistryOperatorWritesForAnUnwrappedName() public {
        bytes32 venue = _own("venue.eth", alice);
        ens.setApproval(alice, carol, true);
        vm.expectEmit(true, true, true, true, address(resolver));
        emit L1Resolver.Configured(venue, alice, carol, _registrySettings(registryA));
        vm.prank(carol);
        resolver.configure(venue, alice, _registrySettings(registryA));
        (, address r) = _routedTo("x.venue.eth");
        assertEq(r, registryA);
    }

    function test_Configure_AWrapperOperatorWritesForAWrappedName() public {
        bytes32 venue = _ownWrapped("venue.eth", alice);
        wrapper.setApproval(alice, carol, true);
        vm.prank(carol);
        resolver.configure(venue, alice, _registrySettings(registryA));
        (, address r) = _routedTo("x.venue.eth");
        assertEq(r, registryA);
    }

    /// ENS does not let a holder's REGISTRY operator touch that holder's
    /// WRAPPED names, and neither does this.
    function test_Configure_OperatorsOfTheOtherKindAreRefused() public {
        bytes32 wrapped = _ownWrapped("venue.eth", alice);
        ens.setApproval(alice, carol, true);
        vm.expectRevert(L1Resolver.Unauthorized.selector);
        vm.prank(carol);
        resolver.configure(wrapped, alice, _registrySettings(registryA));

        bytes32 unwrapped = _own("other.eth", alice);
        wrapper.setApproval(alice, bob, true);
        vm.expectRevert(L1Resolver.Unauthorized.selector);
        vm.prank(bob);
        resolver.configure(unwrapped, alice, _registrySettings(registryA));
    }

    function test_Configure_ANonOperatorIsRefused() public {
        bytes32 venue = _ownWrapped("venue.eth", alice);
        vm.expectRevert(L1Resolver.Unauthorized.selector);
        vm.prank(stranger);
        resolver.configure(venue, alice, _registrySettings(registryA));

        // Not even this contract's owner, who holds only the gateway settings.
        vm.expectRevert(L1Resolver.Unauthorized.selector);
        vm.prank(resolverOwner);
        resolver.configure(venue, alice, _registrySettings(registryA));
    }

    /*//////////////////////////////////////////////////////////////
                               D. VIEWS
    //////////////////////////////////////////////////////////////*/

    function test_Views_SettingsAndSettingsOf() public {
        bytes32 venue = _ownWrapped("venue.eth", alice);
        L1Resolver.Settings memory s = _registrySettings(registryA);
        s.moduleData = hex"c0ffee";
        _configure(venue, alice, s);

        assertEq(resolver.settings(venue, alice).registry, registryA);
        assertEq(resolver.settings(venue, bob).registry, address(0));
        (address owner, L1Resolver.Settings memory read) = resolver.settingsOf(venue);
        assertEq(owner, alice);
        assertEq(read.chainId, ARBITRUM_ONE);
        assertEq(read.moduleData, hex"c0ffee");
    }

    /// `routeFor` is the same walk as `resolve()`, so they cannot disagree.
    function test_RouteFor_IsTheRouteResolveTakes() public {
        bytes32 brand = _own("brand.eth", alice);
        _configure(brand, alice, _registrySettings(registryA));
        bytes32 events = _own("events.brand.eth", carol);
        _configure(events, carol, _registrySettings(registryC));

        string[3] memory names = [string("x.events.brand.eth"), "y.brand.eth", "events.brand.eth"];
        bytes32[3] memory expectNode = [events, brand, events];
        address[3] memory expectOwner = [carol, alice, carol];
        for (uint256 i; i < 3; ++i) {
            (bytes32 node, address owner, L1Resolver.Settings memory s) = resolver.routeFor(_dns(names[i]));
            (, address routed) = _routedTo(names[i]);
            assertEq(node, expectNode[i], names[i]);
            assertEq(owner, expectOwner[i], names[i]);
            assertEq(s.registry, routed, names[i]);
        }

        (bytes32 none, address nobody, L1Resolver.Settings memory empty) = resolver.routeFor(_dns("x.unset.eth"));
        assertEq(none, bytes32(0));
        assertEq(nobody, address(0));
        assertEq(empty.registry, address(0));

        vm.expectRevert(L1Resolver.UnsupportedName.selector);
        resolver.routeFor(hex"00");
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /// @dev `[` + 64 lowercase hex + `]`, length-prefixed as a DNS label.
    function _bracket(bytes32 h) internal pure returns (bytes memory label) {
        bytes memory hexChars = bytes(vm.toString(h)); // "0x" + 64 lowercase hex
        label = new bytes(67);
        label[0] = bytes1(uint8(66));
        label[1] = "[";
        for (uint256 i; i < 64; ++i) label[2 + i] = hexChars[2 + i];
        label[66] = "]";
    }
}
