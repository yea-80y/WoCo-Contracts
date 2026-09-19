// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {NameEncoder} from "@ensdomains/ens-contracts/utils/NameEncoder.sol";
import {DeploySubEnsRegistry} from "../script/DeploySubEnsRegistry.s.sol";
import {L1Resolver} from "../src/durin/L1Resolver.sol";
import {L2Registry} from "../src/durin/L2Registry.sol";
import {L2Resolver} from "../src/durin/L2Resolver.sol";
import {WoCoRegistrar} from "../src/WoCoRegistrar.sol";

/**
 * FORK REHEARSAL of the sub-ENS v2 cutover (WoCo-Contracts #21): the live
 * Arbitrum One registry and the live mainnet L1 resolver at pinned blocks, with
 * the Safe impersonated. Nothing is broadcast.
 *
 * It runs what the cutover will run, one step per helper: the deploy script's
 * own admin guard, deploy, tripwire and state checks (C2); the wiring calldata
 * the script prints, sent by the Safe (C3); the re-mint from the known-good
 * records table (C4); the retirement of v1 (C9); the Safe handing the seat on;
 * and `setL2Registry` from the Safe that holds `woco.eth`, then the rollback (C6).
 *
 * The live v1 records at the pinned block are checked against the table first.
 * If a later block is used and they differ, stop: the table, not live v1 state,
 * is what gets re-minted.
 *
 * Skipped unless both RPC URLs are set, so CI skips it:
 *   ARB_ONE_RPC_URL=… MAINNET_RPC_URL=… forge test --match-contract SubEnsV2CutoverFork -vv
 * Optional: ARB_ONE_FORK_BLOCK / MAINNET_FORK_BLOCK to re-pin.
 */
contract SubEnsV2CutoverForkTest is Test {
    uint256 constant ARB_ONE_BLOCK = 504938268;
    uint256 constant MAINNET_BLOCK = 25973193;

    address constant SAFE = 0xD26abFb5fBd37eFBD876e87cB169286eF0f14BA2;
    address constant SPONSOR = 0x7b318c46a6FDC544212ebd83335f6b7414A97925;
    address constant V1_REGISTRY = 0x8630000177d44ec12e4752Ae0C8b26390d30A2B6;
    address constant V1_REGISTRAR = 0xACfe7c02909a5c1eB64aE5aA10D18618323403a2;
    address constant L1_RESOLVER = 0x172031E6a8428617B05F2002e0e278bb8fb3Ed8A;
    bytes32 constant WOCO_ETH = 0x616c19dee44e200629c0e4918ca0fe2f6e85100ea0b354c4f888e11c07a9006f;
    uint256 constant ARB_ONE_COIN_TYPE = 0x8000a4b1;

    // The known-good records (cutover plan §0), read 2026-09-14 at ARB_ONE_BLOCK.
    address constant NABIL = 0x73478eb498679DB88E2C2A72C38f81f8861f8C75;
    address constant TEST = 0xeA1478b3818F3a06B83ceB7Ec6f710a51115D879;
    bytes constant NABIL_SITE = hex"e40101fa011b20d66c6ff7650a468c2fd98439c8f04547b5b8a4b933d349ff16db1d0b00c23adc";
    bytes constant TEST_SITE = hex"e40101fa011b206a20bc33c1b52baf70c847a0d13f0da83e286c6cb9f9059009332886e1cacf9a";

    function test_fork_cutoverEndToEnd() public {
        string memory arbRpc = vm.envOr("ARB_ONE_RPC_URL", string(""));
        string memory l1Rpc = vm.envOr("MAINNET_RPC_URL", string(""));
        if (bytes(arbRpc).length == 0 || bytes(l1Rpc).length == 0) {
            vm.skip(true);
            return;
        }
        uint256 l1Fork = vm.createFork(l1Rpc, vm.envOr("MAINNET_FORK_BLOCK", MAINNET_BLOCK));
        vm.createSelectFork(arbRpc, vm.envOr("ARB_ONE_FORK_BLOCK", ARB_ONE_BLOCK));

        _assertRecords(V1_REGISTRY, "nabil.woco.eth", NABIL, NABIL_SITE, "v1 nabil differs from the table - stop");
        _assertRecords(V1_REGISTRY, "test.woco.eth", TEST, TEST_SITE, "v1 test differs from the table - stop");

        (address registry, address registrar) = _deployAndWire();
        _remintAndCompare(registry, registrar);
        _retireV1();
        _handTheSeatOn(registry);

        vm.selectFork(l1Fork);
        _flipL1AndRollBack(registry);
    }

    /*//////////////////////////////////////////////////////////////
                              THE STEPS
    //////////////////////////////////////////////////////////////*/

    /// C2 + C3: the script's own deploy and checks with the real Safe as admin,
    /// then the exact wiring calldata the script prints, sent by the Safe.
    function _deployAndWire() internal returns (address registry, address registrar) {
        CutoverHarness harness = new CutoverHarness();
        uint256 gasBefore = gasleft();
        (registry, registrar) = harness.deployAndCheck(SAFE, SPONSOR);
        emit log_named_uint("C2 execution gas (Arbitrum adds its L1 data fee on top)", gasBefore - gasleft());

        bytes memory wiring = harness.wiringCall(registrar);
        vm.prank(SAFE);
        (bool wired,) = registry.call(wiring);
        assertTrue(wired, "the printed wiring call failed from the Safe");
    }

    /// C4: the sponsor re-mints both names from the table — bare, since the
    /// registrar never writes a pointer — and each HOLDER points its name back
    /// at its site, as it would after the cutover. v2 then answers the
    /// gateway's call exactly as v1 does, and its records are the holders' alone.
    function _remintAndCompare(address registry, address registrar) internal {
        vm.startPrank(SPONSOR);
        bytes32 nabilNode = WoCoRegistrar(registrar).register("nabil", NABIL);
        bytes32 testNode = WoCoRegistrar(registrar).register("test", TEST);
        vm.stopPrank();
        vm.prank(NABIL);
        L2Registry(registry).setContenthash(nabilNode, NABIL_SITE);
        vm.prank(TEST);
        L2Registry(registry).setContenthash(testNode, TEST_SITE);

        _assertRecords(registry, "nabil.woco.eth", NABIL, NABIL_SITE, "v2 nabil is not the table");
        _assertRecords(registry, "test.woco.eth", TEST, TEST_SITE, "v2 test is not the table");
        _assertResolvesAlike(registry, "nabil.woco.eth");
        _assertResolvesAlike(registry, "test.woco.eth");

        bytes32 nabil = vm.ensNamehash("nabil.woco.eth");
        address stranger = makeAddr("stranger");
        vm.expectRevert(abi.encodeWithSelector(L2Resolver.Unauthorized.selector, nabil));
        vm.prank(stranger);
        L2Registry(registry).setContenthash(nabil, hex"e301");
    }

    /// C9: the Safe retires v1's registrar — two pranked calls here; the atomic
    /// Safe batch itself is rehearsed on Arbitrum Sepolia (plan R5). Its sponsor
    /// mints nothing there afterwards.
    function _retireV1() internal {
        vm.startPrank(SAFE);
        WoCoRegistrar(V1_REGISTRAR).removeSponsor(SPONSOR);
        L2Registry(V1_REGISTRY).removeRegistrar(V1_REGISTRAR);
        vm.stopPrank();
        assertFalse(L2Registry(V1_REGISTRY).registrars(V1_REGISTRAR), "v1 registrar still enrolled");

        string[] memory none = new string[](0);
        vm.expectRevert(abi.encodeWithSelector(WoCoRegistrar.NotAuthorisedSponsor.selector, SPONSOR));
        vm.prank(SPONSOR);
        IV1Registrar(V1_REGISTRAR).register("another", NABIL, NABIL_SITE, none, none);
    }

    /// The seat's way on, driven by the real Safe contract.
    function _handTheSeatOn(address registry) internal {
        address dao = makeAddr("dao");
        vm.prank(SAFE);
        L2Registry(registry).nominateAdmin(dao);
        vm.prank(dao);
        L2Registry(registry).acceptAdmin();
        assertEq(L2Registry(registry).owner(), dao, "the Safe could not hand the seat on");
    }

    /// C6 from the Safe that holds woco.eth, then the rollback. The apex keeps
    /// answering from L1 throughout.
    function _flipL1AndRollBack(address registry) internal {
        L1Resolver l1 = L1Resolver(L1_RESOLVER);
        (uint64 chainBefore, address registryBefore) = l1.l2Registry(WOCO_ETH);
        assertEq(chainBefore, 42161, "L1 does not point at Arbitrum One");
        assertEq(registryBefore, V1_REGISTRY, "L1 does not point at v1");

        bytes memory apexCall = abi.encodeWithSignature("contenthash(bytes32)", WOCO_ETH);
        bytes memory apexBefore = l1.resolve(_dns("woco.eth"), apexCall);

        vm.prank(SAFE);
        l1.setL2Registry(WOCO_ETH, 42161, registry);
        (, address registryAfter) = l1.l2Registry(WOCO_ETH);
        assertEq(registryAfter, registry, "setL2Registry did not land");

        assertEq(_offchainRegistry(l1, "nabil.woco.eth"), registry, "a subname lookup does not name v2");
        assertEq(_offchainRegistry(l1, "test.woco.eth"), registry, "a subname lookup does not name v2");
        assertEq(l1.resolve(_dns("woco.eth"), apexCall), apexBefore, "the apex stopped answering from L1");

        vm.prank(SAFE);
        l1.setL2Registry(WOCO_ETH, 42161, V1_REGISTRY);
        assertEq(_offchainRegistry(l1, "nabil.woco.eth"), V1_REGISTRY, "rollback did not restore v1");
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    function _assertRecords(
        address registry,
        string memory name,
        address holder,
        bytes memory site,
        string memory why
    ) internal view {
        bytes32 node = vm.ensNamehash(name);
        L2Registry r = L2Registry(registry);
        assertEq(r.owner(node), holder, why);
        assertEq(r.contenthash(node), site, why);
        assertEq(r.addr(node, 60), abi.encodePacked(holder), why);
        assertEq(r.addr(node, ARB_ONE_COIN_TYPE), abi.encodePacked(holder), why);
    }

    /// Every record read the gateway serves, through `resolve`, v2 against v1.
    function _assertResolvesAlike(address registry, string memory name) internal view {
        bytes32 node = vm.ensNamehash(name);
        bytes memory dnsName = _dns(name);
        bytes[5] memory reads = [
            abi.encodeWithSignature("addr(bytes32)", node),
            abi.encodeWithSignature("addr(bytes32,uint256)", node, uint256(60)),
            abi.encodeWithSignature("addr(bytes32,uint256)", node, ARB_ONE_COIN_TYPE),
            abi.encodeWithSignature("contenthash(bytes32)", node),
            abi.encodeWithSignature("text(bytes32,string)", node, "url")
        ];
        for (uint256 i; i < reads.length; ++i) {
            assertEq(
                L2Registry(registry).resolve(dnsName, reads[i]),
                L2Registry(V1_REGISTRY).resolve(dnsName, reads[i]),
                string.concat(name, ": v2 resolves differently from v1")
            );
        }
    }

    /// The registry an L1 lookup sends the gateway to: the last argument of the
    /// `stuffedResolveCall` inside the `OffchainLookup` revert.
    function _offchainRegistry(L1Resolver l1, string memory name) internal view returns (address) {
        bytes memory inner = abi.encodeWithSignature("addr(bytes32)", vm.ensNamehash(name));
        try l1.resolve(_dns(name), inner) returns (bytes memory) {
            revert("expected an OffchainLookup");
        } catch (bytes memory err) {
            assertTrue(bytes4(err) == L1Resolver.OffchainLookup.selector, "not an OffchainLookup");
            (,, bytes memory callData,,) = abi.decode(_afterSelector(err), (address, string[], bytes, bytes4, bytes));
            (,,, address target) = abi.decode(_afterSelector(callData), (bytes, bytes, uint64, address));
            return target;
        }
    }

    function _dns(string memory name) internal pure returns (bytes memory dnsName) {
        (dnsName,) = NameEncoder.dnsEncodeName(name);
    }

    function _afterSelector(bytes memory b) internal pure returns (bytes memory out) {
        out = new bytes(b.length - 4);
        for (uint256 i; i < out.length; ++i) {
            out[i] = b[i + 4];
        }
    }
}

/// @dev The deploy script's own steps, without its environment: the admin guard,
///      the deploy, the tripwire and the state checks, in the order `run()` uses.
contract CutoverHarness is DeploySubEnsRegistry {
    function deployAndCheck(address admin, address sponsor) external returns (address registry, address registrar) {
        _requireSafeShapedAdmin(admin);
        address impl;
        (registry, impl, registrar) = _deploy("woco.eth", admin, sponsor, reservedLabels());
        _assertRegistryRunsOurImplementation(registry, impl);
        _assertDeployedState(registry, registrar, admin, sponsor);
    }
}

/// @dev The LIVE v1 registrar's mint, which took records at mint. v2.2's
///      `register` is two arguments; this is only for driving v1 on the fork.
interface IV1Registrar {
    function register(
        string calldata label,
        address owner_,
        bytes calldata contenthash,
        string[] calldata textKeys,
        string[] calldata textValues
    ) external returns (bytes32);
}
