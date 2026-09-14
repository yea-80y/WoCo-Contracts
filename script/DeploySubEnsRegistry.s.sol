// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {WoCoSubEnsDeployer} from "../src/WoCoSubEnsDeployer.sol";
import {WoCoRegistrar} from "../src/WoCoRegistrar.sol";
import {L2Registry} from "../src/durin/L2Registry.sol";
import {L2Resolver} from "../src/durin/L2Resolver.sol";

/// @title DeploySubEnsRegistry
/// @notice Deploys WoCo's sub-ENS registry (v2) for `woco.eth` and its
///         WoCoRegistrar in ONE transaction through `WoCoSubEnsDeployer`, with
///         both admin roles on `REGISTRY_ADMIN` from the start, and proves the
///         registry runs OUR implementation before anything is broadcast.
///
/// @dev Run against Arbitrum Sepolia first, with a Safe there as the admin:
///        forge script script/DeploySubEnsRegistry.s.sol --rpc-url arb_sepolia --broadcast
///
///      Required env:
///        DEPLOYER_PRIVATE_KEY — pays for the one transaction. Holds no role at
///                               any point.
///        SPONSOR_ADDRESS      — platform gas-sponsor wallet authorised to mint.
///        REGISTRY_ADMIN       — the Safe. Holds the admin seat and owns the
///                               registrar from construction. REQUIRED.
///
///      The parent name is NOT configurable: see `PARENT_NAME`.
///
///      NOT DONE HERE, BY DESIGN: wiring the registrar in. `addRegistrar` is the
///      admin's own transaction; the script prints its calldata
///      (`wiringCall`).
///
/// WHAT CHANGED IN v2 (WoCo-Contracts #21)
///
/// v1 cloned and initialised in separate transactions, which left the clone open
/// to anyone's `initialize` in between (audit 924 F-10 / 927 M9), and gave both
/// admin roles to the deployer first, then moved them to the Safe with two
/// single-step, irreversible transfers. v2 does neither: one transaction, roles
/// set at construction, nothing to rotate. The `ALLOW_EOA_ADMIN` escape hatch
/// went with the rotation — rehearse on Arbitrum Sepolia with a Safe, as on
/// mainnet.
///
/// WHY THIS DEPLOYS ITS OWN IMPLEMENTATION (WoCo-Event-App #440)
///
/// An earlier version created the registry through Durin's canonical
/// `L2RegistryFactory`, which clones an implementation fixed at the factory's
/// construction — NameStone's — so every WoCo change to `L2Registry.sol` existed
/// only in this repo and never on chain. The tripwire below asserts, at deploy
/// time, that the registry about to go live runs OUR source. Reinstating a
/// factory call trips it.
///
/// ⚠️ `REGISTRY_ADMIN` RECEIVES THE WHOLE REGISTRY AT CONSTRUCTION. The admin seat
/// then moves only through `nominateAdmin`, which only its holder can call, so a
/// wrong address here loses the registry for good. Verify it on a block explorer
/// before broadcasting. The guard below refuses an address with no code, and an
/// EOA carrying an EIP-7702 delegation — which is what the Safe's own signer
/// account is — but it CANNOT catch a well-formed contract you do not control.
contract DeploySubEnsRegistry is Script {
    /// @notice The parent name this registry serves, and its namehash.
    /// @dev Fixed rather than configured: a registry initialised under a
    ///      mistyped parent mints normally and answers nothing once L1 points at
    ///      it. The node is a literal, checked against the deployed registry,
    ///      because comparing `baseNode()` with a namehash computed from the same
    ///      string would check nothing.
    string constant PARENT_NAME = "woco.eth";
    bytes32 constant PARENT_NODE = 0x616c19dee44e200629c0e4918ca0fe2f6e85100ea0b354c4f888e11c07a9006f;

    /// @notice The implementation NameStone's canonical `L2RegistryFactory`
    ///         clones (read from the factory on Arb Sepolia, 2026-09-02). Named
    ///         here so that a deploy which somehow ends up pointing at upstream
    ///         Durin fails by NAME rather than by a bytecode mismatch nobody
    ///         reads. Never a deploy target.
    address constant NAMESTONE_REGISTRY_IMPLEMENTATION = 0xdeB09eB3111cB75d538216e8B8fC30047d75fb34;

    /// @dev EIP-1167 minimal-proxy runtime: PREFIX ‖ 20-byte impl ‖ SUFFIX.
    bytes10 constant CLONE_PREFIX = 0x363d3d373d3d3d363d73;
    bytes15 constant CLONE_SUFFIX = 0x5af43d82803e903d91602b57fd5bf3;
    uint256 constant CLONE_RUNTIME_LENGTH = 45;

    /// @dev EIP-7702 delegation designator: 0xef0100 ‖ 20-byte delegate. No
    ///      deployed contract's code can start with 0xEF (EIP-3541), so the
    ///      prefix alone identifies a delegated account.
    bytes3 constant DELEGATION_PREFIX = 0xef0100;

    /// @dev A node that is registered nowhere: not the zero node the
    ///      uninitialised implementation calls `baseNode`, and not a namehash
    ///      anything could mint. Used only to make WoCo's functions answer.
    bytes32 constant PROBE_NODE = keccak256("woco/deploy/tripwire-probe");

    /// @return registryAddress  The initialised registry clone, admin seat on `REGISTRY_ADMIN`.
    /// @return registrarAddress The `WoCoRegistrar`, owned by `REGISTRY_ADMIN`, not yet wired in.
    function run() external returns (address registryAddress, address registrarAddress) {
        uint256 deployerPk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address sponsor = vm.envAddress("SPONSOR_ADDRESS");
        address registryAdmin = _registryAdmin();
        _requireSafeShapedAdmin(registryAdmin);

        vm.startBroadcast(deployerPk);
        address implAddr;
        (registryAddress, implAddr, registrarAddress) =
            _deploy(PARENT_NAME, registryAdmin, sponsor, reservedLabels());
        vm.stopBroadcast();

        // Forge runs the whole of `run()` as a simulation before it broadcasts
        // anything, so a check below that fails stops the deploy transaction from
        // ever being sent.
        _assertRegistryRunsOurImplementation(registryAddress, implAddr);
        _assertDeployedState(registryAddress, registrarAddress, registryAdmin, sponsor);

        console.log("Parent name:        ", PARENT_NAME);
        console.log("L2Registry impl:    ", implAddr);
        console.log("L2Registry (clone): ", registryAddress);
        console.log("WoCoRegistrar:      ", registrarAddress);
        console.log("Registry admin:     ", registryAdmin);
        console.log("Registrar owner:    ", registryAdmin);
        console.log("Deployer (no roles):", vm.addr(deployerPk));
        console.log("Authorised sponsor: ", sponsor);
        console.log("NEXT - the registry admin sends, to the registry above:");
        console.logBytes(wiringCall(registrarAddress));
    }

    /// @notice Labels the registrar will never mint.
    function reservedLabels() public pure returns (string[] memory labels) {
        labels = new string[](8);
        labels[0] = "woco";
        labels[1] = "admin";
        labels[2] = "support";
        labels[3] = "help";
        labels[4] = "www";
        labels[5] = "api";
        labels[6] = "app";
        labels[7] = "mail";
    }

    /// @notice The calldata the registry admin sends to the registry to let the
    ///         new registrar mint. Public so the tests execute exactly what is
    ///         printed.
    function wiringCall(address registrar) public pure returns (bytes memory) {
        return abi.encodeCall(L2Registry.addRegistrar, (registrar));
    }

    /*//////////////////////////////////////////////////////////////
                              DEPLOYMENT
    //////////////////////////////////////////////////////////////*/

    /// @notice Who receives the admin seat and the registrar.
    /// @dev Required, not defaulted: whoever this is holds the registry for good.
    ///      `virtual` ONLY so that tests can vary it: `vm.setEnv` writes the whole
    ///      forge process's environment while test functions run in parallel,
    ///      so a per-test value would race. The guard on it stays in `run()`.
    function _registryAdmin() internal view virtual returns (address) {
        return vm.envAddress("REGISTRY_ADMIN");
    }

    /// @notice Creates the registry, its implementation and the registrar.
    /// @dev `virtual` ONLY so that tests can substitute a deployment the checks
    ///      must reject. Production always runs this body.
    function _deploy(string memory parentName, address admin, address sponsor, string[] memory labels)
        internal
        virtual
        returns (address registryAddr, address implAddr, address registrarAddr)
    {
        WoCoSubEnsDeployer deployer = new WoCoSubEnsDeployer(parentName, admin, sponsor, labels);
        return (address(deployer.registry()), address(deployer.implementation()), address(deployer.registrar()));
    }

    /// @dev Refuses an admin that cannot be the Safe: the zero address, an
    ///      address with no code (a typo, or a bare key), and an EOA carrying an
    ///      EIP-7702 delegation. The last is not hypothetical — the Safe's own
    ///      signer is such an account, it has code, and a plain code check
    ///      would take it.
    function _requireSafeShapedAdmin(address admin) internal view {
        require(admin != address(0), "REGISTRY_ADMIN must not be the zero address");
        bytes memory code = admin.code;
        require(code.length > 0, "REGISTRY_ADMIN has no code - expected the Safe");
        require(
            bytes3(code) != DELEGATION_PREFIX,
            "REGISTRY_ADMIN is an EIP-7702 delegated EOA - expected the Safe, not a signer account"
        );
    }

    /// @dev What the Safe's signers are told they are getting. Every clause
    ///      holds by construction of `WoCoSubEnsDeployer`; checked anyway, because
    ///      a deploy that reports success over a wrong state has no other signal.
    function _assertDeployedState(address registryAddr, address registrarAddr, address admin, address sponsor)
        internal
        view
    {
        L2Registry registry = L2Registry(registryAddr);
        WoCoRegistrar registrar = WoCoRegistrar(registrarAddr);

        require(registry.baseNode() == PARENT_NODE, "registry is not woco.eth - its base node is not namehash(woco.eth)");
        require(registry.owner() == admin, "registry admin seat is not on REGISTRY_ADMIN");
        require(registrar.owner() == admin, "registrar is not owned by REGISTRY_ADMIN");
        require(address(registrar.registry()) == registryAddr, "registrar mints into a different registry");
        require(registrar.authorisedSponsors(sponsor), "SPONSOR_ADDRESS is not an authorised sponsor");

        string[] memory labels = reservedLabels();
        for (uint256 i; i < labels.length; ++i) {
            require(registrar.reserved(keccak256(bytes(labels[i]))), "a reserved label is not reserved");
        }
    }

    /*//////////////////////////////////////////////////////////////
                              THE TRIPWIRE
    //////////////////////////////////////////////////////////////*/

    /// @notice Refuses to continue unless the registry about to go live executes
    ///         the v2 `L2Registry` source in THIS repo.
    ///
    /// @dev Independent checks, because one is not enough to survive a careless
    ///      edit:
    ///
    ///        (1) SHAPE + TARGET — `registryAddr` is a canonical EIP-1167 clone
    ///            whose embedded implementation is exactly `implAddr`.
    ///
    ///        (2) NOT UPSTREAM — the implementation is not NameStone's known
    ///            address. Redundant with (1) by construction; kept because it
    ///            names the failure the operator actually cares about.
    ///
    ///        (3) OUR CODE — the implementation ANSWERS as ours does. Each WoCo
    ///            function is called on the implementation with arguments that
    ///            make our source revert with one of our own custom errors, and
    ///            the revert data is matched against that error's selector. A
    ///            contract without the function reverts with empty data; one
    ///            that merely mentions the selector in its bytecode does the
    ///            same. Behaviour survives address substitution; addresses and
    ///            byte scans do not.
    ///
    ///        (4) v2, NOT v1 — `acceptAdmin` answers with v2's own error, and
    ///            `nonces`, which v1's signed record setters needed and v1
    ///            answers like any view, does not exist at all.
    ///
    ///      If a WoCo function is ever removed from `L2Registry`, its probe must
    ///      be re-pointed at whatever replaces it; deleting the probe is not the
    ///      fix. If the error vocabulary changes, the expected selectors change
    ///      with it.
    function _assertRegistryRunsOurImplementation(address registryAddr, address implAddr) internal view {
        address embedded = _cloneImplementationOf(registryAddr);
        require(embedded == implAddr, "registry is not a clone of the implementation this script deployed");
        require(
            implAddr != NAMESTONE_REGISTRY_IMPLEMENTATION,
            "registry implementation is NameStone's - the factory path is back"
        );
        // #422. On the uninitialised implementation `owner()` is the zero
        // address, so `onlyOwner` refuses us before the body runs.
        require(
            _revertsWith(
                implAddr,
                abi.encodeCall(L2Registry.adminTransfer, (PROBE_NODE, address(1))),
                L2Resolver.Unauthorized.selector
            ),
            "registry implementation does not run WoCo's adminTransfer - it is not our bytecode"
        );
        // #464. PROBE_NODE is not the base node and is owned by nobody, so our
        // source refuses it as unregistered whichever guard it checks first.
        require(
            _revertsWith(
                implAddr,
                abi.encodeCall(L2Registry.release, (PROBE_NODE)),
                L2Registry.ReleaseUnregistered.selector
            ),
            "registry implementation does not run WoCo's release - it is not our bytecode"
        );
        // #464, the signature rail. Same unregistered probe node; `expiration`
        // is max so the expiry modifier passes and the body's own guard is what
        // answers. No signature is examined before that guard, so the validator
        // (absent on a fork, real on chain) is never reached.
        require(
            _revertsWith(
                implAddr,
                abi.encodeCall(
                    L2Registry.releaseWithSignature, (PROBE_NODE, type(uint256).max, address(1), bytes(""))
                ),
                L2Registry.ReleaseUnregistered.selector
            ),
            "registry implementation does not run WoCo's releaseWithSignature - it is not our bytecode"
        );
        // v2 admin handover. No handover is open on the uninitialised
        // implementation, so our source refuses whoever calls.
        require(
            _revertsWith(implAddr, abi.encodeCall(L2Registry.acceptAdmin, ()), L2Registry.NotPendingAdmin.selector),
            "registry implementation does not run v2's acceptAdmin - it is not the v2 bytecode"
        );
        require(
            _revertsEmpty(implAddr, abi.encodeWithSignature("nonces(bytes32)", PROBE_NODE)),
            "registry implementation still answers nonces - it carries v1's signed record setters"
        );
    }

    /// @dev Extracts the implementation address from an EIP-1167 minimal proxy,
    ///      reverting if `clone` is not one. The prefix/suffix are checked as
    ///      well as the length, so a 45-byte contract that merely happens to be
    ///      the right size cannot pass.
    function _cloneImplementationOf(address clone) internal view returns (address impl) {
        bytes memory code = clone.code;
        require(code.length == CLONE_RUNTIME_LENGTH, "registry is not an EIP-1167 clone");

        bytes10 prefix;
        bytes15 suffix;
        assembly {
            // `code` is length-prefixed; its bytes start at code+0x20.
            prefix := mload(add(code, 0x20))
            impl := shr(96, mload(add(code, 0x2a))) // 0x20 + 10
            suffix := mload(add(code, 0x3e)) // 0x20 + 30
        }
        require(prefix == CLONE_PREFIX && suffix == CLONE_SUFFIX, "registry is not an EIP-1167 clone");
    }

    /// @dev True if a STATICCALL of `callData` on `target` reverts with data
    ///      whose first four bytes are `expectedError`. A static call so that
    ///      nothing here can be a transaction, and so that a probe which
    ///      somehow got past a guard would fail on its first state write
    ///      rather than succeed.
    function _revertsWith(address target, bytes memory callData, bytes4 expectedError)
        internal
        view
        returns (bool)
    {
        (bool ok, bytes memory ret) = target.staticcall(callData);
        if (ok) return false;
        // Truncating to the first four bytes IS the comparison: a custom
        // error's selector, with whatever arguments follow it ignored. A
        // shorter or empty revert zero-pads and so never matches.
        // forge-lint: disable-next-line(unsafe-typecast)
        return bytes4(ret) == expectedError;
    }

    /// @dev True if a STATICCALL of `callData` on `target` reverts with no data
    ///      at all — what a contract with no matching function and no fallback
    ///      does.
    function _revertsEmpty(address target, bytes memory callData) internal view returns (bool) {
        (bool ok, bytes memory ret) = target.staticcall(callData);
        return !ok && ret.length == 0;
    }
}
