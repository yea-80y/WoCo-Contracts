// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {WoCoRegistrar} from "../src/WoCoRegistrar.sol";
import {IL2Registry} from "../src/durin/interfaces/IL2Registry.sol";

/// @title RedeployRegistrar
/// @notice Deploys a NEW WoCoRegistrar against an EXISTING L2Registry, and
///         prints the admin batch that swaps it in: enrol the new registrar,
///         then retire the previous one. Use this when registrar policy changes
///         and the registry stays.
///
/// @dev Run against Arbitrum Sepolia:
///        forge script script/RedeployRegistrar.s.sol --rpc-url arb_sepolia --broadcast --verify
///
///      Required env:
///        DEPLOYER_PRIVATE_KEY  — pays for the one transaction. Holds no role.
///        SPONSOR_ADDRESS       — platform gas-sponsor wallet authorised to mint.
///        L2_REGISTRY_ADDRESS   — the registry the new registrar mints into. Its
///                                admin owns the new registrar, read live.
///      Optional env:
///        PREVIOUS_REGISTRAR    — the registrar being replaced. When set it must
///                                be enrolled in this registry and owned by the
///                                registry admin, and its retirement is part of
///                                the printed batch.
///
/// WHY THE RETIREMENT IS PART OF THE BATCH (audit 927 M2). v1 only printed a
/// reminder to remove the previous registrar, so a redeploy could leave it able to
/// mint and repoint names indefinitely. `removeRegistrar` is the retirement:
/// afterwards the previous registrar can neither mint nor repoint. Removing its
/// sponsor too is hygiene — it keeps a later re-enrolment of that registrar from
/// bringing its sponsor straight back with it.
///
/// WHY THERE IS NO WIRING HERE. The registry admin is the Safe, so no deployer key
/// can call `addRegistrar`. v1 wired conditionally and needed
/// `EXPECT_MANUAL_WIRING` so it would not report success over a registrar that
/// could not mint; v2 never wires, and prints what the Safe must send.
///
/// WHY THERE IS NO OWNER INPUT (v2.1). A v2.1 registrar has no owner of its own:
/// `owner()` is its registry's admin, read live (audit 937 F13). v2's
/// `REGISTRAR_ADMIN` is gone with the stored owner it set.
contract RedeployRegistrar is Script {
    /// @notice namehash("woco.eth"), as `DeploySubEnsRegistry` pins it.
    bytes32 constant PARENT_NODE = 0x616c19dee44e200629c0e4918ca0fe2f6e85100ea0b354c4f888e11c07a9006f;

    /// @notice Everything this script reads from its environment, in one place.
    struct Config {
        uint256 deployerPk;
        address sponsor;
        address registryAddress;
        address previousRegistrar;
    }

    /// @dev `virtual` ONLY so that tests can vary the inputs. They cannot do it
    ///      through the environment: `vm.setEnv` writes the whole forge
    ///      process's environment and Foundry runs test functions in parallel,
    ///      so per-test environments race, visibly and intermittently. The
    ///      guards themselves stay in `run()` and are never overridden.
    ///      Production always runs this body.
    function _config() internal view virtual returns (Config memory c) {
        c.deployerPk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        c.sponsor = vm.envAddress("SPONSOR_ADDRESS");
        c.registryAddress = vm.envAddress("L2_REGISTRY_ADDRESS");
        c.previousRegistrar = vm.envOr("PREVIOUS_REGISTRAR", address(0));
    }

    function run() external returns (address registrarAddress) {
        Config memory c = _config();

        IL2Registry registry = IL2Registry(c.registryAddress);
        // Catches a registry for another name. It cannot tell a retired woco.eth
        // registry from the live one: the printed addresses below are for that.
        require(
            registry.baseNode() == PARENT_NODE,
            "L2_REGISTRY_ADDRESS is not a woco.eth registry - its base node is not namehash(woco.eth)"
        );
        // A mistyped previous registrar would print a retirement that retires
        // nothing, while the real one keeps minting.
        require(
            c.previousRegistrar == address(0) || registry.registrars(c.previousRegistrar),
            "PREVIOUS_REGISTRAR is not enrolled in this registry"
        );
        // The batch is sent by the registry admin, and `removeSponsor` succeeds
        // only from the previous registrar's owner: if the two differ, the batch
        // reverts as a unit. A v2 registrar stored its own owner, and one bound
        // to another registry answers for that registry's admin.
        require(
            c.previousRegistrar == address(0) || Ownable(c.previousRegistrar).owner() == registry.owner(),
            "PREVIOUS_REGISTRAR is not owned by the registry admin - retire its sponsor separately"
        );

        vm.startBroadcast(c.deployerPk);
        WoCoRegistrar registrar = new WoCoRegistrar(c.registryAddress, c.sponsor, reservedLabels());
        vm.stopBroadcast();
        registrarAddress = address(registrar);

        console.log("L2Registry (existing):", c.registryAddress);
        console.log("WoCoRegistrar (new):  ", registrarAddress);
        console.log("Registrar owner:      ", registrar.owner());
        console.log("Authorised sponsor:   ", c.sponsor);
        console.log("Registry admin:       ", registry.owner());
        console.log("NEXT - the registry admin sends this batch, in order (one Safe transaction):");
        (address[] memory targets, bytes[] memory data) =
            adminBatch(c.registryAddress, registrarAddress, c.previousRegistrar, c.sponsor);
        for (uint256 i; i < targets.length; ++i) {
            console.log("  to:", targets[i]);
            console.logBytes(data[i]);
        }
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

    /// @notice The admin batch that swaps the new registrar in. A Safe batch is
    ///         atomic, so the order matters only to an operator who sends the
    ///         calls one by one: enrolling the new registrar first means there is
    ///         never a moment with no registrar. Public so the tests execute
    ///         exactly what is printed.
    /// @param previousRegistrar Zero for a first registrar; otherwise its sponsor
    ///                          is removed and it is unenrolled.
    function adminBatch(address registry, address newRegistrar, address previousRegistrar, address sponsor)
        public
        pure
        returns (address[] memory targets, bytes[] memory data)
    {
        uint256 n = previousRegistrar == address(0) ? 1 : 3;
        targets = new address[](n);
        data = new bytes[](n);

        targets[0] = registry;
        data[0] = abi.encodeCall(IL2Registry.addRegistrar, (newRegistrar));

        if (n == 3) {
            targets[1] = previousRegistrar;
            data[1] = abi.encodeCall(WoCoRegistrar.removeSponsor, (sponsor));
            targets[2] = registry;
            data[2] = abi.encodeCall(IL2Registry.removeRegistrar, (previousRegistrar));
        }
    }
}
