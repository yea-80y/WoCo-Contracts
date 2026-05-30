// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {WoCoRegistrar} from "../src/WoCoRegistrar.sol";
import {IL2Registry} from "../src/durin/interfaces/IL2Registry.sol";

/// @title RedeployRegistrar
/// @notice Deploys a NEW WoCoRegistrar against an EXISTING L2Registry, wires it in,
///         authorises the sponsor, and seeds reserved names.
///         Use this when the registrar logic changes but the registry is already live.
/// @dev Run against Arbitrum Sepolia:
///        forge script script/RedeployRegistrar.s.sol --rpc-url arb_sepolia --broadcast --verify
///      Env required:
///        DEPLOYER_PRIVATE_KEY  — deployer + registry admin + registrar owner
///        SPONSOR_ADDRESS       — platform gas-sponsor wallet authorised to mint
///        L2_REGISTRY_ADDRESS   — existing L2Registry to wire the new registrar into
///      Optional:
///        PLATFORM_SIGNER_ADDRESS — defaults to SPONSOR_ADDRESS (same key, buildathon)
contract RedeployRegistrar is Script {
    function run() external {
        uint256 deployerPk   = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer     = vm.addr(deployerPk);
        address sponsor      = vm.envAddress("SPONSOR_ADDRESS");
        address registry     = vm.envAddress("L2_REGISTRY_ADDRESS");
        address platformSigner = vm.envOr("PLATFORM_SIGNER_ADDRESS", sponsor);

        vm.startBroadcast(deployerPk);

        // Deploy the new registrar with EIP-712 domain separation.
        WoCoRegistrar registrar = new WoCoRegistrar(registry, deployer, platformSigner);

        // Wire into the existing registry (deployer must be registry admin).
        IL2Registry(registry).addRegistrar(address(registrar));

        // Authorise the platform gas-sponsor wallet to call register() directly.
        registrar.addSponsor(sponsor);

        // Reserve platform / impersonation-risk labels.
        string[8] memory reservedLabels =
            ["woco", "admin", "support", "help", "www", "api", "app", "mail"];
        for (uint256 i; i < reservedLabels.length; ++i) {
            registrar.setReserved(reservedLabels[i], true);
        }

        vm.stopBroadcast();

        console.log("L2Registry (existing):", registry);
        console.log("WoCoRegistrar (new):  ", address(registrar));
        console.log("Owner / admin:        ", deployer);
        console.log("Authorised sponsor:   ", sponsor);
        console.log("Platform signer:      ", platformSigner);
        console.log("Domain separator:     ");
        console.logBytes32(registrar.DOMAIN_SEPARATOR());
    }
}
