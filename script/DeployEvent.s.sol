// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/WoCoEvent.sol";

/**
 * Deploy WoCoEvent to any of the four supported chains:
 *
 *   Base Sepolia (staging):
 *     forge script script/DeployEvent.s.sol \
 *       --rpc-url base_sepolia --broadcast --verify
 *
 *   Base mainnet (production) — explicit user confirmation required:
 *     forge script script/DeployEvent.s.sol \
 *       --rpc-url base --broadcast --verify
 *
 *   Optimism mainnet (failover) — explicit user confirmation required:
 *     forge script script/DeployEvent.s.sol \
 *       --rpc-url optimism --broadcast --verify
 *
 *   Optimism Sepolia (failover staging):
 *     forge script script/DeployEvent.s.sol \
 *       --rpc-url op_sepolia --broadcast --verify
 *
 * Dry-run (no broadcast — safe for mainnet testing):
 *     forge script script/DeployEvent.s.sol --rpc-url base
 *
 * Required env vars:
 *   DEPLOYER_PRIVATE_KEY   — deployer EOA private key
 *
 * Deployed address is written to deployments/{chainId}.json.
 * The deployer EOA is set as both initial owner and initial sponsor.
 * Rotate to multisig (owner) and dedicated sponsor wallet before production load.
 */
contract DeployWoCoEvent is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer    = vm.addr(deployerKey);

        console.log("Deploying WoCoEvent...");
        console.log("  Chain ID:  ", block.chainid);
        console.log("  Deployer:  ", deployer);
        console.log("  Owner:     ", deployer, "(rotate to multisig post-deploy)");
        console.log("  Sponsor:   ", deployer, "(rotate to sponsor wallet pre-load)");

        vm.startBroadcast(deployerKey);
        WoCoEvent woco = new WoCoEvent(deployer, deployer);
        vm.stopBroadcast();

        console.log("WoCoEvent deployed to:", address(woco));

        _writeDeployment(address(woco), deployer);
    }

    function _writeDeployment(address contractAddr, address deployer) internal {
        vm.createDir("deployments", true);

        string memory obj = "deployment";
        vm.serializeString(obj, "contract", "WoCoEvent");
        vm.serializeUint(obj, "chainId", block.chainid);
        vm.serializeAddress(obj, "deployer", deployer);
        vm.serializeString(obj, "note_owner", "Rotate to multisig post-deploy");
        vm.serializeString(obj, "note_sponsor", "Rotate to dedicated sponsor wallet pre-load");
        string memory json = vm.serializeAddress(obj, "address", contractAddr);

        string memory path = string.concat(
            "deployments/",
            vm.toString(block.chainid),
            ".json"
        );
        vm.writeJson(json, path);
        console.log("Deployment saved to:", path);
    }
}
