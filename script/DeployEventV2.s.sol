// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "../src/WoCoEventV2.sol";

/**
 * Deploy WoCoEventV2 (USDC-settled, buyer-pays-directly) to a supported chain.
 *
 * Usage:
 *   Arbitrum Sepolia (buildathon staging — primary target):
 *     forge script script/DeployEventV2.s.sol \
 *       --rpc-url arb_sepolia --broadcast --verify
 *
 *   Arbitrum One (production — explicit confirmation required):
 *     forge script script/DeployEventV2.s.sol \
 *       --rpc-url arbitrum --broadcast --verify
 *
 *   Base Sepolia (failover staging):
 *     forge script script/DeployEventV2.s.sol \
 *       --rpc-url base_sepolia --broadcast --verify
 *
 *   Base mainnet (failover production — explicit confirmation required):
 *     forge script script/DeployEventV2.s.sol \
 *       --rpc-url base --broadcast --verify
 *
 * Dry-run (no broadcast):
 *     forge script script/DeployEventV2.s.sol --rpc-url arb_sepolia
 *
 * Required env vars:
 *   DEPLOYER_PRIVATE_KEY — deployer EOA private key
 *
 * Optional env vars (overrides per-chain defaults below):
 *   PAYMENT_TOKEN     — ERC20 to settle in (defaults to canonical USDC per chain)
 *   PLATFORM_TREASURY — fee recipient (defaults to deployer)
 *   PLATFORM_FEE_BPS  — default platform fee bps (defaults to 150 = 1.5%)
 *   INITIAL_SPONSOR   — Stripe-webhook sponsor wallet (defaults to deployer)
 *
 * Deployer is the initial owner — rotate to multisig post-deploy.
 * Deployment address written to deployments/{chainId}-v2.json.
 */
contract DeployWoCoEventV2 is Script {
    // Canonical USDC addresses per chain. Sources:
    //   - Circle's official deployments page (Arbitrum One, Base, Optimism)
    //   - Circle testnet faucet addresses (Sepolia variants)
    function _defaultUsdc(uint256 chainId) internal pure returns (address) {
        if (chainId == 42_161)    return 0xaf88d065e77c8cC2239327C5EDb3A432268e5831; // Arbitrum One
        if (chainId == 421_614)   return 0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d; // Arbitrum Sepolia
        if (chainId == 8_453)     return 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913; // Base
        if (chainId == 84_532)    return 0x036CbD53842c5426634e7929541eC2318f3dCF7e; // Base Sepolia
        if (chainId == 10)        return 0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85; // Optimism
        if (chainId == 11_155_420)return 0x5fd84259d66Cd46123540766Be93DFE6D43130D7; // Optimism Sepolia
        revert("No default USDC for this chain; set PAYMENT_TOKEN env");
    }

    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer    = vm.addr(deployerKey);

        address token    = vm.envOr("PAYMENT_TOKEN",     _defaultUsdc(block.chainid));
        address treasury = vm.envOr("PLATFORM_TREASURY", deployer);
        address sponsor  = vm.envOr("INITIAL_SPONSOR",   deployer);
        // forge-lint: disable-next-line(unsafe-typecast)
        uint16 feeBps    = uint16(vm.envOr("PLATFORM_FEE_BPS", uint256(150)));

        console.log("Deploying WoCoEventV2...");
        console.log("  Chain ID:        ", block.chainid);
        console.log("  Deployer / Owner:", deployer);
        console.log("  Payment token:   ", token);
        console.log("  Platform fee bps:", feeBps);
        console.log("  Treasury:        ", treasury);
        console.log("  Initial sponsor: ", sponsor, "(legacy Stripe webhook path)");

        vm.startBroadcast(deployerKey);
        WoCoEventV2 woco = new WoCoEventV2(
            deployer,
            sponsor,
            IERC20(token),
            treasury,
            feeBps
        );
        vm.stopBroadcast();

        console.log("WoCoEventV2 deployed to:", address(woco));

        _writeDeployment(address(woco), deployer, token, treasury, sponsor, feeBps);
    }

    function _writeDeployment(
        address contractAddr,
        address deployer,
        address token,
        address treasury,
        address sponsor,
        uint16  feeBps
    ) internal {
        vm.createDir("deployments", true);

        string memory obj = "deployment";
        vm.serializeString (obj, "contract",        "WoCoEventV2");
        vm.serializeUint   (obj, "chainId",          block.chainid);
        vm.serializeAddress(obj, "deployer",         deployer);
        vm.serializeAddress(obj, "paymentToken",     token);
        vm.serializeAddress(obj, "platformTreasury", treasury);
        vm.serializeAddress(obj, "initialSponsor",   sponsor);
        vm.serializeUint   (obj, "defaultFeeBps",    uint256(feeBps));
        vm.serializeString (obj, "note_owner",       "Rotate to multisig post-deploy");
        vm.serializeString (obj, "note_treasury",    "Currently = deployer; set PLATFORM_TREASURY to override");
        string memory json = vm.serializeAddress(obj, "address", contractAddr);

        string memory path = string.concat(
            "deployments/",
            vm.toString(block.chainid),
            "-v2.json"
        );
        vm.writeJson(json, path);
        console.log("Deployment saved to:", path);
    }
}
