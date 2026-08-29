// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import {WoCoTicketLedger} from "../src/WoCoTicketLedger.sol";

/**
 * Deploy WoCoTicketLedger — the allocation ledger, with no payment handling.
 *
 * Unlike DeployEventV2.s.sol this takes NO payment token, treasury, or fee:
 * the contract holds no funds, so there is nothing to configure. Money
 * settings belong to WoCoPayments when it ships.
 *
 * Usage:
 *   Arbitrum Sepolia (staging):
 *     forge script script/DeployTicketLedger.s.sol \
 *       --rpc-url arb_sepolia --broadcast --verify
 *
 *   Arbitrum One (production — explicit confirmation required):
 *     forge script script/DeployTicketLedger.s.sol \
 *       --rpc-url arbitrum --broadcast --verify
 *
 * Dry-run (no broadcast):
 *     forge script script/DeployTicketLedger.s.sol --rpc-url arb_sepolia
 *
 * Required env:
 *   DEPLOYER_PRIVATE_KEY — deployer EOA private key
 *   INITIAL_SPONSOR      — the sponsor wallet that will mint (the server's
 *                          WOCO_SPONSOR_PRIVATE_KEY address). REQUIRED, with
 *                          no default: defaulting it to the deployer produces
 *                          a contract the server cannot mint through, and a
 *                          console warning is not a safeguard because forge
 *                          script output scrolls past.
 *
 * POST-DEPLOY, IN THIS ORDER (1 before 2 — reversing them opens a window in
 * which every mint reverts NotAuthorised and ticket fulfilment stops):
 *   1. Confirm the sponsor is authorised:
 *        cast call <ledger> "authorisedSponsors(address)(bool)" <sponsor>
 *      If false, from the owner: cast send <ledger> "addSponsor(address)" <sponsor>
 *   2. Point the server at the new address
 *      (WOCO_EVENT_ADDRESS_LEDGER_{chainId} + WOCO_EVENT_VERSION_{chainId}).
 *   3. Rotate `owner` to the multisig (Ownable2Step: transfer then accept).
 *   4. Rotate `disputeAuthority` to the multisig — it starts as the deployer,
 *      and it is the only address that can force-cancel an event.
 *
 * CUTOVER TRAP: `getEventContractVersion` returns "v1" for ANY unrecognised
 * value. So setting WOCO_EVENT_VERSION_{chainId} to the ledger's literal before
 * the server cascade ships does not fail loudly — it silently routes all
 * traffic to the V1 contract. Ship the server change first, then flip the env.
 */
contract DeployWoCoTicketLedger is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer    = vm.addr(deployerKey);
        // Required, not defaulted — see the header. A wrong sponsor is a
        // contract the server cannot mint through, discovered at first sale.
        address sponsor     = vm.envAddress("INITIAL_SPONSOR");
        require(sponsor != address(0), "INITIAL_SPONSOR must not be the zero address");

        console.log("Deploying WoCoTicketLedger...");
        console.log("  Chain ID:        ", block.chainid);
        console.log("  Deployer / Owner:", deployer);
        console.log("  Initial sponsor: ", sponsor);

        vm.startBroadcast(deployerKey);
        WoCoTicketLedger ledger = new WoCoTicketLedger(deployer, sponsor);
        vm.stopBroadcast();

        console.log("WoCoTicketLedger deployed to:", address(ledger));

        _writeDeployment(address(ledger), deployer, sponsor);
    }

    function _writeDeployment(address contractAddr, address deployer, address sponsor) internal {
        vm.createDir("deployments", true);

        string memory obj = "deployment";
        vm.serializeString (obj, "contract",       "WoCoTicketLedger");
        vm.serializeUint   (obj, "chainId",         block.chainid);
        vm.serializeAddress(obj, "deployer",        deployer);
        vm.serializeAddress(obj, "initialSponsor",  sponsor);
        vm.serializeString (obj, "note_owner",      "Rotate to multisig post-deploy (Ownable2Step)");
        vm.serializeString (obj, "note_dispute",    "disputeAuthority starts as deployer; rotate to multisig");
        vm.serializeString (obj, "note_payments",   "Holds no funds. Money lives in WoCoPayments (not yet built)");
        string memory json = vm.serializeAddress(obj, "address", contractAddr);

        string memory path = string.concat(
            "deployments/",
            vm.toString(block.chainid),
            "-ledger.json"
        );
        vm.writeJson(json, path);
        console.log("Deployment saved to:", path);
    }
}
