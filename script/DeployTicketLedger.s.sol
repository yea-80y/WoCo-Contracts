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
 * Required env (none defaulted — each is a decision that cannot be undone
 * cheaply, and a console warning is not a safeguard because forge script
 * output scrolls past):
 *   DEPLOYER_PRIVATE_KEY — pays gas and nothing else; it holds no role.
 *   INITIAL_OWNER        — the Safe. It becomes owner AND dispute authority
 *                          in the deploy transaction itself, so no handover is
 *                          left to do and the deployer never holds either role.
 *                          On Arbitrum One it must be a contract native to that
 *                          chain (a Safe deployed there): an L1 Safe acting via
 *                          the bridge arrives aliased and could never pass
 *                          onlyOwner (audit 959 I-2).
 *   INITIAL_SPONSOR      — the sponsor wallet that will mint (the server's
 *                          WOCO_SPONSOR_PRIVATE_KEY address). A wrong sponsor is
 *                          a contract the server cannot mint through,
 *                          discovered at first sale.
 *   INITIAL_SPONSOR_MINTS_PER_HOUR — that sponsor's hourly mint cap (audit 959
 *                          M-1). 4294967295 = unlimited. The Safe retunes it
 *                          later with setSponsorMintCap.
 *
 * POST-DEPLOY, IN THIS ORDER (1 before 2 — reversing them opens a window in
 * which every mint reverts NotAuthorised and ticket fulfilment stops):
 *   1. Confirm the sponsor and its cap:
 *        cast call <ledger> "authorisedSponsors(address)(bool)" <sponsor>
 *        cast call <ledger> "sponsorMintAllowance(address)(uint32,uint32,uint64)" <sponsor>
 *   2. Point the server at the new address
 *      (WOCO_EVENT_ADDRESS_LEDGER_{chainId} + WOCO_EVENT_VERSION_{chainId}).
 *   3. Confirm owner() and disputeAuthority() both read the Safe.
 */
contract DeployWoCoTicketLedger is Script {
    function run() external {
        uint256 deployerKey = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer    = vm.addr(deployerKey);
        address owner       = vm.envAddress("INITIAL_OWNER");
        address sponsor     = vm.envAddress("INITIAL_SPONSOR");
        uint256 perHour     = vm.envUint("INITIAL_SPONSOR_MINTS_PER_HOUR");
        require(owner != address(0), "INITIAL_OWNER must not be the zero address");
        require(sponsor != address(0), "INITIAL_SPONSOR must not be the zero address");
        require(perHour <= type(uint32).max, "INITIAL_SPONSOR_MINTS_PER_HOUR exceeds uint32");
        if (block.chainid == 42161) {
            require(owner.code.length > 0, "INITIAL_OWNER must be a Safe deployed on Arbitrum One");
            require(owner != sponsor, "INITIAL_OWNER must not be the sponsor");
        }

        console.log("Deploying WoCoTicketLedger...");
        console.log("  Chain ID:            ", block.chainid);
        console.log("  Deployer (gas only): ", deployer);
        console.log("  Owner + dispute auth:", owner);
        console.log("  Initial sponsor:     ", sponsor);
        console.log("  Sponsor mints/hour:  ", perHour);

        vm.startBroadcast(deployerKey);
        // safe: bounded to uint32 by the require above
        // forge-lint: disable-next-line(unsafe-typecast)
        WoCoTicketLedger ledger = new WoCoTicketLedger(owner, sponsor, uint32(perHour));
        vm.stopBroadcast();

        require(ledger.owner() == owner, "owner read-back failed");
        require(ledger.disputeAuthority() == owner, "dispute authority read-back failed");
        require(ledger.authorisedSponsors(sponsor), "sponsor read-back failed");

        console.log("WoCoTicketLedger deployed to:", address(ledger));

        _writeDeployment(address(ledger), deployer, owner, sponsor, perHour);
    }

    function _writeDeployment(
        address contractAddr,
        address deployer,
        address owner,
        address sponsor,
        uint256 perHour
    ) internal {
        vm.createDir("deployments", true);

        string memory obj = "deployment";
        vm.serializeString (obj, "contract",              "WoCoTicketLedger");
        vm.serializeUint   (obj, "chainId",               block.chainid);
        vm.serializeAddress(obj, "deployer",              deployer);
        vm.serializeAddress(obj, "owner",                 owner);
        vm.serializeAddress(obj, "disputeAuthority",      owner);
        vm.serializeAddress(obj, "initialSponsor",        sponsor);
        vm.serializeUint   (obj, "initialSponsorPerHour", perHour);
        vm.serializeString (obj, "note_payments",         "Holds no funds. Money lives in WoCoPayments (not yet built)");
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
